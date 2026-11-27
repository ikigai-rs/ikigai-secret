//! Stores and routes (`docs/storage-backends.md`, ledger #4486): the `[secret]` section a host
//! reads from its config home, the refusals that keep a wrong section from being half-applied,
//! and [`RoutingBackend`], the one [`Backend`] that sends each secret name to its store.
//!
//! This module does no I/O. The host reads `config.toml`, deserializes the `[secret]` table into
//! a [`SecretSection`] (it is `Deserialize`, so `toml::from_str` or any serde format will do,
//! as with core's `CacheConfig`), and hands it to [`SecretConfig::from_section`], which either
//! answers a whole, checked configuration or refuses with one sentence per problem. Only then
//! does [`SecretConfig::build`] construct anything.
//!
//! ```
//! use ikigai_secret::{SecretConfig, SecretSection};
//!
//! let section: SecretSection = toml::from_str(
//!     r#"
//!     default = "local"
//!
//!     [store.local]
//!     kind = "file"
//!     path = "~/.ikigai/secrets"
//!
//!     [store.archive]
//!     kind = "file"
//!     path = "/srv/ikigai/archive"
//!     write = false
//!
//!     [[route]]
//!     match = "old.*"
//!     store = "archive"
//!     "#,
//! )
//! .unwrap();
//! let config = SecretConfig::from_section(Some(&section), Some("/home/svc".as_ref())).unwrap();
//! assert_eq!(config.route_for("old.token").store, "archive");
//! assert_eq!(config.route_for("old.token").route, Some(1));
//! assert_eq!(config.route_for("api.token").store, "local");
//! assert_eq!(config.route_for("api.token").route, None);
//!
//! // A route to a store that is not configured refuses the whole section, naming the line.
//! let typo: SecretSection = toml::from_str(
//!     r#"
//!     default = "local"
//!     [store.local]
//!     kind = "file"
//!     path = "/srv/secrets"
//!     [[route]]
//!     match = "zoom.*"
//!     store = "teem"
//!     "#,
//! )
//! .unwrap();
//! let refused = SecretConfig::from_section(Some(&typo), None).unwrap_err();
//! assert_eq!(
//!     refused.problems(),
//!     ["`store = \"teem\"` in [[secret.route]] number 1 (`match = \"zoom.*\"`) names no \
//!       configured store; the configured stores are local."]
//! );
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_core::{Error, Result};
use serde::Deserialize;

use crate::{Backend, FileBackend, Signed};

/// The Keychain service, and the Secure Enclave label prefix, a store gets when its table names
/// none: the one [`default_backend`](crate::default_backend) has always used.
pub const DEFAULT_SERVICE: &str = "ikigai-secret";

/// Every store kind the `[secret]` section can name, in the order a refusal lists them. The
/// first three are built here; `age-file` and `fnox` are accepted by the parser and refused as
/// not built yet until their tasks land.
pub const STORE_KINDS: [&str; 5] = ["keychain", "secure-enclave", "file", "age-file", "fnox"];

/// The thread every cacheable inspection answer hangs from. The configuration is read once, at
/// start; a host that reloads it builds a new [`RoutingBackend`] and cuts this thread, so no
/// answer about the old stores and routes outlives them.
pub const CONFIG_THREAD: &str = "urn:secret:config";

// =====================================================================================
// The section as a host deserializes it.
// =====================================================================================

/// The `[secret]` table of a host's `config.toml`, as deserialized: nothing checked yet. Unknown
/// keys are refused by the deserializer. Hand it to [`SecretConfig::from_section`].
///
/// ```toml
/// [secret]
/// default = "keychain"                # the store every name no route matches goes to
///
/// [secret.store.keychain]
/// kind = "keychain"                   # keychain | secure-enclave | file | age-file | fnox
/// service = "ikigai-secret"           # keychain: the Keychain service (the default)
///
/// [secret.store.local]
/// kind = "file"
/// path = "~/.ikigai/secrets"          # file: absolute, or under the home the host passes
/// write = false                       # any store: refuse writes (default true)
///
/// [[secret.route]]                    # read in order; the first match wins
/// match = "owner:id:acme:name:*"      # a glob on the full secret name
/// store = "local"
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SecretSection {
    /// The store that takes every name no route matches. Required.
    #[serde(default)]
    pub default: Option<String>,
    /// The `[secret.store.<name>]` tables, by store name.
    #[serde(default, rename = "store")]
    pub stores: BTreeMap<String, StoreTable>,
    /// The `[[secret.route]]` entries, in order.
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteTable>,
}

/// One `[secret.store.<name>]` table: its `kind` and the settings that kind reads. Each kind
/// reads only its own settings, and a setting of another kind is refused by name.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StoreTable {
    /// One of [`STORE_KINDS`].
    pub kind: String,
    /// Any kind: `false` refuses every write (Sink, Delete, generate) to a name routed here, after
    /// every capability check. `true` when absent.
    #[serde(default)]
    pub write: Option<bool>,
    /// `keychain`: the Keychain service its items live under ([`DEFAULT_SERVICE`] when absent).
    #[serde(default)]
    pub service: Option<String>,
    /// `secure-enclave`: the prefix of its keys' labels ([`DEFAULT_SERVICE`] when absent).
    #[serde(default)]
    pub label_prefix: Option<String>,
    /// `file` (and `age-file`, not built yet): the store directory. Absent for `file`, today's
    /// place: `IKIGAI_SECRETS` when set, else the data home's `secrets` directory.
    #[serde(default)]
    pub path: Option<String>,
    /// `age-file` (not built yet): where the age identity comes from.
    #[serde(default)]
    pub identity: Option<String>,
    /// `fnox` (not built yet): the one fnox configuration file.
    #[serde(default)]
    pub config: Option<String>,
    /// `fnox` (not built yet): the fnox profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// `fnox` (not built yet): `map` or `escaped`.
    #[serde(default)]
    pub names: Option<String>,
    /// `fnox` (not built yet): ikigai name to fnox key.
    #[serde(default)]
    pub map: Option<BTreeMap<String, String>>,
}

/// One `[[secret.route]]` entry: a glob on the full secret name, and the store it sends a
/// matching name to.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RouteTable {
    /// The glob (`match` in the table): `*` is any run of characters, `?` any one character,
    /// `[...]` a class, everything else itself.
    #[serde(rename = "match")]
    pub pattern: String,
    /// The store a matching name goes to.
    pub store: String,
}

// =====================================================================================
// The checked configuration.
// =====================================================================================

/// What a store is, with the settings its backend is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreKind {
    /// The macOS Keychain: one generic password per secret, under `service`.
    Keychain {
        /// The Keychain service.
        service: String,
    },
    /// The macOS Secure Enclave: non-extractable signing keys labeled `<label_prefix>.<name>`.
    SecureEnclave {
        /// The label prefix.
        label_prefix: String,
    },
    /// A private directory of owner-only files ([`FileBackend`]).
    File {
        /// The directory, or `None` for today's place (`IKIGAI_SECRETS`, else the data home).
        dir: Option<PathBuf>,
    },
}

impl StoreKind {
    /// The kind's name, as the section spells it.
    pub fn name(&self) -> &'static str {
        match self {
            StoreKind::Keychain { .. } => "keychain",
            StoreKind::SecureEnclave { .. } => "secure-enclave",
            StoreKind::File { .. } => "file",
        }
    }

    /// One sentence on what the kind is. Never a path, an account, a token or a value.
    pub fn about(&self) -> &'static str {
        match self {
            StoreKind::Keychain { .. } => "The macOS Keychain, one item per secret.",
            StoreKind::SecureEnclave { .. } => {
                "Signing keys made inside this Mac's Secure Enclave, whose private halves never \
                 leave it, so values are generated there and never written."
            }
            StoreKind::File { .. } => {
                "A private directory of owner-only files, one per secret, not encrypted at rest."
            }
        }
    }

    /// Whether the kind can store a value a Sink hands it (the Secure Enclave cannot).
    fn holds_values(&self) -> bool {
        !matches!(self, StoreKind::SecureEnclave { .. })
    }
}

/// One configured store: its name, its kind, and whether writes to it are allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSpec {
    name: String,
    kind: StoreKind,
    write: bool,
}

impl StoreSpec {
    /// The store's name (the `<name>` of `[secret.store.<name>]`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The store's kind and settings.
    pub fn kind(&self) -> &StoreKind {
        &self.kind
    }

    /// Whether a Sink can store a value here: the store allows writes and its kind holds values.
    pub fn writable(&self) -> bool {
        self.write && self.kind.holds_values()
    }

    /// Whether the section set `write = false` on this store.
    pub fn read_only(&self) -> bool {
        !self.write
    }
}

/// One checked route: its glob and the store it sends a matching name to.
#[derive(Clone, Debug)]
pub struct RouteSpec {
    pattern: String,
    store: String,
    glob: glob::Pattern,
}

impl PartialEq for RouteSpec {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.store == other.store
    }
}

impl Eq for RouteSpec {}

impl RouteSpec {
    /// The glob, as the section spells it.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The store a matching name goes to.
    pub fn store(&self) -> &str {
        &self.store
    }

    /// Whether `name` matches the glob. `*` and `?` match any character, `:` and `.` included.
    pub fn matches(&self, name: &str) -> bool {
        self.glob.matches(name)
    }
}

/// Where one name routes: the store, and which route sent it there (1-based, the order of the
/// `[[secret.route]]` entries), or `None` when no route matched and the default took it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routed<'a> {
    /// The store's name.
    pub store: &'a str,
    /// The route that matched, numbered from 1; `None` for the default.
    pub route: Option<usize>,
}

/// A checked `[secret]` configuration: every store, every route and the default, each one
/// known to be valid on this platform. Built only by [`from_section`](Self::from_section), so
/// holding one means nothing in it can be refused later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretConfig {
    default: String,
    stores: Vec<StoreSpec>,
    routes: Vec<RouteSpec>,
    configured: bool,
}

/// Why a `[secret]` section was refused: one sentence per problem, each naming its line. A
/// refused section applies nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretConfigError {
    problems: Vec<String>,
}

impl SecretConfigError {
    fn new(problems: Vec<String>) -> Self {
        SecretConfigError { problems }
    }

    /// Every problem found, one sentence each, in the order of the section.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

impl fmt::Display for SecretConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.problems.len();
        write!(
            f,
            "The [secret] section was refused and nothing in it was applied ({count} {}):",
            if count == 1 { "problem" } else { "problems" }
        )?;
        for problem in &self.problems {
            write!(f, "\n- {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SecretConfigError {}

/// Which platform the section is checked for. `keychain` and `secure-enclave` are macOS stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Mac,
    Other,
}

impl Platform {
    pub(crate) fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Mac
        } else {
            Platform::Other
        }
    }
}

/// The one store today's [`default_backend`](crate::default_backend) builds: the Keychain under
/// [`DEFAULT_SERVICE`] on a Mac, the file store in today's place elsewhere. Named for its kind.
pub(crate) fn platform_store() -> StoreSpec {
    let kind = match Platform::current() {
        Platform::Mac => StoreKind::Keychain {
            service: DEFAULT_SERVICE.to_string(),
        },
        Platform::Other => StoreKind::File { dir: None },
    };
    StoreSpec {
        name: kind.name().to_string(),
        kind,
        write: true,
    }
}

/// The backend for one store's kind. A Mac kind off a Mac cannot pass the parser; should one
/// arrive anyway it becomes a store that refuses every operation, never a different store.
pub(crate) fn build_kind(kind: &StoreKind) -> Arc<dyn Backend> {
    match kind {
        #[cfg(target_os = "macos")]
        StoreKind::Keychain { service } => Arc::new(crate::KeychainBackend::new(service)),
        #[cfg(target_os = "macos")]
        StoreKind::SecureEnclave { label_prefix } => {
            Arc::new(crate::SecureEnclaveBackend::new(label_prefix))
        }
        #[cfg(not(target_os = "macos"))]
        StoreKind::Keychain { .. } | StoreKind::SecureEnclave { .. } => {
            Arc::new(FileBackend::refusing(format!(
                "a `{}` store is a macOS store, and this host is not a Mac",
                kind.name()
            )))
        }
        StoreKind::File { dir: Some(dir) } => Arc::new(FileBackend::new(dir)),
        StoreKind::File { dir: None } => Arc::new(FileBackend::in_data_dir_or_refusing()),
    }
}

/// Whether `name` can name a store: lowercase ASCII letters, digits, `-` and `_`, beginning with
/// a letter or a digit, so it can stand in `urn:secret:store:name:{store}` as itself.
fn is_store_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// A list in words: `a`, `a and b`, `a, b and c`.
fn words(items: &[&str]) -> String {
    match items {
        [] => "none".to_string(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A TOML string literal, for quoting a value back in a refusal as the line spells it.
fn quoted(value: &str) -> String {
    format!("{value:?}")
}

impl SecretConfig {
    /// Check a `[secret]` section for this platform.
    ///
    /// `None` (the host's `config.toml` has no `[secret]` section) answers exactly today's
    /// [`default_backend`](crate::default_backend): one store, the Keychain under
    /// [`DEFAULT_SERVICE`] on a Mac and the file store in today's place elsewhere, as the
    /// default, with no routes. `home` is the home directory the host resolved, which a store
    /// `path` beginning with `~/` is read under; a `~` path with no home is refused, and so is a
    /// relative path, since a store must never depend on the working directory.
    ///
    /// Refused, each with one sentence naming the line, and all of them reported at once: an
    /// unknown kind, a kind not built yet (`age-file`, `fnox`), a `keychain` or `secure-enclave`
    /// store off macOS, a setting another kind reads, a store name that cannot stand in an IRI,
    /// a missing `default` or one that names no store, a route to a store that is not
    /// configured, a route whose `match` is empty or not a glob, and two routes with the same
    /// `match`. A refused section applies nothing.
    pub fn from_section(
        section: Option<&SecretSection>,
        home: Option<&Path>,
    ) -> std::result::Result<Self, SecretConfigError> {
        Self::from_section_on(section, home, Platform::current())
    }

    pub(crate) fn from_section_on(
        section: Option<&SecretSection>,
        home: Option<&Path>,
        platform: Platform,
    ) -> std::result::Result<Self, SecretConfigError> {
        let Some(section) = section else {
            let store = platform_store();
            return Ok(SecretConfig {
                default: store.name.clone(),
                stores: vec![store],
                routes: Vec::new(),
                configured: false,
            });
        };
        let mut problems = Vec::new();

        let mut stores = Vec::new();
        for (name, table) in &section.stores {
            if !is_store_name(name) {
                problems.push(format!(
                    "[secret.store.{name}] is not a store name: a store name is lowercase \
                     letters, digits, `-` and `_`, beginning with a letter or a digit, so that \
                     it can stand in urn:secret:store:name:{{store}}."
                ));
                continue;
            }
            if let Some(kind) = check_store(name, table, home, platform, &mut problems) {
                stores.push(StoreSpec {
                    name: name.clone(),
                    kind,
                    write: table.write.unwrap_or(true),
                });
            }
        }
        let named: Vec<&str> = section.stores.keys().map(String::as_str).collect();
        let configured = |store: &str| section.stores.contains_key(store);

        let default = match &section.default {
            None => {
                problems.push(
                    "[secret] has no `default`: name the store that takes every secret no route \
                     matches, as `default = \"<store>\"`."
                        .to_string(),
                );
                String::new()
            }
            Some(default) if !configured(default) => {
                problems.push(format!(
                    "`default = {}` in [secret] names no configured store; the configured \
                     stores are {}.",
                    quoted(default),
                    words(&named)
                ));
                String::new()
            }
            Some(default) => default.clone(),
        };

        let mut routes: Vec<RouteSpec> = Vec::new();
        let mut seen: Vec<(&str, usize)> = Vec::new();
        for (index, route) in section.routes.iter().enumerate() {
            let number = index + 1;
            let line = format!(
                "[[secret.route]] number {number} (`match = {}`)",
                quoted(&route.pattern)
            );
            let mut ok = true;
            if route.pattern.is_empty() {
                problems.push(format!(
                    "`match = \"\"` in [[secret.route]] number {number} is empty, so it would \
                     match only a secret with no name; give it a glob such as \"zoom.*\"."
                ));
                ok = false;
            }
            if let Some((_, first)) = seen.iter().find(|(p, _)| *p == route.pattern) {
                problems.push(format!(
                    "`match = {}` in [[secret.route]] number {number} repeats route number \
                     {first}, which always matches first, so this route could never send a name \
                     anywhere.",
                    quoted(&route.pattern)
                ));
                ok = false;
            } else {
                seen.push((&route.pattern, number));
            }
            if !configured(&route.store) {
                problems.push(format!(
                    "`store = {}` in {line} names no configured store; the configured stores \
                     are {}.",
                    quoted(&route.store),
                    words(&named)
                ));
                ok = false;
            }
            let glob = match glob::Pattern::new(&route.pattern) {
                Ok(glob) => Some(glob),
                Err(e) => {
                    if !route.pattern.is_empty() {
                        problems.push(format!(
                            "`match = {}` in [[secret.route]] number {number} is not a glob: \
                             {}.",
                            quoted(&route.pattern),
                            e.msg
                        ));
                    }
                    None
                }
            };
            if let (true, Some(glob)) = (ok, glob) {
                routes.push(RouteSpec {
                    pattern: route.pattern.clone(),
                    store: route.store.clone(),
                    glob,
                });
            }
        }

        if problems.is_empty() {
            Ok(SecretConfig {
                default,
                stores,
                routes,
                configured: true,
            })
        } else {
            Err(SecretConfigError::new(problems))
        }
    }

    /// Whether this configuration came from a `[secret]` section (`false`: today's default).
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    /// The store every name no route matches goes to.
    pub fn default_store(&self) -> &str {
        &self.default
    }

    /// Every configured store, ordered by name.
    pub fn stores(&self) -> &[StoreSpec] {
        &self.stores
    }

    /// One store by name.
    pub fn store(&self, name: &str) -> Option<&StoreSpec> {
        self.stores.iter().find(|store| store.name == name)
    }

    /// The routes, in the order they are read.
    pub fn routes(&self) -> &[RouteSpec] {
        &self.routes
    }

    /// Where `name` lives: the first route whose glob matches it, else the default. A pure
    /// function of the name and the route table: no store is asked, so the answer says nothing
    /// about whether a secret by that name exists.
    pub fn route_for(&self, name: &str) -> Routed<'_> {
        match self
            .routes
            .iter()
            .enumerate()
            .find(|(_, route)| route.matches(name))
        {
            Some((index, route)) => Routed {
                store: &route.store,
                route: Some(index + 1),
            },
            None => Routed {
                store: &self.default,
                route: None,
            },
        }
    }

    /// Build every store this configuration names (the kinds built here: `keychain`,
    /// `secure-enclave`, `file`) and the [`RoutingBackend`] over them. Constructing a store
    /// opens nothing: a Keychain backend holds its service name, a file backend its directory,
    /// until a request reaches it.
    pub fn build(self) -> RoutingBackend {
        let backends = self
            .stores
            .iter()
            .map(|store| build_kind(&store.kind))
            .collect();
        RoutingBackend {
            config: self,
            backends,
        }
    }
}

/// Check one store table for its kind's settings, pushing a problem per refusal. `Some` when the
/// table describes a store this release builds.
fn check_store(
    name: &str,
    table: &StoreTable,
    home: Option<&Path>,
    platform: Platform,
    problems: &mut Vec<String>,
) -> Option<StoreKind> {
    let line = format!("[secret.store.{name}]");
    let settings: [(&str, bool); 9] = [
        ("write", table.write.is_some()),
        ("service", table.service.is_some()),
        ("label_prefix", table.label_prefix.is_some()),
        ("path", table.path.is_some()),
        ("identity", table.identity.is_some()),
        ("config", table.config.is_some()),
        ("profile", table.profile.is_some()),
        ("names", table.names.is_some()),
        ("map", table.map.is_some()),
    ];
    let reads: &[&str] = match table.kind.as_str() {
        "keychain" => &["write", "service"],
        "secure-enclave" => &["write", "label_prefix"],
        "file" => &["write", "path"],
        "age-file" | "fnox" => {
            problems.push(format!(
                "`kind = {}` in {line} is not built yet in this release of ikigai-secret; use \
                 keychain, secure-enclave or file until it lands.",
                quoted(&table.kind)
            ));
            return None;
        }
        unknown => {
            problems.push(format!(
                "`kind = {}` in {line} names no store kind; the kinds are {}.",
                quoted(unknown),
                words(&STORE_KINDS)
            ));
            return None;
        }
    };
    let before = problems.len();
    for (setting, present) in settings {
        if present && !reads.contains(&setting) {
            problems.push(format!(
                "`{setting}` in {line} is not a setting of a {} store, which reads {}.",
                table.kind,
                words(reads)
            ));
        }
    }
    if matches!(table.kind.as_str(), "keychain" | "secure-enclave") && platform != Platform::Mac {
        problems.push(format!(
            "`kind = {}` in {line} is a macOS store, and this host is not a Mac; use a file \
             store here.",
            quoted(&table.kind)
        ));
    }
    let non_empty = |setting: &str, value: &Option<String>, problems: &mut Vec<String>| match value
    {
        Some(value) if value.is_empty() => {
            problems.push(format!(
                "`{setting} = \"\"` in {line} is empty; give it a value or leave it out."
            ));
            None
        }
        Some(value) => Some(value.clone()),
        None => None,
    };
    let kind = match table.kind.as_str() {
        "keychain" => StoreKind::Keychain {
            service: non_empty("service", &table.service, problems)
                .unwrap_or_else(|| DEFAULT_SERVICE.to_string()),
        },
        "secure-enclave" => StoreKind::SecureEnclave {
            label_prefix: non_empty("label_prefix", &table.label_prefix, problems)
                .unwrap_or_else(|| DEFAULT_SERVICE.to_string()),
        },
        _ => StoreKind::File {
            dir: match table.path.as_deref() {
                None => None,
                Some(path) => store_dir(path, &line, home, problems),
            },
        },
    };
    (problems.len() == before).then_some(kind)
}

/// A store `path` as a directory: absolute as given, or `~` and `~/…` under the host's `home`.
fn store_dir(
    path: &str,
    line: &str,
    home: Option<&Path>,
    problems: &mut Vec<String>,
) -> Option<PathBuf> {
    let under_home = if path == "~" {
        Some("")
    } else {
        path.strip_prefix("~/")
    };
    match under_home {
        Some(rest) => match home.filter(|home| home.is_absolute()) {
            Some(home) => Some(if rest.is_empty() {
                home.to_path_buf()
            } else {
                home.join(rest)
            }),
            None => {
                problems.push(format!(
                    "`path = {}` in {line} begins with `~`, and the host has no home directory \
                     to read it under; give an absolute path.",
                    quoted(path)
                ));
                None
            }
        },
        None if Path::new(path).is_absolute() => Some(PathBuf::from(path)),
        None => {
            problems.push(format!(
                "`path = {}` in {line} is relative, and a secrets store never depends on the \
                 working directory; give an absolute path, or one beginning with `~/`.",
                quoted(path)
            ));
            None
        }
    }
}

// =====================================================================================
// The routing backend.
// =====================================================================================

/// The [`Backend`] over every configured store: each call goes to the store its name routes to
/// ([`SecretConfig::route_for`]), and only there.
///
/// **One store per name.** A miss in the routed store is a miss (`get` answers `None`, so the
/// resource answers NotFound); no other store is ever tried, so a name in one store can never
/// shadow the name meant for another, and where a secret lives never depends on what each store
/// happens to hold. [`sign`](Backend::sign) and
/// [`generate_signing_key`](Backend::generate_signing_key) route the same way.
///
/// **Read-only stores.** A write (`set`, `replace`, `create`, `delete`) to a name routed to a
/// store with `write = false` is refused as Conflict, naming the store, and
/// [`accepts_writes`](Backend::accepts_writes) says so before the presence gate is asked. The
/// resource faces call the backend only after every capability check, so the refusal never
/// tells an ungranted caller anything.
///
/// **Routing never widens a scope.** The route table is consulted only by the backend, after
/// the face has checked the name's own scope; a route says where an allowed operation goes,
/// never whether it is allowed.
pub struct RoutingBackend {
    config: SecretConfig,
    /// One backend per store, in the order of `config.stores`.
    backends: Vec<Arc<dyn Backend>>,
}

impl RoutingBackend {
    /// A routing backend over backends the host built itself, one per configured store, by
    /// store name: how a test, or a host holding a store this crate does not build, supplies
    /// them. Refused when a configured store has no backend, or a backend names no store.
    pub fn with_stores(
        config: SecretConfig,
        mut backends: BTreeMap<String, Arc<dyn Backend>>,
    ) -> std::result::Result<Self, SecretConfigError> {
        let mut problems = Vec::new();
        let mut ordered = Vec::new();
        for store in &config.stores {
            match backends.remove(&store.name) {
                Some(backend) => ordered.push(backend),
                None => problems.push(format!(
                    "the store {} is configured, and no backend was supplied for it.",
                    store.name
                )),
            }
        }
        for extra in backends.keys() {
            problems.push(format!(
                "a backend was supplied for {extra}, which is not a configured store."
            ));
        }
        if problems.is_empty() {
            Ok(RoutingBackend {
                config,
                backends: ordered,
            })
        } else {
            Err(SecretConfigError::new(problems))
        }
    }

    /// The configuration this backend routes by.
    pub fn config(&self) -> &SecretConfig {
        &self.config
    }

    /// The backend of the store named `store`.
    pub fn backend(&self, store: &str) -> Option<&Arc<dyn Backend>> {
        self.config
            .stores
            .iter()
            .position(|spec| spec.name == store)
            .map(|index| &self.backends[index])
    }

    /// The store `name` routes to, and its backend.
    fn routed(&self, name: &str) -> (&StoreSpec, &Arc<dyn Backend>) {
        let store = self.config.route_for(name).store;
        let index = self
            .config
            .stores
            .iter()
            .position(|spec| spec.name == store)
            .expect("a checked configuration routes only to configured stores");
        (&self.config.stores[index], &self.backends[index])
    }

    /// The routed backend for a write to `name`, or the refusal when its store is read-only.
    fn writable(&self, name: &str) -> Result<&Arc<dyn Backend>> {
        let (store, backend) = self.routed(name);
        if store.read_only() {
            return Err(Error::Conflict(format!(
                "`{name}` lives in the store {}, which is read-only (`write = false`), so it \
                 cannot be written or deleted there",
                store.name
            )));
        }
        Ok(backend)
    }
}

impl Backend for RoutingBackend {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.routed(name).1.get(name)
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.writable(name)?.set(name, value)
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.writable(name)?.delete(name)
    }

    fn exists(&self, name: &str) -> Result<bool> {
        self.routed(name).1.exists(name)
    }

    fn replace(&self, name: &str, value: &[u8]) -> Result<()> {
        self.writable(name)?.replace(name, value)
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<bool> {
        self.writable(name)?.create(name, value)
    }

    fn sign(&self, name: &str, message: &[u8]) -> Result<Option<Signed>> {
        self.routed(name).1.sign(name, message)
    }

    fn generate_signing_key(&self, name: &str) -> Result<Option<(String, Vec<u8>)>> {
        self.writable(name)?.generate_signing_key(name)
    }

    fn accepts_writes(&self, name: &str) -> Result<()> {
        let backend = self.writable(name)?;
        backend.accepts_writes(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(text: &str) -> SecretSection {
        toml::from_str(text).expect("the fixture deserializes")
    }

    fn refused(text: &str, platform: Platform) -> Vec<String> {
        SecretConfig::from_section_on(Some(&section(text)), Some(Path::new("/home/svc")), platform)
            .expect_err("refused")
            .problems()
            .to_vec()
    }

    const FILE: &str = "default = \"local\"\n[store.local]\nkind = \"file\"\npath = \"/srv/s\"\n";

    #[test]
    fn no_section_is_exactly_the_platform_default() {
        for platform in [Platform::Mac, Platform::Other] {
            let config = SecretConfig::from_section_on(None, None, platform).unwrap();
            assert!(!config.is_configured());
            assert_eq!(config.stores(), [platform_store()]);
            assert_eq!(config.default_store(), platform_store().name());
            assert!(config.routes().is_empty());
        }
        // The one store is what `default_backend()` has always built.
        let expected = if cfg!(target_os = "macos") {
            StoreKind::Keychain {
                service: "ikigai-secret".into(),
            }
        } else {
            StoreKind::File { dir: None }
        };
        assert_eq!(platform_store().kind(), &expected);
        assert!(platform_store().writable());
    }

    #[test]
    fn an_unknown_kind_is_refused_naming_the_line() {
        let problems = refused(
            "default = \"v\"\n[store.v]\nkind = \"vault\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`kind = \"vault\"` in [secret.store.v] names no store kind; the kinds are \
              keychain, secure-enclave, file, age-file and fnox."
            ]
        );
    }

    #[test]
    fn age_file_and_fnox_are_accepted_kinds_refused_as_not_built_yet() {
        let problems = refused(
            "default = \"a\"\n[store.a]\nkind = \"age-file\"\npath = \"~/s\"\nidentity = \"x\"\n\
             [store.f]\nkind = \"fnox\"\nconfig = \"/f.toml\"\nnames = \"map\"\n[store.f.map]\n\
             \"a.b\" = \"A_B\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`kind = \"age-file\"` in [secret.store.a] is not built yet in this release of \
                 ikigai-secret; use keychain, secure-enclave or file until it lands.",
                "`kind = \"fnox\"` in [secret.store.f] is not built yet in this release of \
                 ikigai-secret; use keychain, secure-enclave or file until it lands."
            ]
        );
    }

    #[test]
    fn mac_stores_are_refused_off_macos_and_accepted_on_it() {
        let text = "default = \"k\"\n[store.k]\nkind = \"keychain\"\n[store.e]\n\
                    kind = \"secure-enclave\"\n";
        assert_eq!(
            refused(text, Platform::Other),
            [
                "`kind = \"secure-enclave\"` in [secret.store.e] is a macOS store, and this host \
                 is not a Mac; use a file store here.",
                "`kind = \"keychain\"` in [secret.store.k] is a macOS store, and this host is \
                 not a Mac; use a file store here."
            ]
        );
        let config =
            SecretConfig::from_section_on(Some(&section(text)), None, Platform::Mac).unwrap();
        assert_eq!(
            config.store("k").unwrap().kind(),
            &StoreKind::Keychain {
                service: DEFAULT_SERVICE.into()
            }
        );
        assert!(
            !config.store("e").unwrap().writable(),
            "the Enclave holds no values"
        );
    }

    #[test]
    fn a_default_that_names_nothing_is_refused() {
        let problems = refused(
            "default = \"nope\"\n[store.local]\nkind = \"file\"\npath = \"/s\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            ["`default = \"nope\"` in [secret] names no configured store; the configured stores \
              are local."]
        );
        let missing = refused("[store.local]\nkind = \"file\"\n", Platform::Other);
        assert_eq!(
            missing,
            [
                "[secret] has no `default`: name the store that takes every secret no route \
              matches, as `default = \"<store>\"`."
            ]
        );
    }

    #[test]
    fn a_route_to_an_unconfigured_store_is_refused() {
        let problems = refused(
            &format!("{FILE}[[route]]\nmatch = \"zoom.*\"\nstore = \"team\"\n"),
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`store = \"team\"` in [[secret.route]] number 1 (`match = \"zoom.*\"`) names no \
              configured store; the configured stores are local."
            ]
        );
    }

    #[test]
    fn two_routes_with_the_same_match_are_refused() {
        let problems = refused(
            &format!(
                "{FILE}[[route]]\nmatch = \"a.*\"\nstore = \"local\"\n[[route]]\nmatch = \"b\"\n\
                 store = \"local\"\n[[route]]\nmatch = \"a.*\"\nstore = \"local\"\n"
            ),
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`match = \"a.*\"` in [[secret.route]] number 3 repeats route number 1, which \
              always matches first, so this route could never send a name anywhere."
            ]
        );
    }

    #[test]
    fn a_match_that_is_empty_or_not_a_glob_is_refused() {
        let problems = refused(
            &format!(
                "{FILE}[[route]]\nmatch = \"\"\nstore = \"local\"\n[[route]]\nmatch = \"[\"\n\
                 store = \"local\"\n"
            ),
            Platform::Other,
        );
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("`match = \"\"` in [[secret.route]] number 1 is empty"));
        assert!(
            problems[1].starts_with("`match = \"[\"` in [[secret.route]] number 2 is not a glob"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_setting_of_another_kind_is_refused_by_name() {
        let problems = refused(
            "default = \"local\"\n[store.local]\nkind = \"file\"\npath = \"/s\"\n\
             service = \"x\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`service` in [secret.store.local] is not a setting of a file store, which reads \
              write and path."
            ]
        );
    }

    #[test]
    fn paths_are_absolute_or_under_the_hosts_home() {
        let config = |path: &str, home: Option<&str>| {
            let text = format!("default = \"l\"\n[store.l]\nkind = \"file\"\npath = \"{path}\"\n");
            SecretConfig::from_section_on(
                Some(&section(&text)),
                home.map(Path::new),
                Platform::Other,
            )
        };
        let dir = |c: SecretConfig| match c.store("l").unwrap().kind() {
            StoreKind::File { dir } => dir.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            dir(config("~/.ikigai/s", Some("/home/svc")).unwrap()),
            Some(PathBuf::from("/home/svc/.ikigai/s"))
        );
        assert_eq!(
            dir(config("/srv/s", None).unwrap()),
            Some(PathBuf::from("/srv/s"))
        );
        let relative = config("secrets", Some("/home/svc")).unwrap_err();
        assert!(relative.problems()[0].contains("is relative"), "{relative}");
        let homeless = config("~/s", None).unwrap_err();
        assert!(
            homeless.problems()[0].contains("no home directory"),
            "{homeless}"
        );
        let relative_home = config("~/s", Some("home")).unwrap_err();
        assert!(relative_home.problems()[0].contains("no home directory"));
    }

    #[test]
    fn a_store_name_that_cannot_stand_in_an_iri_is_refused() {
        let problems = refused(
            "default = \"Team\"\n[store.Team]\nkind = \"file\"\npath = \"/s\"\n",
            Platform::Other,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("[secret.store.Team] is not a store name"));
    }

    #[test]
    fn every_problem_is_reported_at_once_and_nothing_is_applied() {
        let err = SecretConfig::from_section_on(
            Some(&section(
                "default = \"x\"\n[store.a]\nkind = \"vault\"\n[[route]]\nmatch = \"z\"\n\
                 store = \"y\"\n",
            )),
            None,
            Platform::Other,
        )
        .unwrap_err();
        assert_eq!(err.problems().len(), 3, "{err}");
        assert!(err.to_string().starts_with(
            "The [secret] section was refused and nothing in it was applied (3 problems):\n- "
        ));
    }

    #[test]
    fn unknown_keys_are_refused_by_the_deserializer() {
        let typo = toml::from_str::<SecretSection>("defualt = \"x\"\n");
        assert!(typo.unwrap_err().to_string().contains("defualt"));
        let route = toml::from_str::<SecretSection>("[[route]]\nmatches = \"x\"\nstore = \"y\"\n");
        assert!(route.unwrap_err().to_string().contains("matches"));
    }

    #[test]
    fn the_first_matching_route_wins_else_the_default() {
        let config = SecretConfig::from_section_on(
            Some(&section(
                "default = \"a\"\n[store.a]\nkind = \"file\"\npath = \"/a\"\n[store.b]\n\
                 kind = \"file\"\npath = \"/b\"\n[[route]]\nmatch = \"owner:id:acme:name:*\"\n\
                 store = \"b\"\n[[route]]\nmatch = \"owner:*\"\nstore = \"a\"\n[[route]]\n\
                 match = \"zoom.?\"\nstore = \"b\"\n",
            )),
            None,
            Platform::Other,
        )
        .unwrap();
        let at = |name: &str| {
            let routed = config.route_for(name);
            (routed.store.to_string(), routed.route)
        };
        assert_eq!(at("owner:id:acme:name:db"), ("b".into(), Some(1)));
        assert_eq!(at("owner:id:other:name:db"), ("a".into(), Some(2)));
        assert_eq!(at("zoom.x"), ("b".into(), Some(3)));
        assert_eq!(at("zoom.xy"), ("a".into(), None));
        assert_eq!(at("plain"), ("a".into(), None));
    }
}
