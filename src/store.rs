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

use crate::age_file::{recipient_kind, AgeFileBackend, AgeKeys, HOST_DEFAULT_IDENTITY};
use crate::{Backend, FileBackend, Reencrypted, Signed};

/// The Keychain service, and the Secure Enclave label prefix, a store gets when its table names
/// none: the one [`default_backend`](crate::default_backend) has always used.
pub const DEFAULT_SERVICE: &str = "ikigai-secret";

/// Every store kind the `[secret]` section can name, in the order a refusal lists them. The
/// first four are built here (`age-file` since 0.5.3, ledger #4488). `fnox` (since 0.5.4, ledger
/// #4489) is checked here and built by the host through the `ikigai-secret-fnox` connector, since
/// fnox reads files and the environment and runs provider commands, which this crate never does.
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
/// [secret.store.server]
/// kind = "age-file"                   # each item age-encrypted at rest
/// path = "/srv/ikigai/secrets"        # absent: the data home's `secrets` directory
/// identity = "file:/etc/ikigai/age"   # where the HOST gets the age identity from
/// recipients = ["age1…"]              # more recipients every item is sealed to (recovery)
///
/// [secret.store.local]
/// kind = "file"
/// path = "~/.ikigai/secrets"          # file: absolute, or under the home the host passes
/// write = false                       # any store: refuse writes (default true)
///
/// [secret.store.team]
/// kind = "fnox"                       # read through fnox's library, read-only
/// config = "~/work/acme/fnox.toml"    # the one fnox file; never fnox's upward search
/// profile = "prod"                    # absent: fnox's default profile
/// names = "map"                       # map (the default) | escaped
///
/// [secret.store.team.map]             # names = "map": ikigai name to fnox key, one to one
/// "zoom.client-secret" = "ZOOM_CLIENT_SECRET"
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
    /// `file` and `age-file`: the store directory. Absent for `file`, today's place:
    /// `IKIGAI_SECRETS` when set, else the data home's `secrets` directory. Absent for `age-file`,
    /// the data home's `secrets` directory (never `IKIGAI_SECRETS`, which is deprecated).
    #[serde(default)]
    pub path: Option<String>,
    /// `age-file`: where the age identity comes from, which the HOST resolves (a file, a system
    /// credential, an age plugin). Required.
    #[serde(default)]
    pub identity: Option<String>,
    /// `age-file`: more age recipients every item is sealed to, besides the identity's own (a
    /// recovery key kept off the machine). Each is an `age1…` recipient, X25519 or a plugin's.
    #[serde(default)]
    pub recipients: Option<Vec<String>>,
    /// `fnox`: the one fnox configuration file, absolute or under the host's home. Required.
    #[serde(default)]
    pub config: Option<String>,
    /// `fnox`: the fnox profile (fnox's default profile when absent, never `FNOX_PROFILE`).
    #[serde(default)]
    pub profile: Option<String>,
    /// `fnox`: how a secret name becomes a fnox key, `map` (the default) or `escaped`
    /// ([`FnoxNames`]).
    #[serde(default)]
    pub names: Option<String>,
    /// `fnox` with `names = "map"`: ikigai name to fnox key, one to one.
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
    /// The file store's layout with each item age-encrypted ([`AgeFileBackend`]).
    AgeFile {
        /// The directory.
        dir: PathBuf,
        /// Where the host gets the age identity from, as the section spells it.
        identity: String,
        /// The configured recipients beyond the identity's own, as the section spells them.
        recipients: Vec<String>,
    },
    /// One fnox configuration file, read through fnox's library by the host's
    /// `ikigai-secret-fnox` connector. Always read-only.
    Fnox {
        /// The fnox configuration file. Only this file (and what it imports) is read, never
        /// fnox's upward search from the working directory.
        config: PathBuf,
        /// The fnox profile, or `None` for fnox's default profile.
        profile: Option<String>,
        /// How a secret name becomes a fnox key.
        names: FnoxNames,
    },
}

/// How a `fnox` store turns a secret name into a fnox key. Both mappings are ONE TO ONE: a lossy
/// one (`a.b` and `a-b` both becoming `A_B`) would let a caller allowed to read one name read the
/// secret meant for the other, which it holds no scope for. So there is no third mapping.
///
/// ```
/// use std::collections::BTreeMap;
/// use ikigai_secret::FnoxNames;
///
/// let map = FnoxNames::Map(BTreeMap::from([("zoom.client-secret".into(), "ZOOM_SECRET".into())]));
/// assert_eq!(map.key_for("zoom.client-secret").as_deref(), Some("ZOOM_SECRET"));
/// assert_eq!(map.key_for("zoom.other"), None); // unlisted: NotFound
///
/// assert_eq!(FnoxNames::Escaped.key_for("zoom.client-secret").as_deref(),
///            Some("zoom_2Eclient_2Dsecret"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FnoxNames {
    /// `names = "map"`, the default: the `[secret.store.<s>.map]` table, secret name to fnox key.
    /// A name the table does not list is NotFound; a table sending two names to one key is
    /// refused when the section is checked.
    Map(BTreeMap<String, String>),
    /// `names = "escaped"`: [`fnox_escape`], an injective transform, for a fnox file written for
    /// ikigai.
    Escaped,
}

impl FnoxNames {
    /// The fnox key `name` reads, or `None` when it reads none (an unlisted name, or the empty
    /// name), which the store answers as NotFound.
    pub fn key_for(&self, name: &str) -> Option<String> {
        match self {
            FnoxNames::Map(map) => map.get(name).cloned(),
            FnoxNames::Escaped => (!name.is_empty()).then(|| fnox_escape(name)),
        }
    }

    /// The mapping's name, as the section spells it.
    pub fn name(&self) -> &'static str {
        match self {
            FnoxNames::Map(_) => "map",
            FnoxNames::Escaped => "escaped",
        }
    }
}

/// The `escaped` mapping of a secret name to a fnox key: ASCII letters pass, and so do ASCII
/// digits after the first character; every other character, `_` included, becomes `_` and two
/// uppercase hex digits per UTF-8 byte (`.` is `_2E`, `_` is `_5F`). A leading digit is escaped
/// too, because a fnox key cannot begin with one.
///
/// Injective: a literal is never `_`, and every `_` begins exactly three characters, so a key
/// reads back to exactly one name and no two names meet. Every key it makes is a valid fnox key
/// ([`is_fnox_key`]) when `name` is not empty.
///
/// ```
/// use ikigai_secret::fnox_escape;
///
/// assert_eq!(fnox_escape("a.b"), "a_2Eb");
/// assert_eq!(fnox_escape("a-b"), "a_2Db");
/// assert_eq!(fnox_escape("a_b"), "a_5Fb");
/// assert_eq!(fnox_escape("1password"), "_31password");
/// assert_eq!(fnox_escape("owner:id:acme:name:db"), "owner_3Aid_3Aacme_3Aname_3Adb");
/// ```
pub fn fnox_escape(name: &str) -> String {
    use std::fmt::Write as _;
    let mut key = String::with_capacity(name.len());
    for (index, ch) in name.char_indices() {
        if ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit()) {
            key.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).bytes() {
                let _ = write!(key, "_{byte:02X}");
            }
        }
    }
    key
}

/// Whether `key` is a fnox key: ASCII letters, digits and `_`, beginning with a letter or `_`
/// (fnox's `^[A-Za-z_][A-Za-z0-9_]*$`).
pub fn is_fnox_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl StoreKind {
    /// The kind's name, as the section spells it.
    pub fn name(&self) -> &'static str {
        match self {
            StoreKind::Keychain { .. } => "keychain",
            StoreKind::SecureEnclave { .. } => "secure-enclave",
            StoreKind::File { .. } => "file",
            StoreKind::AgeFile { .. } => "age-file",
            StoreKind::Fnox { .. } => "fnox",
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
            StoreKind::AgeFile { .. } => {
                "A private directory of owner-only files, one per secret, each encrypted at rest \
                 to the store's age recipients."
            }
            StoreKind::Fnox { .. } => {
                "A fnox configuration, read through fnox's library: each secret name maps to one \
                 fnox key, which fnox's providers answer. Read-only."
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
    /// A refusal of `problems`, one sentence each: how a connector that builds a store this
    /// crate does not (`ikigai-secret-fnox`) refuses the section the same way, so a host prints
    /// one kind of refusal at start.
    pub fn new(problems: Vec<String>) -> Self {
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

/// What a host with no `[secret]` section finds already on this machine
/// ([`found_install`](crate::found_install)), which [`SecretConfig::for_host`] turns into a store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Found {
    /// No store yet: a new install, which gets an `age-file` store.
    Nothing,
    /// An install from before (Keychain items, a file store with secrets in it, or
    /// `IKIGAI_SECRETS` set), which keeps its store unchanged.
    Existing,
    /// The `age-file` store an earlier start of a new install made (its marker is there).
    AgeFile,
}

/// The data home's `secrets` directory under `home`, when `home` is absolute.
pub(crate) fn data_home_secrets(home: Option<&Path>) -> Option<PathBuf> {
    let home = home.filter(|home| home.is_absolute())?;
    ikigai_core::config::data_home_from(Some(home.as_os_str().to_os_string()))
        .and_then(|data| ikigai_core::config::data_path_in(&data, "secrets"))
        .filter(|dir| dir.is_absolute())
}

/// The refusal of an `age-file` store its host built no keys for.
fn no_keys(store: &str, identity: &str) -> String {
    format!(
        "the store {store} is an age-file store, and the host was not given its age identity \
         (identity = {}), so it can neither read nor write a secret; the host builds its keys \
         and passes them to SecretConfig::build_with_keys",
        quoted(identity)
    )
}

/// The refusal of a `fnox` store its host did not build through the connector.
fn no_connector(store: &str) -> String {
    format!(
        "the store {store} is a fnox store, and the host did not build it through the \
         ikigai-secret-fnox connector, so it can read nothing; the host passes the connector's \
         backends to SecretConfig::build_with_backends"
    )
}

/// The backend for one store's kind. A Mac kind off a Mac cannot pass the parser; should one
/// arrive anyway it becomes a store that refuses every operation, never a different store. A
/// `fnox` store is the host's to build, so here it refuses too.
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
        StoreKind::AgeFile { dir, identity, .. } => Arc::new(AgeFileBackend::without_keys(
            dir,
            no_keys("(unnamed)", identity),
        )),
        StoreKind::Fnox { .. } => Arc::new(FileBackend::refusing(no_connector("(unnamed)"))),
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
    /// [`default_backend`](crate::default_backend), the store an EXISTING install keeps (a host
    /// that also tells a new install from an old one calls [`for_host`](Self::for_host)): one
    /// store, the Keychain under
    /// [`DEFAULT_SERVICE`] on a Mac and the file store in today's place elsewhere, as the
    /// default, with no routes. `home` is the home directory the host resolved, which a store
    /// `path` beginning with `~/` is read under; a `~` path with no home is refused, and so is a
    /// relative path, since a store must never depend on the working directory.
    ///
    /// Refused, each with one sentence naming the line, and all of them reported at once: an
    /// unknown kind, a `keychain` or `secure-enclave` store off
    /// macOS, a setting another kind reads, an `age-file` store with no `identity`, or with a
    /// `recipients` entry that is not an age recipient, a `fnox` store with no `config`, with
    /// `write = true`, with an unknown `names`, with no `map` table under `names = "map"` (or one
    /// under `escaped`), or with a table entry that is not a fnox key or that sends two names to
    /// one key, a store name that cannot stand in an IRI,
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
                // A fnox store is read-only: `write = true` was refused above.
                let fnox = matches!(kind, StoreKind::Fnox { .. });
                stores.push(StoreSpec {
                    name: name.clone(),
                    kind,
                    write: table.write.unwrap_or(true) && !fnox,
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

    /// The configuration for a host: its `[secret]` section when it has one, else the store this
    /// machine already uses, or an `age-file` store for a new install (`docs/storage-backends.md`
    /// section 9, decision 5). `found` is what [`found_install`](crate::found_install) answered.
    ///
    /// - A section: exactly [`from_section`](Self::from_section); `found` is not consulted.
    /// - No section and [`Found::Existing`]: today's store, as `from_section(None, …)`, unchanged.
    ///   [`notice`](Self::notice) then has the one line the host prints at start.
    /// - No section and [`Found::Nothing`] or [`Found::AgeFile`]: one `age-file` store, named
    ///   `age-file`, in the data home's `secrets` directory under `home`, whose identity is the
    ///   host's own default ([`HOST_DEFAULT_IDENTITY`]) and with no further recipients. Refused
    ///   when there is no absolute `home` to place it under.
    ///
    /// ```
    /// use ikigai_secret::{Found, SecretConfig, StoreKind, HOST_DEFAULT_IDENTITY};
    ///
    /// let new = SecretConfig::for_host(None, Some("/home/svc".as_ref()), Found::Nothing).unwrap();
    /// assert_eq!(new.default_store(), "age-file");
    /// assert!(matches!(
    ///     new.stores()[0].kind(),
    ///     StoreKind::AgeFile { identity, .. } if identity == HOST_DEFAULT_IDENTITY
    /// ));
    /// assert_eq!(new.notice(), None);
    ///
    /// let old = SecretConfig::for_host(None, Some("/home/svc".as_ref()), Found::Existing).unwrap();
    /// assert_eq!(old, SecretConfig::from_section(None, Some("/home/svc".as_ref())).unwrap());
    /// assert!(old.notice().unwrap().contains("age-file"));
    /// ```
    pub fn for_host(
        section: Option<&SecretSection>,
        home: Option<&Path>,
        found: Found,
    ) -> std::result::Result<Self, SecretConfigError> {
        Self::for_host_on(section, home, found, Platform::current())
    }

    pub(crate) fn for_host_on(
        section: Option<&SecretSection>,
        home: Option<&Path>,
        found: Found,
        platform: Platform,
    ) -> std::result::Result<Self, SecretConfigError> {
        if section.is_some() || found == Found::Existing {
            return Self::from_section_on(section, home, platform);
        }
        let dir = data_home_secrets(home).ok_or_else(|| {
            SecretConfigError::new(vec![
                "There is no [secret] section and no secrets store yet, so a new age-file store \
                 would be made in the data home, and the host has no absolute home directory to \
                 put it under; set HOME, or add a [secret] section naming the store's path."
                    .to_string(),
            ])
        })?;
        let kind = StoreKind::AgeFile {
            dir,
            identity: HOST_DEFAULT_IDENTITY.to_string(),
            recipients: Vec::new(),
        };
        let store = StoreSpec {
            name: kind.name().to_string(),
            kind,
            write: true,
        };
        Ok(SecretConfig {
            default: store.name.clone(),
            stores: vec![store],
            routes: Vec::new(),
            configured: false,
        })
    }

    /// The one line a host prints at start when it has no `[secret]` section and keeps an
    /// existing install's store: that `age-file` is now the default for new installs, how to move
    /// to it, and that `IKIGAI_SECRETS` is deprecated. `None` for every other configuration.
    pub fn notice(&self) -> Option<String> {
        if self.configured {
            return None;
        }
        let store = self.stores.first()?;
        if matches!(store.kind, StoreKind::AgeFile { .. }) {
            return None;
        }
        Some(format!(
            "ikigai-secret: secrets stay in the {} store, as before. New installs now get an \
             age-file store, which encrypts each secret at rest; to move to one, add a [secret] \
             section with an age-file store and copy each secret into it with \
             urn:secret:store:name:{{store}}:copy. IKIGAI_SECRETS is deprecated: name the store's \
             path in the [secret] section instead.",
            store.kind.name()
        ))
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
    /// `secure-enclave`, `file`, `age-file`) and the [`RoutingBackend`] over them. Constructing a
    /// store opens nothing: a Keychain backend holds its service name, a file backend its
    /// directory, until a request reaches it.
    ///
    /// An `age-file` store needs the age keys only its host can build, so here it refuses every
    /// operation, saying so; a host with `age-file` stores calls
    /// [`build_with_keys`](Self::build_with_keys). A `fnox` store likewise refuses here; a host
    /// with `fnox` stores calls [`build_with_backends`](Self::build_with_backends).
    pub fn build(self) -> RoutingBackend {
        let backends = self
            .stores
            .iter()
            .map(|store| match &store.kind {
                StoreKind::AgeFile { dir, identity, .. } => Arc::new(AgeFileBackend::without_keys(
                    dir,
                    no_keys(&store.name, identity),
                )) as Arc<dyn Backend>,
                StoreKind::Fnox { .. } => {
                    Arc::new(FileBackend::refusing(no_connector(&store.name)))
                }
                kind => build_kind(kind),
            })
            .collect();
        RoutingBackend {
            config: self,
            backends,
        }
    }

    /// [`build`](Self::build), with the age keys the host built for each `age-file` store, by
    /// store name (from the store's `identity` and `recipients`; [`X25519Keys`](crate::X25519Keys)
    /// for identity text the host read). Refused whole, naming each store, when an `age-file`
    /// store has no keys or keys are given for a store that is not an `age-file` store. A `fnox`
    /// store refuses every operation, as under [`build`](Self::build).
    pub fn build_with_keys(
        self,
        keys: BTreeMap<String, Arc<dyn AgeKeys>>,
    ) -> std::result::Result<RoutingBackend, SecretConfigError> {
        self.assemble(keys, None)
    }

    /// [`build_with_keys`](Self::build_with_keys), with the backends the host built for each
    /// `fnox` store, by store name: what `ikigai_secret_fnox::backends` answers. Refused whole,
    /// naming each store, when a `fnox` store has no backend or a backend is given for a store
    /// this crate builds itself or for no configured store.
    ///
    /// ```
    /// use std::collections::BTreeMap;
    /// use ikigai_secret::{SecretConfig, SecretSection};
    ///
    /// let section: SecretSection = toml::from_str(
    ///     r#"
    ///     default = "team"
    ///     [store.team]
    ///     kind = "fnox"
    ///     config = "/srv/acme/fnox.toml"
    ///     names = "escaped"
    ///     "#,
    /// )
    /// .unwrap();
    /// let config = SecretConfig::from_section(Some(&section), None).unwrap();
    /// // A host that built no fnox backend is refused, naming the store.
    /// let refused = config.build_with_backends(BTreeMap::new(), BTreeMap::new()).err().unwrap();
    /// assert!(refused.problems()[0].starts_with("the store team is a fnox store, and no backend"));
    /// ```
    pub fn build_with_backends(
        self,
        keys: BTreeMap<String, Arc<dyn AgeKeys>>,
        backends: BTreeMap<String, Arc<dyn Backend>>,
    ) -> std::result::Result<RoutingBackend, SecretConfigError> {
        self.assemble(keys, Some(backends))
    }

    /// Build every store, with the host's age keys and, when given, its fnox backends.
    fn assemble(
        self,
        mut keys: BTreeMap<String, Arc<dyn AgeKeys>>,
        mut supplied: Option<BTreeMap<String, Arc<dyn Backend>>>,
    ) -> std::result::Result<RoutingBackend, SecretConfigError> {
        let mut problems = Vec::new();
        let mut backends = Vec::new();
        for store in &self.stores {
            match &store.kind {
                StoreKind::AgeFile { dir, identity, .. } => match keys.remove(&store.name) {
                    Some(key) => backends.push(Arc::new(AgeFileBackend::new(dir, key)) as _),
                    None => problems.push(format!("{}.", no_keys(&store.name, identity))),
                },
                StoreKind::Fnox { .. } => match supplied.as_mut() {
                    None => backends
                        .push(Arc::new(FileBackend::refusing(no_connector(&store.name)))
                            as Arc<dyn Backend>),
                    Some(supplied) => match supplied.remove(&store.name) {
                        Some(backend) => backends.push(backend),
                        None => problems.push(format!(
                            "the store {} is a fnox store, and no backend was supplied for it; \
                             the host builds it with ikigai_secret_fnox::backends.",
                            store.name
                        )),
                    },
                },
                kind => backends.push(build_kind(kind)),
            }
        }
        for extra in supplied.iter().flat_map(|supplied| supplied.keys()) {
            problems.push(match self.store(extra) {
                Some(store) => format!(
                    "a backend was supplied for the store {extra}, which is a {} store that \
                     ikigai-secret builds itself.",
                    store.kind.name()
                ),
                None => {
                    format!("a backend was supplied for {extra}, which is not a configured store.")
                }
            });
        }
        for extra in keys.keys() {
            problems.push(match self.store(extra) {
                Some(store) => format!(
                    "age keys were given for the store {extra}, which is a {} store and seals \
                     nothing.",
                    store.kind.name()
                ),
                None => {
                    format!("age keys were given for {extra}, which is not a configured store.")
                }
            });
        }
        if problems.is_empty() {
            Ok(RoutingBackend {
                config: self,
                backends,
            })
        } else {
            Err(SecretConfigError::new(problems))
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
    let settings: [(&str, bool); 10] = [
        ("write", table.write.is_some()),
        ("service", table.service.is_some()),
        ("label_prefix", table.label_prefix.is_some()),
        ("path", table.path.is_some()),
        ("identity", table.identity.is_some()),
        ("recipients", table.recipients.is_some()),
        ("config", table.config.is_some()),
        ("profile", table.profile.is_some()),
        ("names", table.names.is_some()),
        ("map", table.map.is_some()),
    ];
    let reads: &[&str] = match table.kind.as_str() {
        "keychain" => &["write", "service"],
        "secure-enclave" => &["write", "label_prefix"],
        "file" => &["write", "path"],
        "age-file" => &["write", "path", "identity", "recipients"],
        "fnox" => &["write", "config", "profile", "names", "map"],
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
                "`{setting}` in {line} is not a setting of {} {} store, which reads {}.",
                if table.kind.starts_with('a') {
                    "an"
                } else {
                    "a"
                },
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
        "age-file" => {
            let identity = non_empty("identity", &table.identity, problems);
            if table.identity.is_none() {
                problems.push(format!(
                    "{line} is an age-file store with no `identity`: name where the host gets the \
                     age identity that opens its secrets, as `identity = \"file:/etc/ikigai/age\"`."
                ));
            }
            let recipients = table.recipients.clone().unwrap_or_default();
            for (index, recipient) in recipients.iter().enumerate() {
                if let Err(why) = recipient_kind(recipient) {
                    problems.push(format!(
                        "entry {} of `recipients` in {line} {why}.",
                        index + 1
                    ));
                }
            }
            let dir = match table.path.as_deref() {
                Some(path) => store_dir("path", path, &line, home, problems),
                None => {
                    let dir = data_home_secrets(home);
                    if dir.is_none() {
                        problems.push(format!(
                            "{line} has no `path`, so its directory would be the data home's \
                             `secrets`, and the host has no home directory to read it under; give \
                             an absolute path."
                        ));
                    }
                    dir
                }
            };
            match (dir, identity) {
                (Some(dir), Some(identity)) => StoreKind::AgeFile {
                    dir,
                    identity,
                    recipients,
                },
                _ => return None,
            }
        }
        "fnox" => check_fnox(name, table, &line, home, problems)?,
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
                Some(path) => store_dir("path", path, &line, home, problems),
            },
        },
    };
    (problems.len() == before).then_some(kind)
}

/// Check a `fnox` store's own settings, pushing a problem per refusal. The settings of other
/// kinds were refused by the caller.
fn check_fnox(
    name: &str,
    table: &StoreTable,
    line: &str,
    home: Option<&Path>,
    problems: &mut Vec<String>,
) -> Option<StoreKind> {
    let before = problems.len();
    if table.write == Some(true) {
        problems.push(format!(
            "`write = true` in {line} asks a fnox store to take writes, which this release does \
             not build: a fnox store is read-only, so leave `write` out or set it to false."
        ));
    }
    let config = match table.config.as_deref() {
        None => {
            problems.push(format!(
                "{line} is a fnox store with no `config`: name the one fnox configuration file \
                 it reads, as `config = \"~/work/acme/fnox.toml\"`; a fnox store never searches \
                 for one."
            ));
            None
        }
        Some("") => {
            problems.push(format!(
                "`config = \"\"` in {line} is empty; give it a value or leave it out."
            ));
            None
        }
        Some(path) => store_dir("config", path, line, home, problems),
    };
    let profile = match table.profile.as_deref() {
        Some("") => {
            problems.push(format!(
                "`profile = \"\"` in {line} is empty; give it a value or leave it out."
            ));
            None
        }
        profile => profile.map(str::to_string),
    };
    let names = match (table.names.as_deref(), &table.map) {
        (None | Some("map"), None) => {
            problems.push(format!(
                "{line} maps secret names with a table (`names = \"map\"`, the default) and has \
                 no [secret.store.{name}.map] table, so it could read nothing; add the table, \
                 secret name to fnox key, or set `names = \"escaped\"`."
            ));
            None
        }
        (None | Some("map"), Some(map)) => {
            let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for (secret, key) in map {
                if is_fnox_key(key) {
                    by_key.entry(key).or_default().push(secret);
                } else {
                    problems.push(format!(
                        "`{} = {}` in [secret.store.{name}.map] names {}, which is not a fnox \
                         key: a fnox key is ASCII letters, digits and `_`, beginning with a \
                         letter or `_`.",
                        quoted(secret),
                        quoted(key),
                        quoted(key)
                    ));
                }
            }
            for (key, secrets) in by_key.iter().filter(|(_, secrets)| secrets.len() > 1) {
                let quoted_names: Vec<String> = secrets.iter().map(|s| quoted(s)).collect();
                let as_str: Vec<&str> = quoted_names.iter().map(String::as_str).collect();
                problems.push(format!(
                    "[secret.store.{name}.map] sends {} to the one fnox key {}, so a caller \
                     allowed to read one of them would read the secret meant for the others; give \
                     each name its own key.",
                    words(&as_str),
                    quoted(key)
                ));
            }
            Some(FnoxNames::Map(map.clone()))
        }
        (Some("escaped"), None) => Some(FnoxNames::Escaped),
        (Some("escaped"), Some(_)) => {
            problems.push(format!(
                "[secret.store.{name}.map] is read only with `names = \"map\"`, and {line} sets \
                 `names = \"escaped\"`; remove one of them."
            ));
            None
        }
        (Some(other), _) => {
            problems.push(format!(
                "`names = {}` in {line} is not a name mapping; use \"map\" (an explicit \
                 [secret.store.{name}.map] table, the default) or \"escaped\".",
                quoted(other)
            ));
            None
        }
    };
    if problems.len() != before {
        return None;
    }
    Some(StoreKind::Fnox {
        config: config?,
        profile,
        names: names?,
    })
}

/// A store `path` (or a fnox `config`) as a path: absolute as given, or `~` and `~/…` under the
/// host's `home`. `setting` is the line's key, for the refusal.
fn store_dir(
    setting: &str,
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
                    "`{setting} = {}` in {line} begins with `~`, and the host has no home \
                     directory to read it under; give an absolute path.",
                    quoted(path)
                ));
                None
            }
        },
        None if Path::new(path).is_absolute() => Some(PathBuf::from(path)),
        None => {
            problems.push(format!(
                "`{setting} = {}` in {line} is relative, and a secrets store never depends on the \
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

/// The Conflict a write to `name` in the fnox store `store` meets: the one sentence the routing
/// backend and the connector's own backend both answer.
///
/// ```
/// assert_eq!(
///     ikigai_secret::fnox_read_only("team", "zoom.token"),
///     "the store `team` is read-only: it is a fnox store, read through fnox's library, so \
///      `zoom.token` cannot be written or deleted there"
/// );
/// ```
pub fn fnox_read_only(store: &str, name: &str) -> String {
    format!(
        "the store `{store}` is read-only: it is a fnox store, read through fnox's library, so \
         `{name}` cannot be written or deleted there"
    )
}

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
        if matches!(store.kind, StoreKind::Fnox { .. }) {
            return Err(Error::Conflict(fnox_read_only(&store.name, name)));
        }
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

    /// Refused: a reencrypt names its store (`urn:secret:store:name:{store}:reencrypt`), which
    /// asks that store's backend; the routing backend itself holds no items.
    fn reencrypt(&self, may_write: &dyn Fn(&str) -> bool) -> Result<Reencrypted> {
        let _ = may_write;
        Err(Error::Conflict(
            "reencrypt runs on one store, named in urn:secret:store:name:{store}:reencrypt".into(),
        ))
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

    fn fnox_config(text: &str) -> SecretConfig {
        SecretConfig::from_section_on(
            Some(&section(text)),
            Some(Path::new("/home/svc")),
            Platform::Other,
        )
        .expect("accepted")
    }

    #[test]
    fn a_fnox_store_reads_config_profile_names_and_map() {
        let config = fnox_config(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"~/acme/fnox.toml\"\n\
             profile = \"prod\"\n[store.f.map]\n\"zoom.client-secret\" = \"ZOOM_SECRET\"\n\
             \"a.b\" = \"_A_B\"\n",
        );
        let store = config.store("f").unwrap();
        assert_eq!(
            store.kind(),
            &StoreKind::Fnox {
                config: PathBuf::from("/home/svc/acme/fnox.toml"),
                profile: Some("prod".into()),
                names: FnoxNames::Map(BTreeMap::from([
                    ("a.b".into(), "_A_B".into()),
                    ("zoom.client-secret".into(), "ZOOM_SECRET".into()),
                ])),
            }
        );
        assert!(store.read_only(), "a fnox store is read-only");
        assert!(!store.writable());
        // `write = false` is accepted, and `escaped` needs no table.
        let escaped = fnox_config(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"/f.toml\"\n\
             names = \"escaped\"\nwrite = false\n",
        );
        assert!(matches!(
            escaped.store("f").unwrap().kind(),
            StoreKind::Fnox {
                names: FnoxNames::Escaped,
                profile: None,
                ..
            }
        ));
    }

    #[test]
    fn a_fnox_store_is_refused_a_sentence_per_problem() {
        let problems = refused(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nwrite = true\npath = \"/x\"\n\
             profile = \"\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`path` in [secret.store.f] is not a setting of a fnox store, which reads write, \
                 config, profile, names and map.",
                "`write = true` in [secret.store.f] asks a fnox store to take writes, which this \
                 release does not build: a fnox store is read-only, so leave `write` out or set it \
                 to false.",
                "[secret.store.f] is a fnox store with no `config`: name the one fnox \
                 configuration file it reads, as `config = \"~/work/acme/fnox.toml\"`; a fnox \
                 store never searches for one.",
                "`profile = \"\"` in [secret.store.f] is empty; give it a value or leave it out.",
                "[secret.store.f] maps secret names with a table (`names = \"map\"`, the default) \
                 and has no [secret.store.f.map] table, so it could read nothing; add the table, \
                 secret name to fnox key, or set `names = \"escaped\"`.",
            ]
        );
        let relative = refused(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"fnox.toml\"\n\
             names = \"lossy\"\n",
            Platform::Other,
        );
        assert_eq!(
            relative,
            [
                "`config = \"fnox.toml\"` in [secret.store.f] is relative, and a secrets store \
                 never depends on the working directory; give an absolute path, or one beginning \
                 with `~/`.",
                "`names = \"lossy\"` in [secret.store.f] is not a name mapping; use \"map\" (an \
                 explicit [secret.store.f.map] table, the default) or \"escaped\".",
            ]
        );
        let both = refused(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"/f.toml\"\n\
             names = \"escaped\"\n[store.f.map]\n\"a\" = \"A\"\n",
            Platform::Other,
        );
        assert_eq!(
            both,
            [
                "[secret.store.f.map] is read only with `names = \"map\"`, and [secret.store.f] \
              sets `names = \"escaped\"`; remove one of them."
            ]
        );
    }

    #[test]
    fn a_map_sending_two_names_to_one_key_or_naming_no_fnox_key_is_refused() {
        let problems = refused(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"/f.toml\"\n\
             [store.f.map]\n\"a.b\" = \"A_B\"\n\"a-b\" = \"A_B\"\n\"a_b\" = \"A_B\"\n\
             \"c\" = \"C\"\n\"d\" = \"1D\"\n\"e\" = \"E.F\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`\"d\" = \"1D\"` in [secret.store.f.map] names \"1D\", which is not a fnox key: \
                 a fnox key is ASCII letters, digits and `_`, beginning with a letter or `_`.",
                "`\"e\" = \"E.F\"` in [secret.store.f.map] names \"E.F\", which is not a fnox \
                 key: a fnox key is ASCII letters, digits and `_`, beginning with a letter or `_`.",
                "[secret.store.f.map] sends \"a-b\", \"a.b\" and \"a_b\" to the one fnox key \
                 \"A_B\", so a caller allowed to read one of them would read the secret meant for \
                 the others; give each name its own key.",
            ]
        );
    }

    /// Read an `escaped` key back to its name: the inverse the injectivity argument rests on.
    fn unescape(key: &str) -> Option<String> {
        let mut bytes = Vec::new();
        let mut rest = key.as_bytes();
        while let Some((&first, tail)) = rest.split_first() {
            if first == b'_' {
                let hex = std::str::from_utf8(tail.get(..2)?).ok()?;
                if hex.chars().any(|c| c.is_ascii_lowercase()) {
                    return None;
                }
                bytes.push(u8::from_str_radix(hex, 16).ok()?);
                rest = &tail[2..];
            } else {
                bytes.push(first);
                rest = tail;
            }
        }
        String::from_utf8(bytes).ok()
    }

    #[test]
    fn escaped_names_never_meet_and_are_always_fnox_keys() {
        let names = [
            "a.b",
            "a-b",
            "a_b",
            "a:b",
            "a b",
            "A.B",
            "ab",
            "a_2Eb",
            "a_2eb",
            "_2E",
            ".",
            "_",
            "1",
            "1password",
            "a1",
            "x9.y",
            "owner:id:acme:name:db",
            "owner_3Aid",
            "zoom.secret",
            "zoom_secret",
            "zoom-secret",
            "ZOOM.SECRET",
            "é",
            "e\u{301}",
            "日本",
            "a\u{0}b",
        ];
        let mut seen = std::collections::BTreeMap::new();
        for name in names {
            let key = fnox_escape(name);
            assert!(is_fnox_key(&key), "{name:?} became {key:?}, not a fnox key");
            assert_eq!(unescape(&key).as_deref(), Some(name), "{key:?} reads back");
            if let Some(other) = seen.insert(key.clone(), name) {
                panic!("{name:?} and {other:?} both reach {key:?}");
            }
        }
        // Every key reads back to exactly the one name it came from, so two names never meet.
        assert_eq!(seen.len(), names.len());
        assert_eq!(FnoxNames::Escaped.key_for(""), None);
        assert_eq!(FnoxNames::Escaped.name(), "escaped");
    }

    #[test]
    fn a_fnox_store_refuses_every_write_and_reads_nothing_without_its_connector() {
        let config = fnox_config(
            "default = \"f\"\n[store.f]\nkind = \"fnox\"\nconfig = \"/f.toml\"\n\
             names = \"escaped\"\n",
        );
        let routing = config.clone().build();
        for result in [
            routing.set("zoom.token", b"x"),
            routing.delete("zoom.token"),
            routing.replace("zoom.token", b"x"),
            routing.accepts_writes("zoom.token"),
        ] {
            assert_eq!(
                result.unwrap_err(),
                Error::Conflict(fnox_read_only("f", "zoom.token"))
            );
        }
        let read = routing.get("zoom.token").unwrap_err().to_string();
        assert!(read.contains("ikigai-secret-fnox connector"), "{read}");
        // build_with_backends wants a backend for the fnox store, and none for a store built here.
        let missing = config
            .clone()
            .build_with_backends(BTreeMap::new(), BTreeMap::new())
            .err()
            .unwrap();
        assert_eq!(
            missing.problems(),
            [
                "the store f is a fnox store, and no backend was supplied for it; the host builds \
              it with ikigai_secret_fnox::backends."
            ]
        );
        let stray: Arc<dyn Backend> = Arc::new(FileBackend::refusing("unused".into()));
        let extra = config
            .build_with_backends(
                BTreeMap::new(),
                BTreeMap::from([
                    ("f".to_string(), Arc::clone(&stray)),
                    ("g".to_string(), stray),
                ]),
            )
            .err()
            .unwrap();
        assert_eq!(
            extra.problems(),
            ["a backend was supplied for g, which is not a configured store."]
        );
    }

    #[test]
    fn an_age_file_store_reads_path_identity_and_recipients() {
        let recipient = ikigai_encrypt::age::Identity::generate()
            .to_public()
            .to_string();
        let text = format!(
            "default = \"a\"\n[store.a]\nkind = \"age-file\"\npath = \"~/s\"\n\
             identity = \"file:/etc/ikigai/age\"\nrecipients = [\"{recipient}\", \
             \"age1yubikey1qwerty\"]\nwrite = false\n"
        );
        let config = SecretConfig::from_section_on(
            Some(&section(&text)),
            Some(Path::new("/home/svc")),
            Platform::Other,
        )
        .unwrap();
        let store = config.store("a").unwrap();
        assert_eq!(
            store.kind(),
            &StoreKind::AgeFile {
                dir: PathBuf::from("/home/svc/s"),
                identity: "file:/etc/ikigai/age".into(),
                recipients: vec![recipient, "age1yubikey1qwerty".into()],
            }
        );
        assert!(store.read_only());
        // No `path`: the data home's `secrets` directory under the host's home.
        let bare = SecretConfig::from_section_on(
            Some(&section(
                "default = \"a\"\n[store.a]\nkind = \"age-file\"\nidentity = \"x\"\n",
            )),
            Some(Path::new("/home/svc")),
            Platform::Other,
        )
        .unwrap();
        assert!(matches!(
            bare.store("a").unwrap().kind(),
            StoreKind::AgeFile { dir, .. } if dir == Path::new("/home/svc/.ikigai/secrets")
        ));
    }

    #[test]
    fn an_age_file_store_without_identity_or_with_a_bad_recipient_is_refused() {
        let problems = refused(
            "default = \"a\"\n[store.a]\nkind = \"age-file\"\npath = \"/s\"\n\
             recipients = [\"ssh-ed25519 AAAA\", \"age1notbech32\"]\nservice = \"x\"\n",
            Platform::Other,
        );
        assert_eq!(
            problems,
            [
                "`service` in [secret.store.a] is not a setting of an age-file store, which reads \
                 write, path, identity and recipients.",
                "[secret.store.a] is an age-file store with no `identity`: name where the host \
                 gets the age identity that opens its secrets, as \
                 `identity = \"file:/etc/ikigai/age\"`.",
                "entry 1 of `recipients` in [secret.store.a] is not an age recipient: a recipient \
                 begins with `age1`, as `age-keygen` and the age plugins print them.",
                "entry 2 of `recipients` in [secret.store.a] is not a valid X25519 age recipient \
                 (its checksum or length is wrong).",
            ]
        );
        let homeless = SecretConfig::from_section_on(
            Some(&section(
                "default = \"a\"\n[store.a]\nkind = \"age-file\"\nidentity = \"x\"\n",
            )),
            None,
            Platform::Other,
        )
        .unwrap_err();
        assert_eq!(
            homeless.problems(),
            [
                "[secret.store.a] has no `path`, so its directory would be the data home's \
              `secrets`, and the host has no home directory to read it under; give an absolute \
              path."
            ]
        );
    }

    #[test]
    fn a_host_with_no_section_keeps_an_existing_store_and_gives_a_new_install_age_file() {
        let home = Some(Path::new("/home/svc"));
        for platform in [Platform::Mac, Platform::Other] {
            let existing =
                SecretConfig::for_host_on(None, home, Found::Existing, platform).unwrap();
            assert_eq!(
                existing,
                SecretConfig::from_section_on(None, home, platform).unwrap()
            );
            let notice = existing.notice().unwrap();
            assert!(
                notice.starts_with("ikigai-secret: secrets stay in the "),
                "{notice}"
            );
            assert!(notice.contains("IKIGAI_SECRETS is deprecated"), "{notice}");
            for found in [Found::Nothing, Found::AgeFile] {
                let new = SecretConfig::for_host_on(None, home, found, platform).unwrap();
                assert!(!new.is_configured());
                assert_eq!(new.default_store(), "age-file");
                assert_eq!(
                    new.stores()[0].kind(),
                    &StoreKind::AgeFile {
                        dir: PathBuf::from("/home/svc/.ikigai/secrets"),
                        identity: HOST_DEFAULT_IDENTITY.into(),
                        recipients: Vec::new(),
                    }
                );
                assert!(new.stores()[0].writable());
                assert_eq!(new.notice(), None);
            }
        }
        // A section always wins over what was found.
        let configured =
            SecretConfig::for_host_on(Some(&section(FILE)), home, Found::Nothing, Platform::Other)
                .unwrap();
        assert_eq!(configured.default_store(), "local");
        assert_eq!(configured.notice(), None);
        // A new install with no home to put its store under is refused, with the fix.
        let homeless =
            SecretConfig::for_host_on(None, None, Found::Nothing, Platform::Other).unwrap_err();
        assert!(homeless.problems()[0].contains("set HOME"), "{homeless}");
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
