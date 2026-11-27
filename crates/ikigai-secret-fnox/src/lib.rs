//! A read-only fnox store for `ikigai-secret` (ledger #4489, `docs/storage-backends.md` section
//! 6.1): a [`Backend`] that reads each secret through fnox's library, from ONE fnox
//! configuration file.
//!
//! This is a **host-role connector**. fnox reads its configuration file and what it imports,
//! reads environment variables and runs provider commands (`op`, `aws`, `bw`), so it may only be
//! reached from a host, never from a module crate. `ikigai-secret` itself checks the `[secret]`
//! section's `kind = "fnox"` stores and never depends on this crate; a host builds them here and
//! hands them over:
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use ikigai_secret::{SecretConfig, SecretSection};
//!
//! # fn start(section: &SecretSection) -> Result<(), ikigai_secret::SecretConfigError> {
//! let config = SecretConfig::from_section(Some(section), Some("/home/svc".as_ref()))?;
//! let fnox = ikigai_secret_fnox::backends(&config)?; // opens each fnox file, or refuses
//! let routing = config.build_with_backends(BTreeMap::new(), fnox)?; // + age keys, if any
//! let space = ikigai_secret::routed_space(std::sync::Arc::new(routing));
//! # let _ = space; Ok(()) }
//! ```
//!
//! What the store does:
//!
//! - **One file, never the search.** [`Fnox::open`] loads exactly the store's `config` (and its
//!   imports), never `Fnox::discover`'s walk from the root to the working directory. The profile
//!   is always set from the section (fnox's default profile when it names none), so
//!   `FNOX_PROFILE` in the host's environment never chooses it.
//! - **One-to-one names.** A secret name becomes a fnox key through the store's [`FnoxNames`]
//!   (an explicit map, or the injective `escaped` transform), checked by `ikigai-secret`. A name
//!   with no key, a key fnox does not declare (`SecretNotFound`), a declared key that resolves to
//!   nothing (`Ok(None)`) and a provider's "no such item" are all NotFound (`get` answers `None`).
//! - **Never interactive.** [`FnoxStore::open`] and every read set fnox's process-wide
//!   non-interactive switch, [`fnox_core::env::set_non_interactive`]. That one switch is what
//!   turns prompting off through the library: it stops the sign-in prompt (`prompt_auth`, which
//!   fnox also skips without a terminal), the passphrase prompt of a protected age identity, and
//!   every provider that needs a person at the machine (Touch ID on the keychain provider, a
//!   FIDO2 touch), which then refuse instead of waiting. `prompt_auth = false` in the fnox file is
//!   NOT enough on its own: `FNOX_PROMPT_AUTH=true` in the environment overrides it, and it does
//!   not reach the age passphrase prompt. A signed-out provider is refused with a sentence that
//!   names the store, the provider and how to sign in at the machine.
//! - **Errors never carry fnox's text.** fnox's messages can quote its configuration file, a
//!   provider's output or a value, so every refusal is written here from the error's KIND: the
//!   store, the secret name, the provider's name and type, and what to do.
//! - **Read-only.** Every write (`set`, `replace`, `create`, `delete`, a generate) is Conflict,
//!   with [`fnox_read_only`]'s sentence; the routing backend refuses first, after every capability
//!   check.
//! - **Never cached here.** Each read asks fnox. fnox's own daemon is not used: the library reads
//!   the providers directly.
//!
//! ⚠ **What fnox still reads from the host's environment**, which this store cannot stop and a
//! host operator should know: a declared key with neither a provider value nor a default falls
//! back to the environment variable OF THE SAME NAME; `FNOX_AGE_KEY` and `FNOX_AGE_IDENTITY`
//! choose the age identity ahead of the file's `key_file`; `FNOX_IF_MISSING` and
//! `FNOX_IF_MISSING_DEFAULT` decide what a missing value does; `FNOX_CONFIG_DIR` and the XDG
//! variables place fnox's default age identity. A host that mounts a fnox store runs with an
//! environment it controls.

use std::collections::BTreeMap;
use std::sync::Arc;

use fnox_core::error::FnoxError;
use fnox_core::library::Fnox;
use ikigai_core::{Error, Result};
use ikigai_secret::{
    fnox_read_only, Backend, FnoxNames, RoutingBackend, SecretConfig, SecretConfigError, StoreKind,
    StoreSpec,
};

pub use ikigai_secret::{fnox_escape, is_fnox_key};

/// Open every `fnox` store `config` names: the backends a host passes to
/// [`SecretConfig::build_with_backends`], by store name. Refused whole, one sentence per store
/// that cannot be opened (its file is missing or not fnox's, or its profile is not a profile
/// name), so a host refuses to start rather than run with half its stores.
pub fn backends(
    config: &SecretConfig,
) -> std::result::Result<BTreeMap<String, Arc<dyn Backend>>, SecretConfigError> {
    let mut problems = Vec::new();
    let mut opened = BTreeMap::new();
    for spec in config.stores() {
        if !matches!(spec.kind(), StoreKind::Fnox { .. }) {
            continue;
        }
        match FnoxStore::open(spec) {
            Ok(store) => {
                opened.insert(spec.name().to_string(), Arc::new(store) as Arc<dyn Backend>);
            }
            Err(problem) => problems.push(problem),
        }
    }
    if problems.is_empty() {
        Ok(opened)
    } else {
        Err(SecretConfigError::new(problems))
    }
}

/// [`backends`], then [`SecretConfig::build_with_backends`] with the host's age keys: the
/// routing backend over every configured store, fnox stores included.
pub fn routing(
    config: SecretConfig,
    age_keys: BTreeMap<String, Arc<dyn ikigai_secret::AgeKeys>>,
) -> std::result::Result<RoutingBackend, SecretConfigError> {
    let fnox = backends(&config)?;
    config.build_with_backends(age_keys, fnox)
}

/// One `fnox` store: its name, the fnox file it opened at start, its profile and its mapping.
pub struct FnoxStore {
    store: String,
    fnox: Fnox,
    profiles: Vec<String>,
    names: FnoxNames,
}

impl std::fmt::Debug for FnoxStore {
    /// The store's name and mapping only: never the configuration's contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnoxStore")
            .field("store", &self.store)
            .field("profiles", &self.profiles)
            .field("names", &self.names.name())
            .finish_non_exhaustive()
    }
}

impl FnoxStore {
    /// Open the fnox store `spec` describes: turn fnox's prompting off, load its one file, set
    /// its profile, and list the profile's keys once so a profile the file does not declare is
    /// refused at start. `Err` is one sentence naming the store and its `config` line, never
    /// fnox's own message (which can quote the file).
    pub fn open(spec: &StoreSpec) -> std::result::Result<Self, String> {
        let StoreKind::Fnox {
            config,
            profile,
            names,
        } = spec.kind()
        else {
            return Err(format!(
                "the store {} is a {} store, not a fnox store, so ikigai-secret-fnox does not \
                 open it.",
                spec.name(),
                spec.kind().name()
            ));
        };
        let store = spec.name().to_string();
        let line = format!(
            "`config = {:?}` in [secret.store.{store}]",
            config.display().to_string()
        );
        if let Some(profile) = profile {
            if !fnox_core::env::is_valid_profile_name(profile) {
                return Err(format!(
                    "`profile = {profile:?}` in [secret.store.{store}] is not a fnox profile name: \
                     a profile name has no path separators, commas or control characters."
                ));
            }
        }
        fnox_core::env::set_non_interactive(true);
        let fnox = Fnox::open(config).map_err(|e| open_refusal(&store, &line, &e))?;
        // Always set the profile, so FNOX_PROFILE in the environment never picks it.
        let profiles: Vec<String> = profile.iter().cloned().collect();
        let fnox = fnox.with_profiles(profiles.clone()).with_no_defaults(false);
        let profiles = fnox_core::config::Config::normalize_profiles(&profiles);
        fnox.list().map_err(|e| open_refusal(&store, &line, &e))?;
        Ok(FnoxStore {
            store,
            fnox,
            profiles,
            names: names.clone(),
        })
    }

    /// The store's name.
    pub fn store(&self) -> &str {
        &self.store
    }

    /// The fnox key `name` reads, if any.
    pub fn key_for(&self, name: &str) -> Option<String> {
        self.names.key_for(name)
    }

    /// The provider that answers `key` in this store's profile, as (its name in the fnox file,
    /// its type), when the file says.
    fn provider_of(&self, key: &str) -> Option<(String, String)> {
        let config = self.fnox.config();
        let secrets = config.get_secrets(&self.profiles).ok()?;
        let secret = secrets.get(key)?;
        let name = match secret.provider() {
            Some(name) => name.to_string(),
            None => config.get_default_provider(&self.profiles).ok()??,
        };
        let kind = config
            .get_providers(&self.profiles)
            .ok()?
            .get(&name)?
            .provider_type()
            .to_string();
        Some((name, kind))
    }

    /// Ask fnox for `key`, on a thread of its own with its own runtime: `Backend` is synchronous,
    /// fnox's `get` is async, and a host calls the backend from inside its own runtime, where
    /// blocking on another future would panic.
    fn ask(&self, key: &str) -> std::result::Result<fnox_core::Result<Option<String>>, String> {
        fnox_core::env::set_non_interactive(true);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map(|runtime| runtime.block_on(self.fnox.get(key)))
                        .map_err(|e| format!("could not start a runtime to ask fnox: {e}"))
                })
                .join()
                .unwrap_or_else(|_| Err("fnox panicked while reading it".to_string()))
        })
    }

    /// The refusal for a failed read of `name` (fnox key `key`), from the error's kind alone.
    fn refusal(&self, name: &str, key: &str, error: &FnoxError) -> Error {
        let store = &self.store;
        let provider = match self.provider_of(key) {
            Some((provider, kind)) => Provider {
                name: provider,
                kind,
            },
            None => Provider {
                name: "(none)".into(),
                kind: "(unknown)".into(),
            },
        };
        let whose = format!(
            "the store `{store}` could not read `{name}`: its fnox provider `{}` ({})",
            provider.name, provider.kind
        );
        let look = "run `fnox check` against this store's fnox file at the machine to see \
                    fnox's own message, which is not passed on because it can carry a secret";
        Error::Endpoint(match error {
            FnoxError::ProviderAuthFailed { .. } => format!(
                "{whose} needs a sign-in, and a host never prompts for one; {}, then try again",
                sign_in(&provider.kind)
            ),
            FnoxError::AgeNotConfigured
            | FnoxError::AgeIdentityNotFound { .. }
            | FnoxError::AgeIdentityReadFailed { .. }
            | FnoxError::AgeIdentityParseFailed { .. } => format!(
                "{whose} has no age identity it can use on this machine; {}, then try again",
                sign_in("age")
            ),
            FnoxError::AgeDecryptionFailed { .. } => format!(
                "{whose} could not decrypt the value with its age identity, which is not one of \
                 the recipients the value was encrypted to; {look}"
            ),
            FnoxError::NotInBuild { .. } => match feature_of(&provider.kind) {
                Some(feature) => format!(
                    "{whose} is not built into this host; rebuild the host with \
                     ikigai-secret-fnox's `{feature}` feature"
                ),
                None => format!("{whose} is not built into this host"),
            },
            FnoxError::ProviderCliNotFound { .. } => format!(
                "{whose} runs a command that is not installed on this machine, or not on the \
                 host's PATH; install it for the user the host runs as, then try again"
            ),
            FnoxError::Config(_)
            | FnoxError::ConfigValidationFailed { .. }
            | FnoxError::ProfileNotFound { .. }
            | FnoxError::ProfileInheritanceCycle { .. }
            | FnoxError::ProviderNotConfigured { .. }
            | FnoxError::ProviderNotConfiguredWithSource { .. }
            | FnoxError::DefaultProviderNotFoundWithSource { .. }
            | FnoxError::ProviderConfigCycle { .. }
            | FnoxError::ProviderConfigResolutionFailed { .. } => format!(
                "the store `{store}` could not read `{name}`: fnox refused the store's \
                 configuration for the key `{key}`; {look}"
            ),
            _ => format!("{whose} failed; {look}"),
        })
    }
}

/// A provider as a refusal names it.
struct Provider {
    name: String,
    kind: String,
}

/// How to sign in to a provider of `kind` at the machine, as a clause.
fn sign_in(kind: &str) -> String {
    let how = match kind {
        "1password" => "with `op signin`",
        "bitwarden" => "with `bw login`, then `bw unlock`",
        "aws-sm" | "aws-ps" | "aws-kms" => "with `aws sso login`, or the credentials it uses",
        "azure-sm" | "azure-kms" | "azure-ac" => "with `az login`",
        "gcp-sm" | "gcp-kms" => "with `gcloud auth application-default login`",
        "vault" => "with `vault login`",
        "age" => {
            return "give the age provider an identity file that needs no passphrase, readable \
                    only by the user the host runs as (a passphrase-protected identity needs a \
                    terminal)"
                .to_string()
        }
        _ => "",
    };
    if how.is_empty() {
        "sign in to it at the machine, as the user the host runs as".to_string()
    } else {
        format!("sign in at the machine, as the user the host runs as, {how}")
    }
}

/// This crate's feature that builds a provider of `kind`, for the providers behind one.
fn feature_of(kind: &str) -> Option<&'static str> {
    Some(match kind {
        k if k.starts_with("aws-") => "aws",
        k if k.starts_with("azure-") => "azure",
        k if k.starts_with("gcp-") => "gcp",
        "keeper-sm" => "keeper",
        "kubernetes" => "kubernetes",
        "enpass" => "enpass",
        "fido2" => "fido2",
        _ => return None,
    })
}

/// The refusal of a fnox store that cannot be opened at start, from the error's kind alone.
fn open_refusal(store: &str, line: &str, error: &FnoxError) -> String {
    const CHECK: &str = "run `fnox check` against that file at the machine to see fnox's own \
                         message, which is not passed on because it can quote the file";
    let (why, then) = match error {
        FnoxError::ConfigFileNotFound { .. } | FnoxError::ConfigNotFound { .. } => {
            ("names no file", "name the store's fnox file")
        }
        FnoxError::ConfigReadFailed { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            ("names no file", "name the store's fnox file")
        }
        FnoxError::ConfigReadFailed { .. } => (
            "names a file the host cannot read",
            "check that it is a file the user the host runs as can read",
        ),
        FnoxError::ProfileNotFound { .. } => (
            "names a fnox file that does not declare the store's profile",
            CHECK,
        ),
        FnoxError::ProfileInheritanceCycle { .. } => (
            "names a fnox file whose profiles inherit from each other in a cycle",
            CHECK,
        ),
        _ => (
            "names a file fnox does not accept as its configuration",
            CHECK,
        ),
    };
    format!("{line} {why}, so the fnox store {store} cannot be opened; {then}.")
}

impl Backend for FnoxStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(key) = self.names.key_for(name) else {
            return Ok(None);
        };
        match self.ask(&key) {
            Err(why) => Err(Error::Endpoint(format!(
                "the store `{}` could not read `{name}`: {why}",
                self.store
            ))),
            Ok(Ok(value)) => Ok(value.map(String::into_bytes)),
            Ok(Err(
                FnoxError::SecretNotFound { .. } | FnoxError::ProviderSecretNotFound { .. },
            )) => Ok(None),
            Ok(Err(error)) => Err(self.refusal(name, &key, &error)),
        }
    }

    fn set(&self, name: &str, _value: &[u8]) -> Result<()> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn delete(&self, name: &str) -> Result<()> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn replace(&self, name: &str, _value: &[u8]) -> Result<()> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn create(&self, name: &str, _value: &[u8]) -> Result<bool> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn generate_signing_key(&self, name: &str) -> Result<Option<(String, Vec<u8>)>> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn accepts_writes(&self, name: &str) -> Result<()> {
        Err(Error::Conflict(fnox_read_only(&self.store, name)))
    }

    fn health(&self) -> String {
        "the fnox configuration was opened at start; its providers are asked only when a read \
         reaches them"
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_provider_family_behind_a_feature_names_it() {
        for (kind, feature) in [
            ("aws-sm", "aws"),
            ("aws-ps", "aws"),
            ("aws-kms", "aws"),
            ("azure-sm", "azure"),
            ("gcp-kms", "gcp"),
            ("keeper-sm", "keeper"),
            ("kubernetes", "kubernetes"),
            ("enpass", "enpass"),
            ("fido2", "fido2"),
        ] {
            assert_eq!(feature_of(kind), Some(feature), "{kind}");
        }
        assert_eq!(feature_of("1password"), None);
        assert_eq!(feature_of("age"), None);
    }

    #[test]
    fn sign_in_names_the_command_for_the_common_providers() {
        assert_eq!(
            sign_in("1password"),
            "sign in at the machine, as the user the host runs as, with `op signin`"
        );
        assert_eq!(
            sign_in("doppler"),
            "sign in to it at the machine, as the user the host runs as"
        );
        assert!(sign_in("age").contains("needs no passphrase"));
    }
}
