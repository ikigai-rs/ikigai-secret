//! Secrets for ikigai (`urn:secret:*`): resolve and store secrets through the OS
//! keystore, capability-gated.
//!
//! Slice 1 (here): a named-secret **store** — the macOS **Keychain**
//! (`Security.framework`) on a Mac, a dev **file backend** everywhere else — behind a
//! [`Backend`] trait, plus a capability-gated **read face** `urn:secret:{name}`
//! (`Source`). Secrets are never cached. The write/delete faces and a Touch-ID unlock
//! session (`urn:secret:unlock`, `LAContext`) are a later slice; the [`Backend`] trait
//! already exposes get/set/delete for a host (e.g. a relying party's credential store).
//!
//! Scopes: `urn:cap:secret:read:<name>` (default-deny). A holder can only read a secret
//! its capability names.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    Description, Endpoint, EndpointSpace, Error, Invocation, ReprType, Representation, Result,
    UriTemplate, Verb,
};

/// A secret store: get / set / delete a named secret's bytes. Implemented by the OS
/// keystore (macOS Keychain) or a dev file store; a host uses it directly (a relying
/// party's credential store) or through the `urn:secret:*` resource face.
pub trait Backend: Send + Sync {
    /// The secret's bytes, or `None` if absent.
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Store (or replace) the secret's bytes.
    fn set(&self, name: &str, value: &[u8]) -> Result<()>;
    /// Remove the secret; `Ok` even if it was absent.
    fn delete(&self, name: &str) -> Result<()>;
}

/// The default backend for this platform: the macOS Keychain, else a dev file store
/// (which is **not** hardware-backed — a Mac deployment gets the Keychain).
pub fn default_backend() -> Arc<dyn Backend> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(KeychainBackend::new("ikigai-secret"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(FileBackend::in_config_dir())
    }
}

/// The `urn:secret:*` space over `backend`. Mount it in a host kernel.
pub fn space(backend: Arc<dyn Backend>) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse("urn:secret:{name}").expect("valid template"),
        SecretEndpoint { backend },
    )
}

/// [`space`] over [`default_backend`].
pub fn default_space() -> EndpointSpace {
    space(default_backend())
}

/// `urn:secret:{name}` — read a secret, capability-gated. Write/delete over the wire are
/// a later slice; a host writes through the [`Backend`] directly for now.
struct SecretEndpoint {
    backend: Arc<dyn Backend>,
}

#[async_trait]
impl Endpoint for SecretEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let name = inv
            .bindings
            .get("name")
            .map(|s| s.to_string())
            .ok_or_else(|| Error::MissingArgument("name".into()))?;
        match inv.request.verb {
            Verb::Source => {
                let scope = format!("urn:cap:secret:read:{name}");
                if !inv.capability.allows(&scope) {
                    return Err(Error::Denied(format!(
                        "reading `{name}` requires `{scope}`"
                    )));
                }
                let bytes = self
                    .backend
                    .get(&name)?
                    .ok_or_else(|| Error::Endpoint(format!("no secret `{name}`")))?;
                // Never cacheable — a secret must not linger in a shared cache.
                Ok(Representation::new(
                    ReprType::new("application/octet-stream"),
                    bytes,
                ))
            }
            other => Err(Error::Endpoint(format!(
                "urn:secret does not support {other:?} yet"
            ))),
        }
    }

    fn name(&self) -> &str {
        "secret"
    }

    fn describe(&self) -> Description {
        Description::new("urn:secret")
            .summary(
                "Read a secret from the OS keystore (macOS Keychain), capability-gated by \
                 `urn:cap:secret:read:<name>`. Never cached.",
            )
            .verb(Verb::Source)
    }
}

/// A dev file backend: one file per secret under a directory (default `~/.ikigai/secrets`,
/// override with `IKIGAI_SECRETS`). Not hardware-backed — for non-macOS / development.
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    /// A backend rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileBackend { dir: dir.into() }
    }

    /// A backend at `$IKIGAI_SECRETS`, then `~/.ikigai/secrets`.
    pub fn in_config_dir() -> Self {
        let dir = std::env::var_os("IKIGAI_SECRETS")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ikigai").join("secrets"))
            })
            .unwrap_or_else(|| PathBuf::from(".ikigai-secrets"));
        FileBackend { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(safe)
    }
}

impl Backend for FileBackend {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Endpoint(format!("secret read: {e}"))),
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| Error::Endpoint(format!("secret dir: {e}")))?;
        std::fs::write(self.path(name), value)
            .map_err(|e| Error::Endpoint(format!("secret write: {e}")))
    }

    fn delete(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.path(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Endpoint(format!("secret delete: {e}"))),
        }
    }
}

/// The macOS Keychain backend — a generic-password item per secret, under one service.
#[cfg(target_os = "macos")]
pub struct KeychainBackend {
    service: String,
}

#[cfg(target_os = "macos")]
impl KeychainBackend {
    /// A backend storing items under the Keychain `service`.
    pub fn new(service: &str) -> Self {
        KeychainBackend {
            service: service.to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Backend for KeychainBackend {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        use security_framework::passwords::get_generic_password;
        match get_generic_password(&self.service, name) {
            Ok(bytes) => Ok(Some(bytes)),
            // errSecItemNotFound — the secret simply isn't there.
            Err(e) if e.code() == -25300 => Ok(None),
            Err(e) => Err(Error::Endpoint(format!("keychain read: {e}"))),
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        use security_framework::passwords::set_generic_password;
        set_generic_password(&self.service, name, value)
            .map_err(|e| Error::Endpoint(format!("keychain write: {e}")))
    }

    fn delete(&self, name: &str) -> Result<()> {
        use security_framework::passwords::delete_generic_password;
        match delete_generic_password(&self.service, name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()),
            Err(e) => Err(Error::Endpoint(format!("keychain delete: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Capability, Request, Verb};
    use ikigai_resolve::Resolver;

    #[test]
    fn a_secret_round_trips_through_the_file_backend() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::new(dir.path());
        assert!(backend.get("k").unwrap().is_none(), "absent before set");
        backend.set("k", b"hunter2").unwrap();
        assert_eq!(backend.get("k").unwrap().as_deref(), Some(&b"hunter2"[..]));
        backend.delete("k").unwrap();
        assert!(backend.get("k").unwrap().is_none(), "gone after delete");
        backend.delete("k").unwrap(); // delete of an absent secret is Ok
    }

    #[test]
    fn the_read_face_is_capability_gated() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        backend.set("api-key", b"sk-123").unwrap();
        let kernel = ikigai_core::Kernel::new(Arc::new(space(backend)));

        let req = || {
            Request::new(
                Verb::Source,
                ikigai_core::Iri::parse("urn:secret:api-key").unwrap(),
            )
        };
        // Without the read scope: denied.
        assert!(
            Resolver::issue_as(
                &kernel,
                req(),
                &Capability::scoped(["urn:cap:secret:read:other"])
            )
            .is_err(),
            "a cap for another secret can't read this one"
        );
        // With the scope: the bytes come back.
        let (repr, _) = Resolver::issue_as(
            &kernel,
            req(),
            &Capability::scoped(["urn:cap:secret:read:api-key"]),
        )
        .expect("granted read resolves");
        assert_eq!(repr.bytes, b"sk-123");
    }
}
