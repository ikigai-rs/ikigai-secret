//! Secrets for ikigai (`urn:secret:*`): resolve and store secrets through the OS
//! keystore, capability-gated.
//!
//! - A named-secret **store** — the macOS **Keychain** (`Security.framework`) on a Mac,
//!   a dev **file backend** everywhere else — behind a [`Backend`] trait, plus a
//!   capability-gated **read face** `urn:secret:{name}` (`Source`). Secrets are never
//!   cached. The trait exposes get/set/delete for a host (e.g. a relying party's
//!   credential store); write/delete *over the wire* are a later slice.
//! - A **biometric gate**: [`require_biometric`] (macOS Touch ID via `LAContext`, a
//!   no-op elsewhere) and the resource `urn:secret:unlock`, so a host can require
//!   physical presence for a sensitive operation (e.g. enrolling a passkey).
//! - **Key generation**: the reserved operation `urn:secret:generate` (`name=<keyname>`,
//!   `type=ed25519`) mints an Ed25519 keypair, storing the private key as **PKCS8-PEM**
//!   under `<name>` and the public key as **SPKI-PEM** under `<name>.pub`, and returns
//!   the public key. Cap-gated (`urn:cap:secret:generate`) and biometric-gated. The
//!   private key never leaves through this op — it is retrieved separately through the
//!   cap-gated read face (the same PKCS8-PEM `ikigai-sign` reads via `key=urn:secret:<name>`).
//!
//! Scopes (default-deny): `urn:cap:secret:read:<name>`, `urn:cap:secret:unlock`,
//! `urn:cap:secret:generate`.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error, Invocation, ReprType, Representation,
    Result, UriTemplate, Verb,
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

/// Require biometric presence (Touch ID) for a sensitive operation, showing `reason` in
/// the prompt. **macOS only** — a no-op on other platforms (the gate is a Mac-deployment
/// property). Blocks until the user responds. `Err(Denied)` if the check fails.
pub fn require_biometric(reason: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use robius_authentication::{
            AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
        };
        let policy = PolicyBuilder::new()
            .biometrics(Some(BiometricStrength::Strong))
            .build()
            .ok_or_else(|| Error::Endpoint("no biometric policy available".into()))?;
        let text = Text {
            android: AndroidText {
                title: reason,
                subtitle: None,
                description: None,
            },
            apple: reason,
            windows: WindowsText::new_truncated(reason, reason),
        };
        Context::new(())
            .blocking_authenticate(text, &policy)
            .map_err(|e| Error::Denied(format!("biometric check failed: {e:?}")))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Ok(())
    }
}

/// Mint a fresh Ed25519 keypair from the OS CSPRNG, returning `(pkcs8_pem, spki_pem)` —
/// the private key as PKCS8-PEM and the public key as SPKI-PEM. These are the standard
/// encodings `ikigai-sign` parses (and what `openssl genpkey -algorithm ed25519` emits).
fn generate_ed25519() -> Result<(String, String)> {
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::spki::EncodePublicKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let signing = SigningKey::generate(&mut OsRng);
    let pkcs8 = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::Endpoint(format!("PKCS8 encode: {e}")))?;
    let spki = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Endpoint(format!("SPKI encode: {e}")))?;
    Ok((pkcs8.to_string(), spki))
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
        // `urn:secret:unlock` is a reserved operation, not a stored secret: prove
        // biometric presence (Touch ID), capability-gated by `urn:cap:secret:unlock`.
        if name == "unlock" {
            if inv.request.verb != Verb::Source {
                return Err(Error::Endpoint("urn:secret:unlock is a Source".into()));
            }
            if !inv.capability.allows("urn:cap:secret:unlock") {
                return Err(Error::Denied(
                    "unlock requires `urn:cap:secret:unlock`".into(),
                ));
            }
            require_biometric("Unlock ikigai secrets")?;
            return Ok(Representation::new(
                ReprType::new("text/plain"),
                b"unlocked".to_vec(),
            ));
        }
        // `urn:secret:generate` is a reserved operation, not a stored secret: mint a
        // keypair. The URI slot `{name}` is taken by the literal `generate`, so the key
        // name arrives as the by-value argument `name=<keyname>` (`type=ed25519`, the
        // only kind for now). Cap-gate FIRST (default-deny, no side effect without it),
        // then prove biometric presence, then generate and store.
        if name == "generate" {
            if inv.request.verb != Verb::Source {
                return Err(Error::Endpoint("urn:secret:generate is a Source".into()));
            }
            if !inv.capability.allows("urn:cap:secret:generate") {
                return Err(Error::Denied(
                    "generate requires `urn:cap:secret:generate`".into(),
                ));
            }
            let key = inv.inline_str("name")?.to_string();
            let kind = if inv.request.args.contains_key("type") {
                inv.inline_str("type")?
            } else {
                "ed25519"
            };
            if kind != "ed25519" {
                return Err(Error::InvalidArgument {
                    name: "type".into(),
                    detail: format!("unsupported key type `{kind}` (only `ed25519`)"),
                });
            }
            require_biometric(&format!("Generate signing key {key}"))?;
            let (pkcs8_pem, spki_pem) = generate_ed25519()?;
            // Private key → `<name>` (PKCS8-PEM); public key → `<name>.pub` (SPKI-PEM).
            self.backend.set(&key, pkcs8_pem.as_bytes())?;
            self.backend
                .set(&format!("{key}.pub"), spki_pem.as_bytes())?;
            // Output is the PUBLIC key only — for distribution to verifiers. The private
            // key is retrieved separately through the cap-gated read face. Not cacheable
            // (mutating + fresh randomness): the default, so nothing to opt into.
            return Ok(Representation::new(
                ReprType::new("application/x-pem-file"),
                spki_pem.into_bytes(),
            ));
        }
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
                 `urn:cap:secret:read:<name>`. Reserved ops (Source): `urn:secret:unlock` \
                 (biometric presence, `urn:cap:secret:unlock`) and `urn:secret:generate` \
                 (mint an Ed25519 keypair — `name=<keyname>` `type=ed25519`; \
                 `urn:cap:secret:generate` + biometric; stores private PKCS8-PEM under \
                 `<name>` and public SPKI-PEM under `<name>.pub`, returns the public key). \
                 Never cached.",
            )
            .verb(Verb::Source)
            .input(
                ArgSpec::new("name")
                    .summary("secret name to read, or the key name to mint for `generate`")
                    .binding(),
            )
            .input(
                ArgSpec::new("type")
                    .summary("`generate` key type (only `ed25519`)")
                    .optional(),
            )
            .output("application/octet-stream")
            .output("application/x-pem-file")
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

    #[test]
    fn unlock_is_capability_gated_before_the_biometric_prompt() {
        // The cap check runs before `require_biometric`, so this is denied without a
        // prompt (a granted unlock would prompt for Touch ID — not testable in CI).
        let dir = tempfile::tempdir().unwrap();
        let kernel =
            ikigai_core::Kernel::new(Arc::new(space(Arc::new(FileBackend::new(dir.path())))));
        let req = Request::new(
            Verb::Source,
            ikigai_core::Iri::parse("urn:secret:unlock").unwrap(),
        );
        assert!(
            Resolver::issue_as(&kernel, req, &Capability::scoped(Vec::<String>::new())).is_err(),
            "unlock without `urn:cap:secret:unlock` is denied"
        );
    }

    fn generate_req(key: &str) -> Request {
        Request::new(
            Verb::Source,
            ikigai_core::Iri::parse("urn:secret:generate").unwrap(),
        )
        .with_arg("name", ikigai_core::ArgRef::Inline(key.as_bytes().to_vec()))
    }

    // Keygen itself is cross-platform and gate-free — unit-test it directly, so the
    // "the pair matches" guarantee holds headless everywhere. The endpoint's biometric
    // gate is a REAL Touch ID prompt on macOS (only a no-op off it), so the granted
    // endpoint path is exercised on non-macOS below and validated on Brian's Mac by hand.
    #[test]
    fn generate_ed25519_produces_a_matching_encoded_pair() {
        use ed25519_dalek::pkcs8::spki::DecodePublicKey;
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

        let (pkcs8_pem, spki_pem) = generate_ed25519().expect("keygen succeeds");
        // Correct PEM armors, and the public encoding never carries private material.
        assert!(
            pkcs8_pem.contains("BEGIN PRIVATE KEY"),
            "private key is PKCS8-PEM"
        );
        assert!(
            spki_pem.contains("BEGIN PUBLIC KEY"),
            "public key is SPKI-PEM"
        );
        assert!(
            !spki_pem.contains("PRIVATE KEY"),
            "the public encoding must not leak private material"
        );
        // Both parse as Ed25519 keys…
        let signing = SigningKey::from_pkcs8_pem(&pkcs8_pem).expect("valid PKCS8 Ed25519 private");
        let verifying = VerifyingKey::from_public_key_pem(&spki_pem).expect("valid SPKI Ed25519");
        // …and the pair matches: a signature by the private key verifies under the public.
        let msg = b"portable code, signed";
        let sig = signing.sign(msg);
        verifying
            .verify(msg, &sig)
            .expect("private/public keypair matches");
    }

    #[test]
    fn generate_without_the_cap_is_denied_and_stores_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        let kernel = ikigai_core::Kernel::new(Arc::new(space(backend.clone())));

        // No cap → denied. The cap check runs before keygen/biometric, so this is denied
        // WITHOUT any Touch ID prompt (holds on macOS too).
        assert!(
            Resolver::issue_as(
                &kernel,
                generate_req("nope"),
                &Capability::scoped(Vec::<String>::new()),
            )
            .is_err(),
            "generate without `urn:cap:secret:generate` is denied"
        );
        // Nothing was stored — neither the private key nor its `.pub`.
        assert!(
            backend.get("nope").unwrap().is_none(),
            "no private key stored"
        );
        assert!(
            backend.get("nope.pub").unwrap().is_none(),
            "no public key stored"
        );
    }

    #[test]
    fn a_stored_generated_key_round_trips_through_the_read_face() {
        // A generated key, stored exactly as the endpoint stores it, comes back through
        // the cap-gated read face as PKCS8-PEM — precisely what `ikigai-sign` reads via
        // `key=urn:secret:app-signer`. (Storing via the backend keeps this headless; the
        // endpoint's own store happens past the biometric gate, checked on Brian's Mac.)
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        let (pkcs8_pem, spki_pem) = generate_ed25519().expect("keygen succeeds");
        backend.set("app-signer", pkcs8_pem.as_bytes()).unwrap();
        backend.set("app-signer.pub", spki_pem.as_bytes()).unwrap();
        let kernel = ikigai_core::Kernel::new(Arc::new(space(backend.clone())));

        let (repr, _) = Resolver::issue_as(
            &kernel,
            Request::new(
                Verb::Source,
                ikigai_core::Iri::parse("urn:secret:app-signer").unwrap(),
            ),
            &Capability::scoped(["urn:cap:secret:read:app-signer"]),
        )
        .expect("granted read resolves");
        let pkcs8 = std::str::from_utf8(&repr.bytes).unwrap();
        assert_eq!(pkcs8, pkcs8_pem, "read face returns the stored PKCS8-PEM");
        assert!(
            pkcs8.contains("BEGIN PRIVATE KEY"),
            "read face returns the PKCS8-PEM private key"
        );
    }

    // The full granted endpoint path — cap → biometric (no-op off macOS) → store both
    // keys → return the SPKI-PEM public key. macOS-gated OUT because there the biometric
    // gate is a real Touch ID prompt (validated by hand on Brian's Mac); runs in the
    // ubuntu CI job, which mirrors the module's existing cfg split.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn generate_endpoint_stores_the_pair_and_returns_the_public_key() {
        use ed25519_dalek::pkcs8::spki::DecodePublicKey;
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        let kernel = ikigai_core::Kernel::new(Arc::new(space(backend.clone())));

        let (repr, _) = Resolver::issue_as(
            &kernel,
            generate_req("signing-key"),
            &Capability::scoped(["urn:cap:secret:generate"]),
        )
        .expect("granted generate resolves");

        // Output is the SPKI-PEM public key — never the private key.
        let returned_pub = std::str::from_utf8(&repr.bytes).expect("PEM is UTF-8");
        assert!(
            returned_pub.contains("BEGIN PUBLIC KEY") && !returned_pub.contains("PRIVATE KEY"),
            "output is the public key only"
        );
        // Private → `<name>` (PKCS8), public → `<name>.pub` (SPKI); returned == stored .pub.
        let priv_pem =
            String::from_utf8(backend.get("signing-key").unwrap().expect("private stored"))
                .unwrap();
        let pub_pem = String::from_utf8(
            backend
                .get("signing-key.pub")
                .unwrap()
                .expect("public stored"),
        )
        .unwrap();
        assert_eq!(pub_pem, returned_pub, "returned pubkey == stored .pub");
        // The stored pair matches.
        let signing = SigningKey::from_pkcs8_pem(&priv_pem).expect("stored key is valid PKCS8");
        let verifying =
            VerifyingKey::from_public_key_pem(&pub_pem).expect("stored .pub is valid SPKI");
        let msg = b"portable code, signed";
        let sig = signing.sign(msg);
        verifying
            .verify(msg, &sig)
            .expect("stored private/public keypair matches");
    }
}
