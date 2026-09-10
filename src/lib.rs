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
//! - **Key generation**: the reserved operation `urn:secret:generate` (`into=<keyname>`,
//!   `type=ed25519`|`age`) mints a keypair — an **Ed25519** signing key (PKCS8/SPKI PEM,
//!   read by `ikigai-sign`) or an **`age`** X25519 encryption key (identity/recipient, read
//!   by `ikigai-encrypt`) — storing the private half under `<name>` and the public half
//!   under `<name>.pub`, and returning the public half. Cap-gated (`urn:cap:secret:generate`)
//!   and biometric-gated; the private key never leaves through this op (retrieved separately
//!   through the cap-gated read face). One identity, two keys: sign *and* encrypt.
//!
//! A **write face** `urn:secret:{name}` (`Sink`) stores an externally-supplied secret (a Zoom
//! credential, an API token) from the piped `content` — REPLACING any existing item so the new one
//! is owned by this process. A keystore item the `security` CLI created re-prompts a code-signed
//! reader on every access; one this face writes does not, because the ACL is this process's.
//!
//! Scopes (default-deny): `urn:cap:secret:read:<name>`, `urn:cap:secret:write:<name>`,
//! `urn:cap:secret:unlock`, `urn:cap:secret:generate`. Each is DECLARED on its action
//! (the per-name pair as the wildcards `urn:cap:secret:read:*` / `urn:cap:secret:write:*`),
//! so the kernel enforces the floor before an endpoint runs and the manifold offers each
//! operation only to a holder of its scope. The reserved operations are bound as their own
//! endpoints ahead of the `{name}` template (see [`space`]). A refused call never reaches
//! the keystore, so an ungranted caller cannot learn whether a name exists; a secret read
//! is never cacheable. `tests/conformance.rs` holds all of that to `ikigai-conformance`.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, ReprType,
    Representation, Result, UriTemplate, Verb,
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

    /// **Sign-through**: sign `message` with the key named `name` WITHOUT extracting the private
    /// half — for a key that can never leave the store (the Secure Enclave, and later a
    /// TPM/YubiKey via PKCS#11). This is how `get`→bytes gives way to sign-through: an
    /// Enclave-resident key has no bytes to `get`, so the store signs on the caller's behalf.
    ///
    /// Returns `None` when this backend can't sign-through the named key, so the caller falls
    /// back to `get`-the-bytes-and-sign-in-process (the software path). The default is
    /// "not a sign-through signer."
    fn sign(&self, name: &str, message: &[u8]) -> Result<Option<Signed>> {
        let _ = (name, message);
        Ok(None)
    }

    /// Generate a NON-EXTRACTABLE signing key named `name`, returning `(algorithm-id, SPKI
    /// public key)`. The private half never leaves the backend — the whole point. `None` if
    /// this backend cannot hold non-extractable keys (e.g. the file store). Default: unsupported.
    fn generate_signing_key(&self, name: &str) -> Result<Option<(String, Vec<u8>)>> {
        let _ = name;
        Ok(None)
    }
}

/// A completed sign-through signature. Everything a verifier or an `ikigai-sign` signature-graph
/// needs, and nothing the private half would reveal: the algorithm id (as `sig:algorithm`), the
/// raw signature in that algorithm's wire form (ES256 → 64-byte r‖s), and the SPKI public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The algorithm id, matching `ikigai-sign`'s `sig:algorithm` (e.g. `"ES256"`).
    pub algorithm: String,
    /// The signature in the algorithm's wire encoding — for ES256, a 64-byte `r‖s`.
    pub signature: Vec<u8>,
    /// The signer's SPKI (DER) public key, for verification and for publishing (`decide.pub`).
    pub public_key_spki: Vec<u8>,
}

// =====================================================================================
// Wire-form conversions for the Enclave (ES256 / P-256). Pure byte-shuffling, and the
// error-prone part of the Enclave path, so they live here — testable WITHOUT the hardware.
// The Enclave (SecKeyCreateSignature) speaks DER + X9.63; `ikigai-sign`, `decide.pub` and every
// standard verifier want fixed r‖s + SPKI. These bridge the two, so nothing downstream is
// Enclave-shaped.
// =====================================================================================

/// The `sig:algorithm` id a Secure-Enclave signature carries — P-256 / ECDSA-SHA256. Matches
/// `ikigai-sign`'s id, so `Signed` drops straight into its crypto-agile graph.
pub const ALG_ES256: &str = "ES256";

/// The fixed SPKI-DER prefix for an uncompressed NIST P-256 public point: `SEQUENCE {
/// AlgorithmIdentifier { id-ecPublicKey, prime256v1 }, BIT STRING }`. Append the 65-byte X9.63
/// point (`0x04‖x‖y`) and you have a standard SPKI public key.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Wrap a raw uncompressed P-256 public point (X9.63, `0x04‖x‖y`, 65 bytes — what the Enclave's
/// `public_key().external_representation()` returns) into standard SPKI DER.
pub fn p256_point_to_spki(point: &[u8]) -> Result<Vec<u8>> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(Error::Endpoint(format!(
            "expected a 65-byte uncompressed P-256 point (0x04‖x‖y), got {} bytes",
            point.len()
        )));
    }
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + point.len());
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.extend_from_slice(point);
    Ok(spki)
}

/// Read one DER `INTEGER` at `*i` in `der` into a 32-byte big-endian P-256 scalar, advancing
/// `*i`. Strips DER's positive-sign leading zero and left-pads a short scalar.
fn read_der_scalar(der: &[u8], i: &mut usize) -> Result<[u8; 32]> {
    let bad = |m: &str| Error::Endpoint(format!("malformed ECDSA DER signature: {m}"));
    if der.get(*i) != Some(&0x02) {
        return Err(bad("expected INTEGER"));
    }
    *i += 1;
    let len = *der.get(*i).ok_or_else(|| bad("truncated length"))? as usize;
    *i += 1;
    let end = i.checked_add(len).ok_or_else(|| bad("length overflow"))?;
    let bytes = der.get(*i..end).ok_or_else(|| bad("INTEGER overruns"))?;
    *i = end;
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    if b.len() > 32 {
        return Err(bad("scalar too long for P-256"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// Convert a DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`, as the Enclave /
/// `SecKeyCreateSignature` emits) into the fixed 64-byte `r‖s` form ES256 uses on the wire and
/// `ikigai-sign` verifies. P-256, so each scalar is 32 bytes big-endian.
pub fn der_ecdsa_to_fixed_rs(der: &[u8]) -> Result<[u8; 64]> {
    let bad = |m: &str| Error::Endpoint(format!("malformed ECDSA DER signature: {m}"));
    let mut i = 0;
    if der.first() != Some(&0x30) {
        return Err(bad("no SEQUENCE"));
    }
    i += 1;
    // Single-byte length: a P-256 signature is always < 128 bytes, so no long-form length.
    let _seq_len = *der.get(i).ok_or_else(|| bad("truncated"))?;
    i += 1;
    let r = read_der_scalar(der, &mut i)?;
    let s = read_der_scalar(der, &mut i)?;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s);
    Ok(sig)
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
///
/// Three entries, in this order: the reserved operations [`UNLOCK_IRI`] and
/// [`GENERATE_IRI`] bound EXACTLY, then the stored-secret template `urn:secret:{name}`.
/// A space resolves first match, so the exact bindings shadow the template: a secret can
/// never be stored under either reserved name, and each operation is offered in the
/// manifold under its own capability (`urn:cap:secret:unlock`, `urn:cap:secret:generate`)
/// rather than hidden inside the template's.
pub fn space(backend: Arc<dyn Backend>) -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new(UNLOCK_IRI), UnlockEndpoint)
        .bind(
            Exact::new(GENERATE_IRI),
            GenerateEndpoint {
                backend: Arc::clone(&backend),
            },
        )
        .bind(
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

/// Mint a fresh `age` X25519 keypair, returning `(identity, recipient)` — the private
/// identity as `AGE-SECRET-KEY-1…` and the public recipient as `age1…`, the exact strings
/// `ikigai-encrypt`'s `key=`/`to=` resources consume. The encryption dual of the ed25519
/// signing key; one identity, two keys (sign + encrypt), both custodied here.
fn generate_age() -> (String, String) {
    use age::secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let secret = identity.to_string().expose_secret().to_string();
    (secret, recipient)
}

/// The XSD `string` datatype IRI — every input of this module is a scalar name or value.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// `urn:secret:unlock` — the biometric-presence operation, bound EXACTLY ahead of the
/// `{name}` template (see [`space`]).
pub const UNLOCK_IRI: &str = "urn:secret:unlock";

/// `urn:secret:generate` — the key-minting operation, bound EXACTLY ahead of the
/// `{name}` template (see [`space`]).
pub const GENERATE_IRI: &str = "urn:secret:generate";

/// The stored-secret endpoint: `urn:secret:{name}`, `Source` under
/// `urn:cap:secret:read:<name>`, `Sink` under `urn:cap:secret:write:<name>`. The
/// capability is checked BEFORE the keystore is consulted, so an ungranted caller learns
/// nothing — not even whether the name exists — and the backend is never touched.
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
                // The kernel already enforced the declared `urn:cap:secret:read:*` floor
                // (some grant under the prefix); this is the exact-name rule behind it.
                let scope = format!("urn:cap:secret:read:{name}");
                if !inv.capability.allows(&scope) {
                    return Err(Error::Denied(format!(
                        "reading `{name}` requires `{scope}`"
                    )));
                }
                let bytes = self
                    .backend
                    .get(&name)?
                    .ok_or_else(|| Error::NotFound(format!("no secret `{name}`")))?;
                // Never cacheable — a secret must not linger in a shared cache. The
                // default expiry is `Always`; nothing here opts into caching.
                Ok(Representation::new(
                    ReprType::new("application/octet-stream"),
                    bytes,
                ))
            }
            // Store an externally-supplied secret (a Zoom credential, an API token) so it lands
            // in the keystore OWNED BY THIS PROCESS. The value is the piped `content`.
            Verb::Sink => {
                let scope = format!("urn:cap:secret:write:{name}");
                if !inv.capability.allows(&scope) {
                    return Err(Error::Denied(format!(
                        "writing `{name}` requires `{scope}`"
                    )));
                }
                let value = inv.inline_str("content")?.to_string();
                // DELETE then SET, deliberately: a plain update would keep an existing item's
                // access control (e.g. one the `security` CLI created, which re-prompts a
                // code-signed reader). Replacing the item re-homes its ACL to whoever writes it
                // — this process — so the owner's daemon then reads it without a Keychain prompt.
                self.backend.delete(&name)?;
                self.backend.set(&name, value.as_bytes())?;
                // Not cacheable, and the reply carries no secret material.
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    b"stored".to_vec(),
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
        // The id `urn:secret` predates the kebab-case convention and is a live MCP tool
        // name; it is renamed in the coordinated wave-two pass, not here.
        let name = || {
            ArgSpec::new("name")
                .summary("the secret's name (the `{name}` URI slot)")
                .class(XSD_STRING)
                .binding()
        };
        Description::new("urn:secret")
            .summary(
                "Read (Source) or store (Sink) a named secret in the OS keystore (macOS Keychain; \
                 a file store elsewhere), capability-gated PER NAME: `urn:cap:secret:read:<name>` \
                 / `urn:cap:secret:write:<name>`, default-deny, refused before the keystore is \
                 consulted. A Sink stores the piped `content`, REPLACING any existing item so the \
                 new one is owned by this process (a keystore item the `security` CLI created \
                 re-prompts a code-signed reader; one this writes does not). Never cached: every \
                 read hits the keystore. The reserved operations `urn:secret:unlock` and \
                 `urn:secret:generate` are bound ahead of this template as their own endpoints.",
            )
            .input(name())
            .output("application/octet-stream")
            .output("text/plain")
            // Per-verb contracts: the capability is parameterized by name, so each action
            // declares the wildcard form — "holds SOME grant under this prefix" — and the
            // exact name is checked at invoke time.
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("read a secret's bytes")
                    .requires("urn:cap:secret:read:*")
                    .input(name())
                    .output("application/octet-stream"),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("store a secret, replacing any existing item")
                    .requires("urn:cap:secret:write:*")
                    .input(name())
                    .input(
                        ArgSpec::new("content")
                            .summary("the secret value to store (piped in)")
                            .class(XSD_STRING),
                    )
                    .output("text/plain"),
            )
    }
}

/// `urn:secret:unlock` — prove biometric presence (Touch ID), capability-gated by
/// `urn:cap:secret:unlock`. A reserved operation, not a stored secret.
struct UnlockEndpoint;

#[async_trait]
impl Endpoint for UnlockEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint("urn:secret:unlock is a Source".into()));
        }
        if !inv.capability.allows("urn:cap:secret:unlock") {
            return Err(Error::Denied(
                "unlock requires `urn:cap:secret:unlock`".into(),
            ));
        }
        require_biometric("Unlock ikigai secrets")?;
        Ok(Representation::new(
            ReprType::new("text/plain"),
            b"unlocked".to_vec(),
        ))
    }

    fn name(&self) -> &str {
        "secret-unlock"
    }

    fn describe(&self) -> Description {
        Description::new("secret-unlock")
            .summary(
                "Prove biometric presence (macOS Touch ID; a no-op elsewhere) for an operation \
                 that needs a person at the machine. Capability-gated by `urn:cap:secret:unlock`, \
                 checked BEFORE any prompt. Never cached.",
            )
            .verb(Verb::Source)
            .requires("urn:cap:secret:unlock")
            .output("text/plain")
    }
}

/// `urn:secret:generate` — mint a keypair into the keystore, capability-gated by
/// `urn:cap:secret:generate` and then biometric-gated. A reserved operation, not a stored
/// secret: the key name arrives as the by-value argument `into=<keyname>`.
struct GenerateEndpoint {
    backend: Arc<dyn Backend>,
}

#[async_trait]
impl Endpoint for GenerateEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint("urn:secret:generate is a Source".into()));
        }
        // Cap-gate FIRST (default-deny), then prove biometric, then store.
        if !inv.capability.allows("urn:cap:secret:generate") {
            return Err(Error::Denied(
                "generate requires `urn:cap:secret:generate`".into(),
            ));
        }
        let key = inv.inline_str("into")?.to_string();
        let kind = if inv.request.args.contains_key("type") {
            inv.inline_str("type")?
        } else {
            "ed25519"
        };
        // Private key → `<name>`; public key → `<name>.pub`; the endpoint returns the
        // PUBLIC half (private is retrieved separately through the cap-gated read face).
        // Not cacheable (mutating + fresh randomness): the default, nothing to opt into.
        match kind {
            // `ed25519` — the SIGNING keypair (PKCS8/SPKI PEM), read by ikigai-sign.
            "ed25519" => {
                require_biometric(&format!("Generate signing key {key}"))?;
                let (pkcs8_pem, spki_pem) = generate_ed25519()?;
                self.backend.set(&key, pkcs8_pem.as_bytes())?;
                self.backend
                    .set(&format!("{key}.pub"), spki_pem.as_bytes())?;
                Ok(Representation::new(
                    ReprType::new("application/x-pem-file"),
                    spki_pem.into_bytes(),
                ))
            }
            // `age` — the ENCRYPTION keypair (X25519 identity/recipient), read by
            // ikigai-encrypt. The dual of the signing key: one identity, two keys.
            "age" => {
                require_biometric(&format!("Generate encryption key {key}"))?;
                let (identity, recipient) = generate_age();
                self.backend.set(&key, identity.as_bytes())?;
                self.backend
                    .set(&format!("{key}.pub"), recipient.as_bytes())?;
                Ok(Representation::new(
                    ReprType::new("text/plain"),
                    recipient.into_bytes(),
                ))
            }
            other => Err(Error::InvalidArgument {
                name: "type".into(),
                detail: format!("unsupported key type `{other}` (use ed25519 or age)"),
            }),
        }
    }

    fn name(&self) -> &str {
        "secret-generate"
    }

    fn describe(&self) -> Description {
        Description::new("secret-generate")
            .summary(
                "Mint a keypair into the keystore: an Ed25519 signing key (`type=ed25519`, the \
                 default; PKCS8-PEM private, SPKI-PEM public, read by ikigai-sign) or an `age` \
                 X25519 encryption key (`type=age`; identity/recipient, read by ikigai-encrypt). \
                 The private half is stored under `<into>`, the public half under `<into>.pub`, \
                 and only the public half is returned. Capability-gated by \
                 `urn:cap:secret:generate`, then biometric-gated (macOS Touch ID). Never cached.",
            )
            .verb(Verb::Source)
            .requires("urn:cap:secret:generate")
            .input(
                ArgSpec::new("into")
                    .summary(
                        "the key name to mint into (private at `<into>`, public at `<into>.pub`)",
                    )
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("type")
                    .summary("`ed25519` (signing, default) or `age` (encryption)")
                    .class(XSD_STRING)
                    .one_of(["ed25519", "age"])
                    .default_value("ed25519")
                    .optional(),
            )
            .output("application/x-pem-file")
            .output("text/plain")
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

/// The macOS **Secure Enclave** backend — a NON-EXTRACTABLE P-256 signing key per name, born and
/// kept inside the Enclave. There is no `get`: the private half never leaves the hardware, so
/// callers `sign` through it instead. The access control is `PrivateKeyUsage` with an
/// after-first-unlock protection class and NO biometric gate — so the daemon signs unattended,
/// which is the whole point (it retires the Keychain-prompt / "Allow all applications" dance).
///
/// The Enclave is per-device: a key made here can only sign here. The booking daemon's decide
/// key must therefore be generated on the machine that signs (bug), and only its PUBLIC half
/// (SPKI) travels — to `decide.pub` on both the Mac and the edge.
#[cfg(target_os = "macos")]
pub struct SecureEnclaveBackend {
    /// Namespaces the Enclave keys' Keychain labels, so several names don't collide.
    label_prefix: String,
}

#[cfg(target_os = "macos")]
impl SecureEnclaveBackend {
    /// A backend whose keys are labelled `<prefix>.<name>` in the Keychain.
    pub fn new(label_prefix: &str) -> Self {
        SecureEnclaveBackend {
            label_prefix: label_prefix.to_string(),
        }
    }

    fn label(&self, name: &str) -> String {
        format!("{}.{name}", self.label_prefix)
    }

    /// The signer's public key as SPKI DER, via the Enclave's raw X9.63 point.
    fn public_spki(key: &security_framework::key::SecKey) -> Result<Vec<u8>> {
        let public = key
            .public_key()
            .ok_or_else(|| Error::Endpoint("enclave key has no public half".into()))?;
        let point = public
            .external_representation()
            .ok_or_else(|| Error::Endpoint("cannot export the enclave public point".into()))?;
        p256_point_to_spki(point.bytes())
    }

    /// Find the private SecKey for `name`, or `None` if there is no Enclave key by that label.
    fn find_private_key(&self, name: &str) -> Result<Option<security_framework::key::SecKey>> {
        use security_framework::item::{
            ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
        };
        let found = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            // Look in the same (data-protection) keychain the Enclave key was generated into.
            .ignore_legacy_keychains()
            .label(&self.label(name))
            .load_refs(true)
            .search();
        let results = match found {
            Ok(results) => results,
            // errSecItemNotFound — no such key.
            Err(e) if e.code() == -25300 => return Ok(None),
            Err(e) => return Err(Error::Endpoint(format!("enclave key lookup: {e}"))),
        };
        for result in results {
            if let SearchResult::Ref(Reference::Key(key)) = result {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
impl Backend for SecureEnclaveBackend {
    /// Non-extractable: there are no bytes to hand back. Callers `sign` instead.
    fn get(&self, _name: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// An Enclave key is generated in place, never injected.
    fn set(&self, _name: &str, _value: &[u8]) -> Result<()> {
        Err(Error::Endpoint(
            "a Secure-Enclave key cannot be set from bytes — use generate_signing_key".into(),
        ))
    }

    /// Delete the private key by label. (A signing key is normally rotated by regenerating.)
    fn delete(&self, name: &str) -> Result<()> {
        match self.find_private_key(name)? {
            Some(key) => key
                .delete()
                .map_err(|e| Error::Endpoint(format!("enclave key delete: {e}"))),
            None => Ok(()),
        }
    }

    fn sign(&self, name: &str, message: &[u8]) -> Result<Option<Signed>> {
        use security_framework::key::Algorithm;
        let key = match self.find_private_key(name)? {
            Some(key) => key,
            // No Enclave key by this name — let the caller fall back to a software key.
            None => return Ok(None),
        };
        // ECDSASignatureMessageX962SHA256 = ES256: the Enclave hashes with SHA-256 and signs,
        // emitting an X9.62 DER signature — normalised to fixed r‖s below.
        let der = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| Error::Endpoint(format!("enclave sign: {e}")))?;
        let rs = der_ecdsa_to_fixed_rs(&der)?;
        Ok(Some(Signed {
            algorithm: ALG_ES256.to_string(),
            signature: rs.to_vec(),
            public_key_spki: Self::public_spki(&key)?,
        }))
    }

    fn generate_signing_key(&self, name: &str) -> Result<Option<(String, Vec<u8>)>> {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::item::Location;
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
        // PrivateKeyUsage (1<<30 = kSecAccessControlPrivateKeyUsage), after-first-unlock,
        // device-bound, NO biometric — the key signs unattended once the Mac is unlocked.
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            1 << 30,
        )
        .map_err(|e| Error::Endpoint(format!("enclave access control: {e}")))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access)
            // The data-protection keychain makes the key PERMANENT (else it is transient and
            // gone before the next `sign`) and is where Enclave-backed keys must live.
            .set_location(Location::DataProtectionKeychain)
            .set_label(self.label(name));
        let key = SecKey::new(&options)
            .map_err(|e| Error::Endpoint(format!("enclave key generation: {e}")))?;
        Ok(Some((ALG_ES256.to_string(), Self::public_spki(&key)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::{Capability, Request, Verb};
    use ikigai_resolve::Resolver;

    // ---- the Enclave wire-form converters, validated against p256's canonical encodings ----
    // (The Enclave itself only runs on real hardware; these are the fiddly bits that don't.)

    #[test]
    fn a_p256_point_wraps_into_spki_that_parses_back_to_the_same_key() {
        use p256::ecdsa::{SigningKey, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;

        let sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false); // 0x04‖x‖y, the Enclave's export form
        let spki = p256_point_to_spki(point.as_bytes()).unwrap();
        // The wrapped SPKI is a standard public key: p256 parses it back to the same point.
        assert_eq!(&VerifyingKey::from_public_key_der(&spki).unwrap(), vk);
    }

    #[test]
    fn a_der_ecdsa_signature_converts_to_the_canonical_fixed_rs() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let sig: Signature = sk.sign(b"the Enclave signs this one day");
        // Convert the DER form (what SecKeyCreateSignature emits) → our fixed r‖s, and it must
        // match p256's own canonical 64-byte encoding of the same signature.
        let der = sig.to_der();
        let fixed = der_ecdsa_to_fixed_rs(der.as_bytes()).unwrap();
        assert_eq!(&fixed[..], &sig.to_bytes()[..]);
    }

    #[test]
    fn short_scalars_are_left_padded_not_misaligned() {
        // A DER INTEGER shorter than 32 bytes (a small r or s) must land right-aligned in the
        // 32-byte slot — the classic ECDSA-fixed-encoding bug. SEQUENCE{ INT 0x01, INT 0x02 }.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let rs = der_ecdsa_to_fixed_rs(&der).unwrap();
        assert_eq!(rs[31], 1, "r is right-aligned");
        assert_eq!(rs[63], 2, "s is right-aligned");
        assert!(rs[..31].iter().all(|&b| b == 0) && rs[32..63].iter().all(|&b| b == 0));
    }

    #[test]
    fn malformed_inputs_error_rather_than_panic() {
        assert!(p256_point_to_spki(&[0u8; 10]).is_err());
        assert!(p256_point_to_spki(&[0x03; 65]).is_err()); // compressed point, wrong tag
        assert!(der_ecdsa_to_fixed_rs(&[]).is_err());
        assert!(der_ecdsa_to_fixed_rs(&[0x30, 0x02, 0x02]).is_err()); // truncated INTEGER
        assert!(der_ecdsa_to_fixed_rs(&[0x30, 0x02, 0x99, 0x01]).is_err()); // not an INTEGER
    }

    /// The end-to-end Enclave path, on REAL hardware. Ignored by default (CI has no usable
    /// Enclave); run it on the signing Mac (`bug`) to validate S0:
    ///
    ///     cargo test enclave_generate_sign_verify -- --ignored
    ///
    /// It generates a throwaway Enclave key, signs, and verifies the r‖s signature against the
    /// exported SPKI with an INDEPENDENT verifier (p256) — proving generate + sign + both wire
    /// converters work against the actual Secure Enclave, then deletes the key.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a real Secure Enclave; run on the signing Mac"]
    fn enclave_generate_sign_verify() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;

        let backend = SecureEnclaveBackend::new("ikigai-secret-test");
        let name = "s0-selftest";
        let _ = backend.delete(name); // start clean

        let (alg, spki) = backend
            .generate_signing_key(name)
            .expect("enclave generate")
            .expect("enclave backend generates");
        assert_eq!(alg, ALG_ES256);

        let message = b"the Enclave really signs this";
        let signed = backend
            .sign(name, message)
            .expect("enclave sign")
            .expect("there is a key to sign with");
        assert_eq!(signed.algorithm, ALG_ES256);
        assert_eq!(
            signed.public_key_spki, spki,
            "sign reports the generated key"
        );

        // The whole point: a standard verifier accepts the Enclave's signature via our converters.
        let key = VerifyingKey::from_public_key_der(&spki).expect("spki parses");
        let sig = Signature::from_slice(&signed.signature).expect("r‖s parses");
        key.verify(message, &sig)
            .expect("the enclave signature verifies");

        backend.delete(name).expect("cleanup");
    }

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
    fn the_write_face_stores_replacing_and_is_capability_gated() {
        use ikigai_core::ArgRef;
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        // A pre-existing value, to prove the write REPLACES it (on macOS this is a fresh,
        // process-owned Keychain item — here, over the file backend, just the new bytes).
        backend.set("zoom-client-secret", b"old").unwrap();
        let kernel = ikigai_core::Kernel::new(Arc::new(space(backend.clone())));

        let req = |val: &str| {
            Request::new(
                Verb::Sink,
                ikigai_core::Iri::parse("urn:secret:zoom-client-secret").unwrap(),
            )
            .with_arg("content", ArgRef::Inline(val.as_bytes().to_vec()))
        };
        // A read cap (or a cap for another name) can't write — and nothing is stored.
        assert!(
            Resolver::issue_as(
                &kernel,
                req("new"),
                &Capability::scoped(["urn:cap:secret:read:zoom-client-secret"])
            )
            .is_err(),
            "a read cap must not write"
        );
        assert_eq!(
            backend.get("zoom-client-secret").unwrap().as_deref(),
            Some(&b"old"[..]),
            "a denied write changes nothing"
        );
        // With the write scope: stored, replacing the old value.
        Resolver::issue_as(
            &kernel,
            req("csec-xyz"),
            &Capability::scoped(["urn:cap:secret:write:zoom-client-secret"]),
        )
        .expect("granted write resolves");
        assert_eq!(
            backend.get("zoom-client-secret").unwrap().as_deref(),
            Some(&b"csec-xyz"[..])
        );
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
        let err = Resolver::issue_as(&kernel, req, &Capability::scoped(Vec::<String>::new()))
            .expect_err("unlock without `urn:cap:secret:unlock` is denied");
        assert!(matches!(err, Error::Denied(_)), "typed: {err:?}");
    }

    fn generate_req(key: &str) -> Request {
        Request::new(
            Verb::Source,
            ikigai_core::Iri::parse("urn:secret:generate").unwrap(),
        )
        .with_arg("into", ikigai_core::ArgRef::Inline(key.as_bytes().to_vec()))
    }

    // Keygen itself is cross-platform and gate-free — unit-test it directly, so the
    // "the pair matches" guarantee holds headless everywhere. The endpoint's biometric
    // gate is a REAL Touch ID prompt on macOS (only a no-op off it), so the granted
    // endpoint path is exercised on non-macOS below and validated on Brian's Mac by hand.
    #[test]
    fn generate_age_produces_a_matching_x25519_pair() {
        use std::str::FromStr;
        let (identity, recipient) = generate_age();
        // The exact age formats `ikigai-encrypt` consumes as `key=`/`to=`.
        assert!(
            identity.starts_with("AGE-SECRET-KEY-1"),
            "identity: {identity}"
        );
        assert!(recipient.starts_with("age1"), "recipient: {recipient}");
        // The identity's public half IS the stored recipient (a real keypair).
        let id = age::x25519::Identity::from_str(&identity).expect("valid age identity");
        assert_eq!(id.to_public().to_string(), recipient);
        // Fresh randomness: a second keygen differs.
        let (other, _) = generate_age();
        assert_ne!(identity, other);
    }

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
        let err = Resolver::issue_as(
            &kernel,
            generate_req("nope"),
            &Capability::scoped(Vec::<String>::new()),
        )
        .expect_err("generate without `urn:cap:secret:generate` is denied");
        assert!(matches!(err, Error::Denied(_)), "typed: {err:?}");
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
