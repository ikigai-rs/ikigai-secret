# ikigai-secret

Secrets for ikigai (`urn:secret:*`): resolve and store secrets through the OS
keystore, **capability-gated**. The first slice of the pluggable secrets facade —
secrets are referenced by URI and resolved only at point-of-use under a capability,
never inlined, never cached.

## This slice

- A [`Backend`] trait — `get` / `set` / `delete` a named secret's bytes — with two
  impls: **macOS Keychain** (`Security.framework`, on a Mac) and a **dev file store**
  (everywhere else; not hardware-backed). `default_backend()` picks per platform.
- A capability-gated **read face**: `urn:secret:{name}` (`Source`), gated by
  `urn:cap:secret:read:<name>` (default-deny). Never cacheable.
- A **biometric gate**: `require_biometric` (macOS Touch ID, a no-op elsewhere) and the
  reserved op `urn:secret:unlock` (`urn:cap:secret:unlock`), for operations needing
  physical presence.
- **Key generation** — the reserved op **`urn:secret:generate`**
  (`name=<keyname>` `type=ed25519`) mints an Ed25519 keypair, **cap-gated**
  (`urn:cap:secret:generate`) then **biometric-gated**. The private key is stored as
  **PKCS8-PEM** under `<name>`, the public key as **SPKI-PEM** under `<name>.pub`, and the
  op returns the public key. The private key never leaves through this op — it is
  retrieved separately through the cap-gated read face, as the same PKCS8-PEM that
  [`ikigai-sign`] reads via `key=urn:secret:<name>`. This closes the loop:

  ```text
  urn:secret:generate name=signing-key   # cap + Touch ID → keypair in the keystore
  urn:sign:sign   key=urn:secret:signing-key
  urn:sign:verify key=urn:secret:signing-key.pub
  ```

A host uses the `Backend` directly (e.g. a relying party storing credential material
in the Keychain instead of a plaintext file), or mounts `space()` for cap-scoped reads
through the kernel.

## Next slices

- Write / delete over the wire (`Sink` / `Delete`).
- Secure-Enclave-gated keys for material that must require biometric presence.
- More key types beyond Ed25519; key rotation / deletion under a capability.
- More backends (Linux Secret Service, `age`-encrypted files, HSM/YubiKey, external
  vaults, passkey) — the facade is fixed, the backends plug in.
