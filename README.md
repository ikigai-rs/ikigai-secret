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

A host uses the `Backend` directly (e.g. a relying party storing credential material
in the Keychain instead of a plaintext file), or mounts `space()` for cap-scoped reads
through the kernel.

## Next slices

- Write / delete over the wire (`Sink` / `Delete`).
- **`urn:secret:unlock`** — a Touch-ID unlock session (`LAContext`), and
  Secure-Enclave-gated keys for material that must require biometric presence.
- More backends (Linux Secret Service, `age`-encrypted files, HSM/YubiKey, external
  vaults, passkey) — the facade is fixed, the backends plug in.
