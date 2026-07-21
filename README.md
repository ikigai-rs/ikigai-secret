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
- **Key generation** — the reserved op **`urn:secret:generate`** (`into=<keyname>`,
  `type=ed25519`|`age`) mints a keypair — an **Ed25519** *signing* key (PKCS8/SPKI PEM, read
  by [`ikigai-sign`]) or an **`age`** X25519 *encryption* key (identity/recipient, read by
  [`ikigai-encrypt`]) — **cap-gated** (`urn:cap:secret:generate`) then **biometric-gated**.
  The private half is stored under `<name>`, the public half under `<name>.pub`, and the op
  returns the public half; the private key never leaves through this op (retrieved separately
  through the cap-gated read face). **One identity, two keys** — sign *and* encrypt from the
  same hardware-backed custody. Name keys `<id>.<role>` (`<id>` an identity, `<role>` ∈
  `sign`/`enc`), so `<name>.pub` reads as "…'s … public key" and a second user is just
  `alice.enc` — no rework. This closes both loops:

  ```text
  # signing (ed25519) → ikigai-sign
  urn:secret:generate into=brian.sign type=ed25519   # cap + Touch ID → keypair in the keystore
  urn:sign:sign   key=urn:secret:brian.sign
  urn:sign:verify key=urn:secret:brian.sign.pub

  # encryption (age) → ikigai-encrypt
  urn:secret:generate into=brian.enc type=age        # cap + Touch ID → age keypair
  source urn:file:msg.txt | urn:encrypt:encrypt to=urn:secret:brian.enc.pub
  … | urn:encrypt:decrypt key=urn:secret:brian.enc
  ```

A host uses the `Backend` directly (e.g. a relying party storing credential material
in the Keychain instead of a plaintext file), or mounts `space()` for cap-scoped reads
through the kernel.

## Next slices

- Write / delete over the wire (`Sink` / `Delete`); key rotation / deletion under a capability.
- Secure-Enclave-gated keys for material that must require biometric presence.
- More backends (Linux Secret Service, HSM/YubiKey, external vaults, passkey) — the facade
  is fixed, the backends plug in.
