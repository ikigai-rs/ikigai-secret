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
  `urn:cap:secret:read:<name>` (default-deny). **Never cacheable** — a cached secret would
  be a secret with no thread and no expiry — and refused BEFORE the keystore is consulted,
  so an ungranted caller cannot learn whether a name exists.
- A capability-gated **write face**: `urn:secret:{name}` (`Sink`), gated by
  `urn:cap:secret:write:<name>`, storing the piped `content` and REPLACING any existing
  item so the new one is owned by this process (an item the `security` CLI created
  re-prompts a code-signed reader; one this face writes does not).
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
and writes through the kernel.

## The manifold

`space()` binds three endpoints, and **declared = enforced** on every action: the kernel
refuses on the declared scope before an endpoint runs, and `urn:kernel:actions` offers
each operation only to a holder of its scope.

| bound at | id | verb | requires |
|---|---|---|---|
| `urn:secret:unlock` | `secret-unlock` | Source | `urn:cap:secret:unlock` |
| `urn:secret:generate` | `secret-generate` | Source | `urn:cap:secret:generate` |
| `urn:secret:{name}` | `urn:secret` | Source | `urn:cap:secret:read:*` (the exact name at invoke) |
| `urn:secret:{name}` | `urn:secret` | Sink | `urn:cap:secret:write:*` (the exact name at invoke) |

The two reserved operations are bound EXACTLY, ahead of the template, so a secret can never
be stored under either name. The id `urn:secret` predates the kebab-case convention and is
a live MCP tool name; it is renamed in the coordinated wave-two pass, not here.

**Passes [`ikigai-conformance`](https://crates.io/crates/ikigai-conformance)**
(`tests/conformance.rs`): the suite walks the three endpoints over the file keystore in a
scratch directory, and the test pins by hand what the suite cannot see — a read is
`Expiry::Always` (and DECLARING it cacheable is a red test), an ungranted caller is refused
identically for a present and an absent secret with the keystore never consulted, the
manifold (`describe()`, catalog, actions, `Meta`) carries no secret value, and every
required input is required. On macOS the two biometric operations are opted out of the
invoking checks — past their capability gate is a real Touch ID prompt — and the ubuntu job
walks them; the gate before the prompt is pinned on both.

## Next slices

- `Exists` / `Delete` over the wire; key rotation / deletion under a capability.
- An injectable presence gate, so the biometric operations can be walked headless on the
  platform they are for (today `require_biometric` is a free function).
- Secure-Enclave-gated keys for material that must require biometric presence.
- More backends (Linux Secret Service, HSM/YubiKey, external vaults, passkey) — the facade
  is fixed, the backends plug in.
