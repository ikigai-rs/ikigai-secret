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
  item. How it replaces is the store's: the Keychain deletes and re-adds, so the new item is
  owned by this process (an item the `security` CLI created re-prompts a code-signed reader;
  one this face writes does not); the file store writes the new value whole and renames it
  over the old one, so a failed write keeps the previous secret; the Secure Enclave refuses
  before deleting anything.
- A **biometric gate**: `require_biometric` (macOS Touch ID, a no-op elsewhere) and the
  reserved op `urn:secret:unlock` (`urn:cap:secret:unlock`), for operations needing
  physical presence.
- **Key generation** — the reserved op **`urn:secret:generate`** (`into=<keyname>`,
  `type=ed25519`|`age`) mints a keypair — an **Ed25519** *signing* key (PKCS8/SPKI PEM, read
  by [`ikigai-sign`]) or an **`age`** X25519 *encryption* key (identity/recipient, read by
  [`ikigai-encrypt`]) — **cap-gated** then **biometric-gated**. It WRITES two secrets, so it
  needs `urn:cap:secret:generate` AND the write scope for both names it writes
  (`urn:cap:secret:write:<name>` and `urn:cap:secret:write:<name>.pub`); it never replaces
  a stored secret (a name holding either half is refused, before the prompt: rotating a key
  is minting a new name) and never mints into a reserved name (`unlock`, `generate`). If the
  public half cannot be written, the private half is removed again, so a failure never leaves
  half a pair. The private half is stored under `<name>`, the public half under `<name>.pub`, and the op
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
| `urn:secret:generate` | `secret-generate` | Source | `urn:cap:secret:generate` AND `urn:cap:secret:write:*` (the exact `<into>` and `<into>.pub` at invoke) |
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

## The file store

`FileBackend` is the default off macOS (and what tests and the cms-web relying party build
directly with `FileBackend::new(dir)`). Not hardware-backed.

- **Where.** `FileBackend::in_data_dir()`: `$IKIGAI_SECRETS` when set (it must be absolute),
  else `~/.ikigai/secrets` in the data home. With `HOME` unset or empty and no
  `IKIGAI_SECRETS` there is **no** store, and it refuses, naming both settings; it never falls
  back to a directory relative to the working directory. (`default_backend()` stays
  infallible: with no store, every operation refuses with that message.) `in_config_dir()`
  is its deprecated old name.
- **Format.** One regular file per secret; the file's whole content is the secret's bytes,
  and its name is the secret's name escaped injectively and case-safely: `a`–`z`, `0`–`9`,
  `-`, `_` and a non-leading `.` are kept verbatim, and every other byte of the UTF-8 —
  uppercase included — becomes `%` and two lowercase hex digits (`team:db` → `team%3adb`,
  `API-KEY` → `%41%50%49-%4b%45%59`, `.` → `%2e`). No file name contains an uppercase letter,
  so distinct names stay distinct files on a volume that folds case (APFS, NTFS), and no name
  can address `.`, `..` or a hidden file. The store's own temporary files are hidden
  (`.tmp-…`).
- **Modes (Unix).** The directory is `0700` and every file `0600`, set explicitly at
  creation, so the umask cannot widen them. An existing directory or file others can **read**
  is tightened to `0700`/`0600` and logged once on stderr (anything in it may already have
  been read); one others can **write**, or owned by another user, is **refused**, because its
  contents (a key, a recipient) are not trusted and tightening it would trust whatever was
  written.
- **Writes are atomic.** A write goes to a `0600` temporary file in the store, is synced,
  and is renamed over the old file, so a failed write (a full disk, a quota) leaves the
  previous secret intact and no partial value.
- **Migrating a store from 0.1.6 or earlier.** A name made only of the verbatim set (every
  name the ecosystem uses today: `cms-passkeys`, `zotero-api-key`, `brian.sign.pub`) keeps
  the file name it always had and reads unchanged. Earlier versions mapped every other
  character to `_` and kept uppercase verbatim, so distinct names could share a file. Which
  name wrote such a file cannot be known, so it is never guessed: a file is served only under
  the name its file name now spells (exactly as before), never under the name that may have
  written it, and a legacy entry differing from a name only in case is refused on a volume
  that folds case. A secret stored under a name outside the verbatim set must be stored
  again.

## Unreleased

Fixes for audit round 3 (ledger #854, and #203). **Version call: a patch, 0.1.7.** The Rust
API is source-compatible (two trait methods with defaults, one deprecation), and every change
in behavior tightens a security property, which consumers pinning `"0.1.6"` should receive
without editing a manifest. Neither consumer needs anything: `ikigai-cli` mounts
`space(default_backend())` and grants nothing scoped for generate, and `ikigai-cms-web` stores
only verbatim-set names. What changes for a caller:

- **The file store's name mapping** is injective and case-safe; names outside the verbatim set
  get new file names (see Migrating, above).
- **The file store is private and atomic**: `0700`/`0600` whatever the umask, wider modes
  tightened or refused, and a replace never deletes first.
- **`urn:secret:generate` requires write authority over what it writes** — a manifold change:
  its action now declares `urn:cap:secret:write:*` beside `urn:cap:secret:generate`, and the
  exact `<into>` and `<into>.pub` scopes are checked at invoke. A caller holding only
  `urn:cap:secret:generate` is now refused. It also refuses a name already holding either half
  (it used to overwrite, so re-running it as "rotation" now refuses: mint a new name) and the
  reserved names, and never leaves half a pair.
- **No store relative to the working directory** when `HOME` is unset: the file store refuses.
- **`Backend::replace` and `Backend::exists`**, with defaults (delete-then-set; get). The
  Sink calls `replace`. The Secure Enclave's refuses before deleting (a Sink over it used to
  delete the key and then fail to store anything).
- **The write face takes any bytes** (the second audit's S3): `content` is no longer required
  to be UTF-8, so a binary secret the read face serves as `application/octet-stream` can be
  replaced through the resource.
- `ikigai-core` floor `0.1.46` → `0.1.58` (`config::data_home_from`).

## Next slices

- `Exists` / `Delete` over the wire; key rotation / deletion under a capability.
- An atomic Keychain replace (add under a temporary account, delete the old item, rename the
  new one with `SecItemUpdate`): today a Keychain write that fails after its delete loses the
  previous secret. It needs the Keychain to test, so it is an arc run on the machine.
- An injectable presence gate, so the biometric operations can be walked headless on the
  platform they are for (today `require_biometric` is a free function).
- Secure-Enclave-gated keys for material that must require biometric presence.
- More backends (Linux Secret Service, HSM/YubiKey, external vaults, passkey) — the facade
  is fixed, the backends plug in.
