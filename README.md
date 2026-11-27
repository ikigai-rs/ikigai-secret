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
- **Exists and Delete** on `urn:secret:{name}`: `Exists` answers `true` or `false` under
  the read scope `urn:cap:secret:read:<name>` (a reader learns as much from a `Source`), and
  `Delete` removes the secret under its OWN scope, `urn:cap:secret:delete:<name>`, so a
  write grant issued before `Delete` existed does not gain deletion. `Delete` then **asks for
  presence** (Touch ID on a Mac), after every capability and argument check, and deletes
  nothing when presence is refused. `Delete` is idempotent, and neither answer is ever cached.
- A **presence gate**: the `PresenceGate` trait, which `urn:secret:unlock`
  (`urn:cap:secret:unlock`), `urn:secret:generate` and a `Delete` on `urn:secret:{name}` ask
  only after every capability and argument check. `space(backend)` uses `BiometricGate` (`require_biometric`: macOS Touch ID,
  a no-op elsewhere); `space_with_gate(backend, gate)` injects another, and any
  `Fn(&str) -> Result<()>` closure is one, so a test stubs it and every gated operation runs
  headless on every platform.
- **Key generation** — the reserved op **`urn:secret:generate`** (`into=<keyname>`,
  `type=ed25519`|`age`) mints a keypair — an **Ed25519** *signing* key (PKCS8/SPKI PEM, read
  by [`ikigai-sign`]) or an **`age`** X25519 *encryption* key (identity/recipient, read by
  [`ikigai-encrypt`]) — **cap-gated** then **biometric-gated**. It WRITES two secrets, so it
  needs `urn:cap:secret:generate` AND the write scope for both names it writes
  (`urn:cap:secret:write:<name>` and `urn:cap:secret:write:<name>.pub`); it never replaces
  a stored secret (a name holding either half is refused, before the prompt: rotating a key
  is minting a new name; and each half is written through `Backend::create`, which stores
  only into a free name, so a secret stored after that check is not replaced either, and two
  generates racing for one name mint once) and never mints into a reserved name (`unlock`,
  `generate`). If the
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

**A secret's name never begins with `-`.** The name is the last segment of its scopes
(`urn:cap:secret:read:<name>`, `urn:cap:secret:write:<name>`), and since `ikigai-core` 0.1.86
that position, with a leading `-`, marks an EXCLUSION (`is_deny_scope`), which `allows()` never
grants: a grant for `-x` could never be honored. So the read face, the write face, generate's
`into` and the file store's own API all refuse such a name with an `InvalidArgument` that says
why, before any capability check and whatever core is linked. A `-` anywhere else in a name is
just a character (`api-key`).

A host uses the `Backend` directly (e.g. a relying party storing credential material
in the Keychain instead of a plaintext file), or mounts `space()` for cap-scoped reads
and writes through the kernel (`space_with_gate()` to choose the presence gate).

## The manifold

`space()` binds three endpoints, and **declared = enforced** on every action: the kernel
refuses on the declared scope before an endpoint runs, and `urn:kernel:actions` offers
each operation only to a holder of its scope.

| bound at | id | verb | requires |
|---|---|---|---|
| `urn:secret:unlock` | `secret-unlock` | Source | `urn:cap:secret:unlock` |
| `urn:secret:generate` | `secret-generate` | Source | `urn:cap:secret:generate` AND `urn:cap:secret:write:*` (the exact `<into>` and `<into>.pub` at invoke) |
| `urn:secret:{name}` | `secret` | Source | `urn:cap:secret:read:*` (the exact name at invoke) |
| `urn:secret:{name}` | `secret` | Sink | `urn:cap:secret:write:*` (the exact name at invoke) |
| `urn:secret:{name}` | `secret` | Exists | `urn:cap:secret:read:*` (the exact name at invoke) |
| `urn:secret:{name}` | `secret` | Delete | `urn:cap:secret:delete:*` (the exact name at invoke), then presence |

The two reserved operations are bound EXACTLY, ahead of the template, so a secret can never
be stored under either name. Each id is the endpoint's one name: the `Description` id equals
`Endpoint::name()`, a kebab-case noun (ledger #11; the template's id was `urn:secret` until
the naming wave, see 0.2.0).

**Passes [`ikigai-conformance`](https://crates.io/crates/ikigai-conformance)**
(`tests/conformance.rs`): the suite walks the three endpoints over the file keystore in a
scratch directory with `secret` declared live (`Suite::live`), so a secret read that
turns cacheable is a red test. The test pins by hand what the suite cannot see — every read
reaches the keystore, under a narrow grant as under root, an ungranted caller is refused
identically for a present and an absent secret with the keystore never consulted, the
manifold (`describe()`, catalog, actions, `Meta`) carries no secret value, and every
required input is required (the suite's `REQUIRED` check, held on the Sink too with
`Suite::required_on_mutating`, plus a hand test for what the walk skips). Nothing is opted
out: the fixture injects a stub presence gate that logs each request beside the keystore
calls, so the two gated operations are walked on macOS too (their real gate is a Touch ID
prompt), and the test pins that the gate is asked only after every other check and that its
refusal stands, for unlock, generate and a `Delete`. The `Delete` declares no `content`, so the
suite fires it only under no grants: the walk deletes nothing and never reaches the gate.

## Stores and routes

Where a secret is stored is configuration (ledger #4486; the design is
[`docs/storage-backends.md`](docs/storage-backends.md)). A host reads the `[secret]` section of
its config home's `config.toml`, deserializes it into a `SecretSection` (serde, as core's
`CacheConfig`), and hands it to `SecretConfig::from_section(section, home)`. This crate reads no
file and no environment for it.

```toml
[secret]
default = "keychain"            # the store every name no route matches goes to

[secret.store.keychain]
kind = "keychain"               # macOS only
service = "ikigai-secret"       # the default

[secret.store.local]
kind = "file"
path = "~/.ikigai/secrets"      # absolute, or under the home the host passes
write = false                   # any store: refuse writes (default true)

[[secret.route]]                # read in order; the first match wins
match = "owner:id:acme:name:*"  # a glob on the full secret name (`*`, `?`, `[...]`)
store = "local"
```

- **Kinds.** `keychain`, `secure-enclave` (both macOS only), `file` and `age-file` (since
  0.5.3, below) are built here. `fnox` (since 0.5.4) is checked here and built by the host
  through the `ikigai-secret-fnox` connector in this repository (see "The fnox store", below).
  Each kind reads only its own settings: `keychain` reads `service`,
  `secure-enclave` reads `label_prefix`, `file` reads `path`, `age-file` reads `path`,
  `identity` and `recipients`, `fnox` reads `config`, `profile`, `names` and `map`, and every
  kind reads `write`.
- **Refused whole.** An unknown kind, a kind not built yet, a Mac store off macOS, a setting
  of another kind, a store name that is not lowercase letters, digits, `-` and `_`, a missing
  `default` or one that names no store, a route to a store that is not configured, a `match`
  that is empty or not a glob, and two routes with the same `match`: each is one sentence
  naming its line, all of them are reported at once, and nothing in a refused section is
  applied. A host refuses to start on one; wiring that into the hosts is ledger #4487.
- **One store per name.** `RoutingBackend` sends every call to the store its name routes to,
  and only there: a miss is NotFound, never "try the next store". `sign` and
  `generate_signing_key` route the same way.
- **Routes never widen a scope.** Every face checks the name's own scope before the backend is
  called, so a route only says where an allowed operation goes. A write to a name routed to a
  store with `write = false` is refused as Conflict after the capability check and before the
  presence gate.
- **No section** is exactly today for an EXISTING install: one store, the one
  `default_backend()` builds (the Keychain under `ikigai-secret` on a Mac, the file store in its
  usual place elsewhere), with no routes. A NEW install gets an `age-file` store instead; see
  "The age-file store", below, for how a host tells them apart.
- **Inspection.** `routed_space(routing)` (or `routed_space_with_gate`) mounts every face of
  `space()` over the routing backend, plus four resources that never carry a path, an
  account, a token or a value. Each answers `text/plain`, or `application/json` with
  `as=application/json`:

  | bound at | id | requires | answers | cached |
  |---|---|---|---|---|
  | `urn:secret:store` | `secret-store` | `urn:cap:secret:inspect` | each store's name, kind, whether it can be written, a sentence | until the config thread is cut |
  | `urn:secret:store:name:{store}` | `secret-store-name` | `urn:cap:secret:inspect` | the same for one store, plus a health line read now | never |
  | `urn:secret:route` | `secret-route` | `urn:cap:secret:inspect` | the ordered routes and the default | until the config thread is cut |
  | `urn:secret:route:secret:{name}` | `secret-route-secret` | `urn:cap:secret:read:<name>` | the store `name` routes to, from the route table alone | until the config thread is cut |

  A host that reloads its configuration cuts `CONFIG_THREAD` (`urn:secret:config`). In the
  routed space the names `store` and `route`, and every name beginning `store:name:` or
  `route:secret:`, belong to these resources, so generate refuses to mint into them.
  `space(backend)` binds none of them and is unchanged.

## The age-file store

`kind = "age-file"` (ledger #4488, the design's section 6.3) is the file store with each item
encrypted at rest. The directory layout, the modes, the atomic writes and the
regular-file-only reads are the file store's, unchanged; each item is a whole binary age file,
so the stock tool opens one at the box (`age -d -i <identity> <file>`).

```toml
[secret.store.server]
kind = "age-file"
path = "/srv/ikigai/secrets"        # absent: the data home's `secrets` directory
identity = "file:/etc/ikigai/age"   # where the HOST gets the age identity from
recipients = ["age1…"]              # more recipients every item is sealed to (a recovery key)
```

- **The identity is the host's.** Building an age identity may read a file or run an age
  plugin (`age-plugin-se`, `age-plugin-yubikey`, `age-plugin-tpm`), which only a host-role crate
  may do, so this crate never resolves `identity`: it carries the string, and the host builds an
  `AgeKeys` (seal to every recipient, open with the identity) and passes it to
  `SecretConfig::build_with_keys(keys)`, by store name. `X25519Keys::new(identity_text,
  recipients)` is the one built here, from identity text the host already read, sealing through
  `ikigai_encrypt::age` (the ecosystem's one implementation of age). Every item is sealed to the
  identity's own recipient and to each configured one, so a recovery key opens every item too.
  A plugin recipient needs a host-built `AgeKeys`; `X25519Keys` refuses one, saying so.
  `build()` still works: an `age-file` store it makes refuses every operation with a sentence
  saying the host gave it no identity.
- **A mixed store reads both.** A store moved in place from `file` (same `path`, `kind =
  "age-file"`) still serves its plaintext items; a write always encrypts, so each item is
  re-encrypted on its next write. An item is ciphertext exactly when it begins with age's header
  line (`AGE_HEADER`). An age file this store's identity cannot open, or one that is not whole,
  is refused with a sentence, never handed back as if it were the secret.
- **Reencrypt.** `urn:secret:store:name:{store}:reencrypt` (Sink, id `secret-store-reencrypt`)
  encrypts every plaintext item at once: one item at a time, each a temporary file renamed over
  the old one, after a backup copy of the directory beside it (`<dir>.backup-<seconds>`, `0700`,
  files `0600`), with one line per item. Idempotent: an item already encrypted is left
  unchanged, and a run with nothing to convert makes no backup. Under the write scope of each
  item it rewrites (`urn:cap:secret:write:<name>`; an item the caller may not write is neither
  read nor named), then the presence gate ("Encrypt the secrets in the store {store}"). A crash
  at any point leaves every item readable, as plaintext or as ciphertext; the answer is refused,
  with its lines, when any item was left as it was, and running it again finishes the job.
- **The default for new installs.** `found_install(home)` says what a host with no `[secret]`
  section finds, judged without reading any secret: `IKIGAI_SECRETS` set, a file store
  directory holding a secret, or (on a Mac) any Keychain item under `ikigai-secret` is an
  EXISTING install; the age-file store's marker (a hidden `.ikigai-age-file` file it leaves in
  its directory on its first write) is the age-file store an earlier start made; anything else
  is new. `SecretConfig::for_host(section, home, found)` then answers the section when there is
  one, today's store for an existing install (and `notice()` has the one line the host prints at
  start: `age-file` is the new default, how to move, and that `IKIGAI_SECRETS` is deprecated),
  and otherwise one `age-file` store named `age-file` in the data home's `secrets` directory,
  whose `identity` is `HOST_DEFAULT_IDENTITY` (`"default"`: the host's own default source).
  `default_backend()` and `from_section(None, …)` are unchanged, so no host changes behavior
  until it calls `for_host`.

## Copying between stores

`urn:secret:store:name:{to}:copy from={store} name={name}` (Sink, id `secret-store-copy`, ledger
#4491) copies one secret from the store `from` into the store `{to}` and never deletes the
source: how an install moves its secrets into a new store after adding a `[secret]` section
(a name newly routed to another store is NotFound there until it is copied). The name can also
be piped in as `content` (one name; a trailing newline is dropped), exactly one of the two.

```text
sink urn:secret:store:name:server:copy from=keychain name=zoom.client-secret
```

- **Three gates, in order:** the name's read scope `urn:cap:secret:read:<name>` AND its write
  scope `urn:cap:secret:write:<name>` (both declared as floors, both checked exactly), then the
  configuration (both stores configured, not the same store, the target writable and able to
  hold a value, the source not a Secure Enclave), then the presence gate ("Copy secret {name}
  from the store {from} to the store {to}"). Only then is either store asked anything, so a
  refused copy reads nothing, writes nothing and prompts nobody.
- **Refused:** into a read-only store (Conflict), from a store that does not hold the name
  (NotFound), and into a store that already holds a different value (Conflict) unless
  `replace=true`. The same value already there writes nothing. Each outcome is one sentence, and
  no answer ever carries a value.
- The write is the target store's own: a free name is created exclusively and a replace is the
  store's atomic replace, so a failure leaves the target as it was and the source untouched.

`tests/copy.rs` pins each gate missing alone, every refusal and outcome, a copy into an
age-file store (encrypted there), and the move out of a store laid out as 0.5.1 wrote it.

`tests/age_file.rs` pins the upgrade from a store as 0.5.1 wrote it (built byte for byte),
`reencrypt` and its second run, a crash mid-reencrypt, a downgrade then a re-upgrade, the
capability and presence order, and the new-install default.

## The fnox store

`kind = "fnox"` (ledger #4489, the design's section 6.1) reads secrets through fnox's library
from ONE fnox configuration file, read-only. fnox reads files and the environment and runs
provider commands (`op`, `aws`, `bw`), which a module crate never does, so the store lives in a
host-role connector, [`crates/ikigai-secret-fnox`](crates/ikigai-secret-fnox/README.md), a
separate crate in this repository's workspace. This crate checks the section and never depends
on the connector.

```toml
[secret.store.team]
kind = "fnox"
config = "~/work/acme/fnox.toml"   # the one fnox file; never fnox's upward search
profile = "prod"                   # absent: fnox's default profile, never FNOX_PROFILE
names = "map"                      # map (the default) | escaped

[secret.store.team.map]            # secret name to fnox key, one to one
"zoom.client-secret" = "ZOOM_CLIENT_SECRET"
```

- **Names map one to one**, because a lossy mapping would let a caller allowed to read one name
  read another's secret. `map` is an explicit table: an unlisted name is NotFound, and a table
  sending two names to one key, or naming something that is not a fnox key, is refused at start.
  `escaped` is `fnox_escape`: ASCII letters pass, digits pass after the first character, and
  every other character, `_` included, becomes `_` and two hex digits per UTF-8 byte
  (`zoom.client-secret` is `zoom_2Eclient_2Dsecret`).
- **Read-only.** Every write to a name routed to a fnox store is Conflict ("the store `team` is
  read-only: …"), after every capability check, and a copy into one is refused. A copy OUT of
  one, into an `age-file` or `file` store, works.
- **The host builds it.** `SecretConfig::build_with_backends(keys, backends)` takes the
  connector's backends by store name (`ikigai_secret_fnox::backends(&config)`, or
  `ikigai_secret_fnox::routing(config, keys)` for both steps); `build` and `build_with_keys` leave
  a fnox store refusing every read, saying so.
- **Never interactive, and errors never carry fnox's text.** See the connector's README, which
  also lists what fnox still reads from the host's environment.

**The other direction: ikigai as a fnox provider.** `contrib/fnox/ikigai.lua` is a fnox Lua
plugin whose `get` reads a fnox secret through `ikigai --quiet -c 'source urn:secret:<name>'`, so
fnox users get ikigai's per-name capabilities, presence gate and audit. It grants nothing and
reads nothing else. Its README says how to declare it, that fnox plugins are not sandboxed, and
what a refusal looks like (ledger #4492).

`tests/routed.rs` walks the routed space with `ikigai-conformance` and pins by hand: every
resource under its narrow grant, every routed path refused under no grants and under grants for
other names with no store and no gate touched, a route never widening a scope, a miss staying
NotFound, read-only stores, and the no-section path forwarding every call unchanged.

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
- **Only regular files.** A read refuses an entry that is a symlink, a FIFO, a directory or a
  device: a symlink is never followed out of the store (nor is what it names `chmod`ed), and a
  FIFO is refused at once rather than waited on.
- **Modes (Unix).** The directory is `0700` and every file `0600`, set explicitly at
  creation, so the umask cannot widen them. An existing directory or file others can **read**
  is tightened to `0700`/`0600` and logged once on stderr (anything in it may already have
  been read); one others can **write**, or owned by another user, is **refused**, because its
  contents (a key, a recipient) are not trusted and tightening it would trust whatever was
  written.
- **Writes are atomic.** A write goes to a `0600` temporary file in the store, is synced,
  and is renamed over the old file, so a failed write (a full disk, a quota) leaves the
  previous secret intact and no partial value.
- **Creating is exclusive.** `create` (what generate writes each half with) writes the value
  to a `0600` temporary file the same way, then HARD-LINKS it to the secret's name, which the
  filesystem refuses when the name is taken: the name appears only once the whole value is on
  disk, and of several writers racing for one name exactly one stores. (So the store needs a
  filesystem with hard links, as every home directory volume has; on one without, `create`
  refuses with the error rather than falling back to a check-then-write.)
- **Migrating a store from 0.1.6 or earlier.** A name made only of the verbatim set (every
  name the ecosystem uses today: `cms-passkeys`, `zotero-api-key`, `brian.sign.pub`) keeps
  the file name it always had and reads unchanged. Earlier versions mapped every other
  character to `_` and kept uppercase verbatim, so distinct names could share a file. Which
  name wrote such a file cannot be known, so it is never guessed: a file is served only under
  the name its file name now spells (exactly as before), never under the name that may have
  written it, and a legacy entry differing from a name only in case is refused on a volume
  that folds case. A secret stored under a name outside the verbatim set must be stored
  again.

## Accessibility

This library has no screens, but people meet its presence prompt and its error sentences. [ACCESSIBILITY.md](ACCESSIBILITY.md) says what is in scope, how it is tested, and the barriers we know about (the macOS presence gate accepts biometrics only, with no password fallback).

## 0.1.7 (2026-10-07)

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
- **Secure Enclave ES256 signatures leave low-S** (ledger #860): `der_ecdsa_to_fixed_rs`
  reflects a high s to n − s (and refuses s ≥ n), so `ikigai-sign`'s verifier, which refuses
  high-S, accepts every Enclave signature rather than about half of them.
- `ikigai-core` floor `0.1.46` → `0.1.58` (`config::data_home_from`).

## 0.1.8 (2026-10-07)

- **A name beginning with `-` is refused** at every face (ledger #874; see "A secret's name
  never begins with `-`", above). Before, such a name was creatable through the write face and
  generate by a caller holding its exact write scope (or root) on `ikigai-core` 0.1.85 and
  earlier, and on 0.1.86 every non-root caller got a bare `Denied` for the scope they held. A
  file store holding one keeps it on disk, but the store no longer serves it: rename the file
  at the box (the file name is the secret's name, `-` kept verbatim) and read it under the new
  name. The library's `ikigai-core` floor is unchanged (`0.1.58`): the refusal uses no new
  core API, and it behaves the same on every core version.

## 0.2.0 (2026-10-17)

### Renamed (BREAKING for anyone matching on ids or MCP tool names)

The naming wave (ledger #11): a resource name is a short kebab-case noun, and the
`Description` id is that name, not an IRI. One id changes; no IRI does, so nothing that
resolves `urn:secret:{name}` changes.

| what | old | new |
| --- | --- | --- |
| id of the `urn:secret:{name}` endpoint (the catalog label) | `urn:secret` | `secret` |
| its MCP tool names (one per verb) | `urn_secret__source`, `…__sink`, `…__exists`, `…__delete` | `secret__source`, `secret__sink`, `secret__exists`, `secret__delete` |

`secret-unlock` and `secret-generate` already conformed and are unchanged. The id now equals
`Endpoint::name()` (`secret`), so a conformance fixture keyed by either name reaches the
endpoint; before, one keyed by `secret` was silently ignored. The conformance suite now runs
`NAMES` too. A breaking change under 0.x, so the release is a minor bump.

### Added

- **The presence gate is injectable** (ledger #201): `PresenceGate`, `BiometricGate` and
  `space_with_gate(backend, gate)`. `space(backend)` is unchanged in behavior (it uses
  `BiometricGate`), and `require_biometric` stays public. The conformance walk and the
  generate tests now run on macOS with the gate stubbed; the macOS opt-outs are gone.
- **`Exists` and `Delete` on `urn:secret:{name}`** (ledger #202), each a per-verb action:
  `Exists` under `urn:cap:secret:read:*`, `Delete` under the new `urn:cap:secret:delete:*`
  (the exact name at invoke). A manifold change: a holder of a delete scope is now offered
  `Delete`, and nothing a host already granted gains it. Tested over the file store; over the
  Keychain both run the backend's existing `exists` (a read of the item) and `delete`, which
  no test reaches (TCC).
- **`Delete` asks for presence** (ledger #1525, Brian 2026-10-14): like unlock and generate, a
  `Delete` on `urn:secret:{name}` asks the presence gate after every capability and argument
  check, and a refusal is its answer with nothing deleted. Under `space(backend)` on a Mac that
  is a Touch ID prompt per delete, so a host deleting unattended injects its own gate through
  `space_with_gate`. A refused-by-capability delete never asks.

## 0.5.4

The fnox read store (ledger #4489), the next step of configurable secret storage (epic ledger
#4485), and the repository becomes a workspace. Additive, so a patch: nothing a 0.5.3 host calls
changes behavior, and the crate's name, files and API are where they were.

- `kind = "fnox"` is accepted: `StoreKind::Fnox`, `FnoxNames`, `fnox_escape`, `is_fnox_key`
  and `fnox_read_only`, with the `config`, `profile`, `names` and `map` settings and their
  refusals (no `config`, a relative one, `write = true`, an unknown `names`, a missing or
  misplaced `map`, a key that is not a fnox key, two names sent to one key). A fnox store is
  always read-only.
- `SecretConfig::build_with_backends(keys, backends)`: `build_with_keys` plus the host's
  backends for the stores this crate does not build. `SecretConfigError::new` is public, so a
  connector refuses the same way.
- A copy into a fnox store is refused with its own sentence.
- New crate in the workspace: `ikigai-secret-fnox` 0.1.0 (`crates/ikigai-secret-fnox`), the
  host-role connector. This crate does not depend on it.

## 0.5.3

The `age-file` store (ledger #4488) and copying between stores (ledger #4491), the next steps
of configurable secret storage (epic ledger #4485). Additive, so a patch: nothing a 0.5.2 host
calls changes behavior.

- `StoreKind::AgeFile` and the `[secret]` section's `age-file` kind, reading `path`, `identity`
  and the new `recipients`; refused, a sentence each, with no `identity`, with a `recipients`
  entry that is not an age recipient, and with no `path` and no home. `fnox` is still refused as
  not built yet. A refusal of another kind's setting now says "an age-file store".
- `AgeKeys`, `AgeError`, `X25519Keys`, `AgeFileBackend`, `AGE_HEADER`, `Reencrypted` and
  `SecretConfig::build_with_keys`: see "The age-file store", above.
- `urn:secret:store:name:{store}:reencrypt` (`REENCRYPT_TEMPLATE`, id `secret-store-reencrypt`) in
  the routed space, and a `Backend::reencrypt` method whose default refuses. ⚠ A backend that
  wraps another should forward it.
- `found_install`, `Found`, `SecretConfig::for_host`, `SecretConfig::notice` and
  `HOST_DEFAULT_IDENTITY`: the new-install default.
- `urn:secret:store:name:{to}:copy` (`COPY_TEMPLATE`, id `secret-store-copy`) in the routed
  space: see "Copying between stores", above.
- New dependency: `ikigai-encrypt` 0.5 with `default-features = false` (its age library only).

## 0.5.2

Stores and routes (ledger #4486), the first step of configurable secret storage (epic ledger
#4485). Additive, so a patch: nothing a 0.5.1 host calls changes behavior.

- `SecretSection`, `SecretConfig`, `SecretConfigError`, `StoreKind`, `StoreSpec`, `RouteSpec`,
  `Routed` and `RoutingBackend`: the `[secret]` section, its refusals and the routing backend
  (see "Stores and routes", above).
- `routed_space` and `routed_space_with_gate`, with the four inspection resources under the
  new `urn:cap:secret:inspect` (and `urn:cap:secret:read:<name>` for where a name lives).
- Two `Backend` methods with defaults: `accepts_writes` (asked after the capability check and
  before the presence gate; the faces call it before a Sink, a Delete and a generate) and
  `health` (one line for `urn:secret:store:name:{store}`; the file store judges its directory).
  ⚠ A backend that wraps another should forward both.
- `default_backend()` is now built through the same function as the no-section configuration;
  what it builds is unchanged.
- The `secret` endpoint's summary says "the store its name routes to" rather than naming the
  OS keystore.
- New dependencies: `serde` (the section is `Deserialize`), `serde_json` (the JSON faces) and
  `glob` (a route's `match`); `toml` for tests only.
- `contrib/fnox/ikigai.lua` (ledger #4492): ikigai as a fnox provider, `get` only, with
  `tests/fnox_plugin.rs` testing the exact command line it builds in Lua 5.4 (`mlua`, a
  dev-dependency, vendored). Not part of the Rust API.

## 0.5.1

A patch from the third unled audit (ledger #4023): the file store serves only regular files.

- A read opens a secret's file without following a link at its name and without waiting on it,
  and refuses any entry that is not a regular file (a symlink, a FIFO, a directory or a device)
  with a sentence, before judging its mode or reading it. A symlinked store directory still
  works. Regression tests: `tests/audit_4023.rs`.

## 0.5.0

Moves onto ikigai-core 0.4, scope opacity and structured denials (the core 0.4.0 cascade, ledger
#3913). `Error::Denied` now carries a `Denial`; every refusal here builds one from the same
sentence as before, so what a caller reads is unchanged. Core's types are in this crate's API, so
the release is a minor bump, and it carries the unreleased audit fixes below (planned as 0.4.1,
never published).

- `ikigai-core` `"0.3.0"` → `"0.4.1"` (0.4.1 because the test build's `ikigai-resolve` 0.6.0
  requires it).
- Dev-dependencies: `ikigai-resolve` `"0.3.0"` → `"0.6.0"` and `ikigai-conformance` `"0.14.0"` →
  `"0.15.0"`, their releases on core 0.4.
- Tests that read a refusal's text read it through `Denial::message()`.

Fixes from the second unled audit (ledger #3499), first planned as a patch: one trait method
with a default, and one behavior change that only tightens a stated promise.

- **Generate's "never replaces" was a check-then-act.** It asked whether either name held a
  secret, then wrote each half with `set`, which replaces. A secret stored between the check
  and the write (a Sink by a holder of that name's write scope) was overwritten by a fresh
  private key, and two generates into one name both passed the check and both answered with
  a public half, though only one pair survived on disk. The other caller held an `age`
  recipient (or a verifying key) whose private half was gone, so anything encrypted to it
  could never be decrypted. Generate now writes each half through the new
  **`Backend::create`** (store only if the name is free; `Ok(false)` when taken), and a name
  taken meanwhile is refused as the up-front check refuses it. `tests/audit_3499.rs`.
- **`Backend::create`**: the file store creates exclusively (a hard link, above). The
  default, which the Keychain backend still uses, is `exists` then `set` and is no better
  than before; a Keychain override (`SecItemAdd` refuses a duplicate on its own) needs the
  machine to test. ⚠ A backend that WRAPS another (a recorder, a throttle) must forward
  `create`, or it gets that default.

## 0.4.0

Moves onto ikigai-core 0.3, the scoped content store (ledger #2965): held content is scoped to
whoever delivered it, and `ContentStore::put`/`put_replay` are root-only. This crate calls
neither, so no code changed. Core's types are in this crate's API, so the release is a minor
bump.

- `ikigai-core` `"0.2.0"` → `"0.3.0"`.
- Dev-dependencies: `ikigai-resolve` `"0.2.0"` → `"0.3.0"` (the first on core 0.3) and
  `ikigai-conformance` `"0.12.0"` → `"0.14.0"`.

## 0.3.0

Moves onto ikigai-core 0.2, the streams release (ledger #2261, #2355). Core's types are in
this crate's API (`Endpoint`, `EndpointSpace`, `Error`), so a consumer must be on core 0.2
too: a breaking change under 0.x, so the release is a minor bump. No code changed: core 0.2
builds this crate as it was.

- `ikigai-core` `"0.1.58"` → `"0.2.0"`. The old pin meant `<0.2.0` under 0.x caret rules.
- Dev-dependencies: `ikigai-resolve` `"0.1.28"` → `"0.2.0"` (the first on core 0.2) and
  `ikigai-conformance` `"0.8.0"` → `"0.11.0"`. The conformance walk now also runs DATATYPES
  and FAILURES, and passes both: `secret` has no Turtle face and states no failure classes,
  so neither has anything to judge yet.

## Next slices

- Key rotation under a capability.
- A Keychain `exists` that does not read the item's bytes (today it is the default, a
  `get`, which a foreign-ACL item answers with a prompt), and a Secure Enclave `exists` that
  finds the key by label (today it answers `false`, since an Enclave key has no bytes to
  `get`). Both need the machine to test.
- An atomic Keychain replace (add under a temporary account, delete the old item, rename the
  new one with `SecItemUpdate`): today a Keychain write that fails after its delete loses the
  previous secret. It needs the Keychain to test, so it is an arc run on the machine.
- Secure-Enclave-gated keys for material that must require biometric presence.
- More backends (Linux Secret Service, HSM/YubiKey, external vaults, passkey) — the facade
  is fixed, the backends plug in.
