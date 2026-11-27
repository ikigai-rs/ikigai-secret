# Configurable secret storage, and fnox both ways

Design spike for ledger #3748 (fnox, both directions), widened to the ask behind it: configurable
options for where secrets are stored, as soon as possible. Status: **decided** (Brian, 2026-11-27;
section 9). Section 10's task 1 (stores and routes, ledger #4486) and task 7 (the fnox Lua
plugin's `get`, ledger #4492) are built for 0.5.2, and task 3 (`age-file`, ledger #4488) for
0.5.3; the rest are filed.

References are to this repository at `b083c84` (0.5.1) and to fnox 1.50.0 (released 2026-11-18,
MIT, <https://fnox.jdx.dev>, <https://github.com/jdx/fnox>). The fnox facts below were read from
its documentation, its `Cargo.toml` and docs.rs on 2026-11-27; each is marked with where it came
from.

## 1. The problem

Where a secret is stored is decided in code, not configuration. `default_backend()`
(`src/lib.rs:261`) answers the macOS Keychain on a Mac and the dev file store everywhere else,
and every host calls it: the embedded host (`ikigai-cli/crates/ikigai-embedded/src/lib.rs:2878`,
`:2895`, `:5394`) and gonk (`ikigai-gonk/src/onboard.rs:1053`, `src/main.rs:1876`). So:

- a Linux server or a rented VPS keeps every secret in a plaintext file store, with only file
  modes between it and anyone who reads the disk or a backup;
- an operator who already keeps secrets in 1Password, Vault, a cloud secret manager or a
  password store cannot point ikigai at them;
- a team cannot keep its own secrets in its own store while a person keeps theirs in the
  Keychain.

fnox already speaks to about thirty stores. The point of #3748 was not to compete with it on
breadth. This note uses fnox for breadth and keeps what ikigai adds: per-name capabilities,
refusal before the store is consulted, the presence gate, never caching a secret, and an audit
trail.

## 2. What must not change

These hold whatever store answers. Each is relied on below.

- **The face and its scopes are the same.** `urn:secret:{name}` (and the owner-keyed
  `urn:secret:owner:id:{o}:name:{n}` of `docs/owner-keyed-secrets.md`) keep their verbs and
  their per-name scopes. A caller cannot tell which store answered except through the
  inspection resources in section 4, which are gated.
- **Refused before the store.** Every capability check happens before any store is consulted,
  so an ungranted caller still cannot learn whether a name exists, in any store.
- **Never cached.** A secret read stays uncacheable. A store's own cache (fnox's daemon) is
  outside ikigai and is off by default in what this note configures (section 6.4).
- **The presence gate stays ikigai's.** Unlock, generate and delete ask the host's gate, as
  today. A store's own prompts (Touch ID on fnox's keychain provider, a 1Password sign-in) are
  additional, never a replacement.
- **Hypothesis H.** A module crate never opens a path, a socket or a process by itself. fnox
  does all three (it reads config files up the directory tree, reads environment variables,
  and runs `op`, `aws` and other provider commands). So fnox is reached only from a
  host-role connector crate (section 6.1), never from this crate.

## 3. The model: stores, routes, one owner per name

Configuration names **stores** and **routes**:

- A **store** is one configured backend instance: a kind (`keychain`, `secure-enclave`, `file`,
  `age-file`, `fnox`) plus its settings. Several stores of one kind are allowed (two fnox
  configurations, two file stores).
- A **route** sends a set of secret names to one store, by a glob on the full name. Routes are
  read in order, the first match wins, and `default` takes what no route matches.
- **A name lives in exactly one store.** There is no fallthrough: a miss in the routed store is
  NotFound, never "try the next one". Fallthrough would let a name in an earlier store shadow
  the intended one silently, and would make "where does this secret live" depend on what each
  store happens to hold today, which no one can check before a read.

Owner-keyed names route naturally: `owner:id:acme:name:*` sends one owner's secrets to its own
store. A route never widens a capability; it only says where an already-allowed read goes.

## 4. Resource map

| set | name | kind | how |
|---|---|---|---|
| secret | `urn:secret:{name}`, `urn:secret:owner:id:{o}:name:{n}` | **atom** (unchanged) | the routed store's item; Source, Sink, Exists, Delete as today |
| store | `urn:secret:store` | composition (Source, Meta) | the configured stores: name, kind, whether it can be written, and a sentence on what it is. Never a path, an account, a token or a value. Under `urn:cap:secret:inspect` |
| one store | `urn:secret:store:name:{s}` | composition | the same, for one store, plus a health line (reachable, read-only, signed out). Under `urn:cap:secret:inspect` |
| route | `urn:secret:route` | composition | the ordered routes and the default, as data. Under `urn:cap:secret:inspect` |
| where a name lives | `urn:secret:route:secret:{name}` | tiny function | the store a name routes to, from the route table alone, never by asking a store (so it reveals nothing about existence). Under the name's own read scope |

The stores and routes are configuration, read once by the host at start (section 5), so the
inspection compositions are cacheable and hang from the configuration's thread; a reload cuts
it. A secret read stays uncacheable.

Code is needed only for the stores themselves (each is a `Backend`, the trait in
`src/lib.rs:66`) and one routing `Backend` that picks the store by name. The routing is a pure
function of the name and the route table.

## 5. Configuration

A `[secret]` section in the config home's `config.toml`, read by the host, which builds the
stores and hands this crate a routing backend. Nothing is read from the environment
(the config-home rule); `IKIGAI_SECRETS` keeps working for one release as the file store's path
when there is no `[secret]` section (section 8).

```toml
[secret]
default = "keychain"

[secret.store.keychain]
kind = "keychain"              # macOS only; refused at start elsewhere
service = "ikigai-secret"

[secret.store.server]
kind = "age-file"               # a file store whose items are age-encrypted at rest
path = "~/.ikigai/secrets"
identity = "keychain:age-host"  # where the age identity comes from (section 6.3)

[secret.store.team]
kind = "fnox"
config = "~/work/acme/fnox.toml"   # one file, never the upward search
profile = "prod"
write = false                       # read-only until section 6.2's writes are built
names = "map"                       # ikigai names to fnox keys, one to one (section 6.1)

[secret.store.team.map]
"zoom.client-secret" = "ZOOM_CLIENT_SECRET"

[[secret.route]]
match = "owner:id:acme:name:*"
store = "team"

[[secret.route]]
match = "zoom.*"
store = "team"
```

The host refuses to start, with a sentence naming the line, when the section is malformed: an
unknown kind, a route to a store that is not configured, a `keychain` store off macOS, a
default that names nothing, two routes with the same match, or a fnox store whose `config` is
missing. A wrong configuration is never half-applied.

## 6. The stores

### 6.1 fnox as a store behind ikigai (read)

A connector crate, `ikigai-secret-fnox`, implements `Backend` over fnox's library. fnox
publishes one: crate `fnox` 1.50.0 exposes `Fnox::open(path)`, `with_profile(..)`,
`async fn get(&self, key) -> Result<Option<String>, FnoxError>` and `fn list()`
(docs.rs, `fnox::library`). Its module docs say the first cut covers `get` and `list`, and that
`set` is a follow-up.

- **One file, never the search.** The store uses `Fnox::open(config)`, which loads one file and
  its imports. It never uses `Fnox::discover()`, which walks every directory from the root down
  to the working directory and merges whatever `fnox.toml` it finds there. A host's working
  directory must not decide where its secrets come from.
- **Name mapping must be one-to-one.** fnox keys match `^[A-Za-z_][A-Za-z0-9_]*$` (fnox
  configuration reference); ikigai names carry `.`, `-` and `:`. A lossy mapping is a
  capability hole: if `a.b` and `a-b` both became `A_B`, a caller allowed to read `a-b` would
  read the fnox secret meant for `a.b`, which it holds no scope for. So only two mappings are
  offered:
  - `names = "map"` (the default): an explicit `[secret.store.<s>.map]` table from ikigai name
    to fnox key. A name the table does not list is NotFound. The configuration is refused at
    start when two names map to one key.
  - `names = "escaped"`: an injective transform. ASCII letters and digits pass through, and
    every other character, `_` included, becomes `_` and two hex digits (`.` is `_2E`, `_` is
    `_5F`), so no two names meet. It suits a fnox file written for ikigai, not one a team
    already keeps.
- **Absence.** A key fnox does not declare (`SecretNotFound`) and a declared key that resolves to
  nothing (`Ok(None)` under fnox's `if_missing = warn|ignore`) are both ikigai's NotFound.
- **Never interactive.** fnox prompts to sign in (`prompt_auth`, default true) and offers each
  provider's `auth_command`. A host has no terminal, so the store runs fnox non-interactively
  and turns an authentication failure into a refusal that names the store and says how to sign
  in at the box (for 1Password, `op signin`). **Open:** the library documentation does not say
  how to turn prompting off from the API; the binary has `--non-interactive` and
  `FNOX_NON_INTERACTIVE`. The first build must find the library's switch, or set it in the
  fnox file the store loads (`prompt_auth = false`), and test that a signed-out provider refuses
  rather than waits.
- **Dependencies.** `fnox` is edition 2024 with `rust-version = 1.91.1`, and its default
  features pull the AWS, Azure, GCP, Keeper, Kubernetes, Enpass and FIDO2 SDKs (its
  `Cargo.toml`). The connector depends on it with `default-features = false` and re-exports
  those as its own opt-in features, so a host builds only the providers it uses.
- **Errors.** A provider failure is a refusal naming the store and the provider kind, never the
  key's value and never fnox's raw error text when that text can carry a value or a token.

### 6.2 fnox writes

The library has no `set` yet. Until it does, a store with `write = true` writes through the
`fnox set --provider <p> <KEY>` command with the value on **standard input**, never in the
arguments (fnox's own `set` page warns that an argument value shows in process listings). This
is a process, so it too lives only in the connector. A `Sink` or `Delete` on a name routed to a
read-only store is refused as Conflict ("the store `team` is read-only"), after every capability
check. Many fnox providers are read-only by nature (1Password, Bitwarden, Doppler, Kubernetes,
and others, per fnox's provider overview); for those, `fnox set` records a reference, not a
secret, which is never what an ikigai `Sink` means, so the store refuses writes for them even
with `write = true`.

### 6.3 An encrypted file store, `age-file`

The quickest real improvement for a Linux server: the file store, with each item encrypted to an
age recipient at rest, using the `age` crate as `ikigai-encrypt` does. The identity is itself a
secret, named in the configuration: in the Keychain on a Mac, and on Linux in a file readable
only by the service account, or a hardware key through an age plugin. This removes "anyone who
reads the disk or a backup reads every secret" while changing nothing else. A store whose items
are mixed (some plaintext from before) reads both and writes only encrypted (section 8).

### 6.4 What fnox's daemon and leases mean here

fnox's daemon caches resolved values in memory, per user (fnox daemon guide). ikigai never
caches a secret, so the configuration this note writes sets no daemon, and the store's
documentation says what enabling one would mean. fnox leases (short-lived AWS STS, Vault,
GitHub and similar credentials, fnox leases guide) are out of scope for the first build: a lease
is minted, not stored, and belongs with the egress credential door (ledger #3745).

## 7. ikigai as a fnox provider (the other direction)

fnox loads Lua 5.4 provider plugins (`type = "lua"`), which must define `get(ctx, ref)` and may
define `put`, `get_batch`, `encrypt` and `test`; a plugin reaches commands through `fnox.cmd`
(fnox Lua provider docs). A plugin, `contrib/fnox/ikigai.lua` in this repository, resolves a
fnox secret through ikigai: `get` runs `ikigai --quiet -c 'source urn:secret:<ref>'` against the
local host's socket, so a fnox user gets ikigai's per-name capabilities, presence gate and audit
for the secrets fnox reads through it. The capability is whatever the `ikigai` command's identity
holds; the plugin grants nothing. `put` (a `sink` with the value on standard input) comes after
`get`, once the plugin's `fnox.cmd` is shown to pass standard input without an argument. fnox's
docs say a plugin runs with the user's permissions and is not sandboxed; the plugin's README says
so too.

## 8. Upgrade from older versions

- **No `[secret]` section, existing install** (every install today): the host builds exactly
  what `default_backend()` builds now, the Keychain on a Mac and the file store elsewhere, with
  `IKIGAI_SECRETS` still honored for the file store's path, so nothing moves. A one-line notice
  at start says `age-file` is now the default for new installs, how to move to it, and that
  `IKIGAI_SECRETS` is deprecated. "Existing" is decided by what is there: a file store directory
  with entries, or (on a Mac) any item under the `ikigai-secret` Keychain service.
- **No `[secret]` section, new install:** an `age-file` store at the data home's
  `secrets` directory, its identity held as `docs/unattended-unlock.md` says.
- **Adding a section** never moves a secret. A name newly routed to another store is NotFound
  there until it is copied. Copying is an explicit operation,
  `urn:secret:store:name:{to}:copy from={store} name={name}`, under the name's read scope, the
  write scope and the presence gate, which never deletes the source. A copy into a read-only
  store is refused.
- **`file` to `age-file` in place:** the store reads a plaintext item as today and re-encrypts it
  on its next write; a `reencrypt` operation does all of them, idempotently, one item at a time
  (temporary file and rename, as the file store already writes), after a backup copy of the store
  directory, with one line per item.
- Tests start the new code on a store written by 0.5.1 (and by 0.4.x, whose layout is the same)
  with no section, and with a section that routes some names elsewhere.

## 9. Decisions (Brian, 2026-11-27)

1. **Configuration in the config home**, `[secret]` with `store.*` tables and ordered `route`s,
   as in section 5. Accepted.
2. **One store per name, no fallthrough** (section 3). Accepted.
3. **fnox through its library for reads, its command for writes** (6.1, 6.2). Accepted.
4. **The connector is a subcrate**, `crates/ikigai-secret-fnox` in this repository, which becomes
   a workspace. Accepted.
5. **`age-file` is the default store.** With no `[secret]` section, a NEW install (no store yet:
   no Keychain items under the service and no file store directory) gets an `age-file` store, on
   every platform. An existing install keeps the store it has, unchanged, until its operator
   copies its secrets over (section 8); the host says once at start that `age-file` is now the
   default and how to move. Where the age identity is held is the companion design,
   `docs/unattended-unlock.md`.
6. **Name mapping for fnox stores:** an explicit `map` table by default, with the injective
   `escaped` transform as the only alternative (6.1). A lossy transform is ruled out. Accepted.

## 10. Tasks, in the order that gets configurable storage soonest

1. **Stores and routes in ikigai-secret** (no I/O in the crate: the host passes the parsed
   section). A `RoutingBackend` over named stores, the section's parser and its refusals,
   `keychain` / `secure-enclave` / `file` as kinds, the inspection resources of section 4 under
   `urn:cap:secret:inspect`, and the no-section path identical to today. Patch release (additive).
2. **Host wiring** in the embedded host and gonk: read `[secret]` from the config home, build the
   stores, mount `space(routing)`; refuse to start on a bad section. One item per host.
3. **`age-file`** (6.3), with the in-place upgrade and `reencrypt`.
4. **`ikigai-secret-fnox`, read-only** (6.1): library, one file, one-to-one name mapping (with a
   test that two names never reach one key), absence,
   non-interactive (with the open question settled by a test), opt-in provider features.
   Tests run offline on a fixture `fnox.toml` using fnox's `age` and `plain` providers.
5. **fnox writes** through `fnox set` on standard input (6.2), opt-in per store.
6. **`urn:secret:store:name:{to}:copy`** (section 8).
7. **The Lua plugin** (section 7), `get` first, with a test that resolves through a test host.
8. **An ikigai-log line per secret read, write and delete**: the name, the store, the principal,
   never the value.
9. **The Operations book:** a "Where secrets live" page with the section, the stores and the
   upgrade steps, every shell block a CI-run transcript.
