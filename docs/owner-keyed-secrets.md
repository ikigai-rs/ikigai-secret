# Owner-keyed, grant-scoped secrets

Design spike for ledger #3750, informing the build in ledger #3743 under the organizational-grants
epic (ledger #3736). Status: **proposed**. Nothing here is built; the decisions at the end are
Brian's.

Line references are to this repository at `7ac5fc4` and to `ikigai-core` 0.3.0, the manifest's
floor. A fresh resolve (what CI builds) takes 0.3.5: its `capability.rs` and `grammar.rs` are
identical, and the cited `select.rs`, `alias.rs`, `error.rs` and `kernel.rs` passages move by a
few lines without changing. `tests/owner_keyed_facts.rs` pins the facts this design rests on,
and passes on both; each is marked **(pinned)** where it is used.

## 1. The problem

`ikigai-secret` serves capability-gated secret custody as one flat set: `urn:secret:{name}`
(`src/lib.rs:333-336`), gated per name by `urn:cap:secret:{read,write,delete}:<name>`
(`src/lib.rs:508`, `:528`, `:552`, `:569`). This has two gaps.

1. **The name breaks the naming rule.** The rule is: singular, type first, every partition by a
   named key. `urn:secret:{name}` partitions the secret set by an unnamed value.
2. **There is no owner.** An organization has many owners: people, teams, repositories,
   release trains. Today every secret on a host lives in one namespace (on a Mac, one Keychain
   service, `src/lib.rs:264`). So "a worker on repository R reads R's deploy token" and "the
   release manager reads the publish token" can only be told apart by name conventions that no
   one enforces.

The grants model (ledger #3736) supplies roles, assignments, delegation that only narrows, and
kinds of work. This document says what this module must name and enforce so those roles can
grant secrets precisely, so revocation means something, and so release and publish secrets stay
away from agents. It also says how to get there from the published 0.4.0 without breaking
anyone.

## 2. What exists today

All of these are relied on below.

- **Refused before the keystore.** Each verb checks its exact per-name scope with
  `Capability::allows` before touching the backend (`src/lib.rs:508-517`). So an ungranted
  caller cannot learn whether a name exists (`tests/conformance.rs:446`).
- **Declared floors are family wildcards.** The actions declare `urn:cap:secret:read:*`,
  `write:*` and `delete:*` (`src/lib.rs:628`, `:635`, `:647`, `:657`). The kernel tests these as
  a PRESENCE test: "holds some scope under this prefix" (`ikigai-core` `select.rs:811-819`).
- **Never cached.** Every read reaches the keystore (`src/lib.rs:518-523`;
  `tests/conformance.rs:413`). Anything derived from a secret inherits that, because effective
  expiry is the most restrictive of the dependencies' expiries (`ikigai-core`
  `kernel.rs:5032-5047`).
- **`allows` is exact.** No trailing or infix wildcard on a held scope (`ikigai-core`
  `capability.rs:546-555`). **(pinned)**
- **The `-` rule.** A name beginning with `-` is refused at every face (`src/lib.rs:467-481`,
  `src/file.rs:149`), because in `urn:cap:secret:read:<name>` the name sits where
  `is_deny_scope` reads an exclusion (`ikigai-core` `capability.rs:179-195`).
- **The presence gate.** Delete, unlock and generate ask the presence gate after every
  capability check (`src/lib.rs:579`, `:681`, `:831`). Off macOS the platform gate is a no-op
  (`src/lib.rs:404-408`).
- **Consumers spell scopes and names themselves.** ikigai-meeting builds
  `urn:cap:secret:read:{name}` itself (`ikigai-meeting/src/lib.rs:565`). gonk's onboarding
  builds generate's three scopes (`ikigai-gonk/src/onboard.rs:2849-2851`). cms-web reads
  `urn:secret:zotero-api-key` (`ikigai-cms-web/src/zotero.rs:199`).
- **No door serves secrets.** gonk links this crate for its controller key and "never serves
  `urn:secret:*` at any door" (`ikigai-gonk/Cargo.toml:1384-1387`). Secrets are read inside a
  host (the cli, cms-web), under capabilities that host mints from its own configuration.

## 3. The resource map

| name | kind | holds | verbs |
|---|---|---|---|
| `urn:secret` | the set of all secrets | unbound; named by the rule, read by nobody | none |
| `urn:secret:owner` | the set partitioned by owner | unbound | none |
| `urn:secret:owner:id:{owner}` | one owner's secrets | unbound (no backend can list a keystore today, see 3.4) | none |
| `urn:secret:owner:id:{owner}:name:{name}` | **atom**: one secret's bytes | the keystore item | Source, Sink, Exists, Delete |
| `urn:secret:owner:id:{owner}:policy` | **atom**: the owner's classification (name to kind of work) | a small document | Source, Sink |
| `urn:secret:unlock` | operation (presence) | nothing | Source (unchanged) |
| `urn:secret:generate` | operation (mint a keypair into two atoms) | nothing of its own | Source |
| `urn:secret:{name}` | **legacy alias** for `urn:secret:owner:id:{legacy}:name:{name}` | nothing of its own | as the atom, for one release |

Only two kinds of atom hold state: a secret and an owner's policy. Everything else is an
operation over atoms or an alias of one. No composition needs code.

### 3.1 Binding order

A space resolves the first match, and `urn:secret:{name}` matches every IRI under
`urn:secret:`, new-form names included **(pinned:
`the_legacy_template_takes_a_new_form_name_whole`)**. So the order is fixed:

1. `urn:secret:unlock`, exact (as today)
2. `urn:secret:generate`, exact (as today)
3. `urn:secret:owner:id:{owner}:name:{name}`
4. `urn:secret:owner:id:{owner}:policy`
5. `urn:secret:{name}`, the legacy alias (removed after the window)

### 3.2 Parsing is unambiguous only if an owner id cannot contain `:`

`UriTemplate` gives each `{var}` the run up to the leftmost next literal that lets the rest
match (`ikigai-core` `grammar.rs:102-108`). The template's last variable takes the remainder. So in
`urn:secret:owner:id:{owner}:name:{name}`, the owner is everything before the first `:name:`. A
name spelled `x:owner:id:acme:name:deploy-token` under owner `legacy` stays owner `legacy`'s name
**(pinned: `the_proposed_template_captures_the_owner_as_the_first_segment`)**.

This holds only if no owner id contains `:name:`, and the simple rule that guarantees that
is:

- **An owner id** matches `[a-z0-9][a-z0-9._-]{0,63}`: lowercase, no `:`, no leading `-` or
  `.`, at most 64 bytes. Anything else is `InvalidArgument { name: "owner" }`, refused before
  any capability check.
- **A name** is any non-empty string, with two exceptions:
  - It may not begin with `-`. The rule stays, so every face answers alike (see decision 6).
  - It may not begin with `owner:`. The legacy alias and the storage key need that prefix
    reserved (3.5, 6.3).

Both name refusals are `InvalidArgument { name: "name" }`, refused before any capability check.

The policy template (4) can only match an IRI that the secret template (3) did not, because
an IRI with a `:name:` after the owner is a secret. With `:` banned from owner ids, `…:policy`
always means owner `{owner}`'s policy.

### 3.3 What an owner id names

The module treats an owner id as opaque. The organization tree (ledger #3749) gives it meaning:
a person (`brian`), an organization (`ikigai-rs`), a repository (`ikigai-secret`), or a release
train. One id space keeps scopes short and lets a role template take the owner as a parameter.
See decision 2.

### 3.4 The sets stay unbound

The naming rule asks for the set names. Serving them means listing a keystore, and `Backend`
has no list operation (`src/lib.rs:66-131`). A listing would also disclose names to anyone who
holds a read scope for one secret. They are reserved and unbound until a design for listing
exists.

### 3.5 Storage keys

The backend trait is unchanged: one string key per secret (`src/lib.rs:66-72`). The endpoint
computes the key:

- For owner `{owner}`, name `{name}`: `owner:id:{owner}:name:{name}`, the IRI minus
  `urn:secret:`.
- For the **legacy owner** (6.1), during and after the window: the bare `{name}`, so existing
  Keychain items and file-store files are reached unchanged and nothing moves. Moving a
  Keychain item is the non-atomic delete-then-set (`src/lib.rs:935-947`), so a data migration is
  a real risk avoided, not a convenience.

The file store escapes `:` as `%3a` (`src/file.rs:139-161`), so the new keys are ordinary file
names. The Keychain account is the key verbatim (`src/lib.rs:910-913`).

Today's 0.4.0 already keys a new-form IRI by exactly this path and checks exactly the scope in
section 4 **(pinned: `a_new_form_iri_already_resolves_with_the_proposed_scope_and_storage_key`)**.
So a 0.4.0 host and a 0.5.0 host agree, IRI to scope to keystore item, for every owner except
the legacy owner. That means a mixed fleet is safe during rollout.

## 4. Capabilities

### 4.1 The spelling

**One derivation rule: `urn:cap:secret:{verb}:{path}`, where `{path}` is the resource IRI minus
`urn:secret:`.**

| resource | verb | scope |
|---|---|---|
| `urn:secret:owner:id:{o}:name:{n}` | Source, Exists | `urn:cap:secret:read:owner:id:{o}:name:{n}` |
| `urn:secret:owner:id:{o}:name:{n}` | Sink | `urn:cap:secret:write:owner:id:{o}:name:{n}` |
| `urn:secret:owner:id:{o}:name:{n}` | Delete | `urn:cap:secret:delete:owner:id:{o}:name:{n}` |
| `urn:secret:owner:id:{o}:policy` | Source | `urn:cap:secret:read:owner:id:{o}:policy` |
| `urn:secret:owner:id:{o}:policy` | Sink | `urn:cap:secret:write:owner:id:{o}:policy` |

The rule is the same one 0.4.0 applies to `urn:secret:{name}`. Only the shape of the path
changes. The brief suggested `urn:cap:secret:read:<owner>/<name>`; this spelling is better for
four reasons:

1. **The parameter goes last, as core requires.** Core has no infix wildcard
   (`capability.rs:546-551`), so the verb comes before the path. The declared floors
   (`urn:cap:secret:read:*` and the others) are unchanged, and every new scope satisfies them
   **(pinned: `allows_is_exact_and_the_declared_floor_is_a_presence_test`)**.
2. **No owner or name can be deny-shaped.** The rule part of every new scope begins with the
   literal `owner:`, so `is_deny_scope` never reads an exclusion, whatever the owner or the
   name begins with **(pinned: `no_new_form_scope_is_deny_shaped`)**. The hazard behind the `-`
   rule is gone by construction for new names.
3. **The scope reads as the resource.** One mechanical function maps IRI to scope, the same in
   this module, in a role template and in a grant file. The `/` spelling would add a second
   separator and a second escaping question: a name containing `/`.
4. **Owner scopes cannot collide.** Owner ids exclude `:`, so `owner:id:{o}:name:{n}` is
   injective in `(o, n)`, and a policy path never equals a secret path.

### 4.2 Declared and enforced, per action

| action | declares (kernel floor) | enforces at invoke, in order |
|---|---|---|
| secret Source | `urn:cap:secret:read:*` | owner and name well-formed, exact read scope, then the kind rule (5), then the keystore |
| secret Exists | `urn:cap:secret:read:*` | as Source (the kind rule too: whether a publish token exists is still a release fact) |
| secret Sink | `urn:cap:secret:write:*` | owner and name well-formed, exact write scope, then the keystore |
| secret Delete | `urn:cap:secret:delete:*` | owner and name well-formed, exact delete scope, presence gate, then the keystore |
| policy Source | `urn:cap:secret:read:*` | owner well-formed, exact policy read scope |
| policy Sink | `urn:cap:secret:write:*` | owner well-formed, exact policy write scope, document well-formed |
| generate | `urn:cap:secret:generate`, `urn:cap:secret:write:*` | `owner` and `into` well-formed, `urn:cap:secret:generate`, exact write scope of `{into}` and `{into}.pub` under `owner`, free names, presence gate, exclusive create |
| unlock | `urn:cap:secret:unlock` | unchanged |

`generate` gains a required `owner=` argument beside `into=` and keeps its current shape
otherwise (`src/lib.rs:765-847`). `urn:cap:secret:generate` stays unparameterized. The owner
scoping comes through the two write scopes, which already name the owner.

### 4.3 No wildcard grants in this release

A role grants **exact** scopes. A role template expands its parameters into concrete strings,
and attenuation intersects sets of concrete strings (`capability.rs:387-418`), so narrowing
delegation works with no new matching.

An owner-wide grant (`…:owner:id:acme:name:*`) would need this module to interpret its own
wildcard grammar, as ikigai-fs does for path prefixes, because `allows` will not
**(pinned)**. It would also silently cover every secret created under the owner later. That is
a widening nobody proposed, which the grants model's "widening needs a second person" exists to
stop. See decision 3.

## 5. Roles grant sets of secret scopes

Roles are ledger #3749's data. This module only needs a role to expand to the scopes above.
Two examples, written as templates:

```text
role repository-worker(repo)           # a worker on repository R reads R's deploy token
  urn:cap:secret:read:owner:id:{repo}:name:deploy-token

role release-manager(org)                   # the release manager reads the publish token
  urn:cap:secret:read:owner:id:{org}:name:crates-io-publish-token
  kind of work: publish                     # person principals only, see 5.1
```

Assigning `repository-worker(ikigai-secret)` to a worker gives exactly
`urn:cap:secret:read:owner:id:ikigai-secret:name:deploy-token`. The assignment's window, owner,
reason and approver live with the assignment, not here.

### 5.1 The kind-of-work rule: release and publish secrets never reach an agent

There are two lines of defense, and this module owns the second.

1. **In the grants layer** (ledger #3741 and #3749): a role carrying a `release` or `publish`
   kind can be assigned only to a person principal. A proposal that assigns it to an agent is
   refused there. That is the line that matters, and it is not this module's.
2. **At the secret, as defense in depth**: the owner's **policy** atom classifies names into
   kinds. A read or exists of a name classified `release` or `publish` also requires that the
   caller is a person. Otherwise the answer is `Denied`, naming the kind and what is missing:

   ```text
   reading `crates-io-publish-token` of `ikigai-rs` is publish work, which only a person may do;
   this request is not from a person
   ```

   It is checked after the exact scope, so only a holder of the read scope learns the kind, and
   before the keystore.

**How the module knows "a person".** It cannot know it from the capability alone. The principal
scope says who a request is FOR (`capability.rs:208`, `:452`), not whether a person or an agent
is acting. The module therefore takes a host-injected classifier, like the presence gate
(`src/lib.rs:353-365`):

```rust
pub trait PrincipalClass: Send + Sync {
    /// Whether `capability`'s principal is a person, as the host's door authenticated it.
    fn is_person(&self, capability: &Capability) -> bool;
}
```

- The default answers `false` for every scoped capability and `true` only for root (the host's
  own authority). So a host that wires nothing gets the safe answer: classified secrets are
  readable only by root.
- gonk answers from the identity its door authenticated: a passkey principal is a person
  (`urn:iki:gonk:passkey:…`, `ikigai-gonk/tests/doors.rs:691`), and a machine client
  certificate is not.

**What this does not stop**, stated plainly:

- **A person's own agent working in-process under the person's capability.** That agent carries
  the person's principal. The boundary that holds is the DOOR: an agent that connects as itself
  authenticates as a machine. And `clamp` keeps the ceiling's principal whatever the client
  carried (`capability.rs:433-449`), so it cannot claim the person's. The rule is only as good
  as the host's habit of giving agents their own door identity, which is the grants layer's job.
- **The presence gate is not a person proof.** It would be a natural extra check on a Mac, but it
  is a no-op everywhere else (`src/lib.rs:404-408`), so it cannot be the rule. See decision 5.

**The policy document** is a small mapping. Its format is decision 4; the recommendation is
Turtle with SKOS kinds, so the kind IRIs are the work-kind taxonomy's own:

```turtle
<urn:secret:owner:id:ikigai-rs:name:crates-io-publish-token>
    <https://ikigai-rs.dev/ns#workKind> <https://ikigai-rs.dev/ns/kind#publish> .
```

The policy is cacheable: it is a pure document. A Sink cuts its thread, so the next secret read
sees a reclassification. Reading the policy does not make a secret read cacheable, because the
secret read was never cacheable. An absent policy classifies nothing. A policy that cannot be read
(a store error) fails CLOSED: the secret read answers `Endpoint` and reads nothing.

## 6. Revocation is on the next request

### 6.1 Why it is the next request

Three properties together give this:

1. **The scope is checked on every invocation**, against the capability that request carries
   (`src/lib.rs:508-513`).
2. **No secret read is cached** (`src/lib.rs:518-523`), and neither is anything derived from one
   (`kernel.rs:5032-5047`). The cache also partitions by capability, so even a cacheable answer is
   never served to a capability that did not earn it.
3. **The door re-reads the grant per request.** That is the host's half, and it is the half that
   does not exist yet for secrets: no door serves them (`ikigai-gonk/Cargo.toml:1384-1387`).
   Today the "door" is a host minting a capability from its configuration. Revocation there
   takes effect when the host re-mints: a restart, or a configuration reload if the host has one.
   For ledger #3743 this is the first build question (see 9).

Compare a recipient list (an `age` file encrypted to a team): removing a member does not stop
them decrypting the ciphertext they already hold. Here no ciphertext is handed out. Every read
is a fresh decision.

### 6.2 What revocation does not cover

- **A value already read.** Bytes in a process's environment, a file, a shell history, a log,
  an LLM's context, or a delegate's memory stay there. Revocation stops the next read, not the
  last one. The remedy is ROTATION, and rotation needs to know who read what. That is the
  host's per-request trace (`Kernel::issue_traced` with ikigai-log's principal column); this
  module emits no log of its own.
- **What a secret already made.** An access token minted from a client secret, a signature made
  with a key, or a session opened with a password stays valid until it expires or is revoked
  where it lives.
- **A capability held past the request.** A scheduled job's recorded capability, or a session
  that mints once at connect and reuses the result, revokes at re-mint, not at the next request.
- **Copies of the keystore.** Backups and offsite copies are outside every scope.

## 7. Migration from 0.4.0

### 7.1 The release

**0.5.0**, a minor bump: the API gains arguments and a trait, and the default space's binding
changes. The space takes a **legacy owner**, a host-configured owner id (for example the
operator's own, `brian`). Every legacy name belongs to that owner.

### 7.2 The legacy alias is the module's binding, not a core alias

Core's alias table cannot express this migration. The old namespace `urn:secret:` is a prefix of
the new one, so a prefix rule `urn:secret:` → `urn:secret:owner:id:{legacy}:name:` rewrites its own
output until the hop limit, and every name is refused, old and new
**(pinned: `a_core_prefix_alias_from_the_old_namespace_to_the_new_refuses_every_name`)**.

Exact rules would work, but they need every legacy name listed in advance, and no backend can
list them (3.4). So the legacy face is binding 5: the `urn:secret:{name}` template, served by the
same endpoint with the owner fixed to the legacy owner.

Core's alias rules still frame it:

- **Authority is checked against the backing resource.** Core rewrites before the capability check
  (`ikigai-core` `alias.rs:68-84`).
- **The catalog lists the new name.** It lists the backing name once (`alias.rs:115-127`). Binding 5
  is described as an alias of binding 3, so `urn:kernel:actions` offers only the new names.

### 7.3 Old grants during the window

Core never rewrites capability scopes to follow a name (`alias.rs:81-84`): migrating grants is
an explicit act by whoever mints them. So the window has two halves:

- **The grant files migrate mechanically.** Rewrite `urn:cap:secret:{v}:{n}` to
  `urn:cap:secret:{v}:owner:id:{legacy}:name:{n}`. In the grants model this is one proposal
  with a diff that changes no effective authority.
- **For one release the endpoint also honors a legacy scope, for the legacy owner only.** A
  request for (`{legacy}`, `{n}`), through either IRI, passes with
  `urn:cap:secret:{v}:{n}` as well as the new scope. A legacy scope never authorizes any other
  owner. Without this, every host breaks the moment it upgrades and stays broken until its grants
  file is rewritten. That is the flag day the alias exists to avoid.

**One residue.** On 0.4.0 a host could have granted a flat name beginning with `owner:`, for
example `urn:cap:secret:read:owner:id:acme:name:x`. After the upgrade that string means acme's
`x`. A preflight in the host's upgrade refuses to start while its grants hold any
`urn:cap:secret:*:owner:…` scope, and names each one.

### 7.4 Consumers

During the window every consumer keeps working, because its names are legacy names of the
legacy owner. After it, three consumers change:

- ikigai-meeting's own scope string (`ikigai-meeting/src/lib.rs:565`)
- gonk's onboarding scopes (`ikigai-gonk/src/onboard.rs:2849-2851`)
- cms-web's IRI (`ikigai-cms-web/src/zotero.rs:199`)

To stop the spelling being re-implemented, this crate exports the derivation:

```rust
pub fn secret_iri(owner: &str, name: &str) -> Result<Iri>;
pub fn secret_scope(verb: SecretVerb, owner: &str, name: &str) -> Result<String>;
```

Both validate their inputs as section 3.2 says. Consumers call these instead of `format!`.

### 7.5 The changelog entry (0.5.0)

```markdown
## 0.5.0

### Added
- Owner-keyed secrets: `urn:secret:owner:id:{owner}:name:{name}`, scoped
  `urn:cap:secret:{read,write,delete}:owner:id:{owner}:name:{name}`.
- An owner's policy, `urn:secret:owner:id:{owner}:policy`, classifying names into kinds of work;
  `release` and `publish` names are readable only by a person (`PrincipalClass`).
- `generate` takes `owner=`. `secret_iri` and `secret_scope` build names and scopes.

### Deprecated (removed in 0.6.0)
- `urn:secret:{name}`: now an alias for the configured legacy owner's
  `urn:secret:owner:id:{legacy}:name:{name}`, and the legacy scope `urn:cap:secret:{verb}:{name}`,
  honored for the legacy owner only. Migrate grants with the mechanical rewrite in
  docs/owner-keyed-secrets.md section 7.3.

### Changed
- A name may not begin with `owner:`. A host whose grants hold a `urn:cap:secret:*:owner:` scope
  is refused at startup (see section 7.3).
```

0.6.0 removes binding 5 and the legacy-scope acceptance. Storage keys for the legacy owner stay
bare names (3.5), so removing the alias moves no data.

## 8. Refusals

Every refusal comes before the keystore unless the table says otherwise.

| case | answer | when |
|---|---|---|
| owner id malformed (empty, `:`, uppercase, too long, leading `-` or `.`) | `InvalidArgument { name: "owner" }` | before the capability check |
| name begins with `-` or `owner:` | `InvalidArgument { name: "name" }` | before the capability check |
| no scope under the declared family | `Denied` (the kernel, naming the wildcard) | before the endpoint runs |
| no exact scope for this owner and name | `Denied`, naming the exact scope | before the keystore, identical for present and absent secrets |
| a `release` or `publish` name, caller not a person | `Denied`, naming the kind | after the scope, before the keystore |
| policy unreadable | `Endpoint` (fail closed) | after the scope, before the keystore |
| secret absent | `NotFound` | after the scope and the kind rule |
| generate into a name that holds a secret | `Conflict` (see decision 7) | before the presence prompt, and again at the exclusive create |
| presence refused (Delete, generate) | the gate's error, normally `Denied` | last, with nothing changed |
| policy document malformed on Sink | `InvalidArgument { name: "content" }` | before the store |

**Cacheable:** the policy atom only. A secret Source or Exists, generate, unlock and every
refusal stay uncacheable, as today.

## 9. What this changes for ledger #3743's build

1. **There is no door for secrets yet.** "Revocation at the door" assumes a door that re-reads a
   principal's grant on every request. gonk does not serve `urn:secret:*`
   (`ikigai-gonk/Cargo.toml:1384-1387`), and hosts mint from their configuration. So the build
   either adds a secret door to a host that re-reads grants per request, or states that revocation
   happens at re-mint. The test "after revocation the next read is denied" is only true of the
   first.
2. **The alias cannot be a core `AliasTable` rule** (7.2). The build binds the legacy template
   itself.
3. **"A person, never an agent" needs a principal classifier from the host** (5.1). It cannot be
   read from a capability today. If more modules than this one need it, a door-minted actor-class
   scope in core (beside `urn:cap:principal:`) is the better home. That is a core design question,
   reported up rather than decided here.
4. **Consumers spell scopes by hand** (7.4). The build exports the derivation and the migration
   moves three consumers onto it.

## 10. Tests that would prove it

Already pinned in `tests/owner_keyed_facts.rs` (true today):

- `a_new_form_iri_already_resolves_with_the_proposed_scope_and_storage_key`
- `the_legacy_template_takes_a_new_form_name_whole`
- `the_proposed_template_captures_the_owner_as_the_first_segment`
- `a_core_prefix_alias_from_the_old_namespace_to_the_new_refuses_every_name`
- `allows_is_exact_and_the_declared_floor_is_a_presence_test`
- `no_new_form_scope_is_deny_shaped`

For the build (each over a recording backend, so "before the keystore" is checked by an empty
call log):

- **Roles.** A principal holding `repository-worker(ikigai-secret)`'s expansion reads
  that deploy token, and is `Denied` for another repository's, with the keystore untouched.
- **Revocation.** The same host issues a read under the role's capability (bytes), then under the
  capability re-minted without it (`Denied`), with no cache entry between them.
- **Alias isolation**, the brief's test. Under every grant a test can build (root, the legacy
  owner's legacy scopes, the legacy owner's new scopes), no request through `urn:secret:{name}`
  ever reaches a storage key under another owner. In particular:
  - `urn:secret:owner:id:acme:name:x` is routed to binding 3, not the alias.
  - A legacy scope `urn:cap:secret:read:{n}` is `Denied` for (`acme`, `{n}`).
  - A legacy name beginning with `owner:` is refused as `InvalidArgument`.
  - A name `x:owner:id:acme:name:y` under the legacy owner keys `owner:id:{legacy}:name:…`
    storage, or the bare name for the legacy owner, and never acme's.
- **Kind rule.** A name classified `publish` is `Denied` to a scoped capability under the default
  classifier and to a machine principal under a classifier that knows it, and readable by a person
  principal. A reclassification by policy Sink takes effect on the next read (the policy's thread
  is cut). An unreadable policy fails closed.
- **Window.** A legacy scope reads the legacy owner's secret through both IRIs, and the same test
  fails against a build with the window closed.
- **Conformance.** `ikigai-conformance` walks all five bindings, with the policy declared
  cacheable and the secret declared live.

## 11. Decisions for Brian

1. **The name and scope spelling.** Recommendation: `urn:secret:owner:id:{owner}:name:{name}`,
   with scopes `urn:cap:secret:{verb}:owner:id:{owner}:name:{name}` (the IRI's path after the
   verb, one derivation rule), rather than `urn:cap:secret:{verb}:<owner>/<name>`. Reasons in 4.1:
   the parameter goes last, no scope can be deny-shaped, and the scope reads as the resource.
2. **What an owner id names.** Recommendation: one opaque id space, `[a-z0-9][a-z0-9._-]{0,63}`,
   whose meaning (person, organization, repository, release train) comes from the organization
   tree, not from this module.
3. **Owner-wide wildcard grants.** Recommendation: not in 0.5.0. Roles expand to exact scopes. A
   module-interpreted `…:name:*` would silently cover secrets created later, which is a widening
   no one proposed.
4. **Where a secret's kind of work lives.** Recommendation: in the owner's policy atom
   (`urn:secret:owner:id:{owner}:policy`, Turtle with SKOS kind IRIs). The alternative is a
   `kind` partition in the name (`…:kind:publish:name:{n}`). The policy is better because
   classifying is a separate authority from writing, so a writer cannot declassify. It also lets
   a reclassification happen without moving bytes, and a Keychain move is the non-atomic
   delete-then-set.
5. **How "a person" is known.** Recommendation: a host-injected `PrincipalClass`, defaulting to
   "only root", so a host that wires nothing is closed. Not the presence gate, which is a no-op off
   macOS. Report up whether a door-minted actor-class scope belongs in core instead.
6. **Keep the `-` rule for new names?** It is no longer needed for capability safety (4.1).
   Recommendation: keep it anyway, so the file store and every face refuse alike, with one sentence
   to explain.
7. **Generate's "already holds a secret".** Today it is `InvalidArgument { name: "into" }`
   (`src/lib.rs:753-761`). Core's taxonomy says a refusal by current state is `Conflict`
   (`ikigai-core` `error.rs:41-68`). Recommendation: the new owner-keyed generate answers
   `Conflict`. Changing the legacy answer is a separate finding, not this arc's.
8. **The legacy window.** Recommendation: legacy names and legacy scopes are honored for the
   legacy owner only, for exactly one minor release (0.5.x), then removed in 0.6.0. The startup
   preflight refuses a grants file holding a `urn:cap:secret:*:owner:` scope.
9. **Storage keys for the legacy owner.** Recommendation: they stay the bare name forever, so
   neither the upgrade nor the alias's removal moves a stored secret.
10. **Generate's owner.** Recommendation: a required `owner=` beside `into=`, and
    `urn:cap:secret:generate` stays unparameterized. The owner scoping comes through the two exact
    write scopes generate already requires.
