# ikigai-secret-fnox

A read-only [fnox](https://fnox.jdx.dev) store for
[ikigai-secret](https://github.com/ikigai-rs/ikigai-secret): each secret is read through fnox's
library from ONE fnox configuration file, with secret names mapped one to one to fnox keys, and
nothing ever waits on a prompt (ledger #4489; the design is `docs/storage-backends.md`, section
6.1, in this repository).

This is a **host-role connector**: fnox reads its configuration file and what it imports, reads
environment variables and runs provider commands (`op`, `aws`, `bw`). ikigai-secret is a module
and checks the `[secret]` section's `kind = "fnox"` stores itself; a host opens them here and
hands them over:

```rust,ignore
let config = ikigai_secret::SecretConfig::from_section(Some(&section), Some(home))?;
let routing = ikigai_secret_fnox::routing(config, age_keys)?; // opens each fnox file, or refuses
let space = ikigai_secret::routed_space(std::sync::Arc::new(routing));
```

`routing` is `backends(&config)` followed by `SecretConfig::build_with_backends(age_keys,
backends)`. Each refusal is one sentence in a `SecretConfigError`, so a host refuses to start on
a store it cannot open, as it does on a wrong section.

## The section

```toml
[secret.store.team]
kind = "fnox"
config = "~/work/acme/fnox.toml"   # absolute, or under the host's home; never searched for
profile = "prod"                   # absent: fnox's default profile
names = "map"                      # map (the default) | escaped

[secret.store.team.map]            # names = "map": secret name to fnox key, one to one
"zoom.client-secret" = "ZOOM_CLIENT_SECRET"
```

## What the store does

- **One file, never the search.** `Fnox::open(config)` only, never `Fnox::discover()`, which
  walks every directory from the root down to the working directory. The profile is always set
  from the section (fnox's default when it names none), so `FNOX_PROFILE` in the host's
  environment never chooses it, and a profile name fnox would silently drop is refused at start.
- **One-to-one names**, checked by ikigai-secret when the section is read: an explicit `map`
  table (an unlisted name is NotFound; two names sent to one key are refused), or the injective
  `escaped` transform (`zoom.client-secret` is `zoom_2Eclient_2Dsecret`).
- **Absence is NotFound**: a name with no key, a key fnox does not declare, a declared key that
  resolves to nothing (`if_missing = "warn"` or `"ignore"`), and a provider's "no such item".
- **Never interactive.** Opening the store, and every read, sets fnox's process-wide
  non-interactive switch (`fnox_core::env::set_non_interactive(true)`). It stops the sign-in
  prompt, the passphrase prompt of a protected age identity, and every provider that needs a
  person at the machine, which refuse instead. A signed-out provider is refused with a sentence
  naming the store, the secret, the provider and how to sign in at the machine:

  > the store `team` could not read `zoom.client-secret`: its fnox provider `op` (1password)
  > needs a sign-in, and a host never prompts for one; sign in at the machine, as the user the
  > host runs as, with `op signin`, then try again

  `prompt_auth = false` in the fnox file is not enough on its own: `FNOX_PROMPT_AUTH=true` in
  the environment overrides it, and it does not reach the age passphrase prompt.
- **Errors never carry fnox's text**, which can quote the configuration file, a provider's
  output or a value: each refusal is written from the error's kind and says to run `fnox check`
  at the machine for fnox's own message.
- **Read-only.** Every write is Conflict ("the store `team` is read-only: …"), after every
  capability check. Writes through `fnox set` are a later task.
- **Never cached here.** Each read asks fnox's providers; fnox's daemon is not used.

## What fnox still reads from the host's environment

The store cannot stop these, and an operator who mounts a fnox store should know them:

- a declared key with neither a provider value nor a default falls back to the environment
  variable **of the same name** (pinned by `tests/env_fallback.rs`);
- `FNOX_AGE_KEY` and `FNOX_AGE_IDENTITY` choose the age identity ahead of the file's
  `key_file`;
- `FNOX_IF_MISSING` and `FNOX_IF_MISSING_DEFAULT` decide what a missing value does, and under
  `warn` (fnox's default) fnox writes one warning line naming the key to the host's standard
  error;
- `FNOX_CONFIG_DIR` and the XDG variables place fnox's default age identity.

So a host that mounts a fnox store runs with an environment it controls.

## Features

fnox's provider families with large SDKs are opt-in, so a host builds only what it uses: `aws`,
`azure`, `gcp`, `keeper`, `kubernetes`, `enpass`, `fido2` (fnox's names). Every other provider
(age, plain, 1Password, Bitwarden, Vault, the OS keychain, password-store and the rest) is in
the base build. A store whose provider is not built is refused with the feature to add.

The crate depends on `fnox-core` (fnox's library crate, which the `fnox` crate re-exports beside
its command-line program) with `default-features = false`. `rust-version` is 1.91.1, fnox's.

## Tests

Offline, on a fixture `fnox.toml` written at test time with fnox's `age` and `plain` providers
(`tests/fnox_store.rs`): the map and `escaped` mappings, absence, the profile, a
passphrase-protected age identity refused at once, a provider failure's sentence, every write
refused, the start-up refusals, the routed space under narrow grants, and a copy out of the fnox
store into a file store.

## License

MIT OR Apache-2.0, like ikigai-secret. fnox is MIT, by Jeff Dickey.
