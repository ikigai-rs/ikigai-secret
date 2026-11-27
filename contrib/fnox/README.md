# ikigai as a fnox provider

`ikigai.lua` is a [fnox](https://fnox.jdx.dev) Lua provider plugin (ledger #4492; design in
[`docs/storage-backends.md`](../../docs/storage-backends.md), section 7). With it, fnox reads a
secret through ikigai: for each secret, the plugin runs

```text
ikigai --quiet -c 'source urn:secret:<value>'
```

so the read goes through ikigai's per-name capabilities, its presence gate and its audit, in the
host that the `ikigai` command reaches. The plugin grants nothing. It can read only what that
command's identity is allowed to read, and it never opens a store itself.

This release has `get` only, so fnox can read through ikigai but not write. `put` comes later,
once `fnox.cmd` is shown to pass a value to a command on standard input rather than in its
arguments.

## Declaring it

Copy `ikigai.lua` next to your `fnox.toml` (or point at it in this checkout), then declare a
provider and the secrets it answers:

```toml
[providers.ikigai]
type = "lua"
plugin = "./ikigai.lua"
# Both options are optional:
#   command: the ikigai binary to run (default "ikigai", found on PATH)
#   connect: a kernel server to attach to, as `ikigai --connect` takes it
#            (a Unix socket path, or quic://host:port); absent, the command's own host answers
options = { connect = "/run/ikigai/kernel.sock" }

[secrets]
ZOOM_CLIENT_SECRET = { provider = "ikigai", value = "zoom.client-secret" }
ACME_DB = { provider = "ikigai", value = "owner:id:acme:name:db" }
```

A secret's `value` is the ikigai secret name: the part after `urn:secret:`. The plugin passes on
only ASCII letters, digits, `.`, `_`, `-` and `:`, and never a name that begins with `-`. Any
other name is refused before a command runs, because ikigai's command grammar would read a
space, a quote, `=` or `|` as something other than part of the name.

## What it can do on your machine

**fnox plugins are not sandboxed.** They run with your user's permissions, as fnox's own
documentation says. This plugin runs exactly one command per secret, the `ikigai` command above,
with an empty standard input. It does not use a shell, and it reads nothing else. Read it before
you declare it: it is short.

The value comes back as text. `ikigai -c` ends each answer with one newline, and the plugin
removes that newline and nothing else. A secret whose bytes are not UTF-8 text does not come
through unchanged.

## What a refusal looks like

**No such secret.** ikigai answers NotFound, and the plugin returns nothing, so fnox's
`if_missing` and `default` apply as they would for any provider. ikigai's answer is:

```text
error: not found: no secret `zoom.x`
```

**Not allowed.** The command's identity does not hold `urn:cap:secret:read:<name>`. The lookup
fails with ikigai's own sentence, which names the scope it needs, and fnox reports it with the
provider's name:

```text
ikigai refused urn:secret:zoom.x: error: denied: reading `zoom.x` requires `urn:cap:secret:read:zoom.x`
```

Ask whoever runs the host for that grant. Signing in to anything will not help, so the plugin
does not report this as an authentication error.

**No host.** When the `connect` target is not running, the lookup fails with the command's own
sentence:

```text
ikigai refused urn:secret:zoom.x: ikigai: connect /run/ikigai/kernel.sock: No such file or directory (os error 2)
```

**A name it will not pass on.** No command runs, and the lookup fails with:

```text
ikigai: `zoom x` is not a secret name this plugin passes on: use ASCII letters, digits, `.`, `_`, `-` and `:` only
```

No refusal carries a secret's value: ikigai's error sentences never do.

## How it is tested

`tests/fnox_plugin.rs` tests **the exact command line the plugin builds, not a run through
fnox**. Neither fnox nor a kernel host with a secret to read is available on CI. The test loads
the plugin into Lua 5.4 beside a stand-in for `fnox.cmd`, which records each command and answers
the way `ikigai` 0.5.3 does. It pins the argument list, the empty standard input, the newline
handling, NotFound as nothing, refusals in ikigai's words, and names refused before any command
runs. A run through a real fnox against a test host has not been done yet.
