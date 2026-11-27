# Accessibility

How this repository approaches accessibility: what is in scope, the standard we aim at, the
evidence that exists today and what it does not cover, the barriers we know about, and how to
report one. It is a working agreement for contributors, maintainers and coding agents. It is not
a conformance claim, an Accessibility Conformance Report or a VPAT, and it is not legal advice.

Adapted from the [ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md)
(MIT).

## Project information

| Field | Value |
|---|---|
| Project | ikigai-secret: a library that stores and reads secrets through the OS keystore, behind capabilities, and asks a person to prove presence before sensitive operations |
| Published at | [crates.io/crates/ikigai-secret](https://crates.io/crates/ikigai-secret); no web pages of its own |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-secret/issues/new) |
| Target | WCAG 2.2 Level AA, applied to the text and prompts this library produces |
| Status | Evaluation in progress. No conformance claim. |
| Last reviewed | 2026-11-27 |
| Next review | a change to the presence gate, to an error message, to the inspection text, or to the platforms a gate supports |

## Commitment

This library has no screens, but people still meet it: in a system authentication prompt when an
operation needs proof that someone is at the machine, and in the error sentences a host shows when
an operation is refused. If the prompt can only be passed one way, it shuts out everyone who cannot
use that way; if a refusal is not in plain words, the person reading it cannot act on it. We say
what has not been tested, and we name the barriers we know about below rather than leaving them to
be found.

## Scope

### In scope

- **The presence prompt.** `urn:secret:unlock`, `urn:secret:generate` and a `Delete` on
  `urn:secret:{name}` ask the presence gate, after every capability and argument check. The
  platform gate, `BiometricGate`, shows the operating system's own authentication dialog with this
  library's reason text: "Unlock ikigai secrets", "Delete secret {name}", "Generate signing key
  {name}", "Generate encryption key {name}", and (since 0.5.3) "Encrypt the secrets in the store
  {store}" before `urn:secret:store:name:{store}:reencrypt`.
- **Error text.** The sentences in `Error::Denied`, `Error::InvalidArgument` and `Error::Endpoint`
  values this library returns, which hosts may show to people (for example, why a secret name
  beginning with `-` is refused).
- **Descriptions.** The endpoint descriptions (Meta) a host can render as help.
- **Configuration refusals.** The sentences `SecretConfigError` carries when a host's `[secret]`
  section is refused (since 0.5.2): one per problem, each naming the line, which a host prints
  when it refuses to start.
- **Inspection text.** The `text/plain` faces of `urn:secret:store`,
  `urn:secret:store:name:{store}` and `urn:secret:route` (since 0.5.2): one sentence per store or
  route. `urn:secret:route:secret:{name}` answers the bare store name, for scripts.
- **The age-file store's text** (since 0.5.3): the refusal when an encrypted secret cannot be
  opened, the refusals of an `age-file` store's settings and of age keys, the one line per item a
  reencrypt answers, and the start-up notice `SecretConfig::notice` gives a host to print.
- **The fnox plugin's text.** The refusal sentences `contrib/fnox/ikigai.lua` raises, and its
  README.

### Not ours to fix, still ours to report

- **The system authentication dialog itself** (on macOS, LocalAuthentication's Touch ID sheet):
  its layout, its VoiceOver support and its keyboard behavior belong to the operating system. We
  choose the policy it enforces and the reason text it shows.
- **How a host presents our errors.** A host decides where and how an error sentence is shown.

## How it is tested

Every named check has a result: Pass, Fail or Blocked, with its evidence. A Pass covers only the
stated check, not overall accessibility. Every Pass below was run on main at `792de1e` on
2026-11-12 on macOS (arm64) with rustc and cargo 1.100.0: `cargo test --all-features`, 66 passed,
0 failed, 3 ignored. CI runs the same tests on every pull request. Every presence-gated operation
runs headless through an injected gate (any `Fn(&str) -> Result<()>` closure is a gate), so the
tests exercise the order of checks and the reason strings without showing a real prompt.

| Check | Result | Evidence |
|---|---|---|
| The presence prompt is asked last, after every capability and argument check, and its refusal stands | Pass | `cargo test`: `tests/conformance.rs` (`the_presence_gate_is_asked_last_and_its_refusal_stands`, `delete_asks_the_presence_gate_last`) and `src/lib.rs` (`unlock_is_capability_gated_before_the_presence_gate`). A person refused for a missing capability is never shown a prompt they cannot pass. |
| Prompt reason text in words: "Unlock ikigai secrets", "Generate signing key {name}", "Delete secret {name}" | Pass | `cargo test`: `tests/conformance.rs` asserts each string the gate is asked with. Checks the text handed to the gate, not how the system dialog shows it. |
| Prompt reason text "Generate encryption key {name}" | Blocked | In `src/lib.rs` (the `urn:secret:generate` endpoint), but no test asserts it. |
| A refused secret name beginning with `-` names the argument and why | Pass | `cargo test`: `tests/deny_shaped_names.rs` (`the_read_face_refuses_a_name_beginning_with_dash`, `generate_refuses_into_beginning_with_dash` and the rest of the suite) checks the error kind and the argument it names. |
| A refused `[secret]` section says, in one sentence per problem, which line is wrong and what to do | Pass | Run on the ledger #4486 branch on 2026-11-27, macOS (arm64), rustc 1.100.0, `cargo test`: 102 passed, 0 failed, 3 ignored. `src/store.rs` unit tests (`an_unknown_kind_is_refused_naming_the_line`, `a_route_to_an_unconfigured_store_is_refused`, `a_default_that_names_nothing_is_refused`, `two_routes_with_the_same_match_are_refused`, `mac_stores_are_refused_off_macos_and_accepted_on_it` and the rest) assert each sentence whole; `every_problem_is_reported_at_once_and_nothing_is_applied` asserts they are listed together. Checks the words, not how a host shows them. |
| The inspection text faces are sentences in words, with no arrows or symbols standing for words | Pass | Same run: `tests/routed.rs` (`every_inspection_resource_answers_under_its_narrow_grant`) asserts the whole text of `urn:secret:store`, one store's lines and `urn:secret:route`. |
| A write to a read-only store is refused with a sentence naming the store, before any presence prompt | Pass | Same run: `tests/routed.rs` (`a_read_only_store_refuses_writes_after_the_capability_and_before_presence`) asserts the sentence and that the gate was never asked. |
| The fnox plugin's refusals are sentences: ikigai's own words, or a plain sentence saying which characters a name may use | Pass | `cargo test --test fnox_plugin` on 2026-11-27 (mlua 0.12, Lua 5.4 vendored): `a_refusal_is_an_error_in_ikigais_words`, `a_name_the_command_grammar_would_split_is_refused_before_any_command`. Read in a stand-in for fnox, not in fnox's own output. |
| An `age-file` store's settings are refused in one sentence per problem, naming the line (no `identity`, a `recipients` entry that is not an age recipient, no `path` and no home) | Pass | Run on the ledger #4488 branch on 2026-11-27, macOS (arm64), rustc 1.100.0, `just gates` (fmt, clippy, `cargo test`: 128 passed, 0 failed, 3 ignored; `cargo doc`). `src/store.rs` unit test `an_age_file_store_without_identity_or_with_a_bad_recipient_is_refused` asserts each sentence whole. |
| An encrypted secret that cannot be opened is refused with a sentence saying why and what to do, never served as the secret | Pass | Same run: `tests/age_file.rs` (`an_item_sealed_to_another_identity_is_refused_never_served_as_the_secret`) asserts the whole sentence for an item sealed to another identity, and the reason for a torn one. |
| A reencrypt answers one sentence per item, then a summary, with no value and no other caller's names | Pass | Same run: `tests/age_file.rs` (`reencrypt_converts_everything_and_a_second_run_changes_nothing`) asserts the whole answer, `reencrypt_reads_and_names_only_what_the_caller_may_write` that no other name appears, `a_crash_mid_reencrypt_leaves_every_item_readable` the line and the summary for an item left as it was. |
| The presence prompt "Encrypt the secrets in the store {store}" is asked after every capability check, and its refusal stands | Pass | Same run: `tests/age_file.rs` (`reencrypt_converts_everything_and_a_second_run_changes_nothing` asserts the reason text; `reencrypt_reads_and_names_only_what_the_caller_may_write` and `reencrypt_refuses_a_store_that_is_not_age_file_or_is_read_only_before_the_gate` that a refused call never asks; `a_refused_presence_gate_reencrypts_nothing`). |
| The start-up notice for an existing install is one plain line | Pass | Same run: `src/store.rs` (`a_host_with_no_section_keeps_an_existing_store_and_gives_a_new_install_age_file`) and the `SecretConfig::for_host` doctest assert its opening, the deprecation sentence and that it names `age-file`. The whole line is not asserted. |
| The macOS prompt can be passed without biometrics | Fail | Source review of `BiometricGate` in `src/lib.rs` on 2026-11-12: the policy is `PolicyBuilder::new().biometrics(Some(BiometricStrength::Strong))`, with no device-password fallback. See Known limitations. |
| A failed prompt reports a plain sentence | Fail | Source review of `BiometricGate` in `src/lib.rs` on 2026-11-12: `biometric check failed: {e:?}` puts the platform error's debug form in the message. |
| The real system prompt (Touch ID sheet) | Blocked | Exercised only by hand on a Mac, with no recorded date or result. No CI job can show it. |
| Manual keyboard | Blocked | No person has completed the system prompt or a host's error display from the keyboard for this review. |
| Screen reader | Blocked | No screen reader has been used with the system prompt, with a host showing this library's errors, or with the inspection text. |
| Screen magnifier | Blocked | No screen magnifier has been used with this output. |
| Speech input | Blocked | No speech-input software has been used with this output. |
| Switch access | Blocked | No switch-access software has been used with this output. |
| Braille display | Blocked | No braille display has been used with this output. |

## Known limitations

- **The macOS presence gate accepts biometrics only.** `BiometricGate` builds a policy of strong
  biometrics with no fallback to the device password, so a person who cannot use Touch ID (no
  finger enrolled, a disability, a keyboard without Touch ID, a Mac without it) cannot pass the
  prompt, and cannot unlock, generate a key, or delete a secret on that machine. A host can
  supply another gate with `space_with_gate` (for example one that allows the device password);
  changing the default is tracked as an open issue.
- **A failed prompt reports a debug-formatted reason** (`biometric check failed: …` followed by
  the platform error's debug form), not a plain sentence a person can act on.
- **On every platform but macOS the presence gate does nothing**: no prompt is shown, which is
  not a barrier but is a security property hosts must know (see the README).
- Error sentences follow no tested style guide yet; some name internal stores ("secret write: …")
  rather than saying what the person can do.

## Contributing

Read this file before changing the presence gate, a reason string or an error message. In the pull
request, give each check a row in a Check | Result | Evidence table: Pass, Fail or Blocked, with
the test or command, the tool and its version, or why it could not run. Keep an unrun check as
Blocked, a screen reader nobody ran included; never omit it.

## Reporting a barrier

Open [a GitHub issue](https://github.com/ikigai-rs/ikigai-secret/issues/new) describing what you
tried, what happened, and what assistive technology or setting you use if any. We aim to
acknowledge a report within 7 days. For anything security-sensitive, do not open a public issue:
contact the maintainers privately first.

## Change history

| Date | Change |
|---|---|
| 2026-11-12 | "How it is tested" as a Pass / Fail / Blocked table, each Pass run on main at `792de1e`; the two known barriers recorded as Fail rows. |
| 2026-11-27 | 0.5.2 (ledger #4486): the configuration refusals and the inspection text in scope, with three Pass rows run on that branch. |
| 2026-11-27 | The fnox plugin's refusals in scope (ledger #4492), one Pass row. |
| 2026-11-27 | 0.5.3 (ledger #4488): the age-file store's text and the reencrypt prompt in scope, five Pass rows run on that branch. |
