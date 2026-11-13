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
| Last reviewed | 2026-11-12 |
| Next review | a change to the presence gate, to an error message, or to the platforms a gate supports |

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
  {name}", "Generate encryption key {name}".
- **Error text.** The sentences in `Error::Denied`, `Error::InvalidArgument` and `Error::Endpoint`
  values this library returns, which hosts may show to people (for example, why a secret name
  beginning with `-` is refused).
- **Descriptions.** The endpoint descriptions (Meta) a host can render as help.

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
| The macOS prompt can be passed without biometrics | Fail | Source review of `BiometricGate` in `src/lib.rs` on 2026-11-12: the policy is `PolicyBuilder::new().biometrics(Some(BiometricStrength::Strong))`, with no device-password fallback. See Known limitations. |
| A failed prompt reports a plain sentence | Fail | Source review of `BiometricGate` in `src/lib.rs` on 2026-11-12: `biometric check failed: {e:?}` puts the platform error's debug form in the message. |
| The real system prompt (Touch ID sheet) | Blocked | Exercised only by hand on a Mac, with no recorded date or result. No CI job can show it. |
| Manual keyboard | Blocked | No person has completed the system prompt or a host's error display from the keyboard for this review. |
| Screen reader | Blocked | No screen reader has been used with the system prompt or with a host showing this library's errors. |
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
