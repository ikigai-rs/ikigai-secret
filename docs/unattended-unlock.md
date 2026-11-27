# Holding the age identity without an unlock prompt, and moving off the Keychain

Design spike, the companion to `docs/storage-backends.md` (decided 2026-11-27: `age-file` is the
default store for new installs). That note says each item is encrypted to an age recipient. This
one says where the identity that decrypts them is held, so a service on a Mac, a Linux server or
a rented VPS reads its secrets with nobody at the screen, and how an install moves there from the
Keychain. Status: **decided** (Brian, 2026-11-27, as proposed; section 8).

Sources were read on 2026-11-27 and are named where used. A behavior no source documents is marked
**(verify)**, with the test that settles it; nothing is built on an unverified one.

## 1. Why the Keychain prompts

A login Keychain item's access list names trusted applications by their code signature's
designated requirement. A binary built and ad-hoc signed by `cargo install` is a new applicant,
so the item asks "allow access" again. A stable self-signed identity makes "Always Allow" survive
rebuilds. Two limits remain, both seen in practice:

- a macOS update can re-evaluate the access lists and drop the grants, after which a daemon
  under launchd cannot read its key until someone answers a prompt at the screen;
- a CLI cannot use the Secure Enclave through the Keychain without a paid entitlement (the
  `-34018` error).

fnox's keychain provider has the same shape: it says macOS "may show an access prompt for each
keychain item", needs a desktop session, and its `touch_id = true` mode "prompts for every
protected read" (fnox keychain provider docs).

## 2. The options, by whether they need a person

| Where the identity lives | Unattended? | Bound to | Notes |
|---|---|---|---|
| **Secure Enclave, `age-plugin-se`** | **(verify)** with `--access-control=none` | that Mac; not exportable | `keygen --access-control=` takes `none, passcode, any-biometry, any-biometry-and-passcode, any-biometry-or-passcode, current-biometry, current-biometry-and-passcode`; the default is `any-biometry-or-passcode`. Decrypting needs macOS 14 or later (age-plugin-se README). It uses the Enclave through CryptoKit with the key kept as a wrapped blob in the identity file, not a Keychain item, so the Keychain access list and the `-34018` entitlement should not apply **(verify)**. |
| **YubiKey PIV, `age-plugin-yubikey`** | yes, while plugged in, with a PIN policy of `once` and no touch | the key | PIN and touch policies are set at `--generate`. With `once`, the PIN is cached until the key is unplugged, **another applet such as FIDO2 is used**, or `--generate` runs again. YubiKey 4 and 5 series (age-plugin-yubikey README). Linux needs `pcscd`. Which policy values allow no PIN at all is not on the README **(verify)**. |
| **TPM 2.0, `age-plugin-tpm`** | yes, without a PIN | that machine | "Keys created on the TPM, sealed outside of it"; the PIN is optional, and `AGE_TPM_PIN` is readable from `/proc/<pid>/environ`, so use no PIN or a credential the service manager supplies (age-plugin-tpm README). |
| **A file readable only by the service** | yes | the disk | Today's level of protection, moved to one file. Protects against nothing that can read that file. |
| **systemd credential** (Linux) | yes | the machine (TPM2 when present, else the host key) | `systemd-creds encrypt` and `LoadCredentialEncrypted=` hand the identity to the service at start, never on disk in the clear. **(verify)** the systemd version on each server, and whether a VPS exposes a TPM. |
| **1Password service account, through fnox** | yes | the token | Service accounts give "servers scoped access to secrets in 1Password, without a person signing in", scoped per vault, up to 100 per account, subject to rate limits (1Password service-accounts docs). fnox's `1password` provider takes the token from its config, `FNOX_OP_SERVICE_ACCOUNT_TOKEN` or `OP_SERVICE_ACCOUNT_TOKEN` (fnox docs). The token is itself the one secret to hold, by one of the rows above. |
| 1Password app integration (biometric) | **no** | a person | Unlock is Touch ID or the device password, for a person at a terminal (1Password CLI app-integration docs). Right for an operator's shell, never for a service. |
| **YubiHSM 2** | yes, with an authentication key | the device | PKCS#11 and native libraries, network-shareable (Yubico product page). Its authentication key is again a secret to hold somewhere, and it is far more than this needs today. |
| Cloud KMS (AWS, GCP, Azure) | yes, with the machine's cloud identity | the cloud account | Only for a host that already runs in that cloud; fnox supports `aws-kms`, `gcp-kms` and `azure-kms` as encryption providers (fnox provider overview). |

So: **1Password through its app integration does not solve this; a service account does.** A
hardware key solves it if it is configured to decrypt without a person: a YubiKey with a cached
PIN and no touch, a TPM without a PIN, and (to be verified) the Secure Enclave with no access
control.

## 3. Two rules that make any of them safe

1. **Every store is encrypted to at least two recipients:** the machine's own (Enclave, TPM or
   service file) and a **recovery** recipient that is not on the machine. A device-bound key dies
   with the device ("cannot be transferred to another machine", age-plugin-se README), so a
   store with one device-bound recipient is one logic-board failure from gone. The recovery
   identity lives offline: a YubiKey in a drawer, or an age key kept in a password manager.
2. **Unattended decrypt is not unattended authority.** Unlocking the store at start does not
   remove ikigai's own presence gate: unlock, generate and delete still ask a person through the
   host's gate, and every read still needs its per-name scope. The no-prompt identity only means a
   service can start and serve what it is already allowed to serve.

## 4. Recommendations

| Machine | Identity | Recovery | Why |
|---|---|---|---|
| **a Mac that runs services** | Secure Enclave via `age-plugin-se`, `--access-control=none`, once section 6's test passes | a YubiKey 5 kept offline, or an age key in a password manager | no Keychain access list to break on a rebuild or an OS update; non-exportable. If the test fails, a YubiKey 5C Nano left in the Mac, PIN policy `once`, touch `never`, **used for nothing else** (a FIDO2 passkey on the same key clears the PIN cache) |
| **a Linux server** | `age-plugin-tpm` without a PIN, if it has TPM 2.0; else a systemd credential | the same offline recovery | unattended, bound to the machine, nothing in the environment |
| **a rented VPS** | a systemd credential, sealed to the virtual TPM if the provider offers one, else to the host key | the same offline recovery | no hardware can be plugged in. A host-key credential still keeps the identity out of disk images and backups, though not from root on the box |
| **a VPS's secrets that rotate or are shared** (API tokens, SMTP) | a 1Password service account, read through a fnox store, scoped to one vault for that host only | 1Password itself | rotation happens in one place; the service account's token is held by the row above |
| **people** | 1Password with app integration in their own shell; a YubiKey 5 for passkeys | — | a person's interactive use, kept apart from any service's key |

A YubiHSM 2 or a cloud KMS is not recommended now: each adds a device or an account whose own
authentication key is the same problem one level up, for a scale this does not have.

## 5. Migrating an install off the Keychain

Each step is safe to stop after, and nothing is deleted until the last:

1. **Make the identities.** On the machine: `age-plugin-se keygen --access-control=none` (or the
   YubiKey or TPM equivalent), and choose the recovery recipient.
2. **Add the store, route nothing.** A `[secret]` section with the existing Keychain as a store,
   kept as the default, and a new `age-file` store encrypted to both recipients. Nothing moves.
3. **Copy.** `urn:secret:store:name:{to}:copy` for each secret (storage-backends task 6): under the
   name's read and write scopes and the presence gate, never deleting the source. The Keychain
   may prompt once per item during this step; that is the last time.
4. **Switch the default** to the `age-file` store. Keep the Keychain store configured, read-only,
   so a rollback is one line.
5. **Prove it unattended.** Restart the service under launchd (or systemd) with nobody at the
   screen and read each secret through a test request; on a Mac, also after the next macOS
   update.
6. **Retire the Keychain items**, explicitly, only after step 5 has held for an agreed time.

## Upgrade from older versions

- An install that does nothing keeps its Keychain store unchanged (`docs/storage-backends.md`,
  section 8). This design never moves a secret by itself.
- **Downgrade:** an older release ignores the `[secret]` section and reads the Keychain, which
  still holds every item until step 6, so going back works up to that step. After step 6 an older
  release finds nothing; the release note says so.
- A store encrypted to two recipients is readable by either, so losing the machine's key never
  loses the store while the recovery identity exists.

## 6. What must be verified before it is recommended for real

1. On a Mac with macOS 14 or later: an `age-plugin-se` identity made with `--access-control=none`
   decrypts under launchd with nobody logged in at the screen, before and after the reading binary
   is rebuilt and re-signed, and after a macOS minor update. If it prompts in any of those cases,
   the Mac recommendation falls back to the YubiKey row.
2. `age-plugin-yubikey`: which `--pin-policy` and `--touch-policy` values give no prompt for a
   long-running process, and that the cache survives an idle day.
3. Each Linux server: whether it has TPM 2.0, and `age-plugin-tpm` decrypting under a systemd user unit.
4. Each VPS: the systemd version, whether the VPS offers a virtual TPM, and `LoadCredentialEncrypted=`
   delivering the identity to the service.
5. The age crate's plugin support from a host-role crate: building a plugin identity runs the
   `age-plugin-<name>` binary, which only a host or connector crate may do (Hypothesis H).

## 7. Tasks

1. **Verify** section 6, items 1 to 4, on the real machines, as a short report with the exact
   commands and what each printed. This is Brian's or the hub's, at the machines.
2. **Identity sources in the hosts**: `identity = "se:<file>" | "yubikey:<file>" | "tpm:<file>" |
   "file:<path>" | "systemd-credential:<name>" | "secret:<store>/<name>"`, resolved by the host
   (it may run an age plugin), handed to the `age-file` store as an identity.
3. **Multiple recipients and a recovery recipient** on `age-file`, with a refusal at start for a
   store whose only recipients are device-bound.
4. **The migration** of section 5 as an Operations book page, every step a CI-run transcript
   where it can be, and the at-the-machine steps stated as such.
5. **A VPS**: its `[secret]` section, the systemd unit with the credential, and a fnox store
   over a 1Password service account scoped to that host's vault.

## 8. Decisions (Brian, 2026-11-27: all four as proposed)

1. **The Mac identity:** Secure Enclave first (if section 6's test passes), with a dedicated
   YubiKey as the fallback.
2. **The recovery recipient:** an offline YubiKey, or an age key kept in a password manager.
3. **A VPS:** a systemd credential for the store's identity, plus a 1Password service account
   (through fnox) for the secrets that rotate. This needs a 1Password plan with service accounts.
4. **Dedicated hardware:** buy a YubiKey 5C Nano per Mac that runs services (only if the Enclave
   test fails), kept for that purpose alone.
