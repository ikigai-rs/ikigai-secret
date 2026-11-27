//! The fnox store, read through fnox's own library, OFFLINE: a fixture `fnox.toml` written at
//! test time beside its age identities, using fnox's `age` and `plain` providers only. Nothing is
//! fetched and no real provider is reached.
//!
//! ## The fixture
//!
//! ```toml
//! [providers.plain]   type = "plain"
//! [providers.sealed]  type = "age", key_file = "<dir>/id.txt"      # a plain identity
//! [providers.locked]  type = "age", key_file = "<dir>/locked.age"  # passphrase-protected
//! [providers.other]   type = "age", key_file = "<dir>/id.txt"      # values sealed to another key
//!
//! [secrets]
//! ZOOM_SECRET   sealed to id.txt            PLAIN_TOKEN  plain
//! LOCKED        sealed, opened by locked.age WRONG_KEY   sealed to a key nobody here holds
//! EMPTY         declared, no value, if_missing = "ignore"
//! zoom_2Eclient_2Dsecret  plain (the `escaped` key of `zoom.client-secret`)
//! [profiles.prod.secrets]  PROD_ONLY  plain
//! ```
//!
//! ## What is pinned
//!
//! - [`a_mapped_name_reads_its_key_and_absence_is_not_found`]: the map, and the three kinds of
//!   absence (`SecretNotFound`, `Ok(None)`, an unlisted name).
//! - [`an_escaped_name_reads_its_escaped_key_only`].
//! - [`the_profile_is_the_sections_never_the_environments`].
//! - [`a_signed_out_provider_refuses_at_once_and_never_prompts`]: the open question of the design
//!   (section 6.1), settled: `fnox_core::env::set_non_interactive(true)`.
//! - [`a_provider_failure_names_the_store_and_provider_and_never_fnoxs_text`].
//! - [`every_write_is_refused_as_read_only`].
//! - [`a_store_that_cannot_be_opened_refuses_the_host_at_start`].
//! - [`a_refused_caller_never_reaches_fnox_and_a_granted_one_does`]: the routed space, as a host
//!   mounts it.
//! - [`a_secret_copies_from_a_fnox_store_into_a_file_store`].
//!
//! `tests/env_fallback.rs` pins fnox's environment fallback, in a process of its own because it
//! sets a variable.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_secret::{
    fnox_read_only, routed_space_with_gate, Backend, SecretConfig, SecretSection, StoreKind,
};
use ikigai_secret_fnox::{backends, routing, FnoxStore};

/// The fixture: a scratch directory holding the identities and `fnox.toml`.
struct Fixture {
    dir: tempfile::TempDir,
}

/// An age value as fnox's `age` provider reads it: the binary age file, base64.
fn sealed(recipient: &age::x25519::Recipient, value: &str) -> String {
    let bytes = age::encrypt(recipient, value.as_bytes()).unwrap();
    base64(&bytes)
}

/// Standard base64 with padding, written here so the test needs no encoder crate.
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let text = format!("{}\n", identity.to_string().expose_secret());
        std::fs::write(dir.path().join("id.txt"), &text).unwrap();
        // The same identity, protected by a passphrase: opening it needs a terminal.
        let passphrase = age::scrypt::Recipient::new("correct horse".to_owned().into());
        let locked = age::encrypt(&passphrase, text.as_bytes()).unwrap();
        std::fs::write(dir.path().join("locked.age"), locked).unwrap();
        let stranger = age::x25519::Identity::generate().to_public();
        let id = dir.path().join("id.txt");
        let lock = dir.path().join("locked.age");
        let toml = format!(
            r#"
[providers.plain]
type = "plain"

[providers.sealed]
type = "age"
recipients = ["{recipient}"]
key_file = "{id}"

[providers.locked]
type = "age"
recipients = ["{recipient}"]
key_file = "{lock}"

[providers.other]
type = "age"
recipients = ["{stranger}"]
key_file = "{id}"

[secrets]
ZOOM_SECRET = {{ provider = "sealed", value = "{zoom}" }}
PLAIN_TOKEN = {{ provider = "plain", value = "plain-value" }}
LOCKED = {{ provider = "locked", value = "{locked}" }}
WRONG_KEY = {{ provider = "other", value = "{wrong}" }}
EMPTY = {{ if_missing = "ignore" }}
zoom_2Eclient_2Dsecret = {{ provider = "plain", value = "escaped-value" }}

[profiles.prod.secrets]
PROD_ONLY = {{ provider = "plain", value = "prod-value" }}
"#,
            id = id.display(),
            lock = lock.display(),
            zoom = sealed(&recipient, "zoom-sealed-value"),
            locked = sealed(&recipient, "locked-value"),
            wrong = sealed(&stranger, "never-read"),
        );
        let mut file = std::fs::File::create(dir.path().join("fnox.toml")).unwrap();
        file.write_all(toml.as_bytes()).unwrap();
        Fixture { dir }
    }

    fn config_path(&self) -> PathBuf {
        self.dir.path().join("fnox.toml")
    }

    /// A checked `[secret]` section with one fnox store `team` over the fixture, plus `extra`
    /// lines in its table.
    fn config(&self, extra: &str) -> SecretConfig {
        let text = format!(
            "default = \"team\"\n[store.team]\nkind = \"fnox\"\nconfig = {:?}\n{extra}",
            self.config_path().display().to_string()
        );
        section_config(&text)
    }

    /// The mapped store most tests use.
    fn mapped(&self) -> FnoxStore {
        let config = self.config(
            "[store.team.map]\n\"zoom.client-secret\" = \"ZOOM_SECRET\"\n\
             \"plain.token\" = \"PLAIN_TOKEN\"\n\"locked\" = \"LOCKED\"\n\
             \"wrong\" = \"WRONG_KEY\"\n\"empty\" = \"EMPTY\"\n\"undeclared\" = \"NOT_DECLARED\"\n\
             \"prod\" = \"PROD_ONLY\"\n",
        );
        FnoxStore::open(&config.stores()[0]).unwrap()
    }
}

fn section_config(text: &str) -> SecretConfig {
    let section: SecretSection = toml::from_str(text).unwrap();
    SecretConfig::from_section(Some(&section), Some(Path::new("/home/svc"))).unwrap()
}

/// fnox's `get`, driven without a tokio runtime: the age provider needs none.
async fn tokio_free_get(fnox: &fnox_core::Fnox, key: &str) -> fnox_core::Result<Option<String>> {
    fnox.get(key).await
}

fn read(store: &FnoxStore, name: &str) -> Option<String> {
    store
        .get(name)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .map(|bytes| String::from_utf8(bytes).unwrap())
}

#[test]
fn a_mapped_name_reads_its_key_and_absence_is_not_found() {
    let fixture = Fixture::new();
    let store = fixture.mapped();
    assert_eq!(
        read(&store, "zoom.client-secret").as_deref(),
        Some("zoom-sealed-value")
    );
    assert_eq!(read(&store, "plain.token").as_deref(), Some("plain-value"));
    assert!(store.exists("plain.token").unwrap());
    // A key fnox does not declare (SecretNotFound), a declared key with no value (Ok(None)) and a
    // name the table does not list are all absent.
    assert_eq!(read(&store, "undeclared"), None);
    assert_eq!(read(&store, "empty"), None);
    assert_eq!(read(&store, "unlisted.name"), None);
    assert!(!store.exists("unlisted.name").unwrap());
    // The table is one to one: a key reachable by its name is not reachable by its spelling.
    assert_eq!(read(&store, "ZOOM_SECRET"), None);
    assert_eq!(read(&store, "zoom_2Eclient_2Dsecret"), None);
}

#[test]
fn an_escaped_name_reads_its_escaped_key_only() {
    let fixture = Fixture::new();
    let config = fixture.config("names = \"escaped\"\n");
    let store = FnoxStore::open(&config.stores()[0]).unwrap();
    assert_eq!(
        store.key_for("zoom.client-secret").as_deref(),
        Some("zoom_2Eclient_2Dsecret")
    );
    assert_eq!(
        read(&store, "zoom.client-secret").as_deref(),
        Some("escaped-value")
    );
    // Every other spelling of "zoom client secret" is another key, and absent.
    for other in [
        "zoom-client-secret",
        "zoom_client_secret",
        "zoom.client.secret",
        "ZOOM_SECRET",
    ] {
        assert_eq!(read(&store, other), None, "{other}");
    }
}

#[test]
fn the_profile_is_the_sections_never_the_environments() {
    let fixture = Fixture::new();
    // The default profile does not hold PROD_ONLY.
    assert_eq!(read(&fixture.mapped(), "prod"), None);
    let config = fixture.config(
        "profile = \"prod\"\n[store.team.map]\n\"prod\" = \"PROD_ONLY\"\n\"plain.token\" = \
         \"PLAIN_TOKEN\"\n",
    );
    let prod = FnoxStore::open(&config.stores()[0]).unwrap();
    assert_eq!(read(&prod, "prod").as_deref(), Some("prod-value"));
    // fnox merges the top-level secrets into every profile.
    assert_eq!(read(&prod, "plain.token").as_deref(), Some("plain-value"));
}

#[test]
fn a_signed_out_provider_refuses_at_once_and_never_prompts() {
    let fixture = Fixture::new();
    let store = fixture.mapped();
    // Opening the store turned fnox's process-wide non-interactive switch on: the library's
    // one switch, which stops the sign-in prompt, the age passphrase prompt and every provider
    // that needs a person at the machine.
    assert!(fnox_core::env::is_non_interactive());
    // And this fnox honors it: asked directly, its age provider takes the non-interactive branch
    // (it says no terminal is available) rather than opening the terminal to ask. This is the
    // only place fnox's own text is read, and only to prove which branch ran.
    let direct = futures::executor::block_on(async {
        let fnox = fnox_core::Fnox::open(fixture.config_path()).unwrap();
        tokio_free_get(&fnox, "LOCKED").await
    });
    match direct {
        Err(fnox_core::FnoxError::ProviderAuthFailed { details, .. }) => assert!(
            details.contains("no terminal is available to prompt"),
            "fnox did not take its non-interactive branch: {details}"
        ),
        other => panic!("expected ProviderAuthFailed, got {other:?}"),
    }
    let start = Instant::now();
    let refused = store.get("locked").unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "a signed-out provider must refuse, never wait: {:?}",
        start.elapsed()
    );
    assert_eq!(
        refused,
        Error::Endpoint(
            "the store `team` could not read `locked`: its fnox provider `locked` (age) needs a \
             sign-in, and a host never prompts for one; give the age provider an identity file \
             that needs no passphrase, readable only by the user the host runs as (a \
             passphrase-protected identity needs a terminal), then try again"
                .into()
        )
    );
}

#[test]
fn a_provider_failure_names_the_store_and_provider_and_never_fnoxs_text() {
    let fixture = Fixture::new();
    let store = fixture.mapped();
    let refused = store.get("wrong").unwrap_err().to_string();
    assert_eq!(
        refused,
        "endpoint error: the store `team` could not read `wrong`: its fnox provider `other` \
         (age) could not decrypt the value with its age identity, which is not one of the \
         recipients the value was encrypted to; run `fnox check` against this store's fnox file \
         at the machine to see fnox's own message, which is not passed on because it can carry \
         a secret"
    );
    let toml = std::fs::read_to_string(fixture.config_path()).unwrap();
    assert!(
        !refused.contains(fixture.dir.path().to_str().unwrap()),
        "no path"
    );
    for line in toml.lines().filter(|l| l.contains("value = ")) {
        let value = line.split('"').nth(3).unwrap();
        assert!(!refused.contains(value), "no value from the file");
    }
}

#[test]
fn every_write_is_refused_as_read_only() {
    let fixture = Fixture::new();
    let store = fixture.mapped();
    let read_only = Error::Conflict(fnox_read_only("team", "plain.token"));
    assert_eq!(store.set("plain.token", b"x").unwrap_err(), read_only);
    assert_eq!(store.replace("plain.token", b"x").unwrap_err(), read_only);
    assert_eq!(store.create("plain.token", b"x").unwrap_err(), read_only);
    assert_eq!(store.delete("plain.token").unwrap_err(), read_only);
    assert_eq!(store.accepts_writes("plain.token").unwrap_err(), read_only);
    assert_eq!(
        store.generate_signing_key("plain.token").unwrap_err(),
        read_only
    );
    // And the value is still there.
    assert_eq!(read(&store, "plain.token").as_deref(), Some("plain-value"));
    assert!(
        !store.health().contains('/'),
        "the health line names no path"
    );
}

#[test]
fn a_store_that_cannot_be_opened_refuses_the_host_at_start() {
    let fixture = Fixture::new();
    let missing = section_config(
        "default = \"team\"\n[store.team]\nkind = \"fnox\"\nconfig = \"/no/such/fnox.toml\"\n\
         names = \"escaped\"\n",
    );
    assert_eq!(
        backends(&missing).err().unwrap().problems(),
        [
            "`config = \"/no/such/fnox.toml\"` in [secret.store.team] names no file, so the fnox \
          store team cannot be opened; name the store's fnox file."
        ]
    );
    // A file fnox refuses: its contents (here a value-shaped string) never reach the refusal.
    let bad = fixture.dir.path().join("bad.toml");
    std::fs::write(&bad, "[secrets]\nTOKEN = { value = \"hunter2-secret\" \n").unwrap();
    let broken = section_config(&format!(
        "default = \"team\"\n[store.team]\nkind = \"fnox\"\nconfig = {:?}\nnames = \"escaped\"\n",
        bad.display().to_string()
    ));
    let problem = backends(&broken).err().unwrap().problems()[0].clone();
    assert!(
        problem.ends_with(
            "in [secret.store.team] names a file fnox does not accept as its configuration, so \
             the fnox store team cannot be opened; run `fnox check` against that file at the \
             machine to see fnox's own message, which is not passed on because it can quote the \
             file."
        ),
        "{problem}"
    );
    assert!(!problem.contains("hunter2"), "{problem}");
    // A profile name fnox would silently drop (and so fall back to the default) is refused.
    let config = fixture.config("profile = \"prod/x\"\nnames = \"escaped\"\n");
    assert_eq!(
        FnoxStore::open(&config.stores()[0]).unwrap_err(),
        "`profile = \"prod/x\"` in [secret.store.team] is not a fnox profile name: a profile \
         name has no path separators, commas or control characters."
    );
    // Only fnox stores are opened here.
    let file = section_config("default = \"l\"\n[store.l]\nkind = \"file\"\npath = \"/srv/s\"\n");
    assert!(backends(&file).unwrap().is_empty());
    assert!(matches!(file.stores()[0].kind(), StoreKind::File { .. }));
    assert!(FnoxStore::open(&file.stores()[0])
        .unwrap_err()
        .contains("not a fnox store"));
}

/// A routed space over the fixture: the fnox store `team` (the default) and a file store
/// `local`, with a presence gate that always allows.
fn kernel(fixture: &Fixture, local: &Path) -> Kernel {
    let text = format!(
        "default = \"team\"\n[store.team]\nkind = \"fnox\"\nconfig = {:?}\n\
         [store.team.map]\n\"zoom.client-secret\" = \"ZOOM_SECRET\"\n\"locked\" = \"LOCKED\"\n\
         [store.local]\nkind = \"file\"\npath = {:?}\n[[route]]\nmatch = \"local.*\"\n\
         store = \"local\"\n",
        fixture.config_path().display().to_string(),
        local.display().to_string()
    );
    let routing = routing(section_config(&text), BTreeMap::new()).unwrap();
    let gate = |_: &str| -> ikigai_core::Result<()> { Ok(()) };
    Kernel::new(Arc::new(routed_space_with_gate(
        Arc::new(routing),
        Arc::new(gate),
    )))
}

fn issue(
    kernel: &Kernel,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
    cap: &Capability,
) -> Result<String, Error> {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    futures::executor::block_on(kernel.issue(request, cap))
        .map(|r| String::from_utf8(r.bytes.to_vec()).unwrap())
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

#[test]
fn a_refused_caller_never_reaches_fnox_and_a_granted_one_does() {
    let fixture = Fixture::new();
    let local = tempfile::tempdir().unwrap();
    let kernel = kernel(&fixture, local.path());
    // `locked` would answer the sign-in refusal if fnox were asked. Ungranted, the caller is
    // denied first, so it cannot even learn that the store has trouble.
    for cap in [scoped(&[]), scoped(&["urn:cap:secret:read:other"])] {
        let denied = issue(&kernel, Verb::Source, "urn:secret:locked", &[], &cap).unwrap_err();
        assert!(matches!(denied, Error::Denied(_)), "{denied:?}");
    }
    let granted = issue(
        &kernel,
        Verb::Source,
        "urn:secret:locked",
        &[],
        &scoped(&["urn:cap:secret:read:locked"]),
    )
    .unwrap_err();
    assert!(granted.to_string().contains("needs a sign-in"), "{granted}");
    let value = issue(
        &kernel,
        Verb::Source,
        "urn:secret:zoom.client-secret",
        &[],
        &scoped(&["urn:cap:secret:read:zoom.client-secret"]),
    )
    .unwrap();
    assert_eq!(value, "zoom-sealed-value");
    // A Sink is refused as read-only, after the capability check: ungranted it is Denied.
    let write = scoped(&["urn:cap:secret:write:zoom.client-secret"]);
    let sink = |cap: &Capability| {
        issue(
            &kernel,
            Verb::Sink,
            "urn:secret:zoom.client-secret",
            &[("content", "new")],
            cap,
        )
    };
    assert!(matches!(sink(&scoped(&[])).unwrap_err(), Error::Denied(_)));
    assert_eq!(
        sink(&write).unwrap_err(),
        Error::Conflict(fnox_read_only("team", "zoom.client-secret"))
    );
    // The inspection resource says what the store is, and never where its file is.
    let stores = issue(
        &kernel,
        Verb::Source,
        "urn:secret:store",
        &[],
        &scoped(&[ikigai_secret::INSPECT_SCOPE]),
    )
    .unwrap();
    assert!(
        stores.contains("team: a fnox store, the default, read-only."),
        "{stores}"
    );
    assert!(
        !stores.contains(fixture.dir.path().to_str().unwrap()),
        "{stores}"
    );
}

#[test]
fn a_secret_copies_from_a_fnox_store_into_a_file_store() {
    let fixture = Fixture::new();
    let local = tempfile::tempdir().unwrap();
    let kernel = kernel(&fixture, local.path());
    let both = scoped(&[
        "urn:cap:secret:read:zoom.client-secret",
        "urn:cap:secret:write:zoom.client-secret",
    ]);
    let answer = issue(
        &kernel,
        Verb::Sink,
        "urn:secret:store:name:local:copy",
        &[("from", "team"), ("name", "zoom.client-secret")],
        &both,
    )
    .unwrap();
    assert!(
        answer.starts_with("Copied `zoom.client-secret` from the store team"),
        "{answer}"
    );
    let copied = ikigai_secret::FileBackend::new(local.path())
        .get("zoom.client-secret")
        .unwrap();
    assert_eq!(copied.as_deref(), Some(&b"zoom-sealed-value"[..]));
    // Into the fnox store: refused, a fnox store is read-only.
    let into = issue(
        &kernel,
        Verb::Sink,
        "urn:secret:store:name:team:copy",
        &[("from", "local"), ("name", "zoom.client-secret")],
        &both,
    )
    .unwrap_err();
    assert_eq!(
        into,
        Error::Conflict(
            "the store team is a fnox store, which is read-only, so nothing can be copied into it"
                .into()
        )
    );
}
