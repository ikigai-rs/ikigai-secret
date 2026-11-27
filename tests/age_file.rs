//! The `age-file` store (ledger #4488, `docs/storage-backends.md` sections 6.3 and 8): each item
//! age-encrypted at rest, the in-place move from `file`, `reencrypt`, and the new-install default.
//!
//! ## Upgrade from older versions
//!
//! A store "as 0.5.1 wrote it" is built byte for byte by [`store_as_0_5_1_wrote_it`]: the file
//! store's format has not changed since 0.1.7 (0.5.2 and the 0.4.x line write the same layout),
//! so the fixture spells each file name and its whole content literally, with the modes 0.5.1
//! set, rather than calling this release's code to make it. Pinned:
//!
//! - [`a_store_written_by_0_5_1_reads_unchanged_and_a_write_encrypts`];
//! - [`reencrypt_converts_everything_and_a_second_run_changes_nothing`];
//! - [`a_crash_mid_reencrypt_leaves_every_item_readable`]: a seal that fails partway, and a
//!   temporary file a killed process left behind;
//! - [`a_downgrade_then_a_re_upgrade`]: what the older file store reads from an encrypted store,
//!   what it writes there, and the age-file store reading both again.
//!
//! The Keychain cannot run here (TCC), so its half of the new-install probe is injected.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_encrypt::age::{ExposeSecret, Identity};
use ikigai_secret::{
    found_install, routed_space_with_gate, AgeError, AgeFileBackend, AgeKeys, Backend, FileBackend,
    Found, SecretConfig, SecretSection, StoreKind, X25519Keys, AGE_HEADER,
};

// =====================================================================================
// Fixtures.
// =====================================================================================

/// A store directory exactly as ikigai-secret 0.5.1 (and 0.5.2, and 0.4.x) wrote it: one regular
/// file per secret, the whole content the secret's bytes, named by the injective escape
/// (`a`-`z`, `0`-`9`, `-`, `_` and a non-leading `.` verbatim, every other byte `%xx`), the
/// directory `0700` and each file `0600`.
fn store_as_0_5_1_wrote_it(dir: &Path) -> Vec<(&'static str, &'static [u8])> {
    let items: Vec<(&str, &str, &[u8])> = vec![
        ("api.token", "api.token", b"tok-1234"),
        ("team:db", "team%3adb", b"postgres://u:p@db/x"),
        ("API-KEY", "%41%50%49-%4b%45%59", b"UPPER"),
        (
            "owner:id:acme:name:zoom",
            "owner%3aid%3aacme%3aname%3azoom",
            b"zoom-secret",
        ),
        ("bin", "bin", b"\x00\x01\xff\xfe binary"),
        ("empty", "empty", b""),
    ];
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (_, file, bytes) in &items {
        let path = dir.join(file);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    items
        .into_iter()
        .map(|(name, _, bytes)| (name, bytes))
        .collect()
}

fn identity_text(identity: &Identity) -> String {
    format!(
        "# test identity\n{}\n",
        identity.to_string().expose_secret()
    )
}

fn keys(identity: &Identity) -> Arc<X25519Keys> {
    Arc::new(X25519Keys::new(&identity_text(identity), &[]).unwrap())
}

/// One request's answer as text, or the error.
type Answer = Result<String, Error>;

/// A routed space over one age-file store `vault` at `dir` (and a plain `file` store `plain`
/// beside it), its gate logged.
struct World {
    kernel: Kernel,
    gate: Arc<Mutex<Vec<String>>>,
}

impl World {
    fn new(dir: &Path, keys: Arc<dyn AgeKeys>) -> World {
        Self::with_section(dir, keys, "")
    }

    fn with_section(dir: &Path, keys: Arc<dyn AgeKeys>, extra: &str) -> World {
        let plain = dir.with_extension("plain");
        let text = format!(
            "default = \"vault\"\n\
             [store.vault]\nkind = \"age-file\"\npath = \"{}\"\nidentity = \"file:/k\"\n{extra}\
             [store.plain]\nkind = \"file\"\npath = \"{}\"\n\
             [[route]]\nmatch = \"plain.*\"\nstore = \"plain\"\n",
            dir.display(),
            plain.display()
        );
        let section: SecretSection = toml::from_str(&text).unwrap();
        let config = SecretConfig::from_section(Some(&section), None).unwrap();
        let routing = Arc::new(
            config
                .build_with_keys(BTreeMap::from([("vault".to_string(), keys)]))
                .unwrap(),
        );
        let gate = Arc::new(Mutex::new(Vec::new()));
        let log = gate.clone();
        let present = move |reason: &str| -> ikigai_core::Result<()> {
            log.lock().unwrap().push(reason.to_string());
            Ok(())
        };
        World {
            kernel: Kernel::new(Arc::new(routed_space_with_gate(routing, Arc::new(present)))),
            gate,
        }
    }

    fn issue(&self, verb: Verb, iri: &str, content: Option<&[u8]>, cap: &Capability) -> Answer {
        let mut request = Request::new(verb, Iri::parse(iri).unwrap());
        if let Some(content) = content {
            request = request.with_arg("content", ArgRef::Inline(content.to_vec()));
        }
        futures::executor::block_on(self.kernel.issue(request, cap))
            .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, Error> {
        let request = Request::new(
            Verb::Source,
            Iri::parse(format!("urn:secret:{name}")).unwrap(),
        );
        let cap = Capability::scoped([format!("urn:cap:secret:read:{name}")]);
        futures::executor::block_on(self.kernel.issue(request, &cap)).map(|r| r.bytes.to_vec())
    }

    fn write(&self, name: &str, value: &[u8]) {
        let cap = Capability::scoped([format!("urn:cap:secret:write:{name}")]);
        self.issue(Verb::Sink, &format!("urn:secret:{name}"), Some(value), &cap)
            .unwrap();
    }

    fn reencrypt(&self, cap: &Capability) -> Answer {
        self.issue(
            Verb::Sink,
            "urn:secret:store:name:vault:reencrypt",
            None,
            cap,
        )
    }
}

/// The write scope of every name in `names`.
fn writes(names: &[&str]) -> Capability {
    Capability::scoped(names.iter().map(|n| format!("urn:cap:secret:write:{n}")))
}

/// Every non-hidden file in `dir` and its bytes, by file name.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| e.file_name().into_string().unwrap())
        .filter(|f| !f.starts_with('.'))
        .map(|f| {
            let bytes = std::fs::read(dir.join(&f)).unwrap();
            (f, bytes)
        })
        .collect()
}

/// The backup directories made beside `dir`.
fn backups(dir: &Path) -> Vec<PathBuf> {
    let prefix = format!("{}.backup-", dir.file_name().unwrap().to_str().unwrap());
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    found.sort();
    found
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

// =====================================================================================
// The store.
// =====================================================================================

#[test]
fn a_store_written_by_0_5_1_reads_unchanged_and_a_write_encrypts() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let items = store_as_0_5_1_wrote_it(&dir);
    let identity = Identity::generate();
    let world = World::new(&dir, keys(&identity));

    // Every item 0.5.1 wrote reads exactly as it did, through the age-file store.
    for (name, bytes) in &items {
        assert_eq!(world.read(name).unwrap(), *bytes, "{name}");
    }
    // And nothing was rewritten by reading.
    assert!(!snapshot(&dir).values().any(|b| b.starts_with(AGE_HEADER)));
    assert!(!dir.join(".ikigai-age-file").exists());

    // A write encrypts: the file on disk is a binary age file the identity opens, private.
    world.write("api.token", b"tok-5678");
    let on_disk = std::fs::read(dir.join("api.token")).unwrap();
    assert!(on_disk.starts_with(AGE_HEADER));
    assert!(!on_disk.windows(8).any(|w| w == b"tok-5678"));
    assert_eq!(
        ikigai_encrypt::age::open(&on_disk, std::slice::from_ref(&identity)).unwrap(),
        b"tok-5678"
    );
    assert_eq!(mode(&dir.join("api.token")), 0o600);
    assert_eq!(world.read("api.token").unwrap(), b"tok-5678");
    // The marker is there now, so a host with no section knows it for an age-file store.
    assert!(dir.join(".ikigai-age-file").exists());
    // The other items are still the plaintext 0.5.1 wrote.
    assert_eq!(
        std::fs::read(dir.join("team%3adb")).unwrap(),
        b"postgres://u:p@db/x"
    );
}

#[test]
fn an_item_sealed_to_another_identity_is_refused_never_served_as_the_secret() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let other = Identity::generate();
    let foreign = AgeFileBackend::new(&dir, keys(&other));
    foreign.set("x", b"theirs").unwrap();
    let world = World::new(&dir, keys(&Identity::generate()));
    let refused = world.read("x").unwrap_err();
    assert_eq!(
        refused.to_string(),
        Error::Endpoint(
            "the secret `x` cannot be read: it is an age file sealed to no identity this store \
             holds. It is left as it is; inspect it at the box with `age -d -i <identity>`"
                .into()
        )
        .to_string()
    );
    // A torn age file is refused the same way, naming what is wrong.
    let mut torn = std::fs::read(dir.join("x")).unwrap();
    torn.truncate(torn.len() - 5);
    std::fs::write(dir.join("x"), &torn).unwrap();
    let world = World::new(&dir, keys(&other));
    let why = world.read("x").unwrap_err().to_string();
    assert!(why.contains("it is not a whole age file"), "{why}");
}

#[test]
fn recipients_seal_every_item_to_a_recovery_key_too() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let host = Identity::generate();
    let recovery = Identity::generate();
    let keys = X25519Keys::new(&identity_text(&host), &[recovery.to_public().to_string()]).unwrap();
    let world = World::new(&dir, Arc::new(keys));
    world.write("db", b"pw");
    let on_disk = std::fs::read(dir.join("db")).unwrap();
    assert_eq!(
        ikigai_encrypt::age::open(&on_disk, &[recovery]).unwrap(),
        b"pw"
    );
    assert_eq!(ikigai_encrypt::age::open(&on_disk, &[host]).unwrap(), b"pw");
}

#[test]
fn x25519_keys_refuse_a_plugin_recipient_and_bad_identity_text() {
    let host = identity_text(&Identity::generate());
    let plugin = X25519Keys::new(&host, &["age1yubikey1qwertyuiop".to_string()]).unwrap_err();
    assert!(
        plugin
            .to_string()
            .contains("entry 1 of `recipients` is an age-plugin-yubikey recipient"),
        "{plugin}"
    );
    let empty = X25519Keys::new("# nothing here\n", &[]).unwrap_err();
    assert!(
        empty.to_string().contains("holds no age identity"),
        "{empty}"
    );
    let bad = X25519Keys::new("AGE-SECRET-KEY-1NOPE\n", &[]).unwrap_err();
    assert!(
        !bad.to_string().contains("NOPE"),
        "a refusal never echoes key text: {bad}"
    );
}

#[test]
fn without_keys_an_age_file_store_refuses_every_operation_saying_why() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let section: SecretSection = toml::from_str(&format!(
        "default = \"vault\"\n[store.vault]\nkind = \"age-file\"\npath = \"{}\"\n\
         identity = \"tpm:/k\"\n",
        dir.display()
    ))
    .unwrap();
    let config = SecretConfig::from_section(Some(&section), None).unwrap();
    let routing = config.clone().build();
    let why = routing.get("x").unwrap_err().to_string();
    assert!(
        why.contains(
            "the store vault is an age-file store, and the host was not given its age \
                      identity (identity = \"tpm:/k\")"
        ),
        "{why}"
    );
    assert!(routing.set("x", b"v").is_err());
    assert!(!dir.exists(), "nothing was made");
    assert_eq!(
        routing.backend("vault").unwrap().health(),
        "unavailable: the host was not given this store's age identity"
    );

    let missing = config
        .clone()
        .build_with_keys(BTreeMap::new())
        .err()
        .unwrap();
    assert_eq!(missing.problems().len(), 1, "{missing}");
    let extra = config
        .build_with_keys(BTreeMap::from([
            (
                "vault".to_string(),
                keys(&Identity::generate()) as Arc<dyn AgeKeys>,
            ),
            (
                "nope".to_string(),
                keys(&Identity::generate()) as Arc<dyn AgeKeys>,
            ),
        ]))
        .err()
        .unwrap();
    assert_eq!(
        extra.problems(),
        ["age keys were given for nope, which is not a configured store."]
    );
}

// =====================================================================================
// Reencrypt.
// =====================================================================================

const ALL: [&str; 6] = [
    "api.token",
    "team:db",
    "API-KEY",
    "owner:id:acme:name:zoom",
    "bin",
    "empty",
];

#[test]
fn reencrypt_converts_everything_and_a_second_run_changes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let items = store_as_0_5_1_wrote_it(&dir);
    let before = snapshot(&dir);
    let identity = Identity::generate();
    let world = World::new(&dir, keys(&identity));

    let answer = world.reencrypt(&writes(&ALL)).unwrap();
    let backup = backups(&dir);
    assert_eq!(backup.len(), 1, "{answer}");
    assert_eq!(
        answer,
        format!(
            "Backed up the store to {} before converting it; remove that copy once you have \
             checked the store, since it holds the plaintext.\n\
             API-KEY: encrypted.\n\
             api.token: encrypted.\n\
             bin: encrypted.\n\
             empty: encrypted.\n\
             owner:id:acme:name:zoom: encrypted.\n\
             team:db: encrypted.\n\
             Encrypted 6 items; 0 already encrypted; 0 left as they were. Only items this \
             capability may write were looked at.",
            backup[0].display()
        )
    );
    assert_eq!(
        world.gate.lock().unwrap().as_slice(),
        ["Encrypt the secrets in the store vault"]
    );
    // The backup is the store as it was, private.
    assert_eq!(snapshot(&backup[0]), before);
    assert_eq!(mode(&backup[0]), 0o700);
    for file in before.keys() {
        assert_eq!(mode(&backup[0].join(file)), 0o600);
    }
    // Every item is now an age file, private, and reads as it did.
    let after = snapshot(&dir);
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>()
    );
    for (file, bytes) in &after {
        assert!(bytes.starts_with(AGE_HEADER), "{file}");
        assert_eq!(mode(&dir.join(file)), 0o600);
    }
    for (name, bytes) in &items {
        assert_eq!(world.read(name).unwrap(), *bytes, "{name}");
    }

    // A second run changes nothing: no new backup, every byte the same.
    let again = world.reencrypt(&writes(&ALL)).unwrap();
    assert!(
        again.starts_with("API-KEY: already encrypted, unchanged.\n"),
        "{again}"
    );
    assert!(
        again.ends_with(
            "Encrypted 0 items; 6 already encrypted; 0 left as they were. Only items this \
             capability may write were looked at."
        ),
        "{again}"
    );
    assert_eq!(backups(&dir).len(), 1);
    assert_eq!(snapshot(&dir), after);
}

#[test]
fn reencrypt_reads_and_names_only_what_the_caller_may_write() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    store_as_0_5_1_wrote_it(&dir);
    let before = snapshot(&dir);
    let world = World::new(&dir, keys(&Identity::generate()));

    // Under no write scope at all: refused by the declared floor, nothing touched, no prompt.
    let refused = world
        .reencrypt(&Capability::scoped([
            "urn:cap:secret:read:team:db".to_string()
        ]))
        .unwrap_err();
    assert!(matches!(refused, Error::Denied(_)), "{refused}");
    assert!(world.gate.lock().unwrap().is_empty());
    assert_eq!(snapshot(&dir), before);
    assert!(backups(&dir).is_empty());

    // Under one name's write scope: that item alone, and no other name appears.
    let answer = world.reencrypt(&writes(&["team:db"])).unwrap();
    for other in ["api.token", "API-KEY", "zoom", "bin", "empty"] {
        assert!(!answer.contains(other), "{other} named in: {answer}");
    }
    assert!(
        answer.contains("\nteam:db: encrypted.\nEncrypted 1 item; 0 already"),
        "{answer}"
    );
    let after = snapshot(&dir);
    for (file, bytes) in &after {
        assert_eq!(bytes.starts_with(AGE_HEADER), file == "team%3adb", "{file}");
    }
}

#[test]
fn reencrypt_refuses_a_store_that_is_not_age_file_or_is_read_only_before_the_gate() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let world = World::new(&dir, keys(&Identity::generate()));
    let file = world
        .issue(
            Verb::Sink,
            "urn:secret:store:name:plain:reencrypt",
            None,
            &writes(&["x"]),
        )
        .unwrap_err();
    assert!(
        file.to_string().contains(
            "the store plain is a file store, which does not encrypt its items; only an \
             age-file store can be reencrypted"
        ),
        "{file}"
    );
    let none = world
        .issue(
            Verb::Sink,
            "urn:secret:store:name:nope:reencrypt",
            None,
            &writes(&["x"]),
        )
        .unwrap_err();
    assert!(matches!(none, Error::NotFound(_)), "{none}");

    let read_only = World::with_section(&dir, keys(&Identity::generate()), "write = false\n");
    let refused = read_only.reencrypt(&writes(&["x"])).unwrap_err();
    assert!(refused.to_string().contains("is read-only"), "{refused}");
    assert!(world.gate.lock().unwrap().is_empty());
    assert!(read_only.gate.lock().unwrap().is_empty());
}

#[test]
fn a_refused_presence_gate_reencrypts_nothing() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    store_as_0_5_1_wrote_it(&dir);
    let before = snapshot(&dir);
    let section: SecretSection = toml::from_str(&format!(
        "default = \"vault\"\n[store.vault]\nkind = \"age-file\"\npath = \"{}\"\nidentity = \"x\"\n",
        dir.display()
    ))
    .unwrap();
    let routing = Arc::new(
        SecretConfig::from_section(Some(&section), None)
            .unwrap()
            .build_with_keys(BTreeMap::from([(
                "vault".to_string(),
                keys(&Identity::generate()) as Arc<dyn AgeKeys>,
            )]))
            .unwrap(),
    );
    let nobody = |_: &str| -> ikigai_core::Result<()> { Err(Error::Denied("nobody here".into())) };
    let kernel = Kernel::new(Arc::new(routed_space_with_gate(routing, Arc::new(nobody))));
    let request = Request::new(
        Verb::Sink,
        Iri::parse("urn:secret:store:name:vault:reencrypt").unwrap(),
    );
    let refused = futures::executor::block_on(kernel.issue(request, &writes(&ALL))).unwrap_err();
    assert!(matches!(refused, Error::Denied(ref d) if d.message() == "nobody here"));
    assert_eq!(snapshot(&dir), before);
    assert!(backups(&dir).is_empty());
}

/// Keys that seal the first `budget` items and then fail, as a process killed partway would stop.
struct FailAfter {
    inner: Arc<X25519Keys>,
    budget: usize,
    sealed: AtomicUsize,
}

impl AgeKeys for FailAfter {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AgeError> {
        if self.sealed.fetch_add(1, Ordering::SeqCst) >= self.budget {
            return Err(AgeError::Failed("the test stopped sealing here".into()));
        }
        self.inner.seal(plaintext)
    }
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AgeError> {
        self.inner.open(ciphertext)
    }
}

#[test]
fn a_crash_mid_reencrypt_leaves_every_item_readable() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let items = store_as_0_5_1_wrote_it(&dir);
    let identity = Identity::generate();
    // A killed process can leave its temporary file behind (written, never renamed).
    std::fs::write(dir.join(".tmp-00000000deadbeef"), b"half a secret").unwrap();

    let failing = Arc::new(FailAfter {
        inner: keys(&identity),
        budget: 3,
        sealed: AtomicUsize::new(0),
    });
    let world = World::new(&dir, failing);
    let refused = world.reencrypt(&writes(&ALL)).unwrap_err().to_string();
    assert!(
        refused.contains("Encrypted 3 items; 0 already encrypted; 3 left as they were."),
        "{refused}"
    );
    assert!(
        refused.contains(
            "empty: left as it is, because it could not be sealed: the test stopped \
                          sealing here."
        ),
        "{refused}"
    );
    assert!(refused.contains("run reencrypt again: every item already encrypted stays encrypted"));

    // Every item reads as it did, three of them now encrypted and three still plaintext.
    let world = World::new(&dir, keys(&identity));
    for (name, bytes) in &items {
        assert_eq!(world.read(name).unwrap(), *bytes, "{name}");
    }
    let sealed = snapshot(&dir)
        .values()
        .filter(|b| b.starts_with(AGE_HEADER))
        .count();
    assert_eq!(sealed, 3);
    // The leftover temporary file is no secret: never listed, never named, never read.
    let answer = world.reencrypt(&writes(&ALL)).unwrap();
    assert!(!answer.contains("deadbeef"), "{answer}");
    assert!(
        answer.contains("Encrypted 3 items; 3 already encrypted; 0 left"),
        "{answer}"
    );
    for (name, bytes) in &items {
        assert_eq!(world.read(name).unwrap(), *bytes, "{name}");
    }
    // Two backups: one per run that had something to convert. Each holds the plaintext as it
    // was at that run.
    assert_eq!(backups(&dir).len(), 2);
}

#[test]
fn a_downgrade_then_a_re_upgrade() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("secrets");
    let items = store_as_0_5_1_wrote_it(&dir);
    let identity = Identity::generate();
    let world = World::new(&dir, keys(&identity));
    world.write("new.secret", b"written by 0.5.3");
    world.reencrypt(&writes(&ALL)).unwrap();

    // Downgrade: the file store of 0.5.2 and earlier (this crate's `FileBackend`, whose format is
    // unchanged) reads each encrypted item as its age file, which the stock age tool opens with
    // the identity; it never sees the marker.
    let older = FileBackend::new(&dir);
    let raw = older.get("api.token").unwrap().unwrap();
    assert!(raw.starts_with(AGE_HEADER));
    assert_eq!(
        ikigai_encrypt::age::open(&raw, std::slice::from_ref(&identity)).unwrap(),
        b"tok-1234"
    );
    assert!(!older.exists(".ikigai-age-file").unwrap_or(false));
    // It writes plaintext, as it always did.
    older.set("api.token", b"rotated while downgraded").unwrap();
    older.set("downgraded.only", b"plain").unwrap();

    // Re-upgrade: the age-file store reads both kinds, and reencrypt converts what the older
    // release wrote.
    let world = World::new(&dir, keys(&identity));
    assert_eq!(
        world.read("api.token").unwrap(),
        b"rotated while downgraded"
    );
    assert_eq!(world.read("downgraded.only").unwrap(), b"plain");
    assert_eq!(world.read("new.secret").unwrap(), b"written by 0.5.3");
    for (name, bytes) in items.iter().filter(|(n, _)| *n != "api.token") {
        assert_eq!(world.read(name).unwrap(), *bytes, "{name}");
    }
    let answer = world
        .reencrypt(&writes(
            &[&ALL[..], &["new.secret", "downgraded.only"]].concat(),
        ))
        .unwrap();
    assert!(
        answer.contains("Encrypted 2 items; 6 already encrypted; 0 left"),
        "{answer}"
    );
    assert!(snapshot(&dir).values().all(|b| b.starts_with(AGE_HEADER)));
}

// =====================================================================================
// The new-install default.
// =====================================================================================

#[test]
fn a_new_install_gets_age_file_and_keeps_it_on_the_next_start() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // No store yet. (`found_install` asks the real Keychain on a Mac, so its answer there depends
    // on the machine; the injected probe is pinned in the crate's unit tests.)
    if !cfg!(target_os = "macos") && std::env::var_os("IKIGAI_SECRETS").is_none() {
        assert_eq!(found_install(Some(&home)).unwrap(), Found::Nothing);
    }
    let config = SecretConfig::for_host(None, Some(&home), Found::Nothing).unwrap();
    let StoreKind::AgeFile { dir, .. } = config.stores()[0].kind().clone() else {
        panic!("{config:?}");
    };
    assert_eq!(dir, home.join(".ikigai/secrets"));
    let identity = Identity::generate();
    let routing = config
        .build_with_keys(BTreeMap::from([(
            "age-file".to_string(),
            keys(&identity) as Arc<dyn AgeKeys>,
        )]))
        .unwrap();
    routing.set("first", b"secret").unwrap();
    // The next start finds the age-file store it made, not a plaintext store from before.
    if std::env::var_os("IKIGAI_SECRETS").is_none() {
        assert_eq!(found_install(Some(&home)).unwrap(), Found::AgeFile);
    }
}
