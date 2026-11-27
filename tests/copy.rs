//! Copying a secret between stores (ledger #4491, `docs/storage-backends.md` section 8):
//! `urn:secret:store:name:{to}:copy from={store} name={name}`, never deleting the source.
//!
//! ## The fixture
//!
//! ```toml
//! default = "local"
//! [store.local]    kind = "file"                 # a store as 0.5.1 wrote it
//! [store.vault]    kind = "age-file"             # where an install moves to
//! [store.team]     kind = "file"
//! [store.archive]  kind = "file", write = false
//! ```
//!
//! Every store is wrapped in a [`Recording`] that logs each `Backend` call beside the presence
//! gate, so a refused copy can be shown to have touched no store and asked nobody.
//!
//! ## What is pinned
//!
//! - [`missing_any_one_gate_refuses_and_copies_nothing`]: the read scope, the write scope, the
//!   presence gate, each alone missing.
//! - [`a_copy_writes_the_target_and_never_deletes_the_source`], into an age-file store too.
//! - The refusals: a read-only store, a source without the name, a different value without
//!   `replace=true`, the same value (a no-op), a store copied into itself, unknown stores.
//! - [`a_store_written_by_0_5_1_moves_into_age_file_by_copy`]: the upgrade path the copy exists
//!   for, from a store laid out byte for byte as 0.5.1 wrote it.
//! - [`a_failed_write_into_the_target_leaves_the_source_and_no_partial_item`].

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_encrypt::age::{ExposeSecret, Identity};
use ikigai_secret::{
    routed_space_with_gate, AgeFileBackend, Backend, FileBackend, RoutingBackend, SecretConfig,
    SecretSection, X25519Keys, AGE_HEADER,
};

const SECTION: &str = r#"
default = "local"

[store.local]
kind = "file"
path = "/never/local"

[store.vault]
kind = "age-file"
path = "/never/vault"
identity = "file:/never/key"

[store.team]
kind = "file"
path = "/never/team"

[store.archive]
kind = "file"
path = "/never/archive"
write = false
"#;

type Log = Arc<Mutex<Vec<String>>>;

/// A backend that logs every call (`<store> <op> <name>`), then forwards it.
struct Recording {
    store: String,
    inner: Arc<dyn Backend>,
    log: Log,
    /// When set, every write fails, as a full disk would.
    broken: bool,
}

impl Recording {
    fn note(&self, op: &str, name: &str) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{} {op} {name}", self.store));
    }
    fn refuse(&self) -> ikigai_core::Result<()> {
        if self.broken {
            Err(Error::Endpoint(
                "secret write: No space left on device".into(),
            ))
        } else {
            Ok(())
        }
    }
}

impl Backend for Recording {
    fn get(&self, name: &str) -> ikigai_core::Result<Option<Vec<u8>>> {
        self.note("get", name);
        self.inner.get(name)
    }
    fn set(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.note("set", name);
        self.refuse()?;
        self.inner.set(name, value)
    }
    fn delete(&self, name: &str) -> ikigai_core::Result<()> {
        self.note("delete", name);
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> ikigai_core::Result<bool> {
        self.note("exists", name);
        self.inner.exists(name)
    }
    fn replace(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.note("replace", name);
        self.refuse()?;
        self.inner.replace(name, value)
    }
    fn create(&self, name: &str, value: &[u8]) -> ikigai_core::Result<bool> {
        self.note("create", name);
        self.refuse()?;
        self.inner.create(name, value)
    }
    fn accepts_writes(&self, name: &str) -> ikigai_core::Result<()> {
        self.note("accepts_writes", name);
        self.inner.accepts_writes(name)
    }
}

struct World {
    kernel: Kernel,
    log: Log,
    /// The real stores under the recordings, by name, for seeding and checking.
    stores: BTreeMap<String, Arc<dyn Backend>>,
    dirs: BTreeMap<String, tempfile::TempDir>,
    identity: Identity,
}

impl World {
    fn new() -> World {
        Self::with(|_| false, |_, _| {})
    }

    /// A world whose store `name` is broken when `broken(name)`, and whose directories `seed`
    /// may fill before any backend is built.
    fn with(broken: impl Fn(&str) -> bool, seed: impl Fn(&str, &Path)) -> World {
        let identity = Identity::generate();
        let text = format!("{}\n", identity.to_string().expose_secret());
        let section: SecretSection = toml::from_str(SECTION).unwrap();
        let config = SecretConfig::from_section(Some(&section), None).unwrap();
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mut stores = BTreeMap::new();
        let mut dirs = BTreeMap::new();
        let mut backends: BTreeMap<String, Arc<dyn Backend>> = BTreeMap::new();
        for spec in config.stores() {
            let name = spec.name().to_string();
            let dir = tempfile::tempdir().unwrap();
            seed(&name, dir.path());
            let inner: Arc<dyn Backend> = if name == "vault" {
                Arc::new(AgeFileBackend::new(
                    dir.path(),
                    Arc::new(X25519Keys::new(&text, &[]).unwrap()),
                ))
            } else {
                Arc::new(FileBackend::new(dir.path()))
            };
            backends.insert(
                name.clone(),
                Arc::new(Recording {
                    store: name.clone(),
                    inner: inner.clone(),
                    log: log.clone(),
                    broken: broken(&name),
                }),
            );
            stores.insert(name.clone(), inner);
            dirs.insert(name, dir);
        }
        let routing = Arc::new(RoutingBackend::with_stores(config, backends).unwrap());
        let gate_log = log.clone();
        let gate = move |reason: &str| -> ikigai_core::Result<()> {
            gate_log.lock().unwrap().push(format!("gate {reason}"));
            Ok(())
        };
        World {
            kernel: Kernel::new(Arc::new(routed_space_with_gate(routing, Arc::new(gate)))),
            log,
            stores,
            dirs,
            identity,
        }
    }

    fn seed(&self, store: &str, name: &str, value: &[u8]) {
        self.stores[store].set(name, value).unwrap();
    }

    fn held(&self, store: &str, name: &str) -> Option<Vec<u8>> {
        self.stores[store].get(name).unwrap()
    }

    fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn clear(&self) {
        self.log.lock().unwrap().clear();
    }

    fn copy(&self, to: &str, args: &[(&str, &str)], cap: &Capability) -> Result<String, Error> {
        let mut request = Request::new(
            Verb::Sink,
            Iri::parse(format!("urn:secret:store:name:{to}:copy")).unwrap(),
        );
        for (name, value) in args {
            request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
        }
        futures::executor::block_on(self.kernel.issue(request, cap))
            .map(|r| String::from_utf8(r.bytes.to_vec()).unwrap())
    }
}

/// The read and write scopes of `name`: what a copy of it needs.
fn both(name: &str) -> Capability {
    Capability::scoped([
        format!("urn:cap:secret:read:{name}"),
        format!("urn:cap:secret:write:{name}"),
    ])
}

#[test]
fn a_copy_writes_the_target_and_never_deletes_the_source() {
    let world = World::new();
    world.seed("local", "zoom.token", b"z-123");
    let answer = world
        .copy(
            "team",
            &[("from", "local"), ("name", "zoom.token")],
            &both("zoom.token"),
        )
        .unwrap();
    assert_eq!(
        answer,
        "Copied `zoom.token` from the store local into the store team. The store local still \
         holds it."
    );
    assert_eq!(world.held("team", "zoom.token").unwrap(), b"z-123");
    assert_eq!(world.held("local", "zoom.token").unwrap(), b"z-123");
    assert!(!answer.contains("z-123"));
    assert_eq!(
        world.calls(),
        [
            "team accepts_writes zoom.token",
            "gate Copy secret zoom.token from the store local to the store team",
            "local get zoom.token",
            "team get zoom.token",
            "team create zoom.token",
        ]
    );
    assert!(!world.calls().iter().any(|c| c.contains("delete")));

    // Into an age-file store, the copy is encrypted at rest there.
    let answer = world
        .copy(
            "vault",
            &[("from", "local"), ("name", "zoom.token")],
            &both("zoom.token"),
        )
        .unwrap();
    assert!(answer.starts_with("Copied `zoom.token` from the store local into the store vault."));
    let on_disk = std::fs::read(world.dirs["vault"].path().join("zoom.token")).unwrap();
    assert!(on_disk.starts_with(AGE_HEADER));
    assert_eq!(
        ikigai_encrypt::age::open(&on_disk, std::slice::from_ref(&world.identity)).unwrap(),
        b"z-123"
    );

    // The name can arrive piped, as `content`, with its trailing newline dropped.
    world.seed("local", "db.pw", b"pw");
    let piped = world
        .copy(
            "team",
            &[("from", "local"), ("content", "db.pw\n")],
            &both("db.pw"),
        )
        .unwrap();
    assert!(piped.starts_with("Copied `db.pw`"), "{piped}");
}

#[test]
fn missing_any_one_gate_refuses_and_copies_nothing() {
    let world = World::new();
    world.seed("local", "k", b"v");
    let args = [("from", "local"), ("name", "k")];
    for (cap, why) in [
        (
            Capability::scoped(["urn:cap:secret:write:k".to_string()]),
            "", // the kernel's floor refuses before the endpoint: no read grant at all
        ),
        (
            Capability::scoped(["urn:cap:secret:read:k".to_string()]),
            "", // the kernel's floor refuses before the endpoint: no write grant at all
        ),
        (
            Capability::scoped([
                "urn:cap:secret:read:k".to_string(),
                "urn:cap:secret:write:other".to_string(),
            ]),
            "missing `urn:cap:secret:write:k`",
        ),
        (
            Capability::scoped([
                "urn:cap:secret:read:other".to_string(),
                "urn:cap:secret:write:k".to_string(),
            ]),
            "missing `urn:cap:secret:read:k`",
        ),
    ] {
        world.clear();
        let refused = world.copy("team", &args, &cap).unwrap_err();
        assert!(matches!(refused, Error::Denied(_)), "{refused}");
        assert!(refused.to_string().contains(why), "{refused}");
        assert!(world.calls().is_empty(), "{:?}", world.calls());
        assert_eq!(world.held("team", "k"), None);
    }

    // Both scopes, and nobody at the machine: refused by the gate, and no store touched.
    let section: SecretSection = toml::from_str(SECTION).unwrap();
    let config = SecretConfig::from_section(Some(&section), None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut backends: BTreeMap<String, Arc<dyn Backend>> = BTreeMap::new();
    for spec in config.stores() {
        backends.insert(
            spec.name().to_string(),
            Arc::new(FileBackend::new(dir.path().join(spec.name()))),
        );
    }
    let source = backends["local"].clone();
    let target = backends["team"].clone();
    source.set("k", b"v").unwrap();
    let routing = Arc::new(RoutingBackend::with_stores(config, backends).unwrap());
    let nobody = |_: &str| -> ikigai_core::Result<()> { Err(Error::Denied("nobody here".into())) };
    let kernel = Kernel::new(Arc::new(routed_space_with_gate(routing, Arc::new(nobody))));
    let mut request = Request::new(
        Verb::Sink,
        Iri::parse("urn:secret:store:name:team:copy").unwrap(),
    );
    for (name, value) in args {
        request = request.with_arg(name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    let refused = futures::executor::block_on(kernel.issue(request, &both("k"))).unwrap_err();
    assert!(matches!(refused, Error::Denied(ref d) if d.message() == "nobody here"));
    assert_eq!(target.get("k").unwrap(), None);
    assert_eq!(source.get("k").unwrap().unwrap(), b"v");
}

#[test]
fn a_read_only_store_is_refused_before_presence() {
    let world = World::new();
    world.seed("local", "k", b"v");
    let refused = world
        .copy("archive", &[("from", "local"), ("name", "k")], &both("k"))
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        Error::Conflict(
            "the store archive is read-only (`write = false`), so nothing can be copied into it"
                .into()
        )
        .to_string()
    );
    assert!(world.calls().is_empty(), "{:?}", world.calls());
}

#[test]
fn a_source_without_the_name_is_not_found_and_nothing_is_written() {
    let world = World::new();
    let refused = world
        .copy(
            "team",
            &[("from", "local"), ("name", "absent")],
            &both("absent"),
        )
        .unwrap_err();
    assert!(matches!(refused, Error::NotFound(_)), "{refused}");
    assert!(
        refused
            .to_string()
            .contains("the store local holds no secret `absent`, so nothing was copied"),
        "{refused}"
    );
    assert_eq!(world.held("team", "absent"), None);
    assert!(!world.calls().iter().any(|c| c.starts_with("team create")));
}

#[test]
fn a_different_value_is_kept_unless_replace_is_true() {
    let world = World::new();
    world.seed("local", "k", b"fresh-value");
    world.seed("team", "k", b"stale-value");
    let refused = world
        .copy("team", &[("from", "local"), ("name", "k")], &both("k"))
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        Error::Conflict(
            "the store team already holds a different value for `k`, so nothing was copied; \
             copy again with replace=true to replace it"
                .into()
        )
        .to_string()
    );
    assert_eq!(world.held("team", "k").unwrap(), b"stale-value");
    for (value, words) in [("false", true), ("yes", false)] {
        let again = world
            .copy(
                "team",
                &[("from", "local"), ("name", "k"), ("replace", value)],
                &both("k"),
            )
            .unwrap_err();
        assert_eq!(matches!(again, Error::Conflict(_)), words, "{again}");
    }
    let replaced = world
        .copy(
            "team",
            &[("from", "local"), ("name", "k"), ("replace", "true")],
            &both("k"),
        )
        .unwrap();
    assert_eq!(
        replaced,
        "Replaced `k` in the store team with the value from the store local. The store local \
         still holds it."
    );
    assert_eq!(world.held("team", "k").unwrap(), b"fresh-value");
    assert_eq!(world.held("local", "k").unwrap(), b"fresh-value");
    assert!(!replaced.contains("value-") && !replaced.contains("fresh"));
}

#[test]
fn the_same_value_writes_nothing() {
    let world = World::new();
    world.seed("local", "k", b"same");
    world.seed("team", "k", b"same");
    world.clear();
    let answer = world
        .copy("team", &[("from", "local"), ("name", "k")], &both("k"))
        .unwrap();
    assert_eq!(
        answer,
        "The store team already holds the same value for `k`, so nothing was written. The store \
         local still holds it."
    );
    assert!(!world
        .calls()
        .iter()
        .any(|c| c.contains("create") || c.contains("replace") || c.contains(" set ")));
}

/// One refused call: the target store, the arguments, and words the refusal carries.
type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);

#[test]
fn arguments_are_refused_before_any_store() {
    let world = World::new();
    world.seed("local", "k", b"v");
    // (to, args, words the refusal carries)
    let cases: [Case; 5] = [
        ("team", &[("from", "team"), ("name", "k")], "into itself"),
        (
            "team",
            &[("from", "nope"), ("name", "k")],
            "no store named `nope`",
        ),
        (
            "nope",
            &[("from", "local"), ("name", "k")],
            "no store named `nope`",
        ),
        ("team", &[("from", "local")], "name"),
        (
            "team",
            &[("from", "local"), ("name", "k"), ("content", "k")],
            "named twice",
        ),
    ];
    for (to, args, why) in cases {
        world.clear();
        let refused = world.copy(to, args, &both("k")).unwrap_err();
        assert!(
            refused.to_string().contains(why),
            "{to} {args:?}: {refused}"
        );
        assert!(world.calls().is_empty(), "{:?}", world.calls());
    }
    // `from` is required.
    let missing = world
        .copy("team", &[("name", "k")], &both("k"))
        .unwrap_err();
    assert!(
        matches!(missing, Error::MissingArgument(ref a) if a == "from"),
        "{missing}"
    );
}

/// A store directory as ikigai-secret 0.5.1 (and 0.5.2) wrote it: names escaped, whole files,
/// the directory `0700` and each file `0600`.
fn as_0_5_1_wrote_it(dir: &Path) {
    for (file, bytes) in [
        ("api.token", &b"tok-1234"[..]),
        ("team%3adb", b"postgres://u:p@db/x"),
    ] {
        let path = dir.join(file);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_store_written_by_0_5_1_moves_into_age_file_by_copy() {
    let world = World::with(
        |_| false,
        |store, dir| {
            if store == "local" {
                as_0_5_1_wrote_it(dir);
            }
        },
    );
    for (name, bytes) in [
        ("api.token", &b"tok-1234"[..]),
        ("team:db", b"postgres://u:p@db/x"),
    ] {
        world
            .copy("vault", &[("from", "local"), ("name", name)], &both(name))
            .unwrap();
        assert_eq!(world.held("vault", name).unwrap(), bytes);
        assert_eq!(
            world.held("local", name).unwrap(),
            bytes,
            "the source keeps {name}"
        );
    }
    // The old store's files are byte for byte what 0.5.1 wrote.
    assert_eq!(
        std::fs::read(world.dirs["local"].path().join("team%3adb")).unwrap(),
        b"postgres://u:p@db/x"
    );
    for file in ["api.token", "team%3adb"] {
        let sealed = std::fs::read(world.dirs["vault"].path().join(file)).unwrap();
        assert!(sealed.starts_with(AGE_HEADER), "{file}");
    }
}

#[test]
fn a_failed_write_into_the_target_leaves_the_source_and_no_partial_item() {
    let world = World::with(|store| store == "team", |_, _| {});
    world.seed("local", "k", b"v");
    let failed = world
        .copy("team", &[("from", "local"), ("name", "k")], &both("k"))
        .unwrap_err();
    assert!(
        failed.to_string().contains("No space left on device"),
        "{failed}"
    );
    assert_eq!(world.held("local", "k").unwrap(), b"v");
    assert_eq!(world.held("team", "k"), None);
    let leftovers: Vec<_> = std::fs::read_dir(world.dirs["team"].path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
