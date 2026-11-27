//! Stores and routes (ledger #4486): the routed space, held to the module recipe and to the
//! rules every store keeps (`docs/storage-backends.md`, section 2).
//!
//! ## The fixture
//!
//! Three FILE stores, each over its own scratch directory and each wrapped in a [`Recording`]
//! that logs every `Backend` call (and the presence gate, which logs beside them), so a test can
//! say which store a request reached and that a refused one reached none:
//!
//! ```toml
//! default = "local"
//! [store.local]    kind = "file"
//! [store.team]     kind = "file"
//! [store.archive]  kind = "file", write = false
//! [[route]] match = "owner:id:acme:name:*"  store = "team"
//! [[route]] match = "zoom.*"                store = "team"
//! [[route]] match = "old.*"                 store = "archive"
//! ```
//!
//! The Keychain and the Enclave cannot run in CI or from an agent shell (TCC), so they are not
//! walked; the routing is the same code over any store.
//!
//! ## What is pinned
//!
//! - [`conforms`]: `ikigai-conformance` walks all eight endpoints of the routed space. `secret`
//!   and `secret-store-name` (its health line is read now) are declared live; `secret-store`,
//!   `secret-route` and `secret-route-secret` cacheable. `secret-store-reencrypt` (ledger #4488)
//!   is a Sink with no `content`, so the walk fires it only under no grants; `tests/age_file.rs`
//!   pins what it does.
//! - [`every_inspection_resource_answers_under_its_narrow_grant`] and the JSON faces.
//! - [`no_capability_check_is_skipped_on_any_routed_path`]: every verb, on a name routed to each
//!   store and to the default, under no grants and under grants for other names: refused, and no
//!   store and no gate touched.
//! - [`a_route_never_widens_a_scope`].
//! - [`one_store_per_name_a_miss_is_not_found`]: never "try the next store".
//! - [`a_read_only_store_refuses_writes_after_the_capability_and_before_presence`].
//! - [`with_no_section_every_call_reaches_the_one_store_unchanged`]: today's behavior.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ikigai_conformance::{Check, Checks, Fixture, Suite};
use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Error, Expiry, Iri, Kernel, MetaRenderer,
    ReprType, Representation, Request, Verb,
};
use ikigai_secret::{
    routed_space_with_gate, Backend, FileBackend, PresenceGate, RoutingBackend, SecretConfig,
    SecretSection, Signed, CONFIG_THREAD, GENERATE_IRI, INSPECT_SCOPE, ROUTE_IRI, STORE_IRI,
};

const SECTION: &str = r#"
default = "local"

[store.local]
kind = "file"
path = "/never/local"

[store.team]
kind = "file"
path = "/never/team"

[store.archive]
kind = "file"
path = "/never/archive"
write = false

[[route]]
match = "owner:id:acme:name:*"
store = "team"

[[route]]
match = "zoom.*"
store = "team"

[[route]]
match = "old.*"
store = "archive"
"#;

/// One logged call: which store, what, on which name. The gate logs as store `gate`.
type Call = (String, String, String);

/// One request a test fires: the verb, the IRI and the inline arguments.
type Attempt<'a> = (Verb, &'a str, Vec<(&'a str, &'a str)>);

/// A file store that logs every call to a log shared by every store and the gate.
struct Recording {
    store: String,
    inner: FileBackend,
    log: Arc<Mutex<Vec<Call>>>,
}

impl Recording {
    fn note(&self, op: &str, name: &str) {
        self.log
            .lock()
            .unwrap()
            .push((self.store.clone(), op.into(), name.into()));
    }
}

impl Backend for Recording {
    fn get(&self, name: &str) -> ikigai_core::Result<Option<Vec<u8>>> {
        self.note("get", name);
        self.inner.get(name)
    }
    fn set(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.note("set", name);
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
        self.inner.replace(name, value)
    }
    fn create(&self, name: &str, value: &[u8]) -> ikigai_core::Result<bool> {
        self.note("create", name);
        self.inner.create(name, value)
    }
    fn sign(&self, name: &str, message: &[u8]) -> ikigai_core::Result<Option<Signed>> {
        self.note("sign", name);
        self.inner.sign(name, message)
    }
    fn generate_signing_key(&self, name: &str) -> ikigai_core::Result<Option<(String, Vec<u8>)>> {
        self.note("generate_signing_key", name);
        self.inner.generate_signing_key(name)
    }
    fn accepts_writes(&self, name: &str) -> ikigai_core::Result<()> {
        self.note("accepts_writes", name);
        self.inner.accepts_writes(name)
    }
    fn health(&self) -> String {
        self.note("health", "");
        self.inner.health()
    }
}

/// The presence gate: logs, and finds someone at the machine.
struct Gate(Arc<Mutex<Vec<Call>>>);

impl PresenceGate for Gate {
    fn require(&self, reason: &str) -> ikigai_core::Result<()> {
        self.0
            .lock()
            .unwrap()
            .push(("gate".into(), "require".into(), reason.into()));
        Ok(())
    }
}

/// Every field of a description as text: the catalog and `Meta` render through it.
struct EveryField;

impl MetaRenderer for EveryField {
    fn render(
        &self,
        description: &Description,
        _target: &ReprType,
    ) -> ikigai_core::Result<Representation> {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            format!("{description:#?}").into_bytes(),
        ))
    }
}

struct World {
    kernel: Kernel,
    space: Arc<EndpointSpace>,
    log: Arc<Mutex<Vec<Call>>>,
    stores: BTreeMap<String, Arc<Recording>>,
    _dirs: Vec<tempfile::TempDir>,
}

impl World {
    fn calls(&self) -> Vec<Call> {
        self.log.lock().unwrap().clone()
    }
    fn clear(&self) {
        self.log.lock().unwrap().clear();
    }
    fn issue(
        &self,
        verb: Verb,
        iri: &str,
        args: &[(&str, &str)],
        capability: &Capability,
    ) -> Result<Representation, Error> {
        futures::executor::block_on(self.kernel.issue(request(verb, iri, args), capability))
    }
    fn text(&self, iri: &str, capability: &Capability) -> String {
        let repr = self
            .issue(Verb::Source, iri, &[], capability)
            .unwrap_or_else(|e| panic!("{iri}: {e}"));
        String::from_utf8(repr.bytes).unwrap()
    }
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

fn world_from(config: SecretConfig) -> World {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut dirs = Vec::new();
    let mut stores = BTreeMap::new();
    let mut backends: BTreeMap<String, Arc<dyn Backend>> = BTreeMap::new();
    for spec in config.stores() {
        let dir = tempfile::tempdir().unwrap();
        let recording = Arc::new(Recording {
            store: spec.name().to_string(),
            inner: FileBackend::new(dir.path()),
            log: log.clone(),
        });
        dirs.push(dir);
        backends.insert(spec.name().to_string(), recording.clone());
        stores.insert(spec.name().to_string(), recording);
    }
    let routing = Arc::new(RoutingBackend::with_stores(config, backends).unwrap());
    let space = Arc::new(routed_space_with_gate(routing, Arc::new(Gate(log.clone()))));
    let kernel = Kernel::with_meta_renderer(space.clone(), Arc::new(EveryField));
    World {
        kernel,
        space,
        log,
        stores,
        _dirs: dirs,
    }
}

fn world() -> World {
    let section: SecretSection = toml::from_str(SECTION).unwrap();
    world_from(SecretConfig::from_section(Some(&section), None).unwrap())
}

/// Seed `name` straight into one store, bypassing the routing (and the log).
fn seed(world: &World, store: &str, name: &str, value: &[u8]) {
    world.stores[store].inner.set(name, value).unwrap();
}

// =====================================================================================

#[test]
fn conforms() {
    let world = world();
    seed(&world, "local", "conformance", b"s3cret-value-7f3a9c");
    let suite = Suite::new()
        .checks(Checks::all())
        .live("secret")
        .live("secret-store-name")
        .cacheable("secret-store")
        .cacheable("secret-route")
        .cacheable("secret-route-secret")
        .required_on_mutating()
        .fixture(Fixture::new("secret", Verb::Source).binding("name", "conformance"))
        .fixture(Fixture::new("secret", Verb::Sink).binding("name", "conformance"))
        .fixture(Fixture::new("secret", Verb::Exists).binding("name", "conformance"))
        .fixture(Fixture::new("secret", Verb::Delete).binding("name", "conformance"))
        .fixture(Fixture::new("secret-store-name", Verb::Source).binding("store", "local"))
        .fixture(Fixture::new("secret-route-secret", Verb::Source).binding("name", "zoom.x"))
        .fixture(Fixture::new("secret-store-reencrypt", Verb::Sink).binding("store", "local"))
        .host_named_space(
            "ikigai_secret::routed_space_with_gate(routing, gate)",
            world.space.clone(),
        )
        .body_space(world.space.clone());
    let report = suite.run_blocking(&world.kernel);
    eprintln!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_eq!(report.endpoints, 8, "{report}");
    assert_eq!(report.actions, 11, "{report}");
    assert_eq!(
        report.checks.skipped().collect::<Vec<_>>(),
        Vec::<Check>::new(),
        "{report}"
    );
    assert!(report.declared.opted_out.is_empty(), "{report}");
}

#[test]
fn every_inspection_resource_answers_under_its_narrow_grant() {
    let world = world();
    let inspect = scoped(&[INSPECT_SCOPE]);
    assert_eq!(
        world.text(STORE_IRI, &inspect),
        "archive: a file store, read-only. A private directory of owner-only files, one per \
         secret, not encrypted at rest.\n\
         local: a file store, the default, writable. A private directory of owner-only \
         files, one per secret, not encrypted at rest.\n\
         team: a file store, writable. A private directory of owner-only files, one per \
         secret, not encrypted at rest.\n"
    );
    assert_eq!(
        world.text("urn:secret:store:name:team", &inspect),
        "team: a file store, writable. A private directory of owner-only files, one per \
         secret, not encrypted at rest.\nhealth: reachable\n"
    );
    assert_eq!(
        world.text(ROUTE_IRI, &inspect),
        "route 1: names matching owner:id:acme:name:* go to team.\n\
         route 2: names matching zoom.* go to team.\n\
         route 3: names matching old.* go to archive.\n\
         default: every other name goes to local.\n"
    );
    // Where a name lives takes the name's own read scope; `inspect` alone does not give it.
    let read = scoped(&["urn:cap:secret:read:zoom.x"]);
    assert_eq!(
        world.text("urn:secret:route:secret:zoom.x", &read),
        "team\n"
    );
    assert_eq!(
        world.text(
            "urn:secret:route:secret:owner:id:acme:name:db",
            &scoped(&["urn:cap:secret:read:owner:id:acme:name:db"])
        ),
        "team\n"
    );
    assert_eq!(
        world.text(
            "urn:secret:route:secret:plain",
            &scoped(&["urn:cap:secret:read:plain"])
        ),
        "local\n"
    );
    for (iri, capability) in [
        ("urn:secret:route:secret:zoom.x", &inspect),
        (STORE_IRI, &read),
        ("urn:secret:store:name:team", &read),
        (ROUTE_IRI, &read),
    ] {
        let err = world.issue(Verb::Source, iri, &[], capability).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{iri}: {err:?}");
    }
    // An unknown store, under the grant: NotFound, never another store.
    let err = world
        .issue(Verb::Source, "urn:secret:store:name:nope", &[], &inspect)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    // Nothing above read a secret: only the health line asked the team store anything.
    assert_eq!(
        world.calls(),
        [("team".to_string(), "health".to_string(), String::new())]
    );
}

#[test]
fn the_json_faces_carry_the_same_data() {
    let world = world();
    let inspect = scoped(&[INSPECT_SCOPE]);
    let json = |iri: &str, capability: &Capability| -> serde_json::Value {
        let repr = world
            .issue(Verb::Source, iri, &[("as", "application/json")], capability)
            .unwrap();
        assert_eq!(repr.repr_type, ReprType::new("application/json"));
        serde_json::from_slice(&repr.bytes).unwrap()
    };
    let stores = json(STORE_IRI, &inspect);
    assert_eq!(stores["default"], "local");
    assert_eq!(stores["stores"][0]["name"], "archive");
    assert_eq!(stores["stores"][0]["writable"], false);
    assert_eq!(stores["stores"][0]["read_only"], true);
    assert_eq!(stores["stores"][1]["default"], true);
    let one = json("urn:secret:store:name:local", &inspect);
    assert_eq!(one["kind"], "file");
    assert_eq!(one["health"], "reachable");
    let routes = json(ROUTE_IRI, &inspect);
    assert_eq!(routes["routes"][1]["match"], "zoom.*");
    assert_eq!(routes["routes"][1]["number"], 2);
    assert_eq!(routes["default"], "local");
    let at = json(
        "urn:secret:route:secret:plain",
        &scoped(&["urn:cap:secret:read:plain"]),
    );
    assert_eq!(
        at,
        serde_json::json!({"name": "plain", "store": "local", "route": null})
    );
    // Never a path: the fixture's directories appear nowhere.
    for value in [stores, one, routes] {
        assert!(!value.to_string().contains("/never/"), "{value}");
    }
    let err = world
        .issue(Verb::Source, STORE_IRI, &[("as", "text/turtle")], &inspect)
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument { ref name, .. } if name == "as"),
        "{err:?}"
    );
}

#[test]
fn the_configuration_answers_are_cached_until_its_thread_is_cut() {
    let world = world();
    let inspect = scoped(&[INSPECT_SCOPE]);
    let read = scoped(&["urn:cap:secret:read:zoom.x"]);
    let cases = [
        (STORE_IRI, &inspect),
        (ROUTE_IRI, &inspect),
        ("urn:secret:route:secret:zoom.x", &read),
    ];
    for (iri, capability) in cases {
        let repr = world.issue(Verb::Source, iri, &[], capability).unwrap();
        assert_eq!(repr.expiry, Expiry::Never, "{iri}");
        assert!(
            world
                .kernel
                .is_cached(&request(Verb::Source, iri, &[]), capability),
            "{iri}"
        );
    }
    world.kernel.cut(CONFIG_THREAD);
    for (iri, capability) in cases {
        assert!(
            !world
                .kernel
                .is_cached(&request(Verb::Source, iri, &[]), capability),
            "a reload drops {iri}"
        );
    }
    // One store's answer carries a health line read now: never cached.
    let store = world
        .issue(Verb::Source, "urn:secret:store:name:team", &[], &inspect)
        .unwrap();
    assert_eq!(store.expiry, Expiry::Always);
}

/// Every verb of every face, on a name routed to each store and to the default, under no
/// grants and under grants for OTHER names (each verb's own scope, and the inspect scope): a
/// typed `Denied`, and no store, no health check and no presence gate touched. The secret is
/// seeded in its own store, so a refusal that reached the store would differ from one that did
/// not.
#[test]
fn no_capability_check_is_skipped_on_any_routed_path() {
    let world = world();
    let names = [
        ("plain", "local"),
        ("zoom.x", "team"),
        ("owner:id:acme:name:db", "team"),
        ("old.k", "archive"),
    ];
    for (name, store) in names {
        seed(&world, store, name, b"value");
    }
    world.clear();
    let others = scoped(&[
        "urn:cap:secret:read:other",
        "urn:cap:secret:write:other",
        "urn:cap:secret:delete:other",
        "urn:cap:secret:generate",
        INSPECT_SCOPE,
    ]);
    let nothing = scoped(&[]);
    for (name, _) in names {
        let secret = format!("urn:secret:{name}");
        let route = format!("urn:secret:route:secret:{name}");
        let attempts: [Attempt; 6] = [
            (Verb::Source, &secret, vec![]),
            (Verb::Sink, &secret, vec![("content", "never stored")]),
            (Verb::Exists, &secret, vec![]),
            (Verb::Delete, &secret, vec![]),
            (Verb::Source, GENERATE_IRI, vec![("into", name)]),
            (Verb::Source, &route, vec![]),
        ];
        for (verb, iri, args) in &attempts {
            for capability in [&nothing, &others] {
                let err = world
                    .issue(*verb, iri, args, capability)
                    .err()
                    .unwrap_or_else(|| panic!("{verb:?} {iri} {args:?} under {capability:?}"));
                assert!(matches!(err, Error::Denied(_)), "{verb:?} {iri}: {err:?}");
            }
        }
    }
    assert_eq!(world.calls(), Vec::<Call>::new(), "nothing was touched");
}

#[test]
fn a_route_never_widens_a_scope() {
    let world = world();
    seed(&world, "team", "zoom.a", b"a");
    seed(&world, "team", "zoom.b", b"b");
    seed(&world, "team", "owner:id:acme:name:a", b"acme a");
    seed(&world, "team", "owner:id:acme:name:b", b"acme b");
    world.clear();
    // A grant for one name routed to `team` reads that name, and nothing else `team` holds.
    let zoom_a = scoped(&["urn:cap:secret:read:zoom.a", "urn:cap:secret:write:zoom.a"]);
    let read = world
        .issue(Verb::Source, "urn:secret:zoom.a", &[], &zoom_a)
        .unwrap();
    assert_eq!(read.bytes, b"a");
    for (verb, iri) in [
        (Verb::Source, "urn:secret:zoom.b"),
        (Verb::Exists, "urn:secret:zoom.b"),
        (Verb::Sink, "urn:secret:zoom.b"),
        (Verb::Source, "urn:secret:route:secret:zoom.b"),
    ] {
        let err = world
            .issue(verb, iri, &[("content", "x")], &zoom_a)
            .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{verb:?} {iri}: {err:?}");
    }
    // The same for owner-keyed names: one owner's route is not a grant over that owner.
    let acme_a = scoped(&["urn:cap:secret:read:owner:id:acme:name:a"]);
    assert_eq!(
        world
            .issue(
                Verb::Source,
                "urn:secret:owner:id:acme:name:a",
                &[],
                &acme_a
            )
            .unwrap()
            .bytes,
        b"acme a"
    );
    for iri in [
        "urn:secret:owner:id:acme:name:b",
        "urn:secret:owner:id:other:name:a",
    ] {
        let err = world.issue(Verb::Source, iri, &[], &acme_a).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{iri}: {err:?}");
    }
    assert_eq!(
        world.calls(),
        [
            ("team".into(), "get".into(), "zoom.a".into()),
            ("team".into(), "get".into(), "owner:id:acme:name:a".into()),
        ],
        "only the two granted reads reached a store"
    );
}

#[test]
fn one_store_per_name_a_miss_is_not_found() {
    let world = world();
    // `zoom.x` sits in the default store, but it routes to `team`, which does not hold it.
    seed(&world, "local", "zoom.x", b"in the wrong store");
    world.clear();
    let read = scoped(&["urn:cap:secret:read:zoom.x"]);
    let err = world
        .issue(Verb::Source, "urn:secret:zoom.x", &[], &read)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    let exists = world
        .issue(Verb::Exists, "urn:secret:zoom.x", &[], &read)
        .unwrap();
    assert_eq!(exists.bytes, b"false");
    assert_eq!(
        world.calls(),
        [
            ("team".into(), "get".into(), "zoom.x".into()),
            ("team".into(), "exists".into(), "zoom.x".into()),
        ],
        "the routed store alone was asked"
    );
    // And a write lands only in the routed store.
    let write = scoped(&["urn:cap:secret:write:zoom.x"]);
    world
        .issue(
            Verb::Sink,
            "urn:secret:zoom.x",
            &[("content", "right")],
            &write,
        )
        .unwrap();
    assert_eq!(
        world.stores["team"].inner.get("zoom.x").unwrap().as_deref(),
        Some(&b"right"[..])
    );
    assert_eq!(
        world.stores["local"]
            .inner
            .get("zoom.x")
            .unwrap()
            .as_deref(),
        Some(&b"in the wrong store"[..])
    );
}

#[test]
fn a_read_only_store_refuses_writes_after_the_capability_and_before_presence() {
    let world = world();
    seed(&world, "archive", "old.k", b"kept");
    world.clear();
    let all = scoped(&[
        "urn:cap:secret:read:old.k",
        "urn:cap:secret:write:old.k",
        "urn:cap:secret:delete:old.k",
        "urn:cap:secret:write:old.k.pub",
        "urn:cap:secret:generate",
    ]);
    for (verb, iri, args) in [
        (Verb::Sink, "urn:secret:old.k", vec![("content", "new")]),
        (Verb::Delete, "urn:secret:old.k", vec![]),
        (Verb::Source, GENERATE_IRI, vec![("into", "old.k")]),
    ] {
        let err = world.issue(verb, iri, &args, &all).unwrap_err();
        assert_eq!(
            err,
            Error::Conflict(
                "`old.k` lives in the store archive, which is read-only (`write = false`), so \
                 it cannot be written or deleted there"
                    .into()
            ),
            "{verb:?} {iri}"
        );
    }
    // The presence gate was never asked, and the store was never reached: the routing refuses
    // before it asks the store anything.
    assert_eq!(world.calls(), Vec::<Call>::new());
    // Reading still works.
    assert_eq!(
        world
            .issue(Verb::Source, "urn:secret:old.k", &[], &all)
            .unwrap()
            .bytes,
        b"kept"
    );
}

#[test]
fn generate_never_mints_into_an_inspection_name() {
    let world = world();
    let generate = |into: &str| {
        let public = format!("{into}.pub");
        let capability = scoped(&[
            "urn:cap:secret:generate",
            &format!("urn:cap:secret:write:{into}"),
            &format!("urn:cap:secret:write:{public}"),
        ]);
        world.issue(Verb::Source, GENERATE_IRI, &[("into", into)], &capability)
    };
    for into in ["store", "route", "store:name:x", "route:secret:x"] {
        let err = generate(into).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument { name, detail }
                if name == "into" && detail.contains("names the inspection resource")),
            "{into}: {err:?}"
        );
    }
    assert_eq!(world.calls(), Vec::<Call>::new());
    // A name merely beginning with the same letters is a secret like any other.
    generate("storefront").unwrap();
}

/// With no `[secret]` section the routed backend is today's one store, and every `Backend` call
/// reaches it once, unchanged, `create` and `replace` included (never decomposed into other
/// calls).
#[test]
fn with_no_section_every_call_reaches_the_one_store_unchanged() {
    let config = SecretConfig::from_section(None, None).unwrap();
    assert!(!config.is_configured());
    assert_eq!(config.stores().len(), 1);
    assert!(config.routes().is_empty());
    let store = config.default_store().to_string();
    assert_eq!(config.route_for("anything:at:all").store, store);

    let log = Arc::new(Mutex::new(Vec::new()));
    let dir = tempfile::tempdir().unwrap();
    let recording: Arc<dyn Backend> = Arc::new(Recording {
        store: store.clone(),
        inner: FileBackend::new(dir.path()),
        log: log.clone(),
    });
    let routing =
        RoutingBackend::with_stores(config, BTreeMap::from([(store.clone(), recording)])).unwrap();
    routing.set("a", b"1").unwrap();
    routing.replace("a", b"2").unwrap();
    assert!(routing.create("b", b"3").unwrap());
    assert_eq!(routing.get("a").unwrap().as_deref(), Some(&b"2"[..]));
    assert!(routing.exists("b").unwrap());
    routing.accepts_writes("a").unwrap();
    assert_eq!(routing.sign("a", b"m").unwrap(), None);
    assert_eq!(routing.generate_signing_key("k").unwrap(), None);
    routing.delete("a").unwrap();
    let ops: Vec<(String, String)> = log
        .lock()
        .unwrap()
        .iter()
        .map(|(s, op, name)| {
            assert_eq!(s, &store);
            (op.clone(), name.clone())
        })
        .collect();
    let expected: Vec<(String, String)> = [
        ("set", "a"),
        ("replace", "a"),
        ("create", "b"),
        ("get", "a"),
        ("exists", "b"),
        ("accepts_writes", "a"),
        ("sign", "a"),
        ("generate_signing_key", "k"),
        ("delete", "a"),
    ]
    .iter()
    .map(|(op, name)| (op.to_string(), name.to_string()))
    .collect();
    assert_eq!(ops, expected);
}

#[test]
fn with_stores_refuses_a_missing_or_extra_backend() {
    let section: SecretSection = toml::from_str(SECTION).unwrap();
    let config = SecretConfig::from_section(Some(&section), None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(FileBackend::new(dir.path()));
    let err = RoutingBackend::with_stores(
        config,
        BTreeMap::from([
            ("local".to_string(), backend.clone()),
            ("stray".to_string(), backend),
        ]),
    )
    .err()
    .unwrap();
    assert_eq!(
        err.problems(),
        [
            "the store archive is configured, and no backend was supplied for it.",
            "the store team is configured, and no backend was supplied for it.",
            "a backend was supplied for stray, which is not a configured store."
        ]
    );
}
