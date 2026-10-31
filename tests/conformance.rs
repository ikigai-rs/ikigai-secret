//! The module recipe as one test: `ikigai-conformance` walks the three endpoints
//! [`ikigai_secret::space`] binds and reports every violation at once.
//!
//! ## The fixture kernel: the FILE keystore over a scratch directory
//!
//! The suite FIRES the actions it checks — `Sink` included — so the kernel under
//! test is a fixture: [`ikigai_secret::FileBackend`] rooted at a fresh temporary
//! directory, seeded with one secret the `{name}` binding names. The Keychain
//! backend is macOS/TCC and cannot run in CI or from an agent shell, so it is not
//! walked; the endpoints are the same code over either store. The backend is
//! wrapped in [`Recording`], which logs every `Backend` call by name — the
//! only witness to what the walk touched, and to what a refused call did NOT.
//!
//! [`Recording`] is also the fixture's **presence gate** (ledger #201): the space is built
//! with [`ikigai_secret::space_with_gate`], and every time an operation asks for presence the
//! request lands in the same log, as [`Op::Presence`], in order with the keystore calls. It
//! always finds someone at the machine, so the platform's real Touch ID prompt is never
//! reached and `secret-unlock` and `secret-generate` are walked on EVERY platform, macOS
//! included (they used to be opted out there).
//!
//! ## Declarations, and why each
//!
//! - `secret` is declared **live** (`Suite::live`), nothing is `pure` and nothing
//!   is `cacheable`: a secret read must NEVER be cacheable (a cached secret is a secret
//!   with no thread and no expiry), so every read is `Expiry::Always`. Without the
//!   declaration the cache probe is silent on an `Always` result and equally silent on
//!   a read that BECAME cacheable (a `.cacheable()` added to the Source walked clean);
//!   with it, a cacheable secret read is a `CACHEABLE` finding in [`conforms`]. The
//!   declaration applies to the Source only (the Sink is mutating, so `CACHEABLE` does
//!   not run there). [`reads_are_never_cached`] keeps what the probe's one resolution
//!   under root cannot see: a narrow grant, and every read reaching the keystore.
//! - Every check runs, `NAMES` included: the stored-secret endpoint's id is `secret`
//!   (ledger #11's naming wave renamed it from the full IRI `urn:secret`), the same as its
//!   `Endpoint::name()`, and `secret-unlock` and `secret-generate` were kebab-case from
//!   birth. [`names_conform`] pins the three ids.
//! - Nothing is opted out. The two operations behind the presence gate are walked under
//!   root with the gate stubbed (above), on every platform.
//! - `Suite::required_on_mutating()` (conformance 0.8, `REQUIRED`). By default the
//!   check drops required inputs from `Source`/`Exists` only: there it drops generate's
//!   `into` (the `secret` Source and Exists take only the `{name}` binding, not by
//!   value, and unlock takes none). Declaring it holds the Sink too: `content` is dropped
//!   from the pipeline probe's firing and must be a typed `MissingArgument`. The kernel is
//!   the scratch file store, so a wrongly accepted drop could only write there, and the
//!   endpoint refuses before the keystore is consulted (the footprint in [`conforms`] is
//!   unchanged). A clean report proves the declaration reached a Sink: an unreached one is
//!   a `DECLARATIONS` finding. The Delete takes only the binding, so nothing is dropped.
//! - `secret`'s `Delete` (ledger #202) declares no `content`, so the suite fires it
//!   only under no grants (ENFORCED), never under root: the walk deletes nothing, and never
//!   reaches the presence gate a `Delete` asks.
//!
//! - The three space constructors are declared **host-named** (`SPACE-NAME`, ledger #987):
//!   [`ikigai_secret::space_with_gate`] and [`ikigai_secret::space`] are parameterized by the
//!   backend (and gate) they are handed, and [`ikigai_secret::default_space`] builds over the
//!   ambient platform backend (the Keychain on macOS, a directory read from the environment
//!   elsewhere), so none is configuration-free and only the host knows which instance it
//!   holds. The fixture's own `space_with_gate(backend, gate)` is declared by value, the
//!   same `Arc` the kernel walks. `space(backend)` and `default_space()` are CONSTRUCTED for
//!   their declarations and nothing more: building either touches no keystore and asks no
//!   gate (the Keychain backend holds a service name until it is called; the file backend
//!   reads two environment variables), and the check reads only `id()` and `topology()`, so
//!   neither is invoked.
//!
//! No module namespace: there is no RDF face (a secret has no graph to skolemize).
//!
//! ## What the suite cannot see, pinned by hand
//!
//! - **Denied before the keystore** ([`ungranted_callers_are_refused_before_the_keystore_is_touched`]):
//!   ENFORCED sees a typed `Denied` under no grants; it cannot see that the keystore
//!   was never consulted, nor that a present and an absent secret refuse
//!   identically. The recording backend and a second name can. Three capability
//!   shapes: no grants (the KERNEL refuses on the declared `urn:cap:secret:read:*`
//!   before the endpoint runs — conformance PENDING #46), a grant on ANOTHER name
//!   (the wildcard admits the call; the endpoint's per-name rule refuses), and
//!   the exact grant (one `get`). Source, Sink, Exists and Delete alike, and the two
//!   gated operations never ask the presence gate.
//! - **Exists and Delete** ([`exists_and_delete_answer_under_their_own_scopes`]): the
//!   answers, the scope each takes (a write grant does not delete), and the keystore calls.
//! - **The presence gate comes last, and its refusal stands**
//!   ([`the_presence_gate_is_asked_last_and_its_refusal_stands`],
//!   [`delete_asks_the_presence_gate_last`]): for unlock, generate and a `Delete`.
//! - **Required means required** (PENDING #49, [`required_inputs_are_required`]):
//!   drop `content` from a Sink, `into` from a generate — `MissingArgument`, and
//!   for generate BEFORE the presence gate.
//! - **Declared outputs against what is served** (PENDING #11/#31,
//!   [`declared_outputs_are_the_media_types_served`]).
//! - **The manifold carries no secret VALUE** ([`the_manifold_carries_no_secret`]):
//!   `describe()`, `urn:kernel:catalog`, `urn:kernel:actions` and a `Meta` on the
//!   secret's own IRI are all resolved under root and searched for the seeded bytes.
//! - **The walk mutates the fixture** (PENDING #13/#40): PIPELINE fires the Sink
//!   under root with `content=x`, so after [`conforms`] the seeded secret IS `x`.
//!   Asserted, with the exact backend log: one `get` (the cache probe's single
//!   resolution — `Always` returns before a second), one `exists` (the same for the
//!   Exists), one `replace` (the pipeline probe's Sink, fired once) — and nothing under no
//!   grants.

use ikigai_conformance::{Check, Checks, Fixture, Report, SpaceNaming, Suite};
use ikigai_core::{
    ArgRef, Capability, Description, EndpointSpace, Error, Expiry, Iri, Kernel, MetaRenderer,
    ReprType, Representation, Request, Verb,
};
use ikigai_secret::{Backend, FileBackend, PresenceGate, GENERATE_IRI, UNLOCK_IRI};
use std::sync::{Arc, Mutex};

/// The three descriptions `space()` binds, by id, with the IRI each is bound at.
const SECRET: &str = "secret";
const UNLOCK: &str = "secret-unlock";
const GENERATE: &str = "secret-generate";
const SECRET_TEMPLATE: &str = "urn:secret:{name}";

/// The seeded secret: its name (the `{name}` binding every fired action uses) and
/// a value distinctive enough to grep the manifold for.
const NAME: &str = "conformance";
const VALUE: &[u8] = b"s3cret-value-7f3a9c";
/// A name nothing is stored under.
const ABSENT: &str = "absent";

/// The value the suite's PIPELINE probe writes: `sample_value` of an `xsd:string`.
const PROBE_CONTENT: &[u8] = b"x";

/// One keystore operation the walk performed, or one request for presence.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Get(String),
    Set(String),
    Delete(String),
    Exists(String),
    Replace(String),
    /// The presence gate was asked, with this reason.
    Presence(String),
}

/// A backend that logs every operation by name and delegates to the file store; and the
/// fixture's presence gate, which logs each request and finds someone at the machine.
struct Recording {
    inner: FileBackend,
    log: Mutex<Vec<Op>>,
}

impl Recording {
    fn ops(&self) -> Vec<Op> {
        self.log.lock().unwrap().clone()
    }

    /// The operations on one name, in order.
    fn ops_on(&self, name: &str) -> Vec<Op> {
        self.ops()
            .into_iter()
            .filter(|op| match op {
                Op::Get(n) | Op::Set(n) | Op::Delete(n) | Op::Exists(n) | Op::Replace(n) => {
                    n == name
                }
                Op::Presence(_) => false,
            })
            .collect()
    }

    /// The reasons the presence gate was asked with, in order.
    fn presence(&self) -> Vec<String> {
        self.ops()
            .into_iter()
            .filter_map(|op| match op {
                Op::Presence(reason) => Some(reason),
                _ => None,
            })
            .collect()
    }

    fn clear(&self) {
        self.log.lock().unwrap().clear();
    }
}

impl Backend for Recording {
    fn get(&self, name: &str) -> ikigai_core::Result<Option<Vec<u8>>> {
        self.log.lock().unwrap().push(Op::Get(name.into()));
        self.inner.get(name)
    }
    fn set(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.log.lock().unwrap().push(Op::Set(name.into()));
        self.inner.set(name, value)
    }
    fn delete(&self, name: &str) -> ikigai_core::Result<()> {
        self.log.lock().unwrap().push(Op::Delete(name.into()));
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> ikigai_core::Result<bool> {
        self.log.lock().unwrap().push(Op::Exists(name.into()));
        self.inner.exists(name)
    }
    fn replace(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.log.lock().unwrap().push(Op::Replace(name.into()));
        self.inner.replace(name, value)
    }
}

impl PresenceGate for Recording {
    fn require(&self, reason: &str) -> ikigai_core::Result<()> {
        self.log.lock().unwrap().push(Op::Presence(reason.into()));
        Ok(())
    }
}

/// The smallest `Meta` renderer: every field of the description, as text. The
/// catalog and a `Meta` request both render through it, and a leak check wants
/// every field visible, so `Debug` is the right face here.
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

/// A fresh fixture: the file keystore over a scratch directory, seeded with one
/// secret, logged, and the same recorder as the presence gate. The directory lives as long
/// as the guard.
fn fixture() -> (Kernel, Arc<Recording>, tempfile::TempDir) {
    let (kernel, _space, backend, dir) = fixture_with_space();
    (kernel, backend, dir)
}

/// [`fixture`], plus the space the kernel walks — the one `Arc`, so the suite's
/// host-named declaration is the very instance under test.
fn fixture_with_space() -> (
    Kernel,
    Arc<EndpointSpace>,
    Arc<Recording>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("scratch dir");
    let backend = Arc::new(Recording {
        inner: FileBackend::new(dir.path()),
        log: Mutex::new(Vec::new()),
    });
    backend.inner.set(NAME, VALUE).expect("seed");
    let space = Arc::new(ikigai_secret::space_with_gate(
        backend.clone(),
        backend.clone(),
    ));
    let kernel = Kernel::with_meta_renderer(space.clone(), Arc::new(EveryField));
    (kernel, space, backend, dir)
}

/// The labels the three space constructors are declared under.
const SPACE_LABEL: &str = "ikigai_secret::space_with_gate(backend, gate)";
const PLAIN_SPACE_LABEL: &str = "ikigai_secret::space(backend)";
const DEFAULT_SPACE_LABEL: &str = "ikigai_secret::default_space()";

/// The suite for this module: the seeded name bound on every verb of `secret`
/// (a fixture per verb, so the intent survives a suite that looks bindings up per
/// action), `secret` declared live, every check run, REQUIRED held on
/// the Sink too, and the three space constructors declared host-named
/// (`space_with_gate` as the instance the kernel walks; `space` over a scratch store it
/// never touches) — see the file docs. Nothing is opted out.
fn suite(space: Arc<EndpointSpace>, scratch: &std::path::Path) -> Suite {
    let plain = ikigai_secret::space(Arc::new(FileBackend::new(scratch.join("never-walked"))));
    Suite::new()
        .checks(Checks::all())
        .live(SECRET)
        .required_on_mutating()
        .fixture(Fixture::new(SECRET, Verb::Source).binding("name", NAME))
        .fixture(Fixture::new(SECRET, Verb::Sink).binding("name", NAME))
        .fixture(Fixture::new(SECRET, Verb::Exists).binding("name", NAME))
        .fixture(Fixture::new(SECRET, Verb::Delete).binding("name", NAME))
        .host_named_space(SPACE_LABEL, space.clone())
        .host_named_space(PLAIN_SPACE_LABEL, plain)
        .host_named_space(DEFAULT_SPACE_LABEL, ikigai_secret::default_space())
        .body_space(space)
}

/// The walk saw three endpoints and six actions (`secret` Source + Sink + Exists +
/// Delete, one Source each for unlock and generate), skipped no check, and opted out
/// nothing. A fourth endpoint bound without a line here is held to a weaker standard.
fn assert_shape(report: &Report) {
    assert_eq!(report.endpoints, 3, "{report}");
    assert_eq!(report.actions, 6, "{report}");
    assert_eq!(
        report.checks.skipped().collect::<Vec<_>>(),
        Vec::<Check>::new(),
        "no check is skipped: {report}"
    );
    assert!(report.declared.opted_out.is_empty(), "{report}");
    assert!(report.declared.pure.is_empty(), "{report}");
    assert!(report.declared.cacheable.is_empty(), "{report}");
    assert_eq!(report.declared.live, [SECRET], "{report}");
    assert!(report.declared.namespaces.is_empty(), "{report}");
    assert!(report.declared.required_on_mutating, "{report}");
    let spaces: Vec<(&str, &SpaceNaming)> = report
        .declared
        .spaces
        .iter()
        .map(|s| (s.label.as_str(), &s.naming))
        .collect();
    assert_eq!(
        spaces,
        [
            (SPACE_LABEL, &SpaceNaming::HostNamed),
            (PLAIN_SPACE_LABEL, &SpaceNaming::HostNamed),
            (DEFAULT_SPACE_LABEL, &SpaceNaming::HostNamed)
        ],
        "every constructor declared, each host-named: {report}"
    );
}

#[test]
fn conforms() {
    let (kernel, space, backend, dir) = fixture_with_space();
    let report = suite(space, dir.path()).run_blocking(&kernel);
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);

    // The walk's footprint on the keystore, exactly: the cache probe read the
    // seeded secret once (`Always` needs no second resolution) and asked whether it
    // exists once, the pipeline probe fired the Sink once (one `replace`: the file
    // store's is atomic, never a delete then a set), and ENFORCED — under no grants —
    // never reached the store, so the Delete deleted nothing. REQUIRED's Sink without
    // `content` was refused before the store too.
    assert_eq!(
        backend.ops_on(NAME),
        [
            Op::Get(NAME.into()),
            Op::Replace(NAME.into()),
            Op::Exists(NAME.into())
        ],
        "the walk's footprint on the seeded secret"
    );
    // PENDING #40: the walk mutates the fixture — the seeded secret is now the
    // probe's `x`.
    assert_eq!(
        backend.inner.get(NAME).unwrap().as_deref(),
        Some(PROBE_CONTENT),
        "the pipeline probe's Sink landed"
    );
    // Generate's minimal call (`into=x`) checked that neither name held a secret
    // (generate never replaces), asked for presence, then minted the pair; unlock asked
    // for presence. On every platform: the gate is the stub, never a Touch ID prompt.
    let minted: Vec<Op> = backend
        .ops()
        .into_iter()
        .filter(|op| match op {
            Op::Set(n) | Op::Exists(n) => n == "x" || n == "x.pub",
            Op::Presence(_) => true,
            _ => false,
        })
        .collect();
    assert_eq!(
        minted,
        [
            Op::Presence("Unlock ikigai secrets".into()),
            Op::Exists("x".into()),
            Op::Exists("x.pub".into()),
            Op::Presence("Generate signing key x".into()),
            Op::Set("x".into()),
            Op::Set("x.pub".into())
        ]
    );
    assert_eq!(
        backend.ops().len(),
        9,
        "and nothing else: {:?}",
        backend.ops()
    );
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn issue(
    kernel: &Kernel,
    verb: Verb,
    iri: &str,
    args: &[(&str, &str)],
    capability: &Capability,
) -> Result<Representation, Error> {
    futures::executor::block_on(kernel.issue(request(verb, iri, args), capability))
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

fn secret_iri(name: &str) -> String {
    format!("urn:secret:{name}")
}

/// A secret read is `Expiry::Always` — never cached, under the exact grant and
/// under root alike — and every read reaches the keystore. The suite's `live`
/// declaration holds the expiry (one resolution, under root); this holds the rest.
#[test]
fn reads_are_never_cached() {
    let (kernel, backend, _dir) = fixture();
    let read = scoped(&[&format!("urn:cap:secret:read:{NAME}")]);
    for capability in [&read, &Capability::root()] {
        let repr = issue(&kernel, Verb::Source, &secret_iri(NAME), &[], capability).unwrap();
        assert_eq!(repr.bytes, VALUE);
        assert_eq!(repr.expiry, Expiry::Always, "a secret read is live");
        assert!(repr.threads().is_empty(), "and names no thread");
        assert!(
            !kernel.is_cached(&request(Verb::Source, &secret_iri(NAME), &[]), capability),
            "nothing was stored in the cache"
        );
    }
    assert_eq!(
        backend.ops_on(NAME),
        [Op::Get(NAME.into()), Op::Get(NAME.into())],
        "every read hits the keystore"
    );
}

/// Denied before the keystore. Under no grants and under a grant on ANOTHER name, a
/// present secret and an absent one refuse identically — a typed, permanent
/// `Denied` whose text differs only by the name asked for — and the keystore is
/// never consulted, so an ungranted caller cannot learn whether a name exists.
/// Two gates are in play: with no secret grant at all the KERNEL refuses on the
/// declared wildcard before the endpoint runs (the denial names the wildcard);
/// with a grant on another name the wildcard admits the call and the endpoint's
/// per-name rule refuses it (the denial names the exact scope). The same holds
/// for the Sink, the Exists and the Delete, and for the two gated operations, whose
/// denial is the capability's: the presence gate is never asked (it logs to the same
/// recorder, so an empty log says so). Under the exact grant: one `get`, and an absent
/// name is a typed `NotFound`.
#[test]
fn ungranted_callers_are_refused_before_the_keystore_is_touched() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();

    let read_wildcard = "urn:cap:secret:read:*";
    let write_wildcard = "urn:cap:secret:write:*";
    let delete_wildcard = "urn:cap:secret:delete:*";
    let other_read = "urn:cap:secret:read:other";
    let other_write = "urn:cap:secret:write:other";
    let other_delete = "urn:cap:secret:delete:other";
    let deny = |verb: Verb, iri: &str, capability: &Capability| -> String {
        let err = issue(
            &kernel,
            verb,
            iri,
            &[("content", "never stored")],
            capability,
        )
        .err()
        .unwrap_or_else(|| panic!("{verb:?} {iri} resolved under {capability:?}"));
        assert!(matches!(err, Error::Denied(_)), "{verb:?} {iri}: {err:?}");
        assert!(!err.is_transient(), "{verb:?} {iri}: {err:?}");
        err.to_string()
    };

    // Source, Sink, Exists and Delete, under no grants (kernel floor) and under another
    // name's grant (endpoint rule): present and absent refuse identically.
    for (verb, capability, names) in [
        (Verb::Source, scoped(&[]), read_wildcard),
        (Verb::Source, scoped(&[other_read]), "urn:cap:secret:read:"),
        (Verb::Sink, scoped(&[]), write_wildcard),
        (Verb::Sink, scoped(&[other_write]), "urn:cap:secret:write:"),
        (Verb::Exists, scoped(&[]), read_wildcard),
        (Verb::Exists, scoped(&[other_read]), "urn:cap:secret:read:"),
        (Verb::Delete, scoped(&[]), delete_wildcard),
        (
            Verb::Delete,
            scoped(&[other_delete]),
            "urn:cap:secret:delete:",
        ),
    ] {
        let present = deny(verb, &secret_iri(NAME), &capability);
        let absent = deny(verb, &secret_iri(ABSENT), &capability);
        assert!(
            present.contains(names),
            "{verb:?}: names the gate: {present}"
        );
        assert_eq!(
            present.replace(NAME, "{name}"),
            absent.replace(ABSENT, "{name}"),
            "{verb:?}: a present and an absent secret refuse alike"
        );
    }
    // A read grant does not write; a write grant does not read (the floor is
    // per family, not per module).
    deny(
        Verb::Sink,
        &secret_iri(NAME),
        &scoped(&[&format!("urn:cap:secret:read:{NAME}")]),
    );
    deny(
        Verb::Source,
        &secret_iri(NAME),
        &scoped(&[&format!("urn:cap:secret:write:{NAME}")]),
    );
    // The gated operations refuse on their capability, before the presence gate.
    for (iri, scope) in [
        (UNLOCK_IRI, "urn:cap:secret:unlock"),
        (GENERATE_IRI, "urn:cap:secret:generate"),
    ] {
        for capability in [
            scoped(&[]),
            scoped(&[other_read, other_write, other_delete]),
        ] {
            let err = issue(&kernel, Verb::Source, iri, &[("into", "k")], &capability)
                .err()
                .unwrap_or_else(|| panic!("{iri} resolved under {capability:?}"));
            assert!(matches!(err, Error::Denied(_)), "{iri}: {err:?}");
            assert!(err.to_string().contains(scope), "{iri}: {err}");
        }
    }
    // A delete grant does not read (or ask), and a read or write grant does not delete.
    deny(
        Verb::Exists,
        &secret_iri(NAME),
        &scoped(&[&format!("urn:cap:secret:delete:{NAME}")]),
    );
    for scope in ["read", "write"] {
        deny(
            Verb::Delete,
            &secret_iri(NAME),
            &scoped(&[&format!("urn:cap:secret:{scope}:{NAME}")]),
        );
    }
    assert!(
        backend.ops().is_empty(),
        "no refused call reached the keystore or the presence gate: {:?}",
        backend.ops()
    );
    assert_eq!(
        backend.inner.get(NAME).unwrap().as_deref(),
        Some(VALUE),
        "and nothing was written"
    );

    // Under the exact grant: one get; an absent name is a typed, permanent NotFound.
    let read = |name: &str| {
        issue(
            &kernel,
            Verb::Source,
            &secret_iri(name),
            &[],
            &scoped(&[&format!("urn:cap:secret:read:{name}")]),
        )
    };
    assert_eq!(read(NAME).unwrap().bytes, VALUE);
    let err = read(ABSENT).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert!(!err.is_transient(), "{err:?}");
    assert_eq!(
        backend.ops(),
        [Op::Get(NAME.into()), Op::Get(ABSENT.into())],
        "a granted read consults the keystore once"
    );
}

/// PENDING #49: a required input dropped from an otherwise valid call is a
/// `MissingArgument` naming it — `content` on the Sink, `into` on generate — and
/// the keystore is untouched and the presence gate never asked. Since conformance 0.8
/// the suite's REQUIRED check sees both typed refusals; this test owns the NAME of the
/// missing argument, and the untouched keystore and gate.
#[test]
fn required_inputs_are_required() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();
    let err = issue(
        &kernel,
        Verb::Sink,
        &secret_iri(NAME),
        &[],
        &scoped(&[&format!("urn:cap:secret:write:{NAME}")]),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::MissingArgument(name) if name == "content"),
        "{err:?}"
    );
    let err = issue(
        &kernel,
        Verb::Source,
        GENERATE_IRI,
        &[],
        // The declared floor (generate, and SOME write grant): what is missing is `into`.
        &scoped(&["urn:cap:secret:generate", "urn:cap:secret:write:k"]),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::MissingArgument(name) if name == "into"),
        "{err:?}"
    );
    assert!(backend.ops().is_empty(), "{:?}", backend.ops());
}

fn declared_outputs(kernel: &Kernel, pattern: &str) -> Vec<Vec<String>> {
    kernel
        .describe_pattern(pattern)
        .unwrap_or_else(|| panic!("{pattern} describes itself"))
        .action_specs()
        .iter()
        .map(|spec| {
            spec.outputs
                .iter()
                .map(|o| ikigai_conformance::rdf::bare_media_type(o))
                .collect()
        })
        .collect()
}

/// What `ikigai-conformance` 0.1.0 does not check (PENDING #11/#31): a declared
/// output that is not an RDF face is never compared with what the action serves.
/// Read by hand, then pinned: `urn:secret:{name}` serves bytes on Source and a
/// `text/plain` answer on Sink, Exists and Delete; unlock serves `text/plain`; generate
/// serves the PEM public key for `ed25519` and the `text/plain` recipient for `age` — two
/// declared outputs, each served by one `type`. The gated operations are fired through
/// the stub gate, on every platform.
#[test]
fn declared_outputs_are_the_media_types_served() {
    let (kernel, _backend, _dir) = fixture();
    let root = Capability::root();
    let served = |verb: Verb, iri: &str, args: &[(&str, &str)]| -> String {
        let repr = issue(&kernel, verb, iri, args, &root).unwrap_or_else(|e| panic!("{iri}: {e}"));
        ikigai_conformance::rdf::bare_media_type(&repr.repr_type.media_type)
    };

    assert_eq!(
        declared_outputs(&kernel, SECRET_TEMPLATE),
        [
            vec!["application/octet-stream"],
            vec!["text/plain"],
            vec!["text/plain"],
            vec!["text/plain"]
        ],
        "Source, Sink, Exists, Delete"
    );
    assert_eq!(
        served(Verb::Source, &secret_iri(NAME), &[]),
        "application/octet-stream"
    );
    assert_eq!(
        served(Verb::Sink, &secret_iri(NAME), &[("content", "v")]),
        "text/plain"
    );
    assert_eq!(served(Verb::Exists, &secret_iri(NAME), &[]), "text/plain");
    assert_eq!(served(Verb::Delete, &secret_iri(NAME), &[]), "text/plain");

    assert_eq!(declared_outputs(&kernel, UNLOCK_IRI), [vec!["text/plain"]]);
    let generate = declared_outputs(&kernel, GENERATE_IRI);
    assert_eq!(generate, [vec!["application/x-pem-file", "text/plain"]]);
    assert_eq!(served(Verb::Source, UNLOCK_IRI, &[]), "text/plain");
    assert_eq!(
        served(Verb::Source, GENERATE_IRI, &[("into", "k1")]),
        "application/x-pem-file"
    );
    assert_eq!(
        served(
            Verb::Source,
            GENERATE_IRI,
            &[("into", "k2"), ("type", "ed25519")]
        ),
        "application/x-pem-file"
    );
    assert_eq!(
        served(
            Verb::Source,
            GENERATE_IRI,
            &[("into", "k3"), ("type", "age")]
        ),
        "text/plain"
    );
}

/// The manifold must not leak. `describe()`, the catalog, the action manifold
/// and a `Meta` on the secret's own IRI are all resolved under root — the most
/// any caller can hold — and none carries the seeded value, nor the receipt of a
/// Sink.
#[test]
fn the_manifold_carries_no_secret() {
    let (kernel, backend, _dir) = fixture();
    let root = Capability::root();
    let value = std::str::from_utf8(VALUE).unwrap();
    let described = format!("{:?}", kernel.describe_pattern(SECRET_TEMPLATE).unwrap());
    assert!(!described.contains(value), "describe(): {described}");
    for (verb, iri) in [
        (Verb::Source, "urn:kernel:catalog"),
        (Verb::Source, "urn:kernel:actions"),
        (Verb::Meta, &secret_iri(NAME)),
    ] {
        let repr = issue(&kernel, verb, iri, &[], &root).unwrap_or_else(|e| panic!("{iri}: {e}"));
        let text = String::from_utf8_lossy(&repr.bytes);
        assert!(
            !text.contains(value),
            "{verb:?} {iri} carries the secret: {text}"
        );
        assert!(!text.is_empty(), "{verb:?} {iri} answered");
    }
    assert!(
        backend.ops().is_empty(),
        "self-description never consults the keystore: {:?}",
        backend.ops()
    );
    let receipt = issue(
        &kernel,
        Verb::Sink,
        &secret_iri(NAME),
        &[("content", value)],
        &root,
    )
    .unwrap();
    assert_eq!(
        receipt.bytes, b"stored",
        "the Sink's reply carries no material"
    );
}

/// Ledger #11: every id is a kebab-case noun. NAMES alone reports nothing, and the three
/// ids the manifold carries are exactly `secret`, `secret-unlock` and `secret-generate`
/// (the first was the full IRI `urn:secret` before the naming wave).
#[test]
fn names_conform() {
    let (kernel, backend, _dir) = fixture();
    let report = Suite::new().checks(Checks::NAMES).run_blocking(&kernel);
    assert!(report.is_clean(), "{report}");
    assert_eq!(report.endpoints, 3, "{report}");
    let ids: Vec<String> = [SECRET_TEMPLATE, UNLOCK_IRI, GENERATE_IRI]
        .iter()
        .map(|pattern| kernel.describe_pattern(pattern).unwrap().id)
        .collect();
    assert_eq!(ids, [SECRET, UNLOCK, GENERATE]);
    assert!(backend.ops().is_empty(), "NAMES is a static check");
}

/// The contract as the manifold states it: `secret` has a Source and an Exists
/// under the read wildcard, a Sink under the write wildcard and a Delete under the delete
/// wildcard, each binding `name`, the Sink requiring `content`; unlock one Source under its own exact capability;
/// generate one Source under its own capability AND the write wildcard (it writes
/// `<into>` and `<into>.pub`, whose exact scopes it checks at invoke); every input
/// has a class; generate's `into` is required and
/// its `type` is optional with a default among its `one_of`.
#[test]
fn the_manifold_states_the_contract() {
    /// One action's contract: verb, the scopes it requires, its inputs and whether
    /// each is required.
    type Action = (Verb, &'static [&'static str], Vec<(&'static str, bool)>);
    let (kernel, _backend, _dir) = fixture();
    let contract: [(&str, &str, Vec<Action>); 3] = [
        (
            SECRET_TEMPLATE,
            SECRET,
            vec![
                (
                    Verb::Source,
                    &["urn:cap:secret:read:*"],
                    vec![("name", true)],
                ),
                (
                    Verb::Sink,
                    &["urn:cap:secret:write:*"],
                    vec![("name", true), ("content", true)],
                ),
                (
                    Verb::Exists,
                    &["urn:cap:secret:read:*"],
                    vec![("name", true)],
                ),
                (
                    Verb::Delete,
                    &["urn:cap:secret:delete:*"],
                    vec![("name", true)],
                ),
            ],
        ),
        (
            UNLOCK_IRI,
            UNLOCK,
            vec![(Verb::Source, &["urn:cap:secret:unlock"], vec![])],
        ),
        (
            GENERATE_IRI,
            GENERATE,
            vec![(
                Verb::Source,
                &["urn:cap:secret:generate", "urn:cap:secret:write:*"],
                vec![("into", true), ("type", false)],
            )],
        ),
    ];
    for (pattern, id, actions) in contract {
        let description = kernel.describe_pattern(pattern).unwrap();
        assert_eq!(description.id, id);
        let specs = description.action_specs();
        assert_eq!(specs.len(), actions.len(), "{id}: actions");
        for (spec, (verb, requires, inputs)) in specs.iter().zip(actions) {
            assert_eq!(spec.verb, verb, "{id}");
            assert_eq!(
                spec.requires, requires,
                "{id} {verb:?}: declared = enforced"
            );
            let declared: Vec<(&str, bool)> = spec
                .inputs
                .iter()
                .map(|i| (i.name.as_str(), i.required))
                .collect();
            assert_eq!(
                declared, inputs,
                "{id} {verb:?}: inputs and whether required"
            );
            for input in &spec.inputs {
                assert!(
                    input.class.as_deref().is_some_and(|c| c.contains(':')),
                    "{id} {verb:?}: input `{}` has a class",
                    input.name
                );
            }
        }
    }
    let generate = kernel.describe_pattern(GENERATE_IRI).unwrap();
    let kind = generate
        .action_specs()
        .remove(0)
        .inputs
        .into_iter()
        .find(|i| i.name == "type")
        .unwrap();
    assert_eq!(kind.one_of, ["ed25519", "age"]);
    assert_eq!(kind.default.as_deref(), Some("ed25519"));
}

/// Exists and Delete (ledger #202), each under its own scope. Exists answers `true` or
/// `false` under the read scope, never cached; Delete removes the secret under
/// `urn:cap:secret:delete:<name>`, asks the presence gate, and is idempotent; afterward Exists
/// says `false` and a read is a typed `NotFound`. One keystore call per answer, the scope
/// checked first.
#[test]
fn exists_and_delete_answer_under_their_own_scopes() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();
    let read = |name: &str| scoped(&[&format!("urn:cap:secret:read:{name}")]);
    let delete = |name: &str| scoped(&[&format!("urn:cap:secret:delete:{name}")]);
    let exists = |name: &str| {
        let repr = issue(&kernel, Verb::Exists, &secret_iri(name), &[], &read(name))
            .unwrap_or_else(|e| panic!("exists {name}: {e}"));
        assert_eq!(
            repr.expiry,
            Expiry::Always,
            "whether a secret exists is live"
        );
        String::from_utf8(repr.bytes).unwrap()
    };

    assert_eq!(exists(NAME), "true");
    assert_eq!(exists(ABSENT), "false");

    let receipt = issue(&kernel, Verb::Delete, &secret_iri(NAME), &[], &delete(NAME)).unwrap();
    assert_eq!(receipt.bytes, b"deleted", "the reply carries no material");
    assert_eq!(exists(NAME), "false", "deleted");
    let err = issue(&kernel, Verb::Source, &secret_iri(NAME), &[], &read(NAME)).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    // Idempotent: deleting what is not there answers the same.
    let again = issue(&kernel, Verb::Delete, &secret_iri(NAME), &[], &delete(NAME)).unwrap();
    assert_eq!(again.bytes, b"deleted");

    assert_eq!(
        backend.ops(),
        [
            Op::Exists(NAME.into()),
            Op::Exists(ABSENT.into()),
            Op::Presence(format!("Delete secret {NAME}")),
            Op::Delete(NAME.into()),
            Op::Exists(NAME.into()),
            Op::Get(NAME.into()),
            Op::Presence(format!("Delete secret {NAME}")),
            Op::Delete(NAME.into()),
        ],
        "one keystore call per answer, each delete behind the presence gate"
    );
}

/// The presence gate (ledger #201) is asked only once every other check has passed, and
/// what it answers stands. Generate under root into a fresh name checks both names are
/// free, THEN asks, then mints; into a name already holding a secret it refuses without
/// asking. A gate that finds nobody turns unlock, generate and a `Delete` into its `Denied`;
/// generate then stores nothing, and the `Delete` deletes nothing.
#[test]
fn the_presence_gate_is_asked_last_and_its_refusal_stands() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();
    let root = Capability::root();

    issue(&kernel, Verb::Source, GENERATE_IRI, &[("into", "k")], &root).unwrap();
    let err = issue(
        &kernel,
        Verb::Source,
        GENERATE_IRI,
        &[("into", NAME)],
        &root,
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::InvalidArgument { name, .. } if name == "into"),
        "{err:?}"
    );
    assert_eq!(
        backend.ops(),
        [
            Op::Exists("k".into()),
            Op::Exists("k.pub".into()),
            Op::Presence("Generate signing key k".into()),
            Op::Set("k".into()),
            Op::Set("k.pub".into()),
            Op::Exists(NAME.into()),
        ],
        "asked after the checks, before the store; not at all for a refused name"
    );
    assert_eq!(backend.presence().len(), 1);

    // Nobody at the machine: the gate's refusal is the answer, and nothing is stored.
    let nobody =
        |_: &str| -> ikigai_core::Result<()> { Err(Error::Denied("nobody at the machine".into())) };
    let kernel = Kernel::new(Arc::new(ikigai_secret::space_with_gate(
        backend.clone(),
        Arc::new(nobody),
    )));
    backend.clear();
    for (iri, args) in [
        (UNLOCK_IRI, &[][..]),
        (GENERATE_IRI, &[("into", "n"), ("type", "age")][..]),
    ] {
        let err = issue(&kernel, Verb::Source, iri, args, &root).unwrap_err();
        assert!(
            matches!(&err, Error::Denied(why) if why == "nobody at the machine"),
            "{iri}: {err:?}"
        );
    }
    assert_eq!(
        backend.ops(),
        [Op::Exists("n".into()), Op::Exists("n.pub".into())],
        "generate checked, was refused presence, and stored nothing"
    );

    // And a Delete refused presence deletes nothing: the gate's refusal is the answer,
    // under root as under the exact grant, and the keystore is never asked to delete.
    for capability in [root.clone(), delete(NAME)] {
        let err = issue(&kernel, Verb::Delete, &secret_iri(NAME), &[], &capability).unwrap_err();
        assert!(
            matches!(&err, Error::Denied(why) if why == "nobody at the machine"),
            "delete: {err:?}"
        );
    }
    assert_eq!(
        backend.inner.get(NAME).unwrap().as_deref(),
        Some(VALUE),
        "the secret survives a delete refused presence"
    );
    assert_eq!(
        backend.ops(),
        [Op::Exists("n".into()), Op::Exists("n.pub".into())],
        "and the keystore was never asked to delete"
    );
}

fn delete(name: &str) -> Capability {
    scoped(&[&format!("urn:cap:secret:delete:{name}")])
}

/// A Delete asks the presence gate (Brian, 2026-10-14) once every capability and argument
/// check has passed, and only then deletes: the gate first, the keystore second, for a
/// present secret and an absent one alike (the delete is idempotent, and whether the name
/// held a secret is not consulted before asking). A refused delete never asks: the gate
/// logs to the same recorder, so an empty log says so.
#[test]
fn delete_asks_the_presence_gate_last() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();

    // Refused by capability: neither the gate nor the keystore is reached.
    for capability in [
        scoped(&[]),
        delete("other"),
        scoped(&[
            &format!("urn:cap:secret:read:{NAME}"),
            &format!("urn:cap:secret:write:{NAME}"),
        ]),
    ] {
        let err = issue(&kernel, Verb::Delete, &secret_iri(NAME), &[], &capability).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
    }
    // Refused as an invalid name, before any capability check: nothing reached either.
    let err = issue(
        &kernel,
        Verb::Delete,
        &secret_iri("-deny-shaped"),
        &[],
        &Capability::root(),
    )
    .unwrap_err();
    assert!(matches!(&err, Error::InvalidArgument { .. }), "{err:?}");
    assert!(backend.ops().is_empty(), "{:?}", backend.ops());

    // Granted: the gate, then the delete.
    for name in [NAME, ABSENT] {
        let receipt = issue(&kernel, Verb::Delete, &secret_iri(name), &[], &delete(name)).unwrap();
        assert_eq!(receipt.bytes, b"deleted");
    }
    assert_eq!(
        backend.ops(),
        [
            Op::Presence(format!("Delete secret {NAME}")),
            Op::Delete(NAME.into()),
            Op::Presence(format!("Delete secret {ABSENT}")),
            Op::Delete(ABSENT.into()),
        ],
        "asked after every check, before the keystore"
    );
    assert!(backend.inner.get(NAME).unwrap().is_none(), "deleted");
}
