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
//! wrapped in [`Recording`], which logs every `get`/`set`/`delete` by name — the
//! only witness to what the walk touched, and to what a refused call did NOT.
//!
//! ## Declarations, and why each
//!
//! - Nothing is `pure` and nothing is `cacheable`: a secret read must NEVER be
//!   cacheable (a cached secret is a secret with no thread and no expiry), so every
//!   read is `Expiry::Always` and the cache probe has nothing to hold it to. The
//!   suite has no spelling for "live by design" (conformance PENDING #22), so
//!   [`reads_are_never_cached`] pins it by hand — and walks once more with
//!   `cacheable("urn:secret")` declared, asserting the finding that draws.
//! - `NAMES` is skipped suite-wide, not opted out per id: the id `urn:secret` is a
//!   live MCP tool name (`urn_secret__source`), renamed in one coordinated pass
//!   (wave two, owned by `ikigai-core-PENDING.md` §1). `Suite::opt_out` cannot
//!   carry this — it drops the INVOKING checks and leaves NAMES running — so the
//!   check is dropped and [`names_are_wave_two`] pins the one finding the pass
//!   will flip. The two endpoints added in this wave (`secret-unlock`,
//!   `secret-generate`) are kebab-case from birth.
//! - On macOS, `secret-unlock` and `secret-generate` are opted out of the invoking
//!   checks: past their capability gate is a REAL Touch ID prompt (`LAContext`),
//!   which a headless process gets back as `SystemCanceled` — the walk under root
//!   would report the prompt, not the module. The gate BEFORE the prompt is what
//!   matters, and [`ungranted_callers_are_refused_before_the_keystore_is_touched`]
//!   pins it on every platform. Off macOS the prompt is a no-op and both are
//!   walked: the ubuntu CI job covers what the macOS job cannot.
//!
//! No module namespace: there is no RDF face (a secret has no graph to skolemize).
//!
//! ## What the suite cannot see, pinned by hand
//!
//! - **Denied before Exists** ([`ungranted_callers_are_refused_before_the_keystore_is_touched`]):
//!   ENFORCED sees a typed `Denied` under no grants; it cannot see that the keystore
//!   was never consulted, nor that a present and an absent secret refuse
//!   identically. The recording backend and a second name can. Three capability
//!   shapes: no grants (the KERNEL refuses on the declared `urn:cap:secret:read:*`
//!   before the endpoint runs — conformance PENDING #46), a grant on ANOTHER name
//!   (the wildcard admits the call; the endpoint's per-name rule refuses), and
//!   the exact grant (one `get`).
//! - **Required means required** (PENDING #49, [`required_inputs_are_required`]):
//!   drop `content` from a Sink, `into` from a generate — `MissingArgument`, and
//!   for generate BEFORE the biometric gate, so this holds on macOS too.
//! - **Declared outputs against what is served** (PENDING #11/#31,
//!   [`declared_outputs_are_the_media_types_served`]).
//! - **The manifold carries no secret VALUE** ([`the_manifold_carries_no_secret`]):
//!   `describe()`, `urn:kernel:catalog`, `urn:kernel:actions` and a `Meta` on the
//!   secret's own IRI are all resolved under root and searched for the seeded bytes.
//! - **The walk mutates the fixture** (PENDING #13/#40): PIPELINE fires the Sink
//!   under root with `content=x`, so after [`conforms`] the seeded secret IS `x`.
//!   Asserted, with the exact backend log: one `get` (the cache probe's single
//!   resolution — `Always` returns before a second), one `delete` + one `set` (the
//!   pipeline probe's Sink, fired once) — and nothing under no grants.

use ikigai_conformance::{Check, Checks, Fixture, Report, Suite};
use ikigai_core::{
    ArgRef, Capability, Description, Error, Expiry, Iri, Kernel, MetaRenderer, ReprType,
    Representation, Request, Verb,
};
use ikigai_secret::{Backend, FileBackend, GENERATE_IRI, UNLOCK_IRI};
use std::sync::{Arc, Mutex};

/// The three descriptions `space()` binds, by id, with the IRI each is bound at.
const SECRET: &str = "urn:secret";
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

/// One keystore operation the walk performed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Get(String),
    Set(String),
    Delete(String),
}

/// A backend that logs every operation by name and delegates to the file store.
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
                Op::Get(n) | Op::Set(n) | Op::Delete(n) => n == name,
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
/// secret, logged. The directory lives as long as the guard.
fn fixture() -> (Kernel, Arc<Recording>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("scratch dir");
    let backend = Arc::new(Recording {
        inner: FileBackend::new(dir.path()),
        log: Mutex::new(Vec::new()),
    });
    backend.inner.set(NAME, VALUE).expect("seed");
    let kernel = Kernel::with_meta_renderer(
        Arc::new(ikigai_secret::space(backend.clone())),
        Arc::new(EveryField),
    );
    (kernel, backend, dir)
}

/// The suite for this module: the seeded name bound on both verbs of `urn:secret`
/// (a fixture per verb, so the intent survives a suite that looks bindings up per
/// action), NAMES dropped (wave two), and on macOS the two biometric operations
/// opted out of the invoking checks — see the file docs.
fn suite() -> Suite {
    let suite = Suite::new()
        .checks(Checks::all() - Checks::NAMES)
        .fixture(Fixture::new(SECRET, Verb::Source).binding("name", NAME))
        .fixture(Fixture::new(SECRET, Verb::Sink).binding("name", NAME));
    #[cfg(target_os = "macos")]
    let suite = suite
        .opt_out(
            UNLOCK,
            Some(Verb::Source),
            "past the capability gate is a real Touch ID prompt (TCC): headless it is \
             SystemCanceled, not the module; the gate is pinned by hand",
        )
        .opt_out(
            GENERATE,
            Some(Verb::Source),
            "past the capability gate is a real Touch ID prompt (TCC): headless it is \
             SystemCanceled, not the module; the gate is pinned by hand",
        );
    suite
}

/// Whether the biometric operations were walked under root (they are, wherever
/// `require_biometric` is a no-op).
const BIOMETRIC_WALKED: bool = !cfg!(target_os = "macos");

/// The walk saw three endpoints and four actions (`urn:secret` Source + Sink,
/// one Source each for unlock and generate), skipped exactly NAMES, and opted out
/// exactly the biometric operations on macOS. A fourth endpoint bound without a
/// line here is held to a weaker standard.
fn assert_shape(report: &Report) {
    assert_eq!(report.endpoints, 3, "{report}");
    assert_eq!(report.actions, 4, "{report}");
    assert_eq!(
        report.checks.skipped().collect::<Vec<_>>(),
        vec![Check::Names],
        "only NAMES is skipped: {report}"
    );
    let opted: Vec<&str> = report
        .declared
        .opted_out
        .iter()
        .map(|o| o.endpoint.as_str())
        .collect();
    let expected: &[&str] = if BIOMETRIC_WALKED {
        &[]
    } else {
        &[UNLOCK, GENERATE]
    };
    assert_eq!(opted, expected, "{report}");
    assert!(report.declared.pure.is_empty(), "{report}");
    assert!(report.declared.namespaces.is_empty(), "{report}");
}

#[test]
fn conforms() {
    let (kernel, backend, _dir) = fixture();
    let report = suite().run_blocking(&kernel);
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
    assert!(report.declared.cacheable.is_empty(), "{report}");

    // The walk's footprint on the keystore, exactly: the cache probe read the
    // seeded secret once (`Always` needs no second resolution), the pipeline
    // probe fired the Sink once (delete + set), and ENFORCED — under no grants —
    // never reached the store.
    assert_eq!(
        backend.ops_on(NAME),
        [
            Op::Get(NAME.into()),
            Op::Delete(NAME.into()),
            Op::Set(NAME.into())
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
    // Wherever generate was walked, its minimal call (`into=x`) minted a pair.
    let minted: Vec<Op> = backend
        .ops()
        .into_iter()
        .filter(|op| matches!(op, Op::Set(n) if n == "x" || n == "x.pub"))
        .collect();
    if BIOMETRIC_WALKED {
        assert_eq!(minted, [Op::Set("x".into()), Op::Set("x.pub".into())]);
        assert_eq!(
            backend.ops().len(),
            5,
            "and nothing else: {:?}",
            backend.ops()
        );
    } else {
        assert!(minted.is_empty(), "opted out: nothing minted: {minted:?}");
        assert_eq!(
            backend.ops().len(),
            3,
            "and nothing else: {:?}",
            backend.ops()
        );
    }
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
/// under root alike — and DECLARING it cacheable draws exactly one finding, on
/// the Source of `urn:secret`, naming the declaration. That finding is the only
/// way a future `.cacheable()` on a secret becomes visible: the types are
/// identical either way.
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

    let (kernel, _backend, _dir) = fixture();
    let report = suite().cacheable(SECRET).run_blocking(&kernel);
    eprintln!("[declared cacheable]\n{report}");
    let findings: Vec<&ikigai_conformance::Finding> = report.findings.iter().collect();
    assert_eq!(findings.len(), 1, "{report}");
    let finding = findings[0];
    assert_eq!(finding.check, Check::Cacheable, "{report}");
    assert_eq!(finding.endpoint, SECRET, "{report}");
    assert_eq!(finding.verb, Some(Verb::Source), "{report}");
    assert!(
        finding.detail.contains("declared cacheable"),
        "the finding names the declaration: {finding}"
    );
    assert_eq!(report.declared.cacheable, [SECRET], "{report}");
}

/// Denied before Exists. Under no grants and under a grant on ANOTHER name, a
/// present secret and an absent one refuse identically — a typed, permanent
/// `Denied` whose text differs only by the name asked for — and the keystore is
/// never consulted, so an ungranted caller cannot learn whether a name exists.
/// Two gates are in play: with no secret grant at all the KERNEL refuses on the
/// declared wildcard before the endpoint runs (the denial names the wildcard);
/// with a grant on another name the wildcard admits the call and the endpoint's
/// per-name rule refuses it (the denial names the exact scope). The same holds
/// for the Sink, and for the two biometric operations, whose denial is the
/// capability's — never `biometric check failed`, which would mean a prompt was
/// reached. Under the exact grant: one `get`, and an absent name is a typed
/// `NotFound`.
#[test]
fn ungranted_callers_are_refused_before_the_keystore_is_touched() {
    let (kernel, backend, _dir) = fixture();
    backend.clear();

    let read_wildcard = "urn:cap:secret:read:*";
    let write_wildcard = "urn:cap:secret:write:*";
    let other_read = "urn:cap:secret:read:other";
    let other_write = "urn:cap:secret:write:other";
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

    // Source and Sink, under no grants (kernel floor) and under another name's
    // grant (endpoint rule): present and absent refuse identically.
    for (verb, capability, names) in [
        (Verb::Source, scoped(&[]), read_wildcard),
        (Verb::Source, scoped(&[other_read]), "urn:cap:secret:read:"),
        (Verb::Sink, scoped(&[]), write_wildcard),
        (Verb::Sink, scoped(&[other_write]), "urn:cap:secret:write:"),
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
    // The biometric operations refuse on their capability, before any prompt.
    for (iri, scope) in [
        (UNLOCK_IRI, "urn:cap:secret:unlock"),
        (GENERATE_IRI, "urn:cap:secret:generate"),
    ] {
        for capability in [scoped(&[]), scoped(&[other_read, other_write])] {
            let err = issue(&kernel, Verb::Source, iri, &[("into", "k")], &capability)
                .err()
                .unwrap_or_else(|| panic!("{iri} resolved under {capability:?}"));
            assert!(matches!(err, Error::Denied(_)), "{iri}: {err:?}");
            assert!(err.to_string().contains(scope), "{iri}: {err}");
            assert!(
                !err.to_string().contains("biometric"),
                "{iri}: the capability refused, not the prompt: {err}"
            );
        }
    }
    assert!(
        backend.ops().is_empty(),
        "no refused call reached the keystore: {:?}",
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
/// the keystore is untouched. Generate reads `into` BEFORE its biometric gate,
/// so this holds on macOS with no prompt.
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
        &scoped(&["urn:cap:secret:generate"]),
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
/// Read by hand, then pinned: `urn:secret` serves bytes on Source and a
/// `text/plain` receipt on Sink; unlock serves `text/plain`; generate serves the
/// PEM public key for `ed25519` and the `text/plain` recipient for `age` — two
/// declared outputs, each served by one `type`. The biometric operations are
/// fired only where their prompt is a no-op.
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
        [vec!["application/octet-stream"], vec!["text/plain"]],
        "Source, then Sink"
    );
    assert_eq!(
        served(Verb::Source, &secret_iri(NAME), &[]),
        "application/octet-stream"
    );
    assert_eq!(
        served(Verb::Sink, &secret_iri(NAME), &[("content", "v")]),
        "text/plain"
    );

    assert_eq!(declared_outputs(&kernel, UNLOCK_IRI), [vec!["text/plain"]]);
    let generate = declared_outputs(&kernel, GENERATE_IRI);
    assert_eq!(generate, [vec!["application/x-pem-file", "text/plain"]]);
    if BIOMETRIC_WALKED {
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

/// The one finding the wave-two rename will flip: `urn:secret` is a full-IRI id
/// (and a live MCP tool name); the two endpoints born in this wave are kebab-case.
#[test]
fn names_are_wave_two() {
    let (kernel, backend, _dir) = fixture();
    let report = Suite::new().checks(Checks::NAMES).run_blocking(&kernel);
    let flagged: Vec<&str> = report
        .of(Check::Names)
        .map(|f| f.endpoint.as_str())
        .collect();
    assert_eq!(flagged, [SECRET], "{report}");
    assert_eq!(report.findings.len(), 1, "{report}");
    assert_eq!(report.endpoints, 3, "{report}");
    assert!(backend.ops().is_empty(), "NAMES is a static check");
}

/// The contract as the manifold states it: `urn:secret` has a Source under the
/// read wildcard and a Sink under the write wildcard, each binding `name`, the
/// Sink requiring `content`; unlock and generate each one Source under their own
/// exact capability; every input has a class; generate's `into` is required and
/// its `type` is optional with a default among its `one_of`.
#[test]
fn the_manifold_states_the_contract() {
    /// One action's contract: verb, the scope it requires, its inputs and whether
    /// each is required.
    type Action = (Verb, &'static str, Vec<(&'static str, bool)>);
    let (kernel, _backend, _dir) = fixture();
    let contract: [(&str, &str, Vec<Action>); 3] = [
        (
            SECRET_TEMPLATE,
            SECRET,
            vec![
                (Verb::Source, "urn:cap:secret:read:*", vec![("name", true)]),
                (
                    Verb::Sink,
                    "urn:cap:secret:write:*",
                    vec![("name", true), ("content", true)],
                ),
            ],
        ),
        (
            UNLOCK_IRI,
            UNLOCK,
            vec![(Verb::Source, "urn:cap:secret:unlock", vec![])],
        ),
        (
            GENERATE_IRI,
            GENERATE,
            vec![(
                Verb::Source,
                "urn:cap:secret:generate",
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
                spec.requires,
                [requires],
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
