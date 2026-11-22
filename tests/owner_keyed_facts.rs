//! Facts the owner-keyed design (`docs/owner-keyed-secrets.md`, ledger #3750) relies on, pinned
//! against the crate and the core it links today. Nothing here is the new design: each test
//! states something TRUE NOW that the design builds on, so a change that breaks one is a change
//! the design has to be revisited for.
//!
//! 1. A new-form IRI already resolves through 0.4.0's `urn:secret:{name}`: the template takes the
//!    whole partition path as the name, checks `urn:cap:secret:<verb>:<path>`, and keys the
//!    keystore by `<path>`. So the proposed scope spelling and storage key agree with what a
//!    0.4.0 host does for the same IRI, and another owner's grant is refused before the keystore.
//! 2. The proposed template captures the OWNER as the first segment, however the name is spelled,
//!    so a name cannot smuggle a second owner into the parse.
//! 3. A core prefix alias from the old namespace to the new one cannot work, because the old
//!    namespace is a prefix of the new: every name is refused. The legacy face is the module's.
//! 4. `Capability::allows` is exact (no trailing wildcard), while the declared `…:read:*` floor is
//!    a presence test a new-form scope satisfies.
//! 5. No new-form scope is deny-shaped, whatever its owner or name begins with.

use std::sync::{Arc, Mutex};

use ikigai_core::{
    is_deny_scope, AliasTable, ArgRef, Canonical, Capability, Error, Grammar, Iri, Kernel, Request,
    Result, UriTemplate, Verb,
};
use ikigai_secret::{space_with_gate, Backend};

/// A backend that records every keystore call and holds what it is given.
#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<String>>,
    held: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Recording {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn log(&self, op: &str, name: &str) {
        self.calls.lock().unwrap().push(format!("{op} {name}"));
    }
}

impl Backend for Recording {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.log("get", name);
        Ok(self
            .held
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone()))
    }
    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.log("set", name);
        let mut held = self.held.lock().unwrap();
        held.retain(|(n, _)| n != name);
        held.push((name.to_string(), value.to_vec()));
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.log("delete", name);
        self.held.lock().unwrap().retain(|(n, _)| n != name);
        Ok(())
    }
    fn replace(&self, name: &str, value: &[u8]) -> Result<()> {
        self.log("replace", name);
        self.set(name, value)
    }
}

fn kernel_over(backend: Arc<Recording>) -> Kernel {
    let backend: Arc<dyn Backend> = backend;
    let never = |reason: &str| -> Result<()> { panic!("the presence gate was asked: {reason}") };
    Kernel::new(Arc::new(space_with_gate(backend, Arc::new(never))))
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

fn issue(kernel: &Kernel, request: Request, capability: &Capability) -> Result<Vec<u8>> {
    futures::executor::block_on(kernel.issue(request, capability)).map(|r| r.bytes.to_vec())
}

const ACME_DEPLOY: &str = "owner:id:acme:name:deploy-token";

#[test]
fn a_new_form_iri_already_resolves_with_the_proposed_scope_and_storage_key() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    let iri = format!("urn:secret:{ACME_DEPLOY}");

    // The write scope the design proposes for (acme, deploy-token) is the one 0.4.0 checks.
    let write = scoped(&[&format!("urn:cap:secret:write:{ACME_DEPLOY}")]);
    let sink = Request::new(Verb::Sink, Iri::parse(iri.clone()).unwrap())
        .with_arg("content", ArgRef::Inline(b"t0ken".to_vec()));
    issue(&kernel, sink, &write).expect("stored under the proposed write scope");
    // And the keystore key is the partition path, verbatim.
    assert_eq!(
        backend.calls(),
        [
            format!("replace {ACME_DEPLOY}"),
            format!("set {ACME_DEPLOY}")
        ]
    );

    let read = scoped(&[&format!("urn:cap:secret:read:{ACME_DEPLOY}")]);
    let source = || Request::new(Verb::Source, Iri::parse(iri.clone()).unwrap());
    assert_eq!(issue(&kernel, source(), &read).unwrap(), b"t0ken");

    // Another owner's grant for the same name passes the kernel's `read:*` floor and is refused
    // by the per-name rule, before the keystore.
    let before = backend.calls().len();
    let other = scoped(&["urn:cap:secret:read:owner:id:other:name:deploy-token"]);
    let err = issue(&kernel, source(), &other).unwrap_err();
    assert!(
        matches!(&err, Error::Denied(why) if why.message().contains(&format!("urn:cap:secret:read:{ACME_DEPLOY}"))),
        "refused naming the exact scope: {err:?}"
    );
    assert_eq!(
        backend.calls().len(),
        before,
        "the keystore was not consulted"
    );
}

#[test]
fn the_legacy_template_takes_a_new_form_name_whole() {
    // So the new template must be bound AHEAD of the legacy one, and a legacy name beginning
    // with `owner:` is shadowed by it.
    let legacy = UriTemplate::parse("urn:secret:{name}").unwrap();
    let bound = legacy
        .match_iri(&Iri::parse(format!("urn:secret:{ACME_DEPLOY}")).unwrap())
        .expect("the legacy template matches a new-form IRI");
    assert_eq!(bound.get("name"), Some(ACME_DEPLOY));
}

#[test]
fn the_proposed_template_captures_the_owner_as_the_first_segment() {
    let template = UriTemplate::parse("urn:secret:owner:id:{owner}:name:{name}").unwrap();
    // A name spelled to look like a second owner partition stays a name of the FIRST owner.
    let iri =
        Iri::parse("urn:secret:owner:id:legacy:name:x:owner:id:acme:name:deploy-token").unwrap();
    let bound = template.match_iri(&iri).expect("matches");
    assert_eq!(bound.get("owner"), Some("legacy"));
    assert_eq!(bound.get("name"), Some("x:owner:id:acme:name:deploy-token"));
    // An IRI with no `:name:` key is not a secret under this template.
    let policy = Iri::parse("urn:secret:owner:id:acme:policy").unwrap();
    assert!(template.match_iri(&policy).is_none());
}

#[test]
fn a_core_prefix_alias_from_the_old_namespace_to_the_new_refuses_every_name() {
    let table = AliasTable::new().prefix("urn:secret:", "urn:secret:owner:id:legacy:name:");
    for name in ["deploy-token", ACME_DEPLOY] {
        let iri = Iri::parse(format!("urn:secret:{name}")).unwrap();
        match table.canonicalize(&iri) {
            Canonical::Refused(refusal) => assert!(
                refusal.reason.contains("exceeded"),
                "refused for the hop limit: {}",
                refusal.reason
            ),
            other => panic!("expected a refusal for `{name}`, got {other:?}"),
        }
    }
}

#[test]
fn allows_is_exact_and_the_declared_floor_is_a_presence_test() {
    let owner_wide = scoped(&["urn:cap:secret:read:owner:id:acme:name:*"]);
    assert!(!owner_wide.allows(&format!("urn:cap:secret:read:{ACME_DEPLOY}")));
    let exact = scoped(&[&format!("urn:cap:secret:read:{ACME_DEPLOY}")]);
    assert!(exact.satisfies("urn:cap:secret:read:*"));
    assert!(!exact.satisfies("urn:cap:secret:write:*"));
}

#[test]
fn no_new_form_scope_is_deny_shaped() {
    for verb in ["read", "write", "delete"] {
        for (owner, name) in [("acme", "x"), ("-acme", "x"), ("acme", "-x"), ("-", "-")] {
            let scope = format!("urn:cap:secret:{verb}:owner:id:{owner}:name:{name}");
            assert!(!is_deny_scope(&scope), "{scope} reads as a grant");
        }
    }
    // The legacy spelling's hazard, for contrast: the name sits in the reserved position.
    assert!(is_deny_scope("urn:cap:secret:read:-x"));
}
