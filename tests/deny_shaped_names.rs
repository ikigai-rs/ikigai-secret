//! A secret's name may not begin with `-` (ledger #874).
//!
//! The name is the last segment of its scopes, `urn:cap:secret:read:<name>` and
//! `urn:cap:secret:write:<name>`, which is the position ikigai-core 0.1.86 reserves across
//! `urn:cap:` for an EXCLUSION (`is_deny_scope`): `allows()` never grants a deny-shaped token,
//! so a grant for `-x` could never be honored and the caller saw a bare `Denied` for the very
//! scope they held. Every face now refuses such a name as an invalid argument, before any
//! capability check and whatever core is linked: the read face, the write face, generate's
//! `into`, and the file store's own API.
//!
//! Reproduced before the fix in a scratch copy of main: with core 0.1.69 (main's lock) a Sink
//! to `urn:secret:-x` under exactly `urn:cap:secret:write:-x` STORED the secret; resolved
//! fresh (core 0.1.86) the same call answered `Denied("writing `-x` requires
//! `urn:cap:secret:write:-x`")`.

use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Result, Verb};
use ikigai_resolve::Resolver;
use ikigai_secret::{space, Backend, FileBackend};
use std::sync::{Arc, Mutex};

/// A backend that records every call and holds nothing: a refusal must never reach it.
#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<String>>,
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
        Ok(None)
    }
    fn set(&self, name: &str, _value: &[u8]) -> Result<()> {
        self.log("set", name);
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.log("delete", name);
        Ok(())
    }
    fn exists(&self, name: &str) -> Result<bool> {
        self.log("exists", name);
        Ok(false)
    }
    fn replace(&self, name: &str, _value: &[u8]) -> Result<()> {
        self.log("replace", name);
        Ok(())
    }
}

fn kernel_over(backend: Arc<Recording>) -> Kernel {
    let backend: Arc<dyn Backend> = backend;
    Kernel::new(Arc::new(space(backend)))
}

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
}

fn source(name: &str) -> Request {
    Request::new(
        Verb::Source,
        Iri::parse(format!("urn:secret:{name}")).unwrap(),
    )
}

fn sink(name: &str, value: &[u8]) -> Request {
    Request::new(
        Verb::Sink,
        Iri::parse(format!("urn:secret:{name}")).unwrap(),
    )
    .with_arg("content", ArgRef::Inline(value.to_vec()))
}

fn generate(into: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:secret:generate").unwrap())
        .with_arg("into", ArgRef::Inline(into.as_bytes().to_vec()))
        .with_arg("type", ArgRef::Inline(b"ed25519".to_vec()))
}

/// The refusal: an `InvalidArgument` on `arg` whose detail says why.
fn assert_refused(err: &Error, arg: &str, what: &str) {
    match err {
        Error::InvalidArgument { name, detail } => {
            assert_eq!(name, arg, "{what}: refused on the wrong argument: {err:?}");
            assert!(
                detail.contains("begins with `-`") && detail.contains("exclusion"),
                "{what}: the refusal does not say why: {detail}"
            );
        }
        other => panic!("{what}: expected InvalidArgument on `{arg}`, got {other:?}"),
    }
}

#[test]
fn the_read_face_refuses_a_name_beginning_with_dash() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    // The exact grant (what a caller would hold), a grant for another name (which satisfies
    // the kernel's `urn:cap:secret:read:*` floor and nothing else), and root: every one is
    // answered with the same refusal, so it comes before the capability check.
    for (what, cap) in [
        ("the exact grant", scoped(&["urn:cap:secret:read:-x"])),
        (
            "another name's grant",
            scoped(&["urn:cap:secret:read:other"]),
        ),
        ("root", Capability::root()),
    ] {
        let err = Resolver::issue_as(&kernel, source("-x"), &cap)
            .expect_err("a name beginning with `-` is refused");
        assert_refused(&err, "name", what);
    }
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());
}

#[test]
fn the_write_face_refuses_a_name_beginning_with_dash() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    for (what, cap) in [
        ("the exact grant", scoped(&["urn:cap:secret:write:-x"])),
        (
            "another name's grant",
            scoped(&["urn:cap:secret:write:other"]),
        ),
        ("root", Capability::root()),
    ] {
        let err = Resolver::issue_as(&kernel, sink("-x", b"value"), &cap)
            .expect_err("a name beginning with `-` is refused");
        assert_refused(&err, "name", what);
    }
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());
}

/// A `-` anywhere but first is just a character: the common case keeps working.
#[test]
fn a_dash_inside_a_name_is_still_a_name() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    Resolver::issue_as(
        &kernel,
        sink("api-key", b"v"),
        &scoped(&["urn:cap:secret:write:api-key"]),
    )
    .expect("an interior `-` is stored");
    assert_eq!(backend.calls(), ["replace api-key"]);
}

/// Generate's `into` is refused before every check that follows it. The capability here holds
/// `urn:cap:secret:generate` and `write:-k` but NOT `write:-k.pub`, so without the refusal the
/// call stops at `Denied` before the biometric gate: safe to run on a Mac, where that gate is a
/// real Touch ID prompt.
#[test]
fn generate_refuses_into_beginning_with_dash() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    let cap = scoped(&["urn:cap:secret:generate", "urn:cap:secret:write:-k"]);
    let err = Resolver::issue_as(&kernel, generate("-k"), &cap)
        .expect_err("an `into` beginning with `-` is refused");
    assert_refused(&err, "into", "generate");
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());
}

/// With every grant (root) the refusal still comes first. Off macOS only: were the refusal
/// missing, this call would reach the biometric gate, which on a Mac is a real prompt.
#[cfg(not(target_os = "macos"))]
#[test]
fn generate_refuses_into_beginning_with_dash_even_for_root() {
    let backend = Arc::new(Recording::default());
    let kernel = kernel_over(backend.clone());
    let err = Resolver::issue_as(&kernel, generate("-k"), &Capability::root())
        .expect_err("an `into` beginning with `-` is refused");
    assert_refused(&err, "into", "generate as root");
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());
}

/// The file store's public API refuses what the resource refuses, on every operation, and
/// creates nothing. A file already on disk under such a name (only creatable before this
/// change) is not served through the API either.
#[test]
fn the_file_store_refuses_a_name_beginning_with_dash() {
    let scratch = tempfile::tempdir().unwrap();
    let dir = scratch.path().join("secrets");
    let store = FileBackend::new(&dir);

    assert_refused(&store.set("-x", b"v").unwrap_err(), "name", "set");
    assert_refused(&store.replace("-x", b"v").unwrap_err(), "name", "replace");
    assert!(!dir.exists(), "a refused write created the store");

    // Plant a legacy file under the name, through a name the store does accept.
    store.set("x", b"legacy").unwrap();
    std::fs::rename(dir.join("x"), dir.join("-x")).unwrap();

    assert_refused(&store.get("-x").unwrap_err(), "name", "get");
    assert_refused(&store.exists("-x").unwrap_err(), "name", "exists");
    assert_refused(&store.delete("-x").unwrap_err(), "name", "delete");
    assert!(dir.join("-x").exists(), "a refused delete removed the file");
}
