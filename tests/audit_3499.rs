//! Regression tests for the second unled audit (ledger #3499): generate's "never replaces"
//! was a check-then-act.
//!
//! `urn:secret:generate` asked `exists` for both names, then `set` each half. `set` replaces,
//! so anything that landed between the check and the write was lost:
//!
//! - **a secret stored meanwhile** (a Sink by a holder of its write scope) was overwritten by
//!   a freshly minted private key, though generate promises never to replace one;
//! - **two generates into one name** both passed the check and both "minted". Only one pair
//!   survives on disk, so at least one caller was handed a public half (an `age` recipient, a
//!   verifying key) whose private half had been overwritten: whatever it encrypts to that
//!   recipient can never be decrypted.
//!
//! On 09af35c both kernel tests below fail (reproduced with wrappers that do not forward
//! `create`, which did not exist yet). The fix is [`Backend::create`]: store only if the name
//! is free, which the file store does atomically by hard-linking a fully written temporary
//! file to the name. The file-store tests pin that primitive directly.
//!
//! No assertion message here prints a secret's bytes, even a throwaway one.

use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_resolve::Resolver;
use ikigai_secret::{space_with_gate, Backend, FileBackend};
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};

fn kernel_over(backend: Arc<dyn Backend>) -> Kernel {
    let present = |_: &str| -> ikigai_core::Result<()> { Ok(()) };
    Kernel::new(Arc::new(space_with_gate(backend, Arc::new(present))))
}

fn generate(into: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:secret:generate").unwrap())
        .with_arg("into", ArgRef::Inline(into.as_bytes().to_vec()))
        .with_arg("type", ArgRef::Inline(b"age".to_vec()))
}

/// Every entry in the store directory, by name.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The recipient an `age` identity's private half derives.
fn recipient_of(identity: &[u8]) -> String {
    use std::str::FromStr;
    let identity = std::str::from_utf8(identity).expect("an age identity is text");
    age::x25519::Identity::from_str(identity)
        .expect("an age identity parses")
        .to_public()
        .to_string()
}

/// What another writer does to the store.
type Writer = Box<dyn FnOnce(&FileBackend) + Send>;

/// The file store, with a hook run once right after the first `exists` answers: another
/// writer landing between generate's check and its write.
struct WriteAfterCheck {
    inner: FileBackend,
    hook: Mutex<Option<Writer>>,
}

impl Backend for WriteAfterCheck {
    fn get(&self, name: &str) -> ikigai_core::Result<Option<Vec<u8>>> {
        self.inner.get(name)
    }
    fn set(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.inner.set(name, value)
    }
    fn delete(&self, name: &str) -> ikigai_core::Result<()> {
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> ikigai_core::Result<bool> {
        let answer = self.inner.exists(name)?;
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook(&self.inner);
        }
        Ok(answer)
    }
    fn create(&self, name: &str, value: &[u8]) -> ikigai_core::Result<bool> {
        self.inner.create(name, value)
    }
}

#[test]
fn generate_never_replaces_a_secret_stored_after_its_check() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(WriteAfterCheck {
        inner: FileBackend::new(dir.path().join("secrets")),
        hook: Mutex::new(Some(Box::new(|store: &FileBackend| {
            store.set("deploy", b"stored-meanwhile").unwrap()
        }))),
    });
    let kernel = kernel_over(backend.clone());
    let out = Resolver::issue_as(&kernel, generate("deploy"), &Capability::root());
    let kept = backend.inner.get("deploy").unwrap().as_deref() == Some(&b"stored-meanwhile"[..]);
    assert!(
        kept,
        "generate replaced a secret stored after its existence check"
    );
    let err = out.map(|_| "it minted").expect_err("the name is taken");
    assert!(
        matches!(&err, Error::InvalidArgument { name, .. } if name == "into"),
        "refused as the up-front check refuses: {err:?}"
    );
    assert!(
        backend.inner.get("deploy.pub").unwrap().is_none(),
        "and no public half was left without its private half"
    );
}

/// The file store, holding every caller at a barrier once both of generate's existence checks
/// have answered, so two generates are past the check before either writes.
struct BothPastTheCheck {
    inner: FileBackend,
    barrier: Barrier,
    /// The barrier holds only the first two `.pub` checks (one per generate), so a later
    /// `exists` can never wait for a partner that is not coming.
    held: std::sync::atomic::AtomicUsize,
}

impl Backend for BothPastTheCheck {
    fn get(&self, name: &str) -> ikigai_core::Result<Option<Vec<u8>>> {
        self.inner.get(name)
    }
    fn set(&self, name: &str, value: &[u8]) -> ikigai_core::Result<()> {
        self.inner.set(name, value)
    }
    fn delete(&self, name: &str) -> ikigai_core::Result<()> {
        self.inner.delete(name)
    }
    fn exists(&self, name: &str) -> ikigai_core::Result<bool> {
        let answer = self.inner.exists(name)?;
        // Generate asks `<into>` first and `<into>.pub` last.
        if name.ends_with(".pub") && self.held.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2
        {
            self.barrier.wait();
        }
        Ok(answer)
    }
    fn create(&self, name: &str, value: &[u8]) -> ikigai_core::Result<bool> {
        self.inner.create(name, value)
    }
}

#[test]
fn two_generates_racing_for_one_name_mint_once_and_the_pair_matches() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(BothPastTheCheck {
        inner: FileBackend::new(dir.path().join("secrets")),
        barrier: Barrier::new(2),
        held: std::sync::atomic::AtomicUsize::new(0),
    });
    let kernel = Arc::new(kernel_over(backend.clone()));
    let racers: Vec<_> = (0..2)
        .map(|_| {
            let kernel = Arc::clone(&kernel);
            std::thread::spawn(move || {
                Resolver::issue_as(&kernel, generate("relay"), &Capability::root())
                    .map(|(repr, _)| String::from_utf8(repr.bytes).unwrap())
            })
        })
        .collect();
    let answers: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();

    let private = backend
        .inner
        .get("relay")
        .unwrap()
        .expect("one pair is stored");
    let public = backend
        .inner
        .get("relay.pub")
        .unwrap()
        .expect("both halves");
    let stored_recipient = String::from_utf8(public).unwrap();
    assert_eq!(
        recipient_of(&private),
        stored_recipient,
        "the stored halves are one pair"
    );
    let minted: Vec<&String> = answers.iter().filter_map(|a| a.as_ref().ok()).collect();
    for recipient in &minted {
        assert_eq!(
            **recipient, stored_recipient,
            "a caller was handed a public half whose private half is not stored"
        );
    }
    assert_eq!(minted.len(), 1, "exactly one generate mints");
    let refused = answers.iter().find_map(|a| a.as_ref().err()).unwrap();
    assert!(
        matches!(refused, Error::InvalidArgument { name, .. } if name == "into"),
        "the other is refused as a taken name: {refused:?}"
    );
}

#[test]
fn the_file_store_creates_only_a_free_name() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets");
    let backend = FileBackend::new(&store);
    assert!(
        backend.create("k", b"first").unwrap(),
        "a free name is created"
    );
    assert!(
        !backend.create("k", b"second").unwrap(),
        "a taken name is not"
    );
    assert!(
        backend.get("k").unwrap().as_deref() == Some(&b"first"[..]),
        "and the stored secret is unchanged"
    );
    assert_eq!(entries(&store), ["k"], "no temporary file is left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.join("k"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "created owner-only");
    }
}

#[test]
fn racing_creates_on_the_file_store_store_exactly_one_value() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets");
    let backend = Arc::new(FileBackend::new(&store));
    let racers = 8;
    let start = Arc::new(Barrier::new(racers));
    let handles: Vec<_> = (0..racers)
        .map(|i| {
            let backend = Arc::clone(&backend);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let value = format!("value-{i}");
                start.wait();
                (backend.create("shared", value.as_bytes()).unwrap(), value)
            })
        })
        .collect();
    let results: Vec<(bool, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners: Vec<&String> = results
        .iter()
        .filter(|(created, _)| *created)
        .map(|(_, v)| v)
        .collect();
    assert_eq!(winners.len(), 1, "exactly one create stores");
    assert!(
        backend.get("shared").unwrap().as_deref() == Some(winners[0].as_bytes()),
        "and what is stored is the winner's value"
    );
    assert_eq!(entries(&store), ["shared"], "no temporary file is left");
}
