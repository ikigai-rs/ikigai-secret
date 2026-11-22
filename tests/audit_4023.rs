//! Regression tests for the unled keystore audit (ledger #4023): what the file store does with
//! an entry that is not a regular file.
//!
//! Each asserts the correct behavior:
//!
//! - **S1** a symlink entry is refused, never followed, and what it names is left untouched.
//! - **S2** a FIFO entry is refused at once, never waited on.
//!
//! Each runs through the kernel under the narrow grant for the one name it reads.

#![cfg(unix)]

use ikigai_core::{Capability, Iri, Kernel, Request, Verb};
use ikigai_secret::{space_with_gate, Backend, FileBackend};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The space over `backend`, its presence gate stubbed: no test here may reach Touch ID.
fn kernel_over(backend: Arc<dyn Backend>) -> Kernel {
    let present = |_: &str| -> ikigai_core::Result<()> { Ok(()) };
    Kernel::new(Arc::new(space_with_gate(backend, Arc::new(present))))
}

fn read(kernel: &Kernel, name: &str) -> ikigai_core::Result<Vec<u8>> {
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:secret:{name}")).unwrap(),
    );
    let grant = Capability::scoped([format!("urn:cap:secret:read:{name}")]);
    futures::executor::block_on(kernel.issue(request, &grant)).map(|r| r.bytes.to_vec())
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// A store with one ordinary secret in it, made by the backend so its modes are the store's.
fn store(root: &Path) -> (std::path::PathBuf, Arc<FileBackend>) {
    let dir = root.join("secrets");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("ordinary", b"stored-here").unwrap();
    (dir, backend)
}

#[test]
fn s1_a_read_never_follows_a_symlink_out_of_the_store() {
    let root = tempfile::tempdir().unwrap();
    let (dir, backend) = store(root.path());
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, b"not-a-secret-of-this-store").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("api")).unwrap();

    let kernel = kernel_over(backend);
    let answer = read(&kernel, "api");
    assert!(
        answer.is_err(),
        "a symlink entry is refused, not followed: served {:?}",
        answer.map(|b| String::from_utf8_lossy(&b).into_owned())
    );
    assert_eq!(
        mode(&outside),
        0o644,
        "a read of the store changed the mode of a file outside it"
    );
    assert_eq!(
        read(&kernel, "ordinary").unwrap(),
        b"stored-here",
        "an ordinary secret beside it still reads"
    );
}

#[test]
fn s2_a_read_of_a_fifo_entry_refuses_rather_than_hanging() {
    let root = tempfile::tempdir().unwrap();
    let (dir, backend) = store(root.path());
    let fifo =
        std::ffi::CString::new(dir.join("pipe").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "mkfifo");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let kernel = kernel_over(backend);
        let _ = tx.send(read(&kernel, "pipe"));
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(answer) => assert!(answer.is_err(), "a FIFO entry is refused: {answer:?}"),
        // The reader is still blocked in `open`; the thread is abandoned with the tempdir.
        Err(_) => panic!("a read of a FIFO entry blocked instead of refusing"),
    }
}
