//! Regression tests for audit round 3 (ledger #854): the file store and `urn:secret:generate`.
//!
//! Ported from the audit's reproductions and extended. Every test asserts the CORRECT
//! behavior; on 82294b7 each B-numbered test fails because of the defect it names.
//!
//! - **B1** the file store's name mapping was not injective: distinct names (`team:db` and
//!   `team_db`, two equal-length non-ASCII names, and on a case-insensitive volume `API-KEY`
//!   and `api-key`) shared one file, while the capability is checked on the raw name.
//! - **B2** the store was created with the process umask (files 0644, directory 0755).
//! - **B3** a Sink deleted, then truncated in place, so a failed write lost the old secret.
//! - **B4a** generate checked only `urn:cap:secret:generate`, then wrote `<into>` and
//!   `<into>.pub` with no write authority; **B4b** it stored under a reserved name.
//!
//! The generate tests run on every platform: [`kernel_over`] injects a stub presence gate
//! (ledger #201), so the real Touch ID prompt a Mac would show is never reached. They used to
//! run only off macOS, and on a Mac under WASI; that path still works (build with
//! `cargo test --target wasm32-wasip1 --test audit_854 --no-run` and run the `.wasm` under
//! Node's WASI with a preopened directory passed as `SCRATCH_DIR`; tempfile's `/tmp` is not
//! reachable there, which is the only reason [`scratch`] reads it).

use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Verb};
use ikigai_resolve::Resolver;
use ikigai_secret::{space_with_gate, Backend, FileBackend};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A scratch directory for one test: `$SCRATCH_DIR/<tag>` when set (a WASI run, where the
/// harness preopens it), else a fresh tempdir held by the guard.
fn scratch(tag: &str) -> (PathBuf, Option<tempfile::TempDir>) {
    match std::env::var("SCRATCH_DIR") {
        Ok(root) => {
            let p = PathBuf::from(root).join(tag);
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            (p, None)
        }
        Err(_) => {
            let t = tempfile::tempdir().unwrap();
            (t.path().to_path_buf(), Some(t))
        }
    }
}

/// The store directory inside a scratch directory: created by the backend, not the test, so
/// the backend's own creation (and its modes) is what is exercised.
fn store(tag: &str) -> (PathBuf, Option<tempfile::TempDir>) {
    let (dir, guard) = scratch(tag);
    (dir.join("secrets"), guard)
}

/// The space over `backend`, its presence gate stubbed to find someone at the machine: on
/// macOS the platform gate is a real Touch ID prompt, so no test here may reach it.
fn kernel_over(backend: Arc<dyn Backend>) -> Kernel {
    let present = |_: &str| -> ikigai_core::Result<()> { Ok(()) };
    Kernel::new(Arc::new(space_with_gate(backend, Arc::new(present))))
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

fn scoped(scopes: &[&str]) -> Capability {
    Capability::scoped(scopes.iter().map(|s| s.to_string()))
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

// =============================================================================================
// B1: one name, one file — injective and case-safe
// =============================================================================================

#[test]
fn b1_a_read_grant_for_one_name_does_not_read_another_secret() {
    let (dir, _guard) = store("b1-read");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("team_db", b"victim-password").unwrap();
    let kernel = kernel_over(backend);

    // The caller holds ONLY the read scope for `team:db`, a name nothing was stored under.
    let got = Resolver::issue_as(
        &kernel,
        source("team:db"),
        &scoped(&["urn:cap:secret:read:team:db"]),
    );
    match got {
        Err(Error::NotFound(_)) => {}
        Ok((repr, _)) => panic!(
            "read of `team:db` returned the secret stored under `team_db`: {:?}",
            String::from_utf8_lossy(&repr.bytes)
        ),
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

#[test]
fn b1_a_write_grant_for_one_name_does_not_overwrite_another_secret() {
    let (dir, _guard) = store("b1-write");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("team_db", b"victim-password").unwrap();
    let kernel = kernel_over(backend.clone());

    Resolver::issue_as(
        &kernel,
        sink("team:db", b"attacker-value"),
        &scoped(&["urn:cap:secret:write:team:db"]),
    )
    .expect("the granted write resolves");
    assert_eq!(
        backend.get("team_db").unwrap().as_deref(),
        Some(&b"victim-password"[..]),
        "a write to `team:db` replaced the secret stored under `team_db`"
    );
    assert_eq!(
        backend.get("team:db").unwrap().as_deref(),
        Some(&b"attacker-value"[..]),
        "and the write landed under its own name"
    );
}

#[test]
fn b1_non_ascii_names_of_equal_length_are_distinct_secrets() {
    let (dir, _guard) = store("b1-nonascii");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("шифр", b"victim-cipher-key").unwrap();
    let kernel = kernel_over(backend);
    let got = Resolver::issue_as(
        &kernel,
        source("ключ"),
        &scoped(&["urn:cap:secret:read:ключ"]),
    );
    assert!(
        matches!(got, Err(Error::NotFound(_))),
        "a grant for `ключ` read the secret `шифр`: {:?}",
        got.map(|(r, _)| String::from_utf8_lossy(&r.bytes).into_owned())
    );
}

/// On a case-insensitive volume (APFS's default, NTFS) `API-KEY` and `api-key` were one file.
/// The read below fails only where the scratch volume folds case; the entry check fails on
/// ANY volume, because it asks the stronger question: could two of these file names ever be
/// one file on a volume that folds case?
#[test]
fn b1_names_differing_only_in_case_are_distinct_secrets() {
    let (dir, _guard) = store("b1-case");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("api-key", b"victim-api-key").unwrap();
    let kernel = kernel_over(backend.clone());
    let got = Resolver::issue_as(
        &kernel,
        source("API-KEY"),
        &scoped(&["urn:cap:secret:read:API-KEY"]),
    );
    assert!(
        matches!(got, Err(Error::NotFound(_))),
        "a grant for `API-KEY` read the secret `api-key`: {:?}",
        got.map(|(r, _)| String::from_utf8_lossy(&r.bytes).into_owned())
    );

    for (name, value) in [("Api-Key", "b"), ("API-KEY", "c"), ("ApI-kEy", "d")] {
        backend.set(name, value.as_bytes()).unwrap();
    }
    let names = entries(&dir);
    let mut folded: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    folded.dedup();
    assert_eq!(
        folded.len(),
        4,
        "four names, four files that stay four on a case-folding volume: {names:?}"
    );
    for (name, value) in [
        ("api-key", "victim-api-key"),
        ("Api-Key", "b"),
        ("API-KEY", "c"),
        ("ApI-kEy", "d"),
    ] {
        assert_eq!(
            backend.get(name).unwrap().as_deref(),
            Some(value.as_bytes()),
            "{name}"
        );
    }
}

/// `.`, `..` and a leading dot can only ever address a regular file inside the store.
#[test]
fn b1_dot_names_address_only_files_inside_the_store() {
    let (dir, _guard) = store("b1-dots");
    let backend = FileBackend::new(&dir);
    let names = [".", "..", ".hidden", "../escape", "a/b", "...", "%2e"];
    for (i, name) in names.iter().enumerate() {
        backend
            .set(name, format!("v{i}").as_bytes())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            backend.get(name).unwrap().as_deref(),
            Some(format!("v{i}").as_bytes()),
            "{name}"
        );
    }
    let listed = entries(&dir);
    assert_eq!(listed.len(), names.len(), "one file per name: {listed:?}");
    for entry in &listed {
        assert!(!entry.starts_with('.'), "no hidden or dot entry: {entry}");
        assert!(dir.join(entry).is_file(), "a regular file: {entry}");
    }
    let parent = dir.parent().unwrap();
    assert_eq!(
        entries(parent),
        ["secrets"],
        "nothing was written beside the store"
    );
}

#[test]
fn b1_an_empty_name_is_refused() {
    let (dir, _guard) = store("b1-empty");
    let backend = FileBackend::new(&dir);
    assert!(
        backend.set("", b"v").is_err(),
        "an empty name names nothing"
    );
    assert!(backend.get("").is_err());
}

/// Migration: a name made only of the lowercase-safe set keeps the file name it has always
/// had, so an existing store reads unchanged; a name the old mapping collapsed is never
/// served from the collapsed file.
#[test]
fn b1_safe_names_keep_their_file_names_and_collapsed_names_are_never_guessed() {
    let (dir, _guard) = store("b1-migrate");
    std::fs::create_dir_all(&dir).unwrap();
    // A store an earlier version wrote: plain files named by the old mapping.
    for (file, value) in [
        ("cms-passkeys", "passkeys"),
        ("zotero-api-key", "zotero"),
        ("brian.sign.pub", "spki"),
        ("team_db", "written-as-team:db"),
    ] {
        std::fs::write(dir.join(file), value).unwrap();
    }
    restrict(&dir);
    let backend = FileBackend::new(&dir);
    for (name, value) in [
        ("cms-passkeys", "passkeys"),
        ("zotero-api-key", "zotero"),
        ("brian.sign.pub", "spki"),
        ("team_db", "written-as-team:db"),
    ] {
        assert_eq!(
            backend.get(name).unwrap().as_deref(),
            Some(value.as_bytes()),
            "{name} reads unchanged"
        );
    }
    // `team:db` collapsed onto `team_db` under the old mapping. Which name wrote that file is
    // unknowable, so it is never served as `team:db`.
    assert!(backend.get("team:db").unwrap().is_none());
    // And a new write of a safe name lands on the same file name it always had.
    backend.set("new-key_1.pub", b"x").unwrap();
    assert!(dir.join("new-key_1.pub").is_file());
}

/// A legacy entry that differs from a name only in case (an earlier version wrote `API-KEY`
/// verbatim) is never served under the lowercase name: on a case-folding volume it is refused
/// as ambiguous, on a case-sensitive one it is simply not that name's file.
#[test]
fn b1_a_legacy_entry_differing_in_case_is_never_served() {
    let (dir, _guard) = store("b1-legacy-case");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("API-KEY"), b"legacy-upper").unwrap();
    restrict(&dir);
    let backend = FileBackend::new(&dir);
    match backend.get("api-key") {
        Ok(None) | Err(_) => {}
        Ok(Some(bytes)) => panic!(
            "`api-key` was served the legacy `API-KEY` entry: {:?}",
            String::from_utf8_lossy(&bytes)
        ),
    }
    // A write to `api-key` must not replace it either, wherever the volume folds case.
    let _ = backend.set("api-key", b"new");
    assert_eq!(
        std::fs::read(dir.join("API-KEY")).unwrap(),
        b"legacy-upper",
        "the legacy entry is untouched"
    );
}

/// Give a hand-built store the owner-only modes the backend demands, so a migration test is
/// about names and not about modes.
fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for entry in std::fs::read_dir(dir).unwrap() {
            std::fs::set_permissions(
                entry.unwrap().path(),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

// =============================================================================================
// B2: private by construction
// =============================================================================================

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
#[test]
fn b2_file_backend_secrets_are_private_to_the_owner() {
    let (dir, _guard) = store("b2-modes");
    let backend = FileBackend::new(&dir);
    backend
        .set("brian.sign", b"-----BEGIN PRIVATE KEY-----")
        .unwrap();
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(mode(&file), 0o600, "secret file mode {:o}", mode(&file));
    assert_eq!(mode(&dir), 0o700, "secret dir mode {:o}", mode(&dir));
}

/// The modes hold under ANY umask: run in a child process under `umask 000`, because the umask
/// is process-global and this binary's other tests create files concurrently.
#[cfg(unix)]
#[test]
fn b2_modes_are_independent_of_the_umask() {
    run_in_child("umask 000", "b2_inner_modes_under_the_inherited_umask");
}

#[cfg(unix)]
#[test]
#[ignore = "run by b2_modes_are_independent_of_the_umask in a child under `umask 000`"]
fn b2_inner_modes_under_the_inherited_umask() {
    let (dir, _guard) = store("b2-umask");
    let backend = FileBackend::new(&dir);
    backend.set("k", b"v").unwrap();
    backend.set("k", b"v2").unwrap(); // a replace, too
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("k")), 0o600);
}

/// An existing store others can READ is tightened (once: it is private afterwards).
#[cfg(unix)]
#[test]
fn b2_an_existing_store_others_can_read_is_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _guard) = store("b2-tighten");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("k"), b"v").unwrap();
    std::fs::set_permissions(dir.join("k"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let backend = FileBackend::new(&dir);
    assert_eq!(backend.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    assert_eq!(mode(&dir), 0o700, "the directory was tightened");
    assert_eq!(mode(&dir.join("k")), 0o600, "the file was tightened");
}

/// An existing store or file someone else could WRITE is refused: its contents (a key, a
/// recipient) are not trusted, and tightening now would trust whatever was written.
#[cfg(unix)]
#[test]
fn b2_a_store_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _guard) = store("b2-refuse");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("k"), b"v").unwrap();
    std::fs::set_permissions(dir.join("k"), std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let backend = FileBackend::new(&dir);
    let err = backend
        .get("k")
        .expect_err("a group-writable store is refused");
    assert!(err.to_string().contains("writable"), "{err}");
    assert!(backend.set("k", b"w").is_err(), "and no write lands in it");
    assert_eq!(mode(&dir), 0o770, "a refused store is not silently fixed");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(dir.join("k"), std::fs::Permissions::from_mode(0o602)).unwrap();
    let err = backend
        .get("k")
        .expect_err("a world-writable secret is refused");
    assert!(err.to_string().contains("writable"), "{err}");
}

// =============================================================================================
// B3: a failed write keeps the previous secret
// =============================================================================================

/// A write that fails (here: a 512-byte file-size limit standing in for a full disk) leaves
/// the previous secret intact and no partial value behind.
#[cfg(unix)]
#[test]
fn b3_a_failed_sink_keeps_the_previous_secret() {
    run_in_child(
        "trap '' XFSZ; ulimit -f 1",
        "b3_inner_a_failed_sink_under_a_file_size_limit",
    );
}

#[cfg(unix)]
#[test]
#[ignore = "run by b3_a_failed_sink_keeps_the_previous_secret in a child under `ulimit -f 1`"]
fn b3_inner_a_failed_sink_under_a_file_size_limit() {
    let (dir, _guard) = store("b3");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("api-token", b"old-token-value").unwrap();
    let kernel = kernel_over(backend.clone());
    let big = vec![b'n'; 8192];

    let out = Resolver::issue_as(
        &kernel,
        sink("api-token", &big),
        &scoped(&["urn:cap:secret:write:api-token"]),
    );
    let after = backend.get("api-token").unwrap();
    assert!(out.is_err(), "the limit makes the write fail");
    assert!(
        after.as_deref() == Some(&b"old-token-value"[..]),
        "the write failed and the old secret is gone; stored now: {} bytes",
        after.as_ref().map_or(0, Vec::len)
    );
    assert_eq!(entries(&dir), ["api-token"], "no temporary file is left");
}

/// Run one `#[ignore]`d test of this binary in a child process whose shell first runs
/// `prelude`, and require it to pass. `wait`, not `try_wait`: the child must be reaped.
#[cfg(unix)]
fn run_in_child(prelude: &str, test: &str) {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{prelude}; exec \"$0\" --ignored --exact {test} --test-threads=1"
        ))
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{test} failed in the child:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("1 passed"),
        "{test} ran: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// =============================================================================================
// B4: generate writes only what its caller may write, and never a reserved name
// =============================================================================================

fn generate(into: &str, kind: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:secret:generate").unwrap())
        .with_arg("into", ArgRef::Inline(into.as_bytes().to_vec()))
        .with_arg("type", ArgRef::Inline(kind.as_bytes().to_vec()))
}

#[test]
fn b4_generate_does_not_overwrite_a_secret_the_caller_cannot_write() {
    let (dir, _guard) = store("b4a");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("zoom-client-secret", b"victim").unwrap();
    let kernel = kernel_over(backend.clone());
    let out = Resolver::issue_as(
        &kernel,
        generate("zoom-client-secret", "age"),
        &scoped(&["urn:cap:secret:generate"]),
    );
    assert!(
        matches!(out, Err(Error::Denied(_))),
        "generate with no write scope: {:?}",
        out.map(|_| "it resolved")
    );
    assert_eq!(
        backend.get("zoom-client-secret").unwrap().as_deref(),
        Some(&b"victim"[..]),
        "generate replaced a secret the caller holds no write scope for"
    );
}

/// Write authority over BOTH halves: `<into>` and `<into>.pub`.
#[test]
fn b4_generate_needs_write_authority_over_both_halves() {
    let (dir, _guard) = store("b4a-halves");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("alice.enc.pub", b"victim-recipient").unwrap();
    let kernel = kernel_over(backend.clone());
    let out = Resolver::issue_as(
        &kernel,
        generate("alice.enc", "age"),
        &scoped(&["urn:cap:secret:generate", "urn:cap:secret:write:alice.enc"]),
    );
    let err = out.expect_err("no write scope for `alice.enc.pub`");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(
        err.to_string()
            .contains("urn:cap:secret:write:alice.enc.pub"),
        "{err}"
    );
    assert!(
        backend.get("alice.enc").unwrap().is_none(),
        "nothing minted"
    );
    assert_eq!(
        backend.get("alice.enc.pub").unwrap().as_deref(),
        Some(&b"victim-recipient"[..])
    );

    // With both, it mints.
    let (repr, _) = Resolver::issue_as(
        &kernel,
        generate("bob.enc", "age"),
        &scoped(&[
            "urn:cap:secret:generate",
            "urn:cap:secret:write:bob.enc",
            "urn:cap:secret:write:bob.enc.pub",
        ]),
    )
    .expect("generate with both write scopes mints");
    assert_eq!(
        backend.get("bob.enc.pub").unwrap().as_deref(),
        Some(&repr.bytes[..])
    );
    assert!(backend.get("bob.enc").unwrap().is_some());
}

/// Generate never overwrites, even under root: either half already present refuses, and
/// nothing changes. Rotation is a new name.
#[test]
fn b4_generate_refuses_a_name_that_already_holds_a_secret() {
    let (dir, _guard) = store("b4a-exists");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("brian.sign", b"victim-private").unwrap();
    backend.set("carol.sign.pub", b"victim-public").unwrap();
    let kernel = kernel_over(backend.clone());
    for into in ["brian.sign", "carol.sign"] {
        let err = Resolver::issue_as(&kernel, generate(into, "ed25519"), &Capability::root())
            .expect_err("an existing name is refused");
        assert!(
            matches!(&err, Error::InvalidArgument { name, .. } if name == "into"),
            "{into}: {err:?}"
        );
    }
    assert_eq!(
        backend.get("brian.sign").unwrap().as_deref(),
        Some(&b"victim-private"[..])
    );
    assert!(backend.get("brian.sign.pub").unwrap().is_none());
    assert!(backend.get("carol.sign").unwrap().is_none());
    assert_eq!(
        backend.get("carol.sign.pub").unwrap().as_deref(),
        Some(&b"victim-public"[..])
    );
}

// README: "a secret can never be stored under either reserved name".
#[test]
fn b4_generate_never_stores_under_a_reserved_name() {
    let (dir, _guard) = store("b4b");
    let backend = Arc::new(FileBackend::new(&dir));
    let kernel = kernel_over(backend.clone());
    for reserved in ["unlock", "generate"] {
        let err = Resolver::issue_as(&kernel, generate(reserved, "ed25519"), &Capability::root())
            .expect_err("a reserved name is refused");
        assert!(
            matches!(&err, Error::InvalidArgument { name, .. } if name == "into"),
            "{reserved}: {err:?}"
        );
        assert!(
            backend.get(reserved).unwrap().is_none(),
            "a private key was stored under the reserved name `{reserved}`"
        );
        assert!(backend.get(&format!("{reserved}.pub")).unwrap().is_none());
    }
}

// =============================================================================================
// S3 (the second audit): the write face takes any bytes, as the read face serves them
// =============================================================================================

/// The read face answers `application/octet-stream`, so the write face must take the same
/// bytes: a binary secret set through the backend can be replaced through the resource.
#[test]
fn s3_the_write_face_stores_any_bytes() {
    let (dir, _guard) = store("s3");
    let backend = Arc::new(FileBackend::new(&dir));
    backend.set("blob", &[0x00, 0xff, 0x01]).unwrap();
    let kernel = kernel_over(backend.clone());
    let binary = [0xff, 0x00, 0x80, 0xfe, b'\n'];
    Resolver::issue_as(
        &kernel,
        sink("blob", &binary),
        &scoped(&["urn:cap:secret:write:blob"]),
    )
    .expect("a non-UTF-8 value is stored");
    let (repr, _) = Resolver::issue_as(
        &kernel,
        source("blob"),
        &scoped(&["urn:cap:secret:read:blob"]),
    )
    .unwrap();
    assert_eq!(repr.bytes, binary, "and read back byte for byte");
}
