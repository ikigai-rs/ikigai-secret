//! The file keystore: [`FileBackend`], one owner-only file per secret in a private directory.
//!
//! This module is the crate's only reach into the filesystem.
//! Hypothesis H (an endpoint reaches resources only by requests) does not apply to the
//! keystore itself: a secrets store is a CONNECTOR, the code that holds the bytes a request for
//! `urn:secret:{name}` answers with, so it opens its own directory by design. Keeping every such
//! operation here lets one named exception cover exactly the keystore and nothing else.

// ambient: fs: the file keystore is this connector's job: it owns the private secrets directory (create, judge its owner and mode, list, read, atomic write, delete) and nothing outside it
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use ikigai_core::{Error, Result};

use crate::{refuse_deny_shaped, Backend};

/// A dev file backend: one file per secret in a PRIVATE directory (default
/// `~/.ikigai/secrets`, override with `IKIGAI_SECRETS`). Not hardware-backed — for non-macOS
/// and development.
///
/// **The storage format.** A secret's bytes are the whole content of one regular file whose
/// name is the secret's name, escaped so that the mapping is injective and case-safe:
///
/// - `a`–`z`, `0`–`9`, `-`, `_` and `.` are kept verbatim — except a LEADING `.`, so no name
///   can address `.`, `..` or a hidden file (the store's own temporary files are hidden);
/// - every other byte of the name's UTF-8, uppercase ASCII included, is written as `%` and
///   two lowercase hex digits (`API-KEY` → `%41%50%49-%4b%45%59`, `team:db` → `team%3adb`).
///
/// A name that is empty or begins with `-` is refused by every operation: the resource refuses
/// a leading `-` because no capability could grant it, and the store refuses what the resource
/// does.
///
/// No file name the mapping produces contains an uppercase letter, so two distinct names are
/// two distinct files even on a volume that folds case. A name made only of the verbatim set
/// keeps the file name every earlier version gave it, so an existing store of such names
/// reads unchanged. An earlier version mapped every other character to `_`, collapsing
/// distinct names onto one file; which name wrote such a file cannot be known, so it is
/// served only under the name its file name spells (as before), never under the name that may
/// have written it.
///
/// **Modes (Unix).** The directory is `0700` and every file `0600`, set explicitly at
/// creation so the umask cannot widen them. An existing directory or file others can READ is
/// tightened to `0700`/`0600` and logged once on stderr; one others can WRITE, or owned by
/// another user, is refused: its contents are not trusted, and tightening it would trust
/// whatever was written. **Writes are atomic**: a `set` writes a `0600` temporary file in the
/// store, syncs it and renames it over the old one, so a failed write leaves the previous
/// secret intact.
pub struct FileBackend {
    /// The store directory, or why there is none: every operation then refuses with it.
    pub(crate) dir: std::result::Result<PathBuf, String>,
}

impl FileBackend {
    /// A backend rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileBackend {
            dir: Ok(dir.into()),
        }
    }

    /// A backend at `$IKIGAI_SECRETS`, else in the data home (`~/.ikigai/secrets`).
    ///
    /// Refuses rather than guessing: with `HOME` unset or empty and no `IKIGAI_SECRETS` there
    /// is no store, and a store relative to the working directory is never used (nor a
    /// relative `IKIGAI_SECRETS`), because secrets would land wherever the process happened
    /// to start.
    pub fn in_data_dir() -> Result<Self> {
        store_dir_from(std::env::var_os("IKIGAI_SECRETS"), std::env::var_os("HOME"))
            .map(FileBackend::new)
            .map_err(Error::Endpoint)
    }

    /// The old name of [`in_data_dir`](Self::in_data_dir): the store is DATA, not config.
    /// Infallible for compatibility, so with no store it returns a backend that refuses every
    /// operation with the reason (it no longer falls back to a directory relative to the
    /// working directory).
    #[deprecated(
        since = "0.1.7",
        note = "the store is in the data home; use `FileBackend::in_data_dir`, which refuses \
                rather than returning a backend that refuses every operation"
    )]
    pub fn in_config_dir() -> Self {
        Self::in_data_dir_or_refusing()
    }

    /// [`in_data_dir`](Self::in_data_dir), or a backend that refuses every operation with the
    /// reason there is no store — for the infallible [`default_backend`](crate::default_backend).
    pub(crate) fn in_data_dir_or_refusing() -> Self {
        FileBackend {
            dir: store_dir_from(std::env::var_os("IKIGAI_SECRETS"), std::env::var_os("HOME")),
        }
    }

    fn dir(&self) -> Result<&Path> {
        self.dir
            .as_deref()
            .map_err(|why| Error::Endpoint(why.clone()))
    }

    /// The store directory and `name`'s file name in it.
    fn locate(&self, name: &str) -> Result<(&Path, String)> {
        Ok((self.dir()?, file_name(name)?))
    }
}

/// Where the file store lives: `secrets` (the `IKIGAI_SECRETS` value) when set and non-empty,
/// else `<home>/.ikigai/secrets`. `Err` naming the fix when there is no absolute answer.
pub(crate) fn store_dir_from(
    secrets: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> std::result::Result<PathBuf, String> {
    if let Some(dir) = secrets.filter(|value| !value.is_empty()) {
        let dir = PathBuf::from(dir);
        return if dir.is_absolute() {
            Ok(dir)
        } else {
            Err(format!(
                "IKIGAI_SECRETS is `{}`, a path relative to the working directory; the secrets \
                 store must be an absolute directory",
                dir.display()
            ))
        };
    }
    ikigai_core::config::data_home_from(home)
        .and_then(|home| ikigai_core::config::data_path_in(&home, "secrets"))
        .filter(|dir| dir.is_absolute())
        .ok_or_else(|| {
            "no secrets store: HOME is unset, empty or relative, so there is no \
             ~/.ikigai/secrets, and secrets are never kept relative to the working directory; \
             set HOME, or set IKIGAI_SECRETS to an absolute directory"
                .to_string()
        })
}

/// A secret's file name: injective and free of uppercase (see [`FileBackend`]).
pub(crate) fn file_name(name: &str) -> Result<String> {
    use std::fmt::Write;
    if name.is_empty() {
        return Err(Error::InvalidArgument {
            name: "name".into(),
            detail: "an empty name names no secret".into(),
        });
    }
    // The store refuses what the resource refuses, so a name no grant could ever cover is not
    // creatable through the library either.
    refuse_deny_shaped(name, "name")?;
    let mut out = String::with_capacity(name.len());
    for (i, byte) in name.bytes().enumerate() {
        let verbatim =
            matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') || (byte == b'.' && i > 0);
        if verbatim {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02x}");
        }
    }
    Ok(out)
}

/// The refusal for a legacy entry that differs from a name's file only in case.
fn ambiguous(dir: &Path, file: &str) -> Error {
    Error::Endpoint(format!(
        "the secrets store {} holds an entry that differs from `{file}` only in case — written \
         by ikigai-secret 0.1.6 or earlier, which kept uppercase verbatim. This volume folds \
         case, so it is the same file, and which name stored it cannot be known; it is refused \
         rather than guessed. Inspect it at the box, then rename or remove it",
        dir.display()
    ))
}

/// Whether `dir` holds an entry named exactly `file`, byte for byte. Asked only once a file
/// is known to be there: on a volume that folds case, opening `api-key` also opens a legacy
/// `API-KEY`, and only the directory listing says which spelling is on disk.
fn exact_entry(dir: &Path, file: &str) -> Result<bool> {
    let io = |e: std::io::Error| Error::Endpoint(format!("secret store listing: {e}"));
    for entry in std::fs::read_dir(dir).map_err(io)? {
        if entry.map_err(io)?.file_name() == std::ffi::OsStr::new(file) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the store directory exists, judging its owner and mode when it does.
fn check_dir(dir: &Path) -> Result<bool> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            modes::guard(dir, &meta, modes::DIR, |mode| {
                std::fs::set_permissions(dir, mode)
            })?;
            Ok(true)
        }
        Ok(_) => Err(Error::Endpoint(format!(
            "the secrets store {} is not a directory",
            dir.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Endpoint(format!(
            "secrets store {}: {e}",
            dir.display()
        ))),
    }
}

/// The store directory, created private if it is absent.
fn ensure_dir(dir: &Path) -> Result<()> {
    if check_dir(dir)? {
        return Ok(());
    }
    let io = |e: std::io::Error| Error::Endpoint(format!("secrets store {}: {e}", dir.display()));
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    #[cfg(unix)]
    let builder = {
        let mut builder = std::fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, modes::DIR);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    match builder.create(dir) {
        // Created here: set the mode outright, so the umask cannot have narrowed or widened it.
        Ok(()) => modes::set(dir, modes::DIR).map_err(io)?,
        // Created meanwhile by someone else: judged like any existing store, below.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(e)),
    }
    check_dir(dir).map(|_| ())
}

/// Write `value` to `target` whole: a private temporary file in the store, synced, renamed
/// over the target. A failure at any point leaves the previous file (or none) and no partial
/// one; the temporary file is removed.
fn write_atomic(dir: &Path, target: &Path, value: &[u8]) -> Result<()> {
    use rand_core::RngCore;
    use std::io::Write;
    let fail = |e: std::io::Error| Error::Endpoint(format!("secret write: {e}"));

    let mut attempt = 0;
    let (tmp, mut file) = loop {
        // Hidden, so never a secret's file name (no name maps to a leading `.`). Random, not
        // a pid: unique across processes, and `process::id` panics on WASI.
        let tmp = dir.join(format!(".tmp-{:016x}", rand_core::OsRng.next_u64()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, modes::FILE);
        match options.open(&tmp) {
            Ok(file) => break (tmp, file),
            // A collision (vanishingly unlikely, but cheap to survive): draw another name.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                attempt += 1;
            }
            Err(e) => return Err(fail(e)),
        }
    };
    let written = (|| {
        modes::set_file(&file, modes::FILE)?;
        file.write_all(value)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, target)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(fail(e));
    }
    // The rename's own durability, best-effort: not every platform can open a directory.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

impl Backend for FileBackend {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        let (dir, file) = self.locate(name)?;
        if !check_dir(dir)? {
            return Ok(None);
        }
        let path = dir.join(&file);
        let mut handle = match std::fs::File::open(&path) {
            Ok(handle) => handle,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Endpoint(format!("secret read: {e}"))),
        };
        if !exact_entry(dir, &file)? {
            return Err(ambiguous(dir, &file));
        }
        // On the handle, not the path: what is judged is exactly what is then read.
        let meta = handle
            .metadata()
            .map_err(|e| Error::Endpoint(format!("secret read: {e}")))?;
        modes::guard(&path, &meta, modes::FILE, |mode| {
            handle.set_permissions(mode)
        })?;
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Endpoint(format!("secret read: {e}")))?;
        Ok(Some(bytes))
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        let (dir, file) = self.locate(name)?;
        ensure_dir(dir)?;
        let target = dir.join(&file);
        if target.symlink_metadata().is_ok() && !exact_entry(dir, &file)? {
            return Err(ambiguous(dir, &file));
        }
        write_atomic(dir, &target, value)
    }

    fn delete(&self, name: &str) -> Result<()> {
        let (dir, file) = self.locate(name)?;
        if !check_dir(dir)? {
            return Ok(());
        }
        let path = dir.join(&file);
        if path.symlink_metadata().is_ok() && !exact_entry(dir, &file)? {
            return Err(ambiguous(dir, &file));
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Endpoint(format!("secret delete: {e}"))),
        }
    }

    fn exists(&self, name: &str) -> Result<bool> {
        let (dir, file) = self.locate(name)?;
        if !check_dir(dir)? {
            return Ok(false);
        }
        match dir.join(&file).symlink_metadata() {
            Ok(_) if exact_entry(dir, &file)? => Ok(true),
            Ok(_) => Err(ambiguous(dir, &file)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Endpoint(format!("secret lookup: {e}"))),
        }
    }

    /// Atomic: [`set`](Backend::set) already renames a whole file over the old one, so a
    /// replace never deletes first and a failure keeps the previous secret.
    fn replace(&self, name: &str, value: &[u8]) -> Result<()> {
        self.set(name, value)
    }
}

/// Who may read or write the file store, judged by owner and mode. Unix only: elsewhere there
/// are no mode bits to judge, and the platform's ACLs govern, as they did before.
pub(crate) mod modes {
    use ikigai_core::Result;
    use std::path::Path;

    /// The store directory's mode.
    pub const DIR: u32 = 0o700;
    /// Every secret file's mode.
    pub const FILE: u32 = 0o600;

    /// What an entry's owner and mode allow.
    #[derive(Debug, PartialEq, Eq)]
    #[cfg_attr(not(unix), allow(dead_code))] // judged only where there are mode bits
    pub enum Exposure {
        /// Owner-only, owned by this process's user.
        Private,
        /// Others can read (or traverse) it but not write it: tightened, and logged once
        /// (it is private afterwards). Refusing would take the store down while protecting
        /// nothing already disclosed; tightening stops further disclosure.
        Tighten,
        /// Someone else could have written it, so its contents (a key, a recipient) are not
        /// trusted; tightening now would trust whatever they wrote. A person checks it.
        Refuse(String),
    }

    /// Judge `mode` on an entry owned by uid `owner`, read by a process running as uid `me`.
    /// Pure, so every branch is testable, the foreign-owner one included.
    #[cfg_attr(not(unix), allow(dead_code))] // judged only where there are mode bits
    pub fn judge(mode: u32, owner: u32, me: u32) -> Exposure {
        if owner != me {
            return Exposure::Refuse(format!(
                "is owned by uid {owner}, not by this process's uid {me}"
            ));
        }
        if mode & 0o022 != 0 {
            return Exposure::Refuse(format!(
                "is writable by its group or by everyone (mode {:04o})",
                mode & 0o7777
            ));
        }
        if mode & 0o077 != 0 {
            return Exposure::Tighten;
        }
        Exposure::Private
    }

    /// Refuse an entry someone else could have written; tighten one others can only read,
    /// through `chmod` (the path for a directory, the open handle for a file).
    #[cfg(unix)]
    pub fn guard(
        path: &Path,
        meta: &std::fs::Metadata,
        private: u32,
        chmod: impl FnOnce(std::fs::Permissions) -> std::io::Result<()>,
    ) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot fail.
        let me = unsafe { libc::geteuid() };
        let mode = meta.mode() & 0o7777;
        match judge(mode, meta.uid(), me) {
            Exposure::Private => Ok(()),
            Exposure::Tighten => {
                chmod(std::fs::Permissions::from_mode(private)).map_err(|e| {
                    ikigai_core::Error::Endpoint(format!(
                        "{} is readable by others (mode {mode:04o}) and could not be tightened \
                         to {private:04o}: {e}",
                        path.display()
                    ))
                })?;
                // Logged once: the entry is private from here on, so the next check is silent.
                eprintln!(
                    "ikigai-secret: {} was readable by others (mode {mode:04o}); tightened it \
                     to {private:04o}. Anything in it may already have been read.",
                    path.display()
                );
                Ok(())
            }
            Exposure::Refuse(why) => Err(ikigai_core::Error::Endpoint(format!(
                "refusing the secrets store entry {} : it {why}, so its contents are not \
                 trusted; check them at the box, then fix it with `chmod {private:o}` (and \
                 `chown` if it is not yours)",
                path.display()
            ))),
        }
    }

    #[cfg(not(unix))]
    pub fn guard(
        _path: &Path,
        _meta: &std::fs::Metadata,
        _private: u32,
        _chmod: impl FnOnce(std::fs::Permissions) -> std::io::Result<()>,
    ) -> Result<()> {
        Ok(())
    }

    /// Set a path's mode outright (Unix; elsewhere nothing to set).
    pub fn set(path: &Path, mode: u32) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Ok(())
        }
    }

    /// Set an open file's mode outright (Unix; elsewhere nothing to set).
    pub fn set_file(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
        }
        #[cfg(not(unix))]
        {
            let _ = (file, mode);
            Ok(())
        }
    }
}
