//! The `age-file` store (ledger #4488, `docs/storage-backends.md` section 6.3): the file store,
//! with each item encrypted at rest to the store's age recipients.
//!
//! The layout, the modes, the atomic writes and the regular-file-only reads are the file store's,
//! unchanged: [`AgeFileBackend`] wraps a [`FileBackend`] and hands it ciphertext. Each item is a
//! whole binary age file, so the stock `age` command opens one at the box with the store's
//! identity (`age -d -i <identity> <file>`), which is the recovery path when nothing else runs.
//!
//! **The identity is the host's.** Building an age identity may read a file or run an age plugin
//! (`age-plugin-se`, `age-plugin-yubikey`, `age-plugin-tpm`), and only a host-role crate may do
//! either (Hypothesis H). So this crate never resolves one: the host reads the store's
//! `identity = "…"` (`StoreKind::AgeFile`), builds an [`AgeKeys`] and hands it over through
//! [`SecretConfig::build_with_keys`](crate::SecretConfig::build_with_keys) or
//! [`AgeFileBackend::new`]. [`X25519Keys`] is the one this crate builds, from identity TEXT the
//! host already read (`AGE-SECRET-KEY-1…` lines), sealing through `ikigai_encrypt::age`, the
//! ecosystem's one implementation of age. A host holding a plugin identity implements
//! [`AgeKeys`] itself.
//!
//! **Mixed stores.** A store moved in place from `file` holds plaintext items from before. A read
//! serves a plaintext item as the file store always did, and a write always encrypts, so each
//! item is re-encrypted on its next write; [`Backend::reencrypt`] does all of them at once. An
//! item is ciphertext exactly when it begins with age's header line, [`AGE_HEADER`].

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_core::{Error, Result};
use ikigai_encrypt::age as sealed;

use crate::file::{self, Item};
use crate::{Backend, FileBackend};

/// The first line of every binary age file, and so of every item an `age-file` store writes. An
/// item that does not begin with it is a plaintext item from before the store was encrypted.
pub const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

/// What the `age-file` store's `identity` names when a host with no `[secret]` section makes the
/// store for a new install: the host's own default identity source. Which source that is on each
/// machine (the Secure Enclave, a TPM, a file only the service can read) is the host's to decide
/// (`docs/unattended-unlock.md`, section 4); this crate only carries the word.
pub const HOST_DEFAULT_IDENTITY: &str = "default";

/// Why an [`AgeKeys`] could not seal or open. No variant carries a key or a plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgeError {
    /// The bytes are a whole age file, and none of these identities opens it.
    NoMatchingKey,
    /// The bytes are not a whole, unaltered age file (cut short, altered, or not age at all).
    Corrupt,
    /// Anything else, as one sentence that names no key and no plaintext.
    Failed(String),
}

impl fmt::Display for AgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgeError::NoMatchingKey => {
                f.write_str("it is an age file sealed to no identity this store holds")
            }
            AgeError::Corrupt => {
                f.write_str("it is not a whole age file: it was cut short or altered")
            }
            AgeError::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for AgeError {}

/// The keys an `age-file` store seals and opens its items with, built by the host from the
/// store's `identity` and `recipients`.
///
/// [`seal`](AgeKeys::seal) encrypts to EVERY recipient the store's items are for: the identity's
/// own and each configured one (a recovery key kept off the machine, `docs/unattended-unlock.md`
/// rule 1), so any one of them opens every item. [`open`](AgeKeys::open) decrypts with the
/// identity. Neither is ever handed a name, and neither may log, cache or echo what it is given.
pub trait AgeKeys: Send + Sync {
    /// Seal `plaintext` to every recipient of the store, as a binary age file.
    fn seal(&self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, AgeError>;
    /// Open a binary age file sealed to one of the store's identities.
    fn open(&self, ciphertext: &[u8]) -> std::result::Result<Vec<u8>, AgeError>;
}

/// X25519 age keys: identities read from text, sealing to their own recipients and to the
/// configured X25519 recipients, through `ikigai_encrypt::age`.
///
/// ```
/// use ikigai_secret::{AgeKeys, X25519Keys};
/// use ikigai_encrypt::age::{ExposeSecret, Identity};
///
/// let host = Identity::generate();
/// let recovery = Identity::generate();
/// let text = format!("# this host\n{}\n", host.to_string().expose_secret());
/// let keys = X25519Keys::new(&text, &[recovery.to_public().to_string()]).unwrap();
///
/// let sealed = keys.seal(b"hunter2").unwrap();
/// assert!(sealed.starts_with(ikigai_secret::AGE_HEADER));
/// assert_eq!(keys.open(&sealed).unwrap(), b"hunter2");
/// // The recovery identity opens it too, which is what it is for.
/// let recovery_text = recovery.to_string().expose_secret().to_string();
/// let recovery_only = X25519Keys::new(&recovery_text, &[]).unwrap();
/// assert_eq!(recovery_only.open(&sealed).unwrap(), b"hunter2");
/// ```
pub struct X25519Keys {
    identities: Vec<sealed::Identity>,
    recipients: Vec<sealed::Recipient>,
}

impl fmt::Debug for X25519Keys {
    /// Counts only: never a key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Keys")
            .field("identities", &self.identities.len())
            .field("recipients", &self.recipients.len())
            .finish()
    }
}

impl X25519Keys {
    /// Keys from `identity_text` (one `AGE-SECRET-KEY-1…` per line; blank lines and `#` comments
    /// allowed, as age's own identity files are) and the store's configured `recipients`. Items
    /// are sealed to each identity's own recipient and to every configured one.
    ///
    /// Refused, naming the line or the entry and never echoing a key: identity text with no
    /// identity or a line that is not one, and a recipient that is not an X25519 age recipient.
    /// A plugin recipient (`age1yubikey1…`, `age1se1…`) is refused here because sealing to one
    /// runs its plugin, which only a host may do; such a host implements [`AgeKeys`] itself.
    pub fn new(identity_text: &str, recipients: &[String]) -> Result<Self> {
        let identities =
            sealed::parse_identities(identity_text).map_err(|e| Error::InvalidArgument {
                name: "identity".into(),
                detail: match e {
                    sealed::Error::NoKeys => {
                        "the identity text holds no age identity (only blank lines and comments)"
                            .to_string()
                    }
                    other => format!("the identity text is not an age identity: {other}"),
                },
            })?;
        let mut sealed_to: Vec<sealed::Recipient> = identities
            .iter()
            .map(|identity| identity.to_public())
            .collect();
        for (index, recipient) in recipients.iter().enumerate() {
            let entry = index + 1;
            match recipient_kind(recipient) {
                Ok(RecipientKind::X25519(parsed)) => sealed_to.push(parsed),
                Ok(RecipientKind::Plugin(plugin)) => {
                    return Err(Error::InvalidArgument {
                        name: "recipients".into(),
                        detail: format!(
                            "entry {entry} of `recipients` is an age-plugin-{plugin} recipient, \
                             and sealing to it runs that plugin, which only the host may do; \
                             these keys seal to X25519 recipients only"
                        ),
                    })
                }
                Err(why) => {
                    return Err(Error::InvalidArgument {
                        name: "recipients".into(),
                        detail: format!("entry {entry} of `recipients` {why}"),
                    })
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        sealed_to.retain(|recipient| seen.insert(recipient.to_string()));
        Ok(X25519Keys {
            identities,
            recipients: sealed_to,
        })
    }
}

impl AgeKeys for X25519Keys {
    fn seal(&self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, AgeError> {
        sealed::seal(plaintext, &self.recipients)
            .map_err(|e| AgeError::Failed(format!("age could not seal it ({})", seal_words(&e))))
    }

    fn open(&self, ciphertext: &[u8]) -> std::result::Result<Vec<u8>, AgeError> {
        sealed::open(ciphertext, &self.identities).map_err(|e| match e {
            sealed::Error::NoMatchingKey => AgeError::NoMatchingKey,
            e if e.is_corrupt() => AgeError::Corrupt,
            sealed::Error::Panicked => {
                AgeError::Failed("age failed while opening it, and produced nothing".into())
            }
            other => AgeError::Failed(format!("age could not open it ({other})")),
        })
    }
}

/// A seal failure in words. `ikigai_encrypt::age::Error` names no key or plaintext.
fn seal_words(e: &sealed::Error) -> String {
    match e {
        sealed::Error::Panicked => "age failed and produced nothing".to_string(),
        other => other.to_string(),
    }
}

/// What a configured recipient is.
pub(crate) enum RecipientKind {
    /// An X25519 recipient (`age1…`), parsed and checked (never a low-order point).
    X25519(sealed::Recipient),
    /// A plugin recipient (`age1<plugin>1…`), named by its plugin.
    Plugin(String),
}

/// Classify one configured recipient, or say in a clause why it is not one (to follow "entry N
/// of `recipients`"). An age recipient is Bech32: its human-readable part is everything before
/// the LAST `1`, which is `age` for X25519 and `age1<plugin>` for a plugin's recipient.
pub(crate) fn recipient_kind(recipient: &str) -> std::result::Result<RecipientKind, String> {
    let not_one = || {
        "is not an age recipient: a recipient begins with `age1`, as `age-keygen` and the age \
         plugins print them"
            .to_string()
    };
    if !recipient.starts_with("age1") || recipient.chars().any(char::is_whitespace) {
        return Err(not_one());
    }
    let separator = recipient.rfind('1').ok_or_else(not_one)?;
    let readable = &recipient[..separator];
    if readable == "age" {
        return match sealed::parse_recipients(recipient) {
            Ok(mut parsed) if parsed.len() == 1 => Ok(RecipientKind::X25519(parsed.remove(0))),
            Ok(_) => Err(not_one()),
            Err(sealed::Error::LowOrder { .. }) => {
                Err("is a low-order X25519 point, which anyone could open a file sealed to".into())
            }
            Err(_) => Err(
                "is not a valid X25519 age recipient (its checksum or length is \
                           wrong)"
                    .into(),
            ),
        };
    }
    match readable.strip_prefix("age1") {
        Some(plugin)
            if !plugin.is_empty()
                && plugin
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c)) =>
        {
            Ok(RecipientKind::Plugin(plugin.to_string()))
        }
        _ => Err(not_one()),
    }
}

/// The age-file backend: [`FileBackend`]'s directory, layout and guarantees, with every item
/// sealed by the store's [`AgeKeys`] on its way to the disk and opened on its way back.
///
/// - `get` opens an item that begins with [`AGE_HEADER`] and serves any other item as the
///   plaintext a file store wrote before; an age file it cannot open is refused with a sentence,
///   never handed back as if it were the secret.
/// - `set`, `replace` and `create` seal first, then write exactly as the file store does (a
///   temporary file renamed over the name, or hard-linked to a free one), and leave the store's
///   marker in the directory, so a host with no `[secret]` section knows it for an age-file store.
/// - `exists` and `delete` are the file store's: neither needs the keys' secret half.
pub struct AgeFileBackend {
    files: FileBackend,
    keys: std::result::Result<Arc<dyn AgeKeys>, String>,
}

impl AgeFileBackend {
    /// An age-file store in `dir`, sealing and opening with `keys`.
    pub fn new(dir: impl Into<PathBuf>, keys: Arc<dyn AgeKeys>) -> Self {
        AgeFileBackend {
            files: FileBackend::new(dir),
            keys: Ok(keys),
        }
    }

    /// An age-file store the host gave no keys: every operation refuses with `why`.
    pub(crate) fn without_keys(dir: impl Into<PathBuf>, why: String) -> Self {
        AgeFileBackend {
            files: FileBackend::new(dir),
            keys: Err(why),
        }
    }

    fn keys(&self) -> Result<&Arc<dyn AgeKeys>> {
        self.keys
            .as_ref()
            .map_err(|why| Error::Endpoint(why.clone()))
    }

    fn dir(&self) -> Result<&Path> {
        self.files.dir()
    }

    fn seal(&self, name: &str, value: &[u8]) -> Result<Vec<u8>> {
        self.keys()?.seal(value).map_err(|e| {
            Error::Endpoint(format!(
                "the secret `{name}` was not stored: {e}; nothing was written"
            ))
        })
    }

    /// The plaintext of an item's stored bytes.
    fn plaintext(&self, name: &str, stored: Vec<u8>) -> Result<Vec<u8>> {
        if !stored.starts_with(AGE_HEADER) {
            return Ok(stored);
        }
        self.keys()?.open(&stored).map_err(|e| {
            Error::Endpoint(format!(
                "the secret `{name}` cannot be read: {e}. It is left as it is; inspect it at the \
                 box with `age -d -i <identity>`"
            ))
        })
    }
}

impl Backend for AgeFileBackend {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.keys()?;
        match self.files.get(name)? {
            Some(stored) => self.plaintext(name, stored).map(Some),
            None => Ok(None),
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        // The name is judged (and refused) before anything is sealed or made.
        file::file_name(name)?;
        let sealed = self.seal(name, value)?;
        file::mark_age_file(self.dir()?)?;
        self.files.set(name, &sealed)
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.keys()?;
        self.files.delete(name)
    }

    fn exists(&self, name: &str) -> Result<bool> {
        self.keys()?;
        self.files.exists(name)
    }

    /// Atomic, as the file store's: the sealed item is renamed over the old one.
    fn replace(&self, name: &str, value: &[u8]) -> Result<()> {
        self.set(name, value)
    }

    /// Atomic, as the file store's: the sealed item is hard-linked to a free name.
    fn create(&self, name: &str, value: &[u8]) -> Result<bool> {
        file::file_name(name)?;
        let sealed = self.seal(name, value)?;
        file::mark_age_file(self.dir()?)?;
        self.files.create(name, &sealed)
    }

    fn health(&self) -> String {
        match &self.keys {
            Err(_) => "unavailable: the host was not given this store's age identity".to_string(),
            Ok(_) => self.files.health(),
        }
    }

    fn reencrypt(&self, may_write: &dyn Fn(&str) -> bool) -> Result<Reencrypted> {
        let keys = self.keys()?;
        reencrypt_dir(self.dir()?, keys.as_ref(), may_write)
    }
}

/// What one item of a reencrypt came to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Encrypted,
    Already,
    ForeignKey,
    Corrupt,
    Changed,
    Failed(String),
}

/// What a reencrypt did: an optional backup, then one line per item it looked at, in file-name
/// order. Only items the caller may write are looked at, so nothing here names another.
/// [`Display`](fmt::Display) renders the whole answer: the backup line, the item lines and a
/// summary, one sentence each.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reencrypted {
    /// The backup copy of the directory, made before the first item was converted. `None` when
    /// nothing needed converting, so a second run makes no backup and changes nothing.
    pub backup: Option<PathBuf>,
    /// One sentence per item looked at.
    pub lines: Vec<String>,
    /// Items encrypted by this run.
    pub encrypted: usize,
    /// Items that were already encrypted, opened by this store's identity, and left unchanged.
    pub already: usize,
    /// Items left as they are because they could not be converted or read: an age file sealed to
    /// another identity, one that is not whole, one that changed while it was converted, or a
    /// failure. Each has its line; the operation is refused when any is non-zero.
    pub left: usize,
}

impl Reencrypted {
    /// Whether every item looked at is now encrypted to this store's keys.
    pub fn complete(&self) -> bool {
        self.left == 0
    }
}

impl fmt::Display for Reencrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(backup) = &self.backup {
            writeln!(
                f,
                "Backed up the store to {} before converting it; remove that copy once you have \
                 checked the store, since it holds the plaintext.",
                backup.display()
            )?;
        }
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        let items = |n: usize| if n == 1 { "item" } else { "items" };
        write!(
            f,
            "Encrypted {} {}; {} already encrypted; {} left as {}. Only items this capability may \
             write were looked at.",
            self.encrypted,
            items(self.encrypted),
            self.already,
            self.left,
            if self.left == 1 {
                "it was"
            } else {
                "they were"
            }
        )?;
        if self.left > 0 {
            write!(
                f,
                " Fix what the lines above name and run reencrypt again: every item already \
                 encrypted stays encrypted."
            )?;
        }
        Ok(())
    }
}

/// One item after the first pass: its outcome so far, and its plaintext and the stamp of the
/// file it was read from when it is still to be converted.
type Judged = (Item, Outcome, Option<(Vec<u8>, file::Stamp)>);

/// Encrypt, one at a time, every plaintext item in `dir` that `may_write` allows, after a backup
/// copy of the directory. Idempotent: an item already sealed to these keys is left unchanged, and
/// a run with nothing to convert makes no backup. Each item is a temporary file renamed over the
/// old one, so a crash at any point leaves every item readable, as plaintext or as ciphertext.
fn reencrypt_dir(
    dir: &Path,
    keys: &dyn AgeKeys,
    may_write: &dyn Fn(&str) -> bool,
) -> Result<Reencrypted> {
    let mut report = Reencrypted {
        backup: None,
        lines: Vec::new(),
        encrypted: 0,
        already: 0,
        left: 0,
    };
    if file::dir_state(dir)? == file::DirState::Empty {
        return Ok(report);
    }
    // First pass: judge every item the caller may write, reading it once.
    let mut judged: Vec<Judged> = Vec::new();
    for item in file::items(dir)? {
        if !may_write(&item.name) {
            continue;
        }
        match file::read_item(dir, &item.file) {
            Ok(None) => continue, // removed meanwhile: nothing to convert
            Ok(Some((bytes, stamp))) => {
                if bytes.starts_with(AGE_HEADER) {
                    let outcome = match keys.open(&bytes) {
                        Ok(_) => Outcome::Already,
                        Err(AgeError::NoMatchingKey) => Outcome::ForeignKey,
                        Err(AgeError::Corrupt) => Outcome::Corrupt,
                        Err(AgeError::Failed(why)) => Outcome::Failed(why),
                    };
                    judged.push((item, outcome, None));
                } else {
                    judged.push((item, Outcome::Encrypted, Some((bytes, stamp))));
                }
            }
            Err(e) => {
                let why = message(e);
                judged.push((
                    item,
                    Outcome::Failed(format!("it could not be read: {why}")),
                    None,
                ));
            }
        }
    }
    // A backup before the first conversion, and only when there is one to make.
    if judged.iter().any(|(_, _, plain)| plain.is_some()) {
        report.backup = Some(file::backup(dir)?);
        file::mark_age_file(dir)?;
    }
    for (item, outcome, plain) in judged {
        let outcome = match plain {
            None => outcome,
            Some((bytes, stamp)) => match keys.seal(&bytes) {
                Err(e) => Outcome::Failed(format!("it could not be sealed: {e}")),
                Ok(sealed) => match file::replace_if_unchanged(dir, &item.file, &stamp, &sealed) {
                    Ok(true) => Outcome::Encrypted,
                    Ok(false) => Outcome::Changed,
                    Err(e) => Outcome::Failed(format!("it could not be written: {}", message(e))),
                },
            },
        };
        let name = &item.name;
        let line = match &outcome {
            Outcome::Encrypted => {
                report.encrypted += 1;
                format!("{name}: encrypted.")
            }
            Outcome::Already => {
                report.already += 1;
                format!("{name}: already encrypted, unchanged.")
            }
            Outcome::ForeignKey => {
                report.left += 1;
                format!(
                    "{name}: left as it is, because it is an age file sealed to no identity this \
                     store holds."
                )
            }
            Outcome::Corrupt => {
                report.left += 1;
                format!(
                    "{name}: left as it is, because it begins as an age file and is not a whole \
                     one."
                )
            }
            Outcome::Changed => {
                report.left += 1;
                format!(
                    "{name}: left as it is, because it was written while it was being converted; \
                     run reencrypt again."
                )
            }
            Outcome::Failed(why) => {
                report.left += 1;
                format!("{name}: left as it is, because {why}.")
            }
        };
        report.lines.push(line);
    }
    Ok(report)
}

/// An error's sentence without a variant's prefix.
pub(crate) fn message(e: Error) -> String {
    match e {
        Error::Endpoint(why) | Error::Conflict(why) | Error::NotFound(why) => why,
        other => other.to_string(),
    }
}
