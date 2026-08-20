//! Where subject keys live, and the rules that keep erasure honest.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use yaam_contract::SubjectHash;
use zeroize::Zeroize;

use crate::error::Error;
use crate::seal::Epoch;

/// Length of a subject key encryption key.
const KEK_LEN: usize = 32;

/// Custody of per-subject, per-epoch keys.
///
/// Implementations must keep key material out of every backup path. A wrapped key surviving in a
/// snapshot means destroying the live copy erases nothing while verification still passes — the
/// failure this whole design exists to avoid.
pub trait KeyStore {
    /// Fetches a subject's key for an epoch, if it exists.
    fn get(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<Option<Vec<u8>>>;

    /// Mints a key, refusing if the subject is tombstoned.
    ///
    /// Keys are minted lazily, so this refusal is what stops a late-arriving record from
    /// re-creating a key for someone already erased.
    fn mint(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<Vec<u8>>;

    /// Destroys every key for a subject, across all epochs.
    fn destroy_subject(&self, subject: &SubjectHash) -> crate::Result<()>;

    /// Destroys one epoch's key for a subject, for retention.
    fn destroy_epoch(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<()>;

    /// Whether a subject is tombstoned and may never hold keys again.
    fn is_tombstoned(&self, subject: &SubjectHash) -> crate::Result<bool>;

    /// Records a subject as erased. Append-only; never reversed.
    fn tombstone(&self, subject: &SubjectHash) -> crate::Result<()>;
}

thread_local! {
    /// A stack rather than a slot, so nesting restores the outer store instead of clearing it.
    static AMBIENT: RefCell<Vec<Arc<dyn KeyStore>>> = const { RefCell::new(Vec::new()) };
}

/// Restores the previous ambient store even if `f` panics.
struct AmbientGuard;

impl Drop for AmbientGuard {
    fn drop(&mut self) {
        AMBIENT.with_borrow_mut(Vec::pop);
    }
}

/// Runs `f` with `store` as the ambient key store for this thread.
///
/// [`crate::seal::seal`] and [`crate::seal::unseal`] take no store argument, and a sealing that
/// skipped wrapping would emit a block anyone could read — so they read the store from here and
/// fail with [`Error::NoKeyStore`] when none is installed. Callers that can pass a store should use
/// [`crate::seal::seal_in`] instead.
pub fn with_store<R>(store: Arc<dyn KeyStore>, f: impl FnOnce() -> R) -> R {
    AMBIENT.with_borrow_mut(|stack| stack.push(store));
    let _guard = AmbientGuard;
    f()
}

/// The innermost installed store, if any.
pub(crate) fn ambient() -> Option<Arc<dyn KeyStore>> {
    AMBIENT.with_borrow(|stack| stack.last().cloned())
}

/// Filesystem key store.
///
/// Layout under the root: `keys/<subject>/<epoch>` holds one raw key, `tombstones/<subject>` marks a
/// subject erased. Both trees are `0700`, every file `0600`, and a key file is written with
/// `create_new` so a replayed mint can never overwrite the key an existing record depends on.
#[derive(Debug)]
pub struct FsKeyStore {
    root: PathBuf,
}

impl FsKeyStore {
    /// Opens a key store rooted at `root`, creating it if absent.
    pub fn open(root: impl Into<PathBuf>) -> crate::Result<Self> {
        let root = root.into();
        for dir in [&root, &root.join("keys"), &root.join("tombstones")] {
            create_private_dir(dir)?;
        }
        Ok(Self { root })
    }

    /// Path of a subject's key directory, rejecting anything that could escape the root.
    fn subject_dir(&self, subject: &SubjectHash) -> crate::Result<PathBuf> {
        Ok(self
            .root
            .join("keys")
            .join(safe_component(subject.as_str())?))
    }

    /// Path of one epoch's key file.
    fn key_path(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<PathBuf> {
        Ok(self
            .subject_dir(subject)?
            .join(safe_component(epoch.as_str())?))
    }

    /// Path of a subject's tombstone marker.
    fn tombstone_path(&self, subject: &SubjectHash) -> crate::Result<PathBuf> {
        Ok(self
            .root
            .join("tombstones")
            .join(safe_component(subject.as_str())?))
    }
}

impl KeyStore for FsKeyStore {
    fn get(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<Option<Vec<u8>>> {
        // A tombstoned subject reports no key even if a file lingers: erasure must not depend on
        // the unlink having completed.
        if self.is_tombstoned(subject)? {
            return Ok(None);
        }
        match fs::read(self.key_path(subject, epoch)?) {
            Ok(bytes) if bytes.len() == KEK_LEN => Ok(Some(bytes)),
            Ok(bytes) => Err(Error::MalformedBlock(format!(
                "subject key for `{}` is {} bytes",
                subject.as_str(),
                bytes.len()
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn mint(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<Vec<u8>> {
        if self.is_tombstoned(subject)? {
            return Err(Error::Tombstoned(subject.as_str().to_owned()));
        }
        if let Some(existing) = self.get(subject, epoch)? {
            return Ok(existing);
        }

        let dir = self.subject_dir(subject)?;
        create_private_dir(&dir)?;
        let mut key = vec![0u8; KEK_LEN];
        crate::seal::fill_random(&mut key);
        match write_private_new(&self.key_path(subject, epoch)?, &key) {
            Ok(()) => Ok(key),
            // Lost a race with a concurrent mint: the winner's key is the one records were sealed
            // under, so adopt it and discard ours.
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                key.zeroize();
                self.get(subject, epoch)?.ok_or_else(|| {
                    Error::KeyAbsent(subject.as_str().to_owned(), epoch.as_str().to_owned())
                })
            }
            Err(e) => {
                key.zeroize();
                Err(e)
            }
        }
    }

    fn destroy_subject(&self, subject: &SubjectHash) -> crate::Result<()> {
        remove_if_present(&self.subject_dir(subject)?, true)
    }

    fn destroy_epoch(&self, subject: &SubjectHash, epoch: &Epoch) -> crate::Result<()> {
        remove_if_present(&self.key_path(subject, epoch)?, false)
    }

    fn is_tombstoned(&self, subject: &SubjectHash) -> crate::Result<bool> {
        Ok(self.tombstone_path(subject)?.exists())
    }

    fn tombstone(&self, subject: &SubjectHash) -> crate::Result<()> {
        let path = self.tombstone_path(subject)?;
        match write_private_new(&path, b"") {
            // Already tombstoned. Append-only means a repeat is a no-op, never an overwrite.
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
}

/// Rejects a path component that could climb out of the store root.
///
/// Subject hashes and epoch labels are already constrained, but this is the last line before a
/// filesystem call, and a store that can be aimed elsewhere is not a store.
fn safe_component(value: &str) -> crate::Result<&str> {
    if value.is_empty() || value.contains(['/', '\\', '\0']) || value.contains("..") {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe key store path component `{value}`"),
        )));
    }
    Ok(value)
}

/// Creates a directory only the owner can traverse, if it does not exist.
fn create_private_dir(path: &Path) -> crate::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    // `recursive` leaves an existing directory's mode alone, which would silently keep a
    // world-readable store world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes a new owner-only file, failing if it already exists, and fsyncs before returning.
///
/// The fsync is not decoration: a key that reaches no platter while the record that needs it does
/// is an unreadable body after a crash.
fn write_private_new(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    use std::io::Write;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Removes a file or directory tree, treating absence as success.
///
/// Destruction is replayed by the erasure sweeper, so it has to be idempotent.
fn remove_if_present(path: &Path, tree: bool) -> crate::Result<()> {
    let outcome = if tree {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match outcome {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::block::parse_subject;

    fn subject(n: u8) -> SubjectHash {
        parse_subject(&format!("s_{:064x}", u32::from(n) + 1)).unwrap()
    }

    fn epoch() -> Epoch {
        Epoch::containing(1_770_000_000_000)
    }

    fn store() -> (TempDir, FsKeyStore) {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn minting_is_idempotent() {
        let (_dir, store) = store();
        let subject = subject(0);

        assert!(store.get(&subject, &epoch()).unwrap().is_none());
        let first = store.mint(&subject, &epoch()).unwrap();
        assert_eq!(first.len(), KEK_LEN);
        // A replayed mint must return the key existing records were sealed under, never a new one.
        assert_eq!(store.mint(&subject, &epoch()).unwrap(), first);
        assert_eq!(store.get(&subject, &epoch()).unwrap().unwrap(), first);
    }

    #[test]
    fn keys_differ_per_subject_and_epoch() {
        let (_dir, store) = store();
        let one = store.mint(&subject(0), &epoch()).unwrap();
        let other_subject = store.mint(&subject(1), &epoch()).unwrap();
        let other_epoch = store
            .mint(&subject(0), &Epoch::containing(1_700_000_000_000))
            .unwrap();

        assert_ne!(one, other_subject);
        assert_ne!(one, other_epoch);
    }

    #[test]
    fn minting_refuses_a_tombstoned_subject() {
        let (_dir, store) = store();
        let subject = subject(0);

        store.tombstone(&subject).unwrap();
        assert!(store.is_tombstoned(&subject).unwrap());
        assert!(matches!(
            store.mint(&subject, &epoch()),
            Err(Error::Tombstoned(_))
        ));
        // Even a key minted earlier stops being reachable, so a lingering file cannot un-erase.
        assert!(store.get(&subject, &epoch()).unwrap().is_none());
    }

    #[test]
    fn tombstoning_is_append_only() {
        let (_dir, store) = store();
        let subject = subject(0);
        store.mint(&subject, &epoch()).unwrap();

        store.tombstone(&subject).unwrap();
        store.tombstone(&subject).unwrap();
        assert!(store.is_tombstoned(&subject).unwrap());
    }

    #[test]
    fn destruction_is_idempotent() {
        let (_dir, store) = store();
        let subject = subject(0);
        store.mint(&subject, &epoch()).unwrap();

        store.destroy_epoch(&subject, &epoch()).unwrap();
        store.destroy_epoch(&subject, &epoch()).unwrap();
        assert!(store.get(&subject, &epoch()).unwrap().is_none());

        store.destroy_subject(&subject).unwrap();
        store.destroy_subject(&subject).unwrap();
        assert!(!store.is_tombstoned(&subject).unwrap());
    }

    #[test]
    fn destroying_a_subject_takes_every_epoch() {
        let (_dir, store) = store();
        let subject = subject(0);
        let old = Epoch::containing(1_600_000_000_000);
        store.mint(&subject, &epoch()).unwrap();
        store.mint(&subject, &old).unwrap();

        store.destroy_subject(&subject).unwrap();

        assert!(store.get(&subject, &epoch()).unwrap().is_none());
        assert!(store.get(&subject, &old).unwrap().is_none());
    }

    #[test]
    fn reopening_an_existing_store_keeps_its_keys() {
        let dir = TempDir::new().unwrap();
        let key = FsKeyStore::open(dir.path())
            .unwrap()
            .mint(&subject(0), &epoch())
            .unwrap();

        let reopened = FsKeyStore::open(dir.path()).unwrap();
        assert_eq!(reopened.get(&subject(0), &epoch()).unwrap().unwrap(), key);
    }

    #[test]
    fn a_truncated_key_file_is_an_error_not_a_weak_key() {
        let (_dir, store) = store();
        let subject = subject(0);
        store.mint(&subject, &epoch()).unwrap();
        fs::write(store.key_path(&subject, &epoch()).unwrap(), [0u8; 8]).unwrap();

        assert!(matches!(
            store.get(&subject, &epoch()),
            Err(Error::MalformedBlock(_))
        ));
    }

    #[test]
    fn path_components_cannot_escape_the_root() {
        assert!(safe_component("2026-Q3").is_ok());
        for bad in ["", "..", "../etc", "a/b", "a\\b", "a\0b"] {
            assert!(safe_component(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = store();
        let subject = subject(0);
        store.mint(&subject, &epoch()).unwrap();

        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.path().to_path_buf()), 0o700);
        assert_eq!(mode(dir.path().join("keys")), 0o700);
        assert_eq!(mode(dir.path().join("tombstones")), 0o700);
        assert_eq!(mode(store.subject_dir(&subject).unwrap()), 0o700);
        assert_eq!(mode(store.key_path(&subject, &epoch()).unwrap()), 0o600);

        store.tombstone(&subject).unwrap();
        assert_eq!(mode(store.tombstone_path(&subject).unwrap()), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_loose_mode_on_an_existing_root_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        FsKeyStore::open(dir.path()).unwrap();

        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_bad_subject_string_never_reaches_the_filesystem() {
        let (_dir, store) = store();
        // Not reachable through `SubjectHash::parse`, but the store is the last line of defence.
        let hostile: SubjectHash = serde_json::from_str("\"../../escape\"").unwrap();
        assert!(store.get(&hostile, &epoch()).is_err());
        assert!(store.mint(&hostile, &epoch()).is_err());
        assert!(store.destroy_subject(&hostile).is_err());
        assert!(store.destroy_epoch(&hostile, &epoch()).is_err());
        assert!(store.tombstone(&hostile).is_err());
        assert!(store.is_tombstoned(&hostile).is_err());
    }
}
