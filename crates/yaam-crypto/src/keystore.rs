//! Where subject keys live, and the rules that keep erasure honest.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

/// Protection for key material at rest.
///
/// [`FsKeyStore`] writes what [`KeyWrapper::wrap`] returns and reads back through
/// [`KeyWrapper::unwrap`]. A deployment points this at whatever holds its master key — a KMS, an
/// HSM, a sealed enclave — so a key file recovered from a snapshot, a stale volume or a decommissioned
/// disk is inert without a call to that service. With no such layer the file *is* the key, and
/// "encrypted at rest" is a claim with no mechanism behind it.
///
/// Not the same wrapping as [`crate::seal`]'s: that wraps a record's shares *under* a subject key and
/// travels inside the sealed body. This wraps the subject key itself and never leaves the key store's
/// disk.
///
/// No client for any key service ships here: the deployment that has the key service is the one that
/// can talk to it, and a stub in this crate would be a dependency for everybody and a working
/// implementation for nobody. [`Passthrough`] is the development stand-in.
pub trait KeyWrapper: Send + Sync {
    /// Wraps key material for storage.
    fn wrap(&self, key: &[u8]) -> crate::Result<Vec<u8>>;

    /// Reverses [`KeyWrapper::wrap`].
    ///
    /// Failure must be an error. Key material this cannot recover is not key material that was
    /// erased, and the store keeps those two apart on the strength of this contract.
    fn unwrap(&self, wrapped: &[u8]) -> crate::Result<Vec<u8>>;

    /// How this wrapper protects key material, for a health report.
    ///
    /// Defaulted so a deployment's own wrapper need not implement it, and never a secret: this
    /// reaches a startup log, which is the most widely copied text a deployment produces.
    fn scheme(&self) -> &'static str {
        "an unnamed wrapper"
    }

    /// Whether this wrapper actually protects key material.
    ///
    /// Separate from [`KeyWrapper::scheme`] so a caller deciding whether to warn asks a predicate
    /// rather than matching on prose. Defaulted to `true`, because a wrapper that protects nothing is
    /// the exception and should have to say so.
    fn protects(&self) -> bool {
        true
    }
}

/// A [`KeyWrapper`] that stores key material exactly as handed to it.
///
/// For development and tests, and nothing else. There is no protection here whatsoever: a key file
/// written under this wrapper is a usable key to anyone who can read the file, which is the state
/// [`KeyWrapper`] exists to get a deployment out of.
#[derive(Debug, Clone, Copy, Default)]
pub struct Passthrough;

impl KeyWrapper for Passthrough {
    fn protects(&self) -> bool {
        false
    }

    fn scheme(&self) -> &'static str {
        "none \u{2014} key material is stored as written (development only)"
    }

    fn wrap(&self, key: &[u8]) -> crate::Result<Vec<u8>> {
        Ok(key.to_vec())
    }

    fn unwrap(&self, wrapped: &[u8]) -> crate::Result<Vec<u8>> {
        Ok(wrapped.to_vec())
    }
}

/// Filesystem key store.
///
/// Layout under the root: `keys/<subject>/<epoch>` holds one key as its [`KeyWrapper`] wrote it,
/// `tombstones/<subject>` marks a subject erased. Both trees are `0700`, every file `0600`, and a key
/// file is written with `create_new` so a replayed mint can never overwrite the key an existing
/// record depends on.
pub struct FsKeyStore {
    root: PathBuf,
    /// Applied on the way to disk and reversed on the way back.
    wrapper: Box<dyn KeyWrapper>,
}

/// Written by hand because the wrapper is a trait object: demanding `Debug` of every deployment's
/// key service client would be a real constraint bought for a derive.
impl std::fmt::Debug for FsKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsKeyStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl FsKeyStore {
    /// Opens a key store rooted at `root`, creating it if absent, wrapping key material with
    /// `wrapper`.
    ///
    /// The wrapper is chosen once, at open. A key already on disk was wrapped by whatever was in
    /// force when it was written, so opening the same root under a different wrapper makes those keys
    /// unreadable rather than migrating them — which is why this seam goes in before real keys exist.
    pub fn new(
        root: impl Into<PathBuf>,
        wrapper: impl KeyWrapper + 'static,
    ) -> crate::Result<Self> {
        let root = root.into();
        for dir in [&root, &root.join("keys"), &root.join("tombstones")] {
            create_private_dir(dir)?;
        }
        Ok(Self {
            root,
            wrapper: Box::new(wrapper),
        })
    }

    /// Opens a key store that writes key material in the clear.
    ///
    /// The name is the point. Unwrapped key storage is right for development and for tests and wrong
    /// everywhere else, so reaching it costs a caller the word `unwrapped` at the call site, where a
    /// reviewer sees it.
    pub fn unwrapped(root: impl Into<PathBuf>) -> crate::Result<Self> {
        Self::new(root, Passthrough)
    }

    /// How key material in this store is protected.
    #[must_use]
    pub fn wrapping(&self) -> &'static str {
        self.wrapper.scheme()
    }

    /// Whether key material in this store is protected at all.
    #[must_use]
    pub fn protects(&self) -> bool {
        self.wrapper.protects()
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
            // A file that will not unwrap is a failure, never an absence. `Ok(None)` here reads as
            // "already erased", and a caller acting on that would report data destroyed when the
            // wrapping key is merely out of reach.
            Ok(stored) => {
                let key = self.wrapper.unwrap(&stored)?;
                if key.len() != KEK_LEN {
                    return Err(Error::MalformedBlock(format!(
                        "subject key for `{}` unwrapped to {} bytes",
                        subject.as_str(),
                        key.len()
                    )));
                }
                Ok(Some(key))
            }
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
        let wrapped = match self.wrapper.wrap(&key) {
            Ok(wrapped) => wrapped,
            // Nothing is written, so a key service that cannot answer leaves the store exactly as it
            // was and the caller free to try again.
            Err(e) => {
                key.zeroize();
                return Err(e);
            }
        };
        match write_private_new(&self.key_path(subject, epoch)?, &wrapped) {
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

    fn subject(n: u8) -> SubjectHash {
        SubjectHash::parse(&format!("s_{:064x}", u32::from(n) + 1)).unwrap()
    }

    fn epoch() -> Epoch {
        Epoch::containing(1_770_000_000_000)
    }

    fn store() -> (TempDir, FsKeyStore) {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::unwrapped(dir.path()).unwrap();
        (dir, store)
    }

    /// A stand-in for a key service: reversible, and refuses material another instance wrote.
    ///
    /// The label is what makes the tests meaningful. A wrapper that merely scrambled bytes would
    /// unwrap anything into garbage, and "wrapped under a key this deployment does not have" is the
    /// case that has to surface as a failure rather than as a plausible-looking key.
    struct Labelled(u8);

    impl KeyWrapper for Labelled {
        fn wrap(&self, key: &[u8]) -> crate::Result<Vec<u8>> {
            let mut out = vec![self.0];
            out.extend(key.iter().map(|byte| byte ^ self.0));
            Ok(out)
        }

        fn unwrap(&self, wrapped: &[u8]) -> crate::Result<Vec<u8>> {
            match wrapped.split_first() {
                Some((label, body)) if *label == self.0 => {
                    Ok(body.iter().map(|byte| byte ^ self.0).collect())
                }
                _ => Err(Error::Authentication),
            }
        }
    }

    /// A wrapper whose unwrap succeeds with the wrong number of bytes.
    struct Lossy;

    impl KeyWrapper for Lossy {
        fn wrap(&self, key: &[u8]) -> crate::Result<Vec<u8>> {
            Ok(key.to_vec())
        }

        fn unwrap(&self, wrapped: &[u8]) -> crate::Result<Vec<u8>> {
            Ok(wrapped[..wrapped.len() / 2].to_vec())
        }
    }

    /// A wrapper that cannot reach its key service.
    struct Offline;

    impl KeyWrapper for Offline {
        fn wrap(&self, _key: &[u8]) -> crate::Result<Vec<u8>> {
            Err(Error::Authentication)
        }

        fn unwrap(&self, _wrapped: &[u8]) -> crate::Result<Vec<u8>> {
            Err(Error::Authentication)
        }
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
        let key = FsKeyStore::unwrapped(dir.path())
            .unwrap()
            .mint(&subject(0), &epoch())
            .unwrap();

        let reopened = FsKeyStore::unwrapped(dir.path()).unwrap();
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
    fn a_wrapped_key_round_trips_and_is_not_on_disk_in_the_clear() {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::new(dir.path(), Labelled(0x5a)).unwrap();
        let subject = subject(0);

        let key = store.mint(&subject, &epoch()).unwrap();
        assert_eq!(key.len(), KEK_LEN);
        assert_eq!(store.get(&subject, &epoch()).unwrap().unwrap(), key);
        assert_eq!(store.mint(&subject, &epoch()).unwrap(), key);

        // The whole point of the seam: the bytes at rest are not the key.
        let stored = fs::read(store.key_path(&subject, &epoch()).unwrap()).unwrap();
        assert_ne!(stored, key);
    }

    #[test]
    fn the_real_wrapper_keeps_a_key_across_reopens_and_refuses_a_wrong_passphrase() {
        // The contract above, proven against the wrapper a deployment actually fits rather than a
        // test double. The double could satisfy it while the real one did not.
        use crate::wrapper::{Cost, PassphraseWrapper};

        // Cheap on purpose: real cost parameters make this a benchmark.
        let cheap = Cost {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        };
        let derive =
            |pass: &[u8]| PassphraseWrapper::with_salt(pass, [3u8; 16], cheap).expect("derived");

        let dir = TempDir::new().unwrap();
        let subject = subject(0);
        let minted = FsKeyStore::new(dir.path(), derive(b"a passphrase"))
            .unwrap()
            .mint(&subject, &epoch())
            .unwrap();

        // Reopened with the same passphrase: the same key, so nothing sealed under it is lost.
        let same = FsKeyStore::new(dir.path(), derive(b"a passphrase")).unwrap();
        assert_eq!(
            same.get(&subject, &epoch()).unwrap().as_deref(),
            Some(minted.as_ref())
        );
        assert!(same.protects(), "a passphrase wrapper protects");
        assert!(same.wrapping().contains("argon2id"));

        // Reopened with the wrong one: an error, never an absence. An absence here would report a
        // key destroyed that is sitting on disk intact.
        let wrong = FsKeyStore::new(dir.path(), derive(b"the wrong passphrase")).unwrap();
        assert!(matches!(
            wrong.get(&subject, &epoch()),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn an_unwrapped_store_says_so() {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::unwrapped(dir.path()).unwrap();
        assert!(!store.protects());
        assert!(store.wrapping().starts_with("none"));
    }

    #[test]
    fn a_key_wrapped_by_another_wrapper_is_an_error_not_a_missing_key() {
        let dir = TempDir::new().unwrap();
        let subject = subject(0);
        FsKeyStore::new(dir.path(), Labelled(0x11))
            .unwrap()
            .mint(&subject, &epoch())
            .unwrap();

        // Same root, a wrapper that cannot open what is there. Reporting `None` would tell the caller
        // the key was erased, and a caller acting on that would report data destroyed that is not.
        let other = FsKeyStore::new(dir.path(), Labelled(0x22)).unwrap();
        assert!(matches!(
            other.get(&subject, &epoch()),
            Err(Error::Authentication)
        ));
        assert!(other.mint(&subject, &epoch()).is_err());
    }

    #[test]
    fn a_key_that_unwraps_to_the_wrong_length_is_refused() {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::new(dir.path(), Lossy).unwrap();
        let subject = subject(0);
        store.mint(&subject, &epoch()).unwrap();

        // Short by half rather than corrupt, which is the case worth refusing: a weak key that
        // works is worse than a read that fails.
        assert!(matches!(
            store.get(&subject, &epoch()),
            Err(Error::MalformedBlock(_))
        ));
    }

    #[test]
    fn a_wrapper_that_cannot_answer_writes_nothing_and_hides_nothing() {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::new(dir.path(), Offline).unwrap();
        let subject = subject(0);

        assert!(store.mint(&subject, &epoch()).is_err());
        // Nothing on disk, so the next attempt is a first attempt rather than a collision with a
        // key nobody can read.
        assert!(!store.key_path(&subject, &epoch()).unwrap().exists());

        create_private_dir(&store.subject_dir(&subject).unwrap()).unwrap();
        fs::write(store.key_path(&subject, &epoch()).unwrap(), [0u8; KEK_LEN]).unwrap();
        // A key service that is down must not look like an erasure that happened.
        assert!(store.get(&subject, &epoch()).is_err());
    }

    #[test]
    fn the_store_prints_its_root_and_reaches_no_further() {
        let (dir, store) = store();
        let printed = format!("{store:?}");

        assert!(printed.contains("FsKeyStore"), "{printed}");
        assert!(
            printed.contains(&dir.path().display().to_string()),
            "{printed}"
        );
        // The wrapper is left out on purpose: diagnostics are one more place key material surfaces,
        // and a deployment's key service client is under no obligation to be careful in `Debug`.
        assert!(printed.ends_with(".. }"), "{printed}");
    }

    #[test]
    fn unwrapped_and_an_explicit_passthrough_are_the_same_store() {
        let dir = TempDir::new().unwrap();
        let first = subject(0);
        let key = FsKeyStore::unwrapped(dir.path())
            .unwrap()
            .mint(&first, &epoch())
            .unwrap();

        let explicit = FsKeyStore::new(dir.path(), Passthrough).unwrap();
        assert_eq!(explicit.get(&first, &epoch()).unwrap().unwrap(), key);
        assert_eq!(explicit.mint(&first, &epoch()).unwrap(), key);
        // And in the other direction, so neither constructor is the odd one out.
        let other = subject(1);
        let minted = explicit.mint(&other, &epoch()).unwrap();
        assert_eq!(
            FsKeyStore::unwrapped(dir.path())
                .unwrap()
                .get(&other, &epoch())
                .unwrap()
                .unwrap(),
            minted
        );
        // Passthrough is exactly what it says: the key file is the key.
        assert_eq!(
            fs::read(explicit.key_path(&other, &epoch()).unwrap()).unwrap(),
            minted
        );
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
        FsKeyStore::unwrapped(dir.path()).unwrap();

        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_bad_path_component_never_reaches_the_filesystem() {
        let (_dir, store) = store();
        // A subject hash cannot be built with a traversal in it any more, but an epoch label read
        // from a stored block is only checked for separators — so the store still checks its own
        // path components before it touches the disk.
        let hostile = Epoch::from_stored("2026-Q3\0").unwrap();
        assert!(store.get(&subject(0), &hostile).is_err());
        assert!(store.mint(&subject(0), &hostile).is_err());
        assert!(store.destroy_epoch(&subject(0), &hostile).is_err());
    }
}
