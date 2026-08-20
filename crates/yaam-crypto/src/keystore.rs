//! Where subject keys live, and the rules that keep erasure honest.

use yaam_contract::SubjectHash;

use crate::seal::Epoch;

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

/// Filesystem key store.
#[derive(Debug)]
pub struct FsKeyStore {
    #[expect(dead_code, reason = "read once the implementation lands")]
    root: std::path::PathBuf,
}

impl FsKeyStore {
    /// Opens a key store rooted at `root`, creating it if absent.
    pub fn open(_root: impl Into<std::path::PathBuf>) -> crate::Result<Self> {
        todo!("create dirs with restrictive permissions")
    }
}
