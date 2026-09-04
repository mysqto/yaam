//! Failures that callers must distinguish.

use std::path::PathBuf;

use thiserror::Error;
use yaam_crypto::KeyCheck;

/// Result alias for core operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Core failures.
///
/// The distinction that matters most: [`Error::Invalid`] means the caller must fix the record and
/// is safe to reject, while [`Error::SubjectUnresolved`] is transient and must never be reported as
/// a rejection — dropping a record because a lookup was briefly unavailable loses audit history
/// exactly when it matters most.
#[derive(Debug, Error)]
pub enum Error {
    /// The record violates the contract. Permanent; reject it.
    #[error(transparent)]
    Invalid(#[from] yaam_contract::Error),
    /// A subject could not be resolved right now. Transient; quarantine and retry.
    #[error("subject resolution unavailable")]
    SubjectUnresolved,
    /// Sealing failed.
    #[error(transparent)]
    Crypto(#[from] yaam_crypto::Error),
    /// The index failed.
    #[error(transparent)]
    Store(#[from] yaam_store::Error),
    /// Serialisation failed.
    #[error(transparent)]
    Markdown(#[from] yaam_md::Error),
    /// The subject key is not the one this store recorded being armed with.
    ///
    /// A refusal to open, and the one failure in this area worth a startup outage: the alternative is
    /// a second pseudonym for every subject already on record, which no later decision can undo. See
    /// [`crate::arming`] for what the check does and does not prove.
    #[error(
        "the subject key is not the one this store was armed with: {} records check value \
         {recorded}, and this key derives {derived}. Every pseudonym the store already holds came \
         from the key that recorded value belongs to, so coming up under this one would file a \
         second, unrelatable pseudonym for every subject already on record — and there is no \
         re-key, no re-seal and no delete to take that back. Name the store's own key; or, if this \
         key is that key and the recorded value was adopted from one that was not, remove the file \
         and the next open records this key's",
        path.display()
    )]
    SubjectKeyMismatch {
        /// The file holding the recorded value.
        path: PathBuf,
        /// What the store records.
        recorded: KeyCheck,
        /// What the key handed to this process derives.
        derived: KeyCheck,
    },
    /// The recorded check value could not be read, so nothing can be said about the key.
    ///
    /// Held apart from [`Error::SubjectKeyMismatch`] because the remedy is not the same: this is a
    /// file to restore, not a setting to change. Also a refusal — a check that answers "cannot tell"
    /// and opens anyway is no check at all on the one open where it would have mattered.
    #[error(
        "the subject-key check value at {} {detail}. It records which subject key this store's \
         pseudonyms were derived from, and without it this process cannot tell the store's own key \
         from a substitute — which would file a second, unrelatable pseudonym for every subject \
         already on record, with no re-key, no re-seal and no delete to take it back. A backup \
         carries it: restore the file. If it is lost and the key is known to be this store's own, \
         remove the file and the next open records the check value again",
        path.display()
    )]
    SubjectKeyCheckUnreadable {
        /// The file that could not be used.
        path: PathBuf,
        /// What is wrong with it, as a clause the message reads on from.
        detail: String,
    },
    /// A legal hold forbids this destruction.
    ///
    /// Its own variant because it is the one refusal that is neither the caller's mistake nor this
    /// store's fault: two obligations point in opposite directions and [`crate::hold`] is what
    /// arbitrates. A caller told `422` would go looking for the malformed field it did not send,
    /// and one told `500` would raise an incident — the answer is that a person has to decide
    /// which obligation now applies and release the hold, or not.
    ///
    /// The message carries the holds, because a refusal that does not say which obligation blocked
    /// it is one nobody can act on.
    #[error("{0}")]
    Held(String),
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
