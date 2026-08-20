//! Failures that callers must distinguish.

use thiserror::Error;

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
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
