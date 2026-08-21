//! Sidecar failures.

use thiserror::Error;

/// Result alias for sidecar operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong locally.
#[derive(Debug, Error)]
pub enum Error {
    /// The record is malformed. Permanent; tell the caller.
    #[error("rejected: {0}")]
    Rejected(String),
    /// Upstream is unreachable; the record was spooled.
    #[error("spooled: upstream unavailable")]
    Spooled,
    /// The spool is full and upstream is still down.
    #[error("spool full")]
    SpoolFull,
    /// No answer arrived, and there was nothing to queue.
    ///
    /// Separate from [`Error::Spooled`] because a read has no *later*: a caller is waiting for data,
    /// and a receipt promising it eventually would be a promise to hand back something already
    /// stale. Only the read path produces this.
    #[error("unreachable: {0}")]
    Unreachable(String),
    /// Sealing failed.
    #[error(transparent)]
    Crypto(#[from] yaam_crypto::Error),
    /// Filesystem or socket failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
