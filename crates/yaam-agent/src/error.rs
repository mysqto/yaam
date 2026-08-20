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
    /// Sealing failed.
    #[error(transparent)]
    Crypto(#[from] yaam_crypto::Error),
    /// Filesystem or socket failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
