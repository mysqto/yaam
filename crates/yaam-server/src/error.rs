//! Service failures and their status mapping.

use thiserror::Error;

/// Result alias for service operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What a request can fail with.
///
/// The mapping matters: a malformed record is the caller's bug and gets `422`, while a transient
/// dependency failure gets `503` so the caller retries instead of discarding the record.
#[derive(Debug, Error)]
pub enum Error {
    /// Signature missing, malformed, or wrong.
    #[error("unauthenticated")]
    Unauthenticated,
    /// Authenticated, but not permitted — including attributing a record to another agent.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The record violates the contract. Permanent.
    #[error("unprocessable: {0}")]
    Unprocessable(String),
    /// A dependency is briefly unavailable. Retry.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Everything else.
    #[error(transparent)]
    Core(#[from] yaam_core::Error),
}
