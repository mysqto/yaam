//! Cryptographic and key-management failures.

use thiserror::Error;

/// Result alias for crypto operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong sealing, unsealing, or handling keys.
#[derive(Debug, Error)]
pub enum Error {
    /// Authentication failed: wrong key, tampered ciphertext, or mismatched associated data.
    #[error("authentication failed while unsealing")]
    Authentication,
    /// A subject's key is absent — usually because it was destroyed, which is the intended outcome.
    #[error("no key for subject `{0}` in epoch `{1}`")]
    KeyAbsent(String, String),
    /// Refusing to mint a key for a subject that has been erased.
    #[error("subject `{0}` is tombstoned; minting a key would un-erase it")]
    Tombstoned(String),
    /// The share set does not match the record's subjects.
    #[error("expected {expected} shares, got {got}")]
    ShareCount {
        /// Shares the record requires.
        expected: usize,
        /// Shares supplied.
        got: usize,
    },
    /// A stored blob could not be parsed.
    #[error("malformed sealed block: {0}")]
    MalformedBlock(String),
    /// Underlying I/O failure.
    #[error("key store io: {0}")]
    Io(#[from] std::io::Error),
}
