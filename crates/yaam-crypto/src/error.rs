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
    /// A keying secret of the wrong size, which no amount of padding would make into one.
    #[error("a subject key must be {expected} bytes, got {got}")]
    SubjectKeyLength {
        /// Bytes the derivation requires.
        expected: usize,
        /// Bytes supplied.
        got: usize,
    },
    /// A keying secret that is not hex. Never quotes the value: a message that did would put the
    /// secret into every log that captured the startup failure.
    #[error("a subject key must be hex-encoded")]
    SubjectKeyNotHex,
    /// The subject key could not be reached at all — the file is not there, the key service did not
    /// answer. Held apart from the two above, which say key material arrived and was not a key: those
    /// name a file an operator fixes in place, this one names custody that has to be reachable before
    /// the process can run at all.
    ///
    /// Carries the source's own account of why, wrapped by the startup path that knows which setting
    /// selected the source. Never the key or anything derived from it: this text reaches a startup
    /// log.
    #[error("{0}")]
    SubjectKeyUnavailable(String),
    /// An identifier that canonicalises to nothing. Held apart from a malformed record because the
    /// remedy is the caller's: one shared pseudonym for every such identifier would make each of
    /// their bodies erasable by any one of their requests.
    #[error("a subject identifier canonicalises to nothing under canon version {0}")]
    SubjectIdEmpty(u32),
    /// Underlying I/O failure.
    #[error("key store io: {0}")]
    Io(#[from] std::io::Error),
}
