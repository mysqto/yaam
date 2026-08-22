//! Failures a caller must distinguish.

use thiserror::Error;

/// Result alias for knowledge operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong deriving, writing or reading knowledge.
///
/// The distinction that matters: [`Error::Unrenderable`] is a value this layer refuses to write,
/// while [`Error::Unreadable`] is a note it refuses to read back. Both are drift between the tree
/// and this build, and both are reported rather than papered over — a note that round-trips
/// approximately is a note whose provenance cannot be trusted, and provenance is the only thing
/// making a fact checkable.
#[derive(Debug, Error)]
pub enum Error {
    /// A value cannot be written into a note without becoming ambiguous on the way back.
    #[error("`{0}` cannot be written into a note unambiguously")]
    Unrenderable(String),
    /// A note file this build cannot read back.
    #[error("unreadable note: {0}")]
    Unreadable(String),
    /// A stored value the record contract refused.
    #[error(transparent)]
    Contract(#[from] yaam_contract::Error),
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
