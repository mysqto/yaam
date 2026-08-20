//! Parse and render failures.

use thiserror::Error;

/// Result alias for Markdown operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong reading or writing a record file.
#[derive(Debug, Error)]
pub enum Error {
    /// The file has no frontmatter block.
    #[error("missing frontmatter")]
    MissingFrontmatter,
    /// Frontmatter was present but unparseable.
    #[error("malformed frontmatter: {0}")]
    MalformedFrontmatter(String),
    /// Frontmatter parsed but violated the contract.
    #[error(transparent)]
    Contract(#[from] yaam_contract::Error),
    /// The sealed block could not be parsed.
    #[error(transparent)]
    Crypto(#[from] yaam_crypto::Error),
}
