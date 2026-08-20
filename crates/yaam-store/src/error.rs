//! Index failures.

use thiserror::Error;

/// Result alias for store operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong talking to the index.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying database failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A row's stored checksum disagrees with its file, meaning the index has drifted.
    #[error("index drift on record `{0}`")]
    Drift(String),
    /// Schema version on disk is newer than this binary understands.
    #[error("index schema version {found} is newer than supported {supported}")]
    SchemaTooNew {
        /// Version found on disk.
        found: u32,
        /// Highest version this build handles.
        supported: u32,
    },
}
