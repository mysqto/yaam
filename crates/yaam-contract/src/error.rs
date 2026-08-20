//! Contract-level failures.

use thiserror::Error;

/// Result alias for contract operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A record or identifier that does not satisfy the contract.
#[derive(Debug, Error)]
pub enum Error {
    /// An entity ID did not match its kind's canonical form.
    #[error("entity id `{id}` is not canonical for kind `{kind}`")]
    NotCanonical {
        /// The entity kind.
        kind: String,
        /// The offending identifier.
        id: String,
    },
    /// An entity kind is absent from the loaded registry.
    #[error("unknown entity kind `{0}`")]
    UnknownEntityKind(String),
    /// An `attrs` key is not declared for this action.
    #[error("attribute `{key}` is not declared for action `{action}`")]
    UndeclaredAttr {
        /// The action name.
        action: String,
        /// The offending attribute key.
        key: String,
    },
    /// A `sensitive` attribute was found in plaintext frontmatter.
    #[error("attribute `{0}` is classified sensitive and may not appear in frontmatter")]
    SensitiveAttrInFrontmatter(String),
    /// A record failed a structural invariant.
    #[error("invalid record: {0}")]
    Invalid(String),
}
