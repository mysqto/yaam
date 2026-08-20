//! Contract-level failures.

use thiserror::Error;

/// Result alias for contract operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A record or identifier that does not satisfy the contract.
///
/// `PartialEq` is derived because every consumer asserts on whole results: without it `assert_eq!`
/// on a `Result` does not compile, and each crate ends up hand-writing a `matches!` instead.
#[derive(Debug, Error, PartialEq, Eq)]
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
    /// A spec file under `spec/` is malformed.
    ///
    /// Separate from [`Error::Invalid`] because the two need different responses: a broken record
    /// is rejected and its sender told, while a broken spec means this deployment is misconfigured
    /// and no record can be trusted until it is fixed.
    #[error("invalid spec: {detail}")]
    Spec {
        /// What was wrong with the spec.
        detail: String,
    },
}
