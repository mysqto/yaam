//! The derived index.
//!
//! Nothing here is authoritative. Every row is reproducible from the Markdown tree, which is why
//! the schema carries no column without an on-disk source, and why deleting the database is a
//! recoverable operation rather than data loss.
//!
//! One writer, always. Reads may be concurrent; writes go through a single owner so the
//! single-writer assumption is enforced by structure rather than convention.

#![forbid(unsafe_code)]

pub mod error;
pub mod health;
pub mod query;
pub mod schema;
pub mod store;

pub use error::{Error, Result};
pub use store::{Batch, FanoutJob, PublishInput, Store, Writer};

/// Rebuilds a record id from its stored text.
///
/// Goes through the contract's own parser rather than a local constructor, so the index cannot mint
/// an id shape the contract would reject. A value that fails is drift by definition: the row no
/// longer matches the tree it was derived from.
pub(crate) fn stored_record_id(text: String) -> Result<yaam_contract::RecordId> {
    yaam_contract::RecordId::parse(&text).map_err(|_| Error::Drift(text))
}

/// Rebuilds a record's structure from the frontmatter column it was indexed from.
///
/// Parsed through the contract's own type rather than handed on as text, for two reasons. A stored
/// projection this build cannot read is drift by definition — the row no longer matches the tree —
/// and passing the column through unparsed would forward to a caller whatever the column happened to
/// hold. The identifier column is compared against the one inside the projection, because they are
/// written by the same publish and only one of them is what every index and path is keyed by.
pub(crate) fn stored_structure(
    id: String,
    frontmatter: &str,
) -> Result<yaam_contract::RecordStructure> {
    let structure: yaam_contract::RecordStructure =
        serde_json::from_str(frontmatter).map_err(|_| Error::Drift(id.clone()))?;
    if structure.record_id.as_str() != id {
        return Err(Error::Drift(id));
    }
    Ok(structure)
}
