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
