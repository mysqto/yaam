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
pub mod query;
pub mod schema;
pub mod store;

pub use error::{Error, Result};
pub use store::{Store, Writer};
