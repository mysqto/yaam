//! Wire types and the canonicalisation rules that guard them.
//!
//! Three shapes must agree: the wire record, the Markdown frontmatter, and the database columns.
//! They are all projections of [`ActionRecord`], so divergence is a compile error rather than a
//! runtime surprise. `summary` is the one deliberate exception — it is prose that becomes the
//! record body, and for erasable records that body is sealed.

#![forbid(unsafe_code)]

pub mod attrs;
pub mod entity;
pub mod error;
pub mod ids;
pub mod record;
mod spec_yaml;

pub use error::{Error, Result};
pub use ids::{CanonVer, RecordId, SchemaVer, SubjectHash};
pub use record::{ActionRecord, DataClass, Outcome, Role, SubjectRef, Visibility};
