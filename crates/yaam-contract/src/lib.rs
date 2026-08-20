//! Wire types and the canonicalisation rules that guard them.
//!
//! [`request`] is here for the same reason: what a write request looks like and what a signature
//! covers are wire rules, and a service and a sidecar that spell either differently cannot talk.
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
pub mod request;
mod spec_yaml;
pub mod timestamp;

pub use error::{Error, Result};
pub use ids::{CanonVer, RecordId, SchemaVer, SubjectHash};
pub use record::{ActionRecord, DataClass, Outcome, Role, SubjectRef, Visibility};
pub use request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys};
