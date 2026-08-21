//! Wire types and the canonicalisation rules that guard them.
//!
//! [`request`] is here for the same reason: what a write request looks like and what a signature
//! covers are wire rules, and a service and a sidecar that spell either differently cannot talk.
//!
//! [`mask`] is here for that reason too. The service only *checks* a body against the redaction
//! policy and refuses one that still matches, so masking is the writer's job — and a writer masking
//! against a different reading of the policy than the service checks against is exactly the failure
//! worth designing out.
//!
//! Three shapes must agree: the wire record, the Markdown frontmatter, and the database columns.
//! They are all projections of [`ActionRecord`]. That is not a compile error — nothing in the type
//! system can see three crates at once — so it is a test: [`lockstep`] holds the rule and the list
//! of deliberate exceptions, and `xtask` hands it the three shapes as the crates that own them
//! spell them. `summary` is the largest exception: prose that becomes the record body, sealed with
//! it for erasable records.
//!
//! [`schema`] emits the same shapes as `spec/schemas/*.json`, which is what other implementations
//! vendor. Generated rather than written, so the published description cannot become a fourth shape.

#![forbid(unsafe_code)]

pub mod attrs;
pub mod entity;
pub mod error;
pub mod ids;
pub mod lockstep;
pub mod mask;
pub mod record;
pub mod request;
pub mod schema;
mod spec_yaml;
pub mod timestamp;

pub use error::{Error, Result};
pub use ids::{CanonVer, RecordId, SchemaVer, SubjectHash};
pub use record::{ActionRecord, DataClass, Outcome, Role, SubjectRef, Visibility};
pub use request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys};
