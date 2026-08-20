//! The action record: the only thing this system stores.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    attrs,
    entity::EntityRef,
    ids::{CanonVer, RecordId, SchemaVer, SubjectHash},
};

/// How the outcome of an action is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The action did what it set out to do.
    Success,
    /// It failed.
    Failure,
    /// It partly succeeded, and the record says how.
    Partial,
    /// It was refused, by us or by a downstream system.
    Declined,
}

/// Who may read a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// The actor only. Stored apart, with tighter filesystem permissions.
    Owner,
    /// A named team.
    Team,
    /// Everyone in the deployment.
    Org,
    /// Audit records. Readable only by the operator role.
    Operator,
}

/// Whether a record's body is erasable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// System and operational activity. Body stored in plaintext.
    Internal,
    /// Traceable to a data subject. Body sealed; erasable by destroying subject keys.
    SubjectDerived,
}

/// The part a subject plays in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Acted, or was acted for.
    Principal,
    /// Named in the record without being its principal.
    Party,
}

/// One data subject named by a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRef {
    /// The keyed pseudonym.
    pub hash: SubjectHash,
    /// The part this subject plays.
    pub role: Role,
    /// Canonicalisation ruleset that produced `hash`.
    pub canon_ver: CanonVer,
}

/// A single thing an agent did.
///
/// `action` and `outcome` are top-level and indexed because every useful query filters on them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// Identity and idempotency key.
    pub record_id: RecordId,
    /// Schema version this record was written under.
    pub schema_ver: SchemaVer,
    /// Source-reported time. May be skewed; not used for ordering.
    pub at: String,
    /// Time stamped by the service. Authoritative for ordering and windowing.
    pub received_at: String,
    /// `true` when `received_at` came from an upstream source rather than our clock.
    pub backfilled: bool,
    /// Which agent produced this.
    pub agent: String,
    /// Agent version, for attributing behaviour changes.
    pub agent_ver: Option<String>,
    /// Ties every stage of one interaction together.
    pub correlation_id: Option<String>,
    /// What was done.
    pub action: String,
    /// How it went.
    pub outcome: Outcome,
    /// Declared, classified attributes.
    pub attrs: BTreeMap<String, attrs::Value>,
    /// Entities this record joins on.
    pub entities: Vec<EntityRef>,
    /// Data subjects named by this record. Empty for [`DataClass::Internal`].
    pub subjects: Vec<SubjectRef>,
    /// Read scope.
    pub visibility: Visibility,
    /// Team, required when `visibility` is [`Visibility::Team`].
    pub team: Option<String>,
    /// Whether the body is erasable.
    pub data_class: DataClass,
    /// Redaction policy applied before the write.
    pub redaction_policy: String,
    /// Fields the policy masked. Informational.
    pub fields_masked: Vec<String>,
    /// Free tags.
    pub tags: Vec<String>,
    /// Prose. Becomes the record body, sealed when `data_class` is subject-derived.
    pub summary: String,
}

impl ActionRecord {
    /// Checks the invariants that cannot be expressed in the type system.
    ///
    /// Notably: a subject-derived record must name at least one subject, and a team-scoped record
    /// must name its team.
    pub fn validate(&self) -> crate::Result<()> {
        todo!("cross-field invariants")
    }
}
