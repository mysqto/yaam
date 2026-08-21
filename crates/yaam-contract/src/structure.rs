//! What a read hands back: a record's structure, and never its body.
//!
//! [`RecordStructure`] is the record's frontmatter — the plaintext half — as one wire shape. It has
//! no field for prose, which is the point: "a read returns no body" is then a property of the type
//! rather than a rule each handler has to remember, and it holds for a sealed body and a plaintext
//! one alike. A read that branched on [`DataClass`] to hand back plaintext bodies for internal
//! records would be returning structure *except sometimes*, and the exception is what leaks.
//!
//! The key set is exactly `yaam_md::frontmatter::KEYS`, with no exemption list and no way past it —
//! `xtask` hands both to [`crate::lockstep`], which fails the build if they drift. Frontmatter is
//! what survives in every derived copy, so anything unsafe to hand a caller was already unsafe to
//! put there.
//!
//! [`DataClass`]: crate::DataClass

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ActionRecord, DataClass, Outcome, SubjectRef, Visibility, attrs,
    entity::EntityRef,
    ids::{RecordId, SchemaVer},
};

/// One record as a read returns it: every frontmatter key, and no body.
///
/// Deserialised from the frontmatter a record was stored with rather than rebuilt from parts, so a
/// read describes the record on disk and not this build's idea of it. Unknown fields are refused for
/// the reason [`ActionRecord`] refuses them: a stored key this type does not declare is one nothing
/// downstream reads, and passing it through would forward whatever the store happened to hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordStructure {
    /// Identity the record is addressable by.
    pub record_id: RecordId,
    /// Schema version the record was written under.
    pub schema_ver: SchemaVer,
    /// Source-reported time. May be skewed; never used for ordering.
    pub at: String,
    /// Time stamped by the service. Authoritative for ordering and windowing.
    pub received_at: String,
    /// `true` when `received_at` came from an upstream source rather than the service's clock.
    pub backfilled: bool,
    /// Which agent produced this.
    pub agent: String,
    /// Agent version, for attributing behaviour to a release.
    pub agent_ver: Option<String>,
    /// Ties every stage of one interaction together.
    pub correlation_id: Option<String>,
    /// What was done.
    pub action: String,
    /// How it went.
    pub outcome: Outcome,
    /// Declared, classified attributes. Structural keys only — a sensitive one is refused on write,
    /// so it is not in frontmatter to be read back.
    pub attrs: BTreeMap<String, attrs::Value>,
    /// Entities this record joins on.
    pub entities: Vec<EntityRef>,
    /// Data subjects named by this record, as keyed pseudonyms. Never a direct identifier.
    pub subjects: Vec<SubjectRef>,
    /// Read scope the record was stored under.
    pub visibility: Visibility,
    /// Team, present when `visibility` is team-scoped.
    pub team: Option<String>,
    /// Whether the body is erasable. Reported so a caller knows what it is *not* being given.
    pub data_class: DataClass,
    /// Redaction policy applied before the write.
    pub redaction_policy: String,
    /// Fields the policy masked. Informational.
    pub fields_masked: Vec<String>,
    /// Free tags.
    pub tags: Vec<String>,
}

impl RecordStructure {
    /// Bytes this structure takes on the wire.
    ///
    /// Serialised rather than counted from the field list, because two records of the same shape are
    /// not the same size: `attrs`, `entities`, `subjects` and `tags` are where the bytes are. A
    /// structure that will not serialise reports nothing rather than failing a read — the only way
    /// in is a non-finite confidence, which `ActionRecord::validate` refuses on the way in.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(0, |bytes| bytes.len())
    }
}

impl From<&ActionRecord> for RecordStructure {
    /// Projects a record onto its structure, dropping `summary`.
    ///
    /// The projection a writer holds. A read builds the same shape from stored frontmatter instead,
    /// which is why nothing here reaches for a body: there is nowhere to put one.
    fn from(record: &ActionRecord) -> Self {
        Self {
            record_id: record.record_id.clone(),
            schema_ver: record.schema_ver,
            at: record.at.clone(),
            received_at: record.received_at.clone(),
            backfilled: record.backfilled,
            agent: record.agent.clone(),
            agent_ver: record.agent_ver.clone(),
            correlation_id: record.correlation_id.clone(),
            action: record.action.clone(),
            outcome: record.outcome,
            attrs: record.attrs.clone(),
            entities: record.entities.clone(),
            subjects: record.subjects.clone(),
            visibility: record.visibility,
            team: record.team.clone(),
            data_class: record.data_class,
            redaction_policy: record.redaction_policy.clone(),
            fields_masked: record.fields_masked.clone(),
            tags: record.tags.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::internal_record;

    #[test]
    fn a_structure_carries_every_field_of_the_record_it_came_from() {
        let mut record = internal_record();
        record.agent_ver = Some("2.1.0".to_owned());
        record.correlation_id = Some("c-8f21".to_owned());
        record.backfilled = true;
        record.visibility = Visibility::Team;
        record.team = Some("platform".to_owned());
        record.outcome = Outcome::Partial;
        record
            .attrs
            .insert("service".to_owned(), attrs::Value::Text("api".to_owned()));
        record.entities.push(EntityRef {
            kind: "ticket".to_owned(),
            id: "PROJ-42".to_owned(),
            role: crate::entity::Role::Primary,
            confidence: 1.0,
        });
        record.fields_masked.push("summary".to_owned());
        record.tags.push("release".to_owned());

        let structure = RecordStructure::from(&record);
        assert_eq!(structure.record_id, record.record_id);
        assert_eq!(structure.schema_ver, record.schema_ver);
        assert_eq!(structure.at, record.at);
        assert_eq!(structure.received_at, record.received_at);
        assert_eq!(structure.backfilled, record.backfilled);
        assert_eq!(structure.agent, record.agent);
        assert_eq!(structure.agent_ver, record.agent_ver);
        assert_eq!(structure.correlation_id, record.correlation_id);
        assert_eq!(structure.action, record.action);
        assert_eq!(structure.outcome, record.outcome);
        assert_eq!(structure.attrs, record.attrs);
        assert_eq!(structure.entities, record.entities);
        assert_eq!(structure.subjects, record.subjects);
        assert_eq!(structure.visibility, record.visibility);
        assert_eq!(structure.team, record.team);
        assert_eq!(structure.data_class, record.data_class);
        assert_eq!(structure.redaction_policy, record.redaction_policy);
        assert_eq!(structure.fields_masked, record.fields_masked);
        assert_eq!(structure.tags, record.tags);
    }

    /// The one thing a read must never carry, checked on the serialised form rather than the type:
    /// a field added later would compile and would still be wrong.
    #[test]
    fn no_prose_reaches_the_wire() {
        let mut record = internal_record();
        record.summary = "a body a caller must not receive".to_owned();
        let json = serde_json::to_string(&RecordStructure::from(&record)).expect("serialises");
        assert!(!json.contains("summary"), "{json}");
        assert!(!json.contains("a caller must not receive"), "{json}");
    }

    #[test]
    fn a_structure_round_trips_through_json() {
        let structure = RecordStructure::from(&internal_record());
        let json = serde_json::to_string(&structure).expect("serialises");
        assert_eq!(
            serde_json::from_str::<RecordStructure>(&json).expect("parses"),
            structure
        );
    }

    /// A stored projection carrying a body is refused, not quietly dropped: a read that accepted it
    /// would be one deployment's index away from handing prose to a caller.
    #[test]
    fn a_stored_projection_with_a_body_is_refused() {
        let mut json =
            serde_json::to_value(RecordStructure::from(&internal_record())).expect("serialises");
        json.as_object_mut()
            .expect("an object")
            .insert("summary".to_owned(), serde_json::json!("prose"));
        let error = serde_json::from_value::<RecordStructure>(json)
            .expect_err("`summary` is not a key a read returns");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn wire_bytes_grows_with_what_the_record_carries() {
        let bare = RecordStructure::from(&internal_record()).wire_bytes();
        let mut record = internal_record();
        record.tags = vec!["release".to_owned(); 20];
        let laden = RecordStructure::from(&record).wire_bytes();
        assert!(laden > bare, "{laden} is not more than {bare}");

        // It is the serialised length, not an estimate of one: the caller pays for these bytes.
        let structure = RecordStructure::from(&internal_record());
        let serialised = serde_json::to_vec(&structure).expect("serialises");
        assert_eq!(structure.wire_bytes(), serialised.len());
    }
}
