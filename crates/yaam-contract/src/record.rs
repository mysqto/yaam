//! The action record: the only thing this system stores.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    attrs,
    entity::EntityRef,
    ids::{CanonVer, RecordId, SchemaVer, SubjectHash},
};

/// How the outcome of an action is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// The actor only.
    ///
    /// Stored apart: a subtree of its own per owner, whose directories and files admit no group or
    /// other access. The two halves cover each other — a scoped read answers nothing to anybody
    /// else, and a reader on the host cannot go around the query by opening the file unless it is
    /// the identity the writer runs as.
    Owner,
    /// A named team.
    Team,
    /// Everyone in the deployment.
    Org,
    /// Audit records. Readable only by the operator role.
    Operator,
}

impl Visibility {
    /// How this level is spelled on the wire and in every derived copy.
    ///
    /// Needed because the index promotes visibility into a column and has to compare against the
    /// same spelling the frontmatter carries; a second spelling would silently match nothing.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Team => "team",
            Self::Org => "org",
            Self::Operator => "operator",
        }
    }
}

/// Whether a record's body is erasable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// System and operational activity. Body stored in plaintext.
    Internal,
    /// Traceable to a data subject. Body sealed; erasable by destroying subject keys.
    SubjectDerived,
}

/// The part a subject plays in a record.
// Renamed for the schema, as `entity::Role` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "SubjectRole")]
pub enum Role {
    /// Acted, or was acted for.
    Principal,
    /// Named in the record without being its principal.
    Party,
}

/// One data subject named by a record.
///
/// Unknown fields are refused for the reason [`ActionRecord`] refuses them: a field this type does
/// not declare is one nothing downstream will ever read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
///
/// The wire record, the Markdown frontmatter and the index columns are three projections of this
/// type and cannot diverge. `summary` is the exception, being prose that becomes the record body.
///
/// Unknown fields are refused, for the reason [`WriteRequest`] refuses them one level up, and with
/// more force: here the mistyped field *is* the record, so dropping it would store history the
/// caller did not describe and cannot tell is missing. `attrs` stays open — it is a declared map,
/// checked against `spec/attrs-schema.yaml` rather than against this struct.
///
/// [`WriteRequest`]: crate::request::WriteRequest
// Every other divergence between the three projections fails the build: `crate::lockstep` holds the
// rule and the table of deliberate exceptions, and `xtask` hands it the three shapes. It was a
// convention before that, and a convention missed it twice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
    #[schemars(length(min = 1))]
    pub action: String,
    /// How it went.
    pub outcome: Outcome,
    /// Declared, classified attributes.
    ///
    /// Deliberately open: the permitted keys are declared per action in `spec/attrs-schema.yaml`,
    /// which is deployment configuration this type cannot see. Closing the map here would make the
    /// contract carry one deployment's vocabulary.
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
    ///
    /// Both timestamps are checked for *format* here, at the boundary the writer can still act on.
    /// They are carried as text and converted downstream — by the index, and by the tree deriving a
    /// record's directory from its date — so an unreadable stamp reaching that far surfaces as a
    /// `NOT NULL` violation inside a publish, naming a column rather than the field that was sent.
    ///
    /// The subject rule runs one way here and the other way on the write path, and the asymmetry is
    /// deliberate. An internal record that names subjects claims an erasability its plaintext body
    /// cannot deliver, nothing later can make that claim true, and only the writer knows which half
    /// it meant — so it is refused wherever a record is read.
    ///
    /// A subject-derived record that names none is the same fault only if it is still true after
    /// resolution. A deployment whose store derives pseudonyms keeps the keying secret in the
    /// service, precisely so no caller holds it; such a caller cannot compute a pseudonym and would
    /// have to send a value it knows is wrong to get past a check here. So that half is checked once
    /// the subjects are settled instead — the write pipeline refuses a record that resolves to no
    /// subject, before a byte of it is written, because its body would be sealed under a key nobody
    /// can destroy. Refusing it here as well would not add a guarantee; it would only rule out every
    /// deployment that resolves subjects on the write path.
    pub fn validate(&self) -> crate::Result<()> {
        if self.action.trim().is_empty() {
            return Err(crate::Error::Invalid("action is empty".to_owned()));
        }

        for (field, text) in [("at", &self.at), ("received_at", &self.received_at)] {
            if crate::timestamp::parse_ms(text).is_none() {
                return Err(crate::Error::Invalid(format!(
                    "{field} `{text}` is not a timestamp this can read"
                )));
            }
        }

        if self.data_class == DataClass::Internal && !self.subjects.is_empty() {
            return Err(crate::Error::Invalid(format!(
                "internal record names {} subject(s)",
                self.subjects.len()
            )));
        }

        if self.visibility == Visibility::Team
            && self.team.as_ref().is_none_or(|t| t.trim().is_empty())
        {
            return Err(crate::Error::Invalid(
                "team-scoped record names no team".to_owned(),
            ));
        }

        for entity in &self.entities {
            // NaN belongs to no range, so `contains` rejects it without a special case.
            if !(0.0..=1.0).contains(&entity.confidence) {
                return Err(crate::Error::Invalid(format!(
                    "entity `{}` of kind `{}` has confidence {} outside 0.0..=1.0",
                    entity.id, entity.kind, entity.confidence
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::entity::{self, EntityRef};

    /// A minimal valid record, for this crate's tests: internal, org-visible, no subjects.
    pub(crate) fn internal_record() -> ActionRecord {
        ActionRecord {
            record_id: RecordId::generate(),
            schema_ver: SchemaVer(1),
            at: "2026-01-01T00:00:00Z".to_owned(),
            received_at: "2026-01-01T00:00:01Z".to_owned(),
            backfilled: false,
            agent: "test-agent".to_owned(),
            agent_ver: None,
            correlation_id: None,
            action: "deploy".to_owned(),
            outcome: Outcome::Success,
            attrs: BTreeMap::new(),
            entities: Vec::new(),
            subjects: Vec::new(),
            visibility: Visibility::Org,
            team: None,
            data_class: DataClass::Internal,
            redaction_policy: "default-v1".to_owned(),
            fields_masked: Vec::new(),
            tags: Vec::new(),
            summary: "deployed the service".to_owned(),
        }
    }

    fn subject() -> SubjectRef {
        SubjectRef {
            hash: SubjectHash::parse(&format!("s_{}", "ab".repeat(32))).expect("valid hash"),
            role: Role::Principal,
            canon_ver: CanonVer(1),
        }
    }

    fn entity_ref(confidence: f32) -> EntityRef {
        EntityRef {
            kind: "ticket".to_owned(),
            id: "PROJ-42".to_owned(),
            role: entity::Role::Primary,
            confidence,
        }
    }

    #[test]
    fn a_minimal_internal_record_is_valid() {
        internal_record().validate().unwrap();
    }

    /// A subject-derived record may leave its subjects to the store, because a deployment that
    /// derives pseudonyms in the service is one whose callers cannot compute one. What such a record
    /// must not do is get written that way, and that is the write pipeline's refusal to make: it is
    /// the only place where "this resolved to no subject" is a fact rather than a guess about what
    /// the store will do next.
    #[test]
    fn a_subject_derived_record_may_name_no_subject_and_leave_it_to_resolution() {
        let mut r = internal_record();
        r.data_class = DataClass::SubjectDerived;
        r.validate()
            .expect("the subjects are the store's to settle");

        r.subjects.push(subject());
        r.validate()
            .expect("and a record that brings its own is no worse");
    }

    #[test]
    fn an_internal_record_must_name_none() {
        let mut r = internal_record();
        r.subjects.push(subject());
        let err = r
            .validate()
            .expect_err("internal records carry no subjects");
        assert!(err.to_string().contains("names 1 subject"), "{err}");
    }

    #[test]
    fn team_visibility_requires_a_team() {
        let mut r = internal_record();
        r.visibility = Visibility::Team;
        assert!(r.validate().is_err());

        // Whitespace is not a team name.
        r.team = Some("   ".to_owned());
        assert!(r.validate().is_err());

        r.team = Some("platform".to_owned());
        r.validate().unwrap();
    }

    #[test]
    fn other_visibilities_need_no_team() {
        for visibility in [Visibility::Owner, Visibility::Org, Visibility::Operator] {
            let mut r = internal_record();
            r.visibility = visibility;
            r.validate().unwrap();
        }
    }

    #[test]
    fn action_must_not_be_empty() {
        for action in ["", "   "] {
            let mut r = internal_record();
            r.action = action.to_owned();
            assert!(r.validate().is_err(), "{action:?} must be rejected");
        }
    }

    #[test]
    fn confidence_must_be_a_probability() {
        for good in [0.0, 0.5, 1.0] {
            let mut r = internal_record();
            r.entities.push(entity_ref(good));
            r.validate().unwrap();
        }
        for bad in [-0.1, 1.1, f32::NAN, f32::INFINITY] {
            let mut r = internal_record();
            r.entities.push(entity_ref(bad));
            let err = r.validate().expect_err("confidence out of range");
            assert!(err.to_string().contains("PROJ-42"), "{err}");
        }
    }

    #[test]
    fn every_entity_is_checked_not_just_the_first() {
        let mut r = internal_record();
        r.entities.push(entity_ref(1.0));
        r.entities.push(entity_ref(2.0));
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_timestamp_the_store_cannot_read_is_rejected_on_the_way_in() {
        for bad in ["", "2026-08-20", "2026-08-20T09:14:02", "yesterday"] {
            let mut r = internal_record();
            r.at = bad.to_owned();
            let err = r.validate().expect_err("an unreadable `at`");
            assert!(err.to_string().contains("at `"), "{err}");

            let mut r = internal_record();
            r.received_at = bad.to_owned();
            let err = r.validate().expect_err("an unreadable `received_at`");
            assert!(err.to_string().contains("received_at `"), "{err}");
        }
    }

    #[test]
    fn a_record_survives_json() {
        let mut r = internal_record();
        r.data_class = DataClass::SubjectDerived;
        r.subjects.push(subject());
        r.subjects.push(SubjectRef {
            hash: SubjectHash::parse(&format!("s_{}", "cd".repeat(32))).unwrap(),
            role: Role::Party,
            canon_ver: CanonVer(2),
        });
        r.entities.push(entity_ref(0.75));
        r.visibility = Visibility::Team;
        r.team = Some("platform".to_owned());
        r.outcome = Outcome::Partial;
        r.agent_ver = Some("1.2.3".to_owned());
        r.correlation_id = Some("c-1".to_owned());
        r.backfilled = true;
        r.attrs
            .insert("service".to_owned(), attrs::Value::Text("api".to_owned()));
        r.fields_masked.push("summary".to_owned());
        r.tags.push("release".to_owned());

        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ActionRecord>(&json).unwrap(), r);
        // Enum spellings are part of the wire contract, not an implementation detail.
        assert!(json.contains(r#""outcome":"partial""#), "{json}");
        assert!(json.contains(r#""data_class":"subject_derived""#), "{json}");
        assert!(json.contains(r#""visibility":"team""#), "{json}");
        assert!(json.contains(r#""role":"principal""#), "{json}");
    }

    #[test]
    fn a_field_the_record_does_not_declare_is_refused_rather_than_dropped() {
        // What this costs when it is dropped: the record stored is not the record the caller
        // described, and no later read can tell. The wrapper has always refused a stray field at
        // the top level; one *inside* the record is the same mistake about more.
        let mut r = internal_record();
        r.entities.push(entity_ref(1.0));
        r.subjects.push(subject());
        r.data_class = DataClass::SubjectDerived;
        let json = serde_json::to_value(&r).expect("serialises");

        for pointer in ["/nonsense", "/entities/0/nonsense", "/subjects/0/nonsense"] {
            let mut smuggled = json.clone();
            let (parent, key) = pointer.rsplit_once('/').expect("a pointer names its key");
            smuggled
                .pointer_mut(parent)
                .expect("the parent is in the document")
                .as_object_mut()
                .expect("an object")
                .insert(key.to_owned(), serde_json::json!(1));
            let error = serde_json::from_value::<ActionRecord>(smuggled)
                .expect_err("an undeclared field must be refused");
            assert!(
                error.to_string().contains("unknown field"),
                "{pointer}: {error}"
            );
        }
    }

    #[test]
    fn a_visibility_spells_itself_the_way_it_serialises() {
        // The index compares a column against `as_str`, and that column holds the serialised form.
        for visibility in [
            Visibility::Owner,
            Visibility::Team,
            Visibility::Org,
            Visibility::Operator,
        ] {
            let json = serde_json::to_string(&visibility).unwrap();
            assert_eq!(json, format!("\"{}\"", visibility.as_str()));
        }
    }

    #[test]
    fn every_outcome_round_trips() {
        for outcome in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Partial,
            Outcome::Declined,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
        }
    }
}
