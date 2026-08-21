//! A record with every field populated.
//!
//! The projection check compares a record's wire JSON against its frontmatter JSON. A field left
//! empty or absent would compare equal on both sides whatever had happened to it, so the sample has
//! to be maximal — and a test asserts that it is, which is what makes adding a field to
//! `ActionRecord` without adding it here a failure rather than a quiet hole.

use std::collections::BTreeMap;

use yaam_contract::attrs::Value as AttrValue;
use yaam_contract::entity::{self, EntityRef};
use yaam_contract::record::{Role as SubjectRole, SubjectRef};
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, SchemaVer, SubjectHash, Visibility,
};

/// A valid record carrying a distinguishable value in every field.
///
/// Team-scoped and subject-derived so `team` and `subjects` are populated: those are the two fields
/// the contract only requires conditionally, and therefore the two easiest to leave out of a
/// fixture.
///
/// # Panics
/// If the record it builds is not valid, which would mean the sample had drifted from the rules it
/// exists to exercise.
#[must_use]
pub fn maximal() -> ActionRecord {
    let record = ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: "2026-01-01T00:00:00Z".to_owned(),
        received_at: "2026-01-01T00:00:01Z".to_owned(),
        backfilled: true,
        agent: "agent_a".to_owned(),
        agent_ver: Some("1.2.3".to_owned()),
        correlation_id: Some("c-8f21".to_owned()),
        action: "deploy".to_owned(),
        outcome: Outcome::Partial,
        // One of each attribute type, so a projection that mishandled a scalar kind would show.
        attrs: BTreeMap::from([
            ("service".to_owned(), AttrValue::Text("api".to_owned())),
            ("build".to_owned(), AttrValue::Int(412)),
            ("rolled_back".to_owned(), AttrValue::Bool(false)),
        ]),
        entities: vec![
            entity_ref("ticket", "PROJ-42", entity::Role::Primary, 1.0),
            entity_ref("deploy", "d-9", entity::Role::Related, 0.75),
        ],
        subjects: vec![
            subject_ref("ab", SubjectRole::Principal, 1),
            subject_ref("cd", SubjectRole::Party, 2),
        ],
        visibility: Visibility::Team,
        team: Some("platform".to_owned()),
        data_class: DataClass::SubjectDerived,
        redaction_policy: "default-v1".to_owned(),
        fields_masked: vec!["summary".to_owned()],
        tags: vec!["release".to_owned(), "staging".to_owned()],
        summary: "rolled build 412 out to staging".to_owned(),
    };
    record
        .validate()
        .expect("the sample must be a record the contract accepts");
    record
}

/// One entity reference.
fn entity_ref(kind: &str, id: &str, role: entity::Role, confidence: f32) -> EntityRef {
    EntityRef {
        kind: kind.to_owned(),
        id: id.to_owned(),
        role,
        confidence,
    }
}

/// One subject reference, its pseudonym filled from a repeated hex pair.
fn subject_ref(fill: &str, role: SubjectRole, canon_ver: u32) -> SubjectRef {
    SubjectRef {
        hash: SubjectHash::parse(&format!("s_{}", fill.repeat(32))).expect("a valid pseudonym"),
        role,
        canon_ver: CanonVer(canon_ver),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    /// Whether a value would compare equal to anything by being empty.
    fn is_vacuous(value: &Json) -> bool {
        match value {
            Json::Null => true,
            Json::String(text) => text.is_empty(),
            Json::Array(items) => items.is_empty() || items.iter().any(is_vacuous),
            Json::Object(fields) => fields.is_empty() || fields.values().any(is_vacuous),
            Json::Bool(_) | Json::Number(_) => false,
        }
    }

    /// The guard that keeps the projection check honest as fields are added.
    #[test]
    fn every_field_of_the_sample_carries_a_value() {
        let wire = serde_json::to_value(maximal()).expect("a record serialises");
        for (field, value) in wire.as_object().expect("a record is an object") {
            assert!(
                !is_vacuous(value),
                "`{field}` is empty in the sample, so the projection check cannot see it change"
            );
        }
    }

    /// A false negative here would let every other check pass on a record nobody would accept.
    #[test]
    fn the_sample_is_a_record_the_contract_accepts() {
        maximal().validate().expect("valid");
    }

    #[test]
    fn a_vacuous_value_is_recognised_at_every_depth() {
        assert!(is_vacuous(&Json::Null));
        assert!(is_vacuous(&serde_json::json!([{ "a": "" }])));
        assert!(is_vacuous(&serde_json::json!({ "a": [] })));
        assert!(!is_vacuous(&serde_json::json!([{ "a": false }])));
    }

    #[test]
    fn two_samples_differ_only_in_their_identifier() {
        let (first, second) = (maximal(), maximal());
        assert_ne!(first.record_id, second.record_id);
        assert_eq!(
            ActionRecord {
                record_id: second.record_id.clone(),
                ..first
            },
            second
        );
    }
}
