//! What knowledge holds, and the gate deciding which records may contribute to it.

use yaam_contract::{DataClass, RecordId, RecordStructure, Visibility, attrs};

/// Confidence a reference must carry to become a fact.
///
/// `1.0` — read out of a structured field, never inferred from prose. The same bar
/// `yaam_core::bundle` sets, for the same reason and more so: a guess a caller cannot tell apart
/// from a fact is worse once it has been written down under the heading "what is true".
const MIN_CONFIDENCE: f32 = 1.0;

/// An entity as knowledge keys it: a kind and a canonical identifier, and nothing else.
///
/// Role and confidence are properties of one record's *reference* to an entity, not of the entity,
/// so they are not part of its identity. Identifiers arrive already canonicalised — the write path
/// canonicalises on the way in — so nothing here re-derives them; a second canonicaliser would
/// eventually disagree with the one the tree was written by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityKey {
    /// Entity kind, as `spec/entities.yaml` declares it.
    pub kind: String,
    /// Canonical identifier within that kind.
    pub id: String,
}

impl EntityKey {
    /// Builds a key from its two parts.
    #[must_use]
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// One statement knowledge holds about an entity.
///
/// Every variant is a pure function of the frontmatter fields of one record. There is no inference
/// here, no threshold and no free text: a fact is a restatement of something a record declared in a
/// structured field, which is what makes it re-derivable and what keeps this layer out of the
/// business of guessing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fact {
    /// The entity was recorded alongside a structural attribute.
    ///
    /// Co-occurrence, and worded that way on purpose: the attribute belonged to the *record*, not
    /// necessarily to this entity. A record naming two entities pairs its attributes with both, so a
    /// caller must read this as "seen together in one record" and not as "this entity has this
    /// property". Deciding which entity an attribute really describes would be inference, and this
    /// layer makes none — the provenance is there so a caller who needs to know can look.
    Attribute {
        /// Entity the statement is about.
        entity: EntityKey,
        /// Attribute key, as the record declared it.
        key: String,
        /// Attribute value, flattened to text.
        value: String,
    },
    /// An agent acted on the entity.
    Actor {
        /// Entity the statement is about.
        entity: EntityKey,
        /// Agent that produced the record.
        agent: String,
    },
    /// The entity was named by the same record as another entity.
    ///
    /// Emitted in both directions, so each entity's own note is complete without having to consult
    /// its neighbours'.
    Association {
        /// Entity the statement is about.
        entity: EntityKey,
        /// The entity it appeared with.
        with: EntityKey,
    },
}

impl Fact {
    /// The entity whose note this fact belongs in.
    #[must_use]
    pub fn entity(&self) -> &EntityKey {
        match self {
            Self::Attribute { entity, .. }
            | Self::Actor { entity, .. }
            | Self::Association { entity, .. } => entity,
        }
    }
}

/// One fact, and the record it was read out of.
///
/// Provenance is not optional and not a separate table: a fact travels with the identifier of the
/// record it came from, so a reader can always go back to the structure behind it. A fact without
/// provenance is an assertion, and this layer makes none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// What was observed.
    pub fact: Fact,
    /// The record it was read out of.
    pub source: RecordId,
    /// That record's server-stamped time, verbatim.
    ///
    /// Kept as the record spells it rather than as milliseconds, so a note shows a time a person can
    /// read and still round-trips exactly. The ordering is done on the parsed value.
    pub at: String,
}

/// Why a record contributes nothing to knowledge.
///
/// Reported rather than folded into one count, because the three mean different things to an
/// operator: erasable records are *expected* to be excluded and their number is a measure of the
/// store, while an unreadable stamp is a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// The record's body is erasable, so nothing derived from it may be written down.
    Erasable,
    /// The record is not readable org-wide, so its structure may not enter a shared note.
    Scoped,
    /// The record's server stamp will not parse, so nothing derived from it could be ordered.
    Untimed,
}

/// A record that may contribute to knowledge.
///
/// The gate, and the reason this layer can claim erasure reaches everything it holds. Three
/// conditions, each closing a hole that would otherwise be real:
///
/// - **The body must not be erasable.** A note is an aggregate over many records, and an aggregate
///   cannot be un-aggregated from a backup: subtracting one record's contribution from a note
///   already written is a *data* operation, and data operations reach live copies only — not prior
///   object versions, not last night's copy. So a record whose content is erasable contributes
///   nothing at all, and no knowledge row exists that a key destruction would have to reach. In this
///   contract `data_class: internal` and "names no subject" are the same condition; both are checked
///   anyway, because a stored projection is read back without being revalidated.
/// - **The record must be readable org-wide.** Owner-visible records are stored in a private subtree
///   and team-scoped ones are readable by one team; a note is a shared file with no scope of its own,
///   so deriving from either would move restricted structure somewhere the restriction does not
///   apply. A scoped knowledge tree is a possible later decision, and it should be an explicit one.
/// - **The server stamp must be readable.** Every fact carries a time, first and last observation
///   bound a note's lines, and a record whose stamp will not parse cannot be placed among the rest.
///
/// The type is what enforces this: there is no way to derive from a [`RecordStructure`] except by
/// passing it through [`Derivable::of`] first.
#[derive(Debug, Clone, Copy)]
pub struct Derivable<'a>(&'a RecordStructure);

impl<'a> Derivable<'a> {
    /// Admits a record's structure, or says why it contributes nothing.
    pub fn of(structure: &'a RecordStructure) -> std::result::Result<Self, Ineligible> {
        if structure.data_class != DataClass::Internal || !structure.subjects.is_empty() {
            return Err(Ineligible::Erasable);
        }
        if structure.visibility != Visibility::Org {
            return Err(Ineligible::Scoped);
        }
        if yaam_contract::timestamp::parse_ms(&structure.received_at).is_none() {
            return Err(Ineligible::Untimed);
        }
        Ok(Self(structure))
    }

    /// The structure this was admitted from.
    #[must_use]
    pub fn structure(&self) -> &'a RecordStructure {
        self.0
    }

    /// Everything this record says, as facts.
    ///
    /// Attributes need no filtering: a `sensitive` key is refused on the way in, so every key in
    /// frontmatter is structural by the time it is read back. Entity references below the confidence
    /// bar are dropped — including from the association pairs, so a guessed reference cannot
    /// associate two entities that were never really named together.
    #[must_use]
    pub fn observations(&self) -> Vec<Observation> {
        let record = self.0;
        let certain: Vec<EntityKey> = record
            .entities
            .iter()
            .filter(|entity| entity.confidence >= MIN_CONFIDENCE)
            .map(|entity| EntityKey::new(entity.kind.clone(), entity.id.clone()))
            .collect();

        let mut out = Vec::new();
        for entity in &certain {
            for (key, value) in &record.attrs {
                out.push(self.observed(Fact::Attribute {
                    entity: entity.clone(),
                    key: key.clone(),
                    value: value_text(value),
                }));
            }
            out.push(self.observed(Fact::Actor {
                entity: entity.clone(),
                agent: record.agent.clone(),
            }));
            for other in &certain {
                if other != entity {
                    out.push(self.observed(Fact::Association {
                        entity: entity.clone(),
                        with: other.clone(),
                    }));
                }
            }
        }
        out
    }

    /// Attaches this record's provenance to a fact.
    fn observed(self, fact: Fact) -> Observation {
        Observation {
            fact,
            source: self.0.record_id.clone(),
            at: self.0.received_at.clone(),
        }
    }
}

/// Flattens an attribute value to the text a note carries.
///
/// A note is text, and a fact is compared as text: the store's own attribute rows are text for the
/// same reason. Rendering the value here rather than at the note keeps one spelling of `42`.
fn value_text(value: &attrs::Value) -> String {
    match value {
        attrs::Value::Text(text) => text.clone(),
        attrs::Value::Int(number) => number.to_string(),
        attrs::Value::Bool(flag) => flag.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Derivable, EntityKey, Fact, Ineligible, value_text};
    use crate::testkit;
    use yaam_contract::{RecordStructure, Visibility, attrs};

    #[test]
    fn a_record_yields_one_fact_per_structured_thing_it_says() {
        let structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        let derivable = Derivable::of(&structure).expect("derivable");
        let facts: Vec<Fact> = derivable
            .observations()
            .into_iter()
            .map(|observed| observed.fact)
            .collect();

        let deploy = EntityKey::new("deploy", "api/staging#17");
        let ticket = EntityKey::new("ticket", "PROJ-42");

        // Three attributes and one agent per entity, plus the pair in both directions.
        assert_eq!(facts.len(), 2 * (3 + 1 + 1));
        assert!(facts.contains(&Fact::Attribute {
            entity: deploy.clone(),
            key: "environment".to_owned(),
            value: "staging".to_owned(),
        }));
        assert!(facts.contains(&Fact::Attribute {
            entity: ticket.clone(),
            key: "duration_ms".to_owned(),
            value: "1420".to_owned(),
        }));
        assert!(facts.contains(&Fact::Actor {
            entity: deploy.clone(),
            agent: "agent_a".to_owned(),
        }));
        assert!(facts.contains(&Fact::Association {
            entity: deploy.clone(),
            with: ticket.clone(),
        }));
        assert!(facts.contains(&Fact::Association {
            entity: ticket,
            with: deploy.clone(),
        }));

        // Every fact belongs in the note of the entity it names, and carries where it came from.
        let observed = derivable.observations();
        assert!(observed.iter().all(|o| o.source == structure.record_id));
        assert!(observed.iter().all(|o| o.at == structure.received_at));
        assert_eq!(
            observed
                .iter()
                .filter(|o| *o.fact.entity() == deploy)
                .count(),
            5
        );
    }

    /// The gate is the erasure argument, so each refusal is asserted rather than assumed.
    #[test]
    fn an_erasable_record_contributes_nothing() {
        let structure = testkit::subject_derived_structure("2026-08-22T11:00:00Z");
        assert_eq!(Derivable::of(&structure).err(), Some(Ineligible::Erasable));

        // And a stored projection that is internal but still names a subject: the contract couples
        // the two, and a projection read back off disk is not revalidated, so both are checked.
        let mut inconsistent = testkit::internal_structure("2026-08-20T09:00:00Z");
        inconsistent.subjects = structure.subjects.clone();
        assert_eq!(
            Derivable::of(&inconsistent).err(),
            Some(Ineligible::Erasable)
        );
    }

    #[test]
    fn a_scoped_record_contributes_nothing() {
        for visibility in [Visibility::Owner, Visibility::Team, Visibility::Operator] {
            let mut structure = testkit::internal_structure("2026-08-20T09:00:00Z");
            structure.visibility = visibility;
            structure.team = Some("platform".to_owned());
            assert_eq!(Derivable::of(&structure).err(), Some(Ineligible::Scoped));
        }
    }

    #[test]
    fn a_record_with_an_unreadable_stamp_contributes_nothing() {
        let mut structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        structure.received_at = "the day before yesterday".to_owned();
        assert_eq!(Derivable::of(&structure).err(), Some(Ineligible::Untimed));
    }

    /// A guessed reference is not a fact, and must not associate entities either.
    #[test]
    fn a_reference_below_the_confidence_bar_is_not_a_fact() {
        let mut structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        structure.entities[1].confidence = 0.9;
        let facts: Vec<Fact> = Derivable::of(&structure)
            .expect("derivable")
            .observations()
            .into_iter()
            .map(|observed| observed.fact)
            .collect();

        assert!(facts.iter().all(|fact| fact.entity().kind == "deploy"));
        assert!(
            !facts
                .iter()
                .any(|fact| matches!(fact, Fact::Association { .. })),
            "an uncertain reference cannot associate two entities: {facts:?}"
        );
    }

    #[test]
    fn a_record_naming_no_entity_yields_no_facts() {
        let mut structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        structure.entities.clear();
        assert!(
            Derivable::of(&structure)
                .expect("derivable")
                .observations()
                .is_empty()
        );
    }

    #[test]
    fn every_attribute_type_has_one_spelling() {
        assert_eq!(value_text(&attrs::Value::Text("api".to_owned())), "api");
        assert_eq!(value_text(&attrs::Value::Int(-7)), "-7");
        assert_eq!(value_text(&attrs::Value::Bool(true)), "true");
    }

    /// The input type is the mechanism: a body has nowhere to go.
    #[test]
    fn the_derivation_input_carries_no_prose() {
        let structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        let json = serde_json::to_string(&structure).expect("serialises");
        assert!(!json.contains("summary"), "{json}");
        assert!(serde_json::from_str::<RecordStructure>(&json).is_ok());
    }
}
