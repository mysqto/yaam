//! One entity's note: the file knowledge is kept in, and the way back out of it.
//!
//! A note is Markdown with wikilinks, like the rest of the tree, so an entity's knowledge is
//! readable in an ordinary editor. It is also the only representation: there is no second,
//! machine-readable copy beside it, because two copies of one derivation drift and the tree is what
//! a rebuild has to reproduce. That is what makes the round trip load-bearing rather than a
//! convenience — [`Note::render`] refuses a value it could not read back, instead of writing a line
//! whose provenance would come back wrong.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use yaam_contract::{RecordId, entity::Registry, timestamp};

use crate::fact::{EntityKey, Fact, Observation};
use crate::{Error, Result};

/// The knowledge tree, under the memory root.
pub const KNOWLEDGE_DIR: &str = "knowledge";

/// Notes, one per entity, inside [`KNOWLEDGE_DIR`].
pub const NOTES_DIR: &str = "entities";

/// Extension of every note file.
pub(crate) const NOTE_EXT: &str = "md";

/// Source records listed per fact.
///
/// Bounded for the reason a timeline head is bounded: an entity with twenty thousand references
/// would otherwise make one note larger than the records it summarises, and reading it more
/// expensive than reading the tree. The *count* on each line stays exact — it is the list that is
/// capped, at the newest end, because a reader checking a fact wants the references that are still
/// current.
pub const MAX_SOURCES_PER_FACT: usize = 20;

/// Separator between a fact line's fields.
const FIELD: &str = " · ";

/// Separator between a fact's first and last observation.
const SPAN: &str = " … ";

/// What one note says about one fact.
///
/// The count and the two bounds are aggregates, and they are the reason the whole tree is rebuilt
/// rather than updated in place: there is no way to take one record's contribution back out of a
/// count that has already been written to a file, a backup and an object version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The statement.
    pub fact: Fact,
    /// How many records said it. Exact, whatever `sources` was capped to.
    pub observations: usize,
    /// Server time of the earliest record that said it, verbatim.
    pub first: String,
    /// Server time of the latest, verbatim.
    pub last: String,
    /// The newest records that said it, at most [`MAX_SOURCES_PER_FACT`], newest first.
    pub sources: Vec<RecordId>,
}

/// Everything knowledge holds about one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The entity this note is about.
    pub entity: EntityKey,
    /// What is held about it, in a deterministic order.
    pub facts: Vec<Held>,
}

impl Note {
    /// Groups observations into the notes they belong in.
    ///
    /// One pass over everything derived, because a fact's count and bounds are only known once every
    /// record has been seen. The ordering is total — facts by their own order, sources newest first
    /// and by identifier within one instant — so two rebuilds over one tree produce the same bytes.
    #[must_use]
    pub fn collate(observations: Vec<Observation>) -> Vec<Self> {
        let mut grouped: BTreeMap<EntityKey, BTreeMap<Fact, Vec<Observation>>> = BTreeMap::new();
        for observed in observations {
            grouped
                .entry(observed.fact.entity().clone())
                .or_default()
                .entry(observed.fact.clone())
                .or_default()
                .push(observed);
        }

        grouped
            .into_iter()
            .map(|(entity, facts)| Self {
                entity,
                facts: facts
                    .into_iter()
                    .map(|(fact, seen)| held(fact, seen))
                    .collect(),
            })
            .collect()
    }

    /// Renders the complete note file.
    ///
    /// Refuses a value it could not parse back: every scalar is written inside backticks and every
    /// entity inside a wikilink, so a backtick, a bracket or a newline in one of them would move a
    /// field boundary and make the line say something else. Refusing is the only safe answer — a
    /// note whose fields have shifted reports the wrong provenance for a fact, which is worse than
    /// not reporting it.
    pub fn render(&self) -> Result<String> {
        let mut out = format!("# {}\n\n", link(&self.entity)?);
        out.push_str(
            "Derived from the record tree. Rebuilt wholesale, so nothing here is authoritative: \
             delete it and rebuild.\n\n",
        );
        for held in &self.facts {
            out.push_str(&render_fact(held)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Parses a note file.
    ///
    /// Strict: a line this build cannot read is [`Error::Unreadable`] rather than a line skipped,
    /// because a note is derived and a rebuild is cheap. Silently dropping facts would make a note
    /// that had drifted look like an entity with less history.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let heading = lines
            .next()
            .and_then(|line| line.strip_prefix("# "))
            .ok_or_else(|| Error::Unreadable("no entity heading".to_owned()))?;
        let entity = sole_entity(heading)?;

        let mut facts = Vec::new();
        for line in lines {
            if let Some(body) = line.strip_prefix("- ") {
                facts.push(parse_fact(&entity, body)?);
            }
        }
        Ok(Self { entity, facts })
    }

    /// Text a search matches against.
    ///
    /// Every scalar this note carries, and nothing else: identifiers, attribute keys and values, and
    /// agent names. No prose, because there is none to match — the derivation never had a body.
    #[must_use]
    pub fn searchable_text(&self) -> String {
        let mut out = format!("{}:{}", self.entity.kind, self.entity.id);
        for held in &self.facts {
            out.push(' ');
            match &held.fact {
                Fact::Attribute { key, value, .. } => {
                    out.push_str(key);
                    out.push(' ');
                    out.push_str(value);
                }
                Fact::Actor { agent, .. } => out.push_str(agent),
                Fact::Association { with, .. } => {
                    out.push_str(&with.kind);
                    out.push(':');
                    out.push_str(&with.id);
                }
            }
        }
        out
    }
}

/// Where an entity's note belongs, relative to the memory root.
///
/// The identifier is encoded by the contract's own transform, so an entity holding a `/` becomes one
/// filename rather than a directory level. Then the guard that transform does not give: `.` and `..`
/// survive it unchanged, and either would aim a note out of the knowledge tree.
pub fn note_relative(entity: &EntityKey) -> Result<PathBuf> {
    Ok(Path::new(KNOWLEDGE_DIR).join(note_within(entity)?))
}

/// Where an entity's note belongs inside a knowledge tree, wherever that tree is rooted.
///
/// Separate from [`note_relative`] because a rebuild writes the next tree beside the live one and
/// then swaps it into place: both need the same path under two different roots, and deriving it
/// twice is how the two would come to disagree.
pub(crate) fn note_within(entity: &EntityKey) -> Result<PathBuf> {
    Ok(Path::new(NOTES_DIR)
        .join(segment(&entity.kind)?)
        .join(format!("{}.{NOTE_EXT}", segment(&entity.id)?)))
}

/// One filename-safe path segment, or a refusal.
fn segment(part: &str) -> Result<String> {
    let encoded = Registry::to_path_segment(part);
    if encoded.is_empty()
        || encoded == "."
        || encoded == ".."
        || encoded.contains(['\\', '\0'])
        || encoded.contains(std::path::MAIN_SEPARATOR)
    {
        return Err(Error::Unrenderable(part.to_owned()));
    }
    Ok(encoded)
}

/// Aggregates every observation of one fact into the line a note carries.
fn held(fact: Fact, mut seen: Vec<Observation>) -> Held {
    let observations = seen.len();
    // Newest first, then by identifier so records sharing an instant have one order. Identifiers
    // are ULIDs and so already time-ordered, which makes the tiebreak agree with the clock.
    seen.sort_by(|left, right| {
        stamp(&right.at)
            .cmp(&stamp(&left.at))
            .then_with(|| right.source.as_str().cmp(left.source.as_str()))
    });
    let first = seen.last().map(|o| o.at.clone()).unwrap_or_default();
    let last = seen.first().map(|o| o.at.clone()).unwrap_or_default();
    Held {
        fact,
        observations,
        first,
        last,
        sources: seen
            .into_iter()
            .take(MAX_SOURCES_PER_FACT)
            .map(|observed| observed.source)
            .collect(),
    }
}

/// A server stamp as milliseconds, for ordering only.
///
/// Every observation reaching here came through `Derivable::of`, which refuses a stamp that will not
/// parse, so the fallback cannot be taken by a derived note. It is here rather than an unwrap
/// because a note parsed back off disk carries whatever the file held.
fn stamp(text: &str) -> i64 {
    timestamp::parse_ms(text).unwrap_or(i64::MIN)
}

/// Renders one fact as its line.
fn render_fact(held: &Held) -> Result<String> {
    let mut line = match &held.fact {
        Fact::Attribute { key, value, .. } => {
            format!("- attr {} = {}", quoted(key)?, quoted(value)?)
        }
        Fact::Actor { agent, .. } => format!("- actor {}", quoted(agent)?),
        Fact::Association { with, .. } => format!("- link {}", link(with)?),
    };
    line.push_str(FIELD);
    let _ = write!(line, "seen {}", quoted(&held.observations.to_string())?);
    line.push_str(FIELD);
    line.push_str(&quoted(&held.first)?);
    line.push_str(SPAN);
    line.push_str(&quoted(&held.last)?);
    for source in &held.sources {
        line.push_str(FIELD);
        let _ = write!(line, "[[record:{}]]", source.as_str());
    }
    Ok(line)
}

/// Parses one fact line, in the entity whose note it was found in.
fn parse_fact(entity: &EntityKey, body: &str) -> Result<Held> {
    let (kind, rest) = body
        .split_once(' ')
        .ok_or_else(|| Error::Unreadable(format!("fact line `{body}` has no kind")))?;
    let quotes = quotes(rest);
    let links = yaam_md::wikilink::extract(rest);

    // Field counts differ per kind, and are checked before anything is read out of position.
    let (wanted, entities) = match kind {
        "attr" => (5, 0),
        "actor" => (4, 0),
        "link" => (3, 1),
        other => {
            return Err(Error::Unreadable(format!("unknown fact kind `{other}`")));
        }
    };
    if quotes.len() != wanted || links.len() < entities {
        return Err(Error::Unreadable(format!(
            "fact line `{body}` holds {} quoted field(s) and {} link(s)",
            quotes.len(),
            links.len()
        )));
    }

    let fact = match kind {
        "attr" => Fact::Attribute {
            entity: entity.clone(),
            key: quotes[0].to_owned(),
            value: quotes[1].to_owned(),
        },
        "actor" => Fact::Actor {
            entity: entity.clone(),
            agent: quotes[0].to_owned(),
        },
        _ => Fact::Association {
            entity: entity.clone(),
            with: EntityKey::new(links[0].0.clone(), links[0].1.clone()),
        },
    };

    let counted = quotes[wanted - 3];
    let observations = counted
        .parse::<usize>()
        .map_err(|_| Error::Unreadable(format!("`{counted}` is not an observation count")))?;
    let mut sources = Vec::new();
    for (link_kind, id) in links.into_iter().skip(entities) {
        if link_kind != "record" {
            return Err(Error::Unreadable(format!(
                "fact line `{body}` links a `{link_kind}` where a record belongs"
            )));
        }
        sources.push(RecordId::parse(&id)?);
    }
    Ok(Held {
        fact,
        observations,
        first: quotes[wanted - 2].to_owned(),
        last: quotes[wanted - 1].to_owned(),
        sources,
    })
}

/// The one entity a heading names.
fn sole_entity(heading: &str) -> Result<EntityKey> {
    let mut found = yaam_md::wikilink::extract(heading);
    if found.len() != 1 {
        return Err(Error::Unreadable(format!(
            "heading `{heading}` names {} entities",
            found.len()
        )));
    }
    let (kind, id) = found.remove(0);
    Ok(EntityKey::new(kind, id))
}

/// A scalar inside backticks, or a refusal if it would not survive the round trip.
fn quoted(value: &str) -> Result<String> {
    if value.contains(['`', '\n', '\r']) {
        return Err(Error::Unrenderable(value.to_owned()));
    }
    Ok(format!("`{value}`"))
}

/// An entity as a wikilink, or a refusal.
///
/// Brackets and newlines would move the link boundary; a kind holding a `:` would move the split
/// between kind and identifier, so an entity of kind `a` and id `b:c` and one of kind `a:b` and id
/// `c` would render identically and come back as the same entity.
fn link(entity: &EntityKey) -> Result<String> {
    for part in [&entity.kind, &entity.id] {
        if part.is_empty() || part.contains(['[', ']', '\n', '\r']) {
            return Err(Error::Unrenderable(part.clone()));
        }
    }
    if entity.kind.contains(':') {
        return Err(Error::Unrenderable(entity.kind.clone()));
    }
    Ok(format!("[[{}:{}]]", entity.kind, entity.id))
}

/// Every backtick-quoted span of a line, in order.
///
/// Positional: a line's fields are read by index, so this is what decides what a field *is*. An odd
/// final backtick opens a span nothing closes, and the unterminated remainder is dropped rather than
/// treated as a field — which is caught by the field count, since a dropped span shortens the line.
fn quotes(line: &str) -> Vec<&str> {
    let parts: Vec<&str> = line.split('`').collect();
    // An even number of parts means an odd number of backticks: the last span was opened and never
    // closed, so it is not a field.
    let complete = if parts.len().is_multiple_of(2) {
        parts.len() - 1
    } else {
        parts.len()
    };
    parts
        .into_iter()
        .take(complete)
        .skip(1)
        .step_by(2)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Held, MAX_SOURCES_PER_FACT, Note, note_relative, quotes, render_fact, segment};
    use crate::fact::{Derivable, EntityKey, Fact, Observation};
    use crate::testkit;
    use yaam_contract::RecordId;

    /// An observation of one fact at one time, from a fresh record.
    fn seen(fact: Fact, at: &str) -> Observation {
        Observation {
            fact,
            source: RecordId::generate(),
            at: at.to_owned(),
        }
    }

    fn deploy() -> EntityKey {
        EntityKey::new("deploy", "api/staging#17")
    }

    #[test]
    fn a_note_collates_every_observation_of_one_fact() {
        let fact = Fact::Actor {
            entity: deploy(),
            agent: "agent_a".to_owned(),
        };
        let notes = Note::collate(vec![
            seen(fact.clone(), "2026-08-21T10:30:00.500Z"),
            seen(fact.clone(), "2026-08-20T09:00:00Z"),
            seen(fact.clone(), "2026-08-22T11:00:00Z"),
        ]);

        assert_eq!(notes.len(), 1);
        let held = &notes[0].facts[0];
        assert_eq!(held.fact, fact);
        assert_eq!(held.observations, 3);
        assert_eq!(held.first, "2026-08-20T09:00:00Z");
        assert_eq!(held.last, "2026-08-22T11:00:00Z");
        assert_eq!(held.sources.len(), 3);
    }

    #[test]
    fn a_note_round_trips_through_its_file() {
        let structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        let notes = Note::collate(Derivable::of(&structure).expect("derivable").observations());
        assert_eq!(notes.len(), 2, "one note per entity named");

        for note in notes {
            let rendered = note.render().expect("renders");
            assert_eq!(Note::parse(&rendered).expect("parses"), note);
            // The line a person reads is the line the parser reads.
            assert!(rendered.starts_with("# [["), "{rendered}");
        }
    }

    #[test]
    fn every_fact_kind_round_trips() {
        let facts = [
            Fact::Attribute {
                entity: deploy(),
                key: "environment".to_owned(),
                value: "staging".to_owned(),
            },
            Fact::Actor {
                entity: deploy(),
                agent: "agent_a".to_owned(),
            },
            Fact::Association {
                entity: deploy(),
                with: EntityKey::new("ticket", "PROJ-42"),
            },
        ];
        let notes = Note::collate(
            facts
                .iter()
                .map(|fact| seen(fact.clone(), "2026-08-20T09:00:00Z"))
                .collect(),
        );
        let rendered = notes[0].render().expect("renders");
        assert_eq!(Note::parse(&rendered).expect("parses"), notes[0]);
        assert_eq!(notes[0].facts.len(), 3);
    }

    /// The count stays exact when the list is capped, or a reader would think an entity quieter
    /// than it is.
    #[test]
    fn provenance_is_capped_and_the_count_is_not() {
        let fact = Fact::Actor {
            entity: deploy(),
            agent: "agent_a".to_owned(),
        };
        let observed: Vec<Observation> = (0..MAX_SOURCES_PER_FACT + 5)
            .map(|_| seen(fact.clone(), "2026-08-20T09:00:00Z"))
            .collect();
        let newest = observed
            .iter()
            .map(|o| o.source.as_str().to_owned())
            .max()
            .expect("some");

        let notes = Note::collate(observed);
        let held = &notes[0].facts[0];
        assert_eq!(held.observations, MAX_SOURCES_PER_FACT + 5);
        assert_eq!(held.sources.len(), MAX_SOURCES_PER_FACT);
        assert_eq!(held.sources[0].as_str(), newest, "newest first");
        assert_eq!(
            Note::parse(&notes[0].render().expect("renders")).expect("parses"),
            notes[0]
        );
    }

    #[test]
    fn a_value_that_would_shift_a_field_is_refused() {
        let unrenderable = [
            Fact::Attribute {
                entity: deploy(),
                key: "note".to_owned(),
                value: "holds a ` backtick".to_owned(),
            },
            Fact::Actor {
                entity: deploy(),
                agent: "two\nlines".to_owned(),
            },
            Fact::Association {
                entity: deploy(),
                with: EntityKey::new("ticket", "PROJ]]-42"),
            },
            Fact::Association {
                entity: deploy(),
                with: EntityKey::new("a:b", "c"),
            },
            Fact::Association {
                entity: deploy(),
                with: EntityKey::new("ticket", String::new()),
            },
        ];
        for fact in unrenderable {
            let notes = Note::collate(vec![seen(fact.clone(), "2026-08-20T09:00:00Z")]);
            assert!(notes[0].render().is_err(), "{fact:?}");
        }
    }

    #[test]
    fn a_note_this_build_cannot_read_is_refused() {
        for text in [
            "no heading at all\n",
            "# not a wikilink\n",
            "# [[a:b]] [[c:d]]\n",
            "# [[deploy:api]]\n- attr\n",
            "# [[deploy:api]]\n- rumour `x` · seen `1` · `t` … `t`\n",
            "# [[deploy:api]]\n- actor `a` · seen `1` · `t`\n",
            "# [[deploy:api]]\n- actor `a` · seen `many` · `t` … `t`\n",
            "# [[deploy:api]]\n- actor `a` · seen `1` · `t` … `t` · [[ticket:PROJ-1]]\n",
            "# [[deploy:api]]\n- actor `a` · seen `1` · `t` … `t` · [[record:nope]]\n",
            "# [[deploy:api]]\n- link `a` · seen `1` · `t` … `t`\n",
        ] {
            assert!(Note::parse(text).is_err(), "{text:?}");
        }
    }

    /// Prose is what a note has none of, checked on the rendered file rather than the type.
    #[test]
    fn a_note_carries_no_prose_and_no_ciphertext() {
        let structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        let notes = Note::collate(Derivable::of(&structure).expect("derivable").observations());
        for note in &notes {
            let rendered = note.render().expect("renders");
            assert!(!rendered.contains("```sealed"), "{rendered}");
            assert!(!rendered.contains(testkit::BODY), "{rendered}");
            assert!(!rendered.contains("summary"), "{rendered}");
        }
        assert!(notes[0].searchable_text().contains("staging"));
        assert!(notes[0].searchable_text().contains("agent_a"));
        assert!(!notes[0].searchable_text().contains(testkit::BODY));
    }

    #[test]
    fn a_notes_path_encodes_the_identifier_rather_than_splitting_it() {
        assert_eq!(
            note_relative(&deploy()).expect("a path"),
            std::path::PathBuf::from("knowledge/entities/deploy/api~sstaging~h17.md")
        );
    }

    /// `.` and `..` survive the encoding untouched, and either would aim a note out of the tree.
    #[test]
    fn an_entity_that_cannot_name_a_file_is_refused() {
        for part in ["", ".", "..", "a\\b"] {
            assert!(segment(part).is_err(), "{part:?}");
            assert!(
                note_relative(&EntityKey::new("deploy", part)).is_err(),
                "{part:?}"
            );
            assert!(
                note_relative(&EntityKey::new(part, "api")).is_err(),
                "{part:?}"
            );
        }
    }

    #[test]
    fn an_unterminated_quote_shortens_the_line_rather_than_becoming_a_field() {
        assert_eq!(quotes("`a` and `b`"), ["a", "b"]);
        assert_eq!(quotes("`a` and `unterminated"), ["a"]);
        assert!(quotes("nothing quoted").is_empty());
    }

    /// A note with no facts is still a note: an entity may be named by nothing but a record that
    /// has since left the tree, and an empty file says so where a missing one says nothing.
    #[test]
    fn a_note_with_no_facts_round_trips() {
        let note = Note {
            entity: deploy(),
            facts: Vec::new(),
        };
        let rendered = note.render().expect("renders");
        assert_eq!(Note::parse(&rendered).expect("parses"), note);
        assert!(!note.searchable_text().is_empty());
    }

    #[test]
    fn a_fact_with_no_sources_still_renders_its_bounds() {
        let held = Held {
            fact: Fact::Actor {
                entity: deploy(),
                agent: "agent_a".to_owned(),
            },
            observations: 0,
            first: String::new(),
            last: String::new(),
            sources: Vec::new(),
        };
        let line = render_fact(&held).expect("renders");
        assert!(line.contains("seen `0`"), "{line}");
    }
}
