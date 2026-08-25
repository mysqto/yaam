//! Reading knowledge back.
//!
//! Three reads, and one rule across all of them: a read hands back facts and the identifiers of the
//! records behind them, or it hands back record *structure*. Never prose — there is none to hand
//! back, because the derivation never had a body and a note holds no line that came from one.

use std::fs;
use std::io;
use std::path::Path;

use yaam_contract::{RecordId, RecordStructure};

use crate::Result;
use crate::fact::{Derivable, EntityKey};
use crate::note::{KNOWLEDGE_DIR, NOTES_DIR, Note, note_relative};

/// What one entity's note says, or `None` if knowledge holds nothing about it.
///
/// The note is parsed rather than returned as text, so a file this build cannot read is an error
/// instead of a caller's parsing problem. Identifiers are taken as given: the write path
/// canonicalised them, and canonicalising again here would need the entity registry and would be a
/// second implementation of the rules the tree was written under.
pub fn lookup(root: &Path, entity: &EntityKey) -> Result<Option<Note>> {
    let path = root.join(note_relative(entity)?);
    match fs::read_to_string(&path) {
        Ok(text) => Note::parse(&text).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Notes whose scalars contain `term`, case-insensitively, newest path order first.
///
/// A substring match over each note's own scalars — identifiers, attribute keys and values, agent
/// names — and not full-text search. The plan puts knowledge's full-text index in the shared
/// `SQLite` file alongside memory's; this layer does not own that file, and a private index would be
/// a second derived copy of a derived tree. Saying which of the two this is matters: a caller that
/// expected stemming and ranking would read an empty answer as "nothing known".
pub fn search(root: &Path, term: &str, limit: usize) -> Result<Vec<Note>> {
    if term.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    let needle = term.to_lowercase();
    let mut found = Vec::new();
    for path in note_files(root)? {
        if found.len() == limit {
            break;
        }
        let note = Note::parse(&fs::read_to_string(&path)?)?;
        if note.searchable_text().to_lowercase().contains(&needle) {
            found.push(note);
        }
    }
    Ok(found)
}

/// The structure of the records behind a fact, in the order asked.
///
/// Structure, never a body: [`RecordStructure`] has no field for prose, which is what makes "the
/// evidence for a fact is checkable without reading anybody's data" true rather than intended.
///
/// Every candidate goes back through the same gate that admitted the fact. An identifier naming a
/// record this layer would not have derived from is *not* returned, because otherwise a caller could
/// read a scoped record's structure by guessing its identifier — the read path would have become a
/// way around the boundary the derivation respects.
///
/// One walk of the record tree per call, because a record's path is derived from its timestamp and an
/// identifier does not carry one. That is the same trade the fan-out drain makes, and the reason this
/// takes a list rather than one identifier at a time.
pub fn evidence(root: &Path, sources: &[RecordId]) -> Result<Vec<RecordStructure>> {
    if sources.is_empty() {
        return Ok(Vec::new());
    }
    let (structures, _) = crate::build::read_structures(root)?;
    let admitted: Vec<RecordStructure> = structures
        .into_iter()
        .filter(|structure| Derivable::of(structure).is_ok())
        .collect();

    Ok(sources
        .iter()
        .filter_map(|wanted| {
            admitted
                .iter()
                .find(|structure| structure.record_id == *wanted)
                .cloned()
        })
        .collect())
}

/// Every note file, in a deterministic order.
fn note_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let dir = root.join(KNOWLEDGE_DIR).join(NOTES_DIR);
    let mut found = Vec::new();
    let mut pending = vec![dir];
    while let Some(next) = pending.pop() {
        let entries = match fs::read_dir(&next) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|ext| ext == crate::note::NOTE_EXT)
            {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{evidence, lookup, search};
    use crate::build::rebuild;
    use crate::fact::EntityKey;
    use crate::note::{KNOWLEDGE_DIR, NOTES_DIR};
    use crate::testkit::{self, Harness};
    use std::fs;
    use yaam_contract::RecordId;

    fn populated() -> (Harness, RecordId) {
        let mut harness = Harness::new();
        let first = testkit::internal("2026-08-20T09:00:00Z");
        let id = first.record_id.clone();
        harness.accept(first);
        harness.accept(testkit::internal("2026-08-21T10:30:00.500Z"));
        harness.accept(testkit::subject_derived(
            "2026-08-22T11:00:00Z",
            &[testkit::subject('a')],
        ));
        harness.accept(testkit::owner("2026-08-22T11:30:00Z", "agent_b"));
        rebuild(harness.root()).expect("rebuilt");
        (harness, id)
    }

    #[test]
    fn a_lookup_answers_with_the_note_or_with_nothing() {
        let (harness, _) = populated();
        let note = lookup(harness.root(), &EntityKey::new("deploy", "api/staging#17"))
            .expect("lookup")
            .expect("a note");
        assert_eq!(note.entity.id, "api/staging#17");
        assert_eq!(note.facts.len(), 5);
        assert!(note.facts.iter().all(|held| held.observations == 2));

        assert!(
            lookup(harness.root(), &EntityKey::new("deploy", "api/prod#1"))
                .expect("lookup")
                .is_none()
        );
        // The erasable record's entity was never derived from, so knowledge holds nothing about it.
        assert!(
            lookup(harness.root(), &EntityKey::new("order_ref", "ord10014721"))
                .expect("lookup")
                .is_none()
        );
        // An entity that cannot name a file is refused rather than looked up somewhere else.
        assert!(lookup(harness.root(), &EntityKey::new("deploy", "..")).is_err());
    }

    #[test]
    fn a_search_matches_the_scalars_a_note_carries() {
        let (harness, _) = populated();
        assert_eq!(
            search(harness.root(), "STAGING", 10).expect("search").len(),
            2
        );
        assert_eq!(
            search(harness.root(), "PROJ-42", 10).expect("search").len(),
            2
        );
        assert_eq!(
            search(harness.root(), "agent_a", 10).expect("search").len(),
            2
        );
        assert_eq!(
            search(harness.root(), "agent_a", 1).expect("search").len(),
            1
        );
        assert!(
            search(harness.root(), "nothing here", 10)
                .expect("search")
                .is_empty()
        );
        assert!(search(harness.root(), "", 10).expect("search").is_empty());
        assert!(
            search(harness.root(), "staging", 0)
                .expect("search")
                .is_empty()
        );
        // A body is not searchable because it was never read.
        assert!(
            search(harness.root(), testkit::BODY, 10)
                .expect("search")
                .is_empty()
        );
    }

    #[test]
    fn a_note_the_reader_refuses_fails_both_reads() {
        let (harness, _) = populated();
        let path = harness
            .root()
            .join(KNOWLEDGE_DIR)
            .join(NOTES_DIR)
            .join("ticket/PROJ-42.md");
        fs::write(&path, "not a note at all\n").expect("write");

        // The same file, refused the same way by both reads: a reader that skipped an unreadable
        // note in one path and refused it in the other would be answering two questions.
        let error =
            lookup(harness.root(), &EntityKey::new("ticket", "PROJ-42")).expect_err("refused");
        assert!(matches!(error, crate::Error::Unreadable(_)), "{error}");
        assert!(search(harness.root(), "staging", 10).is_err());
    }

    #[test]
    fn evidence_hands_back_structure_and_nothing_else() {
        let (harness, id) = populated();
        let note = lookup(harness.root(), &EntityKey::new("ticket", "PROJ-42"))
            .expect("lookup")
            .expect("a note");
        let sources = &note.facts[0].sources;
        assert_eq!(sources.len(), 2);

        let found = evidence(harness.root(), sources).expect("evidence");
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|structure| structure.record_id == id));
        let json = serde_json::to_string(&found).expect("serialises");
        assert!(!json.contains("summary"), "{json}");
        assert!(!json.contains(testkit::BODY), "{json}");

        assert!(evidence(harness.root(), &[]).expect("evidence").is_empty());
    }

    /// The read path applies the same gate the derivation does, or it becomes a way around it.
    #[test]
    fn evidence_refuses_a_record_the_derivation_would_not_have_used() {
        let mut harness = Harness::new();
        let owned = testkit::owner("2026-08-22T11:30:00Z", "agent_b");
        let sealed = testkit::subject_derived("2026-08-22T11:00:00Z", &[testkit::subject('a')]);
        let wanted = vec![owned.record_id.clone(), sealed.record_id.clone()];
        harness.accept(owned);
        harness.accept(sealed);
        rebuild(harness.root()).expect("rebuilt");

        assert!(
            evidence(harness.root(), &wanted)
                .expect("evidence")
                .is_empty(),
            "a scoped or erasable record's structure is not reachable by naming it"
        );
    }
}
