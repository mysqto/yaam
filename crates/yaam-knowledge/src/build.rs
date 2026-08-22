//! Rebuilding the knowledge tree from the record tree.
//!
//! This is the operation that proves knowledge is derived, and it is the only way knowledge is ever
//! written. There is no incremental update, deliberately: a note's counts and bounds are aggregates,
//! and there is no way to take one record's contribution back out of a count already written to a
//! file — and from there to a backup and an object version. Rebuilding wholesale means every note is
//! a statement about the tree *as it now stands*, so a record that has left the tree, or a body that
//! has been erased, is gone from knowledge on the next rebuild without anything having to chase it.
//!
//! Durability is deliberately not claimed. A knowledge tree is derived and disposable, so nothing
//! here fsyncs: the recovery for a lost or half-written tree is another rebuild, and pretending
//! otherwise would be a guarantee with no mechanism behind it. What *is* defined is the crash
//! window — see [`rebuild`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use yaam_contract::RecordStructure;
use yaam_md::Document;

use crate::fact::{Derivable, Ineligible};
use crate::note::{KNOWLEDGE_DIR, NOTES_DIR, Note};
use crate::{Error, Result};

/// The authoritative record tree, under the memory root.
///
/// Named here rather than imported because `yaam-core` keeps its layout private, and a knowledge
/// rebuild reading a directory nothing writes would report an empty store rather than fail. The
/// tests write through the real pipeline for exactly that reason: a wrong name here finds no records
/// and no test passes.
const RECORDS_DIR: &str = "records";

/// Manifests of archived records, still one frontmatter projection per line.
const COLD_DIR: &str = "cold";

/// Extension of every record file.
const RECORD_EXT: &str = "md";

/// Extension of every cold manifest.
const MANIFEST_EXT: &str = "jsonl";

/// Where the next knowledge tree is assembled before it replaces the live one.
const REBUILD_DIR: &str = ".rebuild";

/// Holds what the last rebuild read, inside the knowledge tree.
const STATE_DIR: &str = ".index";

/// The file itself.
const STATE_FILE: &str = "sync-state.json";

/// What a rebuild produced.
///
/// The three exclusion counts are separate because they mean different things to an operator.
/// `skipped_erasable` is *expected* — it measures how much of the store is erasable, and a zero
/// there in a store with subject-derived records would mean the gate had stopped working.
/// `skipped_unreadable` is a fault.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildReport {
    /// Record structures read, from the live tree and from cold manifests.
    pub records_read: usize,
    /// Of those, the ones that contributed.
    pub records_used: usize,
    /// Excluded because their bodies are erasable.
    pub skipped_erasable: usize,
    /// Excluded because they are not readable org-wide.
    pub skipped_scoped: usize,
    /// Excluded because their server stamp would not parse.
    pub skipped_untimed: usize,
    /// Files and manifest lines that would not parse at all.
    pub skipped_unreadable: usize,
    /// Entities that ended up with a note.
    pub entities: usize,
    /// Facts across every note.
    pub facts: usize,
}

/// What the last rebuild read, and when.
///
/// Every field but `rebuilt_ms` is derived from the tree; that one is read from the clock, and is the
/// reason this file is compared separately from the notes when a test asks whether two rebuilds
/// agree. It is here because an operator has to be able to tell a knowledge tree that is current
/// from one whose rebuild stopped running a week ago.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// When the rebuild finished, in milliseconds since the Unix epoch.
    pub rebuilt_ms: i64,
    /// Record structures read.
    pub records_read: usize,
    /// Of those, the ones that contributed.
    pub records_used: usize,
    /// Entities holding a note.
    pub entities: usize,
    /// Facts across every note.
    pub facts: usize,
}

/// Rebuilds the knowledge tree in place.
///
/// The next tree is assembled under `knowledge/.rebuild/` and swapped in by a rename, so a reader
/// sees either the previous tree or the new one and never a half-written mixture of the two.
///
/// The crash window, stated rather than glossed: the state file is removed *before* the swap and
/// written *after* it, so a rebuild that dies part way leaves no state file. "No state file" is
/// therefore a definite answer — this tree is mid-rebuild or has never been built — where a stale
/// one left in place would have described a tree that is no longer there. Recovery is to run this
/// again.
pub fn rebuild(root: &Path) -> Result<BuildReport> {
    let (structures, skipped_unreadable) = read_structures(root)?;
    let mut report = BuildReport {
        records_read: structures.len(),
        skipped_unreadable,
        ..BuildReport::default()
    };

    let mut observations = Vec::new();
    for structure in &structures {
        match Derivable::of(structure) {
            Ok(derivable) => {
                report.records_used += 1;
                observations.extend(derivable.observations());
            }
            Err(Ineligible::Erasable) => report.skipped_erasable += 1,
            Err(Ineligible::Scoped) => report.skipped_scoped += 1,
            Err(Ineligible::Untimed) => report.skipped_untimed += 1,
        }
    }

    let notes = Note::collate(observations);
    report.entities = notes.len();
    report.facts = notes.iter().map(|note| note.facts.len()).sum();

    publish(root, &notes)?;
    write_state(root, &report)?;
    Ok(report)
}

/// What the last rebuild recorded, or `None` if none has completed.
pub fn state(root: &Path) -> Result<Option<SyncState>> {
    let path = root.join(KNOWLEDGE_DIR).join(STATE_DIR).join(STATE_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| Error::Unreadable(format!("{STATE_FILE}: {error}"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Every record structure the tree still holds, and how many sources would not parse.
///
/// The live tree and the cold manifests both, because an archived record's structure is still in the
/// tree — a manifest line *is* the frontmatter projection — and knowledge that vanished when a record
/// was archived would not be a function of the tree.
///
/// Nothing here looks at a body. A plaintext record's prose is restored onto `summary` by
/// [`Document::parse`], and the projection onto [`RecordStructure`] is what drops it again: there is
/// no field for it to land in. That is the whole mechanism, and it holds for a sealed record without
/// a second branch.
pub(crate) fn read_structures(root: &Path) -> Result<(Vec<RecordStructure>, usize)> {
    let mut found = Vec::new();
    let mut unreadable = 0;

    for path in walk(&root.join(RECORDS_DIR), RECORD_EXT)? {
        match Document::parse(&fs::read_to_string(&path)?) {
            Ok(document) => found.push(RecordStructure::from(&document.record)),
            Err(_) => unreadable += 1,
        }
    }

    for path in walk(&root.join(COLD_DIR), MANIFEST_EXT)? {
        for line in fs::read_to_string(&path)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<RecordStructure>(line) {
                Ok(structure) => found.push(structure),
                Err(_) => unreadable += 1,
            }
        }
    }

    Ok((found, unreadable))
}

/// Writes the notes into a fresh tree and swaps it into place.
fn publish(root: &Path, notes: &[Note]) -> Result<()> {
    let knowledge = root.join(KNOWLEDGE_DIR);
    let staging = knowledge.join(REBUILD_DIR);
    // A leftover from a rebuild that died is not a partial answer worth keeping.
    remove_dir_if_present(&staging)?;
    fs::create_dir_all(staging.join(NOTES_DIR))?;

    for note in notes {
        let path = staging.join(crate::note::note_within(&note.entity)?);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, note.render()?)?;
    }

    // The state file goes before the swap, so a crash between the two cannot leave a state file
    // describing a tree that is no longer there.
    remove_file_if_present(&knowledge.join(STATE_DIR).join(STATE_FILE))?;
    let live = knowledge.join(NOTES_DIR);
    remove_dir_if_present(&live)?;
    fs::rename(staging.join(NOTES_DIR), &live)?;
    remove_dir_if_present(&staging)?;
    Ok(())
}

/// Records what this rebuild read.
fn write_state(root: &Path, report: &BuildReport) -> Result<()> {
    let dir = root.join(KNOWLEDGE_DIR).join(STATE_DIR);
    fs::create_dir_all(&dir)?;
    let state = SyncState {
        rebuilt_ms: now_ms(),
        records_read: report.records_read,
        records_used: report.records_used,
        entities: report.entities,
        facts: report.facts,
    };
    let text = serde_json::to_string_pretty(&state)
        .map_err(|error| Error::Unrenderable(error.to_string()))?;
    fs::write(dir.join(STATE_FILE), text)?;
    Ok(())
}

/// Every file under `dir` with this extension, in a deterministic order.
///
/// A missing directory is an empty answer, not a failure: a store that has never been written to has
/// no record tree, and a rebuild over it should produce an empty knowledge tree rather than an error.
fn walk(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
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
            } else if path.extension().is_some_and(|found| found == ext) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Removes a directory and everything under it, if it is there.
fn remove_dir_if_present(dir: &Path) -> Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Removes a file, if it is there.
fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The wall clock in milliseconds since the Unix epoch.
///
/// Saturating rather than panicking: a clock before the epoch is a misconfigured host, and a rebuild
/// is not the place to discover it.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Observations of every derivable record in a tree, for the tests that need them directly.
#[cfg(test)]
pub(crate) fn observations(root: &Path) -> Result<Vec<crate::fact::Observation>> {
    let (structures, _) = read_structures(root)?;
    Ok(structures
        .iter()
        .filter_map(|structure| Derivable::of(structure).ok())
        .flat_map(|derivable| derivable.observations())
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::{NOTES_DIR, REBUILD_DIR, observations, rebuild, state};
    use crate::note::KNOWLEDGE_DIR;
    use crate::testkit::{self, Harness};

    /// Every note file in a knowledge tree, by path, so two rebuilds compare file by file.
    ///
    /// The state file is excluded: its `rebuilt_ms` is read from the clock, so it is the one thing a
    /// rebuild cannot be expected to reproduce.
    fn notes(harness: &Harness) -> BTreeMap<String, String> {
        let dir = harness.root().join(KNOWLEDGE_DIR).join(NOTES_DIR);
        let mut found = BTreeMap::new();
        let mut pending = vec![dir.clone()];
        while let Some(next) = pending.pop() {
            let Ok(entries) = fs::read_dir(&next) else {
                continue;
            };
            for entry in entries {
                let entry = entry.expect("entry");
                let path = entry.path();
                if entry.file_type().expect("type").is_dir() {
                    pending.push(path);
                } else {
                    let key = path
                        .strip_prefix(&dir)
                        .expect("under the notes directory")
                        .to_string_lossy()
                        .into_owned();
                    found.insert(key, fs::read_to_string(&path).expect("read"));
                }
            }
        }
        found
    }

    /// A store holding one of each kind of record the gate has to decide about.
    fn populated() -> Harness {
        let mut harness = Harness::new();
        for received_at in ["2026-08-20T09:00:00Z", "2026-08-21T10:30:00.500Z"] {
            harness.accept(testkit::internal(received_at));
        }
        harness.accept(testkit::subject_derived(
            "2026-08-22T11:00:00Z",
            &[testkit::subject('a')],
        ));
        harness.accept(testkit::owner("2026-08-22T11:30:00Z", "agent_b"));
        harness.pipeline.drain_fanout(100).expect("drained");
        harness
    }

    #[test]
    fn a_rebuild_derives_a_note_per_entity_and_says_what_it_left_out() {
        let harness = populated();
        let report = rebuild(harness.root()).expect("rebuilt");

        assert_eq!(report.records_read, 4);
        assert_eq!(report.records_used, 2, "two org-wide internal records");
        assert_eq!(report.skipped_erasable, 1);
        assert_eq!(report.skipped_scoped, 1);
        assert_eq!(report.skipped_untimed, 0);
        assert_eq!(report.skipped_unreadable, 0);

        // Both records name the same two entities, so knowledge holds two notes.
        assert_eq!(report.entities, 2);
        let files = notes(&harness);
        assert_eq!(files.len(), 2);
        assert!(
            files.contains_key("deploy/api~sstaging~h17.md"),
            "{files:?}"
        );
        assert!(files.contains_key("ticket/PROJ-42.md"), "{files:?}");

        // Each note holds three attributes, one actor and one association, each seen twice.
        assert_eq!(report.facts, 2 * 5);
        let deploy = &files["deploy/api~sstaging~h17.md"];
        assert!(
            deploy.contains("- attr `environment` = `staging`"),
            "{deploy}"
        );
        assert!(deploy.contains("- actor `agent_a`"), "{deploy}");
        assert!(deploy.contains("- link [[ticket:PROJ-42]]"), "{deploy}");
        assert!(deploy.contains("seen `2`"), "{deploy}");

        let recorded = state(harness.root()).expect("state").expect("a state file");
        assert_eq!(recorded.records_read, 4);
        assert_eq!(recorded.records_used, 2);
        assert_eq!(recorded.entities, 2);
        assert_eq!(recorded.facts, 10);
        assert!(recorded.rebuilt_ms > 0);
    }

    #[test]
    fn a_rebuild_is_idempotent() {
        let harness = populated();
        rebuild(harness.root()).expect("rebuilt");
        let once = notes(&harness);
        let report = rebuild(harness.root()).expect("rebuilt again");
        assert_eq!(notes(&harness), once);
        assert_eq!(report.entities, 2);
        // Nothing is left behind beside the live tree.
        assert!(
            !harness
                .root()
                .join(KNOWLEDGE_DIR)
                .join(REBUILD_DIR)
                .exists()
        );
    }

    /// The property the whole layer rests on: a record that has left the tree takes its knowledge
    /// with it. This is also the mechanism erasure relies on — knowledge says only what the tree
    /// still says.
    #[test]
    fn knowledge_holds_only_what_the_tree_still_says() {
        let mut harness = Harness::new();
        let first = testkit::internal("2026-08-20T09:00:00Z");
        let path = harness.root().join(format!(
            "records/2026/08/20/{}.md",
            first.record_id.as_str()
        ));
        harness.accept(first);
        harness.accept(testkit::internal("2026-08-21T09:00:00Z"));

        let before = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(before.records_used, 2);
        assert!(notes(&harness)["ticket/PROJ-42.md"].contains("seen `2`"));

        fs::remove_file(&path).expect("remove");
        let after = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(after.records_used, 1);
        assert!(notes(&harness)["ticket/PROJ-42.md"].contains("seen `1`"));
    }

    #[test]
    fn an_archived_records_structure_still_contributes() {
        let mut harness = Harness::new();
        harness.accept(testkit::internal("2026-08-20T09:00:00Z"));

        // A cold manifest is the frontmatter projection, one record per line — the same shape a read
        // returns, so it carries no body to begin with.
        let archived = testkit::internal_structure("2026-01-05T08:00:00Z");
        let mut lines = serde_json::to_string(&archived).expect("line");
        lines.push('\n');
        lines.push_str("{\"not\": \"a record\"}\n");
        lines.push('\n');
        fs::create_dir_all(harness.root().join("cold")).expect("cold dir");
        fs::write(harness.root().join("cold/2026-01.jsonl"), lines).expect("manifest");

        let report = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(report.records_read, 2);
        assert_eq!(report.records_used, 2);
        assert_eq!(report.skipped_unreadable, 1);
        assert!(notes(&harness)["ticket/PROJ-42.md"].contains("seen `2`"));
    }

    #[test]
    fn a_file_that_will_not_parse_is_counted_and_skipped() {
        let harness = populated();
        fs::write(
            harness.root().join("records/2026/08/20/broken.md"),
            "---\naction: [unclosed\n---\nbody\n",
        )
        .expect("write");

        let report = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(report.skipped_unreadable, 1);
        assert_eq!(report.records_used, 2, "one bad file aborts nothing");
    }

    #[test]
    fn a_record_with_an_unreadable_stamp_is_counted_apart() {
        let mut harness = Harness::new();
        harness.accept(testkit::internal("2026-08-20T09:00:00Z"));

        // Written straight into a manifest: the write path refuses such a record, and the reason
        // this case exists at all is a projection restored from somewhere that did not.
        let mut structure = testkit::internal_structure("2026-08-20T09:00:00Z");
        structure.received_at = "sometime".to_owned();
        let line = format!("{}\n", serde_json::to_string(&structure).expect("line"));
        fs::create_dir_all(harness.root().join("cold")).expect("cold dir");
        fs::write(harness.root().join("cold/odd.jsonl"), line).expect("manifest");

        let report = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(report.skipped_untimed, 1);
        assert_eq!(report.records_used, 1);
    }

    #[test]
    fn an_empty_store_rebuilds_to_an_empty_tree() {
        let harness = Harness::new();
        let report = rebuild(harness.root()).expect("rebuilt");
        assert_eq!(report, super::BuildReport::default());
        assert!(notes(&harness).is_empty());
        assert!(state(harness.root()).expect("state").is_some());
    }

    /// A rebuild that died leaves no state file, and its staging tree is not mistaken for an answer.
    #[test]
    fn a_stale_staging_tree_is_discarded_and_a_missing_state_file_is_no_state() {
        let harness = populated();
        rebuild(harness.root()).expect("rebuilt");

        let staging = harness.root().join(KNOWLEDGE_DIR).join(REBUILD_DIR);
        fs::create_dir_all(staging.join(NOTES_DIR).join("deploy")).expect("staging");
        fs::write(
            staging.join(NOTES_DIR).join("deploy/stale.md"),
            "# [[a:b]]\n",
        )
        .expect("a note from a rebuild that died");
        fs::remove_file(
            harness
                .root()
                .join(KNOWLEDGE_DIR)
                .join(".index")
                .join("sync-state.json"),
        )
        .expect("remove");
        assert!(state(harness.root()).expect("state").is_none());

        rebuild(harness.root()).expect("rebuilt");
        assert!(!notes(&harness).contains_key("deploy/stale.md"));
        assert!(state(harness.root()).expect("state").is_some());
    }

    #[test]
    fn an_unreadable_state_file_is_reported_rather_than_ignored() {
        let harness = populated();
        rebuild(harness.root()).expect("rebuilt");
        fs::write(
            harness
                .root()
                .join(KNOWLEDGE_DIR)
                .join(".index")
                .join("sync-state.json"),
            "not json",
        )
        .expect("write");
        assert!(state(harness.root()).is_err());
    }

    /// Derivation never sees a body, and the tree is where that is worth checking: a plaintext
    /// record's prose is on `summary` after parsing, and the projection is what drops it.
    #[test]
    fn no_body_reaches_derivation_from_the_tree() {
        let harness = populated();
        for observed in observations(harness.root()).expect("observations") {
            let rendered = format!("{observed:?}");
            assert!(!rendered.contains(testkit::BODY), "{rendered}");
        }
    }

    /// Erasure, and whether it reaches everything this layer holds.
    ///
    /// A note is an aggregate, and an aggregate is the shape of thing crypto-shredding cannot reach:
    /// destroying a key makes a *body* unreadable in every copy, but a count already written into a
    /// note, a backup and an object version can only be corrected by a data operation, and data
    /// operations reach live copies only. So the gate is the mechanism — an erasable record
    /// contributes nothing, and there is no row for a key destruction to have to reach.
    ///
    /// These tests check that from both sides: that nothing erasable reaches a note, and that the
    /// records a note *does* name are records no key protects.
    mod erasure {
        use super::{notes, populated, rebuild};
        use crate::note::Note;
        use crate::testkit::{self, Harness};
        use crate::{Derivable, fact::Fact};
        use std::fs;
        use yaam_contract::DataClass;

        /// Every note file's text, concatenated, for the scans that must find nothing.
        fn all_text(harness: &Harness) -> String {
            notes(harness).into_values().collect::<Vec<_>>().join("\n")
        }

        #[test]
        fn nothing_erasable_reaches_a_note() {
            let harness = populated();
            let report = rebuild(harness.root()).expect("rebuilt");
            assert_eq!(report.skipped_erasable, 1, "the gate must have refused one");

            let text = all_text(&harness);
            // The subject's pseudonym, the entity only the erasable record named, its one attribute
            // value, and the body itself. None of them may be anywhere in the knowledge tree.
            for absent in [
                testkit::subject('a').as_str(),
                "ord10014721",
                "order_ref",
                "```sealed",
                testkit::BODY,
            ] {
                assert!(!text.contains(absent), "`{absent}` reached a note:\n{text}");
            }
        }

        /// The invariant, checked over the whole tree rather than argued: every record a note names
        /// is one no key protects, so no key destruction could leave a note behind.
        #[test]
        fn every_record_a_note_names_is_one_no_key_protects() {
            let harness = populated();
            rebuild(harness.root()).expect("rebuilt");
            let (structures, _) = super::super::read_structures(harness.root()).expect("read");

            let mut checked = 0;
            for text in notes(&harness).into_values() {
                for held in Note::parse(&text).expect("parses").facts {
                    for source in held.sources {
                        let structure = structures
                            .iter()
                            .find(|candidate| candidate.record_id == source)
                            .expect("a note names only records the tree still holds");
                        assert_eq!(structure.data_class, DataClass::Internal);
                        assert!(structure.subjects.is_empty());
                        assert!(Derivable::of(structure).is_ok());
                        checked += 1;
                    }
                }
            }
            assert!(
                checked > 0,
                "the invariant has to be checked against something"
            );
        }

        /// An erasure that really destroyed a key must leave the knowledge tree with nothing to
        /// correct — which is what "no erasure hole" means here. Byte equality is the assertion: a
        /// single count that had to change would mean knowledge had been holding something the key
        /// destruction could not reach.
        #[test]
        fn an_erasure_leaves_the_knowledge_tree_with_nothing_to_correct() {
            let mut harness = Harness::new();
            let erased = testkit::subject('a');
            harness.accept(testkit::internal("2026-08-20T09:00:00Z"));
            harness.accept(testkit::subject_derived(
                "2026-08-22T11:00:00Z",
                std::slice::from_ref(&erased),
            ));
            harness.pipeline.drain_fanout(100).expect("drained");

            rebuild(harness.root()).expect("rebuilt");
            let before = notes(&harness);
            assert!(!before.is_empty(), "there is knowledge to put at risk");

            let report =
                yaam_core::erase::erase_subject(&mut harness.pipeline, &erased).expect("erased");
            assert_eq!(
                report.bodies_sealed_off, 1,
                "the erasure has to have destroyed something for this to prove anything"
            );
            assert_eq!(report.keys_destroyed, 1);

            let after = rebuild(harness.root()).expect("rebuilt");
            assert_eq!(notes(&harness), before);
            assert_eq!(after.skipped_erasable, 1);
            assert!(!all_text(&harness).contains(erased.as_str()));
        }

        /// A record held back pending subject resolution lives outside the published tree, and its
        /// body must not enter an artefact that is backed up. A knowledge note is such an artefact.
        #[test]
        fn a_quarantined_record_contributes_nothing() {
            let mut harness = Harness::new();
            harness.accept(testkit::internal("2026-08-20T09:00:00Z"));

            // Subjects that will not resolve, so the record is spooled rather than published.
            let mut harness = harness.resolving_with(testkit::HoldsSubjects);
            let held = testkit::subject('f');
            let quarantined =
                testkit::subject_derived("2026-08-23T12:00:00Z", std::slice::from_ref(&held));
            let id = quarantined.record_id.clone();
            assert!(matches!(
                harness.accept(quarantined),
                yaam_core::pipeline::Accepted::Quarantined(_)
            ));

            let report = rebuild(harness.root()).expect("rebuilt");
            assert_eq!(report.records_read, 1, "the spool is not part of the tree");
            let text = all_text(&harness);
            assert!(!text.contains(id.as_str()), "{text}");
            assert!(!text.contains(held.as_str()), "{text}");
            assert!(!text.contains("ord10014721"), "{text}");
        }

        /// The counterfactual, so the gate is not the only thing standing between a body and a note:
        /// even handed a record it would have used, derivation has nowhere to put prose.
        #[test]
        fn derivation_has_nowhere_to_put_prose() {
            let mut harness = Harness::new();
            let record = testkit::internal("2026-08-20T09:00:00Z");
            let path = harness.root().join(format!(
                "records/2026/08/20/{}.md",
                record.record_id.as_str()
            ));
            harness.accept(record);
            assert!(
                fs::read_to_string(&path)
                    .expect("read")
                    .contains(testkit::BODY),
                "the record file holds the prose"
            );

            rebuild(harness.root()).expect("rebuilt");
            let text = all_text(&harness);
            assert!(!text.is_empty());
            assert!(!text.contains(testkit::BODY), "{text}");

            // And no fact was built out of anything but a structured field.
            for held in Note::parse(&notes(&harness)["ticket/PROJ-42.md"])
                .expect("parses")
                .facts
            {
                match held.fact {
                    Fact::Attribute { key, value, .. } => {
                        assert!(["service", "environment", "duration_ms"].contains(&key.as_str()));
                        assert!(!value.contains(' ') || value == "staging");
                    }
                    Fact::Actor { agent, .. } => assert_eq!(agent, "agent_a"),
                    Fact::Association { with, .. } => assert_eq!(with.kind, "deploy"),
                }
            }
        }
    }
}
