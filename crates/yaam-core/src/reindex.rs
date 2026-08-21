//! Rebuilding the index from the tree.
//!
//! This is the operation that proves the index is derived. It replays the tombstone log *first* and
//! then reproduces every row from the Markdown tree plus local cold manifests — in that order, or a
//! rebuild would resurrect structure that was erased. A publish carrying no key share deliberately
//! keeps the share the index already holds, so a replay after the walk could not take one back;
//! re-applying each erasure to the tree first makes the walk itself produce the erased shape.
//!
//! The rebuild itself is one transaction. That is both what makes it affordable — one durability
//! round trip rather than one per record — and what makes an interrupted rebuild safe: the truncate
//! and the rows that replace it commit together or not at all, so a rebuild that dies half way
//! leaves the index it started from rather than a shorter one that looks finished.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use yaam_contract::ActionRecord;
use yaam_md::Document;
use yaam_store::{Batch, PublishInput};

use crate::{Pipeline, Result, fsutil, layout};

/// What a rebuild produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReindexReport {
    /// Records indexed from the live tree.
    pub from_tree: usize,
    /// Records indexed from cold manifests.
    pub from_manifests: usize,
    /// Files skipped because their frontmatter would not parse.
    pub skipped: usize,
    /// Erasures re-applied from the tombstone log.
    pub tombstones_replayed: usize,
}

/// Rebuilds the index in place.
///
/// The replay comes *before* the walk on purpose. A publish that carries no key share deliberately
/// keeps the share the index already holds, so a replay running after the walk could not take one
/// back. Re-applying each erasure to the tree first makes the walk itself produce the erased shape,
/// which is the only version of "derived" that survives a restored backup or a late replay of an
/// erased subject's record. The replay writes to the tree and the key store, not to the index, so it
/// sits outside the transaction that follows.
///
/// Everything after it — truncate, tree, manifests, quarantine register — is one transaction. A
/// rebuild's cost at `synchronous = FULL` was two thirds durability, one commit per record; and a
/// rebuild that truncated in its own transaction left a window in which the index was short, live and
/// indistinguishable from a finished one. One transaction answers both. It is affordable because the
/// index is derived and bounded by the tree, and it is preferable to a resumable batch boundary
/// because there is nothing to resume from: a rebuild reads the whole tree either way, so a
/// half-finished one has no partial state worth keeping.
///
/// The sources are listed before the transaction opens, which is also when the tree stops being
/// consulted for *which* files exist. A file appearing during the rebuild is not indexed by it; the
/// sweeper's own pass is what picks that up, the same as before.
///
/// A file whose frontmatter will not parse is counted and skipped rather than aborting the rebuild:
/// one unreadable file must not be able to keep the index from being rebuilt at all.
pub fn reindex_all(pipeline: &mut Pipeline) -> Result<ReindexReport> {
    let tombstones_replayed = crate::erase::replay_tombstones(pipeline)?;
    let sources = Sources::list(pipeline)?;

    let mut batch = pipeline.writer_mut().batch()?;
    batch.truncate_derived()?;
    let (from_tree, tree_skipped) = index_tree(&mut batch, &sources.tree)?;
    let (from_manifests, manifest_skipped) = index_manifests(&mut batch, &sources.manifests)?;
    reregister_quarantine(&mut batch, &sources.quarantine)?;
    batch.commit()?;

    Ok(ReindexReport {
        from_tree,
        from_manifests,
        skipped: tree_skipped + manifest_skipped,
        tombstones_replayed,
    })
}

/// The files one rebuild will read.
///
/// Listed up front because the transaction borrows the writer for the whole rebuild, and because a
/// rebuild should walk the tree once: the alternative is three walks interleaved with the writes
/// they feed, which is slower and gives the tree three different chances to change underneath.
struct Sources {
    /// Record files in the live tree.
    tree: Vec<PathBuf>,
    /// Cold manifests, one record's frontmatter per line.
    manifests: Vec<PathBuf>,
    /// Spooled copies of records still held back.
    quarantine: Vec<PathBuf>,
}

impl Sources {
    /// Walks the three directories a rebuild derives from.
    fn list(pipeline: &Pipeline) -> Result<Self> {
        let root = pipeline.root();
        let mut tree = fsutil::walk_files(&root.join(layout::RECORDS_DIR), layout::RECORD_EXT)?;
        tree.sort_by_cached_key(|path| arrival_key(path));
        Ok(Self {
            tree,
            manifests: fsutil::walk_files(&root.join(layout::COLD_DIR), "jsonl")?,
            quarantine: fsutil::walk_files(&root.join(layout::QUARANTINE_DIR), layout::RECORD_EXT)?,
        })
    }
}

/// Orders the tree by when each record arrived, out of the path alone.
///
/// A record's path ends `YYYY/MM/DD/<id>.md` wherever in the tree it sits, and a record id sorts by
/// the time it was minted, so the last four components put the whole tree in arrival order without
/// opening a file.
///
/// Plain path order does not, and the difference is not cosmetic. Owner-visible records live under
/// `records/owner/`, which sorts after every dated directory, so a rebuild walking paths gave every
/// owner-visible record in the store a higher row id than every other record. Row id is the order the
/// full-text index can be walked in, and it is what bounds a search: capping the candidates at the
/// newest end of a match then found owner-visible records and nothing else. Measured on the
/// benchmark's store, a common word came back with an empty page.
fn arrival_key(path: &Path) -> Vec<OsString> {
    let mut parts: Vec<OsString> = path
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    // Fewer than four components can only be a stray file directly under the tree root: it keeps
    // whatever order its own name gives it, which is at least deterministic.
    let dated = parts.len().saturating_sub(4);
    parts.split_off(dated)
}

/// Indexes every record file in the live tree.
fn index_tree(batch: &mut Batch<'_>, paths: &[PathBuf]) -> Result<(usize, usize)> {
    let mut indexed = 0;
    let mut skipped = 0;
    for path in paths {
        match Document::parse(&fs::read_to_string(path)?) {
            Ok(document) => {
                crate::pipeline::publish_document(batch, &document)?;
                indexed += 1;
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "record file skipped");
                skipped += 1;
            }
        }
    }
    Ok((indexed, skipped))
}

/// Indexes the manifests of records that have been archived out of the live tree.
///
/// A manifest is one record's frontmatter JSON per line — the same projection the index stores — so
/// a cold archive is produced by copying rows out and read back by putting them in. Bodies are not
/// in a manifest, which is why an archived record is queryable but not searchable.
fn index_manifests(batch: &mut Batch<'_>, paths: &[PathBuf]) -> Result<(usize, usize)> {
    let mut indexed = 0;
    let mut skipped = 0;
    for path in paths {
        for line in fs::read_to_string(path)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match manifest_record(line) {
                Ok(record) => {
                    batch.publish(PublishInput {
                        record: &record,
                        searchable_body: "",
                        subject_keys: &[],
                    })?;
                    indexed += 1;
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "manifest line skipped");
                    skipped += 1;
                }
            }
        }
    }
    Ok((indexed, skipped))
}

/// Re-registers the records still held in the quarantine spool.
///
/// The register of what is held back is derived too: the spool files are the authority, and their
/// key date comes from the record's own server stamp. Not counted in the report, because nothing here
/// is *indexed* — these records are precisely the ones that are not.
fn reregister_quarantine(batch: &mut Batch<'_>, paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        let Ok(document) = Document::parse(&fs::read_to_string(path)?) else {
            tracing::warn!(path = %path.display(), "unparseable quarantine copy skipped");
            continue;
        };
        let stamp = layout::stamp_of(&document.record)?;
        batch.enqueue_quarantine(
            document.record.record_id.as_str(),
            &stamp.date(),
            &path.to_string_lossy(),
        )?;
    }
    Ok(())
}

/// Reads one manifest line into a record.
///
/// `summary` is filled in when absent, because the frontmatter projection removes it: prose lives in
/// the body, and a manifest has no body to hold one.
fn manifest_record(line: &str) -> Result<ActionRecord> {
    let mut value: Json =
        serde_json::from_str(line).map_err(|e| crate::pipeline::invalid(e.to_string()))?;
    if let Some(object) = value.as_object_mut() {
        object
            .entry("summary")
            .or_insert_with(|| Json::String(String::new()));
    }
    let record: ActionRecord =
        serde_json::from_value(value).map_err(|e| crate::pipeline::invalid(e.to_string()))?;
    record.validate()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::reindex_all;
    use crate::testkit::{self, BODY, Harness};

    /// Writes a small store: two internal records, one sealed, one held in quarantine.
    fn populated() -> Harness {
        let mut harness = Harness::new();
        for received_at in ["2026-08-20T09:00:00Z", "2026-08-21T10:30:00.500Z"] {
            harness
                .pipeline
                .accept(testkit::internal(received_at), BODY)
                .expect("accepted");
        }
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-22T11:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");

        // Owner-visible, and so stored apart under `records/owner/`: a rebuild that walked only
        // the dated tree would silently drop it, and the index would answer without it.
        harness
            .pipeline
            .accept(testkit::owner("2026-08-22T11:30:00Z", "agent_b"), BODY)
            .expect("accepted");

        let erased = testkit::subject('f');
        yaam_crypto::keystore::KeyStore::tombstone(harness.pipeline.keys(), &erased)
            .expect("tombstone");
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-23T12:00:00Z", &[erased]),
                BODY,
            )
            .expect("quarantined");

        harness.pipeline.drain_fanout(100).expect("drained");
        harness
    }

    #[test]
    fn every_row_comes_back_from_the_tree_alone() {
        let harness = populated();
        let before = harness.snapshot();
        let counts = harness.counts();
        assert_eq!(counts["records"], 4);
        assert_eq!(counts["quarantine_pending"], 1);

        // The index is disposable: this deletes the file, not just its contents.
        let mut harness = harness.without_index();
        assert_eq!(harness.counts()["records"], 0);

        let report = reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.from_tree, 4);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.from_manifests, 0);
        assert_eq!(report.tombstones_replayed, 0);

        // Logical equality, table by table: a `SQLite` file is not reproducible byte for byte, but
        // every row that is supposed to be derived from the tree has to be.
        assert_eq!(harness.snapshot(), before);
        assert_eq!(harness.counts(), counts);
    }

    #[test]
    fn a_rebuild_indexes_in_arrival_order_even_out_of_the_owner_subtree() {
        let mut harness = Harness::new();
        // An owner-visible record between two others. It is stored apart, under `records/owner/`,
        // which sorts after every dated directory — so a rebuild walking paths would index it last.
        for record in [
            testkit::internal("2026-08-20T09:00:00Z"),
            testkit::owner("2026-08-21T09:00:00Z", "agent_b"),
            testkit::internal("2026-08-22T09:00:00Z"),
        ] {
            harness.pipeline.accept(record, BODY).expect("accepted");
        }

        let mut harness = harness.without_index();
        reindex_all(&mut harness.pipeline).expect("rebuilt");

        let stamps = harness.received_ms_by_row_id();
        assert_eq!(stamps.len(), 3);
        assert!(
            stamps.is_sorted(),
            "row ids must follow the clock, or the full-text candidate cap takes the wrong \
             records: {stamps:?}"
        );
    }

    #[test]
    fn a_rebuild_is_idempotent() {
        let mut harness = populated();
        reindex_all(&mut harness.pipeline).expect("rebuilt");
        let once = harness.snapshot();
        reindex_all(&mut harness.pipeline).expect("rebuilt again");
        assert_eq!(harness.snapshot(), once);
    }

    #[test]
    fn a_rebuild_that_fails_part_way_leaves_the_index_it_started_from() {
        let harness = populated();
        let before = harness.snapshot();
        let counts = harness.counts();

        // A file the walk cannot skip and the index will not take: subject-derived, so its body may
        // not be indexed, but written as prose. Dated after the records already in the tree, so the
        // rebuild has published several before it reaches this one.
        let refused = testkit::plain_document(
            &testkit::subject_derived("2026-08-24T13:00:00Z", &[testkit::subject('b')]),
            BODY,
        );
        let path = harness.root().join("records/2026/08/24/refused.md");
        fs::create_dir_all(path.parent().expect("a parent")).expect("dated dir");
        fs::write(&path, refused.render()).expect("write");

        let mut harness = harness;
        reindex_all(&mut harness.pipeline).expect_err("a refused record must fail the rebuild");

        // Not "mostly rebuilt": every row the rebuild had already written is gone with the
        // transaction, and what a reader sees is the index from before it started. A truncate that
        // committed on its own would have left a shorter index that answers as if it were finished.
        assert_eq!(
            harness.snapshot(),
            before,
            "an interrupted rebuild must leave the index it started from"
        );
        assert_eq!(harness.counts(), counts);
    }

    #[test]
    fn a_file_that_will_not_parse_is_counted_and_skipped() {
        let mut harness = populated();
        fs::write(
            harness
                .root()
                .join("records/2026/08/20/01ARZ3NDEKTSV4RRFFQ69G5FAV.md"),
            "---\naction: [unclosed\n---\nbody\n",
        )
        .expect("write");

        let report = reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.skipped, 1, "one bad file must not abort the rebuild");
        assert_eq!(report.from_tree, 4);
    }

    #[test]
    fn a_cold_manifest_is_indexed_alongside_the_tree() {
        let mut harness = Harness::new();
        let archived = testkit::internal("2026-01-05T08:00:00Z");
        // The manifest format is the frontmatter projection, so the body is absent by construction.
        let mut json = serde_json::to_value(&archived).expect("json");
        json.as_object_mut().expect("object").remove("summary");
        let mut lines = serde_json::to_string(&json).expect("line");
        lines.push('\n');
        lines.push_str("{\"not\": \"a record\"}\n");
        lines.push('\n');
        fs::write(harness.root().join("cold/2026-01.jsonl"), lines).expect("manifest");

        let report = reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.from_manifests, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(harness.counts()["records"], 1);
        // Queryable but not searchable: a manifest carries no body to index.
        let store = harness.pipeline.reader().expect("reader");
        assert!(
            yaam_store::query::search(
                &store,
                "shards",
                10,
                &yaam_store::query::Scope::Unrestricted
            )
            .expect("search")
            .is_empty()
        );
        assert_eq!(
            yaam_store::query::by_entity_unbounded(&store, "ticket", "PROJ-42", 1.0)
                .expect("by entity")
                .len(),
            1
        );
    }

    #[test]
    fn a_quarantined_record_is_still_held_after_a_rebuild() {
        let harness = populated();
        let mut harness = harness.without_index();
        reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(
            harness.counts()["quarantine_pending"],
            1,
            "the register of what is held back is derived from the spool"
        );
    }
}
