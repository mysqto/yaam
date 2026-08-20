//! Rebuilding the index from the tree.
//!
//! This is the operation that proves the index is derived. It must reproduce every row from the
//! Markdown tree plus local cold manifests — and then replay tombstones, or a rebuild would
//! resurrect structure that was erased.

use std::fs;

use serde_json::Value as Json;
use yaam_contract::ActionRecord;
use yaam_md::Document;
use yaam_store::PublishInput;

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
/// The order is truncate, replay, walk — and the replay comes *before* the walk on purpose. A
/// publish that carries no key share deliberately keeps the share the index already holds, so a
/// replay running after the walk could not take one back. Re-applying each erasure to the tree first
/// makes the walk itself produce the erased shape, which is the only version of "derived" that
/// survives a restored backup or a late replay of an erased subject's record.
///
/// A file whose frontmatter will not parse is counted and skipped rather than aborting the rebuild:
/// one unreadable file must not be able to keep the index from being rebuilt at all.
pub fn reindex_all(pipeline: &mut Pipeline) -> Result<ReindexReport> {
    pipeline.writer_mut().truncate_derived()?;
    let tombstones_replayed = crate::erase::replay_tombstones(pipeline)?;
    let (from_tree, tree_skipped) = index_tree(pipeline)?;
    let (from_manifests, manifest_skipped) = index_manifests(pipeline)?;
    reregister_quarantine(pipeline)?;
    Ok(ReindexReport {
        from_tree,
        from_manifests,
        skipped: tree_skipped + manifest_skipped,
        tombstones_replayed,
    })
}

/// Indexes every record file in the live tree.
fn index_tree(pipeline: &mut Pipeline) -> Result<(usize, usize)> {
    let mut indexed = 0;
    let mut skipped = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::RECORDS_DIR),
        layout::RECORD_EXT,
    )? {
        match Document::parse(&fs::read_to_string(&path)?) {
            Ok(document) => {
                pipeline.commit(&document)?;
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
fn index_manifests(pipeline: &mut Pipeline) -> Result<(usize, usize)> {
    let mut indexed = 0;
    let mut skipped = 0;
    for path in fsutil::walk_files(&pipeline.root().join(layout::COLD_DIR), "jsonl")? {
        for line in fs::read_to_string(&path)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match manifest_record(line) {
                Ok(record) => {
                    pipeline.writer_mut().publish(PublishInput {
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
fn reregister_quarantine(pipeline: &mut Pipeline) -> Result<()> {
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::QUARANTINE_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            tracing::warn!(path = %path.display(), "unparseable quarantine copy skipped");
            continue;
        };
        let stamp = layout::stamp_of(&document.record)?;
        pipeline.writer_mut().enqueue_quarantine(
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
        assert_eq!(counts["records"], 3);
        assert_eq!(counts["quarantine_pending"], 1);

        // The index is disposable: this deletes the file, not just its contents.
        let mut harness = harness.without_index();
        assert_eq!(harness.counts()["records"], 0);

        let report = reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.from_tree, 3);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.from_manifests, 0);
        assert_eq!(report.tombstones_replayed, 0);

        // Logical equality, table by table: a `SQLite` file is not reproducible byte for byte, but
        // every row that is supposed to be derived from the tree has to be.
        assert_eq!(harness.snapshot(), before);
        assert_eq!(harness.counts(), counts);
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
        assert_eq!(report.from_tree, 3);
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
            yaam_store::query::search(&store, "shards", 10)
                .expect("search")
                .is_empty()
        );
        assert_eq!(
            yaam_store::query::by_entity(&store, "ticket", "PROJ-42", 1.0)
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
