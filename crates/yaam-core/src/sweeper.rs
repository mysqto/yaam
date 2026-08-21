//! Convergence after a crash.
//!
//! Three jobs, each closing one window the write path leaves open. The grace period matters: a
//! staging file may belong to a write happening right now, and without it the sweeper races the
//! writer for the same path.

use std::fs;
use std::path::{Path, PathBuf};

use yaam_md::Document;
use yaam_store::query::{self, Scope};

use crate::fsutil;
use crate::layout;
use crate::{Pipeline, Result};

/// Files younger than this are assumed to belong to an in-flight write.
pub const GRACE_MS: i64 = 60_000;

/// A fan-out claim older than this is assumed to be held by a process that died.
///
/// Longer than [`GRACE_MS`] because the cost of being wrong is different. Reclaiming a live claim
/// gives two drains the same job — every handler is idempotent, so that is survivable but wasteful —
/// while a claim nobody reclaims is work that never happens. Minutes, therefore: comfortably more
/// than a drain takes, and comfortably less than an operator's patience.
pub const CLAIM_GRACE_MS: i64 = 5 * 60_000;

/// How far back a sweep looks for files the index has not caught up with.
///
/// A bound is needed — an unbounded scan grows with the whole archive — and it is measured in file
/// modification time, so what limits the work is how recently a file was *written* rather than what
/// date its path claims.
pub const SWEEP_LOOKBACK_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Staging files re-driven to completion.
    pub staged_redriven: usize,
    /// Published files that had no index row.
    pub reindexed: usize,
    /// Entity files repaired after an interrupted rollover.
    pub entities_repaired: usize,
    /// Fan-out jobs whose claim outlived the process holding it.
    pub fanout_reclaimed: usize,
}

/// Re-drives incomplete work.
///
/// The scan for unindexed files is bounded by file modification time rather than by the date in the
/// path: replayed and backfilled records carry old dates, so a path-based bound would skip them
/// permanently.
pub fn sweep(pipeline: &mut Pipeline) -> Result<SweepReport> {
    Ok(SweepReport {
        staged_redriven: redrive_staging(pipeline)?,
        reindexed: index_the_unindexed(pipeline)?,
        entities_repaired: repair_timeline_heads(pipeline)?,
        fanout_reclaimed: reclaim_fanout(pipeline)?,
    })
}

/// Staging files old enough that the write behind them is presumed dead.
///
/// Shared with the health read rather than counted a second time there: a backlog figure that
/// disagreed with what a sweep would actually pick up would send an operator looking for work that
/// is not owed. The grace period is the whole safety argument — a staging file younger than
/// [`GRACE_MS`] may belong to a write in flight, and treating it as abandoned would have two
/// processes renaming the same path.
pub(crate) fn stale_staging(pipeline: &Pipeline) -> Result<Vec<PathBuf>> {
    let now = fsutil::now_ms();
    let mut stale = Vec::new();
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::STAGING_DIR),
        layout::RECORD_EXT,
    )? {
        if now - fsutil::mtime_ms(&path)? >= GRACE_MS {
            stale.push(path);
        }
    }
    Ok(stale)
}

/// Published record files the index has no row for.
///
/// One point lookup per candidate file, rather than reading every indexed identifier to answer a
/// question about a handful of them: the id set costs the whole table on every pass, and grows with
/// the archive while the number of files in the window does not.
///
/// Shared with the health read, which is the point: drift is *this* set, and a second definition of
/// it would report a number no sweep acts on.
pub(crate) fn unindexed(pipeline: &Pipeline) -> Result<Vec<PathBuf>> {
    let store = pipeline.reader()?;
    let cutoff = fsutil::now_ms() - SWEEP_LOOKBACK_MS;
    let mut drifted = Vec::new();
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::RECORDS_DIR),
        layout::RECORD_EXT,
    )? {
        // The bound that matters: a record replayed today into an old date directory has a recent
        // mtime and is swept, where a bound on the path's date would never look at it again.
        if fsutil::mtime_ms(&path)? < cutoff {
            continue;
        }
        // Unrestricted, because this read is not answering anybody: it compares the index against
        // the tree, and a row it could not see is a row it would publish a second time.
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
            && query::exists(&store, stem, &Scope::Unrestricted)?
        {
            continue;
        }
        drifted.push(path);
    }
    Ok(drifted)
}

/// Window one: a staging file whose write never reached the tree.
///
/// The grace period is the whole safety argument. A staging file younger than [`GRACE_MS`] may
/// belong to a write in flight, and re-driving it would have two processes renaming the same path
/// and committing the same row — so it is left alone, and picked up by the next sweep if the writer
/// really did die.
fn redrive_staging(pipeline: &mut Pipeline) -> Result<usize> {
    let mut redriven = 0;
    for path in stale_staging(pipeline)? {
        let text = fs::read_to_string(&path)?;
        let Ok(document) = Document::parse(&text) else {
            // A half-written staging file cannot be published and will never parse. Set aside
            // rather than retried forever, and rather than deleted: it is somebody's record.
            set_aside(pipeline.root(), &path)?;
            continue;
        };

        let stamp = layout::stamp_of(&document.record)?;
        let destination = pipeline.published_path(&document.record, &stamp)?;
        if destination.exists() {
            // A completed write: the rename happened and only the index row may be missing. The
            // published file is authoritative, so the row is committed from *it*, not from the copy.
            let published = Document::parse(&fs::read_to_string(&destination)?)?;
            pipeline.commit(&published)?;
            fsutil::remove_if_present(&path)?;
        } else {
            pipeline.place(&document, &path, &stamp)?;
            pipeline.commit(&document)?;
        }
        redriven += 1;
    }
    Ok(redriven)
}

/// Window two: a published file whose index row never landed.
///
/// No grace period here, and deliberately so: committing a row is idempotent, so there is no race to
/// lose against a writer doing the same thing a moment later.
fn index_the_unindexed(pipeline: &mut Pipeline) -> Result<usize> {
    let mut reindexed = 0;
    for path in unindexed(pipeline)? {
        match Document::parse(&fs::read_to_string(&path)?) {
            Ok(document) => {
                pipeline.commit(&document)?;
                reindexed += 1;
            }
            // Not the sweeper's business to repair a record file; `reindex` counts and reports it.
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "unparseable record skipped");
            }
        }
    }
    Ok(reindexed)
}

/// Window three: a timeline rollover that renamed the head away and never made a new one.
///
/// The next append would recreate the head, but nothing guarantees another record ever names that
/// entity — and until one does the tree is missing a file every reader expects to find.
fn repair_timeline_heads(pipeline: &mut Pipeline) -> Result<usize> {
    let mut repaired = 0;
    let mut pending = vec![pipeline.root().join(layout::ENTITIES_DIR)];
    while let Some(dir) = pending.pop() {
        pending.extend(fsutil::subdirs(&dir)?);
        let head = dir.join("timeline.md");
        if head.exists() {
            continue;
        }
        let has_parts = fs::read_dir(&dir).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("timeline-"))
            })
        });
        if has_parts {
            fsutil::write_sync(&head, b"")?;
            fsutil::sync_dir(&dir)?;
            repaired += 1;
        }
    }
    Ok(repaired)
}

/// Window four: a fan-out job whose drain died holding the claim.
///
/// Nothing renews a claim, so a claimed row is invisible to every later drain until something puts
/// it back. A rebuild would too, by re-enqueueing from the tree, but a rebuild is not something an
/// operator should have to run to get one job moving again.
fn reclaim_fanout(pipeline: &mut Pipeline) -> Result<usize> {
    let cutoff = fsutil::now_ms() - CLAIM_GRACE_MS;
    let reclaimed = pipeline.writer_mut().reclaim_stale_fanout(cutoff)?;
    if reclaimed > 0 {
        tracing::warn!(reclaimed, "fan-out claims outlived their drain");
    }
    Ok(reclaimed)
}

/// Moves a file the sweeper cannot act on out of the way, under `.dead-letter/`.
fn set_aside(root: &Path, path: &Path) -> Result<()> {
    let dir = root.join(layout::DEAD_LETTER_DIR);
    fs::create_dir_all(&dir)?;
    let name = path.file_name().unwrap_or(path.as_os_str());
    fs::rename(path, dir.join(name))?;
    fsutil::sync_dir(&dir)?;
    tracing::warn!(path = %path.display(), "staging file will not parse; set aside");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{CLAIM_GRACE_MS, GRACE_MS, SWEEP_LOOKBACK_MS, SweepReport, sweep};
    use crate::testkit::{self, BODY, Harness};

    /// A server time whose directory is the one the harness expects.
    const T09: &str = "2026-08-20T09:14:03.117Z";

    /// Comfortably past the grace period.
    const STALE_MS: u64 = GRACE_MS as u64 + 5_000;

    #[test]
    fn a_crash_after_staging_and_before_the_rename_is_re_driven() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let document = testkit::plain_document(&record, BODY);

        let staged = harness.pipeline.stage(&document).expect("staged");
        // The write ends here. The caller was told nothing, but the record is durable.
        assert!(!harness.path_of(&record).exists());
        testkit::age(&staged, STALE_MS);

        let report = sweep(&mut harness.pipeline).expect("swept");
        assert_eq!(report.staged_redriven, 1);
        assert!(
            harness.path_of(&record).exists(),
            "the record reached the tree"
        );
        assert_eq!(harness.counts()["records"], 1, "and the index caught up");
        assert!(!staged.exists(), "the rename consumed the staging copy");

        // Converged: a second sweep has nothing left to do.
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );
    }

    #[test]
    fn a_crash_after_the_rename_and_before_the_commit_is_indexed() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let document = testkit::plain_document(&record, BODY);
        let stamp = crate::layout::stamp_of(&record).expect("stamp");

        let staged = harness.pipeline.stage(&document).expect("staged");
        harness
            .pipeline
            .place(&document, &staged, &stamp)
            .expect("placed");
        // The write ends here: the file is published and the index knows nothing.
        assert!(harness.path_of(&record).exists());
        assert_eq!(harness.counts()["records"], 0);

        let report = sweep(&mut harness.pipeline).expect("swept");
        assert_eq!(
            report,
            SweepReport {
                reindexed: 1,
                ..SweepReport::default()
            },
            "the rename left no staging file, so this is window two"
        );
        assert_eq!(harness.counts()["records"], 1);
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );
    }

    #[test]
    fn a_crash_after_the_commit_and_before_fan_out_loses_no_work() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        // The write is complete and the caller has been told so; only fan-out is outstanding.
        assert_eq!(harness.counts()["fanout_queue"], 1);

        // Nothing for the sweeper: the record is published and indexed.
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );

        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 1);
        let timeline = harness.root().join("entities/ticket/PROJ-42/timeline.md");
        assert!(
            fs::read_to_string(&timeline)
                .expect("timeline")
                .contains(record.record_id.as_str())
        );
    }

    #[test]
    fn a_claim_the_drain_holding_it_never_released_is_reclaimed() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");

        // A drain that claimed the job and died before finishing it. The row is claimed, so no
        // later drain can see it at all.
        let now = crate::fsutil::now_ms();
        let claimed = harness
            .pipeline
            .writer_mut()
            .claim_fanout(10, now)
            .expect("claimed");
        assert_eq!(claimed.len(), 1);
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);

        // Inside the grace period the claim may still belong to a drain that is running.
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );

        harness.age_fanout_claims(CLAIM_GRACE_MS + 1_000);
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport {
                fanout_reclaimed: 1,
                ..SweepReport::default()
            }
        );

        // And the work actually happens, rather than waiting for a rebuild to re-enqueue it.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 1);
        let timeline = harness.root().join("entities/ticket/PROJ-42/timeline.md");
        assert!(
            fs::read_to_string(&timeline)
                .expect("timeline")
                .contains(record.record_id.as_str())
        );
    }

    #[test]
    fn a_staging_file_inside_the_grace_period_is_left_alone() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let document = testkit::plain_document(&record, BODY);
        let staged = harness.pipeline.stage(&document).expect("staged");

        // A fresh staging file may belong to a write in flight, and racing it would have two
        // processes renaming the same path.
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );
        assert!(staged.exists(), "an in-flight write must not be touched");
        assert!(!harness.path_of(&record).exists());

        testkit::age(&staged, STALE_MS);
        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept").staged_redriven,
            1
        );
    }

    #[test]
    fn a_dedupe_hit_during_a_re_drive_is_a_completed_write_not_a_failure() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        let before = harness.counts();

        // A retry that staged a second copy before the first write published: the record is already
        // in the tree, so the copy is dropped rather than renamed over it.
        let staged = harness
            .pipeline
            .stage(&testkit::plain_document(&record, BODY))
            .expect("staged");
        testkit::age(&staged, STALE_MS);

        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept").staged_redriven,
            1
        );
        assert!(!staged.exists());
        assert_eq!(
            harness.counts(),
            before,
            "a re-drive of a done write adds nothing"
        );
    }

    #[test]
    fn an_old_date_path_with_a_recent_mtime_is_still_swept() {
        let mut harness = Harness::new();
        // A record replayed today from a backfill: its path says 2024, its file was written now.
        let record = testkit::internal("2024-01-02T03:04:05Z");
        let document = testkit::plain_document(&record, BODY);
        let stamp = crate::layout::stamp_of(&record).expect("stamp");
        let staged = harness.pipeline.stage(&document).expect("staged");
        let published = harness
            .pipeline
            .place(&document, &staged, &stamp)
            .expect("placed");
        assert!(published.to_string_lossy().contains("records/2024/01/02"));

        assert_eq!(sweep(&mut harness.pipeline).expect("swept").reindexed, 1);
        assert_eq!(harness.counts()["records"], 1);
    }

    #[test]
    fn a_file_older_than_the_lookback_is_outside_the_sweep() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let document = testkit::plain_document(&record, BODY);
        let stamp = crate::layout::stamp_of(&record).expect("stamp");
        let staged = harness.pipeline.stage(&document).expect("staged");
        let published = harness
            .pipeline
            .place(&document, &staged, &stamp)
            .expect("placed");

        // The bound has to be somewhere: a sweep is not a rebuild, and `reindex` is what reaches
        // the whole archive.
        testkit::age(&published, SWEEP_LOOKBACK_MS as u64 + 60_000);
        assert_eq!(sweep(&mut harness.pipeline).expect("swept").reindexed, 0);
        assert_eq!(harness.counts()["records"], 0);
    }

    #[test]
    fn a_staging_file_that_will_never_parse_is_set_aside() {
        let mut harness = Harness::new();
        let path = harness
            .root()
            .join(".staging/01ARZ3NDEKTSV4RRFFQ69G5FAV.md");
        fs::write(&path, "half a fi").expect("a torn write");
        testkit::age(&path, STALE_MS);

        assert_eq!(
            sweep(&mut harness.pipeline).expect("swept"),
            SweepReport::default()
        );
        assert!(!path.exists(), "it must not be retried forever");
        assert!(
            harness
                .root()
                .join(".dead-letter/01ARZ3NDEKTSV4RRFFQ69G5FAV.md")
                .exists(),
            "nor deleted: it is somebody's record"
        );
    }

    #[test]
    fn an_interrupted_timeline_rollover_gets_its_head_back() {
        let mut harness = Harness::new();
        let dir = harness.root().join("entities/ticket/PROJ-42");
        fs::create_dir_all(&dir).expect("dirs");
        // The state a crash between the rename and the new head leaves behind.
        fs::write(dir.join("timeline-0001.md"), "- older history\n").expect("part");

        let report = sweep(&mut harness.pipeline).expect("swept");
        assert_eq!(report.entities_repaired, 1);
        assert_eq!(
            fs::read_to_string(dir.join("timeline.md")).expect("head"),
            ""
        );
        // A directory with a head is complete, so a second sweep leaves it alone.
        assert_eq!(
            sweep(&mut harness.pipeline)
                .expect("swept")
                .entities_repaired,
            0
        );
    }

    #[test]
    fn an_unparseable_published_record_does_not_stop_the_sweep() {
        let mut harness = Harness::new();
        let good = testkit::internal(T09);
        let document = testkit::plain_document(&good, BODY);
        let stamp = crate::layout::stamp_of(&good).expect("stamp");
        let staged = harness.pipeline.stage(&document).expect("staged");
        harness
            .pipeline
            .place(&document, &staged, &stamp)
            .expect("placed");

        let broken = harness
            .root()
            .join("records/2026/08/20/01ARZ3NDEKTSV4RRFFQ69G5FAV.md");
        fs::write(&broken, "no frontmatter here\n").expect("write");

        assert_eq!(sweep(&mut harness.pipeline).expect("swept").reindexed, 1);
        assert_eq!(harness.counts()["records"], 1);
    }
}
