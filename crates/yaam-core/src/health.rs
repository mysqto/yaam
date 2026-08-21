//! A read-only account of whether the store needs attention.
//!
//! Four questions, chosen because they are the ones whose answers change what an operator does
//! next: is the index a version this build can use, has the index fallen behind the tree, is there
//! work the sweeper has not got through, and how many records are held back waiting for a subject to
//! resolve.
//!
//! Every figure is derived the same way the operation that acts on it derives it —
//! [`crate::sweeper`]'s own scans, not a second definition of them. A drift count that disagrees
//! with what a rebuild would find is worse than no count at all: it sends an operator looking for
//! something that is not there, or leaves them satisfied while it is.
//!
//! Read-only throughout. Nothing here writes, publishes or reclaims, so it is safe to run against a
//! live deployment and safe to run on a timer.

use yaam_store::health::IndexHealth;

use crate::{Pipeline, Result, fsutil, layout, sweeper};

/// What a health read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthReport {
    /// What the index says about itself.
    pub index: IndexHealth,
    /// Published records the index has no row for.
    ///
    /// Bounded by [`sweeper::SWEEP_LOOKBACK_MS`], like the sweep that would fix it: an unbounded
    /// comparison grows with the whole archive, and a figure nobody can afford to compute is a
    /// figure nobody computes.
    pub index_drift: usize,
    /// Work the sweeper still owes.
    pub sweeper_backlog: SweeperBacklog,
    /// Records held back until their subjects resolve, counted from the spool on disk.
    ///
    /// The spool rather than the index register, because the spool is the authority: the register is
    /// derived from it, and a rebuild reproduces the register from these files.
    pub quarantine_depth: usize,
}

impl HealthReport {
    /// Whether anything here calls for an operator.
    ///
    /// The schema version is reported but not judged here: an index newer than this build is refused
    /// by the writer when the pipeline opens, so a report that got this far was read from a file this
    /// build can use.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.index_drift > 0 || self.sweeper_backlog.total() > 0
    }
}

/// Work a sweep would pick up.
///
/// Split three ways rather than summed, because the three call for different reactions: staging
/// files mean writes that died, pending fan-out means a drain that is not running, and stale claims
/// mean a drain that died holding work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweeperBacklog {
    /// Staging files old enough that the write behind them is presumed dead.
    pub staged: usize,
    /// Fan-out jobs nobody has taken.
    pub fanout_pending: usize,
    /// Fan-out claims older than [`sweeper::CLAIM_GRACE_MS`], so presumed held by a dead process.
    pub stale_claims: usize,
}

impl SweeperBacklog {
    /// Everything a sweep would act on.
    #[must_use]
    pub fn total(&self) -> usize {
        self.staged + self.fanout_pending + self.stale_claims
    }
}

/// Reads the store's health without changing anything.
///
/// Fails if the index cannot be opened, which is itself the answer: an absent or unreadable index
/// needs a rebuild, not a closer look at its queue depths.
pub fn check(pipeline: &Pipeline) -> Result<HealthReport> {
    let store = pipeline.reader()?;
    let index = yaam_store::health::read(&store)?;
    let claim_cutoff = fsutil::now_ms() - sweeper::CLAIM_GRACE_MS;
    Ok(HealthReport {
        index,
        index_drift: sweeper::unindexed(pipeline)?.len(),
        sweeper_backlog: SweeperBacklog {
            staged: sweeper::stale_staging(pipeline)?.len(),
            fanout_pending: index.fanout_pending,
            stale_claims: yaam_store::health::stale_claims(&store, claim_cutoff)?,
        },
        quarantine_depth: fsutil::walk_files(
            &pipeline.paths().root.join(layout::QUARANTINE_DIR),
            layout::RECORD_EXT,
        )?
        .len(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::check;
    use crate::testkit::{self, BODY, Harness};

    /// A tree nothing has gone wrong in reports nothing to do.
    #[test]
    fn a_healthy_store_asks_for_nothing() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.index.records, 1);
        assert_eq!(
            report.index.schema_version,
            report.index.supported_schema_version
        );
        assert_eq!(report.index_drift, 0);
        assert_eq!(report.sweeper_backlog.total(), 0);
        assert_eq!(report.quarantine_depth, 0);
        assert!(!report.needs_attention());
    }

    /// The figures an operator acts on: a record the index lost, and work still queued.
    #[test]
    fn a_dropped_index_shows_up_as_drift() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");

        // Fan-out was enqueued and never drained, which is exactly the backlog a check reports.
        let before = check(&harness.pipeline).expect("health");
        assert!(before.sweeper_backlog.fanout_pending > 0);
        assert!(before.needs_attention());

        let harness = harness.without_index();
        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.index.records, 0);
        assert_eq!(report.index_drift, 1, "the tree still holds the record");
    }

    /// A quarantined record is held on disk, and the depth is read from there.
    #[test]
    fn a_held_record_is_counted_from_the_spool() {
        let mut harness = Harness::new();
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

        assert_eq!(
            check(&harness.pipeline).expect("health").quarantine_depth,
            1
        );
    }

    /// A staging file a dead write left behind is backlog once the grace period has passed.
    #[test]
    fn an_abandoned_staging_file_is_backlog_only_once_it_is_old() {
        let harness = Harness::new();
        let staged = harness.root().join(".staging/abandoned.md");
        fs::write(&staged, "---\naction: deploy\n---\nbody\n").expect("staged");

        assert_eq!(
            check(&harness.pipeline)
                .expect("health")
                .sweeper_backlog
                .staged,
            0,
            "a fresh staging file may belong to a write in flight"
        );

        testkit::age(
            &staged,
            u64::try_from(crate::sweeper::GRACE_MS).unwrap() + 1_000,
        );
        assert_eq!(
            check(&harness.pipeline)
                .expect("health")
                .sweeper_backlog
                .staged,
            1
        );
    }
}
