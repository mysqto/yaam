//! Convergence after a crash.
//!
//! Three jobs, each closing one window the write path leaves open. The grace period matters: a
//! staging file may belong to a write happening right now, and without it the sweeper races the
//! writer for the same path.

/// Files younger than this are assumed to belong to an in-flight write.
pub const GRACE_MS: i64 = 60_000;

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Staging files re-driven to completion.
    pub staged_redriven: usize,
    /// Published files that had no index row.
    pub reindexed: usize,
    /// Entity files repaired after an interrupted rollover.
    pub entities_repaired: usize,
}

/// Re-drives incomplete work.
///
/// The scan for unindexed files is bounded by file modification time rather than by the date in the
/// path: replayed and backfilled records carry old dates, so a path-based bound would skip them
/// permanently.
pub fn sweep(_pipeline: &mut crate::Pipeline) -> crate::Result<SweepReport> {
    todo!("staging orphans, unindexed files by mtime, entity rollover repair")
}
