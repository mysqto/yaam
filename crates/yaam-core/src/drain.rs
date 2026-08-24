//! Running the fan-out queue on demand.
//!
//! Fan-out is enqueued inside the write transaction and run afterwards, so entity timelines and
//! subject audit records exist only because something drained the queue. In a deployment that
//! something is the service's maintenance timer. A store driven only by the command line has no
//! timer, and [`crate::reindex::reindex_all`] drops every materialised timeline and re-enqueues the
//! work that writes them again — so without this, a rebuild leaves `entities/` empty for as long as
//! nothing happens to drain it, which on a command-line-only store is for ever.
//!
//! # Bounded, always
//!
//! Nothing here waits for the queue to be empty. A drain that ran until it was could be held there
//! by a service publishing records beside it, and an operator command that does not return is worse
//! than one that says what it got through. Both bounds are therefore counted in jobs, and both are
//! in the report: [`MAX_JOBS`] for a drain an operator asked for, and the backlog measured once up
//! front for the drain a rebuild or an erasure does on its own behalf ([`drain_backlog`]).

use std::fs;
use std::io;

use crate::{Pipeline, Result, layout};

/// Jobs one drain claims, runs and reports on.
///
/// Both the bound an explicit drain takes by default and the size of one round of a larger one,
/// because the two answer the same question: how much work is it reasonable to hold in memory and
/// account for in one report.
///
/// Ten thousand, where a maintenance round inside the service takes 256. The service's bound is
/// there to stop one round holding the write lock while requests wait behind it; an operator drain
/// has no requests to starve, and each round re-walks the record tree to find the records its jobs
/// name — so a small round would pay for that walk over and over, and a store with more than this
/// queued has something wrong with its drain rather than a busy afternoon.
pub const MAX_JOBS: usize = 10_000;

/// What a drain got through, and what it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Jobs settled: completed, or set aside after their last attempt.
    pub settled: usize,
    /// Jobs this drain was allowed to settle.
    ///
    /// Reported because it is the difference between "the queue is empty" and "this is as far as one
    /// pass goes", and no count of finished work distinguishes those on its own.
    pub budget: usize,
    /// Jobs still queued when the drain returned.
    ///
    /// The same figure [`crate::health::check`] prints as the fan-out backlog, read from the same
    /// place: a drain that reported a number no health read agrees with would be a second opinion
    /// about the same queue.
    pub remaining: usize,
    /// Jobs sitting in `.dead-letter/`, waiting for a person.
    ///
    /// Counted from the directory rather than from this drain alone, because that is the number
    /// somebody has to act on: a job set aside by an earlier drain is owed the same attention as
    /// one set aside by this one. [`crate::health::check`] reads the same directory through the
    /// same counter, so the two commands agree about who is owed a look.
    pub dead_lettered: usize,
}

impl DrainReport {
    /// Whether the bound, rather than an empty queue, is what ended this drain.
    #[must_use]
    pub fn hit_bound(&self) -> bool {
        self.settled >= self.budget && self.remaining > 0
    }

    /// Whether what is left wants an operator.
    ///
    /// Work still queued after a drain does not converge by itself on a store with nothing running
    /// against it, and a dead-lettered job does not converge at all.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.remaining > 0 || self.dead_lettered > 0
    }
}

/// Settles up to `budget` fan-out jobs, then reports.
///
/// In rounds of [`MAX_JOBS`] so a single claim cannot pull an unbounded queue into memory, and it
/// stops early on a round that settled nothing: what is left then is either nothing at all or jobs
/// that failed and are waiting out their backoff, and an immediate second claim helps with neither.
/// A round that settles some but not all of what it claimed keeps going, because the jobs it could
/// not do are the ones now waiting and the rest of the queue is not.
///
/// That leaves one case short: a whole round of failures at the head of the queue stops a drain with
/// ready work behind them. It is reported rather than worked around — the remainder is in the
/// report, the failures are in the log, and after [`crate::pipeline`]'s retry budget those jobs are
/// set aside and stop blocking anything.
pub fn drain(pipeline: &mut Pipeline, budget: usize) -> Result<DrainReport> {
    let mut settled = 0;
    while settled < budget {
        let round = pipeline.drain_fanout(MAX_JOBS.min(budget - settled))?;
        if round == 0 {
            break;
        }
        settled += round;
    }
    Ok(DrainReport {
        settled,
        budget,
        remaining: queued(pipeline)?,
        dead_lettered: dead_lettered(pipeline)?,
    })
}

/// Settles the backlog as it stood when this was called.
///
/// What a rebuild and an erasure use, and the bound is the queue depth read once up front rather
/// than a constant. Two reasons. It is enough: the work a rebuild re-enqueues is bounded by the tree
/// that same command has just read end to end, so the drain is proportional to something the caller
/// already paid for, and the timelines it dropped come back in full however large the store is. And
/// it is finite: a record published beside this drain adds to the queue but not to the bound, so a
/// busy store cannot hold the command open.
pub fn drain_backlog(pipeline: &mut Pipeline) -> Result<DrainReport> {
    let backlog = queued(pipeline)?;
    drain(pipeline, backlog)
}

/// Fan-out jobs nobody has taken, including those waiting out a backoff.
fn queued(pipeline: &Pipeline) -> Result<usize> {
    Ok(yaam_store::health::read(&pipeline.reader()?)?.fanout_pending)
}

/// Files in `.dead-letter/`, one per job that ran out of attempts.
///
/// Shared with [`crate::health::check`] rather than counted there again, so a drain and a health
/// read cannot come back with two numbers for one directory.
pub(crate) fn dead_lettered(pipeline: &Pipeline) -> Result<usize> {
    let dir = pipeline.paths().root.join(layout::DEAD_LETTER_DIR);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        // Nothing has ever been set aside here, which is the same answer as an empty directory.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut aside = 0;
    for entry in entries {
        if !entry?.file_type()?.is_dir() {
            aside += 1;
        }
    }
    Ok(aside)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{DrainReport, drain, drain_backlog};
    use crate::testkit::{self, BODY, Harness};

    /// A store with one internal record accepted and nothing drained.
    fn queued() -> Harness {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        harness
    }

    #[test]
    fn a_drain_settles_the_queue_and_reports_nothing_left() {
        let mut harness = queued();
        let report = drain(&mut harness.pipeline, 10).expect("drained");
        assert_eq!(
            report,
            DrainReport {
                settled: 1,
                budget: 10,
                remaining: 0,
                dead_lettered: 0,
            }
        );
        assert!(!report.hit_bound());
        assert!(!report.needs_attention());
        assert!(
            harness
                .root()
                .join("entities/ticket/PROJ-42/timeline.md")
                .is_file(),
            "the timeline is what the queue was holding"
        );
    }

    /// The queue depth a drain reports has to be the one a health read reports, or one of them is
    /// telling an operator something no command acts on.
    #[test]
    fn what_a_drain_says_is_left_is_what_a_health_read_says_is_left() {
        let mut harness = queued();
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-21T09:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");

        let report = drain(&mut harness.pipeline, 1).expect("drained");
        assert_eq!(report.settled, 1);
        assert_eq!(
            report.remaining,
            crate::health::check(&harness.pipeline)
                .expect("health")
                .sweeper_backlog
                .fanout_pending
        );
    }

    /// And the same for the jobs nothing will retry. A drain that asks for an operator over a
    /// directory a health read does not count is two verdicts about one store.
    #[test]
    fn what_a_drain_says_was_set_aside_is_what_a_health_read_says_was() {
        let mut harness = Harness::new();
        let record = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        fs::remove_file(harness.path_of(&record)).expect("remove");

        let mut report = drain(&mut harness.pipeline, 10).expect("drained");
        while report.remaining > 0 {
            harness.release_fanout();
            report = drain(&mut harness.pipeline, 10).expect("drained");
        }
        assert_eq!(report.dead_lettered, 1);

        let health = crate::health::check(&harness.pipeline).expect("health");
        assert_eq!(report.dead_lettered, health.dead_lettered);
        assert_eq!(
            report.needs_attention(),
            health.needs_attention(),
            "a store is degraded to both commands or to neither"
        );
    }

    #[test]
    fn a_drain_that_reaches_its_bound_says_what_is_left() {
        let mut harness = queued();
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-21T09:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");

        let report = drain(&mut harness.pipeline, 1).expect("drained");
        assert_eq!(report.settled, 1);
        assert_eq!(report.budget, 1);
        assert!(report.remaining > 0, "{report:?}");
        assert!(report.hit_bound());
        assert!(report.needs_attention());

        // And the rest is still there to be had, which is what makes the bound a pass rather than a
        // loss.
        let rest = drain(&mut harness.pipeline, 10).expect("drained");
        assert_eq!(rest.remaining, 0);
        assert!(!rest.hit_bound());
    }

    #[test]
    fn a_drain_of_an_empty_queue_reports_nothing_and_asks_for_nothing() {
        let mut harness = Harness::new();
        let report = drain(&mut harness.pipeline, 10).expect("drained");
        assert_eq!(report.settled, 0);
        assert_eq!(report.remaining, 0);
        assert!(!report.hit_bound(), "an empty queue is not a bound reached");
        assert!(!report.needs_attention());
    }

    /// The bound a rebuild's own drain takes has to cover what that rebuild re-enqueued, or the
    /// timelines it dropped stay dropped.
    #[test]
    fn the_backlog_bound_covers_what_a_rebuild_re_enqueued() {
        let mut harness = queued();
        drain(&mut harness.pipeline, 10).expect("drained");
        let timeline = harness.root().join("entities/ticket/PROJ-42/timeline.md");

        let rebuilt = crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(
            rebuilt.timelines_dropped, 2,
            "one head per entity the record names"
        );
        assert!(
            !timeline.exists(),
            "the rebuild took the file with the rows"
        );

        let report = drain_backlog(&mut harness.pipeline).expect("drained");
        assert_eq!(report.budget, report.settled);
        assert_eq!(report.remaining, 0);
        assert!(timeline.is_file(), "the timeline came back");
    }

    /// A job that cannot be done leaves the drain reporting a remainder rather than an error: the
    /// queue is derived, and the caller has been told exactly what is still owed.
    #[test]
    fn a_job_that_fails_is_left_queued_and_counted() {
        let mut harness = Harness::new();
        let record = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        // The tree is authoritative; without the file there is nothing to write a timeline from.
        fs::remove_file(harness.path_of(&record)).expect("remove");

        let report = drain(&mut harness.pipeline, 10).expect("drained");
        assert_eq!(report.settled, 0);
        assert_eq!(report.remaining, 1);
        assert_eq!(report.dead_lettered, 0, "it still has attempts left");
        assert!(report.needs_attention());
    }

    /// A job out of attempts is counted where an operator can see it, and stops being a remainder.
    #[test]
    fn a_job_out_of_attempts_is_counted_as_set_aside() {
        let mut harness = Harness::new();
        let record = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        fs::remove_file(harness.path_of(&record)).expect("remove");

        // The retry budget is spent across drains on purpose, so this is what a test does instead of
        // waiting out the backoff between them.
        let mut report = drain(&mut harness.pipeline, 10).expect("drained");
        while report.remaining > 0 {
            harness.release_fanout();
            report = drain(&mut harness.pipeline, 10).expect("drained");
        }

        assert_eq!(report.settled, 1, "setting a job aside settles it");
        assert_eq!(report.dead_lettered, 1);
        assert!(
            report.needs_attention(),
            "a job nothing will retry has to be somebody's to look at"
        );
    }
}
