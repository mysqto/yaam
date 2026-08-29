//! A read-only account of whether the store needs attention.
//!
//! Eight questions, chosen because they are the ones whose answers change what an operator does
//! next: is the index a version this build can use, has the index fallen behind the tree, is there
//! work the sweeper has not got through, how many records are held back waiting for a subject to
//! resolve **and how long the oldest of them has waited**, is anything set aside in `.dead-letter/`
//! that only a person will clear, is the key material on disk protected, and **does any key stand
//! for a subject an erasure has already destroyed the keys of**.
//!
//! The last of those is the standing signal for a key store recovered by hand. Erasure is key
//! destruction, so a key file put back from a copy taken before an erasure un-erases a body — and
//! nothing else in this deployment would say so, because the live refusals are made from the tree
//! and would go on being made correctly by a store that had one. [`crate::restore`] is the remedy
//! and this is the alarm; a remedy nobody knows to run is a runbook step, which is what this
//! guarantee had instead of a mechanism.
//!
//! Every figure is derived the same way the operation that acts on it derives it —
//! [`crate::sweeper`]'s own scans, not a second definition of them. A drift count that disagrees
//! with what a rebuild would find is worse than no count at all: it sends an operator looking for
//! something that is not there, or leaves them satisfied while it is.
//!
//! Read-only throughout. Nothing here writes, publishes or reclaims, so it is safe to run against a
//! live deployment and safe to run on a timer.

use yaam_crypto::keystore::KeyMaterial;
use yaam_store::health::IndexHealth;

use crate::{Pipeline, Result, fsutil, layout, restore, sweeper};

/// How long a record may sit in quarantine before the spool is a fault rather than a wait.
///
/// Seven days, and the same seven days as [`crate::erase::KEY_BACKUP_WINDOW_MS`] — deliberately, and
/// for the reason §10.4 gives for tying them: re-keying a record needs every one of its shares, so a
/// record's subjects must resolve before any of them is shredded, and a shred completes at the end of
/// the key-backup window. A quarantine that outlived that window would hold a body whose re-keying
/// had already become impossible.
///
/// Two constants rather than one because they are two facts that happen to coincide, and a build that
/// moved one without the other would be making a claim nobody had argued for. A test asserts they
/// still agree, which is the assertion that turns the coincidence into something that cannot drift
/// silently.
///
/// This is a *threshold on visibility*, not the hard stop itself. The hard stop — publish the record
/// structure-only and destroy the day's quarantine key — needs a representation for an unresolved
/// `subject_derived` record that the write path deliberately refuses today, and that is a contract
/// change nobody has taken. Until it exists, the honest interim is that a spool outliving the SLA is
/// reported and degrades the store rather than sitting there silently.
pub const QUARANTINE_SLA_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

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
    /// How long the oldest held record has been waiting, in milliseconds, or `None` when nothing is
    /// held.
    ///
    /// Measured from the record's own `received_at` and never from `quarantine_pending.first_seen_ms`.
    /// That column is a wall-clock read taken at registration, and a rebuild deletes and re-registers
    /// the whole table — so an age keyed on it returns to zero on every `reindex --all`, and a spool
    /// that had outlived its SLA for a month would never once have said so. The spool file is the
    /// authority on what is held and the record inside it carries the only clock a rebuild cannot
    /// move.
    pub quarantine_oldest_ms: Option<i64>,
    /// Held records whose own `received_at` will not parse, so nothing can age them out.
    ///
    /// Counted apart rather than folded into the age above: a record held too long and a record held
    /// with nothing saying since when are different files to go and look at, and the second one is
    /// invisible to every threshold there is.
    pub quarantine_undated: usize,
    /// Key files standing for subjects an erasure has already destroyed the keys of.
    ///
    /// Nil on every store where nothing has gone wrong, and the whole point of the figure is that it
    /// is not nil on the one where something has: a key store recovered from a copy taken before an
    /// erasure. `yaam restore-keys` reconciles a recovery as part of installing it, so this counts
    /// the recoveries that did not go through it — a hand copy, an interrupted one, a volume
    /// remounted from a snapshot.
    pub resurrected_keys: usize,
    /// Fan-out jobs sitting in `.dead-letter/`, waiting for a person.
    ///
    /// The same figure [`crate::drain`] reports, counted by the same function: a job nothing will
    /// retry is exactly the kind of thing a health read exists to surface, and a store where
    /// `drain` asks for an operator while `check` says nothing has two answers to one question.
    pub dead_lettered: usize,
    /// What the key material on disk says about its own protection.
    ///
    /// Read from the key files rather than from the wrapper the reading process holds, which is what
    /// makes it an account of the store: `yaam check` run with no passphrase over a wrapped store
    /// used to report it unwrapped and development-only, and neither was true.
    pub key_material: KeyMaterial,
}

impl HealthReport {
    /// Whether anything here calls for an operator.
    ///
    /// The schema version is reported but not judged here: an index newer than this build is refused
    /// by the writer when the pipeline opens, so a report that got this far was read from a file this
    /// build can use.
    ///
    /// A dead letter counts, and it is the one figure here that no amount of waiting reduces —
    /// which is the same judgement [`crate::drain::DrainReport::needs_attention`] makes, so the two
    /// commands cannot differ about whether one store wants somebody.
    ///
    /// A resurrected key counts, and it is the most serious thing this report can say: a body a data
    /// subject was told had been erased is readable again. A quarantine past
    /// [`QUARANTINE_SLA_MS`] counts too — the depth alone never distinguished a spool draining
    /// normally from one that had stopped, which is what made the missing hard stop invisible rather
    /// than merely unimplemented.
    ///
    /// Key material in the clear is reported but not judged either, with one exception. A store
    /// deliberately opened unwrapped is a development store, and a command whose exit code called
    /// that broken would be a command a development script has to ignore. A store holding *both*
    /// wrapped and unwrapped keys is nobody's decision: no wrapper reads all of it, so some sealed
    /// bodies are unreadable, and only a person can put that right.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.index_drift > 0
            || self.sweeper_backlog.total() > 0
            || self.dead_lettered > 0
            || self.resurrected_keys > 0
            || self.quarantine_overdue()
            || matches!(self.key_material, KeyMaterial::Mixed { .. })
    }

    /// Whether the quarantine spool has outlived the SLA, or holds something no clock can age out.
    ///
    /// Both arms are the same fault seen twice: a record nobody will come back for. The undated arm
    /// is the one a threshold alone would miss forever.
    #[must_use]
    pub fn quarantine_overdue(&self) -> bool {
        self.quarantine_undated > 0
            || self
                .quarantine_oldest_ms
                .is_some_and(|age| age >= QUARANTINE_SLA_MS)
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
/// needs a rebuild, not a closer look at its queue depths. A key file that cannot be read fails the
/// same way, for the same reason: a report that skipped one would be a report about the key material
/// it happened to be able to open.
pub fn check(pipeline: &Pipeline) -> Result<HealthReport> {
    let store = pipeline.reader()?;
    let index = yaam_store::health::read(&store)?;
    let claim_cutoff = fsutil::now_ms() - sweeper::CLAIM_GRACE_MS;
    let (quarantine_oldest_ms, quarantine_undated) = restore::quarantine_age(pipeline)?;
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
        quarantine_oldest_ms,
        quarantine_undated,
        resurrected_keys: restore::resurrected_keys(pipeline)?,
        dead_lettered: crate::drain::dead_lettered(pipeline)?,
        key_material: pipeline.key_material()?,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use yaam_crypto::keystore::{KeyMaterial, Passthrough};
    use yaam_crypto::wrapper::{Cost, PassphraseWrapper, Scheme};

    use super::check;
    use crate::testkit::{self, BODY, Harness};

    /// A wrapper cheap enough that these tests are not an argon2 benchmark.
    fn cheap_wrapper() -> PassphraseWrapper {
        PassphraseWrapper::with_salt(
            b"a passphrase",
            [7u8; 16],
            Cost {
                memory_kib: 8,
                passes: 1,
                lanes: 1,
            },
        )
        .expect("wrapper")
    }

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
        assert_eq!(report.dead_lettered, 0);
        assert!(!report.needs_attention());
    }

    /// A job set aside is the one figure here that no amount of waiting reduces, so it is the one a
    /// clean health read would be most wrong about.
    #[test]
    fn a_job_set_aside_for_a_person_is_counted_and_wants_one() {
        let harness = Harness::new();
        fs::write(
            harness.root().join(".dead-letter/some-record.bundle"),
            "record: some-record\njob: bundle\nattempts: 5\nreason: gone\n",
        )
        .expect("a job set aside");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.dead_lettered, 1);
        assert_eq!(
            report.sweeper_backlog.total(),
            0,
            "nothing is queued: this is work that stopped, not work that is waiting"
        );
        assert!(report.needs_attention());
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

    /// A quarantined record is held on disk, and the depth is read from there — with the age of
    /// the oldest beside it, because the depth alone never told a spool that is draining from one
    /// that has stopped.
    #[test]
    fn a_held_record_is_counted_from_the_spool_and_carries_its_age() {
        let mut harness = Harness::new().resolving_with(testkit::UnavailableLookup);
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-23T12:00:00Z", &[testkit::subject('f')]),
                BODY,
            )
            .expect("quarantined");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.quarantine_depth, 1);
        assert!(
            report.quarantine_oldest_ms.is_some_and(|age| age > 0),
            "the age comes from the record's own stamp: {report:?}"
        );
        assert_eq!(report.quarantine_undated, 0);
    }

    /// The threshold, and the fault it makes visible. A spool that has outlived the SLA is an
    /// outage that stopped, not a lookup about to answer, and there is no terminal state to expire
    /// it — so being seen is the whole mechanism.
    #[test]
    fn a_spool_past_the_sla_wants_a_person() {
        let harness = Harness::new();
        let spool = harness.root().join(crate::layout::QUARANTINE_DIR);
        fs::create_dir_all(&spool).expect("spool");
        let document =
            crate::testkit::plain_document(&testkit::internal("2020-01-01T00:00:00Z"), "");
        fs::write(spool.join("held.md"), document.render()).expect("held");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.quarantine_depth, 1);
        assert!(
            report.quarantine_oldest_ms.expect("an age") >= super::QUARANTINE_SLA_MS,
            "{report:?}"
        );
        assert!(report.quarantine_overdue());
        assert!(report.needs_attention());
    }

    /// Two numbers, one argument. §10.4 ties the quarantine hard stop to the key-backup window —
    /// re-keying a record needs every share, so its subjects must resolve before any of them is
    /// shredded, and a shred completes at the end of that window. They are separate constants
    /// because they are separate facts; this is what stops one moving without the other being
    /// argued for.
    #[test]
    fn the_quarantine_sla_is_the_key_backup_window() {
        assert_eq!(
            super::QUARANTINE_SLA_MS,
            crate::erase::KEY_BACKUP_WINDOW_MS,
            "a record whose quarantine outlived the key-backup window is one whose re-keying had \
             already become impossible"
        );
    }

    /// The most serious thing this report can say, and it is nil on every store where nothing has
    /// gone wrong — which is why it is a figure rather than a warning that only ever appears once.
    #[test]
    fn a_key_standing_for_an_erased_subject_wants_a_person() {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject)),
                BODY,
            )
            .expect("accepted");
        assert_eq!(
            check(&harness.pipeline).expect("health").resurrected_keys,
            0
        );

        crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let report = check(&harness.pipeline).expect("health");
        assert_eq!(
            report.resurrected_keys, 0,
            "an erasure leaves nothing standing: {report:?}"
        );

        // A key store recovered by hand from a copy taken before the erasure. Every live refusal
        // goes on being made correctly, because they are made from the tree — this is the one figure
        // that says the destruction has been walked back.
        let key = harness
            .pipeline
            .paths()
            .key_store
            .join("keys")
            .join(subject.as_str());
        fs::create_dir_all(&key).expect("dir");
        fs::write(key.join("2026-Q3"), [0u8; 32]).expect("a key that came back");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.resurrected_keys, 1);
        assert!(report.needs_attention());
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

    /// The store the old report was most wrong about: nothing subject-derived has been written, so
    /// there is no key material to be wrapped or in the clear, and "none, development only" was a
    /// claim about files that do not exist.
    #[test]
    fn a_store_that_has_sealed_nothing_reports_no_key_material() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.key_material, KeyMaterial::Absent);
        assert!(!report.key_material.exposed());
        assert!(
            !report.needs_attention(),
            "a store with no key material is not a store to page anyone about"
        );
    }

    /// The one state the development-only warning belongs to.
    #[test]
    fn key_material_written_in_the_clear_is_reported_as_such() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(report.key_material, KeyMaterial::Unwrapped { files: 1 });
        assert!(report.key_material.exposed());
        assert!(
            !report.needs_attention(),
            "unwrapped is a configuration somebody chose, so it is reported and not judged"
        );
    }

    /// Read from the header, so a report is the store's and not the reader's. This is the deployment
    /// bug: an operator with no passphrase asking a wrapped store what it holds.
    #[test]
    fn wrapped_key_material_is_named_to_a_reader_holding_no_passphrase() {
        let mut harness = Harness::new().wrapping_keys_with(cheap_wrapper());
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let harness = harness.wrapping_keys_with(Passthrough);
        let report = check(&harness.pipeline).expect("health");
        assert_eq!(
            report.key_material,
            KeyMaterial::Wrapped {
                scheme: Some(Scheme::PassphraseArgon2id),
                files: 1,
            }
        );
        assert!(!report.key_material.exposed());
        assert!(
            report.key_material.to_string().contains("argon2id"),
            "the scheme comes from the blob: {}",
            report.key_material
        );
        assert!(
            !harness.pipeline.key_wrapper_protects(),
            "and no passphrase"
        );
    }

    /// What fitting a wrapper to a store that already held keys leaves behind. Neither answer alone
    /// is true of it, and the wrapped half is the half nothing can read.
    #[test]
    fn a_store_holding_both_kinds_of_key_asks_for_a_person() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", &[testkit::subject('a')]),
                BODY,
            )
            .expect("accepted");
        let mut harness = harness.wrapping_keys_with(cheap_wrapper());
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T10:00:00Z", &[testkit::subject('b')]),
                BODY,
            )
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let report = check(&harness.pipeline).expect("health");
        assert_eq!(
            report.key_material,
            KeyMaterial::Mixed {
                wrapped: 1,
                unwrapped: 1,
            }
        );
        assert!(report.key_material.exposed());
        assert!(
            report.needs_attention(),
            "no wrapper reads all of this store, and only a person can settle it"
        );
    }
}
