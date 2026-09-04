//! Retention, as a pass an operator runs rather than a period a document claims.
//!
//! Keys are minted per subject *and* per calendar quarter so that retention can be enforced by
//! destroying a quarter's keys. That much existed; nothing walked the key store and destroyed
//! anything, so the retention period was a sentence rather than a mechanism. This is the pass.
//!
//! **The unit is a quarter, and that is visible in what it keeps.** A key of epoch `2025-Q4` opens
//! every body received between the first of October and the end of December, so the quarter is
//! indivisible: destroying it reaches the youngest record in it as well as the oldest. The pass
//! therefore errs long. Asked to keep `keep_quarters` quarters it keeps the current one and those,
//! and destroys everything strictly older — so a policy of four quarters retains no record for less
//! than twelve months and some for as long as fifteen. [`window_months`] is that arithmetic, and it
//! is reported rather than left for an operator to work out, because "one year" and "up to fifteen
//! months" are different promises to make to a regulator.
//!
//! **Nothing here runs itself.** No timer, no daemon, no scheduled execution: an operator or an
//! external scheduler invokes it. A destruction that cannot be un-done is not something a process
//! should decide to do while nobody is watching, and a period that a service enforced on its own
//! clock would be enforced on a restored store's clock too.
//!
//! **It is safe to run twice.** The pass reads what the key store holds and destroys what is past
//! the cutoff; a key already gone is not in the walk, and the destruction itself treats an absent
//! file as success. A second run over an unchanged store destroys nothing and says so.
//!
//! **A hold outranks it.** [`crate::hold`] is consulted for every candidate, and a held key is
//! reported as held rather than passed over in silence — a pass whose report did not distinguish
//! "nothing was due" from "the obligation to preserve won" would hide the one outcome an operator
//! has to act on.
//!
//! **What it does not do.** It does not rewrite the tree. The mechanism is that the key is gone, in
//! this copy and every other; the ciphertext left behind is inert. Rewriting every record whose
//! epoch was destroyed would demand a full index rebuild on a routine operation, which
//! [`crate::erase`] can afford once per request and this cannot. The consequence is worth stating:
//! [`crate::unseal`] reports such a body as gone with no erasure accounting for it, which is true —
//! no erasure did — and the epoch label it prints beside that is what an operator joins against the
//! cutoff below. Nothing here records *when* a cutoff was applied, so that join is against the
//! policy rather than against a log.

use std::collections::{BTreeMap, BTreeSet};

use yaam_contract::SubjectHash;
use yaam_crypto::keystore::KeyStore as _;
use yaam_crypto::seal::Epoch;

use crate::{Pipeline, Result};

/// One key the store holds, and what the pass decided about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    /// Whose key it is.
    subject: SubjectHash,
    /// Which quarter it opens.
    epoch: Epoch,
    /// What the cutoff and the holds together decided.
    verdict: Verdict,
}

/// What a pass decided about one key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Newer than the cutoff.
    Keep,
    /// Older than the cutoff, and nothing preserves it.
    Destroy,
    /// Older than the cutoff, and these holds preserve it.
    Held(Vec<String>),
    /// An epoch label this build cannot read as a quarter, so its age is unknown and it is kept.
    Unreadable,
}

/// What a retention pass would do, or did.
///
/// The counts are deliberately checkable against the store rather than summary figures: `keys/`
/// holds one file per subject and epoch, so `destroyed_by_epoch` is a claim an operator can count.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetainReport {
    /// The oldest epoch whose keys survive this cutoff.
    pub oldest_kept: String,
    /// Keys the key store held when the pass began.
    pub keys_walked: usize,
    /// Keys newer than the cutoff, left alone.
    pub keys_kept: usize,
    /// Keys destroyed. Zero on a second run over an unchanged store.
    pub keys_destroyed: usize,
    /// Keys past the cutoff that a hold preserved.
    pub keys_held: usize,
    /// Keys whose epoch label this build cannot read as a quarter, and which are kept whatever
    /// their age. Not zero is a store to look at: it means another implementation, or a later
    /// build, minted labels this pass declines to age.
    pub keys_unreadable: usize,
    /// How many keys were destroyed, per epoch label.
    pub destroyed_by_epoch: BTreeMap<String, usize>,
    /// Identifiers of the holds that preserved something, so the report names what to release.
    pub holds: Vec<String>,
    /// Subjects a hold preserved keys for.
    pub subjects_held: usize,
}

impl RetainReport {
    /// Whether anything was preserved against the cutoff by a hold.
    #[must_use]
    pub fn blocked(&self) -> bool {
        self.keys_held > 0
    }
}

/// The narrowest and widest retention a whole number of quarters can promise, in months.
///
/// Reported rather than reasoned about at the call site. Asked to keep `keep_quarters` quarters,
/// the pass destroys a key only once the whole quarter it covers is that far behind, so the
/// youngest record it reaches is `3 × keep_quarters` months old and the oldest record it spares is
/// up to three months older than that. Four quarters is therefore "twelve to fifteen months", and
/// saying "a year" without saying which is how a retention claim becomes untrue in the direction
/// nobody checks.
#[must_use]
pub const fn window_months(keep_quarters: u32) -> (u32, u32) {
    (keep_quarters * 3, keep_quarters * 3 + 3)
}

/// This process's clock, in milliseconds since the Unix epoch.
///
/// Exported because the two passes below take the instant rather than reading a clock of their own:
/// a cutoff a test cannot choose is a quarter boundary nothing can assert. The command line passes
/// this; a test passes the instant it wants to stand on.
#[must_use]
pub fn now_ms() -> i64 {
    crate::fsutil::now_ms()
}

/// What a pass would destroy, without destroying it.
///
/// Read-only, and its own function for the reason [`crate::erase::preview`] is: the destruction
/// cannot be undone, and a confirmation over a count of quarters is not a check while a count of
/// keys is.
pub fn preview(pipeline: &Pipeline, keep_quarters: u32, as_of_ms: i64) -> Result<RetainReport> {
    let (oldest_kept, candidates) = survey(pipeline, keep_quarters, as_of_ms)?;
    Ok(tally(&oldest_kept, &candidates))
}

/// Destroys every key past the cutoff that no hold preserves.
///
/// The walk is taken once and acted on, rather than re-derived per destruction: a key minted while
/// the pass runs belongs to the current quarter and is never a candidate, so the only drift the
/// order could produce is a key destroyed by something else in the meantime — which
/// [`yaam_crypto::keystore::KeyStore::destroy_epoch`] treats as success, because it has to for the
/// erasure sweeper to be able to replay.
pub fn destroy_expired(
    pipeline: &mut Pipeline,
    keep_quarters: u32,
    as_of_ms: i64,
) -> Result<RetainReport> {
    let (oldest_kept, candidates) = survey(pipeline, keep_quarters, as_of_ms)?;
    for candidate in &candidates {
        if candidate.verdict == Verdict::Destroy {
            pipeline
                .keys()
                .destroy_epoch(&candidate.subject, &candidate.epoch)?;
        }
    }
    let report = tally(&oldest_kept, &candidates);
    if report.keys_destroyed > 0 {
        tracing::info!(
            keys = report.keys_destroyed,
            oldest_kept = report.oldest_kept.as_str(),
            "retention destroyed subject keys"
        );
    }
    Ok(report)
}

/// Every key the store holds, with the cutoff and what it decides about each.
///
/// One read of the hold log for the whole walk. Asking per subject would read the same file once
/// per key and, worse, could see a hold placed halfway through — so a pass would destroy under one
/// answer and report under another.
fn survey(
    pipeline: &Pipeline,
    keep_quarters: u32,
    as_of_ms: i64,
) -> Result<(Epoch, Vec<Candidate>)> {
    let now = Epoch::containing(as_of_ms);
    let oldest_kept = now.quarters_before(keep_quarters).ok_or_else(|| {
        crate::pipeline::invalid(format!(
            "keeping {keep_quarters} quarter(s) before `{}` reaches off the calendar an epoch \
             label can express, so there is no cutoff to apply",
            now.as_str()
        ))
    })?;

    let mut held: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for hold in crate::hold::standing(pipeline)? {
        held.entry(hold.subject.as_str().to_owned())
            .or_default()
            .push(hold.id);
    }

    let mut candidates = Vec::new();
    for (subject, epoch) in pipeline.keys().key_epochs()? {
        let verdict = match epoch.precedes(&oldest_kept) {
            None => Verdict::Unreadable,
            Some(false) => Verdict::Keep,
            Some(true) => match held.get(subject.as_str()) {
                Some(holds) => Verdict::Held(holds.clone()),
                None => Verdict::Destroy,
            },
        };
        candidates.push(Candidate {
            subject,
            epoch,
            verdict,
        });
    }
    Ok((oldest_kept, candidates))
}

/// The report a surveyed walk adds up to.
fn tally(oldest_kept: &Epoch, candidates: &[Candidate]) -> RetainReport {
    let mut report = RetainReport {
        oldest_kept: oldest_kept.as_str().to_owned(),
        keys_walked: candidates.len(),
        ..RetainReport::default()
    };
    let mut holds = BTreeSet::new();
    let mut subjects_held = BTreeSet::new();
    for candidate in candidates {
        match &candidate.verdict {
            Verdict::Keep => report.keys_kept += 1,
            Verdict::Unreadable => report.keys_unreadable += 1,
            Verdict::Destroy => {
                report.keys_destroyed += 1;
                *report
                    .destroyed_by_epoch
                    .entry(candidate.epoch.as_str().to_owned())
                    .or_default() += 1;
            }
            Verdict::Held(ids) => {
                report.keys_held += 1;
                holds.extend(ids.iter().cloned());
                subjects_held.insert(candidate.subject.as_str().to_owned());
            }
        }
    }
    report.holds = holds.into_iter().collect();
    report.subjects_held = subjects_held.len();
    report
}

#[cfg(test)]
mod tests {
    use yaam_crypto::keystore::KeyStore as _;

    use super::{destroy_expired, preview, window_months};
    use crate::testkit::{self, Harness};

    /// The first instant of 2027-Q1.
    const Q1_2027: i64 = 1_798_761_600_000;
    /// The last instant of 2026-Q4, one millisecond earlier.
    const Q4_2026_END: i64 = 1_798_761_599_999;

    /// A store holding one subject's keys for each of the labelled quarters.
    fn with_keys(labels: &[&str]) -> (Harness, yaam_contract::SubjectHash) {
        let harness = Harness::new();
        let subject = testkit::subject('a');
        for label in labels {
            let epoch = yaam_crypto::seal::Epoch::from_stored(label).expect("a label");
            harness
                .pipeline
                .keys()
                .mint(&subject, &epoch)
                .expect("minted");
        }
        (harness, subject)
    }

    /// Epochs this store holds for one subject, oldest first.
    fn epochs(harness: &Harness, subject: &yaam_contract::SubjectHash) -> Vec<String> {
        harness
            .pipeline
            .keys()
            .key_epochs()
            .expect("walk")
            .into_iter()
            .filter(|(held, _)| held == subject)
            .map(|(_, epoch)| epoch.as_str().to_owned())
            .collect()
    }

    /// One millisecond decides a whole quarter's keys, and the pass errs long.
    ///
    /// The granularity property. A key covers a calendar quarter and cannot be split, so a cutoff
    /// cannot land inside one: at the last instant of 2026-Q4 a four-quarter policy still keeps
    /// 2025-Q4, and one millisecond later it destroys the whole of it. That is why four quarters is
    /// "twelve to fifteen months" rather than "a year" — asserted here so the two numbers cannot
    /// drift apart from the arithmetic that produces them.
    #[test]
    fn the_retention_cutoff_moves_a_whole_quarter_at_a_time_and_never_part_of_one() {
        assert_eq!(
            window_months(4),
            (12, 15),
            "four quarters keeps no record less than twelve months and some for fifteen"
        );

        let labels = ["2025-Q3", "2025-Q4", "2026-Q1", "2026-Q4", "2027-Q1"];
        let (mut harness, subject) = with_keys(&labels);

        // The last instant of 2026-Q4: the current quarter is 2026-Q4, so keeping four quarters
        // keeps back to 2025-Q4 and only 2025-Q3 is past the cutoff.
        let before = preview(&harness.pipeline, 4, Q4_2026_END).expect("previewed");
        assert_eq!(before.oldest_kept, "2025-Q4");
        assert_eq!(before.keys_destroyed, 1);
        assert_eq!(
            before.destroyed_by_epoch.keys().collect::<Vec<_>>(),
            vec!["2025-Q3"]
        );

        // One millisecond later the current quarter is 2027-Q1, and the cutoff has moved a whole
        // quarter: 2025-Q4 goes with 2025-Q3, all at once.
        let after = preview(&harness.pipeline, 4, Q1_2027).expect("previewed");
        assert_eq!(after.oldest_kept, "2026-Q1");
        assert_eq!(after.keys_destroyed, 2);

        let report = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("destroyed");
        assert_eq!(report.keys_destroyed, 2);
        assert_eq!(
            epochs(&harness, &subject),
            vec!["2026-Q1", "2026-Q4", "2027-Q1"],
            "everything from the cutoff onwards, and nothing before it"
        );
    }

    /// Running the pass twice destroys nothing the second time.
    ///
    /// What makes it safe to put behind a scheduler that may fire twice, or to re-run after an
    /// interruption. The second run must not merely avoid failing: it has to *report* nothing
    /// destroyed, because an operator reconciling two runs against the store would otherwise be
    /// told the same keys were destroyed twice.
    #[test]
    fn a_second_retention_pass_over_an_unchanged_store_destroys_nothing() {
        let (mut harness, subject) = with_keys(&["2025-Q3", "2025-Q4", "2026-Q4"]);

        let first = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("first pass");
        assert_eq!(first.keys_destroyed, 2);
        assert_eq!(first.keys_walked, 3);
        let after_first = epochs(&harness, &subject);

        let second = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("second pass");
        assert_eq!(second.keys_destroyed, 0, "nothing was left to destroy");
        assert!(second.destroyed_by_epoch.is_empty());
        assert_eq!(second.keys_walked, 1, "only what the first pass left");
        assert_eq!(second.oldest_kept, first.oldest_kept);
        assert_eq!(
            epochs(&harness, &subject),
            after_first,
            "the store is the same"
        );
    }

    /// A hold keeps a key the cutoff would have destroyed, and the report says which hold.
    ///
    /// The arbitration, from the retention side. Two obligations reach the same key: the cutoff
    /// says destroy it and the hold says preserve it. Silence would be the failure — a pass that
    /// skipped a held key without saying so would report a store retained down to policy while an
    /// open obligation kept a quarter alive indefinitely, and nobody would know which.
    #[test]
    fn a_held_subjects_key_is_kept_past_the_cutoff_and_the_report_names_the_hold() {
        let harness = Harness::new();
        let held = testkit::subject('a');
        let free = testkit::subject('b');
        let epoch = yaam_crypto::seal::Epoch::from_stored("2025-Q3").expect("a label");
        for subject in [&held, &free] {
            harness
                .pipeline
                .keys()
                .mint(subject, &epoch)
                .expect("minted");
        }
        let order = crate::hold::place(
            &harness.pipeline,
            &held,
            "preservation order on an open matter",
            "operator_a",
            &[],
        )
        .expect("placed");

        let mut harness = harness;
        let report = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("pass");

        assert_eq!(report.keys_destroyed, 1, "the unheld subject's key went");
        assert_eq!(report.keys_held, 1, "the held subject's did not");
        assert_eq!(report.subjects_held, 1);
        assert_eq!(report.holds, vec![order.id.clone()], "and it says which");
        assert!(report.blocked(), "an operator has to be able to see this");
        assert_eq!(epochs(&harness, &held), vec!["2025-Q3"]);
        assert!(epochs(&harness, &free).is_empty());

        // Released, the same pass takes it: the hold delays destruction, it does not exempt.
        crate::hold::release(&harness.pipeline, &order.id, "matter closed", "operator_a")
            .expect("released");
        let after = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("pass");
        assert_eq!(after.keys_destroyed, 1);
        assert!(!after.blocked());
        assert!(epochs(&harness, &held).is_empty());
    }

    /// An epoch label this build cannot age is kept, whatever it looks like.
    ///
    /// The safe direction, and the one that cannot be undone if it is wrong. A label another
    /// implementation minted might be older than any cutoff, but nothing here can tell — and
    /// destroying a key because its label was unreadable is a body nobody can ever open again.
    #[test]
    fn a_key_whose_epoch_label_cannot_be_read_as_a_quarter_is_kept_and_counted() {
        let (mut harness, subject) = with_keys(&["2025-Q3", "2099-H1"]);

        let report = destroy_expired(&mut harness.pipeline, 4, Q1_2027).expect("pass");
        assert_eq!(report.keys_destroyed, 1);
        assert_eq!(report.keys_unreadable, 1);
        assert_eq!(
            epochs(&harness, &subject),
            vec!["2099-H1"],
            "kept, because its age is not something this build can decide"
        );
    }

    /// A cutoff that falls off the calendar is refused rather than applied to everything.
    #[test]
    fn a_cutoff_that_reaches_off_the_calendar_is_refused() {
        let (harness, _) = with_keys(&["2025-Q3"]);
        let error = preview(&harness.pipeline, 100_000, Q1_2027).expect_err("refused");
        assert!(
            error.to_string().contains("off the calendar"),
            "the refusal has to say why: {error}"
        );
    }

    /// The clock is exported so a caller need not reach for one of its own.
    #[test]
    fn the_passs_own_clock_reads_a_plausible_instant() {
        assert!(super::now_ms() > 1_700_000_000_000);
    }
}
