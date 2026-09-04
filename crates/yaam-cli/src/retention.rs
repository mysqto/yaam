//! The retention pass, and the legal holds that outrank it.
//!
//! Its own module rather than a ninth and tenth report in [`crate::ops`] because the two belong
//! together: the hold exists so that a destruction — this pass's, or `erase`'s — has something to
//! be refused by, and reading either half without the other leaves the impression that a retention
//! period is unconditional.
//!
//! Thin for the reason [`crate::ops`] is thin. What is due, what a quarter's granularity costs, and
//! what a hold forbids are all [`yaam_core::retain`]'s and [`yaam_core::hold`]'s judgements. What is
//! here is the confirmation flag, the prose an operator reads, and the exit code a script reads.

use std::fmt::Write as _;
use std::io::Write;

use yaam_contract::timestamp;
use yaam_contract::{RecordId, SubjectHash};
use yaam_core::hold::Hold;
use yaam_core::retain::RetainReport;
use yaam_core::{Pipeline, hold, retain};

use crate::cli::HoldCommand;
use crate::error::{Error, Result, config, failed};
use crate::exit::Exit;
use crate::ops::{emit, line};

/// What a destroyed epoch does and does not reach, said wherever the pass is offered.
///
/// Repeated at the point of action rather than left to the documentation, for the reason `erase`
/// repeats its own sentence: this is what an operator has to have read before confirming.
const REACHES: &str = "destroying an epoch's keys makes the sealed bodies of every record received \
     in that quarter permanently unreadable, in this copy and in every other, because no surviving \
     copy holds the key. It does not delete records: frontmatter, attributes, entity references and \
     timelines are retained, so the store still answers what happened and only what the records \
     said becomes unreadable.";

/// Runs the retention pass, once the operator has said so explicitly.
///
/// Without `confirmed` this prints what would be destroyed and stops, for the reason `erase` does:
/// a confirmation over a count of quarters is not a check, and a count of keys per epoch is.
///
/// [`Exit::Degraded`] where a hold preserved something. Not a failure — the hold winning is the
/// mechanism working — but it is the one outcome that leaves the store holding keys the retention
/// policy says should be gone, and a monitor that could not see it would report a store as retained
/// down to policy while an open litigation hold kept a quarter alive indefinitely.
pub fn retain(
    pipeline: &mut Pipeline,
    keep_quarters: u32,
    confirmed: bool,
    out: &mut dyn Write,
) -> Result<Exit> {
    let now = yaam_core::retain::now_ms();
    let preview = retain::preview(pipeline, keep_quarters, now)
        .map_err(|error| failed("reading what a retention pass would destroy", &error))?;

    if !confirmed {
        let mut text = describe(keep_quarters, &preview, false);
        text.push_str("\nnothing was destroyed. Pass --confirm-destroy-keys to mean it.\n");
        emit(out, &text)?;
        return Err(Error::Unconfirmed(
            "a retention pass destroys keys irreversibly and was not confirmed".to_owned(),
        ));
    }

    let report = retain::destroy_expired(pipeline, keep_quarters, now)
        .map_err(|error| failed("destroying keys past the retention cutoff", &error))?;
    emit(out, &describe(keep_quarters, &report, true))?;
    if report.blocked() {
        Ok(Exit::Degraded)
    } else {
        Ok(Exit::Ok)
    }
}

/// A retention pass, as an operator reads it.
///
/// Every count is one the store can be counted against: `keys/<subject>/<epoch>` is one file per
/// key, so `destroyed_by_epoch` is checkable with `ls`. That is the difference between a report and
/// a reassurance.
fn describe(keep_quarters: u32, report: &RetainReport, done: bool) -> String {
    let (least, most) = retain::window_months(keep_quarters);
    let mut text = if done {
        format!("retention pass complete, keeping {keep_quarters} quarter(s)\n")
    } else {
        format!("a retention pass keeping {keep_quarters} quarter(s) would:\n")
    };
    let _ = writeln!(text, "  {:<20}{}", "oldest epoch kept", report.oldest_kept);
    line(&mut text, "keys in the store", report.keys_walked);
    line(&mut text, "keys kept", report.keys_kept);
    line(
        &mut text,
        if done {
            "keys destroyed"
        } else {
            "keys to destroy"
        },
        report.keys_destroyed,
    );
    line(&mut text, "keys held", report.keys_held);
    line(&mut text, "keys unaged", report.keys_unreadable);

    for (epoch, keys) in &report.destroyed_by_epoch {
        let _ = writeln!(
            text,
            "  {:<20}{keys} key(s){}",
            epoch,
            if done { " destroyed" } else { " to destroy" }
        );
    }

    // The granularity, spelled out rather than left as an inference. "One year" and "up to fifteen
    // months" are different promises, and only one of them is what a quarter's granularity can keep.
    let _ = writeln!(
        text,
        "\na key covers a whole calendar quarter and cannot be split, so this pass keeps the \
         current quarter and {keep_quarters} before it. No record loses its key before it is \
         {least} months old, and the oldest record still holding one is up to {most} months old: \
         asked for {least} months of retention, this store keeps between {least} and {most}."
    );

    if report.keys_held > 0 {
        let _ = writeln!(
            text,
            "\n{} key(s) past the cutoff were kept for {} subject(s) under a legal hold, which \
             outranks retention. Release the hold when the obligation ends and the next pass takes \
             them:",
            report.keys_held, report.subjects_held
        );
        for id in &report.holds {
            let _ = writeln!(text, "  {id}");
        }
        text.push_str("`yaam hold list` prints them in full.\n");
    }

    if report.keys_unreadable > 0 {
        let _ = writeln!(
            text,
            "\n{} key(s) carry an epoch label this build cannot read as a calendar quarter, so \
             their age is unknown and they were kept. A label another implementation or a later \
             build minted is the expected cause; nothing here will ever age them.",
            report.keys_unreadable
        );
    }

    text.push('\n');
    text.push_str(REACHES);
    text.push('\n');
    text
}

/// Places, lifts or lists holds.
pub fn hold_command(pipeline: &Pipeline, what: &HoldCommand, out: &mut dyn Write) -> Result<Exit> {
    match what {
        HoldCommand::Place {
            subject,
            record,
            reason,
            operator,
        } => place(
            pipeline,
            subject.as_deref(),
            record.as_deref(),
            reason,
            operator,
            out,
        ),
        HoldCommand::Release {
            id,
            reason,
            operator,
        } => release(pipeline, id, reason, operator, out),
        HoldCommand::List => list(pipeline, out),
    }
}

/// Places one hold, over a subject or over the subjects a record names.
fn place(
    pipeline: &Pipeline,
    subject: Option<&str>,
    record: Option<&str>,
    reason: &str,
    operator: &str,
    out: &mut dyn Write,
) -> Result<Exit> {
    let placed = match (subject, record) {
        (Some(subject), None) => {
            let subject = SubjectHash::parse(subject).map_err(|error| {
                config(format!(
                    "--subject is not a subject pseudonym: {error}. It is `s_` followed by 64 hex \
                     characters"
                ))
            })?;
            vec![
                hold::place(pipeline, &subject, reason, operator, &[])
                    .map_err(|error| failed("placing the hold", &error))?,
            ]
        }
        (None, Some(record)) => {
            let record = RecordId::parse(record).map_err(|error| {
                config(format!(
                    "--record is not a record identifier: {error}. It is the 26-character ULID a \
                     record is filed under"
                ))
            })?;
            hold::place_over_record(pipeline, &record, reason, operator)
                .map_err(|error| failed("placing the hold", &error))?
        }
        // Clap refuses the pair; neither is a surface it can refuse for us, because both are
        // optional on their own.
        _ => {
            return Err(Error::Usage(
                "a hold is placed over exactly one of --subject and --record".to_owned(),
            ));
        }
    };

    let mut text = format!("placed {} hold(s)\n", placed.len());
    for hold in &placed {
        describe_hold(&mut text, hold);
    }
    text.push_str(
        "\na hold outranks both erasure and retention: `erase` refuses while it stands, and a \
         retention pass keeps the subject's keys and names the hold. It is not a deletion of \
         anything and it expires on nothing — release it when the obligation ends, or it holds for \
         ever.\n",
    );
    emit(out, &text)?;
    Ok(Exit::Ok)
}

/// Lifts one hold by identifier.
fn release(
    pipeline: &Pipeline,
    id: &str,
    reason: &str,
    operator: &str,
    out: &mut dyn Write,
) -> Result<Exit> {
    let hold = hold::release(pipeline, id, reason, operator)
        // Rejected rather than failed: an unknown identifier and a hold already lifted are both
        // permanent as asked, and retrying the same command changes neither.
        .map_err(|error| Error::Rejected(error.to_string()))?;
    let mut text = format!("released {}\n", hold.id);
    describe_hold(&mut text, &hold);
    let _ = writeln!(text, "  {:<20}{operator}: {reason}", "lifted by");
    text.push_str(
        "\nthe placement and the lift are both on record: the log is append-only, so what was held \
         then stays readable and this release is a line rather than an edit. Nothing was destroyed \
         — the next `erase` or `retain` is now free to reach these keys.\n",
    );
    emit(out, &text)?;
    Ok(Exit::Ok)
}

/// Lists what stands.
fn list(pipeline: &Pipeline, out: &mut dyn Write) -> Result<Exit> {
    let holds = hold::standing(pipeline).map_err(|error| failed("reading the holds", &error))?;
    let mut text = format!("{} hold(s) standing\n", holds.len());
    if holds.is_empty() {
        text.push_str(
            "nothing is held, so `erase` and `retain` are unconditional here. A hold placed \
             against a subject this store has never heard of would still show, which is what makes \
             an empty answer mean what it says.\n",
        );
    }
    for hold in &holds {
        describe_hold(&mut text, hold);
    }
    emit(out, &text)?;
    Ok(Exit::Ok)
}

/// One hold, in the form every command here prints it.
fn describe_hold(text: &mut String, hold: &Hold) {
    let _ = writeln!(text, "  {}", hold.id);
    let _ = writeln!(text, "  {:<20}{}", "subject", hold.subject.as_str());
    let _ = writeln!(
        text,
        "  {:<20}{}",
        "placed",
        timestamp::format_ms(hold.at_ms)
    );
    let _ = writeln!(text, "  {:<20}{}", "placed by", hold.operator);
    let _ = writeln!(text, "  {:<20}{}", "reason", hold.reason);
    if !hold.records.is_empty() {
        let _ = writeln!(text, "  {:<20}{}", "over records", hold.records.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use yaam_core::{Paths, Pipeline};
    use yaam_crypto::keystore::{FsKeyStore, KeyStore as _};

    use super::{hold_command, retain};
    use crate::cli::HoldCommand;
    use crate::exit::Exit;
    use crate::fixtures::{self, BODY};

    /// A tree with this repository's spec, the pipeline over it, and a second handle on its key
    /// store.
    ///
    /// The second handle is how a test mints and counts keys. `Pipeline` keeps its own custody
    /// private, and widening that so a test could reach it would put a key store on the interface
    /// for the sake of a test.
    struct Tree {
        _dir: tempfile::TempDir,
        pipeline: Pipeline,
        keys: FsKeyStore,
    }

    impl Tree {
        fn new() -> Self {
            let dir = fixtures::tree();
            let paths = Paths::under(dir.path());
            let keys = FsKeyStore::unwrapped(&paths.key_store).expect("a key store");
            let pipeline = Pipeline::with_paths(paths).expect("a pipeline over the tree");
            Self {
                _dir: dir,
                pipeline,
                keys,
            }
        }

        /// Mints one key for a subject, `back` quarters before the current one.
        ///
        /// Relative to this process's clock, because the command line reads that clock and takes no
        /// flag to override it — deliberately, since an `--as-of` would let an operator destroy
        /// more than policy allows. The quarter-boundary arithmetic itself is asserted where the
        /// instant *is* a parameter, in `yaam_core::retain`'s own tests.
        fn mint(&self, subject: &yaam_contract::SubjectHash, back: u32) {
            self.keys
                .mint(subject, &Self::epoch_back(back))
                .expect("minted");
        }

        /// The epoch `back` quarters before the current one.
        fn epoch_back(back: u32) -> yaam_crypto::seal::Epoch {
            yaam_crypto::seal::Epoch::containing(yaam_core::retain::now_ms())
                .quarters_before(back)
                .expect("a quarter inside the calendar")
        }

        /// How many keys the store holds.
        fn key_count(&self) -> usize {
            self.keys.key_epochs().expect("walk").len()
        }
    }

    /// The text a command printed.
    fn run(command: impl FnOnce(&mut Vec<u8>) -> crate::error::Result<Exit>) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = command(&mut out).expect("the command ran");
        (exit, String::from_utf8(out).expect("utf-8"))
    }

    /// The report says what a quarter's granularity costs, in the numbers a regulator would ask
    /// about.
    ///
    /// Not a nicety. "One year of retention" and "up to fifteen months of retention" are different
    /// claims, and only the second is one a quarter-granular key store can keep. A report that
    /// printed the policy back without the consequence would let an operator repeat the wrong one.
    #[test]
    fn an_unconfirmed_retention_pass_spells_out_the_quarter_granularity_and_destroys_nothing() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        // Five quarters back, so a four-quarter policy is one whole quarter past it.
        tree.mint(&subject, 5);

        let mut out = Vec::new();
        let error = retain(&mut tree.pipeline, 4, false, &mut out)
            .expect_err("an unconfirmed pass must not destroy");
        assert_eq!(error.exit(), Exit::Unconfirmed);
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(
            printed.contains(&format!(
                "oldest epoch kept   {}",
                Tree::epoch_back(4).as_str()
            )),
            "{printed}"
        );
        assert!(printed.contains("keys to destroy     1"), "{printed}");
        assert!(
            printed.contains("between 12 and 15"),
            "the granularity is the cost, and it has to be in the report: {printed}"
        );
        assert!(printed.contains("--confirm-destroy-keys"), "{printed}");
        assert_eq!(tree.key_count(), 1, "nothing was destroyed");
    }

    /// A confirmed pass destroys, reports per epoch, and a second run reports nothing.
    ///
    /// The per-epoch line is what makes the report checkable rather than merely reassuring: the key
    /// store holds one file per subject and epoch, so an operator can count it.
    #[test]
    fn a_confirmed_retention_pass_reports_per_epoch_and_is_safe_to_run_again() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        // One whole quarter past the cutoff, and one inside it.
        tree.mint(&subject, 5);
        tree.mint(&subject, 1);

        let (exit, printed) = run(|out| retain(&mut tree.pipeline, 4, true, out));
        assert_eq!(exit, Exit::Ok);
        assert!(printed.contains("keys destroyed      1"), "{printed}");
        assert!(
            printed.contains(&format!(
                "{:<20}1 key(s) destroyed",
                Tree::epoch_back(5).as_str()
            )),
            "the per-epoch line is what an operator counts against `keys/`: {printed}"
        );

        let (exit, again) = run(|out| retain(&mut tree.pipeline, 4, true, out));
        assert_eq!(exit, Exit::Ok, "running it twice is not a failure");
        assert!(again.contains("keys destroyed      0"), "{again}");
        assert_eq!(tree.key_count(), 1);
    }

    /// A held key survives the pass, the report names the hold, and the exit code says so.
    ///
    /// [`Exit::Degraded`] because this is the one outcome that leaves the store holding keys the
    /// retention policy says should be gone. A monitor that saw `0` here would report a store
    /// retained down to policy while an open obligation kept a quarter alive indefinitely.
    #[test]
    fn a_retention_pass_blocked_by_a_hold_says_which_hold_and_exits_degraded() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        tree.mint(&subject, 5);

        let (exit, placed) = run(|out| {
            hold_command(
                &tree.pipeline,
                &HoldCommand::Place {
                    subject: Some(subject.as_str().to_owned()),
                    record: None,
                    reason: "litigation hold on an open matter".to_owned(),
                    operator: "operator_a".to_owned(),
                },
                out,
            )
        });
        assert_eq!(exit, Exit::Ok);
        assert!(placed.contains("placed 1 hold(s)"), "{placed}");
        let id = placed
            .lines()
            .find_map(|line| line.trim().strip_prefix("hold-"))
            .map(|rest| format!("hold-{rest}"))
            .expect("the report prints the identifier an operator releases by");

        let (exit, printed) = run(|out| retain(&mut tree.pipeline, 4, true, out));
        assert_eq!(exit, Exit::Degraded);
        assert!(printed.contains("keys destroyed      0"), "{printed}");
        assert!(printed.contains("keys held           1"), "{printed}");
        assert!(
            printed.contains(&id),
            "the report has to name what to release: {printed}"
        );
        assert_eq!(tree.key_count(), 1, "the held key is still there");

        // Released, the same pass takes it.
        let (exit, released) = run(|out| {
            hold_command(
                &tree.pipeline,
                &HoldCommand::Release {
                    id: id.clone(),
                    reason: "matter closed".to_owned(),
                    operator: "operator_a".to_owned(),
                },
                out,
            )
        });
        assert_eq!(exit, Exit::Ok);
        assert!(released.contains("released hold-"), "{released}");
        let (exit, printed) = run(|out| retain(&mut tree.pipeline, 4, true, out));
        assert_eq!(exit, Exit::Ok);
        assert!(printed.contains("keys destroyed      1"), "{printed}");
    }

    /// An erasure under a hold is refused with the hold, and exits `8` rather than `1`.
    ///
    /// A hold is permanent as asked: retrying the same command changes nothing, and only a person
    /// can decide which of the two obligations now applies. Reported as a plain failure it would
    /// look like a store fault.
    #[test]
    fn an_erasure_under_a_hold_is_refused_with_the_hold_and_not_as_a_fault() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &subject),
                BODY,
            )
            .expect("accepted");
        yaam_core::hold::place(
            &tree.pipeline,
            &subject,
            "litigation hold on an open matter",
            "operator_a",
            &[],
        )
        .expect("placed");

        let mut out = Vec::new();
        // Confirmed, deliberately: `--confirm-destroy-keys` must not read as a flag that overrides
        // a preservation order.
        let error = crate::ops::erase(&mut tree.pipeline, subject.as_str(), true, &mut out)
            .expect_err("a hold outranks an erasure");
        assert_eq!(error.exit(), Exit::Rejected);
        assert!(
            error
                .to_string()
                .contains("litigation hold on an open matter"),
            "the refusal has to say which obligation blocked it: {error}"
        );
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(printed.contains("and it is refused"), "{printed}");
        assert!(printed.contains("yaam hold release"), "{printed}");
        assert_eq!(tree.key_count(), 1, "nothing was destroyed");
    }

    /// A hold over a record holds its subjects, and the listing surfaces what stands.
    ///
    /// A hold nobody can enumerate is a hold that will be forgotten, so the listing is part of the
    /// mechanism rather than a convenience.
    #[test]
    fn a_hold_placed_over_a_record_is_listed_against_the_subjects_it_protects() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        let record = fixtures::subject_record("2026-08-20T09:00:00Z", &subject);
        let id = record.record_id.clone();
        tree.pipeline.accept(record, BODY).expect("accepted");

        let (_, empty) = run(|out| hold_command(&tree.pipeline, &HoldCommand::List, out));
        assert!(empty.contains("0 hold(s) standing"), "{empty}");
        assert!(
            empty.contains("nothing is held"),
            "an empty answer has to say what it means: {empty}"
        );

        let (_, placed) = run(|out| {
            hold_command(
                &tree.pipeline,
                &HoldCommand::Place {
                    subject: None,
                    record: Some(id.as_str().to_owned()),
                    reason: "preservation order".to_owned(),
                    operator: "operator_a".to_owned(),
                },
                out,
            )
        });
        assert!(placed.contains(subject.as_str()), "{placed}");
        assert!(placed.contains(id.as_str()), "{placed}");

        let (_, listed) = run(|out| hold_command(&tree.pipeline, &HoldCommand::List, out));
        assert!(listed.contains("1 hold(s) standing"), "{listed}");
        assert!(listed.contains("preservation order"), "{listed}");
        assert!(listed.contains("operator_a"), "{listed}");
    }

    /// Neither a bad pseudonym nor a bad record identifier nor neither flag reaches the log.
    #[test]
    fn a_hold_over_nothing_askable_is_refused_before_anything_is_written() {
        let tree = Tree::new();
        for what in [
            HoldCommand::Place {
                subject: Some("not-a-pseudonym".to_owned()),
                record: None,
                reason: "a reason".to_owned(),
                operator: "operator_a".to_owned(),
            },
            HoldCommand::Place {
                subject: None,
                record: Some("not-an-id".to_owned()),
                reason: "a reason".to_owned(),
                operator: "operator_a".to_owned(),
            },
            HoldCommand::Place {
                subject: None,
                record: None,
                reason: "a reason".to_owned(),
                operator: "operator_a".to_owned(),
            },
        ] {
            let mut out = Vec::new();
            assert!(
                hold_command(&tree.pipeline, &what, &mut out).is_err(),
                "{what:?}"
            );
        }
        let (_, listed) = run(|out| hold_command(&tree.pipeline, &HoldCommand::List, out));
        assert!(listed.contains("0 hold(s) standing"), "{listed}");
    }

    /// A release nothing is holding is rejected, not reported as a store fault.
    #[test]
    fn releasing_a_hold_that_does_not_exist_is_a_rejection() {
        let tree = Tree::new();
        let mut out = Vec::new();
        let error = hold_command(
            &tree.pipeline,
            &HoldCommand::Release {
                id: "hold-nothing".to_owned(),
                reason: "closed".to_owned(),
                operator: "operator_a".to_owned(),
            },
            &mut out,
        )
        .expect_err("no such hold");
        assert_eq!(error.exit(), Exit::Rejected);
    }

    /// A cutoff off the end of the calendar is a failure with a reason, not a pass over everything.
    #[test]
    fn a_retention_cutoff_that_cannot_be_computed_is_reported_rather_than_applied() {
        let mut tree = Tree::new();
        let mut out = Vec::new();
        let error = retain(&mut tree.pipeline, 100_000, false, &mut out).expect_err("refused");
        assert!(error.to_string().contains("off the calendar"), "{error}");
    }
}
