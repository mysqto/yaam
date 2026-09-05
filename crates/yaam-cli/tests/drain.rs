//! Fan-out through the built binary, on a store nothing else is running against.
//!
//! The property under test is what an operator is left holding. Fan-out is enqueued by a write and
//! re-enqueued wholesale by every rebuild, and it is a *service* that normally runs it — so on a
//! store driven by `yaam` alone, a rebuild that returned without draining left `entities/` empty
//! while `--help` and the contract both said timelines were retained. These tests assert on the
//! timeline files rather than on exit codes, because an empty `entities/` was a state every command
//! reported success over.
//!
//! In process for the writes, because sealing a subject-derived record needs a pipeline, and through
//! the binary for every operator action: what a command leaves behind in the tree is the half a
//! library test does not see.

#![forbid(unsafe_code)]

use std::fs;

use yaam_core::Pipeline;

mod support;

use support::{BODY, Deployment, record, subject, subject_derived, timeline_mentions, yaam};

/// The entity an internal fixture record names.
const TICKET: (&str, &str) = ("ticket", "PROJ-42");

/// The entity a subject-derived fixture record names.
const ORDER: (&str, &str) = ("order_ref", "ord10014721");

#[test]
fn a_store_with_queued_work_is_drained_by_the_subcommand() {
    let deployment = Deployment::new();
    let record = record();
    let id = record.record_id.clone();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline.accept(record, BODY).expect("accepted");
    }
    let timeline = deployment.timeline_dir(TICKET.0, TICKET.1);
    assert_eq!(
        timeline_mentions(&timeline, &id),
        0,
        "the publish enqueues the work; nothing has run it"
    );

    let drained = yaam(&["--root", deployment.root_str(), "drain"]);
    assert_eq!(
        drained.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&drained.stderr)
    );
    let said = String::from_utf8_lossy(&drained.stdout);
    assert!(said.contains("jobs settled        1"), "{said}");
    assert!(said.contains("jobs still queued   0"), "{said}");
    assert_eq!(timeline_mentions(&timeline, &id), 1, "{said}");

    // And the queue a health read sees agrees with the one the drain reported.
    let checked = yaam(&["--root", deployment.root_str(), "check"]);
    assert_eq!(checked.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&checked.stdout).contains("fan-out pending 0"),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
}

/// The regression: a rebuild has to leave the timelines it dropped on disk again.
#[test]
fn a_rebuild_leaves_the_timelines_re_materialised() {
    let deployment = Deployment::new();
    let record = record();
    let id = record.record_id.clone();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline.accept(record, BODY).expect("accepted");
        assert_eq!(pipeline.drain_fanout(10).expect("drained"), 1);
    }
    let head = deployment
        .timeline_dir(TICKET.0, TICKET.1)
        .join("timeline.md");
    assert!(head.is_file());

    let rebuilt = yaam(&["--root", deployment.root_str(), "reindex", "--all"]);
    assert_eq!(
        rebuilt.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let said = String::from_utf8_lossy(&rebuilt.stdout);
    assert!(said.contains("timelines dropped   1"), "{said}");
    assert!(said.contains("jobs still queued   0"), "{said}");

    // The file, and the line in it. "The command exited 0" was true of the state this closes.
    assert!(
        head.is_file(),
        "the rebuild dropped the timeline and left it dropped: {said}"
    );
    assert!(
        fs::read_to_string(&head)
            .expect("the head")
            .contains(&format!("[[record:{}", id.as_str())),
        "the timeline is back but the record is not in it: {:?}",
        fs::read_to_string(&head)
    );
}

/// A restore ends in a rebuild too, and its debt is the one the backup manifest promises: timelines
/// are left out of a backup *because* a rebuild writes them again.
#[test]
fn a_restore_leaves_the_timelines_the_backup_left_behind() {
    let deployment = Deployment::new();
    let record = record();
    let id = record.record_id.clone();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline.accept(record, BODY).expect("accepted");
        assert_eq!(pipeline.drain_fanout(10).expect("drained"), 1);
    }

    // Outside both stores: a backup inside the tree it copies is refused.
    let outside = tempfile::tempdir().expect("tempdir");
    let into = outside.path().join("backup");
    let into_str = into.to_str().expect("utf-8");
    yaam(&["--root", deployment.root_str(), "backup", "--to", into_str]);
    assert!(
        !into.join("entities").exists(),
        "the manifest excludes materialised timelines, which is what makes the drain below owed"
    );

    let destination = tempfile::tempdir().expect("tempdir");
    let destination_str = destination.path().to_str().expect("utf-8");
    let restored = yaam(&["--root", destination_str, "restore", "--from", into_str]);
    let said = String::from_utf8_lossy(&restored.stdout);
    assert_eq!(
        restored.status.code(),
        Some(0),
        "{said}{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(said.contains("jobs still queued   0"), "{said}");

    let head = destination
        .path()
        .join("entities")
        .join(TICKET.0)
        .join(TICKET.1)
        .join("timeline.md");
    assert!(
        fs::read_to_string(&head)
            .unwrap_or_default()
            .contains(&format!("[[record:{}", id.as_str())),
        "a restored store owes the timeline the backup left for it to rebuild: {said}"
    );
}

/// An erasure ends in a rebuild, so it has the same debt to settle — over the timelines the contract
/// says an erasure *retains*.
#[test]
fn an_erasure_leaves_the_timelines_re_materialised() {
    let deployment = Deployment::new().writing_subjects();
    let erased = subject('a');
    let record = subject_derived(std::slice::from_ref(&erased));
    let id = record.record_id.clone();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline.accept(record, BODY).expect("accepted");
        assert_eq!(pipeline.drain_fanout(10).expect("drained"), 2);
    }
    let head = deployment
        .timeline_dir(ORDER.0, ORDER.1)
        .join("timeline.md");
    assert!(head.is_file());

    let erasure = yaam(&[
        "--root",
        deployment.root_str(),
        "erase",
        "--subject",
        erased.as_str(),
        "--confirm-destroy-keys",
    ]);
    assert_eq!(
        erasure.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&erasure.stderr)
    );
    let said = String::from_utf8_lossy(&erasure.stdout);
    assert!(said.contains("keys destroyed      1"), "{said}");
    assert!(said.contains("jobs still queued   0"), "{said}");

    assert!(
        fs::read_to_string(&head)
            .expect("the head")
            .contains(&format!("[[record:{}", id.as_str())),
        "an erasure retains timelines, so the record has to still be listed: {:?}",
        fs::read_to_string(&head)
    );
    // The audit record of the naming is the other half of what fan-out owes, and it outlives the
    // erasure by design: pseudonyms only.
    assert!(
        deployment
            .root()
            .join("audit/subjects")
            .join(format!("{}.md", id.as_str()))
            .is_file()
    );
}

#[test]
fn a_drain_that_hits_its_bound_reports_the_remainder() {
    let deployment = Deployment::new().writing_subjects();
    let root = deployment.root_str();
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline
            .accept(subject_derived(&[subject('b')]), BODY)
            .expect("accepted");
    }

    // Two jobs queued — a timeline and an audit record — and a bound of one.
    let drained = yaam(&["--root", root, "drain", "--max-jobs", "1"]);
    let said = String::from_utf8_lossy(&drained.stdout);
    assert_eq!(
        drained.status.code(),
        Some(4),
        "work left behind is what `check` calls degraded: {said}"
    );
    assert!(said.contains("jobs settled        1"), "{said}");
    assert!(said.contains("jobs still queued   1"), "{said}");
    assert!(said.contains("bound               1"), "{said}");
    assert!(said.contains("the bound stopped this drain"), "{said}");

    // The same remainder, from the command whose job is to report it.
    let checked = yaam(&["--root", root, "check"]);
    assert_eq!(checked.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&checked.stdout).contains("fan-out pending 1"),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );

    // A bound is a pass over the queue, not a loss: the rest is still there for the next one.
    let rest = yaam(&["--root", root, "drain"]);
    assert_eq!(
        rest.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rest.stdout)
    );
}

/// Erasure is the irreversible half, and a fan-out job that cannot run is not it.
#[test]
fn a_fan_out_job_that_cannot_run_does_not_fail_an_erasure() {
    let deployment = Deployment::new().writing_subjects();
    let erased = subject('c');
    {
        let mut pipeline = Pipeline::new(deployment.root()).expect("pipeline");
        pipeline
            .accept(subject_derived(std::slice::from_ref(&erased)), BODY)
            .expect("accepted");
    }

    // A file where the audit record's own directory has to be, so the job that writes it cannot
    // succeed however often it is retried. Under `audit/`, because that survives the rebuild inside
    // the erasure — `entities/` is dropped and made again by it.
    fs::write(deployment.root().join("audit/subjects"), "not a directory").expect("in the way");

    let erasure = yaam(&[
        "--root",
        deployment.root_str(),
        "erase",
        "--subject",
        erased.as_str(),
        "--confirm-destroy-keys",
    ]);
    let said = String::from_utf8_lossy(&erasure.stdout);
    assert_eq!(
        erasure.status.code(),
        Some(0),
        "the keys were destroyed, which is what this command was asked to do: {said}{}",
        String::from_utf8_lossy(&erasure.stderr)
    );
    assert!(said.contains("keys destroyed      1"), "{said}");
    assert!(
        said.contains("jobs still queued   1"),
        "the job that could not run has to be reported: {said}"
    );
    assert!(said.contains("yaam drain"), "{said}");

    // The store is the one that is degraded, and that is the command that says so.
    let checked = yaam(&["--root", deployment.root_str(), "check"]);
    assert_eq!(checked.status.code(), Some(4));
}

/// A job nobody will retry has to look the same to both commands.
///
/// It used not to: `drain` counted `.dead-letter/` and exited degraded, `check` did not count it at
/// all and exited clean over the same store. Two verdicts about whether one store wants a person is
/// the defect, whichever of them a monitor happens to read.
#[test]
fn a_dead_letter_is_degraded_to_check_as_it_is_to_drain() {
    let deployment = Deployment::new();
    let root = deployment.root_str();
    // Set aside by some earlier drain, which is the state an operator actually finds: the queue is
    // empty and the work is still owed.
    drop(Pipeline::new(deployment.root()).expect("pipeline"));
    fs::write(
        deployment.root().join(".dead-letter/some-record.bundle"),
        "record: some-record\njob: bundle\nattempts: 5\nreason: gone\n",
    )
    .expect("a job set aside");

    let drained = yaam(&["--root", root, "drain"]);
    let said = String::from_utf8_lossy(&drained.stdout);
    assert_eq!(drained.status.code(), Some(4), "{said}");
    assert!(said.contains("set aside           1"), "{said}");

    let checked = yaam(&["--root", root, "check"]);
    let printed = String::from_utf8_lossy(&checked.stdout);
    assert_eq!(
        checked.status.code(),
        Some(4),
        "a drain asking for an operator and a check saying nothing is the disagreement: {printed}"
    );
    assert!(printed.contains("dead-lettered      1"), "{printed}");
    assert!(printed.contains("`yaam reindex --all`"), "{printed}");
}
