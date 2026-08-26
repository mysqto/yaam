//! The seven operator commands.
//!
//! Thin on purpose: each one opens a pipeline, calls the library operation the documentation names,
//! and renders the report. Every judgement they make — what drift is, what a backlog is, what an
//! erasure reaches — is the library's, because a second opinion held only in a command-line tool is
//! an opinion no test of the library can contradict.
//!
//! Each report is composed as text and written once. Writing line by line would put a failure path
//! behind every line, and there is only one thing to say about a report that could not be written.
//! Output goes to a writer rather than to `println!`, so a test can read what an operator would see;
//! it is prose because the audience is a person at a terminal, and the exit code is what a script
//! reads.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use yaam_contract::SubjectHash;
use yaam_core::backup::{self, BackupReport};
use yaam_core::drain::{self, DrainReport};
use yaam_core::erase::{self, ErasePreview};
use yaam_core::health::{self, HealthReport};
use yaam_core::reindex;
use yaam_core::{Paths, Pipeline};
use yaam_crypto::keystore::KeyMaterial;

use crate::error::{Error, Result, config, failed};
use crate::exit::Exit;

/// What erasure does not reach, stated wherever erasure is offered.
///
/// Repeated at the point of action rather than left to the documentation, because this is the
/// sentence an operator has to have read before confirming — and the one a data subject is owed a
/// truthful version of.
const RETAINED: &str = "frontmatter, attributes, entity references and timelines are retained: after this the store \
     still answers that this subject was named, when, and about what — only what the records said \
     becomes unreadable";

/// What a file in `.dead-letter/` means, said the same way by every command that counts one.
///
/// `drain` and `check` both report that count, and a store is degraded to both of them for it. One
/// sentence, so the two cannot end up recommending different things about the same directory.
const DEAD_LETTERED: &str = "`.dead-letter/` holds fan-out that ran out of attempts. Nothing will retry it, and no record \
     was lost: each file names the job and why it failed, and `yaam reindex --all` queues that work \
     again once the cause is gone.\n";

/// Rebuilds the index from the tree, then runs the fan-out that rebuild re-enqueued.
///
/// The drain is part of the command rather than a step to remember, for the same reason the restore
/// carries its rebuild: a rebuild drops every materialised timeline along with the index rows that
/// account for their lines, so a command that returned there would leave `entities/` empty — for
/// ever, on a store with no service to converge it, while `--help` and the contract both say
/// timelines are retained.
///
/// [`Exit::Degraded`] when the drain leaves work behind, because that is the state `check` calls
/// degraded over the same queue. Re-running a rebuild is safe, and the narrower remedy the report
/// names is `yaam drain`.
pub fn reindex(pipeline: &mut Pipeline, out: &mut dyn Write) -> Result<Exit> {
    let index = pipeline.paths().index.clone();
    let report =
        reindex::reindex_all(pipeline).map_err(|error| failed("rebuilding the index", &error))?;

    let mut text = format!("rebuilt {}\n", index.display());
    line(&mut text, "from the tree", report.from_tree);
    line(&mut text, "from cold manifests", report.from_manifests);
    line(&mut text, "erasures replayed", report.tombstones_replayed);
    line(&mut text, "timelines dropped", report.timelines_dropped);
    line(&mut text, "files skipped", report.skipped);
    if report.timelines_dropped > 0 {
        text.push_str(
            "a materialised timeline is dropped with the index rows that say which lines it \
             already holds; the fan-out this queued writes them again, which is the drain below\n",
        );
    }
    if report.skipped > 0 {
        text.push_str(
            "a skipped file is one whose frontmatter would not parse; it is still in the tree, and \
             its rows are not in the index\n",
        );
    }
    let converged = settle_fanout(drain::drain_backlog(pipeline), &mut text);
    emit(out, &text)?;
    if converged {
        Ok(Exit::Ok)
    } else {
        Ok(Exit::Degraded)
    }
}

/// Destroys a subject's keys, once the operator has said so explicitly.
///
/// Without `confirmed` this prints what would be destroyed and stops. That is the whole reason the
/// preview exists in the library: a confirmation over a 64-character pseudonym nobody can read at a
/// glance is not a check, and a count of what is about to become unreadable is.
///
/// A confirmed erasure ends in a rebuild, so it owes the same drain a rebuild does — the timelines
/// this command's own wording says are *retained* are dropped by that rebuild, and something has to
/// write them again. Unlike [`reindex`], what the drain manages does not reach the exit code: see the
/// comment on the success below.
pub fn erase(
    pipeline: &mut Pipeline,
    subject: &str,
    confirmed: bool,
    out: &mut dyn Write,
) -> Result<Exit> {
    let subject = SubjectHash::parse(subject).map_err(|error| {
        config(format!(
            "--subject is not a subject pseudonym: {error}. It is `s_` followed by 64 hex characters"
        ))
    })?;
    let preview = erase::preview(pipeline, &subject)
        .map_err(|error| failed("reading what an erasure would reach", &error))?;
    let mut text = describe_preview(&subject, &preview);

    if !confirmed {
        text.push_str("\nnothing was destroyed. Pass --confirm-destroy-keys to mean it.\n");
        emit(out, &text)?;
        return Err(Error::Unconfirmed(
            "erasure is irreversible and was not confirmed".to_owned(),
        ));
    }

    let report = erase::erase_subject(pipeline, &subject)
        .map_err(|error| failed("destroying the subject's keys", &error))?;
    let _ = writeln!(text, "\nerased {}", subject.as_str());
    line(&mut text, "bodies sealed off", report.bodies_sealed_off);
    line(&mut text, "keys destroyed", report.keys_destroyed);
    line(&mut text, "quarantine settled", report.quarantine_settled);
    let _ = writeln!(text, "  tombstone           {}", report.tombstone_id);
    // Reported, and deliberately not folded into the exit code below.
    let _ = settle_fanout(drain::drain_backlog(pipeline), &mut text);
    let _ = writeln!(
        text,
        "\ncompleteness cannot be asserted until the key backup window has passed. Confirm with:\n  \
         yaam verify-erasure --tombstone {}",
        report.tombstone_id
    );
    emit(out, &text)?;
    // Success, whatever the drain above managed. This command was asked to destroy keys and it did;
    // the destruction is irreversible and already stands. A fan-out job that could not run is a
    // separate and recoverable thing, so saying otherwise here would report the one outcome nobody
    // can act on by re-running the command — and would invite exactly that. What is still owed is in
    // the report, and `yaam check` is where "does this store want an operator" is a scriptable
    // question.
    Ok(Exit::Ok)
}

/// Reports whether an erasure can be asserted complete.
pub fn verify_erasure(
    pipeline: &mut Pipeline,
    tombstone: &str,
    out: &mut dyn Write,
) -> Result<Exit> {
    let complete = erase::confirm_erasure(pipeline, tombstone)
        .map_err(|error| failed("reading the tombstone log", &error))?;
    if complete {
        let text = format!(
            "{tombstone}: complete\nno recoverable key copy remains, and the backup window has \
             passed\n"
        );
        emit(out, &text)?;
        return Ok(Exit::Ok);
    }
    let text = format!(
        "{tombstone}: not yet\neither a key file is still present, or a snapshot taken before the \
         destruction is still inside its {} day retention window. The destruction stands; only \
         the attestation waits.\n",
        erase::KEY_BACKUP_WINDOW_MS / (24 * 60 * 60 * 1_000)
    );
    emit(out, &text)?;
    Ok(Exit::Incomplete)
}

/// Copies the store's authoritative half into a fresh directory.
///
/// The exclusions are printed rather than left implicit. An operator holding a backup has to be
/// able to see that the key store is not in it — that absence is the whole reason an erasure
/// reaches every copy, and a report that mentioned only what was copied would read the same
/// whether the exclusion had held or not.
pub fn backup(pipeline: &Pipeline, to: &Path, out: &mut dyn Write) -> Result<Exit> {
    let report =
        backup::back_up(pipeline, to).map_err(|error| failed("writing the backup", &error))?;
    emit(out, &describe_backup(pipeline, to, &report))?;
    // A file beside the store that no manifest classifies is not in the backup and nobody decided
    // that; a monitor should be able to branch on it without reading the prose.
    if report.unclassified.is_empty() {
        Ok(Exit::Ok)
    } else {
        Ok(Exit::Degraded)
    }
}

/// Restores a backup into a store, rebuilds its index, and runs the fan-out that queued.
///
/// Takes paths rather than an open pipeline: the destination reads its `spec/` from the backup, so
/// the store has to be opened after the copy rather than before it. Which is also why the drain
/// opens a store of its own — the one the rebuild used is gone by the time this returns.
///
/// The drain is here for the reason it is in [`reindex`]: the rebuild inside a restore drops every
/// materialised timeline and re-enqueues the work that writes them again, so a restore that
/// returned there would hand over a store whose `entities/` is empty — and on a store with no
/// service to converge it, empty for ever. A backup carries no timelines precisely because a
/// rebuild reproduces them, and this is where that promise is kept.
///
/// [`Exit::Degraded`] when the drain leaves work behind, matching what `check` says about the same
/// queue. Re-running the restore is not the remedy and the report does not offer it: the narrower
/// one is `yaam drain`.
pub fn restore(paths: &Paths, from: &Path, out: &mut dyn Write) -> Result<Exit> {
    let report =
        backup::restore(paths, from).map_err(|error| failed("restoring the backup", &error))?;

    let mut text = format!(
        "restored {} from {}\n",
        paths.root.display(),
        from.display()
    );
    line(&mut text, "files copied", report.files);
    line(&mut text, "records indexed", report.records_indexed);
    line(&mut text, "erasures replayed", report.erasures_replayed);
    text.push_str(
        "\nthe index was rebuilt as part of this restore, and the restored tombstone log was \
         replayed over it: an erasure ordered before the backup was taken stays applied\n",
    );
    text.push_str(
        "no key material was restored, because a backup carries none. Bodies are readable only \
         where their keys still are: recover the key store from its own copy if this store is \
         meant to read them\n",
    );
    // A store of this command's own, opened over what it has just written: the pipeline the rebuild
    // ran on belonged to the restore and is closed. Its failure is the drain's failure and is
    // reported as one — the files are in place either way, and the queue that is left is derived.
    let converged = settle_fanout(
        Pipeline::with_paths(paths.clone())
            .and_then(|mut pipeline| drain::drain_backlog(&mut pipeline)),
        &mut text,
    );
    emit(out, &text)?;
    if converged {
        Ok(Exit::Ok)
    } else {
        Ok(Exit::Degraded)
    }
}

/// Reads the store's health.
///
/// [`Exit::Degraded`] when something wants an operator, so a monitor can branch on it without
/// matching on text.
pub fn check(pipeline: &Pipeline, out: &mut dyn Write) -> Result<Exit> {
    let report = health::check(pipeline).map_err(|error| failed("reading the index", &error))?;
    emit(out, &describe_health(pipeline, &report))?;
    if report.needs_attention() {
        Ok(Exit::Degraded)
    } else {
        Ok(Exit::Ok)
    }
}

/// Runs queued fan-out work: the entity timelines and subject audit records a bundle reads.
///
/// The command a store with no service behind it needs. `max_jobs` is a bound and not a target: this
/// settles up to that many jobs and reports, rather than waiting for a queue that a concurrent
/// writer can keep filling.
///
/// [`Exit::Degraded`] when anything is left, which is the judgement `check` makes about the same
/// queue read from the same place.
pub fn drain(pipeline: &mut Pipeline, max_jobs: usize, out: &mut dyn Write) -> Result<Exit> {
    let root = pipeline.paths().root.clone();
    let report = drain::drain(pipeline, max_jobs)
        .map_err(|error| failed("draining the fan-out queue", &error))?;
    let mut text = format!("drained {}\n", root.display());
    describe_drain(&report, &mut text);
    emit(out, &text)?;
    if report.needs_attention() {
        Ok(Exit::Degraded)
    } else {
        Ok(Exit::Ok)
    }
}

/// Describes the fan-out a rebuild re-enqueued, drained on the caller's behalf.
///
/// Never an error, and never a report of one. Every caller has already done the thing it was asked
/// to do — an index rebuilt, a subject's keys destroyed, a backup put back — and fan-out that could
/// not run is a separate, recoverable thing: the queue is derived, the work is still queued, and a
/// later `yaam drain` or a running service does it. `false` says the store did not converge, which
/// is a judgement the caller is free to spend its exit code on or not.
///
/// The drain is passed in rather than run here because a restore has no open store to run it on
/// until it has finished copying, and opening one is then part of the same attempt.
fn settle_fanout(drained: yaam_core::Result<DrainReport>, text: &mut String) -> bool {
    text.push_str("\nfan-out the rebuild queued:\n");
    match drained {
        Ok(report) => {
            describe_drain(&report, text);
            !report.needs_attention()
        }
        Err(error) => {
            let _ = writeln!(
                text,
                "  could not be drained: {error}\nnothing is lost — the queue is derived and the \
                 work is still in it. Run `yaam drain` once the cause is fixed, or let a running \
                 service converge it"
            );
            false
        }
    }
}

/// A finished drain, as an operator reads it.
///
/// One description shared by the explicit command and the drains a rebuild and an erasure run on
/// their own behalf: three accounts of one queue would drift, and the numbers are the same numbers.
fn describe_drain(report: &DrainReport, text: &mut String) {
    line(text, "jobs settled", report.settled);
    line(text, "jobs still queued", report.remaining);
    line(text, "set aside", report.dead_lettered);
    line(text, "bound", report.budget);
    if report.hit_bound() {
        text.push_str(
            "the bound stopped this drain, not an empty queue: it is one pass over the work, so \
             that a command cannot be held open by a writer filling the queue beside it. Run \
             `yaam drain` again for the rest.\n",
        );
    } else if report.remaining > 0 {
        text.push_str(
            "what is left failed and is waiting out its retry delay. It stays queued: run \
             `yaam drain` again in a moment, or let a running service converge it.\n",
        );
    }
    if report.dead_lettered > 0 {
        text.push_str(DEAD_LETTERED);
    }
}

/// A finished backup, as an operator reads it.
fn describe_backup(pipeline: &Pipeline, to: &Path, report: &BackupReport) -> String {
    let mut text = format!(
        "backed up {} to {}\n",
        pipeline.paths().root.display(),
        to.display()
    );
    line(&mut text, "files", report.files);
    let _ = writeln!(text, "  {:<20}{}", "bytes", report.bytes);

    text.push_str("\nleft behind, deliberately:\n");
    for entry in backup::excluded() {
        let present = if report.excluded.iter().any(|name| name == entry.name) {
            "present"
        } else {
            "absent"
        };
        let _ = writeln!(text, "  {:<20}{present}: {}", entry.name, entry.reason);
    }

    if !report.unclassified.is_empty() {
        let _ = writeln!(
            text,
            "\nbeside the store, in no manifest, and NOT copied: {}. Either these belong in the \
             manifest or they belong somewhere else — a keyring or an unsealing key kept here \
             would have been swept into the backup by a copy that guessed.",
            report.unclassified.join(", ")
        );
    }
    text
}

/// What an erasure would reach, as an operator has to read it before confirming.
fn describe_preview(subject: &SubjectHash, preview: &ErasePreview) -> String {
    let mut text = format!("erasing {} would destroy:\n", subject.as_str());
    line(&mut text, "records naming it", preview.records);
    line(&mut text, "readable bodies", preview.bodies_readable);
    line(&mut text, "keys, all epochs", preview.keys);
    line(&mut text, "quarantined records", preview.quarantined);
    if preview.already_tombstoned {
        text.push_str(
            "this subject is already tombstoned; re-running settles anything that arrived since\n",
        );
    }
    if preview.records == 0 && preview.keys == 0 && preview.quarantined == 0 {
        text.push_str(
            "nothing here names this subject. Check the pseudonym before confirming: the store \
             cannot tell a subject with no records from one whose hash was mistyped\n",
        );
    }
    text.push_str("irreversible, and it reaches every copy including backups\n");
    text.push_str(RETAINED);
    text.push('\n');
    text
}

/// A health report, as an operator reads it.
fn describe_health(pipeline: &Pipeline, report: &HealthReport) -> String {
    let paths = pipeline.paths();
    let mut text = String::new();
    let _ = writeln!(text, "store  {}", paths.root.display());
    let _ = writeln!(text, "index  {}", paths.index.display());
    let _ = writeln!(
        text,
        "schema version     {} (this build reads up to {})",
        report.index.schema_version, report.index.supported_schema_version
    );
    let _ = writeln!(text, "records indexed    {}", report.index.records);
    let _ = writeln!(text, "index drift        {}", report.index_drift);
    let _ = writeln!(
        text,
        "sweeper backlog    {} (staging {}, fan-out pending {}, stale claims {})",
        report.sweeper_backlog.total(),
        report.sweeper_backlog.staged,
        report.sweeper_backlog.fanout_pending,
        report.sweeper_backlog.stale_claims
    );
    let _ = writeln!(text, "quarantine depth   {}", report.quarantine_depth);
    // Beside the two queue depths above, because it is the third answer to "how much work is this
    // store holding" — and the only one that no service converges on its own.
    let _ = writeln!(text, "dead-lettered      {}", report.dead_lettered);
    // Said on every health read and not only at startup, and read off the key files rather than
    // taken from the wrapper this command happens to hold: a key file recovered from a snapshot or a
    // decommissioned disk is a usable key if this line says none, and an operator who ran this
    // without a passphrase must not be told that about a store that is wrapped.
    let _ = writeln!(text, "key wrapping       {}", report.key_material);

    if report.index_drift > 0 {
        let _ = writeln!(
            text,
            "\n{} record(s) in the tree have no index row. Run `yaam reindex --all`.",
            report.index_drift
        );
    }
    if report.sweeper_backlog.total() > 0 {
        text.push_str(
            "\nthere is work the sweeper has not got through. A running service converges on its \
             own; a backlog that does not shrink means nothing is draining it.\n",
        );
    }
    if report.sweeper_backlog.fanout_pending > 0 {
        // Named here because this is the figure `yaam drain` reports back, and a backlog with no
        // command beside it reads as something only a service can fix.
        text.push_str("run `yaam drain` to run the queued fan-out now.\n");
    }
    if report.dead_lettered > 0 {
        text.push('\n');
        text.push_str(DEAD_LETTERED);
    }
    if let KeyMaterial::Mixed { unwrapped, .. } = report.key_material {
        // The one key-material state a person has to settle, so it gets the sentence rather than
        // being left to a reader of the line above. Both halves are wrong at once: the files with no
        // marker are usable keys, and no single wrapper reads the whole store — the records sealed
        // under whichever half this deployment cannot open stay unreadable until it can.
        let _ = writeln!(
            text,
            "\n{unwrapped} key file(s) carry no wrapping marker while the rest do, which is what \
             fitting a wrapper to a store that already held keys leaves behind. Each unmarked file \
             is a usable key to anyone who can read it, and a process holding the wrapper cannot \
             read those keys at all: the bodies sealed under them stay unreadable until they are \
             wrapped with the same passphrase."
        );
    }
    text
}

/// One `label  count` line of a report, aligned so a column of numbers reads as one.
///
/// Shared with [`crate::knowledge`], whose reports are read beside these: two alignments would put
/// two column widths in one operator's scrollback.
pub(crate) fn line(text: &mut String, label: &str, count: usize) {
    let _ = writeln!(text, "  {label:<20}{count}");
}

/// Writes the finished report.
///
/// The one failure path, and it is a broken pipe: the reader has gone away, and there is nobody left
/// to tell about it. Shared with [`crate::knowledge`] so there is one of it rather than two.
pub(crate) fn emit(out: &mut dyn Write, text: &str) -> Result<()> {
    out.write_all(text.as_bytes())
        .map_err(|error| failed("writing the report", &error))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use yaam_core::{Paths, Pipeline};

    use super::{backup, check, drain, erase, reindex, restore, verify_erasure};
    use crate::exit::Exit;
    use crate::fixtures::{self, BODY};

    /// A tree with this repository's spec, and the pipeline over it.
    struct Tree {
        dir: tempfile::TempDir,
        pipeline: Pipeline,
    }

    impl Tree {
        fn new() -> Self {
            let dir = fixtures::tree();
            let pipeline =
                Pipeline::with_paths(Paths::under(dir.path())).expect("a pipeline over the tree");
            Self { dir, pipeline }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }
    }

    /// A wrapper cheap enough that a test is not an argon2 benchmark. Never a real store's cost.
    fn cheap_wrapper() -> yaam_crypto::wrapper::PassphraseWrapper {
        yaam_crypto::wrapper::PassphraseWrapper::with_salt(
            b"a passphrase",
            [7u8; 16],
            yaam_crypto::wrapper::Cost {
                memory_kib: 8,
                passes: 1,
                lanes: 1,
            },
        )
        .expect("wrapper")
    }

    /// A backup destination outside every store, since a backup inside the tree it copies is
    /// refused.
    fn elsewhere() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    /// The text a command printed.
    fn run(command: impl FnOnce(&mut Vec<u8>) -> crate::error::Result<Exit>) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = command(&mut out).expect("the command ran");
        (exit, String::from_utf8(out).expect("utf-8"))
    }

    #[test]
    fn a_rebuild_reports_what_it_indexed() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");

        let (exit, printed) = run(|out| reindex(&mut tree.pipeline, out));
        assert_eq!(exit, Exit::Ok);
        assert!(printed.contains("from the tree       1"), "{printed}");
        assert!(printed.contains("erasures replayed   0"), "{printed}");
        // Nothing has drained, so there is no materialised timeline to drop and nothing to explain.
        assert!(printed.contains("timelines dropped   0"), "{printed}");
        assert!(!printed.contains("writes them again"), "{printed}");
    }

    /// A rebuild takes the materialised timelines with it, and says so.
    ///
    /// Worth a line of output: between the rebuild and the fan-out it queued, an entity's timeline
    /// is a file that is not there, and an operator reading a report is who needs to know.
    #[test]
    fn a_rebuild_says_it_dropped_the_timelines_it_will_write_again() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        tree.pipeline.drain_fanout(100).expect("drained");

        let (_, printed) = run(|out| reindex(&mut tree.pipeline, out));
        assert!(printed.contains("timelines dropped   1"), "{printed}");
        assert!(printed.contains("writes them again"), "{printed}");
    }

    /// The gap this drain closes: a rebuild used to return with `entities/` empty, and on a store
    /// driven only by this command line nothing came along to fill it again.
    #[test]
    fn a_rebuild_leaves_the_timeline_it_dropped_materialised_again() {
        let mut tree = Tree::new();
        let record = fixtures::record("2026-08-20T09:00:00Z");
        let id = record.record_id.clone();
        tree.pipeline.accept(record, BODY).expect("accepted");
        tree.pipeline.drain_fanout(100).expect("drained");
        let timeline = tree.root().join("entities/ticket/PROJ-42/timeline.md");
        assert!(timeline.is_file());

        let (exit, printed) = run(|out| reindex(&mut tree.pipeline, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("jobs still queued   0"), "{printed}");
        assert!(
            fs::read_to_string(&timeline)
                .expect("the timeline is back")
                .contains(&format!("[[record:{}", id.as_str())),
            "the rebuild left the record's line out of the timeline it dropped"
        );
    }

    #[test]
    fn a_drain_reports_what_it_settled_and_what_it_left() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");

        let (exit, printed) = run(|out| drain(&mut tree.pipeline, 10, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("jobs settled        1"), "{printed}");
        assert!(printed.contains("jobs still queued   0"), "{printed}");
        assert!(
            printed.contains("bound               10"),
            "the bound has to be in the report, or a remainder cannot be read: {printed}"
        );
    }

    /// A bound reached is a remainder, and a remainder is what `check` calls degraded.
    #[test]
    fn a_drain_that_reaches_its_bound_reports_the_remainder_and_is_degraded() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &fixtures::subject('a')),
                BODY,
            )
            .expect("accepted");

        let (exit, printed) = run(|out| drain(&mut tree.pipeline, 1, out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("jobs settled        1"), "{printed}");
        assert!(printed.contains("jobs still queued   1"), "{printed}");
        assert!(
            printed.contains("the bound stopped this drain"),
            "{printed}"
        );

        // The number the remainder is reported as is the number `check` reports for the same queue.
        let (_, health) = run(|out| check(&tree.pipeline, out));
        assert!(health.contains("fan-out pending 1"), "{health}");

        let (exit, printed) = run(|out| drain(&mut tree.pipeline, 10, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("jobs still queued   0"), "{printed}");
    }

    #[test]
    fn a_rebuild_says_when_it_skipped_a_file_it_could_not_read() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        fs::write(
            tree.root().join("records/2026/08/20/unreadable.md"),
            "---\naction: [unclosed\n---\nbody\n",
        )
        .expect("write");

        let (_, printed) = run(|out| reindex(&mut tree.pipeline, out));
        assert!(printed.contains("files skipped       1"), "{printed}");
        assert!(
            printed.contains("still in the tree"),
            "a skipped file needs the operator told what it means: {printed}"
        );
    }

    #[test]
    fn a_healthy_store_reports_ok_and_a_drifted_one_reports_degraded() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        tree.pipeline.drain_fanout(100).expect("drained");

        let (exit, printed) = run(|out| check(&tree.pipeline, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("index drift        0"), "{printed}");
        assert!(printed.contains("records indexed    1"), "{printed}");
        // This store's one record is internal, so it has no subject key and there is nothing on
        // disk to be wrapped or in the clear. Saying "none" here was the false statement: it read as
        // key material lying about unprotected, over a key store holding none.
        assert!(
            printed.contains("key wrapping       nothing yet"),
            "an empty key store has to claim neither: {printed}"
        );
        assert!(
            !printed.contains("development only"),
            "and must not call the store development-only: {printed}"
        );

        // The index is disposable, so this is the drift the documentation is about.
        let Tree { dir, pipeline } = tree;
        drop(pipeline);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(dir.path().join(format!("index.sqlite{suffix}")));
        }
        let pipeline = Pipeline::with_paths(Paths::under(dir.path())).expect("reopened");
        let (exit, printed) = run(|out| check(&pipeline, out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("yaam reindex --all"), "{printed}");
    }

    #[test]
    fn an_undrained_queue_reports_degraded_with_what_it_means() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");

        let (exit, printed) = run(|out| check(&tree.pipeline, out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("fan-out pending"), "{printed}");
        assert!(printed.contains("nothing is draining it"), "{printed}");
    }

    /// A queue that is empty and still owes somebody an afternoon. `drain` has always reported this
    /// and exited degraded over it; `check` did not count it at all, so a monitor reading the one
    /// command whose job is this question was told the store was fine.
    #[test]
    fn a_job_set_aside_reports_degraded_and_names_what_clears_it() {
        let tree = Tree::new();
        fs::write(
            tree.root().join(".dead-letter/some-record.bundle"),
            "record: some-record\njob: bundle\nattempts: 5\nreason: gone\n",
        )
        .expect("a job set aside");

        let (exit, printed) = run(|out| check(&tree.pipeline, out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("dead-lettered      1"), "{printed}");
        assert!(
            printed.contains("`yaam reindex --all`"),
            "a count with no remedy beside it is a count nobody acts on: {printed}"
        );
    }

    #[test]
    fn an_unconfirmed_erasure_previews_and_destroys_nothing() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('a');
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &subject),
                BODY,
            )
            .expect("accepted");

        let mut out = Vec::new();
        let error = erase(&mut tree.pipeline, subject.as_str(), false, &mut out)
            .expect_err("an unconfirmed erasure must not act");
        assert_eq!(error.exit(), Exit::Unconfirmed);
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(printed.contains("records naming it   1"), "{printed}");
        assert!(printed.contains("keys, all epochs    1"), "{printed}");
        assert!(
            printed.contains("are retained"),
            "what erasure does not reach has to be said before confirming: {printed}"
        );
        assert!(printed.contains("--confirm-destroy-keys"), "{printed}");

        // Nothing was destroyed, so the second preview reads the same as the first.
        let mut again = Vec::new();
        let _ = erase(&mut tree.pipeline, subject.as_str(), false, &mut again);
        assert!(
            String::from_utf8(again)
                .expect("utf-8")
                .contains("keys, all epochs    1")
        );
    }

    #[test]
    fn a_confirmed_erasure_destroys_and_names_the_tombstone_to_verify() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('b');
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &subject),
                BODY,
            )
            .expect("accepted");

        let (exit, printed) = run(|out| erase(&mut tree.pipeline, subject.as_str(), true, out));
        assert_eq!(exit, Exit::Ok);
        assert!(printed.contains("bodies sealed off   1"), "{printed}");
        assert!(printed.contains("keys destroyed      1"), "{printed}");

        let tombstone = printed
            .lines()
            .find_map(|line| line.trim().strip_prefix("tombstone           "))
            .expect("the tombstone id is what verification takes")
            .to_owned();

        // Fresh: the backup window has not passed, so completeness is a "not yet" rather than a
        // failure — and that distinction is the exit code.
        let (exit, printed) = run(|out| verify_erasure(&mut tree.pipeline, &tombstone, out));
        assert_eq!(exit, Exit::Incomplete);
        assert!(printed.contains("not yet"), "{printed}");
        assert!(printed.contains("The destruction stands"), "{printed}");

        // Re-running says the subject is already tombstoned rather than pretending it is new work.
        let (_, again) = run(|out| erase(&mut tree.pipeline, subject.as_str(), true, out));
        assert!(again.contains("already tombstoned"), "{again}");
    }

    /// Completion is the other half of verification, and it has its own exit code.
    #[test]
    fn an_erasure_past_its_backup_window_reports_complete() {
        let tree = Tree::new();
        // A tombstone for a subject with no keys, ordered long enough ago that the key backup
        // window has passed. Written by hand because the window is a day, and a test cannot wait.
        let long_ago = 1_000_000_000_000_i64;
        fs::write(
            tree.dir.path().join("tombstones.jsonl"),
            format!(
                "{{\"tombstone_id\":\"tomb-old\",\"subject\":\"{}\",\"at_ms\":{long_ago},\"complete\":false}}\n",
                fixtures::subject('d').as_str()
            ),
        )
        .expect("log");

        // The replay a rebuild performs is what tombstones the subject in the key store, which is
        // one of the two things completion needs to be true.
        let mut pipeline = tree.pipeline;
        yaam_core::reindex::reindex_all(&mut pipeline).expect("rebuilt");

        let (exit, printed) = run(|out| verify_erasure(&mut pipeline, "tomb-old", out));
        assert_eq!(exit, Exit::Ok);
        assert!(printed.contains("complete"), "{printed}");

        // Stamped complete, so asking again answers from the log rather than re-checking.
        let (exit, _) = run(|out| verify_erasure(&mut pipeline, "tomb-old", out));
        assert_eq!(exit, Exit::Ok);
    }

    /// Erasure is the irreversible half, and it has happened by the time the drain runs. A job that
    /// could not run is recoverable and separate, so it is reported and does not touch the exit code:
    /// a failure here would send an operator to re-run the one command that must never be re-run for
    /// a reason it did not have.
    #[test]
    fn an_erasure_whose_fan_out_cannot_run_still_reports_success() {
        let mut tree = Tree::new();
        let subject = fixtures::subject('f');
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &subject),
                BODY,
            )
            .expect("accepted");

        // A file where the audit record's directory has to be, so the job that writes it cannot
        // succeed. It survives the rebuild inside the erasure, which is what makes it reach the
        // drain — where the timelines under `entities/` are dropped and made again.
        fs::write(tree.root().join("audit/subjects"), "not a directory").expect("in the way");

        let (exit, printed) = run(|out| erase(&mut tree.pipeline, subject.as_str(), true, out));
        assert_eq!(
            exit,
            Exit::Ok,
            "the keys were destroyed; that is what this command was asked for: {printed}"
        );
        assert!(printed.contains("keys destroyed      1"), "{printed}");
        assert!(
            printed.contains("jobs still queued   1"),
            "the job that could not run has to be said out loud: {printed}"
        );
        assert!(printed.contains("yaam drain"), "{printed}");
    }

    #[test]
    fn an_erasure_of_a_subject_nothing_names_says_so_rather_than_reporting_success() {
        let mut tree = Tree::new();
        let mut out = Vec::new();
        let error = erase(
            &mut tree.pipeline,
            fixtures::subject('c').as_str(),
            false,
            &mut out,
        )
        .expect_err("unconfirmed");
        assert_eq!(error.exit(), Exit::Unconfirmed);
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(
            printed.contains("nothing here names this subject"),
            "a mistyped pseudonym looks exactly like a subject with no records: {printed}"
        );
    }

    /// A backup names what it left behind as well as what it took, because the absence is the
    /// property an operator has to be able to check.
    #[test]
    fn a_backup_reports_what_it_copied_and_what_it_deliberately_did_not() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        let held = elsewhere();
        let into = held.path().join("backup");

        let (exit, printed) = run(|out| backup(&tree.pipeline, &into, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("left behind, deliberately"), "{printed}");
        assert!(
            printed.contains("keystore"),
            "the key store exclusion is the one an operator has to see: {printed}"
        );
        assert!(!into.join("keystore").exists());
        assert!(into.join("records").is_dir());
    }

    /// A file beside the store is in no manifest, so it is not in the backup — and that is a
    /// scriptable outcome rather than a line of prose.
    #[test]
    fn an_unclassified_file_beside_the_store_reports_degraded() {
        let tree = Tree::new();
        fs::write(tree.root().join("keyring.json"), "{}").expect("a file beside the store");

        let held = elsewhere();
        let (exit, printed) = run(|out| backup(&tree.pipeline, &held.path().join("backup"), out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("keyring.json"), "{printed}");
    }

    /// The restore drill, through the commands an operator would actually run.
    #[test]
    fn a_restore_rebuilds_the_index_and_says_the_erasure_log_was_replayed() {
        let mut source = Tree::new();
        let subject = fixtures::subject('e');
        let record = fixtures::subject_record("2026-08-20T09:00:00Z", &subject);
        let id = record.record_id.clone();
        source.pipeline.accept(record, BODY).expect("accepted");
        let held = elsewhere();
        let into = held.path().join("backup");
        let (_, printed) = run(|out| backup(&source.pipeline, &into, out));
        assert!(printed.contains("files"), "{printed}");

        // Erased after the copy was taken, which is the ordering that matters: the backup holds the
        // sealed body and never held the key.
        let (_, _) = run(|out| erase(&mut source.pipeline, subject.as_str(), true, out));

        // A destination that is not a store yet: no `spec/` of its own, so what it reads records
        // under has to have arrived in the backup.
        let elsewhere = elsewhere();
        let paths = yaam_core::Paths::under(elsewhere.path().join("restored"));
        let (exit, printed) = run(|out| restore(&paths, &into, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("records indexed     1"), "{printed}");
        assert!(printed.contains("stays applied"), "{printed}");
        assert!(paths.root.join("spec/entities.yaml").is_file());
        assert!(
            !paths
                .key_store
                .join("keys")
                .read_dir()
                .is_ok_and(|mut held| held.next().is_some()),
            "a restore must not have produced key material"
        );

        // The timeline the backup deliberately did not carry, on disk with the record in it. This
        // used to be the state a restore left behind — a store whose `entities/` was empty and
        // nothing to fill it — and "the command exited 0" was true of that too.
        let timeline = paths
            .root
            .join("entities/order_ref/ord10014721/timeline.md");
        assert!(
            fs::read_to_string(&timeline)
                .expect("the timeline the restore's own drain wrote")
                .contains(&format!("[[record:{}", id.as_str())),
            "{printed}"
        );

        // The restored store answers, which is the half that files-on-disk does not prove.
        let restored = yaam_core::Pipeline::with_paths(paths).expect("the restored store");
        let (exit, health) = run(|out| check(&restored, out));
        assert_eq!(
            exit,
            Exit::Ok,
            "the restore drained what its rebuild queued, so nothing is owed: {health}"
        );
        assert!(health.contains("records indexed    1"), "{health}");
        assert!(health.contains("index drift        0"), "{health}");
    }

    /// A restore that would merge, or would put keys back, is refused.
    #[test]
    fn a_restore_refuses_a_store_with_records_and_a_backup_carrying_keys() {
        let mut source = Tree::new();
        source
            .pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        let held = elsewhere();
        let into = held.path().join("backup");
        let (_, _) = run(|out| backup(&source.pipeline, &into, out));

        // Into a store that already holds records: that is a merge, and two record sets in one tree
        // cannot be told apart afterwards.
        let error = restore(source.pipeline.paths(), &into, &mut Vec::new()).expect_err("a merge");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("not a merge"), "{error}");

        // And a backup somebody put a key store back into.
        fs::create_dir_all(into.join("keystore")).expect("dir");
        let elsewhere = elsewhere();
        let paths = yaam_core::Paths::under(elsewhere.path().join("restored"));
        let error = restore(&paths, &into, &mut Vec::new()).expect_err("carries keys");
        assert!(error.to_string().contains("keystore"), "{error}");
    }

    #[test]
    fn a_subject_that_is_not_a_pseudonym_is_a_configuration_error_naming_the_shape() {
        let mut tree = Tree::new();
        let error = erase(&mut tree.pipeline, "not-a-hash", true, &mut Vec::new())
            .expect_err("not a pseudonym");
        assert_eq!(error.exit(), Exit::Config);
        assert!(error.to_string().contains("64 hex"), "{error}");
    }

    #[test]
    fn verifying_an_unknown_tombstone_is_a_failure_not_a_quiet_no() {
        let mut tree = Tree::new();
        let error = verify_erasure(&mut tree.pipeline, "tomb-nothing", &mut Vec::new())
            .expect_err("no such tombstone");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("tombstone"), "{error}");
    }

    /// The deployment this fixed: `yaam check` over a wrapped store, run with no passphrase, used to
    /// answer from its own wrapper and report the keys unprotected and the store development-only.
    #[test]
    fn a_wrapped_store_names_its_scheme_to_a_check_run_without_a_passphrase() {
        let Tree { dir, pipeline } = Tree::new();
        let mut pipeline = pipeline.with_key_wrapper(cheap_wrapper()).expect("wrapped");
        pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &fixtures::subject('a')),
                BODY,
            )
            .expect("accepted");
        pipeline.drain_fanout(100).expect("drained");
        drop(pipeline);

        // Reopened exactly as the operator ran it: no --key-passphrase-file, so this process cannot
        // read a single one of those keys. The header can be read without them.
        let plain = Pipeline::with_paths(Paths::under(dir.path())).expect("reopened");
        let (exit, printed) = run(|out| check(&plain, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(
            printed.contains("key wrapping       argon2id over a passphrase"),
            "the scheme comes from the blob on disk: {printed}"
        );
        assert!(
            !printed.contains("development only"),
            "a wrapped store is not a development store: {printed}"
        );
    }

    /// The one state that warning belongs to, and it names the count so it cannot be read as a
    /// claim about a store with no keys at all.
    #[test]
    fn a_store_whose_keys_are_in_the_clear_says_so() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &fixtures::subject('a')),
                BODY,
            )
            .expect("accepted");
        tree.pipeline.drain_fanout(100).expect("drained");

        let (exit, printed) = run(|out| check(&tree.pipeline, out));
        assert_eq!(
            exit,
            Exit::Ok,
            "a development store is not a broken one: {printed}"
        );
        assert!(
            printed.contains("key wrapping       none — 1 key file(s)"),
            "{printed}"
        );
        assert!(printed.contains("development only"), "{printed}");
    }

    /// A store wrapped after it already held keys. Reporting either half alone hides the other: the
    /// unmarked files are usable keys, and the marked ones are unreadable to a process without the
    /// passphrase — so this is the one key-material state that asks for a person.
    #[test]
    fn a_store_holding_both_kinds_of_key_says_what_to_do_about_it() {
        let Tree { dir, mut pipeline } = Tree::new();
        pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &fixtures::subject('a')),
                BODY,
            )
            .expect("accepted");
        let mut pipeline = pipeline.with_key_wrapper(cheap_wrapper()).expect("wrapped");
        pipeline
            .accept(
                fixtures::subject_record("2026-08-20T10:00:00Z", &fixtures::subject('b')),
                BODY,
            )
            .expect("accepted");
        pipeline.drain_fanout(100).expect("drained");
        drop(pipeline);

        let plain = Pipeline::with_paths(Paths::under(dir.path())).expect("reopened");
        let (exit, printed) = run(|out| check(&plain, out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(
            printed.contains("key wrapping       mixed — 1 key file(s)"),
            "{printed}"
        );
        assert!(
            printed.contains("1 key file(s) carry no wrapping marker"),
            "the operator needs the sentence, not just the count: {printed}"
        );
        assert!(
            printed.contains("stay unreadable until they are wrapped"),
            "{printed}"
        );
    }
}
