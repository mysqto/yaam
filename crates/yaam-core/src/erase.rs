//! Erasure by key destruction.
//!
//! What this reaches and what it does not is the whole point, so it is stated rather than implied:
//! destroying a subject's keys makes their record *bodies* permanently unreadable in every copy,
//! including backups. It does not reach frontmatter, attributes, entity references or timelines —
//! that structure is retained, and callers must not describe this as erasing everything.
//!
//! Concretely, after an erasure the store still answers "this record named this subject, at this
//! time, with this outcome, about these entities". What no copy anywhere can answer is what the
//! record *said*. A caller that owes a data subject more than that owes them a different design.
//!
//! Two further consequences worth stating plainly. A record naming several subjects has one body
//! and one key set: destroying any one subject's key ends that body for all of them, because the
//! key is derived from every share. And the live tree is rewritten to drop the ciphertext it can no
//! longer decrypt — belt and braces, not the mechanism; the mechanism is that the key is gone.

use std::collections::BTreeSet;
use std::fs;
use std::io;

use serde::{Deserialize, Serialize};
use yaam_contract::{RecordId, SubjectHash};
use yaam_crypto::keystore::KeyStore as _;
use yaam_md::{Body, Document};

use crate::{Pipeline, Result, fsutil, layout};

/// How long a key snapshot may still exist after destruction.
///
/// Erasure cannot be asserted complete while a backup taken before the destruction is still inside
/// its retention window, because restoring it would restore the key. The window is a property of the
/// deployment's backup schedule; this is a conservative day.
pub const KEY_BACKUP_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;

/// What an erasure did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EraseReport {
    /// Records whose bodies became unreadable.
    pub bodies_sealed_off: usize,
    /// Keys destroyed, across all epochs.
    pub keys_destroyed: usize,
    /// Quarantined records resolved or discarded as part of this request.
    pub quarantine_settled: usize,
    /// Identifier of the tombstone written: `tomb-` followed by a ULID. Prefixed because the log is
    /// read beside record identifiers, and one that could be mistaken for a record would be.
    pub tombstone_id: String,
}

/// One line of the append-only tombstone log.
///
/// Append-only means completion is a *second* line for the same identifier rather than an edit of
/// the first: an erasure record that can be rewritten is an erasure record that can be unwritten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tombstone {
    /// Identifier the caller confirms against.
    ///
    /// Spelled `tombstone_id` on the wire: the log is read by other tools, and a field named `id`
    /// beside a subject and a timestamp says less than it should.
    #[serde(rename = "tombstone_id")]
    pub(crate) id: String,
    /// The erased subject's pseudonym.
    pub(crate) subject: String,
    /// When the destruction was ordered, in milliseconds since the Unix epoch.
    pub(crate) at_ms: i64,
    /// Whether the backup window has since passed with no recoverable key found.
    pub(crate) complete: bool,
}

/// Erases a subject's bodies and records the fact permanently.
///
/// Verification is two-phase. The live check runs here; completion cannot be asserted until the key
/// backup window has passed, so the tombstone is only stamped complete later.
///
/// The order is chosen so that every crash point leaves an erasure that is still in progress rather
/// than one that has quietly stopped: the log entry comes first, because it is what
/// [`crate::reindex::reindex_all`] replays, and the key store tombstone comes before the keys are
/// destroyed, because a record arriving in between must not be able to mint a fresh key.
pub fn erase_subject(pipeline: &mut Pipeline, subject: &SubjectHash) -> Result<EraseReport> {
    let tombstone_id = format!("tomb-{}", RecordId::generate().as_str());
    append(
        pipeline,
        &Tombstone {
            id: tombstone_id.clone(),
            subject: subject.as_str().to_owned(),
            at_ms: fsutil::now_ms(),
            complete: false,
        },
    )?;

    pipeline.keys().tombstone(subject)?;
    let keys_destroyed = count_key_files(pipeline, subject)?;
    pipeline.keys().destroy_subject(subject)?;

    let bodies_sealed_off = drop_bodies(pipeline, subject)?;
    let quarantine_settled = discard_quarantine(pipeline, subject)?;

    // The derived index holds a wrapped share per subject, and there is no way to un-write one row:
    // the index is rebuilt from the erased tree instead. Expensive, and exactly what "the index is
    // disposable" is for.
    crate::reindex::reindex_all(pipeline)?;
    verify_live(pipeline, subject)?;

    Ok(EraseReport {
        bodies_sealed_off,
        keys_destroyed,
        quarantine_settled,
        tombstone_id,
    })
}

/// Confirms that no recoverable key copy remains, and stamps the tombstone complete.
///
/// `false` is not a failure: it means "not yet", either because a key file is still there or because
/// a snapshot taken before the destruction could still be restored. The check covers the key root
/// and anything beside it, including a backup directory a deployment keeps there; a snapshot held
/// somewhere this process cannot see is the operator's attestation, not this function's.
pub fn confirm_erasure(pipeline: &mut Pipeline, tombstone_id: &str) -> Result<bool> {
    let Some(entry) = read_log(pipeline)?
        .into_iter()
        .rfind(|entry| entry.id == tombstone_id)
    else {
        return Err(unknown_tombstone(tombstone_id));
    };
    if entry.complete {
        return Ok(true);
    }

    let subject = SubjectHash::parse(&entry.subject)?;
    if count_key_files(pipeline, &subject)? > 0 || !pipeline.keys().is_tombstoned(&subject)? {
        return Ok(false);
    }
    if fsutil::now_ms() < entry.at_ms + KEY_BACKUP_WINDOW_MS {
        return Ok(false);
    }

    append(
        pipeline,
        &Tombstone {
            complete: true,
            ..entry
        },
    )?;
    Ok(true)
}

/// Re-applies every erasure the log records.
///
/// Called by the rebuild, and idempotent so it can be. Without it a rebuild would index a record
/// restored from a backup — or replayed late by a sender that never heard about the erasure — as if
/// its subject had never been erased, complete with the wrapped share the tree still carries.
pub(crate) fn replay_tombstones(pipeline: &Pipeline) -> Result<usize> {
    let mut seen = BTreeSet::new();
    let mut replayed = 0;
    for entry in read_log(pipeline)? {
        if !seen.insert(entry.id.clone()) {
            continue;
        }
        let subject = SubjectHash::parse(&entry.subject)?;
        pipeline.keys().tombstone(&subject)?;
        pipeline.keys().destroy_subject(&subject)?;
        drop_bodies(pipeline, &subject)?;
        discard_quarantine(pipeline, &subject)?;
        replayed += 1;
    }
    Ok(replayed)
}

/// Rewrites every live record naming `subject` to carry no body.
///
/// Returns how many bodies this took away. A record already without one is not counted again, which
/// is what makes a replay report nothing rather than the same erasure twice.
fn drop_bodies(pipeline: &Pipeline, subject: &SubjectHash) -> Result<usize> {
    let mut dropped = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::RECORDS_DIR),
        layout::RECORD_EXT,
    )? {
        let text = fs::read_to_string(&path)?;
        let Ok(document) = Document::parse(&text) else {
            continue;
        };
        if !names(&document, subject) || matches!(document.body, Body::Plain(_)) {
            continue;
        }
        let erased = Document {
            record: document.record,
            body: Body::Plain(String::new()),
        };
        fsutil::replace_atomically(&path, erased.render().as_bytes())?;
        dropped += 1;
    }
    Ok(dropped)
}

/// Discards the spooled copies of records held for a subject that has now been erased.
///
/// This is what settles a quarantine that can never resolve: the subject's keys are gone, so the
/// record can never be sealed under them, and the spool copy is the last readable copy of the body.
fn discard_quarantine(pipeline: &Pipeline, subject: &SubjectHash) -> Result<usize> {
    let mut settled = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::QUARANTINE_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            continue;
        };
        if names(&document, subject) {
            fsutil::remove_if_present(&path)?;
            settled += 1;
        }
    }
    Ok(settled)
}

/// Whether a record names a subject.
fn names(document: &Document, subject: &SubjectHash) -> bool {
    document
        .record
        .subjects
        .iter()
        .any(|named| &named.hash == subject)
}

/// Counts key files belonging to a subject anywhere under the key root.
///
/// The key store lays keys out as `<epoch>` files inside a directory named for the subject, so any
/// file whose parent is that directory is a key — including one inside a backup directory a
/// deployment keeps beside the live one, which is the copy that would make destruction a fiction.
fn count_key_files(pipeline: &Pipeline, subject: &SubjectHash) -> Result<usize> {
    let root = pipeline.root().join(layout::KEYSTORE_DIR);
    let mut count = 0;
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        let is_subject_dir = dir.file_name().is_some_and(|name| name == subject.as_str());
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if is_subject_dir {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// The live half of verification: what this process can see, it must see gone.
fn verify_live(pipeline: &Pipeline, subject: &SubjectHash) -> Result<()> {
    if !pipeline.keys().is_tombstoned(subject)? {
        return Err(unverified(subject, "the subject is not tombstoned"));
    }
    let remaining = count_key_files(pipeline, subject)?;
    if remaining > 0 {
        return Err(unverified(
            subject,
            &format!("{remaining} key file(s) remain under the key root"),
        ));
    }
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::RECORDS_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            continue;
        };
        if names(&document, subject) && matches!(document.body, Body::Sealed(_)) {
            return Err(unverified(
                subject,
                &format!("`{}` still carries a sealed body", path.display()),
            ));
        }
    }
    Ok(())
}

/// Appends one line to the tombstone log, durably.
fn append(pipeline: &Pipeline, entry: &Tombstone) -> Result<()> {
    let line = serde_json::to_string(entry).map_err(|e| crate::pipeline::invalid(e.to_string()))?;
    let path = pipeline.root().join(layout::TOMBSTONE_LOG);
    fsutil::append_line_sync(&path, &line)?;
    fsutil::sync_dir(fsutil::parent_of(&path)?)?;
    Ok(())
}

/// Reads the tombstone log in order.
///
/// A line that will not parse is skipped and logged: the log is append-only, so a torn last line
/// from an interrupted write is the one corruption to expect, and refusing to read the whole log
/// because of it would block every rebuild.
pub(crate) fn read_log(pipeline: &Pipeline) -> Result<Vec<Tombstone>> {
    let path = pipeline.root().join(layout::TOMBSTONE_LOG);
    let Some(text) = fsutil::read_to_string_opt(&path)? else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<Tombstone>(line) {
            Ok(entry) => entries.push(entry),
            Err(error) => tracing::warn!(%error, "unreadable tombstone line skipped"),
        }
    }
    Ok(entries)
}

/// A tombstone identifier no line in the log carries.
fn unknown_tombstone(id: &str) -> crate::Error {
    crate::Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no tombstone `{id}` in the log"),
    ))
}

/// Verification found something the erasure should have removed.
///
/// The crate's error type has no verification arm, and this *is* a statement about the filesystem —
/// a key file that is still there, a body that was not rewritten — so it is reported as one rather
/// than dressed up as something else.
fn unverified(subject: &SubjectHash, detail: &str) -> crate::Error {
    crate::Error::Io(io::Error::other(format!(
        "erasure of `{}` is unverified: {detail}",
        subject.as_str()
    )))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use yaam_crypto::Epoch;
    use yaam_md::{Body, Document};

    use super::{
        KEY_BACKUP_WINDOW_MS, Tombstone, confirm_erasure, count_key_files, erase_subject, read_log,
        verify_live,
    };
    use crate::testkit::{self, BODY, Harness};

    /// A server time inside the epoch the fixtures use.
    const T11: &str = "2026-08-22T11:00:00Z";

    /// A store holding one sealed record about one subject, plus one unrelated internal record.
    fn with_sealed_record() -> (
        Harness,
        yaam_contract::SubjectHash,
        yaam_contract::ActionRecord,
    ) {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        let record = testkit::subject_derived(T11, std::slice::from_ref(&subject));
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");
        (harness, subject, record)
    }

    #[test]
    fn erasure_takes_the_body_and_keeps_the_structure() {
        let (mut harness, subject, record) = with_sealed_record();
        let path = harness.path_of(&record);
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("```sealed")
        );

        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert_eq!(report.bodies_sealed_off, 1);
        assert_eq!(report.keys_destroyed, 1);
        assert_eq!(report.quarantine_settled, 0);
        assert!(report.tombstone_id.starts_with("tomb-"));

        // The body is gone from the live tree and unreadable in every other copy.
        let parsed = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        assert!(matches!(parsed.body, Body::Plain(text) if text.is_empty()));
        assert!(
            yaam_crypto::keystore::KeyStore::get(
                harness.pipeline.keys(),
                &subject,
                &Epoch::containing(1_787_000_000_000)
            )
            .expect("get")
            .is_none()
        );

        // The structure is retained, deliberately: the record still says who it was about.
        assert_eq!(parsed.record.subjects.len(), 1);
        assert_eq!(parsed.record.entities.len(), 1);
        assert_eq!(parsed.record.attrs.len(), 1);
        let counts = harness.counts();
        assert_eq!(counts["records"], 2);
        assert_eq!(counts["record_subjects"], 1);
        // Three references: two from the unrelated internal record, one from the erased one.
        assert_eq!(counts["entity_refs"], 3);
        // The entity timeline is structure too, and stays.
        assert!(
            harness
                .root()
                .join("entities/order_ref/ord10014721/timeline.md")
                .exists()
        );

        // What the index must not keep is key material.
        let subject_rows: Vec<String> = harness
            .snapshot()
            .into_iter()
            .filter(|line| line.starts_with("subject|"))
            .collect();
        assert_eq!(subject_rows.len(), 1);
        assert!(subject_rows[0].ends_with("|1||~"), "{:?}", subject_rows[0]);
        verify_live(&harness.pipeline, &subject).expect("verified");
    }

    #[test]
    fn erasing_twice_is_the_same_erasure() {
        let (mut harness, subject, _) = with_sealed_record();
        erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let second = erase_subject(&mut harness.pipeline, &subject).expect("erased again");
        assert_eq!(second.bodies_sealed_off, 0, "there is no body left to take");
        assert_eq!(second.keys_destroyed, 0);
        assert_eq!(read_log(&harness.pipeline).expect("log").len(), 2);
    }

    #[test]
    fn a_rebuild_without_the_tombstone_replay_would_resurrect_what_was_erased() {
        let (mut harness, subject, record) = with_sealed_record();
        let path = harness.path_of(&record);
        let restored = fs::read_to_string(&path).expect("read");

        erase_subject(&mut harness.pipeline, &subject).expect("erased");

        // A backup restore, or a sender replaying a record it wrote before the erasure: the sealed
        // block, wrapped share and all, is back in the tree.
        fs::write(&path, &restored).expect("restore");
        let resurrected = Document::parse(&restored).expect("parses");
        harness.pipeline.commit(&resurrected).expect("committed");
        let with_share: Vec<String> = harness
            .snapshot()
            .into_iter()
            .filter(|line| line.starts_with("subject|"))
            .collect();
        assert!(
            !with_share[0].ends_with("|~"),
            "indexing the tree alone puts the wrapped share back: {:?}",
            with_share[0]
        );

        // Which is what the replay is for. Erase, rebuild, verify — in that order and together.
        let report = crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.tombstones_replayed, 1);
        assert_eq!(report.from_tree, 2);
        assert!(
            !fs::read_to_string(&path)
                .expect("read")
                .contains("```sealed"),
            "the replay re-erased the restored copy"
        );
        let after: Vec<String> = harness
            .snapshot()
            .into_iter()
            .filter(|line| line.starts_with("subject|"))
            .collect();
        assert!(after[0].ends_with("|1||~"), "{:?}", after[0]);
        verify_live(&harness.pipeline, &subject).expect("still erased after the rebuild");
    }

    #[test]
    fn a_record_arriving_after_an_erasure_is_quarantined_and_then_settled() {
        let (mut harness, subject, _) = with_sealed_record();
        erase_subject(&mut harness.pipeline, &subject).expect("erased");

        // Late, and unsealable: its subject's keys are gone for good.
        let late = testkit::subject_derived("2026-08-24T09:00:00Z", std::slice::from_ref(&subject));
        assert!(matches!(
            harness
                .pipeline
                .accept(late, BODY)
                .expect("held, not dropped"),
            crate::pipeline::Accepted::Quarantined(_)
        ));
        assert_eq!(harness.counts()["quarantine_pending"], 1);

        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert_eq!(
            report.quarantine_settled, 1,
            "the spooled body cannot be kept"
        );
        assert_eq!(harness.counts()["quarantine_pending"], 0);
    }

    #[test]
    fn completion_waits_for_the_backup_window() {
        let (mut harness, _, _) = with_sealed_record();
        let subject = testkit::subject('a');
        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");

        // The live copies are gone, but a snapshot taken a moment ago could still hold the key.
        assert!(!confirm_erasure(&mut harness.pipeline, &report.tombstone_id).expect("checked"));

        age_tombstone(&harness, KEY_BACKUP_WINDOW_MS + 60_000);
        assert!(confirm_erasure(&mut harness.pipeline, &report.tombstone_id).expect("checked"));
        // Stamped complete by a second line, and a repeat reads that line rather than re-checking.
        let log = read_log(&harness.pipeline).expect("log");
        assert_eq!(log.len(), 2);
        assert!(log[1].complete);
        assert!(confirm_erasure(&mut harness.pipeline, &report.tombstone_id).expect("checked"));

        assert!(confirm_erasure(&mut harness.pipeline, "tomb-nothing").is_err());
    }

    #[test]
    fn a_key_left_in_a_backup_directory_blocks_completion() {
        let (mut harness, subject, _) = with_sealed_record();
        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        age_tombstone(&harness, KEY_BACKUP_WINDOW_MS + 60_000);

        // A snapshot of the key store kept beside it. Destroying the live copy erased nothing.
        let backup = harness
            .root()
            .join("keystore/keys.bak")
            .join(subject.as_str());
        fs::create_dir_all(&backup).expect("dirs");
        fs::write(backup.join("2026-Q3"), [7u8; 32]).expect("a recoverable key");

        assert_eq!(
            count_key_files(&harness.pipeline, &subject).expect("count"),
            1
        );
        assert!(!confirm_erasure(&mut harness.pipeline, &report.tombstone_id).expect("checked"));
        assert!(verify_live(&harness.pipeline, &subject).is_err());
    }

    #[test]
    fn a_torn_log_line_does_not_stop_a_replay() {
        let (mut harness, subject, _) = with_sealed_record();
        erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let log = harness.root().join("tombstones.jsonl");
        let mut text = fs::read_to_string(&log).expect("read");
        text.push_str("{\"tombstone_id\":\"tomb-tor\n");
        fs::write(&log, text).expect("write");

        let report = crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.tombstones_replayed, 1);
    }

    #[test]
    fn an_empty_log_replays_nothing() {
        let mut harness = Harness::new();
        assert_eq!(read_log(&harness.pipeline).expect("log").len(), 0);
        let report = crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(report.tombstones_replayed, 0);
    }

    /// Backdates every log entry, which is how a test reaches past the backup window.
    ///
    /// The log is append-only in service; rewriting it here is a test rig, not a supported operation.
    fn age_tombstone(harness: &Harness, by_ms: i64) {
        let path = harness.root().join("tombstones.jsonl");
        let aged: Vec<String> = read_log(&harness.pipeline)
            .expect("log")
            .into_iter()
            .map(|entry| {
                serde_json::to_string(&Tombstone {
                    at_ms: entry.at_ms - by_ms,
                    ..entry
                })
                .expect("line")
            })
            .collect();
        fs::write(path, aged.join("\n") + "\n").expect("write");
    }
}
