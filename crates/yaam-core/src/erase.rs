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
//!
//! A third, about what an erasure *writes*. The tombstone line it appends carries the records it
//! reached and the roles the subject held on them, permanently and in the clear. That is deliberate
//! — it is the account of the erasure, and an account nobody can read afterwards is not one — but
//! it concentrates a subject-to-record mapping into a file that is never deleted and travels in the
//! backup. See [`Tombstone::records`] for what that does and does not add to what the store already
//! keeps.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;

use serde::{Deserialize, Serialize};
use yaam_contract::{RecordId, Role, SubjectHash};
use yaam_crypto::keystore::KeyStore as _;
use yaam_md::{Body, Document};

use crate::{Pipeline, Result, fsutil, layout};

/// How long a key snapshot may still exist after destruction.
///
/// Erasure cannot be asserted complete while a backup taken before the destruction is still inside
/// its retention window, because restoring it would restore the key.
///
/// Seven days, because that is the number the erasure SLA states — *immediate for live copies,
/// complete within seven days* — and this constant is what decides when the tombstone carries the
/// completion stamp that sentence refers to. A key store on the intended schedule keeps seven daily
/// copies on a rolling seven-day window, so a copy taken the hour before a destruction is on the
/// shelf for nearly a week afterwards. A shorter window here would stamp a tombstone complete with
/// six of those copies still holding the key, and the attestation would be false in the one
/// direction nobody can check from the live tree. Erring long only makes an operator wait for a
/// stamp; erring short makes the stamp a lie.
pub const KEY_BACKUP_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// What an erasure did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EraseReport {
    /// Records whose bodies became unreadable.
    pub bodies_sealed_off: usize,
    /// Keys destroyed, across all epochs.
    pub keys_destroyed: usize,
    /// Records taken out of quarantine by this request and published with no body.
    ///
    /// Settled rather than held: an erasure is the one condition a quarantined record can never
    /// retry its way out of, so the hold ends here — structure published, body dropped.
    pub quarantine_settled: usize,
    /// Identifier of the tombstone written: `tomb-` followed by a ULID. Prefixed because the log is
    /// read beside record identifiers, and one that could be mistaken for a record would be.
    pub tombstone_id: String,
}

/// One record an erasure reached, and the part the erased subject played in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ErasedRecord {
    /// The record's identifier.
    pub(crate) record_id: String,
    /// Every role the erased subject held on that record.
    ///
    /// A list rather than one value, because a record may name the same subject more than once —
    /// one reference per canonicalisation version is the expected case — and an erasure that
    /// reported one of them would be reporting less than it reached.
    pub(crate) roles: Vec<Role>,
}

/// One line of the append-only tombstone log.
///
/// Append-only means completion is a *second* line for the same identifier rather than an edit of
/// the first: an erasure record that can be rewritten is an erasure record that can be unwritten.
///
/// Every field a line has ever carried is optional on the way in. The log is the one file in the
/// store that is never rewritten, so lines written by older builds are read by newer ones for as
/// long as the store exists, and a reader that refused them would refuse the oldest erasures first.
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
    /// Every record this erasure reached, with the roles the subject held on each.
    ///
    /// This is the artefact that answers "which records did this erasure reach" without walking the
    /// tree, and it is the only account of that which survives the tree being restored, rebuilt or
    /// archived. The roles are here for the same reason: `record_subjects` carries them too, but a
    /// derived index is not proof of what was erased, and if it ever has to be proved that a
    /// subject was a principal on one record and merely a party to another, that distinction is
    /// part of it.
    ///
    /// **Read this before deciding the log is a safe place to keep it.** The tombstone log is
    /// plaintext, is never deleted, and travels in the backup — so this list is a permanent,
    /// concentrated, greppable subject-to-record mapping in the clear, in the one file no later
    /// decision can prune. It adds no *fact* the store did not already retain: the same pairings
    /// survive in each erased record's own frontmatter, in `record_subjects`, and in
    /// `audit/subjects/`, all three live and all three in the backup. What it changes is shape and
    /// permanence — a ready-made dossier per erasure instead of a join across surfaces that could
    /// in principle be narrowed later. That is a widening of the *documented* residue, not of the
    /// data, and it is a decision for whoever signs the residue off rather than one this code
    /// should make quietly. Written because the plan requires it in steps 2 and 5 and cites it as
    /// where the retained graph lives; flagged because the sign-off rests on a document that
    /// describes this log as holding the pseudonym alone.
    ///
    /// Absent from a line an older build wrote, and empty is not "reached nothing" — it is "this
    /// line does not say". Nothing derives behaviour from it: the replay re-reads the tree.
    #[serde(default)]
    pub(crate) records: Vec<ErasedRecord>,
}

/// What an erasure would reach, without reaching it.
///
/// Exists because the destruction is irreversible and an operator naming the wrong pseudonym has no
/// second chance. A confirmation prompt over a hash nobody can read at a glance is not a check; a
/// count of what is about to become unreadable is.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ErasePreview {
    /// Live records naming this subject.
    pub records: usize,
    /// Of those, the ones whose bodies are still readable and would stop being.
    pub bodies_readable: usize,
    /// Keys that would be destroyed, across all epochs.
    pub keys: usize,
    /// Records held in quarantine for this subject, which the erasure settles.
    pub quarantined: usize,
    /// Whether this subject has already been tombstoned by an earlier erasure.
    pub already_tombstoned: bool,
}

/// Counts what [`erase_subject`] would destroy.
///
/// Read-only: nothing here writes, so it is safe to run before deciding. It walks the same three
/// places the erasure does — the live tree, the key store and the quarantine spool — rather than
/// asking the index, because the index holds a wrapped share per subject and the tree is what the
/// erasure actually rewrites.
pub fn preview(pipeline: &Pipeline, subject: &SubjectHash) -> Result<ErasePreview> {
    let mut records = 0;
    let mut bodies_readable = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::RECORDS_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            continue;
        };
        if !names(&document, subject) {
            continue;
        }
        records += 1;
        // An already-emptied body is one an earlier erasure or replay reached; counting it again
        // would overstate what this run takes away.
        if !matches!(document.body, Body::Plain(_)) {
            bodies_readable += 1;
        }
    }
    let mut quarantined = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::QUARANTINE_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            continue;
        };
        if names(&document, subject) {
            quarantined += 1;
        }
    }
    Ok(ErasePreview {
        records,
        bodies_readable,
        keys: count_key_files(pipeline, subject)?,
        quarantined,
        already_tombstoned: pipeline.keys().is_tombstoned(subject)?,
    })
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
///
/// The rebuild takes the materialised timelines with it, so they are re-derived rather than kept:
/// their lines are a function of the records, and the fan-out the rebuild re-enqueues writes them
/// again. Nothing an erasure removes from a record can come back with them — the rebuild reads the
/// erased tree.
///
/// The record list goes into the log line the erasure opens with rather than into a second line
/// afterwards. It is read from the two surfaces this then rewrites, before either is touched, so a
/// crash anywhere after the append leaves a tombstone that already names everything this run was
/// about; the other order leaves one that names nothing and cannot be completed by hand.
pub fn erase_subject(pipeline: &mut Pipeline, subject: &SubjectHash) -> Result<EraseReport> {
    let tombstone_id = format!("tomb-{}", RecordId::generate().as_str());
    append(
        pipeline,
        &Tombstone {
            id: tombstone_id.clone(),
            subject: subject.as_str().to_owned(),
            at_ms: fsutil::now_ms(),
            complete: false,
            records: affected(pipeline, subject)?,
        },
    )?;

    pipeline.keys().tombstone(subject)?;
    let keys_destroyed = count_key_files(pipeline, subject)?;
    pipeline.keys().destroy_subject(subject)?;

    let bodies_sealed_off = drop_bodies(pipeline, subject)?;
    let quarantine_settled = sweep_quarantine(pipeline, subject)?;

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
        sweep_quarantine(pipeline, &subject)?;
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

/// Settles the records held in quarantine for a subject that has now been erased.
///
/// This is the sweep the erasure owes the spool, and what it is *for* decides how it behaves. A
/// quarantined record for the subject being erased is a body that outlives the erasure it should
/// have been caught by: the spool copy is sealed under a per-date quarantine key that no erasure
/// destroys, it is the last readable copy of that body, and it sits in the one directory nothing
/// queries. Left alone it is also a hold that can never end — resolution can never succeed for a
/// subject whose keys are gone, so the retry the spool exists for has nothing to come back to.
///
/// So the record is *published structure-only*, not deleted. The frontmatter and its subject list
/// go into the tree like any other record's, the body is dropped, and no key is minted. That is
/// exactly what [`crate::pipeline::Pipeline::seal_body`] already does for a record that arrives
/// *after* an erasure, and a quarantined record is the same record reaching the same state from the
/// other direction: an erasure has landed on it and the body cannot be kept. One condition, one set
/// of manners. Deleting it instead — which is what this did before — silently dropped an action
/// record, which is the one loss the write path is built never to take, and it left the erasure
/// unable to say what it had reached because the evidence went with the body.
///
/// The index is not written here. Both callers rebuild it from the tree immediately afterwards —
/// [`erase_subject`] as its last step, [`replay_tombstones`] because
/// [`crate::reindex::reindex_all`] runs it before the walk — so the published record and the
/// retracted `quarantine_pending` row both come out of that rebuild, from the tree, which is the
/// only version of "derived" that survives a restore.
///
/// Idempotent from both ends: a record already in the tree is left as it stands rather than
/// overwritten with this copy, because a spool file whose record has since published normally holds
/// the *older* subject set, and a spool file that is gone is a sweep that already ran.
fn sweep_quarantine(pipeline: &Pipeline, subject: &SubjectHash) -> Result<usize> {
    let mut settled = 0;
    for path in fsutil::walk_files(
        &pipeline.root().join(layout::QUARANTINE_DIR),
        layout::RECORD_EXT,
    )? {
        let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
            continue;
        };
        if !names(&document, subject) {
            continue;
        }
        publish_structure_only(pipeline, document)?;
        fsutil::remove_if_present(&path)?;
        settled += 1;
    }
    Ok(settled)
}

/// Publishes a held record into the tree with its body dropped.
///
/// Through the same stage-then-rename the write path uses, so the file lands with the mode its
/// visibility calls for and appears whole or not at all. The spool copy is removed only once this
/// has returned: the other order loses the record if the publish fails.
fn publish_structure_only(pipeline: &Pipeline, held: Document) -> Result<()> {
    let structure = Document {
        record: held.record,
        body: Body::Plain(String::new()),
    };
    let stamp = layout::stamp_of(&structure.record)?;
    if pipeline.published_path(&structure.record, &stamp)?.exists() {
        return Ok(());
    }
    let staged = pipeline.stage(&structure)?;
    pipeline.place(&structure, &staged, &stamp)?;
    Ok(())
}

/// Every record an erasure of `subject` reaches, with the roles it holds on each.
///
/// Both surfaces the erasure rewrites are read — the live tree and the quarantine spool — because
/// the tombstone is meant to answer what the erasure reached, and a held record it publishes
/// structure-only is something it reached. Keyed by record identifier so the two cannot list the
/// same record twice, and ordered, so two runs over the same store produce the same line.
fn affected(pipeline: &Pipeline, subject: &SubjectHash) -> Result<Vec<ErasedRecord>> {
    let mut found: BTreeMap<String, Vec<Role>> = BTreeMap::new();
    for dir in [layout::RECORDS_DIR, layout::QUARANTINE_DIR] {
        for path in fsutil::walk_files(&pipeline.root().join(dir), layout::RECORD_EXT)? {
            let Ok(document) = Document::parse(&fs::read_to_string(&path)?) else {
                continue;
            };
            let roles = roles_of(&document, subject);
            if roles.is_empty() {
                continue;
            }
            let entry = found
                .entry(document.record.record_id.as_str().to_owned())
                .or_default();
            for role in roles {
                if !entry.contains(&role) {
                    entry.push(role);
                }
            }
        }
    }
    Ok(found
        .into_iter()
        .map(|(record_id, roles)| ErasedRecord { record_id, roles })
        .collect())
}

/// The roles a subject holds on one record, in the order the record names them.
fn roles_of(document: &Document, subject: &SubjectHash) -> Vec<Role> {
    document
        .record
        .subjects
        .iter()
        .filter(|named| &named.hash == subject)
        .map(|named| named.role)
        .collect()
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
    let root = pipeline.paths().key_store.clone();
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

    use yaam_contract::{CanonVer, Role, SubjectRef};
    use yaam_crypto::Epoch;
    use yaam_md::{Body, Document};

    use super::{
        ErasedRecord, KEY_BACKUP_WINDOW_MS, Tombstone, confirm_erasure, count_key_files,
        erase_subject, preview, read_log, verify_live,
    };
    use crate::fsutil;
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

    /// The preview has to count what the erasure would reach, and nothing else.
    ///
    /// It is what an operator confirms against, so an overcount would have them refuse a safe
    /// erasure and an undercount would have them approve one they had not understood.
    #[test]
    fn a_preview_counts_what_an_erasure_would_reach() {
        let (harness, subject, _) = with_sealed_record();

        // A record held back during a lookup outage, for a different subject who is then erased:
        // in the quarantine spool, and not this subject's, so it must not be counted here.
        let other = testkit::subject('f');
        let mut harness = harness.resolving_with(testkit::UnavailableLookup);
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-23T12:00:00Z", std::slice::from_ref(&other)),
                BODY,
            )
            .expect("quarantined");
        let mut harness = harness.resolving_with(crate::resolve::DeclaredSubjects);
        yaam_crypto::keystore::KeyStore::tombstone(harness.pipeline.keys(), &other)
            .expect("tombstone");

        // A file the walk cannot parse must be skipped rather than abort the count.
        fs::write(
            harness.root().join("records/2026/08/20/unreadable.md"),
            "---\naction: [unclosed\n---\nbody\n",
        )
        .expect("write");

        let found = preview(&harness.pipeline, &subject).expect("preview");
        assert_eq!(found.records, 1);
        assert_eq!(
            found.bodies_readable, 1,
            "the body is still sealed, not gone"
        );
        assert_eq!(found.keys, 1);
        assert_eq!(found.quarantined, 0, "the held record is another subject's");
        assert!(!found.already_tombstoned);

        // The other subject's own preview sees the spooled copy, which is what an erasure settles.
        let held = preview(&harness.pipeline, &other).expect("preview");
        assert_eq!(held.quarantined, 1);
        assert!(
            held.already_tombstoned,
            "a subject the key store has tombstoned has to be reported as such"
        );

        // After the erasure nothing is left to take away, and a second run would report as much.
        erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let after = preview(&harness.pipeline, &subject).expect("preview");
        assert_eq!(after.records, 1, "the record itself is retained");
        assert_eq!(after.bodies_readable, 0, "its body is already gone");
        assert_eq!(after.keys, 0);
        assert!(after.already_tombstoned);
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
        // The entity timeline is structure too, and stays — re-derived rather than kept, because
        // the rebuild an erasure ends in drops the timelines with the rows that account for them.
        let timeline = harness
            .root()
            .join("entities/order_ref/ord10014721/timeline.md");
        assert!(!timeline.exists(), "the rebuild took the timelines with it");
        harness.pipeline.drain_fanout(100).expect("drained");
        assert_eq!(
            fs::read_to_string(&timeline)
                .expect("timeline")
                .matches(record.record_id.as_str())
                .count(),
            1,
            "the erased record is still listed, once"
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

    /// A record arriving after the erasure leaves the erasure exactly as complete as it was.
    ///
    /// The record is published structure-only by the write path — see
    /// `pipeline::tests::a_record_for_an_erased_subject_is_published_without_a_body` — and the
    /// property that belongs here is the erasure side of it: nothing new to destroy, nothing new to
    /// hold, and a verification that still passes over a tree that has grown a record.
    #[test]
    fn a_record_arriving_after_an_erasure_leaves_it_verified() {
        let (mut harness, subject, _) = with_sealed_record();
        erase_subject(&mut harness.pipeline, &subject).expect("erased");

        let late = testkit::subject_derived("2026-08-24T09:00:00Z", std::slice::from_ref(&subject));
        harness
            .pipeline
            .accept(late, BODY)
            .expect("published, not held");
        assert_eq!(harness.counts()["quarantine_pending"], 0);
        assert_eq!(harness.counts()["records"], 3);

        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert_eq!(
            report.bodies_sealed_off, 0,
            "the late record never had a body to take"
        );
        assert_eq!(report.quarantine_settled, 0);
        verify_live(&harness.pipeline, &subject).expect("still verified");
    }

    /// A record held during a lookup outage is published structure-only when its subject is erased.
    ///
    /// The spool copy is the last readable copy of that body, sealed under a quarantine key the
    /// erasure does not destroy, so leaving it would leave the one thing the erasure was for. But
    /// the record itself is an action record, and dropping one is the loss the write path is built
    /// never to take — so the hold ends the way it ends for a record that arrives *after* an
    /// erasure: the structure is published, the body is not.
    #[test]
    fn a_held_record_is_published_structure_only_by_its_subjects_erasure() {
        let (harness, _, _) = with_sealed_record();
        let subject = testkit::subject('b');
        let held = testkit::subject_derived("2026-08-24T09:00:00Z", std::slice::from_ref(&subject));

        let mut harness = harness.resolving_with(testkit::UnavailableLookup);
        harness
            .pipeline
            .accept(held.clone(), BODY)
            .expect("held, not dropped");
        assert_eq!(harness.counts()["quarantine_pending"], 1);
        let path = harness.path_of(&held);
        assert!(!path.exists(), "a held record is not in the tree yet");

        let mut harness = harness.resolving_with(crate::resolve::DeclaredSubjects);
        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert_eq!(
            report.quarantine_settled, 1,
            "the spooled body cannot be kept"
        );
        assert_eq!(harness.counts()["quarantine_pending"], 0);

        // Published, not discarded: the record is in the tree, its subjects are still on it, and
        // the body it was held with is gone rather than travelling out of the spool with it.
        let published = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        assert!(matches!(&published.body, Body::Plain(text) if text.is_empty()));
        assert_eq!(published.record.subjects.len(), 1);
        assert_eq!(published.record.subjects[0].hash, subject);
        assert_eq!(published.record.entities.len(), 1);
        assert!(published.record.summary.is_empty());
        assert_eq!(
            harness.counts()["records"],
            3,
            "the held record is indexed by the rebuild the erasure ends in"
        );
        verify_live(&harness.pipeline, &subject).expect("verified");

        // And it is the same shape a record arriving after the erasure takes, which is the point:
        // one condition, one set of manners.
        let late = testkit::subject_derived("2026-08-25T09:00:00Z", std::slice::from_ref(&subject));
        harness.pipeline.accept(late.clone(), BODY).expect("stored");
        let after = Document::parse(&fs::read_to_string(harness.path_of(&late)).expect("read"))
            .expect("parses");
        assert!(matches!(&after.body, Body::Plain(text) if text.is_empty()));
    }

    /// The tombstone says which records the erasure reached, and in what role.
    ///
    /// Without it the only account of what an erasure covered is a walk of a tree that a restore, a
    /// rebuild or an archive can change underneath the answer. The roles are part of it because
    /// "was a principal here, merely a party there" is a distinction the erasure destroyed the
    /// evidence for everywhere else it is provable.
    #[test]
    fn a_tombstone_names_the_records_an_erasure_reached_and_the_roles_on_them() {
        let (harness, subject, record) = with_sealed_record();

        // A second record naming the same subject as a party rather than as its principal.
        let mut second = testkit::subject_derived("2026-08-23T10:00:00Z", &[]);
        second.subjects = vec![
            SubjectRef {
                hash: testkit::subject('c'),
                role: Role::Principal,
                canon_ver: CanonVer(1),
            },
            SubjectRef {
                hash: subject.clone(),
                role: Role::Party,
                canon_ver: CanonVer(1),
            },
        ];
        let mut harness = harness;
        harness
            .pipeline
            .accept(second.clone(), BODY)
            .expect("accepted");

        // And one held back by an outage, which the erasure reaches by publishing it.
        let mut harness = harness.resolving_with(testkit::UnavailableLookup);
        let field =
            testkit::subject_derived("2026-08-24T09:00:00Z", std::slice::from_ref(&subject));
        harness.pipeline.accept(field.clone(), BODY).expect("held");
        let mut harness = harness.resolving_with(crate::resolve::DeclaredSubjects);

        let report = erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let entry = read_log(&harness.pipeline)
            .expect("log")
            .into_iter()
            .find(|entry| entry.id == report.tombstone_id)
            .expect("the line this erasure wrote");

        let mut expected = vec![
            ErasedRecord {
                record_id: record.record_id.as_str().to_owned(),
                roles: vec![Role::Principal],
            },
            ErasedRecord {
                record_id: second.record_id.as_str().to_owned(),
                roles: vec![Role::Party],
            },
            ErasedRecord {
                record_id: field.record_id.as_str().to_owned(),
                roles: vec![Role::Principal],
            },
        ];
        expected.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        assert_eq!(
            entry.records, expected,
            "the tombstone has to name every record the erasure reached, spool included"
        );
        // The unrelated internal record is not one of them, and neither is the other subject's.
        assert!(
            !entry
                .records
                .iter()
                .any(|reached| reached.roles.is_empty() || reached.record_id.is_empty())
        );

        // The completion stamp carries the same list forward, so the finished line is the one an
        // operator can read the erasure off without the opening line beside it.
        age_tombstone(&harness, KEY_BACKUP_WINDOW_MS + 60_000);
        assert!(confirm_erasure(&mut harness.pipeline, &report.tombstone_id).expect("checked"));
        let stamped = read_log(&harness.pipeline)
            .expect("log")
            .into_iter()
            .rfind(|entry| entry.id == report.tombstone_id)
            .expect("the completion line");
        assert!(stamped.complete);
        assert_eq!(stamped.records, expected);
    }

    /// A line an older build wrote is still readable, and says so rather than claiming nothing.
    ///
    /// The log is the one file in the store that is never rewritten, so every line ever appended to
    /// it has to keep parsing. A reader that required the record list would refuse the oldest
    /// erasures — the ones whose completion stamp matters most.
    #[test]
    fn a_tombstone_line_without_a_record_list_still_reads() {
        let (mut harness, subject, _) = with_sealed_record();
        let long_ago = fsutil::now_ms() - KEY_BACKUP_WINDOW_MS - 60_000;
        fs::write(
            harness.root().join("tombstones.jsonl"),
            format!(
                "{{\"tombstone_id\":\"tomb-old\",\"subject\":\"{}\",\"at_ms\":{long_ago},\
                 \"complete\":false}}\n",
                subject.as_str()
            ),
        )
        .expect("write");

        let log = read_log(&harness.pipeline).expect("log");
        assert!(
            log[0].records.is_empty(),
            "the line does not say, and cannot"
        );
        // Readable enough to replay and to complete, which is what the log is for.
        assert_eq!(
            crate::reindex::reindex_all(&mut harness.pipeline)
                .expect("rebuilt")
                .tombstones_replayed,
            1
        );
        assert!(confirm_erasure(&mut harness.pipeline, "tomb-old").expect("checked"));
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
