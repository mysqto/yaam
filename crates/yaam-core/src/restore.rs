//! Recovering a key store, and holding one to the erasures it never heard about.
//!
//! # The hole this closes
//!
//! [`crate::backup`] restores the tree. It cannot restore the key store, because no backup contains
//! one — that exclusion is the argument the whole erasure guarantee rests on. So the key store has a
//! second recovery path, and until this module existed that path was a file copy: an operator with a
//! dead key disk copied yesterday's key material back into place, and nothing anywhere compared what
//! they had just installed against what had since been erased.
//!
//! Measured, on a scratch store, with a real sealed body: a tree restored from a pre-erasure backup
//! plus a key store restored from a pre-erasure copy reads the erased body back in full plaintext.
//! The live store refuses the same key correctly, and refuses it without reaching for the key at
//! all, because the live store carries `tombstones.jsonl`. That is the whole difference, and it is
//! why the exposure is exactly the disaster-recovery shape rather than an exotic one.
//!
//! # Where the authority lives
//!
//! A restored key store is, by construction, a set of keys that no tombstone has been applied to.
//! So the question is which record of the erasures to apply, and there are two, written at the same
//! moment and travelling separately afterwards:
//!
//! - **The tree's erasure log**, `tombstones.jsonl`, which is in every backup of the tree — that is
//!   [`crate::backup::MANIFEST`]'s reason for carrying it — and which [`crate::erase`] replays over
//!   the tree on every rebuild.
//! - **The key store's own blocklist**, one marker per erased subject, which travels in whatever
//!   copy the key store's own recovery keeps and in nothing else.
//!
//! Neither contains the other, and a recovery mixes copies taken at different moments, so this
//! reconciles against **both**: a key store recovered from after an erasure carries the marker even
//! where the tree beside it predates the log line, and a tree recovered from after one carries the
//! log line even where the key copy predates the marker. Applying the union reaches every erasure
//! either half has heard of.
//!
//! # What it cannot reach, and why that makes this a confirmation
//!
//! An erasure that *neither* half heard of is not reachable from anything on disk. Restore a tree
//! from before an erasure and a key store from before it and there is no local record that the
//! erasure ever happened — the log line and the marker are both in the copies that were not
//! restored. That is the shape a rehearsal measured plaintext out of, and no command can find what
//! no artifact carries.
//!
//! Which is the whole reason [`restore_key_store`] is confirmed rather than merely correct. The
//! bound is exact and worth stating as one: **the erasures at risk are those ordered after the
//! newer of the two artifacts was taken.** An erasure ordered between them is in whichever half is
//! newer — the tree's log if the tree is newer, the key store's blocklist if the key copy is —
//! and [`reconcile`] applies it either way. Only an erasure ordered after *both* is in neither, and
//! the person who knows whether there was one is the operator, not the store. So this prints what it
//! would be reconciling against, names the newest erasure either half has heard of, and stops. A
//! command that installed key material while unable to say whether it was walking back over an
//! erasure would be making a promise out of the operator's silence.
//!
//! [`crate::health::HealthReport::resurrected_keys`] is the standing signal for the other half of
//! the same problem: a key store put back with `cp`, which never reaches any of this.

use std::fs;
use std::path::Path;

use yaam_contract::SubjectHash;
use yaam_crypto::keystore::KeyStore as _;

use crate::erase::KEY_BACKUP_WINDOW_MS;
use crate::{Pipeline, Result, fsutil, layout};

/// What a reconcile compared, and what it destroyed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    /// Subjects an erasure stands against, from the tree's log and the key store's own blocklist
    /// together.
    pub subjects_erased: usize,
    /// Of those, the ones that still held a key when this ran.
    ///
    /// The finding, when it is not zero. A key store that needed nothing reports `0` here and a
    /// recovery that walked back over an erasure reports what it walked back over, which is the
    /// number an operator has to be able to see rather than infer from a silence.
    pub subjects_resurrected: usize,
    /// Key files destroyed.
    pub keys_destroyed: usize,
    /// Subjects the key store had no blocklist marker for, which now have one.
    ///
    /// A restored key store can hold the keys and none of the markers. Re-tombstoning is what stops
    /// the next record for that subject minting a fresh key, and it is done before the keys are
    /// destroyed for the reason an erasure does it in that order.
    pub blocklist_restored: usize,
}

impl Reconciliation {
    /// Whether this reconcile actually walked something back.
    #[must_use]
    pub fn undid_something(&self) -> bool {
        self.subjects_resurrected > 0 || self.blocklist_restored > 0
    }
}

/// What a key-store recovery would install, and what it would be reconciled against.
///
/// The report an operator reads before confirming. Its point is the one fact this process cannot
/// establish for itself: whether an erasure was ordered after both of these copies were taken, in
/// which case no line and no marker records it and installing the keys walks back over it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyRestorePreview {
    /// Key files the copy carries.
    pub key_files: usize,
    /// Blocklist markers the copy carries: what it knew had been erased when it was taken.
    pub markers: usize,
    /// Every erasure the destination tree's log records, as `(tombstone, ordered_ms)`.
    pub logged: Vec<(String, i64)>,
    /// Subjects the destination's key store already blocks.
    pub blocked_here: usize,
    /// When the newest erasure either half knows of was ordered.
    ///
    /// The line the confirmation turns on: an erasure ordered after this is in neither copy, and
    /// nothing here can discover one. `None` means neither half records an erasure at all, which is
    /// either a store that has never erased anything or two copies that both predate the first one.
    pub newest_erasure_ms: Option<i64>,
}

/// What a key-store restore put back, and what it then took away again.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeyRestoreReport {
    /// Key files copied in.
    pub files: usize,
    /// Blocklist markers copied in, the copy's own account of what it knew had been erased.
    pub markers: usize,
    /// The reconcile that ran before this returned.
    pub reconciled: Reconciliation,
    /// Every tombstone in the tree's log, with the standing of its attestation afterwards.
    pub attestations: Vec<(String, Attestation)>,
}

impl KeyRestoreReport {
    /// Whether every erasure the log records can now be asserted complete.
    #[must_use]
    pub fn all_attested(&self) -> bool {
        self.attestations
            .iter()
            .all(|(_, attestation)| attestation.complete())
    }
}

/// The three conditions step-7 verification is made of, itemised.
///
/// One `false` used to stand for all three, which is the state an operator cannot act on: a key file
/// that is present and a window that has not passed are the same answer and opposite jobs — one is a
/// key store to re-reconcile, the other is a week to wait. The verdict is still
/// [`crate::erase::confirm_erasure`]'s and this is not a second one; these are the inputs it decides
/// from, reported separately so that "not yet" says which of them is not yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attestation {
    /// Key files still under the key root for this subject. Must be nil.
    pub keys_present: usize,
    /// Whether the key store's blocklist names the subject, so no fresh key can be minted.
    pub tombstoned: bool,
    /// When the destruction was ordered, in milliseconds since the Unix epoch.
    pub ordered_ms: i64,
    /// When the key-backup window closes, in milliseconds since the Unix epoch.
    pub window_closes_ms: i64,
    /// The clock this was read against, so a report is reproducible from its own fields.
    pub now_ms: i64,
    /// Whether the log already carries a completion stamp for this tombstone.
    pub stamped: bool,
}

impl Attestation {
    /// Whether nothing stands in the way of the completion stamp.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.stamped || (self.settled() && self.window_passed())
    }

    /// Whether the live half holds: no key, and a blocklist that will not mint another.
    ///
    /// The half a wait does nothing for. `false` here is a key store to put right, and it is the
    /// distinction the single "not yet" was hiding.
    #[must_use]
    pub fn settled(&self) -> bool {
        self.keys_present == 0 && self.tombstoned
    }

    /// Whether the key-backup window has passed.
    #[must_use]
    pub fn window_passed(&self) -> bool {
        self.now_ms >= self.window_closes_ms
    }

    /// Milliseconds left on the window, or zero once it has passed.
    #[must_use]
    pub fn remaining_ms(&self) -> i64 {
        (self.window_closes_ms - self.now_ms).max(0)
    }
}

/// Destroys every key the erasures on record forbid, and restores the blocklist that forbids them.
///
/// Idempotent, and cheap on a store where nothing is wrong: the common answer is a
/// [`Reconciliation`] of zeroes. Run after both restores rather than after one, because either copy
/// can be the half that carries an erasure the other has not heard of.
///
/// The order inside the loop is the erasure's own — blocklist first, keys second — so that a record
/// arriving in the middle of this cannot mint the key it is about to lose.
pub fn reconcile(pipeline: &Pipeline) -> Result<Reconciliation> {
    let mut report = Reconciliation::default();
    for subject in erased_subjects(pipeline)? {
        report.subjects_erased += 1;
        if !pipeline.keys().is_tombstoned(&subject)? {
            pipeline.keys().tombstone(&subject)?;
            report.blocklist_restored += 1;
        }
        let keys = pipeline.keys().key_files_for(&subject)?;
        if keys > 0 {
            pipeline.keys().destroy_subject(&subject)?;
            report.subjects_resurrected += 1;
            report.keys_destroyed += keys;
        }
    }
    Ok(report)
}

/// Key files standing for subjects an erasure has already destroyed the keys of.
///
/// Read-only, and it is the standing signal rather than the remedy: a key store put back by hand,
/// with no command run over it, is a store where nothing has reconciled and nothing has said so.
/// Counted in files rather than in subjects because one subject holds one key per epoch and the
/// quarter that is still readable is the thing being counted.
pub fn resurrected_keys(pipeline: &Pipeline) -> Result<usize> {
    let mut count = 0;
    for subject in erased_subjects(pipeline)? {
        count += pipeline.keys().key_files_for(&subject)?;
    }
    Ok(count)
}

/// Itemises the three conditions the completion stamp waits on.
///
/// Reads, never stamps. [`crate::erase::confirm_erasure`] is what decides and what writes the
/// completion line; this is the account of the same three inputs, so a "not yet" can name which one
/// it is.
pub fn attestation(pipeline: &Pipeline, tombstone_id: &str) -> Result<Attestation> {
    let Some(entry) = crate::erase::read_log(pipeline)?
        .into_iter()
        .rfind(|entry| entry.id == tombstone_id)
    else {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no tombstone `{tombstone_id}` in the log"),
        )));
    };
    let subject = SubjectHash::parse(&entry.subject)?;
    Ok(Attestation {
        keys_present: pipeline.keys().key_files_for(&subject)?,
        tombstoned: pipeline.keys().is_tombstoned(&subject)?,
        ordered_ms: entry.at_ms,
        window_closes_ms: entry.at_ms + KEY_BACKUP_WINDOW_MS,
        now_ms: fsutil::now_ms(),
        stamped: entry.complete,
    })
}

/// The standing of every erasure the tree's log records, newest line per tombstone.
pub fn attestations(pipeline: &Pipeline) -> Result<Vec<(String, Attestation)>> {
    let mut ids: Vec<String> = Vec::new();
    for entry in crate::erase::read_log(pipeline)? {
        if !ids.iter().any(|seen| seen == &entry.id) {
            ids.push(entry.id.clone());
        }
    }
    ids.into_iter()
        .map(|id| Ok((id.clone(), attestation(pipeline, &id)?)))
        .collect()
}

/// Installs a key-store copy into this store's key root, then reconciles it against the erasures.
///
/// The copy and the reconcile are one operation and not two on purpose. Two would be a runbook step
/// an operator can stop halfway through, and the halfway state — keys back, nothing reconciled — is
/// exactly the state that reads an erased body back in plaintext. §10.4 words the rule as a runbook
/// ("the restore runbook therefore deletes all KEKs for tombstoned subjects"); a runbook is a
/// sentence, and this is the sentence with a mechanism under it.
///
/// Takes an open pipeline, which is what forces the useful ordering: the tree is restored first, so
/// the erasure log this reconciles against is on disk before any key is. A key store recovered into
/// a directory that is not a store yet has nothing to be held to.
///
/// Refuses a destination that already holds key material, for [`crate::backup::restore`]'s reason: a
/// key store half from one copy and half from another is two key stores, and afterwards nobody can
/// say which epochs came from where. Blocklist markers already in the destination are *kept* and
/// merged with the copy's — they are an account of an erasure, and an account of an erasure is
/// never overwritten by an older one.
pub fn restore_key_store(pipeline: &mut Pipeline, from: &Path) -> Result<KeyRestoreReport> {
    let into = pipeline.paths().key_store.clone();
    refuse_unless_key_store(from)?;
    refuse_occupied_key_store(pipeline, &into)?;

    let mut report = KeyRestoreReport::default();
    // Both directories, whether or not the copy carried them. A key store is opened with them in
    // place, and a recovery that left one out would be a store whose next tombstone had nowhere to
    // be written — which is the write that stops a late record minting a key for an erased subject.
    for dir in [&into, &into.join(KEYS_DIR), &into.join(TOMBSTONES_DIR)] {
        fsutil::create_private_dir_all(dir)?;
    }
    copy_into(
        &from.join(KEYS_DIR),
        &into.join(KEYS_DIR),
        &mut report.files,
    )?;
    copy_into(
        &from.join(TOMBSTONES_DIR),
        &into.join(TOMBSTONES_DIR),
        &mut report.markers,
    )?;

    report.reconciled = reconcile(pipeline)?;
    report.attestations = attestations(pipeline)?;
    Ok(report)
}

/// Reads what a recovery would install and what it would be held to, installing nothing.
///
/// Its own function for [`crate::erase::preview`]'s reason: the decision this asks an operator to
/// take is one they cannot take from the path they typed. What they need in front of them is the
/// date of the newest erasure either copy has heard of, because the question they are being asked is
/// whether anything was erased after it.
pub fn preview_key_store(pipeline: &Pipeline, from: &Path) -> Result<KeyRestorePreview> {
    refuse_unless_key_store(from)?;
    refuse_occupied_key_store(pipeline, &pipeline.paths().key_store.clone())?;

    let mut preview = KeyRestorePreview {
        key_files: count_files(&from.join(KEYS_DIR))?,
        markers: count_files(&from.join(TOMBSTONES_DIR))?,
        blocked_here: pipeline.keys().tombstoned_subjects()?.len(),
        ..KeyRestorePreview::default()
    };
    for entry in crate::erase::read_log(pipeline)? {
        if !preview.logged.iter().any(|(id, _)| id == &entry.id) {
            preview.logged.push((entry.id.clone(), entry.at_ms));
        }
        preview.newest_erasure_ms = Some(
            preview
                .newest_erasure_ms
                .map_or(entry.at_ms, |seen: i64| seen.max(entry.at_ms)),
        );
    }
    Ok(preview)
}

/// Files under a directory, at any depth, for the two counts a preview reports.
fn count_files(dir: &Path) -> Result<usize> {
    let mut count = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Where a key store keeps its keys, as [`yaam_crypto::keystore::FsKeyStore`] lays them out.
const KEYS_DIR: &str = "keys";
/// Where a key store keeps its blocklist.
const TOMBSTONES_DIR: &str = "tombstones";

/// Every subject an erasure stands against, from both records of what was erased.
///
/// The union, sorted and deduplicated. See this module's header for why one record is not enough.
fn erased_subjects(pipeline: &Pipeline) -> Result<Vec<SubjectHash>> {
    let mut subjects: Vec<SubjectHash> = pipeline.keys().tombstoned_subjects()?;
    for entry in crate::erase::read_log(pipeline)? {
        subjects.push(SubjectHash::parse(&entry.subject)?);
    }
    subjects.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    subjects.dedup_by(|a, b| a.as_str() == b.as_str());
    Ok(subjects)
}

/// Refuses a source directory that is not a key store.
///
/// A key store is two named directories and nothing else identifies one, so this is a shape test
/// rather than a manifest read. It exists because the destination is the key root: a mistyped path
/// would otherwise copy whatever it named into the one directory in the deployment that must hold
/// only keys, and the reconcile that follows would report nothing wrong with it.
fn refuse_unless_key_store(from: &Path) -> Result<()> {
    if from.join(KEYS_DIR).is_dir() || from.join(TOMBSTONES_DIR).is_dir() {
        return Ok(());
    }
    Err(crate::backup::refused(format!(
        "`{}` holds neither `{KEYS_DIR}/` nor `{TOMBSTONES_DIR}/`, so it is not a copy of a key \
         store. A key store is recovered from its own bounded-window copy, never from a backup of \
         the tree — a backup carries no key material at all",
        from.display()
    )))
}

/// Refuses to merge a recovered key store into one that already holds keys.
fn refuse_occupied_key_store(pipeline: &Pipeline, into: &Path) -> Result<()> {
    let held = match pipeline.key_material()? {
        yaam_crypto::keystore::KeyMaterial::Absent => 0,
        yaam_crypto::keystore::KeyMaterial::Unwrapped { files }
        | yaam_crypto::keystore::KeyMaterial::Wrapped { files, .. } => files,
        yaam_crypto::keystore::KeyMaterial::Mixed { wrapped, unwrapped } => wrapped + unwrapped,
    };
    if held > 0 {
        return Err(crate::backup::refused(format!(
            "`{}` already holds {held} key file(s); a key-store restore is not a merge. Two copies \
             mixed in one root cannot be told apart afterwards, and one of them may hold a key an \
             erasure destroyed",
            into.display()
        )));
    }
    Ok(())
}

/// Copies one directory of a key store in, counting the files and keeping them private.
///
/// Merges rather than replaces at the file level — a marker already in the destination stays, and a
/// key that is somehow already there is refused before this runs. Modes are set by
/// [`fsutil::create_private_dir_all`] and carried by [`fs::copy`], so a recovered key is `0600` in
/// its new home as it was in its old one.
fn copy_into(from: &Path, to: &Path, files: &mut usize) -> Result<()> {
    if !from.exists() {
        return Ok(());
    }
    fsutil::create_private_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_into(&entry.path(), &target, files)?;
        } else {
            if let Some(parent) = target.parent() {
                fsutil::create_private_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            *files += 1;
        }
    }
    fsutil::sync_dir(to)?;
    Ok(())
}

/// The age of the oldest record the quarantine spool is holding, and how many have no readable age.
///
/// Read from each spooled record's own `received_at` and never from the index. The register row's
/// `first_seen_ms` is a wall-clock read taken at registration, and a rebuild deletes and re-registers
/// the whole table — so an age keyed on it resets to zero on every `reindex --all` and a spool that
/// outlived its hard stop would never once report that it had. The spool file is the authority on
/// what is held, and the record inside it carries the only clock a rebuild cannot move.
///
/// Lives here rather than in [`crate::health`] because it is the same argument as the rest of this
/// module: a derived figure that a rebuild resets is a figure that certifies nothing.
pub(crate) fn quarantine_age(pipeline: &Pipeline) -> Result<(Option<i64>, usize)> {
    let now = fsutil::now_ms();
    let mut oldest: Option<i64> = None;
    let mut undated = 0;
    for path in fsutil::walk_files(
        &pipeline.paths().root.join(layout::QUARANTINE_DIR),
        layout::RECORD_EXT,
    )? {
        let stamped = fs::read_to_string(&path)
            .ok()
            .and_then(|text| yaam_md::Document::parse(&text).ok())
            .and_then(|document| layout::stamp(&document.record.received_at).map(|stamp| stamp.ms));
        match stamped {
            Some(ms) => {
                let age = now - ms;
                oldest = Some(oldest.map_or(age, |seen: i64| seen.max(age)));
            }
            // A held record whose own stamp cannot be read has no clock at all, so it can never age
            // out and no threshold will ever fire for it. Counted separately rather than folded into
            // the oldest age, because "held too long" and "held with nothing saying since when" are
            // different files to go and look at.
            None => undated += 1,
        }
    }
    Ok((oldest, undated))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use yaam_crypto::keystore::KeyStore as _;
    use yaam_md::{Body, Document};

    use super::{
        Attestation, KEY_BACKUP_WINDOW_MS, attestation, reconcile, restore_key_store,
        resurrected_keys,
    };
    use crate::testkit::{self, BODY, Harness};
    use crate::{erase, layout, unseal};

    /// Copies a directory tree verbatim, empty directories included.
    ///
    /// Not [`super::copy_into`]: that is the routine under test, and a fixture built out of it would
    /// pass whatever it did.
    fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
        fs::create_dir_all(to).expect("dir");
        for entry in fs::read_dir(from).expect("read") {
            let entry = entry.expect("entry");
            let target = to.join(entry.file_name());
            if entry.file_type().expect("type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).expect("copy");
            }
        }
    }

    /// A store's whole key root, copied aside the way an operator's bounded-window copy is taken.
    fn copy_key_store(harness: &Harness, into: &std::path::Path) {
        copy_tree(&harness.pipeline.paths().key_store.clone(), into);
    }

    /// The rehearsal's own scenario, and the one that measured plaintext coming back.
    ///
    /// A tree restored from a pre-erasure backup, a key store restored from a pre-erasure copy, and
    /// the erased body must not be readable afterwards. Written so that it fails if the protection
    /// is removed: the assertion is on the body, through the only command that can read one.
    #[test]
    fn a_pre_erasure_key_store_recovered_beside_a_post_erasure_tree_reads_nothing_back() {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        let record =
            testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject));
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        // The key-store copy the deployment's bounded window keeps, taken before the erasure.
        let stash = tempfile::TempDir::new().expect("stash");
        copy_key_store(&harness, stash.path());

        erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert_eq!(
            resurrected_keys(&harness.pipeline).expect("count"),
            0,
            "an erasure leaves no key standing"
        );

        // Disaster recovery: the key store is gone and the copy is the only one there is.
        let key_root = harness.pipeline.paths().key_store.clone();
        fs::remove_dir_all(&key_root).expect("the key disk failed");
        let report = restore_key_store(&mut harness.pipeline, stash.path()).expect("restored");

        assert!(report.files > 0, "the copy carried the key: {report:?}");
        assert_eq!(
            report.reconciled.subjects_resurrected, 1,
            "the copy predates the erasure, so exactly one subject came back: {report:?}"
        );
        assert_eq!(report.reconciled.keys_destroyed, 1);
        assert!(report.reconciled.undid_something());
        assert_eq!(
            resurrected_keys(&harness.pipeline).expect("count"),
            0,
            "and nothing is left standing"
        );

        // The measurement that matters, made the way the rehearsal made it.
        let read = unseal::read_body(
            &mut harness.pipeline,
            &id,
            "operator",
            "the restored store must not answer this",
        )
        .expect("a refusal, not a failure");
        assert!(
            matches!(read, unseal::Read::Shredded { .. }),
            "the erased body came back after a key-store recovery: {read:?}"
        );
        let text = fs::read_to_string(harness.root().join(published(&harness, &id)))
            .expect("the record file");
        assert!(
            !text.contains(BODY),
            "the plaintext is in the tree after a recovery"
        );
    }

    /// Where the record ended up, so the file can be read back.
    fn published(harness: &Harness, id: &yaam_contract::RecordId) -> std::path::PathBuf {
        for path in crate::fsutil::walk_files(
            &harness.root().join(layout::RECORDS_DIR),
            layout::RECORD_EXT,
        )
        .expect("walk")
        {
            if path.to_string_lossy().contains(id.as_str()) {
                return path;
            }
        }
        panic!("no file for {}", id.as_str());
    }

    /// The half of the union the tree's log cannot supply: a key copy that knows about an erasure a
    /// restored tree has never heard of.
    #[test]
    fn the_key_stores_own_blocklist_is_an_authority_the_log_is_not() {
        let mut harness = Harness::new();
        let subject = testkit::subject('b');
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject)),
                BODY,
            )
            .expect("accepted");

        // A marker with no log line behind it: a key store recovered from after an erasure, beside a
        // tree recovered from before it.
        harness.pipeline.keys().tombstone(&subject).expect("marked");
        assert!(
            erase::read_log(&harness.pipeline).expect("log").is_empty(),
            "the tree knows nothing about this erasure"
        );
        assert_eq!(resurrected_keys(&harness.pipeline).expect("count"), 1);

        let report = reconcile(&harness.pipeline).expect("reconciled");
        assert_eq!(report.subjects_erased, 1);
        assert_eq!(report.subjects_resurrected, 1);
        assert_eq!(report.keys_destroyed, 1);
        assert_eq!(resurrected_keys(&harness.pipeline).expect("count"), 0);
    }

    /// The other half: a log line whose blocklist marker did not travel. Re-tombstoning is what
    /// stops the next record minting a fresh key for a subject already erased.
    #[test]
    fn a_recovered_key_store_missing_its_blocklist_gets_one_back() {
        let mut harness = Harness::new();
        let subject = testkit::subject('c');
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject)),
                BODY,
            )
            .expect("accepted");
        erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");

        // A recovery that put the keys back and the markers not: the shape a hand copy of
        // `keys/` alone leaves behind, over a key root the store itself has laid out.
        let markers = harness.pipeline.paths().key_store.join("tombstones");
        for entry in fs::read_dir(&markers).expect("markers") {
            fs::remove_file(entry.expect("entry").path()).expect("marker gone");
        }
        assert!(
            !harness
                .pipeline
                .keys()
                .is_tombstoned(&subject)
                .expect("asked"),
            "the blocklist really is gone"
        );

        let report = reconcile(&harness.pipeline).expect("reconciled");
        assert_eq!(report.blocklist_restored, 1);
        assert!(
            harness
                .pipeline
                .keys()
                .is_tombstoned(&subject)
                .expect("asked"),
            "and a late record can no longer mint a key"
        );
    }

    /// Nothing to walk back is the ordinary answer, and it has to be cheap and silent.
    #[test]
    fn a_store_with_no_erasures_reconciles_to_zeroes() {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");

        let report = reconcile(&harness.pipeline).expect("reconciled");
        assert_eq!(report, super::Reconciliation::default());
        assert!(!report.undid_something());
    }

    /// Refusals: a source that is not a key store, and a destination that already holds one.
    #[test]
    fn a_key_store_restore_refuses_a_wrong_source_and_a_merge() {
        let mut harness = Harness::new();
        let elsewhere = tempfile::TempDir::new().expect("dir");
        let error = restore_key_store(&mut harness.pipeline, elsewhere.path())
            .expect_err("not a key store");
        assert!(
            error.to_string().contains("not a copy of a key store"),
            "{error}"
        );

        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", &[testkit::subject('d')]),
                BODY,
            )
            .expect("accepted");
        let stash = tempfile::TempDir::new().expect("stash");
        copy_key_store(&harness, stash.path());
        let error =
            restore_key_store(&mut harness.pipeline, stash.path()).expect_err("would merge");
        assert!(error.to_string().contains("not a merge"), "{error}");
    }

    /// The three conditions, told apart. This is what one `false` was hiding.
    #[test]
    fn an_attestation_names_which_of_the_three_conditions_is_not_yet() {
        let mut harness = Harness::new();
        let subject = testkit::subject('e');
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject)),
                BODY,
            )
            .expect("accepted");
        let stash = tempfile::TempDir::new().expect("stash");
        copy_key_store(&harness, stash.path());

        let report = erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");
        let young = attestation(&harness.pipeline, &report.tombstone_id).expect("attested");
        assert!(
            young.settled(),
            "the live half holds immediately: {young:?}"
        );
        assert!(!young.window_passed(), "and the window has not: {young:?}");
        assert!(!young.complete());
        assert!(young.remaining_ms() > 0);
        assert_eq!(
            young.window_closes_ms - young.ordered_ms,
            KEY_BACKUP_WINDOW_MS
        );

        // Now the other condition, which the same "not yet" used to stand for: a key put back by
        // hand, with nothing run over it.
        let key_root = harness.pipeline.paths().key_store.clone();
        copy_tree(&stash.path().join("keys"), &key_root.join("keys"));
        assert_eq!(
            harness
                .pipeline
                .keys()
                .key_files_for(&subject)
                .expect("counted"),
            1,
            "the copy carried a key back"
        );

        let broken = attestation(&harness.pipeline, &report.tombstone_id).expect("attested");
        assert_eq!(broken.keys_present, 1);
        assert!(
            !broken.settled(),
            "a key came back, and that is not a wait: {broken:?}"
        );
        assert!(
            broken.tombstoned,
            "the blocklist is untouched by a copied key file"
        );
        assert_eq!(resurrected_keys(&harness.pipeline).expect("count"), 1);
    }

    /// The age of the spool comes from the record and not from the register, so a rebuild cannot
    /// reset it. This is the trap: `first_seen_ms` is a wall-clock read and a rebuild re-registers
    /// the table.
    #[test]
    fn the_quarantine_age_survives_a_rebuild() {
        let mut harness = Harness::new().resolving_with(testkit::UnavailableLookup);
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-23T12:00:00Z", &[testkit::subject('f')]),
                BODY,
            )
            .expect("quarantined");

        let (before, undated) = super::quarantine_age(&harness.pipeline).expect("age");
        assert_eq!(undated, 0);
        let before = before.expect("a held record has an age");
        assert!(
            before > 0,
            "the record's own stamp is in the past: {before}"
        );

        crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        let (after, _) = super::quarantine_age(&harness.pipeline).expect("age");
        let after = after.expect("still held");
        assert!(
            after >= before,
            "a rebuild reset the clock: {before} became {after}"
        );
    }

    /// A held record whose own stamp will not read is counted apart, because no threshold can ever
    /// fire for it.
    #[test]
    fn a_held_record_with_no_readable_stamp_is_counted_on_its_own() {
        let harness = Harness::new();
        let spool = harness.root().join(layout::QUARANTINE_DIR);
        fs::create_dir_all(&spool).expect("spool");
        let mut record = testkit::internal("2026-08-23T12:00:00Z");
        record.received_at = "whenever".to_owned();
        let document = Document {
            record,
            body: Body::Plain(String::new()),
        };
        fs::write(spool.join("undated.md"), document.render()).expect("written");

        let (oldest, undated) = super::quarantine_age(&harness.pipeline).expect("age");
        assert_eq!(oldest, None);
        assert_eq!(undated, 1);
    }

    /// The two counts an operator reads side by side must be counted by one rule. `erase`'s preview
    /// reports what its own verification counts; the key store reports what a reconcile acts on, and
    /// a store with a copy nested under its key root is where a narrower rule would differ.
    #[test]
    fn the_key_count_agrees_with_the_one_an_erasure_previews() {
        let mut harness = Harness::new();
        let subject = testkit::subject('9');
        harness
            .pipeline
            .accept(
                testkit::subject_derived("2026-08-20T09:00:00Z", std::slice::from_ref(&subject)),
                BODY,
            )
            .expect("accepted");

        // A copy kept *inside* the key root, which is the deployment habit the broad rule exists
        // for. Staged outside first, because copying a directory into itself does not terminate.
        let stash = tempfile::TempDir::new().expect("stash");
        copy_key_store(&harness, stash.path());
        let nested = harness.pipeline.paths().key_store.join("yesterday");
        fs::create_dir_all(&nested).expect("nested");
        let mut moved = 0;
        super::copy_into(&stash.path().join("keys"), &nested.join("keys"), &mut moved)
            .expect("staged copy");
        assert_eq!(moved, 1, "the copy carries the one key there is");

        let previewed = erase::preview(&harness.pipeline, &subject)
            .expect("preview")
            .keys;
        let counted = harness
            .pipeline
            .keys()
            .key_files_for(&subject)
            .expect("counted");
        assert_eq!(previewed, counted, "two rules for one figure");
        assert_eq!(counted, 2, "the live key and the copy beside it");
    }

    /// The merge refusal has to hold over a *wrapped* key store, which is the production shape: the
    /// count is read from the files on disk, so it does not depend on this process being able to
    /// open them.
    #[test]
    fn the_merge_refusal_holds_over_a_wrapped_key_store() {
        let wrapper = yaam_crypto::wrapper::PassphraseWrapper::with_salt(
            b"a passphrase",
            [7u8; 16],
            yaam_crypto::wrapper::Cost {
                memory_kib: 8,
                passes: 1,
                lanes: 1,
            },
        )
        .expect("wrapper");
        let mut harness = Harness::new().wrapping_keys_with(wrapper);
        harness
            .pipeline
            .accept(
                testkit::subject_derived(
                    "2026-08-20T09:00:00Z",
                    std::slice::from_ref(&testkit::subject('7')),
                ),
                BODY,
            )
            .expect("accepted");

        let stash = tempfile::TempDir::new().expect("stash");
        copy_key_store(&harness, stash.path());
        let error =
            restore_key_store(&mut harness.pipeline, stash.path()).expect_err("would merge");
        assert!(error.to_string().contains("not a merge"), "{error}");
    }

    /// A blocklist marker whose name is not a pseudonym is a subject whose keys a reconcile would
    /// silently leave standing. It fails loudly instead.
    #[test]
    fn a_blocklist_marker_that_is_not_a_pseudonym_is_refused() {
        let harness = Harness::new();
        let markers = harness.pipeline.paths().key_store.join("tombstones");
        fs::create_dir_all(&markers).expect("markers");
        fs::write(markers.join("not-a-hash"), "").expect("marker");

        let error = reconcile(&harness.pipeline).expect_err("unreadable blocklist");
        assert!(
            error.to_string().contains("not a subject pseudonym"),
            "{error}"
        );
    }

    /// A copy carrying only the blocklist is still a key store: a key root that has erased
    /// everything it ever held has no `keys/` left to copy.
    #[test]
    fn a_copy_carrying_only_a_blocklist_previews_and_installs() {
        let mut harness = Harness::new();
        let subject = testkit::subject('4');
        let stash = tempfile::TempDir::new().expect("stash");
        fs::create_dir_all(stash.path().join("tombstones")).expect("dir");
        fs::write(stash.path().join("tombstones").join(subject.as_str()), "").expect("marker");

        let preview = super::preview_key_store(&harness.pipeline, stash.path()).expect("preview");
        assert_eq!(preview.key_files, 0);
        assert_eq!(preview.markers, 1);
        assert_eq!(preview.blocked_here, 0);
        assert_eq!(preview.newest_erasure_ms, None, "no log line names it");
        assert!(preview.logged.is_empty());

        let report = restore_key_store(&mut harness.pipeline, stash.path()).expect("restored");
        assert_eq!(report.markers, 1);
        assert_eq!(report.files, 0);
        assert!(
            report.all_attested(),
            "an empty log attests vacuously: {report:?}"
        );
        assert!(
            harness
                .pipeline
                .keys()
                .is_tombstoned(&subject)
                .expect("asked"),
            "the copy's blocklist is now this store's"
        );
    }

    /// A preview names every erasure the tree records and the newest of them, which is the date the
    /// confirmation turns on.
    #[test]
    fn a_preview_names_every_erasure_and_the_newest_of_them() {
        let mut harness = Harness::new();
        for fill in ['5', '6'] {
            let subject = testkit::subject(fill);
            harness
                .pipeline
                .accept(
                    testkit::subject_derived(
                        "2026-08-20T09:00:00Z",
                        std::slice::from_ref(&subject),
                    ),
                    BODY,
                )
                .expect("accepted");
            erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");
        }
        let stash = tempfile::TempDir::new().expect("stash");
        fs::create_dir_all(stash.path().join("keys")).expect("dir");

        let preview = super::preview_key_store(&harness.pipeline, stash.path()).expect("preview");
        assert_eq!(preview.logged.len(), 2);
        assert_eq!(preview.blocked_here, 2);
        let newest = preview.newest_erasure_ms.expect("a date");
        assert!(
            preview.logged.iter().all(|(_, at)| *at <= newest),
            "the newest is the newest: {preview:?}"
        );

        let standings = super::attestations(&harness.pipeline).expect("attested");
        assert_eq!(standings.len(), 2);
        assert!(standings.iter().all(|(_, a)| a.settled() && !a.complete()));
    }

    /// An attestation that names no tombstone is a failure and not an empty answer.
    #[test]
    fn an_unknown_tombstone_is_refused() {
        let harness = Harness::new();
        let error = attestation(&harness.pipeline, "tomb-nothing").expect_err("unknown");
        assert!(error.to_string().contains("no tombstone"), "{error}");
    }

    /// Held to `Attestation`'s own arithmetic rather than to a clock.
    #[test]
    fn a_stamped_tombstone_is_complete_whatever_the_window_says() {
        let stamped = Attestation {
            keys_present: 0,
            tombstoned: true,
            ordered_ms: 0,
            window_closes_ms: i64::MAX,
            now_ms: 0,
            stamped: true,
        };
        assert!(stamped.complete());
        assert!(
            !Attestation {
                stamped: false,
                ..stamped
            }
            .complete()
        );
    }
}
