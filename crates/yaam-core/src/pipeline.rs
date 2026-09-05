//! The write path.
//!
//! Ordering is deliberate: the file is published *before* the index row is written, so the tree
//! stays authoritative and the index is a follower. Staging is fsynced — file *and* directory —
//! before the caller is told the write succeeded, which is where the durability promise begins.
//!
//! The five steps, and what each one owes the caller:
//!
//! 0. **Dedupe** on the published path. A record already in the tree changes nothing.
//! 1. **Validate** before any I/O, then seal if the record is subject-derived.
//! 2. **Stage** to `.staging/<id>.md` and fsync the file *and* its directory. Only now is the write
//!    durable, and only now may the caller be told it succeeded.
//! 3. **Publish**: rename into the dated tree, fsync the destination directory, then commit the
//!    index row. Fan-out is enqueued inside that same transaction.
//! 4. **Fan-out**, drained separately, idempotent, dead-lettered after repeated failure.
//!
//! Each boundary between steps is a crash window, and each has a defined winner: an unpublished
//! staging file loses to a later write of the same record, and a published file always beats the
//! index, which the sweeper then catches up.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use yaam_contract::attrs::Schema;
use yaam_contract::entity::Registry;
use yaam_contract::{ActionRecord, DataClass, RecordId, SubjectHash, SubjectRef};
use yaam_crypto::keystore::{FsKeyStore, KeyMaterial, KeyStore as _, KeyWrapper};
use yaam_crypto::{Epoch, SealedBody};
use yaam_md::{Body, Document};
use yaam_store::{FanoutJob, PublishInput, Store, Writer};

#[cfg(feature = "crash-points")]
use crate::crash;
use crate::fsutil;
use crate::layout::{self, Stamp};
use crate::paths::Paths;
use crate::policy::Redaction;
use crate::resolve::{DeclaredSubjects, Resolution, SubjectResolver};
use crate::subject_writes::SubjectWrites;
use crate::{Error, Result};

/// Claims of one fan-out job before it is set aside.
///
/// Counted across drains, not within one: a failed job goes back to the queue with a delay, so the
/// budget buys five separated attempts rather than five in the same second. Five because the
/// failures worth waiting out — a directory that is briefly unwritable, a record file a replica has
/// not caught up with — are gone within the backoff below, and a job that survives all five is not
/// waiting on a moment.
const FANOUT_MAX_ATTEMPTS: u32 = 5;

/// Delay before a job's first retry. Doubles per attempt.
const FANOUT_BACKOFF_MS: i64 = 1_000;

/// How long a job that failed again may be pushed out.
///
/// A ceiling rather than unbounded doubling: the point of backoff is to stop hammering something
/// that is broken, not to park work for so long that nobody sees it fail.
const FANOUT_BACKOFF_CAP_MS: i64 = 60_000;

/// Fan-out work every published record needs: the entity timelines a bundle reads.
const JOB_BUNDLE: &str = "bundle";

/// Fan-out work only records naming subjects need: the audit record of that naming.
const JOB_SUBJECT_LINK: &str = "subject_link";

/// Live head of an entity's timeline.
const TIMELINE_HEAD: &str = "timeline.md";

/// Prefix of a frozen timeline part.
const TIMELINE_PART: &str = "timeline-";

/// Size at which a timeline head is frozen and a fresh one started.
///
/// Bounded so a busy entity's timeline stays a set of files a reader can open rather than one that
/// grows with its whole history. It used to bound the idempotency check too, which is what made
/// that check wrong; the index answers it now, so this size is a readability choice again.
const TIMELINE_MAX_BYTES: u64 = 64 * 1024;

/// Outcome of accepting a record.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Stored. First time this identifier was seen.
    Stored(RecordId),
    /// Already present; nothing changed. Replays are expected and harmless.
    Duplicate(RecordId),
    /// Held pending subject resolution, unpublished and unindexed.
    Quarantined(RecordId),
}

/// The write pipeline.
pub struct Pipeline {
    /// Where the tree, the index and the key store are.
    paths: Paths,
    /// The single index writer. Owning it is what serialises writes.
    writer: Writer,
    /// Custody of per-subject keys.
    keys: FsKeyStore,
    /// How a record's subjects are determined. Declared-as-sent unless a deployment replaces it.
    resolver: Box<dyn SubjectResolver>,
    /// Whether this store accepts subject-derived records at all.
    ///
    /// Read from the tree at open, like every other `spec/` answer, and held here rather than
    /// handed in by whoever built the pipeline. That is the point of it: there is no constructor,
    /// no builder and no flag that produces a pipeline without this, so no caller can be the one
    /// that forgot to ask.
    subject_writes: SubjectWrites,
    /// Configured entity kinds, for canonicalising identifiers.
    registry: Registry,
    /// Configured attribute surface.
    attrs: Schema,
    /// Configured redaction policy.
    redaction: Redaction,
}

/// Written by hand because the resolver is a trait object: demanding `Debug` of every deployment's
/// subject lookup would be a real constraint bought for a derive.
impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl Pipeline {
    /// Builds a pipeline over a memory tree, creating the layout if it is absent.
    ///
    /// Configuration is read from `<root>/spec/`, which is why the root is the only argument: a
    /// store is then a single directory to move, back up or hand to another implementation. A spec
    /// file that is absent declares nothing, and this fails closed — an unconfigured entity kind or
    /// attribute key is rejected rather than admitted unchecked. The one exception is the redaction
    /// policy, where "nothing declared" can only mean nothing to check; both cases are logged.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        Self::with_paths(Paths::under(root))
    }

    /// The same pipeline over paths the deployment chose itself.
    ///
    /// What [`Pipeline::new`] delegates to. Every path a running deployment touches comes from the
    /// one [`Paths`] it was given — writer, reader and the erasure verifier alike — so a relocated
    /// index or key store is relocated for all of them at once. Naming an index here and deriving it
    /// from the root anywhere else is how a service ends up reading a file nothing writes.
    pub fn with_paths(paths: Paths) -> Result<Self> {
        for dir in [
            layout::RECORDS_DIR,
            layout::ENTITIES_DIR,
            layout::AUDIT_DIR,
            layout::COLD_DIR,
            layout::STAGING_DIR,
            layout::QUARANTINE_DIR,
            layout::DEAD_LETTER_DIR,
        ] {
            fs::create_dir_all(paths.root.join(dir))?;
        }
        // The index may sit outside the tree, in which case nothing above has made its directory.
        if let Some(parent) = paths.index.parent() {
            fs::create_dir_all(parent)?;
        }
        let spec = paths.root.join(layout::SPEC_DIR);
        Ok(Self {
            keys: FsKeyStore::unwrapped(&paths.key_store)?,
            resolver: Box::new(DeclaredSubjects),
            subject_writes: SubjectWrites::load(&paths.root)?,
            writer: Writer::open(&paths.index)?,
            registry: load_registry(&spec.join("entities.yaml"))?,
            attrs: load_attrs(&spec.join("attrs-schema.yaml"))?,
            redaction: Redaction::load(&spec.join("redaction/default.yaml"))?,
            paths,
        })
    }

    /// Wraps key material with `wrapper` instead of writing it in the clear.
    ///
    /// Set this before the first record is written. A key already on disk was wrapped by whatever
    /// was in force when it was written, so changing the wrapper over live key material makes those
    /// keys unreadable rather than migrating them.
    pub fn with_key_wrapper(mut self, wrapper: impl KeyWrapper + 'static) -> Result<Self> {
        self.keys = FsKeyStore::new(&self.paths.key_store, wrapper)?;
        Ok(self)
    }

    /// Determines a record's subjects with `resolver` instead of trusting the ones it declares.
    ///
    /// [`crate::resolve::DeclaredSubjects`] is the default, so a deployment adopts this only if it
    /// has a lookup to plug in.
    #[must_use]
    pub fn with_subject_resolver(mut self, resolver: impl SubjectResolver + 'static) -> Self {
        self.resolver = Box::new(resolver);
        self
    }

    /// Runs a record through dedupe, validation, resolution, sealing, staging and publish.
    ///
    /// Replay-safe end to end. A record whose identifier is already in the tree returns
    /// [`Accepted::Duplicate`] and touches nothing, which is what makes a retry, a spool replay and
    /// a sweep re-drive all safe to run against the same record at the same time.
    pub fn accept(&mut self, record: ActionRecord, body: &str) -> Result<Accepted> {
        let id = record.record_id.clone();
        // The stamp comes first because the published path is derived from it, and step 0 needs the
        // path. An unreadable timestamp is a permanent fault either way.
        let stamp = layout::stamp_of(&record)?;

        if self.published_path(&record, &stamp)?.exists() {
            return Ok(Accepted::Duplicate(id));
        }

        let mut record = self.validated(record, body)?;
        let (subjects, sealed) = match self.resolve_and_seal(&record, &stamp, body) {
            Ok(resolved) => resolved,
            Err(Error::SubjectUnresolved) => {
                self.quarantine(&record, &stamp, body)?;
                return Ok(Accepted::Quarantined(id));
            }
            Err(other) => return Err(other),
        };
        // The resolver's answer is the record's subject set from here on: the frontmatter, the
        // wrapped shares that reach the index and the audit record all have to agree with what the
        // body was sealed under.
        record.subjects = subjects;

        let document = Document {
            record,
            body: sealed,
        };
        let staged = self.stage(&document)?;
        // Two of the three windows a crash test stops a real process in. Inert unless armed.
        #[cfg(feature = "crash-points")]
        crash::checkpoint(crash::STAGED);
        self.place(&document, &staged, &stamp)?;
        self.commit(&document)?;
        self.settle_quarantine(&id)?;
        #[cfg(feature = "crash-points")]
        crash::checkpoint(crash::COMMITTED);
        Ok(Accepted::Stored(id))
    }

    /// Drains queued fan-out work: entity timelines and audit records.
    ///
    /// Every handler is idempotent, because a drain that crashed after doing the work and before
    /// marking it done will run again.
    ///
    /// A job that fails goes back to the queue with a delay, not into the dead-letter directory: the
    /// failures worth retrying — an unwritable directory, a record file this process cannot yet see
    /// — are the ones a delay outlasts, and a retry in the same drain would spend the budget on the
    /// same instant. Only after [`FANOUT_MAX_ATTEMPTS`] claims is a job written to `.dead-letter/`
    /// and completed, so it stops holding a place in the queue and stays visible to an operator.
    ///
    /// Returns how many jobs it settled — completed or dead-lettered. A job put back for later is
    /// not one of them: the caller asked what the queue got through, and that work is still owed.
    ///
    /// Fan-out is derived, so nothing here is lost for good: [`crate::reindex::reindex_all`]
    /// re-enqueues every job from the tree — and from the cold manifests, which is why a job whose
    /// record has been archived has to be doable. A rebuild removes the timelines it is about to
    /// rebuild, so a drain that could only read the tree would lose an archived record's line for
    /// good instead of merely delaying it.
    pub fn drain_fanout(&mut self, max_jobs: usize) -> Result<usize> {
        let limit = u32::try_from(max_jobs).unwrap_or(u32::MAX);
        if limit == 0 {
            return Ok(0);
        }
        let now = fsutil::now_ms();
        let jobs = self.writer.claim_fanout(limit, now)?;
        if jobs.is_empty() {
            return Ok(0);
        }

        let located = self.locate_records()?;
        let archived = self.locate_archived(&jobs, &located)?;
        let mut settled = 0;
        for job in jobs {
            let Err(reason) = self.run_job(&job, &located, &archived) else {
                self.writer.complete_fanout(job.id)?;
                settled += 1;
                continue;
            };
            if job.attempts >= FANOUT_MAX_ATTEMPTS {
                self.dead_letter(&job, &reason.to_string())?;
                self.writer.complete_fanout(job.id)?;
                settled += 1;
                continue;
            }
            let delay = backoff_ms(job.attempts);
            tracing::warn!(
                record = job.record.as_str(),
                kind = %job.kind,
                attempts = job.attempts,
                delay,
                error = %reason,
                "fan-out failed; queued for a later drain"
            );
            self.writer.fail_fanout(job.id, now + delay)?;
        }
        Ok(settled)
    }

    /// The entity kinds this deployment configured.
    ///
    /// Public because the read paths need the same canonicalisation the write path applies: an
    /// identifier matched as sent against an index of canonical ones answers nothing, and "nothing"
    /// is indistinguishable from "no history".
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Whether this store accepts subject-derived records.
    ///
    /// Public so a startup log can state the posture it came up under. What it is *not* is a way to
    /// ask before writing: the refusal is in [`Pipeline::accept`] precisely so that no caller has to
    /// remember to check, and a caller that branches on this answer has reintroduced the gap.
    #[must_use]
    pub fn subject_writes(&self) -> SubjectWrites {
        self.subject_writes
    }

    /// The paths this pipeline works over.
    ///
    /// Public because the operations built on a pipeline need the same three paths it uses — an
    /// erasure verifier looking for keys somewhere else would attest to a destruction it never
    /// checked.
    #[must_use]
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Root of the memory tree.
    pub(crate) fn root(&self) -> &Path {
        &self.paths.root
    }

    /// The index writer, for the operations that rebuild derived rows.
    pub(crate) fn writer_mut(&mut self) -> &mut Writer {
        &mut self.writer
    }

    /// What the key material in this pipeline's key store says about its own protection.
    ///
    /// Read off the disk, so the answer does not depend on this process holding the passphrase.
    /// Asking the wrapper instead answers a different question — what the *next* key will be written
    /// under — and a report that confused the two called a wrapped store development-only whenever
    /// the operator reading it passed no passphrase.
    pub fn key_material(&self) -> Result<KeyMaterial> {
        Ok(self.keys.key_material()?)
    }

    /// Whether the wrapper this pipeline holds protects the key material it writes.
    ///
    /// About this process, not about the store — [`Pipeline::key_material`] is that question. What
    /// this one answers is what a store holding no key material yet is about to become.
    #[must_use]
    pub fn key_wrapper_protects(&self) -> bool {
        self.keys.wrapper_protects()
    }

    /// How the wrapper this pipeline holds would protect a key it writes.
    #[must_use]
    pub fn key_wrapper_scheme(&self) -> &'static str {
        self.keys.wrapper_scheme()
    }

    /// Custody of the subject keys.
    pub(crate) fn keys(&self) -> &FsKeyStore {
        &self.keys
    }

    /// The redaction policy every record written here must declare.
    ///
    /// Read off the loaded policy rather than spelled by the caller: a record this crate builds for
    /// itself — an audit record, say — has to name the policy in force in *this* store, and a
    /// constant here would refuse the write on every deployment that configured a different one.
    pub(crate) fn redaction_policy(&self) -> &str {
        self.redaction.name()
    }

    /// Opens a read handle onto the index.
    ///
    /// A second connection rather than a shared one: reads must not be able to migrate the schema,
    /// and the write handle stays the single owner of every mutation.
    pub(crate) fn reader(&self) -> Result<Store> {
        Ok(Store::open_read(&self.paths.index)?)
    }

    /// Where a record belongs in the tree.
    ///
    /// Derived from the record, not from its identifier alone: an owner-visible record is stored
    /// apart, so its visibility and its owner are part of the answer.
    pub(crate) fn published_path(&self, record: &ActionRecord, stamp: &Stamp) -> Result<PathBuf> {
        Ok(self
            .paths
            .root
            .join(layout::record_relative(record, stamp)?))
    }

    /// Step 1: everything that must hold before any byte is written.
    ///
    /// Checked here rather than at the index: a contract failure the caller can fix must arrive
    /// before a partially written record exists to clean up.
    fn validated(&self, mut record: ActionRecord, body: &str) -> Result<ActionRecord> {
        // First, and before the contract's own rules, because this one is not about the record: it
        // is about whether this store writes records of that class at all. It sits on the accept
        // path and nowhere else, which is the distinction the whole thing turns on. A store that
        // enabled the class, wrote under it, and then turned it off still holds those records, and
        // must still reindex, verify, unseal and erase them — none of which comes through here.
        // Refusing on a rebuild would brick exactly the store that took the decision seriously.
        if record.data_class == DataClass::SubjectDerived && !self.subject_writes.accepts() {
            return Err(invalid(self.subject_writes_refused(&record)));
        }
        record.validate()?;
        layout::stamp(&record.at)
            .ok_or_else(|| invalid(format!("record has an unreadable at `{}`", record.at)))?;
        self.attrs
            .validate_frontmatter(&record.action, &record.attrs)?;

        let outcome = outcome_text(record.outcome);
        if let Some(permitted) = self.attrs.outcomes_for(&record.action)
            && !permitted.iter().any(|allowed| allowed == outcome)
        {
            return Err(invalid(format!(
                "action `{}` does not permit outcome `{outcome}`",
                record.action
            )));
        }

        for entity in &mut record.entities {
            entity.id = self.registry.canonicalise(&entity.kind, &entity.id)?;
        }

        if record.redaction_policy != self.redaction.name() {
            return Err(invalid(format!(
                "record declares redaction policy `{}`, this deployment applies `{}`",
                record.redaction_policy,
                self.redaction.name()
            )));
        }
        if let Some(pattern) = self.redaction.first_match(body) {
            return Err(invalid(format!(
                "body still matches redaction pattern `{pattern}`; the writer must redact first"
            )));
        }

        // The body is the record's prose, so the two must not disagree. A sealed record carries no
        // plaintext summary at all: that copy would be outside the reach of key destruction.
        record.summary = match record.data_class {
            DataClass::Internal => body.to_owned(),
            DataClass::SubjectDerived => String::new(),
        };
        Ok(record)
    }

    /// What a caller is told when this store does not write the class its record declares.
    ///
    /// Three things, in the order a caller needs them: what was refused and that nothing was
    /// written, what to change, and what accepting it would have done. The last one is not
    /// decoration — a caller reading only "rejected" concludes it has found a bug and retries, and
    /// an operator reading only "rejected" reaches for the setting that makes it stop.
    ///
    /// Front-loaded because it is read through a keyhole: the sidecar quotes a bounded prefix of
    /// the service's answer back to the caller, so the refusal and the remedy have to arrive before
    /// the reasoning does.
    fn subject_writes_refused(&self, record: &ActionRecord) -> String {
        format!(
            "subject-derived records are refused by this store, and nothing was written. To accept \
             them, declare `{key}: {enabled}` in spec/{file} ({path}). Accepting record `{id}` \
             would have derived a pseudonym for an entity reference it states and sealed its body \
             under a subject key that cannot be rotated; a store's first subject-derived record \
             cannot be taken back, because there is no re-key, no re-seal and no delete. Until that \
             declaration is made, this record is writable as `data_class: internal`, whose body is \
             stored in plaintext and which names no subject",
            key = SubjectWrites::SPEC_KEY,
            enabled = SubjectWrites::Enabled.as_str(),
            file = SubjectWrites::SPEC_FILE,
            path = self
                .paths
                .root
                .join(layout::SPEC_DIR)
                .join(SubjectWrites::SPEC_FILE)
                .display(),
            id = record.record_id.as_str(),
        )
    }

    /// Step 1, second half: resolve the record's subjects, then seal the body under them.
    ///
    /// One step because the two share a failure: a subject that cannot be resolved *right now* is
    /// [`Error::SubjectUnresolved`], never a rejection, whether the resolver said so or the key
    /// store could not answer. Every shape it takes is transient in the sense that matters — the
    /// record is real and must not be dropped: a lookup that is down will come back, and a
    /// tombstoned subject means the record arrived after an erasure, which
    /// [`crate::erase::erase_subject`] settles rather than the writer losing its history over.
    ///
    /// Returns the resolved subjects alongside the body, because the caller has to write both or
    /// neither.
    fn resolve_and_seal(
        &self,
        record: &ActionRecord,
        stamp: &Stamp,
        body: &str,
    ) -> Result<(Vec<SubjectRef>, Body)> {
        let resolved = match self.resolver.resolve(record) {
            Resolution::Resolved(subjects) => subjects,
            Resolution::Unavailable(reason) => {
                tracing::info!(
                    record = record.record_id.as_str(),
                    reason,
                    "subject resolution unavailable"
                );
                return Err(Error::SubjectUnresolved);
            }
            // Rejected rather than held, and this is the branch that must not be confused with the
            // one above: a record the resolver cannot key is a record no retry improves, and a spool
            // file for it would never empty. The reason reaches the caller, because it is the caller
            // who holds the record and can fix what it names.
            Resolution::Refused(reason) => return Err(invalid(reason)),
        };
        check_class(record, &resolved)?;
        let sealed = self.seal_body(record, &resolved, stamp, body)?;
        Ok((resolved, sealed))
    }

    /// Seals the body when the record is subject-derived, under the subjects resolution settled on.
    ///
    /// A subject whose keys have been destroyed is the case that must not be confused with a subject
    /// lookup that is merely down, and it is the same distinction [`Resolution::Refused`] draws on
    /// the resolver side: quarantine is for a condition a retry improves, and an erasure is not one.
    /// Held back as unresolved, such a record would sit in the spool for ever — because resolution
    /// can never succeed — holding a *readable* body, under a live quarantine key, about the one
    /// person who asked for theirs to be gone, until some later erasure run for the same subject
    /// happened to discard it.
    ///
    /// So it is published structure-only instead: the frontmatter still says who and when, the body
    /// is dropped before it reaches disk, and no key is minted for a tombstoned subject. That is the
    /// same shape an erased record already has, which is why nothing downstream needs a new field to
    /// read it — [`crate::unseal::inspect`] reports it as shredded, with the tombstone that accounts
    /// for it, and a later erasure finds nothing left to take.
    fn seal_body(
        &self,
        record: &ActionRecord,
        resolved: &[SubjectRef],
        stamp: &Stamp,
        body: &str,
    ) -> Result<Body> {
        if record.data_class == DataClass::Internal {
            return Ok(Body::Plain(body.to_owned()));
        }
        let subjects: Vec<SubjectHash> = resolved.iter().map(|s| s.hash.clone()).collect();
        if self.tombstoned(&subjects)? {
            tracing::warn!(
                record = record.record_id.as_str(),
                "a subject of this record is erased, so it is published with no body"
            );
            return Ok(Body::Plain(String::new()));
        }
        let epoch = Epoch::containing(stamp.ms);
        match self.seal(&record.record_id, &subjects, &epoch, body) {
            Ok(sealed) => Ok(Body::Sealed(sealed)),
            Err(Error::SubjectUnresolved) => {
                // The question above and the seal are not one operation, so an erasure running in
                // another process can land between them. Asking again is what keeps that window
                // from spooling a body whose key is already gone; a key store that cannot answer
                // the second time leaves the record held, which is where it already was.
                if self.tombstoned(&subjects).unwrap_or(false) {
                    tracing::warn!(
                        record = record.record_id.as_str(),
                        "a subject of this record was erased mid-write, so it is published with no \
                         body"
                    );
                    Ok(Body::Plain(String::new()))
                } else {
                    Err(Error::SubjectUnresolved)
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Whether any of these subjects has been erased.
    ///
    /// A key store that cannot answer is reported as an unresolved subject rather than as "not
    /// erased": the alternative is sealing a body under a key the store was about to refuse.
    fn tombstoned(&self, subjects: &[SubjectHash]) -> Result<bool> {
        for subject in subjects {
            if self
                .keys
                .is_tombstoned(subject)
                .map_err(|_| Error::SubjectUnresolved)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Seals a body, mapping a key store that cannot answer onto quarantine.
    fn seal(
        &self,
        id: &RecordId,
        subjects: &[SubjectHash],
        epoch: &Epoch,
        body: &str,
    ) -> Result<SealedBody> {
        yaam_crypto::seal::seal(&self.keys, id, subjects, epoch, body.as_bytes()).map_err(|error| {
            match error {
                // Key custody could not serve this record. The body is still unwritten, so the only
                // safe outcome is to hold it rather than to reject or to store it in the clear.
                yaam_crypto::Error::Io(_)
                | yaam_crypto::Error::Tombstoned(_)
                | yaam_crypto::Error::KeyAbsent(..) => Error::SubjectUnresolved,
                other => Error::Crypto(other),
            }
        })
    }

    /// Holds a record back, sealed, until its subjects resolve.
    ///
    /// The spool copy is sealed under a *quarantine* key rather than left in the clear, which is the
    /// whole reason this path is not simply "retry later in memory": the record is on disk, so it
    /// has to be as unreadable there as it would be once published.
    ///
    /// That key is modelled as a reserved pseudo-subject, one per date, so quarantine reuses the key
    /// store's own custody, destruction and durability rules instead of introducing a second place
    /// keys can live. The date is the record's own, not a clock read, so a replay lands on the same
    /// key.
    fn quarantine(&mut self, record: &ActionRecord, stamp: &Stamp, body: &str) -> Result<()> {
        let date = stamp.date();
        let subject = quarantine_subject(&date)?;
        let epoch = Epoch::containing(stamp.ms);
        let sealed = self.seal(&record.record_id, &[subject], &epoch, body)?;
        let document = Document {
            record: record.clone(),
            body: Body::Sealed(sealed),
        };

        let dir = self.paths.root.join(layout::QUARANTINE_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!(
            "{}.{}",
            record.record_id.as_str(),
            layout::RECORD_EXT
        ));
        fsutil::write_sync(&path, document.render().as_bytes())?;
        fsutil::sync_dir(&dir)?;

        self.writer.enqueue_quarantine(
            record.record_id.as_str(),
            &date,
            &path.to_string_lossy(),
        )?;
        tracing::info!(
            record = record.record_id.as_str(),
            "quarantined pending subject resolution"
        );
        Ok(())
    }

    /// Drops the spooled copy of a record that has now been published, and its register row.
    ///
    /// The re-presentation that resolves a quarantine is an ordinary [`Pipeline::accept`] — a retry,
    /// a spool replay — so this runs on every publish and is a no-op for the records that were never
    /// held.
    ///
    /// The spool file goes first. It is the authority on what is held back, so a crash between the
    /// two leaves a row a rebuild retracts, where the other order would leave a spool file a rebuild
    /// registers again.
    fn settle_quarantine(&mut self, id: &RecordId) -> Result<()> {
        let path = self.paths.root.join(layout::QUARANTINE_DIR).join(format!(
            "{}.{}",
            id.as_str(),
            layout::RECORD_EXT
        ));
        if path.exists() {
            fsutil::remove_if_present(&path)?;
            tracing::info!(record = id.as_str(), "quarantine settled by publish");
        }
        self.writer.dequeue_quarantine(id.as_str())?;
        Ok(())
    }

    /// Step 2: the write-ahead copy, durable before the caller hears anything.
    ///
    /// Both syncs are load-bearing. Without the file sync the bytes may not be on the platter;
    /// without the directory sync the *name* may not be, and a staging file nothing can find is a
    /// record the sweeper will never re-drive.
    pub(crate) fn stage(&self, document: &Document) -> Result<PathBuf> {
        let dir = self.paths.root.join(layout::STAGING_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!(
            "{}.{}",
            document.record.record_id.as_str(),
            layout::RECORD_EXT
        ));
        // Staged under the mode it will be published with, because a rename carries the mode it
        // finds: a copy that spent this window readable was readable, whatever it becomes.
        fsutil::write_sync_mode(
            &path,
            document.render().as_bytes(),
            layout::record_mode(&document.record),
        )?;
        fsutil::sync_dir(&dir)?;
        Ok(path)
    }

    /// Step 3a: rename the staged copy into the dated tree.
    ///
    /// `ENOENT` with the destination present is a *completed* write, not a failure: another pass —
    /// a retry, or the sweeper — already renamed this exact record into place. Treating it as an
    /// error would turn convergence into a permanent alarm.
    pub(crate) fn place(
        &self,
        document: &Document,
        staged: &Path,
        stamp: &Stamp,
    ) -> Result<PathBuf> {
        let destination = self.published_path(&document.record, stamp)?;
        let parent = fsutil::parent_of(&destination)?;
        self.create_record_dirs(&document.record, parent)?;
        match fs::rename(staged, &destination) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound && destination.exists() => {}
            Err(e) => return Err(e.into()),
        }
        fsutil::sync_dir(parent)?;
        Ok(destination)
    }

    /// Creates the directory chain a record's file goes in.
    ///
    /// An owner's subtree is created — and every level of it re-tightened — so only the identity
    /// running the service can traverse it. Re-tightened because a recursive create leaves an
    /// existing directory's mode alone, which would keep a tree restored from a loose backup, or
    /// written by an older build, world-readable for ever.
    fn create_record_dirs(&self, record: &ActionRecord, parent: &Path) -> Result<()> {
        let Some(owner_root) = layout::owner_relative(record)? else {
            fs::create_dir_all(parent)?;
            return Ok(());
        };
        fsutil::create_private_dir_all(parent)?;
        let owner_root = self.paths.root.join(owner_root);
        let mut dir = parent;
        while dir.starts_with(&owner_root) {
            fsutil::make_private(dir)?;
            dir = fsutil::parent_of(dir)?;
        }
        // The loop stops one level short of `records/owner`, and that level is the one that hides
        // which identities have records at all. `records/` itself stays traversable.
        fsutil::make_private(dir)?;
        Ok(())
    }

    /// Step 3b: commit the index row, and the fan-out jobs inside the same transaction.
    ///
    /// Second on purpose. The file is authoritative, so a crash here leaves a published record the
    /// sweeper indexes; the reverse order would leave an index row pointing at nothing.
    pub(crate) fn commit(&mut self, document: &Document) -> Result<()> {
        let mut batch = self.writer.batch()?;
        publish_document(&mut batch, document)?;
        batch.commit()?;
        Ok(())
    }

    /// Every record file in the tree, by identifier.
    ///
    /// A record's path is derived from its timestamp, which a job row does not carry, so the map is
    /// built once per drain rather than searched per job.
    pub(crate) fn locate_records(&self) -> Result<BTreeMap<String, PathBuf>> {
        let mut located = BTreeMap::new();
        for path in fsutil::walk_files(
            &self.paths.root.join(layout::RECORDS_DIR),
            layout::RECORD_EXT,
        )? {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                located.insert(stem.to_owned(), path);
            }
        }
        Ok(located)
    }

    /// The archived records this batch of jobs needs, out of the cold manifests.
    ///
    /// Only the jobs whose record has no file in the tree, and empty — with the manifests unread —
    /// when there are none. A manifest pass costs the size of the archive, so it is made once per
    /// batch, for the same reason [`Pipeline::locate_records`] walks the tree once per drain.
    ///
    /// Records rather than paths: the line has to be parsed to know which record it holds, so
    /// keeping the answer costs one batch's worth of records and saves reading a manifest again.
    ///
    /// The index is not asked, though a rebuild derived a row from the very line this is looking
    /// for. It records no provenance, so it cannot say which manifest to open — and the record it
    /// does hold is derived where the manifest is authoritative. Reading it back would also make
    /// this lookup unable to fail: a job row cannot exist without its record row, so a record
    /// nothing local holds would fan out from the index instead of telling anyone it is gone.
    fn locate_archived(
        &self,
        jobs: &[FanoutJob],
        located: &BTreeMap<String, PathBuf>,
    ) -> Result<BTreeMap<String, ActionRecord>> {
        let wanted: BTreeSet<&str> = jobs
            .iter()
            .map(|job| job.record.as_str())
            .filter(|id| !located.contains_key(*id))
            .collect();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        crate::reindex::cold_records(&self.paths.root, &wanted)
    }

    /// The work one job stands for.
    ///
    /// Both handlers need the record and nothing else, which is what makes an archived record's job
    /// doable at all: its file is gone from the tree, and its manifest line is the same record.
    ///
    /// A record in neither the tree nor a manifest is still `NotFound`, and still reported the way
    /// it was — the caller retries it and then dead-letters it. That is the right shape for both
    /// causes: a file a replica has not caught up with is transient, and a record nothing local
    /// holds is a fault an operator has to see rather than one this can decide is nothing.
    fn run_job(
        &mut self,
        job: &FanoutJob,
        located: &BTreeMap<String, PathBuf>,
        archived: &BTreeMap<String, ActionRecord>,
    ) -> Result<()> {
        let record = match located.get(job.record.as_str()) {
            Some(path) => Document::parse(&fs::read_to_string(path)?)?.record,
            None => archived.get(job.record.as_str()).cloned().ok_or_else(|| {
                Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "record `{}` is not in the tree or a cold manifest",
                        job.record.as_str()
                    ),
                ))
            })?,
        };
        match job.kind.as_str() {
            JOB_BUNDLE => self.append_timelines(&record),
            JOB_SUBJECT_LINK => self.write_subject_audit(&record),
            other => Err(invalid(format!("unknown fan-out job kind `{other}`"))),
        }
    }

    /// Records a job as needing an operator rather than another retry.
    fn dead_letter(&self, job: &FanoutJob, reason: &str) -> Result<()> {
        let dir = self.paths.root.join(layout::DEAD_LETTER_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.{}", job.record.as_str(), job.kind));
        fsutil::write_sync(
            &path,
            format!(
                "record: {}\njob: {}\nattempts: {}\nreason: {reason}\n",
                job.record.as_str(),
                job.kind,
                job.attempts
            )
            .as_bytes(),
        )?;
        fsutil::sync_dir(&dir)?;
        tracing::warn!(record = job.record.as_str(), kind = %job.kind, reason, "fan-out dead-lettered");
        Ok(())
    }

    /// Appends the record to the timeline of every entity it names.
    ///
    /// Idempotent by bookkeeping rather than by inspection: the index holds one row per line, and
    /// the row is claimed in a transaction that commits only once the line is on disk. Inspection
    /// was what this used to do, and it was wrong past a second rollover — the frozen part holding
    /// the line stops being the newest one, and a re-enqueued job appended the same history again.
    ///
    /// A failed append leaves no row, so the job comes back and does the work. The claim's own
    /// documentation carries the rest of the argument, including what a crash inside the commit
    /// leaves behind.
    fn append_timelines(&mut self, record: &ActionRecord) -> Result<()> {
        for entity in &record.entities {
            let dir = self
                .paths
                .root
                .join(layout::ENTITIES_DIR)
                .join(&entity.kind)
                .join(Registry::to_path_segment(&entity.id));
            fs::create_dir_all(&dir)?;
            let head = dir.join(TIMELINE_HEAD);
            if head_is_full(&head)? {
                roll_over(&dir, &head)?;
            }
            // Keyed by the entity as the index knows it, not as the path spells it: the row sits
            // beside `entity_refs`, and the directory name is an encoding of the same identity.
            let Some(mention) = self.writer.claim_timeline_mention(
                record.record_id.as_str(),
                &entity.kind,
                &entity.id,
            )?
            else {
                continue;
            };
            let link = yaam_md::wikilink::render(&yaam_contract::entity::EntityRef {
                kind: "record".to_owned(),
                id: record.record_id.as_str().to_owned(),
                role: entity.role,
                confidence: entity.confidence,
            });
            fsutil::append_line_sync(
                &head,
                &format!(
                    "- {link} {} {}/{}",
                    record.received_at,
                    record.action,
                    outcome_text(record.outcome)
                ),
            )?;
            mention.commit()?;
        }
        Ok(())
    }

    /// Writes the audit record of which subjects a record names.
    ///
    /// One file per record, whose content is a function of the record, so a replay rewrites the same
    /// bytes instead of appending a second account of the same fact. Pseudonyms only: this file
    /// survives erasure, which is exactly why it may not carry anything a key destruction should
    /// have reached.
    fn write_subject_audit(&self, record: &ActionRecord) -> Result<()> {
        if record.subjects.is_empty() {
            return Ok(());
        }
        let dir = self.paths.root.join(layout::AUDIT_DIR).join("subjects");
        fs::create_dir_all(&dir)?;
        let mut text = format!(
            "# subjects named by [[record:{}]]\n\n",
            record.record_id.as_str()
        );
        for subject in &record.subjects {
            let _ = writeln!(
                text,
                "- [[subject:{}]] role={} canon_ver={}",
                subject.hash.as_str(),
                subject_role_text(subject.role),
                subject.canon_ver.0
            );
        }
        let path = dir.join(format!(
            "{}.{}",
            record.record_id.as_str(),
            layout::RECORD_EXT
        ));
        fsutil::write_sync(&path, text.as_bytes())?;
        fsutil::sync_dir(&dir)?;
        Ok(())
    }
}

/// How long a job waits before its next claim, doubling per attempt up to the cap.
fn backoff_ms(attempts: u32) -> i64 {
    let doublings = attempts.saturating_sub(1).min(16);
    FANOUT_BACKOFF_MS
        .saturating_mul(1i64 << doublings)
        .min(FANOUT_BACKOFF_CAP_MS)
}

/// Freezes a full timeline head and starts a fresh one.
///
/// Rename then create, so the frozen part is never a copy of live lines. The window between the two
/// leaves a directory with parts and no head, which [`crate::sweeper::sweep`] repairs.
fn roll_over(dir: &Path, head: &Path) -> Result<()> {
    let part = dir.join(format!("{TIMELINE_PART}{:04}.md", next_part_number(dir)?));
    fs::rename(head, &part)?;
    fsutil::sync_dir(dir)?;
    #[cfg(feature = "crash-points")]
    crash::checkpoint(crash::ROLLED_OVER);
    fsutil::write_sync(head, b"")?;
    fsutil::sync_dir(dir)?;
    Ok(())
}

/// Whether the timeline head has reached its rollover size.
fn head_is_full(head: &Path) -> Result<bool> {
    match fs::metadata(head) {
        Ok(meta) => Ok(meta.len() >= TIMELINE_MAX_BYTES),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The number the next frozen part takes.
fn next_part_number(dir: &Path) -> Result<u32> {
    let mut highest = 0;
    for path in fsutil::walk_files(dir, "md")? {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(digits) = stem.strip_prefix(TIMELINE_PART)
            && let Ok(number) = digits.parse::<u32>()
        {
            highest = highest.max(number);
        }
    }
    Ok(highest + 1)
}

/// Indexes one document into an open transaction.
///
/// The one place a document becomes [`PublishInput`], so a live write and a rebuild cannot disagree
/// about what the index gets — they differ only in how many of these go into one transaction.
pub(crate) fn publish_document(
    batch: &mut yaam_store::Batch<'_>,
    document: &Document,
) -> Result<()> {
    let keys = subject_keys(document);
    batch.publish(PublishInput {
        record: &document.record,
        searchable_body: document.searchable_text(),
        subject_keys: &keys,
    })?;
    Ok(())
}

/// The wrapped shares a publish should carry, taken from the sealed body itself.
///
/// Filtered to the subjects the record names: the index refuses a share for a subject that is not
/// in the frontmatter, and a quarantine copy is sealed under exactly such a pseudo-subject.
fn subject_keys(document: &Document) -> Vec<(SubjectHash, Epoch, Vec<u8>)> {
    let Body::Sealed(sealed) = &document.body else {
        return Vec::new();
    };
    sealed
        .shares
        .iter()
        .filter(|share| {
            document
                .record
                .subjects
                .iter()
                .any(|subject| subject.hash == share.subject)
        })
        .map(|share| {
            (
                share.subject.clone(),
                sealed.epoch.clone(),
                share.bytes.clone(),
            )
        })
        .collect()
}

/// The reserved pseudo-subject whose key wraps a quarantined body for one date.
///
/// Derived from the date rather than random, so the spool file can be opened again from the
/// `qkek_date` the index row keeps and nothing further has to be stored to find the key.
fn quarantine_subject(date: &str) -> Result<SubjectHash> {
    let mut digits = hex::encode(format!("quarantine/{date}"));
    digits.truncate(64);
    while digits.len() < 64 {
        digits.push('0');
    }
    Ok(SubjectHash::parse(&format!("s_{digits}"))?)
}

/// Wire spelling of an outcome, as the contract serialises it.
fn outcome_text(outcome: yaam_contract::Outcome) -> &'static str {
    match outcome {
        yaam_contract::Outcome::Success => "success",
        yaam_contract::Outcome::Failure => "failure",
        yaam_contract::Outcome::Partial => "partial",
        yaam_contract::Outcome::Declined => "declined",
    }
}

/// Wire spelling of a subject role.
fn subject_role_text(role: yaam_contract::Role) -> &'static str {
    match role {
        yaam_contract::Role::Principal => "principal",
        yaam_contract::Role::Party => "party",
    }
}

/// Holds the resolver to the contract rule that ties a record's class to its subjects.
///
/// [`ActionRecord::validate`] already checked what arrived; this checks what resolution *replaced* it
/// with, and the two failures need different words because they have different culprits. Neither is
/// survivable: a subject-derived record with no subjects would be sealed under a key nobody can
/// destroy, and an internal record naming subjects would claim an erasability its plaintext body
/// cannot deliver.
fn check_class(record: &ActionRecord, resolved: &[SubjectRef]) -> Result<()> {
    match record.data_class {
        DataClass::SubjectDerived if resolved.is_empty() => Err(invalid(
            "subject resolution produced no subject for a subject-derived record",
        )),
        DataClass::Internal if !resolved.is_empty() => Err(invalid(format!(
            "subject resolution produced {} subject(s) for an internal record",
            resolved.len()
        ))),
        _ => Ok(()),
    }
}

/// A record the caller must fix.
pub(crate) fn invalid(detail: impl Into<String>) -> Error {
    Error::Invalid(yaam_contract::Error::Invalid(detail.into()))
}

/// Loads the entity registry, or reports a deployment that configured none.
fn load_registry(path: &Path) -> Result<Registry> {
    let Some(text) = fsutil::read_to_string_opt(path)? else {
        tracing::warn!(
            path = %path.display(),
            "no entity kinds configured; records naming entities will be rejected"
        );
        return Ok(Registry::default());
    };
    Ok(Registry::from_yaml(&text)?)
}

/// Loads the attribute schema, or reports a deployment that configured none.
fn load_attrs(path: &Path) -> Result<Schema> {
    let Some(text) = fsutil::read_to_string_opt(path)? else {
        tracing::warn!(
            path = %path.display(),
            "no attribute schema configured; records carrying attrs will be rejected"
        );
        return Ok(Schema::default());
    };
    Ok(Schema::from_yaml(&text)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use yaam_contract::{CanonVer, DataClass, Outcome, Role, SubjectRef, attrs};
    use yaam_crypto::keystore::{KeyStore as _, KeyWrapper};
    use yaam_md::{Body, Document};

    use super::{Accepted, Error, KeyMaterial, Pipeline, quarantine_subject};
    use crate::resolve::{DeclaredSubjects, Resolution, SubjectResolver};
    use crate::testkit::{self, BODY, Harness};

    /// A record's server time, and so the directory it lands in.
    const T09: &str = "2026-08-20T09:14:03.117Z";

    /// A subject lookup driven by a table keyed on the record identifier.
    ///
    /// Stands in for a deployment that decides a record's subjects itself rather than believing what
    /// arrived. An identifier it has never heard of is a lookup it cannot complete, not a record
    /// without subjects.
    struct Mapped(BTreeMap<String, Vec<SubjectRef>>);

    impl SubjectResolver for Mapped {
        fn resolve(&self, record: &yaam_contract::ActionRecord) -> Resolution {
            match self.0.get(record.record_id.as_str()) {
                Some(subjects) => Resolution::Resolved(subjects.clone()),
                None => Resolution::Unavailable("no entry for this record yet".to_owned()),
            }
        }
    }

    /// A lookup that can say the record itself is the problem, which is a different answer from
    /// either "here they are" or "ask me later".
    struct Refuses;

    impl SubjectResolver for Refuses {
        fn resolve(&self, _record: &yaam_contract::ActionRecord) -> Resolution {
            Resolution::Refused("the record names two of them".to_owned())
        }
    }

    /// A lookup that completes and finds nothing, which for a subject-derived record is a bug.
    struct ResolvesToNothing;

    impl SubjectResolver for ResolvesToNothing {
        fn resolve(&self, _record: &yaam_contract::ActionRecord) -> Resolution {
            Resolution::Resolved(Vec::new())
        }
    }

    /// A stand-in for a key service: reversible, and enough to show the wrapper is on the write
    /// path. What a wrapper that *cannot* open a file does is `yaam-crypto`'s test, not this one.
    struct Xor(u8);

    impl KeyWrapper for Xor {
        fn wrap(&self, key: &[u8]) -> yaam_crypto::Result<Vec<u8>> {
            Ok(key.iter().map(|byte| byte ^ self.0).collect())
        }

        fn unwrap(&self, wrapped: &[u8]) -> yaam_crypto::Result<Vec<u8>> {
            self.wrap(wrapped)
        }
    }

    /// A resolver's answer, in the shape a record carries.
    fn subject_ref(fill: char) -> SubjectRef {
        SubjectRef {
            hash: testkit::subject(fill),
            role: Role::Principal,
            canon_ver: CanonVer(1),
        }
    }

    /// One way to break a record, and the name of what it breaks.
    type Case = (&'static str, Box<dyn Fn(&mut yaam_contract::ActionRecord)>);

    /// A resolver that counts every record it was asked about, into a counter its caller keeps.
    ///
    /// What it proves is not that a record was refused but *where*: a pseudonym is derived inside
    /// the resolver, so a refusal that reaches this at all is a refusal that came too late.
    struct Counting(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl SubjectResolver for Counting {
        fn resolve(&self, record: &yaam_contract::ActionRecord) -> Resolution {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Resolution::Resolved(record.subjects.clone())
        }
    }

    /// The default a store cannot drift away from: a record whose class says its body is sealed and
    /// keyed to a subject is refused, and the store is left exactly as it was.
    ///
    /// A store declares no such thing when it ships. What used to happen instead is the whole point
    /// of this test: the record was accepted, a key was minted for a pseudonym under a subject key
    /// that cannot be rotated, and nothing afterwards could take it back.
    #[test]
    fn a_subject_derived_record_is_refused_unless_the_store_declares_the_class() {
        let mut harness = Harness::new().declaring(None);
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);
        let path = harness.path_of(&record);

        let error = harness
            .pipeline
            .accept(record, BODY)
            .expect_err("a store that declared nothing writes no such record");
        assert!(
            matches!(error, Error::Invalid(_)),
            "permanent and the caller's to act on, not a retry: {error}"
        );
        assert!(!path.exists(), "nothing was published");
        assert!(
            fs::read_dir(harness.root().join(".staging"))
                .expect("staging")
                .next()
                .is_none(),
            "and nothing was staged either: the refusal is ahead of every byte"
        );
        assert!(
            fs::read_dir(harness.root().join(".quarantine"))
                .expect("quarantine")
                .next()
                .is_none(),
            "a refusal is not a hold; there is nothing here to re-present"
        );
        assert!(
            matches!(
                harness.pipeline.key_material().expect("readable"),
                KeyMaterial::Absent
            ),
            "no key was minted, which is the thing that could not have been undone"
        );
        assert_eq!(harness.counts()["records"], 0, "and no index row");
    }

    /// The same refusal from the declaration that says so out loud, rather than from an absent file.
    /// An operator who turned the class off has said the same thing as one who never turned it on.
    #[test]
    fn a_declaration_that_refuses_the_class_refuses_it_as_firmly_as_an_absent_one() {
        let mut harness = Harness::new().declaring(Some(testkit::SPEC_WRITES_REFUSED));
        let error = harness
            .pipeline
            .accept(
                testkit::subject_derived(T09, &[testkit::subject('a')]),
                BODY,
            )
            .expect_err("refused");
        assert!(
            error.to_string().contains("refused by this store"),
            "{error}"
        );
    }

    /// A caller that gets a bare rejection assumes a bug and retries. This one is told what was
    /// refused, that nothing was written, what to change, and what accepting it would have done —
    /// the last because "just turn it on" is the wrong reflex for a decision nothing can undo.
    #[test]
    fn the_refusal_says_what_was_refused_what_to_change_and_what_it_would_have_cost() {
        let mut harness = Harness::new().declaring(None);
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);
        let id = record.record_id.clone();
        let said = harness
            .pipeline
            .accept(record, BODY)
            .expect_err("refused")
            .to_string();

        for expected in [
            "subject-derived records are refused by this store",
            "nothing was written",
            "writes: enabled",
            "subject-writes.yaml",
            id.as_str(),
            "cannot be rotated",
            "no re-key, no re-seal and no delete",
            "data_class: internal",
        ] {
            assert!(said.contains(expected), "{expected} missing from: {said}");
        }
        assert!(
            said.contains(harness.root().to_str().expect("utf-8 root")),
            "a host running several stores needs to know which one refused: {said}"
        );
    }

    /// Where the refusal sits, asserted rather than assumed: ahead of resolution, which is where a
    /// pseudonym would have been derived. A refusal downstream of that has already done the one
    /// thing this exists to prevent, and would look identical from the outside.
    #[test]
    fn a_refused_record_never_reaches_the_subject_resolver() {
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let mut harness = Harness::new()
                .declaring(None)
                .resolving_with(Counting(std::sync::Arc::clone(&asked)));
            harness
                .pipeline
                .accept(
                    testkit::subject_derived(T09, &[testkit::subject('a')]),
                    BODY,
                )
                .expect_err("refused");
            assert_eq!(
                asked.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "the resolver derives the pseudonym; it must not have been asked"
            );

            // An internal record on the same store still goes through it, so the count above is the
            // refusal and not a resolver that was never wired up.
            harness
                .pipeline
                .accept(testkit::internal(T09), BODY)
                .expect("accepted");
        }
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// And the declaration is what lets one through: the same record, the same store, one line of
    /// configuration apart.
    #[test]
    fn the_declaration_is_what_lets_a_subject_derived_record_through() {
        let mut harness = Harness::new();
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);
        let path = harness.path_of(&record);
        assert!(matches!(
            harness.pipeline.accept(record, BODY).expect("accepted"),
            Accepted::Stored(_)
        ));

        let parsed = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        assert!(
            matches!(parsed.body, Body::Sealed(_)),
            "enabled means sealed, which is the state the refusal was protecting"
        );
    }

    /// The regression that matters most, and the one a refusal in the wrong layer would cause: a
    /// store that enabled the class, wrote under it, and then stopped still holds those records.
    ///
    /// Every operation over what it already holds has to keep working — the index is derived and
    /// deleting it is a routine remedy, so a rebuild that refused the records in its own tree would
    /// leave the store unqueryable with no way back. Only the accept path refuses.
    #[test]
    fn a_store_that_stops_writing_the_class_still_rebuilds_and_reads_what_it_holds() {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        let stored = testkit::subject_derived(T09, std::slice::from_ref(&subject));
        let id = stored.record_id.clone();
        let path = harness.path_of(&stored);
        harness.pipeline.accept(stored, BODY).expect("accepted");
        harness.pipeline.drain_fanout(16).expect("drained");

        // The decision is taken back.
        let mut harness = harness.declaring(Some(testkit::SPEC_WRITES_REFUSED));
        harness
            .pipeline
            .accept(
                testkit::subject_derived(T09, &[testkit::subject('b')]),
                BODY,
            )
            .expect_err("no new record of the class");

        // A rebuild — from the tree, over records of the class it no longer writes.
        let report = crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(
            report.from_tree, 1,
            "the record it already holds: {report:?}"
        );
        assert_eq!(report.skipped, 0);
        assert_eq!(harness.counts()["records"], 1);
        assert_eq!(harness.counts()["record_subjects"], 1);

        // And from nothing at all, which is what an operator who deletes the index gets.
        let mut harness = harness.without_index();
        assert_eq!(
            crate::reindex::reindex_all(&mut harness.pipeline)
                .expect("rebuilt from an empty index")
                .from_tree,
            1
        );

        // The body still opens, and the erasure that is the whole point of the class still runs.
        let document = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        assert!(matches!(document.body, Body::Sealed(_)));
        crate::unseal::inspect(&harness.pipeline, &id).expect("inspectable");
        let report = crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");
        assert!(
            report.keys_destroyed > 0,
            "the store can still answer an erasure request for what it wrote: {report:?}"
        );
    }

    #[test]
    fn a_record_lands_in_a_dated_path_and_reads_back_unchanged() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let path = harness.path_of(&record);

        let accepted = harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        assert_eq!(accepted, Accepted::Stored(record.record_id.clone()));
        assert!(
            path.ends_with("records/2026/08/20/".to_owned() + record.record_id.as_str() + ".md"),
            "{}",
            path.display()
        );

        let parsed = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        assert_eq!(parsed.searchable_text(), BODY);
        assert_eq!(parsed.record.summary, BODY);
        assert_eq!(parsed.record.attrs, record.attrs);
        assert_eq!(parsed.record.entities, record.entities);
        // The staging copy is a rename source: a successful publish leaves nothing behind.
        assert!(
            fs::read_dir(harness.root().join(".staging"))
                .expect("staging")
                .next()
                .is_none()
        );
    }

    #[test]
    fn the_same_record_accepted_twice_is_a_duplicate_and_changes_nothing() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        assert!(matches!(
            harness
                .pipeline
                .accept(record.clone(), BODY)
                .expect("accepted"),
            Accepted::Stored(_)
        ));
        let before = harness.counts();

        let again = harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        assert_eq!(again, Accepted::Duplicate(record.record_id));
        assert_eq!(harness.counts(), before, "a replay must not add a row");
        // Nor a second staging copy for the sweeper to find.
        assert!(
            fs::read_dir(harness.root().join(".staging"))
                .expect("staging")
                .next()
                .is_none()
        );
    }

    #[test]
    fn a_subject_derived_record_is_sealed_and_indexes_no_searchable_text() {
        let mut harness = Harness::new();
        let subjects = [testkit::subject('a'), testkit::subject('b')];
        let record = testkit::subject_derived(T09, &subjects);
        let path = harness.path_of(&record);

        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        let text = fs::read_to_string(&path).expect("read");
        assert!(
            !text.contains("Rolled out"),
            "the prose must not be on disk: {text}"
        );

        let parsed = Document::parse(&text).expect("parses");
        assert!(matches!(parsed.body, Body::Sealed(_)));
        assert_eq!(parsed.searchable_text(), "");
        // One wrapped share per subject reached the index, each under an epoch.
        let counts = harness.counts();
        assert_eq!(counts["record_subjects"], 2);
        let shares = harness.snapshot();
        assert_eq!(
            shares
                .iter()
                .filter(|line| line.starts_with("subject|"))
                .count(),
            2
        );
        assert!(
            shares
                .iter()
                .all(|line| !line.contains("subject|") || !line.ends_with("|~"))
        );
    }

    /// A record naming an erased subject is published with its structure and without its body.
    ///
    /// The behaviour this replaces held it as unresolved, which spooled a *readable* body about an
    /// erased subject and spooled it for ever: resolution can never succeed for a subject whose
    /// keys are gone, so nothing settled the file except a later erasure for the same subject
    /// happening to discard it.
    #[test]
    fn a_record_for_an_erased_subject_is_published_without_a_body() {
        let mut harness = Harness::new();
        let subject = testkit::subject('c');
        // An erased subject: minting a key would un-erase it, so the body cannot be sealed at all.
        yaam_crypto::keystore::KeyStore::tombstone(harness.pipeline.keys(), &subject)
            .expect("tombstone");

        let record = testkit::subject_derived(T09, std::slice::from_ref(&subject));
        assert_eq!(
            harness
                .pipeline
                .accept(record.clone(), BODY)
                .expect("not a rejection"),
            Accepted::Stored(record.record_id.clone())
        );

        // Published and indexed, so the structural account survives — and nothing is held back,
        // because there is nothing a retry would improve.
        let path = harness.path_of(&record);
        let text = fs::read_to_string(&path).expect("read");
        let published = Document::parse(&text).expect("parses");
        assert!(matches!(published.body, Body::Plain(ref body) if body.is_empty()));
        assert!(
            !text.contains("Rolled out"),
            "the body must not reach disk in any form"
        );
        assert_eq!(published.record.subjects.len(), 1);
        assert_eq!(harness.counts()["records"], 1);
        assert_eq!(harness.counts()["quarantine_pending"], 0);
        assert!(
            !harness
                .root()
                .join(".quarantine")
                .join(record.record_id.as_str().to_owned() + ".md")
                .exists()
        );

        // And no key was minted for a subject whose keys were destroyed, which is what the older
        // refusal was protecting: a fresh one here would un-erase them.
        assert!(
            yaam_crypto::keystore::KeyStore::get(
                harness.pipeline.keys(),
                &subject,
                &yaam_crypto::Epoch::containing(
                    yaam_contract::timestamp::parse_ms(T09).expect("parses")
                ),
            )
            .expect("get")
            .is_none()
        );

        // It reads back as what it is — shredded, with the erasure that accounts for it — rather
        // than as a record whose body somebody could go looking for.
        assert!(matches!(
            crate::unseal::inspect(&harness.pipeline, &record.record_id).expect("inspected"),
            crate::unseal::Held::Shredded { ref erasures, .. } if erasures.len() == 1
        ));
    }

    #[test]
    fn a_key_store_that_cannot_answer_quarantines_rather_than_rejecting() {
        let mut harness = Harness::new();
        let subject = testkit::subject('d');
        // The subject's key directory is occupied by a file: custody cannot serve this record now.
        let keys = harness.root().join("keystore/keys");
        fs::create_dir_all(&keys).expect("keys dir");
        fs::write(keys.join(subject.as_str()), b"not a directory").expect("obstruct");

        let record = testkit::subject_derived(T09, &[subject]);
        assert_eq!(
            harness
                .pipeline
                .accept(record.clone(), BODY)
                .expect("not a rejection"),
            Accepted::Quarantined(record.record_id)
        );
    }

    #[test]
    fn a_replayed_quarantine_is_recorded_once() {
        let mut harness = Harness::new().resolving_with(testkit::UnavailableLookup);
        let record = testkit::subject_derived(T09, &[testkit::subject('e')]);

        for _ in 0..2 {
            assert!(matches!(
                harness
                    .pipeline
                    .accept(record.clone(), BODY)
                    .expect("accepted"),
                Accepted::Quarantined(_)
            ));
        }
        assert_eq!(harness.counts()["quarantine_pending"], 1);
    }

    #[test]
    fn validation_rejects_what_the_caller_must_fix() {
        let mut harness = Harness::new();
        let cases: Vec<Case> = vec![
            (
                "an undeclared attribute",
                Box::new(|r| {
                    r.attrs
                        .insert("undeclared".to_owned(), attrs::Value::Int(1));
                }),
            ),
            (
                "a sensitive attribute in frontmatter",
                Box::new(|r| {
                    r.attrs.insert(
                        "sensitive_note".to_owned(),
                        attrs::Value::Text("x".to_owned()),
                    );
                }),
            ),
            (
                "an outcome the action does not permit",
                Box::new(|r| r.outcome = Outcome::Declined),
            ),
            (
                "an unknown entity kind",
                Box::new(|r| r.entities[0].kind = "unconfigured".to_owned()),
            ),
            (
                "an entity id that is not canonical",
                Box::new(|r| r.entities[1].id = "not a ticket key".to_owned()),
            ),
            (
                "a policy this deployment does not apply",
                Box::new(|r| r.redaction_policy = "other-v9".to_owned()),
            ),
            (
                "an unreadable server time",
                Box::new(|r| r.received_at = "yesterday".to_owned()),
            ),
            (
                "an unreadable source time",
                Box::new(|r| r.at = "yesterday".to_owned()),
            ),
            (
                "a subject-derived record naming nobody",
                Box::new(|r| r.data_class = DataClass::SubjectDerived),
            ),
        ];

        for (what, break_it) in cases {
            let mut record = testkit::internal(T09);
            break_it(&mut record);
            let error = harness
                .pipeline
                .accept(record, BODY)
                .expect_err(&format!("{what} must be rejected"));
            assert!(matches!(error, crate::Error::Invalid(_)), "{what}: {error}");
        }
        assert_eq!(
            harness.counts()["records"],
            0,
            "no rejection may leave a row"
        );
    }

    #[test]
    fn a_body_the_policy_would_have_masked_is_refused() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let error = harness
            .pipeline
            .accept(record, "credentials: Bearer abcdefghijklmnopqrstuvwx")
            .expect_err("an unredacted body is the writer's bug");
        assert!(error.to_string().contains("bearer_token"), "{error}");
    }

    #[test]
    fn an_unconfigured_deployment_fails_closed() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut pipeline = Pipeline::new(dir.path()).expect("a pipeline with no spec");
        let mut record = testkit::internal(T09);
        record.redaction_policy = String::new();
        // Nothing is declared, so nothing carrying attributes or entities is admitted.
        assert!(pipeline.accept(record.clone(), BODY).is_err());

        record.attrs.clear();
        record.entities.clear();
        assert!(matches!(
            pipeline
                .accept(record, BODY)
                .expect("a bare record still writes"),
            Accepted::Stored(_)
        ));
    }

    #[test]
    fn fan_out_materialises_timelines_and_audit_records_once() {
        let mut harness = Harness::new();
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");

        let timeline = harness
            .root()
            .join("entities/order_ref/ord10014721/timeline.md");
        let audit = harness
            .root()
            .join("audit/subjects")
            .join(record.record_id.as_str().to_owned() + ".md");
        // Step 3 committed the jobs; nothing has run them yet.
        assert!(!timeline.exists());
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 2);

        let link = format!("[[record:{}]]", record.record_id.as_str());
        assert_eq!(
            fs::read_to_string(&timeline)
                .expect("timeline")
                .matches(&link)
                .count(),
            1
        );
        assert!(
            fs::read_to_string(&audit)
                .expect("audit")
                .contains("role=principal")
        );

        // A second drain finds nothing, and re-running the work would not duplicate a line anyway.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
        harness
            .pipeline
            .append_timelines(&record)
            .expect("replayed");
        assert_eq!(
            fs::read_to_string(&timeline)
                .expect("timeline")
                .matches(&link)
                .count(),
            1
        );
    }

    #[test]
    fn a_drain_of_nothing_is_free() {
        let mut harness = Harness::new();
        assert_eq!(harness.pipeline.drain_fanout(0).expect("drained"), 0);
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
    }

    #[test]
    fn a_failed_fan_out_job_waits_out_its_backoff_before_the_next_drain_sees_it() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        // The tree is authoritative; without the file the job cannot be done.
        fs::remove_file(harness.path_of(&record)).expect("remove");

        // Nothing settled, and the job is back in the queue rather than left claimed — which is
        // what it used to be, invisible to every later drain.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
        assert_eq!(harness.fanout_row(), ("pending".to_owned(), 1));

        // A drain a moment later must not pick it up: the delay is the whole point of putting it
        // back, and a retry in the same instant would spend the budget on the same failure.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
        assert_eq!(
            harness.fanout_row(),
            ("pending".to_owned(), 1),
            "the job was claimed before its backoff had passed"
        );

        // Once the delay has passed it is claimed again, and counts the attempt.
        assert_eq!(harness.release_fanout(), 1);
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
        assert_eq!(harness.fanout_row(), ("pending".to_owned(), 2));
    }

    #[test]
    fn a_fan_out_job_that_fails_every_attempt_is_dead_lettered_and_completed() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        fs::remove_file(harness.path_of(&record)).expect("remove");

        let letter = harness
            .root()
            .join(".dead-letter")
            .join(record.record_id.as_str().to_owned() + ".bundle");
        for attempt in 1..super::FANOUT_MAX_ATTEMPTS {
            assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
            assert_eq!(harness.fanout_row(), ("pending".to_owned(), attempt));
            assert!(!letter.exists(), "set aside after {attempt} attempt(s)");
            harness.release_fanout();
        }

        // The budget is spent: the job stops being retried and starts being visible instead.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 1);
        assert!(
            fs::read_to_string(&letter)
                .expect("letter")
                .contains("is not in the tree")
        );
        assert_eq!(
            harness.fanout_row(),
            ("done".to_owned(), super::FANOUT_MAX_ATTEMPTS)
        );
        // Completed, not left pending: a dead-lettered job must not hold a place in the queue.
        assert_eq!(harness.release_fanout(), 0);
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
    }

    #[test]
    fn the_backoff_doubles_and_then_stops_growing() {
        // The delay has to grow — a fixed one retries a broken directory as fast as it can — and it
        // has to stop growing, or a job ends up parked for longer than anybody is watching.
        assert_eq!(super::backoff_ms(1), super::FANOUT_BACKOFF_MS);
        assert_eq!(super::backoff_ms(2), super::FANOUT_BACKOFF_MS * 2);
        assert_eq!(super::backoff_ms(3), super::FANOUT_BACKOFF_MS * 4);
        assert_eq!(super::backoff_ms(60), super::FANOUT_BACKOFF_CAP_MS);
    }

    #[test]
    fn an_unknown_job_kind_is_set_aside_rather_than_wedging_the_queue() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        let job = yaam_store::FanoutJob {
            id: 1,
            record: record.record_id.clone(),
            kind: "from_a_later_version".to_owned(),
            attempts: 1,
        };
        let located = harness.pipeline.locate_records().expect("located");
        let archived = harness
            .pipeline
            .locate_archived(std::slice::from_ref(&job), &located)
            .expect("archived");
        assert!(harness.pipeline.run_job(&job, &located, &archived).is_err());
    }

    /// A record archived out of the tree keeps its fan-out; a record nothing holds does not.
    ///
    /// The manifests answer for the records they hold and for no others. Turning "not found" into
    /// "nothing to do" here would make a genuinely missing record silently correct — and a missing
    /// record is the one thing a fan-out failure is supposed to be able to tell an operator about.
    #[test]
    fn a_record_in_neither_the_tree_nor_a_manifest_is_still_a_fault() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        fs::remove_file(harness.path_of(&record)).expect("remove");
        // An archive holding some other record, so the lookup runs and comes back empty rather
        // than never running at all.
        fs::write(
            harness.root().join("cold/2026-01.jsonl"),
            testkit::manifest_line(&testkit::internal("2026-01-05T08:00:00Z")),
        )
        .expect("manifest");

        let job = yaam_store::FanoutJob {
            id: 1,
            record: record.record_id.clone(),
            kind: super::JOB_BUNDLE.to_owned(),
            attempts: 1,
        };
        let located = harness.pipeline.locate_records().expect("located");
        let archived = harness
            .pipeline
            .locate_archived(std::slice::from_ref(&job), &located)
            .expect("archived");
        assert!(archived.is_empty(), "no manifest holds this record");
        let error = harness
            .pipeline
            .run_job(&job, &located, &archived)
            .expect_err("a record nothing local holds is a real fault");
        assert!(
            matches!(&error, crate::Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound),
            "the failure has to stay the kind a drain retries and then dead-letters: {error}"
        );

        // And the drain still treats it that way: nothing settled, the job back in the queue.
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 0);
        assert_eq!(harness.fanout_row(), ("pending".to_owned(), 1));
    }

    #[test]
    fn a_full_timeline_head_rolls_over_and_keeps_appending() {
        let mut harness = Harness::new();
        let first = testkit::internal(T09);
        harness
            .pipeline
            .accept(first.clone(), BODY)
            .expect("accepted");
        harness.pipeline.drain_fanout(10).expect("drained");

        let dir = harness.root().join("entities/ticket/PROJ-42");
        let head = dir.join("timeline.md");
        fs::write(&head, "x".repeat(70 * 1024)).expect("a head at its limit");

        let second = testkit::internal("2026-08-21T09:14:03Z");
        harness
            .pipeline
            .accept(second.clone(), BODY)
            .expect("accepted");
        harness.pipeline.drain_fanout(10).expect("drained");

        assert!(
            dir.join("timeline-0001.md").exists(),
            "the full head was frozen"
        );
        let live = fs::read_to_string(&head).expect("head");
        assert!(live.contains(second.record_id.as_str()));
        assert!(live.len() < 1024, "the new head starts empty");

        // The mention row still stands wherever the line was frozen, so a replay adds nothing.
        let third = testkit::internal("2026-08-22T09:14:03Z");
        harness.pipeline.accept(third, BODY).expect("accepted");
        harness.pipeline.drain_fanout(10).expect("drained");
        harness
            .pipeline
            .append_timelines(&second)
            .expect("replayed");
        assert_eq!(
            fs::read_to_string(&head)
                .expect("head")
                .matches(second.record_id.as_str())
                .count(),
            1
        );
    }

    /// The bug this table exists for, in its second form: a job that appended and was handed out
    /// again, two rollovers later.
    ///
    /// Two, because that is what the old check could not survive. It read the head and the part
    /// the head most recently became — the only two files *one* rollover could have moved the line
    /// into. After a second one the line sits in an older part, both files it read come back
    /// without it, and the append happens again. The index does not care which file it is in.
    #[test]
    fn a_fan_out_job_re_driven_past_two_rollovers_lists_the_record_once() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 1);

        let dir = harness.root().join("entities/ticket/PROJ-42");
        let head = dir.join("timeline.md");
        assert_eq!(testkit::timeline_mentions(&dir, &record.record_id), 1);

        // Two rollovers after the append, by hand: the line's file is no longer the newest part.
        fs::rename(&head, dir.join("timeline-0001.md")).expect("freeze");
        fs::write(dir.join("timeline-0002.md"), "- older history\n").expect("a later part");
        fs::write(&head, "").expect("a fresh head");

        // The job is handed out again — a claim its drain died holding, reclaimed by a sweep.
        assert_eq!(harness.requeue_fanout(), 1);
        assert_eq!(harness.pipeline.drain_fanout(10).expect("drained"), 1);
        assert_eq!(
            testkit::timeline_mentions(&dir, &record.record_id),
            1,
            "the record is listed twice; the head holds {:?}",
            fs::read_to_string(&head)
        );
    }

    #[test]
    fn a_record_that_resolves_later_leaves_no_spooled_copy() {
        let mut harness = Harness::new();
        let subject = testkit::subject('9');
        let keys = harness.root().join("keystore/keys");
        fs::create_dir_all(&keys).expect("keys dir");
        let obstruction = keys.join(subject.as_str());
        fs::write(&obstruction, b"custody is briefly unavailable").expect("obstruct");

        let record = testkit::subject_derived(T09, std::slice::from_ref(&subject));
        assert!(matches!(
            harness.pipeline.accept(record.clone(), BODY).expect("held"),
            Accepted::Quarantined(_)
        ));
        let spooled = harness
            .root()
            .join(".quarantine")
            .join(record.record_id.as_str().to_owned() + ".md");
        assert!(spooled.exists());

        // Custody recovers, and the writer re-presents the record — a retry or a spool replay.
        fs::remove_file(&obstruction).expect("clear");
        assert!(matches!(
            harness.pipeline.accept(record, BODY).expect("published"),
            Accepted::Stored(_)
        ));
        assert!(
            !spooled.exists(),
            "a published record has no business in the spool"
        );
        // Retracted by the publish itself. Waiting for a rebuild would leave the register naming a
        // spool file that is not there, and every reader of it wrong until then.
        assert_eq!(harness.counts()["quarantine_pending"], 0);
        // And the rebuild agrees, because it derives the register from the spool directory.
        crate::reindex::reindex_all(&mut harness.pipeline).expect("rebuilt");
        assert_eq!(harness.counts()["quarantine_pending"], 0);
    }

    #[test]
    fn an_owner_visible_record_is_stored_apart_and_invisible_to_another_identity() {
        use yaam_contract::Visibility;
        use yaam_store::query::{self, Filter, Scope};

        let mut harness = Harness::new();
        let record = testkit::owner(T09, "agent_a");
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");

        let path = harness.path_of(&record);
        assert!(
            path.to_string_lossy()
                .contains("records/owner/agent_a/2026/08/20/"),
            "{}",
            path.display()
        );
        assert!(path.exists(), "{}", path.display());

        // The other half of the promise: the record is out of the shared tree, and a scoped read
        // by anybody else answers nothing however widely that caller is entitled.
        let store = harness.pipeline.reader().expect("reader");
        let seen_by = |agent: &str| {
            query::by_filter(
                &store,
                &Filter {
                    scope: Scope::Caller {
                        visibility: vec![Visibility::Owner, Visibility::Org, Visibility::Team],
                        agent: agent.to_owned(),
                        teams: vec!["platform".to_owned()],
                    },
                    ..Filter::default()
                },
            )
            .expect("query")
        };
        assert_eq!(seen_by("agent_a"), vec![record.record_id.clone()]);
        assert!(seen_by("agent_b").is_empty(), "another identity saw it");
    }

    #[cfg(unix)]
    #[test]
    fn an_owner_visible_record_admits_no_reader_but_its_own_identity() {
        let mut harness = Harness::new();
        let record = testkit::owner(T09, "agent_a");

        // The staged copy first: a rename carries the mode it finds, so a window in which the copy
        // was group-readable would be a window in which it was read.
        let document = testkit::plain_document(&record, BODY);
        let staged = harness.pipeline.stage(&document).expect("staged");
        assert_eq!(testkit::mode_of(&staged), 0o600);
        fs::remove_file(&staged).expect("discard");

        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        let path = harness.path_of(&record);
        assert_eq!(testkit::mode_of(&path), 0o600, "{}", path.display());

        // And every directory over it, up to and including `records/owner`: a file nobody can
        // traverse to is unopenable whatever its own mode says.
        let stop = harness.root().join("records");
        let mut dir = path.parent().expect("a parent");
        while dir != stop {
            assert_eq!(testkit::mode_of(dir), 0o700, "{}", dir.display());
            dir = dir.parent().expect("a parent");
        }
        // `records/` itself stays traversable: what is private is the owner subtree, not the tree.
        assert_ne!(testkit::mode_of(&stop) & 0o007, 0);
    }

    #[cfg(unix)]
    #[test]
    fn an_owner_subtree_left_loose_by_an_older_write_is_tightened() {
        let mut harness = Harness::new();
        // What a tree written before the boundary existed — or restored from a loose backup — looks
        // like: the directories are there, and anybody on the host can walk them.
        let loose = harness.root().join("records/owner/agent_a/2026/08/20");
        fs::create_dir_all(&loose).expect("dirs");
        crate::fsutil::make_private(&loose).expect("mode");
        std::fs::set_permissions(
            harness.root().join("records/owner"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("loosen");

        harness
            .pipeline
            .accept(testkit::owner(T09, "agent_a"), BODY)
            .expect("accepted");
        assert_eq!(
            testkit::mode_of(&harness.root().join("records/owner")),
            0o700
        );
    }

    #[test]
    fn a_resolver_that_cannot_answer_quarantines_and_the_record_comes_back() {
        let mut harness = Harness::new().resolving_with(testkit::UnavailableLookup);
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);

        assert_eq!(
            harness
                .pipeline
                .accept(record.clone(), BODY)
                .expect("not a rejection"),
            Accepted::Quarantined(record.record_id.clone())
        );
        assert!(!harness.path_of(&record).exists());
        assert_eq!(harness.counts()["records"], 0);
        assert_eq!(harness.counts()["quarantine_pending"], 1);
        let spooled = harness
            .root()
            .join(".quarantine")
            .join(record.record_id.as_str().to_owned() + ".md");
        let held = fs::read_to_string(&spooled).expect("spooled");
        assert!(
            !held.contains("Rolled out"),
            "a held body is sealed on disk, not merely delayed"
        );
        assert!(
            held.contains(quarantine_subject("2026-08-20").expect("key").as_str()),
            "sealed under the day's quarantine key, so the spool needs no second key store"
        );

        // The lookup comes back and the record is re-presented, which is the settle path that
        // already existed: no second mechanism, and nothing to replay by hand.
        let mut harness = harness.resolving_with(DeclaredSubjects);
        assert_eq!(
            harness
                .pipeline
                .accept(record.clone(), BODY)
                .expect("accepted"),
            Accepted::Stored(record.record_id.clone())
        );
        assert!(harness.path_of(&record).exists());
        assert_eq!(harness.counts()["records"], 1);
        assert_eq!(harness.counts()["quarantine_pending"], 0);
        assert!(!spooled.exists(), "the spooled copy is dropped on publish");
    }

    #[test]
    fn what_the_resolver_answers_is_what_gets_sealed() {
        let declared = testkit::subject('a');
        let record = testkit::subject_derived(T09, std::slice::from_ref(&declared));
        let resolved = [subject_ref('b'), subject_ref('c')];
        let mut harness = Harness::new().resolving_with(Mapped(BTreeMap::from([(
            record.record_id.as_str().to_owned(),
            resolved.to_vec(),
        )])));

        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");

        // Frontmatter, wrapped shares and audit all follow the resolver, not the record: a body
        // sealed to one subject set and indexed under another would be undestroyable by the subject
        // the index names.
        let stored = Document::parse(&fs::read_to_string(harness.path_of(&record)).expect("read"))
            .expect("parses");
        assert_eq!(stored.record.subjects, resolved);
        let shares = harness.snapshot();
        for subject in &resolved {
            assert!(
                shares.iter().any(
                    |line| line.starts_with("subject|") && line.contains(subject.hash.as_str())
                ),
                "{} reached the index",
                subject.hash.as_str()
            );
        }
        assert!(
            shares.iter().all(|line| !line.contains(declared.as_str())),
            "the subject the record declared is not the one it was sealed under"
        );
        assert_eq!(harness.counts()["record_subjects"], 2);

        // And a record the table has no entry for is held, not rejected: a lookup that has not
        // caught up is the same transient failure whatever shape a resolver takes.
        let unknown = testkit::subject_derived(T09, &[testkit::subject('d')]);
        assert_eq!(
            harness
                .pipeline
                .accept(unknown.clone(), BODY)
                .expect("not a rejection"),
            Accepted::Quarantined(unknown.record_id)
        );
    }

    /// A refusal is rejected with its reason and holds nothing back. The distinction that matters:
    /// the same record arriving while a lookup is down is spooled, and one the resolver will never be
    /// able to key would sit in that spool for ever, never queryable and never published.
    #[test]
    fn a_refused_record_is_rejected_with_its_reason_and_not_spooled() {
        let mut harness = Harness::new().resolving_with(Refuses);
        let record = testkit::subject_derived(T09, &[testkit::subject('a')]);
        let id = record.record_id.clone();

        let err = harness
            .pipeline
            .accept(record, BODY)
            .expect_err("a record no retry improves");
        assert!(
            matches!(&err, crate::Error::Invalid(_)) && err.to_string().contains("two of them"),
            "the caller is told what to fix: {err}"
        );
        assert!(
            !harness
                .root()
                .join(crate::layout::QUARANTINE_DIR)
                .join(format!("{}.md", id.as_str()))
                .exists(),
            "a permanent fault does not get a spool file"
        );
        assert_eq!(harness.counts()["quarantine_pending"], 0);
    }

    #[test]
    fn a_resolver_that_contradicts_the_record_class_is_a_rejection() {
        let mut none = Harness::new().resolving_with(ResolvesToNothing);
        let sealed = testkit::subject_derived(T09, &[testkit::subject('a')]);
        // Sealed under no subject at all would be unerasable by construction, so this is the
        // deployment's bug to fix rather than something to hold and retry.
        assert!(matches!(
            none.pipeline.accept(sealed, BODY),
            Err(crate::Error::Invalid(_))
        ));

        let plain = testkit::internal(T09);
        let mut extra = Harness::new().resolving_with(Mapped(BTreeMap::from([(
            plain.record_id.as_str().to_owned(),
            vec![subject_ref('a')],
        )])));
        assert!(matches!(
            extra.pipeline.accept(plain, BODY),
            Err(crate::Error::Invalid(_))
        ));
    }

    #[test]
    fn a_wrapped_key_store_stores_no_usable_key() {
        let mut harness = Harness::new().wrapping_keys_with(Xor(0x33));
        let subject = testkit::subject('a');
        let record = testkit::subject_derived(T09, std::slice::from_ref(&subject));

        let epoch =
            yaam_crypto::Epoch::containing(crate::layout::stamp_of(&record).expect("stamp").ms);
        harness.pipeline.accept(record, BODY).expect("accepted");

        // Minted through the pipeline, so the wrapper is on the write path and not just constructed.
        let key = harness
            .pipeline
            .keys()
            .get(&subject, &epoch)
            .expect("readable")
            .expect("minted");
        let stored = fs::read(
            harness
                .root()
                .join("keystore/keys")
                .join(subject.as_str())
                .join(epoch.as_str()),
        )
        .expect("key file");
        assert_ne!(stored, key, "a recovered key file is not a key");
    }

    #[test]
    fn a_pipeline_prints_its_root_and_reaches_no_further() {
        let harness = Harness::new();
        let printed = format!("{:?}", harness.pipeline);

        assert!(printed.contains("Pipeline"), "{printed}");
        assert!(
            printed.contains(&harness.root().display().to_string()),
            "{printed}"
        );
        // The plug-ins are left out: a deployment's resolver and key wrapper are under no obligation
        // to be careful about what they print.
        assert!(printed.ends_with(".. }"), "{printed}");
    }

    #[test]
    fn a_quarantine_key_is_one_per_date_and_derived_from_it() {
        let one = quarantine_subject("2026-08-20").expect("valid");
        let other = quarantine_subject("2026-08-21").expect("valid");
        assert_ne!(one, other);
        assert_eq!(one, quarantine_subject("2026-08-20").expect("valid"));
        assert_eq!(one.as_str().len(), 66);
    }
}
