//! The one audited path back to a sealed body.
//!
//! Sealing has a mechanism and erasure has a mechanism; reading had neither, which made a sealed
//! body write-only in practice. Nothing in either workspace returned one, so the first sealed record
//! in a deployment took its capability dark with it and no command said so — and a regulator asking
//! what was retained about a person would have been answered by an operator unwrapping shares by
//! hand.
//!
//! Two properties are the whole of this module, and both are about ordering rather than about
//! cryptography.
//!
//! **A body cannot be read without a record of the reading.** The audit record is published — staged,
//! fsynced, renamed into the tree, indexed — *before* a single key is fetched. It is not a side
//! effect of the read and it is not written afterwards: an audit write that fails after the plaintext
//! is in hand leaves the operator holding what nothing recorded, and no later pass can discover that
//! it happened. Written first, the two failure shapes are a line for a read that then failed, and
//! nothing at all. Only the first is visible to whoever has to reconcile the trail, and only the
//! first can be explained.
//!
//! **What cannot be read says so.** A subject whose keys are destroyed leaves a body no copy anywhere
//! will ever open again. That is a definite answer about a record that certainly existed, and
//! reporting it as an empty result — or as a record that could not be found — would have an operator
//! chasing a store fault instead of reading the erasure that is working exactly as designed.
//!
//! The audit record itself is an ordinary record: [`Visibility::Operator`], so only the operator role
//! reads it back, and [`DataClass::Internal`], so no key destruction can ever reach it. It names the
//! subjects whose keys were used, in pseudonym, and that naming deliberately outlives their erasure
//! — the tombstone log retains the same pseudonyms for the same reason. A trail that erasure could
//! prune is a trail that cannot answer "who read this before it was erased".

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use yaam_contract::{
    ActionRecord, DataClass, Outcome, RecordId, SchemaVer, SubjectHash, Visibility, timestamp,
};
use yaam_crypto::keystore::KeyStore as _;
use yaam_md::{Body, Document};

use crate::pipeline::Accepted;
use crate::{Pipeline, Result, erase, fsutil};

/// The action every audited read is recorded under.
///
/// Public because it is how the trail is queried: `--action unseal` over an operator-scoped read is
/// the answer to "what has been decrypted here", and a caller matching a string of its own would
/// eventually match nothing and read that as nothing having happened.
pub const AUDIT_ACTION: &str = "unseal";

/// Schema version the audit record is written under.
///
/// This build's own, not the audited record's: the two are separate records, and stamping a read
/// with the version of the thing it read would make a migration of the audit trail unable to tell
/// which rows it had already touched.
const AUDIT_SCHEMA_VER: SchemaVer = SchemaVer(1);

/// An erasure that accounts for a key being gone.
///
/// The tombstone is optional because the key store's own tombstone is what refuses a key, and the
/// log is a separate append-only file: a subject tombstoned directly — by a replay, or by a
/// half-finished erasure — is gone from the key store with nothing in the log naming it. Reporting
/// that as no erasure at all would be the more misleading of the two answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erasure {
    /// Whose keys are gone.
    pub subject: SubjectHash,
    /// The tombstone identifier the log carries for it, when it carries one.
    pub tombstone: Option<String>,
}

/// What the store holds for one record's body, before any key is touched.
///
/// Read-only, and it reveals nothing: every field of it is either frontmatter or the size of a
/// ciphertext. This is what an unconfirmed read prints, so an operator can see whether the read they
/// are about to have recorded against their name would answer anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// A sealed body, gated by these subjects' keys for this epoch.
    ///
    /// `erasures` is what makes the preview honest: non-empty means the attempt will fail, because
    /// one of the subjects the shares name has been erased.
    Sealed {
        /// Subjects whose shares the block carries. Every one of them is needed.
        subjects: Vec<SubjectHash>,
        /// Epoch label whose subject keys wrap the shares.
        epoch: String,
        /// Size of the stored ciphertext, tag included.
        ciphertext_bytes: usize,
        /// Erasures that already stand against those subjects.
        erasures: Vec<Erasure>,
    },
    /// A plaintext body. No key gates it, so there is nothing here to unseal.
    Plain,
    /// A subject-derived record carrying no ciphertext: the body is already gone from this copy.
    Shredded {
        /// Subjects the record names, which is retained structure.
        subjects: Vec<SubjectHash>,
        /// Erasures that account for it, empty when nothing in the log does.
        erasures: Vec<Erasure>,
    },
    /// No record with this identifier is in the tree.
    Absent {
        /// Whether a cold manifest names it, which makes it archived rather than unknown.
        archived: bool,
    },
}

/// What an audited read found. Every arm but the first hands back no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// The plaintext, and the audit record written before the key was used.
    Revealed {
        /// The body, as it was sealed.
        body: String,
        /// Identifier of the audit record that stands for this reading.
        audit: RecordId,
    },
    /// A key this read needs is gone, so no copy of this body will open again.
    ///
    /// `audit` is `Some` only where a key was actually reached for: a read refused on the strength
    /// of frontmatter and the tombstone log touches nothing and is nobody's business to record.
    Shredded {
        /// Subjects the block or the frontmatter names.
        subjects: Vec<SubjectHash>,
        /// Erasures that account for the absence, empty when nothing in the log does.
        erasures: Vec<Erasure>,
        /// The audit record, when the attempt got as far as the key store.
        audit: Option<RecordId>,
    },
    /// The body was never sealed. It is plaintext in the tree, and this command is not how it is read.
    Plain,
    /// Nothing in the tree carries this identifier.
    Absent {
        /// Whether a cold manifest names it.
        archived: bool,
    },
}

/// Reports what a read would attempt, without attempting it.
///
/// Its own function because a confirmation over a record identifier is not a check: an operator
/// about to have a decrypt recorded against their name is owed the chance to see that the record is
/// the one they meant, that its body is still there, and that the keys have not already been
/// destroyed. Nothing here writes, and nothing here fetches a key.
pub fn inspect(pipeline: &Pipeline, record: &RecordId) -> Result<Held> {
    let Some(path) = pipeline.locate_records()?.remove(record.as_str()) else {
        return Ok(Held::Absent {
            archived: archived(pipeline, record)?,
        });
    };
    let document = Document::parse(&fs::read_to_string(&path)?)?;
    let named: Vec<SubjectHash> = document
        .record
        .subjects
        .iter()
        .map(|subject| subject.hash.clone())
        .collect();

    match &document.body {
        Body::Sealed(sealed) => {
            let subjects: Vec<SubjectHash> = sealed
                .shares
                .iter()
                .map(|share| share.subject.clone())
                .collect();
            Ok(Held::Sealed {
                erasures: erasures(pipeline, &subjects)?,
                epoch: sealed.epoch.as_str().to_owned(),
                ciphertext_bytes: sealed.ciphertext.len(),
                subjects,
            })
        }
        // A subject-derived record with no ciphertext is one an erasure or a replay reached. The
        // plaintext half of that branch is deliberately not read: a record whose class says its body
        // is erasable must not be printed by this command just because some editor left prose there,
        // or the audited path would have an unaudited one beside it.
        Body::Plain(_) if document.record.data_class == DataClass::SubjectDerived => {
            Ok(Held::Shredded {
                erasures: erasures(pipeline, &named)?,
                subjects: named,
            })
        }
        Body::Plain(_) => Ok(Held::Plain),
    }
}

/// Reads one sealed body, having first recorded who read it and why.
///
/// The order is the point, and it is the opposite of the convenient one. Nothing is decrypted until
/// the audit record is published and indexed, so a store that cannot accept the audit record cannot
/// answer the read either — the error surfaces here and the plaintext is never fetched, let alone
/// returned. Doing it the other way round would make the audit a courtesy: the first full disk or
/// unwritable tree would hand back a body with nothing anywhere saying it had been handed back, and
/// nothing later could tell that reading from a read that never happened.
///
/// Everything refusable without a key is refused before the audit record is written — a record that
/// is not here, a body that was never sealed, keys already destroyed. Those attempts reach no key
/// material and reveal nothing, so recording them would fill the trail an auditor reads with
/// mistyped identifiers.
///
/// `operator` becomes the audit record's agent and `reason` becomes its body, so both are refused
/// empty: an audit line naming nobody, for no stated purpose, is a line that answers neither
/// question anybody asks of it. The body goes through the deployment's redaction policy like any
/// other, which means a reason carrying something the policy masks fails the read rather than
/// entering the store — the right way round for a field an operator types by hand.
pub fn read_body(
    pipeline: &mut Pipeline,
    record: &RecordId,
    operator: &str,
    reason: &str,
) -> Result<Read> {
    let operator = named_operator(operator)?;
    let reason = stated_reason(reason)?;

    let (subjects, epoch) = match inspect(pipeline, record)? {
        Held::Sealed {
            subjects,
            epoch,
            erasures,
            ..
        } if erasures.is_empty() => (subjects, epoch),
        Held::Sealed {
            subjects, erasures, ..
        }
        | Held::Shredded {
            subjects, erasures, ..
        } => {
            return Ok(Read::Shredded {
                subjects,
                erasures,
                audit: None,
            });
        }
        Held::Plain => return Ok(Read::Plain),
        Held::Absent { archived } => return Ok(Read::Absent { archived }),
    };

    // The audit record, before the key store is asked for anything. A failure here is the whole read
    // failing, which is the property this module exists for.
    let audit = audit_record(pipeline, record, &subjects, &epoch, operator, reason);
    let audit_id = audit.record_id.clone();
    let body = audit.summary.clone();
    match pipeline.accept(audit, &body)? {
        Accepted::Stored(_) => {}
        // Neither is reachable with a freshly generated identifier and an internal record that names
        // no subject, and both would mean the trail did not gain a line. Refusing beats revealing on
        // the strength of an assumption about the write path.
        Accepted::Duplicate(id) | Accepted::Quarantined(id) => {
            return Err(crate::pipeline::invalid(format!(
                "the audit record `{}` for reading `{}` was not published, so nothing was read",
                id.as_str(),
                record.as_str()
            )));
        }
    }

    reveal(pipeline, record, &audit_id)
}

/// Fetches every share and decrypts, now that the reading is on the record.
///
/// Split out so the ordering above reads as one sequence. A key that has gone missing between the
/// inspection and here — a key store restored short, a file removed by hand — is the same permanent
/// answer as an erasure, and is reported as one rather than as a crypto failure an operator would
/// take for corruption.
fn reveal(pipeline: &Pipeline, record: &RecordId, audit: &RecordId) -> Result<Read> {
    let path = pipeline
        .locate_records()?
        .remove(record.as_str())
        .ok_or_else(|| {
            crate::pipeline::invalid(format!(
                "record `{}` left the tree while its read was being recorded",
                record.as_str()
            ))
        })?;
    let document = Document::parse(&fs::read_to_string(&path)?)?;
    let Body::Sealed(sealed) = &document.body else {
        return Ok(Read::Plain);
    };

    match yaam_crypto::seal::unseal(pipeline.keys(), record, sealed) {
        Ok(plaintext) => Ok(Read::Revealed {
            body: String::from_utf8(plaintext).map_err(|error| {
                crate::pipeline::invalid(format!(
                    "record `{}` unsealed to bytes that are not text: {error}",
                    record.as_str()
                ))
            })?,
            audit: audit.clone(),
        }),
        Err(yaam_crypto::Error::KeyAbsent(subject, _)) => {
            let subjects: Vec<SubjectHash> = sealed
                .shares
                .iter()
                .map(|share| share.subject.clone())
                .collect();
            tracing::warn!(
                record = record.as_str(),
                %subject,
                "a sealed body's key is gone; the read was recorded and answered nothing"
            );
            Ok(Read::Shredded {
                erasures: erasures(pipeline, &subjects)?,
                subjects,
                audit: Some(audit.clone()),
            })
        }
        Err(other) => Err(other.into()),
    }
}

/// The record that stands for one reading.
///
/// An ordinary action record, deliberately: it is staged and fsynced before it is published, indexed
/// in the same transaction as every other, carried by a backup, and re-derived by a rebuild. An
/// audit trail in a format of its own would have had none of that, and would have had to earn each
/// of those properties again.
///
/// `Outcome::Success` is about the grant and not about the plaintext, because this record is written
/// before any key is touched and cannot yet know how the decrypt went. What it attests is the thing
/// a regulator asks for: that this operator was authorised to read this body, at this instant, for
/// this stated reason. Whether the bytes then decrypted is a question about the key store, and the
/// tombstone log is what answers it.
fn audit_record(
    pipeline: &Pipeline,
    record: &RecordId,
    subjects: &[SubjectHash],
    epoch: &str,
    operator: &str,
    reason: &str,
) -> ActionRecord {
    let now = timestamp::format_ms(fsutil::now_ms());
    let mut summary = format!(
        "operator `{operator}` was granted a decrypt of [[record:{}]].\n\nreason: {reason}\n\n\
         keys used: epoch {epoch}, subject(s)",
        record.as_str()
    );
    for subject in subjects {
        summary.push(' ');
        summary.push_str(subject.as_str());
    }
    summary.push_str(
        ".\nThis record is written before the keys are fetched, so it stands whether or not the \
         body decrypted.\n",
    );

    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: AUDIT_SCHEMA_VER,
        // Both stamps are this instant: the reading is what happened, and this is what recorded it.
        // A backfilled audit record would be one describing a read nobody here observed.
        at: now.clone(),
        received_at: now,
        backfilled: false,
        agent: operator.to_owned(),
        agent_ver: None,
        correlation_id: None,
        action: AUDIT_ACTION.to_owned(),
        outcome: Outcome::Success,
        // No attributes and no entity references, on purpose. Both surfaces are deployment
        // configuration — an undeclared attribute key is a rejection, and an entity kind this
        // deployment has not configured is another — so either would make an audited read
        // impossible on a store whose `spec/` never anticipated one. What the record has to say it
        // says in prose, which no schema can refuse.
        attrs: BTreeMap::new(),
        entities: Vec::new(),
        // Empty because the record is internal, which is what keeps it out of erasure's reach: an
        // audit record a subject could erase is an audit record that disappears exactly when it is
        // being asked for. The pseudonyms are in the prose instead.
        subjects: Vec::new(),
        visibility: Visibility::Operator,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: pipeline.redaction_policy().to_owned(),
        fields_masked: Vec::new(),
        tags: Vec::new(),
        summary,
    }
}

/// The erasures standing against a set of subjects.
///
/// Both sources are consulted because they fail differently: the key store's tombstone is what
/// actually refuses a key, and the log is what names the erasure that ordered it. A subject
/// tombstoned with nothing in the log is still erased, and is reported with no tombstone identifier
/// rather than left out.
fn erasures(pipeline: &Pipeline, subjects: &[SubjectHash]) -> Result<Vec<Erasure>> {
    let log = erase::read_log(pipeline)?;
    let mut found = Vec::new();
    for subject in subjects {
        if !pipeline.keys().is_tombstoned(subject)? {
            continue;
        }
        found.push(Erasure {
            subject: subject.clone(),
            tombstone: log
                .iter()
                .rev()
                .find(|entry| entry.subject == subject.as_str())
                .map(|entry| entry.id.clone()),
        });
    }
    Ok(found)
}

/// Whether a cold manifest names this record.
///
/// Asked only once the tree has come up empty, and it changes the answer rather than decorating it:
/// an archived record's body is in the archive this store no longer holds, which is a different
/// thing for an operator to do next than an identifier nothing has ever heard of.
fn archived(pipeline: &Pipeline, record: &RecordId) -> Result<bool> {
    let wanted = BTreeSet::from([record.as_str()]);
    Ok(!crate::reindex::cold_records(pipeline.root(), &wanted)?.is_empty())
}

/// The operator's name, refused empty.
fn named_operator(operator: &str) -> Result<&str> {
    let trimmed = operator.trim();
    if trimmed.is_empty() {
        return Err(crate::pipeline::invalid(
            "a read has to name the operator making it: the audit record's whole purpose is to say \
             who read the body"
                .to_owned(),
        ));
    }
    Ok(trimmed)
}

/// The stated reason, refused empty.
fn stated_reason(reason: &str) -> Result<&str> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(crate::pipeline::invalid(
            "a read has to state why: an audit trail of decrypts with no reasons in it answers the \
             question nobody asks"
                .to_owned(),
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use yaam_contract::{DataClass, RecordId, Visibility};
    use yaam_md::Document;

    use super::{AUDIT_ACTION, Held, Read, inspect, read_body};
    use crate::testkit::{self, BODY, Harness};

    /// A server time inside the epoch the fixtures use.
    const T11: &str = "2026-08-22T11:00:00Z";

    /// A store holding one sealed record about one subject.
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
        (harness, subject, record)
    }

    /// Every audit record in the tree, oldest first.
    fn audit_records(harness: &Harness) -> Vec<yaam_contract::ActionRecord> {
        let mut found: Vec<yaam_contract::ActionRecord> =
            crate::fsutil::walk_files(&harness.root().join("records"), crate::layout::RECORD_EXT)
                .expect("walk")
                .into_iter()
                .filter_map(|path| Document::parse(&fs::read_to_string(&path).expect("read")).ok())
                .map(|document| document.record)
                .filter(|record| record.action == AUDIT_ACTION)
                .collect();
        found.sort_by(|a, b| a.record_id.as_str().cmp(b.record_id.as_str()));
        found
    }

    /// The body comes back, and the reading is on the record before it does.
    ///
    /// The property the whole module exists for: there is no arrangement of these two writes that
    /// leaves a body read and unrecorded, and this is the test that would fail if the audit write
    /// were moved after the decrypt and then broke.
    #[test]
    fn a_read_returns_the_body_and_leaves_an_audit_record_naming_who_read_it() {
        let (mut harness, subject, record) = with_sealed_record();

        let read = read_body(
            &mut harness.pipeline,
            &record.record_id,
            "operator_a",
            "regulator asked what is retained",
        )
        .expect("read");
        let Read::Revealed { body, audit } = read else {
            panic!("the body is sealed and its key is here: {read:?}");
        };
        assert_eq!(body, BODY, "the plaintext is what was sealed");

        let trail = audit_records(&harness);
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].record_id, audit);
        assert_eq!(trail[0].agent, "operator_a");
        assert_eq!(
            trail[0].visibility,
            Visibility::Operator,
            "only the operator role may read the trail back"
        );
        assert_eq!(
            trail[0].data_class,
            DataClass::Internal,
            "an audit record a key destruction could reach is one that disappears when it is wanted"
        );
        assert!(trail[0].subjects.is_empty(), "internal records name none");
        assert!(
            trail[0]
                .summary
                .contains("regulator asked what is retained"),
            "the reason is what makes the trail worth reading: {}",
            trail[0].summary
        );
        assert!(
            trail[0].summary.contains(record.record_id.as_str())
                && trail[0].summary.contains(subject.as_str()),
            "the trail has to say which body and whose keys: {}",
            trail[0].summary
        );
    }

    /// A read the store cannot record is a read that does not happen.
    ///
    /// The ordering, asserted from the failing side. `records/` is made unwritable, so publishing
    /// the audit record fails; the body must stay unread rather than being handed back with the
    /// trail silently one line short.
    #[test]
    #[cfg(unix)]
    fn a_read_whose_audit_record_cannot_be_written_reveals_nothing() {
        use std::os::unix::fs::PermissionsExt as _;

        let (mut harness, _, record) = with_sealed_record();
        // The staging directory, because that is the first thing a publish writes and the last thing
        // that depends on today's date: an unwritable one is a store that cannot take a record at
        // all, which is precisely the condition under which a body must stay unread.
        let staging = harness.root().join(".staging");
        let restore = fs::metadata(&staging).expect("metadata").permissions();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o500)).expect("read-only");

        let error = read_body(
            &mut harness.pipeline,
            &record.record_id,
            "operator_a",
            "a reason",
        )
        .expect_err("the audit record cannot be published, so the read must fail");
        fs::set_permissions(&staging, restore).expect("restored");

        assert!(
            !error.to_string().contains(BODY),
            "the failure must not carry the body it refused to reveal: {error}"
        );
        assert!(
            audit_records(&harness).is_empty(),
            "nothing was recorded, which is why nothing was revealed"
        );
    }

    /// An erased subject's body is unreadable for ever, and the answer says so.
    ///
    /// This is the case that must not read as "no such record": the record is right there, its
    /// structure answers every question except the one asked, and an operator told nothing would go
    /// looking for a store fault. The refusal reaches no key, so it leaves no audit line either.
    #[test]
    fn a_read_of_an_erased_subjects_body_is_a_permanent_answer_and_not_an_empty_one() {
        let (mut harness, subject, record) = with_sealed_record();
        harness.pipeline.drain_fanout(100).expect("drained");
        let erased = crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");

        let read = read_body(
            &mut harness.pipeline,
            &record.record_id,
            "operator_a",
            "a reason",
        )
        .expect("an answer, not a failure");
        let Read::Shredded {
            subjects,
            erasures,
            audit,
        } = read
        else {
            panic!("the keys are gone: {read:?}");
        };
        assert_eq!(subjects, vec![subject.clone()]);
        assert_eq!(erasures.len(), 1);
        assert_eq!(erasures[0].subject, subject);
        assert_eq!(
            erasures[0].tombstone.as_deref(),
            Some(erased.tombstone_id.as_str()),
            "the erasure that accounts for it is what an operator asks about next"
        );
        assert_eq!(audit, None, "no key was reached for, so nothing was read");
        assert!(audit_records(&harness).is_empty());
    }

    /// Ciphertext whose key is simply gone is the same permanent answer, and that read *is* recorded.
    ///
    /// A tree restored beside a key store that was not — the one recovery that leaves a store full of
    /// blocks nothing can open. No tombstone accounts for it, so the refusal cannot be made from
    /// frontmatter: the key store has to be asked, and being asked is what earns the audit line.
    /// Which is also the only way the trail can show that somebody tried.
    #[test]
    fn ciphertext_whose_key_is_missing_is_reported_as_gone_and_the_attempt_is_recorded() {
        let (mut harness, subject, record) = with_sealed_record();
        yaam_crypto::keystore::KeyStore::destroy_subject(harness.pipeline.keys(), &subject)
            .expect("a key store that did not come back with the tree");

        let read = read_body(
            &mut harness.pipeline,
            &record.record_id,
            "operator_a",
            "a reason",
        )
        .expect("an answer");
        let Read::Shredded {
            subjects,
            erasures,
            audit,
        } = read
        else {
            panic!("no key can open it: {read:?}");
        };
        assert_eq!(subjects, vec![subject]);
        assert!(
            erasures.is_empty(),
            "no erasure accounts for it, and inventing one would be worse than saying so"
        );
        assert!(
            audit.is_some(),
            "the key store was asked, so the attempt is on the record"
        );
        assert_eq!(audit_records(&harness).len(), 1);
    }

    /// A tombstoned subject is refused even while its key file is still on disk.
    ///
    /// The half-finished erasure: tombstoned, keys not yet unlinked, ciphertext still in the tree.
    /// The key store answers nothing for a tombstoned subject whatever the file says, so the read is
    /// refused from the tombstone rather than by trying and failing — which keeps the trail free of a
    /// line for an attempt that could never have got a key.
    #[test]
    fn a_tombstoned_subject_is_refused_before_the_audit_even_with_its_key_file_still_there() {
        let (mut harness, subject, record) = with_sealed_record();
        yaam_crypto::keystore::KeyStore::tombstone(harness.pipeline.keys(), &subject)
            .expect("tombstoned, and nothing unlinked yet");
        assert_eq!(
            crate::erase::preview(&harness.pipeline, &subject)
                .expect("preview")
                .keys,
            1,
            "the key file is still there, which is what makes this the interesting case"
        );

        let read = read_body(
            &mut harness.pipeline,
            &record.record_id,
            "operator_a",
            "a reason",
        )
        .expect("an answer");
        let Read::Shredded {
            erasures, audit, ..
        } = read
        else {
            panic!("the subject is tombstoned: {read:?}");
        };
        assert_eq!(erasures.len(), 1);
        assert_eq!(
            erasures[0].tombstone, None,
            "the key store's own tombstone, with nothing in the log naming it"
        );
        assert_eq!(audit, None, "no key could have been reached for");
        assert!(audit_records(&harness).is_empty());
    }

    /// A plaintext body is not this command's to print, and an unknown identifier is not a body.
    ///
    /// Both matter for the same reason: this is the only path that prints a body, so anything it
    /// prints without an audit record would be a second, silent path. A plaintext body is readable
    /// from the tree by whoever may read the tree, and saying so is more use than printing it here.
    #[test]
    fn a_plaintext_body_and_an_unknown_record_are_both_refused_without_touching_a_key() {
        let mut harness = Harness::new();
        let plain = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(plain.clone(), BODY)
            .expect("accepted");

        assert_eq!(
            read_body(
                &mut harness.pipeline,
                &plain.record_id,
                "operator_a",
                "a reason"
            )
            .expect("an answer"),
            Read::Plain
        );
        assert_eq!(
            inspect(&harness.pipeline, &plain.record_id).expect("inspected"),
            Held::Plain
        );

        let unknown = RecordId::generate();
        assert_eq!(
            read_body(&mut harness.pipeline, &unknown, "operator_a", "a reason")
                .expect("an answer"),
            Read::Absent { archived: false }
        );
        assert!(audit_records(&harness).is_empty());
    }

    /// The preview says what the read would attempt, and nothing it says costs a key.
    #[test]
    fn the_preview_names_the_subjects_and_the_epoch_a_read_would_use() {
        let (harness, subject, record) = with_sealed_record();

        let held = inspect(&harness.pipeline, &record.record_id).expect("inspected");
        let Held::Sealed {
            subjects,
            epoch,
            ciphertext_bytes,
            erasures,
        } = held
        else {
            panic!("the body is sealed");
        };
        assert_eq!(subjects, vec![subject]);
        assert_eq!(epoch, "2026-Q3");
        assert!(ciphertext_bytes >= BODY.len(), "the tag is in there too");
        assert!(erasures.is_empty(), "nothing has been erased");
        assert!(
            audit_records(&harness).is_empty(),
            "a preview is not a reading"
        );
    }

    /// A read with nobody's name on it, or no reason, is refused before anything happens.
    ///
    /// Both fields are the whole value of the trail. A store full of decrypt records attributed to
    /// nobody, for no purpose, would satisfy the mechanism and answer none of the questions the
    /// mechanism exists to answer.
    #[test]
    fn a_read_without_an_operator_or_a_reason_is_refused() {
        let (mut harness, _, record) = with_sealed_record();
        for (operator, reason) in [("", "a reason"), ("  ", "a reason"), ("operator_a", " ")] {
            let error = read_body(&mut harness.pipeline, &record.record_id, operator, reason)
                .expect_err("refused");
            assert!(
                error.to_string().contains("has to"),
                "the refusal has to say what is missing: {error}"
            );
        }
        assert!(audit_records(&harness).is_empty());
    }

    /// An archived record is a different answer from an unknown one.
    #[test]
    fn a_record_only_a_cold_manifest_names_is_reported_as_archived() {
        let mut harness = Harness::new();
        let record = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(record.clone(), BODY)
            .expect("accepted");
        let path = harness.path_of(&record);
        let document = Document::parse(&fs::read_to_string(&path).expect("read")).expect("parses");
        fs::create_dir_all(harness.root().join("cold")).expect("dirs");
        fs::write(
            harness.root().join("cold/2026-08.jsonl"),
            serde_json::to_string(&document.record).expect("json") + "\n",
        )
        .expect("manifest");
        fs::remove_file(&path).expect("archived out of the tree");

        assert_eq!(
            inspect(&harness.pipeline, &record.record_id).expect("inspected"),
            Held::Absent { archived: true }
        );
    }
}
