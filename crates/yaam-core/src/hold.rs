//! Legal hold: what arbitrates when preservation and erasure point in opposite directions.
//!
//! Two obligations reach the same keys from opposite ends. Erasure destroys a subject's keys on
//! request and retention destroys an epoch's keys on age; a litigation or AML hold requires that
//! the same keys survive, because a key destroyed makes the bodies it opens unreadable in every
//! copy and no order can put them back. Without something arbitrating, whichever obligation was
//! executed first won, and the loser was discovered afterwards or not at all.
//!
//! **A hold is placed on a subject, and that is not an arbitrary choice.** The mechanism both
//! obligations use is key destruction, and keys are per subject and per epoch. A hold that could
//! not be reduced to "these keys survive" would be a label with nothing behind it — which is the
//! criticism this module exists to answer. So a hold names a subject, which is exactly what
//! [`erase`](crate::erase) and [`retain`](crate::retain) can each decline to touch.
//!
//! A hold is nevertheless *placed* in whichever vocabulary the order arrived in.
//! [`place_over_record`] takes a record identifier, reads the subjects that record names, and holds
//! those — because "preserve everything about this matter" is how a preservation order is written,
//! and because holding a record without holding the keys its body depends on would preserve a file
//! nothing can read. Records are immutable, so resolving once at placement cannot go stale.
//!
//! Several holds may stand over one subject, each with its own identifier, reason and author. That
//! is the point of identifiers: a litigation hold lifting must not release the AML hold beside it.
//! A subject is held while any hold over it is unreleased.
//!
//! **Where a hold lives, and what that costs.** [`layout::HOLD_LOG`] under the memory root,
//! append-only, and [`crate::backup::MANIFEST`] carries it. It travels because the obligation
//! travels: a hold that a restore dropped would be a preservation order silently lifted by a
//! disaster recovery, and the store would then erase or retain exactly what it was told to keep.
//! The cost is a plaintext, never-pruned file naming held subjects — the same residue class as
//! [`crate::erase`]'s tombstone log, which sits beside it and is priced in
//! [`crate::erase::Tombstone::records`]. It is deliberately *not* a record: nothing under
//! `records/` is what this writes, so unlike a record body it never enters the full-text index.
//!
//! A release is a second line rather than an edit of the first, for the reason a completed
//! tombstone is: a hold that can be rewritten is a hold that can be unwritten, and the question an
//! auditor asks is not only what is held now but what was held then, and who lifted it.

use std::collections::BTreeMap;
use std::fs;

use serde::{Deserialize, Serialize};
use yaam_contract::{RecordId, SubjectHash};
use yaam_md::Document;

use crate::{Pipeline, Result, fsutil, layout};

/// Prefix every hold identifier carries.
///
/// Prefixed for the reason a tombstone identifier is: the two logs are read side by side, and an
/// identifier that could be mistaken for the other kind would be.
pub const HOLD_PREFIX: &str = "hold-";

/// What one line of the hold log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    /// The hold begins.
    Placed,
    /// The hold ends. Only the identifier, the actor and the reason are meaningful.
    Released,
}

/// One line of the append-only hold log.
///
/// Every field a line has ever carried is optional on the way in, for the reason the tombstone log
/// gives: this file is never rewritten, so lines written by older builds are read by newer ones for
/// as long as the store exists, and a reader that refused them would refuse the oldest holds first.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    /// Identifier the hold is released and reported under.
    #[serde(rename = "hold_id")]
    id: String,
    /// Whether this line places the hold or ends it.
    event: Event,
    /// The held subject's pseudonym. Carried on both lines so a release can be read alone.
    subject: String,
    /// When this line was written, in milliseconds since the Unix epoch.
    at_ms: i64,
    /// Why. Refused empty: a hold nobody can account for is one nobody dares lift.
    reason: String,
    /// Who placed or lifted it.
    operator: String,
    /// Records the hold was placed over, where it was placed over records.
    #[serde(default)]
    records: Vec<String>,
}

/// A hold standing over one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    /// Its identifier, as [`HOLD_PREFIX`] followed by a ULID.
    pub id: String,
    /// Whose keys it preserves.
    pub subject: SubjectHash,
    /// When it was placed, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// Why it was placed.
    pub reason: String,
    /// Who placed it.
    pub operator: String,
    /// Records it was placed over, empty where it was placed on the subject directly.
    pub records: Vec<String>,
}

/// Places a hold over one subject's keys.
///
/// The subject need not be one this store has ever heard of. A preservation order can arrive before
/// the records it covers, and a hold that could only be placed over a subject already on record
/// would be unplaceable exactly when it is most needed — a late-arriving record would then mint a
/// key nothing was protecting.
pub fn place(
    pipeline: &Pipeline,
    subject: &SubjectHash,
    reason: &str,
    operator: &str,
    records: &[RecordId],
) -> Result<Hold> {
    let reason = stated(
        reason,
        "a hold has to say why: a hold nobody can account for is a hold nobody dares lift",
    )?;
    let operator = stated(operator, "a hold has to name who placed it")?;
    let hold = Hold {
        id: format!("{HOLD_PREFIX}{}", RecordId::generate().as_str()),
        subject: subject.clone(),
        at_ms: fsutil::now_ms(),
        reason: reason.to_owned(),
        operator: operator.to_owned(),
        records: records
            .iter()
            .map(|record| record.as_str().to_owned())
            .collect(),
    };
    append(pipeline, &placement(&hold))?;
    Ok(hold)
}

/// Places a hold over every subject one record names.
///
/// The vocabulary a preservation order actually arrives in, reduced at placement to the thing that
/// can be enforced. One hold per subject rather than one hold naming several, so lifting the order
/// on one person's data does not lift it on another's.
///
/// A record naming no subject is refused rather than held vacuously: its body is not gated by any
/// key, so no destruction this store performs can reach it, and a hold saying otherwise would be an
/// obligation an operator believed was in force.
pub fn place_over_record(
    pipeline: &Pipeline,
    record: &RecordId,
    reason: &str,
    operator: &str,
) -> Result<Vec<Hold>> {
    let Some(path) = pipeline.locate_records()?.remove(record.as_str()) else {
        return Err(crate::pipeline::invalid(format!(
            "no record `{}` is in this tree, so nothing can be read out of it to hold",
            record.as_str()
        )));
    };
    let document = Document::parse(&fs::read_to_string(&path)?)?;
    let mut subjects: Vec<SubjectHash> = document
        .record
        .subjects
        .iter()
        .map(|subject| subject.hash.clone())
        .collect();
    subjects.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    subjects.dedup();
    if subjects.is_empty() {
        return Err(crate::pipeline::invalid(format!(
            "record `{}` names no subject, so no key gates its body and no hold here would \
             preserve anything",
            record.as_str()
        )));
    }

    let over = [record.clone()];
    subjects
        .iter()
        .map(|subject| place(pipeline, subject, reason, operator, &over))
        .collect()
}

/// Lifts one hold.
///
/// By identifier, never by subject: releasing "the hold on this subject" would lift every hold over
/// them, and the whole reason holds have identifiers is that a litigation hold lifting must not lift
/// the AML hold beside it.
///
/// A hold already released is refused rather than released again. The second release would be a
/// line in the log attributing a lift to somebody who lifted nothing.
pub fn release(pipeline: &Pipeline, id: &str, reason: &str, operator: &str) -> Result<Hold> {
    let reason = stated(
        reason,
        "a release has to say why: the log is what an auditor reads to see who lifted an obligation, and on what grounds",
    )?;
    let operator = stated(operator, "a release has to name who lifted it")?;
    let (placed, released) = read(pipeline)?;
    let Some(hold) = placed.get(id) else {
        return Err(crate::pipeline::invalid(format!(
            "no hold `{id}` is on record, so nothing here is holding anything"
        )));
    };
    if released.contains_key(id) {
        return Err(crate::pipeline::invalid(format!(
            "hold `{id}` was already released, and releasing it again would attribute a lift to \
             somebody who lifted nothing"
        )));
    }
    append(
        pipeline,
        &Line {
            id: hold.id.clone(),
            event: Event::Released,
            subject: hold.subject.as_str().to_owned(),
            // This line's own instant and author, not the placement's: what an auditor asks of a
            // release is who lifted the obligation and when, and copying the placement's fields
            // here would answer with the person who imposed it.
            at_ms: fsutil::now_ms(),
            reason: reason.to_owned(),
            operator: operator.to_owned(),
            records: Vec::new(),
        },
    )?;
    Ok(hold.clone())
}

/// Every hold standing over anything, oldest first.
///
/// What answers "what is currently held". A hold nobody can enumerate is a hold that will be
/// forgotten, and a forgotten hold is worse than none: it blocks an erasure an operator cannot
/// explain, or it lapses without anybody noticing that the obligation did not.
pub fn standing(pipeline: &Pipeline) -> Result<Vec<Hold>> {
    let (placed, released) = read(pipeline)?;
    let mut holds: Vec<Hold> = placed
        .into_values()
        .filter(|hold| !released.contains_key(&hold.id))
        .collect();
    holds.sort_by_key(|hold| (hold.at_ms, hold.id.clone()));
    Ok(holds)
}

/// The holds standing over one subject, oldest first.
pub fn standing_for(pipeline: &Pipeline, subject: &SubjectHash) -> Result<Vec<Hold>> {
    Ok(standing(pipeline)?
        .into_iter()
        .filter(|hold| hold.subject == *subject)
        .collect())
}

/// Refuses a destruction while anything holds the subject.
///
/// The one call both obligations make. It is a refusal rather than a boolean because the answer an
/// operator needs is not "no" but "no, because of this hold, placed by this person, on these
/// grounds, and here is what to release" — and a predicate at the call site is a message each
/// caller words differently.
pub fn refuse_if_held(pipeline: &Pipeline, subject: &SubjectHash) -> Result<()> {
    let holds = standing_for(pipeline, subject)?;
    if holds.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "held: {} hold(s) stand over subject {}, and destroying its keys would make bodies \
         unreadable that this store has been ordered to preserve. Nothing was destroyed.",
        holds.len(),
        subject.as_str()
    );
    for hold in &holds {
        let _ = std::fmt::Write::write_fmt(
            &mut message,
            format_args!(
                "\n  {} placed {} by `{}`: {}",
                hold.id,
                yaam_contract::timestamp::format_ms(hold.at_ms),
                hold.operator,
                hold.reason
            ),
        );
        if !hold.records.is_empty() {
            let _ = std::fmt::Write::write_fmt(
                &mut message,
                format_args!(" (over {})", hold.records.join(", ")),
            );
        }
    }
    message.push_str(
        "\nRelease it first if the obligation has ended: `yaam hold release --hold <id> --reason \
         … --operator …`. Two obligations point in opposite directions here, and only a person can \
         say which one now applies.",
    );
    Err(crate::Error::Held(message))
}

/// The log, split into what was placed and what was released, by identifier.
///
/// A line that will not parse is skipped and logged, for the reason the tombstone log's reader
/// skips one: the file is append-only, so a torn last line from an interrupted write is the one
/// corruption to expect, and refusing the whole log over it would leave every hold unreadable —
/// which on this file means every hold silently unenforced.
fn read(pipeline: &Pipeline) -> Result<(BTreeMap<String, Hold>, BTreeMap<String, i64>)> {
    let path = pipeline.root().join(layout::HOLD_LOG);
    let mut placed = BTreeMap::new();
    let mut released = BTreeMap::new();
    let Some(text) = fsutil::read_to_string_opt(&path)? else {
        return Ok((placed, released));
    };
    for text in text.lines().filter(|line| !line.trim().is_empty()) {
        let line: Line = match serde_json::from_str(text) {
            Ok(line) => line,
            Err(error) => {
                tracing::warn!(%error, "unreadable hold line skipped");
                continue;
            }
        };
        match line.event {
            Event::Placed => {
                let subject = SubjectHash::parse(&line.subject)?;
                placed.insert(
                    line.id.clone(),
                    Hold {
                        id: line.id,
                        subject,
                        at_ms: line.at_ms,
                        reason: line.reason,
                        operator: line.operator,
                        records: line.records,
                    },
                );
            }
            Event::Released => {
                released.insert(line.id, line.at_ms);
            }
        }
    }
    Ok((placed, released))
}

/// The log line that places a hold.
fn placement(hold: &Hold) -> Line {
    Line {
        id: hold.id.clone(),
        event: Event::Placed,
        subject: hold.subject.as_str().to_owned(),
        at_ms: hold.at_ms,
        reason: hold.reason.clone(),
        operator: hold.operator.clone(),
        records: hold.records.clone(),
    }
}

/// Appends one line to the hold log, durably.
///
/// Same durability as the tombstone log's append, and for the same reason: a hold that reached no
/// platter is an obligation the next crash lifts.
fn append(pipeline: &Pipeline, entry: &Line) -> Result<()> {
    let text = serde_json::to_string(entry).map_err(|e| crate::pipeline::invalid(e.to_string()))?;
    let path = pipeline.root().join(layout::HOLD_LOG);
    fsutil::append_line_sync(&path, &text)?;
    fsutil::sync_dir(fsutil::parent_of(&path)?)?;
    Ok(())
}

/// A field refused empty, with the sentence saying what is missing.
fn stated<'a>(value: &'a str, missing: &str) -> Result<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(crate::pipeline::invalid(missing.to_owned()));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use yaam_contract::RecordId;
    use yaam_crypto::keystore::KeyStore as _;
    use yaam_md::Body;

    use super::{place, place_over_record, refuse_if_held, release, standing, standing_for};
    use crate::testkit::{self, BODY, Harness};

    /// A server time inside the epoch the fixtures use.
    const T11: &str = "2026-08-22T11:00:00Z";

    /// A store holding one sealed record about one subject.
    fn with_sealed_record() -> (Harness, yaam_contract::SubjectHash, RecordId) {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        let record = testkit::subject_derived(T11, std::slice::from_ref(&subject));
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");
        (harness, subject, id)
    }

    /// An erasure under a hold destroys nothing, and says which hold stopped it.
    ///
    /// The arbitration, from the erasure side, and the one direction where getting it wrong cannot
    /// be undone. A refusal that came halfway through would have refused nothing: the tombstone is
    /// replayed by every rebuild, so a log line written before the refusal would re-erase the
    /// subject on the next rebuild whatever the hold said. So this asserts the whole store is
    /// untouched — no log line, the key still there, the body still sealed — and not merely that a
    /// failure came back.
    #[test]
    fn an_erasure_is_refused_while_a_hold_stands_and_destroys_nothing() {
        let (mut harness, subject, record) = with_sealed_record();
        harness.pipeline.drain_fanout(100).expect("drained");
        let hold = place(
            &harness.pipeline,
            &subject,
            "litigation hold on an open matter",
            "operator_a",
            &[],
        )
        .expect("placed");

        let error = crate::erase::erase_subject(&mut harness.pipeline, &subject)
            .expect_err("a hold outranks an erasure");
        assert!(
            matches!(error, crate::Error::Held(_)),
            "its own failure, so `/erase` can answer 409 rather than 422 or 500: {error:?}"
        );
        let said = error.to_string();
        for expected in [
            hold.id.as_str(),
            "litigation hold on an open matter",
            "operator_a",
            "yaam hold release",
        ] {
            assert!(
                said.contains(expected),
                "a refusal that does not say why is one nobody can act on; missing \
                 `{expected}`: {said}"
            );
        }

        // Nothing moved. Every one of these would have been changed by an erasure that got as far
        // as its first write.
        assert!(
            crate::erase::read_log(&harness.pipeline)
                .expect("log")
                .is_empty(),
            "no tombstone line, so no rebuild will replay an erasure that was refused"
        );
        assert!(
            !harness
                .pipeline
                .keys()
                .is_tombstoned(&subject)
                .expect("ask")
        );
        assert_eq!(
            crate::erase::preview(&harness.pipeline, &subject)
                .expect("preview")
                .keys,
            1,
            "the key the hold preserves is still there"
        );
        let path = harness.pipeline.locate_records().expect("locate")[record.as_str()].clone();
        let document = yaam_md::Document::parse(&std::fs::read_to_string(&path).expect("read"))
            .expect("parse");
        assert!(
            matches!(document.body, Body::Sealed(_)),
            "and the body it preserves is still sealed"
        );

        // The preview says so too, before any confirmation is asked for.
        assert_eq!(
            crate::erase::preview(&harness.pipeline, &subject)
                .expect("preview")
                .holds,
            vec![hold.clone()]
        );

        // Released, the erasure goes through: a hold delays a destruction, it does not exempt.
        release(&harness.pipeline, &hold.id, "matter closed", "operator_a").expect("released");
        crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("no longer held");
        assert!(
            harness
                .pipeline
                .keys()
                .is_tombstoned(&subject)
                .expect("ask")
        );
    }

    /// Several holds may stand over one subject, and lifting one does not lift the other.
    ///
    /// The whole reason holds carry identifiers. A litigation hold ending must not release the AML
    /// hold beside it, and a release keyed by subject could not tell them apart.
    #[test]
    fn holds_are_lifted_one_at_a_time_and_the_subject_stays_held_while_any_stands() {
        let harness = Harness::new();
        let subject = testkit::subject('a');
        let litigation = place(
            &harness.pipeline,
            &subject,
            "litigation hold",
            "operator_a",
            &[],
        )
        .expect("placed");
        let aml =
            place(&harness.pipeline, &subject, "aml hold", "operator_b", &[]).expect("placed");

        assert_eq!(
            standing_for(&harness.pipeline, &subject)
                .expect("read")
                .len(),
            2
        );
        release(
            &harness.pipeline,
            &litigation.id,
            "matter closed",
            "operator_a",
        )
        .expect("released");

        let left = standing_for(&harness.pipeline, &subject).expect("read");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, aml.id);
        assert!(
            refuse_if_held(&harness.pipeline, &subject).is_err(),
            "one obligation remains, so the subject is still held"
        );

        release(
            &harness.pipeline,
            &aml.id,
            "reporting period closed",
            "operator_b",
        )
        .expect("released");
        assert!(standing(&harness.pipeline).expect("read").is_empty());
        refuse_if_held(&harness.pipeline, &subject).expect("nothing holds it now");
    }

    /// A hold placed over a record holds the subjects its body depends on.
    ///
    /// The vocabulary a preservation order arrives in, reduced at placement to the thing that can be
    /// enforced. Holding the record alone would preserve a file nothing can read.
    #[test]
    fn a_hold_over_a_record_holds_every_subject_that_record_names() {
        let mut harness = Harness::new();
        let subjects = [testkit::subject('a'), testkit::subject('b')];
        let record = testkit::subject_derived(T11, &subjects);
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");

        let placed = place_over_record(&harness.pipeline, &id, "preservation order", "operator_a")
            .expect("placed");
        assert_eq!(
            placed.len(),
            2,
            "one hold per subject, so one can be lifted"
        );
        for hold in &placed {
            assert_eq!(hold.records, vec![id.as_str().to_owned()]);
            assert!(refuse_if_held(&harness.pipeline, &hold.subject).is_err());
        }

        // A record nothing knows about, and one whose body no key gates: both refused rather than
        // held vacuously, because a hold that preserves nothing is an obligation somebody believes
        // is in force.
        assert!(
            place_over_record(
                &harness.pipeline,
                &RecordId::generate(),
                "preservation order",
                "operator_a"
            )
            .is_err()
        );
        let internal = testkit::internal(T11);
        let internal_id = internal.record_id.clone();
        harness.pipeline.accept(internal, BODY).expect("accepted");
        let error = place_over_record(
            &harness.pipeline,
            &internal_id,
            "preservation order",
            "operator_a",
        )
        .expect_err("names no subject");
        assert!(error.to_string().contains("names no subject"), "{error}");
    }

    /// A hold has to say why and who, and cannot be lifted twice or by the wrong name.
    ///
    /// Both fields are the whole value of the log. A hold nobody can account for is one nobody
    /// dares lift, and a release attributed to nobody is an obligation that ended for no stated
    /// reason.
    #[test]
    fn a_hold_without_a_reason_or_an_author_is_refused_and_so_is_a_second_release() {
        let harness = Harness::new();
        let subject = testkit::subject('a');
        for (reason, operator) in [("", "operator_a"), ("  ", "operator_a"), ("a reason", " ")] {
            let error =
                place(&harness.pipeline, &subject, reason, operator, &[]).expect_err("refused");
            assert!(error.to_string().contains("has to"), "{error}");
        }

        let hold =
            place(&harness.pipeline, &subject, "a reason", "operator_a", &[]).expect("placed");
        for (reason, operator) in [("", "operator_a"), ("a reason", "")] {
            assert!(release(&harness.pipeline, &hold.id, reason, operator).is_err());
        }
        release(&harness.pipeline, &hold.id, "closed", "operator_a").expect("released");
        let again = release(&harness.pipeline, &hold.id, "closed", "operator_a")
            .expect_err("already released");
        assert!(again.to_string().contains("already released"), "{again}");
        let unknown = release(&harness.pipeline, "hold-nothing", "closed", "operator_a")
            .expect_err("no such hold");
        assert!(unknown.to_string().contains("no hold"), "{unknown}");
    }

    /// A hold can be placed over a subject this store has never heard of.
    ///
    /// A preservation order can arrive before the records it covers. A hold placeable only over a
    /// subject already on record would be unplaceable exactly when it matters most, and the next
    /// record to arrive would mint a key nothing was protecting.
    #[test]
    fn a_subject_this_store_has_never_seen_can_still_be_held() {
        let harness = Harness::new();
        let stranger = testkit::subject('c');
        let hold = place(
            &harness.pipeline,
            &stranger,
            "order naming a person no record here mentions yet",
            "operator_a",
            &[],
        )
        .expect("placed");
        assert_eq!(standing(&harness.pipeline).expect("read"), vec![hold]);
    }

    /// A torn last line leaves the rest of the log readable.
    ///
    /// Append-only, so an interrupted write is the one corruption to expect. Refusing the whole log
    /// over it would mean every hold silently unenforced, which is the opposite of what a hold is
    /// for.
    #[test]
    fn an_unreadable_line_does_not_take_the_rest_of_the_log_with_it() {
        let harness = Harness::new();
        let subject = testkit::subject('a');
        let hold =
            place(&harness.pipeline, &subject, "a reason", "operator_a", &[]).expect("placed");

        let path = harness.root().join(crate::layout::HOLD_LOG);
        let mut text = std::fs::read_to_string(&path).expect("read");
        text.push_str("{\"hold_id\":\"hold-torn\",\n");
        std::fs::write(&path, text).expect("write");

        assert_eq!(standing(&harness.pipeline).expect("read"), vec![hold]);
    }
}
