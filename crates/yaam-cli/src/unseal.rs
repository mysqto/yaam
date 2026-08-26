//! The one command that prints a record body.
//!
//! Its own module rather than an eighth report in [`crate::ops`], because everything that can put
//! customer plaintext on a terminal is in this file and there is nowhere else to look. That is worth
//! a module boundary on its own: the property being kept is negative — no *other* path returns a
//! sealed body — and a negative property is only checkable where the positive one is in one place.
//!
//! Thin for the reason [`crate::ops`] is thin. What may be read, in what order the reading is
//! recorded, and what an unreadable body is called are all [`yaam_core::unseal`]'s judgements. What
//! is here is the confirmation flag, the prose an operator reads, and the exit code a script reads.
//!
//! The register is `erase`'s, deliberately. Both commands are irreversible in the way that matters:
//! an erasure cannot be undone, and a body that has been read cannot be unread — the audit record
//! naming the operator who read it is permanent, and so is whatever they do with what they saw. So
//! both print what the operation would reach and stop, and both take a flag that says the operator
//! meant it.

use std::fmt::Write as _;
use std::io::Write;

use yaam_contract::RecordId;
use yaam_core::Pipeline;
use yaam_core::unseal::{self, AUDIT_ACTION, Erasure, Held, Read};

use crate::error::{Error, Result, config, failed};
use crate::exit::Exit;
use crate::ops::{emit, line};

/// What the audit record is, said wherever a read is offered or refused.
///
/// Repeated at the point of action rather than left to the documentation, because an operator about
/// to be named in a permanent record is owed the sentence before they confirm, not after.
const RECORDED: &str = "the read is recorded first: one record with `action: unseal` and \
     `visibility: operator`, naming the operator and the reason, published and indexed before a key \
     is fetched. A store that cannot record the read cannot answer it, which is the whole ordering — \
     an audit record written afterwards is one a full disk turns into a body nobody can tell was \
     read.";

/// What survives a read, said where the body is handed over.
const RETAINED_TRAIL: &str = "the audit record is internal and names no subject, so no erasure \
     reaches it: a trail a data subject could destroy is a trail that disappears exactly when \
     somebody asks who read their data before it went.";

/// Reads one record's sealed body, once the operator has said so explicitly.
///
/// Without `confirmed` this prints what the read would reach and stops, for the reason `erase` does:
/// a confirmation over a 26-character identifier nobody can read at a glance is not a check, and a
/// statement of whose keys are about to be used is.
///
/// [`Exit::Rejected`] for every answer that is not a body — a record that is not here, a body that
/// was never sealed, keys that are gone. All three are permanent as asked: retrying changes nothing,
/// and the report says which of them it was, because "gone for ever" and "identifier mistyped" call
/// for opposite next moves and an empty answer would look the same either way.
pub fn unseal(
    pipeline: &mut Pipeline,
    record: &str,
    operator: &str,
    reason: &str,
    confirmed: bool,
    out: &mut dyn Write,
) -> Result<Exit> {
    let record = RecordId::parse(record).map_err(|error| {
        config(format!(
            "--record is not a record identifier: {error}. It is the 26-character ULID a record is \
             filed under"
        ))
    })?;

    if !confirmed {
        let held = unseal::inspect(pipeline, &record)
            .map_err(|error| failed("reading what this record holds", &error))?;
        let mut text = describe_held(&record, &held, operator);
        text.push_str("\nnothing was read. Pass --confirm-read-body to mean it.\n");
        emit(out, &text)?;
        return Err(Error::Unconfirmed(
            "a read of a sealed body is permanently recorded and was not confirmed".to_owned(),
        ));
    }

    let read = unseal::read_body(pipeline, &record, operator, reason)
        .map_err(|error| failed("reading the sealed body", &error))?;
    let (text, exit) = describe_read(&record, &read);
    emit(out, &text)?;
    Ok(exit)
}

/// What a read would reach, as an operator has to read it before confirming.
fn describe_held(record: &RecordId, held: &Held, operator: &str) -> String {
    let mut text = String::new();
    match held {
        Held::Sealed {
            subjects,
            epoch,
            ciphertext_bytes,
            erasures,
        } => {
            let _ = writeln!(text, "reading the body of {} would:", record.as_str());
            line(&mut text, "ciphertext bytes", *ciphertext_bytes);
            line(&mut text, "keys needed", subjects.len());
            let _ = writeln!(text, "  {:<20}{epoch}", "epoch");
            for subject in subjects {
                let _ = writeln!(text, "  {:<20}{}", "subject", subject.as_str());
            }
            let _ = writeln!(text, "  {:<20}{operator}", "recorded against");
            if erasures.is_empty() {
                text.push_str(
                    "every one of those keys is needed to open the body, so the read stops \
                     answering for ever the moment any one of those subjects is erased.\n",
                );
                text.push_str(RECORDED);
                text.push('\n');
            } else {
                text.push_str(
                    "and it would answer nothing: a key this body needs has already been \
                     destroyed.\n",
                );
                describe_erasures(&mut text, erasures);
            }
        }
        Held::Plain => text.push_str(&plain_body(record)),
        Held::Shredded { subjects, erasures } => {
            let _ = writeln!(
                text,
                "reading the body of {} would answer nothing. It is already gone:",
                record.as_str()
            );
            for subject in subjects {
                let _ = writeln!(text, "  {:<20}{}", "subject named", subject.as_str());
            }
            describe_erasures(&mut text, erasures);
        }
        Held::Absent { archived } => text.push_str(&absent(record, *archived)),
    }
    text
}

/// What a finished read found, and what a script should make of it.
fn describe_read(record: &RecordId, read: &Read) -> (String, Exit) {
    match read {
        Read::Revealed { body, audit } => {
            let mut text = format!("read the body of {}\n", record.as_str());
            let _ = writeln!(text, "  {:<20}{}", "recorded as", audit.as_str());
            let _ = writeln!(text, "  {:<20}{AUDIT_ACTION}", "audit action");
            text.push_str(RETAINED_TRAIL);
            text.push_str("\n\nthe body follows, between the markers.\n");
            let _ = writeln!(text, "----- body of {} -----", record.as_str());
            text.push_str(body);
            if !body.ends_with('\n') {
                text.push('\n');
            }
            text.push_str("----- end -----\n");
            (text, Exit::Ok)
        }
        Read::Shredded {
            subjects,
            erasures,
            audit,
        } => {
            let mut text = format!("{}: its body is gone for ever\n", record.as_str());
            for subject in subjects {
                let _ = writeln!(text, "  {:<20}{}", "subject named", subject.as_str());
            }
            describe_erasures(&mut text, erasures);
            match audit {
                // The attempt reached the key store, so it is on the record whether or not it
                // answered. Said out loud because the operator's name is now in a permanent record
                // beside a read that returned nothing, and finding that out later reads as a bug.
                Some(audit) => {
                    let _ = writeln!(
                        text,
                        "the attempt is recorded as {}: the key store was asked, and an audit trail \
                         that hid the answered-nothing attempts would be one nobody could reconcile.",
                        audit.as_str()
                    );
                }
                None => text.push_str(
                    "nothing was recorded, because nothing was read: the refusal is made from \
                     frontmatter and the erasure log, and no key was reached for.\n",
                ),
            }
            (text, Exit::Rejected)
        }
        Read::Plain => (
            format!(
                "{}: its body is not sealed\n{}",
                record.as_str(),
                plain_body(record)
            ),
            Exit::Rejected,
        ),
        Read::Absent { archived } => (
            format!(
                "{}: no such record in this tree\n{}",
                record.as_str(),
                absent(record, *archived)
            ),
            Exit::Rejected,
        ),
    }
}

/// The erasures that account for a body being unreadable, or the honest absence of any.
///
/// An empty list is the interesting case and is never left silent: a body whose key is gone with no
/// erasure behind it is a key store that came back short of the tree it belongs to, which is an
/// operator's problem and not a data subject's right being exercised.
fn describe_erasures(text: &mut String, erasures: &[Erasure]) {
    if erasures.is_empty() {
        text.push_str(
            "no erasure in the log accounts for it. A key that is absent with nothing having \
             ordered its destruction is a key store restored short of the tree beside it — recover \
             the key store from its own copy, because the bodies are readable only where their keys \
             are.\n",
        );
        return;
    }
    for erasure in erasures {
        let _ = match &erasure.tombstone {
            Some(tombstone) => writeln!(
                text,
                "  {:<20}{} under {tombstone}",
                "erased",
                erasure.subject.as_str()
            ),
            None => writeln!(
                text,
                "  {:<20}{}, on the key store's own tombstone, with nothing in the erasure log \
                 naming it",
                "erased",
                erasure.subject.as_str()
            ),
        };
    }
    text.push_str(
        "no key exists to read this body, in this store or in any copy of it, and none can be \
         minted again: the subject is tombstoned. That is the erasure working, not a fault. The \
         record itself is retained — frontmatter, attributes, entity references and timelines — so \
         the store still answers that this subject was named, when, and about what.\n",
    );
    if erasures.iter().any(|erasure| erasure.tombstone.is_some()) {
        text.push_str(
            "`yaam verify-erasure --tombstone …` reports whether that erasure can yet be asserted \
             complete.\n",
        );
    }
}

/// Why a plaintext body is not this command's to print.
fn plain_body(record: &RecordId) -> String {
    format!(
        "the body of {} is plaintext in the tree, so no key gates it and no key was used. It is not \
         printed here: a body this command handed back without an audit record would be a second, \
         unrecorded way to read one, and the trail would stop meaning what it says. Read it through \
         the service, which enforces the caller's own visibility, or open the record file.\n",
        record.as_str()
    )
}

/// What an identifier the tree does not carry means, which depends on whether an archive does.
fn absent(record: &RecordId, archived: bool) -> String {
    if archived {
        return format!(
            "a cold manifest names {}, so it was archived out of this tree. A manifest carries \
             structure and no body: the ciphertext left with the archive, and reading it means \
             restoring that archive first.\n",
            record.as_str()
        );
    }
    format!(
        "nothing in this store's tree carries {}. Check the identifier before reading anything into \
         this: a record that was never written and one whose identifier was mistyped look the same \
         from here.\n",
        record.as_str()
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use yaam_contract::{RecordId, SubjectHash};
    use yaam_core::{Paths, Pipeline};

    use super::unseal;
    use crate::exit::Exit;
    use crate::fixtures::{self, BODY};

    /// A tree with this repository's spec, one sealed record in it, and the pipeline over it.
    struct Tree {
        _dir: tempfile::TempDir,
        pipeline: Pipeline,
        subject: SubjectHash,
        record: RecordId,
    }

    impl Tree {
        /// A store holding one sealed record about one subject.
        fn sealed() -> Self {
            let dir = fixtures::tree();
            let mut pipeline =
                Pipeline::with_paths(Paths::under(dir.path())).expect("a pipeline over the tree");
            let subject = fixtures::subject('a');
            let record = fixtures::subject_record("2026-08-20T09:00:00Z", &subject);
            let id = record.record_id.clone();
            pipeline.accept(record, BODY).expect("accepted");
            Self {
                _dir: dir,
                pipeline,
                subject,
                record: id,
            }
        }
    }

    /// How many audit records the tree holds, counted from the files themselves.
    ///
    /// The frontmatter rather than the index, because the claim is that the reading is on disk: an
    /// index row is derived and a rebuild would put it back from these files anyway.
    fn audit_records_in(dir: &std::path::Path) -> usize {
        let mut found = 0;
        for entry in fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                found += audit_records_in(&path);
            } else if fs::read_to_string(&path)
                .expect("read")
                .contains("action: unseal")
            {
                found += 1;
            }
        }
        found
    }

    /// The text a read printed, and what it exited with.
    fn run(tree: &mut Tree, record: &str, confirmed: bool) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = unseal(
            &mut tree.pipeline,
            record,
            "operator_a",
            "a data subject asked what is retained",
            confirmed,
            &mut out,
        )
        .expect("the command ran");
        (exit, String::from_utf8(out).expect("utf-8"))
    }

    /// An unconfirmed read prints whose keys it would use and reads nothing.
    ///
    /// The half of the register `erase` establishes: the operator sees what the read costs — a
    /// permanent record with their name on it — before it costs it.
    #[test]
    fn an_unconfirmed_read_previews_and_reads_nothing() {
        let mut tree = Tree::sealed();
        let mut out = Vec::new();
        let error = unseal(
            &mut tree.pipeline,
            tree.record.as_str(),
            "operator_a",
            "a reason",
            false,
            &mut out,
        )
        .expect_err("an unconfirmed read must not act");
        assert_eq!(error.exit(), Exit::Unconfirmed);

        let printed = String::from_utf8(out).expect("utf-8");
        assert!(printed.contains("keys needed         1"), "{printed}");
        assert!(printed.contains(tree.subject.as_str()), "{printed}");
        assert!(printed.contains("epoch               2026-Q3"), "{printed}");
        assert!(
            printed.contains("recorded against    operator_a"),
            "who the record will name has to be visible before it is written: {printed}"
        );
        assert!(printed.contains("--confirm-read-body"), "{printed}");
        assert!(
            !printed.contains(BODY),
            "a preview that printed the body would be an unrecorded read: {printed}"
        );
    }

    /// A confirmed read prints the body, and names the record that says it did.
    #[test]
    fn a_confirmed_read_prints_the_body_between_markers_and_names_its_audit_record() {
        let mut tree = Tree::sealed();
        let id = tree.record.as_str().to_owned();
        let (exit, printed) = run(&mut tree, &id, true);
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains(BODY), "{printed}");
        assert!(printed.contains("----- end -----"), "{printed}");

        let audit = printed
            .lines()
            .find_map(|line| line.trim().strip_prefix("recorded as         "))
            .expect("the report names the audit record")
            .to_owned();
        assert!(
            RecordId::parse(&audit).is_ok(),
            "the audit record has to be nameable to be readable: {audit}"
        );
        // And it is in the tree, where an operator-scoped read finds it.
        assert_eq!(
            audit_records_in(&tree.pipeline.paths().root.join("records")),
            1,
            "one reading, one record"
        );
    }

    /// An erased subject's record is refused with the reason, not with an empty answer.
    ///
    /// The failure this is here to prevent: an operator reading "nothing found" and opening an
    /// incident about a missing record, when the store is doing exactly what it promised a data
    /// subject it would do.
    #[test]
    fn a_read_of_an_erased_body_says_it_is_gone_for_ever_and_names_the_erasure() {
        let mut tree = Tree::sealed();
        let subject = tree.subject.clone();
        let id = tree.record.as_str().to_owned();
        let report = yaam_core::erase::erase_subject(&mut tree.pipeline, &subject).expect("erased");

        let (exit, printed) = run(&mut tree, &id, true);
        assert_eq!(exit, Exit::Rejected, "{printed}");
        assert!(printed.contains("gone for ever"), "{printed}");
        assert!(printed.contains(&report.tombstone_id), "{printed}");
        assert!(printed.contains("verify-erasure"), "{printed}");
        assert!(
            printed.contains("is retained"),
            "what survives an erasure has to be said here too: {printed}"
        );
        assert!(
            printed.contains("nothing was recorded"),
            "no key was reached for, and the report says so: {printed}"
        );
        assert!(!printed.contains(BODY), "{printed}");
    }

    /// The preview of a read that cannot answer says so, rather than describing a body it would get.
    ///
    /// An operator previewing an erased record must not be told what the read would cost and left to
    /// find out it would cost nothing: the confirmation is worth asking for only where there is
    /// something to confirm.
    #[test]
    fn an_unconfirmed_read_of_an_erased_record_says_it_would_answer_nothing() {
        let mut tree = Tree::sealed();
        let subject = tree.subject.clone();
        let id = tree.record.as_str().to_owned();
        yaam_core::erase::erase_subject(&mut tree.pipeline, &subject).expect("erased");

        let mut out = Vec::new();
        unseal(
            &mut tree.pipeline,
            &id,
            "operator_a",
            "a reason",
            false,
            &mut out,
        )
        .expect_err("unconfirmed either way");
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(printed.contains("would answer nothing"), "{printed}");
        assert!(printed.contains(subject.as_str()), "{printed}");

        // And an identifier the tree does not carry reads the same way before confirmation as after.
        let mut out = Vec::new();
        unseal(
            &mut tree.pipeline,
            RecordId::generate().as_str(),
            "operator_a",
            "a reason",
            false,
            &mut out,
        )
        .expect_err("unconfirmed");
        assert!(
            String::from_utf8(out).expect("utf-8").contains("mistyped"),
            "an unknown identifier is the likeliest reason to be here"
        );
    }

    /// A key store restored short of its tree is reported as that, and the attempt is on the record.
    ///
    /// The one unreadable body that is nobody's erasure: the ciphertext is there, no tombstone
    /// explains the missing key, and the remedy is recovering the key store rather than reading the
    /// erasure log. Calling it an erasure here would send an operator looking for a request nobody
    /// made.
    #[test]
    fn a_body_whose_key_is_missing_with_no_erasure_behind_it_says_which_of_the_two_it_is() {
        let mut tree = Tree::sealed();
        let subject = tree.subject.clone();
        let id = tree.record.as_str().to_owned();
        // The key files removed and nothing tombstoned: the key store this tree came back without.
        let keys = tree
            .pipeline
            .paths()
            .key_store
            .join("keys")
            .join(subject.as_str());
        fs::remove_dir_all(&keys).expect("a key store that did not come back with the tree");

        let (exit, printed) = run(&mut tree, &id, true);
        assert_eq!(exit, Exit::Rejected, "{printed}");
        assert!(printed.contains("no erasure in the log"), "{printed}");
        assert!(
            printed.contains("recover"),
            "the remedy is the key store's own copy, not the erasure log: {printed}"
        );
        assert!(
            printed.contains("the attempt is recorded as"),
            "the key store was asked, and the trail says so: {printed}"
        );
        assert!(!printed.contains(BODY), "{printed}");
    }

    /// A plaintext body is refused, and the refusal says where it is instead.
    #[test]
    fn a_read_of_a_body_no_key_gates_is_refused_rather_than_printed() {
        let dir = fixtures::tree();
        let mut pipeline =
            Pipeline::with_paths(Paths::under(dir.path())).expect("a pipeline over the tree");
        let record = fixtures::record("2026-08-20T09:00:00Z");
        let id = record.record_id.clone();
        pipeline.accept(record, BODY).expect("accepted");

        let mut out = Vec::new();
        let exit = unseal(
            &mut pipeline,
            id.as_str(),
            "operator_a",
            "a reason",
            true,
            &mut out,
        )
        .expect("an answer");
        let printed = String::from_utf8(out).expect("utf-8");
        assert_eq!(exit, Exit::Rejected, "{printed}");
        assert!(printed.contains("not sealed"), "{printed}");
        assert!(
            !printed.contains(BODY),
            "printing it here would be the second, unrecorded read path: {printed}"
        );
    }

    /// An identifier nothing carries is its own answer, and a malformed one never reaches the store.
    #[test]
    fn an_unknown_record_is_refused_and_a_malformed_identifier_is_a_config_error() {
        let mut tree = Tree::sealed();
        let (exit, printed) = run(&mut tree, RecordId::generate().as_str(), true);
        assert_eq!(exit, Exit::Rejected, "{printed}");
        assert!(printed.contains("no such record"), "{printed}");
        assert!(printed.contains("mistyped"), "{printed}");

        let mut out = Vec::new();
        let error = unseal(
            &mut tree.pipeline,
            "not-a-ulid",
            "operator_a",
            "a reason",
            true,
            &mut out,
        )
        .expect_err("refused before the store is read");
        assert_eq!(error.exit(), Exit::Config);
        assert!(out.is_empty(), "nothing was read, so nothing is reported");
    }

    /// A read nobody signed for is refused, and the store is left untouched.
    #[test]
    fn a_read_with_no_operator_named_is_refused() {
        let mut tree = Tree::sealed();
        let mut out = Vec::new();
        let error = unseal(
            &mut tree.pipeline,
            tree.record.as_str(),
            "   ",
            "a reason",
            true,
            &mut out,
        )
        .expect_err("an unattributable read must not happen");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("who read the body"), "{error}");
    }
}
