//! Which subject key a store's pseudonyms were derived from.
//!
//! [`SubjectKey`] cannot be rotated, and nothing about the wrong one is visible. The derivation is a
//! pure function, so a substitute key comes up clean, seals bodies, publishes records, and files a
//! second pseudonym for a reference already on record: no drift, no warning, and no repair, because
//! there is no re-key, no re-seal and no delete. The two pseudonym spaces then stay unrelated for as
//! long as the store exists. Everything else under the root can be rebuilt from the tree; this is
//! the one mistake a rebuild cannot reach, which is why it is worth a check of its own.
//!
//! So a store records *which* key it was armed with, as a value that is not the key:
//! [`KeyCheck`], one fixed-input HMAC under the subject key. A later open derives the value again
//! and compares. What that buys is the whole point — a wrong or truncated key becomes a refusal at
//! startup naming the problem, instead of a second pseudonym space nobody can see.
//!
//! # Where the record lives, and why in the tree
//!
//! [`layout::SUBJECT_CHECK_FILE`], directly under the memory root, classified by
//! [`crate::backup::MANIFEST`] as included. Three constraints leave one place:
//!
//! - **It has to survive a rebuild.** The index is derived and disposable — deleting it is a routine
//!   remedy — so a check value recorded there would be discarded by the operation an operator
//!   reaches for when something looks wrong.
//! - **It has to travel in a backup.** A restored tree carries pseudonyms derived from the key that
//!   wrote it. If the check value stayed behind, arming a restored store with a different key would
//!   be silent again, in exactly the situation where the key is most likely to be re-entered by hand.
//! - **It must not be in the key store.** That is the one entry a copy may never contain, which is
//!   what [`crate::backup`] rests on — so a check value kept there is one only the live store has.
//!
//! All of which requires the value not to be a secret, and it is not: a fixed-label HMAC reveals the
//! key no more than a pseudonym does. [`KeyCheck`] states the one thing it does cost, and why 32
//! bytes from a CSPRNG do not care.
//!
//! # What "armed" means here, given that nothing arms a store
//!
//! There is no arming command and no arming event. A store is armed by a declaration in
//! `spec/subjects.yaml` and a key handed to a process, both read afresh at every open. So the record
//! is written by the first open that finds none — [`Arming::Adopted`] — and checked by every open
//! after it.
//!
//! That is trust on first use, and the limit is worth stating plainly rather than implying more:
//! **adoption believes the key it is handed.** A store armed before this existed — records
//! published, no check value on file — takes the check value of whichever key its next open
//! presents. If that open is the deployment's own, every later one is checked against it. If it is a
//! substitute, the substitute is what gets recorded, and the store's real key becomes the one that
//! is refused. Adoption is therefore a warning in the startup log rather than a line to scroll past,
//! and it says the key was trusted rather than verified.
//!
//! The alternative — refusing to open a store that records nothing — was rejected. It would take
//! every already-armed deployment down at the upgrade meant to protect it, which is a worse failure
//! than the one being closed, and an operator's fastest way out of it would be to point the store at
//! a fresh key. A deployment that wants the record written *before* its key goes somewhere it might
//! be mistyped writes it by opening the store once with the key it is already running on; the check
//! value is in the log line, and comparing it afterwards is what makes the next entry of that key
//! verifiable rather than assumed.
//!
//! # What it does not prove
//!
//! - **Not that the key is the original one.** A check value and a key replaced together agree with
//!   each other. This detects a mistake, not somebody with write access to the root, and it has
//!   exactly the standing of `spec/`: configuration in the tree, trusted as far as the tree is.
//! - **Not that this key wrote the records already on file.** For an adopted store nothing here was
//!   compared against a pseudonym in the tree. The claim is "the same key as last time", and for a
//!   store armed before the check existed, last time begins at adoption.
//! - **Nothing at all about custody.** Whether the key is leaked, copied or held by one person is
//!   [`yaam_crypto::custody`]'s subject; a check value is the same either way.
//!
//! # Three outcomes, told apart
//!
//! A recorded value that does not match and one that cannot be read are different findings, and each
//! gets its own refusal: [`crate::Error::SubjectKeyMismatch`] says the key is wrong,
//! [`crate::Error::SubjectKeyCheckUnreadable`] says nothing can be said. Both stop the process — the
//! second because a check that answers "cannot tell" and opens anyway is no check at all on the one
//! open where it would have mattered — and what differs is the remedy each message names, so an
//! operator does not have to guess whether the key or the file is the problem.
//!
//! Failing to *write* the record is the third outcome and the only one that is not a refusal
//! ([`Arming::Unrecorded`]). A root that cannot be written to is a legitimate way to run a store,
//! and refusing there would deny an open that no check was protecting anyway. It says so in the log
//! at every open, because nothing is protected until the value is on disk.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yaam_crypto::subject::{KeyCheck, SubjectKey};

use crate::{Error, Result, fsutil, layout};

/// Format version of the recorded check value.
///
/// Read and refused rather than assumed, as every other stated version in this workspace is: a file
/// a later build wrote is one this build must not interpret under its own rules, and a check value
/// misread is the failure the whole file exists to prevent.
const CHECK_VERSION: u32 = 1;

/// What an open found the store recording about its subject key.
///
/// Returned rather than logged here, because the words a startup log uses belong to the layer that
/// knows which setting named the key — the same division [`yaam_crypto::custody::SubjectKeySource`]
/// makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arming {
    /// The store recorded a check value, and this key derives it.
    Verified,
    /// The store recorded nothing, and this key's check value is now on record.
    ///
    /// The trust-on-first-use case. Worth a warning wherever it is reported: the key was recorded,
    /// not verified.
    Adopted,
    /// The store recorded nothing and nothing could be written, with the reason.
    ///
    /// Not a refusal. Carries what stopped the write, because a store that cannot record this is a
    /// store where the next wrong key is still silent.
    Unrecorded(String),
}

/// The recorded file, as it sits under the root.
///
/// JSON with named fields rather than a bare line of hex, which is not decoration: a key file *is* a
/// bare line of hex, and two files under one deployment that look alike is how the wrong one ends up
/// in a secret manager.
#[derive(Debug, Serialize, Deserialize)]
struct Recorded {
    /// [`CHECK_VERSION`].
    version: u32,
    /// The check value, as [`KeyCheck`] renders it.
    check: String,
    /// When the value was recorded, in milliseconds since the Unix epoch.
    ///
    /// Informational, and defaulted on read for that reason: it answers "was this adopted at the
    /// open I intended?", which is the question trust on first use leaves an operator with. Nothing
    /// branches on it, so a file without one is still a file this build can check against.
    #[serde(default)]
    armed_ms: i64,
}

/// Checks `key` against what `root` records, recording it if `root` records nothing.
///
/// The one call every process that fetches a subject key makes before deriving with it. Cheap: one
/// small read, one HMAC, and a write only on the open that finds nothing.
///
/// # Errors
/// [`Error::SubjectKeyMismatch`] where the store records a value this key does not derive, and
/// [`Error::SubjectKeyCheckUnreadable`] where the record cannot be read or is not one this build
/// understands. Both are refusals; see this module's own account of why the second one is.
pub fn verify_or_arm(root: &Path, key: &SubjectKey) -> Result<Arming> {
    let path = root.join(layout::SUBJECT_CHECK_FILE);
    let derived = key.check_value();
    match fsutil::read_to_string_opt(&path) {
        // Absence is the only thing that means "not armed yet". Every other read failure is a file
        // that may well hold the value this open needed to be checked against.
        Ok(None) => Ok(record(&path, &derived)),
        Ok(Some(text)) => verify(path, &text, &derived),
        Err(error) => Err(unreadable(path, format!("cannot be read: {error}"))),
    }
}

/// Compares a recorded value against the one this key derives.
fn verify(path: PathBuf, text: &str, derived: &KeyCheck) -> Result<Arming> {
    let recorded: Recorded = match serde_json::from_str(text) {
        Ok(recorded) => recorded,
        Err(error) => return Err(unreadable(path, format!("does not parse: {error}"))),
    };
    if recorded.version != CHECK_VERSION {
        return Err(unreadable(
            path,
            format!(
                "states format version {}, and this build reads {CHECK_VERSION}",
                recorded.version
            ),
        ));
    }
    let Ok(recorded) = KeyCheck::parse(&recorded.check) else {
        return Err(unreadable(
            path,
            "holds no check value: the `check` field is not 64 hex digits".to_owned(),
        ));
    };
    if recorded == *derived {
        return Ok(Arming::Verified);
    }
    Err(Error::SubjectKeyMismatch {
        path,
        recorded,
        derived: derived.clone(),
    })
}

/// Records this key's check value, or reports why it could not be.
///
/// Written atomically, so an interrupted arming leaves the store unarmed rather than holding half a
/// value it would refuse itself over. The temporary that makes that possible is classified by
/// [`crate::backup::MANIFEST`] like the index's journal files are, so a crash here cannot leave a
/// backup reporting an entry nobody can account for.
fn record(path: &Path, derived: &KeyCheck) -> Arming {
    let recorded = Recorded {
        version: CHECK_VERSION,
        check: derived.to_string(),
        armed_ms: fsutil::now_ms(),
    };
    let mut text = serde_json::to_string_pretty(&recorded)
        .expect("a version, a hex string and an integer serialise");
    text.push('\n');
    match fsutil::replace_atomically(path, text.as_bytes()) {
        Ok(()) => Arming::Adopted,
        Err(error) => {
            Arming::Unrecorded(format!("{} could not be written: {error}", path.display()))
        }
    }
}

/// A recorded value this build cannot use, whatever the reason.
fn unreadable(path: PathBuf, detail: String) -> Error {
    Error::SubjectKeyCheckUnreadable { path, detail }
}

#[cfg(test)]
mod tests {
    use super::{Arming, CHECK_VERSION, Recorded, verify_or_arm};
    use crate::{Error, layout};
    use std::path::{Path, PathBuf};
    use yaam_crypto::subject::{SUBJECT_KEY_LEN, SubjectKey};

    /// A key with no structure to it. Any 32 bytes derive; these are not special.
    fn key(byte: u8) -> SubjectKey {
        SubjectKey::from_bytes(&[byte; SUBJECT_KEY_LEN]).expect("32 bytes")
    }

    /// An empty root, and where the check value would go under it.
    fn root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(layout::SUBJECT_CHECK_FILE);
        (dir, path)
    }

    /// Writes `text` where the check value belongs.
    fn record_text(path: &Path, text: &str) {
        std::fs::write(path, text).expect("written");
    }

    /// The state every store armed before this existed is in: records on file, nothing recording
    /// which key derived their pseudonyms. It must open, and it must say that it adopted rather than
    /// checked — the two are not the same claim.
    #[test]
    fn a_store_recording_nothing_adopts_the_key_it_is_opened_with() {
        let (dir, path) = root();
        assert_eq!(
            verify_or_arm(dir.path(), &key(0x5a)).expect("opened"),
            Arming::Adopted
        );

        let text = std::fs::read_to_string(&path).expect("recorded");
        let recorded: Recorded = serde_json::from_str(&text).expect("parsed");
        assert_eq!(recorded.version, CHECK_VERSION);
        assert_eq!(recorded.check, key(0x5a).check_value().to_string());
        assert!(recorded.armed_ms > 0, "an adoption says when it happened");
        assert!(
            !text.contains(&"5a".repeat(SUBJECT_KEY_LEN)),
            "the file may name the key and must never carry it"
        );
    }

    /// The right key still opens the store, at every open after the first. This is the half of the
    /// mechanism that a wrong refusal would break, and a live deployment cannot afford either half.
    #[test]
    fn the_key_a_store_was_armed_with_keeps_opening_it() {
        let (dir, path) = root();
        verify_or_arm(dir.path(), &key(0x5a)).expect("armed");
        let after_arming = std::fs::read(&path).expect("recorded");

        for _ in 0..2 {
            assert_eq!(
                verify_or_arm(dir.path(), &key(0x5a)).expect("opened"),
                Arming::Verified
            );
        }
        assert_eq!(
            std::fs::read(&path).expect("recorded"),
            after_arming,
            "a check is a read: nothing is rewritten once a store is armed"
        );
    }

    /// The defect this exists to close, in the shape a rehearsal found it: a substituted key file
    /// used to come up clean and file a second pseudonym for a reference already on record.
    ///
    /// Asserted on the message rather than on the variant, because the message is what an operator
    /// acts on at three in the morning: it has to name the file, both values, and what running
    /// anyway would do that nothing can undo.
    #[test]
    fn a_key_the_store_was_not_armed_with_is_refused_by_name() {
        let (dir, _path) = root();
        verify_or_arm(dir.path(), &key(0x5a)).expect("armed");

        let error = verify_or_arm(dir.path(), &key(0x5b)).expect_err("a substituted key");
        assert!(
            matches!(error, Error::SubjectKeyMismatch { .. }),
            "a wrong key is not the same finding as an unreadable record: {error}"
        );
        let said = error.to_string();
        for expected in [
            layout::SUBJECT_CHECK_FILE,
            &key(0x5a).check_value().to_string(),
            &key(0x5b).check_value().to_string(),
            "second, unrelatable pseudonym",
            "no re-key",
        ] {
            assert!(said.contains(expected), "{expected} missing from: {said}");
        }
    }

    /// A record that cannot be read is not a record that disagrees, and the remedy is not the same
    /// one: this is a file to restore, not a setting to change. It still refuses, because a check
    /// that answers "cannot tell" and opens anyway is no check on the open that needed it.
    #[test]
    fn a_record_that_cannot_be_read_refuses_differently() {
        let (dir, path) = root();
        let cases = [
            ("not json at all", "does not parse"),
            (
                r#"{"version": 2, "check": "00"}"#,
                "states format version 2",
            ),
            (
                r#"{"version": 1, "check": "not a check value"}"#,
                "holds no check value",
            ),
        ];
        for (text, expected) in cases {
            record_text(&path, text);
            let error = verify_or_arm(dir.path(), &key(0x5a)).expect_err("unusable");
            assert!(
                matches!(error, Error::SubjectKeyCheckUnreadable { .. }),
                "{text}: {error}"
            );
            let said = error.to_string();
            assert!(said.contains(expected), "{text}: {said}");
            assert!(
                said.contains("A backup carries it"),
                "the remedy is the file, not the key: {said}"
            );
        }
    }

    /// A read that fails for any reason other than absence is the same finding: only absence means
    /// "not armed yet", because everything else may be the value this open needed.
    #[test]
    fn a_record_that_cannot_be_opened_is_not_taken_for_an_unarmed_store() {
        let (dir, path) = root();
        std::fs::create_dir(&path).expect("something that is not a readable file");
        let error = verify_or_arm(dir.path(), &key(0x5a)).expect_err("unusable");
        assert!(
            matches!(error, Error::SubjectKeyCheckUnreadable { ref detail, .. } if detail.contains("cannot be read")),
            "{error}"
        );
    }

    /// A root that cannot be written to still opens. The check is what is unavailable, not the
    /// store, and it says so — every open, since nothing is protected until it is on disk.
    #[test]
    fn a_root_that_cannot_record_the_value_opens_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A root that is not there stands in for any root a write cannot reach: read-only mount,
        // full filesystem, a directory this process may not write.
        let absent = dir.path().join("not-a-store");
        let outcome = verify_or_arm(&absent, &key(0x5a)).expect("the store still opens");
        assert!(
            matches!(outcome, Arming::Unrecorded(ref why) if why.contains(layout::SUBJECT_CHECK_FILE)),
            "{outcome:?}"
        );
    }
}
