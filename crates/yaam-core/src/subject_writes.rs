//! Whether a store writes records of the subject-derived class at all.
//!
//! # The hole this closes
//!
//! Two things had become one decision, and only one of them was ever taken. `spec/subjects.yaml`
//! says what an erasure unit *is*, and a subject key handed to the process says how a pseudonym is
//! derived from one. Neither of them says the store may *write* such a record — and nothing else
//! did either. A deployment could be fully armed, with an operator's own sign-off saying
//! subject-derived writes were held pending a decision, and the only thing between that decision
//! and the first permanent pseudonym was that nobody had sent the record yet.
//!
//! [`crate::pipeline::Pipeline::accept`] is where that is now refused, and it is refused by
//! default. Every writer crosses that one function — the HTTP service, the sidecar behind it, the
//! CLI, a test — so there is no second path to remember to guard, which is exactly how the hole
//! came about the first time: a rule enforced in one caller is a rule the next caller does not have.
//!
//! # Why the default is refusal, and cannot be anything else
//!
//! A subject-derived record is sealed under a key derived from a pseudonym, and the pseudonym is an
//! HMAC under a subject key that cannot be rotated. There is no re-key, no re-seal and no delete.
//! The first such record a store writes is therefore permanent in a way nothing else here is: an
//! ordinary mistake in this system is recoverable by a rebuild, and this one is not recoverable at
//! all. A posture that could drift to enabled — by an upgrade, by an environment variable read out
//! of ambient state, by a default nobody chose — would be machinery taking a decision that
//! machinery cannot undo.
//!
//! So: absent means refused, and enabling is a line an operator writes.
//!
//! # Why a file of its own, beside `subjects.yaml` rather than inside it
//!
//! The two are independent decisions and putting them in one file would couple them. A store may
//! write subject-derived records without declaring any erasure unit at all — that is the
//! [`crate::resolve::DeclaredSubjects`] deployment, whose writers send pseudonyms they computed
//! themselves — and `subjects.yaml` cannot express that, because a declaration naming no kinds is
//! refused and a declaration naming kinds requires a subject key at startup, by the
//! both-halves-or-neither rule. Enabling writes would then force an unrelated resolver onto such a
//! store.
//!
//! It also keeps the deploy of this change safe: the file every armed deployment already has is not
//! touched, and the file that decides the new posture does not exist, so the answer is refused.
//!
//! # What an operator can see
//!
//! One file, one line, read without running anything:
//!
//! ```yaml
//! version: 1
//! writes: enabled
//! ```
//!
//! Absent, or `writes: refused`, and the store writes no subject-derived record. It is in `spec/`,
//! so it travels in a backup with the tree whose posture it describes, and a restore installs it
//! along with the rest of the configuration.
//!
//! # Where it is *not* enforced
//!
//! Nowhere but the accept path, and that is a requirement rather than an omission. A store that
//! enabled the class, wrote under it and then turned it off still holds those records, and must
//! still reindex, verify, unseal and erase them — a refusal that reached
//! [`crate::reindex::reindex_all`] would brick exactly the store that took the decision seriously
//! and then reconsidered.

use std::path::Path;

use saphyr::{LoadableYamlNode, Yaml};

use crate::{fsutil, layout};

/// Format version of the declaration.
///
/// Read and refused rather than assumed, as every other stated version in this workspace is: a file
/// a later build wrote is one this build must not interpret under its own rules.
const DECLARATION_VERSION: i64 = 1;

/// Whether this store accepts records of the subject-derived class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectWrites {
    /// No subject-derived record is accepted. What an absent file means, and the shipped state.
    #[default]
    Refused,
    /// Subject-derived records are accepted: resolved, sealed, and keyed to a subject.
    Enabled,
}

impl SubjectWrites {
    /// Name of the declaration, inside the tree's `spec/` directory.
    pub const SPEC_FILE: &'static str = "subject-writes.yaml";

    /// The key that carries the decision.
    pub const SPEC_KEY: &'static str = "writes";

    /// How the posture is spelled in the file, and in the log line reporting it at startup.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Enabled => "enabled",
        }
    }

    /// Whether this posture accepts subject-derived records.
    #[must_use]
    pub fn accepts(self) -> bool {
        self == Self::Enabled
    }

    /// What `root` declares about accepting subject-derived records.
    ///
    /// # Errors
    /// A file that is there and cannot be read as a declaration this build understands. Absence is
    /// not one of those: it is [`SubjectWrites::Refused`], which is the answer that was true before
    /// this file existed.
    pub fn load(root: &Path) -> crate::Result<Self> {
        let path = root.join(layout::SPEC_DIR).join(Self::SPEC_FILE);
        match fsutil::read_to_string_opt(&path)? {
            None => Ok(Self::Refused),
            Some(text) => Self::from_yaml(&text),
        }
    }

    /// Reads the declaration out of `subject-writes.yaml` content.
    ///
    /// # Errors
    /// Malformed YAML, more than one document, a version this build does not read, a missing
    /// `writes` key, or a value that is neither spelling. Every one of them is refused rather than
    /// defaulted: a file an operator wrote is a decision, and reading an unreadable decision as
    /// "refused" would be this build disagreeing with a written one without saying so. Refusing
    /// costs a startup and is the direction that cannot leak.
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        let mut docs = Yaml::load_from_str(yaml).map_err(|error| {
            spec_error(format!("{} is not valid YAML: {error}", Self::SPEC_FILE))
        })?;
        if docs.len() != 1 {
            return Err(spec_error(format!(
                "{} must hold exactly one YAML document, found {}",
                Self::SPEC_FILE,
                docs.len()
            )));
        }
        let doc = docs.remove(0);
        match doc.as_mapping_get("version").and_then(Yaml::as_integer) {
            Some(DECLARATION_VERSION) => {}
            other => {
                return Err(spec_error(format!(
                    "{} must declare `version: {DECLARATION_VERSION}`, found {}",
                    Self::SPEC_FILE,
                    other.map_or_else(|| "nothing".to_owned(), |found| found.to_string())
                )));
            }
        }
        match doc.as_mapping_get(Self::SPEC_KEY).and_then(Yaml::as_str) {
            Some(text) if text == Self::Refused.as_str() => Ok(Self::Refused),
            Some(text) if text == Self::Enabled.as_str() => Ok(Self::Enabled),
            found => Err(spec_error(format!(
                "{} must declare `{}: {}` or `{}: {}`, found {}. Removing the file means `{}`",
                Self::SPEC_FILE,
                Self::SPEC_KEY,
                Self::Refused.as_str(),
                Self::SPEC_KEY,
                Self::Enabled.as_str(),
                found.map_or_else(|| "nothing".to_owned(), |text| format!("`{text}`")),
                Self::Refused.as_str()
            ))),
        }
    }
}

/// A malformed declaration, in the shape the rest of `spec/` reports one.
fn spec_error(detail: String) -> crate::Error {
    crate::Error::Invalid(yaam_contract::Error::Spec { detail })
}

#[cfg(test)]
mod tests {
    use super::{DECLARATION_VERSION, SubjectWrites};
    use crate::layout;

    /// A root with `text` where the declaration belongs, or none at all.
    fn root(text: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join(layout::SPEC_DIR);
        std::fs::create_dir_all(&spec).expect("spec dir");
        if let Some(text) = text {
            std::fs::write(spec.join(SubjectWrites::SPEC_FILE), text).expect("written");
        }
        dir
    }

    /// The state every store is in until an operator decides otherwise, and the one this whole
    /// module exists to make true: no file, no subject-derived write.
    #[test]
    fn a_store_that_declares_nothing_refuses_subject_derived_writes() {
        let dir = root(None);
        assert_eq!(
            SubjectWrites::load(dir.path()).expect("an absent file is not a failure"),
            SubjectWrites::Refused
        );
        assert!(!SubjectWrites::Refused.accepts());
    }

    /// And a decision, written down, is honoured in both directions.
    #[test]
    fn a_declaration_is_read_as_written() {
        for (text, expected) in [
            ("version: 1\nwrites: enabled\n", SubjectWrites::Enabled),
            ("version: 1\nwrites: refused\n", SubjectWrites::Refused),
        ] {
            let dir = root(Some(text));
            assert_eq!(SubjectWrites::load(dir.path()).expect("read"), expected);
        }
        assert!(SubjectWrites::Enabled.accepts());
    }

    /// A file that cannot be read is refused rather than defaulted. Reading it as "refused" would
    /// be safe by accident and silent by design: the operator wrote a decision and would never
    /// learn this build could not make it out.
    #[test]
    fn a_declaration_this_build_cannot_read_refuses_to_open_and_says_why() {
        let cases = [
            ("\t- not: yaml\n  ][", "is not valid YAML"),
            (
                "version: 1\nwrites: enabled\n---\nversion: 1\nwrites: refused\n",
                "exactly one YAML document",
            ),
            ("version: 2\nwrites: enabled\n", "must declare `version: 1`"),
            ("writes: enabled\n", "must declare `version: 1`"),
            ("version: 1\n", "found nothing"),
            ("version: 1\nwrites: yes\n", "found `yes`"),
            ("version: 1\nwrites: ENABLED\n", "found `ENABLED`"),
        ];
        for (text, expected) in cases {
            let dir = root(Some(text));
            let error = SubjectWrites::load(dir.path()).expect_err("unusable");
            let said = error.to_string();
            assert!(said.contains(expected), "{text:?}: {said}");
        }
        assert_eq!(DECLARATION_VERSION, 1, "the message quotes this version");
    }

    /// The message an operator acts on has to name the file and both spellings, and say what
    /// removing it means — otherwise the remedy for a typo is a guess.
    #[test]
    fn an_unreadable_declaration_names_the_file_and_both_spellings() {
        let dir = root(Some("version: 1\nwrites: sometimes\n"));
        let said = SubjectWrites::load(dir.path())
            .expect_err("unusable")
            .to_string();
        for expected in [
            SubjectWrites::SPEC_FILE,
            "writes: enabled",
            "writes: refused",
            "Removing the file means `refused`",
        ] {
            assert!(said.contains(expected), "{expected} missing from: {said}");
        }
    }
}
