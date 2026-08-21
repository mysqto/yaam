//! Who a record is about.
//!
//! The pipeline used to read subjects straight off the arriving record, which is the right default
//! and the wrong only option. A deployment that keys its records by something it has to look up — a
//! canonicalising service, a directory, a mapping table — needs a step that turns the record into
//! pseudonyms, and that step can be down. This is the seam where such a lookup plugs in.
//!
//! It also makes an existing mechanism reachable. [`crate::Error::SubjectUnresolved`], the
//! quarantine spool and the register row were built for a resolver that could fail transiently, and
//! until now there was no resolver to fail.
//!
//! # Why this crate and not `yaam-contract`
//!
//! [`Resolution::Unavailable`] means nothing on its own; it means what the machinery that receives
//! it does, and all of that — quarantine, the register row, the settle on re-presentation — is here.
//! `yaam-contract` is types and validation, with no write path to be transient about, so a trait
//! whose whole content is "retry me later" would name a behaviour that crate cannot exhibit.

use yaam_contract::{ActionRecord, SubjectRef};

/// A deployment's subject lookup.
///
/// Carries no domain knowledge by construction: it is handed a record and answers with pseudonyms.
/// Everything about what a subject *is* and how its pseudonym is derived stays on the implementing
/// side, which is what lets this crate stay generic.
pub trait SubjectResolver: Send + Sync {
    /// Resolves the subjects a record names.
    fn resolve(&self, record: &ActionRecord) -> Resolution;
}

/// The answer to one resolution.
///
/// Two variants, and deliberately no third for "never resolvable". A record whose subjects can never
/// be resolved is a caller bug — it names something that does not and will not exist — and belongs
/// in validation, where it is rejected once and the writer is told what to fix. Admitting it here
/// would hand a permanent fault a retry loop and a spool file that never empties, which is the
/// failure the split between [`crate::Error::Invalid`] and [`crate::Error::SubjectUnresolved`]
/// exists to prevent.
#[derive(Debug)]
pub enum Resolution {
    /// The subjects this record names.
    Resolved(Vec<SubjectRef>),
    /// Cannot be determined right now. Quarantine and retry.
    Unavailable(String),
}

/// Trusts the subjects already on the record.
///
/// The default, and exactly what the pipeline did before this seam existed, so adopting a resolver
/// is a choice rather than a migration. A deployment whose writers already send pseudonyms needs
/// nothing else.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeclaredSubjects;

impl SubjectResolver for DeclaredSubjects {
    fn resolve(&self, record: &ActionRecord) -> Resolution {
        Resolution::Resolved(record.subjects.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    /// A record's server time. Any readable stamp will do here.
    const T09: &str = "2026-08-20T09:14:03.117Z";

    #[test]
    fn declared_subjects_answers_with_what_the_record_carries() {
        let subjects = [testkit::subject('a'), testkit::subject('b')];
        let record = testkit::subject_derived(T09, &subjects);

        let answer = DeclaredSubjects.resolve(&record);
        assert!(matches!(answer, Resolution::Resolved(subjects) if subjects == record.subjects));
    }

    #[test]
    fn declared_subjects_answers_for_a_record_that_names_none() {
        let answer = DeclaredSubjects.resolve(&testkit::internal(T09));
        assert!(matches!(answer, Resolution::Resolved(subjects) if subjects.is_empty()));
    }
}
