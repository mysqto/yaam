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
//! # The resolver this crate ships
//!
//! [`ReferenceSubjects`] keys erasure on a *transaction*, not on a person: the pseudonym is derived
//! from an entity reference the record already carries, under the kinds a deployment declares in
//! `spec/subjects.yaml`. Nothing on the write path claims to know whose transaction it is, so
//! nothing on the write path can be wrong about that — which matters here more than anywhere,
//! because this store has no correction path for a subject set. [`crate::Pipeline::accept`] returns
//! `Duplicate` for a record whose path is already published, there is no re-key and no re-seal, and
//! there is no delete. A body sealed to the wrong pseudonym is erasable by the wrong person's
//! request and unreachable by the right one's, for ever, and erasure verification will report the
//! job complete either way, because it asserts the absence of the keys it was asked about and
//! nothing else.
//!
//! So the person is resolved to references outside this store, at erasure time, where being wrong is
//! survivable: enumerate again and destroy what was missed, because the keys are still there to
//! destroy. That fan-out is an operator's runbook rather than a code path here — [`crate::erase`]
//! takes one hash.
//!
//! # Why this crate and not `yaam-contract`
//!
//! [`Resolution::Unavailable`] means nothing on its own; it means what the machinery that receives
//! it does, and all of that — quarantine, the register row, the settle on re-presentation — is here.
//! `yaam-contract` is types and validation, with no write path to be transient about, so a trait
//! whose whole content is "retry me later" would name a behaviour that crate cannot exhibit.

use std::collections::BTreeSet;
use std::path::Path;

use saphyr::{LoadableYamlNode, Yaml};
use yaam_contract::extract::FIELD_CONFIDENCE;
use yaam_contract::{ActionRecord, DataClass, Role, SubjectRef};
use yaam_crypto::subject::{Canon, SubjectKey};

use crate::{fsutil, layout};

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
/// Three variants for three next moves, and the two failures are the ones that must never be
/// confused. [`Resolution::Unavailable`] is transient: the record is real, the lookup will come
/// back, and dropping it would lose history exactly when a lookup was flapping — so it quarantines.
/// [`Resolution::Refused`] is permanent and the caller's to fix, so it is rejected once with the
/// reason rather than handed a retry loop and a spool file that never empties. Answering a permanent
/// fault with `Unavailable` is the failure the split between [`crate::Error::Invalid`] and
/// [`crate::Error::SubjectUnresolved`] exists to prevent.
///
/// `Refused` is not a duplicate of validation. [`ActionRecord::validate`] cannot see a deployment's
/// subject rules — which kinds are erasure units, and how many of them one record may name — so a
/// record that is well formed and still unresolvable has no earlier place to be turned away.
#[derive(Debug)]
pub enum Resolution {
    /// The subjects this record names.
    Resolved(Vec<SubjectRef>),
    /// Cannot be determined right now. Quarantine and retry.
    Unavailable(String),
    /// Cannot be determined from this record at all, and re-presenting it unchanged will not help.
    Refused(String),
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

/// The entity kinds this deployment keys erasure on, most preferred first.
///
/// Configuration in the tree, for the reason every other `spec/` file is there: a record's
/// pseudonyms must not depend on which process wrote it. These kinds decide the identifier a
/// pseudonym is taken over, so the service, an operator re-driving the quarantine spool and any
/// later rebuild have to agree about them — and a flag on one command line is a place for them to
/// disagree silently, producing two pseudonyms for one transaction with nothing to relate them
/// again.
///
/// The keying secret goes the other way and is deliberately *not* in the tree: it is passed to the
/// process, as the key-store passphrase is, because a secret that travelled in the backup would be a
/// secret in every copy the backup reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKinds {
    /// Kind names in priority order, as `spec/entities.yaml` spells them.
    kinds: Vec<String>,
}

impl SubjectKinds {
    /// Name of the declaration, inside the tree's `spec/` directory.
    pub const SPEC_FILE: &'static str = "subjects.yaml";

    /// Loads the declaration, or reports that this store keys erasure on nothing.
    ///
    /// An absent file is not an error and is the shipped state: a store with no `subjects.yaml`
    /// resolves no subjects, seals no bodies, and behaves exactly as it did before this existed.
    /// That is deliberate, because the first subject-derived record a store writes cannot be taken
    /// back — there is no re-key and no delete — so enabling this is a decision an operator makes
    /// rather than one an upgrade makes for them.
    ///
    /// Every kind named here must be one `spec/entities.yaml` declares. Without that check a
    /// mistyped kind name is a store that keys erasure on nothing at all, and says so only by
    /// refusing records one at a time.
    ///
    /// # Errors
    /// A malformed file, a file naming no kinds, a duplicate kind, or a kind the entity registry does
    /// not declare. All of them are refused at load rather than at the first record, because the
    /// alternative is the reason arriving one write at a time, at the caller, hours later.
    pub fn load(root: &Path) -> crate::Result<Option<Self>> {
        let spec = root.join(layout::SPEC_DIR);
        let Some(text) = fsutil::read_to_string_opt(&spec.join(Self::SPEC_FILE))? else {
            return Ok(None);
        };
        let declared = Self::from_yaml(&text)?;
        let registry = match fsutil::read_to_string_opt(&spec.join("entities.yaml"))? {
            Some(entities) => yaam_contract::entity::Registry::from_yaml(&entities)?,
            None => yaam_contract::entity::Registry::default(),
        };
        for kind in &declared.kinds {
            if !registry.kinds().iter().any(|known| &known.name == kind) {
                return Err(spec_error(format!(
                    "{} names entity kind `{kind}`, which spec/entities.yaml does not declare",
                    Self::SPEC_FILE
                )));
            }
        }
        Ok(Some(declared))
    }

    /// Reads the declaration out of `subjects.yaml` content.
    ///
    /// # Errors
    /// As [`SubjectKinds::load`], less the cross-check against the entity registry.
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        let mut docs = Yaml::load_from_str(yaml)
            .map_err(|error| spec_error(format!("subjects.yaml is not valid YAML: {error}")))?;
        if docs.len() != 1 {
            return Err(spec_error(format!(
                "subjects.yaml must hold exactly one YAML document, found {}",
                docs.len()
            )));
        }
        let doc = docs.remove(0);
        // A stated version is checked rather than assumed, for the reason every spec file states
        // one: reading a later file under this build's rules is a silent misread.
        match doc.as_mapping_get("version").and_then(Yaml::as_integer) {
            Some(1) => {}
            other => {
                return Err(spec_error(format!(
                    "subjects.yaml must declare `version: 1`, found {}",
                    other.map_or_else(|| "nothing".to_owned(), |found| found.to_string())
                )));
            }
        }
        let listed = doc
            .as_mapping_get("kinds")
            .and_then(Yaml::as_sequence)
            .ok_or_else(|| spec_error("subjects.yaml has no `kinds` sequence".to_owned()))?;

        let mut kinds: Vec<String> = Vec::with_capacity(listed.len());
        for entry in listed {
            let name = entry
                .as_str()
                .ok_or_else(|| spec_error("subjects.yaml kinds must be strings".to_owned()))?;
            if kinds.iter().any(|seen| seen == name) {
                return Err(spec_error(format!(
                    "subjects.yaml names kind `{name}` twice, so its priority is undecided"
                )));
            }
            kinds.push(name.to_owned());
        }
        if kinds.is_empty() {
            // Identical in effect to an absent file and not in intent: whoever wrote this file meant
            // to enable something, and a store that silently sealed nothing would look enabled.
            return Err(spec_error(
                "subjects.yaml names no kinds; remove the file to key erasure on nothing"
                    .to_owned(),
            ));
        }
        Ok(Self { kinds })
    }

    /// The declared kinds, most preferred first.
    #[must_use]
    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }
}

/// A malformed or contradictory `subjects.yaml`, in the shape the rest of `spec/` reports one.
fn spec_error(detail: String) -> crate::Error {
    crate::Error::Invalid(yaam_contract::Error::Spec { detail })
}

/// Derives a record's subject from an entity reference the record already carries.
///
/// The erasure unit is the transaction that reference names, so this resolver makes no claim about a
/// person and needs no lookup: it is a pure function of the record and the keying secret. That is
/// what it is for. Every design that decides *who* a record is about on the write path converts a
/// lookup error into a body erasable by the wrong person and unreachable by the right one, silently
/// and for ever, because this store cannot correct a subject set. This one has no such claim to be
/// wrong about; what can be wrong — which transactions belong to a person — is asked at erasure
/// time, of the system of record, where the answer can still be corrected.
///
/// # How one record's subject is decided
///
/// 1. A record its caller classified [`DataClass::Internal`] resolves to no subject. The class is the
///    caller's declaration and this resolver only ever narrows it: promoting an internal record would
///    seal a body whose caller believes it is plaintext, and would do it to every record that
///    happened to name a reference of a configured kind.
/// 2. Otherwise the configured kinds are tried in order and the first one the record states decides.
///    Declared priority is what answers "which reference wins when a record carries two kinds of
///    them" with a deployment's decision instead of with whichever the caller happened to list first.
/// 3. Only references the caller stated at [`FIELD_CONFIDENCE`] count. A reference lifted from prose
///    is a guess, and a guess deciding erasability is a model in the classification path — the one
///    thing that may never decide whether a record becomes permanently unerasable.
/// 4. The pseudonym is taken over `kind:id`, with `id` the canonical form
///    [`yaam_contract::entity::Registry`] has already rewritten on the way in. Two spellings of one
///    reference are therefore impossible rather than merely unlikely, which matters because they
///    would be two subjects nothing could relate again. Including the kind keeps one identifier under
///    two kinds from collapsing into one subject.
///
/// # What it refuses
///
/// A subject-derived record that states no reference of a configured kind, and one that states two
/// references of the *same* kind, are both [`Resolution::Refused`]. The second is the point: two
/// references of equal standing have no rule to choose between them, sealing to both would make each
/// transaction's erasure destroy the other's body, and picking one would be a coin toss recorded as
/// a fact. A record refused here is a record that was never written, which is the only failure in
/// this area that can still be fixed afterwards.
///
/// An ambiguous higher-priority kind refuses rather than falling through to a lower one, so the rule
/// an operator holds — the first declared kind decides when the record states one — has no exception
/// in the case nobody would think to check.
pub struct ReferenceSubjects {
    /// Kinds to try, in order.
    kinds: SubjectKinds,
    /// The keying secret. It never leaves this struct; see [`SubjectKey`].
    key: SubjectKey,
}

/// Written by hand because [`SubjectKey`] has no derivable [`Debug`] for a reason: a derived one here
/// would print the keying secret in the first log line that formatted a pipeline.
impl std::fmt::Debug for ReferenceSubjects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferenceSubjects")
            .field("kinds", &self.kinds.kinds)
            .field("key", &self.key)
            .finish()
    }
}

impl ReferenceSubjects {
    /// Builds the resolver from a declaration and the keying secret.
    #[must_use]
    pub fn new(kinds: SubjectKinds, key: SubjectKey) -> Self {
        Self { kinds, key }
    }

    /// What this record states about one kind.
    ///
    /// Duplicates of one identifier are one reference: they name one transaction, and the ids are
    /// canonical by the time this runs, so equality means what it says.
    fn stated<'a>(record: &'a ActionRecord, kind: &str) -> Candidates<'a> {
        let ids: BTreeSet<&str> = record
            .entities
            .iter()
            .filter(|entity| entity.kind == kind && entity.confidence >= FIELD_CONFIDENCE)
            .map(|entity| entity.id.as_str())
            .collect();
        let mut found = ids.into_iter();
        match (found.next(), found.count()) {
            (None, _) => Candidates::None,
            (Some(id), 0) => Candidates::One(id),
            (Some(_), rest) => Candidates::Several(rest + 1),
        }
    }
}

/// What one kind contributed to a resolution.
enum Candidates<'a> {
    /// The record states no reference of this kind.
    None,
    /// Exactly one, which is the resolvable case.
    One(&'a str),
    /// Several of equal standing, which is the refusable one.
    Several(usize),
}

impl SubjectResolver for ReferenceSubjects {
    fn resolve(&self, record: &ActionRecord) -> Resolution {
        if record.data_class == DataClass::Internal {
            return Resolution::Resolved(Vec::new());
        }
        for kind in self.kinds.kinds() {
            let id = match Self::stated(record, kind) {
                Candidates::None => continue,
                Candidates::One(id) => id,
                Candidates::Several(count) => {
                    return Resolution::Refused(format!(
                        "record states {count} `{kind}` references of equal standing; a \
                         subject-derived record names one erasure unit, and there is no rule here \
                         to choose between them"
                    ));
                }
            };
            return match self.key.derive(Canon::CURRENT, &format!("{kind}:{id}")) {
                Ok(pseudonym) => Resolution::Resolved(vec![SubjectRef {
                    hash: pseudonym.hash,
                    // The record is about the transaction the reference names, so the transaction is
                    // its principal. There is no second party to be a `Party`: this resolver never
                    // claims to know who took part.
                    role: Role::Principal,
                    canon_ver: pseudonym.canon_ver,
                }]),
                Err(error) => Resolution::Refused(format!(
                    "reference `{kind}:{id}` has no pseudonym: {error}"
                )),
            };
        }
        Resolution::Refused(format!(
            "record states no reference of a kind this store keys erasure on ({}), so its body \
             would be sealed under a key no erasure request could reach",
            self.kinds.kinds().join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    /// A record's server time. Any readable stamp will do here.
    const T09: &str = "2026-08-20T09:14:03.117Z";

    /// A resolver over `kinds`. Any 32 bytes key it; these are not special.
    fn resolver(kinds: &[&str]) -> ReferenceSubjects {
        ReferenceSubjects::new(
            SubjectKinds {
                kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
            },
            SubjectKey::from_bytes(&[0x5a; yaam_crypto::SUBJECT_KEY_LEN]).expect("32 bytes"),
        )
    }

    /// One entity reference, as a caller would state or infer it.
    fn reference(kind: &str, id: &str, confidence: f32) -> yaam_contract::entity::EntityRef {
        yaam_contract::entity::EntityRef {
            kind: kind.to_owned(),
            id: id.to_owned(),
            role: yaam_contract::entity::Role::Primary,
            confidence,
        }
    }

    /// A record its caller declared erasable, stating `entities`.
    fn subject_derived(entities: &[(&str, &str, f32)]) -> ActionRecord {
        let mut record = testkit::internal(T09);
        record.data_class = DataClass::SubjectDerived;
        record.summary = String::new();
        record.entities = entities
            .iter()
            .map(|(kind, id, confidence)| reference(kind, id, *confidence))
            .collect();
        record
    }

    /// The subjects a resolution settled on, or a panic naming what came back instead.
    fn resolved(answer: Resolution) -> Vec<SubjectRef> {
        match answer {
            Resolution::Resolved(subjects) => subjects,
            other => panic!("expected a resolution, got {other:?}"),
        }
    }

    /// The reason a resolution refused, so a test can assert on what a caller is told.
    fn refusal(answer: Resolution) -> String {
        match answer {
            Resolution::Refused(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

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

    #[test]
    fn one_stated_reference_is_the_records_subject() {
        let record = subject_derived(&[("order_ref", "abcd1234", FIELD_CONFIDENCE)]);
        let subjects = resolved(resolver(&["order_ref"]).resolve(&record));

        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].role, Role::Principal);
        assert_eq!(subjects[0].canon_ver, Canon::CURRENT.version());
        assert!(subjects[0].hash.as_str().starts_with("s_"));
    }

    /// The pseudonym is a pure function of the reference, which is what makes a replay of one record
    /// land on the same keys instead of minting a second set nobody can destroy.
    #[test]
    fn one_reference_is_one_pseudonym_however_often_it_is_resolved() {
        let resolver = resolver(&["order_ref"]);
        let record = subject_derived(&[("order_ref", "abcd1234", FIELD_CONFIDENCE)]);
        assert_eq!(
            resolved(resolver.resolve(&record)),
            resolved(resolver.resolve(&record))
        );
    }

    /// One identifier under two kinds is two subjects, because the kind is part of what is hashed.
    #[test]
    fn the_kind_is_part_of_the_identifier_a_pseudonym_is_taken_over() {
        let resolver = resolver(&["order_ref", "ticket"]);
        let order = resolved(resolver.resolve(&subject_derived(&[(
            "order_ref",
            "abcd1234",
            FIELD_CONFIDENCE,
        )])));
        let ticket =
            resolved(resolver.resolve(&subject_derived(&[("ticket", "ABCD-1", FIELD_CONFIDENCE)])));
        assert_ne!(order[0].hash, ticket[0].hash);
    }

    #[test]
    fn the_declared_order_decides_which_kind_is_the_erasure_unit() {
        let record = subject_derived(&[
            ("ticket", "PROJ-42", FIELD_CONFIDENCE),
            ("order_ref", "abcd1234", FIELD_CONFIDENCE),
        ]);
        let by_order = resolved(resolver(&["order_ref", "ticket"]).resolve(&record));
        let by_ticket = resolved(resolver(&["ticket", "order_ref"]).resolve(&record));

        assert_ne!(
            by_order[0].hash, by_ticket[0].hash,
            "the declared priority has to decide, not the order the record happens to list"
        );
    }

    /// The whole point: two references of equal standing have no rule to choose between them, so the
    /// record is refused rather than sealed to a guess that can never be corrected.
    #[test]
    fn two_references_of_one_kind_are_refused_rather_than_chosen_between() {
        let record = subject_derived(&[
            ("order_ref", "abcd1234", FIELD_CONFIDENCE),
            ("order_ref", "efgh5678", FIELD_CONFIDENCE),
        ]);
        let reason = refusal(resolver(&["order_ref"]).resolve(&record));
        assert!(reason.contains("equal standing"), "{reason}");
    }

    /// A lower-priority kind does not rescue an ambiguous higher-priority one: the rule an operator
    /// holds is "the first declared kind decides", and a fall-through would make it untrue in the one
    /// case nobody would think to check.
    #[test]
    fn an_ambiguous_first_kind_is_not_rescued_by_a_later_one() {
        let record = subject_derived(&[
            ("order_ref", "abcd1234", FIELD_CONFIDENCE),
            ("order_ref", "efgh5678", FIELD_CONFIDENCE),
            ("ticket", "PROJ-42", FIELD_CONFIDENCE),
        ]);
        let reason = refusal(resolver(&["order_ref", "ticket"]).resolve(&record));
        assert!(reason.contains("order_ref"), "{reason}");
    }

    #[test]
    fn one_reference_stated_twice_is_one_subject() {
        let record = subject_derived(&[
            ("order_ref", "abcd1234", FIELD_CONFIDENCE),
            ("order_ref", "abcd1234", FIELD_CONFIDENCE),
        ]);
        assert_eq!(resolved(resolver(&["order_ref"]).resolve(&record)).len(), 1);
    }

    /// A reference lifted from prose is a guess, and a guess may not decide whether a body becomes
    /// erasable.
    #[test]
    fn an_inferred_reference_does_not_decide_erasability() {
        let record = subject_derived(&[("order_ref", "abcd1234", 0.6)]);
        let reason = refusal(resolver(&["order_ref"]).resolve(&record));
        assert!(reason.contains("no reference of a kind"), "{reason}");
    }

    #[test]
    fn a_record_stating_no_configured_kind_is_refused() {
        let record = subject_derived(&[("ticket", "PROJ-42", FIELD_CONFIDENCE)]);
        let reason = refusal(resolver(&["order_ref"]).resolve(&record));
        assert!(reason.contains("order_ref"), "{reason}");
    }

    /// The resolver narrows a class and never widens one. An internal record stating a reference of a
    /// configured kind stays plaintext, because its caller believes it is.
    #[test]
    fn an_internal_record_is_not_promoted_by_stating_a_configured_reference() {
        let mut record = testkit::internal(T09);
        record.entities = vec![reference("order_ref", "abcd1234", FIELD_CONFIDENCE)];
        assert!(resolved(resolver(&["order_ref"]).resolve(&record)).is_empty());
    }

    /// A caller cannot bring its own pseudonym: what it sent is replaced by what the store derives.
    #[test]
    fn a_declared_subject_does_not_survive_this_resolver() {
        let mut record = subject_derived(&[("order_ref", "abcd1234", FIELD_CONFIDENCE)]);
        record.subjects = vec![SubjectRef {
            hash: testkit::subject('f'),
            role: Role::Principal,
            canon_ver: Canon::CURRENT.version(),
        }];
        let subjects = resolved(resolver(&["order_ref"]).resolve(&record));

        assert_eq!(subjects.len(), 1);
        assert_ne!(subjects[0].hash, record.subjects[0].hash);
    }

    #[test]
    fn a_declaration_reads_its_kinds_in_the_order_it_names_them() {
        let kinds = SubjectKinds::from_yaml("version: 1\nkinds:\n  - order_ref\n  - ticket\n")
            .expect("declared");
        assert_eq!(kinds.kinds(), ["order_ref".to_owned(), "ticket".to_owned()]);
    }

    #[test]
    fn a_declaration_that_settles_nothing_is_refused() {
        for yaml in [
            "version: 1\nkinds: []\n",
            "version: 1\n",
            "kinds:\n  - order_ref\n",
            "version: 2\nkinds:\n  - order_ref\n",
            "version: 1\nkinds:\n  - order_ref\n  - order_ref\n",
            "version: 1\nkinds:\n  - 7\n",
            "version: 1\nkinds: order_ref\n",
            "version: 1\nkinds: [a\n",
            "version: 1\nkinds: [order_ref]\n---\nversion: 1\nkinds: [ticket]\n",
        ] {
            assert!(
                SubjectKinds::from_yaml(yaml).is_err(),
                "must be refused: {yaml:?}"
            );
        }
    }

    /// The property that keeps an existing store unchanged: no declaration, nothing to resolve.
    #[test]
    fn a_store_that_declares_nothing_loads_no_declaration() {
        let root = tempfile::tempdir().expect("a temporary tree");
        std::fs::create_dir_all(root.path().join("spec")).expect("a spec directory");
        assert!(
            SubjectKinds::load(root.path())
                .expect("an absent declaration is not a failure")
                .is_none()
        );
    }

    #[test]
    fn a_declaration_naming_an_undeclared_kind_is_refused_at_load() {
        let root = tempfile::tempdir().expect("a temporary tree");
        let spec = root.path().join("spec");
        std::fs::create_dir_all(&spec).expect("a spec directory");
        std::fs::write(
            spec.join("entities.yaml"),
            "version: 1\nkinds:\n  order_ref:\n    pattern: '^[a-z0-9]{8,24}$'\n",
        )
        .expect("written");
        std::fs::write(
            spec.join(SubjectKinds::SPEC_FILE),
            "version: 1\nkinds:\n  - order_ref\n",
        )
        .expect("written");
        assert_eq!(
            SubjectKinds::load(root.path())
                .expect("loaded")
                .expect("declared")
                .kinds(),
            ["order_ref".to_owned()]
        );

        std::fs::write(
            spec.join(SubjectKinds::SPEC_FILE),
            "version: 1\nkinds:\n  - oder_ref\n",
        )
        .expect("written");
        let err = SubjectKinds::load(root.path()).expect_err("a kind nothing declares");
        assert!(err.to_string().contains("does not declare"), "{err}");
    }

    /// The property an existing store rests on: with nothing declared, nothing changes. No subject
    /// resolves, no body is sealed, and the key store is never touched — so a store upgraded to this
    /// build has not silently started the one clock that cannot be wound back.
    #[test]
    fn an_unconfigured_store_writes_the_record_it_always_did() {
        let mut harness = testkit::Harness::new();
        assert!(
            SubjectKinds::load(harness.root())
                .expect("an absent declaration is not a failure")
                .is_none(),
            "the fixture tree declares no erasure units, which is the shipped state"
        );

        let record = testkit::internal(T09);
        let path = harness.path_of(&record);
        harness
            .pipeline
            .accept(record, testkit::BODY)
            .expect("accepted");

        let stored = yaam_md::Document::parse(&std::fs::read_to_string(&path).expect("read"))
            .expect("parses");
        assert!(stored.record.subjects.is_empty());
        assert_eq!(stored.record.data_class, DataClass::Internal);
        assert!(
            matches!(stored.body, yaam_md::Body::Plain(text) if text == testkit::BODY),
            "the body stays plaintext, as every body in such a store already is"
        );
        assert!(
            matches!(
                harness.pipeline.key_material().expect("readable"),
                yaam_crypto::keystore::KeyMaterial::Absent
            ),
            "no key was minted, so there is nothing an erasure would have to reach"
        );
    }

    /// End to end, on the resolver this crate ships: the reference the record states decides the
    /// pseudonym, the body is sealed under it, and an operator who can derive that pseudonym from the
    /// reference — which is the whole erasure-time runbook — reaches the body.
    #[test]
    fn a_declared_kind_seals_the_body_and_an_erasure_derived_the_same_way_reaches_it() {
        let record = subject_derived(&[("order_ref", "ord10014721", FIELD_CONFIDENCE)]);
        let mut harness = testkit::Harness::new().resolving_with(resolver(&["order_ref"]));
        let path = harness.path_of(&record);
        harness
            .pipeline
            .accept(record.clone(), testkit::BODY)
            .expect("accepted");

        // What the runbook does: derive the pseudonym for one reference, outside the store.
        let expected = SubjectKey::from_bytes(&[0x5a; yaam_crypto::SUBJECT_KEY_LEN])
            .expect("32 bytes")
            .derive(Canon::CURRENT, "order_ref:ord10014721")
            .expect("derived");

        let stored = yaam_md::Document::parse(&std::fs::read_to_string(&path).expect("read"))
            .expect("parses");
        assert_eq!(stored.record.subjects.len(), 1);
        assert_eq!(stored.record.subjects[0].hash, expected.hash);
        assert_eq!(stored.record.subjects[0].canon_ver, expected.canon_ver);
        assert!(
            matches!(stored.body, yaam_md::Body::Sealed(_)),
            "a subject-derived body is sealed, not stored as prose"
        );

        let report = crate::erase::erase_subject(&mut harness.pipeline, &expected.hash)
            .expect("the erasure runs");
        assert_eq!(report.bodies_sealed_off, 1);
        assert!(
            !std::fs::read_to_string(&path)
                .expect("read")
                .contains("Rolled out"),
            "the body is gone from the live tree, and its keys from every copy"
        );
    }

    #[test]
    fn the_keying_secret_does_not_reach_a_log_line() {
        let printed = format!("{:?}", resolver(&["order_ref"]));
        assert!(printed.contains("order_ref"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
        assert!(!printed.contains("5a"), "{printed}");
    }
}
