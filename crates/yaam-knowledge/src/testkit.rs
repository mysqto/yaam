//! Shared fixtures for this crate's tests.
//!
//! Records are written through the real write pipeline rather than assembled as files by hand. The
//! claim under test is "knowledge is a function of the record tree", and the tree that matters is the
//! one a deployment actually produces — dated directories, an owner subtree, sealed bodies, a
//! quarantine spool. Hand-written files would let this crate's reader agree with this crate's idea of
//! the layout and nothing else.
//!
//! The vocabulary is deliberately neutral — `deploy`, `ticket`, `order_ref` — because a fixture is
//! where domain terms leak in first.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::TempDir;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, RecordStructure, Role, SchemaVer,
    SubjectHash, SubjectRef, Visibility, attrs,
    entity::{self, EntityRef},
};
use yaam_core::Pipeline;

/// Entity kinds this deployment configures.
const SPEC_ENTITIES: &str = concat!(
    "version: 1\n",
    "kinds:\n",
    "  ticket:\n",
    "    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n",
    "    normalise: [trim, uppercase_prefix]\n",
    "  deploy:\n",
    "    pattern: '^[a-z0-9._-]+/[a-z0-9._-]+#[0-9]+$'\n",
    "    normalise: [trim, lowercase]\n",
    "  order_ref:\n",
    "    pattern: '^[a-z0-9]{8,24}$'\n",
    "    normalise: [trim, lowercase]\n",
);

/// The attribute surface this deployment declares.
const SPEC_ATTRS: &str = concat!(
    "version: 1\n",
    "actions:\n",
    "  deploy:\n",
    "    outcome: [success, failure, partial]\n",
    "    attrs:\n",
    "      service: { type: string, class: structural }\n",
    "      environment: { type: string, class: structural }\n",
    "      duration_ms: { type: integer, class: structural }\n",
    "  lookup:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      target_kind: { type: string, class: structural }\n",
);

/// The redaction policy this deployment applies.
const SPEC_REDACTION: &str = concat!(
    "version: 1\n",
    "policy: default-v1\n",
    "patterns:\n",
    "  - name: email\n",
    "    regex: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b'\n",
    "    action: mask\n",
);

/// The policy name records must declare.
const POLICY: &str = "default-v1";

/// A body no configured redaction pattern matches.
pub(crate) const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// A memory root with a configured spec, and the write pipeline over it.
///
/// The temporary directory is held so it outlives the pipeline; dropping the harness removes both.
pub(crate) struct Harness {
    /// Owns the temporary root.
    dir: TempDir,
    /// The pipeline records are written through.
    pub(crate) pipeline: Pipeline,
}

impl Harness {
    /// Builds a memory root with the fixture spec in place.
    pub(crate) fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let spec = dir.path().join("spec");
        fs::create_dir_all(spec.join("redaction")).expect("spec dirs");
        fs::write(spec.join("entities.yaml"), SPEC_ENTITIES).expect("entities spec");
        fs::write(spec.join("attrs-schema.yaml"), SPEC_ATTRS).expect("attrs spec");
        fs::write(spec.join("redaction/default.yaml"), SPEC_REDACTION).expect("redaction spec");
        let pipeline = Pipeline::new(dir.path()).expect("pipeline");
        Self { dir, pipeline }
    }

    /// Root of the memory tree.
    pub(crate) fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Writes one record through the pipeline, and reports what became of it.
    pub(crate) fn accept(&mut self, record: ActionRecord) -> yaam_core::pipeline::Accepted {
        self.pipeline.accept(record, BODY).expect("accepted")
    }

    /// Rebuilds the pipeline over the same tree with a subject resolver in place.
    ///
    /// Destructured rather than assigned through the field, so the temporary root outlives the
    /// pipeline it replaces.
    pub(crate) fn resolving_with(
        self,
        resolver: impl yaam_core::resolve::SubjectResolver + 'static,
    ) -> Self {
        let Self { dir, pipeline } = self;
        Self {
            dir,
            pipeline: pipeline.with_subject_resolver(resolver),
        }
    }
}

/// A resolver that never settles a subject-derived record, so it is held in the quarantine spool.
///
/// Internal records still resolve: they name no subject, and a resolver that reported them
/// unavailable would quarantine the whole store rather than the case under test.
pub(crate) struct HoldsSubjects;

impl yaam_core::resolve::SubjectResolver for HoldsSubjects {
    fn resolve(&self, record: &ActionRecord) -> yaam_core::resolve::Resolution {
        if record.data_class == DataClass::SubjectDerived {
            return yaam_core::resolve::Resolution::Unavailable("held for the test".to_owned());
        }
        yaam_core::resolve::Resolution::Resolved(record.subjects.clone())
    }
}

/// A subject pseudonym, distinct per `fill`, which must be a lowercase hex digit.
pub(crate) fn subject(fill: char) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", fill.to_string().repeat(64))).expect("a valid hash")
}

/// An internal record: plaintext body, no subjects, three attributes, two entity references.
pub(crate) fn internal(received_at: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: received_at.to_owned(),
        received_at: received_at.to_owned(),
        backfilled: false,
        agent: "agent_a".to_owned(),
        agent_ver: Some("1.4.2".to_owned()),
        correlation_id: Some("corr-7f31".to_owned()),
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: BTreeMap::from([
            ("service".to_owned(), attrs::Value::Text("api".to_owned())),
            (
                "environment".to_owned(),
                attrs::Value::Text("staging".to_owned()),
            ),
            ("duration_ms".to_owned(), attrs::Value::Int(1_420)),
        ]),
        entities: vec![
            EntityRef {
                kind: "deploy".to_owned(),
                id: "api/staging#17".to_owned(),
                role: entity::Role::Primary,
                confidence: 1.0,
            },
            EntityRef {
                kind: "ticket".to_owned(),
                id: "PROJ-42".to_owned(),
                role: entity::Role::Related,
                confidence: 1.0,
            },
        ],
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: POLICY.to_owned(),
        fields_masked: Vec::new(),
        tags: vec!["release".to_owned()],
        summary: String::new(),
    }
}

/// An owner-visible record: stored apart, readable only by the agent it names.
pub(crate) fn owner(received_at: &str, agent: &str) -> ActionRecord {
    let mut record = internal(received_at);
    record.agent = agent.to_owned();
    record.visibility = Visibility::Owner;
    record
}

/// A subject-derived record: sealed body, one named subject, one entity of its own.
pub(crate) fn subject_derived(received_at: &str, subjects: &[SubjectHash]) -> ActionRecord {
    let mut record = internal(received_at);
    record.action = "lookup".to_owned();
    record.attrs = BTreeMap::from([(
        "target_kind".to_owned(),
        attrs::Value::Text("order_ref".to_owned()),
    )]);
    record.entities = vec![EntityRef {
        kind: "order_ref".to_owned(),
        id: "ord10014721".to_owned(),
        role: entity::Role::Primary,
        confidence: 1.0,
    }];
    record.data_class = DataClass::SubjectDerived;
    record.subjects = subjects
        .iter()
        .map(|hash| SubjectRef {
            hash: hash.clone(),
            role: Role::Principal,
            canon_ver: CanonVer(1),
        })
        .collect();
    record
}

/// The frontmatter projection of an internal record: what derivation is given.
pub(crate) fn internal_structure(received_at: &str) -> RecordStructure {
    RecordStructure::from(&internal(received_at))
}

/// The frontmatter projection of a subject-derived record.
pub(crate) fn subject_derived_structure(received_at: &str) -> RecordStructure {
    RecordStructure::from(&subject_derived(received_at, &[subject('a')]))
}
