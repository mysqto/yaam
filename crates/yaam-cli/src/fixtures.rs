//! Test fixtures shared across the modules.
//!
//! In one place because the same memory tree proves several different things — that a rebuild counts
//! what it indexed, that a health read comes back clean, that the service binds over it — and
//! several copies of it would drift apart, which is the failure this crate exists to avoid one level
//! up.
//!
//! The vocabulary is deliberately neutral: `deploy`, `ticket`, `order_ref`. A fixture is where a
//! domain term leaks in first.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::TempDir;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role as SubjectRole, SchemaVer,
    SubjectHash, SubjectRef, Visibility, attrs,
    entity::{self, EntityRef},
};

/// Prose no configured redaction pattern matches.
pub(crate) const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// The redaction policy this repository's spec declares. A record must name the one in force.
pub(crate) const POLICY: &str = "default-v1";

/// A temporary memory tree with this repository's own `spec/` in place.
///
/// The repository's spec rather than a fixture one, so a spec change that stopped admitting these
/// records fails here rather than in a deployment.
pub(crate) fn tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
    copy_dir(&spec, &dir.path().join("spec"));
    dir
}

/// Copies a directory tree, which is how the repository's spec reaches a temporary root.
pub(crate) fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy");
        }
    }
}

/// An internal, org-visible record naming one ticket.
pub(crate) fn record(received_at: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: received_at.to_owned(),
        received_at: received_at.to_owned(),
        backfilled: false,
        agent: "agent_a".to_owned(),
        agent_ver: None,
        correlation_id: None,
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: BTreeMap::from([
            ("service".to_owned(), attrs::Value::Text("api".to_owned())),
            (
                "environment".to_owned(),
                attrs::Value::Text("staging".to_owned()),
            ),
        ]),
        entities: vec![EntityRef {
            kind: "ticket".to_owned(),
            id: "PROJ-42".to_owned(),
            role: entity::Role::Primary,
            confidence: 1.0,
        }],
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: POLICY.to_owned(),
        fields_masked: Vec::new(),
        tags: Vec::new(),
        summary: BODY.to_owned(),
    }
}

/// A subject-derived record: its body is sealed, and destroying the subject's keys erases it.
pub(crate) fn subject_record(received_at: &str, subject: &SubjectHash) -> ActionRecord {
    let mut record = record(received_at);
    "lookup".clone_into(&mut record.action);
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
    record.subjects = vec![SubjectRef {
        hash: subject.clone(),
        role: SubjectRole::Principal,
        canon_ver: CanonVer(1),
    }];
    record
}

/// A subject pseudonym, distinct per `fill`, which must be a lowercase hex digit.
pub(crate) fn subject(fill: char) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", fill.to_string().repeat(64))).expect("a valid hash")
}
