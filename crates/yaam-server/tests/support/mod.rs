//! A real memory tree, and the records to put in it.
//!
//! Shared by the integration tests, which is the point: both drive `CoreService` over a temporary
//! tree configured from this repository's own `spec/`, so a spec that stopped admitting the records
//! the tests write would fail here rather than in a deployment.
//!
//! Each test binary uses a subset of these helpers, hence the blanket allow.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role as SubjectRole, SchemaVer,
    SubjectHash, SubjectRef, Visibility, attrs,
    entity::{self, EntityRef},
};
use yaam_server::auth::{Caller, Credential, Keyring, Role};
use yaam_server::service::CoreService;

/// The redaction policy this repository's spec declares. A record must name the one in force.
pub const POLICY: &str = "default-v1";

/// The signing key every test caller shares. One key, several identities: what separates them is
/// the agent name in the signature, not the secret.
pub const KEY: &[u8] = b"an-integration-test-key";

/// A memory tree with the repository's spec in place, and the service over it.
pub struct Tree {
    dir: TempDir,
    /// The service under test, kept as its concrete type so a test can read the index directly.
    pub service: Arc<CoreService>,
}

impl Tree {
    /// Builds a tree, copying `spec/` in from the repository.
    pub fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        copy_dir(&spec, &dir.path().join("spec"));
        let service = CoreService::open(dir.path(), &dir.path().join("index.sqlite"))
            .expect("a service over a fresh tree");
        Self {
            dir,
            service: Arc::new(service),
        }
    }

    /// Root of the memory tree.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The index the service writes, for the one read no route exposes.
    ///
    /// Full-text search lives in the query layer and no endpoint reaches it, so a test asking that
    /// question opens the index the write path built. Derived from the same expression
    /// [`Tree::new`] hands the service, so the two cannot drift into different files.
    pub fn index(&self) -> PathBuf {
        self.dir.path().join("index.sqlite")
    }

    /// Whether a record's file is in the published tree.
    pub fn holds(&self, id: &RecordId) -> bool {
        walk(&self.root().join("records"))
            .iter()
            .any(|path| path.ends_with(format!("{}.md", id.as_str())))
    }

    /// The body as it sits on disk, for asserting what erasure reached.
    pub fn file_of(&self, id: &RecordId) -> String {
        let path = walk(&self.root().join("records"))
            .into_iter()
            .find(|path| path.ends_with(format!("{}.md", id.as_str())))
            .expect("a published record");
        fs::read_to_string(path).expect("read record")
    }
}

/// The callers these tests authenticate, and what each may do.
pub fn keyring() -> Keyring {
    Keyring::new()
        .with(Credential::new("agent_a", Role::Writer, KEY).in_teams(["platform"]))
        .with(Credential::new("agent_b", Role::Reader, KEY).in_teams(["support"]))
        .with(Credential::new("agent_ops", Role::Operator, KEY).in_teams(["platform"]))
}

/// A caller as the keyring would have resolved it.
pub fn caller(agent: &str, role: Role, teams: &[&str]) -> Caller {
    Caller {
        agent: agent.to_owned(),
        role,
        teams: teams.iter().map(|team| (*team).to_owned()).collect(),
    }
}

/// An internal, org-visible record attributed to `agent`, naming one ticket.
pub fn record(agent: &str, received_at: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: received_at.to_owned(),
        received_at: received_at.to_owned(),
        backfilled: false,
        agent: agent.to_owned(),
        agent_ver: Some("1.0.0".to_owned()),
        correlation_id: Some("corr-1".to_owned()),
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: BTreeMap::from([
            ("service".to_owned(), attrs::Value::Text("api".to_owned())),
            (
                "environment".to_owned(),
                attrs::Value::Text("staging".to_owned()),
            ),
            ("duration_ms".to_owned(), attrs::Value::Int(1_200)),
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
        tags: vec!["release".to_owned()],
        summary: BODY.to_owned(),
    }
}

/// A subject-derived record: its body is sealed, and destroying the subject's keys erases it.
pub fn subject_record(agent: &str, received_at: &str, subject: &SubjectHash) -> ActionRecord {
    let mut record = record(agent, received_at);
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
pub fn subject(fill: char) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", fill.to_string().repeat(64))).expect("a valid hash")
}

/// A body no configured redaction pattern matches.
pub const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// Copies a directory tree, which is how the repository's spec reaches a temporary root.
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read spec dir") {
        let entry = entry.expect("spec entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy spec file");
        }
    }
}

/// Every file under `root`, recursively.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            found.extend(walk(&entry.path()));
        } else {
            found.push(entry.path());
        }
    }
    found
}
