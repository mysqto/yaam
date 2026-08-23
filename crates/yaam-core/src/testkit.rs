//! Shared fixtures for this crate's tests.
//!
//! Two things live here because every test needs them and neither is the thing under test: a memory
//! root with a configured `spec/`, and a way to read the derived tables back. The vocabulary is
//! deliberately neutral — `deploy`, `ticket`, `order_ref` — because a fixture is where domain terms
//! leak in first.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use tempfile::TempDir;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role, SchemaVer, SubjectHash, SubjectRef,
    Visibility, attrs,
    entity::{self, EntityRef},
};

use crate::layout;
use crate::pipeline::Pipeline;

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
    "      sensitive_note: { type: string, class: sensitive }\n",
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
    "  - name: bearer_token\n",
    "    regex: '(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]{16,}'\n",
    "    action: mask\n",
    "  - name: email\n",
    "    regex: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b'\n",
    "    action: mask\n",
);

/// The policy name records must declare.
pub(crate) const POLICY: &str = "default-v1";

/// A memory root with a configured spec, and the pipeline over it.
///
/// The temporary directory is held so it outlives the pipeline; dropping the harness removes both.
pub(crate) struct Harness {
    /// Owns the temporary root.
    dir: TempDir,
    /// The pipeline under test.
    pub(crate) pipeline: Pipeline,
}

impl Harness {
    /// Builds a memory root with the fixture spec in place.
    pub(crate) fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let spec = dir.path().join(layout::SPEC_DIR);
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

    /// Deletes the index, connection and all, and reopens over the same tree.
    ///
    /// The drop is the point: an unlinked database a connection still holds open keeps working, so
    /// deleting the file underneath a live writer would make "the index is gone" a fiction.
    pub(crate) fn without_index(self) -> Self {
        let Self { dir, pipeline } = self;
        drop(pipeline);
        for suffix in ["", "-wal", "-shm"] {
            let path = dir.path().join(format!("{}{suffix}", layout::INDEX_FILE));
            crate::fsutil::remove_if_present(&path).expect("remove");
        }
        let pipeline = Pipeline::new(dir.path()).expect("pipeline");
        Self { dir, pipeline }
    }

    /// Rebuilds the pipeline over the same tree with a subject resolver in place.
    ///
    /// Destructured rather than assigned through the field, so the temporary root outlives the
    /// pipeline that is replaced.
    pub(crate) fn resolving_with(
        self,
        resolver: impl crate::resolve::SubjectResolver + 'static,
    ) -> Self {
        let Self { dir, pipeline } = self;
        Self {
            dir,
            pipeline: pipeline.with_subject_resolver(resolver),
        }
    }

    /// Rebuilds the pipeline over the same tree with key material wrapped at rest.
    pub(crate) fn wrapping_keys_with(
        self,
        wrapper: impl yaam_crypto::keystore::KeyWrapper + 'static,
    ) -> Self {
        let Self { dir, pipeline } = self;
        Self {
            dir,
            pipeline: pipeline.with_key_wrapper(wrapper).expect("key store"),
        }
    }

    /// Where a record's file belongs.
    pub(crate) fn path_of(&self, record: &ActionRecord) -> std::path::PathBuf {
        let stamp = layout::stamp_of(record).expect("a readable stamp");
        self.pipeline
            .published_path(record, &stamp)
            .expect("a derivable path")
    }

    /// Opens the index directly, for assertions the query API cannot make.
    fn index(&self) -> Connection {
        let conn = Connection::open_with_flags(
            self.root().join(layout::INDEX_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open index");
        conn.pragma_update(None, "foreign_keys", "ON")
            .expect("pragma");
        conn
    }

    /// Brings every delayed fan-out job's next claim forward, and says how many it moved.
    ///
    /// How a test reaches past a backoff without waiting it out, the way [`age`] reaches past the
    /// sweeper's grace period. A second writing connection is safe here because the pipeline's own
    /// writer is idle for as long as a test holds it still.
    pub(crate) fn release_fanout(&self) -> usize {
        self.writable()
            .execute(
                "UPDATE fanout_queue SET not_before_ms = 0 WHERE state = 'pending'",
                [],
            )
            .expect("release")
    }

    /// Puts every settled fan-out job back in the queue, and says how many it moved.
    ///
    /// A re-drive, as the queue sees one: the work has been done and something is about to do it
    /// again. That is what a reclaimed claim and a rebuild's re-enqueue both look like from here,
    /// and it is the state in which an append has to decide whether it already happened.
    pub(crate) fn requeue_fanout(&self) -> usize {
        self.writable()
            .execute(
                "UPDATE fanout_queue
                    SET state = 'pending', not_before_ms = 0, claimed_ms = NULL",
                [],
            )
            .expect("requeue")
    }

    /// Backdates every held fan-out claim, so a sweep sees the drain holding it as gone.
    pub(crate) fn age_fanout_claims(&self, by_ms: i64) -> usize {
        self.writable()
            .execute(
                "UPDATE fanout_queue SET claimed_ms = claimed_ms - ?1 WHERE state = 'claimed'",
                [by_ms],
            )
            .expect("age claims")
    }

    /// Every record's server-stamped time, in row-id order.
    ///
    /// Row id is the order the full-text index can be walked in, so "row ids follow the clock" is
    /// load-bearing rather than incidental: it is what makes a capped full-text candidate set the
    /// newest matches rather than an arbitrary corner of the store.
    pub(crate) fn received_ms_by_row_id(&self) -> Vec<i64> {
        let conn = self.index();
        let mut stmt = conn
            .prepare("SELECT received_ms FROM records ORDER BY id")
            .expect("prepare");
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .expect("query");
        rows.map(|row| row.expect("row")).collect()
    }

    /// State and attempt count of the one queued job, for the retry tests.
    pub(crate) fn fanout_row(&self) -> (String, u32) {
        self.index()
            .query_row(
                "SELECT state, attempts FROM fanout_queue ORDER BY id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("a queued job")
    }

    /// A connection that may write, for the helpers that stand in for time passing.
    fn writable(&self) -> Connection {
        let conn = Connection::open(self.root().join(layout::INDEX_FILE)).expect("open index");
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .expect("busy timeout");
        conn
    }

    /// Row count of every derived table.
    pub(crate) fn counts(&self) -> BTreeMap<&'static str, i64> {
        let conn = self.index();
        DERIVED_TABLES
            .iter()
            .map(|table| {
                let count = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .expect("count");
                (*table, count)
            })
            .collect()
    }

    /// A logical dump of every derived table.
    ///
    /// Logical, not byte-for-byte: integer primary keys are renumbered by a rebuild and a `SQLite`
    /// file is not reproducible byte for byte, so the comparison is over the content that is
    /// supposed to be derivable. Queue *state* is excluded for the same reason — a drained job and a
    /// freshly enqueued one carry the same work.
    pub(crate) fn snapshot(&self) -> Vec<String> {
        let conn = self.index();
        let mut lines = Vec::new();
        for (label, sql) in SNAPSHOT_QUERIES {
            let mut stmt = conn.prepare(sql).expect("prepare");
            let columns = stmt.column_count();
            let mut rows = stmt.query([]).expect("query");
            while let Some(row) = rows.next().expect("row") {
                let cells: Vec<String> = (0..columns)
                    .map(|index| match row.get_ref(index).expect("cell") {
                        rusqlite::types::ValueRef::Null => "~".to_owned(),
                        rusqlite::types::ValueRef::Integer(v) => v.to_string(),
                        rusqlite::types::ValueRef::Real(v) => format!("{v:?}"),
                        rusqlite::types::ValueRef::Text(v) => {
                            String::from_utf8_lossy(v).into_owned()
                        }
                        rusqlite::types::ValueRef::Blob(v) => hex::encode(v),
                    })
                    .collect();
                lines.push(format!("{label}|{}", cells.join("|")));
            }
        }
        lines
    }
}

/// Every table a rebuild has to reproduce.
///
/// `timeline_mentions` is here for the same reason the rest are, with one wrinkle: its rows are
/// written by the fan-out drain rather than by the publish, so a rebuild reproduces them only once
/// the queue it re-enqueued has been drained.
const DERIVED_TABLES: [&str; 8] = [
    "records",
    "record_attrs",
    "entity_refs",
    "record_subjects",
    "entities",
    "fanout_queue",
    "timeline_mentions",
    "quarantine_pending",
];

/// One query per derived table, ordered so two runs compare line by line.
const SNAPSHOT_QUERIES: [(&str, &str); 8] = [
    (
        "record",
        "SELECT record_id, schema_ver, frontmatter, body, at_ms, received_ms, action, outcome,
                agent, correlation_id, sealed
         FROM records ORDER BY record_id",
    ),
    (
        "attr",
        "SELECT r.record_id, a.key, a.value FROM record_attrs AS a
         JOIN records AS r ON r.id = a.record_pk ORDER BY r.record_id, a.key",
    ),
    (
        "entity_ref",
        "SELECT r.record_id, e.kind, e.entity_id, e.role, e.confidence, e.received_ms
         FROM entity_refs AS e
         JOIN records AS r ON r.id = e.record_pk
         ORDER BY r.record_id, e.kind, e.entity_id, e.role",
    ),
    (
        "subject",
        "SELECT r.record_id, s.subject_hash, s.role, s.canon_ver, s.epoch, s.wrapped_key_share
         FROM record_subjects AS s JOIN records AS r ON r.id = s.record_pk
         ORDER BY r.record_id, s.subject_hash",
    ),
    (
        "entity",
        "SELECT kind, entity_id, first_seen_ms, last_seen_ms, ref_count FROM entities
         ORDER BY kind, entity_id",
    ),
    (
        "job",
        "SELECT record_id, job_kind, enqueued_ms FROM fanout_queue ORDER BY record_id, job_kind",
    ),
    (
        "mention",
        "SELECT record_id, kind, entity_id FROM timeline_mentions
         ORDER BY record_id, kind, entity_id",
    ),
    (
        // `first_seen_ms` is left out: it is the one column read from the clock rather than derived,
        // so a rebuild cannot be expected to reproduce it.
        "held",
        "SELECT record_id, qkek_date, staging_path FROM quarantine_pending ORDER BY record_id",
    ),
];

/// How many times a record's link appears across a timeline head and all its frozen parts.
///
/// One number over every file, because "listed once" is a claim about the timeline as a whole: a
/// count per file would pass while a re-drive wrote the same line into the head and into a part.
pub(crate) fn timeline_mentions(dir: &Path, record: &RecordId) -> usize {
    let needle = format!("[[record:{}", record.as_str());
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("timeline"))
        })
        .map(|entry| {
            fs::read_to_string(entry.path())
                .unwrap_or_default()
                .matches(&needle)
                .count()
        })
        .sum()
}

/// Backdates a file's modification time, which is how a test reaches past a grace period.
pub(crate) fn age(path: &Path, by_ms: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_millis(by_ms);
    fs::File::options()
        .write(true)
        .open(path)
        .expect("open")
        .set_times(fs::FileTimes::new().set_modified(when))
        .expect("set times");
}

/// A subject pseudonym, distinct per `fill`, which must be a lowercase hex digit.
pub(crate) fn subject(fill: char) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", fill.to_string().repeat(64))).expect("a valid hash")
}

/// An internal record: plaintext body, no subjects, two entity references.
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

/// The permission bits of a path.
///
/// Tests assert on these because "tighter filesystem permissions" is a mode or it is nothing: a
/// record stored apart under the process umask is still a record anybody on the host can read.
#[cfg(unix)]
pub(crate) fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

/// A subject-derived record: sealed body, one or more named subjects.
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

/// One cold manifest line for a record, newline included.
///
/// Nothing in this repo writes `cold/` — an archive is produced externally — so a test that reads a
/// manifest has to write one, and every such test has to write the *same* thing: the frontmatter
/// projection, which is a record minus its `summary`. Shared here so a test cannot quietly agree
/// with a format only it believes in.
pub(crate) fn manifest_line(record: &ActionRecord) -> String {
    let mut json = serde_json::to_value(record).expect("json");
    json.as_object_mut().expect("object").remove("summary");
    let mut line = serde_json::to_string(&json).expect("line");
    line.push('\n');
    line
}

/// A body no configured redaction pattern matches.
pub(crate) const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// The document an internal record becomes on disk.
///
/// The same shape validation produces — summary and body hold the same prose — so a test can drive
/// the write steps one at a time without going through [`Pipeline::accept`], which is what makes a
/// crash between two of them reproducible.
pub(crate) fn plain_document(record: &ActionRecord, body: &str) -> yaam_md::Document {
    let mut record = record.clone();
    record.summary = body.to_owned();
    yaam_md::Document {
        record,
        body: yaam_md::Body::Plain(body.to_owned()),
    }
}
