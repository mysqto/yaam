//! Behaviour of the derived index, exercised through its public surface.
//!
//! Several of these tests exist to catch a *silent* failure: a missing pragma, a full-text index
//! that stopped tracking its content table, an index the planner quietly stopped using. Each of
//! those still returns plausible answers, so only an explicit assertion notices.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role, SchemaVer, SubjectHash, SubjectRef,
    Visibility, attrs, entity,
};
use yaam_crypto::Epoch;
use yaam_store::query::{self, Filter, Scope, Window};
use yaam_store::{PublishInput, Store, Writer, schema};

const T10: &str = "2026-08-20T10:00:00Z";
const T11: &str = "2026-08-20T11:00:00Z";
const T12: &str = "2026-08-20T12:00:00Z";

/// The clock a queue test hands to a claim. Fixed, because a backoff measured against a real clock
/// is a test that passes at a speed rather than for a reason.
const NOW: i64 = 1_787_220_000_000;

/// A minimal internal record. Tests adjust only the field under test.
fn record(action: &str, outcome: Outcome, received_at: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: received_at.to_owned(),
        received_at: received_at.to_owned(),
        backfilled: false,
        agent: "deploy_bot".to_owned(),
        agent_ver: Some("1.2.3".to_owned()),
        correlation_id: Some("corr-1".to_owned()),
        action: action.to_owned(),
        outcome,
        attrs: BTreeMap::new(),
        entities: Vec::new(),
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: "default".to_owned(),
        fields_masked: Vec::new(),
        tags: vec!["routine".to_owned()],
        summary: "nothing notable".to_owned(),
    }
}

fn entity_ref(kind: &str, id: &str, confidence: f32) -> entity::EntityRef {
    entity::EntityRef {
        kind: kind.to_owned(),
        id: id.to_owned(),
        role: entity::Role::Primary,
        confidence,
    }
}

fn subject_hash(seed: &str) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", seed.repeat(64 / seed.len()))).expect("subject hash")
}

fn subject(seed: &str) -> SubjectRef {
    SubjectRef {
        hash: subject_hash(seed),
        role: Role::Principal,
        canon_ver: CanonVer(1),
    }
}

/// Publishes a record with no key shares, as a reindex from the tree would.
///
/// A sealed record's body is `""`: the prose is inside the ciphertext, and the index must not hold
/// a second copy of it.
fn publish(writer: &mut Writer, doc: &ActionRecord) -> yaam_store::Result<()> {
    let body = match doc.data_class {
        DataClass::Internal => doc.summary.as_str(),
        DataClass::SubjectDerived => "",
    };
    writer.publish(PublishInput {
        record: doc,
        searchable_body: body,
        subject_keys: &[],
    })
}

/// A connection carrying the store's own pragmas, for assertions the query API does not expose.
fn raw(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("open");
    schema::apply_pragmas(&conn).expect("pragmas");
    conn
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("count")
}

fn ids(records: &[RecordId]) -> Vec<&str> {
    records.iter().map(RecordId::as_str).collect()
}

/// The identifiers a structure read returned, so a scope assertion reads the same either way.
fn structure_ids(records: &[yaam_contract::RecordStructure]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record.record_id.as_str())
        .collect()
}

/// The scope a maintenance read uses: everything, whatever its visibility.
///
/// Most tests here are about a predicate or a plan rather than about entitlements, and reading as
/// nobody in particular would hide the rows they are asserting on.
const ALL: Scope = Scope::Unrestricted;

/// A filter that hides nothing, for the tests whose subject is not visibility.
fn unfiltered() -> Filter {
    Filter {
        scope: ALL,
        ..Filter::default()
    }
}

#[test]
fn migrating_twice_leaves_the_same_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");

    let mut conn = Connection::open(&path).expect("open");
    schema::apply_pragmas(&conn).expect("pragmas");
    schema::migrate(&mut conn).expect("first migrate");
    let objects = count(&conn, "sqlite_schema");
    let version: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version");

    schema::migrate(&mut conn).expect("second migrate");
    assert_eq!(count(&conn, "sqlite_schema"), objects);
    assert_eq!(version, schema::SCHEMA_VERSION);
    assert_eq!(
        conn.query_row::<u32, _, _>("PRAGMA user_version", [], |row| row.get(0))
            .expect("version"),
        schema::SCHEMA_VERSION
    );
}

#[test]
fn a_newer_schema_is_refused_rather_than_downgraded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    Writer::open(&path).expect("open writer");
    raw(&path)
        .execute_batch("PRAGMA user_version = 99")
        .expect("bump version");

    let error = Writer::open(&path).expect_err("must refuse");
    assert!(
        matches!(
            error,
            yaam_store::Error::SchemaTooNew { found: 99, supported } if supported == schema::SCHEMA_VERSION
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn deleting_a_record_cascades_to_everything_derived_from_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![
        entity_ref("deploy", "svc-a/2026.8.1", 1.0),
        entity_ref("ticket", "TCK-77", 0.6),
    ];
    doc.subjects = vec![subject("ab")];
    doc.attrs
        .insert("region".to_owned(), attrs::Value::Text("north".to_owned()));
    publish(&mut writer, &doc).expect("publish");
    writer
        .claim_timeline_mention(doc.record_id.as_str(), "ticket", "TCK-77")
        .expect("claim")
        .expect("a first claim")
        .commit()
        .expect("commit");

    let conn = raw(&path);
    assert_eq!(count(&conn, "entity_refs"), 2);
    assert_eq!(count(&conn, "record_subjects"), 1);
    assert_eq!(count(&conn, "record_attrs"), 1);
    assert_eq!(count(&conn, "timeline_mentions"), 1);
    assert!(count(&conn, "fanout_queue") > 0);

    conn.execute_batch("DELETE FROM records").expect("delete");
    assert_eq!(count(&conn, "entity_refs"), 0, "cascade did not reach refs");
    assert_eq!(count(&conn, "record_subjects"), 0);
    assert_eq!(count(&conn, "record_attrs"), 0);
    assert_eq!(count(&conn, "fanout_queue"), 0);
    assert_eq!(
        count(&conn, "timeline_mentions"),
        0,
        "a mention outliving its record would be a line nothing would ever write again"
    );
}

#[test]
fn the_cascade_depends_on_the_pragma_being_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![entity_ref("deploy", "svc-a/2026.8.1", 1.0)];
    publish(&mut writer, &doc).expect("publish");

    // apply_pragmas must leave the enforcement on whatever the library was built to default to:
    // upstream SQLite defaults it off, and this build happens to default it on, so neither the
    // presence nor the absence of the call can be inferred from behaviour alone.
    assert_eq!(
        raw(&path)
            .query_row::<i64, _, _>("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("pragma"),
        1
    );

    // With enforcement off the reference outlives its record: the cascade is the pragma's doing,
    // not something the schema achieves on its own.
    let unenforced = Connection::open(&path).expect("open");
    unenforced
        .execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM records;")
        .expect("delete");
    assert_eq!(count(&unenforced, "entity_refs"), 1);
}

#[test]
fn full_text_finds_a_plaintext_body_and_never_a_sealed_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut plain = record("deploy", Outcome::Success, T10);
    plain.summary = "rollback of the checkout service completed".to_owned();
    publish(&mut writer, &plain).expect("publish plain");

    let mut sealed = record("chat_message", Outcome::Success, T11);
    sealed.data_class = DataClass::SubjectDerived;
    sealed.subjects = vec![subject("cd")];
    sealed.summary = "distinctivetoken about a named person".to_owned();
    publish(&mut writer, &sealed).expect("publish sealed");

    let store = Store::open_read(&path).expect("open read");
    assert_eq!(
        ids(&query::search(&store, "rollback", 10, &ALL).expect("search")),
        vec![plain.record_id.as_str()]
    );
    assert!(
        query::search(&store, "distinctivetoken", 10, &ALL)
            .expect("search")
            .is_empty(),
        "a sealed body must not be searchable"
    );

    // Not merely absent from the index: absent from the row, and from the frontmatter too, so no
    // copy of the prose survives where key destruction cannot reach.
    let conn = raw(&path);
    let (body, frontmatter): (String, String) = conn
        .query_row(
            "SELECT body, frontmatter FROM records WHERE record_id = ?1",
            [sealed.record_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("row");
    assert!(body.is_empty());
    assert!(!frontmatter.contains("distinctivetoken"));
}

/// The projection a request reads full text with: the row itself, and never the prose that matched.
#[test]
fn a_full_text_read_answers_with_structure_and_pages_like_every_other_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut first = record("deploy", Outcome::Success, T10);
    first.summary = "the second shard stalled and the rollout stopped".to_owned();
    publish(&mut writer, &first).expect("publish");
    let mut second = record("deploy", Outcome::Failure, T11);
    second.summary = "a later attempt stalled on the same shard".to_owned();
    publish(&mut writer, &second).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let found = query::search_structures(&store, "stalled", None, &ALL).expect("search");
    assert_eq!(found.len(), 2, "{:?}", structure_ids(&found));
    // The structure the record was stored with, and no field carrying what the needle matched.
    for structure in &found {
        let written = [&first, &second]
            .into_iter()
            .find(|doc| doc.record_id == structure.record_id)
            .expect("a record this test wrote");
        assert_eq!(structure, &yaam_contract::RecordStructure::from(written));
        let json = serde_json::to_string(structure).expect("serialisable");
        assert!(!json.contains("stalled"), "the body came back: {json}");
    }

    // The page size means what it means everywhere else: a number is honoured, and zero is a page
    // of no rows rather than a page size nobody named.
    assert_eq!(
        query::search_structures(&store, "stalled", Some(1), &ALL)
            .expect("search")
            .len(),
        1
    );
    assert!(
        query::search_structures(&store, "stalled", Some(0), &ALL)
            .expect("search")
            .is_empty(),
        "zero rows is a page a caller may ask for"
    );
}

#[test]
fn full_text_stays_consistent_across_insert_update_and_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut first = record("deploy", Outcome::Success, T10);
    first.summary = "rollback completed".to_owned();
    publish(&mut writer, &first).expect("publish");
    let second = record("deploy", Outcome::Failure, T11);
    publish(&mut writer, &second).expect("publish");

    let conn = raw(&path);
    let integrity = "INSERT INTO records_fts (records_fts) VALUES ('integrity-check')";
    conn.execute_batch(integrity)
        .expect("integrity after insert");

    conn.execute(
        "UPDATE records SET body = 'promotion completed' WHERE record_id = ?1",
        [first.record_id.as_str()],
    )
    .expect("update body");
    conn.execute_batch(integrity)
        .expect("integrity after update");

    let store = Store::open_read(&path).expect("open read");
    assert!(
        query::search(&store, "rollback", 10, &ALL)
            .expect("search")
            .is_empty(),
        "the update trigger did not unindex the old body"
    );
    assert_eq!(
        ids(&query::search(&store, "promotion", 10, &ALL).expect("search")),
        vec![first.record_id.as_str()]
    );

    conn.execute(
        "DELETE FROM records WHERE record_id = ?1",
        [second.record_id.as_str()],
    )
    .expect("delete");
    conn.execute_batch(integrity)
        .expect("integrity after delete");
}

#[test]
fn promoted_columns_populate_from_the_frontmatter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let doc = record("deploy", Outcome::Declined, T10);
    publish(&mut writer, &doc).expect("publish");

    let conn = raw(&path);
    let (action, outcome, agent, sealed): (String, String, String, i64) = conn
        .query_row(
            "SELECT action, outcome, agent, sealed FROM records WHERE record_id = ?1",
            [doc.record_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("row");
    assert_eq!(action, "deploy");
    assert_eq!(outcome, "declined");
    assert_eq!(agent, "deploy_bot");
    assert_eq!(sealed, 0);
}

#[test]
fn timestamps_are_integer_milliseconds_and_ordering_follows_the_server_clock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    // Source clock says this happened first; the server stamped it last.
    let mut skewed = record("deploy", Outcome::Success, T12);
    skewed.at = "2026-08-20T09:00:00.250Z".to_owned();
    publish(&mut writer, &skewed).expect("publish");
    let later_source = record("deploy", Outcome::Success, T11);
    publish(&mut writer, &later_source).expect("publish");

    let conn = raw(&path);
    let (at_ms, received_ms): (i64, i64) = conn
        .query_row(
            "SELECT at_ms, received_ms FROM records WHERE record_id = ?1",
            [skewed.record_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("row");
    assert_eq!(at_ms, 1_787_216_400_250);
    assert_eq!(received_ms, 1_787_227_200_000);

    let store = Store::open_read(&path).expect("open read");
    let newest_first = query::by_filter(&store, &unfiltered()).expect("filter");
    assert_eq!(
        ids(&newest_first),
        vec![skewed.record_id.as_str(), later_source.record_id.as_str()]
    );
}

/// A record at `visibility`, owned by `agent`, optionally in `team`.
fn scoped(
    visibility: Visibility,
    agent: &str,
    team: Option<&str>,
    received_at: &str,
) -> ActionRecord {
    let mut doc = record("deploy", Outcome::Success, received_at);
    doc.visibility = visibility;
    agent.clone_into(&mut doc.agent);
    doc.team = team.map(str::to_owned);
    // The team is in the prose as well as the column, so a full-text read can be caught returning
    // a record the scope should have hidden.
    doc.summary = format!(
        "{} record of {agent}, team {}",
        visibility.as_str(),
        team.unwrap_or("none")
    );
    doc.entities = vec![entity_ref("ticket", "TCK-1", 1.0)];
    doc
}

/// One reader's entitlements: org-wide, its own team, and its own owner-visible records.
fn reader(agent: &str, teams: &[&str]) -> Scope {
    Scope::Caller {
        visibility: vec![Visibility::Org, Visibility::Team, Visibility::Owner],
        agent: agent.to_owned(),
        teams: teams.iter().map(|team| (*team).to_owned()).collect(),
    }
}

/// A tree holding one record at each visibility, and the reader/operator scopes to try on it.
///
/// One fixture for every scoped test, so a rule that leaks through *any* of the four read paths is
/// visible as one failing assertion rather than a missing test.
fn visibility_fixture() -> (tempfile::TempDir, std::path::PathBuf, Vec<ActionRecord>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let docs = vec![
        scoped(Visibility::Org, "deploy_bot", None, T10),
        scoped(Visibility::Team, "deploy_bot", Some("platform"), T10),
        scoped(Visibility::Team, "deploy_bot", Some("support"), T11),
        scoped(Visibility::Owner, "deploy_bot", None, T11),
        scoped(Visibility::Operator, "audit_bot", None, T12),
    ];
    for doc in &docs {
        publish(&mut writer, doc).expect("publish");
    }
    (dir, path, docs)
}

#[test]
fn a_reader_sees_its_own_team_and_no_other() {
    let (_dir, path, docs) = visibility_fixture();
    let store = Store::open_read(&path).expect("open read");

    let filter = Filter {
        scope: reader("deploy_bot", &["platform"]),
        ..Filter::default()
    };
    let visible = query::by_filter(&store, &filter).expect("filter");
    assert_eq!(
        ids(&visible),
        vec![
            docs[3].record_id.as_str(),
            docs[1].record_id.as_str(),
            docs[0].record_id.as_str(),
        ],
        "another team's record, and the audit record, must not be in here"
    );

    // A reader in no team keeps the org-wide record and loses both team ones.
    let teamless = Filter {
        scope: reader("deploy_bot", &[]),
        ..Filter::default()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &teamless).expect("filter")),
        vec![docs[3].record_id.as_str(), docs[0].record_id.as_str()]
    );
}

#[test]
fn an_owner_visible_record_is_invisible_to_another_caller() {
    let (_dir, path, docs) = visibility_fixture();
    let store = Store::open_read(&path).expect("open read");

    let other = Filter {
        scope: reader("audit_bot", &["platform"]),
        ..Filter::default()
    };
    let rows = query::by_filter(&store, &other).expect("filter");
    let visible = ids(&rows);
    assert!(
        !visible.contains(&docs[3].record_id.as_str()),
        "another agent's owner-visible record reached {visible:?}"
    );

    // The same entitlement under its own identity does see it.
    let owner = Filter {
        scope: reader("deploy_bot", &[]),
        ..Filter::default()
    };
    let rows = query::by_filter(&store, &owner).expect("filter");
    assert!(ids(&rows).contains(&docs[3].record_id.as_str()));
}

#[test]
fn only_an_operator_scope_sees_an_audit_record() {
    let (_dir, path, docs) = visibility_fixture();
    let store = Store::open_read(&path).expect("open read");
    let audit = docs[4].record_id.as_str();

    let rows = query::by_filter(
        &store,
        &Filter {
            scope: reader("audit_bot", &["platform"]),
            ..Filter::default()
        },
    )
    .expect("filter");
    let reader_sees = ids(&rows);
    assert!(!reader_sees.contains(&audit), "{reader_sees:?}");

    let operator = Scope::Caller {
        visibility: vec![
            Visibility::Org,
            Visibility::Team,
            Visibility::Owner,
            Visibility::Operator,
        ],
        agent: "audit_bot".to_owned(),
        teams: vec!["platform".to_owned()],
    };
    let rows = query::by_filter(
        &store,
        &Filter {
            scope: operator,
            ..Filter::default()
        },
    )
    .expect("filter");
    let operator_sees = ids(&rows);
    assert!(operator_sees.contains(&audit), "{operator_sees:?}");
}

#[test]
fn every_read_path_applies_the_scope() {
    let (_dir, path, docs) = visibility_fixture();
    let store = Store::open_read(&path).expect("open read");
    let scope = reader("deploy_bot", &["platform"]);
    let hidden = docs[2].record_id.as_str();

    // Entity history: every record here names the same ticket, so only the scope can narrow it.
    let rows =
        query::by_entity(&store, "ticket", "TCK-1", 1.0, None, None, &scope).expect("by_entity");
    let history = ids(&rows);
    assert!(!history.contains(&hidden), "{history:?}");
    assert!(history.contains(&docs[1].record_id.as_str()));

    // The structure projections answer the same rows. Widening the select list must not widen the
    // predicate: a caller outside a record's scope receives neither its structure nor its id.
    let structured =
        query::by_entity_structures(&store, "ticket", "TCK-1", 1.0, None, None, &scope)
            .expect("entity");
    assert_eq!(structure_ids(&structured), history);
    let filtered = query::by_filter_structures(
        &store,
        &Filter {
            scope: scope.clone(),
            ..Filter::default()
        },
    )
    .expect("filter");
    assert!(!structure_ids(&filtered).contains(&hidden), "{filtered:?}");

    // Full text: the other team's summary is in the index, and must not be reachable.
    let hidden_text = query::search(&store, "support", 10, &scope).expect("search");
    assert!(hidden_text.is_empty(), "{:?}", ids(&hidden_text));
    assert!(
        !query::search(&store, "platform", 10, &scope)
            .expect("search")
            .is_empty(),
        "the caller's own team must still be searchable"
    );
    // And the projection a request reads with, which is the one that would hand over the row
    // itself: the wider select list must not widen the match's scope test either.
    assert!(
        query::search_structures(&store, "support", None, &scope)
            .expect("search")
            .is_empty(),
        "the other team's body was reachable as structure"
    );
    assert!(
        !query::search_structures(&store, "platform", None, &scope)
            .expect("search")
            .is_empty()
    );

    // Correlation: each side carries its own scope, so a pair needs both ends visible.
    let left = Filter {
        scope: scope.clone(),
        ..Filter::default()
    };
    let pairs = query::correlate(&store, &left, &left, 7_200_000).expect("correlate");
    assert!(
        pairs
            .iter()
            .all(|(a, b)| a.as_str() != hidden && b.as_str() != hidden),
        "{pairs:?}"
    );
}

#[test]
fn a_read_with_no_scope_returns_nothing_rather_than_everything() {
    let (_dir, path, _docs) = visibility_fixture();
    let store = Store::open_read(&path).expect("open read");

    // The default scope is what a caller whose entitlements could not be established gets.
    assert!(
        query::by_filter(&store, &Filter::default())
            .expect("filter")
            .is_empty()
    );
    assert!(
        query::by_entity(
            &store,
            "ticket",
            "TCK-1",
            1.0,
            None,
            None,
            &Scope::default()
        )
        .expect("by_entity")
        .is_empty()
    );
    assert!(
        query::search(&store, "visible", 10, &Scope::default())
            .expect("search")
            .is_empty()
    );
    assert!(
        query::search_structures(&store, "visible", None, &Scope::default())
            .expect("search")
            .is_empty()
    );
    assert!(
        query::correlate(&store, &Filter::default(), &Filter::default(), 7_200_000)
            .expect("correlate")
            .is_empty()
    );
    // The structure reads default the same way. A projection that widened what an unscoped read
    // returns would hand out structure to a caller nothing authenticated.
    assert!(
        query::by_filter_structures(&store, &Filter::default())
            .expect("filter")
            .is_empty()
    );
    assert!(
        query::by_entity_structures(
            &store,
            "ticket",
            "TCK-1",
            1.0,
            None,
            None,
            &Scope::default()
        )
        .expect("by_entity")
        .is_empty()
    );
}

/// A structure read hands back the frontmatter the record was stored with, field for field.
#[test]
fn a_structure_read_returns_the_stored_frontmatter_and_never_a_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut plain = record("deploy", Outcome::Partial, T10);
    plain.attrs = BTreeMap::from([
        ("service".to_owned(), attrs::Value::Text("api".to_owned())),
        ("duration_ms".to_owned(), attrs::Value::Int(1_420)),
        ("rolled_back".to_owned(), attrs::Value::Bool(true)),
    ]);
    plain.entities = vec![entity_ref("ticket", "TCK-1", 1.0)];
    plain.summary = "prose no read may hand back".to_owned();
    publish(&mut writer, &plain).expect("publish");

    let mut sealed = record("lookup", Outcome::Success, T11);
    sealed.data_class = DataClass::SubjectDerived;
    sealed.subjects = vec![subject("ab")];
    sealed.entities = vec![entity_ref("ticket", "TCK-1", 1.0)];
    sealed.summary = "sealed prose no read may hand back".to_owned();
    publish(&mut writer, &sealed).expect("publish");
    drop(writer);

    let store = Store::open_read(&path).expect("open read");
    let rows = query::by_filter_structures(&store, &unfiltered()).expect("filter");
    assert_eq!(rows.len(), 2, "{rows:?}");

    // Both classes, and neither carries prose: the rule does not branch on `data_class`.
    let json = serde_json::to_string(&rows).expect("serialises");
    assert!(!json.contains("summary"), "{json}");
    assert!(!json.contains("no read may hand back"), "{json}");

    let found = rows
        .iter()
        .find(|row| row.record_id == plain.record_id)
        .expect("the plaintext record");
    assert_eq!(found, &yaam_contract::RecordStructure::from(&plain));
    let found = rows
        .iter()
        .find(|row| row.record_id == sealed.record_id)
        .expect("the sealed record");
    assert_eq!(found, &yaam_contract::RecordStructure::from(&sealed));
}

/// A frontmatter column this build cannot read is drift, named by the record it belongs to.
///
/// Reported rather than skipped or passed through: a read that dropped the row would answer with a
/// short page nobody could tell from a short history, and one that forwarded the column would hand
/// a caller whatever the store happened to hold.
#[test]
fn a_frontmatter_column_the_contract_cannot_read_is_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let doc = record("deploy", Outcome::Success, T10);
    publish(&mut writer, &doc).expect("publish");
    drop(writer);

    let intact: String = raw(&path)
        .query_row("SELECT frontmatter FROM records", [], |row| row.get(0))
        .expect("the stored projection");

    // Two ways the column can stop matching the record: a key the read shape does not declare, and
    // an identifier that disagrees with the one every index is keyed by. Restored between the two,
    // so the second is the failure it names rather than the first one again.
    for tamper in [
        "json_set(frontmatter, '$.summary', 'prose')",
        "json_set(frontmatter, '$.record_id', '01ARZ3NDEKTSV4RRFFQ69G5FAV')",
    ] {
        let conn = raw(&path);
        conn.execute("UPDATE records SET frontmatter = ?1", [&intact])
            .expect("restore");
        conn.execute_batch(&format!("UPDATE records SET frontmatter = {tamper}"))
            .expect("tamper");
        drop(conn);

        let store = Store::open_read(&path).expect("open read");
        let error = query::by_filter_structures(&store, &unfiltered())
            .expect_err("a projection that does not match the record");
        assert!(
            matches!(&error, yaam_store::Error::Drift(id) if id == doc.record_id.as_str()),
            "{error}"
        );
    }
}

#[test]
fn an_unparseable_timestamp_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.received_at = "last tuesday".to_owned();

    let error = publish(&mut writer, &doc).expect_err("must refuse");
    assert!(
        matches!(error, yaam_store::Error::Sqlite(_)),
        "unexpected error: {error}"
    );
    assert_eq!(count(&raw(&path), "records"), 0);
}

#[test]
fn replaying_a_record_changes_no_row_counts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![entity_ref("order_ref", "ORD-1001", 1.0)];
    doc.subjects = vec![subject("ef")];
    doc.attrs
        .insert("region".to_owned(), attrs::Value::Text("north".to_owned()));
    doc.attrs.insert("attempt".to_owned(), attrs::Value::Int(2));
    doc.attrs
        .insert("dry_run".to_owned(), attrs::Value::Bool(false));

    publish(&mut writer, &doc).expect("publish");
    let conn = raw(&path);
    let tables = [
        "records",
        "record_attrs",
        "entity_refs",
        "record_subjects",
        "entities",
        "fanout_queue",
    ];
    let before: Vec<i64> = tables.iter().map(|table| count(&conn, table)).collect();

    publish(&mut writer, &doc).expect("replay");
    let after: Vec<i64> = tables.iter().map(|table| count(&conn, table)).collect();
    assert_eq!(before, after, "a replay added rows");

    // Recomputed, not incremented: an incremented counter would read 2 here.
    let refs: i64 = conn
        .query_row("SELECT ref_count FROM entities", [], |row| row.get(0))
        .expect("ref_count");
    assert_eq!(refs, 1);
}

#[test]
fn the_entity_catalog_is_recomputed_from_the_references() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    for stamp in [T10, T12] {
        let mut doc = record("deploy", Outcome::Success, stamp);
        doc.entities = vec![entity_ref("order_ref", "ORD-1001", 1.0)];
        publish(&mut writer, &doc).expect("publish");
    }

    let (first, last, refs): (i64, i64, i64) = raw(&path)
        .query_row(
            "SELECT first_seen_ms, last_seen_ms, ref_count FROM entities
             WHERE kind = 'order_ref' AND entity_id = 'ORD-1001'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("row");
    assert_eq!(refs, 2);
    assert!(first < last);
}

#[test]
fn by_entity_is_newest_first_and_honours_confidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut certain = record("deploy", Outcome::Success, T10);
    certain.entities = vec![entity_ref("ticket", "TCK-77", 1.0)];
    publish(&mut writer, &certain).expect("publish");

    let mut inferred = record("chat_user", Outcome::Success, T12);
    inferred.entities = vec![entity_ref("ticket", "TCK-77", 0.4)];
    publish(&mut writer, &inferred).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let all =
        query::by_entity(&store, "ticket", "TCK-77", 0.0, None, None, &ALL).expect("by_entity");
    assert_eq!(
        ids(&all),
        vec![inferred.record_id.as_str(), certain.record_id.as_str()]
    );

    let confident =
        query::by_entity(&store, "ticket", "TCK-77", 0.9, None, None, &ALL).expect("by_entity");
    assert_eq!(ids(&confident), vec![certain.record_id.as_str()]);
    assert!(
        query::by_entity(&store, "ticket", "TCK-99", 0.0, None, None, &ALL)
            .expect("by_entity")
            .is_empty()
    );
}

/// One entity inside one window, half-open at the end.
///
/// The half-open end is the property worth pinning: consecutive windows have to tile without
/// double-counting the instant they share, or a correlation run window by window reports the record
/// on the boundary twice.
#[test]
fn by_entity_narrows_to_a_window() {
    // The two instants as the index stores them. Spelled out rather than parsed: a window is asked
    // for in milliseconds, and a test that computed them from the same strings the fixture used
    // would agree with itself about a conversion neither the caller nor the index performs.
    const T10_MS: i64 = 1_787_220_000_000;
    const T12_MS: i64 = 1_787_227_200_000;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut early = record("deploy", Outcome::Success, T10);
    early.entities = vec![entity_ref("ticket", "TCK-88", 1.0)];
    publish(&mut writer, &early).expect("publish");

    let mut late = record("transact", Outcome::Declined, T12);
    late.entities = vec![entity_ref("ticket", "TCK-88", 1.0)];
    publish(&mut writer, &late).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    // Owned, because `ids` borrows the rows and the rows here are a temporary.
    let window = |from_ms, to_ms| -> Vec<String> {
        let rows = query::by_entity(
            &store,
            "ticket",
            "TCK-88",
            0.0,
            Some(Window { from_ms, to_ms }),
            None,
            &ALL,
        )
        .expect("by_entity");
        ids(&rows).into_iter().map(str::to_owned).collect()
    };

    // No window is every reference, newest first.
    assert_eq!(
        ids(
            &query::by_entity(&store, "ticket", "TCK-88", 0.0, None, None, &ALL)
                .expect("by_entity")
        ),
        vec![late.record_id.as_str(), early.record_id.as_str()]
    );
    // A window holding one of them holds only it.
    assert_eq!(
        window(T10_MS, T12_MS),
        vec![early.record_id.as_str().to_owned()]
    );
    // Inclusive start, exclusive end: T12 is in the window that starts at it and out of the one that
    // ends at it.
    assert_eq!(
        window(T12_MS, T12_MS + 1),
        vec![late.record_id.as_str().to_owned()]
    );
    // A window either side of both is empty rather than falling back to the whole history.
    assert!(window(T12_MS + 1, T12_MS + 2).is_empty());
}

#[test]
fn by_filter_matches_on_every_predicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut wanted = record("deploy", Outcome::Failure, T11);
    wanted
        .attrs
        .insert("region".to_owned(), attrs::Value::Text("north".to_owned()));
    publish(&mut writer, &wanted).expect("publish");

    let mut other = record("deploy", Outcome::Success, T12);
    other.agent = "ticket_bot".to_owned();
    other
        .attrs
        .insert("region".to_owned(), attrs::Value::Text("south".to_owned()));
    publish(&mut writer, &other).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let expected = vec![wanted.record_id.as_str()];

    let by_outcome = Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        ..unfiltered()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &by_outcome).expect("q")),
        expected
    );

    let by_attr = Filter {
        attr: Some(("region".to_owned(), "north".to_owned())),
        agent: Some("deploy_bot".to_owned()),
        ..unfiltered()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &by_attr).expect("q")),
        expected
    );

    let by_window = Filter {
        window: Some(Window {
            from_ms: 1_787_223_600_000,
            to_ms: 1_787_227_200_000,
        }),
        ..unfiltered()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &by_window).expect("q")),
        expected
    );

    let capped = Filter {
        limit: Some(1),
        ..unfiltered()
    };
    assert_eq!(query::by_filter(&store, &capped).expect("q").len(), 1);
}

#[test]
fn correlate_finds_the_pair_inside_the_window_and_nothing_outside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let failure = record("deploy", Outcome::Failure, "2026-08-20T10:00:00Z");
    publish(&mut writer, &failure).expect("publish");
    let nearby = record("ticket", Outcome::Success, "2026-08-20T10:00:30Z");
    publish(&mut writer, &nearby).expect("publish");
    let distant = record("ticket", Outcome::Success, "2026-08-20T11:30:00Z");
    publish(&mut writer, &distant).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let left = Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        ..unfiltered()
    };
    let right = Filter {
        action: Some("ticket".to_owned()),
        ..unfiltered()
    };

    let pairs = query::correlate(&store, &left, &right, 60_000).expect("correlate");
    assert_eq!(pairs.len(), 1, "expected exactly the nearby pair");
    assert_eq!(pairs[0].0.as_str(), failure.record_id.as_str());
    assert_eq!(pairs[0].1.as_str(), nearby.record_id.as_str());

    let capped = Filter {
        limit: Some(1),
        ..left.clone()
    };
    assert_eq!(
        query::correlate(&store, &capped, &right, 7_200_000)
            .expect("correlate")
            .len(),
        1,
        "the page cap should apply to pairs"
    );

    // Ten seconds is inside nothing; the same fixture must go quiet.
    assert!(
        query::correlate(&store, &left, &right, 10_000)
            .expect("correlate")
            .is_empty()
    );
    // Widened, the distant record joins the same left side rather than replacing it.
    let both = query::correlate(&store, &left, &right, 7_200_000).expect("correlate");
    assert_eq!(
        both.iter().map(|pair| pair.1.as_str()).collect::<Vec<_>>(),
        vec![nearby.record_id.as_str(), distant.record_id.as_str()]
    );
}

#[test]
fn a_correlated_pair_comes_back_as_two_structures_and_neither_carries_prose() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let failure = record("deploy", Outcome::Failure, "2026-08-20T10:00:00Z");
    publish(&mut writer, &failure).expect("publish");
    let nearby = record("ticket", Outcome::Success, "2026-08-20T10:00:30Z");
    publish(&mut writer, &nearby).expect("publish");
    // Thirty seconds *before* the failure, and otherwise the record the join is looking for. The
    // join is directional, so this must never appear on the right of a pair.
    let earlier = record("ticket", Outcome::Success, "2026-08-20T09:59:30Z");
    publish(&mut writer, &earlier).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let left = Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        ..unfiltered()
    };
    let right = Filter {
        action: Some("ticket".to_owned()),
        ..unfiltered()
    };

    let pairs = query::correlate_structures(&store, &left, &right, 60_000).expect("correlate");
    assert_eq!(pairs.len(), 1, "expected exactly the nearby pair");
    let (asked, found) = &pairs[0];
    // The pair, in the order the question was asked in: the left filter's record on the left. A
    // transposed select list would answer every caller's question backwards.
    assert_eq!(asked.record_id.as_str(), failure.record_id.as_str());
    assert_eq!(found.record_id.as_str(), nearby.record_id.as_str());
    // Structure and not an identifier, which is the whole reason this read exists: the caller has
    // the record rather than a name it cannot resolve.
    assert_eq!(asked.action, "deploy");
    assert_eq!(found.action, "ticket");
    assert_eq!(asked.outcome, Outcome::Failure);
    // The body is in neither select list, so it is in neither half of the pair — the same rule
    // every other structure read holds, and it has two chances to be broken here.
    let wire = serde_json::to_string(&pairs).expect("a serialisable pair");
    assert!(!wire.contains("nothing notable"), "{wire}");
    assert!(!wire.contains("summary"), "{wire}");

    // The identifier read and the structure read select the same rows, or one of them is answering a
    // different question under the same name.
    let same = query::correlate(&store, &left, &right, 60_000).expect("correlate");
    assert_eq!(
        same.iter()
            .map(|(l, r)| (l.as_str(), r.as_str()))
            .collect::<Vec<_>>(),
        pairs
            .iter()
            .map(|(l, r)| (l.record_id.as_str(), r.record_id.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn truncate_derived_empties_every_table_and_keeps_the_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("deploy", Outcome::Success, T10);
    doc.summary = "rollback completed".to_owned();
    doc.entities = vec![entity_ref("order_ref", "ORD-1001", 1.0)];
    doc.subjects = vec![subject("ab")];
    doc.attrs
        .insert("region".to_owned(), attrs::Value::Text("north".to_owned()));
    publish(&mut writer, &doc).expect("publish");
    writer
        .claim_timeline_mention(doc.record_id.as_str(), "order_ref", "ORD-1001")
        .expect("claim")
        .expect("a first claim")
        .commit()
        .expect("commit");

    let conn = raw(&path);
    writer
        .enqueue_quarantine("01HELD", "2026-08-20", "spool/01HELD.md")
        .expect("quarantine");
    let objects_before = count(&conn, "sqlite_schema");

    writer.truncate_derived().expect("truncate");

    for table in [
        "records",
        "record_attrs",
        "entity_refs",
        "record_subjects",
        "entities",
        "fanout_queue",
        "timeline_mentions",
        "quarantine_pending",
        "records_fts",
    ] {
        assert_eq!(count(&conn, table), 0, "{table} still has rows");
    }
    assert_eq!(count(&conn, "sqlite_schema"), objects_before);
    assert_eq!(
        conn.query_row::<u32, _, _>("PRAGMA user_version", [], |row| row.get(0))
            .expect("version"),
        schema::SCHEMA_VERSION
    );
    conn.execute_batch("INSERT INTO records_fts (records_fts) VALUES ('integrity-check')")
        .expect("integrity after truncate");

    // Rebuildable: the same write lands again on the emptied schema.
    publish(&mut writer, &doc).expect("republish");
    let store = Store::open_read(&path).expect("open read");
    assert_eq!(
        ids(&query::search(&store, "rollback", 10, &ALL).expect("search")),
        vec![doc.record_id.as_str()]
    );
}

/// The claim is the whole idempotency argument for a timeline append, so each half is asserted:
/// a first claim is granted, a second is refused, and one that is dropped rather than committed
/// leaves nothing behind.
///
/// The dropped case is the one worth having a test for. It is what a failed append takes, and
/// without it a directory that was briefly unwritable would leave a row saying the line is there.
#[test]
fn a_timeline_mention_is_claimed_once_and_a_dropped_claim_leaves_no_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![entity_ref("ticket", "TCK-77", 1.0)];
    publish(&mut writer, &doc).expect("publish");
    let id = doc.record_id.as_str();

    // Dropped without committing: the append it stood for did not happen.
    drop(
        writer
            .claim_timeline_mention(id, "ticket", "TCK-77")
            .expect("claim")
            .expect("a first claim"),
    );
    let conn = raw(&path);
    assert_eq!(count(&conn, "timeline_mentions"), 0);

    writer
        .claim_timeline_mention(id, "ticket", "TCK-77")
        .expect("claim")
        .expect("claimable again after a rollback")
        .commit()
        .expect("commit");
    assert_eq!(count(&conn, "timeline_mentions"), 1);

    assert!(
        writer
            .claim_timeline_mention(id, "ticket", "TCK-77")
            .expect("claim")
            .is_none(),
        "a line already in the timeline must not be claimable a second time"
    );
    // Per entity, not per record: the same record names several, and each has its own timeline.
    assert!(
        writer
            .claim_timeline_mention(id, "ticket", "TCK-78")
            .expect("claim")
            .is_some()
    );
}

#[test]
fn a_malformed_full_text_query_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    Writer::open(&path).expect("open writer");
    let store = Store::open_read(&path).expect("open read");

    // Reported as the needle's own failure rather than as the index's: prefix and phrase syntax is
    // offered to callers, so a mistake in it is a mistake in the request. An empty needle is one of
    // them — there is no expression that matches everything, and inventing one here would answer a
    // question nobody asked.
    for needle in ["unbalanced \" quote", ""] {
        let error = query::search(&store, needle, 5, &ALL).expect_err("must fail");
        let yaam_store::Error::BadNeedle { needle: named, .. } = &error else {
            panic!("`{needle}` was reported as {error:?}");
        };
        assert_eq!(named, needle, "the answer has to name what was asked");
    }
}

#[test]
fn a_read_handle_needs_an_existing_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = Store::open_read(&dir.path().join("absent.db")).expect_err("must fail");
    assert!(matches!(error, yaam_store::Error::Sqlite(_)));
}

#[test]
fn roles_are_stored_with_their_wire_spelling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("deploy", Outcome::Partial, T10);
    doc.entities = vec![
        entity_ref("order_ref", "ORD-1001", 1.0),
        entity::EntityRef {
            role: entity::Role::Context,
            ..entity_ref("ticket", "TCK-77", 0.9)
        },
        entity::EntityRef {
            role: entity::Role::Related,
            ..entity_ref("chat_user", "u-42", 0.5)
        },
    ];
    doc.data_class = DataClass::SubjectDerived;
    doc.summary = String::new();
    doc.subjects = vec![
        subject("ab"),
        SubjectRef {
            role: Role::Party,
            ..subject("cd")
        },
    ];
    publish(&mut writer, &doc).expect("publish");

    let conn = raw(&path);
    let mut stmt = conn
        .prepare("SELECT role FROM entity_refs ORDER BY role")
        .expect("prepare");
    let roles: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|row| row.expect("row"))
        .collect();
    assert_eq!(roles, ["context", "primary", "related"]);

    let mut stmt = conn
        .prepare("SELECT role FROM record_subjects ORDER BY role")
        .expect("prepare");
    let roles: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|row| row.expect("row"))
        .collect();
    assert_eq!(roles, ["party", "principal"]);

    // A sealed record still enqueues the subject-linking job alongside the bundle job.
    assert_eq!(count(&conn, "fanout_queue"), 2);
    assert_eq!(
        conn.query_row::<i64, _, _>("SELECT sealed FROM records", [], |row| row.get(0))
            .expect("sealed"),
        1
    );
    assert_eq!(
        conn.query_row::<Option<Vec<u8>>, _, _>(
            "SELECT wrapped_key_share FROM record_subjects LIMIT 1",
            [],
            |row| row.get(0)
        )
        .expect("share"),
        None,
        "the index must not hold a key share the key store has not wrapped"
    );
}

#[test]
fn publish_stores_the_wrapped_share_and_its_epoch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("chat_message", Outcome::Success, T10);
    doc.data_class = DataClass::SubjectDerived;
    doc.summary = String::new();
    doc.subjects = vec![subject("ab"), subject("cd")];
    let epoch = Epoch::containing(1_787_216_400_000);
    let keys = [
        (subject_hash("ab"), epoch.clone(), vec![0xa1; 40]),
        (subject_hash("cd"), epoch.clone(), vec![0xc3; 40]),
    ];

    writer
        .publish(PublishInput {
            record: &doc,
            searchable_body: "",
            subject_keys: &keys,
        })
        .expect("publish");

    let conn = raw(&path);
    let mut stmt = conn
        .prepare(
            "SELECT subject_hash, epoch, wrapped_key_share FROM record_subjects
             ORDER BY subject_hash",
        )
        .expect("prepare");
    let rows: Vec<(String, String, Option<Vec<u8>>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .map(|row| row.expect("row"))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, epoch.as_str());
    assert_eq!(rows[0].2, Some(vec![0xa1; 40]));
    assert_eq!(rows[1].2, Some(vec![0xc3; 40]));

    // A later publish with no shares is a reindex from the tree. It must leave the wrap alone: the
    // share lives in the sealed block, and blanking the index copy would strand the row.
    publish(&mut writer, &doc).expect("reindex");
    let (kept_epoch, kept_share): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT epoch, wrapped_key_share FROM record_subjects WHERE subject_hash = ?1",
            [subject_hash("ab").as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("row");
    assert_eq!(kept_epoch, epoch.as_str());
    assert_eq!(kept_share, Some(vec![0xa1; 40]));
}

#[test]
fn a_share_for_a_subject_the_record_does_not_name_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("chat_message", Outcome::Success, T10);
    doc.data_class = DataClass::SubjectDerived;
    doc.summary = String::new();
    doc.subjects = vec![subject("ab")];
    let epoch = Epoch::containing(1_787_216_400_000);

    // Dropping it silently would leave a body whose share is in no row at all.
    let stranger = [(subject_hash("ef"), epoch.clone(), vec![0xef; 40])];
    let error = writer
        .publish(PublishInput {
            record: &doc,
            searchable_body: "",
            subject_keys: &stranger,
        })
        .expect_err("must refuse");
    assert!(
        matches!(error, yaam_store::Error::BadPublishInput { .. }),
        "unexpected error: {error}"
    );

    let twice = [
        (subject_hash("ab"), epoch.clone(), vec![1; 40]),
        (subject_hash("ab"), epoch, vec![2; 40]),
    ];
    assert!(matches!(
        writer.publish(PublishInput {
            record: &doc,
            searchable_body: "",
            subject_keys: &twice,
        }),
        Err(yaam_store::Error::BadPublishInput { .. })
    ));
    assert_eq!(count(&raw(&path), "records"), 0, "a refused publish wrote");
}

#[test]
fn a_sealed_record_may_not_carry_a_searchable_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("chat_message", Outcome::Success, T10);
    doc.data_class = DataClass::SubjectDerived;
    doc.subjects = vec![subject("ab")];

    let error = writer
        .publish(PublishInput {
            record: &doc,
            searchable_body: "distinctivetoken about a named person",
            subject_keys: &[],
        })
        .expect_err("must refuse");
    assert!(
        matches!(error, yaam_store::Error::BadPublishInput { .. }),
        "unexpected error: {error}"
    );

    // And the table itself refuses it too, so a second writer cannot route around the check.
    let conn = raw(&path);
    assert!(
        conn.execute(
            "INSERT INTO records (record_id, schema_ver, frontmatter, body, at_ms, received_ms)
             VALUES ('01SEALED', 1, json('{\"data_class\":\"subject_derived\"}'), 'prose', 0, 0)",
            [],
        )
        .is_err()
    );
}

#[test]
fn quarantine_keeps_the_first_sighting_and_the_key_date() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    writer
        .enqueue_quarantine("01HELD", "2026-08-20", "spool/01HELD.md")
        .expect("enqueue");
    let conn = raw(&path);
    let first: i64 = conn
        .query_row("SELECT first_seen_ms FROM quarantine_pending", [], |row| {
            row.get(0)
        })
        .expect("row");
    assert!(first > 0, "the sighting must be stamped");

    // A retry must not reset the age, or a row that ages out never would.
    writer
        .enqueue_quarantine("01HELD", "2026-08-21", "spool/01HELD.md")
        .expect("replay");
    let (rows, again, date): (i64, i64, String) = conn
        .query_row(
            "SELECT COUNT(*), MIN(first_seen_ms), MIN(qkek_date) FROM quarantine_pending",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("row");
    assert_eq!(rows, 1);
    assert_eq!(again, first);
    assert_eq!(date, "2026-08-20");
}

#[test]
fn a_claimed_fanout_job_is_never_handed_out_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut doc = record("deploy", Outcome::Success, T10);
    doc.data_class = DataClass::SubjectDerived;
    doc.summary = String::new();
    doc.subjects = vec![subject("ab")];
    publish(&mut writer, &doc).expect("publish");

    let claimed = writer.claim_fanout(10, NOW).expect("claim");
    let mut kinds: Vec<&str> = claimed.iter().map(|job| job.kind.as_str()).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, ["bundle", "subject_link"]);
    for job in &claimed {
        assert_eq!(job.record, doc.record_id);
        assert_eq!(job.attempts, 1);
    }

    // Repeated calls are safe because a claim removes the row from the pending set atomically.
    assert!(
        writer
            .claim_fanout(10, NOW)
            .expect("second claim")
            .is_empty(),
        "a claimed job was handed out twice"
    );

    // Completing keeps the row, so a replayed publish enqueues nothing new.
    for job in &claimed {
        writer.complete_fanout(job.id).expect("complete");
    }
    publish(&mut writer, &doc).expect("replay");
    assert!(writer.claim_fanout(10, NOW).expect("claim").is_empty());
    assert_eq!(count(&raw(&path), "fanout_queue"), 2);
}

#[test]
fn fanout_claims_are_oldest_first_and_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let older = record("deploy", Outcome::Success, T10);
    publish(&mut writer, &older).expect("publish");
    let newer = record("deploy", Outcome::Success, T12);
    publish(&mut writer, &newer).expect("publish");

    let first = writer.claim_fanout(1, NOW).expect("claim");
    assert_eq!(first.len(), 1, "the cap must be honoured");
    assert_eq!(first[0].record, older.record_id);

    let second = writer.claim_fanout(1, NOW).expect("claim");
    assert_eq!(second[0].record, newer.record_id);

    // A job claimed twice — a re-drive after a crash — counts its attempts, which is what lets a
    // caller dead-letter one that never finishes.
    writer.complete_fanout(first[0].id).expect("complete");
    writer.fail_fanout(second[0].id, NOW).expect("release");
    let reclaimed = writer.claim_fanout(1, NOW).expect("claim");
    assert_eq!(reclaimed[0].attempts, 2);
}

#[test]
fn a_failed_job_is_claimable_again_only_once_its_delay_has_passed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    publish(&mut writer, &record("deploy", Outcome::Success, T10)).expect("publish");

    let job = writer.claim_fanout(1, NOW).expect("claim").remove(0);
    assert_eq!(job.attempts, 1);
    writer.fail_fanout(job.id, NOW + 5_000).expect("fail");

    // Pending, and still nobody's: the delay is what makes a retry a later attempt rather than the
    // same one again.
    assert!(writer.claim_fanout(1, NOW).expect("claim").is_empty());
    assert!(
        writer
            .claim_fanout(1, NOW + 4_999)
            .expect("claim")
            .is_empty()
    );

    let again = writer.claim_fanout(1, NOW + 5_000).expect("claim");
    assert_eq!(again.len(), 1);
    // Claims are what `attempts` counts. Counting the failure as well would double the number a
    // caller's own limit is compared against.
    assert_eq!(again[0].attempts, 2);

    // A job that finished stays finished: a failure report arriving late must not resurrect it.
    writer.complete_fanout(again[0].id).expect("complete");
    writer.fail_fanout(again[0].id, NOW).expect("late failure");
    assert!(
        writer
            .claim_fanout(1, NOW + 10_000)
            .expect("claim")
            .is_empty()
    );
}

#[test]
fn a_claim_older_than_the_caller_tolerates_is_reclaimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    publish(&mut writer, &record("deploy", Outcome::Success, T10)).expect("publish");

    let job = writer.claim_fanout(1, NOW).expect("claim").remove(0);
    // Nothing renews a claim, so a drain that died holding this one hides the job for ever.
    assert!(
        writer
            .claim_fanout(1, NOW + 60_000)
            .expect("claim")
            .is_empty()
    );

    assert_eq!(writer.reclaim_stale_fanout(NOW - 1).expect("reclaim"), 0);
    assert_eq!(writer.reclaim_stale_fanout(NOW).expect("reclaim"), 1);

    let again = writer.claim_fanout(1, NOW).expect("claim");
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].id, job.id);
    // The attempt still counts, so a job whose holder keeps dying still runs out of budget.
    assert_eq!(again[0].attempts, 2);

    // A completed job is not a stale claim, however long ago it was claimed.
    writer.complete_fanout(again[0].id).expect("complete");
    assert_eq!(
        writer.reclaim_stale_fanout(NOW + 60_000).expect("reclaim"),
        0
    );
}

#[test]
fn a_non_finite_confidence_cannot_be_indexed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    // `SQLite` stores a non-finite float as NULL, so NOT NULL is what stands between a confidence
    // nothing can compare and an entity edge that matches every threshold and no threshold.
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![entity_ref("ticket", "PROJ-42", f32::NAN)];
    let error = publish(&mut writer, &doc).expect_err("must refuse");
    assert!(
        matches!(error, yaam_store::Error::Sqlite(_)),
        "unexpected error: {error}"
    );
    assert_eq!(count(&raw(&path), "records"), 0);
}

#[test]
fn a_write_against_an_index_that_lost_its_table_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    publish(&mut writer, &record("deploy", Outcome::Success, T10)).expect("publish");

    // Something outside this library rewrote the index. Every write here is a single statement, and
    // a statement with nowhere to land has to come back as an error: a writer that reported success
    // for work the index never recorded would be the one failure nothing downstream could notice.
    raw(&path)
        .execute_batch("DROP TABLE fanout_queue; DROP TABLE quarantine_pending;")
        .expect("tamper");

    assert!(writer.fail_fanout(1, NOW).is_err());
    assert!(writer.reclaim_stale_fanout(NOW).is_err());
    assert!(writer.dequeue_quarantine("01HELD").is_err());
}

#[test]
fn a_settled_quarantine_row_goes_when_it_is_settled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    writer
        .enqueue_quarantine("01HELD", "2026-08-20", "spool/01HELD.md")
        .expect("enqueue");
    assert_eq!(count(&raw(&path), "quarantine_pending"), 1);

    writer.dequeue_quarantine("01HELD").expect("dequeue");
    assert_eq!(count(&raw(&path), "quarantine_pending"), 0);
    // Absence is success: every caller is settling something that may already be settled.
    writer.dequeue_quarantine("01HELD").expect("again");
}

#[test]
fn an_existence_check_is_a_point_lookup_and_carries_the_scope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.visibility = Visibility::Owner;
    publish(&mut writer, &doc).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    assert!(query::exists(&store, doc.record_id.as_str(), &ALL).expect("exists"));
    assert!(!query::exists(&store, "01ARZ3NDEKTSV4RRFFQ69G5FAV", &ALL).expect("exists"));
    // A stem no identifier could be is simply not a row, rather than an error.
    assert!(!query::exists(&store, "timeline", &ALL).expect("exists"));

    // Scoped like any other read: an existence check that ignored the scope would answer questions
    // about records the caller may not see.
    let owner = Scope::Caller {
        visibility: vec![Visibility::Owner],
        agent: doc.agent.clone(),
        teams: Vec::new(),
    };
    let other = Scope::Caller {
        visibility: vec![Visibility::Owner],
        agent: "somebody_else".to_owned(),
        teams: Vec::new(),
    };
    assert!(query::exists(&store, doc.record_id.as_str(), &owner).expect("exists"));
    assert!(!query::exists(&store, doc.record_id.as_str(), &other).expect("exists"));
}

#[test]
fn a_read_handle_answers_from_several_threads_at_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let doc = record("deploy", Outcome::Success, T10);
    publish(&mut writer, &doc).expect("publish");

    // The point of the pool: one handle, shared by reference, read concurrently. A single
    // connection is `Send` and not `Sync`, so this would not compile against one.
    let store = Store::open_read(&path).expect("open read");
    let expected = doc.record_id.as_str().to_owned();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let (store, expected) = (&store, expected.as_str());
            scope.spawn(move || {
                for _ in 0..20 {
                    assert_eq!(
                        ids(&query::by_filter(store, &unfiltered()).expect("query")),
                        vec![expected]
                    );
                }
            });
        }
    });

    // And a clone is the same pool, not a second one.
    let clone = store.clone();
    assert_eq!(
        query::by_filter(&clone, &unfiltered())
            .expect("query")
            .len(),
        1
    );
}

#[test]
fn a_stored_id_the_contract_would_reject_reads_as_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let doc = record("deploy", Outcome::Success, T10);
    publish(&mut writer, &doc).expect("publish");

    // Now that the contract validates on the way in, a row whose id it would refuse can only have
    // come from an edit outside this library — which is exactly what index drift is.
    raw(&path)
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             UPDATE records SET record_id = 'not a ulid';
             UPDATE fanout_queue SET record_id = 'not a ulid';",
        )
        .expect("corrupt");

    let store = Store::open_read(&path).expect("open read");
    assert!(matches!(
        query::by_filter(&store, &unfiltered()),
        Err(yaam_store::Error::Drift(_))
    ));
    assert!(matches!(
        writer.claim_fanout(10, NOW),
        Err(yaam_store::Error::Drift(_))
    ));
}

/// A store where one entity carries a long history, oldest first.
fn busy_entity(references: usize) -> (tempfile::TempDir, std::path::PathBuf, Vec<ActionRecord>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut docs = Vec::with_capacity(references);
    for minute in 0..references {
        let mut doc = record(
            "deploy",
            Outcome::Success,
            &format!("2026-08-20T10:{minute:02}:00Z"),
        );
        doc.entities = vec![entity_ref("ticket", "TCK-HOT", 1.0)];
        publish(&mut writer, &doc).expect("publish");
        docs.push(doc);
    }
    (dir, path, docs)
}

#[test]
fn a_hot_entity_is_paged_through_the_query_and_whole_through_the_verification_read() {
    let (_dir, path, docs) = busy_entity(40);
    let store = Store::open_read(&path).expect("open read");

    // What a request gets: the page it asked for, newest first.
    let page =
        query::by_entity(&store, "ticket", "TCK-HOT", 1.0, None, Some(10), &ALL).expect("page");
    assert_eq!(page.len(), 10);
    assert_eq!(
        ids(&page)[0],
        docs[39].record_id.as_str(),
        "a page of entity history is the newest end of it"
    );

    // What a rebuild's verification gets: all of it, however busy the entity is.
    let everything =
        query::by_entity_unbounded(&store, "ticket", "TCK-HOT", 1.0).expect("unbounded");
    assert_eq!(everything.len(), 40);
    assert_eq!(ids(&everything)[..10], ids(&page)[..]);
}

/// A store where `count` records all carry the same common word in their bodies.
fn common_word_corpus(count: usize, team: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    for minute in 0..count {
        let mut doc = record(
            "deploy",
            Outcome::Success,
            &format!("2026-08-20T10:{minute:02}:00Z"),
        );
        doc.visibility = Visibility::Team;
        doc.team = Some(team.to_owned());
        doc.summary = format!("commonword body number {minute}");
        publish(&mut writer, &doc).expect("publish");
    }
    (dir, path)
}

#[test]
fn a_search_for_a_corpus_wide_word_examines_the_page_and_not_the_corpus() {
    let (_dir, path) = common_word_corpus(60, "platform");
    let store = Store::open_read(&path).expect("open read");

    let page = query::search(
        &store,
        "commonword",
        5,
        &reader("deploy_bot", &["platform"]),
    )
    .expect("search");
    assert_eq!(page.len(), 5, "the page the caller asked for, and no more");
    // That the *work* is capped too is a property of the statement, and is asserted on the plan in
    // `query`'s own tests: only the plan can tell a bounded read from one that was fast today.
}

#[test]
fn a_narrowly_scoped_search_can_come_back_short_of_its_page() {
    // The stated cost of bounding this read. The ceiling is applied before the scope test, because
    // neither a limit nor a scope predicate can be pushed into a full-text match, so a caller who
    // may read only the older end of what matched sees a short page rather than a slow one.
    let (_dir, path) = common_word_corpus(60, "support");
    let store = Store::open_read(&path).expect("open read");
    let outsider = reader("deploy_bot", &["platform"]);

    // Ceiling of 20 candidates for a page of one: the newest 20 matches belong to another team, and
    // the query stops there rather than reading on to the 40 this caller might have been shown.
    assert!(
        query::search(&store, "commonword", 1, &outsider)
            .expect("search")
            .is_empty(),
        "a caller entitled to none of the newest matches gets a short page, not a long read"
    );
    // Nothing is wrong with the corpus or the needle: the unscoped read finds them.
    assert_eq!(
        query::search(&store, "commonword", 1, &ALL)
            .expect("search")
            .len(),
        1
    );
}

#[test]
fn a_batch_dropped_without_committing_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let first = record("deploy", Outcome::Success, T10);
    publish(&mut writer, &first).expect("publish");

    // What an interrupted rebuild does: truncate, write, and never reach the commit.
    let mut batch = writer.batch().expect("batch");
    batch.truncate_derived().expect("truncate");
    batch
        .publish(PublishInput {
            record: &record("deploy", Outcome::Failure, T11),
            searchable_body: "",
            subject_keys: &[],
        })
        .expect("publish");
    drop(batch);

    let store = Store::open_read(&path).expect("open read");
    assert_eq!(
        ids(&query::by_filter(&store, &unfiltered()).expect("filter")),
        vec![first.record_id.as_str()],
        "a batch that never committed must leave the index exactly as it was"
    );
}
