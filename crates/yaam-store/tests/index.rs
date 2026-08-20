//! Behaviour of the derived index, exercised through its public surface.
//!
//! Several of these tests exist to catch a *silent* failure: a missing pragma, a full-text index
//! that stopped tracking its content table, an index the planner quietly stopped using. Each of
//! those still returns plausible answers, so only an explicit assertion notices.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role, SchemaVer, SubjectRef, Visibility,
    attrs, entity,
};
use yaam_store::query::{self, Filter, Window};
use yaam_store::{Store, Writer, schema};

const T10: &str = "2026-08-20T10:00:00Z";
const T11: &str = "2026-08-20T11:00:00Z";
const T12: &str = "2026-08-20T12:00:00Z";

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

/// The contract's own deserialisation is the only public way to name an existing subject, its
/// parser not being implemented yet.
fn subject(seed: &str) -> SubjectRef {
    let text = format!("s_{}", seed.repeat(64 / seed.len()));
    SubjectRef {
        hash: serde_json::from_value(serde_json::Value::String(text)).expect("subject hash"),
        role: Role::Principal,
        canon_ver: CanonVer(1),
    }
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
    writer.publish(&doc).expect("publish");

    let conn = raw(&path);
    assert_eq!(count(&conn, "entity_refs"), 2);
    assert_eq!(count(&conn, "record_subjects"), 1);
    assert_eq!(count(&conn, "record_attrs"), 1);
    assert!(count(&conn, "fanout_queue") > 0);

    conn.execute_batch("DELETE FROM records").expect("delete");
    assert_eq!(count(&conn, "entity_refs"), 0, "cascade did not reach refs");
    assert_eq!(count(&conn, "record_subjects"), 0);
    assert_eq!(count(&conn, "record_attrs"), 0);
    assert_eq!(count(&conn, "fanout_queue"), 0);
}

#[test]
fn the_cascade_depends_on_the_pragma_being_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.entities = vec![entity_ref("deploy", "svc-a/2026.8.1", 1.0)];
    writer.publish(&doc).expect("publish");

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
    writer.publish(&plain).expect("publish plain");

    let mut sealed = record("chat_message", Outcome::Success, T11);
    sealed.data_class = DataClass::SubjectDerived;
    sealed.subjects = vec![subject("cd")];
    sealed.summary = "distinctivetoken about a named person".to_owned();
    writer.publish(&sealed).expect("publish sealed");

    let store = Store::open_read(&path).expect("open read");
    assert_eq!(
        ids(&query::search(&store, "rollback", 10).expect("search")),
        vec![plain.record_id.as_str()]
    );
    assert!(
        query::search(&store, "distinctivetoken", 10)
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

#[test]
fn full_text_stays_consistent_across_insert_update_and_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let mut first = record("deploy", Outcome::Success, T10);
    first.summary = "rollback completed".to_owned();
    writer.publish(&first).expect("publish");
    let second = record("deploy", Outcome::Failure, T11);
    writer.publish(&second).expect("publish");

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
        query::search(&store, "rollback", 10)
            .expect("search")
            .is_empty(),
        "the update trigger did not unindex the old body"
    );
    assert_eq!(
        ids(&query::search(&store, "promotion", 10).expect("search")),
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
    writer.publish(&doc).expect("publish");

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
    writer.publish(&skewed).expect("publish");
    let later_source = record("deploy", Outcome::Success, T11);
    writer.publish(&later_source).expect("publish");

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
    let newest_first = query::by_filter(&store, &Filter::default()).expect("filter");
    assert_eq!(
        ids(&newest_first),
        vec![skewed.record_id.as_str(), later_source.record_id.as_str()]
    );
}

#[test]
fn an_unparseable_timestamp_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");
    let mut doc = record("deploy", Outcome::Success, T10);
    doc.received_at = "last tuesday".to_owned();

    let error = writer.publish(&doc).expect_err("must refuse");
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

    writer.publish(&doc).expect("publish");
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

    writer.publish(&doc).expect("replay");
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
        writer.publish(&doc).expect("publish");
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
    writer.publish(&certain).expect("publish");

    let mut inferred = record("chat_user", Outcome::Success, T12);
    inferred.entities = vec![entity_ref("ticket", "TCK-77", 0.4)];
    writer.publish(&inferred).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let all = query::by_entity(&store, "ticket", "TCK-77", 0.0).expect("by_entity");
    assert_eq!(
        ids(&all),
        vec![inferred.record_id.as_str(), certain.record_id.as_str()]
    );

    let confident = query::by_entity(&store, "ticket", "TCK-77", 0.9).expect("by_entity");
    assert_eq!(ids(&confident), vec![certain.record_id.as_str()]);
    assert!(
        query::by_entity(&store, "ticket", "TCK-99", 0.0)
            .expect("by_entity")
            .is_empty()
    );
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
    writer.publish(&wanted).expect("publish");

    let mut other = record("deploy", Outcome::Success, T12);
    other.agent = "ticket_bot".to_owned();
    other
        .attrs
        .insert("region".to_owned(), attrs::Value::Text("south".to_owned()));
    writer.publish(&other).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let expected = vec![wanted.record_id.as_str()];

    let by_outcome = Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        ..Filter::default()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &by_outcome).expect("q")),
        expected
    );

    let by_attr = Filter {
        attr: Some(("region".to_owned(), "north".to_owned())),
        agent: Some("deploy_bot".to_owned()),
        ..Filter::default()
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
        ..Filter::default()
    };
    assert_eq!(
        ids(&query::by_filter(&store, &by_window).expect("q")),
        expected
    );

    let capped = Filter {
        limit: Some(1),
        ..Filter::default()
    };
    assert_eq!(query::by_filter(&store, &capped).expect("q").len(), 1);
}

#[test]
fn correlate_finds_the_pair_inside_the_window_and_nothing_outside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    let mut writer = Writer::open(&path).expect("open writer");

    let failure = record("deploy", Outcome::Failure, "2026-08-20T10:00:00Z");
    writer.publish(&failure).expect("publish");
    let nearby = record("ticket", Outcome::Success, "2026-08-20T10:00:30Z");
    writer.publish(&nearby).expect("publish");
    let distant = record("ticket", Outcome::Success, "2026-08-20T11:30:00Z");
    writer.publish(&distant).expect("publish");

    let store = Store::open_read(&path).expect("open read");
    let left = Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        ..Filter::default()
    };
    let right = Filter {
        action: Some("ticket".to_owned()),
        ..Filter::default()
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
    writer.publish(&doc).expect("publish");

    let conn = raw(&path);
    conn.execute(
        "INSERT INTO quarantine_pending (record_id, staging_path, reason, first_seen_ms)
         VALUES ('01HELD', 'staging/01HELD.md', 'subject unresolved', 1)",
        [],
    )
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
    writer.publish(&doc).expect("republish");
    let store = Store::open_read(&path).expect("open read");
    assert_eq!(
        ids(&query::search(&store, "rollback", 10).expect("search")),
        vec![doc.record_id.as_str()]
    );
}

#[test]
fn a_malformed_full_text_query_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("index.db");
    Writer::open(&path).expect("open writer");
    let store = Store::open_read(&path).expect("open read");

    let error = query::search(&store, "unbalanced \" quote", 5).expect_err("must fail");
    assert!(matches!(error, yaam_store::Error::Sqlite(_)));
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
    writer.publish(&doc).expect("publish");

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
