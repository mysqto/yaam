//! Handles onto the index.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, Transaction, params};
use yaam_contract::{ActionRecord, DataClass, attrs};

use crate::schema;

/// A read handle. Cheap to clone across readers.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
}

/// The single write handle. Owning it is what serialises writes.
#[derive(Debug)]
pub struct Writer {
    conn: Connection,
}

/// Fan-out work every published record needs.
const JOB_BUNDLE: &str = "bundle";
/// Fan-out work only records naming subjects need.
const JOB_SUBJECT_LINK: &str = "subject_link";

impl Store {
    /// Opens the index read-only, migrating nothing.
    ///
    /// A reader that migrated would be a second writer. If the file is older than this build, the
    /// caller's job is to run a writer, not to have reads mutate the schema underneath them.
    pub fn open_read(path: &Path) -> crate::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        schema::apply_pragmas(&conn)?;
        Ok(Self { conn })
    }
}

impl Writer {
    /// Opens the index for writing and brings the schema up to date.
    pub fn open(path: &Path) -> crate::Result<Self> {
        let mut conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        schema::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    /// Inserts a record and everything derived from it, in one transaction.
    ///
    /// Fan-out jobs are enqueued *inside* this transaction: enqueueing after commit loses them to
    /// any crash in between, and nothing would notice.
    ///
    /// Replayable. The record insert turns on its unique id, every derived row is keyed, and the
    /// entity counters are recomputed, so publishing the same record twice is a no-op.
    pub fn publish(&mut self, doc: &ActionRecord) -> crate::Result<()> {
        let frontmatter = frontmatter_json(doc)?;
        // Sealed bodies never reach the index in plaintext, so nothing can search around sealing.
        let body = match doc.data_class {
            DataClass::SubjectDerived => "",
            DataClass::Internal => doc.summary.as_str(),
        };

        // IMMEDIATE, not DEFERRED: the write lock is taken up front, so a busy index fails here
        // rather than half way through the derived rows.
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let record_pk = insert_record(&tx, doc, &frontmatter, body)?;
        let received_ms = tx.query_row(
            "SELECT received_ms FROM records WHERE id = ?1",
            params![record_pk],
            |row| row.get::<_, i64>(0),
        )?;
        insert_attrs(&tx, record_pk, doc)?;
        insert_entities(&tx, record_pk, doc)?;
        insert_subjects(&tx, record_pk, doc)?;
        enqueue_fanout(&tx, doc, received_ms)?;
        tx.commit()?;
        Ok(())
    }

    /// Drops every derived row so the index can be rebuilt from the tree.
    pub fn truncate_derived(&mut self) -> crate::Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Deleting records cascades to attrs, entity refs, subjects and queued fan-out, and the
        // delete trigger unindexes each body. 'delete-all' then clears any full-text row whose
        // record went missing without a trigger firing — a rebuild must not inherit a phantom.
        tx.execute_batch(
            "DELETE FROM records;
             DELETE FROM entities;
             DELETE FROM quarantine_pending;
             INSERT INTO records_fts (records_fts) VALUES ('delete-all');",
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Serialises everything but the body.
///
/// `summary` is removed rather than left in place: for a sealed record it is the very prose the
/// body column refuses to hold, and a copy in the frontmatter would be both searchable and beyond
/// the reach of key destruction.
fn frontmatter_json(doc: &ActionRecord) -> crate::Result<String> {
    let mut value = serde_json::to_value(doc).map_err(bind_failure)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("summary");
    }
    serde_json::to_string(&value).map_err(bind_failure)
}

/// Reports a value that could not be turned into something bindable.
///
/// The store's error type has no serialisation arm, and this is exactly what `rusqlite` calls a
/// binding conversion failure, so it is reported as one rather than mislabelled as index drift.
fn bind_failure(err: serde_json::Error) -> crate::Error {
    crate::Error::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
}

/// Inserts the record, or leaves the existing row alone, and returns its integer key.
fn insert_record(
    tx: &Transaction<'_>,
    doc: &ActionRecord,
    frontmatter: &str,
    body: &str,
) -> crate::Result<i64> {
    // Timestamps are converted by SQLite rather than parsed here, so the stored integer is the
    // same whatever host produced the row. NOT NULL is the guard: an unparseable timestamp yields
    // NULL and fails the insert instead of landing a record at the epoch.
    tx.execute(
        "INSERT INTO records (record_id, schema_ver, frontmatter, body, at_ms, received_ms)
         VALUES (?1, ?2, ?3, ?4,
                 CAST(ROUND(unixepoch(?5, 'subsec') * 1000) AS INTEGER),
                 CAST(ROUND(unixepoch(?6, 'subsec') * 1000) AS INTEGER))
         ON CONFLICT (record_id) DO NOTHING",
        params![
            doc.record_id.as_str(),
            doc.schema_ver.0,
            frontmatter,
            body,
            doc.at,
            doc.received_at,
        ],
    )?;
    Ok(tx.query_row(
        "SELECT id FROM records WHERE record_id = ?1",
        params![doc.record_id.as_str()],
        |row| row.get(0),
    )?)
}

/// Writes the structural attributes as one indexed row per key.
fn insert_attrs(tx: &Transaction<'_>, record_pk: i64, doc: &ActionRecord) -> crate::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO record_attrs (record_pk, key, value) VALUES (?1, ?2, ?3)
         ON CONFLICT (record_pk, key) DO UPDATE SET value = excluded.value",
    )?;
    for (key, value) in &doc.attrs {
        insert.execute(params![record_pk, key, attr_text(value)])?;
    }
    Ok(())
}

/// Flattens an attribute to the text form the filter API compares against.
fn attr_text(value: &attrs::Value) -> String {
    match value {
        attrs::Value::Text(text) => text.clone(),
        attrs::Value::Int(number) => number.to_string(),
        attrs::Value::Bool(flag) => flag.to_string(),
    }
}

/// Writes entity references, then recomputes the catalog rows they feed.
fn insert_entities(tx: &Transaction<'_>, record_pk: i64, doc: &ActionRecord) -> crate::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO entity_refs (record_pk, kind, entity_id, role, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (record_pk, kind, entity_id, role)
             DO UPDATE SET confidence = excluded.confidence",
    )?;
    // Recomputed from entity_refs, never incremented: an incremented counter would double on
    // replay, and there would be nothing to compare it against to notice.
    let mut recount = tx.prepare_cached(
        "INSERT INTO entities (kind, entity_id, first_seen_ms, last_seen_ms, ref_count)
         SELECT er.kind, er.entity_id,
                MIN(rec.received_ms), MAX(rec.received_ms), COUNT(*)
         FROM entity_refs AS er
         JOIN records AS rec ON rec.id = er.record_pk
         WHERE er.kind = ?1 AND er.entity_id = ?2
         GROUP BY er.kind, er.entity_id
         ON CONFLICT (kind, entity_id) DO UPDATE SET
             first_seen_ms = excluded.first_seen_ms,
             last_seen_ms  = excluded.last_seen_ms,
             ref_count     = excluded.ref_count",
    )?;
    for entity in &doc.entities {
        insert.execute(params![
            record_pk,
            entity.kind,
            entity.id,
            role_text(entity.role),
            f64::from(entity.confidence),
        ])?;
        recount.execute(params![entity.kind, entity.id])?;
    }
    Ok(())
}

/// Writes one row per named subject. Key shares stay NULL until the key store wraps them.
fn insert_subjects(tx: &Transaction<'_>, record_pk: i64, doc: &ActionRecord) -> crate::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO record_subjects (record_pk, subject_hash, role, canon_ver)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (record_pk, subject_hash) DO UPDATE SET
             role = excluded.role, canon_ver = excluded.canon_ver",
    )?;
    for subject in &doc.subjects {
        insert.execute(params![
            record_pk,
            subject.hash.as_str(),
            subject_role_text(subject.role),
            subject.canon_ver.0,
        ])?;
    }
    Ok(())
}

/// Enqueues the derived work this record implies.
///
/// Stamped with the record's own server time rather than a clock read, so a reindex reproduces the
/// same rows — a column the tree cannot regenerate would not be derived at all.
fn enqueue_fanout(tx: &Transaction<'_>, doc: &ActionRecord, received_ms: i64) -> crate::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO fanout_queue (record_id, job_kind, enqueued_ms) VALUES (?1, ?2, ?3)
         ON CONFLICT (record_id, job_kind) DO NOTHING",
    )?;
    insert.execute(params![doc.record_id.as_str(), JOB_BUNDLE, received_ms])?;
    if !doc.subjects.is_empty() {
        insert.execute(params![
            doc.record_id.as_str(),
            JOB_SUBJECT_LINK,
            received_ms
        ])?;
    }
    Ok(())
}

/// Wire spelling of an entity role.
fn role_text(role: yaam_contract::entity::Role) -> &'static str {
    match role {
        yaam_contract::entity::Role::Primary => "primary",
        yaam_contract::entity::Role::Context => "context",
        yaam_contract::entity::Role::Related => "related",
    }
}

/// Wire spelling of a subject role.
fn subject_role_text(role: yaam_contract::Role) -> &'static str {
    match role {
        yaam_contract::Role::Principal => "principal",
        yaam_contract::Role::Party => "party",
    }
}
