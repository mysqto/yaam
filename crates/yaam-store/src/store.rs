//! Handles onto the index.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rusqlite::{Connection, OpenFlags, Transaction, params};
use yaam_contract::{ActionRecord, DataClass, RecordId, SubjectHash, attrs};
use yaam_crypto::Epoch;

use crate::schema;

/// Idle connections a [`Store`] keeps rather than closes.
///
/// Bounded because an idle connection is a file handle and a page cache: a burst of readers is
/// worth serving, and worth forgetting about once it is over.
const MAX_IDLE: usize = 8;

/// A read handle. Cheap to clone, and shareable between threads.
///
/// A pool rather than one connection, because `rusqlite::Connection` is `Send` but not `Sync`: it
/// may move between threads and may not be used from two at once. A reader takes a connection out
/// for the length of a statement and puts it back, so one `Store` behind a `&self` answers reads
/// concurrently — where a single connection behind a lock would serialise them and let one slow
/// query block every other.
///
/// Read-only throughout. The single-writer invariant is [`Writer`]'s to hold, and nothing reachable
/// from here can migrate the schema, write a row, or take the write lock away from it.
#[derive(Debug, Clone)]
pub struct Store {
    /// Shared with every clone: what makes two handles one pool rather than two.
    pool: Arc<Pool>,
}

/// The connections one [`Store`] and its clones share.
#[derive(Debug)]
struct Pool {
    /// Where to open another connection when the idle set is empty.
    path: PathBuf,
    /// Connections nobody is using.
    idle: Mutex<Vec<Connection>>,
}

impl Pool {
    /// Takes an idle connection, if there is one.
    ///
    /// A poisoned lock is recovered rather than propagated: the guarded value is a list of idle
    /// connections, and a panic while holding it cannot have left one half-used.
    fn take(&self) -> Option<Connection> {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    /// Puts a connection back, or drops it when the idle set is already full.
    fn put(&self, conn: Connection) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < MAX_IDLE {
            idle.push(conn);
        }
    }
}

/// A connection borrowed from a [`Store`] for the length of one read.
///
/// Returned to the pool on drop, including when the read failed: a connection a failing statement
/// left behind is still a usable connection, and losing it on every error would make an erroring
/// workload open one per read.
#[derive(Debug)]
pub(crate) struct Lease<'a> {
    /// Where the connection goes back to.
    pool: &'a Pool,
    /// `None` only while being handed back.
    conn: Option<Connection>,
}

impl Deref for Lease<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("a lease holds its connection")
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.put(conn);
        }
    }
}

/// The single write handle. Owning it is what serialises writes.
#[derive(Debug)]
pub struct Writer {
    conn: Connection,
}

/// One transaction spanning many writes.
///
/// The index runs `synchronous = FULL`, so every commit is a durability round trip — ~0.43 ms on
/// the array the benchmark ran against. A rebuild that commits per record pays one each: two thirds
/// of a 100,000-record rebuild's wall time was `fsync` and one third the parse-and-insert work it
/// exists to do. One transaction over the whole rebuild pays it once.
///
/// It is also what makes a rebuild atomic. Nothing a batch wrote is visible until
/// [`Batch::commit`], and a batch dropped without committing rolls back — so an interrupted rebuild
/// leaves the index it started from rather than a truncated one that looks finished. That is why
/// [`Batch::truncate_derived`] is here and not only on [`Writer`]: the truncate and the rows that
/// replace it have to be one transaction, or there is a window in which the index is plausible and
/// wrong.
#[derive(Debug)]
pub struct Batch<'a> {
    /// Rolled back on drop, which is what leaves the failure path with no code of its own.
    tx: Transaction<'a>,
}

/// A held claim on one line of one entity's timeline: the row is written, the file is not yet.
///
/// The reason this is a guard rather than a plain insert is that the row and the append have to
/// agree, and they are not the same kind of write — one is a transaction, the other is an fsynced
/// file append that cannot join it. So the transaction stays open across the append and commits
/// after it: a caller that fails to write the line drops this instead of committing, and the row
/// goes with it, which is what lets the fan-out job be retried rather than counted as done.
///
/// One window is left, and it is named rather than papered over: a crash between the append's
/// `fsync` and this commit leaves a line no row accounts for, which the next drive of that job
/// appends again. A file append cannot join a transaction, so no ordering closes it; what
/// converges it is that the rows and the files are dropped together, and a rebuild re-derives both.
#[derive(Debug)]
pub struct TimelineMention<'a> {
    /// Rolled back on drop, so an append that failed leaves no row claiming it happened.
    tx: Transaction<'a>,
}

impl TimelineMention<'_> {
    /// Makes the claim permanent, once the line is on disk.
    pub fn commit(self) -> crate::Result<()> {
        self.tx.commit()?;
        Ok(())
    }
}

/// Fan-out work every published record needs.
const JOB_BUNDLE: &str = "bundle";
/// Fan-out work only records naming subjects need.
const JOB_SUBJECT_LINK: &str = "subject_link";

/// Queue state of a job nobody has taken yet.
pub(crate) const STATE_PENDING: &str = "pending";
/// Queue state of a job handed to a worker.
pub(crate) const STATE_CLAIMED: &str = "claimed";
/// Queue state of a job that finished.
///
/// Kept rather than deleted: the row is what makes a replayed publish a no-op instead of
/// re-enqueueing work that has already been done.
const STATE_DONE: &str = "done";

/// Everything a publish needs that the record itself cannot carry.
///
/// `Writer::publish` used to take the record alone, which left it unable to fill the two columns
/// that do not live in frontmatter: the searchable body, and the wrapped key share and epoch per
/// subject. Both come from the sealing step, so they arrive alongside the record rather than in it.
///
/// Borrows throughout, and so `Copy`: a publish reads its input and owns none of it.
#[derive(Debug, Clone, Copy)]
pub struct PublishInput<'a> {
    /// The record to index.
    pub record: &'a ActionRecord,
    /// Text full-text search may index. `""` for a sealed record, which is what keeps search from
    /// becoming a way around sealing.
    pub searchable_body: &'a str,
    /// One wrapped share per subject, with the epoch whose key wraps it.
    ///
    /// May be empty: a record with no subjects needs none, and a reindex that has only the tree
    /// leaves the existing wrap in place rather than blanking it.
    pub subject_keys: &'a [(SubjectHash, Epoch, Vec<u8>)],
}

/// One claimed unit of fan-out work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutJob {
    /// Queue row id, and the handle [`Writer::complete_fanout`] takes.
    pub id: i64,
    /// Record the work is about.
    pub record: RecordId,
    /// What kind of work: `bundle`, `subject_link`.
    pub kind: String,
    /// How many times this job has been claimed, this claim included.
    pub attempts: u32,
}

impl Store {
    /// Opens the index read-only, migrating nothing.
    ///
    /// A reader that migrated would be a second writer. If the file is older than this build, the
    /// caller's job is to run a writer, not to have reads mutate the schema underneath them.
    ///
    /// One connection is opened here rather than lazily, so an index that is missing or unreadable
    /// is reported by the call that opened it instead of by the first query.
    pub fn open_read(path: &Path) -> crate::Result<Self> {
        let conn = open_reading(path)?;
        Ok(Self {
            pool: Arc::new(Pool {
                path: path.to_path_buf(),
                idle: Mutex::new(vec![conn]),
            }),
        })
    }

    /// Borrows a connection for one read.
    pub(crate) fn lease(&self) -> crate::Result<Lease<'_>> {
        let conn = match self.pool.take() {
            Some(conn) => conn,
            None => open_reading(&self.pool.path)?,
        };
        Ok(Lease {
            pool: &self.pool,
            conn: Some(conn),
        })
    }
}

/// Opens one read-only connection with the pragmas the design depends on.
///
/// `NO_MUTEX` is safe here and load-bearing: a connection is used by one thread at a time by
/// construction — a [`Lease`] is not shareable — so `SQLite`'s own serialisation would be a lock
/// taken to protect against something that cannot happen.
fn open_reading(path: &Path) -> crate::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    schema::apply_pragmas(&conn)?;
    Ok(conn)
}

impl Writer {
    /// Opens the index for writing and brings the schema up to date.
    pub fn open(path: &Path) -> crate::Result<Self> {
        let mut conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        schema::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    /// Opens one transaction for many writes.
    ///
    /// IMMEDIATE, not DEFERRED: the write lock is taken up front, so a busy index fails here rather
    /// than half way through the rows.
    pub fn batch(&mut self) -> crate::Result<Batch<'_>> {
        Ok(Batch {
            tx: self
                .conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?,
        })
    }

    /// Inserts a record and everything derived from it, in one transaction.
    ///
    /// A batch of one. The single-record path is what a live write wants — a record is durable when
    /// the call returns — and [`Writer::batch`] is what a rebuild of a hundred thousand of them
    /// wants.
    pub fn publish(&mut self, input: PublishInput<'_>) -> crate::Result<()> {
        let mut batch = self.batch()?;
        batch.publish(input)?;
        batch.commit()
    }

    /// Records that a record is held back, unpublished, in a spool file.
    ///
    /// Idempotent, and deliberately keeps the *first* sighting: resetting the stamp on every retry
    /// would make a row that ages out never age out.
    pub fn enqueue_quarantine(
        &mut self,
        id: &str,
        qkek_date: &str,
        spool_path: &str,
    ) -> crate::Result<()> {
        enqueue_quarantine_in(&self.conn, id, qkek_date, spool_path)
    }

    /// Forgets that a record is held back.
    ///
    /// The counterpart of [`Writer::enqueue_quarantine`], for the record that resolved: its spool
    /// file is gone, and a row still naming that file is a register entry pointing at nothing until
    /// the next rebuild derives the register again from the spool directory.
    ///
    /// Absence is success. Every caller is settling something that may already have been settled.
    pub fn dequeue_quarantine(&mut self, id: &str) -> crate::Result<()> {
        self.conn.execute(
            "DELETE FROM quarantine_pending WHERE record_id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Claims up to `limit` jobs that are ready at `now_ms`, oldest first.
    ///
    /// The claim and the read are one statement, so a job cannot be handed out twice however often
    /// this is called: a row leaves `pending` in the same atomic step that returns it. `attempts` is
    /// incremented here and only here — it counts claims, which is the number a caller compares
    /// against its own limit, and a job whose holder died has still had its attempt.
    ///
    /// A job [`Writer::fail_fanout`] pushed into the future is not returned until `now_ms` reaches
    /// it. "Now" is a parameter rather than a clock read so a caller can drive the queue's sense of
    /// time — a backoff nothing can advance is a backoff nothing can test.
    pub fn claim_fanout(&mut self, limit: u32, now_ms: i64) -> crate::Result<Vec<FanoutJob>> {
        let mut stmt = self.conn.prepare_cached(
            "UPDATE fanout_queue
                SET state = ?1, attempts = attempts + 1, claimed_ms = ?4
              WHERE id IN (SELECT id FROM fanout_queue
                            WHERE state = ?2 AND not_before_ms <= ?4
                            ORDER BY enqueued_ms, id
                            LIMIT ?3)
          RETURNING id, record_id, job_kind, attempts",
        )?;
        let rows = stmt.query_map(
            params![STATE_CLAIMED, STATE_PENDING, i64::from(limit), now_ms],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            },
        )?;

        let mut jobs = Vec::new();
        for row in rows {
            let (id, record_id, kind, attempts) = row?;
            jobs.push(FanoutJob {
                id,
                record: crate::stored_record_id(record_id)?,
                kind,
                attempts,
            });
        }
        Ok(jobs)
    }

    /// Marks a claimed job finished.
    ///
    /// The row stays, in state `done`. Deleting it would let a replayed publish enqueue the same
    /// work again, which is the duplication the queue's unique key exists to prevent; the rows are
    /// derived and go away with [`Writer::truncate_derived`].
    pub fn complete_fanout(&mut self, job_id: i64) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE fanout_queue SET state = ?1, claimed_ms = NULL WHERE id = ?2",
            params![STATE_DONE, job_id],
        )?;
        Ok(())
    }

    /// Returns a claimed job to the queue, claimable again no earlier than `not_before_ms`.
    ///
    /// This is what makes a retry budget span drains rather than being spent inside one. Without it
    /// a caller could only keep trying immediately or give up, and a drain that died holding a claim
    /// stranded the job until the next rebuild re-enqueued it.
    ///
    /// `attempts` is deliberately *not* incremented here: [`Writer::claim_fanout`] counts every
    /// hand-out, and counting a failure too would double the number a caller's own limit compares
    /// against — and would leave a job whose holder crashed uncounted.
    ///
    /// Only a claimed job moves. A job that finished in the meantime stays finished, so a late
    /// failure report cannot resurrect work already done.
    pub fn fail_fanout(&mut self, job_id: i64, not_before_ms: i64) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE fanout_queue
                SET state = ?1, claimed_ms = NULL, not_before_ms = ?3
              WHERE id = ?2 AND state = ?4",
            params![STATE_PENDING, job_id, not_before_ms, STATE_CLAIMED],
        )?;
        Ok(())
    }

    /// Returns every job claimed at or before `claimed_before_ms` to the queue, and says how many.
    ///
    /// A claim is only as good as the process holding it. Nothing renews one, so a drain that died
    /// mid-job leaves a row no later claim can see — this is the only thing that gets it back, and
    /// [`crate::store`] deliberately does not decide when a claim is old enough: the caller knows
    /// how long its own drains take, and picking a grace period here would be guessing at it.
    ///
    /// `attempts` is left as it stands, so a job whose holder keeps dying still runs out of budget
    /// rather than being retried for ever.
    pub fn reclaim_stale_fanout(&mut self, claimed_before_ms: i64) -> crate::Result<usize> {
        Ok(self.conn.execute(
            "UPDATE fanout_queue
                SET state = ?1, claimed_ms = NULL
              WHERE state = ?2 AND claimed_ms <= ?3",
            params![STATE_PENDING, STATE_CLAIMED, claimed_before_ms],
        )?)
    }

    /// Claims the line naming `record_id` in one entity's timeline, or reports it already written.
    ///
    /// `None` means the line is already in the timeline, wherever in it: the answer is one index
    /// lookup and reads no file, which is the point. The alternative — scanning the timeline — is
    /// either bounded and wrong, because a line frozen into an older part is invisible to it, or
    /// unbounded and priced by the entity's whole history.
    ///
    /// `Some` hands back an open transaction holding the claim. The caller appends the line and
    /// then commits; dropping it instead rolls the claim back, so a failed append is work still
    /// owed rather than a line nothing will ever write.
    pub fn claim_timeline_mention(
        &mut self,
        record_id: &str,
        kind: &str,
        entity_id: &str,
    ) -> crate::Result<Option<TimelineMention<'_>>> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let claimed = tx.execute(
            "INSERT INTO timeline_mentions (record_id, kind, entity_id) VALUES (?1, ?2, ?3)
             ON CONFLICT (record_id, kind, entity_id) DO NOTHING",
            params![record_id, kind, entity_id],
        )?;
        if claimed == 0 {
            return Ok(None);
        }
        Ok(Some(TimelineMention { tx }))
    }

    /// Drops every derived row so the index can be rebuilt from the tree.
    ///
    /// On its own this leaves an empty index, which is a state no reader should ever see: a rebuild
    /// truncates and refills inside one [`Batch`] instead.
    pub fn truncate_derived(&mut self) -> crate::Result<()> {
        let mut batch = self.batch()?;
        batch.truncate_derived()?;
        batch.commit()
    }
}

impl Batch<'_> {
    /// Inserts a record and everything derived from it.
    ///
    /// Fan-out jobs are enqueued *inside* the transaction: enqueueing after commit loses them to any
    /// crash in between, and nothing would notice.
    ///
    /// Replayable. The record insert turns on its unique id, every derived row is keyed, and the
    /// entity counters are recomputed, so publishing the same record twice is a no-op.
    pub fn publish(&mut self, input: PublishInput<'_>) -> crate::Result<()> {
        let doc = input.record;
        // Checked here as well as by the table's own CHECK, so a caller that passes the prose of a
        // sealed record gets told what it did wrong rather than a constraint violation.
        if doc.data_class == DataClass::SubjectDerived && !input.searchable_body.is_empty() {
            return Err(bad_input(
                doc,
                "a sealed record has no searchable body; pass \"\"",
            ));
        }
        let frontmatter = frontmatter_json(doc)?;

        let record_pk = insert_record(&self.tx, doc, &frontmatter, input.searchable_body)?;
        let received_ms = self.tx.query_row(
            "SELECT received_ms FROM records WHERE id = ?1",
            params![record_pk],
            |row| row.get::<_, i64>(0),
        )?;
        insert_attrs(&self.tx, record_pk, doc)?;
        insert_entities(&self.tx, record_pk, received_ms, doc)?;
        insert_subjects(&self.tx, record_pk, &input)?;
        enqueue_fanout(&self.tx, doc, received_ms)?;
        Ok(())
    }

    /// Drops every derived row so the index can be rebuilt from the tree.
    ///
    /// The timeline mentions go with them, which is why a rebuild has to remove the timeline files
    /// too: a file surviving the row that records its line makes the next append write that line a
    /// second time. [`crate::Writer::claim_timeline_mention`] has the argument in full.
    pub fn truncate_derived(&mut self) -> crate::Result<()> {
        // Deleting records cascades to attrs, entity refs, subjects, timeline mentions and queued
        // fan-out, and the delete trigger unindexes each body. 'delete-all' then clears any
        // full-text row whose record went missing without a trigger firing — a rebuild must not
        // inherit a phantom.
        self.tx.execute_batch(
            "DELETE FROM records;
             DELETE FROM entities;
             DELETE FROM quarantine_pending;
             INSERT INTO records_fts (records_fts) VALUES ('delete-all');",
        )?;
        Ok(())
    }

    /// Records that a record is held back, unpublished, in a spool file.
    ///
    /// The batch-scoped [`Writer::enqueue_quarantine`]: a rebuild derives this register from the
    /// spool directory, and it belongs in the same transaction as the rows it sits beside.
    pub fn enqueue_quarantine(
        &mut self,
        id: &str,
        qkek_date: &str,
        spool_path: &str,
    ) -> crate::Result<()> {
        enqueue_quarantine_in(&self.tx, id, qkek_date, spool_path)
    }

    /// Makes everything this batch wrote visible, durably.
    pub fn commit(self) -> crate::Result<()> {
        self.tx.commit()?;
        Ok(())
    }
}

/// Registers a held-back record on whichever connection or transaction is given.
///
/// One statement, so it is atomic on its own; inside a [`Batch`] it joins that transaction instead.
///
/// This is the one write that reads the clock. It has to: the record is not in the tree yet, so
/// there is no server-stamped time to derive the sighting from.
fn enqueue_quarantine_in(
    conn: &Connection,
    id: &str,
    qkek_date: &str,
    spool_path: &str,
) -> crate::Result<()> {
    conn.execute(
        "INSERT INTO quarantine_pending (record_id, qkek_date, staging_path, first_seen_ms)
         VALUES (?1, ?2, ?3, CAST(ROUND(unixepoch('now', 'subsec') * 1000) AS INTEGER))
         ON CONFLICT (record_id) DO NOTHING",
        params![id, qkek_date, spool_path],
    )?;
    Ok(())
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
fn insert_entities(
    tx: &Transaction<'_>,
    record_pk: i64,
    received_ms: i64,
    doc: &ActionRecord,
) -> crate::Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO entity_refs (record_pk, kind, entity_id, role, confidence, received_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (record_pk, kind, entity_id, role)
             DO UPDATE SET confidence = excluded.confidence,
                           received_ms = excluded.received_ms",
    )?;
    // Recomputed from entity_refs, never incremented: an incremented counter would double on
    // replay, and there would be nothing to compare it against to notice. Read out of the reference
    // index alone rather than joined back to `records` — the time is in the index, so recomputing a
    // hot entity's counters no longer costs one row lookup per reference it has ever had.
    let mut recount = tx.prepare_cached(
        "INSERT INTO entities (kind, entity_id, first_seen_ms, last_seen_ms, ref_count)
         SELECT er.kind, er.entity_id,
                MIN(er.received_ms), MAX(er.received_ms), COUNT(*)
         FROM entity_refs AS er
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
            received_ms,
        ])?;
        recount.execute(params![entity.kind, entity.id])?;
    }
    Ok(())
}

/// Writes one row per named subject, with its wrapped share when the caller has one.
///
/// A share for a subject the record does not name is refused rather than dropped: the row it would
/// belong to cannot be built, and a silently discarded key share is a body nothing can unseal.
fn insert_subjects(
    tx: &Transaction<'_>,
    record_pk: i64,
    input: &PublishInput<'_>,
) -> crate::Result<()> {
    let doc = input.record;
    let mut keys: BTreeMap<&str, (&Epoch, &[u8])> = BTreeMap::new();
    for (hash, epoch, wrapped) in input.subject_keys {
        if keys
            .insert(hash.as_str(), (epoch, wrapped.as_slice()))
            .is_some()
        {
            return Err(bad_input(
                doc,
                &format!("subject `{}` was keyed twice", hash.as_str()),
            ));
        }
    }

    let mut insert = tx.prepare_cached(
        "INSERT INTO record_subjects
             (record_pk, subject_hash, role, canon_ver, epoch, wrapped_key_share)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (record_pk, subject_hash) DO UPDATE SET
             role      = excluded.role,
             canon_ver = excluded.canon_ver,
             -- A publish carrying no share is a reindex from the tree, and must not drop a wrap
             -- the tree still holds: the row would then name a subject whose share is nowhere.
             epoch     = CASE WHEN excluded.wrapped_key_share IS NULL
                              THEN record_subjects.epoch ELSE excluded.epoch END,
             wrapped_key_share =
                 COALESCE(excluded.wrapped_key_share, record_subjects.wrapped_key_share)",
    )?;
    for subject in &doc.subjects {
        let keyed = keys.remove(subject.hash.as_str());
        insert.execute(params![
            record_pk,
            subject.hash.as_str(),
            subject_role_text(subject.role),
            subject.canon_ver.0,
            keyed.map_or("", |(epoch, _)| epoch.as_str()),
            keyed.map(|(_, wrapped)| wrapped),
        ])?;
    }

    if let Some(unnamed) = keys.keys().next() {
        return Err(bad_input(doc, &format!("no subject `{unnamed}` to key")));
    }
    Ok(())
}

/// Reports publish input the record cannot accept.
fn bad_input(doc: &ActionRecord, detail: &str) -> crate::Error {
    crate::Error::BadPublishInput {
        record: doc.record_id.as_str().to_owned(),
        detail: detail.to_owned(),
    }
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
