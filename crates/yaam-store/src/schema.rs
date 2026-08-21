//! Schema and migrations.
//!
//! Notes that are easy to get wrong and expensive to discover late:
//! `PRAGMA foreign_keys` is off by default, so cascades are inert without it; an explicit integer
//! primary key is required because an implicit rowid can be renumbered by `VACUUM`, which would
//! silently break the full-text mapping; and external-content full-text tables map columns *by
//! name*, so the content table needs a real `body` column and triggers to stay in sync.

use rusqlite::{Connection, MAIN_DB};

/// Highest schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Applies pragmas that the rest of the design depends on.
///
/// Every one of these fails silently when omitted: cascades become no-ops, committed transactions
/// become droppable, freed pages keep their plaintext. So they are applied on every connection,
/// read or write, rather than once at creation time.
pub fn apply_pragmas(conn: &Connection) -> crate::Result<()> {
    // Journal mode and secure-delete are properties of the file, so a read-only handle cannot set
    // them; attempting it on a rollback-journal file is a hard error rather than a no-op.
    if !conn.is_readonly(MAIN_DB)? {
        // Queried, not executed: the pragma answers with the mode it settled on.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
    }
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // NORMAL can lose a committed transaction on power loss. An index is rebuildable, but a
    // rebuild needs the tree, and silent divergence is worse than a slower commit.
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    // Negative cache_size is KiB rather than pages, so it does not move with page_size.
    conn.pragma_update(None, "cache_size", -65_536i64)?;
    conn.pragma_update(None, "mmap_size", 268_435_456i64)?;
    // Readers would otherwise fail outright while the single writer holds the write lock.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Creates or upgrades the schema.
///
/// Idempotent: the on-disk `user_version` decides which steps still have to run, so migrating an
/// up-to-date file does nothing and migrating a fresh file applies every step.
pub fn migrate(conn: &mut Connection) -> crate::Result<()> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(crate::Error::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    for (index, step) in MIGRATIONS.iter().enumerate() {
        let target = u32::try_from(index).unwrap_or(u32::MAX) + 1;
        if target <= found {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(step)?;
        // Pragmas take no bind parameters, hence the formatted literal; `target` is a loop counter.
        tx.execute_batch(&format!("PRAGMA user_version = {target}"))?;
        tx.commit()?;
    }
    Ok(())
}

/// One statement batch per schema version, in order.
///
/// Append only once a version has shipped: `V1` is still being edited because no release has
/// written a file under it, and rewriting a table is a worse trade than correcting the definition.
/// Note for later steps: `SQLite` rejects `ALTER TABLE ADD COLUMN ... STORED`, so a generated column
/// added after the fact has to be `VIRTUAL` plus its own index.
const MIGRATIONS: &[&str] = &[V1];

/// Version 1: records and everything derived from them.
const V1: &str = r"
-- Explicit integer primary key: VACUUM may renumber an implicit rowid, which would silently
-- repoint every full-text row at the wrong record.
CREATE TABLE records (
    id             INTEGER PRIMARY KEY,
    record_id      TEXT    NOT NULL UNIQUE,
    schema_ver     INTEGER NOT NULL,
    -- Canonical JSON of the record minus its body. Every derived column below comes from here,
    -- which is what keeps the index reproducible from the tree.
    frontmatter    TEXT    NOT NULL,
    -- Plaintext body, or '' when the record is sealed. Enforced, not merely intended: a sealed
    -- body that reached this column would become searchable and route around sealing.
    body           TEXT    NOT NULL
                   CHECK (body = ''
                          OR json_extract(frontmatter, '$.data_class') <> 'subject_derived'),
    -- Source clock. Kept for provenance, never used for ordering: it may be skewed or replayed.
    at_ms          INTEGER NOT NULL,
    -- Server clock. Authoritative for all ordering, windowing and joins.
    received_ms    INTEGER NOT NULL,
    -- Promoted out of the JSON because inline json_extract is not indexable, and the correlation
    -- join would otherwise be a double full scan with per-row JSON parsing.
    action         TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.action')) STORED,
    outcome        TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.outcome')) STORED,
    agent          TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.agent')) STORED,
    correlation_id TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.correlation_id')) STORED,
    -- Promoted for the same reason as the columns above, and needed by *every* read: what a caller
    -- may see is decided per caller, and a predicate over inline JSON could not be one.
    visibility     TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.visibility')) STORED,
    -- NULL unless visibility is 'team'. A team-scoped record without a team is rejected by the
    -- contract, so NULL here can only mean the record is not team-scoped — and NULL matches no
    -- team, which is the answer a scope test wants.
    team           TEXT GENERATED ALWAYS AS (json_extract(frontmatter, '$.team')) STORED,
    sealed         INTEGER GENERATED ALWAYS AS
                   (json_extract(frontmatter, '$.data_class') = 'subject_derived') STORED
) STRICT;

-- Covering for a read that pins both `action` and `outcome` and then range-scans `received_ms`,
-- with `record_id` here so the read never touches the table. The correlation join's right-hand
-- side pins only `action`, which is why it needs the index below rather than this one.
CREATE INDEX records_action_outcome_time
    ON records (action, outcome, received_ms, record_id);
-- The correlation join's right-hand side constrains `action` and range-scans `received_ms`, but
-- says nothing about `outcome`. Under the index above that leaves `outcome` a gap mid-key, so the
-- range degrades from a seek to a per-row filter and the join costs (left rows) x (every row of the
-- right action). Measured: 97 ms windowed and 4.5 s unwindowed become 1.0 ms each with this.
CREATE INDEX records_action_time
    ON records (action, received_ms, record_id);
CREATE INDEX records_agent_time ON records (agent, received_ms);
CREATE INDEX records_time       ON records (received_ms);
CREATE INDEX records_correlation
    ON records (correlation_id, received_ms) WHERE correlation_id IS NOT NULL;

-- Structural attributes, one row per key, so an attribute filter is an index seek rather than a
-- scan over JSON extraction. Values are compared as text; the query API is text-shaped too.
CREATE TABLE record_attrs (
    record_pk INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    key       TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    PRIMARY KEY (record_pk, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX record_attrs_lookup ON record_attrs (key, value, record_pk);

-- Compound primary key rather than a surrogate one: a replayed write collides instead of
-- appending a duplicate edge.
CREATE TABLE entity_refs (
    record_pk  INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL,
    entity_id  TEXT    NOT NULL,
    role       TEXT    NOT NULL,
    confidence REAL    NOT NULL,
    PRIMARY KEY (record_pk, kind, entity_id, role)
) STRICT, WITHOUT ROWID;

CREATE INDEX entity_refs_lookup ON entity_refs (kind, entity_id, confidence, record_pk);

-- A record may name several subjects, each with its own role, key epoch and wrapped key share.
CREATE TABLE record_subjects (
    record_pk         INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    subject_hash      TEXT    NOT NULL,
    role              TEXT    NOT NULL,
    canon_ver         INTEGER NOT NULL,
    -- Key epoch, as the key store labels it (`2026-Q3`). Empty until the share is wrapped, the
    -- same not-yet that a NULL wrapped_key_share records.
    epoch             TEXT    NOT NULL DEFAULT '',
    -- NULL until the key store wraps the share. The plaintext key is never stored here.
    wrapped_key_share BLOB,
    PRIMARY KEY (record_pk, subject_hash)
) STRICT, WITHOUT ROWID;

-- Erasure walks by subject: find every record a destroyed key made unreadable.
CREATE INDEX record_subjects_by_hash ON record_subjects (subject_hash, epoch, record_pk);

-- Catalog of entities seen. Every column is recomputed from entity_refs on write, never
-- incremented, so a replayed record cannot inflate it.
CREATE TABLE entities (
    kind          TEXT    NOT NULL,
    entity_id     TEXT    NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    ref_count     INTEGER NOT NULL,
    PRIMARY KEY (kind, entity_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX entities_recent ON entities (kind, last_seen_ms);

-- Fan-out work, enqueued in the same transaction as the record. UNIQUE(record_id, job_kind)
-- makes enqueue idempotent, so a re-drive cannot multiply the work.
CREATE TABLE fanout_queue (
    id            INTEGER PRIMARY KEY,
    record_id     TEXT    NOT NULL REFERENCES records(record_id) ON DELETE CASCADE,
    job_kind      TEXT    NOT NULL,
    state         TEXT    NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    enqueued_ms   INTEGER NOT NULL,
    -- Earliest time a claim may take this job again. 0 until an attempt fails and asks for a
    -- delay: without it a retry budget can only be spent in a tight loop inside one drain.
    not_before_ms INTEGER NOT NULL DEFAULT 0,
    -- When the claim being held was taken, NULL when nobody holds one. A claim whose holder died
    -- is invisible to every later drain, and this is what dates it for reclamation.
    claimed_ms    INTEGER,
    UNIQUE (record_id, job_kind)
) STRICT;

-- Rows are kept in state 'done' for ever, so a claim must never scan them: state leads, then the
-- readiness test, then the order jobs are handed out in.
CREATE INDEX fanout_queue_claim ON fanout_queue (state, not_before_ms, enqueued_ms);

-- Records held back until their subjects resolve. Pointers only: a body here would be an
-- unsealed copy in a table the erasure path does not own. No foreign key, because the whole point
-- is that the record is not in the index yet.
CREATE TABLE quarantine_pending (
    record_id     TEXT    PRIMARY KEY,
    staging_path  TEXT    NOT NULL,
    -- Date of the quarantine key the spooled copy was sealed under. Without it the spool file
    -- cannot be opened again, so it is the one field the row cannot do without.
    qkek_date     TEXT    NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX quarantine_pending_age ON quarantine_pending (first_seen_ms);

-- External content: the column name 'body' must match records.body, and content_rowid must name
-- the explicit integer key. Nothing is synced automatically; the triggers below do it.
CREATE VIRTUAL TABLE records_fts USING fts5(
    body,
    content = 'records',
    content_rowid = 'id',
    tokenize = 'unicode61'
);

CREATE TRIGGER records_fts_insert AFTER INSERT ON records BEGIN
    INSERT INTO records_fts (rowid, body) VALUES (new.id, new.body);
END;

CREATE TRIGGER records_fts_delete AFTER DELETE ON records BEGIN
    INSERT INTO records_fts (records_fts, rowid, body) VALUES ('delete', old.id, old.body);
END;

-- Scoped to the body: an unrelated column update would otherwise churn the whole index.
CREATE TRIGGER records_fts_update AFTER UPDATE OF body ON records BEGIN
    INSERT INTO records_fts (records_fts, rowid, body) VALUES ('delete', old.id, old.body);
    INSERT INTO records_fts (rowid, body) VALUES (new.id, new.body);
END;
";
