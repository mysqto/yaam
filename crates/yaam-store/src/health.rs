//! What the index can say about its own state.
//!
//! Read in one lease rather than a count at a time, because these numbers are read together and
//! answer one question: whether the index is current, and how much work it is holding. Counted
//! afresh on every call — a cached depth is a depth that was true once.
//!
//! Nothing here is scoped to a caller, and it must stay that way: these are maintenance figures
//! about the file, not answers about anybody's records. A queue depth narrowed to what one caller
//! may see is a queue depth that is wrong.

use crate::store::Store;
use crate::{schema, store};

/// What the index reports about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHealth {
    /// Schema version the file is at.
    pub schema_version: u32,
    /// Highest schema version this build understands.
    ///
    /// Carried alongside rather than left to the reader to look up: a file behind this build needs a
    /// writer run, one ahead of it needs a newer build, and the two are opposite actions.
    pub supported_schema_version: u32,
    /// Records the index holds.
    pub records: usize,
    /// Records held back until their subjects resolve.
    pub quarantine_pending: usize,
    /// Fan-out jobs nobody has taken.
    pub fanout_pending: usize,
    /// Fan-out jobs a drain is holding a claim on.
    ///
    /// Not necessarily work in progress: a claim whose holder died stays here until a sweep
    /// reclaims it, which is why it is reported apart from the pending count.
    pub fanout_claimed: usize,
}

/// Reads every figure in one go.
pub fn read(store: &Store) -> crate::Result<IndexHealth> {
    let conn = store.lease()?;
    let count = |sql: &str| -> crate::Result<usize> {
        let count: i64 = conn.query_row(sql, [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    };
    Ok(IndexHealth {
        schema_version: conn.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        supported_schema_version: schema::SCHEMA_VERSION,
        records: count("SELECT COUNT(*) FROM records")?,
        quarantine_pending: count("SELECT COUNT(*) FROM quarantine_pending")?,
        // The state spellings come from the writer's own constants: a count that named the states
        // itself would keep answering zero after the writer renamed one.
        fanout_pending: count(&format!(
            "SELECT COUNT(*) FROM fanout_queue WHERE state = '{}'",
            store::STATE_PENDING
        ))?,
        fanout_claimed: count(&format!(
            "SELECT COUNT(*) FROM fanout_queue WHERE state = '{}'",
            store::STATE_CLAIMED
        ))?,
    })
}

/// Fan-out claims taken before `claimed_before_ms`.
///
/// The read-only counterpart of [`crate::Writer::reclaim_stale_fanout`], and it takes the same
/// cutoff: a claim is only evidence of a dead drain relative to how long a drain is allowed to
/// take, and that judgement belongs to the caller that knows.
pub fn stale_claims(store: &Store, claimed_before_ms: i64) -> crate::Result<usize> {
    const SQL: &str = "SELECT COUNT(*) FROM fanout_queue WHERE state = ?1 AND claimed_ms < ?2";
    let conn = store.lease()?;
    let bound = rusqlite::params![store::STATE_CLAIMED, claimed_before_ms];
    let count: i64 = conn.query_row(SQL, bound, |row| row.get(0))?;
    Ok(usize::try_from(count).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::read;
    use crate::schema::SCHEMA_VERSION;

    /// An index with nothing in it still answers, and says what version it is.
    #[test]
    fn a_fresh_index_reports_a_current_schema_and_no_backlog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("index.sqlite");
        drop(crate::Writer::open(&path).expect("writer"));

        let store = crate::Store::open_read(&path).expect("reader");
        let health = read(&store).expect("health");
        assert_eq!(health.schema_version, SCHEMA_VERSION);
        assert_eq!(health.supported_schema_version, SCHEMA_VERSION);
        assert_eq!(health.records, 0);
        assert_eq!(health.quarantine_pending, 0);
        assert_eq!(health.fanout_pending, 0);
        assert_eq!(health.fanout_claimed, 0);
        assert_eq!(super::stale_claims(&store, i64::MAX).expect("claims"), 0);
    }
}
