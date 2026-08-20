//! Handles onto the index.

use std::path::Path;

/// A read handle. Cheap to clone across readers.
#[derive(Debug)]
pub struct Store {
    #[expect(dead_code, reason = "read once the implementation lands")]
    conn: rusqlite::Connection,
}

/// The single write handle. Owning it is what serialises writes.
#[derive(Debug)]
pub struct Writer {
    #[expect(dead_code, reason = "read once the implementation lands")]
    conn: rusqlite::Connection,
}

impl Store {
    /// Opens the index read-only, migrating nothing.
    pub fn open_read(_path: &Path) -> crate::Result<Self> {
        todo!("open read-only, apply pragmas")
    }
}

impl Writer {
    /// Opens the index for writing and brings the schema up to date.
    pub fn open(_path: &Path) -> crate::Result<Self> {
        todo!("open, pragmas, migrate")
    }

    /// Inserts a record and everything derived from it, in one transaction.
    ///
    /// Fan-out jobs are enqueued *inside* this transaction: enqueueing after commit loses them to
    /// any crash in between, and nothing would notice.
    pub fn publish(&mut self, _doc: &yaam_contract::ActionRecord) -> crate::Result<()> {
        todo!("BEGIN IMMEDIATE, insert record + entities + subjects + fanout, COMMIT")
    }

    /// Drops every derived row so the index can be rebuilt from the tree.
    pub fn truncate_derived(&mut self) -> crate::Result<()> {
        todo!("delete all rows, keep schema")
    }
}
