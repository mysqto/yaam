//! Schema and migrations.
//!
//! Notes that are easy to get wrong and expensive to discover late:
//! `PRAGMA foreign_keys` is off by default, so cascades are inert without it; an explicit integer
//! primary key is required because an implicit rowid can be renumbered by `VACUUM`, which would
//! silently break the full-text mapping; and external-content full-text tables map columns *by
//! name*, so the content table needs a real `body` column and triggers to stay in sync.

/// Highest schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Applies pragmas that the rest of the design depends on.
pub fn apply_pragmas(_conn: &rusqlite::Connection) -> crate::Result<()> {
    todo!("WAL, synchronous=FULL, foreign_keys=ON, secure_delete=ON, mmap, cache")
}

/// Creates or upgrades the schema.
pub fn migrate(_conn: &mut rusqlite::Connection) -> crate::Result<()> {
    todo!("versioned migrations")
}
