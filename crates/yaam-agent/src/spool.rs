//! The sealed outbound queue.
//!
//! Sidecar-local, not part of the memory tree: the tree belongs to the service, and a sidecar on a
//! different host has no tree at all. Excluded from host backups, drained on reconnect, never
//! archived.

use std::path::Path;

/// An append-only queue of sealed records awaiting upstream.
#[derive(Debug)]
pub struct Spool {
    #[expect(dead_code, reason = "read once the implementation lands")]
    dir: std::path::PathBuf,
}

impl Spool {
    /// Opens or creates a spool.
    pub fn open(_dir: impl AsRef<Path>) -> crate::Result<Self> {
        todo!("create with restrictive permissions")
    }

    /// Appends a sealed record, fsyncing before returning.
    pub fn push(&mut self, _sealed: &[u8]) -> crate::Result<()> {
        todo!("append + fsync")
    }

    /// Replays in order, removing each entry only once upstream has accepted it.
    pub fn drain<F>(&mut self, _send: F) -> crate::Result<usize>
    where
        F: FnMut(&[u8]) -> crate::Result<()>,
    {
        todo!("ordered replay; leave entry on failure")
    }

    /// Number of entries waiting.
    pub fn depth(&self) -> crate::Result<usize> {
        todo!("count entries")
    }
}
