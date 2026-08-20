//! The write path.
//!
//! Ordering is deliberate: the file is published *before* the index row is written, so the tree
//! stays authoritative and the index is a follower. Staging is fsynced — file *and* directory —
//! before the caller is told the write succeeded, which is where the durability promise begins.

use yaam_contract::{ActionRecord, RecordId};

/// Outcome of accepting a record.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Stored. First time this identifier was seen.
    Stored(RecordId),
    /// Already present; nothing changed. Replays are expected and harmless.
    Duplicate(RecordId),
    /// Held pending subject resolution, unpublished and unindexed.
    Quarantined(RecordId),
}

/// The write pipeline.
#[derive(Debug)]
pub struct Pipeline {
    #[expect(dead_code, reason = "read once the implementation lands")]
    root: std::path::PathBuf,
}

impl Pipeline {
    /// Builds a pipeline over a memory tree.
    pub fn new(_root: impl Into<std::path::PathBuf>) -> crate::Result<Self> {
        todo!("ensure tree layout exists")
    }

    /// Runs a record through dedupe, validation, sealing, staging and publish.
    pub fn accept(&mut self, _record: ActionRecord, _body: &str) -> crate::Result<Accepted> {
        todo!("0 dedupe, 1 validate+seal, 2 stage+fsync, 3 publish+commit, 4 enqueue fanout")
    }

    /// Drains queued fan-out work: entity timelines and audit records.
    pub fn drain_fanout(&mut self, _max_jobs: usize) -> crate::Result<usize> {
        todo!("idempotent; dead-letter after repeated failure")
    }
}
