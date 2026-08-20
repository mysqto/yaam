//! Erasure by key destruction.
//!
//! What this reaches and what it does not is the whole point, so it is stated rather than implied:
//! destroying a subject's keys makes their record *bodies* permanently unreadable in every copy,
//! including backups. It does not reach frontmatter, attributes, entity references or timelines —
//! that structure is retained, and callers must not describe this as erasing everything.

use yaam_contract::SubjectHash;

/// What an erasure did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EraseReport {
    /// Records whose bodies became unreadable.
    pub bodies_sealed_off: usize,
    /// Keys destroyed, across all epochs.
    pub keys_destroyed: usize,
    /// Quarantined records resolved or discarded as part of this request.
    pub quarantine_settled: usize,
    /// Identifier of the tombstone written.
    pub tombstone_id: String,
}

/// Erases a subject's bodies and records the fact permanently.
///
/// Verification is two-phase. The live check runs here; completion cannot be asserted until the key
/// backup window has passed, so the tombstone is only stamped complete later.
pub fn erase_subject(
    _pipeline: &mut crate::Pipeline,
    _subject: &SubjectHash,
) -> crate::Result<EraseReport> {
    todo!("tombstone, destroy keys, drop subject rows, rewrite live copies, verify")
}

/// Confirms that no recoverable key copy remains, and stamps the tombstone complete.
pub fn confirm_erasure(
    _pipeline: &mut crate::Pipeline,
    _tombstone_id: &str,
) -> crate::Result<bool> {
    todo!("assert no key backup predates the destruction")
}
