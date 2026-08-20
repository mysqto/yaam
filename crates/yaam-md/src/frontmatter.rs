//! Frontmatter is the machine-readable half of a record, and is always plaintext.
//!
//! It carries structure only — identifiers, timestamps, action, outcome, declared structural
//! attributes, entity and subject references. It never carries prose or sensitive attributes,
//! because it survives in copies that key destruction cannot reach.

use yaam_contract::ActionRecord;

/// Renders a record's frontmatter, without fences.
#[must_use]
pub fn render(_record: &ActionRecord) -> String {
    todo!("stable key order so re-renders are byte-identical")
}

/// Parses frontmatter into a record, leaving the body to the caller.
pub fn parse(_yaml: &str) -> crate::Result<ActionRecord> {
    todo!("parse and validate")
}

/// Canonical JSON projection, as stored in the index for structured queries.
pub fn to_canonical_json(_record: &ActionRecord) -> crate::Result<String> {
    todo!("stable key order; must match frontmatter keys exactly")
}
