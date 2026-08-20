//! The queries the system exists to answer.

use yaam_contract::RecordId;

/// A time window, in server-stamped milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// Inclusive start.
    pub from_ms: i64,
    /// Exclusive end.
    pub to_ms: i64,
}

/// Filters for a record query.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Restrict to one action.
    pub action: Option<String>,
    /// Restrict to one outcome.
    pub outcome: Option<String>,
    /// Restrict to one agent.
    pub agent: Option<String>,
    /// Require a structural attribute to equal a value.
    pub attr: Option<(String, String)>,
    /// Restrict to a time window.
    pub window: Option<Window>,
    /// Page size.
    pub limit: Option<u32>,
}

/// Everything touching one entity, newest first.
pub fn by_entity(
    _store: &crate::Store,
    _kind: &str,
    _id: &str,
    _min_confidence: f32,
) -> crate::Result<Vec<RecordId>> {
    todo!("join entity_refs")
}

/// Filtered record query.
pub fn by_filter(_store: &crate::Store, _filter: &Filter) -> crate::Result<Vec<RecordId>> {
    todo!("build indexed query; never scan on json extraction")
}

/// Correlates two actions falling within `within_ms` of each other.
///
/// The shape most cross-agent questions reduce to: something failed, and something else happened
/// nearby. A non-equi range join, so it needs the covering index to stay cheap.
pub fn correlate(
    _store: &crate::Store,
    _left: &Filter,
    _right: &Filter,
    _within_ms: i64,
) -> crate::Result<Vec<(RecordId, RecordId)>> {
    todo!("windowed join on received_ms")
}

/// Full-text search over plaintext bodies only.
pub fn search(_store: &crate::Store, _needle: &str, _limit: u32) -> crate::Result<Vec<RecordId>> {
    todo!("fts5 match")
}
