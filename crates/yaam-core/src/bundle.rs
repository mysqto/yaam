//! Assembling context for a caller.
//!
//! Sealed bodies are never unsealed here. A caller receives structure — action, outcome,
//! attributes, entities — and never subject plaintext, because plaintext handed to a caller reaches
//! places this system cannot erase.

use yaam_contract::RecordId;

/// Context assembled for one request.
#[derive(Debug, Default)]
pub struct Bundle {
    /// Records judged relevant.
    pub records: Vec<RecordId>,
    /// `true` when a source was unavailable and the bundle is incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
    /// Rough token cost, advisory only.
    pub token_estimate: usize,
}

/// What the caller wants context for.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Entities to gather history for.
    pub entities: Vec<(String, String)>,
    /// Actor whose recent activity is relevant.
    pub actor: Option<String>,
    /// Budget for the whole composition.
    pub deadline_ms: u64,
}

/// Composes a bundle, degrading rather than failing when a source is slow.
///
/// Returning a partial bundle marked `degraded` is safe for questions and unsafe for actions. The
/// caller decides, which is why the flag is explicit rather than implied by an empty result.
pub fn compose(_store: &yaam_store::Store, _request: &Request) -> crate::Result<Bundle> {
    todo!("query within deadline, mark omissions")
}
