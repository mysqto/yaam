//! Request authentication and write attribution.

/// A verified caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The agent identity this caller may write as.
    pub agent: String,
    /// What the caller is allowed to do.
    pub role: Role,
}

/// Capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// May read within its visibility scope.
    Reader,
    /// May also write records attributed to itself.
    Writer,
    /// May erase, unseal with audit, and run maintenance.
    Operator,
}

/// Verifies a signature over the request and resolves the caller.
pub fn verify(_headers: &axum::http::HeaderMap, _body: &[u8]) -> crate::Result<Caller> {
    todo!("constant-time hmac verification, accept current and previous key")
}

/// Rejects a write that attributes a record to an agent other than the caller.
pub fn authorise_write(_caller: &Caller, _record_agent: &str) -> crate::Result<()> {
    todo!("forbid attribution to another agent")
}
