//! Accepting records from local callers.
//!
//! One socket per caller, permissioned to that caller, so the sidecar knows who is on the other end
//! without being told. A single shared socket would let any local process attribute a record to any
//! agent, which would quietly undo write attribution.

use std::path::Path;

/// A configured caller and the socket it owns.
#[derive(Debug, Clone)]
pub struct CallerSocket {
    /// Agent identity records from this socket are attributed to.
    pub agent: String,
    /// Filesystem path of the socket.
    pub path: std::path::PathBuf,
}

/// Serves every configured caller socket until shutdown.
pub async fn serve(_sockets: &[CallerSocket], _state_dir: &Path) -> crate::Result<()> {
    todo!("bind per-caller sockets with restrictive modes, verify peer credentials, read jsonl")
}
