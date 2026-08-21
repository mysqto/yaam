//! The sidecar.
//!
//! Callers hold no key material, for writes or for reads. A caller writes a record by putting a
//! line on one socket, and reads by sending an ordinary HTTP request to another; signing keys,
//! sealing, spooling and retry all live here. So a caller that can record an action cannot read
//! anyone else's, and a compromised caller yields no key — which is the whole point: a signing key
//! in a caller's hands can sign anything, including records attributed to somebody else, and there
//! is no revoking it faster than a caller can use it.
//!
//! Two choices worth knowing. The transport is a socket rather than a spool file the caller appends
//! to, because a file would put plaintext on the caller's disk — the sidecar seals before anything
//! is written. And durability belongs to the sidecar, not the caller: it is supervised and owns a
//! sealed spool, so a caller keeps only a small in-memory buffer and fails loudly rather than
//! inventing its own plaintext queue.
//!
//! # Shape of a running sidecar
//!
//! [`listener::serve`] binds two sockets per [`listener::CallerSocket`] — records and reads — and
//! keeps its spool in the state directory it is given. Where the service is, its public key and the
//! keys to sign with all arrive as an [`upstream::Upstream`] the caller passes in;
//! [`listener::Config::load`] reads one from a file for a deployment that keeps it there, and
//! nothing here reaches for process-wide state.
//!
//! A record's path through the sidecar is: parse, validate, check attribution against the socket,
//! seal to the service's public key, sign, post — and spool only if the service said *later* rather
//! than *no*. A read's is much shorter: check the peer, refuse anything that is not a `GET`, sign
//! the request target as the socket's agent, forward, and hand back what the service answered.
//! Nothing on the read path can spool, which is deliberate — a read the service cannot answer has
//! failed, and answering it later means answering with data that was already stale.
//!
//! # What the service sees
//!
//! One sealed envelope per record, signed as the agent whose socket it arrived on, and reads signed
//! as the same agent. The envelope format and the canonical signed message are both shared code —
//! [`yaam_crypto::envelope`] and [`yaam_contract::request`] — because the service is the other end
//! of both, and a sidecar-local spelling of either is a system whose halves cannot talk while each
//! passes its own tests.

#![forbid(unsafe_code)]

pub mod error;
pub mod listener;
mod proxy;
mod sidecar;
pub mod spool;
#[cfg(test)]
mod stub;
pub mod upstream;

pub use error::{Error, Result};
/// Sealing to the service's public key.
///
/// Re-exported rather than reimplemented: the service opens what this seals, so both sides use one
/// module.
pub use yaam_crypto::envelope;
