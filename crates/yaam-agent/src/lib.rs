//! The sidecar.
//!
//! Callers get one method: write a line to a socket. Signing keys, sealing, spooling and retry all
//! live here, so a caller that can record an action cannot read anyone else's, and a compromised
//! caller yields no key material.
//!
//! Two choices worth knowing. The transport is a socket rather than a spool file the caller appends
//! to, because a file would put plaintext on the caller's disk — the sidecar seals before anything
//! is written. And durability belongs to the sidecar, not the caller: it is supervised and owns a
//! sealed spool, so a caller keeps only a small in-memory buffer and fails loudly rather than
//! inventing its own plaintext queue.
//!
//! # Shape of a running sidecar
//!
//! [`listener::serve`] binds one socket per [`listener::CallerSocket`] and keeps its spool in the
//! state directory it is given. Where the service is, its public key and the keys to sign with all
//! arrive as an [`upstream::Upstream`] the caller passes in — [`listener::Config::load`] reads one
//! from a file for a deployment that keeps it there, and nothing here reaches for process-wide
//! state. A record's path through the sidecar is: parse, validate, check attribution against the
//! socket, seal to the service's public key, sign, post — and spool only if the service said
//! *later* rather than *no*.
//!
//! # What the service sees
//!
//! One sealed envelope per record, signed as the agent whose socket it arrived on. The envelope
//! format and the canonical signed message are both shared code — [`yaam_crypto::envelope`] and
//! [`yaam_contract::request`] — because the service is the other end of both, and a sidecar-local
//! spelling of either is a system whose halves cannot talk while each passes its own tests.

#![forbid(unsafe_code)]

pub mod error;
pub mod listener;
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
