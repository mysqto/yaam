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
//! [`listener::serve`] binds one socket per [`listener::CallerSocket`], reads the service's address
//! and public key from `upstream.json` in its state directory, and keeps its spool in the same
//! place. A record's path through it is: parse, validate, check attribution against the socket, seal
//! to the service's public key, post — and spool only if the service said *later* rather than *no*.
//!
//! # One thing this sidecar does not do
//!
//! It does not authenticate its requests. [`upstream::Upstream`] carries a base URL and the
//! service's *public* key, and neither is a caller credential; the type has nowhere to put the
//! shared secret the service's HMAC verification expects. Deriving one from a public key would look
//! like authentication while providing none, so requests go out unsigned and this says so. Closing
//! the gap needs one field on [`upstream::Upstream`], or a credential argument to
//! [`upstream::Upstream::post_record`] — a change to a frozen surface, and so a decision for whoever
//! owns it rather than one to make quietly here.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod listener;
mod sidecar;
pub mod spool;
#[cfg(test)]
mod stub;
pub mod upstream;

pub use error::{Error, Result};
