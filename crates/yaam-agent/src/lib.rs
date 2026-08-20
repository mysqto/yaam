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

#![forbid(unsafe_code)]

pub mod error;
pub mod listener;
pub mod spool;
pub mod upstream;

pub use error::{Error, Result};
