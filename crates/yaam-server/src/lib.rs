//! The service surface.
//!
//! Five endpoints, all signed — reads included, because every read is narrowed to what the
//! authenticated caller may see, and an anonymous request has no caller to narrow to. Reindex is
//! deliberately *not* an endpoint: it is a command-line operation, so no request can trigger a
//! rebuild.
//!
//! Everything a request needs arrives in [`routes::AppState`]: the keyring, the service, and the
//! key that opens what a sidecar sealed. There is no process-wide installation to resolve — a
//! router that reached for one could not be pointed at two deployments, and configuration that is
//! invisible at the call site is configuration nobody checks.

#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod routes;
pub mod service;

#[cfg(test)]
mod testing;

pub use error::{Error, Result};
