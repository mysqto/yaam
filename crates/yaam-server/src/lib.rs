//! The service surface.
//!
//! Five endpoints, all signed — reads included, because visibility is enforced per caller and that
//! is impossible for an anonymous request. Reindex is deliberately *not* an endpoint: it is a
//! command-line operation, so no request can trigger a rebuild.

#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod routes;

pub use error::{Error, Result};
