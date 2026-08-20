//! The parts that have to be correct under failure.
//!
//! A filesystem rename cannot join a database transaction, so this layer does not claim atomicity
//! across the two. It claims *recoverability*: a write-ahead staging file, publish before index,
//! and a sweeper that converges. Every crash window has a defined winner.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod erase;
pub mod error;
pub mod pipeline;
pub mod reindex;
pub mod sweeper;

pub use error::{Error, Result};
pub use pipeline::Pipeline;
