//! The parts that have to be correct under failure.
//!
//! A filesystem rename cannot join a database transaction, so this layer does not claim atomicity
//! across the two. It claims *recoverability*: a write-ahead staging file, publish before index,
//! and a sweeper that converges. Every crash window has a defined winner.
//!
//! # Layout under the memory root
//!
//! Everything a deployment needs sits under the one path [`Pipeline::new`] is given, so a store is
//! moved by moving a directory:
//!
//! ```text
//! spec/                        configuration: entity kinds, attribute schema, redaction policy
//! records/YYYY/MM/DD/<id>.md   the authoritative record tree
//! records/owner/<agent>/...    owner-visible records, one private subtree per owner
//! entities/<kind>/<id>/        entity timelines, materialised by fan-out
//! audit/subjects/<id>.md       which records name which subjects
//! cold/*.jsonl                 manifests of archived records, still indexable
//! keystore/                    per-subject keys and their tombstones
//! index.sqlite                 the derived index; deleting it is recoverable
//! tombstones.jsonl             append-only erasure log, replayed on every rebuild
//! .staging/<id>.md             write-ahead copies, before publish
//! .quarantine/<id>.md          sealed copies of records whose subjects will not resolve
//! .dead-letter/                fan-out work set aside after repeated failure
//! ```
//!
//! The visible directories are the store; the dot-prefixed ones are machinery. Nothing outside
//! `records/`, `cold/` and `tombstones.jsonl` is authoritative — the rest is either configuration
//! or derived, which is what makes a rebuild routine rather than a recovery.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod erase;
pub mod error;
pub mod health;
pub mod paths;
pub mod pipeline;
pub mod reindex;
pub mod resolve;
pub mod sweeper;

mod fsutil;
mod layout;
mod policy;

#[cfg(test)]
mod testkit;

pub use error::{Error, Result};
pub use paths::Paths;
pub use pipeline::Pipeline;
