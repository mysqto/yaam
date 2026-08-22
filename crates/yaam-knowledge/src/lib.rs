//! Knowledge derived from the record tree.
//!
//! Memory is what happened; knowledge is what is true. This layer holds the second, and it holds it
//! the way the index holds its rows: as a **derived** artefact reproducible from the Markdown record
//! tree alone. Nothing is authoritative here. Deleting `knowledge/` is a recoverable operation, and
//! [`rebuild`] is what recovers it.
//!
//! # What it may read
//!
//! Derivation takes a [`RecordStructure`] — the record's frontmatter, the plaintext half. That type
//! has no field for prose, so "knowledge never extracts from a body" is a property of the input and
//! not a rule each fact has to remember. It holds for a plaintext body and a sealed one alike, and
//! it is why nothing here reaches for `summary`: a sealed record's summary is inside the ciphertext,
//! `yaam_md::Document::parse` reports it as empty, and a layer that read it anyway would be
//! extracting from whichever records happened to be unsealed.
//!
//! # What may contribute
//!
//! Far less than the tree holds, and deliberately: see [`Derivable`]. A record whose body is
//! erasable contributes **nothing**, because a note is an aggregate and an aggregate cannot be
//! un-aggregated from a backup. That is the whole erasure argument, and it is stated on the gate
//! rather than here so it sits beside the code that enforces it.
//!
//! # Layout under the memory root
//!
//! A different tree from memory's, with its own write path, as it must be — the two have opposite
//! update models. Memory appends; knowledge is overwritten wholesale.
//!
//! ```text
//! knowledge/entities/<kind>/<id>.md   one note per entity, rebuilt wholesale
//! knowledge/.index/sync-state.json    what the last rebuild read, and when
//! knowledge/.rebuild/                 the next tree, until it is swapped into place
//! ```
//!
//! [`RecordStructure`]: yaam_contract::RecordStructure

#![forbid(unsafe_code)]

pub mod build;
pub mod error;
pub mod fact;
pub mod note;
pub mod query;

#[cfg(test)]
mod testkit;

pub use build::{BuildReport, SyncState, rebuild, state};
pub use error::{Error, Result};
pub use fact::{Derivable, EntityKey, Fact, Ineligible, Observation};
pub use note::{Held, Note};
pub use query::{evidence, lookup, search};
