//! Records on disk: YAML frontmatter and a body that is either prose or a sealed block.
//!
//! Everything the index holds must be reproducible from these files. That is what lets the index be
//! deleted and rebuilt, and it is easy to break by adding a column with no on-disk source.

#![forbid(unsafe_code)]

pub mod document;
pub mod error;
pub mod frontmatter;
pub mod wikilink;

pub use document::{Body, Document};
pub use error::{Error, Result};
