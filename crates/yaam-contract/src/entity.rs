//! Entity kinds and canonicalisation.
//!
//! Entities are the join keys across records. Kinds are configuration (`spec/entities.yaml`), not
//! hardcoded vocabulary, so a deployment defines the kinds its domain needs.

use serde::{Deserialize, Serialize};

/// A reference from a record to an entity, with the role the entity played.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRef {
    /// The entity kind, e.g. `order_ref`.
    pub kind: String,
    /// The canonical identifier.
    pub id: String,
    /// How the entity relates to the record.
    pub role: Role,
    /// Extraction confidence. Below `1.0` means inferred from text rather than a structured field.
    pub confidence: f32,
}

/// The part an entity plays in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The record is chiefly about this entity.
    Primary,
    /// Supporting context.
    Context,
    /// Mentioned, related but not central.
    Related,
}

/// Normalisation steps a kind applies before matching its pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Normalise {
    /// Strip surrounding whitespace.
    Trim,
    /// Lowercase the whole identifier.
    Lowercase,
    /// Uppercase the portion before the first separator.
    UppercasePrefix,
    /// Lowercase the path-like portion only.
    LowercasePath,
}

/// One configured entity kind.
#[derive(Debug, Clone)]
pub struct KindSpec {
    /// Kind name.
    pub name: String,
    /// Regex the canonical form must match.
    pub pattern: String,
    /// Normalisation applied before matching.
    pub normalise: Vec<Normalise>,
}

/// The loaded set of entity kinds.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    #[expect(dead_code, reason = "read once the implementation lands")]
    kinds: Vec<KindSpec>,
}

impl Registry {
    /// Loads a registry from `entities.yaml` content.
    pub fn from_yaml(_yaml: &str) -> crate::Result<Self> {
        todo!("parse spec/entities.yaml")
    }

    /// Normalises then validates an identifier, returning its canonical form.
    ///
    /// Rejects rather than repairs: an identifier that cannot be canonicalised is a caller bug, and
    /// silently accepting it would put an unjoinable row in the index.
    pub fn canonicalise(&self, _kind: &str, _id: &str) -> crate::Result<String> {
        todo!("normalise then match pattern")
    }

    /// Filename-safe encoding of an identifier.
    ///
    /// Injective: `~` escapes itself first, so distinct identifiers cannot collide on a path. `/`,
    /// `:`, `#` and `@` are all legal in identifiers and hostile in filenames.
    #[must_use]
    pub fn to_path_segment(_id: &str) -> String {
        todo!("~~ ~s ~c ~h ~a escaping, escape-the-escape first")
    }

    /// Inverse of [`Registry::to_path_segment`].
    pub fn from_path_segment(_segment: &str) -> crate::Result<String> {
        todo!("decode escapes")
    }
}
