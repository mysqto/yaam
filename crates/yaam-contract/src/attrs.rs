//! Declared attributes and their classification.
//!
//! `structural` attributes may sit in plaintext frontmatter and are queryable and retained.
//! `sensitive` attributes belong in the record body, which is sealed for erasable records. An
//! undeclared key is rejected — that is what keeps unerasable data out of copies which key
//! destruction cannot reach.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Whether an attribute may live in plaintext frontmatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Queryable, retained, plaintext.
    Structural,
    /// Must live in the sealed body.
    Sensitive,
}

/// A scalar attribute value. Deliberately flat — `attrs` is not a document store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    /// Text.
    Text(String),
    /// Whole number.
    Int(i64),
    /// Truth value.
    Bool(bool),
}

/// The declared attribute surface, keyed by action.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    #[expect(dead_code, reason = "read once the implementation lands")]
    actions: BTreeMap<String, BTreeMap<String, Class>>,
}

impl Schema {
    /// Loads from `attrs-schema.yaml` content.
    pub fn from_yaml(_yaml: &str) -> crate::Result<Self> {
        todo!("parse spec/attrs-schema.yaml")
    }

    /// Rejects undeclared keys, and `sensitive` keys presented as frontmatter.
    pub fn validate_frontmatter(
        &self,
        _action: &str,
        _attrs: &BTreeMap<String, Value>,
    ) -> crate::Result<()> {
        todo!("reject undeclared and sensitive-in-frontmatter")
    }

    /// Classification of one declared key.
    pub fn class_of(&self, _action: &str, _key: &str) -> crate::Result<Class> {
        todo!("look up class")
    }
}
