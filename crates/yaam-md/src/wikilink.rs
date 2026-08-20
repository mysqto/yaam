//! `[[kind:id]]` cross-references.
//!
//! One syntax everywhere, so the tree stays browsable in an ordinary editor and the indexer has a
//! single form to parse.

use yaam_contract::entity::EntityRef;

/// Extracts wikilinks from body text.
#[must_use]
pub fn extract(_body: &str) -> Vec<(String, String)> {
    todo!("scan for [[kind:id]]")
}

/// Renders an entity reference as a wikilink.
#[must_use]
pub fn render(entity: &EntityRef) -> String {
    format!("[[{}:{}]]", entity.kind, entity.id)
}
