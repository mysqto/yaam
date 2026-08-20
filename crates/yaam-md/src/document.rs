//! A whole record file.

use yaam_contract::ActionRecord;
use yaam_crypto::SealedBody;

/// A record's body.
#[derive(Debug, Clone)]
pub enum Body {
    /// Readable prose, for records that are not subject-derived.
    Plain(String),
    /// A sealed block. Unreadable without the subject keys.
    Sealed(SealedBody),
}

/// Frontmatter plus body: the unit written to and read from disk.
#[derive(Debug, Clone)]
pub struct Document {
    /// The record.
    pub record: ActionRecord,
    /// Its body.
    pub body: Body,
}

impl Document {
    /// Renders the complete file.
    #[must_use]
    pub fn render(&self) -> String {
        todo!("--- frontmatter --- then body")
    }

    /// Parses a complete file.
    pub fn parse(_text: &str) -> crate::Result<Self> {
        todo!("split frontmatter from body, detect sealed fence")
    }

    /// Text that full-text search should index.
    ///
    /// Empty for a sealed body: search must never become a way around sealing.
    #[must_use]
    pub fn searchable_text(&self) -> &str {
        match &self.body {
            Body::Plain(s) => s,
            Body::Sealed(_) => "",
        }
    }
}
