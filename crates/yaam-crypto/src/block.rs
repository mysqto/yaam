//! Serialisation of the sealed block, as it appears in a Markdown body.
//!
//! The format is specified rather than incidental so that a second implementation, or `reindex`,
//! agrees byte for byte. Associated data is deliberately *not* stored.

use crate::SealedBody;

/// Current block format version.
pub const FORMAT_VERSION: &str = "v1";

/// Renders a sealed body as the fenced block stored in a record file.
#[must_use]
pub fn render(_body: &SealedBody) -> String {
    todo!("v1 / alg / nonce / epoch / shares / ct")
}

/// Parses a fenced sealed block.
pub fn parse(_text: &str) -> crate::Result<SealedBody> {
    todo!("parse and reject unknown versions")
}
