//! A whole record file.
//!
//! The shape is `---`, frontmatter, `---`, then the body. The body is either prose or a fenced
//! sealed block; nothing else distinguishes the two on disk, which is why the fence is checked at
//! the start of the body rather than anywhere in it.

use yaam_contract::ActionRecord;
use yaam_crypto::SealedBody;

use crate::{Error, frontmatter};

/// Opening fence of a sealed block.
const SEALED_FENCE: &str = "```sealed";

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
    ///
    /// The body is taken from [`Document::body`], not from `record.summary`. For a plaintext record
    /// the two hold the same prose — [`Document::parse`] restores both from the body — and for a
    /// sealed record the summary is inside the ciphertext and nowhere else.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("---\n");
        out.push_str(&frontmatter::render(&self.record));
        out.push_str("---\n\n");
        match &self.body {
            Body::Plain(text) => out.push_str(text),
            Body::Sealed(sealed) => out.push_str(&yaam_crypto::block::render(sealed)),
        }
        // One trailing newline, always. `parse` strips exactly one, so a body that ends in a
        // newline survives the round trip and a file still ends the way text files do.
        out.push('\n');
        out
    }

    /// Parses a complete file.
    ///
    /// A sealed record comes back with an empty `summary`: the prose is in the ciphertext, so the
    /// only honest thing to report from the file alone is that there is none.
    pub fn parse(text: &str) -> crate::Result<Self> {
        let (yaml, body) = split(text)?;
        let mut record = frontmatter::parse(yaml)?;
        let body = if is_sealed(body) {
            Body::Sealed(yaam_crypto::block::parse(body)?)
        } else {
            body.clone_into(&mut record.summary);
            Body::Plain(body.to_owned())
        };
        Ok(Self { record, body })
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

/// Splits a file into its frontmatter YAML and its body text.
///
/// The terminator is the *first* `---` line after the opening fence. A body may contain `---` of
/// its own and is unaffected, because frontmatter is emitted with every string on one line and so
/// can never contain one.
fn split(text: &str) -> crate::Result<(&str, &str)> {
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
        .ok_or(Error::MissingFrontmatter)?;

    let mut offset = 0;
    loop {
        let line_end = rest[offset..].find('\n').map(|i| offset + i);
        let line = line_end.map_or(&rest[offset..], |end| &rest[offset..end]);
        if line.trim_end() == "---" {
            let body = line_end.map_or("", |end| &rest[end + 1..]);
            return Ok((&rest[..offset], trim_separators(body)));
        }
        match line_end {
            Some(end) => offset = end + 1,
            None => {
                return Err(Error::MalformedFrontmatter(
                    "unterminated frontmatter fence".to_owned(),
                ));
            }
        }
    }
}

/// Removes the blank line `render` puts after the closing fence and the newline it puts at the end.
///
/// Exactly one of each, so the body's own leading and trailing newlines are preserved.
fn trim_separators(body: &str) -> &str {
    let body = body
        .strip_prefix("\r\n")
        .or_else(|| body.strip_prefix('\n'))
        .unwrap_or(body);
    body.strip_suffix("\r\n")
        .or_else(|| body.strip_suffix('\n'))
        .unwrap_or(body)
}

/// Whether a body holds a sealed block rather than prose.
///
/// Only the start of the body counts. Prose that merely mentions the fence stays prose, which keeps
/// a mention from making a readable record look unreadable.
fn is_sealed(body: &str) -> bool {
    body.trim_start().starts_with(SEALED_FENCE)
}

#[cfg(test)]
mod tests {
    use yaam_crypto::{Epoch, Nonce, SealedBody, WrappedShare};

    use super::{Body, Document, Error, is_sealed};
    use crate::frontmatter::fixture::{assert_same_record, record, subject_derived, subject_hash};
    use yaam_contract::record::Role as SubjectRole;

    /// A plaintext document whose body is its summary, which is the shape the pipeline writes.
    fn plain(summary: &str) -> Document {
        let mut record = record();
        record.summary = summary.to_owned();
        Document {
            record,
            body: Body::Plain(summary.to_owned()),
        }
    }

    #[test]
    fn a_plaintext_document_round_trips() {
        let document = plain("Rolled out [[deploy:deploy/2026-08-20/17]] to two of three shards.");
        let parsed = Document::parse(&document.render()).expect("renders and parses");

        assert_same_record(&document.record, &parsed.record);
        assert_eq!(document.record, parsed.record);
        assert!(matches!(parsed.body, Body::Plain(_)));
        assert_eq!(parsed.searchable_text(), document.searchable_text());
    }

    #[test]
    fn searchable_text_of_a_plaintext_body_is_the_body() {
        let body = "Deploy declined by the upstream gate.";
        let parsed = Document::parse(&plain(body).render()).expect("parses");
        assert_eq!(parsed.searchable_text(), body);
        assert_eq!(parsed.record.summary, body);
    }

    #[test]
    fn render_is_byte_stable() {
        let document = plain("A stable body.");
        let first = document.render();
        assert_eq!(first, document.render());
        assert_eq!(
            Document::parse(&first).expect("parses").render(),
            first,
            "re-rendering a parsed document must reproduce the file"
        );
    }

    #[test]
    fn a_fence_line_in_the_body_does_not_split_the_frontmatter() {
        let body = "before\n---\nafter\n---";
        let parsed = Document::parse(&plain(body).render()).expect("parses");
        assert_eq!(parsed.searchable_text(), body);
        assert_eq!(parsed.record.action, "deploy");
    }

    #[test]
    fn body_whitespace_survives() {
        for body in ["", "\n", "x", "x\n", "\nx", "x\n\n", "\n\nx\n\n", "---\nx"] {
            let parsed = Document::parse(&plain(body).render()).expect("parses");
            assert_eq!(parsed.searchable_text(), body, "body {body:?}");
        }
    }

    #[test]
    fn a_file_written_with_crlf_parses() {
        let text = plain("body text").render().replace('\n', "\r\n");
        let parsed = Document::parse(&text).expect("parses");
        assert_eq!(parsed.searchable_text(), "body text");
        assert_eq!(parsed.record.action, "deploy");
    }

    #[test]
    fn missing_frontmatter_is_reported() {
        for text in ["", "no frontmatter here\n", "--- \nx\n---\n", "  ---\nx\n"] {
            let error = Document::parse(text).expect_err("rejected");
            assert!(matches!(error, Error::MissingFrontmatter), "{text:?}");
        }
    }

    #[test]
    fn an_unterminated_fence_is_reported() {
        for text in ["---\naction: deploy\n", "---\naction: deploy", "---\n"] {
            let error = Document::parse(text).expect_err("rejected");
            assert!(
                matches!(&error, Error::MalformedFrontmatter(m) if m.contains("unterminated")),
                "{text:?}: {error}"
            );
        }
    }

    #[test]
    fn malformed_frontmatter_is_reported_not_panicked() {
        let error = Document::parse("---\naction: [unclosed\n---\nbody\n").expect_err("rejected");
        assert!(matches!(error, Error::MalformedFrontmatter(_)), "{error}");
    }

    #[test]
    fn a_sealed_fence_is_recognised_only_at_the_start_of_a_body() {
        assert!(is_sealed("```sealed\nv1\n```"));
        assert!(is_sealed("\n```sealed"));
        assert!(!is_sealed(""));
        assert!(!is_sealed("prose"));
        assert!(!is_sealed("```rust\nlet x = 1;\n```"));
        assert!(!is_sealed("prose that mentions ```sealed blocks"));
    }

    /// A sealed body with one share per subject of [`subject_derived`] — so, one.
    ///
    /// Built from stored bytes rather than by sealing: this crate is testing serialisation, and
    /// wiring a key store in would make the assertion depend on the sealing path too.
    ///
    /// One share rather than two, because a record names at most one subject and a fixture pairing
    /// a one-subject record with a two-share body would be a document no store can hold. The block
    /// format still encodes a share list, and `yaam_crypto::block` round-trips two of them; that is
    /// the crate that owns the format, and the right place for it.
    fn sealed_body() -> SealedBody {
        SealedBody {
            nonce: Nonce::from_stored([9; 12]),
            epoch: Epoch::from_stored("2026-Q3").expect("a stored label"),
            shares: vec![WrappedShare {
                subject: subject_hash('a'),
                bytes: vec![0xa1; 40],
            }],
            ciphertext: vec![0xcd; 48],
        }
    }

    #[test]
    fn a_sealed_document_round_trips_and_is_not_searchable() {
        let document = Document {
            record: subject_derived(SubjectRole::Principal),
            body: Body::Sealed(sealed_body()),
        };
        let text = document.render();
        let parsed = Document::parse(&text).expect("renders and parses");

        assert_same_record(&document.record, &parsed.record);
        assert_eq!(parsed.render(), text, "a re-render must reproduce the file");

        let Body::Sealed(parsed_body) = &parsed.body else {
            panic!("a sealed body must not come back as prose");
        };
        let original = sealed_body();
        assert_eq!(parsed_body.nonce, original.nonce);
        assert_eq!(parsed_body.epoch, original.epoch);
        assert_eq!(parsed_body.shares, original.shares);
        assert_eq!(parsed_body.ciphertext, original.ciphertext);

        // The point of the whole scheme: nothing here is indexable, and the prose is not on disk
        // outside the ciphertext.
        assert_eq!(parsed.searchable_text(), "");
        assert_eq!(parsed.record.summary, "");
        assert!(!text.contains("summary"), "{text}");
    }

    #[test]
    fn a_sealed_body_is_recognised_after_a_reindex_of_the_same_file() {
        // Byte stability matters more here than elsewhere: the content checksum decides whether a
        // reindex thinks the file changed, and a sealed file must not look modified every pass.
        let document = Document {
            record: subject_derived(SubjectRole::Principal),
            body: Body::Sealed(sealed_body()),
        };
        assert_eq!(document.render(), document.render());
        let once = Document::parse(&document.render()).expect("parses");
        assert_eq!(
            Document::parse(&once.render()).expect("parses").render(),
            once.render()
        );
    }
}
