//! `[[kind:id]]` cross-references.
//!
//! One syntax everywhere, so the tree stays browsable in an ordinary editor and the indexer has a
//! single form to parse.

use yaam_contract::entity::EntityRef;

/// Extracts wikilinks from body text.
///
/// Returns `(kind, id)` pairs in order of appearance, duplicates included — a body that names an
/// entity three times says something the caller may want to keep.
///
/// Identifiers are returned exactly as written. Canonicalisation belongs to the entity registry,
/// which is the only thing that knows a kind's rules.
#[must_use]
pub fn extract(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find("[[") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("]]") else {
            // No terminator anywhere in what is left; nothing further can match.
            break;
        };
        let inner = &after[..close];
        if inner.contains(['[', ']', '\n']) {
            // A stray bracket run: step one character in rather than past the whole span, so a real
            // link that starts inside it is still found.
            rest = &rest[open + 1..];
            continue;
        }
        if let Some((kind, id)) = inner.split_once(':')
            && !kind.is_empty()
            && !id.is_empty()
        {
            out.push((kind.to_owned(), id.to_owned()));
        }
        rest = &after[close + 2..];
    }
    out
}

/// Renders an entity reference as a wikilink.
#[must_use]
pub fn render(entity: &EntityRef) -> String {
    format!("[[{}:{}]]", entity.kind, entity.id)
}

#[cfg(test)]
mod tests {
    use super::{extract, render};

    use yaam_contract::entity::{EntityRef, Role};

    /// Shorthand for an expected `(kind, id)` pair.
    fn link(kind: &str, id: &str) -> (String, String) {
        (kind.to_owned(), id.to_owned())
    }

    #[test]
    fn text_without_links_yields_nothing() {
        assert!(extract("").is_empty());
        assert!(extract("plain prose, no references at all").is_empty());
        assert!(extract("brackets [like this] are not links").is_empty());
    }

    #[test]
    fn adjacent_links_are_both_found() {
        assert_eq!(
            extract("[[ticket:ticket/9]][[deploy:deploy/17]]"),
            vec![link("ticket", "ticket/9"), link("deploy", "deploy/17")]
        );
    }

    #[test]
    fn links_are_found_amid_prose() {
        assert_eq!(
            extract("closed [[ticket:ticket/9]] after [[pull_request:pull_request/482]] merged"),
            vec![
                link("ticket", "ticket/9"),
                link("pull_request", "pull_request/482")
            ]
        );
    }

    #[test]
    fn malformed_links_are_skipped_without_panicking() {
        for text in [
            "[[",
            "[[[[",
            "]]",
            "[[unterminated:id",
            "[[nocolon]]",
            "[[:id]]",
            "[[kind:]]",
            "[[]]",
            "[[a\nb:c]]",
            "]]stray[[",
            "[[a]b]]",
        ] {
            assert!(extract(text).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_stray_bracket_run_does_not_hide_a_real_link() {
        assert_eq!(
            extract("[[[[order_ref:ord-1]]"),
            vec![link("order_ref", "ord-1")]
        );
        assert_eq!(
            extract("noise [[a]b]] then [[ticket:ticket/9]]"),
            vec![link("ticket", "ticket/9")]
        );
    }

    #[test]
    fn repeats_are_kept_in_order() {
        assert_eq!(
            extract("[[chat_user:u-1]] and [[order_ref:ord-2]] and [[chat_user:u-1]]"),
            vec![
                link("chat_user", "u-1"),
                link("order_ref", "ord-2"),
                link("chat_user", "u-1")
            ]
        );
    }

    #[test]
    fn a_colon_inside_an_id_is_kept() {
        assert_eq!(
            extract("[[chat_user:u:42]]"),
            vec![link("chat_user", "u:42")]
        );
    }

    #[test]
    fn a_rendered_reference_is_extractable() {
        let entity = EntityRef {
            kind: "pull_request".to_owned(),
            id: "pull_request/482".to_owned(),
            role: Role::Primary,
            confidence: 1.0,
        };
        let text = render(&entity);
        assert_eq!(text, "[[pull_request:pull_request/482]]");
        assert_eq!(extract(&text), vec![link(&entity.kind, &entity.id)]);
    }
}
