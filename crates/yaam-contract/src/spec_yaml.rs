//! Shared plumbing for the two spec files this crate loads.
//!
//! Private on purpose: `spec/` is configuration this crate *reads*, so its YAML shape must not leak
//! into the wire contract the rest of the workspace compiles against.

use saphyr::{LoadableYamlNode, Mapping, Yaml};

use crate::Error;

/// The only spec version this build implements.
const SUPPORTED_VERSION: i64 = 1;

/// Parses exactly one YAML document.
///
/// A stream of several documents is rejected rather than having the first silently win: a spec file
/// that grew a stray `---` would otherwise load with half its content missing.
pub fn single_document(yaml: &str) -> crate::Result<Yaml<'_>> {
    let mut docs = Yaml::load_from_str(yaml)
        .map_err(|e| Error::Invalid(format!("spec is not valid YAML: {e}")))?;
    if docs.len() == 1 {
        Ok(docs.remove(0))
    } else {
        Err(Error::Invalid(format!(
            "spec must hold exactly one YAML document, found {}",
            docs.len()
        )))
    }
}

/// Rejects a spec written for a version this build does not implement.
///
/// An absent `version` is accepted so that callers can load a fragment. A *stated* mismatch is
/// fatal, because reading a later spec under this build's rules is precisely the silent misread
/// this check exists to prevent.
pub fn check_version(doc: &Yaml<'_>) -> crate::Result<()> {
    let Some(node) = doc.as_mapping_get("version") else {
        return Ok(());
    };
    match node.as_integer() {
        Some(SUPPORTED_VERSION) => Ok(()),
        Some(other) => Err(Error::Invalid(format!(
            "spec version {other} is not supported, this build implements {SUPPORTED_VERSION}"
        ))),
        None => Err(Error::Invalid(
            "spec `version` must be an integer".to_owned(),
        )),
    }
}

/// Reads a top-level field that must be present and must be a mapping.
pub fn required_mapping<'a, 'input>(
    doc: &'a Yaml<'input>,
    field: &str,
) -> crate::Result<&'a Mapping<'input>> {
    doc.as_mapping_get(field)
        .ok_or_else(|| Error::Invalid(format!("spec has no `{field}` section")))?
        .as_mapping()
        .ok_or_else(|| Error::Invalid(format!("spec `{field}` must be a mapping")))
}

/// Reads a mapping key as a name. A non-string key is a malformed spec, not a name.
pub fn key_name<'a>(key: &'a Yaml<'_>, what: &str) -> crate::Result<&'a str> {
    key.as_str()
        .ok_or_else(|| Error::Invalid(format!("{what} names must be strings")))
}

/// Reads a string field of a mapping node, failing with a message naming its owner.
pub fn required_str<'a>(node: &'a Yaml<'_>, field: &str, owner: &str) -> crate::Result<&'a str> {
    node.as_mapping_get(field)
        .and_then(Yaml::as_str)
        .ok_or_else(|| Error::Invalid(format!("`{owner}` has no string `{field}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_document_rejects_a_stream() {
        assert!(single_document("a: 1\n---\nb: 2\n").is_err());
    }

    #[test]
    fn single_document_rejects_empty_input() {
        assert!(single_document("").is_err());
    }

    #[test]
    fn single_document_rejects_malformed_yaml() {
        let err = single_document("a: [1, 2\n").expect_err("unterminated flow sequence");
        assert!(err.to_string().contains("not valid YAML"), "{err}");
    }

    #[test]
    fn version_is_optional_but_checked_when_present() {
        assert!(check_version(&single_document("version: 1\n").unwrap()).is_ok());
        assert!(check_version(&single_document("other: 1\n").unwrap()).is_ok());
        assert!(check_version(&single_document("version: 2\n").unwrap()).is_err());
        assert!(check_version(&single_document("version: one\n").unwrap()).is_err());
    }

    #[test]
    fn required_mapping_reports_which_field_is_wrong() {
        let doc = single_document("kinds: []\n").unwrap();
        assert!(
            required_mapping(&doc, "kinds")
                .expect_err("a sequence is not a mapping")
                .to_string()
                .contains("must be a mapping")
        );
        assert!(
            required_mapping(&doc, "actions")
                .expect_err("absent")
                .to_string()
                .contains("no `actions` section")
        );
    }

    #[test]
    fn key_name_rejects_a_non_string_key() {
        let doc = single_document("kinds:\n  1: {}\n").unwrap();
        let (key, _) = required_mapping(&doc, "kinds")
            .unwrap()
            .iter()
            .next()
            .unwrap();
        assert!(key_name(key, "entity kind").is_err());
    }

    #[test]
    fn required_str_rejects_absent_and_non_string() {
        let doc = single_document("a: 1\nb: {}\n").unwrap();
        assert!(required_str(&doc, "a", "owner").is_err());
        assert!(required_str(&doc, "missing", "owner").is_err());
        assert_eq!(
            required_str(&single_document("a: x\n").unwrap(), "a", "owner").unwrap(),
            "x"
        );
    }
}
