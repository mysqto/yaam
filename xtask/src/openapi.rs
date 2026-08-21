//! The generated bundle against `spec/memory.v1.yaml`.
//!
//! The `OpenAPI` document describes the same wire by hand, is vendored by other implementations, and
//! has a contract test against the running router — but nothing held it against the *types*. So a
//! field renamed in Rust and in the router together would leave the document quietly describing a
//! service nobody runs, and the document is the half most people read.
//!
//! Only the shapes both sides name are compared. The document also describes responses this bundle
//! does not publish; those are `crates/yaam-server/tests/spec_contract.rs`'s business, which asks
//! the router itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use saphyr::{LoadableYamlNode, Yaml};
use serde_json::Value as Json;

use crate::{generated_objects, object_fields, openapi_path};

/// The document's `components.schemas`, as JSON so both sides read the same way.
///
/// # Panics
/// If the document is missing or is not one YAML mapping with a `components.schemas` section.
#[must_use]
pub fn documented_schemas() -> BTreeMap<String, Json> {
    let text =
        std::fs::read_to_string(openapi_path()).expect("the published document is in `spec`");
    let documents = Yaml::load_from_str(&text).expect("the published document is YAML");
    let root = documents.first().expect("one document");
    let schemas = root
        .as_mapping_get("components")
        .and_then(|c| c.as_mapping_get("schemas"))
        .and_then(Yaml::as_mapping)
        .expect("the document declares component schemas");
    schemas
        .iter()
        .filter_map(|(name, schema)| Some((name.as_str()?.to_owned(), to_json(schema))))
        .collect()
}

/// How the document and the generated bundle disagree, shape by shape.
///
/// An empty result is the two agreeing about every shape they both name.
#[must_use]
pub fn drift() -> Vec<String> {
    let documented = documented_schemas();
    let mut found = Vec::new();
    for (name, generated) in generated_objects() {
        let Some(documented) = documented.get(&name) else {
            continue;
        };
        compare(&name, &generated, documented, &mut found);
    }
    found.extend(missing_spine(&documented));
    found
}

/// Shapes the document must name, or the comparison above passes by having nothing to compare.
///
/// Every check in this module skips a shape the document does not mention. Without this, deleting
/// `ActionRecord` from the document would make the comparison silent rather than loud.
fn missing_spine(documented: &BTreeMap<String, Json>) -> Vec<String> {
    ["ActionRecord", "WriteRequest", "EntityRef", "SubjectRef"]
        .into_iter()
        .filter(|name| !documented.contains_key(*name))
        .map(|name| {
            format!("`{name}` is no longer in `spec/memory.v1.yaml`, so nothing compares it")
        })
        .collect()
}

/// Compares one shape, in whichever of the three forms it takes.
fn compare(name: &str, generated: &Json, documented: &Json, found: &mut Vec<String>) {
    if generated.get("properties").is_some() {
        let (mine, my_required) = object_fields(generated);
        let (theirs, their_required) = object_fields(documented);
        if mine != theirs {
            found.push(report(name, "fields", &mine, &theirs));
        }
        if my_required != their_required {
            found.push(report(
                name,
                "required fields",
                &my_required,
                &their_required,
            ));
        }
        return;
    }
    if let Some(mine) = closed_set(generated) {
        let theirs: BTreeSet<String> = documented
            .get("enum")
            .and_then(Json::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if mine != theirs {
            found.push(report(name, "values", &mine, &theirs));
        }
        return;
    }
    if let Some(mine) = generated.get("pattern").and_then(Json::as_str) {
        let theirs = documented.get("pattern").and_then(Json::as_str);
        if theirs != Some(mine) {
            found.push(format!(
                "`{name}`: the types accept `{mine}` and the document says {theirs:?}"
            ));
        }
    }
}

/// The values a generated closed enum admits, or `None` when the shape is not one.
fn closed_set(schema: &Json) -> Option<BTreeSet<String>> {
    let variants = schema.get("oneOf")?.as_array()?;
    let values: BTreeSet<String> = variants
        .iter()
        .filter_map(|variant| variant.get("const")?.as_str().map(str::to_owned))
        .collect();
    (values.len() == variants.len()).then_some(values)
}

/// One disagreement, saying which side has what.
fn report(
    name: &str,
    what: &str,
    generated: &BTreeSet<String>,
    documented: &BTreeSet<String>,
) -> String {
    let only_in_types: Vec<&str> = generated
        .difference(documented)
        .map(String::as_str)
        .collect();
    let only_in_document: Vec<&str> = documented
        .difference(generated)
        .map(String::as_str)
        .collect();
    let mut message = format!("`{name}`: the {what} differ —");
    if !only_in_types.is_empty() {
        let _ = write!(
            message,
            " {only_in_types:?} are in the types and not the document;"
        );
    }
    if !only_in_document.is_empty() {
        let _ = write!(
            message,
            " {only_in_document:?} are in the document and not the types;"
        );
    }
    message.push_str(" update `spec/memory.v1.yaml`");
    message
}

/// One YAML node as JSON.
///
/// Enough of the conversion for schema comparison: scalars, sequences and mappings with string keys.
/// A YAML feature the document does not use has no representation here, because a conversion nothing
/// exercises is a conversion nobody has checked.
fn to_json(node: &Yaml<'_>) -> Json {
    match node {
        Yaml::Sequence(items) => Json::Array(items.iter().map(to_json).collect()),
        Yaml::Mapping(fields) => Json::Object(
            fields
                .iter()
                .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), to_json(value))))
                .collect(),
        ),
        other => other
            .as_str()
            .map_or(Json::Null, |text| Json::String(text.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document and the types describe one wire, or one of them is describing fiction.
    #[test]
    fn the_document_and_the_generated_bundle_agree() {
        let found = drift();
        assert!(found.is_empty(), "{}", found.join("\n"));
    }

    #[test]
    fn the_document_names_the_shapes_the_bundle_publishes() {
        let documented = documented_schemas();
        for name in ["ActionRecord", "WriteRequest", "Outcome", "RecordId"] {
            assert!(documented.contains_key(name), "{:?}", documented.keys());
        }
    }

    #[test]
    fn a_field_only_one_side_has_is_named_with_the_side() {
        let mut found = Vec::new();
        compare(
            "ActionRecord",
            &serde_json::json!({ "properties": { "a": {}, "redaction": {} }, "required": ["a"] }),
            &serde_json::json!({ "properties": { "a": {} }, "required": ["a"] }),
            &mut found,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        let message = &found[0];
        assert!(message.contains("\"redaction\""), "{message}");
        assert!(
            message.contains("in the types and not the document"),
            "{message}"
        );
    }

    #[test]
    fn a_required_field_only_one_side_has_is_named() {
        let mut found = Vec::new();
        compare(
            "ActionRecord",
            &serde_json::json!({ "properties": { "a": {} } }),
            &serde_json::json!({ "properties": { "a": {} }, "required": ["a"] }),
            &mut found,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        let message = &found[0];
        assert!(message.contains("required fields"), "{message}");
        assert!(
            message.contains("in the document and not the types"),
            "{message}"
        );
    }

    #[test]
    fn an_enum_value_only_one_side_admits_is_named() {
        let mut found = Vec::new();
        compare(
            "Outcome",
            &serde_json::json!({ "oneOf": [{ "const": "success" }, { "const": "deferred" }] }),
            &serde_json::json!({ "enum": ["success"] }),
            &mut found,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("values differ"), "{}", found[0]);
        assert!(found[0].contains("\"deferred\""), "{}", found[0]);
    }

    #[test]
    fn a_pattern_only_one_side_enforces_is_named() {
        let mut found = Vec::new();
        compare(
            "RecordId",
            &serde_json::json!({ "type": "string", "pattern": "^a$" }),
            &serde_json::json!({ "type": "string", "pattern": "^b$" }),
            &mut found,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        let message = &found[0];
        assert!(
            message.contains("^a$") && message.contains("^b$"),
            "{message}"
        );
    }

    /// A `oneOf` of anything but constants is not a closed set, and must not be compared as one.
    /// The document losing a shape has to be louder than the document keeping it wrong.
    #[test]
    fn a_document_that_stopped_naming_a_shape_is_reported() {
        let found = missing_spine(&BTreeMap::new());
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(
            found[0].contains("`ActionRecord` is no longer"),
            "{found:?}"
        );
        assert!(missing_spine(&documented_schemas()).is_empty());
    }

    #[test]
    fn a_union_of_types_is_not_mistaken_for_a_closed_set() {
        assert!(
            closed_set(&serde_json::json!({
                "oneOf": [{ "type": "string" }, { "type": "integer" }]
            }))
            .is_none()
        );
        assert_eq!(
            closed_set(&serde_json::json!({ "oneOf": [{ "const": "a" }] })),
            Some(BTreeSet::from(["a".to_owned()]))
        );
        assert!(closed_set(&serde_json::json!({ "type": "string" })).is_none());
    }

    #[test]
    fn a_shape_with_none_of_the_three_forms_is_left_alone() {
        let mut found = Vec::new();
        compare(
            "AttrValue",
            &serde_json::json!({ "anyOf": [{ "type": "string" }] }),
            &serde_json::json!({ "oneOf": [{ "type": "string" }] }),
            &mut found,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn yaml_becomes_the_json_the_comparison_reads() {
        let documents = Yaml::load_from_str("a: [1, x]\nb: { c: d }\ne:\n").expect("YAML");
        let json = to_json(documents.first().expect("one document"));
        assert_eq!(json["a"][1], "x");
        assert_eq!(json["b"]["c"], "d");
        // A scalar with no string form is null rather than a panic, which is what an absent value is.
        assert_eq!(json["e"], Json::Null);
    }
}
