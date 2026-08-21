//! JSON Schemas for the wire shapes, generated from the types that define them.
//!
//! `spec/schemas/` is vendored by other implementations, so it is a description of these types that
//! leaves this repository and gets believed. Generated rather than written, for the reason
//! [`crate::lockstep`] exists at all: a schema kept by hand would be one more shape with nothing
//! holding it in line, and the two divergences this contract has already paid for were both a shape
//! drifting where only review was watching.

use schemars::{JsonSchema, SchemaGenerator};
use serde_json::Value as Json;

use crate::{ActionRecord, request::WriteRequest};

/// Where a vendored copy of these schemas came from, and what a `$ref` between them resolves
/// against. Taken from the manifest so the published identity cannot drift from the repository.
const BASE_URI: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/main/spec/schemas/");

/// One published schema: the file it lands in, and the document itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// File name, relative to `spec/schemas/`.
    pub file: &'static str,
    /// The schema.
    pub schema: Json,
}

impl Document {
    /// The bytes the file holds.
    ///
    /// Pretty-printed and newline-terminated so a regenerated schema shows up in review as the
    /// fields that changed rather than as one very long line.
    ///
    /// # Panics
    /// Never in practice: a generated schema is plain JSON, so serialising it cannot fail.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = serde_json::to_string_pretty(&self.schema)
            .expect("a generated schema is plain JSON, so it always serialises");
        text.push('\n');
        text
    }
}

/// Generates one schema document from a type.
///
/// Public so that crates outside this one publish their shapes through the same generator: two
/// generators would mean two dialects, and a vendored bundle in two dialects is not a bundle.
#[must_use]
pub fn document<T: JsonSchema>(file: &'static str) -> Document {
    let mut schema = SchemaGenerator::default().into_root_schema_for::<T>();
    schema.insert("$id".to_owned(), Json::String(format!("{BASE_URI}{file}")));
    let mut schema = schema.to_value();
    plain_prose(&mut schema);
    Document { file, schema }
}

/// Rewrites every `description` from rustdoc into prose.
///
/// Descriptions come from doc comments, which is what makes them impossible to forget — but they
/// arrive carrying `rustdoc` intra-doc links, and a reader of the published schema has no crate to
/// resolve `crate::request::WriteRequest` against. So the reference survives and the machinery does
/// not.
fn plain_prose(value: &mut Json) {
    match value {
        Json::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                match (key.as_str(), &mut *field) {
                    ("description", Json::String(text)) => *text = unlink(text),
                    _ => plain_prose(field),
                }
            }
        }
        Json::Array(items) => items.iter_mut().for_each(plain_prose),
        _ => {}
    }
}

/// Strips rustdoc link syntax from one description.
fn unlink(text: &str) -> String {
    let kept: Vec<&str> = text
        .lines()
        // A trailing link definition — ``[`Name`]: path`` — is pure machinery: it names no
        // reference the schema's reader can follow.
        .filter(|line| !is_link_definition(line))
        .collect();
    kept.join("\n")
        .replace("[`", "`")
        .replace("`]", "`")
        .trim_end()
        .to_owned()
}

/// Whether a line is a rustdoc link definition rather than prose.
fn is_link_definition(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("[`")
        && trimmed
            .split_once("`]: ")
            .is_some_and(|(_, target)| !target.trim().is_empty())
}

/// The schemas this crate publishes.
///
/// `envelope.v1.json` is the write envelope — a record plus the prose stored as its body — and is
/// what a caller actually sends. The record has its own file because it is also what a reader gets
/// back and what a Markdown file holds, so an implementation may need it alone.
#[must_use]
pub fn documents() -> Vec<Document> {
    vec![
        document::<ActionRecord>("action-record.v1.json"),
        document::<WriteRequest>("envelope.v1.json"),
    ]
}

/// The field names the wire record carries, read out of its generated schema.
///
/// Read from the schema rather than listed, because a list is the thing that drifted. This is the
/// wire side of [`crate::lockstep`].
///
/// # Panics
/// If the generated record schema has no `properties`, which would mean it had stopped being an
/// object and the lockstep rule no longer had three shapes to compare.
#[must_use]
pub fn wire_fields() -> std::collections::BTreeSet<String> {
    let schema = document::<ActionRecord>("action-record.v1.json").schema;
    schema
        .get("properties")
        .and_then(Json::as_object)
        .expect("the record schema describes an object with properties")
        .keys()
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated record schema, for tests that read into it.
    fn record_schema() -> Json {
        document::<ActionRecord>("action-record.v1.json").schema
    }

    #[test]
    fn every_document_carries_its_own_identity() {
        for doc in documents() {
            assert_eq!(
                doc.schema.get("$id").and_then(Json::as_str),
                Some(format!("{BASE_URI}{}", doc.file).as_str()),
                "{} must say where it came from",
                doc.file
            );
            assert!(
                doc.schema.get("$schema").is_some(),
                "{} must name its dialect",
                doc.file
            );
        }
    }

    #[test]
    fn rendering_is_pretty_and_newline_terminated() {
        let text = documents()[0].render();
        assert!(text.ends_with("}\n"), "{text}");
        assert!(text.contains("\n  \""), "expected indentation: {text}");
    }

    /// `deny_unknown_fields` is a promise to the caller — a mistyped field is refused rather than
    /// dropped — and a schema that omitted it would tell a vendoring implementation the opposite.
    #[test]
    fn closed_types_publish_as_closed() {
        let schema = record_schema();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Json::Bool(false)),
            "{schema:#}"
        );
        for name in ["EntityRef", "SubjectRef"] {
            let def = &schema["$defs"][name];
            assert_eq!(
                def.get("additionalProperties"),
                Some(&Json::Bool(false)),
                "{name} must publish as closed: {def:#}"
            );
        }
    }

    /// `attrs` is the one open map, and the reason has to travel with the schema: its keys are
    /// declared in `spec/attrs-schema.yaml`, which this type cannot see.
    #[test]
    fn attrs_stays_open_and_says_why() {
        let attrs = &record_schema()["properties"]["attrs"];
        assert_eq!(attrs["type"], "object", "{attrs:#}");
        assert!(
            attrs
                .get("additionalProperties")
                .is_some_and(Json::is_object),
            "attrs must admit declared keys: {attrs:#}"
        );
        let description = attrs["description"].as_str().expect("a description");
        assert!(
            description.contains("attrs-schema.yaml"),
            "the description must name where the keys are declared: {description}"
        );
    }

    /// The newtypes deserialise `try_from = "String"`, so a schema describing the struct behind
    /// them would publish an object where the wire carries a scalar.
    #[test]
    fn identifiers_publish_as_constrained_strings() {
        let defs = &record_schema()["$defs"];
        for (name, pattern) in [
            ("RecordId", crate::ids::RECORD_ID_PATTERN),
            ("SubjectHash", crate::ids::SUBJECT_HASH_PATTERN),
        ] {
            let def = &defs[name];
            assert_eq!(def["type"], "string", "{name}: {def:#}");
            assert_eq!(def["pattern"], pattern, "{name}: {def:#}");
        }
    }

    /// The values one closed enum admits, in the order the schema lists them.
    fn admitted(schema: &Json, name: &str) -> Vec<String> {
        schema["$defs"][name]["oneOf"]
            .as_array()
            .expect("a closed enum publishes as a `oneOf` of constants")
            .iter()
            .map(|variant| variant["const"].as_str().expect("a constant").to_owned())
            .collect()
    }

    /// An enum spelling is wire contract: the index compares a column against it, so a schema
    /// naming a fifth outcome or spelling one differently describes a service nobody is running.
    #[test]
    fn enum_spellings_are_the_ones_serde_emits() {
        let schema = record_schema();
        assert_eq!(
            admitted(&schema, "Outcome"),
            ["success", "failure", "partial", "declined"]
        );
        assert_eq!(
            admitted(&schema, "DataClass"),
            ["internal", "subject_derived"]
        );
        assert_eq!(
            admitted(&schema, "Visibility"),
            ["owner", "team", "org", "operator"]
        );
        assert_eq!(admitted(&schema, "SubjectRole"), ["principal", "party"]);
        assert_eq!(
            admitted(&schema, "EntityRole"),
            ["primary", "context", "related"]
        );
    }

    /// Two kinds of role in one bundle need two names, or a vendoring implementation has to guess.
    #[test]
    fn the_two_roles_are_named_apart() {
        let defs = &record_schema()["$defs"];
        assert!(defs.get("Role").is_none(), "{defs:#}");
        assert!(defs.get("Role2").is_none(), "{defs:#}");
    }

    #[test]
    fn descriptions_carry_no_rustdoc_machinery() {
        let rendered = documents().iter().map(Document::render).collect::<String>();
        for machinery in ["[`", "`]", "crate::"] {
            assert!(
                !rendered.contains(machinery),
                "`{machinery}` resolves against nothing outside this crate"
            );
        }
    }

    #[test]
    fn unlinking_keeps_the_reference_and_drops_the_target() {
        assert_eq!(
            unlink("See [`ActionRecord`] first.\n\n[`ActionRecord`]: crate::ActionRecord"),
            "See `ActionRecord` first."
        );
        // A bare paragraph that merely opens with a link is prose, not a definition.
        assert_eq!(unlink("[`Thing`] is a thing."), "`Thing` is a thing.");
        assert_eq!(unlink("plain"), "plain");
    }

    /// The bounds `ActionRecord::validate` enforces, published so a caller can fail before sending.
    #[test]
    fn the_ranges_validate_checks_are_published() {
        let confidence = &record_schema()["$defs"]["EntityRef"]["properties"]["confidence"];
        assert_eq!(confidence["minimum"], 0.0, "{confidence:#}");
        assert_eq!(confidence["maximum"], 1.0, "{confidence:#}");
        let action = &record_schema()["properties"]["action"];
        assert_eq!(action["minLength"], 1, "{action:#}");
    }

    #[test]
    fn doc_comments_reach_the_published_schema() {
        // Otherwise the vendorable artefact is a shape with no reasons attached, and every question
        // it does not answer comes back as a support request.
        let schema = record_schema();
        assert!(
            schema["description"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "{schema:#}"
        );
        for field in ["record_id", "backfilled", "summary", "redaction_policy"] {
            let property = &schema["properties"][field];
            assert!(
                property["description"]
                    .as_str()
                    .is_some_and(|d| !d.is_empty()),
                "{field} must carry its reason: {property:#}"
            );
        }
    }

    #[test]
    fn the_envelope_wraps_a_record() {
        let envelope = document::<WriteRequest>("envelope.v1.json").schema;
        assert_eq!(
            envelope.get("additionalProperties"),
            Some(&Json::Bool(false))
        );
        assert_eq!(envelope["required"], serde_json::json!(["record"]));
        assert!(
            envelope["$defs"].get("ActionRecord").is_some(),
            "the envelope must carry the record it wraps: {envelope:#}"
        );
    }

    #[test]
    fn wire_fields_are_the_records_own() {
        let fields = wire_fields();
        assert!(fields.contains("backfilled"), "{fields:?}");
        assert!(fields.contains("summary"), "{fields:?}");
        // A `$defs` name is not a field, and neither is a schema keyword.
        assert!(!fields.contains("EntityRef"), "{fields:?}");
        assert!(!fields.contains("$schema"), "{fields:?}");
    }
}
