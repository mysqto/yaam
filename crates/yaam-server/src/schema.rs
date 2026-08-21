//! JSON Schemas for the answers this service returns.
//!
//! The wire record and the write envelope are the contract crate's to publish; these two are not,
//! because a response is this service's shape rather than the record's. They go into the same
//! `spec/schemas/` bundle through the same generator, so a vendoring implementation reads one
//! dialect and one set of conventions.

use yaam_contract::schema::{Document, document};

use crate::routes::{BundleResponse, WriteResponse};

/// The schemas this crate publishes.
///
/// `result.v1.json` is the answer to a write: which identifier the record is addressable by, and
/// whether the write stored, was a replay, or was held pending subject resolution. A caller that
/// cannot tell those apart cannot tell a successful retry from a lost record.
#[must_use]
pub fn documents() -> Vec<Document> {
    vec![
        document::<WriteResponse>("result.v1.json"),
        document::<BundleResponse>("bundle.v1.json"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    #[test]
    fn both_answers_are_published() {
        let files: Vec<&str> = documents().iter().map(|d| d.file).collect();
        assert_eq!(files, ["result.v1.json", "bundle.v1.json"]);
    }

    /// A write's three outcomes are the whole point of the answer, so the schema has to name them
    /// rather than describe the field as a string.
    #[test]
    fn the_write_result_names_every_status() {
        let schema = &documents()[0].schema;
        let status = &schema["$defs"]["WriteStatus"]["oneOf"];
        let names: Vec<&str> = status
            .as_array()
            .expect("`WriteStatus` publishes as a closed set of constants")
            .iter()
            .map(|variant| variant["const"].as_str().expect("a constant"))
            .collect();
        assert_eq!(names, ["stored", "duplicate", "quarantined"]);
        // The identifier is published as the string it is on the wire, not as the struct holding it.
        assert_eq!(schema["$defs"]["RecordId"]["type"], "string");
    }

    #[test]
    fn a_bundle_says_when_it_is_incomplete() {
        let schema = &documents()[1].schema;
        for field in ["records", "degraded", "omitted", "token_estimate"] {
            assert!(
                schema["properties"][field].is_object(),
                "{field} missing from {schema:#}"
            );
        }
        assert_eq!(schema["properties"]["degraded"]["type"], "boolean");
        let id = schema["$id"]
            .as_str()
            .expect("a document says where it came from");
        assert!(id.ends_with("bundle.v1.json"), "{id}");
        assert!(matches!(schema.get("$schema"), Some(Json::String(_))));
    }
}
