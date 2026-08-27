//! JSON Schemas for the answers this service returns.
//!
//! The wire record and the write envelope are the contract crate's to publish; these are not,
//! because a response is this service's shape rather than the record's. They go into the same
//! `spec/schemas/` bundle through the same generator, so a vendoring implementation reads one
//! dialect and one set of conventions.

use yaam_contract::schema::{Document, document};

use crate::routes::{BundleResponse, CorrelationsResponse, RecordsResponse, WriteResponse};

/// The schemas this crate publishes.
///
/// `result.v1.json` is the answer to a write: which identifier the record is addressable by, and
/// whether the write stored, was a replay, or was held pending subject resolution. A caller that
/// cannot tell those apart cannot tell a successful retry from a lost record.
///
/// `records.v1.json`, `bundle.v1.json` and `correlations.v1.json` are the read answers. All three
/// are published because all three carry record structure rather than identifiers, and a shape a
/// caller parses with nothing describing it is a shape it has to guess at.
///
/// `correlations.v1.json` is the one that is not a list of records. It answers with *pairs*, because
/// which record happened near which is the answer a correlation gives, and a shape that flattened
/// the two sides into one list would leave the caller re-joining them by timestamp — which is the
/// work the endpoint exists to stop doing by hand.
#[must_use]
pub fn documents() -> Vec<Document> {
    vec![
        document::<WriteResponse>("result.v1.json"),
        document::<RecordsResponse>("records.v1.json"),
        document::<BundleResponse>("bundle.v1.json"),
        document::<CorrelationsResponse>("correlations.v1.json"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    #[test]
    fn every_answer_is_published() {
        let files: Vec<&str> = documents().iter().map(|d| d.file).collect();
        assert_eq!(
            files,
            [
                "result.v1.json",
                "records.v1.json",
                "bundle.v1.json",
                "correlations.v1.json"
            ]
        );
    }

    /// Every read answer carrying a list of records carries the shape of them with it.
    #[test]
    fn a_read_answer_publishes_the_structure_it_returns() {
        for document in documents()
            .into_iter()
            .filter(|d| d.file != "result.v1.json" && d.file != "correlations.v1.json")
        {
            let schema = &document.schema;
            assert_eq!(
                schema["properties"]["records"]["items"]["$ref"], "#/$defs/RecordStructure",
                "{}: {schema:#}",
                document.file
            );
            let structure = &schema["$defs"]["RecordStructure"];
            assert!(
                structure["properties"].get("summary").is_none(),
                "{}: a read answer must not describe a body: {structure:#}",
                document.file
            );
            assert!(
                structure["properties"]["action"].is_object(),
                "{structure:#}"
            );
        }
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
        let schema = &documents()[2].schema;
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

    /// A correlation publishes pairs, and each half of a pair is a record's structure.
    ///
    /// The published shape is what a vendoring implementation builds its parser against, so the pair
    /// being a pair has to be in it: a document describing `pairs` as a list of records would have
    /// every such client flatten the answer and lose which record happened near which.
    #[test]
    fn a_correlation_publishes_pairs_and_neither_half_carries_a_body() {
        let schema = &documents()[3].schema;
        assert_eq!(
            schema["properties"]["pairs"]["items"]["$ref"], "#/$defs/CorrelatedPair",
            "{schema:#}"
        );
        let pair = &schema["$defs"]["CorrelatedPair"];
        for side in ["left", "right"] {
            assert_eq!(
                pair["properties"][side]["$ref"], "#/$defs/RecordStructure",
                "{side} is not a record's structure: {pair:#}"
            );
        }
        let structure = &schema["$defs"]["RecordStructure"];
        assert!(
            structure["properties"].get("summary").is_none(),
            "a read answer must not describe a body: {structure:#}"
        );
        assert!(
            schema["properties"]["token_estimate"].is_object(),
            "{schema:#}"
        );
    }
}
