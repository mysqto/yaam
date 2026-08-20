//! Frontmatter is the machine-readable half of a record, and is always plaintext.
//!
//! It carries structure only — identifiers, timestamps, action, outcome, declared structural
//! attributes, entity and subject references. It never carries prose or sensitive attributes,
//! because it survives in copies that key destruction cannot reach.
//!
//! Rendering goes through one ordered projection ([`project`]), and both the YAML and the canonical
//! JSON are emitted from it. That is deliberate: the index addresses fields by their frontmatter
//! path, so two independent serialisers would let the two drift and make SQL queries return nothing
//! rather than fail.

use std::fmt::Write as _;

use saphyr::{LoadableYamlNode, Scalar as YamlScalar, Yaml};
use serde_json::{Map as JsonMap, Value as Json};
use yaam_contract::{
    ActionRecord, DataClass, Outcome, Visibility,
    attrs::Value as AttrValue,
    entity::{EntityRef, Role as EntityRole},
    record::{Role as SubjectRole, SubjectRef},
};

use crate::Error;

/// The frontmatter keys, in render order.
///
/// Order follows the declaration order of `ActionRecord`, so re-rendering an unchanged record is
/// byte-identical and a new field has exactly one obvious place. `summary` is absent by design: it
/// is prose, so it lives in the body.
const KEYS: [&str; 19] = [
    "record_id",
    "schema_ver",
    "at",
    "received_at",
    "backfilled",
    "agent",
    "agent_ver",
    "correlation_id",
    "action",
    "outcome",
    "attrs",
    "entities",
    "subjects",
    "visibility",
    "team",
    "data_class",
    "redaction_policy",
    "fields_masked",
    "tags",
];

/// Plain scalars that some YAML reader somewhere resolves to a boolean or null.
///
/// Matched case-insensitively and always quoted, so a string stays a string across implementations
/// rather than only across this one.
const RESERVED: [&str; 10] = [
    "null", "~", "true", "false", "yes", "no", "on", "off", "y", "n",
];

/// A frontmatter leaf value.
#[derive(Debug, Clone, PartialEq)]
enum Scalar {
    /// An absent optional field. Rendered rather than omitted, so the key set never varies.
    Null,
    /// Truth value.
    Bool(bool),
    /// Whole number.
    Int(i64),
    /// Extraction confidence. Must be finite to reach canonical JSON.
    Float(f32),
    /// Text.
    Str(String),
}

/// A frontmatter value.
///
/// The four shapes are the only ones a record needs. Keeping the type that narrow means the
/// emitters have no nesting case that never occurs, and therefore none that is never exercised.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    /// A single scalar.
    Leaf(Scalar),
    /// A flat mapping of scalars, as `attrs` is.
    Map(Vec<(String, Scalar)>),
    /// A list of scalars, as `tags` is.
    List(Vec<Scalar>),
    /// A list of flat mappings, as `entities` and `subjects` are.
    Maps(Vec<Vec<(String, Scalar)>>),
}

/// Renders a record's frontmatter, without fences.
#[must_use]
pub fn render(record: &ActionRecord) -> String {
    emit(&project(record))
}

/// Parses frontmatter into a record, leaving the body to the caller.
///
/// `summary` comes back empty: it is prose and therefore not in frontmatter. [`crate::Document`]
/// fills it from the body, which is where a lossless round-trip lives.
pub fn parse(yaml: &str) -> crate::Result<ActionRecord> {
    let docs = Yaml::load_from_str(yaml).map_err(|e| Error::MalformedFrontmatter(e.to_string()))?;
    let Some(Yaml::Mapping(map)) = docs.first() else {
        return Err(Error::MalformedFrontmatter(
            "expected a mapping at the top level".to_owned(),
        ));
    };

    let mut fields = JsonMap::new();
    for (key, value) in map {
        let key = key_str(key)?;
        // An unrecognised key is rejected rather than dropped: silently ignoring it would put a
        // value on disk that no reindex can ever recover.
        if !KEYS.contains(&key) {
            return Err(Error::MalformedFrontmatter(format!(
                "unexpected frontmatter key `{key}`"
            )));
        }
        fields.insert(key.to_owned(), to_json(value)?);
    }
    fields.insert("summary".to_owned(), Json::String(String::new()));

    serde_json::from_value(Json::Object(fields))
        .map_err(|e| Error::MalformedFrontmatter(e.to_string()))
}

/// Canonical JSON projection, as stored in the index for structured queries.
///
/// Keys are the frontmatter keys, at every level, because SQL addresses fields by those paths. Key
/// order is lexicographic and so stable; the frontmatter's declaration order is a readability
/// choice that JSON does not need.
pub fn to_canonical_json(record: &ActionRecord) -> crate::Result<String> {
    let mut fields = JsonMap::new();
    for (key, value) in project(record) {
        fields.insert(key.to_owned(), json_value(&value)?);
    }
    Ok(Json::Object(fields).to_string())
}

/// The single ordered projection of a record, shared by both serialisers.
fn project(record: &ActionRecord) -> Vec<(&'static str, Value)> {
    vec![
        ("record_id", text(record.record_id.as_str())),
        (
            "schema_ver",
            Value::Leaf(Scalar::Int(i64::from(record.schema_ver.0))),
        ),
        ("at", text(&record.at)),
        ("received_at", text(&record.received_at)),
        ("backfilled", Value::Leaf(Scalar::Bool(record.backfilled))),
        ("agent", text(&record.agent)),
        ("agent_ver", optional_text(record.agent_ver.as_deref())),
        (
            "correlation_id",
            optional_text(record.correlation_id.as_deref()),
        ),
        ("action", text(&record.action)),
        ("outcome", text(outcome_name(record.outcome))),
        (
            "attrs",
            Value::Map(
                record
                    .attrs
                    .iter()
                    .map(|(k, v)| (k.clone(), attr_scalar(v)))
                    .collect(),
            ),
        ),
        (
            "entities",
            Value::Maps(record.entities.iter().map(entity_fields).collect()),
        ),
        (
            "subjects",
            Value::Maps(record.subjects.iter().map(subject_fields).collect()),
        ),
        ("visibility", text(visibility_name(record.visibility))),
        ("team", optional_text(record.team.as_deref())),
        ("data_class", text(data_class_name(record.data_class))),
        ("redaction_policy", text(&record.redaction_policy)),
        ("fields_masked", string_list(&record.fields_masked)),
        ("tags", string_list(&record.tags)),
    ]
}

/// Wraps a string as a leaf value.
fn text(value: &str) -> Value {
    Value::Leaf(Scalar::Str(value.to_owned()))
}

/// Wraps an optional string, rendering absence as an explicit null.
fn optional_text(value: Option<&str>) -> Value {
    match value {
        Some(v) => text(v),
        None => Value::Leaf(Scalar::Null),
    }
}

/// Wraps a list of strings.
fn string_list(values: &[String]) -> Value {
    Value::List(values.iter().map(|v| Scalar::Str(v.clone())).collect())
}

/// One entity reference, keyed as `EntityRef` serialises.
fn entity_fields(entity: &EntityRef) -> Vec<(String, Scalar)> {
    vec![
        ("kind".to_owned(), Scalar::Str(entity.kind.clone())),
        ("id".to_owned(), Scalar::Str(entity.id.clone())),
        (
            "role".to_owned(),
            Scalar::Str(entity_role_name(entity.role).to_owned()),
        ),
        ("confidence".to_owned(), Scalar::Float(entity.confidence)),
    ]
}

/// One subject reference, keyed as `SubjectRef` serialises.
fn subject_fields(subject: &SubjectRef) -> Vec<(String, Scalar)> {
    vec![
        (
            "hash".to_owned(),
            Scalar::Str(subject.hash.as_str().to_owned()),
        ),
        (
            "role".to_owned(),
            Scalar::Str(subject_role_name(subject.role).to_owned()),
        ),
        (
            "canon_ver".to_owned(),
            Scalar::Int(i64::from(subject.canon_ver.0)),
        ),
    ]
}

/// One declared attribute value.
fn attr_scalar(value: &AttrValue) -> Scalar {
    match value {
        AttrValue::Text(v) => Scalar::Str(v.clone()),
        AttrValue::Int(v) => Scalar::Int(*v),
        AttrValue::Bool(v) => Scalar::Bool(*v),
    }
}

/// Wire name of an outcome. Spelled out rather than derived, so a rename in the contract fails the
/// round-trip test instead of quietly rewriting every file.
fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Partial => "partial",
        Outcome::Declined => "declined",
    }
}

/// Wire name of a visibility scope.
fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Owner => "owner",
        Visibility::Team => "team",
        Visibility::Org => "org",
        Visibility::Operator => "operator",
    }
}

/// Wire name of a data class.
fn data_class_name(class: DataClass) -> &'static str {
    match class {
        DataClass::Internal => "internal",
        DataClass::SubjectDerived => "subject_derived",
    }
}

/// Wire name of an entity role.
fn entity_role_name(role: EntityRole) -> &'static str {
    match role {
        EntityRole::Primary => "primary",
        EntityRole::Context => "context",
        EntityRole::Related => "related",
    }
}

/// Wire name of a subject role.
fn subject_role_name(role: SubjectRole) -> &'static str {
    match role {
        SubjectRole::Principal => "principal",
        SubjectRole::Party => "party",
    }
}

/// Emits block-style YAML for an ordered field list.
fn emit(fields: &[(&str, Value)]) -> String {
    let mut out = String::new();
    for (key, value) in fields {
        out.push_str(&yaml_string(key));
        out.push(':');
        match value {
            Value::Leaf(scalar) => {
                out.push(' ');
                out.push_str(&yaml_scalar(scalar));
                out.push('\n');
            }
            Value::Map(entries) if entries.is_empty() => out.push_str(" {}\n"),
            Value::Map(entries) => {
                out.push('\n');
                for (name, scalar) in entries {
                    out.push_str("  ");
                    out.push_str(&yaml_string(name));
                    out.push_str(": ");
                    out.push_str(&yaml_scalar(scalar));
                    out.push('\n');
                }
            }
            Value::List(items) if items.is_empty() => out.push_str(" []\n"),
            Value::List(items) => {
                out.push('\n');
                for item in items {
                    out.push_str("  - ");
                    out.push_str(&yaml_scalar(item));
                    out.push('\n');
                }
            }
            Value::Maps(items) if items.is_empty() => out.push_str(" []\n"),
            Value::Maps(items) => {
                out.push('\n');
                for entries in items {
                    out.push_str("  - ");
                    if entries.is_empty() {
                        out.push_str("{}\n");
                        continue;
                    }
                    for (index, (name, scalar)) in entries.iter().enumerate() {
                        // The first key shares the dash's line; the rest align under it.
                        if index > 0 {
                            out.push_str("    ");
                        }
                        out.push_str(&yaml_string(name));
                        out.push_str(": ");
                        out.push_str(&yaml_scalar(scalar));
                        out.push('\n');
                    }
                }
            }
        }
    }
    out
}

/// Renders one scalar as a YAML node.
fn yaml_scalar(scalar: &Scalar) -> String {
    match scalar {
        Scalar::Null => "null".to_owned(),
        Scalar::Bool(v) => v.to_string(),
        Scalar::Int(v) => v.to_string(),
        // Debug gives the shortest text that reads back as the same `f32`, which is what makes a
        // re-render byte-identical and the checksum stable.
        Scalar::Float(v) => format!("{v:?}"),
        Scalar::Str(v) => yaml_string(v),
    }
}

/// Renders a string, quoting it unless a plain scalar is unambiguous.
fn yaml_string(value: &str) -> String {
    if plain_safe(value) {
        value.to_owned()
    } else {
        quote(value)
    }
}

/// Whether a string reads back as itself when written as a plain scalar.
///
/// Conservative on purpose. A wrongly-plain scalar comes back as an integer or a boolean, and the
/// resulting round-trip failure is exactly the silent index drift this crate exists to prevent.
fn plain_safe(value: &str) -> bool {
    let Some(&first) = value.as_bytes().first() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
    {
        return false;
    }
    if value.starts_with("0x") || value.starts_with("0o") {
        return false;
    }
    if value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok() {
        return false;
    }
    !RESERVED.iter().any(|r| value.eq_ignore_ascii_case(r))
}

/// Renders a string as a double-quoted YAML scalar, on one line.
///
/// One line matters: a record body is separated from its frontmatter by a `---` line, and a literal
/// block scalar could contain one.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let code = u32::from(c);
                let _ = write!(out, "\\x{code:02x}");
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Converts one projected value to JSON.
fn json_value(value: &Value) -> crate::Result<Json> {
    match value {
        Value::Leaf(scalar) => json_scalar(scalar),
        Value::Map(entries) => json_object(entries).map(Json::Object),
        Value::List(items) => items
            .iter()
            .map(json_scalar)
            .collect::<crate::Result<Vec<_>>>()
            .map(Json::Array),
        Value::Maps(items) => items
            .iter()
            .map(|entries| json_object(entries).map(Json::Object))
            .collect::<crate::Result<Vec<_>>>()
            .map(Json::Array),
    }
}

/// Converts a flat mapping to a JSON object.
fn json_object(entries: &[(String, Scalar)]) -> crate::Result<JsonMap<String, Json>> {
    let mut out = JsonMap::new();
    for (name, scalar) in entries {
        out.insert(name.clone(), json_scalar(scalar)?);
    }
    Ok(out)
}

/// Converts one scalar to JSON.
fn json_scalar(scalar: &Scalar) -> crate::Result<Json> {
    Ok(match scalar {
        Scalar::Null => Json::Null,
        Scalar::Bool(v) => Json::Bool(*v),
        Scalar::Int(v) => Json::Number((*v).into()),
        Scalar::Float(v) => {
            // Reparse the frontmatter text rather than widening: `f64::from(0.82f32)` is
            // 0.8199999928474426, which would make the index disagree with the file it came from.
            let rendered = format!("{v:?}");
            let number = rendered
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .ok_or_else(|| {
                    yaam_contract::Error::Invalid(format!(
                        "confidence `{rendered}` is not a finite number"
                    ))
                })?;
            Json::Number(number)
        }
        Scalar::Str(v) => Json::String(v.clone()),
    })
}

/// Converts a parsed YAML node to JSON, so the contract's own `Deserialize` does the typing.
fn to_json(node: &Yaml<'_>) -> crate::Result<Json> {
    match node {
        Yaml::Value(scalar) => yaml_scalar_to_json(scalar),
        Yaml::Sequence(items) => items
            .iter()
            .map(to_json)
            .collect::<crate::Result<Vec<_>>>()
            .map(Json::Array),
        Yaml::Mapping(map) => {
            let mut out = JsonMap::new();
            for (key, value) in map {
                out.insert(key_str(key)?.to_owned(), to_json(value)?);
            }
            Ok(Json::Object(out))
        }
        _ => Err(Error::MalformedFrontmatter(
            "unsupported YAML node: expected a scalar, a sequence or a mapping".to_owned(),
        )),
    }
}

/// Converts a parsed YAML scalar to JSON.
fn yaml_scalar_to_json(scalar: &YamlScalar<'_>) -> crate::Result<Json> {
    Ok(match scalar {
        YamlScalar::Null => Json::Null,
        YamlScalar::Boolean(v) => Json::Bool(*v),
        YamlScalar::Integer(v) => Json::Number((*v).into()),
        YamlScalar::FloatingPoint(v) => serde_json::Number::from_f64(v.0)
            .map(Json::Number)
            .ok_or_else(|| Error::MalformedFrontmatter(format!("`{v}` is not a finite number")))?,
        YamlScalar::String(v) => Json::String(v.to_string()),
    })
}

/// Reads a mapping key, which must be a string.
fn key_str<'a>(node: &'a Yaml<'_>) -> crate::Result<&'a str> {
    match node {
        Yaml::Value(YamlScalar::String(key)) => Ok(key.as_ref()),
        _ => Err(Error::MalformedFrontmatter(
            "mapping keys must be strings".to_owned(),
        )),
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Neutral record fixtures, shared with the document tests.

    use std::collections::BTreeMap;

    use yaam_contract::{
        ActionRecord, CanonVer, DataClass, Outcome, RecordId, SchemaVer, SubjectHash, Visibility,
        attrs::Value as AttrValue,
        entity::{EntityRef, Role as EntityRole},
        record::{Role as SubjectRole, SubjectRef},
    };

    /// Builds a subject hash from its stored form.
    ///
    /// Goes through `Deserialize` rather than `SubjectHash::parse`, which is unimplemented on this
    /// branch.
    pub fn subject_hash(fill: char) -> SubjectHash {
        let text = format!("s_{}", fill.to_string().repeat(64));
        serde_json::from_value(serde_json::Value::String(text))
            .expect("a newtype over String deserialises from a JSON string")
    }

    /// A record touching every field: three entities with mixed roles and confidences, two
    /// subjects with different roles and canonicalisation versions, and all three attribute types.
    pub fn record() -> ActionRecord {
        ActionRecord {
            record_id: RecordId::generate(),
            schema_ver: SchemaVer(3),
            at: "2026-08-20T09:14:02Z".to_owned(),
            received_at: "2026-08-20T09:14:03.117Z".to_owned(),
            backfilled: true,
            agent: "agent_a".to_owned(),
            agent_ver: Some("1.4.2".to_owned()),
            correlation_id: Some("corr-7f31".to_owned()),
            action: "deploy".to_owned(),
            outcome: Outcome::Partial,
            attrs: BTreeMap::from([
                (
                    "environment".to_owned(),
                    AttrValue::Text("staging".to_owned()),
                ),
                ("retries".to_owned(), AttrValue::Int(3)),
                ("dry_run".to_owned(), AttrValue::Bool(false)),
            ]),
            entities: vec![
                EntityRef {
                    kind: "deploy".to_owned(),
                    id: "deploy/2026-08-20/17".to_owned(),
                    role: EntityRole::Primary,
                    confidence: 1.0,
                },
                EntityRef {
                    kind: "pull_request".to_owned(),
                    id: "pull_request/482".to_owned(),
                    role: EntityRole::Context,
                    confidence: 0.82,
                },
                EntityRef {
                    kind: "order_ref".to_owned(),
                    id: "ord-91af".to_owned(),
                    role: EntityRole::Related,
                    confidence: 0.5,
                },
            ],
            subjects: vec![
                SubjectRef {
                    hash: subject_hash('a'),
                    role: SubjectRole::Principal,
                    canon_ver: CanonVer(1),
                },
                SubjectRef {
                    hash: subject_hash('b'),
                    role: SubjectRole::Party,
                    canon_ver: CanonVer(2),
                },
            ],
            visibility: Visibility::Team,
            team: Some("team_blue".to_owned()),
            data_class: DataClass::Internal,
            redaction_policy: "default".to_owned(),
            fields_masked: vec!["chat_user".to_owned(), "ticket".to_owned()],
            tags: vec!["rollout".to_owned(), "needs-review".to_owned()],
            summary: String::new(),
        }
    }

    /// Compares two records field by field, so a failure names the field that did not survive.
    #[expect(
        clippy::cognitive_complexity,
        reason = "one assertion per field is the point"
    )]
    pub fn assert_same_record(left: &ActionRecord, right: &ActionRecord) {
        assert_eq!(left.record_id, right.record_id, "record_id");
        assert_eq!(left.schema_ver, right.schema_ver, "schema_ver");
        assert_eq!(left.at, right.at, "at");
        assert_eq!(left.received_at, right.received_at, "received_at");
        assert_eq!(left.backfilled, right.backfilled, "backfilled");
        assert_eq!(left.agent, right.agent, "agent");
        assert_eq!(left.agent_ver, right.agent_ver, "agent_ver");
        assert_eq!(left.correlation_id, right.correlation_id, "correlation_id");
        assert_eq!(left.action, right.action, "action");
        assert_eq!(left.outcome, right.outcome, "outcome");
        assert_eq!(left.attrs, right.attrs, "attrs");
        assert_eq!(left.visibility, right.visibility, "visibility");
        assert_eq!(left.team, right.team, "team");
        assert_eq!(left.data_class, right.data_class, "data_class");
        assert_eq!(
            left.redaction_policy, right.redaction_policy,
            "redaction_policy"
        );
        assert_eq!(left.fields_masked, right.fields_masked, "fields_masked");
        assert_eq!(left.tags, right.tags, "tags");
        assert_eq!(left.summary, right.summary, "summary");

        assert_eq!(left.entities.len(), right.entities.len(), "entity count");
        for (index, (a, b)) in left.entities.iter().zip(&right.entities).enumerate() {
            assert_eq!(a.kind, b.kind, "entities[{index}].kind");
            assert_eq!(a.id, b.id, "entities[{index}].id");
            assert_eq!(a.role, b.role, "entities[{index}].role");
            // Bit equality, not approximate: a confidence that shifts on a round trip changes the
            // content checksum and makes every unmodified file look modified.
            assert_eq!(
                a.confidence.to_bits(),
                b.confidence.to_bits(),
                "entities[{index}].confidence"
            );
        }

        assert_eq!(left.subjects.len(), right.subjects.len(), "subject count");
        for (index, (a, b)) in left.subjects.iter().zip(&right.subjects).enumerate() {
            assert_eq!(a.hash, b.hash, "subjects[{index}].hash");
            assert_eq!(a.role, b.role, "subjects[{index}].role");
            assert_eq!(a.canon_ver, b.canon_ver, "subjects[{index}].canon_ver");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{assert_same_record, record};
    use super::{
        AttrValue, DataClass, EntityRef, EntityRole, Error, Json, KEYS, Outcome, Value, Visibility,
        data_class_name, emit, outcome_name, parse, plain_safe, project, render, to_canonical_json,
        to_json, visibility_name,
    };

    use saphyr::{LoadableYamlNode, Yaml};

    /// Reads rendered frontmatter back into JSON, the way `parse` does before typing it.
    fn rendered_as_json(text: &str) -> Json {
        let docs = Yaml::load_from_str(text).expect("rendered frontmatter is valid YAML");
        to_json(docs.first().expect("one document")).expect("convertible to JSON")
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let original = record();
        let parsed = parse(&render(&original)).expect("rendered frontmatter parses");
        assert_same_record(&original, &parsed);
        assert_eq!(original, parsed);
    }

    #[test]
    fn render_is_byte_stable() {
        let original = record();
        let first = render(&original);
        assert_eq!(first, render(&original));
        // And stable across a round trip, which is what the content checksum depends on.
        let parsed = parse(&first).expect("parses");
        assert_eq!(render(&parsed), first);
    }

    #[test]
    fn render_order_is_the_declared_key_order() {
        let names: Vec<&str> = project(&record()).into_iter().map(|(key, _)| key).collect();
        assert_eq!(names, KEYS.to_vec());
    }

    #[test]
    fn canonical_json_is_the_frontmatter_reread() {
        let original = record();
        let canonical: Json =
            serde_json::from_str(&to_canonical_json(&original).expect("projects"))
                .expect("valid JSON");
        assert_eq!(canonical, rendered_as_json(&render(&original)));
    }

    #[test]
    fn canonical_json_keys_are_the_frontmatter_keys() {
        let original = record();
        let text = to_canonical_json(&original).expect("projects");
        assert_eq!(text, to_canonical_json(&original).expect("projects"));

        let value: Json = serde_json::from_str(&text).expect("valid JSON");
        let keys: Vec<&str> = value
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }

    #[test]
    fn frontmatter_never_carries_prose() {
        let mut original = record();
        original.summary = "the prose that belongs in the body".to_owned();
        let text = render(&original);
        assert!(!text.contains("prose"), "{text}");
        assert!(!text.contains("summary"), "{text}");
        assert_eq!(parse(&text).expect("parses").summary, "");
    }

    #[test]
    fn absent_optionals_render_as_null() {
        let mut original = record();
        original.agent_ver = None;
        original.correlation_id = None;
        original.team = None;
        original.visibility = Visibility::Org;

        let text = render(&original);
        assert!(text.contains("agent_ver: null\n"), "{text}");
        assert!(text.contains("correlation_id: null\n"), "{text}");
        assert!(text.contains("team: null\n"), "{text}");
        assert_eq!(original, parse(&text).expect("parses"));

        let canonical: Json =
            serde_json::from_str(&to_canonical_json(&original).expect("projects"))
                .expect("valid JSON");
        assert_eq!(canonical["team"], Json::Null);
        assert_eq!(canonical, rendered_as_json(&text));
    }

    #[test]
    fn wire_names_are_pinned() {
        // The index filters on these strings, so a rename in the contract must break a test here
        // rather than silently orphan every row already on disk.
        assert_eq!(outcome_name(Outcome::Success), "success");
        assert_eq!(outcome_name(Outcome::Failure), "failure");
        assert_eq!(outcome_name(Outcome::Partial), "partial");
        assert_eq!(outcome_name(Outcome::Declined), "declined");
        assert_eq!(visibility_name(Visibility::Owner), "owner");
        assert_eq!(visibility_name(Visibility::Team), "team");
        assert_eq!(visibility_name(Visibility::Org), "org");
        assert_eq!(visibility_name(Visibility::Operator), "operator");
        assert_eq!(data_class_name(DataClass::Internal), "internal");
        assert_eq!(
            data_class_name(DataClass::SubjectDerived),
            "subject_derived"
        );
    }

    #[test]
    fn every_enum_variant_round_trips() {
        let outcomes = [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Partial,
            Outcome::Declined,
        ];
        let visibilities = [
            Visibility::Owner,
            Visibility::Team,
            Visibility::Org,
            Visibility::Operator,
        ];
        for outcome in outcomes {
            for visibility in visibilities {
                for data_class in [DataClass::Internal, DataClass::SubjectDerived] {
                    let mut original = record();
                    original.outcome = outcome;
                    original.visibility = visibility;
                    original.data_class = data_class;

                    let text = render(&original);
                    assert_eq!(original, parse(&text).expect("parses"));

                    let canonical: Json =
                        serde_json::from_str(&to_canonical_json(&original).expect("projects"))
                            .expect("valid JSON");
                    assert_eq!(canonical, rendered_as_json(&text));
                }
            }
        }
    }

    #[test]
    fn empty_collections_round_trip() {
        let mut original = record();
        original.attrs.clear();
        original.entities.clear();
        original.subjects.clear();
        original.fields_masked.clear();
        original.tags.clear();

        let text = render(&original);
        assert!(text.contains("attrs: {}\n"), "{text}");
        assert!(text.contains("entities: []\n"), "{text}");
        assert!(text.contains("subjects: []\n"), "{text}");
        assert!(text.contains("fields_masked: []\n"), "{text}");
        assert!(text.contains("tags: []\n"), "{text}");
        assert_eq!(original, parse(&text).expect("parses"));
    }

    #[test]
    fn ordinary_values_stay_unquoted() {
        let text = render(&record());
        assert!(text.contains("action: deploy\n"), "{text}");
        assert!(text.contains("outcome: partial\n"), "{text}");
        assert!(text.contains("agent: agent_a\n"), "{text}");
        assert!(text.contains("data_class: internal\n"), "{text}");
        assert!(text.contains("backfilled: true\n"), "{text}");
        assert!(text.contains("schema_ver: 3\n"), "{text}");
        assert!(text.contains("    role: primary\n"), "{text}");
    }

    #[test]
    fn strings_that_resemble_other_types_survive() {
        let awkward = [
            "123",
            "-4",
            "1e5",
            "0x10",
            "0o7",
            "+9",
            "true",
            "FALSE",
            "null",
            "NULL",
            "Null",
            "~",
            "yes",
            "No",
            "on",
            "OFF",
            "y",
            "n",
            ".inf",
            ".nan",
            "1.0",
            "",
            " leading",
            "trailing ",
            "a: b",
            "# comment",
            "- item",
            "line\nbreak",
            "tab\there",
            "quote\"inside",
            "back\\slash",
            "cr\rnl",
            "\u{1}",
            "\u{7f}",
            "héllo wörld",
            "[[deploy:1]]",
            "1_000",
            "e5",
            "5.",
            ".5",
            "@reserved",
            "*star",
            "&amp",
            "!bang",
            "%pct",
            "{brace}",
            "---",
        ];

        let mut original = record();
        original.attrs = awkward
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("k{index}"), AttrValue::Text((*value).to_owned())))
            .collect();
        original
            .attrs
            .insert("with space".to_owned(), AttrValue::Int(-7));
        original
            .attrs
            .insert("123".to_owned(), AttrValue::Bool(true));
        original.tags = awkward.iter().map(|value| (*value).to_owned()).collect();

        let parsed = parse(&render(&original)).expect("parses");
        assert_same_record(&original, &parsed);
    }

    #[test]
    fn confidence_round_trips_bit_for_bit() {
        for confidence in [
            0.0_f32,
            -0.0,
            1.0,
            0.5,
            0.82,
            0.123_456_79,
            1e-8,
            f32::MIN_POSITIVE,
            f32::MAX,
        ] {
            let mut original = record();
            original.entities = vec![EntityRef {
                kind: "ticket".to_owned(),
                id: "ticket/9".to_owned(),
                role: EntityRole::Primary,
                confidence,
            }];
            let parsed = parse(&render(&original)).expect("parses");
            assert_eq!(
                parsed.entities[0].confidence.to_bits(),
                confidence.to_bits(),
                "{confidence:?}"
            );
        }
    }

    #[test]
    fn a_non_finite_confidence_cannot_be_projected() {
        let mut original = record();
        original.entities[0].confidence = f32::NAN;
        let error = to_canonical_json(&original).expect_err("not projectable");
        assert!(matches!(error, Error::Contract(_)), "{error}");
    }

    #[test]
    fn a_non_finite_number_in_frontmatter_is_rejected() {
        let text = render(&record()).replace("confidence: 1.0", "confidence: .nan");
        let error = parse(&text).expect_err("rejected");
        assert!(matches!(error, Error::MalformedFrontmatter(_)), "{error}");
    }

    #[test]
    fn a_missing_field_is_rejected() {
        let error = parse("action: deploy\n").expect_err("rejected");
        assert!(matches!(error, Error::MalformedFrontmatter(_)), "{error}");
    }

    #[test]
    fn an_unexpected_key_is_rejected() {
        let text = format!("{}surprise: 1\n", render(&record()));
        let error = parse(&text).expect_err("rejected");
        assert!(
            matches!(&error, Error::MalformedFrontmatter(m) if m.contains("surprise")),
            "{error}"
        );
    }

    #[test]
    fn summary_is_not_a_frontmatter_key() {
        let text = format!("{}summary: prose\n", render(&record()));
        let error = parse(&text).expect_err("rejected");
        assert!(
            matches!(&error, Error::MalformedFrontmatter(m) if m.contains("summary")),
            "{error}"
        );
    }

    #[test]
    fn frontmatter_must_be_a_mapping() {
        for text in ["", "just a scalar\n", "- a\n- b\n"] {
            let error = parse(text).expect_err("rejected");
            assert!(
                matches!(&error, Error::MalformedFrontmatter(m) if m.contains("mapping")),
                "{text:?}: {error}"
            );
        }
    }

    #[test]
    fn malformed_yaml_is_reported_not_panicked() {
        let error = parse("action: [unclosed\n").expect_err("rejected");
        assert!(matches!(error, Error::MalformedFrontmatter(_)), "{error}");
    }

    #[test]
    fn keys_must_be_strings() {
        for text in ["1: x\n", "attrs:\n  2: x\n"] {
            let error = parse(text).expect_err("rejected");
            assert!(
                matches!(&error, Error::MalformedFrontmatter(m) if m.contains("keys must be")),
                "{text:?}: {error}"
            );
        }
    }

    #[test]
    fn an_incoherent_tagged_scalar_is_rejected() {
        let error = parse("attrs:\n  k: !!int oops\n").expect_err("rejected");
        assert!(
            matches!(&error, Error::MalformedFrontmatter(m) if m.contains("unsupported")),
            "{error}"
        );
    }

    #[test]
    fn the_emitter_handles_an_empty_mapping_in_a_list() {
        let text = emit(&[("entities", Value::Maps(vec![vec![]]))]);
        assert_eq!(text, "entities:\n  - {}\n");
    }

    #[test]
    fn plain_scalars_are_used_only_where_unambiguous() {
        for value in ["deploy", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "v1.4.2", "a/b-c.d"] {
            assert!(plain_safe(value), "{value:?} should stay plain");
        }
        for value in [
            "", "-x", ".5", "0x10", "0o7", "12", "1.5", "true", "a b", "~",
        ] {
            assert!(!plain_safe(value), "{value:?} should be quoted");
        }
    }
}
