//! `spec/memory.v1.yaml` against the router it describes.
//!
//! The spec is vendored by other implementations, so it is believed. A document nobody checks is
//! worse than no document, because it goes on being believed after it stops being true — hence this
//! file, which fails on the drift a reviewer would not see: a route added or renamed, a status code
//! the handlers stopped returning, a query parameter or body field renamed, a header constant
//! changed, or the sealed-body media type moved.
//!
//! Every check below reads the document and then asks the real router, rather than asserting
//! against a second copy of the same expectation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use saphyr::{LoadableYamlNode, Mapping, Yaml};
use tower::ServiceExt;
use yaam_contract::request::{AGENT_HEADER, SIGNATURE_HEADER, sign};
use yaam_contract::{
    ActionRecord, DataClass, Outcome, RecordId, RecordStructure, SchemaVer, SubjectHash, Visibility,
};
use yaam_core::bundle::{self, Bundle};
use yaam_core::erase::EraseReport;
use yaam_core::pipeline::Accepted;
use yaam_crypto::envelope;
use yaam_server::auth::{Caller, Credential, Keyring, Role};
use yaam_server::routes::{AppState, router};
use yaam_server::service::Service;
use yaam_store::query::{Filter, Window};

/// The published contract.
const SPEC: &str = include_str!("../../../spec/memory.v1.yaml");

/// The wiring the contract describes. Read as text because a `Router` cannot be asked what it
/// serves, and a hand-kept list of routes is exactly the second copy this file exists to avoid.
const ROUTES: &str = include_str!("../src/routes.rs");

/// The one signing key these callers share; what separates them is the agent name.
const KEY: &[u8] = b"a-spec-check-key";
const READER: &str = "agent_b";
const WRITER: &str = "agent_a";
const OPERATOR: &str = "agent_ops";

/// How the service under test behaves, so a single request can provoke a chosen status.
#[derive(Debug, Clone, Copy)]
enum Mode {
    /// A write stores.
    Stored,
    /// A write finds its identifier already present.
    Duplicate,
    /// A write is held pending subject resolution.
    Quarantined,
    /// The read names something this deployment cannot answer as it was spelled — an entity
    /// identifier it cannot canonicalise, or a needle the match syntax will not parse.
    ///
    /// A mode rather than a real registry or a real index: both belong to the service, so what this
    /// file can check is that the router reports them as the document says. That they *are* refused,
    /// over the repository's own `spec/entities.yaml` and a real index, is `end_to_end.rs`'s job.
    Unaskable,
    /// Everything is transiently unavailable.
    Unavailable,
    /// Everything fails in a way that is this service's own fault.
    Internal,
}

/// A service that answers however the case under test needs.
#[derive(Debug)]
struct Fake {
    mode: Mode,
}

impl Fake {
    /// The configured failure, if any.
    fn gate(&self) -> yaam_server::Result<()> {
        match self.mode {
            Mode::Unaskable => Err(yaam_server::Error::Unprocessable(
                "entity id `not a ticket` is not canonical for kind `ticket`".to_owned(),
            )),
            Mode::Unavailable => Err(yaam_server::Error::Unavailable(
                "index reopening".to_owned(),
            )),
            Mode::Internal => Err(yaam_server::Error::Core(
                yaam_store::Error::Drift("an unindexed record".to_owned()).into(),
            )),
            _ => Ok(()),
        }
    }
}

impl Service for Fake {
    fn write(
        &self,
        _caller: &Caller,
        record: ActionRecord,
        _body: &str,
    ) -> yaam_server::Result<Accepted> {
        self.gate()?;
        let id = record.record_id;
        Ok(match self.mode {
            Mode::Duplicate => Accepted::Duplicate(id),
            Mode::Quarantined => Accepted::Quarantined(id),
            _ => Accepted::Stored(id),
        })
    }

    fn query(
        &self,
        _caller: &Caller,
        _filter: &Filter,
    ) -> yaam_server::Result<Vec<RecordStructure>> {
        self.gate()?;
        Ok(Vec::new())
    }

    fn search(
        &self,
        _caller: &Caller,
        _needle: &str,
        _limit: Option<u32>,
    ) -> yaam_server::Result<Vec<RecordStructure>> {
        self.gate()?;
        Ok(Vec::new())
    }

    fn entity(
        &self,
        _caller: &Caller,
        _kind: &str,
        _id: &str,
        _min_confidence: f32,
        _window: Option<Window>,
        _limit: Option<u32>,
    ) -> yaam_server::Result<Vec<RecordStructure>> {
        self.gate()?;
        Ok(Vec::new())
    }

    fn correlate(
        &self,
        _caller: &Caller,
        _left: &Filter,
        _right: &Filter,
        _within_ms: i64,
    ) -> yaam_server::Result<Vec<(RecordStructure, RecordStructure)>> {
        self.gate()?;
        Ok(Vec::new())
    }

    fn bundle(&self, _caller: &Caller, _request: &bundle::Request) -> yaam_server::Result<Bundle> {
        self.gate()?;
        Ok(Bundle::default())
    }

    fn erase(&self, _caller: &Caller, _subject: &SubjectHash) -> yaam_server::Result<EraseReport> {
        self.gate()?;
        Ok(EraseReport::default())
    }
}

/// One request, and the operation the spec files it under.
struct Case {
    method: &'static str,
    /// Path as the document spells it, which is not the URI when there are path parameters.
    template: &'static str,
    uri: String,
    /// `None` sends the request unsigned.
    agent: Option<&'static str>,
    body: String,
    mode: Mode,
}

/// A request signed as `agent`, answered by a service in `mode`.
async fn call(case: &Case) -> (StatusCode, String) {
    let keyring = Keyring::new()
        .with(Credential::new(READER, Role::Reader, KEY))
        .with(Credential::new(WRITER, Role::Writer, KEY))
        .with(Credential::new(OPERATOR, Role::Operator, KEY));
    let service = Arc::new(Fake { mode: case.mode }) as Arc<dyn Service>;
    let app = router(AppState::new(Arc::new(keyring), service).unsealing_with(vec![7u8; 32]));

    let mut builder = Request::builder()
        .method(case.method)
        .uri(&case.uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(agent) = case.agent {
        let tag = sign(KEY, case.method, &case.uri, agent, case.body.as_bytes());
        builder = builder
            .header(AGENT_HEADER, agent)
            .header(SIGNATURE_HEADER, tag);
    }
    let request = builder
        .body(Body::from(case.body.clone()))
        .expect("a well-formed request");

    let response = app.oneshot(request).await.expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a complete body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A valid record attributed to `agent`, as the document's example describes one.
fn record(agent: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: "2026-08-20T11:04:05Z".to_owned(),
        received_at: "2026-08-20T11:04:06Z".to_owned(),
        backfilled: false,
        agent: agent.to_owned(),
        agent_ver: None,
        correlation_id: None,
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: std::collections::BTreeMap::new(),
        entities: Vec::new(),
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: "default-v1".to_owned(),
        fields_masked: Vec::new(),
        tags: Vec::new(),
        summary: "Rolled build 412 out to staging.".to_owned(),
    }
}

/// A write request body attributed to `agent`.
fn write_body(agent: &str) -> String {
    serde_json::json!({ "record": record(agent) }).to_string()
}

/// A write request whose record carries a field no schema declares.
fn nested_unknown_field(agent: &str) -> String {
    let mut record = serde_json::to_value(record(agent)).expect("a record serialises");
    record
        .as_object_mut()
        .expect("a record is an object")
        .insert("nonsense".to_owned(), serde_json::json!(1));
    serde_json::json!({ "record": record }).to_string()
}

/// A well-formed erasure request.
fn erase_body() -> String {
    let subject = SubjectHash::parse(&format!("s_{:064x}", 1)).expect("a well-formed pseudonym");
    serde_json::json!({ "subject": subject.as_str() }).to_string()
}

/// Shorthand for one case.
fn case(
    method: &'static str,
    template: &'static str,
    uri: impl Into<String>,
    agent: Option<&'static str>,
    body: impl Into<String>,
    mode: Mode,
) -> Case {
    Case {
        method,
        template,
        uri: uri.into(),
        agent,
        body: body.into(),
        mode,
    }
}

/// Requests that between them provoke every status the document claims, and nothing else.
fn cases() -> Vec<Case> {
    let mut all = write_cases();
    all.extend(query_cases());
    all.extend(search_cases());
    all.extend(entity_cases());
    all.extend(correlate_cases());
    all.extend(bundle_cases());
    all.extend(erase_cases());
    all
}

fn write_cases() -> Vec<Case> {
    let path = "/records";
    vec![
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(WRITER),
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(WRITER),
            Mode::Duplicate,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(WRITER),
            Mode::Quarantined,
        ),
        case("POST", path, path, None, write_body(WRITER), Mode::Stored),
        // A reader may not write, and a writer may not write as somebody else.
        case(
            "POST",
            path,
            path,
            Some(READER),
            write_body(READER),
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(READER),
            Mode::Stored,
        ),
        // Permanent: an undeclared field at the request's top level, and a record that breaks a
        // contract rule no retry of the same bytes can fix.
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            r#"{"nonsense":1,"record":{}}"#,
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            r#"{"record":1}"#,
            Mode::Stored,
        ),
        // An undeclared field *inside* the record, which is the same mistake about more.
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            nested_unknown_field(WRITER),
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(WRITER),
            Mode::Internal,
        ),
        case(
            "POST",
            path,
            path,
            Some(WRITER),
            write_body(WRITER),
            Mode::Unavailable,
        ),
    ]
}

fn query_cases() -> Vec<Case> {
    let path = "/records";
    vec![
        case("GET", path, path, Some(READER), "", Mode::Stored),
        case(
            "GET",
            path,
            "/records?nonsense=1",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, path, None, "", Mode::Stored),
        // Half a window, and an attribute filter that is not `key=value`.
        case(
            "GET",
            path,
            "/records?from_ms=10",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case(
            "GET",
            path,
            "/records?attr=environment",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, path, Some(READER), "", Mode::Internal),
        case("GET", path, path, Some(READER), "", Mode::Unavailable),
    ]
}

fn search_cases() -> Vec<Case> {
    let path = "/search";
    let uri = "/search?q=shards";
    vec![
        case("GET", path, uri, Some(READER), "", Mode::Stored),
        // A needle nobody understood must not widen into a search for everything, and one the match
        // syntax refuses is the caller's to fix.
        case(
            "GET",
            path,
            "/search?nonsense=1",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, uri, None, "", Mode::Stored),
        case("GET", path, uri, Some(READER), "", Mode::Unaskable),
        case("GET", path, uri, Some(READER), "", Mode::Internal),
        case("GET", path, uri, Some(READER), "", Mode::Unavailable),
    ]
}

fn entity_cases() -> Vec<Case> {
    let template = "/entities/{kind}/{id}";
    let uri = "/entities/ticket/PROJ-42";
    vec![
        case("GET", template, uri, Some(READER), "", Mode::Stored),
        case(
            "GET",
            template,
            format!("{uri}?nonsense=1"),
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", template, uri, None, "", Mode::Stored),
        case("GET", template, uri, Some(READER), "", Mode::Unaskable),
        case("GET", template, uri, Some(READER), "", Mode::Internal),
        case("GET", template, uri, Some(READER), "", Mode::Unavailable),
    ]
}

fn correlate_cases() -> Vec<Case> {
    let path = "/correlate";
    // A window on the left and a nearness: the two this endpoint refuses to guess at, so every case
    // that means to reach a handler has to carry both.
    let uri = "/correlate?left.action=transact&left.from_ms=10&left.to_ms=20&within_ms=1000";
    vec![
        case("GET", path, uri, Some(READER), "", Mode::Stored),
        // A mistyped side must not widen that half of the join to everything.
        case(
            "GET",
            path,
            "/correlate?nonsense=1",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, uri, None, "", Mode::Stored),
        // Permanent: half a left window, no window at all, and a backwards nearness — none of which
        // is a narrower question, and each of which would otherwise answer `200` with no pairs.
        case(
            "GET",
            path,
            "/correlate?left.from_ms=10&within_ms=1000",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case(
            "GET",
            path,
            "/correlate?left.from_ms=10&left.to_ms=20&within_ms=-1",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case(
            "GET",
            path,
            "/correlate?left.from_ms=10&left.to_ms=20&within_ms=1&left.attr=environment",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, uri, Some(READER), "", Mode::Internal),
        case("GET", path, uri, Some(READER), "", Mode::Unavailable),
    ]
}

fn bundle_cases() -> Vec<Case> {
    let path = "/bundle";
    vec![
        case("GET", path, path, Some(READER), "", Mode::Stored),
        case(
            "GET",
            path,
            "/bundle?nonsense=1",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, path, None, "", Mode::Stored),
        case(
            "GET",
            path,
            "/bundle?entity=ticket",
            Some(READER),
            "",
            Mode::Stored,
        ),
        case("GET", path, path, Some(READER), "", Mode::Internal),
        case("GET", path, path, Some(READER), "", Mode::Unavailable),
    ]
}

fn erase_cases() -> Vec<Case> {
    let path = "/erase";
    vec![
        case(
            "POST",
            path,
            path,
            Some(OPERATOR),
            erase_body(),
            Mode::Stored,
        ),
        case("POST", path, path, None, erase_body(), Mode::Stored),
        case("POST", path, path, Some(WRITER), erase_body(), Mode::Stored),
        case(
            "POST",
            path,
            path,
            Some(OPERATOR),
            r#"{"nonsense":1}"#,
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(OPERATOR),
            r#"{"subject":"not-a-pseudonym"}"#,
            Mode::Stored,
        ),
        case(
            "POST",
            path,
            path,
            Some(OPERATOR),
            erase_body(),
            Mode::Internal,
        ),
        case(
            "POST",
            path,
            path,
            Some(OPERATOR),
            erase_body(),
            Mode::Unavailable,
        ),
    ]
}

/// The document, as one YAML document or not at all.
fn spec() -> Yaml<'static> {
    let mut docs = Yaml::load_from_str(SPEC).expect("the spec is valid YAML");
    assert_eq!(
        docs.len(),
        1,
        "the spec must be one document: a stray `---` would load with half its content missing"
    );
    docs.remove(0)
}

/// Walks a path of mapping keys.
fn node<'a, 'i>(from: &'a Yaml<'i>, keys: &[&str]) -> &'a Yaml<'i> {
    let mut at = from;
    for key in keys {
        at = at
            .as_mapping_get(key)
            .unwrap_or_else(|| panic!("the spec has no `{}`", keys.join(".")));
    }
    at
}

/// Walks to a mapping, which is what the spec's containers all are.
fn map<'a, 'i>(from: &'a Yaml<'i>, keys: &[&str]) -> &'a Mapping<'i> {
    node(from, keys)
        .as_mapping()
        .unwrap_or_else(|| panic!("`{}` is not a mapping", keys.join(".")))
}

/// The keys of a mapping, as names.
fn keys(mapping: &Mapping<'_>) -> Vec<String> {
    mapping
        .iter()
        .map(|(key, _)| key.as_str().expect("a spec key is a string").to_owned())
        .collect()
}

/// Every `(path, method) -> statuses` the document claims.
fn documented() -> BTreeMap<(String, String), BTreeSet<u16>> {
    let spec = spec();
    let mut out = BTreeMap::new();
    for (path_key, operations) in map(&spec, &["paths"]) {
        let path = path_key.as_str().expect("a path is a string").to_owned();
        let operations = operations.as_mapping().expect("operations are a mapping");
        for (method_key, operation) in operations {
            let method = method_key
                .as_str()
                .expect("a method is a string")
                .to_uppercase();
            let statuses = keys(
                operation
                    .as_mapping_get("responses")
                    .and_then(Yaml::as_mapping)
                    .unwrap_or_else(|| panic!("`{path}` `{method}` documents no responses")),
            )
            .into_iter()
            .map(|code| {
                code.parse::<u16>()
                    .unwrap_or_else(|_| panic!("`{code}` is not a status code"))
            })
            .collect();
            out.insert((path.clone(), method), statuses);
        }
    }
    out
}

/// Every `(path, method)` the router is wired for, read out of its own source.
fn wired() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in ROUTES.lines() {
        let Some((_, after)) = line.split_once(".route(\"") else {
            continue;
        };
        let (path, handlers) = after
            .split_once('"')
            .expect("a route literal closes its quote");
        for verb in ["get", "post", "put", "patch", "delete"] {
            if handlers.contains(&format!("{verb}(")) {
                out.insert((path.to_owned(), verb.to_uppercase()));
            }
        }
    }
    assert!(!out.is_empty(), "no routes found in the router's source");
    out
}

/// The names a `serde` refusal says it would have accepted.
fn accepted_names(message: &str) -> BTreeSet<String> {
    let (_, listed) = message
        .split_once("expected")
        .unwrap_or_else(|| panic!("no accepted-name list in `{message}`"));
    listed
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The query parameters the document declares for one operation, `$ref`s resolved.
fn documented_query_parameters(path: &str, method: &str) -> BTreeSet<String> {
    let spec = spec();
    let operation = node(&spec, &["paths", path, method]);
    let Some(parameters) = operation.as_mapping_get("parameters") else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for parameter in parameters.as_sequence().expect("parameters are a sequence") {
        let resolved = match parameter.as_mapping_get("$ref").and_then(Yaml::as_str) {
            Some(reference) => {
                let name = reference
                    .rsplit('/')
                    .next()
                    .expect("a reference names something");
                node(&spec, &["components", "parameters", name]).clone()
            }
            None => parameter.clone(),
        };
        if resolved.as_mapping_get("in").and_then(Yaml::as_str) == Some("query") {
            out.insert(
                resolved
                    .as_mapping_get("name")
                    .and_then(Yaml::as_str)
                    .expect("a parameter has a name")
                    .to_owned(),
            );
        }
    }
    out
}

/// Follows a `$ref` into the document, or returns the node as it stands.
fn deref(spec: &Yaml<'static>, at: &Yaml<'static>) -> Yaml<'static> {
    match at.as_mapping_get("$ref").and_then(Yaml::as_str) {
        Some(reference) => {
            let keys: Vec<&str> = reference.trim_start_matches("#/").split('/').collect();
            node(spec, &keys).clone()
        }
        None => at.clone(),
    }
}

/// The property names the document claims for one JSON response body.
///
/// `None` when the response is not JSON — the `400` a rejected query string produces is `text/plain`,
/// because it is written before the request reaches a handler.
fn documented_response_fields(path: &str, method: &str, status: u16) -> Option<BTreeSet<String>> {
    let spec = spec();
    let code = status.to_string();
    let response = deref(
        &spec,
        node(&spec, &["paths", path, method, "responses", code.as_str()]),
    );
    let schema = deref(
        &spec,
        response
            .as_mapping_get("content")?
            .as_mapping_get("application/json")?
            .as_mapping_get("schema")?,
    );
    Some(
        keys(schema.as_mapping_get("properties")?.as_mapping()?)
            .into_iter()
            .collect(),
    )
}

/// The property names of a request-body schema, `$ref` resolved.
fn documented_body_fields(path: &str, method: &str) -> BTreeSet<String> {
    let spec = spec();
    let schema = node(
        &spec,
        &[
            "paths",
            path,
            method,
            "requestBody",
            "content",
            "application/json",
            "schema",
        ],
    );
    let reference = schema
        .as_mapping_get("$ref")
        .and_then(Yaml::as_str)
        .expect("a request body refers to a named schema");
    let name = reference
        .rsplit('/')
        .next()
        .expect("a reference names something");
    keys(map(&spec, &["components", "schemas", name, "properties"]))
        .into_iter()
        .collect()
}

#[test]
fn the_document_is_one_parseable_yaml_document() {
    let spec = spec();
    assert_eq!(
        node(&spec, &["openapi"]).as_str(),
        Some("3.1.0"),
        "the schemas below are JSON Schema 2020-12, which is 3.1 only"
    );
    assert!(!map(&spec, &["paths"]).is_empty());
}

#[test]
fn the_documented_paths_and_methods_are_the_ones_the_router_serves() {
    let documented: BTreeSet<(String, String)> = documented().into_keys().collect();
    assert_eq!(
        documented,
        wired(),
        "the document and the router disagree about what is served"
    );
}

#[tokio::test]
async fn every_documented_status_is_produced_and_every_status_produced_is_documented() {
    let mut observed: BTreeMap<(String, String), BTreeSet<u16>> = BTreeMap::new();
    let mut answers: BTreeMap<(String, String, u16), String> = BTreeMap::new();
    for case in cases() {
        let (status, body) = call(&case).await;
        let code = status.as_u16();
        observed
            .entry((case.template.to_owned(), case.method.to_owned()))
            .or_default()
            .insert(code);
        answers
            .entry((case.template.to_owned(), case.method.to_owned(), code))
            .or_insert(body);
    }
    assert_eq!(
        observed,
        documented(),
        "left is what the router returned, right is what the document claims"
    );

    // Every answer's own fields, too: a renamed response field is drift a status code cannot show.
    for ((path, method, status), body) in &answers {
        let Some(expected) = documented_response_fields(path, &method.to_lowercase(), *status)
        else {
            continue;
        };
        let answer: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|_| panic!("{method} {path} {status} answered non-JSON: {body}"));
        let fields: BTreeSet<String> = answer
            .as_object()
            .unwrap_or_else(|| panic!("{method} {path} {status} answered {body}"))
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            fields, expected,
            "{method} {path} {status} answers different fields than the document claims"
        );
    }
}

#[tokio::test]
async fn the_documented_query_parameters_are_the_ones_each_endpoint_accepts() {
    // The router names its own accepted set when it refuses an unknown one, so the comparison is
    // against the handler's field names rather than against a second list kept here.
    let probes = [
        ("/records", "get", "/records?nonsense=1"),
        ("/search", "get", "/search?nonsense=1"),
        (
            "/entities/{kind}/{id}",
            "get",
            "/entities/ticket/PROJ-42?nonsense=1",
        ),
        ("/correlate", "get", "/correlate?nonsense=1"),
        ("/bundle", "get", "/bundle?nonsense=1"),
    ];
    for (template, method, uri) in probes {
        let probe = case("GET", template, uri, Some(READER), "", Mode::Stored);
        let (status, body) = call(&probe).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(
            accepted_names(&body),
            documented_query_parameters(template, method),
            "{template} documents different query parameters than it accepts"
        );
    }
}

#[tokio::test]
async fn the_documented_body_fields_are_the_ones_each_endpoint_accepts() {
    let probes = [
        ("/records", "post", WRITER, r#"{"nonsense":1,"record":{}}"#),
        ("/erase", "post", OPERATOR, r#"{"nonsense":1}"#),
    ];
    for (path, method, agent, body) in probes {
        let probe = case("POST", path, path, Some(agent), body, Mode::Stored);
        let (status, answer) = call(&probe).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {answer}");
        assert_eq!(
            accepted_names(&answer),
            documented_body_fields(path, method),
            "{path} documents different body fields than it accepts"
        );
    }
}

#[test]
fn the_documented_default_row_cap_is_the_one_the_index_applies() {
    // A number a client plans its paging around, so a drifted document is a client that believes a
    // short answer means nothing else matched.
    let spec = spec();
    let described = node(&spec, &["components", "parameters", "limit", "description"])
        .as_str()
        .expect("the parameter is described");
    let cap = format!("`{}`", yaam_store::query::DEFAULT_STRUCTURE_LIMIT);
    assert!(described.contains(&cap), "{described} does not name {cap}");
}

#[test]
fn the_documented_pair_cap_is_the_one_the_index_applies() {
    // The pair cap is the number a client plans a correlation's paging around, and it is not the row
    // cap: a pair row is two structures, so the two figures are deliberately different and a
    // document that named the wrong one would have a client size its answers at twice the truth.
    let spec = spec();
    let described = node(
        &spec,
        &["components", "parameters", "correlate_limit", "description"],
    )
    .as_str()
    .expect("the parameter is described");
    let cap = format!("`{}`", yaam_store::query::DEFAULT_PAIR_LIMIT);
    assert!(described.contains(&cap), "{described} does not name {cap}");
    assert!(
        described.contains(&format!("`{}`", yaam_store::query::DEFAULT_STRUCTURE_LIMIT)),
        "the pair cap is only meaningful beside the row cap it halves: {described}"
    );
}

#[test]
fn the_documented_full_text_ceiling_is_the_one_the_index_applies() {
    // The whole of what a client has to know about a full-text page is that it can come back short,
    // and the document says how short in numbers. A drifted multiple is a client that reads an empty
    // page as "nothing matched" when the answer was "not within the cap".
    let spec = spec();
    let described = node(&spec, &["paths", "/search", "get", "description"])
        .as_str()
        .expect("the endpoint is described");
    for named in [
        yaam_store::query::SCOPE_HEADROOM,
        yaam_store::query::MAX_CANDIDATES,
    ] {
        let literal = format!("`{named}`");
        assert!(
            described.contains(&literal),
            "the search description does not name {literal}: {described}"
        );
    }
}

#[test]
fn the_documented_headers_and_sealed_media_type_are_the_ones_the_code_uses() {
    let spec = spec();
    let schemes = map(&spec, &["components", "securitySchemes"]);
    let mut header_names = BTreeSet::new();
    for (_, scheme) in schemes {
        assert_eq!(
            scheme.as_mapping_get("in").and_then(Yaml::as_str),
            Some("header")
        );
        header_names.insert(
            scheme
                .as_mapping_get("name")
                .and_then(Yaml::as_str)
                .expect("a security scheme names its header")
                .to_owned(),
        );
    }
    assert_eq!(
        header_names,
        BTreeSet::from([AGENT_HEADER.to_owned(), SIGNATURE_HEADER.to_owned()]),
        "a renamed header silently unauthenticates every vendored client"
    );

    let media_types = keys(map(
        &spec,
        &["paths", "/records", "post", "requestBody", "content"],
    ));
    assert!(
        media_types.iter().any(|t| t == envelope::CONTENT_TYPE),
        "a sealed body is announced by its media type, so {:?} must include {}",
        media_types,
        envelope::CONTENT_TYPE
    );
}

#[tokio::test]
async fn no_rebuild_endpoint_is_documented_or_served() {
    // A rebuild walks the whole tree, so no route offers one for its own sake. `POST /erase` is the
    // one request that causes one, because a wrapped share row cannot be retracted any other way;
    // what must stay off the wire is a rebuild a caller can ask for directly.
    for (path, _) in documented().keys() {
        assert!(
            !path.contains("reindex") && !path.contains("sweep"),
            "`{path}` would make a rebuild reachable by request"
        );
    }
    for (method, uri) in [
        ("POST", "/reindex"),
        ("GET", "/reindex"),
        ("POST", "/records/reindex"),
        ("POST", "/sweep"),
    ] {
        let probe = case(method, uri, uri, Some(OPERATOR), "{}", Mode::Stored);
        let (status, _) = call(&probe).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
}
