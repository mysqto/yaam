//! Endpoint wiring.
//!
//! Authentication is a layer over the whole router rather than a check inside each handler, so a
//! route added later is signed by default. It covers the fallback too: an unmatched path must not
//! be a way to reach the service unsigned.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use yaam_contract::{RecordId, SubjectHash};
use yaam_core::bundle;
use yaam_core::pipeline::Accepted;
use yaam_store::query::{Filter, Window};

use crate::auth::{self, Caller, Keyring, Role};
use crate::service::{self, Service};
use crate::{Error, Result};

/// Largest request body the service will buffer.
///
/// The signature covers the whole body, so the body has to be held in memory before anything about
/// it can be trusted; the cap is what stops that being a memory-exhaustion lever. Oversize is
/// permanent — resending the same body cannot help — so it is reported as `422`.
const MAX_BODY_BYTES: usize = 1 << 20;

/// Deadline a bundle request gets when the caller names none.
const DEFAULT_DEADLINE_MS: u64 = 500;

/// Confidence floor for entity history when the caller names none.
///
/// Zero, because the endpoint answers "everything about this entity". Excluding inferred references
/// by default would drop history the caller cannot tell is missing; tightening the floor is the
/// caller's decision to make.
const DEFAULT_MIN_CONFIDENCE: f32 = 0.0;

/// What erasure does not reach.
const RETAINED: &str = "frontmatter, attributes, entity references and timelines are retained";

/// What every handler needs.
#[derive(Clone, Debug)]
pub struct AppState {
    /// `None` resolves the process-wide installation once per request, so a keyring reloaded during
    /// a key roll reaches a router that is already serving.
    fixed: Option<Fixed>,
}

/// An explicitly supplied keyring and service.
#[derive(Clone, Debug)]
struct Fixed {
    keyring: Arc<Keyring>,
    service: Arc<dyn Service>,
}

impl AppState {
    /// State that follows the process-wide installation.
    #[must_use]
    pub fn installed() -> Self {
        Self { fixed: None }
    }

    /// State bound to one keyring and service, for a test or an embedded deployment.
    #[must_use]
    pub fn fixed(keyring: Arc<Keyring>, service: Arc<dyn Service>) -> Self {
        Self {
            fixed: Some(Fixed { keyring, service }),
        }
    }

    /// The keyring this request authenticates against.
    fn keyring(&self) -> Arc<Keyring> {
        self.fixed
            .as_ref()
            .map_or_else(auth::installed_keyring, |fixed| Arc::clone(&fixed.keyring))
    }

    /// The service this request is answered from.
    fn service(&self) -> Arc<dyn Service> {
        self.fixed
            .as_ref()
            .map_or_else(service::installed, |fixed| Arc::clone(&fixed.service))
    }
}

/// Builds the router.
///
/// | Route | Purpose |
/// |---|---|
/// | `POST /records` | Write a record. Idempotent on its identifier. |
/// | `GET /records` | Filtered query. |
/// | `GET /entities/{kind}/{id}` | Everything about one entity. |
/// | `GET /bundle` | Compose context for a request. |
/// | `POST /erase` | Destroy a subject's keys. Operator only. |
pub fn router() -> Router {
    router_with(AppState::installed())
}

/// Builds the router over explicit state.
///
/// There is deliberately no reindex route. A rebuild walks the whole tree, and an endpoint would
/// make that reachable by request — so it stays a command-line operation, which keeps "the index is
/// derived" something an operator asserts rather than something a caller can trigger.
pub fn router_with(state: AppState) -> Router {
    Router::new()
        .route("/records", post(write_record).get(query_records))
        .route("/entities/{kind}/{id}", get(entity_records))
        .route("/bundle", get(compose_bundle))
        .route("/erase", post(erase_subject))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

/// A record and the prose stored as its body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    /// The record itself.
    pub record: yaam_contract::ActionRecord,
    /// Body to store. Defaults to the record's summary, which is the prose that becomes the body
    /// when the caller has nothing longer to add.
    #[serde(default)]
    pub body: Option<String>,
}

/// What a write did.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatus {
    /// First time this identifier was seen.
    Stored,
    /// Already present; nothing changed.
    Duplicate,
    /// Held pending subject resolution.
    Quarantined,
}

/// Answer to a write.
#[derive(Debug, Serialize)]
pub struct WriteResponse {
    /// Identifier the record is addressable by.
    pub record_id: RecordId,
    /// What happened to it.
    pub status: WriteStatus,
}

/// Answer to a read.
#[derive(Debug, Serialize)]
pub struct RecordsResponse {
    /// Matching records, newest first.
    pub records: Vec<RecordId>,
}

/// Filters for a record query.
///
/// Unknown parameters are rejected rather than ignored: a mistyped filter that gets dropped widens
/// the query to everything, and the caller sees a plausible answer to a question it did not ask.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordQuery {
    /// Restrict to one action.
    pub action: Option<String>,
    /// Restrict to one outcome, spelled as the contract serialises it.
    pub outcome: Option<String>,
    /// Restrict to one agent.
    pub agent: Option<String>,
    /// Require a structural attribute, as `key=value`.
    pub attr: Option<String>,
    /// Inclusive start of the window, in server-stamped milliseconds.
    pub from_ms: Option<i64>,
    /// Exclusive end of the window.
    pub to_ms: Option<i64>,
    /// Page size.
    pub limit: Option<u32>,
}

impl RecordQuery {
    /// Turns query parameters into an index filter.
    fn into_filter(self) -> Result<Filter> {
        let attr = match self.attr {
            Some(pair) => Some(
                pair.split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .ok_or_else(|| {
                        Error::Unprocessable(format!("`attr` must be `key=value`, got `{pair}`"))
                    })?,
            ),
            None => None,
        };
        // Half a window is not a narrower query, it is a different one, so supplying the missing
        // bound here would answer a question the caller did not ask.
        let window = match (self.from_ms, self.to_ms) {
            (Some(from_ms), Some(to_ms)) => Some(Window { from_ms, to_ms }),
            (None, None) => None,
            _ => {
                return Err(Error::Unprocessable(
                    "a window needs both `from_ms` and `to_ms`".to_owned(),
                ));
            }
        };
        Ok(Filter {
            action: self.action,
            outcome: self.outcome,
            agent: self.agent,
            attr,
            window,
            limit: self.limit,
        })
    }
}

/// Options for entity history.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityQuery {
    /// Tolerance for inferred references. `1.0` keeps only references read from a structured field.
    pub min_confidence: Option<f32>,
}

/// What a bundle should cover.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleQuery {
    /// Entities to gather history for, as a comma-separated list of `kind:id`.
    pub entity: Option<String>,
    /// Actor whose recent activity is relevant.
    pub actor: Option<String>,
    /// Budget for the whole composition.
    pub deadline_ms: Option<u64>,
}

impl BundleQuery {
    /// Turns query parameters into a composition request.
    fn into_request(self) -> Result<bundle::Request> {
        let mut entities = Vec::new();
        for pair in self.entity.iter().flat_map(|list| list.split(',')) {
            let (kind, id) = pair.split_once(':').ok_or_else(|| {
                Error::Unprocessable(format!("`entity` must be `kind:id`, got `{pair}`"))
            })?;
            entities.push((kind.to_owned(), id.to_owned()));
        }
        Ok(bundle::Request {
            entities,
            actor: self.actor,
            deadline_ms: self.deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS),
        })
    }
}

/// Context assembled for a caller.
#[derive(Debug, Serialize)]
pub struct BundleResponse {
    /// Records judged relevant.
    pub records: Vec<RecordId>,
    /// `true` when a source was unavailable and the bundle is incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
    /// Rough token cost, advisory only.
    pub token_estimate: usize,
}

/// The subject an erasure names.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseRequest {
    /// Keyed pseudonym whose keys are to be destroyed.
    pub subject: SubjectHash,
}

/// What an erasure reached.
#[derive(Debug, Serialize)]
pub struct EraseResponse {
    /// Records whose bodies became unreadable.
    pub bodies_sealed_off: usize,
    /// Keys destroyed, across all epochs.
    pub keys_destroyed: usize,
    /// Quarantined records resolved or discarded as part of this request.
    pub quarantine_settled: usize,
    /// Identifier of the tombstone written.
    pub tombstone_id: String,
    /// What key destruction does not reach, said in the answer so a caller cannot report this as
    /// having deleted everything about the subject.
    pub retained: &'static str,
}

/// Authenticates every request, reads included.
///
/// The body is buffered here because the signature covers it, then put back so the handler sees the
/// request it would have seen anyway.
async fn authenticate(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| {
            Error::Unprocessable(format!(
                "body unreadable or larger than {MAX_BODY_BYTES} bytes"
            ))
        })?;
    let caller = auth::verify_with(&state.keyring(), &parts.headers, &bytes)?;
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

/// Writes one record, attributed to the caller.
async fn write_record(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<(StatusCode, Json<WriteResponse>)> {
    let request: WriteRequest = decode(&body)?;
    auth::authorise_write(&caller, &request.record.agent)?;
    // Validated before the record reaches the pipeline, so the caller is told what is wrong with
    // its record rather than which layer noticed.
    request
        .record
        .validate()
        .map_err(|error| Error::Unprocessable(error.to_string()))?;

    let record_body = request
        .body
        .unwrap_or_else(|| request.record.summary.clone());
    let service = state.service();
    let accepted = blocking(move || service.write(&caller, request.record, &record_body)).await?;

    // A replay is a duplicate, not a conflict: retrying is how a caller recovers from an ambiguous
    // failure, and a `409` would tell it to stop doing the safe thing.
    let (status, id, outcome) = match accepted {
        Accepted::Stored(id) => (StatusCode::CREATED, id, WriteStatus::Stored),
        Accepted::Duplicate(id) => (StatusCode::OK, id, WriteStatus::Duplicate),
        Accepted::Quarantined(id) => (StatusCode::ACCEPTED, id, WriteStatus::Quarantined),
    };
    Ok((
        status,
        Json(WriteResponse {
            record_id: id,
            status: outcome,
        }),
    ))
}

/// Answers a filtered query.
async fn query_records(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(params): Query<RecordQuery>,
) -> Result<Json<RecordsResponse>> {
    let filter = params.into_filter()?;
    let service = state.service();
    let records = blocking(move || service.query(&caller, &filter)).await?;
    Ok(Json(RecordsResponse { records }))
}

/// Answers everything touching one entity.
async fn entity_records(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path((kind, id)): Path<(String, String)>,
    Query(params): Query<EntityQuery>,
) -> Result<Json<RecordsResponse>> {
    let min_confidence = params.min_confidence.unwrap_or(DEFAULT_MIN_CONFIDENCE);
    let service = state.service();
    let records = blocking(move || service.entity(&caller, &kind, &id, min_confidence)).await?;
    Ok(Json(RecordsResponse { records }))
}

/// Composes context for a caller.
async fn compose_bundle(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(params): Query<BundleQuery>,
) -> Result<Json<BundleResponse>> {
    let request = params.into_request()?;
    let service = state.service();
    let bundle = blocking(move || service.bundle(&caller, &request)).await?;
    Ok(Json(BundleResponse {
        records: bundle.records,
        degraded: bundle.degraded,
        omitted: bundle.omitted,
        token_estimate: bundle.token_estimate,
    }))
}

/// Destroys a subject's keys. Operator only.
async fn erase_subject(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<EraseResponse>> {
    // Checked before the body is read: erasure is irreversible, so the role gate is the first thing
    // the request meets.
    auth::require_role(&caller, Role::Operator)?;
    let request: EraseRequest = decode(&body)?;
    let service = state.service();
    let report = blocking(move || service.erase(&caller, &request.subject)).await?;
    Ok(Json(EraseResponse {
        bodies_sealed_off: report.bodies_sealed_off,
        keys_destroyed: report.keys_destroyed,
        quarantine_settled: report.quarantine_settled,
        tombstone_id: report.tombstone_id,
        retained: RETAINED,
    }))
}

/// Reads a JSON request body.
///
/// A body that will not parse is permanent: the caller has to change it, and retrying it unchanged
/// only costs both sides the attempt.
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| Error::Unprocessable(error.to_string()))
}

/// Runs blocking work off the async runtime.
///
/// Every call below reaches the filesystem or `SQLite`; running that on an executor thread stalls
/// unrelated requests. A worker that panicked leaves state nobody can describe, so its failure is
/// reported as transient — retrying is safe, because every write is idempotent on its record id.
async fn blocking<T, F>(work: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::Unavailable("the request handler failed".to_owned()))?
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, header};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{AGENT_HEADER, Credential, SIGNATURE_HEADER};
    use crate::testing::{self, Fake};

    const KEY: &[u8] = b"a-signing-key";
    const READER: &str = "agent-reader";
    const WRITER: &str = "agent-writer";
    const OPERATOR: &str = "agent-operator";

    fn keyring() -> Keyring {
        Keyring::new()
            .with(Credential::new(READER, Role::Reader, KEY))
            .with(Credential::new(WRITER, Role::Writer, KEY))
            .with(Credential::new(OPERATOR, Role::Operator, KEY))
    }

    fn app(fake: &Arc<Fake>) -> Router {
        router_with(AppState::fixed(
            Arc::new(keyring()),
            Arc::clone(fake) as Arc<dyn Service>,
        ))
    }

    /// A request signed by `agent`, or unsigned when `agent` is `None`.
    fn request(method: Method, uri: &str, agent: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(agent) = agent {
            builder = builder
                .header(AGENT_HEADER, agent)
                .header(SIGNATURE_HEADER, auth::sign(KEY, agent, body.as_bytes()));
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    fn get(uri: &str, agent: Option<&str>) -> Request<Body> {
        request(Method::GET, uri, agent, "")
    }

    fn post(uri: &str, agent: Option<&str>, body: &str) -> Request<Body> {
        request(Method::POST, uri, agent, body)
    }

    async fn serve(fake: &Arc<Fake>, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app(fake).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn write_body(agent: &str) -> String {
        let record = testing::record(agent);
        serde_json::json!({ "record": record, "body": "the long form" }).to_string()
    }

    #[tokio::test]
    async fn a_signed_write_is_stored() {
        let fake = Arc::new(Fake::new());
        let (status, body) =
            serve(&fake, post("/records", Some(WRITER), &write_body(WRITER))).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], "stored");
        assert!(body["record_id"].is_string());
        let call = fake.calls().first().cloned().unwrap();
        assert_eq!(call, "write agent-writer agent-writer the long form");
    }

    #[tokio::test]
    async fn a_write_falls_back_to_the_summary_as_its_body() {
        let fake = Arc::new(Fake::new());
        let record = testing::record(WRITER);
        let summary = record.summary.clone();
        let body = serde_json::json!({ "record": record }).to_string();

        let (status, _) = serve(&fake, post("/records", Some(WRITER), &body)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(fake.calls()[0].ends_with(&summary), "{:?}", fake.calls());
    }

    #[tokio::test]
    async fn a_replayed_write_is_a_duplicate_not_a_conflict() {
        let id = RecordId::generate();
        let fake = Arc::new(Fake::new().answering(Accepted::Duplicate(id.clone())));
        let (status, body) =
            serve(&fake, post("/records", Some(WRITER), &write_body(WRITER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "duplicate");
        assert_eq!(body["record_id"], id.as_str());
    }

    #[tokio::test]
    async fn a_quarantined_write_is_accepted_not_rejected() {
        let fake = Arc::new(Fake::new().answering(Accepted::Quarantined(RecordId::generate())));
        let (status, body) =
            serve(&fake, post("/records", Some(WRITER), &write_body(WRITER))).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "quarantined");
    }

    #[tokio::test]
    async fn attributing_a_record_to_another_agent_is_refused() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, post("/records", Some(WRITER), &write_body(READER))).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            fake.calls().is_empty(),
            "a forged attribution must not reach the pipeline"
        );
    }

    #[tokio::test]
    async fn a_reader_may_not_write() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, post("/records", Some(READER), &write_body(READER))).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn an_unsigned_request_is_refused_on_every_route() {
        let fake = Arc::new(Fake::new());
        let unsigned = [
            post("/records", None, &write_body(WRITER)),
            // The one people assume is public. Visibility is per caller, so a read has to know who
            // is asking as much as a write does.
            get("/records", None),
            get("/entities/ticket/T-1", None),
            get("/bundle", None),
            post("/erase", None, "{}"),
        ];
        for request in unsigned {
            let (status, _) = serve(&fake, request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_body_tampered_with_in_flight_is_refused() {
        let fake = Arc::new(Fake::new());
        let mut request = post("/records", Some(WRITER), &write_body(WRITER));
        // Same shape, different record id: the signature was over the bytes, not the shape.
        *request.body_mut() = Body::from(write_body(WRITER));

        let (status, _) = serve(&fake, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_query_carries_its_filters_to_the_index() {
        let held = vec![RecordId::generate()];
        let fake = Arc::new(Fake::new().holding(held.clone()));
        let (status, body) = serve(
            &fake,
            get(
                "/records?action=deploy&outcome=failure&agent=agent-writer&attr=order_ref%3DA-9&from_ms=10&to_ms=20&limit=5",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["records"][0], held[0].as_str());
        let call = &fake.calls()[0];
        for expected in [
            "\"deploy\"",
            "\"failure\"",
            "\"order_ref\"",
            "\"A-9\"",
            "from_ms: 10",
            "to_ms: 20",
            "limit: Some(5)",
        ] {
            assert!(call.contains(expected), "{expected} missing from {call}");
        }
    }

    #[tokio::test]
    async fn half_a_window_is_refused() {
        let fake = Arc::new(Fake::new());
        let (status, body) = serve(&fake, get("/records?from_ms=10", Some(READER))).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().unwrap().contains("window"),
            "{body:?}"
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_malformed_attribute_filter_is_refused() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/records?attr=order_ref", Some(READER))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn a_mistyped_filter_is_refused_rather_than_widened() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/records?actionn=deploy", Some(READER))).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            fake.calls().is_empty(),
            "a filter nobody understood must not become a query for everything"
        );
    }

    #[tokio::test]
    async fn entity_history_defaults_to_every_reference() {
        let fake = Arc::new(Fake::new().holding(vec![RecordId::generate()]));
        let (status, body) = serve(&fake, get("/entities/ticket/T-1", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["records"].as_array().unwrap().len(), 1);
        assert_eq!(fake.calls()[0], "entity agent-reader ticket T-1 0");
    }

    #[tokio::test]
    async fn entity_history_takes_a_confidence_floor() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get("/entities/ticket/T-1?min_confidence=1", Some(READER)),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(fake.calls()[0], "entity agent-reader ticket T-1 1");
    }

    #[tokio::test]
    async fn a_bundle_reports_what_it_left_out() {
        let fake = Arc::new(Fake::new().holding(vec![RecordId::generate()]));
        let (status, body) = serve(
            &fake,
            get(
                "/bundle?entity=ticket:T-1,order_ref:A-9&actor=agent-writer&deadline_ms=25",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["degraded"], true);
        assert_eq!(body["omitted"][0], "one source was slow");
        assert_eq!(body["token_estimate"], 42);
        let call = &fake.calls()[0];
        assert!(
            call.contains("deadline_ms: 25") && call.contains("\"T-1\""),
            "{call}"
        );
    }

    #[tokio::test]
    async fn a_bundle_with_no_entities_uses_the_default_deadline() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/bundle", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            fake.calls()[0].contains(&format!("deadline_ms: {DEFAULT_DEADLINE_MS}")),
            "{:?}",
            fake.calls()
        );
    }

    #[tokio::test]
    async fn a_malformed_entity_in_a_bundle_is_refused() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/bundle?entity=ticket", Some(READER))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn erase_is_operator_only() {
        let subject = testing::subject();
        let body = serde_json::json!({ "subject": subject.as_str() }).to_string();

        for agent in [READER, WRITER] {
            let fake = Arc::new(Fake::new());
            let (status, _) = serve(&fake, post("/erase", Some(agent), &body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{agent} must not erase");
            assert!(fake.calls().is_empty());
        }

        let fake = Arc::new(Fake::new());
        let (status, answer) = serve(&fake, post("/erase", Some(OPERATOR), &body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["keys_destroyed"], 2);
        assert_eq!(answer["tombstone_id"], "tombstone-1");
        // Said in the answer, because an erasure reported as deleting everything is reported wrongly.
        assert!(answer["retained"].as_str().unwrap().contains("timelines"));
        assert_eq!(
            fake.calls()[0],
            format!("erase agent-operator {}", subject.as_str())
        );
    }

    #[tokio::test]
    async fn an_erasure_naming_no_valid_subject_is_refused() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            post("/erase", Some(OPERATOR), "{\"subject\":\"not-a-hash\"}"),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn no_route_triggers_a_reindex() {
        let fake = Arc::new(Fake::new());
        // A rebuild walks the whole tree. It stays a command-line operation, so no request — signed
        // by an operator or otherwise — can start one.
        let attempts = [
            post("/reindex", Some(OPERATOR), "{}"),
            get("/reindex", Some(OPERATOR)),
            post("/records/reindex", Some(OPERATOR), "{}"),
            post("/sweep", Some(OPERATOR), "{}"),
        ];
        for attempt in attempts {
            let (status, _) = serve(&fake, attempt).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_record_that_violates_the_contract_is_permanent() {
        let fake = Arc::new(Fake::new());
        let mut record = testing::record(WRITER);
        // Subject-derived with no subject: the record claims erasability its body cannot deliver,
        // and no retry of the same bytes will fix it.
        record.data_class = yaam_contract::DataClass::SubjectDerived;
        let body = serde_json::json!({ "record": record }).to_string();

        let (status, answer) = serve(&fake, post("/records", Some(WRITER), &body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(answer["error"].as_str().unwrap().contains("subject"));
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_record_is_permanent() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, post("/records", Some(WRITER), "{\"record\":1}")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn an_oversize_body_is_permanent() {
        let fake = Arc::new(Fake::new());
        let body = "x".repeat(MAX_BODY_BYTES + 1);
        let (status, _) = serve(&fake, post("/records", Some(WRITER), &body)).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_service_refusal_reaches_the_caller_as_transient() {
        let fake = Arc::new(Fake::new().refusing("index reopening"));
        let (status, body) = serve(&fake, get("/records", Some(READER))).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["error"].as_str().unwrap().contains("index reopening"));
    }

    #[tokio::test]
    async fn a_panicking_handler_is_reported_as_transient() {
        let fake = Arc::new(Fake::new().panicking());
        let (status, _) = serve(&fake, get("/records", Some(READER))).await;

        // Retrying is safe — every write is keyed — so the caller is told to retry rather than to
        // discard a record that may be perfectly good.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn the_ambient_router_serves_the_installed_keyring_and_service() {
        let fake = Arc::new(Fake::new().holding(vec![RecordId::generate()]));
        auth::install_keyring(keyring());
        service::install(Arc::clone(&fake) as Arc<dyn Service>);

        let signed = router()
            .oneshot(get("/records", Some(READER)))
            .await
            .unwrap();
        assert_eq!(signed.status(), StatusCode::OK);

        let unsigned = router().oneshot(get("/records", None)).await.unwrap();
        assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);

        let missing = router()
            .oneshot(get("/reindex", Some(OPERATOR)))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }
}
