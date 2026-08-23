//! Endpoint wiring.
//!
//! Authentication is a layer over the whole router rather than a check inside each handler, so a
//! route added later is signed by default. It covers the fallback too: an unmatched path must not
//! be a way to reach the service unsigned.

use std::borrow::Cow;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use yaam_contract::{RecordId, RecordStructure, SubjectHash};
use yaam_core::bundle;
use yaam_core::pipeline::Accepted;
use yaam_crypto::envelope;
use yaam_store::query::{Filter, Window};

use crate::auth::{self, Caller, Keyring, Role};
use crate::service::Service;
use crate::{Error, Result};

pub use yaam_contract::request::WriteRequest;

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
///
/// Passed in, never resolved from process state: a router that reached for an ambient keyring or
/// service could not be pointed at two deployments in one process, and a request whose
/// configuration is invisible at the call site is one nobody can check.
#[derive(Clone, Debug)]
pub struct AppState {
    /// Callers this service authenticates.
    keyring: Arc<Keyring>,
    /// What answers the requests.
    service: Arc<dyn Service>,
    /// Secret half of the key sidecars seal to. `None` refuses a sealed body rather than guessing
    /// at it.
    unseal_key: Option<Arc<Vec<u8>>>,
}

impl AppState {
    /// State bound to one keyring and one service.
    #[must_use]
    pub fn new(keyring: Arc<Keyring>, service: Arc<dyn Service>) -> Self {
        Self {
            keyring,
            service,
            unseal_key: None,
        }
    }

    /// Adds the secret half of the key sidecars seal to.
    ///
    /// Without it this service accepts plain JSON only. A sidecar seals to the public half before it
    /// writes the same bytes to its own spool — it can neither read nor reshape what it queued — so
    /// this is the half that lets the service read a record at all.
    #[must_use]
    pub fn unsealing_with(mut self, secret_key: impl Into<Vec<u8>>) -> Self {
        self.unseal_key = Some(Arc::new(secret_key.into()));
        self
    }

    /// The keyring this request authenticates against.
    fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The service this request is answered from.
    fn service(&self) -> Arc<dyn Service> {
        Arc::clone(&self.service)
    }

    /// The request body, opened if it arrived sealed.
    ///
    /// A body that will not open is reported as transient, which is the direction that keeps
    /// history: the bytes are unreadable here, so the service cannot tell a corrupt envelope from a
    /// service configured with the wrong key — and a permanent refusal would have every sidecar
    /// discard perfectly good records over an operator's mistake. A wedged spool is visible and
    /// recoverable; a dropped record is neither.
    fn opened<'b>(&self, headers: &HeaderMap, body: &'b [u8]) -> Result<Cow<'b, [u8]>> {
        let sealed = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with(envelope::CONTENT_TYPE));
        if !sealed {
            return Ok(Cow::Borrowed(body));
        }
        let key = self.unseal_key.as_ref().ok_or_else(|| {
            Error::Unavailable("this service holds no key for sealed bodies".to_owned())
        })?;
        envelope::open(key, body)
            .map(Cow::Owned)
            .map_err(|error| Error::Unavailable(format!("sealed body would not open: {error}")))
    }
}

/// Builds the router over its state.
///
/// | Route | Purpose |
/// |---|---|
/// | `POST /records` | Write a record. Idempotent on its identifier. |
/// | `GET /records` | Filtered query. |
/// | `GET /search` | Which records mention something. Full text over bodies, structure back. |
/// | `GET /entities/{kind}/{id}` | One page of an entity's history, newest first. |
/// | `GET /bundle` | Compose context for a request. |
/// | `POST /erase` | Destroy a subject's keys. Operator only, and rebuilds the index. |
///
/// There is deliberately no reindex route: a rebuild walks the whole tree, so it stays a
/// command-line operation (`yaam reindex`) rather than something any caller can name.
///
/// One request does rebuild the index, and it is `POST /erase`. The derived index holds a wrapped
/// key share per subject and no row can be un-written, so retracting one means rebuilding from the
/// erased tree; [`yaam_core::erase::erase_subject`] does it synchronously, before the answer comes
/// back. It needs the operator role, and it costs the whole tree — which is why it is documented as
/// expensive rather than described as impossible.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/records", post(write_record).get(query_records))
        .route("/search", get(search_records))
        .route("/entities/{kind}/{id}", get(entity_records))
        .route("/bundle", get(compose_bundle))
        .route("/erase", post(erase_subject))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

/// What a write did.
#[derive(Debug, Serialize, PartialEq, Eq, JsonSchema)]
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
#[derive(Debug, Serialize, JsonSchema)]
pub struct WriteResponse {
    /// Identifier the record is addressable by.
    pub record_id: RecordId,
    /// What happened to it.
    pub status: WriteStatus,
}

/// Answer to a read.
///
/// Structure, not identifiers. A read used to answer with the ids of the records it matched, which
/// left the caller holding names it had no way to resolve — the only endpoint that opens a record is
/// operator-only by design. Each entry is the record's stored frontmatter and carries no body,
/// whether that body was sealed or plaintext.
#[derive(Debug, Serialize, JsonSchema)]
pub struct RecordsResponse {
    /// Matching records, newest first.
    pub records: Vec<RecordStructure>,
    /// Rough token cost of this answer, advisory only.
    ///
    /// Here for the same reason it is on a bundle: these reads return the same rows, and a caller
    /// paging them had no way to size an answer before consuming it.
    pub token_estimate: usize,
}

impl RecordsResponse {
    /// Wraps records and measures what returning them costs.
    fn new(records: Vec<RecordStructure>) -> Self {
        let token_estimate = yaam_contract::structure::estimate_tokens(&records);
        Self {
            records,
            token_estimate,
        }
    }
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
    /// Page size. Absent means the index's default cap, not every match.
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
        // The scope is deliberately not a query parameter: what a caller may see comes from the
        // credential the signature proved, and is filled in from it below.
        Ok(Filter {
            action: self.action,
            outcome: self.outcome,
            agent: self.agent,
            attr,
            window,
            limit: self.limit,
            ..Filter::default()
        })
    }
}

/// What a full-text read is looking for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    /// The needle, as a full-text match expression. Required: there is no spelling of "search for
    /// nothing" that a caller means, and defaulting one would answer a question nobody asked.
    pub q: String,
    /// Page size. Absent means the index's default cap, not every match — the same rule the
    /// filtered query follows, and it bites harder here: the matches examined are a multiple of
    /// this, so a page size is what bounds the work as well as the answer.
    pub limit: Option<u32>,
}

/// Options for entity history.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityQuery {
    /// Tolerance for inferred references. `1.0` keeps only references read from a structured field.
    pub min_confidence: Option<f32>,
    /// Page size. Absent means the index's default cap, not every reference — the same rule the
    /// filtered query follows, for the same reason: a busy entity's history is unbounded, and this
    /// endpoint used to answer with all of it.
    pub limit: Option<u32>,
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
    /// Most records to return. Absent means the service's own cap.
    ///
    /// Worth setting: the caller that wants five records is charged for five rather than for the
    /// cap, because this reaches the source reads and not merely the result.
    pub limit: Option<u32>,
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
            // Clamped to the service cap by the composer, so saturating here loses nothing.
            limit: self.limit.map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
            ..bundle::Request::default()
        })
    }
}

/// Context assembled for a caller.
#[derive(Debug, Serialize, JsonSchema)]
pub struct BundleResponse {
    /// Records judged relevant, each as its stored structure and never its body.
    pub records: Vec<RecordStructure>,
    /// `true` when a source was unavailable and the bundle is incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
    /// Rough token cost of the structure being returned, advisory only.
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
    /// Identifier of the tombstone written: `tomb-` followed by a ULID, not a bare ULID.
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
    // The request target as it arrived, query string and all: it is in the signature, so a captured
    // read cannot be replayed with different filters.
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    let caller = auth::verify(
        state.keyring(),
        parts.method.as_str(),
        &target,
        &parts.headers,
        &bytes,
    )?;
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

/// Writes one record, attributed to the caller.
async fn write_record(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<WriteResponse>)> {
    let request: WriteRequest = decode(&state.opened(&headers, &body)?)?;
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
    Ok(Json(RecordsResponse::new(records)))
}

/// Answers which records mention something.
///
/// The needle is the caller's and the answer is structure: this is a read like the others, and the
/// prose it matched on is no more returnable here than anywhere else.
async fn search_records(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<RecordsResponse>> {
    let service = state.service();
    let records = blocking(move || service.search(&caller, &params.q, params.limit)).await?;
    Ok(Json(RecordsResponse::new(records)))
}

/// Answers one page of what touches one entity.
async fn entity_records(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path((kind, id)): Path<(String, String)>,
    Query(params): Query<EntityQuery>,
) -> Result<Json<RecordsResponse>> {
    let min_confidence = params.min_confidence.unwrap_or(DEFAULT_MIN_CONFIDENCE);
    let limit = params.limit;
    let service = state.service();
    let records =
        blocking(move || service.entity(&caller, &kind, &id, min_confidence, limit)).await?;
    Ok(Json(RecordsResponse::new(records)))
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

    /// The service secret a sidecar's envelopes are sealed to, fixed so a test needs no fixture.
    const SERVICE_SECRET: &[u8; 32] = &[7u8; 32];

    /// Public half of [`SERVICE_SECRET`], derived rather than written down twice.
    fn service_public() -> [u8; 32] {
        envelope::public_key(SERVICE_SECRET).expect("a 32-byte secret")
    }

    /// A signed `POST /records` carrying a sealed body, as a sidecar sends it.
    fn sealed_post(agent: &str, sealed: &[u8]) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/records")
            .header(header::CONTENT_TYPE, envelope::CONTENT_TYPE)
            .header(AGENT_HEADER, agent)
            .header(
                SIGNATURE_HEADER,
                auth::sign(KEY, "POST", "/records", agent, sealed),
            )
            .body(Body::from(sealed.to_vec()))
            .unwrap()
    }

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
        router(state(fake))
    }

    /// State over a fake service, able to open what a sidecar seals.
    fn state(fake: &Arc<Fake>) -> AppState {
        AppState::new(Arc::new(keyring()), Arc::clone(fake) as Arc<dyn Service>)
            .unsealing_with(SERVICE_SECRET.to_vec())
    }

    /// A request signed by `agent`, or unsigned when `agent` is `None`.
    fn request(method: &Method, uri: &str, agent: Option<&str>, body: &str) -> Request<Body> {
        let method_name = method.as_str();
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(agent) = agent {
            builder = builder.header(AGENT_HEADER, agent).header(
                SIGNATURE_HEADER,
                auth::sign(KEY, method_name, uri, agent, body.as_bytes()),
            );
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    fn get(uri: &str, agent: Option<&str>) -> Request<Body> {
        request(&Method::GET, uri, agent, "")
    }

    fn post(uri: &str, agent: Option<&str>, body: &str) -> Request<Body> {
        request(&Method::POST, uri, agent, body)
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
    async fn a_field_the_record_does_not_declare_is_refused_before_the_write() {
        // Dropping it would store a record the caller did not describe, and no later read could
        // tell. The wrapper always refused a stray field at the top level; this is the same
        // mistake one level down, where the mistyped field is the record itself.
        let fake = Arc::new(Fake::new());
        let mut record = serde_json::to_value(testing::record(WRITER)).expect("serialises");
        record
            .as_object_mut()
            .expect("an object")
            .insert("nonsense".to_owned(), serde_json::json!(1));
        let body = serde_json::json!({ "record": record }).to_string();

        let (status, answer) = serve(&fake, post("/records", Some(WRITER), &body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            answer["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unknown field"),
            "{answer:?}"
        );
        assert!(
            fake.calls().is_empty(),
            "nothing understood, nothing stored"
        );
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
            get("/search?q=shards", None),
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
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (status, body) = serve(
            &fake,
            get(
                "/records?action=deploy&outcome=failure&agent=agent-writer&attr=order_ref%3DA-9&from_ms=10&to_ms=20&limit=5",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        // Structure, not an identifier a caller would have to ask about again.
        assert_eq!(body["records"][0]["record_id"], held[0].record_id.as_str());
        assert_eq!(body["records"][0]["action"], "deploy");
        assert!(body["records"][0].get("summary").is_none(), "{body}");
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
    async fn a_search_carries_its_needle_and_page_size_to_the_index() {
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (status, body) = serve(&fake, get("/search?q=shards&limit=5", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(fake.calls()[0], "search agent-reader shards Some(5)");
        // Structure, like every other read: the needle reached the prose and the answer does not
        // carry it.
        assert_eq!(body["records"][0]["record_id"], held[0].record_id.as_str());
        assert!(body["records"][0].get("summary").is_none(), "{body}");
        assert!(!body.to_string().contains("rolled out"), "{body}");
    }

    #[tokio::test]
    async fn a_search_that_names_no_page_size_leaves_the_cap_to_the_index() {
        // `None` rather than a number chosen here: the default page size is a property of what a row
        // costs, and the index is where that is decided for every read.
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/search?q=shards", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(fake.calls()[0], "search agent-reader shards None");
    }

    #[tokio::test]
    async fn a_search_with_no_needle_is_refused_rather_than_answered() {
        // A search for nothing is not a search for everything. Absent is refused before a handler
        // runs, like any unparseable query string.
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/search", Some(READER))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = serve(&fake, get("/search?q=shards&needle=x", Some(READER))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(fake.calls().is_empty());
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
    async fn a_rejected_query_string_answers_outside_the_json_error_shape() {
        // The one failure a client cannot parse as `{"error": …}`: the query string is rejected
        // before any handler runs, so the body is plain text. A retry policy written against the
        // JSON shape has to know that, which is why the status table says so.
        let fake = Arc::new(Fake::new());
        let response = app(&fake)
            .oneshot(get("/records?actionn=deploy", Some(READER)))
            .await
            .expect("the router answers");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn entity_history_defaults_to_every_reference_and_one_page() {
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (status, body) = serve(&fake, get("/entities/ticket/T-1", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["records"].as_array().unwrap().len(), 1);
        // Every *reference*, but not every row: an absent `limit` reaches the index as `None`, which
        // is its default cap and not the unbounded read.
        assert_eq!(fake.calls()[0], "entity agent-reader ticket T-1 0 None");
    }

    #[tokio::test]
    async fn a_bundle_passes_its_limit_through_to_the_composer() {
        // The flag has to reach the composer, not merely parse. A limit accepted and dropped is
        // worse than no limit: the caller is told it was honoured.
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get("/bundle?entity=ticket:T-1&limit=5", Some(READER)),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            fake.calls()[0].contains("limit: Some(5)"),
            "the composer was called as {:?}",
            fake.calls()[0]
        );
    }

    #[tokio::test]
    async fn a_query_reports_what_its_answer_costs() {
        // A bundle says what it costs; these reads hand back the same rows and used to say nothing,
        // so a caller paging them could not size an answer before consuming it.
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (_, body) = serve(&fake, get("/records", Some(READER))).await;

        let records: Vec<RecordStructure> =
            serde_json::from_value(body["records"].clone()).unwrap();
        assert_eq!(
            body["token_estimate"].as_u64().unwrap(),
            yaam_contract::structure::estimate_tokens(&records) as u64,
            "the estimate must measure the rows actually returned"
        );
        assert!(body["token_estimate"].as_u64().unwrap() > 0);
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
        assert_eq!(fake.calls()[0], "entity agent-reader ticket T-1 1 None");
    }

    #[tokio::test]
    async fn entity_history_takes_a_page_size() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/entities/ticket/T-1?limit=5", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(fake.calls()[0], "entity agent-reader ticket T-1 0 Some(5)");
    }

    #[tokio::test]
    async fn a_bundle_reports_what_it_left_out() {
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
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
        assert_eq!(answer["tombstone_id"], "tomb-01ARZ3NDEKTSV4RRFFQ69G5FC7");
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
    async fn a_signature_for_one_endpoint_is_refused_on_another() {
        let fake = Arc::new(Fake::new());
        let body = write_body(WRITER);
        // Captured from a write, replayed at erasure: same agent, same key, same body.
        let stolen = auth::sign(KEY, "POST", "/records", WRITER, body.as_bytes());
        let replayed = Request::builder()
            .method(Method::POST)
            .uri("/erase")
            .header(AGENT_HEADER, WRITER)
            .header(SIGNATURE_HEADER, stolen)
            .body(Body::from(body))
            .unwrap();

        let (status, _) = serve(&fake, replayed).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_query_signature_cannot_be_replayed_with_other_filters() {
        let fake = Arc::new(Fake::new());
        let signed = get("/records?agent=agent-writer", Some(READER));
        let signature = signed
            .headers()
            .get(SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let widened = Request::builder()
            .method(Method::GET)
            .uri("/records")
            .header(AGENT_HEADER, READER)
            .header(SIGNATURE_HEADER, signature)
            .body(Body::empty())
            .unwrap();

        let (status, _) = serve(&fake, widened).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a read's filters are its meaning, so they are signed too"
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn a_sealed_write_is_opened_and_stored() {
        let fake = Arc::new(Fake::new());
        let sealed = envelope::seal(&service_public(), write_body(WRITER).as_bytes()).unwrap();
        let (status, body) = serve(&fake, sealed_post(WRITER, &sealed)).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], "stored");
        assert!(fake.calls()[0].starts_with("write agent-writer agent-writer"));
    }

    #[tokio::test]
    async fn a_sealed_body_this_service_cannot_open_is_transient() {
        let fake = Arc::new(Fake::new());
        let sealed = envelope::seal(&service_public(), write_body(WRITER).as_bytes()).unwrap();

        // A service with no key at all, and a body sealed to somebody else's: neither says the
        // record is bad, so neither may tell a sidecar to throw it away.
        let keyless = router(AppState::new(
            Arc::new(keyring()),
            Arc::clone(&fake) as Arc<dyn Service>,
        ));
        let response = keyless.oneshot(sealed_post(WRITER, &sealed)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let elsewhere = envelope::seal(&envelope::generate_keypair().1, b"{}").unwrap();
        let (status, _) = serve(&fake, sealed_post(WRITER, &elsewhere)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(fake.calls().is_empty());
    }
}
