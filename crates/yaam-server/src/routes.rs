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
use yaam_store::query::{self, Filter, Link, Traversal, Window};

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
/// | `GET /correlate` | Which records of one shape were followed by records of another. |
/// | `GET /linked/{kind}/{id}` | What else is connected to one entity, and by which records. |
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
        .route("/correlate", get(correlate_records))
        .route("/linked/{kind}/{id}", get(linked_entities))
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

/// One attribute filter, split at the first `=`, or the refusal naming the parameter it came from.
///
/// Shared by the three parameters that spell one — `attr`, `left.attr` and `right.attr` — because
/// which of them the caller mistyped is the whole content of the refusal. A local copy per handler
/// would name whichever parameter the copy was written for.
fn attr_filter(spec: Option<String>, name: &str) -> Result<Option<(String, String)>> {
    match spec {
        Some(pair) => Ok(Some(
            pair.split_once('=')
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .ok_or_else(|| {
                    Error::Unprocessable(format!("`{name}` must be `key=value`, got `{pair}`"))
                })?,
        )),
        None => Ok(None),
    }
}

impl RecordQuery {
    /// Turns query parameters into an index filter.
    fn into_filter(self) -> Result<Filter> {
        let attr = attr_filter(self.attr, "attr")?;
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

/// One correlated pair: a record, and a record that followed it inside the window.
///
/// Two structures rather than two identifiers, and a pair rather than a flat set. Which decline went
/// with which deploy *is* the answer — a flat list of both sides is what `GET /records` already gives
/// a caller, and it cannot say what happened near what once either side matches more than once.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CorrelatedPair {
    /// The record the question was asked about: the earlier of the two.
    pub left: RecordStructure,
    /// The record that followed it, at or after `left` and no later than `within_ms` after.
    pub right: RecordStructure,
}

/// Answer to a correlation.
///
/// Its own shape rather than a [`RecordsResponse`], because the pairing is the answer: flattened into
/// one `records` list it would be a set of records the caller has to re-join by timestamp, which is
/// the arithmetic this endpoint exists to stop doing by hand.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CorrelationsResponse {
    /// Matching pairs. Newest left record first, and within one left record its right ones in the
    /// order they happened.
    pub pairs: Vec<CorrelatedPair>,
    /// Rough token cost of this answer, advisory only.
    ///
    /// Measured over both halves of every pair, so a left record matching several right ones is
    /// counted once per pair — which is what returning it once per pair costs.
    pub token_estimate: usize,
}

impl CorrelationsResponse {
    /// Wraps pairs and measures what returning them costs.
    fn new(pairs: Vec<(RecordStructure, RecordStructure)>) -> Self {
        // Both halves of every pair, through the same measurement every other read uses: a left
        // record returned in three pairs is counted three times, because that is what returning it
        // three times costs the caller.
        let token_estimate = yaam_contract::structure::estimate_tokens(
            pairs.iter().flat_map(|(left, right)| [left, right]),
        );
        Self {
            pairs: pairs
                .into_iter()
                .map(|(left, right)| CorrelatedPair { left, right })
                .collect(),
            token_estimate,
        }
    }
}

/// The two halves of a correlation, and how near they have to be.
///
/// Two filters in one request, spelled `left.` and `right.` — the same names `GET /records` accepts,
/// prefixed by which side of the join they constrain. Packing a side into one value (`left=action:…`)
/// was the alternative and is worse for the reason this struct is closed: a typo inside a packed
/// value cannot be refused, and a filter that got dropped widens that side of the join to everything.
///
/// The window is `left.`-prefixed and required, and there is deliberately no `right.from_ms`: the
/// right side's window is the left side's plus `within_ms`, computed by the join. A second window
/// would be a second answer to the same question, and a caller that made the two disagree would get
/// an empty page for a reason nothing in the request shows.
///
/// `limit` carries no prefix because it caps *pairs* rather than either side's rows, and a
/// `right.limit` is refused rather than accepted-and-ignored: a page size on the right of a join
/// means nothing, and a parameter that silently does nothing is worse than one that is not there.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelateQuery {
    /// Restrict the left side to one action.
    #[serde(rename = "left.action")]
    pub left_action: Option<String>,
    /// Restrict the left side to one outcome, spelled as the contract serialises it.
    #[serde(rename = "left.outcome")]
    pub left_outcome: Option<String>,
    /// Restrict the left side to one agent.
    #[serde(rename = "left.agent")]
    pub left_agent: Option<String>,
    /// Require a structural attribute on the left side, as `key=value`.
    #[serde(rename = "left.attr")]
    pub left_attr: Option<String>,
    /// Inclusive start of the window the left side is searched in. Required.
    #[serde(rename = "left.from_ms")]
    pub left_from_ms: Option<i64>,
    /// Exclusive end of that window. Required.
    #[serde(rename = "left.to_ms")]
    pub left_to_ms: Option<i64>,
    /// Restrict the right side to one action.
    #[serde(rename = "right.action")]
    pub right_action: Option<String>,
    /// Restrict the right side to one outcome.
    #[serde(rename = "right.outcome")]
    pub right_outcome: Option<String>,
    /// Restrict the right side to one agent.
    #[serde(rename = "right.agent")]
    pub right_agent: Option<String>,
    /// Require a structural attribute on the right side, as `key=value`.
    #[serde(rename = "right.attr")]
    pub right_attr: Option<String>,
    /// How long after a left record a right one still counts, in milliseconds. Required.
    pub within_ms: i64,
    /// Most pairs to return. Absent means the index's own pair cap, not every pair.
    pub limit: Option<u32>,
}

impl CorrelateQuery {
    /// Turns query parameters into the two filters and the nearness the join takes.
    ///
    /// Both refusals happen here rather than at the index, because both are the caller's to fix and
    /// neither is visible in an empty answer.
    fn into_join(self) -> Result<(Filter, Filter, i64)> {
        // Required, unlike every other window on this service. A correlation is a join whose plan
        // decides its cost, and the left window is the only parameter that bounds the side the plan
        // drives from: without it the answer is "the most recent pairs in the store", which moves as
        // records arrive and is the implicit "recent" this query deliberately does not have.
        let window = match (self.left_from_ms, self.left_to_ms) {
            (Some(from_ms), Some(to_ms)) => Window { from_ms, to_ms },
            _ => {
                return Err(Error::Unprocessable(
                    "a correlation needs both `left.from_ms` and `left.to_ms`: the window bounds \
                     the side the join is driven from, and there is no implicit `recent`"
                        .to_owned(),
                ));
            }
        };
        // A negative nearness asks for a right record before the left one, which this join cannot
        // express: it is directional, and the way to ask "what came before" is to swap the sides.
        // Refused rather than answered empty, because an empty page reads as "nothing happened".
        if self.within_ms < 0 {
            return Err(Error::Unprocessable(format!(
                "`within_ms` is {} and the join is directional: a right record is at or after its \
                 left one, so ask about what came before by swapping the two sides",
                self.within_ms
            )));
        }
        // The page goes on the left filter, which is where the index reads a pair cap from. The
        // right side carries none: it is not a page, and one there would silently do nothing.
        let left = Filter {
            action: self.left_action,
            outcome: self.left_outcome,
            agent: self.left_agent,
            attr: attr_filter(self.left_attr, "left.attr")?,
            window: Some(window),
            limit: self.limit,
            ..Filter::default()
        };
        let right = Filter {
            action: self.right_action,
            outcome: self.right_outcome,
            agent: self.right_agent,
            attr: attr_filter(self.right_attr, "right.attr")?,
            ..Filter::default()
        };
        Ok((left, right, self.within_ms))
    }
}

/// One end of a link: the entity, and nothing about the record that named it.
///
/// Not an `EntityRef`. A reference carries a role and a confidence because it is one record's claim
/// about one entity; the ends of a link are not claims, and putting a role here would have attached
/// whichever record was read last to an entity two records away.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LinkedEntity {
    /// Entity kind, as the deployment configures it.
    pub kind: String,
    /// Canonical identifier within the kind.
    pub id: String,
}

/// One edge: two entities, and the record that names both.
///
/// The record is why this is an answer rather than a hint. An edge list of bare identifiers would
/// say *that* two things are connected and never *why*, leaving the caller a read per edge to find
/// out — and a follow-up read is where the scope predicate gets forgotten, which at a graph's worth
/// of edges is a great many chances to forget it.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LinkedEdge {
    /// The entity this edge was reached from: the seed at hop 1, a hop-1 neighbour beyond that.
    pub from: LinkedEntity,
    /// The entity this edge reaches.
    pub to: LinkedEntity,
    /// How many records deep this edge sits. `1` is a record the seed itself is named by.
    pub hop: u32,
    /// What this edge is worth relative to a hop-1 one, attenuated per hop.
    ///
    /// Stated rather than left to the caller: a client merging these with any other signal needs the
    /// exchange rate between a near edge and a far one, and one that had to guess would invent its
    /// own and disagree with every other client.
    pub score: f32,
    /// The weaker of the two references the record makes, so an edge is never reported as stronger
    /// than the worse half of its own evidence.
    pub confidence: f32,
    /// The record naming both ends, as its stored structure and never its body.
    pub via: RecordStructure,
}

/// An entity the traversal reached and refused to walk through.
///
/// Here because a short answer has two causes that call for opposite next moves: nothing else is
/// connected, or everything is and this is the node it all runs through. The same reason a bundle
/// names what it omitted instead of quietly returning less.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Corridor {
    /// Entity kind.
    pub kind: String,
    /// Canonical identifier.
    pub id: String,
    /// References this entity carries inside the window, counted no further than one past
    /// `max_degree` — so this is a floor on how busy it is, not a census.
    pub degree: u32,
}

/// Answer to a traversal.
///
/// Its own shape rather than a [`RecordsResponse`], for the reason a correlation has its own: the
/// structure of the answer *is* the answer. Flattened into a list of records it would be a set the
/// caller has to re-join into a graph, which is the work this endpoint exists to stop doing by hand,
/// and the hop and the corridor refusals would have nowhere to live at all.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LinksResponse {
    /// Edges, nearest hop first and newest evidence first within a hop.
    pub edges: Vec<LinkedEdge>,
    /// Entities reached and not traversed through, because the corridor rule refused them.
    ///
    /// Derived from the edges actually returned, so a page cut short by `limit` may not name every
    /// corridor the traversal refused. That bites less than it reads: edges arrive nearest-hop
    /// first, and the nodes whose degree can stop a traversal are the near ones, so a truncated page
    /// loses far edges before it loses a hub. A caller that needs the whole list narrows the window
    /// rather than raising the page, which is the advice everywhere here.
    pub hubs: Vec<Corridor>,
    /// Rough token cost of this answer, advisory only.
    ///
    /// Measured over the record on every edge, so a record that made three edges is counted three
    /// times — which is what returning it three times costs.
    pub token_estimate: usize,
}

impl LinksResponse {
    /// Wraps the edges, names the corridors the rule refused, and measures what it all costs.
    fn new(links: Vec<Link<RecordStructure>>, asked: &Traversal) -> Self {
        let token_estimate =
            yaam_contract::structure::estimate_tokens(links.iter().map(|link| &link.via));
        // Deduplicated and ordered, because one hub is typically reached by several edges and a list
        // repeating it would read as several hubs. `BTreeMap` rather than a sort afterwards: the key
        // is the pair that identifies an entity, and the degree is a property of it.
        let mut hubs = std::collections::BTreeMap::new();
        for link in links.iter().filter(|link| link.hub(asked)) {
            hubs.insert((link.to.kind.clone(), link.to.id.clone()), link.degree);
        }
        Self {
            edges: links
                .into_iter()
                .map(|link| LinkedEdge {
                    score: link.score(),
                    from: LinkedEntity {
                        kind: link.from.kind,
                        id: link.from.id,
                    },
                    to: LinkedEntity {
                        kind: link.to.kind,
                        id: link.to.id,
                    },
                    hop: link.hop,
                    confidence: link.confidence,
                    via: link.via,
                })
                .collect(),
            hubs: hubs
                .into_iter()
                .map(|((kind, id), degree)| Corridor { kind, id, degree })
                .collect(),
            token_estimate,
        }
    }
}

/// How far a traversal goes, and what it will believe on the way.
///
/// `depth` carries no default and neither does the window, and the two absences are reported
/// differently on purpose — the same split `GET /correlate` already makes. A missing `depth` is
/// `400`, because there is nothing to parse; a half window is `422`, because it parses into a
/// question this service will not answer. Both are permanent, and a client whose retry policy
/// branches on the code should read them the same way.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkedQuery {
    /// How many records deep to go. Required.
    pub depth: u32,
    /// Inclusive start of the window every hop is taken inside. Required, with `to_ms`.
    pub from_ms: Option<i64>,
    /// Exclusive end of that window. Required, with `from_ms`.
    pub to_ms: Option<i64>,
    /// Floor every reference on every hop must clear. Absent means full confidence.
    pub min_confidence: Option<f32>,
    /// Most references an entity may carry inside the window and still be traversed through.
    /// Absent means the service's own cap, and above it is refused.
    pub max_degree: Option<u32>,
    /// Most edges to return. Absent means the index's own cap, not every edge.
    pub limit: Option<u32>,
}

impl LinkedQuery {
    /// Turns query parameters into a traversal, refusing what this read will not guess at.
    ///
    /// `kind` and `id` arrive from the path and are canonicalised below this, by the service, for the
    /// reason `GET /entities/{kind}/{id}` canonicalises its own: a spelling good enough to store has
    /// to be good enough to traverse from, and one this deployment cannot canonicalise is a question
    /// it cannot be asked rather than an entity with no neighbours.
    fn into_traversal(self, kind: String, id: String) -> Result<Traversal> {
        // Required, as on a correlation and for the same reason doubled: the seed's history is as
        // long as the seed is busy, and a traversal reads a history per node on the frontier. There
        // is no implicit `recent` here either.
        let window = match (self.from_ms, self.to_ms) {
            (Some(from_ms), Some(to_ms)) => Window { from_ms, to_ms },
            _ => {
                return Err(Error::Unprocessable(
                    "a traversal needs both `from_ms` and `to_ms`: every hop is taken inside the \
                     window, and there is no implicit `recent`"
                        .to_owned(),
                ));
            }
        };
        // Two refusals rather than one range check: the ends are refused for different reasons, and
        // a caller can only act on the one it hit. Neither is clamped — a depth quietly reduced is a
        // caller believing it saw a hop it did not.
        if self.depth == 0 {
            return Err(Error::Unprocessable(
                "`depth` is 0, which is `GET /entities/{kind}/{id}` with more ceremony: a traversal \
                 starts at one hop"
                    .to_owned(),
            ));
        }
        // The deep end names the measurement rather than the range. "Out of range" would read as a
        // bound a caller might argue with; this is a fact about what the answer would have been. See
        // [`query::MAX_DEPTH`], which is where the number moved and why.
        if self.depth > query::MAX_DEPTH {
            return Err(Error::Unprocessable(format!(
                "`depth` is {} and this service traverses 1 to {} hops: the recursion fills its \
                 {}-edge frontier breadth-first, so the frontier is spent on near hops before far \
                 ones — measured, a 30-day depth-3 traversal comes back as 115 hop-1 edges, 85 \
                 hop-2 edges and no hop-3 edges at all. Refused rather than answered out of the \
                 first two hops under a third hop's name: ask for {} and narrow the window rather \
                 than raising the page. A per-hop budget is what would lift this, and there is not \
                 one yet.",
                self.depth,
                query::MAX_DEPTH,
                query::MAX_FRONTIER,
                query::MAX_DEPTH
            )));
        }
        // Lowering the corridor cap is how an operator tightens a noisy traversal. Raising it would
        // be a request buying back the hub problem the rule exists to prevent, so it is refused
        // rather than clamped — clamped, a caller would believe the number it sent.
        let max_degree = self.max_degree.unwrap_or(query::CORRIDOR_DEGREE);
        if max_degree > query::CORRIDOR_DEGREE {
            return Err(Error::Unprocessable(format!(
                "`max_degree` is {max_degree} and this service will not traverse through an entity \
                 named by more than {} records inside the window: the cap may be lowered and not \
                 raised",
                query::CORRIDOR_DEGREE
            )));
        }
        Ok(Traversal {
            kind,
            id,
            depth: self.depth,
            window,
            min_confidence: self.min_confidence.unwrap_or(query::FULL_CONFIDENCE),
            max_degree,
            limit: self.limit,
            // As everywhere here: what a caller may see comes from the credential its signature
            // proved, and is filled in from it below. Spelled as the scope that matches nothing
            // rather than left to a default, because [`Traversal`] deliberately has none — and an
            // implementation of [`Service`] that forgot to narrow this would then answer nothing
            // instead of everything.
            //
            // [`Service`]: crate::service::Service
            scope: query::Scope::Nothing,
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
    /// Inclusive start of a window over server-stamped time.
    pub from_ms: Option<i64>,
    /// Exclusive end of that window.
    pub to_ms: Option<i64>,
}

impl EntityQuery {
    /// The window this asks for, refusing half of one.
    ///
    /// Half a window is not a narrower query, it is a different one — the same rule `/records`
    /// follows, and stated separately rather than shared because the two structs are deserialised
    /// independently and a shared helper would be one indirection over four lines.
    fn window(&self) -> Result<Option<Window>> {
        match (self.from_ms, self.to_ms) {
            (Some(from_ms), Some(to_ms)) => Ok(Some(Window { from_ms, to_ms })),
            (None, None) => Ok(None),
            _ => Err(Error::Unprocessable(
                "a window needs both `from_ms` and `to_ms`".to_owned(),
            )),
        }
    }
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
    // Before the read, not inside it: a half-window is the caller's mistake, and answering it as an
    // unwindowed history would hand back rows they did not ask for under a `200`.
    let window = params.window()?;
    let service = state.service();
    let records =
        blocking(move || service.entity(&caller, &kind, &id, min_confidence, window, limit))
            .await?;
    Ok(Json(RecordsResponse::new(records)))
}

/// Answers which records of one shape were followed by records of another.
///
/// The join both halves of the cross-agent question used to be asked as: two reads and an
/// intersection the caller performed, or one entity's history inside a window and a judgement about
/// what in it was related. One signed request now, and the pairing comes back as a fact about the
/// store rather than as arithmetic somebody did afterwards.
async fn correlate_records(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(params): Query<CorrelateQuery>,
) -> Result<Json<CorrelationsResponse>> {
    // Before the read: a missing window and a backwards nearness are both the caller's mistakes, and
    // both would otherwise answer `200` with a page that reads as "nothing happened nearby".
    let (left, right, within_ms) = params.into_join()?;
    let service = state.service();
    let pairs = blocking(move || service.correlate(&caller, &left, &right, within_ms)).await?;
    Ok(Json(CorrelationsResponse::new(pairs)))
}

/// Answers what else is connected to one entity, and by which records.
///
/// The read this service had no shape for: every other one takes entities the caller can already
/// name and answers with records. This one answers with the graph those records imply — an edge at a
/// time, each carrying the record that made it, so *why* two things are connected needs no second
/// read.
async fn linked_entities(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path((kind, id)): Path<(String, String)>,
    Query(params): Query<LinkedQuery>,
) -> Result<Json<LinksResponse>> {
    // Before the read: a half window, a depth this service will not run and a corridor cap above its
    // own are all the caller's mistakes, and each would otherwise answer `200` with a page that
    // reads as "nothing is connected to this".
    let asked = params.into_traversal(kind, id)?;
    let service = state.service();
    let traversal = asked.clone();
    let links = blocking(move || service.linked(&caller, &traversal)).await?;
    Ok(Json(LinksResponse::new(links, &asked)))
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
        assert_eq!(
            fake.calls()[0],
            "entity agent-reader ticket T-1 0 None None"
        );
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

    /// One entity inside one window, which is what makes a correlation a single read.
    #[tokio::test]
    async fn entity_history_takes_a_window() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get("/entities/ticket/T-1?from_ms=1000&to_ms=2000", Some(READER)),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            fake.calls()[0],
            "entity agent-reader ticket T-1 0 Some(Window { from_ms: 1000, to_ms: 2000 }) None"
        );
    }

    /// Half a window is a different question, not a narrower one — so it is refused rather than
    /// answered as the whole history, which would hand back rows nobody asked for under a `200`.
    #[tokio::test]
    async fn entity_history_refuses_half_a_window() {
        for target in [
            "/entities/ticket/T-1?from_ms=1000",
            "/entities/ticket/T-1?to_ms=2000",
        ] {
            let fake = Arc::new(Fake::new());
            let (status, body) = serve(&fake, get(target, Some(READER))).await;

            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{target}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("window"),
                "{target}: {body}"
            );
            // Refused before the read, so the service was never asked.
            assert!(fake.calls().is_empty(), "{target} reached the service");
        }
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
        assert_eq!(
            fake.calls()[0],
            "entity agent-reader ticket T-1 1 None None"
        );
    }

    #[tokio::test]
    async fn entity_history_takes_a_page_size() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(&fake, get("/entities/ticket/T-1?limit=5", Some(READER))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            fake.calls()[0],
            "entity agent-reader ticket T-1 0 None Some(5)"
        );
    }

    /// Both sides of the join reach the index as the caller spelled them, and the answer is pairs.
    #[tokio::test]
    async fn a_correlation_carries_both_filters_and_answers_in_pairs() {
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (status, body) = serve(
            &fake,
            get(
                "/correlate?left.action=transact&left.outcome=declined&left.from_ms=1000\
                 &left.to_ms=2000&right.action=deploy&right.attr=environment%3Dproduction\
                 &within_ms=1800000&limit=7",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        // A pair, not a flat list: which record happened near which is the answer, and a `records`
        // key here would mean the pairing was flattened away on the way out.
        assert!(body["records"].is_null(), "{body}");
        assert_eq!(
            body["pairs"][0]["left"]["record_id"], body["pairs"][0]["right"]["record_id"],
            "{body}"
        );
        assert!(
            body["token_estimate"].as_u64().is_some_and(|n| n > 0),
            "{body}"
        );

        let call = &fake.calls()[0];
        // The window on the left filter and nowhere else, the page on the left filter because that
        // is where the index reads a pair cap from, and no page on the right at all.
        assert!(
            call.contains("Window { from_ms: 1000, to_ms: 2000 }"),
            "{call}"
        );
        assert!(call.contains("action: Some(\"transact\")"), "{call}");
        assert!(call.contains("action: Some(\"deploy\")"), "{call}");
        assert!(
            call.contains("attr: Some((\"environment\", \"production\"))"),
            "{call}"
        );
        assert!(call.contains("limit: Some(7)"), "{call}");
        assert!(call.ends_with(" 1800000"), "{call}");
    }

    #[tokio::test]
    async fn a_traversal_carries_every_bound_it_was_asked_with_and_names_what_it_refused() {
        let held = [testing::record(WRITER)];
        let fake = Arc::new(Fake::new().holding(&held));
        let (status, body) = serve(
            &fake,
            get(
                "/linked/order_ref/ord10014733?depth=2&from_ms=1000&to_ms=2000\
                 &min_confidence=0.7&max_degree=8&limit=7",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        // A graph, not a flat list: a `records` key here would mean the edges were flattened away
        // on the way out, taking the hop and the endpoints with them.
        assert!(body["records"].is_null(), "{body}");
        assert_eq!(body["edges"][0]["from"]["id"], "ord10014733", "{body}");
        assert_eq!(body["edges"][0]["hop"], 1, "{body}");
        assert!(
            (body["edges"][0]["score"].as_f64().unwrap_or_default() - 0.5).abs() < 1e-6,
            "the attenuation is contract, so it is on the wire: {body}"
        );
        assert!(body["edges"][0]["via"]["record_id"].is_string(), "{body}");
        // The fake answers with a degree one past whatever cap it was given, so this is the shape
        // that says a refused corridor is named rather than silently dropped.
        assert_eq!(body["hubs"][0]["degree"], 9, "{body}");
        assert_eq!(body["hubs"][0]["id"], "PROJ-42", "{body}");
        assert!(
            body["token_estimate"].as_u64().is_some_and(|n| n > 0),
            "{body}"
        );

        // Every bound reached the index. One absent from here is one the route could drop while the
        // answer still looked plausible.
        let call = &fake.calls()[0];
        assert!(call.contains("depth: 2"), "{call}");
        assert!(
            call.contains("Window { from_ms: 1000, to_ms: 2000 }"),
            "{call}"
        );
        assert!(call.contains("min_confidence: 0.7"), "{call}");
        assert!(call.contains("max_degree: 8"), "{call}");
        assert!(call.contains("limit: Some(7)"), "{call}");
    }

    /// A traversal without its whole window is refused, as a correlation is and for more reason.
    #[tokio::test]
    async fn a_traversal_without_a_window_is_refused_rather_than_run_over_a_whole_history() {
        for target in [
            "/linked/ticket/PROJ-42?depth=1",
            "/linked/ticket/PROJ-42?depth=1&from_ms=1000",
            "/linked/ticket/PROJ-42?depth=1&to_ms=2000",
        ] {
            let fake = Arc::new(Fake::new());
            let (status, body) = serve(&fake, get(target, Some(READER))).await;

            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{target}: {body}");
            assert!(
                body["error"].as_str().unwrap_or_default().contains("hop"),
                "the refusal has to say that the window binds every hop: {target}: {body}"
            );
            assert!(fake.calls().is_empty(), "{target} reached the index");
        }
    }

    /// A depth this service will not run is refused rather than clamped to one it will.
    ///
    /// Clamped, a caller asking for three hops would be handed two and told nothing, and would
    /// report the absence of a third-hop connection as a fact about the store. `3` is in the list
    /// because it is the depth this endpoint used to answer: the frontier fills breadth-first and
    /// spent all 200 edges on hops 1 and 2, so what came back was a two-hop answer wearing a
    /// three-hop label. That is what the refusal below replaced.
    #[tokio::test]
    async fn a_depth_outside_what_the_frontier_can_answer_is_refused_rather_than_clamped() {
        for depth in ["0", "3", "4", "99"] {
            let fake = Arc::new(Fake::new());
            let target = format!("/linked/ticket/PROJ-42?depth={depth}&from_ms=1&to_ms=2");
            let (status, body) = serve(&fake, get(&target, Some(READER))).await;

            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{target}: {body}");
            assert!(
                body["error"].as_str().unwrap_or_default().contains("depth"),
                "{target}: {body}"
            );
            assert!(fake.calls().is_empty(), "{target} reached the index");
        }
        // The deep end says *why*, and the reason is the one thing a caller can act on: it tells
        // them the answer they would have got was composed out of the hops they did not ask about.
        // Asserted on the words rather than only the code, because a refusal that had drifted back
        // to "out of range" would still be a `422`.
        let fake = Arc::new(Fake::new());
        let (status, body) = serve(
            &fake,
            get(
                "/linked/ticket/PROJ-42?depth=3&from_ms=1&to_ms=2",
                Some(READER),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let refusal = body["error"].as_str().unwrap_or_default();
        for phrase in ["breadth-first", "no hop-3 edges at all", "per-hop budget"] {
            assert!(
                refusal.contains(phrase),
                "the refusal has to say why a third hop would misrepresent itself: {refusal}"
            );
        }
        // Depth 0 is refused for its own reason and must not be handed the frontier's.
        let fake = Arc::new(Fake::new());
        let (_, body) = serve(
            &fake,
            get(
                "/linked/ticket/PROJ-42?depth=0&from_ms=1&to_ms=2",
                Some(READER),
            ),
        )
        .await;
        let refusal = body["error"].as_str().unwrap_or_default();
        assert!(
            refusal.contains("/entities/") && !refusal.contains("breadth-first"),
            "depth 0 is a different refusal from the frontier's: {refusal}"
        );
        // A depth that is not a number at all is refused before a handler runs, like any query
        // string that will not parse.
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get(
                "/linked/ticket/PROJ-42?depth=deep&from_ms=1&to_ms=2",
                Some(READER),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The corridor cap may be lowered and not raised, and raising it is refused rather than clamped.
    ///
    /// A clamp would leave the caller believing the number it sent, which for a rule whose whole
    /// purpose is that a request cannot buy its way past it is the one outcome worth refusing.
    #[tokio::test]
    async fn the_corridor_cap_may_be_lowered_and_not_raised() {
        let fake = Arc::new(Fake::new());
        let target = format!(
            "/linked/ticket/PROJ-42?depth=1&from_ms=1&to_ms=2&max_degree={}",
            yaam_store::query::CORRIDOR_DEGREE + 1
        );
        let (status, body) = serve(&fake, get(&target, Some(READER))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("lowered and not raised"),
            "{body}"
        );
        assert!(fake.calls().is_empty());

        // Lowering it reaches the index unchanged, which is the half that makes the refusal a rule
        // rather than a ceiling nobody can move.
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get(
                "/linked/ticket/PROJ-42?depth=1&from_ms=1&to_ms=2&max_degree=2",
                Some(READER),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            fake.calls()[0].contains("max_degree: 2"),
            "{:?}",
            fake.calls()
        );
    }

    /// A traversal that named no floor, cap or page gets the service's own, and says so to the index.
    #[tokio::test]
    async fn a_traversal_that_names_no_bounds_still_carries_the_services_own() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get(
                "/linked/ticket/PROJ-42?depth=1&from_ms=1&to_ms=2",
                Some(READER),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let call = &fake.calls()[0];
        assert!(call.contains("min_confidence: 1.0"), "{call}");
        assert!(
            call.contains(&format!(
                "max_degree: {}",
                yaam_store::query::CORRIDOR_DEGREE
            )),
            "{call}"
        );
        assert!(call.contains("limit: None"), "{call}");
    }

    /// A correlation with no window is refused, and that is a rule `GET /records` does not have.
    ///
    /// The window is what bounds the side the join is driven from. Without it the answer is the most
    /// recent pairs in the store — an implicit "recent" that moves as records arrive, which is the
    /// one thing this query is documented not to have.
    #[tokio::test]
    async fn a_correlation_without_a_window_is_refused_rather_than_run_over_everything() {
        for target in [
            "/correlate?right.action=deploy&within_ms=1000",
            "/correlate?left.from_ms=1000&right.action=deploy&within_ms=1000",
            "/correlate?left.to_ms=2000&right.action=deploy&within_ms=1000",
        ] {
            let fake = Arc::new(Fake::new());
            let (status, body) = serve(&fake, get(target, Some(READER))).await;

            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{target}: {body}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("left.from_ms"),
                "{target}: {body}"
            );
            assert!(fake.calls().is_empty(), "{target} reached the index");
        }
    }

    /// A backwards nearness is refused rather than answered with the empty page it would produce.
    ///
    /// The join is directional, so a negative `within_ms` describes a window that closes before it
    /// opens and can match nothing. Answered as `200` with no pairs, it would read as "nothing
    /// happened near that", which is the wrong conclusion to hand anybody.
    #[tokio::test]
    async fn a_backwards_nearness_is_refused_rather_than_answered_empty() {
        let fake = Arc::new(Fake::new());
        let (status, body) = serve(
            &fake,
            get(
                "/correlate?left.from_ms=1000&left.to_ms=2000&within_ms=-1",
                Some(READER),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("swapping"),
            "the refusal has to say how to ask about what came before: {body}"
        );
        assert!(fake.calls().is_empty());
    }

    /// A nearness is required, so a correlation cannot be asked without saying what "nearby" means.
    #[tokio::test]
    async fn a_correlation_with_no_nearness_is_refused_rather_than_defaulted() {
        let fake = Arc::new(Fake::new());
        let (status, _) = serve(
            &fake,
            get("/correlate?left.from_ms=1000&left.to_ms=2000", Some(READER)),
        )
        .await;

        // `400`, like every other unparseable query string: it is refused before a handler runs.
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(fake.calls().is_empty());
    }

    /// A page size on the right of a join means nothing, so naming one is refused.
    ///
    /// Accepted and ignored, it would be a parameter a caller sets to bound an answer that it does
    /// not bound — the same failure an unknown filter is refused for, one step subtler.
    #[tokio::test]
    async fn a_page_size_on_the_right_of_the_join_is_refused_rather_than_ignored() {
        let fake = Arc::new(Fake::new());
        for target in [
            "/correlate?left.from_ms=1&left.to_ms=2&within_ms=1&right.limit=5",
            "/correlate?left.from_ms=1&left.to_ms=2&within_ms=1&right.from_ms=1&right.to_ms=2",
            "/correlate?left.from_ms=1&left.to_ms=2&within_ms=1&action=deploy",
        ] {
            let (status, _) = serve(&fake, get(target, Some(READER))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}");
        }
        assert!(fake.calls().is_empty());
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
        // Internal and naming a subject: the record claims an erasability its plaintext body cannot
        // deliver, and no retry of the same bytes will fix it. The mirror case — subject-derived and
        // naming none — is deliberately not a contract failure, because a store that derives
        // pseudonyms cannot ask a caller for one; the write path refuses that after resolution.
        record.subjects = vec![yaam_contract::SubjectRef {
            hash: yaam_contract::SubjectHash::parse(&format!("s_{}", "ab".repeat(32)))
                .expect("a valid hash"),
            role: yaam_contract::Role::Principal,
            canon_ver: yaam_contract::CanonVer(1),
        }];
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
