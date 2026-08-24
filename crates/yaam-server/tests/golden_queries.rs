//! Golden queries: the questions an operator asks, and the records that must come back.
//!
//! Every case here writes a record through the service's own write path and then asks a question
//! through its own read path — a signed request at the router, over a real tree and a real index.
//! Nothing seeds a row. A fixture that inserted into the index directly would pass while the write
//! path was broken, and that is exactly the failure this set exists to catch: a record can be
//! accepted, published *and* indexed and still not be findable by the query somebody needs to run.
//! Unit tests on the query builder do not see it, because the builder is correct about the columns
//! it was told about.
//!
//! The set is a table rather than a test per question, so adding a case is a row rather than a
//! function — the difference between a set that grows and one that rots. Two rules make the rows
//! carry their weight:
//!
//! * Every row states the *exact* set it must return, so each positive case is also a check against
//!   false positives. A query matching everything finds the record too.
//! * Several rows must return nothing at all. That half matters as much as the other: "returns the
//!   record" is trivially satisfiable, and only the empty rows say the predicate discriminates.
//!
//! Answers are asserted against *structure*. A read hands back a record's frontmatter and never its
//! prose, so each case names the fields its question was about, and the runner additionally checks
//! that no answer carries a body — for the sealed record and the plaintext ones alike.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::Value;
use tower::ServiceExt;
use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, RecordStructure, Role as SubjectRole,
    SchemaVer, SubjectRef, Visibility, attrs,
    entity::{self, EntityRef},
};
use yaam_server::auth::{self, Credential, Keyring, Role};
use yaam_server::routes::{AppState, router};
use yaam_server::service::Service;

use support::{POLICY, Tree};

/// Rows a full-text read may return. Higher than the fixture set, so a case that finds nothing
/// found nothing because of its needle rather than because of its page.
const SEARCH_LIMIT: u32 = 64;

/// A structural attribute in the two shapes `spec/attrs-schema.yaml` declares.
///
/// A mirror of [`attrs::Value`] rather than the type itself: the wire type owns a `String`, and a
/// table of cases has to be spellable as a constant.
#[derive(Debug, Clone, Copy)]
enum Attr {
    /// A string attribute.
    Text(&'static str),
    /// A whole-number attribute, which a filter matches by its decimal form.
    Int(i64),
}

/// The callers this set authenticates, and what each may see.
///
/// Entitlements reach a read from the credential the signature proved and from nowhere else, so this
/// one table is the whole of what makes the scoped rows below assert something: change a caller's
/// teams here and its answers change.
const AGENTS: &[(&str, Role, &[&str])] = &[
    ("deploy_bot", Role::Writer, &["platform"]),
    ("ledger_bot", Role::Writer, &["platform"]),
    ("release_bot", Role::Writer, &["platform"]),
    ("review_bot", Role::Writer, &["platform"]),
    ("chat_bot", Role::Writer, &["platform", "support"]),
    ("ops_bot", Role::Operator, &["platform", "support"]),
    // In no team, which is what makes the team-scoped rows below assert something.
    ("audit_reader", Role::Reader, &[]),
];

/// One record to write, in the terms an emitter would fill in.
struct Fixture {
    /// Name the golden rows refer to it by. Never on the wire.
    label: &'static str,
    /// Agent the record is attributed to, which is also the caller that writes it.
    agent: &'static str,
    /// Server-stamped time. Authoritative for ordering and for every window below.
    received_at: &'static str,
    action: &'static str,
    outcome: Outcome,
    /// Structural attributes, which is the only class frontmatter may hold.
    attrs: &'static [(&'static str, Attr)],
    /// Entity references, as `kind` and its canonical id.
    entities: &'static [(&'static str, &'static str)],
    visibility: Visibility,
    /// Team, required when `visibility` is team-scoped.
    team: Option<&'static str>,
    /// The prose. Stored as the body, never returned by a read, and findable by full text unless
    /// the record is sealed.
    body: &'static str,
    /// Set for a subject-derived record, whose body is sealed to this pseudonym.
    subject: Option<char>,
}

/// The tree every case reads: thirteen records across five actions, five agents and two teams.
///
/// Deliberately not one record per question. A store holding a single record cannot tell a query
/// that discriminates from a query that matches everything, so each fixture is a near miss for some
/// other fixture's question — same action and a different outcome, same entity and a different kind,
/// same window and a different agent.
const FIXTURES: &[Fixture] = &[
    Fixture {
        label: "deploy_ok",
        agent: "deploy_bot",
        received_at: "2026-08-20T09:00:00Z",
        action: "deploy",
        outcome: Outcome::Success,
        attrs: &[
            ("service", Attr::Text("api")),
            ("environment", Attr::Text("staging")),
            ("build", Attr::Text("b1041")),
            ("duration_ms", Attr::Int(1_200)),
        ],
        entities: &[("ticket", "PROJ-42"), ("deploy", "api/staging#1041")],
        visibility: Visibility::Org,
        team: None,
        body: "Rolled out the api service to staging; all three shards reported healthy.",
        subject: None,
    },
    Fixture {
        label: "deploy_failed",
        agent: "deploy_bot",
        received_at: "2026-08-20T09:30:00Z",
        action: "deploy",
        outcome: Outcome::Failure,
        attrs: &[
            ("service", Attr::Text("api")),
            ("environment", Attr::Text("production")),
            ("build", Attr::Text("b1042")),
        ],
        entities: &[("ticket", "PROJ-42"), ("deploy", "api/production#1042")],
        visibility: Visibility::Org,
        team: None,
        body: "The api rollout to production stalled on the second shard and was rolled back.",
        subject: None,
    },
    Fixture {
        label: "deploy_partial",
        agent: "deploy_bot",
        received_at: "2026-08-20T10:00:00Z",
        action: "deploy",
        outcome: Outcome::Partial,
        attrs: &[
            ("service", Attr::Text("worker")),
            ("environment", Attr::Text("production")),
        ],
        entities: &[("ticket", "PROJ-77")],
        visibility: Visibility::Org,
        team: None,
        body: "Half the worker fleet took the new build; the rest stayed on the previous one.",
        subject: None,
    },
    // Older than every window a "recently" question uses, and otherwise indistinguishable from
    // `deploy_failed`: without it, a filter that ignored its window would still look right.
    Fixture {
        label: "deploy_stale",
        agent: "deploy_bot",
        received_at: "2026-07-02T09:00:00Z",
        action: "deploy",
        outcome: Outcome::Failure,
        attrs: &[
            ("service", Attr::Text("api")),
            ("environment", Attr::Text("production")),
            ("build", Attr::Text("b0994")),
        ],
        entities: &[("ticket", "PROJ-42")],
        visibility: Visibility::Org,
        team: None,
        body: "An earlier api rollout to production failed and was rolled back within the hour.",
        subject: None,
    },
    Fixture {
        label: "promote_ok",
        agent: "release_bot",
        received_at: "2026-08-20T14:00:00Z",
        action: "deploy",
        outcome: Outcome::Success,
        attrs: &[
            ("service", Attr::Text("edge")),
            ("environment", Attr::Text("production")),
            ("build", Attr::Text("b1043")),
        ],
        entities: &[("ticket", "PROJ-77")],
        visibility: Visibility::Org,
        team: None,
        body: "Promoted the edge service to production with no incident to report.",
        subject: None,
    },
    Fixture {
        label: "transact_declined",
        agent: "ledger_bot",
        received_at: "2026-08-20T11:00:00Z",
        action: "transact",
        outcome: Outcome::Declined,
        attrs: &[
            ("provider", Attr::Text("gateway_one")),
            ("decline_code", Attr::Text("insufficient_standing")),
            ("currency", Attr::Text("XTS")),
        ],
        entities: &[("order_ref", "ord10014721")],
        visibility: Visibility::Org,
        team: None,
        body: "The counterparty declined and answered with a standing code.",
        subject: None,
    },
    Fixture {
        label: "transact_failed",
        agent: "ledger_bot",
        received_at: "2026-08-20T11:30:00Z",
        action: "transact",
        outcome: Outcome::Failure,
        attrs: &[
            ("provider", Attr::Text("gateway_two")),
            ("currency", Attr::Text("XTS")),
        ],
        entities: &[("order_ref", "ord10014722")],
        visibility: Visibility::Org,
        team: None,
        body: "The attempt timed out before the provider answered at all.",
        subject: None,
    },
    // Subject-derived, so its body is sealed and indexes no text. `unrepeatableword` appears in no
    // other fixture, which is what lets a row assert that sealing is not searchable around.
    Fixture {
        label: "lookup_sealed",
        agent: "ledger_bot",
        received_at: "2026-08-20T12:00:00Z",
        action: "lookup",
        outcome: Outcome::Success,
        attrs: &[("target_kind", Attr::Text("order_ref"))],
        entities: &[("order_ref", "ord10014721")],
        visibility: Visibility::Org,
        team: None,
        body: "Resolved the party behind unrepeatableword on request.",
        subject: Some('a'),
    },
    Fixture {
        label: "reply_platform",
        agent: "chat_bot",
        received_at: "2026-08-20T13:00:00Z",
        action: "reply",
        outcome: Outcome::Success,
        attrs: &[
            ("channel_kind", Attr::Text("thread")),
            ("chunks", Attr::Int(2)),
        ],
        entities: &[("chat_channel", "ops-room")],
        visibility: Visibility::Team,
        team: Some("platform"),
        body: "Answered in the ops room and split the answer over two messages.",
        subject: None,
    },
    Fixture {
        label: "reply_support",
        agent: "chat_bot",
        received_at: "2026-08-20T13:30:00Z",
        action: "reply",
        outcome: Outcome::Failure,
        attrs: &[
            ("channel_kind", Attr::Text("thread")),
            ("chunks", Attr::Int(1)),
        ],
        entities: &[("chat_channel", "ops-room")],
        visibility: Visibility::Team,
        team: Some("support"),
        body: "The reply was refused by the channel and never reached anybody.",
        subject: None,
    },
    // Two passes over one pull request, an hour apart. A single review record could not tell a
    // timeline that is ordered from one that happens to hold a single row, and the verdict is what
    // changes between them: the question "is this still blocked" is answered by the newer one.
    Fixture {
        label: "review_changes",
        agent: "review_bot",
        received_at: "2026-08-20T15:00:00Z",
        action: "review",
        outcome: Outcome::Success,
        attrs: &[
            ("verdict", Attr::Text("changes_requested")),
            ("findings", Attr::Int(2)),
        ],
        entities: &[
            ("pull_request", "owner/repo#84"),
            ("commit", "owner/repo@3f1c9ab"),
        ],
        visibility: Visibility::Org,
        team: None,
        body: "Read the whole diff and asked for two changes before it can go in.",
        subject: None,
    },
    Fixture {
        label: "review_approved",
        agent: "review_bot",
        received_at: "2026-08-20T16:00:00Z",
        action: "review",
        outcome: Outcome::Success,
        attrs: &[
            ("verdict", Attr::Text("approved")),
            ("findings", Attr::Int(0)),
        ],
        entities: &[("pull_request", "owner/repo#84")],
        visibility: Visibility::Org,
        team: None,
        body: "The two changes landed, so a second pass over the same diff let it through.",
        subject: None,
    },
    // Same action and the same window as the pair above, by another agent and about another pull
    // request. Without it, "this agent's reviews" and "this pull request's reviews" would both be
    // satisfied by a read that ignored the thing it was asked about.
    Fixture {
        label: "review_other",
        agent: "release_bot",
        received_at: "2026-08-20T15:30:00Z",
        action: "review",
        outcome: Outcome::Partial,
        attrs: &[
            ("verdict", Attr::Text("commented")),
            ("findings", Attr::Int(1)),
        ],
        entities: &[("pull_request", "owner/repo#85")],
        visibility: Visibility::Org,
        team: None,
        body: "Got through the migration and left one note; the rest of the diff went unread.",
        subject: None,
    },
];

/// How a golden row asks its question.
enum Ask {
    /// A signed read whose answer is newest first, so the row lists what it finds in that order.
    /// An ordering that silently reversed would leave a "what failed recently" answer starting at
    /// the oldest failure.
    Ordered(&'static str),
    /// A signed read with no promised order — a bundle merges several reads, so its row is a set.
    Unordered(&'static str),
    /// A full-text needle, as an FTS5 expression, asked at `GET /search`.
    ///
    /// No promised order beyond best match first, which is not an order a row can state, so a
    /// full-text row is a set like a bundle's. It asserts at the same layer as every row above: the
    /// needle is signed into the request target and the answer is the structure the route returned.
    Search(&'static str),
}

/// What the answer must carry for the question to have been answered.
///
/// A row that only counted records would pass while the projection dropped the column the question
/// was about, which is the same class of bug one step further along.
enum Needs {
    /// A frontmatter field equal to this text. A string compares bare, anything else by its JSON.
    Field(&'static str, &'static str),
    /// A structural attribute, as `key=value`.
    Attr(&'static str),
    /// An entity reference the answer names, as `kind:id`.
    Entity(&'static str),
}

/// One golden query: a question, the read that asks it, and the answer it must get.
struct Case {
    /// The question in the words somebody would ask it. Failure messages quote this, because
    /// "assertion failed at line 412" does not say what stopped working.
    question: &'static str,
    /// The read.
    ask: Ask,
    /// Timestamps `{from}` and `{to}` in `ask` are replaced with, so a row reads in instants rather
    /// than in epoch milliseconds.
    window: Option<(&'static str, &'static str)>,
    /// Who asks. Entitlements come from the credential the signature proved, so the caller is part
    /// of the question and not a detail of the harness.
    agent: &'static str,
    /// Fixture labels the read must return — exactly these and nothing else.
    finds: &'static [&'static str],
    /// What every returned record must carry.
    needs: &'static [Needs],
}

/// A day covering every fixture but `deploy_stale`, which is what "recently" means here.
const RECENTLY: (&str, &str) = ("2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z");

/// The golden set. Add a question by adding a row.
const GOLDEN: &[Case] = &[
    // ---- find by action and outcome: "what failed recently" ----
    Case {
        question: "which deploys failed recently",
        ask: Ask::Ordered("/records?action=deploy&outcome=failure&from_ms={from}&to_ms={to}"),
        window: Some(RECENTLY),
        agent: "ops_bot",
        finds: &["deploy_failed"],
        needs: &[
            Needs::Field("action", "deploy"),
            Needs::Field("outcome", "failure"),
            Needs::Field("received_at", "2026-08-20T09:30:00Z"),
            Needs::Attr("environment=production"),
        ],
    },
    // The same question without the window, which is a different question: the window is the only
    // thing that makes "recently" mean anything, and a filter that dropped it would pass the row
    // above by returning this answer.
    Case {
        question: "which deploys have ever failed",
        ask: Ask::Ordered("/records?action=deploy&outcome=failure"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed", "deploy_stale"],
        needs: &[Needs::Field("outcome", "failure")],
    },
    Case {
        question: "which transactions were declined rather than merely failing",
        ask: Ask::Ordered("/records?action=transact&outcome=declined"),
        window: None,
        agent: "ops_bot",
        finds: &["transact_declined"],
        needs: &[
            Needs::Field("outcome", "declined"),
            Needs::Attr("decline_code=insufficient_standing"),
            Needs::Attr("provider=gateway_one"),
        ],
    },
    // The outcome the review group declares `partial` for: a diff read as far as the reviewer got.
    // It is a different question from "which reviews asked for changes" — this one is about the
    // reviewer having stopped, and nothing in the verdict says so.
    Case {
        question: "which reviews never got through the whole diff",
        ask: Ask::Ordered("/records?action=review&outcome=partial"),
        window: None,
        agent: "ops_bot",
        finds: &["review_other"],
        needs: &[
            Needs::Field("outcome", "partial"),
            Needs::Entity("pull_request:owner/repo#85"),
        ],
    },
    // ---- find by entity reference: "what happened to this thing" ----
    Case {
        question: "what has happened to this ticket",
        ask: Ask::Ordered("/entities/ticket/PROJ-42"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed", "deploy_ok", "deploy_stale"],
        needs: &[Needs::Entity("ticket:PROJ-42")],
    },
    Case {
        question: "what has happened to this business reference",
        ask: Ask::Ordered("/entities/order_ref/ord10014721"),
        window: None,
        agent: "ops_bot",
        finds: &["lookup_sealed", "transact_declined"],
        needs: &[Needs::Entity("order_ref:ord10014721")],
    },
    // A deploy names itself `service/environment#build`, and a pull request `owner/repo#number`, so
    // both ids carry the two characters a path cannot: the separator, and the one a URI reads as the
    // start of a fragment. Written encoded here because that is what an operator's client has to
    // send — and the row would pass a service that only ever answered single-word ids otherwise.
    Case {
        question: "what happened to this one deploy",
        ask: Ask::Ordered("/entities/deploy/api%2Fproduction%231042"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed"],
        needs: &[
            Needs::Entity("deploy:api/production#1042"),
            Needs::Field("outcome", "failure"),
            Needs::Attr("build=b1042"),
        ],
    },
    Case {
        question: "what happened to this pull request",
        ask: Ask::Ordered("/entities/pull_request/owner%2Frepo%2384"),
        window: None,
        agent: "ops_bot",
        finds: &["review_approved", "review_changes"],
        needs: &[
            Needs::Entity("pull_request:owner/repo#84"),
            Needs::Field("action", "review"),
        ],
    },
    Case {
        question: "what context is there for this ticket",
        ask: Ask::Unordered("/bundle?entity=ticket:PROJ-42"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed", "deploy_ok", "deploy_stale"],
        needs: &[Needs::Entity("ticket:PROJ-42")],
    },
    // ---- find by actor over a time window ----
    Case {
        question: "what did this agent do in the half hour after the first decline",
        ask: Ask::Ordered("/records?agent=ledger_bot&from_ms={from}&to_ms={to}"),
        window: Some(("2026-08-20T11:00:00Z", "2026-08-20T11:30:01Z")),
        agent: "ops_bot",
        finds: &["transact_failed", "transact_declined"],
        needs: &[Needs::Field("agent", "ledger_bot")],
    },
    Case {
        question: "what did this agent do all day",
        ask: Ask::Ordered("/records?agent=ledger_bot&from_ms={from}&to_ms={to}"),
        window: Some(RECENTLY),
        agent: "ops_bot",
        finds: &["lookup_sealed", "transact_failed", "transact_declined"],
        needs: &[Needs::Field("agent", "ledger_bot")],
    },
    // Another agent reviewed inside the same window, so the answer is the agent's reviews rather
    // than the window's: this is the question asked of a reviewing agent before trusting it further.
    Case {
        question: "what did this reviewer review over the afternoon",
        ask: Ask::Ordered("/records?action=review&agent=review_bot&from_ms={from}&to_ms={to}"),
        window: Some(("2026-08-20T14:00:00Z", "2026-08-20T17:00:00Z")),
        agent: "ops_bot",
        finds: &["review_approved", "review_changes"],
        needs: &[
            Needs::Field("action", "review"),
            Needs::Field("agent", "review_bot"),
        ],
    },
    // ---- find by attribute value ----
    Case {
        question: "what touched production",
        ask: Ask::Ordered("/records?attr=environment=production"),
        window: None,
        agent: "ops_bot",
        finds: &[
            "promote_ok",
            "deploy_partial",
            "deploy_failed",
            "deploy_stale",
        ],
        needs: &[Needs::Attr("environment=production")],
    },
    // A whole-number attribute, which the index compares by its decimal form: a filter that only
    // ever matched strings would answer nothing here and look like a store with no such record.
    Case {
        question: "which deploy took twelve hundred milliseconds",
        ask: Ask::Ordered("/records?attr=duration_ms=1200"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_ok"],
        needs: &[Needs::Attr("duration_ms=1200")],
    },
    Case {
        question: "which deploys of the api service are on record",
        ask: Ask::Ordered("/records?action=deploy&attr=service=api"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed", "deploy_ok", "deploy_stale"],
        needs: &[Needs::Attr("service=api"), Needs::Field("action", "deploy")],
    },
    // A review's `outcome` says it ran and its `verdict` says what it concluded, which is why the
    // verdict is an attribute at all: every review here succeeded, so `outcome` cannot separate the
    // one still asking for changes from the one that let the change through.
    Case {
        question: "which reviews are holding a change up",
        ask: Ask::Ordered("/records?action=review&attr=verdict=changes_requested"),
        window: None,
        agent: "ops_bot",
        finds: &["review_changes"],
        needs: &[
            Needs::Attr("verdict=changes_requested"),
            Needs::Attr("findings=2"),
            Needs::Field("outcome", "success"),
        ],
    },
    // `findings: 0` is the whole reason the count is recorded: a change that went in unchallenged is
    // the one somebody comes looking for, and it is otherwise indistinguishable from an approval
    // that had plenty to say first.
    Case {
        question: "which reviews raised nothing at all",
        ask: Ask::Ordered("/records?action=review&attr=findings=0"),
        window: None,
        agent: "ops_bot",
        finds: &["review_approved"],
        needs: &[Needs::Attr("findings=0"), Needs::Attr("verdict=approved")],
    },
    // ---- full text over the body ----
    Case {
        question: "which record mentions stalling",
        ask: Ask::Search("stalled"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_failed"],
        needs: &[Needs::Field("action", "deploy")],
    },
    Case {
        question: "which records mention rolling anything",
        ask: Ask::Search("roll*"),
        window: None,
        agent: "ops_bot",
        finds: &["deploy_ok", "deploy_failed", "deploy_stale"],
        needs: &[Needs::Field("action", "deploy")],
    },
    // Full text is scoped by the same predicate as every other read, and this is the pair that says
    // so: one caller's team holds the only body naming the needle, and a caller in no team asks the
    // same question. A search that tested visibility after matching — or not at all — would answer
    // both rows the same way, and would be a way to read a record no other read admits.
    Case {
        question: "which record mentions being refused, asked from inside the team",
        ask: Ask::Search("refused"),
        window: None,
        agent: "chat_bot",
        finds: &["reply_support"],
        needs: &[
            Needs::Field("action", "reply"),
            Needs::Field("visibility", "team"),
        ],
    },
    Case {
        question: "which record mentions being refused, asked by a caller in no team",
        ask: Ask::Search("refused"),
        window: None,
        agent: "audit_reader",
        finds: &[],
        needs: &[],
    },
    // ---- and the rows that must return nothing ----
    Case {
        question: "did any transaction succeed",
        ask: Ask::Ordered("/records?action=transact&outcome=success"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    Case {
        question: "did anything touch a canary environment",
        ask: Ask::Ordered("/records?attr=environment=canary"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    // A build that was never rolled out, spelled exactly like one that was. An entity read that
    // matched on the kind, or on a prefix of the id, would answer this with somebody else's deploy —
    // and "what happened to deploy X" is the question an incident starts from.
    Case {
        question: "what happened to a deploy nobody ever recorded",
        ask: Ask::Ordered("/entities/deploy/api%2Fproduction%239999"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    // A verdict this deployment writes no record with. `attrs` is a declared map and not a closed
    // one, so an unwritten value is a miss rather than a refusal — which is what makes the two
    // verdict rows above assert something.
    Case {
        question: "did any review reject a change outright",
        ask: Ask::Ordered("/records?action=review&attr=verdict=rejected"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    // The reviewer's own day before, which is the row that makes the windowed question above mean
    // "over the afternoon" rather than "ever".
    Case {
        question: "did this reviewer review anything the day before",
        ask: Ask::Ordered("/records?action=review&agent=review_bot&from_ms={from}&to_ms={to}"),
        window: Some(("2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z")),
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    Case {
        question: "was anything recorded the month before any of this",
        ask: Ask::Ordered("/records?from_ms={from}&to_ms={to}"),
        window: Some(("2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")),
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    // A sealed body indexes no text, so the one word only that record holds must find nothing.
    // Full text is the obvious way around sealing, and it is the reason this row is here.
    Case {
        question: "can full text reach the prose of a sealed record",
        ask: Ask::Search("unrepeatableword"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    Case {
        question: "does a needle nothing was written with match anything",
        ask: Ask::Search("unwrittenneedle"),
        window: None,
        agent: "ops_bot",
        finds: &[],
        needs: &[],
    },
    // Scope is part of the answer rather than a layer above it, so the same question asked by three
    // callers has three correct answers. An operator across both teams sees the channel whole.
    Case {
        question: "what happened in this channel, asked across both teams",
        ask: Ask::Ordered("/entities/chat_channel/ops-room"),
        window: None,
        agent: "ops_bot",
        finds: &["reply_support", "reply_platform"],
        needs: &[Needs::Entity("chat_channel:ops-room")],
    },
    // A caller in one of the two teams sees its own half, and no answer says a half is all there is.
    Case {
        question: "what happened in this channel, asked by one of the teams",
        ask: Ask::Ordered("/entities/chat_channel/ops-room"),
        window: None,
        agent: "deploy_bot",
        finds: &["reply_platform"],
        needs: &[Needs::Entity("chat_channel:ops-room")],
    },
    Case {
        question: "what happened in this channel, asked by a caller in no team",
        ask: Ask::Ordered("/entities/chat_channel/ops-room"),
        window: None,
        agent: "audit_reader",
        finds: &[],
        needs: &[],
    },
];

/// The keyring the router verifies against, from [`AGENTS`].
fn keyring() -> Keyring {
    AGENTS
        .iter()
        .fold(Keyring::new(), |ring, (agent, role, teams)| {
            ring.with(Credential::new(*agent, *role, support::KEY).in_teams(teams.iter().copied()))
        })
}

/// A fixture as the record an emitter would post.
fn record_of(fixture: &Fixture) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: fixture.received_at.to_owned(),
        received_at: fixture.received_at.to_owned(),
        backfilled: false,
        agent: fixture.agent.to_owned(),
        agent_ver: Some("1.4.0".to_owned()),
        correlation_id: Some(format!("corr-{}", fixture.label)),
        action: fixture.action.to_owned(),
        outcome: fixture.outcome,
        attrs: fixture
            .attrs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), attr_value(*value)))
            .collect(),
        entities: fixture
            .entities
            .iter()
            .map(|(kind, id)| EntityRef {
                kind: (*kind).to_owned(),
                id: (*id).to_owned(),
                role: entity::Role::Primary,
                confidence: 1.0,
            })
            .collect(),
        subjects: fixture
            .subject
            .map(|fill| {
                vec![SubjectRef {
                    hash: support::subject(fill),
                    role: SubjectRole::Principal,
                    canon_ver: CanonVer(1),
                }]
            })
            .unwrap_or_default(),
        visibility: fixture.visibility,
        team: fixture.team.map(str::to_owned),
        data_class: if fixture.subject.is_some() {
            DataClass::SubjectDerived
        } else {
            DataClass::Internal
        },
        redaction_policy: POLICY.to_owned(),
        fields_masked: Vec::new(),
        tags: vec![fixture.action.to_owned()],
        summary: fixture.body.to_owned(),
    }
}

/// The wire value for a table entry.
fn attr_value(attr: Attr) -> attrs::Value {
    match attr {
        Attr::Text(text) => attrs::Value::Text(text.to_owned()),
        Attr::Int(number) => attrs::Value::Int(number),
    }
}

/// Signs and sends one request, asserting only that it was answered.
async fn send(app: &axum::Router, method: Method, uri: &str, agent: &str, body: &[u8]) -> String {
    let request = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(auth::AGENT_HEADER, agent)
        .header(
            auth::SIGNATURE_HEADER,
            auth::sign(support::KEY, method.as_str(), uri, agent, body),
        )
        .body(Body::from(body.to_vec()))
        .expect("a well-formed request");

    let response = app.clone().oneshot(request).await.expect("answered");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let text = String::from_utf8(bytes.to_vec()).expect("a JSON answer");
    assert!(
        status.is_success(),
        "{method} {uri} as {agent} answered {status}: {text}"
    );
    text
}

/// Writes every fixture through `POST /records`, and returns each label's record.
///
/// Posted rather than handed to the pipeline, and posted *as the fixture's own agent*: the write is
/// what these queries are asserting about, so it goes the whole way in — signature, validation,
/// pipeline, index.
async fn write_fixtures(app: &axum::Router) -> BTreeMap<&'static str, ActionRecord> {
    let mut written = BTreeMap::new();
    for fixture in FIXTURES {
        let record = record_of(fixture);
        let request = yaam_contract::request::WriteRequest {
            record: record.clone(),
            body: Some(fixture.body.to_owned()),
        };
        let payload = serde_json::to_vec(&request).expect("a serialisable record");
        let answer = send(app, Method::POST, "/records", fixture.agent, &payload).await;
        let parsed: Value = serde_json::from_str(&answer).expect("JSON");
        assert_eq!(
            parsed["status"], "stored",
            "{} was not stored: {answer}",
            fixture.label
        );
        written.insert(fixture.label, record);
    }
    written
}

/// What a read answered: the structures it returned, and the bytes the caller received.
///
/// The raw text is kept because the strongest assertions here are about *absence* — a body that
/// came back under a field nobody parsed is a body that leaked, and a parsed check only sees the
/// fields somebody thought to look for.
struct Answer {
    /// Every structure in the answer, in the order it arrived.
    records: Vec<RecordStructure>,
    /// The answer as text.
    raw: String,
    /// The cost the answer reported for itself.
    token_estimate: usize,
}

/// Parses a `records` answer, whichever endpoint produced it.
fn parse_answer(raw: String) -> Answer {
    let parsed: Value = serde_json::from_str(&raw).expect("a JSON answer");
    let records: Vec<RecordStructure> =
        serde_json::from_value(parsed["records"].clone()).expect("structures");
    let token_estimate = usize::try_from(
        parsed["token_estimate"]
            .as_u64()
            .expect("every read reports what it cost"),
    )
    .expect("a plausible token estimate");
    Answer {
        records,
        raw,
        token_estimate,
    }
}

/// Asks one case's question, and returns the answer.
///
/// One read per row, whichever endpoint answers it: what the question selected is what came back,
/// so nothing here can assert about rows a request did not return.
async fn ask(case: &Case, app: &axum::Router) -> Answer {
    let uri = match case.ask {
        Ask::Ordered(uri) | Ask::Unordered(uri) => target(case, uri),
        Ask::Search(needle) => {
            // Full text takes no window, so a row that named one would have it quietly dropped.
            assert!(
                case.window.is_none(),
                "`{}` names a window a full-text read cannot apply",
                case.question
            );
            format!("/search?q={needle}&limit={SEARCH_LIMIT}")
        }
    };
    parse_answer(send(app, Method::GET, &uri, case.agent, b"").await)
}

/// A case's request target, with its window filled in.
fn target(case: &Case, uri: &str) -> String {
    let Some((from, to)) = case.window else {
        assert!(
            !uri.contains("{from}"),
            "`{uri}` interpolates a window the case does not name"
        );
        return uri.to_owned();
    };
    uri.replace("{from}", &millis(from).to_string())
        .replace("{to}", &millis(to).to_string())
}

/// A timestamp as the milliseconds a window is expressed in.
fn millis(at: &str) -> i64 {
    yaam_contract::timestamp::parse_ms(at).expect("a timestamp the contract can read")
}

/// The labels a set of structures corresponds to, by matching identifiers against what was written.
fn labels(records: &[RecordStructure], written: &BTreeMap<&str, ActionRecord>) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            written
                .iter()
                .find(|(_, fixture)| fixture.record_id == record.record_id)
                .map_or_else(
                    || format!("<unwritten {}>", record.record_id.as_str()),
                    |(label, _)| (*label).to_owned(),
                )
        })
        .collect()
}

/// One field of an answer as a golden row spells it: a string bare, anything else as its JSON.
fn as_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

/// Asserts one `Needs` against one returned record.
fn check(need: &Needs, record: &RecordStructure, question: &str) {
    let value = serde_json::to_value(record).expect("a serialisable structure");
    match need {
        Needs::Field(field, expected) => {
            let found = value.get(field).unwrap_or(&Value::Null);
            assert_eq!(
                &as_text(found),
                expected,
                "`{question}` answered with `{field}` = {found}, which the question needed"
            );
        }
        Needs::Attr(pair) => {
            let (key, expected) = pair.split_once('=').expect("an attribute as `key=value`");
            let found = value["attrs"].get(key).unwrap_or(&Value::Null);
            assert_eq!(
                as_text(found),
                expected,
                "`{question}` answered without the attribute `{pair}`: {found}"
            );
        }
        Needs::Entity(pair) => {
            let (kind, id) = pair.split_once(':').expect("an entity as `kind:id`");
            let named = value["entities"]
                .as_array()
                .expect("structure carries its entities")
                .iter()
                .any(|entity| entity["kind"] == kind && entity["id"] == id);
            assert!(named, "`{question}` answered without `{pair}`: {value}");
        }
    }
}

/// Asserts no answer carries prose, whatever field it might have arrived under.
///
/// Checked against the raw bytes and for every fixture's body, not only the ones the case matched: a
/// read that returned somebody else's body would be worse, not better.
fn no_prose_came_back(raw: &str, question: &str) {
    assert!(
        !raw.contains("summary"),
        "`{question}` named the record's prose field: {raw}"
    );
    for fixture in FIXTURES {
        // Long enough to be distinctive, short enough to catch a truncated body.
        let fragment = fixture
            .body
            .split_once(';')
            .map_or(fixture.body, |(head, _)| head);
        assert!(
            !raw.contains(fragment),
            "`{question}` returned the body of `{}`: {raw}",
            fixture.label
        );
    }
}

#[tokio::test]
async fn every_golden_query_finds_exactly_the_records_its_question_needs() {
    let tree = Tree::new();
    let app = router(AppState::new(
        Arc::new(keyring()),
        Arc::clone(&tree.service) as Arc<dyn Service>,
    ));
    let written = write_fixtures(&app).await;

    for case in GOLDEN {
        let question = case.question;
        let answer = ask(case, &app).await;
        let selected = answer.records.clone();
        let found = labels(&selected, &written);

        // The exact set, so a positive case is also a check that nothing else came back. Order is
        // asserted where the read promises one.
        match case.ask {
            Ask::Ordered(_) => assert_eq!(found, case.finds, "`{question}` (newest first)"),
            Ask::Unordered(_) | Ask::Search(_) => {
                let mut sorted = found.clone();
                sorted.sort();
                let mut expected: Vec<String> =
                    case.finds.iter().map(|label| (*label).to_owned()).collect();
                expected.sort();
                assert_eq!(sorted, expected, "`{question}`");
            }
        }

        for record in &selected {
            // The whole structure, field for field, against what was written. This is where "a read
            // returns the record's frontmatter" is pinned: a projection that dropped or rewrote a
            // field would pass every count above.
            let fixture = written
                .values()
                .find(|written| written.record_id == record.record_id)
                .expect("every answered record was written by this test");
            assert_eq!(record, &RecordStructure::from(fixture), "`{question}`");
            for need in case.needs {
                check(need, record, question);
            }
        }

        no_prose_came_back(&answer.raw, question);
        assert_eq!(
            answer.token_estimate,
            yaam_contract::structure::estimate_tokens(&answer.records),
            "`{question}` reported a cost that does not describe its own answer"
        );
        assert_eq!(
            answer.token_estimate == 0,
            answer.records.is_empty(),
            "`{question}` costed an answer it did not give: {}",
            answer.raw
        );
    }
}

/// No fixture may sit in the tree unasked, and no row may name a fixture that is not there.
///
/// Both halves rot silently. An unreferenced fixture is a record nothing asserts about, and a
/// mistyped label would make a row's expectation unsatisfiable in a way that reads like a bug in the
/// store rather than a typo in the table.
#[test]
fn the_table_and_the_fixtures_describe_each_other() {
    let known: Vec<&str> = FIXTURES.iter().map(|fixture| fixture.label).collect();
    for case in GOLDEN {
        for label in case.finds {
            assert!(known.contains(label), "`{}` names `{label}`", case.question);
        }
    }
    for label in &known {
        assert!(
            GOLDEN.iter().any(|case| case.finds.contains(label)),
            "`{label}` is written and no golden query asks for it"
        );
    }
}

/// The read projection is the shape every assertion above compares against.
///
/// A tripwire, not a rule: a nineteenth field became a twentieth without anybody deciding what the
/// golden set should ask of it, and a full-structure comparison would keep passing regardless.
#[test]
fn the_read_projection_still_has_the_fields_this_set_was_written_against() {
    let record = record_of(&FIXTURES[0]);
    let structure = serde_json::to_value(RecordStructure::from(&record)).expect("serialisable");
    let fields = structure.as_object().expect("an object").len();
    assert_eq!(
        fields, 19,
        "the read projection has {fields} fields; decide what the golden set asks of the change"
    );
    assert!(
        !structure
            .as_object()
            .expect("an object")
            .contains_key("summary"),
        "the projection grew a prose field: {structure}"
    );
}
