//! The service over a real tree: the write path, the read paths, and who may see what.
//!
//! Every test here goes through `CoreService` and the router rather than a fake, because the
//! delegations into `yaam-core` and the visibility predicates in `yaam-store` are exactly what a
//! handler test with a fake cannot check: a fake answers whatever it was told to.

mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt;
use yaam_contract::{RecordId, Visibility};
use yaam_core::bundle;
use yaam_core::pipeline::Accepted;
use yaam_server::auth::{self, Role};
use yaam_server::routes::{AppState, router};
use yaam_server::service::Service;
use yaam_store::query::Filter;

use support::{BODY, KEY, Tree, caller, keyring, record, subject, subject_record};

/// The identifiers a read answered with.
///
/// A read hands back structure, and most assertions here are about *which* records reached the
/// caller; the ones about what a record carries read the structure itself.
fn read_ids(records: &[yaam_contract::RecordStructure]) -> Vec<RecordId> {
    records
        .iter()
        .map(|record| record.record_id.clone())
        .collect()
}

#[test]
fn a_record_written_through_the_service_is_queryable_bundled_and_then_erasable() {
    let tree = Tree::new();
    let service = Arc::clone(&tree.service);
    let writer = caller("agent_a", Role::Writer, &["platform"]);
    let operator = caller("agent_ops", Role::Operator, &["platform"]);

    // Write.
    let internal = record("agent_a", "2026-08-20T09:00:00Z");
    let id = internal.record_id.clone();
    let accepted = service
        .write(&writer, internal.clone(), BODY)
        .expect("written");
    assert_eq!(accepted, Accepted::Stored(id.clone()));
    assert!(tree.holds(&id), "the tree is what the record is stored in");

    // A replay changes nothing, which is what makes a sidecar's retry safe.
    assert_eq!(
        service
            .write(&writer, internal.clone(), BODY)
            .expect("replay"),
        Accepted::Duplicate(id.clone())
    );

    // Query.
    let filter = Filter {
        action: Some("deploy".to_owned()),
        ..Filter::default()
    };
    let queried = service.query(&writer, &filter).expect("query");
    assert_eq!(
        read_ids(&queried),
        vec![id.clone()],
        "the scope comes from the caller, not from the filter the request built"
    );
    // The read is structure, taken from the record's stored frontmatter.
    assert_eq!(queried[0], yaam_contract::RecordStructure::from(&internal));

    // Entity lookup.
    assert_eq!(
        read_ids(
            &service
                .entity(&writer, "ticket", "PROJ-42", 1.0, None, None)
                .expect("entity")
        ),
        vec![id.clone()]
    );

    // Bundle.
    let request = bundle::Request {
        entities: vec![("ticket".to_owned(), "PROJ-42".to_owned())],
        actor: Some("agent_a".to_owned()),
        deadline_ms: 5_000,
        ..bundle::Request::default()
    };
    let bundle = service.bundle(&writer, &request).expect("bundle");
    assert_eq!(read_ids(&bundle.records), vec![id.clone()]);
    assert!(!bundle.degraded, "{:?}", bundle.omitted);

    // Erase, which needs a record whose body is sealed to a subject.
    let subject = subject('a');
    let sealed = subject_record("agent_a", "2026-08-21T09:00:00Z", &subject);
    let sealed_id = sealed.record_id.clone();
    service.write(&writer, sealed, BODY).expect("sealed write");
    assert!(
        !tree.file_of(&sealed_id).contains("shards"),
        "sealed on disk"
    );

    let report = service.erase(&operator, &subject).expect("erased");
    assert_eq!(report.bodies_sealed_off, 1);
    assert!(report.keys_destroyed > 0, "{report:?}");
    assert!(report.tombstone_id.starts_with("tomb-"));

    // The internal record survives the rebuild erasure runs, and the erased one keeps its
    // frontmatter — which is what the endpoint's `retained` field tells a caller.
    let after = read_ids(&service.query(&writer, &Filter::default()).expect("query"));
    assert!(after.contains(&id), "{after:?}");
    assert!(after.contains(&sealed_id), "{after:?}");
}

/// Fan-out and the sweeper have no other caller in a running deployment.
///
/// A write enqueues fan-out inside its own transaction and leaves it there; nothing publishes an
/// entity timeline or a subject audit record until something drains the queue. Before this method
/// existed a service could answer every request correctly while that work never happened at all.
#[test]
fn maintenance_is_what_makes_the_derived_files_appear() {
    let tree = Tree::new();
    let service = Arc::clone(&tree.service);
    let writer = caller("agent_a", Role::Writer, &["platform"]);

    service
        .write(&writer, record("agent_a", "2026-08-20T09:00:00Z"), BODY)
        .expect("written");
    let timeline = tree.root().join("entities/ticket/PROJ-42/timeline.md");
    assert!(
        !timeline.exists(),
        "the write queues the work rather than doing it"
    );

    let first = service.maintain(64).expect("maintenance");
    assert!(first.fanout_settled > 0, "{first:?}");
    assert!(!first.did_nothing());
    assert!(timeline.is_file(), "the timeline is fan-out's own output");

    // Idempotent, and quiet once there is nothing owed: a service doing this on a timer would
    // otherwise report work on every round for ever.
    let second = service.maintain(64).expect("maintenance");
    assert!(
        second.did_nothing(),
        "a second round has nothing left to do: {second:?}"
    );
}

#[test]
fn a_record_the_deployment_does_not_configure_is_refused_before_anything_is_written() {
    let tree = Tree::new();
    let writer = caller("agent_a", Role::Writer, &["platform"]);
    let mut record = record("agent_a", "2026-08-20T09:00:00Z");
    // An entity id the repository's spec cannot canonicalise: the write must not half-happen.
    record.entities[0].id = "not a ticket".to_owned();
    let id = record.record_id.clone();

    let error = tree
        .service
        .write(&writer, record, BODY)
        .expect_err("an unconfigured entity id");
    assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!tree.holds(&id));
}

#[test]
fn a_read_canonicalises_its_identifier_rather_than_answering_nothing() {
    let tree = Tree::new();
    let service = Arc::clone(&tree.service);
    let writer = caller("agent_a", Role::Writer, &["platform"]);
    let stored = record("agent_a", "2026-08-20T09:00:00Z");
    let id = stored.record_id.clone();
    service.write(&writer, stored, BODY).expect("written");

    // The write stored the canonical `PROJ-42`. A read that matched the caller's spelling as sent
    // would answer nothing — and nothing is indistinguishable from "this entity has no history",
    // which is the worst kind of wrong answer because it looks like a fact.
    assert_eq!(
        read_ids(
            &service
                .entity(&writer, "ticket", "  proj-42 ", 1.0, None, None)
                .expect("entity")
        ),
        vec![id.clone()]
    );

    let request = bundle::Request {
        entities: vec![("ticket".to_owned(), "proj-42".to_owned())],
        deadline_ms: 5_000,
        ..bundle::Request::default()
    };
    assert_eq!(
        read_ids(&service.bundle(&writer, &request).expect("bundle").records),
        vec![id]
    );
}

#[test]
fn a_read_the_deployment_cannot_canonicalise_is_refused_rather_than_answered_empty() {
    let tree = Tree::new();
    let reader = caller("agent_b", Role::Reader, &["support"]);

    // An identifier the kind's pattern does not admit, and a kind nothing configures. Both are
    // questions this deployment cannot be asked, and the write path already says so with a `422`.
    for (kind, id) in [("ticket", "not a ticket"), ("no_such_kind", "PROJ-42")] {
        let error = tree
            .service
            .entity(&reader, kind, id, 0.0, None, None)
            .expect_err("an unaskable entity read");
        assert_eq!(
            error.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{kind}/{id}"
        );

        let request = bundle::Request {
            entities: vec![(kind.to_owned(), id.to_owned())],
            deadline_ms: 5_000,
            ..bundle::Request::default()
        };
        let error = tree
            .service
            .bundle(&reader, &request)
            .expect_err("an unaskable bundle term");
        assert_eq!(
            error.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{kind}/{id}"
        );
    }
}

/// A tree holding one record per visibility, and the router over it.
fn scoped_tree() -> (Tree, axum::Router, Vec<RecordId>) {
    let tree = Tree::new();
    let operator = caller("agent_ops", Role::Operator, &["platform"]);
    let mut ids = Vec::new();

    for (visibility, team, agent) in [
        (Visibility::Org, None, "agent_a"),
        (Visibility::Team, Some("platform"), "agent_a"),
        (Visibility::Team, Some("support"), "agent_a"),
        (Visibility::Owner, None, "agent_ops"),
        (Visibility::Operator, None, "agent_ops"),
    ] {
        let mut doc = record(agent, "2026-08-20T09:00:00Z");
        doc.visibility = visibility;
        doc.team = team.map(str::to_owned);
        ids.push(doc.record_id.clone());
        // Written as the operator: what is under test is the read side, and a write of somebody
        // else's record is refused earlier, at the handler.
        tree.service.write(&operator, doc, BODY).expect("written");
    }

    let app = router(AppState::new(
        Arc::new(keyring()),
        Arc::clone(&tree.service) as Arc<dyn Service>,
    ));
    (tree, app, ids)
}

/// One signed read, as the response the caller receives.
async fn read_response(app: &axum::Router, agent: &str, uri: &str) -> axum::response::Response {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(auth::AGENT_HEADER, agent)
        .header(
            auth::SIGNATURE_HEADER,
            auth::sign(KEY, "GET", uri, agent, b""),
        )
        .body(Body::empty())
        .unwrap();

    app.clone().oneshot(request).await.unwrap()
}

/// One signed read, as text: what a caller actually receives, before anything parses it.
///
/// Text rather than a parsed value for the tests that assert on *absence* — a field nobody looked
/// for is a field no parsed assertion notices.
async fn read_as(app: &axum::Router, agent: &str, uri: &str) -> String {
    let response = read_response(app, agent, uri).await;
    assert_eq!(response.status(), StatusCode::OK, "{uri} as {agent}");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).expect("a JSON answer")
}

/// The record ids `agent` sees from `GET /records`.
async fn visible_to(app: &axum::Router, agent: &str) -> Vec<String> {
    let body = read_as(app, agent, "/records").await;
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    answer["records"]
        .as_array()
        .expect("a records array")
        .iter()
        .map(|record| {
            record["record_id"]
                .as_str()
                .expect("every structure names its record")
                .to_owned()
        })
        .collect()
}

/// The records `agent` finds by full text, in identifier order.
///
/// Sorted rather than taken in the order they arrived: the route answers best match first, and every
/// record in the scoped fixture holds the same body, so they all match equally well and their order
/// is not something a test may pin. What is being asserted is *which* records, not their order.
async fn found_by(app: &axum::Router, agent: &str, needle: &str) -> Vec<RecordId> {
    let body = read_as(app, agent, &format!("/search?q={needle}")).await;
    let answer: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
    let structures: Vec<yaam_contract::RecordStructure> =
        serde_json::from_value(answer["records"].clone()).expect("structures");
    let mut found = read_ids(&structures);
    found.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    found
}

#[tokio::test]
async fn a_read_returns_only_what_the_authenticated_caller_may_see() {
    let (_tree, app, ids) = scoped_tree();
    let [org, platform_team, support_team, owned, audit] =
        [0, 1, 2, 3, 4].map(|at| ids[at].as_str());

    // A reader on one team: no other team's records, and no audit trail.
    let support_reader = visible_to(&app, "agent_b").await;
    assert!(
        support_reader.contains(&org.to_owned()),
        "{support_reader:?}"
    );
    assert!(support_reader.contains(&support_team.to_owned()));
    assert!(
        !support_reader.contains(&platform_team.to_owned()),
        "another team's record reached a reader: {support_reader:?}"
    );
    assert!(!support_reader.contains(&audit.to_owned()));

    // The other team's reader sees the mirror image of that.
    let platform_writer = visible_to(&app, "agent_a").await;
    assert!(platform_writer.contains(&platform_team.to_owned()));
    assert!(!platform_writer.contains(&support_team.to_owned()));

    // The owner-visible record is the operator's own, and nobody else's to read.
    assert!(
        !platform_writer.contains(&owned.to_owned()),
        "an owner-visible record of another agent reached {platform_writer:?}"
    );
    assert!(!support_reader.contains(&owned.to_owned()));

    let operator_sees = visible_to(&app, "agent_ops").await;
    assert!(
        operator_sees.contains(&owned.to_owned()),
        "{operator_sees:?}"
    );
    // And the audit record, which only an operator's scope admits.
    assert!(
        operator_sees.contains(&audit.to_owned()),
        "{operator_sees:?}"
    );
}

/// Every read hands back structure, and none of them hands back a body.
///
/// Asserted over a record of each data class, on all three reads, against the raw answer: the point
/// is what is *absent*, and a parsed assertion only sees fields somebody thought to look for.
#[tokio::test]
async fn no_read_returns_a_body_for_either_data_class() {
    let tree = Tree::new();
    let operator = caller("agent_ops", Role::Operator, &["platform"]);

    let plain = record("agent_a", "2026-08-20T09:00:00Z");
    tree.service
        .write(&operator, plain.clone(), BODY)
        .expect("written");
    let sealed = subject_record("agent_a", "2026-08-21T09:00:00Z", &subject('a'));
    tree.service
        .write(&operator, sealed.clone(), BODY)
        .expect("written");

    let app = router(AppState::new(
        Arc::new(keyring()),
        Arc::clone(&tree.service) as Arc<dyn Service>,
    ));

    for uri in [
        "/records",
        // The needle matches the plaintext body, so this read has prose in hand and still must not
        // hand any back. The sealed record indexes no text and so cannot match at all.
        "/search?q=shards",
        "/entities/ticket/PROJ-42",
        "/entities/order_ref/ord10014721",
        "/bundle?entity=ticket:PROJ-42,order_ref:ord10014721",
    ] {
        let body = read_as(&app, "agent_b", uri).await;
        assert!(
            !body.contains("summary"),
            "{uri} named the record's prose field: {body}"
        );
        assert!(!body.contains(BODY), "{uri} returned a body: {body}");
        // A word only the body has, so a partial body is caught as well as a whole one.
        assert!(BODY.contains("shards"), "the fixture body moved: {BODY}");
        assert!(!body.contains("shards"), "{uri} returned prose: {body}");
    }

    // Both classes were in the answers above, so the assertions had something to catch. The classes
    // are named back to the caller, which is how it knows what it is *not* being given.
    let answer: serde_json::Value =
        serde_json::from_str(&read_as(&app, "agent_b", "/records").await).expect("JSON");
    let classes: Vec<&str> = answer["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| record["data_class"].as_str().expect("a data class"))
        .collect();
    assert!(classes.contains(&"internal"), "{classes:?}");
    assert!(classes.contains(&"subject_derived"), "{classes:?}");

    // And the structure is the record's own, field for field.
    let structures: Vec<yaam_contract::RecordStructure> =
        serde_json::from_value(answer["records"].clone()).expect("structures");
    for written in [&plain, &sealed] {
        let found = structures
            .iter()
            .find(|found| found.record_id == written.record_id)
            .expect("the record is in the answer");
        assert_eq!(found, &yaam_contract::RecordStructure::from(written));
    }
}

/// A caller outside a record's scope receives neither its structure nor its id.
///
/// The raw answer is searched for the hidden record's identifier: the read now carries structure, and
/// a record that leaked would leak more than a name.
#[tokio::test]
async fn a_caller_outside_a_records_scope_receives_neither_its_structure_nor_its_id() {
    let (_tree, app, ids) = scoped_tree();
    // The platform team's record, the operator's own, and the audit trail: none of them is a
    // support-team reader's to see.
    let hidden = [ids[1].as_str(), ids[3].as_str(), ids[4].as_str()];

    for uri in [
        "/records",
        "/search?q=shards",
        "/entities/ticket/PROJ-42",
        "/bundle?entity=ticket:PROJ-42",
    ] {
        let body = read_as(&app, "agent_b", uri).await;
        for id in hidden {
            assert!(
                !body.contains(id),
                "{uri} handed `{id}` to a caller outside its scope: {body}"
            );
        }
        // Not vacuous: the records this caller may read are there.
        assert!(body.contains(ids[0].as_str()), "{uri}: {body}");
        assert!(body.contains(ids[2].as_str()), "{uri}: {body}");
    }
}

/// Full text is narrowed by the caller's scope, and narrowed by the query rather than after it.
///
/// The fixture is what makes this assert something: every record in it carries the same body, so the
/// needle matches all five and only the scope predicate can tell the answers apart. A search that
/// forgot it would hand every caller the whole tree — including the audit trail and another team's
/// records, neither of which any other read admits.
#[tokio::test]
async fn a_full_text_read_is_scoped_to_the_caller_like_every_other_read() {
    let (_tree, app, ids) = scoped_tree();
    assert!(BODY.contains("shards"), "the fixture body moved: {BODY}");

    // A reader on one team: the org-visible record and its own team's, and nothing else.
    let support_reader = found_by(&app, "agent_b", "shards").await;
    assert_eq!(support_reader, vec![ids[0].clone(), ids[2].clone()]);
    // The other team's reader sees the mirror image, from the same needle.
    let platform_writer = found_by(&app, "agent_a", "shards").await;
    assert_eq!(platform_writer, vec![ids[0].clone(), ids[1].clone()]);
    // The operator adds its own owner-visible record and the audit trail, and no other team's.
    let operator_sees = found_by(&app, "agent_ops", "shards").await;
    assert_eq!(
        operator_sees,
        vec![
            ids[0].clone(),
            ids[1].clone(),
            ids[3].clone(),
            ids[4].clone()
        ],
        "an operator's reach is the audit level, not every team"
    );

    // Not vacuous in the other direction either: a needle no body holds finds nothing for anybody.
    assert!(
        found_by(&app, "agent_ops", "unwrittenneedle")
            .await
            .is_empty()
    );
}

/// A needle the match syntax will not take is the caller's mistake, and permanent.
///
/// `422` and not `500`: prefix and phrase syntax reaches the caller, so a needle that will not parse
/// is a request to fix rather than a service to retry against. An empty needle is the same mistake
/// spelled shorter — a search for nothing, which is not a search for everything.
#[tokio::test]
async fn a_needle_the_match_syntax_refuses_is_permanent_and_not_this_services_fault() {
    let (_tree, app, _ids) = scoped_tree();

    for needle in ["unbalanced%20%22%20quote", ""] {
        let uri = format!("/search?q={needle}");
        let status = read_response(&app, "agent_b", &uri).await.status();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
    }
}

#[tokio::test]
async fn entity_history_and_bundles_are_scoped_too() {
    let (_tree, app, _ids) = scoped_tree();

    // Every record in the fixture names the same ticket, so an unscoped read would return all five.
    for endpoint in ["/entities/ticket/PROJ-42", "/bundle?entity=ticket:PROJ-42"] {
        let agent = "agent_b";
        let request = Request::builder()
            .method(Method::GET)
            .uri(endpoint)
            .header(auth::AGENT_HEADER, agent)
            .header(
                auth::SIGNATURE_HEADER,
                auth::sign(KEY, "GET", endpoint, agent, b""),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let count = answer["records"].as_array().expect("records").len();
        // This caller may read two of them: the org-wide one and its own team's.
        assert_eq!(count, 2, "{endpoint} returned {answer:?}");
    }
}
