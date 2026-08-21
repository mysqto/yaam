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
    assert_eq!(
        service.query(&writer, &filter).expect("query"),
        vec![id.clone()],
        "the scope comes from the caller, not from the filter the request built"
    );

    // Entity lookup.
    assert_eq!(
        service
            .entity(&writer, "ticket", "PROJ-42", 1.0)
            .expect("entity"),
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
    assert_eq!(bundle.records, vec![id.clone()]);
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
    let after = service.query(&writer, &Filter::default()).expect("query");
    assert!(after.contains(&id), "{after:?}");
    assert!(after.contains(&sealed_id), "{after:?}");
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
        service
            .entity(&writer, "ticket", "  proj-42 ", 1.0)
            .expect("entity"),
        vec![id.clone()]
    );

    let request = bundle::Request {
        entities: vec![("ticket".to_owned(), "proj-42".to_owned())],
        deadline_ms: 5_000,
        ..bundle::Request::default()
    };
    assert_eq!(
        service.bundle(&writer, &request).expect("bundle").records,
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
            .entity(&reader, kind, id, 0.0)
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

/// The record ids `agent` sees from `GET /records`.
async fn visible_to(app: &axum::Router, agent: &str) -> Vec<String> {
    let uri = "/records";
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

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    answer["records"]
        .as_array()
        .expect("a records array")
        .iter()
        .map(|id| id.as_str().expect("a record id").to_owned())
        .collect()
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
