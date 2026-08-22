//! The seam nobody's own tests could see: a real sidecar talking to a real service.
//!
//! Both crates passed their own suites while the system did not work — the sidecar posted unsigned
//! bytes the service had no key to open, and neither test suite had the other side in it. So this
//! test runs [`yaam_agent::listener::serve`] against [`yaam_server::routes::router`] over a real
//! socket and a real port, and asserts a record written by a caller is in the service's tree, and
//! that the caller can read it back without ever holding a key.
//!
//! Anything that changes the wire — the canonical signed message, the envelope, the request shape —
//! fails here, which is the only place it can fail before a deployment.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use yaam_agent::listener::{self, CallerSocket, Limits};
use yaam_agent::upstream::{Credentials, Upstream};
use yaam_contract::request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys};
use yaam_crypto::envelope;
use yaam_server::auth::Role;
use yaam_server::routes::{AppState, router};
use yaam_server::service::Service;
use yaam_store::query::Filter;

use support::{KEY, Tree, caller, keyring, record};

/// A service listening on an ephemeral port, and the tree behind it.
async fn service(secret: &[u8]) -> (Tree, String) {
    let tree = Tree::new();
    let app = router(
        AppState::new(
            Arc::new(keyring()),
            Arc::clone(&tree.service) as Arc<dyn Service>,
        )
        .unsealing_with(secret.to_vec()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (tree, base_url)
}

/// A sidecar for `agent`, pointed at `base_url`, serving one socket in `state`.
async fn sidecar(agent: &str, base_url: &str, public: &[u8], state: &Path) -> std::path::PathBuf {
    sidecar_masking(agent, base_url, public, state, None).await
}

/// As [`sidecar`], with a redaction policy fitted.
async fn sidecar_masking(
    agent: &str,
    base_url: &str,
    public: &[u8],
    state: &Path,
    redaction: Option<yaam_contract::mask::Policy>,
) -> std::path::PathBuf {
    let path = state.join(format!("{agent}.sock"));
    let upstream = Upstream {
        base_url: base_url.to_owned(),
        service_public_key: public.to_vec(),
        credentials: Credentials::new().with(agent, SigningKeys::new(KEY)),
    };
    let sockets = vec![CallerSocket {
        agent: agent.to_owned(),
        path: path.clone(),
    }];
    let state = state.to_path_buf();
    tokio::spawn(async move {
        listener::serve_with(&sockets, &state, &upstream, Limits::default(), redaction)
            .await
            .expect("sidecar");
    });

    // Connectability, not existence: the socket file appears before it accepts.
    for _ in 0..200 {
        if UnixStream::connect(&path).await.is_ok() {
            return path;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the sidecar never accepted a connection");
}

/// The read socket beside a record socket, named the way the library names it.
///
/// Derived through [`CallerSocket::read_path`] rather than spelled out here: a test that wrote the
/// name itself would keep passing after the sidecar started using a different one.
fn read_socket(agent: &str, record: &Path) -> PathBuf {
    CallerSocket {
        agent: agent.to_owned(),
        path: record.to_path_buf(),
    }
    .read_path()
}

/// Waits until a socket answers.
async fn await_socket(path: &Path) {
    for _ in 0..200 {
        if UnixStream::connect(path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{} never accepted a connection", path.display());
}

/// Sends one raw HTTP request to a read socket and returns the whole answer.
///
/// Raw text rather than a client, because what is under test is that the socket speaks HTTP/1.1 at
/// all — a client that shares this repository's own idea of a request would prove less.
async fn read_through(path: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(path).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .await
        .expect("read the answer");
    String::from_utf8_lossy(&answer).into_owned()
}

/// Sends one raw HTTP request straight at the service, with no sidecar in the way.
async fn read_directly(base_url: &str, request: &str) -> String {
    let authority = base_url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(authority).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .await
        .expect("read the answer");
    String::from_utf8_lossy(&answer).into_owned()
}

/// Writes one record line to a caller socket and returns the sidecar's answer.
async fn submit(path: &Path, line: &str) -> String {
    let stream = UnixStream::connect(path).await.expect("connect");
    let (read, mut write) = stream.into_split();
    write.write_all(line.as_bytes()).await.expect("write");
    let mut answer = String::new();
    BufReader::new(read)
        .read_line(&mut answer)
        .await
        .expect("answer");
    answer.trim().to_owned()
}

#[tokio::test]
async fn a_record_written_to_a_sidecar_reaches_the_service() {
    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;

    let doc = record("agent_a", "2026-08-20T09:00:00Z");
    let id = doc.record_id.clone();
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));

    assert_eq!(
        submit(&socket, &line).await,
        r#"{"status":"accepted"}"#,
        "the sidecar reports what the service said, so this is the service accepting it"
    );
    assert!(tree.holds(&id), "the record is not in the service's tree");

    // And it is readable back through the service, under the writer's own scope — as structure,
    // which is the only shape a read hands back.
    let writer = caller("agent_a", Role::Writer, &["platform"]);
    let read = tree
        .service
        .query(&writer, &Filter::default())
        .expect("query");
    assert_eq!(read.len(), 1, "{read:?}");
    assert_eq!(read[0].record_id, id);
    assert_eq!(read[0].action, doc.action);

    // A replay of the same record is a duplicate, not a second copy: the sidecar's retry is safe
    // end to end, not only inside the pipeline.
    assert_eq!(submit(&socket, &line).await, r#"{"status":"accepted"}"#);
    assert_eq!(
        tree.service
            .query(&writer, &Filter::default())
            .expect("query")
            .len(),
        1
    );
}

#[tokio::test]
async fn a_masking_sidecar_turns_a_rejected_body_into_an_accepted_redacted_one() {
    // Without a policy fitted, the service refuses this body permanently and the record is simply
    // lost: `invalid` is not retried, so a caller that forgets to redact loses its history. With one
    // fitted the record lands, redacted, and says so in its own account.
    let policy = yaam_contract::mask::Policy::from_yaml(
        // The policy the deployment ships, not a fixture: a sidecar masking with different
        // patterns than the service checks would pass this test and fail in the field.
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../spec/redaction/default.yaml"),
        )
        .expect("shipped policy"),
    )
    .expect("policy");

    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar_masking("agent_a", &base_url, &public, state.path(), Some(policy)).await;

    let mut doc = record("agent_a", "2026-08-20T09:00:00Z");
    doc.summary = "deploy failed, retried with bearer aaaaaaaaaaaaaaaaaaaa".to_owned();
    let id = doc.record_id.clone();
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));

    assert_eq!(
        submit(&socket, &line).await,
        r#"{"status":"accepted"}"#,
        "the service refuses an unredacted body, so acceptance means the sidecar masked it"
    );
    assert!(tree.holds(&id));

    let writer = caller("agent_a", Role::Writer, &["platform"]);
    let read = tree
        .service
        .query(&writer, &Filter::default())
        .expect("query");
    assert_eq!(read.len(), 1, "{read:?}");
    // The record's own account of its redaction, which is the field a reader trusts.
    assert!(
        read[0].fields_masked.contains(&"bearer_token".to_owned()),
        "{:?}",
        read[0].fields_masked
    );
}

#[tokio::test]
async fn an_unredacted_body_is_still_refused_when_no_policy_is_fitted() {
    // The other half, and the reason fitting a policy is worth the trouble: nothing masks, so the
    // service's check is the only thing standing there and the record does not land.
    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;

    let mut doc = record("agent_a", "2026-08-20T09:00:00Z");
    doc.summary = "deploy failed, retried with bearer aaaaaaaaaaaaaaaaaaaa".to_owned();
    let id = doc.record_id.clone();
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));

    let answer = submit(&socket, &line).await;
    assert!(
        answer.contains("rejected") || answer.contains("redact"),
        "expected a refusal naming redaction, got {answer}"
    );
    assert!(!tree.holds(&id), "an unredacted record must not land");
}

#[tokio::test]
async fn a_sidecar_signing_with_the_wrong_key_is_refused_rather_than_stored() {
    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");

    let path = state.path().join("agent_a.sock");
    let upstream = Upstream {
        base_url,
        service_public_key: public.to_vec(),
        credentials: Credentials::new()
            .with("agent_a", SigningKeys::new(b"the-wrong-key".to_vec())),
    };
    let sockets = vec![CallerSocket {
        agent: "agent_a".to_owned(),
        path: path.clone(),
    }];
    let dir = state.path().to_path_buf();
    tokio::spawn(async move {
        listener::serve_with(&sockets, &dir, &upstream, Limits::default(), None)
            .await
            .expect("sidecar");
    });
    for _ in 0..200 {
        if UnixStream::connect(&path).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let doc = record("agent_a", "2026-08-20T09:00:00Z");
    let id = doc.record_id.clone();
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));
    let answer = submit(&path, &line).await;

    // `401` is permanent: no amount of resending a wrongly signed record makes it acceptable, and
    // spooling it would fill the spool with records that can never land.
    assert!(answer.contains(r#""status":"rejected""#), "{answer}");
    assert!(!tree.holds(&id));
    assert!(
        std::fs::read_dir(state.path().join("spool"))
            .expect("spool dir")
            .next()
            .is_none(),
        "a rejected record must not be spooled"
    );
}

#[tokio::test]
async fn a_service_with_no_unsealing_key_holds_the_record_rather_than_dropping_it() {
    let (_secret, public) = envelope::generate_keypair();
    // Deployed without the secret half: the sidecar seals to a key the service cannot open.
    let tree = Tree::new();
    let app = router(AppState::new(
        Arc::new(keyring()),
        Arc::clone(&tree.service) as Arc<dyn Service>,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;
    let doc = record("agent_a", "2026-08-20T09:00:00Z");
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));

    assert_eq!(
        submit(&socket, &line).await,
        r#"{"status":"spooled"}"#,
        "an operator's key mistake must not make a caller lose its record"
    );
    assert!(!tree.holds(&doc.record_id));
    assert!(
        std::fs::read_dir(state.path().join("spool"))
            .expect("spool dir")
            .next()
            .is_some(),
        "the record is the sidecar's until the service can open it"
    );
}

#[tokio::test]
async fn a_read_reaches_the_service_only_because_the_sidecar_signs_it() {
    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;
    let reads = read_socket("agent_a", &socket);
    await_socket(&reads).await;

    // Written through the record socket, which is the only way a record gets in.
    let doc = record("agent_a", "2026-08-20T09:00:00Z");
    let id = doc.record_id.clone();
    let line = format!("{}\n", serde_json::to_string(&doc).expect("serialise"));
    assert_eq!(submit(&socket, &line).await, r#"{"status":"accepted"}"#);

    // Read back by a caller that holds no signing key at all.
    let answer = read_through(
        &reads,
        "GET /records HTTP/1.1\r\nhost: sidecar\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
    assert!(
        answer.contains(id.as_str()),
        "the service's own answer has to come back whole: {answer}"
    );

    // The same read, unsigned, straight at the service. This is what the caller could do for
    // itself, and it is why the proxy exists rather than being a convenience.
    let refused = read_directly(
        &base_url,
        "GET /records HTTP/1.1\r\nhost: service\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 401 "), "{refused}");
    assert!(refused.contains("unauthenticated"), "{refused}");
    assert!(tree.holds(&id));
}

#[tokio::test]
async fn a_signature_valid_for_one_query_is_refused_on_another() {
    let (secret, _public) = envelope::generate_keypair();
    let (_tree, base_url) = service(&secret).await;

    // The signature a sidecar would put on `?limit=1`, from the one shared spelling of the message.
    let signed = SigningKeys::new(KEY.to_vec()).sign("GET", "/records?limit=1", "agent_a", b"");
    // The header names come from the contract, not from this file: a test that spelled them out
    // would keep passing after the service started reading different ones.
    let request = |target: &str| {
        format!(
            "GET {target} HTTP/1.1\r\nhost: service\r\n{AGENT_HEADER}: \
             agent_a\r\n{SIGNATURE_HEADER}: {signed}\r\nconnection: close\r\n\r\n"
        )
    };

    let accepted = read_directly(&base_url, &request("/records?limit=1")).await;
    assert!(accepted.starts_with("HTTP/1.1 200 "), "{accepted}");

    // Same key, same agent, same body, one different filter. For a read the query *is* the request,
    // so lifting the signature onto another one has to fail.
    let refused = read_directly(&base_url, &request("/records?limit=2")).await;
    assert!(refused.starts_with("HTTP/1.1 401 "), "{refused}");
}

#[tokio::test]
async fn a_write_on_the_read_socket_is_refused_and_never_reaches_the_service() {
    let (secret, public) = envelope::generate_keypair();
    let (tree, base_url) = service(&secret).await;
    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;
    let reads = read_socket("agent_a", &socket);
    await_socket(&reads).await;

    let doc = record("agent_a", "2026-08-20T09:00:00Z");
    let body = serde_json::to_string(&serde_json::json!({"record": doc})).expect("serialise");
    let answer = read_through(
        &reads,
        &format!(
            "POST /records HTTP/1.1\r\nhost: sidecar\r\ncontent-type: application/json\r\ncontent\
             -length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;

    // Refused here, not forwarded: a record proxied as HTTP would skip the sealing and the spool
    // that the record socket gives it, and the caller could not tell.
    assert!(answer.starts_with("HTTP/1.1 405 "), "{answer}");
    assert!(answer.to_lowercase().contains("allow: get"), "{answer}");
    assert!(!tree.holds(&doc.record_id), "it must not have been written");
    assert!(
        std::fs::read_dir(state.path().join("spool"))
            .expect("spool dir")
            .next()
            .is_none(),
        "and it must not have been queued"
    );
}

#[tokio::test]
async fn an_unreachable_service_fails_the_read_rather_than_queueing_it() {
    let (_secret, public) = envelope::generate_keypair();
    // Bind and drop, so the port is almost certainly nobody's.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);

    let state = tempfile::tempdir().expect("state dir");
    let socket = sidecar("agent_a", &base_url, &public, state.path()).await;
    let reads = read_socket("agent_a", &socket);
    await_socket(&reads).await;

    let answer = read_through(
        &reads,
        "GET /records HTTP/1.1\r\nhost: sidecar\r\nconnection: close\r\n\r\n",
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 503 "), "{answer}");
    assert!(
        std::fs::read_dir(state.path().join("spool"))
            .expect("spool dir")
            .next()
            .is_none(),
        "a spooled read would be answered later with data that was already stale"
    );
}
