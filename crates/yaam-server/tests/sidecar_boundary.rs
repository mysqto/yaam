//! The seam nobody's own tests could see: a real sidecar posting to a real service.
//!
//! Both crates passed their own suites while the system did not work — the sidecar posted unsigned
//! bytes the service had no key to open, and neither test suite had the other side in it. So this
//! test runs [`yaam_agent::listener::serve`] against [`yaam_server::routes::router`] over a real
//! socket and a real port, and asserts a record written by a caller is in the service's tree.
//!
//! Anything that changes the wire — the canonical signed message, the envelope, the request shape —
//! fails here, which is the only place it can fail before a deployment.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use yaam_agent::listener::{self, CallerSocket, Limits};
use yaam_agent::upstream::{Credentials, Upstream};
use yaam_contract::request::SigningKeys;
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
        listener::serve_with(&sockets, &state, &upstream, Limits::default())
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

    // And it is readable back through the service, under the writer's own scope.
    let writer = caller("agent_a", Role::Writer, &["platform"]);
    assert_eq!(
        tree.service
            .query(&writer, &Filter::default())
            .expect("query"),
        vec![id.clone()]
    );

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
        listener::serve_with(&sockets, &dir, &upstream, Limits::default())
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
