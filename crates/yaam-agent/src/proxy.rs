//! Signing reads for a caller that holds no key.
//!
//! The service authenticates every request, reads included — what a caller may see is decided per
//! caller, and an anonymous request has no caller to decide about. A caller behind this sidecar
//! holds no signing key on purpose, so its reads had nowhere to go: teaching it to sign would hand
//! it exactly what the sidecar exists to keep away from it. This module is the other answer. The
//! caller sends an ordinary HTTP request over its own socket, the sidecar signs it as that caller
//! and forwards it, and the service's answer comes back unchanged.
//!
//! # Why a second socket
//!
//! Records keep their own socket and their newline-JSON protocol, unchanged. Its acks say things
//! HTTP statuses say badly — `spooled` means *durably queued here*, which is a success — and reads
//! have no such vocabulary to borrow. Two sockets rather than sniffing one: telling an HTTP request
//! line from a JSON line on the same socket is a guess made from whatever the first read happened
//! to return, and a partial first read makes it the wrong guess.
//!
//! # Reads only, and nothing spooled
//!
//! A request that is not a `GET` is refused here and never forwarded. Records belong on the record
//! socket, which seals them and can queue them; a write laundered through this socket would skip
//! both, and the caller would have no way to notice. The method is the gate because the service's
//! entire write surface is `POST` — and [`Upstream::forward_read`] cannot send anything but a `GET`
//! even if this gate were wrong.
//!
//! Nothing here can spool, structurally: this module holds an [`Upstream`] and no spool handle at
//! all. A read the service cannot answer is a read that failed, and `503` says so — a spooled read
//! would be answered eventually with data that was already stale when it was fetched.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::Error;
use crate::listener::peer_owns_socket;
use crate::upstream::Upstream;

/// Largest request body a proxied read may carry.
///
/// The signature covers the body, so the body has to be buffered before it can be signed at all;
/// the bound is what stops that being a memory lever. The same size the service accepts, because a
/// larger one here would only move the refusal a round trip further away.
const MAX_BODY: usize = 1 << 20;

/// What a caller is told when it tries to write here.
const WRITE_REFUSAL: &str = "this socket proxies reads only; a record goes to the record socket, \
                             which seals it and can queue it while the service is unreachable";

/// Signs and forwards one caller's reads.
///
/// Holds an upstream and nothing else. There is deliberately no spool here: see the module note.
pub(crate) struct ReadProxy {
    /// Where the service is, and the key to sign this caller's reads with.
    upstream: Upstream,
}

impl ReadProxy {
    /// A proxy over one upstream.
    pub(crate) fn new(upstream: Upstream) -> Self {
        Self { upstream }
    }

    /// Serves HTTP/1.1 on one accepted connection.
    ///
    /// The peer's credentials are checked before a byte is read, the same way the record socket
    /// checks them: the `0600` mode already turns away everyone but the owner, and credentials
    /// arrive with the connection and cannot be changed afterwards — including in the moment
    /// between binding a socket and tightening it.
    ///
    /// A shutdown lets the request in flight finish and then closes, rather than dropping a caller
    /// mid-answer.
    pub(crate) async fn serve(
        &self,
        stream: UnixStream,
        agent: &str,
        owner: u32,
        mut closed: watch::Receiver<bool>,
    ) -> crate::Result<()> {
        let peer = stream.peer_cred()?;
        if !peer_owns_socket(peer.uid(), owner) {
            tracing::warn!(
                agent,
                peer_uid = peer.uid(),
                owner,
                "refusing a read connection from another user"
            );
            return Ok(());
        }

        let handler = service_fn(|request: Request<Incoming>| async {
            Ok::<_, Infallible>(self.answer(agent, request).await)
        });
        let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), handler);
        let mut connection = std::pin::pin!(connection);
        let served = tokio::select! {
            biased;
            served = connection.as_mut() => served,
            _ = closed.changed() => {
                // Between requests where it can be, after the one in flight where it cannot: a
                // caller holds its connection open, so waiting for it to hang up waits for ever.
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        };
        served.map_err(|e| Error::Io(std::io::Error::other(e)))
    }

    /// Answers one request: refuse it here, or sign it and forward it.
    async fn answer(&self, agent: &str, request: Request<Incoming>) -> Response<Full<Bytes>> {
        if request.method() != Method::GET {
            let method = request.method().clone();
            tracing::warn!(agent, %method, "refusing a write on the read socket");
            return refused(StatusCode::METHOD_NOT_ALLOWED, WRITE_REFUSAL);
        }
        // The path and query as they arrived, and nothing else from the URI: an absolute-form
        // target carrying its own authority would otherwise be asking for a signed read of
        // somewhere else. Whether what is left is usable at all is `forward_read`'s one guard,
        // rather than a second opinion here.
        let target = request
            .uri()
            .path_and_query()
            .map_or_else(String::new, |target| target.as_str().to_owned());
        let Ok(body) = Limited::new(request.into_body(), MAX_BODY).collect().await else {
            return refused(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is unreadable or larger than this sidecar will sign",
            );
        };

        match self
            .upstream
            .forward_read(agent, &target, &body.to_bytes())
            .await
        {
            Ok(answered) => forwarded(&answered),
            // The read failed and nothing was queued. `503` rather than a body invented here: the
            // caller asked for data, and the only thing worse than no data is data that looks real.
            Err(Error::Unreachable(why)) => refused(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("the service could not be reached ({why}); reads are never queued"),
            ),
            // A local fault — an agent this sidecar cannot sign as, or an unusable base URL. The
            // caller cannot fix any of it, so it must not read as the caller's mistake.
            Err(other) => {
                tracing::error!(agent, error = %other, "cannot proxy a read");
                refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("this sidecar cannot proxy the read: {other}"),
                )
            }
        }
    }
}

/// The service's own answer, handed back as it arrived.
fn forwarded(answered: &crate::upstream::ReadResponse) -> Response<Full<Bytes>> {
    let mut response = Response::builder().status(answered.status);
    if let Some(content_type) = &answered.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(Full::new(Bytes::copy_from_slice(&answered.body)))
        .expect("a status and a content-type that came off the wire go back onto it")
}

/// One refusal from the sidecar itself.
///
/// The service's `{"error": …}` shape, so a caller parses one thing whether the answer came from
/// here or from the other end.
fn refused(status: StatusCode, why: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&serde_json::json!({"error": why}))
        .expect("a JSON object of one string field always serialises");
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json");
    if status == StatusCode::METHOD_NOT_ALLOWED {
        // A `405` has to say what is allowed, or a caller cannot tell a wrong method from a wrong
        // path.
        response = response.header(header::ALLOW, "GET");
    }
    response
        .body(Full::new(Bytes::from(body)))
        .expect("a status and two header values this module wrote are a valid response")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yaam_contract::request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys};
    use yaam_crypto::envelope;

    use super::*;
    use crate::stub::Stub;
    use crate::upstream::Credentials;

    /// The key this sidecar and the stub service share.
    const KEY: &[u8] = b"a-shared-signing-key";

    /// A proxy pointed at `base_url`, able to sign as `reader`.
    fn proxy(base_url: String) -> ReadProxy {
        ReadProxy::new(Upstream {
            base_url,
            service_public_key: vec![0u8; envelope::KEY_LEN],
            credentials: Credentials::new().with("reader", SigningKeys::new(KEY)),
        })
    }

    /// Serves `stream` as `reader`'s read socket.
    ///
    /// `by_owner` says whether the socket belongs to the peer, which is the fact the credential
    /// check turns on. The uid comes from the connection rather than from the environment, so the
    /// test asserts the same thing whichever user runs it.
    fn serve(proxy: ReadProxy, stream: UnixStream, by_owner: bool) -> tokio::task::JoinHandle<()> {
        let peer = stream.peer_cred().expect("peer credentials").uid();
        let owner = if by_owner { peer } else { peer + 1 };
        let (closing, closed) = watch::channel(false);
        tokio::spawn(async move {
            proxy
                .serve(stream, "reader", owner, closed)
                .await
                .expect("the connection ends cleanly");
            // Held until the connection is done: a dropped sender is itself a shutdown signal.
            drop(closing);
        })
    }

    /// Sends one raw request over a connected pair and reads the whole answer.
    async fn exchange(mut caller: UnixStream, request: &str) -> String {
        caller
            .write_all(request.as_bytes())
            .await
            .expect("write the request");
        let mut answer = Vec::new();
        caller
            .read_to_end(&mut answer)
            .await
            .expect("read the answer");
        String::from_utf8_lossy(&answer).into_owned()
    }

    /// Waits until the stub has seen `count` requests.
    async fn await_requests(stub: &Stub, count: usize) {
        for _ in 0..500 {
            if stub.request_lines().len() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the stub never saw {count} request(s)");
    }

    #[tokio::test]
    async fn a_read_is_signed_as_the_socket_owner_and_forwarded() {
        let stub = Stub::start(200).await;
        let (caller, served) = UnixStream::pair().expect("a socket pair");
        let serving = serve(proxy(stub.base_url.clone()), served, true);

        let answer = exchange(
            caller,
            "GET /bundle?actor=reader HTTP/1.1\r\nhost: sidecar\r\nconnection: close\r\n\r\n",
        )
        .await;

        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
        assert!(answer.contains("stub says 200"), "{answer}");
        assert!(
            answer.to_lowercase().contains("content-type: text/plain"),
            "the service's own content type has to survive the hop: {answer}"
        );
        assert_eq!(stub.request_lines(), ["GET /bundle?actor=reader HTTP/1.1"]);
        assert_eq!(stub.header(0, AGENT_HEADER).as_deref(), Some("reader"));
        assert_eq!(
            stub.header(0, SIGNATURE_HEADER),
            // Recomputed the way the service will, from the one shared spelling of the message.
            Some(SigningKeys::new(KEY).sign("GET", "/bundle?actor=reader", "reader", b""))
        );
        serving.await.expect("join");
    }

    #[tokio::test]
    async fn the_signature_covers_the_query_string() {
        let stub = Stub::start(200).await;
        for target in ["/records?limit=1", "/records?limit=2"] {
            let (caller, served) = UnixStream::pair().expect("a socket pair");
            let serving = serve(proxy(stub.base_url.clone()), served, true);
            exchange(
                caller,
                &format!("GET {target} HTTP/1.1\r\nhost: s\r\nconnection: close\r\n\r\n"),
            )
            .await;
            serving.await.expect("join");
        }

        let first = stub.header(0, SIGNATURE_HEADER).expect("a signature");
        let second = stub.header(1, SIGNATURE_HEADER).expect("a signature");
        assert_ne!(
            first, second,
            "two different queries must not share a signature, or one read could be replayed as \
             the other"
        );
    }

    #[tokio::test]
    async fn a_write_is_refused_and_never_reaches_the_service() {
        let stub = Stub::start(200).await;
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let (caller, served) = UnixStream::pair().expect("a socket pair");
            let serving = serve(proxy(stub.base_url.clone()), served, true);

            let answer = exchange(
                caller,
                &format!(
                    "{method} /records HTTP/1.1\r\nhost: s\r\ncontent-length: 2\r\nconnection: \
                     close\r\n\r\n{{}}"
                ),
            )
            .await;

            assert!(answer.starts_with("HTTP/1.1 405 "), "{method}: {answer}");
            assert!(answer.to_lowercase().contains("allow: get"), "{answer}");
            assert!(answer.contains("record socket"), "{answer}");
            serving.await.expect("join");
        }
        assert!(
            stub.received().is_empty(),
            "a write must not be proxied at all"
        );
    }

    #[tokio::test]
    async fn a_peer_that_does_not_own_the_socket_gets_nothing() {
        let stub = Stub::start(200).await;
        let (caller, served) = UnixStream::pair().expect("a socket pair");
        // A socket owned by somebody else, which is what the credential check is for.
        let serving = serve(proxy(stub.base_url.clone()), served, false);

        // The write itself may fail: the sidecar hangs up on the credential check, before reading
        // anything. Either way what matters is that no answer comes back.
        let mut caller = caller;
        let _ = caller
            .write_all(b"GET /records HTTP/1.1\r\nhost: s\r\nconnection: close\r\n\r\n")
            .await;
        let mut answer = Vec::new();
        let _ = caller.read_to_end(&mut answer).await;

        assert!(answer.is_empty(), "the connection is dropped, not answered");
        assert!(stub.received().is_empty(), "and nothing was signed");
        serving.await.expect("join");
    }

    #[tokio::test]
    async fn an_unreachable_service_is_a_failed_read_not_a_queued_one() {
        // Bind and drop, so the port is almost certainly nobody's.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let (caller, served) = UnixStream::pair().expect("a socket pair");
        let serving = serve(proxy(format!("http://{addr}")), served, true);
        let answer = exchange(
            caller,
            "GET /records HTTP/1.1\r\nhost: s\r\nconnection: close\r\n\r\n",
        )
        .await;

        assert!(answer.starts_with("HTTP/1.1 503 "), "{answer}");
        assert!(answer.contains("never queued"), "{answer}");
        serving.await.expect("join");
    }

    #[tokio::test]
    async fn the_services_own_refusal_is_what_the_caller_sees() {
        let stub = Stub::start(403).await;
        let (caller, served) = UnixStream::pair().expect("a socket pair");
        let serving = serve(proxy(stub.base_url.clone()), served, true);

        let answer = exchange(
            caller,
            "GET /records HTTP/1.1\r\nhost: s\r\nconnection: close\r\n\r\n",
        )
        .await;

        // Forwarded, not translated: what a caller may see is the service's decision to explain.
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
        assert!(answer.contains("stub says 403"), "{answer}");
        serving.await.expect("join");
    }

    #[tokio::test]
    async fn a_read_for_an_agent_with_no_key_is_this_sidecars_fault() {
        let stub = Stub::start(200).await;
        let (caller, served) = UnixStream::pair().expect("a socket pair");
        let proxy = ReadProxy::new(Upstream {
            base_url: stub.base_url.clone(),
            service_public_key: vec![0u8; envelope::KEY_LEN],
            credentials: Credentials::new(),
        });
        let serving = serve(proxy, served, true);

        let answer = exchange(
            caller,
            "GET /records HTTP/1.1\r\nhost: s\r\nconnection: close\r\n\r\n",
        )
        .await;

        assert!(answer.starts_with("HTTP/1.1 500 "), "{answer}");
        assert!(
            stub.received().is_empty(),
            "an unsigned read must not be attempted"
        );
        serving.await.expect("join");
    }

    #[tokio::test]
    async fn a_body_larger_than_the_signer_will_buffer_is_refused() {
        let stub = Stub::start(200).await;
        let (mut caller, served) = UnixStream::pair().expect("a socket pair");
        let serving = serve(proxy(stub.base_url.clone()), served, true);

        let over = MAX_BODY + 16;
        caller
            .write_all(
                format!(
                    "GET /records HTTP/1.1\r\nhost: s\r\ncontent-length: {over}\r\nconnection: \
                     close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write the head");
        // The write may not complete once the sidecar stops reading, which is the point.
        let _ = caller.write_all(&vec![b'x'; over]).await;
        let mut answer = Vec::new();
        let _ = caller.read_to_end(&mut answer).await;

        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 413 "), "{answer}");
        assert!(stub.received().is_empty());
        let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
    }

    #[tokio::test]
    async fn a_shutdown_answers_the_read_in_flight_and_then_closes() {
        let stub = Stub::start(200).await;
        let (mut caller, served) = UnixStream::pair().expect("a socket pair");
        let (closing, closed) = watch::channel(false);
        let owner = served.peer_cred().expect("peer credentials").uid();
        let proxy = proxy(stub.base_url.clone());
        let serving = tokio::spawn(async move {
            proxy
                .serve(served, "reader", owner, closed)
                .await
                .expect("a clean end");
        });

        // Keep-alive: no `connection: close`, so the caller's end stays open after its answer, which
        // is what an idle caller does — and what a shutdown must not sit waiting for.
        caller
            .write_all(b"GET /records HTTP/1.1\r\nhost: s\r\n\r\n")
            .await
            .expect("write the request");
        // Signalled only once the read is demonstrably in flight, so this is the ordering under
        // test rather than a race with it.
        await_requests(&stub, 1).await;
        let _ = closing.send(true);

        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), caller.read_to_end(&mut answer))
            .await
            .expect("a shutdown must not abandon a read in flight")
            .expect("read the answer");
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the connection has to finish")
            .expect("join");
    }
}
