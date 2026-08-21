//! Talking to the service.
//!
//! The one judgement this module makes is permanent versus transient, and it is load-bearing in
//! both directions: treating a `4xx` as transient wedges the spool behind a record the service will
//! never accept, and treating a `5xx` as permanent throws records away during an outage.
//!
//! Plain HTTP, no TLS stack. The body is already sealed to the service's public key before it
//! reaches this module, so transport encryption is not what keeps it confidential — and a sidecar
//! that cannot read what it posts has nothing left to leak to the network. The *signature* is what
//! makes the service willing to accept it, and it covers method, path, agent and the sealed bytes.
//!
//! # Two operations, not one
//!
//! [`Upstream::post_record`] and [`Upstream::forward_read`] are separate because they fail
//! differently. A write that cannot be delivered is spooled and answered *later*; a read that
//! cannot be delivered has no later at all, so it comes back as [`Error::Unreachable`] and the
//! caller learns immediately. Folding the read into the write path would have inherited the
//! spool-and-retry verdict, which for a read means handing back stale data with nothing to say so.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper::http::uri::Authority;
use hyper::{Request, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use yaam_contract::request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys};
use yaam_crypto::envelope;

use crate::Error;

/// How long one attempt may take, connect and response together.
///
/// A sidecar that blocks forever on a half-open connection stops accepting from its caller, so the
/// timeout is part of the retry design rather than a safety net.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Path a record is posted to. Part of what a signature covers, so it is one constant.
const RECORDS_PATH: &str = "/records";

/// Method a record is posted with.
const WRITE_METHOD: &str = "POST";

/// The only method a proxied read is sent with.
///
/// A constant rather than a parameter: making the method un-passable is what stops this function
/// ever carrying a write. The service's whole write surface is `POST`, and a read that could name
/// its own method would be a way past the record socket's sealing and spool.
const READ_METHOD: &str = "GET";

/// Bytes of an error response quoted back to the caller.
const REASON_LIMIT: usize = 200;

/// Largest response body a proxied read will hold in memory.
///
/// The whole body is buffered because it is handed back over one socket write, so an unbounded
/// answer would be the service deciding how much memory this sidecar uses.
const MAX_READ_RESPONSE: usize = 8 << 20;

/// Where and how to reach the service.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Base URL.
    pub base_url: String,
    /// Public key the sidecar seals records to.
    ///
    /// Asymmetric on purpose: the sidecar can seal but never unseal, so holding this key grants no
    /// read access to anything already stored — on its own spool or at the service.
    pub service_public_key: Vec<u8>,
    /// Signing material, one entry per caller identity this sidecar posts as.
    pub credentials: Credentials,
}

/// The signing material a sidecar holds.
///
/// One entry per agent, keyed the way the service's keyring is keyed, and holding the same
/// [`SigningKeys`] the service verifies against — the sidecar signs with `current`, and which key
/// the service will still accept is the service's business. Sharing the type is what stops the two
/// sides drifting; a sidecar-local notion of "the key" is how they drifted before.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    by_agent: BTreeMap<String, SigningKeys>,
}

impl Credentials {
    /// Credentials for nobody, which signs for nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an agent's material, replacing any it already had.
    #[must_use]
    pub fn with(mut self, agent: impl Into<String>, keys: SigningKeys) -> Self {
        self.by_agent.insert(agent.into(), keys);
        self
    }

    /// The material for `agent`, if this sidecar holds any.
    #[must_use]
    pub fn keys(&self, agent: &str) -> Option<&SigningKeys> {
        self.by_agent.get(agent)
    }
}

/// What the service answered a proxied read with.
///
/// Forwarded rather than classified. The write path classifies a status because a write can be
/// spooled and sent again, so something has to decide whether that is worth doing; a read has no
/// such choice, and the answer the caller needs is the service's own — including its refusals,
/// which say why.
#[derive(Debug)]
pub struct ReadResponse {
    /// Status the service answered with.
    pub status: StatusCode,
    /// The service's `content-type`, when it set one.
    pub content_type: Option<String>,
    /// Response body as it arrived.
    pub body: Vec<u8>,
}

impl Upstream {
    /// Posts one sealed record, distinguishing permanent rejection from transient failure.
    ///
    /// `body` is an envelope from [`crate::envelope::seal`], and `agent` is the identity the socket
    /// established — the service re-checks it against the credential the signature verified, so the
    /// header is a claim, not a grant.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`] for a `4xx` other than `429`, for any other status the service is not
    /// expected to return, and for an agent this sidecar holds no credential for: none of those
    /// become acceptable by being sent again, so the caller is told instead. [`Error::Spooled`] for
    /// `429`, `5xx`, a timeout, or a transport failure — all of which say *later*, not *no*.
    ///
    /// The memory service does not return `429` itself; a proxy, gateway or load balancer in front
    /// of it can, and that is what the case is for. Treating it as transient there is the difference
    /// between a spooled record and a discarded one.
    pub async fn post_record(&self, agent: &str, body: &[u8]) -> crate::Result<()> {
        tokio::time::timeout(ATTEMPT_TIMEOUT, self.attempt(agent, body))
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(agent, "upstream attempt timed out");
                Err(Error::Spooled)
            })
    }

    /// One write request, from connect to classified outcome.
    async fn attempt(&self, agent: &str, body: &[u8]) -> crate::Result<()> {
        // Before the connection, because an agent with no credential is a configuration fault and
        // has nothing to gain from reaching the service unsigned.
        let keys = self.credentials.keys(agent).ok_or_else(|| {
            Error::Rejected(format!("no signing credential configured for `{agent}`"))
        })?;
        let endpoint = self.endpoint(RECORDS_PATH)?;

        // Transport failures are all transient by nature: the record is fine, the path is not.
        let mut sender = connect(&endpoint)
            .await
            .map_err(|e| transient(agent, "connect", &e))?;
        let request = Request::post(endpoint.target.as_str())
            .header(header::HOST, endpoint.authority.as_str())
            .header(header::CONTENT_TYPE, envelope::CONTENT_TYPE)
            .header(AGENT_HEADER, agent)
            .header(
                SIGNATURE_HEADER,
                keys.sign(WRITE_METHOD, &endpoint.target, agent, body),
            )
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| Error::Rejected(format!("unbuildable request: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| transient(agent, "send", &e))?;
        let status = response.status();
        let reason = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        classify(status, &reason)
    }

    /// Signs one read as `agent` and returns what the service answered.
    ///
    /// `target` is the request target in origin form, query string included, and it is what the
    /// signature covers together with the method, the agent and `body`. For a read the query *is*
    /// the request, so a signature over the path alone would let one captured read be replayed with
    /// any filters at all.
    ///
    /// Only a `GET` is ever sent, and the method is a constant in this module rather than a
    /// parameter: a read that could name its own method would be a way past the record socket's
    /// sealing and spool. Nothing the caller sent is forwarded beyond the target and the body
    /// either — a header outside the signature is a header anything on the path could have edited,
    /// and one of them, `content-type`, is how the service decides whether a body is sealed.
    ///
    /// # Errors
    ///
    /// [`Error::Unreachable`] when no answer arrived at all: a transport failure or the attempt
    /// timeout. Nothing is queued, because a read cannot be answered later — the caller would get
    /// data that was already stale when it was fetched, with no way to tell. [`Error::Rejected`]
    /// for a local fault that sending again cannot fix: an agent this sidecar holds no key for, a
    /// target that is not origin-form, or a base URL it cannot build a request from.
    ///
    /// A refusal *by the service* is not an error here. It is a [`ReadResponse`] carrying the
    /// service's own status, because what a caller may see is the service's decision to explain.
    pub async fn forward_read(
        &self,
        agent: &str,
        target: &str,
        body: &[u8],
    ) -> crate::Result<ReadResponse> {
        tokio::time::timeout(ATTEMPT_TIMEOUT, self.read_attempt(agent, target, body))
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(agent, target, "upstream read timed out");
                Err(Error::Unreachable(
                    "the service did not answer in time".to_owned(),
                ))
            })
    }

    /// One read request, from connect to forwarded answer.
    async fn read_attempt(
        &self,
        agent: &str,
        target: &str,
        body: &[u8],
    ) -> crate::Result<ReadResponse> {
        let keys = self.credentials.keys(agent).ok_or_else(|| {
            Error::Rejected(format!("no signing credential configured for `{agent}`"))
        })?;
        // The target is joined onto the configured base URL, so it has to be a path: anything else
        // could put its own authority ahead of the base URL's and send a signed read elsewhere.
        if !target.starts_with('/') {
            return Err(Error::Rejected(format!(
                "read target must be origin-form, got `{target}`"
            )));
        }
        let endpoint = self.endpoint(target)?;

        let mut sender = connect(&endpoint)
            .await
            .map_err(|e| unreachable(agent, "connect", &e))?;
        let request = Request::get(endpoint.target.as_str())
            .header(header::HOST, endpoint.authority.as_str())
            .header(AGENT_HEADER, agent)
            .header(
                SIGNATURE_HEADER,
                keys.sign(READ_METHOD, &endpoint.target, agent, body),
            )
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| Error::Rejected(format!("unbuildable request: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| unreachable(agent, "send", &e))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        // A body that stopped arriving mid-stream is not a short answer, it is no answer: handing
        // back the prefix would be handing back a truncated result the caller cannot detect.
        let body = Limited::new(response.into_body(), MAX_READ_RESPONSE)
            .collect()
            .await
            .map(|collected| collected.to_bytes().to_vec())
            .map_err(|e| unreachable(agent, "response body", &e))?;

        Ok(ReadResponse {
            status,
            content_type,
            body,
        })
    }

    /// Resolves `path` against the base URL, keeping the base URL's authority.
    fn endpoint(&self, path: &str) -> crate::Result<Endpoint> {
        let uri: Uri = format!("{}{path}", self.base_url.trim_end_matches('/'))
            .parse()
            .map_err(|e| Error::Rejected(format!("unusable upstream url: {e}")))?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::Rejected(format!("upstream url has no host: {}", self.base_url)))?
            .clone();
        Ok(Endpoint {
            port: uri.port_u16().unwrap_or(80),
            // Origin-form target, as a direct HTTP/1.1 request should carry: the absolute form is
            // for proxies, and not every server parses it. Taken from the parsed URI rather than
            // the argument, so what is signed is exactly what goes on the wire.
            target: uri
                .path_and_query()
                .map_or_else(|| path.to_owned(), ToString::to_string),
            authority,
        })
    }
}

/// Where one request goes, and the target it names once it gets there.
struct Endpoint {
    /// Host and port from the base URL, for the `Host` header.
    authority: Authority,
    /// Port to connect on.
    port: u16,
    /// Origin-form request target, which is also what the signature covers.
    target: String,
}

/// Opens one HTTP/1.1 connection to `endpoint`.
///
/// The stages are not distinguished in the error, only in its text: both mean the request never
/// left, and the two callers differ on what that means rather than on which stage it was.
async fn connect(endpoint: &Endpoint) -> io::Result<SendRequest<Full<Bytes>>> {
    let stream = TcpStream::connect((endpoint.authority.host(), endpoint.port)).await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| io::Error::other(format!("handshake: {e}")))?;
    // The connection future drives the socket; it ends when the response is complete.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!(error = %e, "upstream connection closed");
        }
    });
    Ok(sender)
}

/// Maps a status to an outcome.
///
/// Split out because this is the decision the module exists to get right, and it is worth testing
/// without a socket in the way.
fn classify(status: StatusCode, reason: &[u8]) -> crate::Result<()> {
    let code = status.as_u16();
    if status.is_success() {
        return Ok(());
    }
    if code == StatusCode::TOO_MANY_REQUESTS.as_u16() || status.is_server_error() {
        tracing::warn!(%status, "upstream is unavailable; spooling");
        return Err(Error::Spooled);
    }
    // Everything else — client errors, and the redirects and informational statuses a service with
    // one write endpoint should never return — is a misconfiguration or a bad record. Neither is
    // fixed by sending the same bytes again.
    Err(Error::Rejected(format!("{status}: {}", snippet(reason))))
}

/// A short, single-line quote of an error response.
fn snippet(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(REASON_LIMIT)]);
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Logs a transport failure and classifies it as retryable.
fn transient(agent: &str, stage: &str, error: &dyn std::fmt::Display) -> Error {
    tracing::warn!(agent, stage, %error, "upstream unreachable; spooling");
    Error::Spooled
}

/// Logs a transport failure on the read path, where there is nothing to retry it from.
fn unreachable(agent: &str, stage: &str, error: &dyn std::fmt::Display) -> Error {
    tracing::warn!(agent, stage, %error, "upstream unreachable; the read fails");
    Error::Unreachable(format!("{stage}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::Stub;

    /// The key the test service and the test sidecar share.
    const KEY: &[u8] = b"a-shared-signing-key";

    /// An upstream pointed at `base_url`, able to sign as `writer`.
    fn upstream(base_url: String) -> Upstream {
        Upstream {
            base_url,
            service_public_key: vec![0u8; envelope::KEY_LEN],
            credentials: Credentials::new().with("writer", SigningKeys::new(KEY)),
        }
    }

    #[test]
    fn success_is_acceptance() {
        for code in [200u16, 201, 202, 204] {
            classify(StatusCode::from_u16(code).unwrap(), b"").unwrap();
        }
    }

    #[test]
    fn client_errors_are_permanent() {
        for code in [400u16, 401, 403, 404, 409, 422] {
            let err = classify(StatusCode::from_u16(code).unwrap(), b"no").unwrap_err();
            assert!(matches!(err, Error::Rejected(_)), "{code} must be rejected");
        }
    }

    #[test]
    fn overload_and_server_errors_are_transient() {
        for code in [429u16, 500, 502, 503, 504] {
            let err = classify(StatusCode::from_u16(code).unwrap(), b"later").unwrap_err();
            assert!(matches!(err, Error::Spooled), "{code} must be spooled");
        }
    }

    #[test]
    fn an_unexpected_status_is_not_retried_forever() {
        for code in [100u16, 301, 302] {
            let err = classify(StatusCode::from_u16(code).unwrap(), b"").unwrap_err();
            assert!(matches!(err, Error::Rejected(_)), "{code}");
        }
    }

    #[test]
    fn the_reason_is_quoted_but_bounded() {
        let long = vec![b'x'; REASON_LIMIT * 2];
        let Err(Error::Rejected(why)) = classify(StatusCode::BAD_REQUEST, &long) else {
            panic!("expected a rejection");
        };
        assert!(why.contains("400"));
        assert!(why.len() < REASON_LIMIT + 40, "{why}");
    }

    #[test]
    fn a_multiline_reason_becomes_one_line() {
        assert_eq!(snippet(b" bad\n  record\t"), "bad record");
    }

    #[tokio::test]
    async fn a_record_reaches_the_service() {
        let stub = Stub::start(202).await;
        upstream(stub.base_url.clone())
            .post_record("writer", b"sealed bytes")
            .await
            .unwrap();
        assert_eq!(stub.received(), [b"sealed bytes".to_vec()]);
        // The write endpoint is part of the contract, so where it landed is asserted too.
        assert_eq!(stub.request_lines(), ["POST /records HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_posted_record_carries_a_signature_over_method_path_agent_and_body() {
        let stub = Stub::start(202).await;
        upstream(stub.base_url.clone())
            .post_record("writer", b"sealed bytes")
            .await
            .unwrap();

        assert_eq!(stub.header(0, AGENT_HEADER).as_deref(), Some("writer"));
        assert_eq!(
            stub.header(0, SIGNATURE_HEADER),
            // Recomputed the way the service will, from the shared spelling of the message.
            Some(SigningKeys::new(KEY).sign("POST", "/records", "writer", b"sealed bytes"))
        );
        assert_eq!(
            stub.header(0, "content-type").as_deref(),
            Some(envelope::CONTENT_TYPE),
            "the service has to be told the body is sealed"
        );
    }

    #[tokio::test]
    async fn an_agent_with_no_credential_is_never_posted_unsigned() {
        let stub = Stub::start(200).await;
        let err = upstream(stub.base_url.clone())
            .post_record("auditor", b"sealed")
            .await
            .unwrap_err();

        assert!(
            matches!(&err, Error::Rejected(why) if why.contains("auditor")),
            "{err}"
        );
        assert!(
            stub.received().is_empty(),
            "an unsigned request must not be attempted at all"
        );
    }

    #[tokio::test]
    async fn a_client_error_from_the_wire_is_rejected() {
        let stub = Stub::start(422).await;
        let err = upstream(stub.base_url.clone())
            .post_record("writer", b"sealed")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rejected(why) if why.contains("422")),);
    }

    #[tokio::test]
    async fn a_server_error_from_the_wire_is_spooled() {
        for code in [429u16, 503] {
            let stub = Stub::start(code).await;
            let err = upstream(stub.base_url.clone())
                .post_record("writer", b"sealed")
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Spooled), "{code}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_service_is_spooled() {
        // Bind and drop, so the port is almost certainly nobody's.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = upstream(format!("http://{addr}"))
            .post_record("writer", b"sealed")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Spooled));
    }

    #[tokio::test]
    async fn a_url_without_a_host_is_a_configuration_error() {
        let err = upstream("not a url".to_owned())
            .post_record("writer", b"sealed")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rejected(_)), "{err}");

        let err = upstream("/records".to_owned())
            .post_record("writer", b"sealed")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rejected(why) if why.contains("no host")));
    }

    #[tokio::test]
    async fn a_read_is_signed_over_the_whole_request_target() {
        let stub = Stub::start(200).await;
        let answered = upstream(stub.base_url.clone())
            .forward_read("writer", "/records?limit=1", b"")
            .await
            .unwrap();

        assert_eq!(answered.status, StatusCode::OK);
        assert_eq!(answered.body, b"stub says 200");
        assert_eq!(answered.content_type.as_deref(), Some("text/plain"));
        assert_eq!(stub.request_lines(), ["GET /records?limit=1 HTTP/1.1"]);
        assert_eq!(
            stub.header(0, SIGNATURE_HEADER),
            Some(SigningKeys::new(KEY).sign("GET", "/records?limit=1", "writer", b""))
        );
        // Nothing else the caller sent crosses: a header outside the signature is a header anything
        // on the path could have edited, and `content-type` decides whether a body is sealed.
        assert!(stub.header(0, "content-type").is_none());
    }

    /// The clock is paused, so the ten-second attempt timeout costs the test nothing: the runtime
    /// advances it as soon as nothing else can run.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_never_gets_an_answer_fails_rather_than_hanging() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accepted and then ignored, which is what a half-open connection looks like. A sidecar
        // parked here for ever would stop answering its caller at all.
        tokio::spawn(async move {
            let _held = listener.accept().await;
            std::future::pending::<()>().await;
        });

        let err = upstream(format!("http://{addr}"))
            .forward_read("writer", "/records", b"")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Unreachable(why) if why.contains("in time")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_read_that_is_not_origin_form_is_never_signed() {
        let stub = Stub::start(200).await;
        for target in ["", "http://elsewhere/records", "records"] {
            let err = upstream(stub.base_url.clone())
                .forward_read("writer", target, b"")
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::Rejected(why) if why.contains("origin-form")),
                "{target}: {err}"
            );
        }
        assert!(
            stub.received().is_empty(),
            "the base URL has to be the only authority a signed read can reach"
        );
    }

    #[tokio::test]
    async fn an_unreachable_service_fails_a_read_rather_than_spooling_it() {
        // Bind and drop, so the port is almost certainly nobody's.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = upstream(format!("http://{addr}"))
            .forward_read("writer", "/records", b"")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unreachable(_)), "{err}");
    }

    #[tokio::test]
    async fn a_read_for_an_agent_with_no_credential_is_not_attempted() {
        let stub = Stub::start(200).await;
        let err = upstream(stub.base_url.clone())
            .forward_read("auditor", "/records", b"")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Rejected(why) if why.contains("auditor")),
            "{err}"
        );
        assert!(stub.received().is_empty());
    }

    #[tokio::test]
    async fn a_refusal_by_the_service_is_forwarded_rather_than_classified() {
        // The write path calls a `403` permanent and a `503` retryable. A read has no retry to
        // decide about: the caller gets the service's own answer either way.
        for code in [403u16, 503] {
            let stub = Stub::start(code).await;
            let answered = upstream(stub.base_url.clone())
                .forward_read("writer", "/records", b"")
                .await
                .unwrap();
            assert_eq!(answered.status.as_u16(), code);
        }
    }

    #[tokio::test]
    async fn a_read_body_is_signed_and_sent_rather_than_dropped() {
        let stub = Stub::start(200).await;
        upstream(stub.base_url.clone())
            .forward_read("writer", "/records", b"a body")
            .await
            .unwrap();

        assert_eq!(stub.received(), [b"a body".to_vec()]);
        assert_eq!(
            stub.header(0, SIGNATURE_HEADER),
            Some(SigningKeys::new(KEY).sign("GET", "/records", "writer", b"a body")),
            "a body signed as empty while a different one was sent is the defect this rules out"
        );
    }

    #[tokio::test]
    async fn a_trailing_slash_does_not_double_up() {
        let stub = Stub::start(200).await;
        upstream(format!("{}/", stub.base_url))
            .post_record("writer", b"sealed")
            .await
            .unwrap();
        assert_eq!(stub.request_lines(), ["POST /records HTTP/1.1"]);
    }
}
