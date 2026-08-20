//! Talking to the service.
//!
//! The one judgement this module makes is permanent versus transient, and it is load-bearing in
//! both directions: treating a `4xx` as transient wedges the spool behind a record the service will
//! never accept, and treating a `5xx` as permanent throws records away during an outage.
//!
//! Plain HTTP, no TLS stack. The body is already sealed to the service's public key before it
//! reaches this module, so transport encryption is not what keeps it confidential — and a sidecar
//! that cannot read what it posts has nothing left to leak to the network.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::Error;

/// How long one attempt may take, connect and response together.
///
/// A sidecar that blocks forever on a half-open connection stops accepting from its caller, so the
/// timeout is part of the retry design rather than a safety net.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Header carrying the agent a record is attributed to.
const AGENT_HEADER: &str = "x-yaam-agent";

/// Bytes of an error response quoted back to the caller.
const REASON_LIMIT: usize = 200;

/// Where and how to reach the service.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Base URL.
    pub base_url: String,
    /// Public key the sidecar seals spool entries to.
    ///
    /// Asymmetric on purpose: the sidecar can seal but never unseal, so holding this key grants no
    /// read access to anything already stored.
    pub service_public_key: Vec<u8>,
}

impl Upstream {
    /// Posts one sealed record, distinguishing permanent rejection from transient failure.
    ///
    /// `body` is an envelope from [`crate::envelope::seal`], and `agent` is the identity the socket
    /// established — the service re-checks it against the caller it authenticated, so the header is
    /// a claim, not a grant.
    ///
    /// Requests are **not** signed. Nothing reachable from this type is a caller credential:
    /// [`Upstream`] carries a base URL and the service's public key, and a public key authenticates
    /// nobody. Rather than derive a secret from something that is not one, this posts unsigned and
    /// says so — see the crate documentation for the credential the API would need.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`] for a `4xx` other than `429`, and for any other status the service is not
    /// expected to return: the record will not become acceptable by being sent again, so the caller
    /// is told instead. [`Error::Spooled`] for `429`, `5xx`, a timeout, or a transport failure —
    /// all of which say *later*, not *no*.
    pub async fn post_record(&self, agent: &str, body: &[u8]) -> crate::Result<()> {
        tokio::time::timeout(ATTEMPT_TIMEOUT, self.attempt(agent, body))
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(agent, "upstream attempt timed out");
                Err(Error::Spooled)
            })
    }

    /// One request, from connect to classified outcome.
    async fn attempt(&self, agent: &str, body: &[u8]) -> crate::Result<()> {
        let target: Uri = format!("{}/records", self.base_url.trim_end_matches('/'))
            .parse()
            .map_err(|e| Error::Rejected(format!("unusable upstream url: {e}")))?;
        let authority = target
            .authority()
            .ok_or_else(|| Error::Rejected(format!("upstream url has no host: {}", self.base_url)))?
            .clone();
        let port = target.port_u16().unwrap_or(80);

        // Transport failures are all transient by nature: the record is fine, the path is not.
        let stream = TcpStream::connect((authority.host(), port))
            .await
            .map_err(|e| transient(agent, "connect", &e))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| transient(agent, "handshake", &e))?;
        // The connection future drives the socket; it ends when the response is complete.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "upstream connection closed");
            }
        });

        // Origin-form target with an explicit `Host`, as a direct HTTP/1.1 request should be:
        // the absolute form is for proxies, and not every server parses it.
        let path = target.path_and_query().map_or("/records", |p| p.as_str());
        let request = Request::post(path)
            .header(header::HOST, authority.as_str())
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(AGENT_HEADER, agent)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::Stub;

    /// An upstream pointed at `base_url`, with a key it never uses here.
    fn upstream(base_url: String) -> Upstream {
        Upstream {
            base_url,
            service_public_key: vec![0u8; crate::envelope::KEY_LEN],
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
    async fn a_trailing_slash_does_not_double_up() {
        let stub = Stub::start(200).await;
        upstream(format!("{}/", stub.base_url))
            .post_record("writer", b"sealed")
            .await
            .unwrap();
        assert_eq!(stub.request_lines(), ["POST /records HTTP/1.1"]);
    }
}
