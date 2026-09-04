//! Service failures and their status mapping.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

/// Result alias for service operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What a request can fail with.
///
/// The mapping matters: a malformed record is the caller's bug and gets `422`, while a transient
/// dependency failure gets `503` so the caller retries instead of discarding the record.
///
/// | Status | From | Body |
/// |---|---|---|
/// | `400` | *not this type* — a rejected query string, before any handler runs | `text/plain` |
/// | `401` | [`Error::Unauthenticated`] | `{"error": …}` |
/// | `403` | [`Error::Forbidden`] | `{"error": …}` |
/// | `409` | a legal hold forbidding a destruction | `{"error": …}` |
/// | `422` | [`Error::Unprocessable`], and a core contract failure | `{"error": …}` |
/// | `500` | any other core failure | `{"error": …}` |
/// | `503` | [`Error::Unavailable`], and an unresolved subject | `{"error": …}` |
///
/// `400` is in the table because a caller's retry policy is written against the whole table, and it
/// is the row that does not come from here: `axum`'s `Query` rejection answers an unknown or
/// unparseable query parameter before a handler is reached, so it is the one failure that is not the
/// `{"error": …}` shape. A client parsing every error body as JSON breaks on exactly that status.
#[derive(Debug, Error)]
pub enum Error {
    /// Signature missing, malformed, or wrong.
    #[error("unauthenticated")]
    Unauthenticated,
    /// Authenticated, but not permitted — including attributing a record to another agent.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The record violates the contract. Permanent.
    #[error("unprocessable: {0}")]
    Unprocessable(String),
    /// A dependency is briefly unavailable. Retry.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Everything else.
    #[error(transparent)]
    Core(#[from] yaam_core::Error),
}

impl Error {
    /// The status this failure is reported as.
    ///
    /// The pair worth getting right is `422` against `503`. `422` says the record will never be
    /// accepted, so a caller that retries it burns its queue on a record that cannot land; `503`
    /// says the record was fine and the service was not, so a caller that discards it loses audit
    /// history. Swapping them breaks a caller in one direction or the other, and neither failure is
    /// visible from here.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Core(inner) => core_status(inner),
        }
    }
}

/// Maps a core failure onto the same permanent/transient split.
///
/// A contract violation is the caller's to fix and an unresolved subject is not: quarantine and
/// retry is the documented handling, so it must not reach the caller as a rejection. Everything
/// else is this service's own fault and says so, because a `500` tells a caller to stop retrying
/// its own record and raise the failure instead.
fn core_status(error: &yaam_core::Error) -> StatusCode {
    match error {
        yaam_core::Error::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        yaam_core::Error::SubjectUnresolved => StatusCode::SERVICE_UNAVAILABLE,
        // A third state, and neither of the two above. The request was well formed and the caller
        // was permitted it; a legal hold requires that these keys survive, and two obligations
        // pointing in opposite directions is a conflict rather than a bad request. `422` would send
        // the caller looking for the malformed field it did not send, and `500` would have it raise
        // an incident against a store that is working exactly as ordered. Neither is retryable and
        // this is not either — what it needs is a person to release the hold, or not.
        yaam_core::Error::Held(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        // Logged here rather than at each call site: this is the one place every failure passes
        // through, so nothing can return an error without leaving a trace.
        tracing::warn!(%status, error = %self, "request failed");
        // Reported as the display form, which names the failure without naming internals: an
        // unauthenticated caller learns that its signature did not verify and nothing else.
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole table, in one place. A caller's retry policy is written against these numbers, so a
    /// change here is a change to every caller's behaviour.
    ///
    /// `400` is absent by construction, and the assertion below says so: it is produced before a
    /// handler runs and carries a `text/plain` body, which is the one answer a client cannot parse
    /// as `{"error": …}`.
    #[test]
    fn every_failure_maps_to_its_documented_status() {
        let cases = [
            (Error::Unauthenticated, StatusCode::UNAUTHORIZED),
            (
                Error::Forbidden("not yours".to_owned()),
                StatusCode::FORBIDDEN,
            ),
            (
                Error::Unprocessable("no action".to_owned()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Error::Unavailable("index reopening".to_owned()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.status(), expected, "{error}");
            assert_ne!(
                error.status(),
                StatusCode::BAD_REQUEST,
                "a `400` from here would answer JSON where the contract promises plain text"
            );
        }
    }

    /// The pair that costs data when it is swapped: a contract violation must not be retried, and
    /// an unresolved subject must not be reported as a rejection.
    #[test]
    fn a_core_failure_keeps_the_permanent_transient_split() {
        let invalid =
            Error::Core(yaam_contract::Error::Invalid("action is empty".to_owned()).into());
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let unresolved = Error::Core(yaam_core::Error::SubjectUnresolved);
        assert_eq!(unresolved.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A hold is a conflict, not a bad request and not our fault.
    ///
    /// The one refusal that is neither party's mistake: the caller asked correctly, the store is
    /// working, and an obligation to preserve outranks the obligation to erase. Reported as `422`
    /// it would read as a malformed request; as `500` it would have somebody raise an incident.
    #[test]
    fn a_legal_hold_is_reported_as_a_conflict_rather_than_a_fault() {
        let held = Error::Core(yaam_core::Error::Held(
            "held: 1 hold(s) stand over subject s_00".to_owned(),
        ));
        assert_eq!(held.status(), StatusCode::CONFLICT);
        assert!(
            held.to_string().contains("hold"),
            "the refusal has to say what blocked it: {held}"
        );
    }

    /// Our own fault, not the caller's: a `500` stops the caller retrying its own record forever
    /// over something only this service can fix.
    #[test]
    fn an_infrastructure_failure_is_ours_to_own() {
        let store = Error::Core(yaam_store::Error::Drift("not-a-record-id".to_owned()).into());
        assert_eq!(store.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_failure_answers_with_its_status_and_a_reason() {
        let response = Error::Forbidden("not your history".to_owned()).into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "forbidden: not your history");
    }
}
