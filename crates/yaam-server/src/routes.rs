//! Endpoint wiring.

use axum::Router;

/// Builds the router.
///
/// | Route | Purpose |
/// |---|---|
/// | `POST /records` | Write a record. Idempotent on its identifier. |
/// | `GET /records` | Filtered query. |
/// | `GET /entities/{kind}/{id}` | Everything about one entity. |
/// | `GET /bundle` | Compose context for a request. |
/// | `POST /erase` | Destroy a subject's keys. Operator only. |
pub fn router() -> Router {
    todo!("mount handlers with auth middleware")
}
