//! The seam between the endpoints and everything under them.
//!
//! The handlers depend on this trait rather than on the pipeline and the index directly, for two
//! reasons. It is what lets the request layer — signatures, roles, status codes — be tested without
//! a tree and a database on disk. And it is the one place a deployment can put a different
//! implementation: a read-only replica, or a service that reaches a remote pipeline.
//!
//! Every method takes the [`Caller`], because visibility is decided per caller. Passing it in one
//! argument at a time would let a handler forget, and a read that forgets who asked returns
//! everything.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};

use yaam_contract::{ActionRecord, RecordId, SubjectHash};
use yaam_core::bundle::{self, Bundle};
use yaam_core::erase::EraseReport;
use yaam_core::pipeline::Accepted;
use yaam_store::Store;
use yaam_store::query::{self, Filter};

use crate::auth::Caller;
use crate::{Error, Result};

/// What the endpoints need from the layers below them.
pub trait Service: std::fmt::Debug + Send + Sync + 'static {
    /// Accepts one record, attributed to the caller.
    fn write(&self, caller: &Caller, record: ActionRecord, body: &str) -> Result<Accepted>;

    /// Answers a filtered query.
    fn query(&self, caller: &Caller, filter: &Filter) -> Result<Vec<RecordId>>;

    /// Answers everything touching one entity.
    fn entity(
        &self,
        caller: &Caller,
        kind: &str,
        id: &str,
        min_confidence: f32,
    ) -> Result<Vec<RecordId>>;

    /// Composes context for a request.
    fn bundle(&self, caller: &Caller, request: &bundle::Request) -> Result<Bundle>;

    /// Destroys a subject's keys.
    fn erase(&self, caller: &Caller, subject: &SubjectHash) -> Result<EraseReport>;
}

/// The service backed by the write pipeline and the derived index.
///
/// Reads are **not** narrowed to the caller's visibility here, and saying so is more useful than
/// implying otherwise: the index offers no visibility or team predicate, so there is no query that
/// would narrow them. The caller is threaded through every method so that the filtering lands here
/// once there is one, and until then a deployment must not describe a non-operator read as scoped.
#[derive(Debug)]
pub struct CoreService {
    /// The pipeline is the single writer, and the lock is what makes that true under concurrent
    /// requests rather than by convention.
    pipeline: Mutex<yaam_core::Pipeline>,
    index: PathBuf,
}

impl CoreService {
    /// Opens the memory tree at `root`, reading the index at `index`.
    ///
    /// The index is a separate argument rather than a path derived from `root`, so a deployment can
    /// keep the disposable half on faster or more local storage than the authoritative half.
    pub fn open(root: &Path, index: &Path) -> Result<Self> {
        let pipeline = yaam_core::Pipeline::new(root)?;
        Ok(Self {
            pipeline: Mutex::new(pipeline),
            index: index.to_path_buf(),
        })
    }

    /// The write pipeline, recovering a lock a panicking request poisoned.
    ///
    /// Refusing every later write because one request panicked would turn a single failure into an
    /// outage. The pipeline's own recovery is the staging file and the sweeper, so an interrupted
    /// write converges without help from this lock.
    fn pipeline(&self) -> std::sync::MutexGuard<'_, yaam_core::Pipeline> {
        self.pipeline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A read handle for one request.
    ///
    /// Per request rather than shared, because a database connection may move between threads but
    /// not be used from two at once. Sharing one behind a lock would serialise reads the index is
    /// built to answer concurrently, and one slow query would then block every other.
    fn store(&self) -> Result<Store> {
        Store::open_read(&self.index).map_err(|error| Error::Core(error.into()))
    }
}

impl Service for CoreService {
    fn write(&self, _caller: &Caller, record: ActionRecord, body: &str) -> Result<Accepted> {
        Ok(self.pipeline().accept(record, body)?)
    }

    fn query(&self, _caller: &Caller, filter: &Filter) -> Result<Vec<RecordId>> {
        Ok(query::by_filter(&self.store()?, filter).map_err(yaam_core::Error::from)?)
    }

    fn entity(
        &self,
        _caller: &Caller,
        kind: &str,
        id: &str,
        min_confidence: f32,
    ) -> Result<Vec<RecordId>> {
        Ok(query::by_entity(&self.store()?, kind, id, min_confidence)
            .map_err(yaam_core::Error::from)?)
    }

    fn bundle(&self, _caller: &Caller, request: &bundle::Request) -> Result<Bundle> {
        Ok(bundle::compose(&self.store()?, request)?)
    }

    fn erase(&self, _caller: &Caller, subject: &SubjectHash) -> Result<EraseReport> {
        Ok(yaam_core::erase::erase_subject(
            &mut self.pipeline(),
            subject,
        )?)
    }
}

/// The service [`crate::routes::router`] resolves against.
///
/// Starts out refusing every request as unavailable: a process that has not been given a tree yet is
/// temporarily wrong, not permanently, so `503` keeps callers holding their records where `422`
/// would make them discard records that were never at fault.
static INSTALLED: LazyLock<RwLock<Arc<dyn Service>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Unconfigured)));

/// Installs the service the ambient router serves from, replacing whatever was there.
pub fn install(service: Arc<dyn Service>) {
    let mut slot = INSTALLED.write().unwrap_or_else(PoisonError::into_inner);
    *slot = service;
}

/// The installed service.
#[must_use]
pub fn installed() -> Arc<dyn Service> {
    INSTALLED
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Stands in until a service is installed.
#[derive(Debug)]
struct Unconfigured;

impl Unconfigured {
    /// The one answer this service has.
    fn unavailable<T>() -> Result<T> {
        Err(Error::Unavailable("no memory tree configured".to_owned()))
    }
}

impl Service for Unconfigured {
    fn write(&self, _caller: &Caller, _record: ActionRecord, _body: &str) -> Result<Accepted> {
        Self::unavailable()
    }

    fn query(&self, _caller: &Caller, _filter: &Filter) -> Result<Vec<RecordId>> {
        Self::unavailable()
    }

    fn entity(
        &self,
        _caller: &Caller,
        _kind: &str,
        _id: &str,
        _min_confidence: f32,
    ) -> Result<Vec<RecordId>> {
        Self::unavailable()
    }

    fn bundle(&self, _caller: &Caller, _request: &bundle::Request) -> Result<Bundle> {
        Self::unavailable()
    }

    fn erase(&self, _caller: &Caller, _subject: &SubjectHash) -> Result<EraseReport> {
        Self::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::auth::Role;
    use crate::testing;

    fn caller() -> Caller {
        Caller {
            agent: "agent-writer".to_owned(),
            role: Role::Operator,
        }
    }

    /// Every unconfigured answer must be the retryable one, since nothing about the request is
    /// wrong and a caller that gives up loses the record.
    #[test]
    fn an_unconfigured_service_is_unavailable_not_unprocessable() {
        let caller = caller();
        let subject = testing::subject();
        let answers = [
            Unconfigured
                .write(&caller, testing::record("agent-writer"), "body")
                .err(),
            Unconfigured.query(&caller, &Filter::default()).err(),
            Unconfigured.entity(&caller, "ticket", "T-1", 0.0).err(),
            Unconfigured
                .bundle(&caller, &bundle::Request::default())
                .err(),
            Unconfigured.erase(&caller, &subject).err(),
        ];
        for answer in answers {
            let error = answer.expect("an unconfigured service answers nothing");
            assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}
