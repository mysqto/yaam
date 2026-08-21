//! The seam between the endpoints and everything under them.
//!
//! The handlers depend on this trait rather than on the pipeline and the index directly, for two
//! reasons. It is what lets the request layer — signatures, roles, status codes — be tested without
//! a tree and a database on disk. And it is the one place a deployment can put a different
//! implementation: a read-only replica, or a service that reaches a remote pipeline.
//!
//! Every method takes the [`Caller`], because visibility is decided per caller: an implementation
//! must narrow every read to [`Caller::scope`], and passing the caller in is what makes that
//! possible to do — and to check. A read that forgets who asked returns everything.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use yaam_contract::entity::Registry;
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

    /// Answers one page of what touches one entity.
    ///
    /// An implementation must canonicalise `kind` and `id` the way the write path does before
    /// matching them, and refuse what it cannot canonicalise. Matching an identifier as sent is how
    /// a caller asking for `proj-42` where the store holds `PROJ-42` gets an empty answer it reads
    /// as "no history".
    ///
    /// `limit` is the page size, `None` meaning the index's own default cap. Not optional in the
    /// sense of unbounded: an entity's history grows with how busy the entity is, and a request
    /// answering with all of it hands the busiest identifier in the store a lever on every reader.
    fn entity(
        &self,
        caller: &Caller,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
    ) -> Result<Vec<RecordId>>;

    /// Composes context for a request.
    ///
    /// The entities it names are canonicalised as [`Service::entity`] canonicalises its own, and for
    /// the same reason: a bundle silently missing a source is worse than one that says so.
    fn bundle(&self, caller: &Caller, request: &bundle::Request) -> Result<Bundle>;

    /// Destroys a subject's keys.
    fn erase(&self, caller: &Caller, subject: &SubjectHash) -> Result<EraseReport>;
}

/// The service backed by the write pipeline and the derived index.
///
/// Every read here is narrowed to [`Caller::scope`], and the scope replaces whatever the request
/// carried rather than intersecting with it: what a caller may see comes from the credential its
/// signature proved, and nothing a request can say may widen it.
#[derive(Debug)]
pub struct CoreService {
    /// The pipeline is the single writer, and the lock is what makes that true under concurrent
    /// requests rather than by convention.
    pipeline: Mutex<yaam_core::Pipeline>,
    /// The pipeline's entity kinds, copied out so a read canonicalises without taking the write
    /// lock: one lock contended by every read is a queue behind whatever is being written.
    registry: Registry,
    index: PathBuf,
    /// The shared read handle, opened by the first read that finds an index.
    store: OnceLock<Store>,
}

impl CoreService {
    /// Opens the memory tree at `root`, reading the index at `index`.
    ///
    /// The index is a separate argument rather than a path derived from `root`, so a deployment can
    /// keep the disposable half on faster or more local storage than the authoritative half.
    pub fn open(root: &Path, index: &Path) -> Result<Self> {
        Ok(Self::with_pipeline(yaam_core::Pipeline::new(root)?, index))
    }

    /// The same service over a pipeline the deployment configured itself.
    ///
    /// How the plug-in seams reach the shipped service: a key wrapper and a subject resolver are set
    /// on the pipeline, so a deployment that uses either builds the pipeline and hands it over
    /// instead of passing a root and getting the defaults.
    pub fn with_pipeline(pipeline: yaam_core::Pipeline, index: &Path) -> Self {
        Self {
            registry: pipeline.registry().clone(),
            pipeline: Mutex::new(pipeline),
            index: index.to_path_buf(),
            store: OnceLock::new(),
        }
    }

    /// The canonical form of an identifier, or the client error saying why there is none.
    ///
    /// `422` and not an empty answer: an unconfigured kind or an identifier the kind's pattern does
    /// not admit is a question this deployment cannot be asked, and answering it with no rows would
    /// have the caller read a bug as a fact. The same status the write path gives the same
    /// identifier, so one spelling cannot be good enough to store and not good enough to find.
    fn canonical(&self, kind: &str, id: &str) -> Result<String> {
        self.registry
            .canonicalise(kind, id)
            .map_err(|error| Error::Unprocessable(error.to_string()))
    }

    /// The write pipeline, recovering a lock a panicking request poisoned.
    ///
    /// Refusing every later write because one request panicked would turn a single failure into an
    /// outage. The pipeline's own recovery is the staging file and the sweeper, so an interrupted
    /// write converges without help from this lock.
    fn pipeline(&self) -> std::sync::MutexGuard<'_, yaam_core::Pipeline> {
        self.pipeline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The read handle every request shares.
    ///
    /// One handle, not one per request: it is a pool of read-only connections, so concurrent reads
    /// still each get their own and a request no longer pays to open a database.
    ///
    /// Opened on first use rather than in [`CoreService::open`], because a deployment may come up
    /// before its index has been built: an absent index is a read that fails, not a service that
    /// refuses to start. A concurrent first read may open a second handle, and the one that loses
    /// the race is closed rather than kept.
    fn store(&self) -> Result<&Store> {
        if let Some(store) = self.store.get() {
            return Ok(store);
        }
        let opened = Store::open_read(&self.index).map_err(|error| Error::Core(error.into()))?;
        Ok(self.store.get_or_init(|| opened))
    }
}

impl Service for CoreService {
    fn write(&self, _caller: &Caller, record: ActionRecord, body: &str) -> Result<Accepted> {
        Ok(self.pipeline().accept(record, body)?)
    }

    fn query(&self, caller: &Caller, filter: &Filter) -> Result<Vec<RecordId>> {
        let scoped = Filter {
            scope: caller.scope(),
            ..filter.clone()
        };
        Ok(query::by_filter(self.store()?, &scoped).map_err(yaam_core::Error::from)?)
    }

    fn entity(
        &self,
        caller: &Caller,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
    ) -> Result<Vec<RecordId>> {
        let id = self.canonical(kind, id)?;
        Ok(query::by_entity(
            self.store()?,
            kind,
            &id,
            min_confidence,
            limit,
            &caller.scope(),
        )
        .map_err(yaam_core::Error::from)?)
    }

    fn bundle(&self, caller: &Caller, request: &bundle::Request) -> Result<Bundle> {
        let mut entities = Vec::with_capacity(request.entities.len());
        for (kind, id) in &request.entities {
            entities.push((kind.clone(), self.canonical(kind, id)?));
        }
        let scoped = bundle::Request {
            entities,
            scope: caller.scope(),
            ..request.clone()
        };
        Ok(bundle::compose(self.store()?, &scoped)?)
    }

    fn erase(&self, _caller: &Caller, subject: &SubjectHash) -> Result<EraseReport> {
        Ok(yaam_core::erase::erase_subject(
            &mut self.pipeline(),
            subject,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;

    /// A read against an index that is not there must be reported, not panicked through.
    ///
    /// `500` rather than `503`: an absent index is not a moment's unavailability, it is a deployment
    /// that needs a rebuild, and a caller that kept retrying would be waiting for something no
    /// amount of patience fixes.
    #[test]
    fn a_read_against_a_missing_index_is_reported_not_panicked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = CoreService::open(dir.path(), &dir.path().join("nowhere/index.sqlite"))
            .expect("a pipeline over an empty tree");
        let caller = Caller {
            agent: "agent-reader".to_owned(),
            role: Role::Reader,
            teams: Vec::new(),
        };

        let error = service
            .query(&caller, &Filter::default())
            .expect_err("an index that is not there answers nothing");
        assert_eq!(
            error.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
