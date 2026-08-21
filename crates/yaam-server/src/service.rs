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
use yaam_core::Paths;
use yaam_core::bundle::{self, Bundle};
use yaam_core::erase::EraseReport;
use yaam_core::pipeline::Accepted;
use yaam_core::sweeper::SweepReport;
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

/// What one maintenance round got through.
///
/// Reported rather than logged from inside, so the caller decides whether a quiet round is worth a
/// line: a service doing this every thirty seconds would otherwise say "nothing happened" for ever.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Maintenance {
    /// Fan-out jobs completed or dead-lettered.
    pub fanout_settled: usize,
    /// What the sweeper re-drove.
    pub sweep: SweepReport,
}

impl Maintenance {
    /// Whether this round found nothing to do.
    #[must_use]
    pub fn did_nothing(&self) -> bool {
        self.fanout_settled == 0 && self.sweep == SweepReport::default()
    }
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
    /// keep the disposable half on faster or more local storage than the authoritative half. It
    /// reaches the pipeline as part of its [`Paths`], not only this service: an index named here and
    /// derived from the root there would have the writer and the reader on two different files, and
    /// every read would answer about records nothing had written.
    pub fn open(root: &Path, index: &Path) -> Result<Self> {
        let paths = Paths::under(root).with_index(index);
        Ok(Self::with_pipeline(yaam_core::Pipeline::with_paths(paths)?))
    }

    /// The same service over a pipeline the deployment configured itself.
    ///
    /// How the plug-in seams reach the shipped service: a key wrapper and a subject resolver are set
    /// on the pipeline, so a deployment that uses either builds the pipeline and hands it over
    /// instead of passing a root and getting the defaults.
    ///
    /// The index to read comes from the pipeline's own [`Paths`] rather than alongside it, so there
    /// is one answer to where it is.
    pub fn with_pipeline(pipeline: yaam_core::Pipeline) -> Self {
        Self {
            registry: pipeline.registry().clone(),
            index: pipeline.paths().index.clone(),
            pipeline: Mutex::new(pipeline),
            store: OnceLock::new(),
        }
    }

    /// Runs one round of the maintenance the store needs, and reports what it did.
    ///
    /// Two jobs, both of which have no other caller in a running deployment. Fan-out is enqueued
    /// inside the write transaction and drained afterwards, so entity timelines and subject audit
    /// records only exist because something calls this. And the sweeper is what closes the windows
    /// the write path leaves open — a staging file whose write died, a published record whose index
    /// row never landed, a timeline head an interrupted rollover renamed away.
    ///
    /// Synchronous, and it takes the write lock: this is the pipeline's own work, and running it
    /// beside a request rather than instead of one is what the lock is for. Both halves are
    /// idempotent, so a round that dies part way is repeated rather than repaired.
    ///
    /// `max_jobs` bounds the fan-out half. What it does not get through stays queued.
    pub fn maintain(&self, max_jobs: usize) -> Result<Maintenance> {
        let mut pipeline = self.pipeline();
        let fanout_settled = pipeline.drain_fanout(max_jobs)?;
        let sweep = yaam_core::sweeper::sweep(&mut pipeline)?;
        Ok(Maintenance {
            fanout_settled,
            sweep,
        })
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
        let index = dir.path().join("relocated/index.sqlite");
        let service = CoreService::open(dir.path(), &index).expect("a pipeline over an empty tree");
        // Deleted under the service, which is the only way the index can be missing now that the
        // pipeline opens the same file it reads: the first read has to report it rather than panic.
        std::fs::remove_file(&index).expect("the pipeline created the index it was given");
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
