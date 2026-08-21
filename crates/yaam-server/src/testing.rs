//! Fixtures shared by the unit tests.
//!
//! A fake service rather than a real one: `yaam-core` is what a handler talks to, and a test that
//! went through it would be testing the pipeline instead of the request layer it means to test.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use yaam_contract::{
    ActionRecord, DataClass, Outcome, RecordId, RecordStructure, SchemaVer, SubjectHash, Visibility,
};
use yaam_core::bundle::{self, Bundle};
use yaam_core::erase::EraseReport;
use yaam_core::pipeline::Accepted;
use yaam_store::query::Filter;

use crate::auth::Caller;
use crate::service::Service;
use crate::{Error, Result};

/// A record attributed to `agent`, valid against the contract.
pub fn record(agent: &str) -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: "2026-01-02T03:04:05Z".to_owned(),
        received_at: "2026-01-02T03:04:06Z".to_owned(),
        backfilled: false,
        agent: agent.to_owned(),
        agent_ver: None,
        correlation_id: None,
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: BTreeMap::new(),
        entities: Vec::new(),
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: "none".to_owned(),
        fields_masked: Vec::new(),
        tags: Vec::new(),
        summary: "rolled out the change".to_owned(),
    }
}

/// A subject hash of the shape the contract accepts.
pub fn subject() -> SubjectHash {
    SubjectHash::parse(&format!("s_{:064x}", 1)).expect("a well-formed subject hash")
}

/// A service that answers from canned data and remembers what it was asked.
///
/// Recording the calls is what lets a test assert the *absence* of one — that a refused request
/// never reached the pipeline, and that no route rebuilds the index.
#[derive(Debug)]
pub struct Fake {
    calls: Mutex<Vec<String>>,
    answer: Mutex<Option<Accepted>>,
    records: Vec<RecordStructure>,
    refusal: Option<String>,
    panics: bool,
}

impl Fake {
    /// A fake that stores every write and returns no records.
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            answer: Mutex::new(None),
            records: Vec::new(),
            refusal: None,
            panics: false,
        }
    }

    /// Answers the next write with `accepted`.
    pub fn answering(self, accepted: Accepted) -> Self {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(accepted);
        self
    }

    /// Returns the structure of `records` from every read.
    ///
    /// Takes whole records rather than structures so a test can say what it wrote, and the fake
    /// projects them the way a real read does — including dropping the body.
    pub fn holding(mut self, records: &[ActionRecord]) -> Self {
        self.records = records.iter().map(RecordStructure::from).collect();
        self
    }

    /// Refuses every call as transiently unavailable.
    pub fn refusing(mut self, reason: &str) -> Self {
        self.refusal = Some(reason.to_owned());
        self
    }

    /// Panics on every call, standing in for a bug below the request layer.
    pub fn panicking(mut self) -> Self {
        self.panics = true;
        self
    }

    /// What the fake was asked, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records one call and applies the configured failure, if any.
    fn called(&self, what: String) -> Result<()> {
        assert!(!self.panics, "the fake was asked to panic: {what}");
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(what);
        match &self.refusal {
            Some(reason) => Err(Error::Unavailable(reason.clone())),
            None => Ok(()),
        }
    }
}

impl Service for Fake {
    fn write(&self, caller: &Caller, record: ActionRecord, body: &str) -> Result<Accepted> {
        self.called(format!("write {} {} {body}", caller.agent, record.agent))?;
        let answer = self
            .answer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        Ok(answer.unwrap_or(Accepted::Stored(record.record_id)))
    }

    fn query(&self, caller: &Caller, filter: &Filter) -> Result<Vec<RecordStructure>> {
        self.called(format!("query {} {filter:?}", caller.agent))?;
        Ok(self.records.clone())
    }

    fn entity(
        &self,
        caller: &Caller,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
    ) -> Result<Vec<RecordStructure>> {
        self.called(format!(
            "entity {} {kind} {id} {min_confidence} {limit:?}",
            caller.agent
        ))?;
        Ok(self.records.clone())
    }

    fn bundle(&self, caller: &Caller, request: &bundle::Request) -> Result<Bundle> {
        self.called(format!("bundle {} {request:?}", caller.agent))?;
        Ok(Bundle {
            records: self.records.clone(),
            degraded: true,
            omitted: vec!["one source was slow".to_owned()],
            token_estimate: 42,
        })
    }

    fn erase(&self, caller: &Caller, subject: &SubjectHash) -> Result<EraseReport> {
        self.called(format!("erase {} {}", caller.agent, subject.as_str()))?;
        Ok(EraseReport {
            bodies_sealed_off: 3,
            keys_destroyed: 2,
            quarantine_settled: 1,
            tombstone_id: "tomb-01ARZ3NDEKTSV4RRFFQ69G5FC7".to_owned(),
        })
    }
}
