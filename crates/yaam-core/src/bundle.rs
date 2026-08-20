//! Assembling context for a caller.
//!
//! Sealed bodies are never unsealed here. A caller receives structure — action, outcome,
//! attributes, entities — and never subject plaintext, because plaintext handed to a caller reaches
//! places this system cannot erase.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use yaam_contract::RecordId;
use yaam_store::query::{self, Filter, Scope};

/// Confidence a reference must carry to reach a bundle.
///
/// `1.0` — read out of a structured field, not inferred from prose. A guess in a bundle is a guess
/// the caller cannot tell apart from a fact.
const MIN_CONFIDENCE: f32 = 1.0;

/// Records one entity or actor may contribute.
const PER_SOURCE_LIMIT: u32 = 200;

/// Records a whole bundle may carry.
///
/// A cap rather than a guideline: an entity with a long history would otherwise decide the size of
/// every caller's context window.
const MAX_RECORDS: usize = 500;

/// Rough token cost of one record's structure, for the advisory estimate.
const TOKENS_PER_RECORD: usize = 120;

/// Context assembled for one request.
#[derive(Debug, Default)]
pub struct Bundle {
    /// Records judged relevant.
    pub records: Vec<RecordId>,
    /// `true` when a source was unavailable and the bundle is incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
    /// Rough token cost, advisory only.
    pub token_estimate: usize,
}

/// What the caller wants context for.
///
/// The scope travels with the request rather than being applied afterwards: a bundle is assembled
/// from several reads, and filtering the assembled result would mean the deadline and the record cap
/// had already been spent on records the caller may not see.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Entities to gather history for.
    pub entities: Vec<(String, String)>,
    /// Actor whose recent activity is relevant.
    pub actor: Option<String>,
    /// Budget for the whole composition.
    pub deadline_ms: u64,
    /// What the caller this bundle is for may see. Defaults to nothing.
    pub scope: Scope,
}

/// Composes a bundle, degrading rather than failing when a source is slow.
///
/// Returning a partial bundle marked `degraded` is safe for questions and unsafe for actions. The
/// caller decides, which is why the flag is explicit rather than implied by an empty result.
///
/// Every source that is not consulted names itself in `omitted`. Silence would leave the caller
/// unable to tell a subject with no history from a source that never answered, and those two call
/// for opposite decisions.
pub fn compose(store: &yaam_store::Store, request: &Request) -> crate::Result<Bundle> {
    let deadline = Instant::now() + Duration::from_millis(request.deadline_ms);
    let mut bundle = Bundle::default();
    let mut seen = HashSet::new();

    for (kind, id) in &request.entities {
        if Instant::now() >= deadline {
            omit(&mut bundle, format!("entity {kind}:{id}: deadline reached"));
            continue;
        }
        let found = query::by_entity(store, kind, id, MIN_CONFIDENCE, &request.scope)?;
        take(
            &mut bundle,
            &mut seen,
            found,
            &format!("entity {kind}:{id}"),
        );
    }

    if let Some(actor) = &request.actor {
        if Instant::now() >= deadline {
            omit(&mut bundle, format!("actor {actor}: deadline reached"));
        } else {
            let filter = Filter {
                agent: Some(actor.clone()),
                limit: Some(PER_SOURCE_LIMIT),
                scope: request.scope.clone(),
                ..Filter::default()
            };
            let found = query::by_filter(store, &filter)?;
            take(&mut bundle, &mut seen, found, &format!("actor {actor}"));
        }
    }

    bundle.token_estimate = bundle.records.len() * TOKENS_PER_RECORD;
    Ok(bundle)
}

/// Adds a source's records, up to the whole-bundle cap.
///
/// Duplicates are dropped rather than counted twice: two entities on the same record make it one
/// record, and a token estimate that double-counted it would mislead the caller about the cost.
fn take(bundle: &mut Bundle, seen: &mut HashSet<String>, found: Vec<RecordId>, source: &str) {
    let mut dropped = 0;
    for id in found {
        if bundle.records.len() >= MAX_RECORDS {
            dropped += 1;
            continue;
        }
        if seen.insert(id.as_str().to_owned()) {
            bundle.records.push(id);
        }
    }
    if dropped > 0 {
        omit(
            bundle,
            format!("{source}: {dropped} record(s) over the bundle cap of {MAX_RECORDS}"),
        );
    }
}

/// Notes a source that did not make it into the bundle, and marks the bundle incomplete.
fn omit(bundle: &mut Bundle, reason: String) {
    bundle.degraded = true;
    bundle.omitted.push(reason);
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use yaam_contract::RecordId;

    use super::{Bundle, MAX_RECORDS, Request, Scope, TOKENS_PER_RECORD, compose, take};
    use crate::testkit::{self, BODY, Harness};

    /// A store with two records on the same ticket, one of them also about a subject.
    fn populated() -> Harness {
        let mut harness = Harness::new();
        harness
            .pipeline
            .accept(testkit::internal("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        let mut sealed = testkit::subject_derived("2026-08-21T09:00:00Z", &[testkit::subject('a')]);
        sealed.entities = testkit::internal("2026-08-21T09:00:00Z").entities;
        harness.pipeline.accept(sealed, BODY).expect("accepted");
        harness
    }

    #[test]
    fn a_bundle_gathers_an_entity_and_an_actor_without_unsealing_anything() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![("ticket".to_owned(), "PROJ-42".to_owned())],
            actor: Some("agent_a".to_owned()),
            deadline_ms: 5_000,
            scope: Scope::Unrestricted,
        };

        let bundle = compose(&store, &request).expect("composed");
        assert_eq!(bundle.records.len(), 2);
        assert!(!bundle.degraded);
        assert!(bundle.omitted.is_empty());
        assert_eq!(bundle.token_estimate, 2 * TOKENS_PER_RECORD);
        // Identifiers and structure only: a caller never receives a body from here.
        assert_eq!(
            bundle.records.iter().collect::<HashSet<_>>().len(),
            2,
            "a record named by two sources is still one record"
        );
    }

    #[test]
    fn a_bundle_that_runs_out_of_time_says_what_it_left_out() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![
                ("ticket".to_owned(), "PROJ-42".to_owned()),
                ("order_ref".to_owned(), "ord10014721".to_owned()),
            ],
            actor: Some("agent_a".to_owned()),
            deadline_ms: 0,
            scope: Scope::Unrestricted,
        };

        let bundle = compose(&store, &request).expect("composed");
        assert!(bundle.degraded, "an incomplete bundle must say so");
        assert_eq!(bundle.omitted.len(), 3, "{:?}", bundle.omitted);
        assert!(bundle.omitted.iter().all(|line| line.contains("deadline")));
        assert!(bundle.omitted.iter().any(|line| line.contains("PROJ-42")));
        assert!(bundle.omitted.iter().any(|line| line.contains("agent_a")));
        assert!(bundle.records.is_empty());
        assert_eq!(bundle.token_estimate, 0);
    }

    #[test]
    fn an_empty_request_composes_an_empty_bundle() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let bundle = compose(&store, &Request::default()).expect("composed");
        assert!(bundle.records.is_empty());
        assert!(
            !bundle.degraded,
            "nothing asked for is not something withheld"
        );
    }

    #[test]
    fn an_entity_with_no_history_contributes_nothing_and_is_not_an_omission() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![("ticket".to_owned(), "PROJ-99".to_owned())],
            deadline_ms: 5_000,
            scope: Scope::Unrestricted,
            ..Request::default()
        };
        let bundle = compose(&store, &request).expect("composed");
        assert!(bundle.records.is_empty());
        assert!(!bundle.degraded);
    }

    #[test]
    fn a_bundle_for_a_caller_with_no_scope_is_empty_rather_than_complete() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![("ticket".to_owned(), "PROJ-42".to_owned())],
            actor: Some("agent_a".to_owned()),
            deadline_ms: 5_000,
            ..Request::default()
        };

        let bundle = compose(&store, &request).expect("composed");
        assert!(
            bundle.records.is_empty(),
            "an unscoped bundle must not assemble history"
        );
    }

    #[test]
    fn records_over_the_cap_are_dropped_and_reported() {
        let mut bundle = Bundle::default();
        let mut seen = HashSet::new();
        let found: Vec<RecordId> = (0..=MAX_RECORDS).map(|_| RecordId::generate()).collect();

        take(&mut bundle, &mut seen, found, "entity ticket:PROJ-42");
        assert_eq!(bundle.records.len(), MAX_RECORDS);
        assert!(bundle.degraded);
        assert_eq!(bundle.omitted.len(), 1);
        assert!(bundle.omitted[0].contains("1 record(s) over the bundle cap"));
    }
}
