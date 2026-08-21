//! Assembling context for a caller.
//!
//! A caller receives each record's structure — action, outcome, attributes, entities — and never a
//! body. Not because a body could not be fetched here, but because prose handed to a caller reaches
//! copies this system cannot erase; the structure comes from the record's stored frontmatter, which
//! is plaintext already and survives erasure by design.
//!
//! The rule does not branch on data class. A sealed body is excluded because it is a body, and a
//! plaintext one is excluded for the same reason — a bundle that returned prose for internal records
//! would be returning structure *except sometimes*, and the exception is what leaks.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use yaam_contract::RecordStructure;
use yaam_store::query::{self, Filter, Scope};

/// Confidence a reference must carry to reach a bundle.
///
/// `1.0` — read out of a structured field, not inferred from prose. A guess in a bundle is a guess
/// the caller cannot tell apart from a fact.
const MIN_CONFIDENCE: f32 = 1.0;

/// Records one entity or actor may contribute.
///
/// Applied to entity history as well as to the actor read, which it was not until a benchmark showed
/// the busiest entity in its store paying for 1,672 records in order to contribute 500. One busy
/// entity would otherwise decide both the cost of every bundle it appears in and how much of it the
/// other sources get.
///
/// Was 200 while a bundle carried identifiers. Half of [`MAX_RECORDS`], so no single source can fill
/// a bundle on its own however busy it is.
const PER_SOURCE_LIMIT: u32 = 50;

/// Page size each source is read at: one row past the cap, so a truncation can be detected.
const OVER_SOURCE_CAP: u32 = PER_SOURCE_LIMIT + 1;

/// Records a whole bundle may carry.
///
/// A cap rather than a guideline: an entity with a long history would otherwise decide the size of
/// every caller's context window.
///
/// Was 500 while a bundle carried identifiers, where 500 rows were 13 KB. A record's frontmatter is
/// 600 to 1,500 bytes depending on how many attributes, entities and tags it carries, so 500 of them
/// is 300–750 KB and 75,000–190,000 tokens — larger than the context it was assembled for, which
/// makes it not a bundle but a flood. A hundred is 60–150 KB and roughly 15,000–37,000 tokens: still
/// a lot, and something a caller can actually hold.
const MAX_RECORDS: usize = 100;

/// No single source may fill a bundle on its own, however busy it is. Checked at compile time: the
/// two caps only mean anything relative to each other, and a later edit to one of them is exactly
/// when this stops holding.
const _: () = assert!((PER_SOURCE_LIMIT as usize) * 2 <= MAX_RECORDS);

/// Context assembled for one request.
#[derive(Debug, Default)]
pub struct Bundle {
    /// Records judged relevant, each as its stored structure and never its body.
    pub records: Vec<RecordStructure>,
    /// `true` when a source was unavailable and the bundle is incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
    /// Rough token cost of the structure being returned, advisory only.
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
        let found = query::by_entity_structures(
            store,
            kind,
            id,
            MIN_CONFIDENCE,
            Some(OVER_SOURCE_CAP),
            &request.scope,
        )?;
        let source = format!("entity {kind}:{id}");
        let found = cap_source(&mut bundle, found, &source);
        take(&mut bundle, &mut seen, found, &source);
    }

    if let Some(actor) = &request.actor {
        if Instant::now() >= deadline {
            omit(&mut bundle, format!("actor {actor}: deadline reached"));
        } else {
            let filter = Filter {
                agent: Some(actor.clone()),
                limit: Some(OVER_SOURCE_CAP),
                scope: request.scope.clone(),
                ..Filter::default()
            };
            let found = query::by_filter_structures(store, &filter)?;
            let source = format!("actor {actor}");
            let found = cap_source(&mut bundle, found, &source);
            take(&mut bundle, &mut seen, found, &source);
        }
    }

    // Measured over what is actually being returned, after the caps and the de-duplication, so the
    // figure describes this bundle rather than a bundle of this many records.
    bundle.token_estimate = yaam_contract::structure::estimate_tokens(&bundle.records);
    Ok(bundle)
}

/// Trims one source to [`PER_SOURCE_LIMIT`], saying so when there was more.
///
/// The read asks for [`OVER_SOURCE_CAP`] and this throws the extra row away, which is what makes
/// "there is more history than this" a fact rather than a guess: a source that returned exactly the
/// cap is otherwise indistinguishable from one whose history is exactly that long.
fn cap_source(
    bundle: &mut Bundle,
    mut found: Vec<RecordStructure>,
    source: &str,
) -> Vec<RecordStructure> {
    if found.len() >= OVER_SOURCE_CAP as usize {
        found.truncate(PER_SOURCE_LIMIT as usize);
        omit(
            bundle,
            format!("{source}: newest {PER_SOURCE_LIMIT} of a longer history"),
        );
    }
    found
}

/// Adds a source's records, up to the whole-bundle cap.
///
/// Duplicates are dropped rather than counted twice: two entities on the same record make it one
/// record, and a token estimate that double-counted it would mislead the caller about the cost.
fn take(
    bundle: &mut Bundle,
    seen: &mut HashSet<String>,
    found: Vec<RecordStructure>,
    source: &str,
) {
    let mut dropped = 0;
    for record in found {
        if bundle.records.len() >= MAX_RECORDS {
            dropped += 1;
            continue;
        }
        if seen.insert(record.record_id.as_str().to_owned()) {
            bundle.records.push(record);
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

    use yaam_contract::{ActionRecord, DataClass, RecordStructure};

    use super::{
        Bundle, MAX_RECORDS, OVER_SOURCE_CAP, PER_SOURCE_LIMIT, Request, Scope, cap_source,
        compose, take,
    };
    use crate::testkit::{self, BODY, Harness};

    /// Structures with distinct identifiers, for the tests about the caps rather than the content.
    fn structures(count: u32) -> Vec<RecordStructure> {
        (0..count)
            .map(|_| {
                let mut record = testkit::internal("2026-08-20T09:00:00Z");
                record.record_id = yaam_contract::RecordId::generate();
                RecordStructure::from(&record)
            })
            .collect()
    }

    /// One bundled record by identifier.
    fn bundled<'a>(bundle: &'a Bundle, record: &ActionRecord) -> &'a RecordStructure {
        bundle
            .records
            .iter()
            .find(|found| found.record_id == record.record_id)
            .expect("the record is in the bundle")
    }

    /// A store with two records on the same ticket, one of them also about a subject.
    fn populated() -> Harness {
        populated_with().0
    }

    /// As [`populated`], and the two records it wrote.
    fn populated_with() -> (Harness, ActionRecord, ActionRecord) {
        let mut harness = Harness::new();
        let plain = testkit::internal("2026-08-20T09:00:00Z");
        harness
            .pipeline
            .accept(plain.clone(), BODY)
            .expect("accepted");
        let mut sealed = testkit::subject_derived("2026-08-21T09:00:00Z", &[testkit::subject('a')]);
        sealed.entities = testkit::internal("2026-08-21T09:00:00Z").entities;
        harness
            .pipeline
            .accept(sealed.clone(), BODY)
            .expect("accepted");
        (harness, plain, sealed)
    }

    #[test]
    fn a_bundle_gathers_an_entity_and_an_actor_without_unsealing_anything() {
        let (harness, plain, sealed) = populated_with();
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
        assert_eq!(
            bundle
                .records
                .iter()
                .map(|record| record.record_id.as_str().to_owned())
                .collect::<HashSet<_>>()
                .len(),
            2,
            "a record named by two sources is still one record"
        );

        // Structure, field by field, and not an identifier the caller would have to ask about
        // again — there is no second read that would answer it.
        for written in [&plain, &sealed] {
            assert_eq!(bundled(&bundle, written), &RecordStructure::from(written));
        }
        let one = bundled(&bundle, &plain);
        assert_eq!(one.action, "deploy");
        assert_eq!(one.agent, "agent_a");
        assert_eq!(one.outcome, yaam_contract::Outcome::Success);
        assert_eq!(one.attrs, plain.attrs);
        assert_eq!(one.entities, plain.entities);
        assert_eq!(one.tags, plain.tags);
        assert_eq!(one.received_at, plain.received_at);
    }

    /// The one thing a read must never carry, asserted on a record of each data class.
    ///
    /// Serialised rather than field-tested: the type has no field for prose, and this is what says
    /// the *answer* has none either — including any field a later change might add.
    #[test]
    fn no_body_reaches_a_bundle_sealed_or_plaintext() {
        let (harness, plain, sealed) = populated_with();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![
                ("ticket".to_owned(), "PROJ-42".to_owned()),
                ("order_ref".to_owned(), "ord10014721".to_owned()),
            ],
            deadline_ms: 5_000,
            scope: Scope::Unrestricted,
            ..Request::default()
        };

        let bundle = compose(&store, &request).expect("composed");
        assert_eq!(
            bundle.records.len(),
            2,
            "both classes have to be in the answer for this to be a test"
        );
        assert_eq!(bundled(&bundle, &plain).data_class, DataClass::Internal);
        assert_eq!(
            bundled(&bundle, &sealed).data_class,
            DataClass::SubjectDerived,
        );

        let json = serde_json::to_string(&bundle.records).expect("serialises");
        assert!(!json.contains("summary"), "{json}");
        assert!(
            !json.contains(BODY),
            "the plaintext body of an internal record reached a caller: {json}"
        );
        // A word the body has and no attribute, entity or tag does, so this fails on a partial
        // body as well as a whole one.
        assert!(BODY.contains("shards"), "the fixture body moved: {BODY}");
        assert!(
            !json.contains("shards"),
            "part of a body reached a caller: {json}"
        );
    }

    /// The estimate describes the bytes being returned, not the number of rows.
    #[test]
    fn the_token_estimate_measures_the_structure_it_returns() {
        let harness = populated();
        let store = harness.pipeline.reader().expect("reader");
        let request = Request {
            entities: vec![("ticket".to_owned(), "PROJ-42".to_owned())],
            deadline_ms: 5_000,
            scope: Scope::Unrestricted,
            ..Request::default()
        };

        let bundle = compose(&store, &request).expect("composed");
        let bytes: usize = bundle.records.iter().map(RecordStructure::wire_bytes).sum();
        assert_eq!(
            bundle.token_estimate,
            bytes.div_ceil(yaam_contract::structure::BYTES_PER_TOKEN)
        );
        assert!(bundle.token_estimate > 0, "{bundle:?}");
        // A record with more in it costs more, which a per-record constant could not say.
        assert!(
            bytes > bundle.records.len() * 200,
            "a record's frontmatter is not 200 bytes: {bytes}"
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
    fn a_source_with_more_history_than_the_cap_says_so() {
        // The read asks for one row past the cap so that this is a fact and not a guess. A source
        // that filled the cap exactly and one that had more to give are different answers, and only
        // the extra row tells them apart.
        let mut bundle = Bundle::default();
        let found = structures(OVER_SOURCE_CAP);

        let kept = cap_source(&mut bundle, found, "entity ticket:PROJ-42");
        assert_eq!(kept.len(), PER_SOURCE_LIMIT as usize);
        assert!(
            bundle.degraded,
            "a truncated source is an incomplete bundle"
        );
        assert_eq!(bundle.omitted.len(), 1);
        assert!(
            bundle.omitted[0].contains("of a longer history"),
            "{:?}",
            bundle.omitted
        );

        // A source that fits says nothing.
        let mut bundle = Bundle::default();
        let found = structures(PER_SOURCE_LIMIT);
        assert_eq!(
            cap_source(&mut bundle, found, "entity ticket:PROJ-42").len(),
            PER_SOURCE_LIMIT as usize
        );
        assert!(!bundle.degraded);
        assert!(bundle.omitted.is_empty());
    }

    #[test]
    fn records_over_the_cap_are_dropped_and_reported() {
        let mut bundle = Bundle::default();
        let mut seen = HashSet::new();
        let found = structures(u32::try_from(MAX_RECORDS).expect("a small cap") + 1);

        take(&mut bundle, &mut seen, found, "entity ticket:PROJ-42");
        assert_eq!(bundle.records.len(), MAX_RECORDS);
        assert!(bundle.degraded);
        assert_eq!(bundle.omitted.len(), 1);
        assert!(bundle.omitted[0].contains("1 record(s) over the bundle cap"));
    }
}
