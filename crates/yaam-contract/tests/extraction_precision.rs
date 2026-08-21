//! Measures the shipped extractor against a labelled corpus.
//!
//! The claim `spec/extractors.yaml` makes is that what it emits is nearly always right, not that it
//! finds everything. That is a measurable claim and it is measured here rather than asserted in a
//! comment, because the failure it guards against is invisible: a wrongly inferred reference is a
//! join key, and a wrong join key silently answers every question that touches it.
//!
//! Precision is a gate. Recall is a ratchet — reported in full on failure, and floored only so it
//! cannot be quietly traded away for the precision the gate asks about.

use std::collections::BTreeSet;

use yaam_contract::entity::Registry;
use yaam_contract::extract::Extractor;

/// The kinds the workspace ships.
const ENTITIES: &str = include_str!("../../../spec/entities.yaml");

/// The rules the workspace ships.
const EXTRACTORS: &str = include_str!("../../../spec/extractors.yaml");

/// The labelled texts.
const CORPUS: &str = include_str!("../testdata/entity-extraction.tsv");

/// The precision the extractor must hold. A gate, not a target.
const MIN_PRECISION: f64 = 0.95;

/// The recall the extractor must not drop below.
///
/// A floor rather than a goal: recall is what the anchor requirement costs, and the cost is worth
/// paying. It is pinned so that a change buying precision by emitting almost nothing fails here.
const MIN_RECALL: f64 = 0.60;

/// Smallest corpus this test accepts, so the bar cannot be met by shrinking the evidence.
const MIN_CASES: usize = 200;

/// `hits / (hits + others)`, which is precision one way round and recall the other.
///
/// Counted through `u32` rather than cast from `usize`: a corpus this size cannot overflow it, and
/// the conversion that cannot lose anything needs no argument about whether it does.
fn ratio(hits: usize, others: usize) -> f64 {
    let total = u32::try_from(hits + others).expect("a corpus of this size fits in u32");
    f64::from(u32::try_from(hits).expect("a corpus of this size fits in u32")) / f64::from(total)
}

/// One labelled text.
struct Case {
    /// `kind:id` references a careful reader would draw from the text.
    expected: BTreeSet<String>,
    /// The text itself.
    text: String,
}

/// Reads the corpus. `#` lines and blanks are commentary.
fn corpus() -> Vec<Case> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (expected, text) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("corpus line is not tab-separated: {line}"));
            Case {
                expected: if expected == "-" {
                    BTreeSet::new()
                } else {
                    expected.split(',').map(str::to_owned).collect()
                },
                text: text.to_owned(),
            }
        })
        .collect()
}

#[test]
fn the_shipped_extractor_is_precise_on_the_labelled_corpus() {
    let registry = Registry::from_yaml(ENTITIES).expect("the shipped kinds load");
    let extractor = Extractor::from_yaml(registry, EXTRACTORS).expect("the shipped rules load");

    let cases = corpus();
    assert!(
        cases.len() >= MIN_CASES,
        "corpus has shrunk to {} cases, below the {MIN_CASES} this measurement needs",
        cases.len()
    );

    let (mut hits, mut wrong, mut missed) = (0_usize, Vec::new(), Vec::new());
    for case in &cases {
        let found: BTreeSet<String> = extractor
            .from_text(&case.text)
            .iter()
            .map(|entity| format!("{}:{}", entity.kind, entity.id))
            .collect();
        hits += found.intersection(&case.expected).count();
        for reference in found.difference(&case.expected) {
            wrong.push(format!("{reference} <- {}", case.text));
        }
        for reference in case.expected.difference(&found) {
            missed.push(format!("{reference} <- {}", case.text));
        }
    }

    // Guards the arithmetic below and the corpus itself: a corpus with no positive labels would
    // report perfect precision on an extractor that never fires.
    assert!(hits > 0, "the corpus has no reference the extractor finds");
    let precision = ratio(hits, wrong.len());
    let recall = ratio(hits, missed.len());
    let report = format!(
        "{} cases: {hits} correct, {} wrong, {} missed — precision {precision:.3}, recall {recall:.3}\n\
         wrong:\n  {}\nmissed:\n  {}",
        cases.len(),
        wrong.len(),
        missed.len(),
        wrong.join("\n  "),
        missed.join("\n  "),
    );

    assert!(
        precision >= MIN_PRECISION,
        "precision below {MIN_PRECISION}\n{report}"
    );
    assert!(recall >= MIN_RECALL, "recall below {MIN_RECALL}\n{report}");
    // The numbers are the deliverable, so they print on success too: `cargo test -- --nocapture`.
    println!("{report}");
}

#[test]
fn every_labelled_reference_is_canonical_and_of_a_configured_kind() {
    // A corpus is evidence, and a label naming a kind that does not exist, or an identifier the
    // registry would reject, is evidence of nothing.
    let registry = Registry::from_yaml(ENTITIES).expect("the shipped kinds load");
    for case in corpus() {
        for reference in &case.expected {
            let (kind, id) = reference
                .split_once(':')
                .unwrap_or_else(|| panic!("label `{reference}` is not `kind:id`"));
            let canonical = registry
                .canonicalise(kind, id)
                .unwrap_or_else(|e| panic!("label `{reference}`: {e}"));
            assert_eq!(
                canonical, id,
                "label `{reference}` is not in canonical form"
            );
            assert!(
                case.text.contains(id) || case.text.to_lowercase().contains(&id.to_lowercase()),
                "label `{reference}` names an identifier absent from: {}",
                case.text
            );
        }
    }
}
