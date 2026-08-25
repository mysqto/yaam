//! The labelled corpus, measured through the emitter rather than through the extractor.
//!
//! `crates/yaam-contract/tests/extraction_precision.rs` already gates the rules themselves. What it
//! cannot see is the path a caller actually takes: argument parsing, the spec directory
//! `--infer-entities` names, the merge with whatever `--entity` stated, and the JSON line that goes
//! to the socket. A precision claim that held for the library and not for that path would be a claim
//! about nothing, and the way it would fail is silent — a wrongly inferred reference is a join key,
//! and a wrong join key answers every question that touches it.
//!
//! So the same corpus, the same floor, read off the record the command would send. It is measured
//! in process rather than by spawning the binary: 280-odd commands is the whole corpus, and what is
//! under test is the record, not the fork.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use yaam_cli::config::Env;

/// The labelled texts, shared with the measurement in `yaam-contract`.
///
/// Read from there rather than copied. Two corpora would drift, and the one that drifted would be
/// the one still reporting a number nobody could act on.
const CORPUS: &str = include_str!("../../yaam-contract/testdata/entity-extraction.tsv");

/// The precision this path must hold, which is the floor the rules themselves are held to.
const MIN_PRECISION: f64 = 0.95;

/// Smallest corpus this accepts, so the bar cannot be met by shrinking the evidence.
const MIN_CASES: usize = 200;

/// The spec directory the workspace ships, as a caller would name it.
fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

/// The `kind:id` references the emitter puts on the record it would send.
///
/// Through the whole command: `--dry-run` prints the exact bytes the socket would receive, so what
/// is read back here is the record itself rather than a rehearsal of one.
fn emitted(summary: &str, spec: Option<&str>) -> BTreeSet<String> {
    let record = dry_run(summary, spec);
    record["entities"]
        .as_array()
        .expect("an entity list")
        .iter()
        .map(|entity| {
            // Every reference on the record came from prose here, so every one has to read as a
            // guess. A `1.0` or a `primary` in this list would mean the merge lost the distinction
            // the record keeps between a stated reference and an inferred one.
            assert_eq!(entity["role"], "related", "{entity}");
            assert!(
                entity["confidence"].as_f64().expect("a confidence") < 0.9,
                "{entity}"
            );
            format!(
                "{}:{}",
                entity["kind"].as_str().expect("a kind"),
                entity["id"].as_str().expect("an id")
            )
        })
        .collect()
}

/// The record one command would have sent, as the dry run prints it.
///
/// `--summary=` rather than a separate argument: a corpus text may begin with a bullet, and clap
/// reads a bare value starting with a hyphen as a flag.
fn dry_run(summary: &str, spec: Option<&str>) -> serde_json::Value {
    let mut args = vec![
        "yaam-emit".to_owned(),
        "--agent=agent_a".to_owned(),
        "--action=note".to_owned(),
        "--outcome=success".to_owned(),
        format!("--summary={summary}"),
        "--dry-run".to_owned(),
    ];
    if let Some(spec) = spec {
        args.push(format!("--infer-entities={spec}"));
    }

    let mut out = Vec::new();
    let code = yaam_cli::emitter(args, &Env::default(), &mut out);
    assert_eq!(code, 0, "{summary}: {}", String::from_utf8_lossy(&out));
    let line = String::from_utf8(out).expect("utf-8");
    serde_json::from_str(line.trim()).expect("one JSON record")
}

/// One labelled text: the references a careful reader would draw, and the text itself.
fn corpus() -> Vec<(BTreeSet<String>, String)> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (expected, text) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("corpus line is not tab-separated: {line}"));
            let expected = if expected == "-" {
                BTreeSet::new()
            } else {
                expected.split(',').map(str::to_owned).collect()
            };
            (expected, text.to_owned())
        })
        .collect()
}

#[test]
fn the_corpus_is_as_precise_through_the_emitter_as_through_the_rules() {
    let spec = spec_dir();
    let spec = spec.to_str().expect("utf-8 path");
    let cases = corpus();
    assert!(
        cases.len() >= MIN_CASES,
        "corpus has shrunk to {} cases, below the {MIN_CASES} this measurement needs",
        cases.len()
    );

    let (mut hits, mut wrong) = (0_usize, Vec::new());
    for (expected, text) in &cases {
        let found = emitted(text, Some(spec));
        hits += found.intersection(expected).count();
        for reference in found.difference(expected) {
            wrong.push(format!("{reference} <- {text}"));
        }
    }

    // Guards the arithmetic and the run: a path that emitted nothing at all would report perfect
    // precision, which is the one way this test could pass while the flag did nothing.
    assert!(hits > 0, "no labelled reference survived the emitter");
    let total = u32::try_from(hits + wrong.len()).expect("a corpus of this size fits in u32");
    let precision = f64::from(u32::try_from(hits).expect("fits in u32")) / f64::from(total);
    assert!(
        precision >= MIN_PRECISION,
        "precision {precision:.3} below {MIN_PRECISION} — {hits} correct, {} wrong:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}

/// Nothing is inferred without the flag, over the very texts the rules would fire on.
///
/// The default path is what every existing caller is on, and the cost of getting this wrong is not
/// visible in a store nothing rewrites: join keys nobody asked for, on every record already written.
#[test]
fn the_corpus_infers_nothing_when_the_flag_is_absent() {
    for (expected, text) in corpus() {
        if expected.is_empty() {
            continue;
        }
        let record = dry_run(&text, None);
        assert_eq!(
            record["entities"].as_array().expect("an entity list").len(),
            0,
            "{text}"
        );
    }
}
