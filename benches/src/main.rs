//! Latency benchmark for the eight figures the design document recorded as estimates.
//!
//! # Running it
//!
//! ```sh
//! cargo run --release -p yaam-bench
//! ```
//!
//! A `--release` binary rather than `cargo bench` or an `#[ignore]`d test, for three reasons. It
//! takes minutes and writes a few hundred megabytes, so it must not be reachable from
//! `cargo test` at all — an ignored test is one `--include-ignored` away from being in the gate.
//! The expensive figure is a single one-shot rebuild that a sampling harness cannot repeat cheaply,
//! and Criterion's mean-and-confidence output is the wrong shape when the binding budget elsewhere
//! in this design is a p99. And the store has to be built once and shared by every measurement,
//! which a per-benchmark `setup` would rebuild.
//!
//! Environment overrides, for a smoke run or a different disk:
//!
//! | variable             | default              | meaning                            |
//! |----------------------|----------------------|------------------------------------|
//! | `YAAM_BENCH_ROOT`    | `target/bench-store` | where the tree and index are built |
//! | `YAAM_BENCH_RECORDS` | `200000`             | records in the final store         |
//! | `YAAM_BENCH_REINDEX` | `100000`             | records the timed rebuild covers   |
//! | `YAAM_BENCH_ITERS`   | `300`                | iterations for the cheap reads     |
//!
//! # What it reports
//!
//! p50/p90/p99/max over the warm, steady-state case, plus one cold sample per measurement taken on
//! a freshly opened connection. Both are labelled, because they answer different questions. Every
//! read also reports the number of rows it returned and the plan the planner chose — a query that
//! is fast because the data happens to fit in memory stops being fast, and the plan is what tells
//! the two apart.

mod synth;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use yaam_contract::Visibility;
use yaam_core::bundle;
use yaam_store::Store;
use yaam_store::query::{self, Filter, Scope, Traversal, Window, explain};

/// Name of the derived index under the memory root.
///
/// Spelled here because it is `pub(crate)` in `yaam-core`; a benchmark opening the index directly
/// needs it, and the layout is part of the crate's documented contract.
const INDEX_FILE: &str = "index.sqlite";

/// The reader every measurement runs as: one caller, one team, three visibility levels.
///
/// A real request-driven read, not [`Scope::Unrestricted`]. The scope is a predicate on every row a
/// query returns, so measuring without it would measure a query the service never issues.
fn reader() -> Scope {
    Scope::Caller {
        visibility: vec![Visibility::Org, Visibility::Team, Visibility::Owner],
        agent: "agent_a".to_owned(),
        teams: vec!["platform".to_owned()],
    }
}

/// One measurement's timings and what it returned.
struct Timings {
    /// Sorted samples from the warm phase.
    warm: Vec<Duration>,
    /// One sample on a connection that has just been opened.
    cold: Duration,
    /// Rows the query returned. Reported because a fast query over nothing is not a fast query.
    rows: usize,
}

impl Timings {
    /// Nearest-rank percentile, `pct` in `1..=100`.
    fn percentile(&self, pct: usize) -> Duration {
        let rank = (self.warm.len() * pct).div_ceil(100).max(1) - 1;
        self.warm[rank]
    }
}

/// A measurement, its recorded estimate, and what it actually cost.
struct Row {
    /// Number in the design document's table, or a number and letter for a variant.
    tag: &'static str,
    /// What was measured.
    what: String,
    /// The estimate on record, or `—` for a variant that had none.
    estimate: &'static str,
    /// The result.
    timings: Timings,
}

/// Formats a duration as milliseconds with three decimals.
fn ms(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1_000.0)
}

/// Whole mebibytes, so a size can be reported without a lossy cast.
fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

/// Runs `body` once cold on a freshly opened store, then warm, and reports the spread.
///
/// The cold sample comes first and on its own connection: a warm-up before it would be measuring
/// the thing it exists to exclude. `SQLite`'s own page cache is what "cold" means here — the host's
/// page cache is warm either way, because dropping it needs privileges a benchmark should not want.
fn measure(index: &Path, iterations: usize, mut body: impl FnMut(&Store) -> usize) -> Timings {
    let cold_store = Store::open_read(index).expect("open index");
    let started = Instant::now();
    let rows = body(&cold_store);
    let cold = started.elapsed();
    drop(cold_store);

    let store = Store::open_read(index).expect("open index");
    // Warm-up: the first few reads populate the page cache, and mixing them into the samples would
    // put the cold cost in the tail of the warm figure.
    for _ in 0..(iterations / 10).max(3) {
        body(&store);
    }
    let mut warm = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let observed = body(&store);
        warm.push(started.elapsed());
        assert_eq!(
            observed, rows,
            "a measured query changed its answer mid-run"
        );
    }
    warm.sort_unstable();
    Timings { warm, cold, rows }
}

/// Reads a positive number from the environment, or falls back.
fn env_usize(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|text| text.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

/// The filesystem a path sits on, from `/proc/mounts`.
///
/// Worth reporting rather than assuming: a `tmpfs` makes every `fsync` free, which flatters the
/// rebuild figure by an order of magnitude and would make it a number nobody can reproduce.
fn filesystem_of(path: &Path) -> String {
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return "unknown".to_owned();
    };
    let mut best = ("unknown".to_owned(), 0);
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(point), Some(kind)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if target.starts_with(point) && point.len() >= best.1 {
            best = (format!("{kind} on {source} at {point}"), point.len());
        }
    }
    best.0
}

/// How the store was built and how long the two rebuilds took.
struct Built {
    /// Path of the derived index.
    index: PathBuf,
    /// Rebuild of the smaller tree — the figure the estimate was written for.
    rebuild_small: Duration,
    /// Rebuild of the whole tree.
    rebuild_full: Duration,
}

/// Prints what machine and what data these figures came from.
fn describe(root: &Path, total: usize) {
    println!("# yaam latency benchmark\n");
    println!("- store root: `{}`", root.display());
    println!("- filesystem: {}", filesystem_of(root));
    println!(
        "- host: {} cores, kernel {}",
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    println!(
        "- cpu: {}",
        fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split(':').nth(1))
            .unwrap_or("unknown")
            .trim()
    );
    println!(
        "- data: {total} records, {} days ending {}, seeded generator",
        synth::SPAN_DAYS,
        synth::ANCHOR
    );
}

/// Writes the tree and builds the index, timing the two rebuilds.
///
/// Generation is deliberately outside every measurement. The rebuild is not: it *is* measurement 8.
fn build(root: &Path, total: usize, rebuild_at: usize, anchor_ms: i64) -> Built {
    // A sample through the real write path first. If the generator produces records the service
    // would refuse, every figure below describes a store that cannot exist.
    let probe = root.join("write-path-probe");
    let accepted =
        synth::sample_through_write_path(&probe, 200, anchor_ms).expect("the write path accepts");
    fs::remove_dir_all(&probe).expect("clear the probe");
    println!("- write path: {accepted} of the same records accepted by `Pipeline::accept`");

    synth::write_spec(root).expect("spec");
    let mut pipeline = yaam_core::Pipeline::new(root).expect("pipeline");

    let first = u64::try_from(rebuild_at).unwrap_or(0);
    let started = Instant::now();
    let bytes = synth::write_tree(root, 0, first, anchor_ms).expect("write tree");
    println!(
        "- generated: {rebuild_at} records, {} MiB of Markdown, in {:.1} s (not measured)",
        mib(bytes),
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    let report = yaam_core::reindex::reindex_all(&mut pipeline).expect("rebuild");
    let rebuild_small = started.elapsed();
    assert_eq!(report.from_tree, rebuild_at, "the rebuild missed records");

    synth::write_tree(root, first, u64::try_from(total).unwrap_or(0), anchor_ms)
        .expect("write tree");
    let started = Instant::now();
    let report = yaam_core::reindex::reindex_all(&mut pipeline).expect("rebuild");
    let rebuild_full = started.elapsed();
    assert_eq!(report.from_tree, total, "the rebuild missed records");
    drop(pipeline);

    let index = root.join(INDEX_FILE);
    println!(
        "- index: {} MiB\n",
        mib(fs::metadata(&index).map_or(0, |meta| meta.len()))
    );
    Built {
        index,
        rebuild_small,
        rebuild_full,
    }
}

/// The identifiers and windows the measurements name.
///
/// Chosen from a tally of the generated records rather than guessed: naming an entity that does not
/// exist would turn a point lookup into a measurement of an empty result.
struct Targets {
    /// The busiest `order_ref`, and how many records carry it.
    hot: (String, usize),
    /// A long-tail `order_ref`, `ticket` and `deploy`, each with its record count.
    tail: [(String, String, usize); 3],
    /// Bodies carrying the searched-for phrase.
    with_phrase: usize,
    /// Bodies carrying the single common word measurement 6a searches for.
    with_common_word: usize,
}

impl Targets {
    /// Tallies the generated records and picks the identifiers to measure against.
    fn pick(total: usize, anchor_ms: i64) -> Self {
        let census = synth::Census::of(0, u64::try_from(total).unwrap_or(0), anchor_ms);
        let hot = census.busiest("order_ref").expect("a busiest order_ref");
        let tail = [("order_ref", 4), ("ticket", 5), ("deploy", 6)].map(|(kind, want)| {
            let (id, count) = census.typical(kind, want).expect("a tail identifier");
            (kind.to_owned(), id, count)
        });
        println!(
            "- entity skew: busiest `order_ref` {} carries {} records; the tail identifiers \
             named below carry {}, {} and {}",
            hot.0, hot.1, tail[0].2, tail[1].2, tail[2].2
        );
        println!(
            "- phrase `{}` appears in {} of {total} bodies; the common word `{}` in {}\n",
            synth::PHRASE,
            census.with_phrase,
            synth::COMMON_WORD,
            census.with_common_word
        );
        Self {
            hot,
            tail,
            with_phrase: census.with_phrase,
            with_common_word: census.with_common_word,
        }
    }
}

/// Every filter the measurements share, built once so a plan and its timing cannot diverge.
struct Queries {
    /// Last seven days of the anchor window.
    week: Window,
    /// Last thirty days of the anchor window.
    month: Window,
    /// The whole generated span. What a traversal from a long-tail entity has to use: an entity
    /// carrying four records over two years has none inside a seven-day window, and a measurement
    /// of an empty answer is not a measurement of this read.
    span: Window,
    /// The full-text expression measurement 6 issues.
    phrase: String,
    /// A typical bundle request.
    typical_bundle: bundle::Request,
    /// The same request aimed at the busiest entity.
    hot_bundle: bundle::Request,
}

/// One action with a failure outcome, optionally windowed.
fn failed_deploys(window: Option<Window>) -> Filter {
    Filter {
        action: Some("deploy".to_owned()),
        outcome: Some("failure".to_owned()),
        window,
        scope: reader(),
        ..Filter::default()
    }
}

/// As [`failed_deploys`], narrowed by an indexed attribute.
fn in_prod(window: Option<Window>) -> Filter {
    Filter {
        attr: Some(("environment".to_owned(), "prod".to_owned())),
        ..failed_deploys(window)
    }
}

/// The right-hand side of the correlation: a different action, unwindowed, joined by time.
fn ticket_updates() -> Filter {
    Filter {
        action: Some("ticket_update".to_owned()),
        scope: reader(),
        ..Filter::default()
    }
}

/// A traversal from one entity, over one window, at the shipped corridor cap.
///
/// The seed and the window are the two parameters that decide the cost, so they are what the
/// measurements below vary. Everything else is what the endpoint defaults to, because a benchmark of
/// a tuned traversal measures the tuning.
fn traversal(kind: &str, id: &str, depth: u32, window: Window) -> Traversal {
    Traversal {
        kind: kind.to_owned(),
        id: id.to_owned(),
        depth,
        window,
        min_confidence: query::FULL_CONFIDENCE,
        max_degree: query::CORRIDOR_DEGREE,
        limit: None,
        scope: reader(),
    }
}

/// One actor's records over a window.
fn one_actor(window: Window) -> Filter {
    Filter {
        agent: Some("agent_a".to_owned()),
        window: Some(window),
        scope: reader(),
        ..Filter::default()
    }
}

impl Queries {
    /// Builds every query shape from the chosen targets.
    fn new(targets: &Targets, anchor_ms: i64) -> Self {
        let window = |days: i64| Window {
            from_ms: anchor_ms - days * synth::DAY_MS,
            to_ms: anchor_ms + synth::DAY_MS,
        };
        let typical_bundle = bundle::Request {
            entities: targets
                .tail
                .iter()
                .map(|(kind, id, _)| (kind.clone(), id.clone()))
                .collect(),
            actor: Some("agent_a".to_owned()),
            // Generous on purpose: a deadline that bit would make this a measurement of the
            // deadline rather than of the work.
            deadline_ms: 30_000,
            scope: reader(),
            // Unset, so the measurement stays comparable with the figures already published: a
            // limit would be measuring a smaller bundle, not a faster one.
            limit: None,
        };
        Self {
            week: window(7),
            month: window(30),
            span: window(synth::SPAN_DAYS),
            phrase: format!("\"{}\"", synth::PHRASE),
            hot_bundle: bundle::Request {
                entities: vec![("order_ref".to_owned(), targets.hot.0.clone())],
                ..typical_bundle.clone()
            },
            typical_bundle,
        }
    }
}

/// Runs every read measurement.
fn read_measurements(
    index: &Path,
    iterations: usize,
    targets: &Targets,
    queries: &Queries,
) -> Vec<Row> {
    let mut rows = single_table_reads(index, iterations, targets, queries);
    rows.extend(join_reads(index, iterations, queries));
    rows.extend(composed_reads(index, iterations, targets, queries));
    rows.extend(traversal_reads(index, iterations, targets, queries));
    rows
}

/// The reads driven from one index: measurements 1 to 4.
fn single_table_reads(
    index: &Path,
    iterations: usize,
    targets: &Targets,
    queries: &Queries,
) -> Vec<Row> {
    let mut rows = entity_reads(index, iterations, targets);
    rows.extend(filtered_reads(index, iterations, queries));
    rows
}

/// One entity's history, at each extent and each projection: measurement 1 and its variants.
fn entity_reads(index: &Path, iterations: usize, targets: &Targets) -> Vec<Row> {
    let (hot_id, hot_count) = (&targets.hot.0, targets.hot.1);
    let (tail_id, tail_count) = (&targets.tail[0].1, targets.tail[0].2);

    vec![
        Row {
            tag: "1",
            what: format!(
                "point lookup: one entity's history (`order_ref` tail, {tail_count} records)"
            ),
            estimate: "<1 ms",
            timings: measure(index, iterations, |store| {
                query::by_entity(store, "order_ref", tail_id, 1.0, None, None, &reader())
                    .expect("by entity")
                    .len()
            }),
        },
        Row {
            tag: "1a",
            what: format!(
                "as 1, the busiest entity ({hot_count} records) at the default page size"
            ),
            estimate: "—",
            timings: measure(index, iterations / 3, |store| {
                query::by_entity(store, "order_ref", hot_id, 1.0, None, None, &reader())
                    .expect("by entity")
                    .len()
            }),
        },
        Row {
            tag: "1b",
            what: format!("as 1a, the busiest entity ({hot_count} records), asking for 10"),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::by_entity(store, "order_ref", hot_id, 1.0, None, Some(10), &reader())
                    .expect("by entity")
                    .len()
            }),
        },
        Row {
            tag: "1s",
            what: format!(
                "as 1a, the busiest entity ({hot_count} records), as structure rather than ids"
            ),
            estimate: "—",
            timings: measure(index, iterations / 3, |store| {
                query::by_entity_structures(store, "order_ref", hot_id, 1.0, None, None, &reader())
                    .expect("by entity")
                    .len()
            }),
        },
        Row {
            tag: "1c",
            what: format!(
                "as 1a, the busiest entity ({hot_count} records), the unbounded verification read"
            ),
            estimate: "—",
            timings: measure(index, iterations / 3, |store| {
                query::by_entity_unbounded(store, "order_ref", hot_id, 1.0)
                    .expect("by entity")
                    .len()
            }),
        },
    ]
}

/// The filtered reads: measurements 2 to 4.
fn filtered_reads(index: &Path, iterations: usize, queries: &Queries) -> Vec<Row> {
    vec![
        Row {
            tag: "2",
            what: "one action with a failure outcome, last 7 days".to_owned(),
            estimate: "~2 ms",
            timings: measure(index, iterations, |store| {
                query::by_filter(store, &failed_deploys(Some(queries.week)))
                    .expect("by filter")
                    .len()
            }),
        },
        Row {
            tag: "2s",
            what: "as 2, returning each match's structure rather than its id".to_owned(),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::by_filter_structures(store, &failed_deploys(Some(queries.week)))
                    .expect("by filter")
                    .len()
            }),
        },
        Row {
            tag: "3",
            what: "as 2, further filtered by an indexed attribute (`environment = prod`)"
                .to_owned(),
            estimate: "~2 ms",
            timings: measure(index, iterations, |store| {
                query::by_filter(store, &in_prod(Some(queries.week)))
                    .expect("by filter")
                    .len()
            }),
        },
        Row {
            tag: "4",
            what: "one actor's records, last 7 days".to_owned(),
            estimate: "~3 ms",
            timings: measure(index, iterations, |store| {
                query::by_filter(store, &one_actor(queries.week))
                    .expect("by filter")
                    .len()
            }),
        },
    ]
}

/// The correlation join: measurement 5 and two variants that bound it differently.
fn join_reads(index: &Path, iterations: usize, queries: &Queries) -> Vec<Row> {
    let day = synth::DAY_MS;

    vec![
        Row {
            tag: "5",
            what: "two actions correlated within 24h, left side windowed to 30 days".to_owned(),
            estimate: "~10-30 ms",
            timings: measure(index, (iterations / 5).max(5), |store| {
                query::correlate(
                    store,
                    &failed_deploys(Some(queries.month)),
                    &ticket_updates(),
                    day,
                )
                .expect("correlate")
                .len()
            }),
        },
        Row {
            tag: "5a",
            what: "as 5, left side windowed to 7 days".to_owned(),
            estimate: "—",
            timings: measure(index, (iterations / 5).max(5), |store| {
                query::correlate(
                    store,
                    &failed_deploys(Some(queries.week)),
                    &ticket_updates(),
                    day,
                )
                .expect("correlate")
                .len()
            }),
        },
        Row {
            tag: "5b",
            what: "as 5, no window at all — the whole two years".to_owned(),
            estimate: "—",
            timings: measure(index, (iterations / 20).max(5), |store| {
                query::correlate(store, &failed_deploys(None), &ticket_updates(), day)
                    .expect("correlate")
                    .len()
            }),
        },
    ]
}

/// The graph read: measurement 9 and the variants that bound it differently.
///
/// Four rows because the cost of a traversal is a product and each factor deserves its own line: the
/// depth, the busyness of the seed, and the width of the window. The first is the one with no
/// estimate on record — this read did not exist when §7.6 was written.
fn traversal_reads(
    index: &Path,
    iterations: usize,
    targets: &Targets,
    queries: &Queries,
) -> Vec<Row> {
    let (hot_id, hot_count) = (&targets.hot.0, targets.hot.1);
    let (tail_kind, tail_id, tail_count) =
        (&targets.tail[0].0, &targets.tail[0].1, targets.tail[0].2);

    vec![
        Row {
            tag: "9",
            what: format!(
                "one hop from the busiest `order_ref` ({hot_count} records), 7-day window"
            ),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::linked(store, &traversal("order_ref", hot_id, 1, queries.week))
                    .expect("linked")
                    .len()
            }),
        },
        Row {
            tag: "9a",
            what: "as 9, two hops — the capability that did not exist".to_owned(),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::linked(store, &traversal("order_ref", hot_id, 2, queries.week))
                    .expect("linked")
                    .len()
            }),
        },
        Row {
            tag: "9s",
            what: "as 9a, returning each edge's record as structure rather than its id".to_owned(),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::linked_structures(store, &traversal("order_ref", hot_id, 2, queries.week))
                    .expect("linked")
                    .len()
            }),
        },
        Row {
            tag: "9b",
            // The depth `GET /linked/{kind}/{id}` refuses, measured at the layer below it. This is
            // the row the refusal rests on: the frontier fills breadth-first and this request spends
            // all 200 edges on hops 1 and 2, so the endpoint declines to serve it as a three-hop
            // answer. Kept, and kept running, because whoever writes the per-hop budget needs the
            // before number — and because a measurement deleted is a measurement nobody can check.
            what:
                "as 9a, three hops over a 30-day window — the depth the endpoint refuses, and why"
                    .to_owned(),
            estimate: "—",
            timings: measure(index, (iterations / 5).max(5), |store| {
                query::linked(store, &traversal("order_ref", hot_id, 3, queries.month))
                    .expect("linked")
                    .len()
            }),
        },
        Row {
            tag: "9c",
            what: format!(
                "two hops from a tail `order_ref` ({tail_count} records) over the whole two years \
                 — the seed is quiet and every corridor is judged on its lifetime traffic"
            ),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::linked(store, &traversal(tail_kind, tail_id, 2, queries.span))
                    .expect("linked")
                    .len()
            }),
        },
    ]
}

/// Full-text search and bundle composition: measurements 6 and 7.
fn composed_reads(
    index: &Path,
    iterations: usize,
    targets: &Targets,
    queries: &Queries,
) -> Vec<Row> {
    let hot_count = targets.hot.1;

    vec![
        Row {
            tag: "6",
            what: format!(
                "full-text phrase `{}`, first 100 of {} matching bodies",
                queries.phrase, targets.with_phrase
            ),
            estimate: "~4 ms",
            timings: measure(index, iterations, |store| {
                query::search(store, &queries.phrase, 100, &reader())
                    .expect("search")
                    .len()
            }),
        },
        Row {
            tag: "6a",
            what: format!(
                "full-text single common word `{}`, first 10 of {} matching bodies",
                synth::COMMON_WORD,
                targets.with_common_word
            ),
            estimate: "—",
            timings: measure(index, iterations, |store| {
                query::search(store, synth::COMMON_WORD, 10, &reader())
                    .expect("search")
                    .len()
            }),
        },
        Row {
            tag: "7",
            what: "bundle composition, typical: three tail entities and one actor".to_owned(),
            estimate: "~10-40 ms",
            timings: measure(index, (iterations / 5).max(5), |store| {
                bundle::compose(store, &queries.typical_bundle)
                    .expect("compose")
                    .records
                    .len()
            }),
        },
        Row {
            tag: "7a",
            what: format!("as 7, but the busiest entity ({hot_count} records) and one actor"),
            estimate: "—",
            timings: measure(index, (iterations / 5).max(5), |store| {
                bundle::compose(store, &queries.hot_bundle)
                    .expect("compose")
                    .records
                    .len()
            }),
        },
    ]
}

/// The planner's account of each read, taken from the query's own statement text.
fn plans(index: &Path, targets: &Targets, queries: &Queries) -> String {
    let store = Store::open_read(index).expect("open index");
    let day = synth::DAY_MS;
    let steps = [
        (
            "1",
            explain::by_entity(
                &store,
                "order_ref",
                &targets.tail[0].1,
                1.0,
                None,
                None,
                &reader(),
            ),
        ),
        (
            "1s",
            explain::by_entity_structures(
                &store,
                "order_ref",
                &targets.tail[0].1,
                1.0,
                None,
                None,
                &reader(),
            ),
        ),
        (
            "2",
            explain::by_filter(&store, &failed_deploys(Some(queries.week))),
        ),
        (
            "2s",
            explain::by_filter_structures(&store, &failed_deploys(Some(queries.week))),
        ),
        (
            "3",
            explain::by_filter(&store, &in_prod(Some(queries.week))),
        ),
        ("4", explain::by_filter(&store, &one_actor(queries.week))),
        (
            "5",
            explain::correlate(
                &store,
                &failed_deploys(Some(queries.month)),
                &ticket_updates(),
                day,
            ),
        ),
        (
            "5b",
            explain::correlate(&store, &failed_deploys(None), &ticket_updates(), day),
        ),
        // The projection a request gets. Its own entry for the reason `2s` has one: the frontmatter
        // column is in neither covering index, so whether selecting it on *both* sides of the join
        // costs the seeks is a property of the plan and of nothing a timing would show.
        (
            "5s",
            explain::correlate_structures(
                &store,
                &failed_deploys(Some(queries.month)),
                &ticket_updates(),
                day,
            ),
        ),
        (
            "6",
            explain::search(&store, &queries.phrase, 100, &reader()),
        ),
        (
            "6a",
            explain::search(&store, synth::COMMON_WORD, 10, &reader()),
        ),
        // The traversal, at both projections. It is the only read here whose join runs once per node
        // on the frontier, so whether each hop still seeks is the difference between a bounded read
        // and one that scans `entity_refs` a frontier's worth of times.
        (
            "9a",
            explain::linked(
                &store,
                &traversal("order_ref", &targets.hot.0, 2, queries.week),
            ),
        ),
        (
            "9s",
            explain::linked_structures(
                &store,
                &traversal("order_ref", &targets.hot.0, 2, queries.week),
            ),
        ),
    ];
    let mut out = String::new();
    for (tag, plan) in steps {
        let _ = writeln!(out, "### {tag}\n\n```\n{}\n```\n", plan.expect("a plan"));
    }
    out
}

/// Prints the two result tables.
fn report(rows: &[Row], built: &Built, total: usize, rebuild_at: usize) {
    println!("## Reads — warm, steady state\n");
    println!("| # | measurement | estimate | rows | iters | p50 | p90 | p99 | max | cold |");
    println!("|---|-------------|----------|-----:|------:|----:|----:|----:|----:|-----:|");
    for row in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            row.tag,
            row.what,
            row.estimate,
            row.timings.rows,
            row.timings.warm.len(),
            ms(row.timings.percentile(50)),
            ms(row.timings.percentile(90)),
            ms(row.timings.percentile(99)),
            ms(*row.timings.warm.last().expect("a sample")),
            ms(row.timings.cold),
        );
    }
    println!("\nMilliseconds. `cold` is one sample on a freshly opened connection.\n");

    println!("## Rebuild — one shot; there is no steady state for it\n");
    println!("| # | measurement | estimate | actual |");
    println!("|---|-------------|----------|-------:|");
    println!(
        "| 8 | `reindex --all` over {rebuild_at} records | <60 s | {:.1} s |",
        built.rebuild_small.as_secs_f64()
    );
    println!(
        "| 8a | `reindex --all` over {total} records | — | {:.1} s |",
        built.rebuild_full.as_secs_f64()
    );
    println!();
}

/// Builds the store, runs every measurement, prints the report.
fn main() {
    if cfg!(debug_assertions) {
        eprintln!(
            "warning: this is a debug build. Run `cargo run --release -p yaam-bench`: \
             a debug build measures the optimiser's absence, not the design's cost."
        );
    }

    let root = std::env::var("YAAM_BENCH_ROOT").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/bench-store"),
        PathBuf::from,
    );
    let total = env_usize("YAAM_BENCH_RECORDS", 200_000);
    let rebuild_at = env_usize("YAAM_BENCH_REINDEX", 100_000).min(total);
    let iterations = env_usize("YAAM_BENCH_ITERS", 300);
    let anchor_ms = yaam_contract::timestamp::parse_ms(synth::ANCHOR).expect("a readable anchor");

    // A fresh tree every run: a rebuild over a tree that already had an index is a different
    // measurement from a rebuild over one that did not.
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the previous store");
    }
    fs::create_dir_all(&root).expect("create the store root");

    describe(&root, total);
    let built = build(&root, total, rebuild_at, anchor_ms);
    let targets = Targets::pick(total, anchor_ms);
    let queries = Queries::new(&targets, anchor_ms);
    let rows = read_measurements(&built.index, iterations, &targets, &queries);

    report(&rows, &built, total, rebuild_at);
    println!(
        "## Query plans\n\n{}",
        plans(&built.index, &targets, &queries)
    );
}
