# Measured latency

The design document recorded eight latency figures as estimates, with a note not to quote them
externally until a benchmark had run. It has now run. These are the actuals.

Five of the eight estimates were comfortably met — by one to two orders of magnitude. Three were
missed: the **correlation join** (3–9× over), **`reindex --all`** (2.8× over), and **full-text
search** (~1.7× over). The join is the one with a decision attached to it, and the answer is in
[Recommendation on the join](#recommendation-on-the-join): the number is bad, but the stated remedy
is the wrong one.

## Running it

```sh
cargo run --release -p yaam-bench
```

Twelve to fifteen minutes, and about 1.5 GiB under `target/bench-store`. Overrides —
`YAAM_BENCH_ROOT`, `YAAM_BENCH_RECORDS`, `YAAM_BENCH_REINDEX`, `YAAM_BENCH_ITERS` — are documented
at the top of `src/main.rs`; a smoke run is `YAAM_BENCH_RECORDS=4000 YAAM_BENCH_REINDEX=2000
YAAM_BENCH_ITERS=40`.

A `--release` binary rather than `cargo bench` or an `#[ignore]`d test. Criterion's mean-and-
confidence-interval output is the wrong shape when the binding budget elsewhere in this design is a
p99; the expensive figure is a one-shot rebuild that a sampling harness cannot repeat cheaply; and
the 200k store has to be built once and shared by every measurement, which a per-benchmark `setup`
would rebuild. A hand-rolled harness printing this table has fewer moving parts and every figure in
it is one you can point at.

**It does not run in CI.** `yaam-bench` is a workspace member, so `cargo fmt`, `cargo clippy
--all-targets` and `cargo test --workspace` all compile it and it cannot rot — but it has no tests
and no `#[bench]`, so nothing in the default test path executes it. An `#[ignore]`d test would have
been one `--include-ignored` away from the gate. It is excluded from the coverage gate
(`--exclude yaam-bench` in `ci/check.sh` and `ci.yml`) because it is measurement code, not library
code: counting its never-executed lines against the workspace figure would move the number without
saying anything about the library.

## Where these came from

| | |
|---|---|
| CPU | Intel Xeon E3-1245 v2 @ 3.40 GHz, 4 cores / 8 threads |
| Memory | 31 GiB |
| Kernel | Linux 6.12.96+deb13-amd64 |
| Filesystem | ext4 on `/dev/md3` (software RAID); measured `fsync` ≈ 0.43 ms |
| Toolchain | rustc 1.97.1 (8bab26f4f 2026-07-14), `--release`, SQLite 3.53.4 (rusqlite `bundled`) |
| Store | 200,000 records over 730 days, seeded generator; 162 MiB of Markdown, 343 MiB index |

The host was shared with another workload during the run, which is the likeliest reason some p99s
sit well above their p50.

The filesystem line matters more than it looks. A second run on `tmpfs`, where `fsync` is free, is
reported below and is the difference between meeting and missing figure 8.

## The eight figures

Warm, steady state. `rows` is what the query returned — a fast query over nothing is not a fast
query. Lettered rows are variants added here, not estimates on record.

| # | measurement | estimate | rows | p50 | p99 | verdict |
|---|-------------|----------|-----:|----:|----:|---------|
| 1 | point lookup: everything on one entity (tail, 4 records) | <1 ms | 4 | **0.039** | 0.066 | met, 15–25× under |
| 1a | as 1, the busiest entity (1,672 records) | — | 1,474 | 1.514 | 2.636 | over what 1 implies |
| 2 | one action with a failure outcome, last 7 days | ~2 ms | 34 | **0.110** | 0.146 | met, 14–18× under |
| 3 | as 2, plus an indexed attribute (`environment = prod`) | ~2 ms | 11 | **0.131** | 0.183 | met, 11–15× under |
| 4 | one actor's records, last 7 days | ~3 ms | 618 | **0.523** | 0.928 | met, 3–6× under |
| 5 | two actions correlated within 24h, left side windowed to 30 days | ~10–30 ms | 1,000 | **90.6** | 159.9 | **missed, 3–9×** |
| 5a | as 5, left side windowed to 7 days | — | 1,000 | 84.8 | 123.5 | |
| 5b | as 5, no window at all — the whole two years | — | 1,000 | 4,248 | 6,348 | |
| 6 | full-text phrase, first 100 of 3,908 matching bodies | ~4 ms | 100 | **6.90** | 8.78 | **missed, ~1.7–2.2×** |
| 7 | bundle composition, typical: three tail entities and one actor | ~10–40 ms | 215 | **0.390** | 0.684 | met, 25–100× under |
| 7a | as 7, the busiest entity and one actor | — | 500 | 2.183 | 3.411 | |

Milliseconds. Full output — p90, max, the cold sample, and the plan behind each distinct statement
shape (figures 1, 2, 3, 4, 5, 5b and 6) — is what `cargo run --release -p yaam-bench` prints. The
lettered variants issue the same statements with different parameters, figure 7 is figures 1 and 4
composed, and figure 8 is not a query.

| # | measurement | estimate | actual |
|---|-------------|----------|-------:|
| 8 | `reindex --all` over 100,000 records | <60 s | **167.5 s** — **missed, 2.8×** |
| 8a | `reindex --all` over 200,000 records | — | 361.2 s |

### Warm and cold

Every read figure above is **warm**: a fresh connection, a warm-up of `iterations / 10` reads, then
the samples. The harness also reports one **cold** sample per measurement, taken on a connection
opened moments earlier with an empty SQLite page cache — typically 2–4× the warm p50 (e.g. figure 1:
0.145 ms cold against 0.039 ms warm). The host's page cache is warm in both cases; dropping it needs
privileges a benchmark should not ask for, so "cold" here means *SQLite's* cache and nothing more.
A genuinely cold host would be slower than either number.

## Where the estimates were wrong, and why

Each of these is read off the query plan the benchmark prints, not inferred.

### 5 — the correlation join

The plan, at 200k records:

```
SEARCH l USING INDEX records_action_outcome_time (action=? AND outcome=? AND received_ms>? AND received_ms<?)
SEARCH r USING INDEX records_action_outcome_time (action=?)
USE TEMP B-TREE FOR LAST 3 TERMS OF ORDER BY
```

Both sides use an index, so this is not a scan — but look at what the right side seeks on. It gets
`action=?` and nothing else. The covering index is `(action, outcome, received_ms, record_id)`, and
the right-hand filter constrains `action` but *not* `outcome`, so `outcome` is a gap in the middle of
the key and the range on `received_ms` cannot be an index constraint. It becomes a per-row filter.

That turns the 24-hour window into a full traversal of every `ticket_update` row — 36,000 of them at
this volume — **for each left row**. Cost is (left rows) × (all rows of the right action), and both
grow with the store.

Two consequences the benchmark measures rather than argues:

- **Windowed, page-limited** (figure 5): the first `ORDER BY` term is index-ordered, so `LIMIT 1000`
  can stop early and only ~20 left rows are ever visited. Cost is then linear in the right action's
  size: 61.8 ms at 100k, 90.6 ms at 200k.
- **Unwindowed** (figure 5b): the planner flips the join to drive from the right side, nothing can
  stop early, and the temp b-tree sorts every pair. 1,080 ms at 100k, 4,248 ms at 200k — quadratic.
  There is no implicit "recent" in `correlate`, so this is a query a caller can legitimately issue.

**One index fixes both.** Adding `records_action_time (action, received_ms, record_id)` to the same
200k index, and re-running the identical statement:

```
SEARCH l USING INDEX records_action_outcome_time (action=? AND outcome=? AND received_ms>? AND received_ms<?)
SEARCH r USING INDEX records_action_time (action=? AND received_ms>? AND received_ms<?)
USE TEMP B-TREE FOR LAST 3 TERMS OF ORDER BY
```

Both statements run in one `sqlite3` process against a copy of the 200k index built by this
benchmark, warm, second iteration:

| | as shipped | with `records_action_time` |
|---|---:|---:|
| 30-day left window | 97 ms | **1.0 ms** |
| no window at all | 4,480 ms | **1.0 ms** |

The right side's time range becomes a seek, and the join stops being a product. The two as-shipped
figures agree with what the harness reports for figures 5 and 5b (90.6 ms and 4,248 ms), which is
the check that the statement measured here is the statement the library runs.

### 8 — `reindex --all`

`reindex_all` calls `Writer::publish` once per record, and `publish` is its own
`BEGIN IMMEDIATE … COMMIT`. The index runs `synchronous = FULL`, so every one of those commits is a
durability round trip. At 100,000 records that is 100,000 of them.

The same 100k rebuild on `tmpfs`, where `fsync` returns without doing anything:

| | 100k rebuild |
|---|---:|
| ext4 on `/dev/md3` | 167.5 s |
| `tmpfs` | 57.8 s, and 63.7 s on the repeat |

So roughly **two thirds of the wall time is durability** and one third is parse-plus-insert work.
The `<60 s` estimate is almost exactly the `tmpfs` figure — it is a correct number for a rebuild that
does not have to survive power loss. On real storage it is 2.8× out, and the gap is proportional to
the disk's `fsync` latency, so it is worse on anything slower than this array.

Scaling is close to linear: 1.68 ms per record at 100k, 1.81 ms at 200k. The 8% drift comes from
`entities.ref_count`, which is recomputed by aggregating every reference to an entity on each write
— correct, and deliberately so, but it grows with the entity's history.

The remedy is batching, not a faster disk: one transaction per *batch* of records during a rebuild
would amortise the `fsync` over hundreds of records and cost nothing in correctness, because a
rebuild that fails part way is restarted rather than resumed.

### 6 — full-text search

```
SCAN records_fts VIRTUAL TABLE INDEX 0:M1
SEARCH rec USING INTEGER PRIMARY KEY (rowid=?)
USE TEMP B-TREE FOR ORDER BY
```

The `LIMIT 100` cannot be pushed into the match. Every hit needs its `records` row — for the scope
predicate and the `sealed = 0` test — and the whole result is sorted in a temp b-tree before the
limit applies. Cost therefore tracks the **corpus-wide match count**, not the store size and not the
page size:

| needle | matching bodies | time |
|---|---:|---:|
| a phrase that matches nothing | 0 | 0.24 ms |
| `"rolling restart"` at 100k records | 1,948 | 3.04 ms |
| `"rolling restart"` at 200k records | 3,908 | 6.90 ms |
| a single common word | 138,485 | 583 ms |

The `~4 ms` estimate is about right for a needle matching a couple of thousand bodies. It is not a
budget the API can hold to, because nothing stops a caller passing a common word. That is a missing
bound, not a slow index.

### 1a — the point lookup at the head of the distribution

`query::by_entity` is the one read with **no row cap** — `Filter::limit` does not reach it and there
is no `LIMIT` in its statement. For a tail identifier the `<1 ms` estimate holds with room to spare
(0.039 ms for 4 records). For the busiest entity in this store it does not: 0.736 ms at 868 records,
1.514 ms at 1,672. It is linear in the entity's history and unbounded, so "point lookup" is only
true at the tail. `bundle::compose` caps its own result at 500 records, but it pays for all of them
first (figure 7a).

## Recommendation on the join

The stated decision rule was: **if the correlation join exceeds ~200 ms, materialise a window table
rather than accept it.**

At the sized volume, with a 30-day left window, it does not exceed 200 ms — p50 90.6 ms, p99
159.9 ms. But that is 80% of the threshold, the windowed form is linear in store size, so it crosses
200 ms somewhere between 250k and 400k records, and the *unwindowed* form of the same public call is
already 4.2 s. By the spirit of the rule, this needs acting on now.

**Do not materialise a window table.** Add the index. `records_action_time (action, received_ms,
record_id)` takes the windowed join from 97 ms to 1.0 ms and the unwindowed one from 4,480 ms to
1.0 ms, measured on this same index, and it needs no new derived state, no new invariant about
keeping that state fresh, and no change to the query API. A materialised window table would buy a
similar speed-up at the price of another thing that has to be rebuilt correctly by
`reindex --all` — which is the operation that already misses its own budget.

Two smaller things fall out of the same measurements and are worth deciding on separately:

1. `search` should bound the work it does, not just the rows it returns — a ceiling on matches, or a
   refusal above one. A single common word costs 583 ms today, and grows with the corpus.
2. `by_entity` should honour a page size, as every other read does.

None of these are changed here: this crate measures, and the fixes are in `yaam-store`'s schema and
query API.

## What the synthetic data models, and what it does not

Cardinality is the point, not volume. A benchmark over uniform data measures a workload nobody has.

- **Entities**: 116,492 distinct identifiers in the built index — 38,786 `order_ref`, 12,008
  `ticket`, 65,698 `deploy`. Most carry a handful of records; the busiest `order_ref` carries 1,933
  references, 1,672 of them confident enough for a bundle, which is the figure 1a case. Ten percent
  of references land on one of eight hot identifiers per kind, which is what produces that head.
  `deploy` identifiers combine a service, an environment and a number, so they stay in the tail —
  the busiest holds 69.
- **Actions**: six, from 34% of traffic down to 3%. The action the failure queries ask about is 12%,
  so the index has something to be selective about.
- **Outcomes**: 88% success, 7% failure, 4% partial, 1% declined. As built: `lookup` 34.1% of
  records, `chat_message` 23.9%, `ticket_update` 18.0% (36,046 rows — the right-hand side of the
  join), `deploy` 12.1%, `order_sync` 8.9%, `reindex_run` 3.0%.
- **Actors**: twelve, three of them carrying about half the traffic between them.
- **Time**: 730 days ending at a fixed anchor, denser towards the recent end (a store that has been
  growing), so a 7-day window holds ~3,800 records rather than the ~1,900 a uniform spread would.
- **Visibility**: as built, 169,854 org, 20,039 team, 10,107 owner — and owner-visible records
  really do live in their own subtree, so the rebuild walk has to find them.

Deliberately not modelled, and each one makes the figures **optimistic**:

- **Every record is `internal` with a plaintext body.** No sealed records, so no per-record
  decryption and — since a sealed body indexes no text — nothing that would reduce the full-text
  corpus either.
- **The fan-out queue is never drained.** Jobs are enqueued by the rebuild and left there. No entity
  timelines are materialised on disk. `bundle::compose` reads only the index, so figures 7 and 7a are
  unaffected, but a real store would have done that work.
- **No cold manifests, no tombstones, no quarantine.** The rebuild walks the live tree only.
- **The host page cache is warm throughout.**

The generator writes Markdown files directly and lets `reindex --all` derive the index, rather than
going through `Pipeline::accept` 200,000 times. That is not a shortcut around the write path — a tree
plus a rebuild is exactly the state a restored backup is in — but it does skip validation, the
attribute schema, canonicalisation and the redaction check. So the run pushes 200 of the same
generated records through `Pipeline::accept` first and reports the count. If the generator ever
produces something the service would refuse, that assertion fails before any figure is printed. It
has already caught one such case.

Vocabulary throughout is neutral (`order_ref`, `ticket`, `deploy`, `chat_message`, `agent_a`), which
`ci/hygiene.sh` enforces as a build gate.

## Reproducibility

Every draw comes from a seeded `SplitMix64`, so two runs on the same machine produce the same
distributions and the same chosen identifiers. Record identifiers are minted fresh each run, as real
ones are; nothing a measurement selects on derives from them. The time anchor is a constant, not the
clock, so "last 7 days" means the same span in every run.

Query plans are obtained through `yaam_store::query::explain`, behind the non-default `explain`
feature this crate turns on. They come from the query's *own* statement text — a plan explained from a
hand-copied second spelling of the SQL is a plan for a statement nobody executes.
