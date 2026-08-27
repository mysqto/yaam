# Measured latency

The design document recorded eight latency figures as estimates, with a note not to quote them
externally until a benchmark had run. It has now run — twice. These are the actuals, and what
happened when the three misses were acted on.

Five of the eight estimates were comfortably met, by one to two orders of magnitude. Three were
missed: the **correlation join** (3–9× over), **`reindex --all`** (2.8× over), and **full-text
search** (~1.7× over). Each miss turned out to be a missing bound rather than a slow index, and the
measurement also found a fourth: `by_entity` had no row cap at all, so an endpoint documented as a
point lookup cost whatever the busiest entity in the store happened to carry.

All four are closed. The join took one index (`records_action_time`); the other three took a page
size on entity history, a candidate ceiling on full-text search, and one transaction for a whole
rebuild. What each of them costs is in [Before and after the
bounds](#before-and-after-the-bounds) — the table below is the store as it stands now, and every
figure the bounds moved is reported beside the number it moved from.

## Running it

```sh
cargo run --release -p yaam-bench
```

About two minutes, and 1.2 GiB under `target/bench-store` — a little more at the peak of a rebuild,
where the write-ahead log holds the index being built. It took twelve to fifteen minutes before the
bounds landed, and the difference is almost all figure 8: two rebuilds that were 528 s together are
now 106 s. Overrides — `YAAM_BENCH_ROOT`, `YAAM_BENCH_RECORDS`, `YAAM_BENCH_REINDEX`,
`YAAM_BENCH_ITERS` — are documented at the top of `src/main.rs`; a smoke run is
`YAAM_BENCH_RECORDS=4000 YAAM_BENCH_REINDEX=2000 YAAM_BENCH_ITERS=40`.

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
| Store | 200,000 records over 730 days, seeded generator; 162 MiB of Markdown, 361 MiB index |

The host was shared with another workload during both runs, which is the likeliest reason some p99s
sit well above their p50 — and it is why the figures the bounds did not touch (2, 3, 4, 7) still
moved by 10–25% between the two runs. That is the run-to-run noise floor on this host: read a
difference smaller than a quarter as no difference. The index also grew from 343 to 361 MiB, which
is the reference index carrying the record's time (see figure 1a below) and costs every read a
little more page cache.

The two runs are the same harness and the same seeded data. The earlier figures quoted below come
from the run before the bounds landed; where a number is labelled *before*, that is where it is
from.

The filesystem line matters more than it looks. A run on `tmpfs`, where `fsync` is free, is what
established that figure 8 was two thirds durability rather than two thirds work; it is reported under
[8](#8--reindex---all). Durability is no longer the binding cost there, but that comparison is how
the cause was found rather than guessed.

## The eight figures

Warm, steady state. `rows` is what the query returned — a fast query over nothing is not a fast
query. Lettered rows are variants added here, not estimates on record.

| # | measurement | estimate | rows | p50 | p99 | verdict |
|---|-------------|----------|-----:|----:|----:|---------|
| 1 | point lookup: one entity's history (tail, 4 records) | <1 ms | 4 | **0.064** | 0.081 | met, 12× under |
| 1a | as 1, the busiest entity (1,672 references), default page | — | 1,000 | 1.631 | 3.569 | one page, not the history |
| 1b | as 1a, asking for 10 | — | 10 | **0.073** | 0.105 | a page costs a page |
| 1c | as 1a, the unbounded verification read | — | 1,672 | 2.021 | 2.226 | what a rebuild pays |
| 2 | one action with a failure outcome, last 7 days | ~2 ms | 34 | **0.122** | 0.144 | met, 14× under |
| 3 | as 2, plus an indexed attribute (`environment = prod`) | ~2 ms | 11 | **0.145** | 0.168 | met, 12× under |
| 4 | one actor's records, last 7 days | ~3 ms | 618 | **0.548** | 0.676 | met, 4–5× under |
| 5 | two actions correlated within 24h, left side windowed to 30 days | ~10–30 ms | 1,000 | **1.586** | 1.768 | met, 6–19× under |
| 5a | as 5, left side windowed to 7 days | — | 1,000 | 1.617 | 1.709 | |
| 5b | as 5, no window at all — the whole two years | — | 1,000 | 1.565 | 1.686 | |
| 6 | full-text phrase, first 100 of 3,908 matching bodies | ~4 ms | 100 | **3.851** | 5.074 | met |
| 6a | full-text single common word, first 10 of 138,277 matching bodies | — | 10 | 4.930 | 6.530 | the corpus-wide case |
| 7 | bundle composition, typical: three tail entities and one actor | ~10–40 ms | 215 | **0.501** | 0.665 | met, 20–80× under |
| 7a | as 7, the busiest entity and one actor | — | 396 | 0.678 | 0.757 | |

Milliseconds. Full output — p90, max, the cold sample, and the plan behind each distinct statement
shape (figures 1, 2, 3, 4, 5, 5b, 6 and 6a, plus the structure projections `2s` and `5s`) — is what
`cargo run --release -p yaam-bench` prints.
The lettered variants issue the same statements with different parameters, figure 7 is figures 1 and
4 composed, and figure 8 is not a query.

| # | measurement | estimate | actual |
|---|-------------|----------|-------:|
| 8 | `reindex --all` over 100,000 records | <60 s | **31.8 s** — met, 1.9× under |
| 8a | `reindex --all` over 200,000 records | — | 74.5 s |

One shot, but not unrepeatable: a second full run of the same harness gave 32.0 s and 74.1 s.
Every read figure above reproduced within the noise floor on that run too, except figure 1a, which
came back 17% faster — which is what a noise floor looks like.

### Warm and cold

Every read figure above is **warm**: a fresh connection, a warm-up of `iterations / 10` reads, then
the samples. The harness also reports one **cold** sample per measurement, taken on a connection
opened moments earlier with an empty SQLite page cache — typically 2–4× the warm p50 (e.g. figure 1:
0.177 ms cold against 0.064 ms warm). The host's page cache is warm in both cases; dropping it needs
privileges a benchmark should not ask for, so "cold" here means *SQLite's* cache and nothing more.
A genuinely cold host would be slower than either number.

## Before and after the bounds

Same harness, same seeded data, same host. Every figure the four bounds moved:

| # | measurement | before | now | |
|---|-------------|-------:|----:|---|
| 1a | busiest entity (1,672 references), default page | 1.514 | 1.631 | 1,474 rows became a 1,000-row page |
| 1b | busiest entity, asking for 10 | 1.3 ‡ | **0.073** | a page now costs a page |
| 5 | correlation join, 30-day window | 90.6 | **1.586** | `records_action_time` |
| 5a | correlation join, 7-day window | 84.8 | **1.617** | same index |
| 5b | correlation join, no window | 4,248 | **1.565** | same index |
| 6 | full-text phrase, 3,908 matches, page of 100 | 6.90 | **3.851** | candidate ceiling |
| 6a | full-text common word, 138,277 matches, page of 10 | 583 † | **4.930** | candidate ceiling |
| 7a | bundle over the busiest entity | 2.183 | **0.678** | per-source cap now applies to entities |
| 8 | `reindex --all`, 100,000 records | 167,500 | **31,800** | one transaction |
| 8a | `reindex --all`, 200,000 records | 361,200 | **74,500** | one transaction |

Milliseconds throughout, p50.

‡ There was no page size to ask for before, so figure 1b has no earlier harness row either. 1.3 ms
is the old statement with `LIMIT 10` bolted on, from the controlled pair under
[1a](#1a--the-point-lookup-at-the-head-of-the-distribution): the cap alone bought nothing, which is
the point of that table.

† Figure 6a had no harness row before the bounds; 583 ms is the hand-run measurement the earlier
report quoted for a single common word. Re-run as a controlled pair on this run's own index — both
statements in one `sqlite3` process, `cache_size` set to the library's own, warm — the old statement
costs 266–277 ms and the new one 4.96–5.08 ms. The 583 ms figure and this 270 ms one differ by cache
configuration, not by statement; the honest comparison is the pair measured together, and it is
50×.

Figures 5, 5a and 5b are the index the previous commit added, measured by the harness for the first
time: predicted 1.0 ms by hand, measured 1.6 ms in the library. The unwindowed form, which was
4.2 s, is now indistinguishable from the windowed one — which was the point of preferring the index
over a materialised window table.

Three of these bounds cost something, and the costs are stated where they are paid: entity history
in [1a](#1a--the-point-lookup-at-the-head-of-the-distribution), full-text recall in
[6](#6--full-text-search), and peak disk during a rebuild in [8](#8--reindex---all).

## Where the estimates were wrong, and why

Each of these is read off the query plan the benchmark prints, not inferred. Each section describes
the code as first measured, and ends with what was done about it.

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

Both consequences are why `GET /correlate` requires its left window rather than merely capping the
read: the quadratic case above is one index away, and the window is the only parameter a request can
carry that bounds the term that grows. Nothing here changes for the projection the endpoint returns —
the pair of *structures* is the same statement with the frontmatter column added to both sides of the
select list, which costs a table lookup per returned row and leaves both seeks in place (plan `5s`).

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

**What was done: one transaction, not a batch size.** A batch boundary would have needed to be a
point something could resume from, and there is nothing to resume: a rebuild truncates the derived
tables and reads the whole tree either way, so a half-finished one has no partial state worth
keeping. The whole rebuild is therefore a single `BEGIN IMMEDIATE`, and the truncate is inside it.

That buys two things. One `fsync` instead of 100,000: **167.5 s → 31.8 s** at 100k and 361.2 s →
74.5 s at 200k. And atomicity, which the batched version could not have had — the previous code
committed the truncate on its own, so from the moment a rebuild started until it finished the live
index was short, readable, and indistinguishable from a finished one. An interrupted rebuild now
leaves the index it started from.

31.8 s is *below* the 57.8 s `tmpfs` figure, so durability was not the only thing removed. Two
smaller changes came with the same commit: `entities.ref_count` is now recomputed from the reference
index alone rather than joined back to `records` — which is what the 8% drift above was — and the
rebuild walks the tree in arrival order, so rows land in primary-key order instead of jumping about.

**What it costs: peak disk.** Nothing a transaction has written is checkpointed into the database
file until it commits, so the write-ahead log holds the whole new index while the rebuild runs. Peak
`-wal` size observed during the 200k rebuild was 335 MiB beside a 361 MiB index — call it double the
index, transiently. A rebuild also now holds the write lock from start to finish, where before
another writer could interleave between records; the design has exactly one writer, so this costs
nothing inside the process and turns a concurrent `yaam reindex` against a running service into a
busy timeout rather than a race.

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

**What was done: a candidate ceiling before the join.** `search` now takes at most
`20 × limit` matches, capped at 5,000, and joins only those to `records`. The cap is taken at the
most recently indexed end of the match, because descending row id is the only order the full-text
index can walk without visiting every hit — measured over a corpus with ~138,000 matches, 200
candidates in row-id order cost 0.2 ms and the same 200 *by rank* cost 195 ms. So ranking the
candidates globally, which would have kept the better matches, gives the bound straight back;
ranking applies within the ceiling instead. The plan the harness now prints:

```
CO-ROUTINE candidates
  SCAN records_fts VIRTUAL TABLE INDEX 192:M1
SCAN candidates
SEARCH rec USING INTEGER PRIMARY KEY (rowid=?)
USE TEMP B-TREE FOR ORDER BY
```

`192` is the descending-row-id scan, and it is the whole difference: the candidate step is its own
co-routine, so the row lookup and the temp b-tree below it see the ceiling and never the corpus.

**What it costs: recall for a narrowly scoped caller.** Neither a `LIMIT` nor a scope predicate can
be pushed into a full-text match, so the ceiling is applied before the scope test. A caller entitled
to a small share of what matched can therefore get a short page — up to an empty one — while records
it may read sit just past the ceiling. Twenty candidates per row asked for is the headroom that
covers a caller who can read a twentieth of the corpus, and no more than that. The trade is pinned
by a test rather than left to this paragraph:
`a_narrowly_scoped_search_can_come_back_short_of_its_page`.

The ceiling also depends on row id following the clock, which is why `reindex` sorts the tree into
arrival order. It did not before, and the first measurement of this bound found it: owner-visible
records live under `records/owner/`, which sorts after every dated directory, so a path-ordered
rebuild gave them all the highest row ids and a common word came back with a page of nothing.

### 1a — the point lookup at the head of the distribution

`query::by_entity` is the one read with **no row cap** — `Filter::limit` does not reach it and there
is no `LIMIT` in its statement. For a tail identifier the `<1 ms` estimate holds with room to spare
(0.039 ms for 4 records). For the busiest entity in this store it does not: 0.736 ms at 868 records,
1.514 ms at 1,672. It is linear in the entity's history and unbounded, so "point lookup" is only
true at the tail. `bundle::compose` caps its own result at 500 records, but it pays for all of them
first (figure 7a).

**What was done: a page size on the endpoint, and an index that makes it mean something.**
`GET /entities/{kind}/{id}` takes `limit` like every other read, defaulting to the same 1,000-row
cap; the rebuild's verification reads `query::by_entity_unbounded`, which takes no page size and no
scope — unbounded and unrestricted are the same decision, so a request-driven path cannot reach for
it and still answer a caller.

A row cap on its own would have been cosmetic, and this is the part worth reporting. Under the old
reference index — `(kind, entity_id, confidence, record_pk)` — the rows came out in record order and
every one of them was sorted before the page was taken, so the `LIMIT` capped the answer and not the
work. Measured on the busiest entity, in one `sqlite3` process against a copy of this run's own 200k
index with the old reference index recreated beside the new one, warm, `cache_size` set to the
library's own:

| statement | p50 |
|---|---:|
| as shipped before: no `LIMIT`, 1,474 rows | 1.8 ms |
| the same statement plus `LIMIT 10` | 1.3 ms |
| as shipped now: `LIMIT 10`, order taken from the reference index | **0.076 ms** |

The same three statements over a purpose-built 200,000-row table whose busiest entity carries 20,000
references: 28 ms, 28 ms, 0.07 ms. Which is the shape of it — the first two grow with the entity and
the third does not. The index is `entity_refs_recent (kind, entity_id, received_ms, confidence,
record_pk)`, which needed the record's server time copied into `entity_refs` — derived like every
other column there, and the reason the index file grew by 5%. `confidence` sits *after* the time
because it is a range test, and a range mid-key ends the ordered walk. The old index is gone rather
than kept beside the new one: with both present the planner prefers the one that can seek on
`confidence`, and sorts the history all over again — measurably the wrong choice, and it is the
1.3 ms row above.

The unbounded read is still there and still costs what it costs — figure 1c, 2.021 ms for 1,672
references — because a rebuild verifying its own output has to see all of them, and a cap that
silently truncated it would turn a hot entity into a verification failure nobody could explain. That
was the reason an earlier pass declined to cap `by_entity` at all, and it is why the cap went on the
endpoint instead.

**What it costs: an endpoint that no longer answers with everything.** A caller that wants a busy
entity's whole history has to page by narrowing `min_confidence`, or ask a filtered query instead.
`bundle::compose` now applies its own documented per-source cap of 200 to entity history — it never
did — and says so in `omitted` when a source had more, which is why figure 7a returns 396 records
rather than 500.

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

Two smaller things fell out of the same measurements and were left as separate decisions:

1. `search` should bound the work it does, not just the rows it returns — a ceiling on matches, or a
   refusal above one. A single common word cost 583 ms, and grew with the corpus.
2. `by_entity` should honour a page size, as every other read does.

Both have since been done, in `yaam-store`'s schema and query API and in the server's own contract;
this crate still only measures. The index landed first, and figures 5, 5a and 5b above are what it
was worth: the recommendation was to add the index rather than materialise a window table, and the
unwindowed join is now as cheap as the windowed one.

## What the synthetic data models, and what it does not

Cardinality is the point, not volume. A benchmark over uniform data measures a workload nobody has.

- **Entities**: 116,492 distinct identifiers in the built index — 38,786 `order_ref`, 12,008
  `ticket`, 65,698 `deploy`. Most carry a handful of records; the busiest `order_ref` carries 1,933
  references, 1,672 of them confident enough for a bundle, which is the figure 1a case. Ten percent
  of references land on one of eight hot identifiers per kind, which is what produces that head.
  `deploy` identifiers combine a service, an environment and a number, so they stay in the tail —
  the busiest holds 69.
- **Words**: bodies are 24 to 48 words drawn from a list of thirty, so any one of them appears in
  about seven bodies in ten — 138,277 of 200,000 for the word figure 6a searches for. That is the
  corpus-wide needle: not a pathological input, just a common word, which is what makes the
  full-text bound worth having.
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
- **Nothing is backfilled.** Every record arrives in server-time order, so row id and the clock
  agree exactly. They agree only approximately in a real store, and figure 6a's candidate ceiling is
  the read that cares: a backfilled record arrives late with an old stamp, and is a candidate as if
  it were new.
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
