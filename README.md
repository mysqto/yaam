# yaam — Yet Another Agent Memory

A portable memory and knowledge service for AI agents.

**Markdown is the source of truth; the index is disposable.** Every record is a Markdown file with
YAML frontmatter. A SQLite index is derived from that tree and can be rebuilt from it at any time —
which is the property that keeps the store readable by `grep`, `jq`, an editor, or any program that
can parse frontmatter, and keeps it from becoming captive to this implementation.

## Why

Agent memory usually ends up as either freeform prose nobody can query, or an opaque database nobody
can inspect. `yaam` takes a third path: a text tree you can read with ordinary tools, plus a derived
index that makes it queryable in single-digit milliseconds.

## Properties

| | |
|---|---|
| **Filesystem-first** | Markdown + YAML frontmatter. No proprietary format. |
| **Derived index** | SQLite + FTS5, rebuildable from the tree. Delete it and run `yaam reindex`. |
| **Crash-recoverable** | Write-ahead staging, atomic publish, a sweeper that converges. No claim of distributed atomicity. |
| **Erasable bodies** | Per-record keys, per-subject key encryption. Deleting a subject's keys makes their record bodies permanently unreadable in every copy, including backups. |
| **Idempotent** | Every write is keyed. Replays, retries and re-drives are safe. |
| **Portable** | Any harness that speaks HTTP can participate; a local sidecar handles signing and sealing so callers hold no keys. |

## Layout

```
crates/
  yaam-contract   wire types, canonical entity IDs, schemas — the vendorable contract
  yaam-crypto     per-record keys, per-subject key encryption, key store
  yaam-md         frontmatter and sealed-body serialisation
  yaam-store      SQLite schema, queries, full-text search
  yaam-core       write pipeline, sweeper, reindex, erasure, bundle composition
  yaam-server     HTTP service
  yaam-agent      local sidecar: one socket per caller, seals and signs on their behalf
spec/             the contract bundle other implementations vendor
```

## Status

Early. See `AGENTS.md` for the invariants any contribution must hold.

## License

MIT OR Apache-2.0
