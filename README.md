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
| **Redacted at the source** | The writer masks, the service only checks and refuses what is still unmasked — so a record's `fields_masked` is the writer's own account. `yaam_contract::mask` is the one implementation of masking, reading the same policy file the service checks against. |
| **Portable** | Any harness that speaks HTTP can participate; a local sidecar handles signing and sealing so callers hold no keys. |

## Layout

```
crates/
  yaam-contract   wire types, canonical entity IDs, schemas, writer-side masking — the vendorable contract
  yaam-crypto     per-record keys, per-subject key encryption, key store
  yaam-md         frontmatter and sealed-body serialisation
  yaam-store      SQLite schema, queries, full-text search
  yaam-core       write pipeline, sweeper, reindex, erasure, bundle composition
  yaam-server     HTTP service
  yaam-agent      local sidecar: one socket per caller, seals and signs on their behalf
spec/             the contract bundle other implementations vendor
```

## Deployment seams

Two traits a deployment implements, neither with an implementation in this repo, and both with a
default that behaves exactly as not using them did.

| | |
|---|---|
| `yaam_crypto::keystore::KeyWrapper` | Wraps subject keys before they reach the disk, so a key file recovered from a snapshot or a stale volume is inert without a call to external key custody. `FsKeyStore::unwrapped` is the development default, named so nobody gets it by accident. |
| `yaam_core::resolve::SubjectResolver` | Decides the subjects a record names. `DeclaredSubjects` trusts the ones it carries; a lookup that is briefly down quarantines the record for a later retry rather than rejecting it. |

## Status

Early. See `AGENTS.md` for the invariants any contribution must hold.

## License

MIT — see [LICENSE](LICENSE).
