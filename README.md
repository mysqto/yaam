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
| **Reads return structure, never a body** | A read answers with each matching record's frontmatter — action, outcome, declared attributes, entity references, subject pseudonyms, timestamps — and never its prose. The rule does not branch on data class: a sealed body is withheld because it is a body, and a plaintext one for the same reason. Reading a body is a tree-level operation, not a request. |
| **Idempotent** | Every write is keyed. Replays, retries and re-drives are safe. |
| **Redacted at the source** | The writer masks, the service only checks and refuses what is still unmasked — so a record's `fields_masked` is the writer's own account. `yaam_contract::mask` is the one implementation of masking, reading the same policy file the service checks against. |
| **Portable** | Any harness that speaks HTTP can participate; a local sidecar handles signing and sealing, for reads as well as writes, so callers hold no keys. |
| **Inferred references are marked as such** | An entity reference read out of a structured field carries `confidence: 1.0`; one inferred from prose carries less and is stored without being joined on by default. Which text counts as evidence is configuration (`spec/extractors.yaml`), and the precision of the answer is measured against a labelled corpus rather than asserted. |

## Layout

```
crates/
  yaam-contract   wire types, canonical entity IDs, schemas, writer-side masking — the vendorable contract
  yaam-crypto     per-record keys, per-subject key encryption, key store
  yaam-md         frontmatter and sealed-body serialisation
  yaam-store      SQLite schema, queries, full-text search
  yaam-core       write pipeline, sweeper, reindex, erasure, bundle composition
  yaam-server     HTTP service
  yaam-agent      local sidecar: two sockets per caller, seals and signs on their behalf
  yaam-cli        the three entry points: `yaam-server`, `yaam-agent`, `yaam`
xtask/            repository chores: generates spec/schemas, checks the shapes behind it
spec/             the contract bundle other implementations vendor
  memory.v1.yaml    the wire contract as OpenAPI 3.1, checked against the router and the types
  schemas/          the same shapes as JSON Schema 2020-12, generated — never edit by hand
  entities.yaml     entity kinds and their canonical ID forms
  extractors.yaml   when text is evidence that a kind was meant — anchors, guards, confidence
  attrs-schema.yaml declared attributes per action, and which of them may sit in plaintext
  redaction/        the redaction policies the writer masks against and the service checks
```

## Running it

Three binaries, one crate, one configuration type. `--root` names the memory tree; `--index` and
`--key-store` default to sitting under it, and every setting is also read from the environment
(`YAAM_ROOT`, `YAAM_INDEX`, `YAAM_KEY_STORE`, `YAAM_LISTEN`, `YAAM_KEYRING`,
`YAAM_UNSEAL_KEY_FILE`, `YAAM_MAINTENANCE_MS`, `YAAM_AGENT_STATE`, `YAAM_LOG`). A flag beats the
environment.

The service drains fan-out and sweeps every `--maintenance-ms` (30 s by default) *and* once at
startup, so a process that comes up over an interrupted write converges without waiting an interval
out.

```sh
# The service. Refuses to start on a misconfiguration, and logs the effective one — never a key.
yaam-server --root /srv/memory --listen 127.0.0.1:8787 \
            --keyring /etc/yaam/keyring.json --unseal-key-file /etc/yaam/sealing.key

# The sidecar. Two sockets per agent the state directory holds a signing key for:
#   <state-dir>/sockets/<agent>.sock        records, one JSON line in, one JSON line out
#   <state-dir>/sockets/<agent>.read.sock   reads, HTTP/1.1, signed as that agent
# `--socket agent=path` names the first; the second is the same path with `.read.sock` for its
# extension. A caller needs no key material for either.
yaam-agent --state-dir /var/lib/yaam/agent

# A read through the sidecar. The request is ordinary HTTP; the signature is the sidecar's to add.
curl --unix-socket /var/lib/yaam/agent/sockets/agent_a.read.sock \
     "http://localhost/records?limit=10"

# The operator command line.
yaam --root /srv/memory check                       # schema, drift, backlog, quarantine
yaam --root /srv/memory reindex --all               # rebuild the index from the tree
yaam --root /srv/memory erase --subject s_…         # prints what it would destroy, and stops
yaam --root /srv/memory erase --subject s_… --confirm-destroy-keys
yaam --root /srv/memory verify-erasure --tombstone tomb-…
yaam --root /srv/memory backup --to /srv/backups/2026-08-20   # authoritative half only
yaam --root /restored     restore --from /srv/backups/2026-08-20
```

A backup carries the tree, the cold manifests, the materialised timelines, the erasure log and the
`spec/` they are read under. It carries **no key store**, no quarantine spool, no staging and no
index: `yaam_core::backup::MANIFEST` declares the split, each exclusion with its reason, and both
commands read that one list. The key store is the load-bearing exclusion — erasure works by
destroying keys, so a key surviving in a backup would make a restore un-erase a subject while live
verification still reported the erasure complete. `restore` refuses a backup that carries one, and
refuses a store that already holds records; it rebuilds the index and replays the restored
tombstone log as part of the same command.

The key store has its own recovery path and is not part of this one. Restoring a tree without it
gives a store that answers structure and no bodies, which is the honest outcome: bodies are
readable only where their keys still are.

Both long-running binaries shut down on `SIGINT` or `SIGTERM`: they stop accepting, finish what is
in flight, and the sidecar removes its sockets and drains what the service will still take.

A record and a read take different paths on purpose. A record can be sealed and queued, so its
socket answers `accepted`, `spooled` or `rejected` — `spooled` meaning *durably held here*, which
HTTP has no good status for. A read cannot be queued at all: an answer that arrives later is data
that was already stale, so an unreachable service is a `503` and nothing is kept. Writes are
refused on the read socket with `405`, because a record proxied as HTTP would skip both the sealing
and the spool that the record socket gives it.

Exit codes are the scriptable interface and are listed in every `--help`:

| | |
|---|---|
| `0` | success |
| `1` | failed — anything the codes below do not describe |
| `2` | usage error |
| `3` | config error — a setting is missing, unreadable, or incomplete |
| `4` | degraded — the store answered, and something in it wants attention |
| `5` | unconfirmed — a destructive command was not confirmed; nothing was done |
| `6` | incomplete — the erasure is real but cannot be asserted complete yet |

### The keyring file

Which callers the service authenticates, and what each may do. Never logged.

```json
{
  "callers": {
    "agent_a":   { "role": "writer",   "key": "<hex>", "teams": ["platform"] },
    "agent_ops": { "role": "operator", "key": "<hex>", "previous_key": "<hex>" }
  }
}
```

### Wrapping key material

`yaam_crypto::wrapper::PassphraseWrapper` derives a key-encryption key with argon2id and wraps
subject keys with AES-256 key wrap. Fit it with `--key-passphrase-file` — a file rather than a value,
because an argument is visible in `ps` to every user on the host.

Without it the store falls back to `Passthrough` and a key file recovered from a snapshot, a stale
volume or a decommissioned disk is a usable key. Both `yaam-server` at startup and `yaam check` on
every read say which of the two is in force, and they ask the store rather than the configuration, so
a wrapper that failed to take effect still warns.

Every wrapped blob carries its own scheme, salt and cost. That is redundant per blob and bought
deliberately: a wrong wrapper errors instead of handing plausible rubbish to the unwrap step, which is
what keeps a destroyed key and an unreadable key distinguishable; passphrase plus blob is enough to
recover, so there is no salt file to lose from the backup the key store is meant to be excluded from;
and cost parameters recorded per blob make raising them a re-wrap at leisure rather than a flag day.

## The three shapes

A record has three faces: the wire record, the Markdown frontmatter, and the index columns. All
three are projections of `yaam_contract::ActionRecord`, and keeping them in step used to be a
convention — which missed a field on the wire that frontmatter spelled differently, and a column
with no field behind it, one after the other. It is now a check: `yaam_contract::lockstep` holds the
rule and the table of deliberate exceptions, each with a reason, and `cargo xtask check` hands it the
three shapes as the crates that own them actually spell them.

```sh
cargo xtask emit     # regenerate spec/schemas from the types
cargo xtask check    # the shapes agree, and the committed schemas are current
```

## Inferring references from text

`spec/entities.yaml` says what an identifier *is*. `spec/extractors.yaml` says when a run of
characters in prose is evidence that one was meant — which is a different question, because
`background` is a canonical `order_ref`, `UTF-8` is a canonical `ticket`, and a twelve-digit run is a
canonical anything that admits digits.

So shape is never enough. A candidate has to clear the kind's own pattern, the configured shape
guards, and a configured keyword within a few words in front of it; a word two kinds claim equally
is dropped rather than guessed at. What comes out is `confidence` below the `0.9` a high-confidence
query asks for — stored, searchable, and not joined on until someone asks for it.

The bar is precision, not recall, because the two failures cost different things. A missed reference
costs one query one fact and is bought back by adding an anchor. A wrong reference is a join key: it
answers every question that touches it, wrongly, and nobody reads the entity graph looking for it.

That claim is measured, not asserted. `crates/yaam-contract/testdata/entity-extraction.tsv` holds a
labelled corpus of short neutral texts — genuine references in context, ordinary words that satisfy a
loose pattern, digit runs that are timestamps or quantities, identifiers with nothing vouching for
them — and the test beside it fails below 0.95 precision.

## Deployment seams

Two traits a deployment implements, neither with an implementation in this repo, and both with a
default that behaves exactly as not using them did.

| | |
|---|---|
| `yaam_crypto::keystore::KeyWrapper` | Wraps subject keys before they reach the disk, so a key file recovered from a snapshot or a stale volume is inert without a call to external key custody. `FsKeyStore::unwrapped` is the development default, named so nobody gets it by accident. |
| `yaam_core::resolve::SubjectResolver` | Decides the subjects a record names. `DeclaredSubjects` trusts the ones it carries; a lookup that is briefly down quarantines the record for a later retry rather than rejecting it. |

## Crash tests

Every durability window has a test that kills a real service inside it with `SIGKILL` and asserts
what a *restarted* one makes of the state left behind: the staged write that never got renamed, the
committed record whose fan-out never drained, the timeline rollover that froze the head and never
made a new one. The windows are opened by a checkpoint the binary carries and arms only when
`YAAM_CRASH_AT` names one — inert otherwise, and logged loudly when it is not.

They wait on the service's own maintenance timer, so they take minutes and are kept out of a routine
test run:

```sh
cargo test -p yaam-cli --test crash_injection -- --ignored
```

`ci/check.sh` and CI both run them.

## Status

Early. See `AGENTS.md` for the invariants any contribution must hold.

## License

MIT — see [LICENSE](LICENSE).
