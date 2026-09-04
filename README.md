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
| **One erasure reaches one body** | A record names at most one data subject. A body sealed under two subject shares would end for both the moment either one was erased, and the survivor would keep a right of access to it that no re-key, re-seal or delete here can answer — so it is refused on the way in rather than written. An event about two subjects is two records, related by `correlation_id` and by the entity references both carry, which are plaintext and survive either erasure. |
| **Reads return structure, never a body** | A read answers with each matching record's frontmatter — action, outcome, declared attributes, entity references, subject pseudonyms, timestamps — and never its prose. The rule does not branch on data class: a sealed body is withheld because it is a body, and a plaintext one for the same reason. A plaintext body is read from the tree; a sealed one only through `yaam unseal`, which records the reading before it performs it. |
| **One audited way back to a sealed body** | `yaam unseal` publishes an operator-visible record naming who read the body and why, and only then fetches a key. A store that cannot record the read cannot answer it, so there is no path that returns a sealed body without a line saying it did. |
| **Derived knowledge** | One note per entity under `knowledge/`, rebuilt wholesale from the record tree by `yaam knowledge build`. Every line restates a structured field some record declared and names the records it came from. Nothing is derived from a record whose body is erasable, so a key destruction has no aggregate to chase. |
| **Correlation is one read** | *Which declines had a deploy near them* is a directional range join over the server-stamped clock, answered as pairs of records by `GET /correlate` — not two reads and an intersection performed by the caller. Its window is required rather than optional: a join whose left side is unbounded is a query whose answer moves with the store, and whose cost moves with the planner. |
| **Traversal is record-mediated, and never through a hub** | *What else is connected to this, and how* is a recursive join over `entity_refs`, answered by `GET /linked/{kind}/{id}` as edges — two entities and the record naming both, so why they are connected needs no second read. Two entities are linked because a record says so; there is no edge table, because an edge with no record behind it could not be rebuilt from the tree. An entity is **reached** however busy it is and is not walked **through** above a capped number of references inside the window, and the ones the rule refused come back named, because "nothing else is connected" and "everything is, through this one node" are the same short answer otherwise. |
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
  yaam-knowledge  facts derived from record structure, rebuilt wholesale from the record tree
  yaam-server     HTTP service
  yaam-agent      local sidecar: two sockets per caller, seals and signs on their behalf
  yaam-cli        the six entry points: `yaam-server`, `yaam-agent`, `yaam`, `yaam-emit`, `yaam-file`, `yaam-read`
hooks/            the pre-commit guard for a repository holding a backup, and its installer
xtask/            repository chores: generates spec/schemas, checks the shapes behind it
spec/             the contract bundle other implementations vendor
  memory.v1.yaml    the wire contract as OpenAPI 3.1, checked against the router and the types
  schemas/          the same shapes as JSON Schema 2020-12, generated — never edit by hand
  entities.yaml     entity kinds and their canonical ID forms
  extractors.yaml   when text is evidence that a kind was meant — anchors, guards, confidence
  attrs-schema.yaml declared attributes per action, and which of them may sit in plaintext
  subjects.yaml     which entity kinds are erasure units — absent, and no body is ever sealed
  redaction/        the redaction policies the writer masks against and the service checks
```

## Running it

Six binaries, one crate, one configuration type. `--root` names the memory tree; `--index` and
`--key-store` default to sitting under it, and every setting is also read from the environment
(`YAAM_ROOT`, `YAAM_INDEX`, `YAAM_KEY_STORE`, `YAAM_KEY_PASSPHRASE_FILE`,
`YAAM_SUBJECT_KEY_FILE`, `YAAM_LISTEN`, `YAAM_KEYRING`, `YAAM_UNSEAL_KEY_FILE`,
`YAAM_MAINTENANCE_MS`, `YAAM_AGENT_STATE`, `YAAM_SOCKET`, `YAAM_AGENT`, `YAAM_READ_SOCKET`,
`YAAM_LOG`). A flag beats the environment.

Two of the six open a store and four never do. `yaam-agent`, `yaam-emit`, `yaam-file` and
`yaam-read` run on the caller's host and have no `--root` to give them: that is what lets a caller
record what it did, and read what it remembers, while holding no key material and no path into
anyone's memory tree. The one directory a caller-side binary will read is the one `--infer-entities`
names — the emitters to lift references onto a record, `yaam-read bundle` to turn a request's own
prose into lookup keys — and each reads two configuration files out of it. A spec directory is not a
store, and nothing in any of them could open one.

The service drains fan-out and sweeps every `--maintenance-ms` (30 s by default) *and* once at
startup, so a process that comes up over an interrupted write converges without waiting an interval
out. A store driven by the command line alone has no such timer: `yaam drain` runs the queue on
demand, and `reindex`, `erase` and `restore` drain what they re-enqueue before they return, so none
of them leaves a store with its entity timelines missing.

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

# Reading. The sidecar signs on the caller's behalf, so this holds no key either. The service's
# JSON goes to stdout unchanged.
export YAAM_READ_SOCKET=/var/lib/yaam/agent/sockets/agent_a.read.sock
yaam-read records --action deploy --attr environment=staging --limit 10
yaam-read search --query "rolled back" --limit 5      # full text over bodies, structure back
yaam-read history --entity deploy:api/staging#1146    # one entity's history, newest first
yaam-read bundle --entity ticket:PROJ-42 --actor agent_a --limit 5   # context for a request

# Two shapes joined on time: which declines had a deploy in the half hour after them. One read,
# answered as pairs. The window is required — see below.
yaam-read correlate --left-action transact --left-outcome declined --right-action deploy \
          --left-from-ms 1787184000000 --left-to-ms 1787270400000 --within-ms 1800000

# Two hops out from an order reference: what is connected to it, and by which records. The
# depth and the window are required, and an entity too busy to be a corridor comes back named
# rather than walked through.
yaam-read linked --entity order_ref:ord10014733 --depth 2 \
          --from-ms 1787184000000 --to-ms 1787270400000

# …and a bundle for a caller that has a sentence rather than a list of entities.
yaam-read bundle --infer-entities /srv/memory/spec --limit 5 \
          --infer-from "any news on ticket PROJ-42?"        # looks up ticket:PROJ-42

yaam-read records --dry-run   # the exact request, no sidecar needed

# The socket is ordinary HTTP, so anything that speaks it can read too.
curl --unix-socket /var/lib/yaam/agent/sockets/agent_a.read.sock \
     "http://localhost/records?limit=10"

# Recording one action. Everything mechanical — the identifier, both timestamps, the schema version,
# `backfilled`, the empty collections — is filled in; what is asked for is what only the caller knows.
export YAAM_SOCKET=/var/lib/yaam/agent/sockets/agent_a.sock YAAM_AGENT=agent_a
yaam-emit --action deploy --outcome success --summary "rolled the api service out to staging" \
          --attr service=api --attr environment=staging --entity deploy:api/staging#1146 --tag release

# …and the references the prose carries and the caller did not state. Opt-in, and what it adds is
# `related` below full confidence: a guess stays a guess in the record it lands in.
yaam-emit --action note --outcome success --summary "closing ticket PROJ-42 after the rollout" \
          --infer-entities /srv/memory/spec

yaam-emit --action deploy --outcome success --summary "…" --dry-run   # the exact line, no sidecar needed

# The operator command line.
yaam --root /srv/memory check                       # schema, drift, backlog, quarantine, dead letters
yaam --root /srv/memory reindex --all               # rebuild the index from the tree, then drain
yaam --root /srv/memory drain                       # run queued fan-out: timelines, audit records
yaam --root /srv/memory drain --max-jobs 500        # …up to a bound; the rest stays queued
yaam --root /srv/memory erase --subject s_…         # prints what it would destroy, and stops
yaam --root /srv/memory erase --subject s_… --confirm-destroy-keys
yaam --root /srv/memory verify-erasure --tombstone tomb-…
yaam --root /srv/memory unseal --record 01ARZ… --operator lead_ops \
     --reason "subject access request"                # prints whose keys it would use, and stops
yaam --root /srv/memory unseal --record 01ARZ… --operator lead_ops \
     --reason "subject access request" --confirm-read-body
yaam --root /srv/memory backup --to /srv/backups/2026-08-20   # authoritative half only
yaam --root /restored     restore --from /srv/backups/2026-08-20   # copy, rebuild, then drain
```

A backup carries the tree, the cold manifests, the subject audit trail, the erasure log and the
`spec/` they are read under. It carries **no key store**, no quarantine spool, no staging, no index
and no materialised timelines: `yaam_core::backup::MANIFEST` declares the split, each exclusion with
its reason, and both commands read that one list. The timelines are left behind because a rebuild
reproduces them — it drops them along with the index rows that record which lines they already hold,
and the fan-out it queues writes them again — from the tree, and from the cold manifests for the
records the tree no longer holds — which the same command then drains before it returns. The key
store is the load-bearing exclusion — erasure works by destroying keys, so a key surviving in a
backup would make a restore un-erase a subject while live verification still reported the erasure
complete. `restore` refuses a backup that carries one, and refuses a store that already holds
records; it rebuilds the index, replays the restored tombstone log and drains the fan-out that
rebuild queued, all as part of the same command.

The key store has its own recovery path and is not part of this one. Restoring a tree without it
gives a store that answers structure and no bodies, which is the honest outcome: bodies are
readable only where their keys still are.

### Keeping a backup under version control

Records are Markdown, so a backup in a private repository is reviewable and diffable — and it is safe
for exactly the reason above: no keys travel, so destroying a key still makes a sealed body
permanently unreadable however long the ciphertext stays in the history. That rests on the key store
never being committed once, and an ignore rule is not a mechanism against a one-way door. `git add -f`
overrides one, a rule written today does not remove what was committed yesterday, and a store whose
`--key-store` points inside the work tree is ignored by nothing.

`yaam guard-commit` is the mechanism. It decides whether a set of paths is safe to commit, reading
the same `yaam_core::backup::MANIFEST` a backup is taken against — so a newly excluded entry protects
a repository the moment it is declared, with no second list to keep in step. It opens no store.

```sh
hooks/install.sh --store store          # writes .git/hooks/pre-commit, records yaam.root
yaam --root store guard-commit --repo .              # what the hook runs
yaam --root store guard-commit --path store/keystore/x   # one path, by hand
yaam guard-commit --print-hook           # the hook the installer writes
```

Keep the store in a subdirectory. Everything beside it is then outside the memory root and none of
the guard's business; a store at the top level of a repository leaves no such place, and the guard
refuses every file there that no manifest entry classifies.

Every unknown refuses, and each kind has its own code: `8` a path no copy may contain, `4` one beside
the store in no manifest, `3` not knowing where the store is, `1` not being able to resolve a path at
all. A path is read twice — its spelling, which catches `records/../keystore/x`, and its identity from
`canonicalize`, which catches a symlink into a key store and a key store relocated under `records/`.
A hardlink is caught by inode, and an excluded entry that merely *exists* in the work tree is refused
on every commit whether anything from it is staged or not.

Two limits, stated rather than assumed. `git commit --no-verify` skips every pre-commit hook, and a
*copy* of a key file is a different file with the same bytes; neither is visible from a hook. What
catches those is the same command run again on the far side — a `pre-receive` hook on the remote, or a
required job over the pushed tree.

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
| `7` | spooled — the sidecar holds the record and is still delivering it; a success |
| `8` | rejected — the request will never be accepted as asked; only its sender can fix it |
| `9` | unreachable — a socket did not answer; nothing was recorded and nothing was read |

`7` is a success and has its own code because the two things it might mean to a monitor are different:
the record is durable, and the service has not seen it yet. A hook that treated it as a failure would
report an outage as a lost record, which is the one thing the spool exists to prevent — so a hook that
branches at all should treat `0` and `7` alike.

### Recording an action

`yaam-emit` builds one `ActionRecord` and writes it to a caller socket. It exists because the socket
takes a complete record — seventeen fields — and hand-building that in every caller is why nothing
emitted records for so long.

| It fills in | It asks for | It will not offer |
|---|---|---|
| `record_id`, `at`, `received_at`, `schema_ver`, `backfilled`, the empty collections | `--agent`, `--action`, `--outcome`, `--summary`, and repeatable `--attr`, `--attr-int`, `--attr-bool`, `--entity`, `--tag` | a subject, a data class, or a store |
| the references the prose carries, on `--infer-entities` | | |

Three attribute flags rather than one that guesses: the type each key is declared with lives in the
deployment's `spec/attrs-schema.yaml`, which a caller cannot read, and a build number that happens to
be all digits is not evidence that it is an integer.

Both timestamps default to now, which is what a hook firing beside the action means. `--at` names the
instant the action happened at instead; `--backfilled` says the record was read out of a source
rather than watched happening, and makes `--at` the received time too. The pair is how history is
imported, and each flag needs the other for a reason: the store orders, windows and joins on the
received time, so `--at` alone would file a note from three years ago as having arrived today, and
`--backfilled` alone would claim a source supplied a received time nothing supplied. The emitter
refuses both of those, and refuses an `--at` in the future outright — a record is something that
happened.

```bash
yaam-emit --action deploy --outcome success --summary "…" \
          --at 2023-05-01T12:00:00Z --backfilled   # stored in 2023, not today
```

`--entity` is the caller stating a fact, and is recorded as a *primary* reference at confidence
`1.0`. Prose holds references too, and a record imported from a source states none at all — it is
searchable and joined to nothing. `--infer-entities SPEC_DIR` runs the deployment's own
`spec/extractors.yaml` over `--summary` and adds what it supports, as *related* references below
`1.0`. The two never become one thing: a read asking for stated references only (`--min-confidence
1.0`, and a bundle always) does not see the inferred ones, and where the caller stated an entity the
prose also names, the stated reference is the one that is recorded.

Opt-in, and a flag rather than an environment variable, because an inferred reference is a join key
with a guess behind it: the decision belongs to the call that knows what its prose is, and an
exported variable would make it for every record on the host. The bar the rules are held to is
precision rather than recall — a reference inferred wrongly is a wrong answer to every question that
touches it, silently — and the number is measured against a labelled corpus in CI.

```bash
yaam-emit --action note --outcome success \
          --summary "closing ticket PROJ-42 after the api rollout" \
          --infer-entities /srv/memory/spec   # ticket:PROJ-42, related, 0.7
```

The directory it names is a spec directory, holding `entities.yaml` and `extractors.yaml`. It is not
a store root by another name: those two files are configuration a deployment distributes to its
caller hosts, the emitter reads them and nothing else, and there is no code in it that could open a
memory tree.

`--redaction-policy` defaults to `default-v1` and must name the policy the deployment *applies* — the
`policy:` field of its `spec/redaction/*.yaml`. The service refuses any other, because a record
declaring a policy that was never run gives a false account of its own redaction; the emitter turns
that refusal into the flag to change rather than a status code.

Subjects stay empty and the data class stays `internal`, and no flag on this binary changes either.
A subject named here could only be invented — the secret a pseudonym is derived under lives with the
service — and a data-class flag on the binary every agent runs would be an invitation to decide by
judgement the one field that must be decided by rule. Filing a record the store will seal is
`yaam-file`'s, below.

### Filing a record about a transaction

`yaam-file` is `yaam-emit` with one thing changed: it classifies the record `subject_derived`, so the
store seals the body under a key that can be destroyed. Same arguments, same protocol, same exit
codes, plus one that is required:

```bash
yaam-file --erasure-unit order_ref:ord10014733 \
          --action refund --outcome success --summary "…"
```

**A record is subject-derived if and only if it names the transaction it is about.** That is the
whole rule, and it is one argument rather than two on purpose: there is no way to invoke this binary
and leave a body in the clear, and no way to claim a record erasable without stating the reference
that makes it so. The reference is recorded as an ordinary stated entity at confidence `1.0`, which
is what the service's resolver requires — a reference lifted from prose is a guess, and a guess may
not decide whether a body is sealed.

`subjects` stays empty here too. This binary holds no keying secret and cannot derive a pseudonym;
the service does that, from this reference, under the entity kinds the store's own
`spec/subjects.yaml` declares as erasure units. A kind it does not declare is a refused record, not a
plaintext one.

A separate binary rather than a flag, because `data_class` decides whether a body is sealed and a
subject linkage becomes permanent, and the store has no re-key, no re-seal and no delete. Installing
it is a decision an operator makes about a host; a flag would be one a caller makes about a record.
Two grants stand behind it, and neither is on its command line:

| where | what it says |
|---|---|
| the sidecar's `upstream.json`, `files_subject_derived: [agent]` | which callers may send the class on their own socket. An unlisted caller is refused there, before anything is masked, sealed or spooled — whether the record came from this binary or from a line of JSON somebody wrote by hand |
| the service's keyring, `"files_subject_derived": true` per caller | which credentials may send it at all. `403`, and nothing is written. This is the one that binds: a sidecar's configuration is edited by whoever runs the caller, and the keyring is not |

Both default to nobody, and stay that way for a configuration written before they existed. A store
that declares no erasure units refuses the class regardless, so the two halves — the writer and the
resolver — can be turned on in either order without a record being written wrong.

### Reading it back

`yaam-read` sends one request to a caller's *read* socket and prints the service's JSON on stdout,
byte for byte. It exists for the same reason the emitter does — the alternative was a signed request
assembled by hand — and it holds no key for a stronger one: the read socket signs on the caller's
behalf, so a reader that signed for itself would be holding exactly what the sidecar exists to keep
away from it. There is no `--root`, no key flag and no `--agent`: the socket is the evidence of who is
asking.

| Read | Command | Answers |
|---|---|---|
| filtered query | `yaam-read records [--action --outcome --agent --attr --from-ms --to-ms --limit]` | `RecordsResponse` |
| entity history | `yaam-read history --entity kind:id [--min-confidence --limit]` | `RecordsResponse` |
| full text | `yaam-read search --query TEXT [--limit]` | `RecordsResponse` |
| correlation | `yaam-read correlate --within-ms MS --left-from-ms MS --left-to-ms MS [--left-action --left-outcome --left-agent --left-attr --right-action --right-outcome --right-agent --right-attr --limit]` | `CorrelationsResponse` |
| traversal | `yaam-read linked --entity kind:id --depth N --from-ms MS --to-ms MS [--min-confidence --max-degree --limit]` | `LinksResponse` |
| context | `yaam-read bundle [--entity kind:id …] [--actor --infer-entities --infer-from --deadline-ms --limit]` | `BundleResponse` |

Six subcommands rather than one flat set of flags, because they are six questions and not six
filters on one: `--query` is required for a search and meaningless to a bundle, a window narrows the
filtered query and is *required* by a correlation and a traversal, and the service answers a parameter
it does not know with `400` rather than ignoring it. Flattened together, `--help` would describe a
request surface that does not exist.

Nothing the caller did not name is sent. Every optional parameter has a documented default at the
service, and a copy of one here would be a second place for it to be out of date.

The three exit codes a script branches on are `0`, `8` and `9`, and the first is the one that matters:
**a read that matched nothing exits `0`**. It is an answer — `200` with an empty page — and folding it
into a failure would make every quiet day look like an outage. `8` says the request will never be
answered as asked; `9` says nothing was read, which includes the service being unreachable from the
sidecar, since a read is never queued.

Percent-encoding is the command's business rather than the caller's, which matters more than it looks:
several configured entity kinds carry `/`, `#` or `@` inside an identifier, and the signature the
sidecar adds covers the request target exactly as sent.

#### Two things happening near each other

`yaam-read correlate` is the one read whose answer is not a list of records. It joins two shapes on
the server-stamped clock and answers with **pairs** — a `left` record, and a `right` record that
followed it inside `--within-ms` — because which record happened near which is the question, and a
flat list of both sides is what `yaam-read records` already gives you.

```bash
# Which gateway declines had a deploy in the three hours after them, over one day.
yaam-read correlate --left-action transact --left-outcome declined \
          --right-action deploy --within-ms 10800000 \
          --left-from-ms 1787184000000 --left-to-ms 1787270400000
```

It replaces two workarounds, and both were worse than they looked. Reading the declines and the
deploys separately and intersecting them by hand leaves the caller doing arithmetic over two pages
that were capped independently. Reading one entity's history inside a window is nearer, but it answers
*what touched this ticket* and leaves which of those records happened near which to whoever read it —
and it can only join records that already share an entity, where a correlation joins on time. Reach
for `history` when the question is about a thing, for `correlate` when it is about two events being
near each other, and for `linked` — below — when it is about what a thing is connected *to*.

**It is directional, and that is the flag people get backwards.** A pair comes back when the `right`
record was stamped at or after the `left` one. So *"what was deployed just before this decline"* puts
the **deploy** on the left — there is no backwards window, and `--within-ms` below zero is refused
rather than answered with the empty page it would produce, because an empty page reads as "nothing
happened nearby".

**`--left-from-ms` and `--left-to-ms` are required**, which no other read here demands. Two reasons,
and the second is the one that decides it. A correlation with no window answers "the most recent pairs
in the store", which moves as records arrive — and a query whose meaning depends on when it ran cannot
be tested. And this is a non-equi range join whose cost is (rows on the left) × (rows the right index
walks per left row); the left window is the only thing a request can say that bounds the first term.
The covering index keeps it cheap today — 1.6 ms for a thousand pairs over 200,000 records, windowed
or not — but the same statement measured 4.2 s unwindowed before that index existed, and the window is
what keeps a planner's change of mind from being an outage. There is deliberately no window on the
right: the right side's window *is* the left side's plus `--within-ms`.

`--limit` caps **pairs**, and the service's own cap is half its cap on the other reads, because a pair
row is two records' frontmatter. A left record matching several right records comes back once per
pair, repeated — narrow `--within-ms` rather than raising the limit.

#### What else is connected to this

`yaam-read linked` is the only read here whose answer is a graph. Every other read takes entities you
can already name and answers with records; this one takes **one** entity and answers with **edges** —
two entities, and the record naming both.

```bash
# Two hops out from an order reference. Hop one is the ticket the decline names; hop two is the
# deploys that ticket carries, which the order reference itself never mentioned.
yaam-read linked --entity order_ref:ord10014733 --depth 2 \
          --from-ms 1787184000000 --to-ms 1787270400000
```

**A link is a record.** Two entities are linked because one record references both. There is no edge
table and there is not going to be one: an edge with no record behind it is a claim this system could
not rebuild from its own Markdown tree, which is the property `yaam reindex` rests on. Each edge
carries the record that made it, as structure, so *why* two things are connected needs no second read
— and a second read is where a scope predicate gets forgotten, which at a graph's worth of edges is a
great many chances to forget it. The predicate is on the mediating record of **every** hop, inside the
recursive query.

**Never traverse through a hub.** An entity is *reached* however busy it is; above `--max-degree`
references inside the window it is not walked *through*. Without that rule, the second hop of any
question passing near a shared identifier answers "everything that identifier ever touched" — correct
and useless. The entities the rule refused come back under `hubs` with the degree that refused them,
because "nothing else is connected" and "everything is, through this one node" are the same short
answer otherwise and call for opposite next moves. The cap may be **lowered and not raised**: raising
it would be a request buying back the problem the rule exists to prevent.

Degree is counted inside the request's own window and no further than one past the cap. An identifier
that carried the world last month and three records during the hour under investigation is exactly the
corridor that hour needs, and a lifetime count would refuse it. The **seed** is not capped: you named
it, so asking about a busy identifier directly is what `history` is for, and the rule governs passing
*through* a node nobody asked for.

**Inferred references may end a path and may not extend one.** `--min-confidence` defaults to full
confidence, which is a bundle's bar rather than an entity read's — a traversal *invents* the far end,
and an inferred link presented as a discovery is indistinguishable from a fact. Lower it and inferred
references become edges; they still never become corridors, because hop two would otherwise quietly
launder what hop one was only willing to show with a confidence attached.

`--depth` and the window are both required, and depth is **1 to 2**. `0` is what `history` already
answers. `3` is refused, and the refusal gives the reason below rather than a range — an answer
decided by its own bound is not a fact about the store.

**The frontier is the sharp edge, and it is why the depth stops at two.** The recursion stops at 200
edges whatever `--limit` says, and it fills breadth-first — so the cap is spent on near hops before
far ones. Measured over 200,000 records, three hops from the busiest identifier over 30 days comes
back as 115 hop-1 edges, 85 hop-2 edges and *no hop-3 edges at all*; unbounded it would have been
347, and over the whole two years 35,845. A request for three hops answered entirely out of the first
two is a defect in the shape of the answer, and nothing in the answer admits to it — so the third hop
is refused instead. **A limit that refuses is better than one that substitutes a different answer.**
The fix is a per-hop budget, which is not expressible as a `LIMIT` on the compound select this read
is; when one is written the cap moves, and until then this measurement is why it sits where it does.

The measurement stays here rather than leaving with the third hop, because it also describes the
second: over a busy enough seed, two hops is a page of hop-1 edges and a few hop-2 ones, which is a
ceiling on recall and not a claim that nothing further is connected. A deep question over a busy seed
should narrow its window rather than raise its page. Over a quiet seed the whole neighbourhood fits
and none of this bites: two hops from a long-tail identifier across two years is 17 edges in 0.7 ms.

#### Naming the entities a caller does not know it has

A bundle composes context out of entities and an actor, which assumes the caller can name them. A
caller holding a *sentence* — the message it is about to answer — can name neither, so it asks about
the actor alone and gets whatever that actor happened to write. Where nothing was ever written under
that name, the answer is empty every time and nothing about it looks broken.

`--infer-entities SPEC_DIR` with `--infer-from TEXT` is the way out: the same extractor `yaam-emit`
runs over a record's prose, run here over the request's prose, and what comes out are lookup keys.
Either flag alone is refused — text with no rules cannot be read and rules with no text have nothing
to read, and either would compose a narrower bundle than was asked for while answering `200`.

**The precision calculus inverts between the two ends, and the floor does not move.** At write time
an inferred reference *becomes* a stored join key, which is why the rules are held below `0.9` and
why a bundle joins only on references a record states at `1.0`: a guess in a bundle is a guess the
caller cannot tell apart from a fact. At read time an inferred entity is only a lookup key. It
matches records that reference it at full confidence, or it matches nothing — so a wrong guess costs
one wasted lookup rather than a permanent falsehood, and this may infer freely where the writer may
not. A record whose only reference was inferred stays out of every bundle, exactly as before.

```bash
yaam-read bundle --infer-entities /srv/memory/spec \
          --infer-from "picking the PROJ-42 rollout back up" --limit 5
```

### Reading a sealed body

A sealed body has one way back and it is not a request. `yaam-read` and the service never unseal, so
customer plaintext cannot reach an agent's context, a chat message or a log line — all places outside
the reach of a key destruction. What is left is one operator command on the host that holds the key
store:

```sh
yaam --root /srv/memory unseal --record 01ARZ… --operator lead_ops \
     --reason "subject access request"                       # whose keys it would use, then stops
yaam --root /srv/memory unseal --record 01ARZ… --operator lead_ops \
     --reason "subject access request" --confirm-read-body   # …and means it
```

**The audit record is written before the key is fetched, and that ordering is the feature.** One
record per reading, `action: unseal` and `visibility: operator`, naming the operator and the reason —
published, fsynced and indexed before anything is decrypted. So a store that cannot record the read
cannot answer it, and the two failure shapes are a recorded read that then failed and nothing at all.
The other order — decrypt, hand back, then record — turns the first unwritable tree into a body
somebody holds and nothing anywhere says was read, which no later pass can discover. Written
afterwards, an audit trail is a courtesy; written first, it is a precondition.

The audit record is `internal` and names no subject, so no erasure reaches it: a trail a data subject
could destroy is a trail that disappears exactly when somebody asks who read their data before it
went. It names the subject pseudonyms in its prose, deliberately, for the same reason the tombstone
log keeps them.

`--confirm-read-body` is `erase`'s register, because the two are irreversible in the same way: an
erasure cannot be undone, and a reading cannot be unread. Without it the command prints whose keys
the read would use, whether they are still there, and whose name the record will carry — then exits
`5` having written nothing.

**A body whose keys are gone says so.** An erased subject's record is refused with the tombstone that
accounts for it and a sentence saying no copy anywhere will open again — never with an empty answer
that reads like a record nobody wrote, which is the report that has an operator opening an incident
about a store doing exactly what it promised. Every non-answer exits `8`: gone for ever, never sealed,
archived out of the tree, or an identifier nothing carries — each with the prose that says which,
because the next move differs and an empty page would not.

### Deriving knowledge

Memory is what happened; knowledge is what is true. The second is a tree of its own under
`knowledge/`, one note per entity, and every line of a note is a restatement of a structured field
some record declared, carrying the identifiers of the records it was read out of. It is derived and
disposable in the way the index is: delete it and build it again.

| Command | What it does |
|---|---|
| `yaam knowledge build` | Rebuilds every note from the record tree and the cold manifests. |
| `yaam knowledge status` | What the last build read, and when. |
| `yaam knowledge note --entity kind:id` | One entity's note. |
| `yaam knowledge search --query TERM [--limit]` | Which notes carry a term. |
| `yaam knowledge evidence --record ID …` | The frontmatter behind a fact. |

Two things about it are load-bearing, and both are properties of the input rather than rules the code
remembers. **Nothing here reads a body:** derivation is handed a record's frontmatter, which has no
field for prose, so it holds for a sealed record and a plaintext one without a second branch.
**Nothing derives from a record a key protects:** a note is an aggregate, and an aggregate cannot be
un-aggregated from a backup — subtracting one record's contribution reaches the live copy and not
last night's — so a record whose body is erasable contributes nothing at all, and there is no
knowledge a key destruction would have to chase. A build reports how much it excluded on those
grounds, and a store holding subject-derived records that excluded none of them is a store whose gate
has stopped working.

There is no incremental build, for the same reason: a note's counts and bounds are aggregates, so
each build is a statement about the tree *as it now stands*, and a record that has left the tree is
gone from knowledge without anything having to chase it either. The next tree is assembled beside the
live one and swapped in by a rename, so a reader sees one tree or the other and never a mixture.

These are the only commands that name a store and open nothing — no index, no key store, no fan-out
queue. A build reads the Markdown tree, which is why it is still available on a store whose index is
the thing that is broken.

```bash
yaam --root /srv/memory knowledge build
yaam --root /srv/memory knowledge search --query staging
yaam --root /srv/memory knowledge note --entity ticket:PROJ-42
```

`status` exits `4` when there is nothing to report, which is a state and not a missing answer: the
state file is removed before a build swaps its tree into place and written after, so its absence says
the tree is mid-build or has never been built. `build` exits `4` for a source that would not parse or
a stamp that would not, and `0` for the exclusions above — a monitor should not be paged over a
boundary that is working.

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
every read say which is the case, and they read it off the key files rather than off the flags: the
answer is a property of the store, so a passphrase the reader did not pass cannot change it.

Three answers, not two, because "no wrapping" and "no key material" are different states:

| on disk | reported as |
| --- | --- |
| every key file carries the marker | the scheme its header names |
| key files exist, none carries the marker | `none`, with the count, and development-only |
| no key files yet | nothing to report — neither claim is true |

The third is the common case for a new store, and calling it unwrapped was a false statement about
files that did not exist. A store holding *both* is what fitting a wrapper to a store that already
had keys leaves behind: `yaam check` reports it as degraded, because no wrapper reads all of it.

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

## Keying erasure on a reference

Nothing in a store is sealed until it declares what an erasure unit *is*. `spec/subjects.yaml` names
the entity kinds whose reference is one, most preferred first:

```yaml
version: 1
kinds:
  - order_ref
```

The pseudonym is then `HMAC-SHA256(subject_key, "subject-pseudo:1" ‖ canon_ver ‖ "order_ref:<id>")`,
rendered as `s_` and 64 hex digits, over the canonical id `entities.yaml` already rewrote on the way
in. The secret comes from `--subject-key-file` — 32 bytes of hex, a file rather than a value for the
reason `--key-passphrase-file` is one — and it stays with the service: a caller holding it would be a
caller able to de-pseudonymise every backup, and callers here are meant to hold no key material.

**Where the secret comes from is a seam, not a file path.** That key can never be rotated — every
pseudonym ever derived is a function of it — so a deployment that moves it into a keychain or a key
service has to be able to do so without changing how a live store fetches it.
`yaam_crypto::custody::SubjectKeySource` is that protocol and `SubjectKeyFile` is the only
implementation that ships: the key is fetched once, at startup, and a source that cannot answer
refuses the process rather than minting or defaulting one.

**The store records which key it was armed with.** Nothing about a wrong subject key is visible: the
derivation is a pure function, so a substituted key file comes up clean, seals bodies, and files a
second pseudonym for a reference already on record — no drift, no warning, and no repair, because
there is no re-key, no re-seal and no delete. So a store keeps `subject-key-check.json` under its
root: `HMAC-SHA256(subject_key, "subject-keychk:1")`, which says *which* key without saying what it
is. A key that does not derive the recorded value is a refusal at startup naming the file and both
values; a record that cannot be *read* is a separate refusal, because "cannot tell" and "does not
match" are not the same finding and not repaired the same way — one is a setting, the other a file.
The value travels in a backup, as the pseudonyms it accounts for do, and it is not a secret, which is
what lets it: a restore is where a key is most likely to be re-entered by hand.

**"Armed" is the first open, because nothing else arms a store.** There is no arming command — a
declaration in the tree and a key handed to a process are what arm one, and both are read afresh at
every open. So the first open that finds no record writes one, and says in the log that the key was
*trusted* rather than verified; every open after it is checked. That is trust on first use, and the
limit is stated rather than implied: a store armed before this existed adopts whichever key its next
open presents, and a check value replaced together with a key agrees with it. This catches a mistyped
or substituted key. It does not catch somebody who can write to the tree, and it says nothing about
whether the records already on file were written under the key it just recorded.

**Both halves or neither.** A declaration with no secret refuses at startup rather than refusing
records one at a time; a secret with no declaration refuses too, because the alternative is an
operator who believes bodies are sealed while every one is written in the clear — into the tree, the
cold manifests and every backup, where nothing later can reach them. Neither half is the shipped
state and changes nothing: no subject resolves, and no key is ever minted.

**The erasure unit is the transaction, not the person.** Nothing on the write path claims to know
whose transaction it is, so nothing on the write path can be wrong about that — which matters because
this store cannot correct a subject set: re-presenting a published record is a duplicate, there is no
re-key, and there is no delete. A body sealed to the wrong pseudonym would be erasable by the wrong
person's request and unreachable by the right one's, and verification would report the erasure
complete either way. So a person is resolved to references *outside* the store, at erasure time,
where a miss is recoverable: enumerate again and destroy what was missed, because the keys are still
there to destroy. That fan-out — person to references, and a reference to its pseudonym under every
live canonicalisation version — is the operator's, because `erase` takes one hash.

**What it refuses rather than guess.** A record whose class says subject-derived and which states no
reference of a declared kind is rejected, and so is one that states two references of the same kind:
two of equal standing have no rule to choose between them, sealing to both would make each
transaction's erasure destroy the other's body, and picking one would be a coin toss recorded as a
fact. Only references a caller *stated* count — one inferred from prose is a guess, and a guess may
not decide whether a body becomes permanently unerasable. A refused record is one that was never
written, which is the only failure here that can still be fixed.

**One record, one subject, one body, one erasure.** The rule above is the shipped resolver's; the
rule beneath it is the contract's, and binds every writer. A body is sealed under a key derived from
every share it has, so a record naming two subjects would be one body either of them could end for
the other — and the survivor would keep a right of access to what it said about them that nothing
here can answer, there being no re-key, no re-seal and no delete. So the record is refused rather
than written, wherever it is read and again once a deployment's resolver has answered.

Refused rather than split, and the reason is that a write carries one body. Copying it into a body
per subject would leave everything the record said about the erased subject readable in the
surviving copy — the erasure defeated rather than narrowed, permanently. Dividing the prose instead
would put a reading of it in the erasability path, which is the one decision no judgement may make.
An event about two subjects is therefore two records, related by `correlation_id` and by the entity
references both carry. That relation is plaintext frontmatter and an erasure takes bodies and keys,
not structure, so it survives either erasure: after one subject's half is unreadable a reader can
still tell the two records were one event. `correlate` and `linked` need nothing new for this — they
join on shape, time and entity references and never read a body — and erasure verification means
what it says for the first time: it asserts the absence of the keys it was asked about, which with
one subject per body is the same statement as "that subject's bodies are gone".

Changing the canonicalisation is a version, never an edit: the version number is an input to the
HMAC, so a bump makes every subject hash differently and uniformly, and the old rules stay registered
because records filed under them keep a hash only those rules reproduce.

## Deployment seams

Three traits a deployment implements, each with a shipped implementation that behaves exactly as not
using it did.

| | |
|---|---|
| `yaam_crypto::custody::SubjectKeySource` | Where the subject-pseudonym secret is fetched from at startup. `SubjectKeyFile` is what `--subject-key-file` does; a keychain or key-service source replaces the fetch and nothing else. A fetch may block and may fail transiently, and either way the answer is the key or a refusal to start — never a key this store did not already derive its pseudonyms with. |
| `yaam_crypto::keystore::KeyWrapper` | Wraps subject keys before they reach the disk, so a key file recovered from a snapshot or a stale volume is inert without a call to external key custody. `FsKeyStore::unwrapped` is the development default, named so nobody gets it by accident. |
| `yaam_core::resolve::SubjectResolver` | Decides the subjects a record names. `DeclaredSubjects` trusts the ones it carries; a lookup that is briefly down quarantines the record for a later retry rather than rejecting it, and one that will never key a given record rejects it with the reason. `ReferenceSubjects` is the implementation this repo ships — see above — and it is fitted only by a store that declares erasure units. |

## Crash tests

Every durability window has a test that kills a real service inside it with `SIGKILL` and asserts
what a *restarted* one makes of the state left behind: the staged write that never got renamed, the
committed record whose fan-out never drained, the timeline rollover that froze the head and never
made a new one. The windows are opened by a checkpoint that only exists in a build with the
`crash-points` feature, and that arms itself only when `YAAM_CRASH_AT` names it — so a release
contains no such code at all, and a build that does still does nothing until asked.

They wait on the service's own maintenance timer, so they take minutes and are kept out of a routine
test run. The feature is what puts the checkpoints into the binaries the test spawns, and the test
target requires it, so the flag is not optional:

```sh
cargo test -p yaam-cli --features crash-points --test crash_injection -- --ignored
```

`ci/check.sh` and CI both run them.

## Status

Early. See `AGENTS.md` for the invariants any contribution must hold.

## License

MIT — see [LICENSE](LICENSE).
