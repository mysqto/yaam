//! The synthetic store the measurements run against.
//!
//! Two properties matter more than volume. **Skew**: most entities carry a handful of records and a
//! few carry thousands, a few actors produce most of the traffic, and outcomes are overwhelmingly
//! successes — a benchmark over uniform data measures a workload nobody has. **Determinism**: every
//! draw comes from a seeded generator, so two runs on the same machine compare, and a figure that
//! moved moved because the code did. Record identifiers are minted fresh each run, as real ones are;
//! nothing a measurement selects on is derived from them.
//!
//! Records are written straight into the tree and the index is then built by
//! [`yaam_core::reindex::reindex_all`]. That is not a shortcut around the write path: the tree is
//! authoritative and the index is derived from it, so a tree plus a rebuild is exactly the state a
//! restored backup is in. It also makes generation cheap enough that the 200k of it is not itself
//! the experiment — and [`sample_through_write_path`] keeps the shortcut honest by pushing a sample
//! of the same records through `Pipeline::accept`.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use yaam_contract::{
    ActionRecord, DataClass, Outcome, RecordId, SchemaVer, Visibility, attrs,
    entity::{self, EntityRef},
};
use yaam_md::{Body, Document};

/// The instant the two-year window ends. Fixed rather than read from the clock: "last 7 days" has
/// to mean the same span on every run or the figures are not comparable.
pub const ANCHOR: &str = "2026-08-21T00:00:00Z";

/// Length of the generated history.
pub const SPAN_DAYS: i64 = 730;

/// Milliseconds in a day.
pub const DAY_MS: i64 = 86_400_000;

/// The redaction policy every generated record declares.
const POLICY: &str = "default-v1";

/// Actions, with the share of traffic each carries.
///
/// Deliberately lopsided: one high-volume read action dominates, and the action the failure queries
/// ask about is a minority of the traffic — which is what makes an index selective.
const ACTIONS: &[(&str, u32)] = &[
    ("lookup", 34),
    ("chat_message", 24),
    ("ticket_update", 18),
    ("deploy", 12),
    ("order_sync", 9),
    ("reindex_run", 3),
];

/// Outcomes, with their share. Failures are rare, which is why finding them is an index question.
const OUTCOMES: &[(Outcome, u32)] = &[
    (Outcome::Success, 88),
    (Outcome::Failure, 7),
    (Outcome::Partial, 4),
    (Outcome::Declined, 1),
];

/// Actors. The first three carry roughly half the traffic between them.
const AGENTS: &[&str] = &[
    "agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g", "agent_h",
    "agent_i", "agent_j", "agent_k", "agent_l",
];

/// Teams a team-visible record may name.
const TEAMS: &[&str] = &["platform", "delivery", "insight", "support"];

/// Service names used as an attribute value and inside `deploy` entity identifiers.
const SERVICES: &[&str] = &[
    "api",
    "worker",
    "gateway",
    "indexer",
    "scheduler",
    "notifier",
    "archiver",
    "resolver",
];

/// Environments. Three values, so the attribute filter in measurement 3 removes about two thirds.
const ENVIRONMENTS: &[&str] = &["prod", "staging", "dev"];

/// Severity values, for the records that carry one.
const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

/// Distinct `order_ref` identifiers in the long tail.
const COLD_ORDERS: u64 = 40_000;

/// Distinct `ticket` identifiers in the long tail.
const COLD_TICKETS: u64 = 12_000;

/// Distinct `deploy` identifiers in the long tail.
const COLD_DEPLOYS: u64 = 6_000;

/// Entities that appear on a large share of records, per kind.
///
/// Eight, ten percent of the time, is what produces "a few with thousands": at 200k records that is
/// around 2,500 records each against a handful for a tail identifier.
const HOT_PER_KIND: u64 = 8;

/// How often a reference names a hot entity rather than one from the tail.
const HOT_SHARE: u32 = 10;

/// Words the prose is drawn from. Neutral operational vocabulary, and no pattern the configured
/// redaction policy would match — a body that had to be masked is a write-path concern, not a
/// read-path one.
const WORDS: &[&str] = &[
    "queue",
    "shard",
    "replica",
    "retry",
    "cache",
    "handler",
    "worker",
    "batch",
    "manifest",
    "checkpoint",
    "timeout",
    "backoff",
    "throughput",
    "quorum",
    "leader",
    "snapshot",
    "digest",
    "partition",
    "migration",
    "endpoint",
    "payload",
    "chunk",
    "segment",
    "cursor",
    "threshold",
    "budget",
    "window",
    "drain",
    "spool",
    "lease",
];

/// The phrase measurement 6 searches for, planted in a small share of bodies.
pub const PHRASE: &str = "rolling restart";

/// How often a body carries [`PHRASE`], as one in this many.
const PHRASE_ONE_IN: u32 = 50;

/// Entity kinds this deployment configures. The same neutral vocabulary the crate's own fixtures
/// use, so a generated identifier is one the write path would canonicalise unchanged.
const SPEC_ENTITIES: &str = concat!(
    "version: 1\n",
    "kinds:\n",
    "  ticket:\n",
    "    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n",
    "    normalise: [trim, uppercase_prefix]\n",
    "  deploy:\n",
    "    pattern: '^[a-z0-9._-]+/[a-z0-9._-]+#[0-9]+$'\n",
    "    normalise: [trim, lowercase]\n",
    "  order_ref:\n",
    "    pattern: '^[a-z0-9]{8,24}$'\n",
    "    normalise: [trim, lowercase]\n",
);

/// The attribute surface this deployment declares, one entry per action in [`ACTIONS`].
const SPEC_ATTRS: &str = concat!(
    "version: 1\n",
    "actions:\n",
    "  deploy:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      service: { type: string, class: structural }\n",
    "      environment: { type: string, class: structural }\n",
    "      duration_ms: { type: integer, class: structural }\n",
    "  lookup:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      target_kind: { type: string, class: structural }\n",
    "      duration_ms: { type: integer, class: structural }\n",
    "  ticket_update:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      severity: { type: string, class: structural }\n",
    "      service: { type: string, class: structural }\n",
    "  chat_message:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      service: { type: string, class: structural }\n",
    "  order_sync:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      service: { type: string, class: structural }\n",
    "      duration_ms: { type: integer, class: structural }\n",
    "  reindex_run:\n",
    "    outcome: [success, failure, partial, declined]\n",
    "    attrs:\n",
    "      service: { type: string, class: structural }\n",
    "      duration_ms: { type: integer, class: structural }\n",
);

/// The redaction policy this deployment applies.
const SPEC_REDACTION: &str = concat!(
    "version: 1\n",
    "policy: default-v1\n",
    "patterns:\n",
    "  - name: bearer_token\n",
    "    regex: '(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]{16,}'\n",
    "    action: mask\n",
    "  - name: email\n",
    "    regex: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b'\n",
    "    action: mask\n",
);

/// `SplitMix64`. A generator rather than a dependency: the benchmark needs draws that repeat, not
/// draws that are unguessable, and a dozen lines here beats a crate the shipped code does not use.
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator.
    ///
    /// The same seed gives the same draws, so every distribution below repeats run to run. Record
    /// identifiers are the one exception — they are minted fresh, as real ones are — and nothing the
    /// measurements select on depends on them.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next raw draw.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A draw below `bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    /// Picks from a list of `(value, share)` pairs.
    fn weighted<T: Copy>(&mut self, table: &[(T, u32)]) -> T {
        let total: u32 = table.iter().map(|(_, share)| share).sum();
        let mut point = u32::try_from(self.below(u64::from(total))).unwrap_or(0);
        for (value, share) in table {
            if point < *share {
                return *value;
            }
            point -= share;
        }
        table[0].0
    }

    /// Picks one element of a slice.
    fn one<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let bound = u64::try_from(items.len()).unwrap_or(1);
        &items[usize::try_from(self.below(bound)).unwrap_or(0)]
    }
}

/// Writes the configuration a pipeline over `root` will read.
pub fn write_spec(root: &Path) -> std::io::Result<()> {
    let spec = root.join("spec");
    fs::create_dir_all(spec.join("redaction"))?;
    fs::write(spec.join("entities.yaml"), SPEC_ENTITIES)?;
    fs::write(spec.join("attrs-schema.yaml"), SPEC_ATTRS)?;
    fs::write(spec.join("redaction/default.yaml"), SPEC_REDACTION)?;
    Ok(())
}

/// Renders `ms` since the Unix epoch as the `RFC3339` form the contract and `SQLite` agree on.
#[must_use]
pub fn rfc3339(ms: i64) -> String {
    let (year, month, day) = yaam_contract::timestamp::civil_from_ms(ms);
    let within_day = ms.rem_euclid(DAY_MS);
    let (hour, minute, second, milli) = (
        within_day / 3_600_000,
        within_day / 60_000 % 60,
        within_day / 1_000 % 60,
        within_day % 1_000,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z")
}

/// One generated record and the file it belongs in, relative to the memory root.
pub struct Generated {
    /// The record.
    pub record: ActionRecord,
    /// Its prose body.
    pub body: String,
    /// Where in the tree it goes.
    pub path: PathBuf,
}

/// Generates one record, `index` records into the run.
///
/// The index seeds the generator, so record *n* is the same record whatever else was generated
/// before it — which is what lets the first half of a run stand alone as a smaller store.
#[must_use]
pub fn generate(index: u64, anchor_ms: i64) -> Generated {
    let mut rng = Rng::new(0x5EED_0000_0000_0000 ^ index);

    // Biased towards the recent end: a store that has been growing is the normal case, and a
    // uniform two years would make every windowed query artificially cheap. The larger of two
    // draws gives a linear ramp — twice as dense at the recent end — in integer arithmetic, so the
    // generated instant is exactly reproducible rather than reproducible to within a rounding.
    let span_ms = u64::try_from(SPAN_DAYS * DAY_MS).unwrap_or(0);
    let offset = rng.below(span_ms).max(rng.below(span_ms));
    let received_ms = anchor_ms - SPAN_DAYS * DAY_MS + i64::try_from(offset).unwrap_or(0);
    // The source clock differs from the server's by a little, as a real one does.
    let at_ms = received_ms - i64::try_from(rng.below(4_000)).unwrap_or(0);

    let action = rng.weighted(ACTIONS);
    let outcome = rng.weighted(OUTCOMES);
    let agent = agent(&mut rng);
    let (visibility, team) = read_scope(&mut rng);
    let body = body(&mut rng);

    let record = ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: rfc3339(at_ms),
        received_at: rfc3339(received_ms),
        backfilled: false,
        agent: agent.to_owned(),
        agent_ver: Some("1.4.2".to_owned()),
        correlation_id: (rng.below(10) < 6)
            .then(|| format!("corr-{:08x}", rng.next() & 0xFFFF_FFFF)),
        action: action.to_owned(),
        outcome,
        attrs: attributes(&mut rng, action),
        entities: entities(&mut rng, action),
        subjects: Vec::new(),
        visibility,
        team,
        data_class: DataClass::Internal,
        redaction_policy: POLICY.to_owned(),
        fields_masked: Vec::new(),
        tags: vec![(*rng.one(SERVICES)).to_owned()],
        // What the write path would set: the body is the record's prose.
        summary: body.clone(),
    };

    let path = record_path(&record, received_ms);
    Generated { record, body, path }
}

/// Picks an actor: three heavy producers, nine light ones.
fn agent(rng: &mut Rng) -> &'static str {
    let heavy = 3usize;
    if rng.below(100) < 54 {
        AGENTS[usize::try_from(rng.below(3)).unwrap_or(0)]
    } else {
        let tail = u64::try_from(AGENTS.len() - heavy).unwrap_or(1);
        AGENTS[heavy + usize::try_from(rng.below(tail)).unwrap_or(0)]
    }
}

/// Picks a visibility, and the team a team-visible record names.
fn read_scope(rng: &mut Rng) -> (Visibility, Option<String>) {
    match rng.below(100) {
        0..=84 => (Visibility::Org, None),
        85..=94 => (Visibility::Team, Some((*rng.one(TEAMS)).to_owned())),
        _ => (Visibility::Owner, None),
    }
}

/// The attributes one action declares.
fn attributes(rng: &mut Rng, action: &str) -> BTreeMap<String, attrs::Value> {
    let mut attributes = BTreeMap::new();
    let mut text = |key: &str, value: &str| {
        attributes.insert(key.to_owned(), attrs::Value::Text(value.to_owned()));
    };
    match action {
        "deploy" => {
            text("service", rng.one(SERVICES));
            text("environment", rng.one(ENVIRONMENTS));
        }
        "lookup" => text("target_kind", rng.one(&["order_ref", "ticket", "deploy"])),
        "ticket_update" => {
            text("severity", rng.one(SEVERITIES));
            text("service", rng.one(SERVICES));
        }
        _ => text("service", rng.one(SERVICES)),
    }
    if action != "ticket_update" && action != "chat_message" {
        attributes.insert(
            "duration_ms".to_owned(),
            attrs::Value::Int(i64::try_from(rng.below(30_000)).unwrap_or(0)),
        );
    }
    attributes
}

/// One to three entity references, skewed so a few identifiers carry a large share of the records.
fn entities(rng: &mut Rng, action: &str) -> Vec<EntityRef> {
    let mut refs = vec![primary(rng, action)];
    for _ in 0..rng.below(3) {
        // Related references are often inferred rather than read out of a field, and a bundle asks
        // only for the ones that were: the low-confidence rows exist to be filtered out.
        let confidence = if rng.below(10) < 3 { 0.6 } else { 1.0 };
        let borrowed = *rng.one(&["deploy", "ticket_update", "order_sync"]);
        let mut related = primary(rng, borrowed);
        related.role = entity::Role::Related;
        related.confidence = confidence;
        if !refs
            .iter()
            .any(|existing: &EntityRef| existing.kind == related.kind && existing.id == related.id)
        {
            refs.push(related);
        }
    }
    refs
}

/// The reference an action's own kind of identifier produces.
fn primary(rng: &mut Rng, action: &str) -> EntityRef {
    let (kind, id) = match action {
        "deploy" | "reindex_run" => (
            "deploy",
            format!(
                "{}/{}#{}",
                rng.one(SERVICES),
                rng.one(ENVIRONMENTS),
                skewed(rng, COLD_DEPLOYS)
            ),
        ),
        "ticket_update" | "chat_message" => {
            ("ticket", format!("PROJ-{}", skewed(rng, COLD_TICKETS)))
        }
        _ => ("order_ref", format!("ord{:08}", skewed(rng, COLD_ORDERS))),
    };
    EntityRef {
        kind: kind.to_owned(),
        id,
        role: entity::Role::Primary,
        confidence: 1.0,
    }
}

/// An identifier number: usually from the long tail, sometimes from the hot handful.
///
/// The hot ones are numbered `0..HOT_PER_KIND` so they are also the ones a reader can name in a
/// query without having to be told which they are.
fn skewed(rng: &mut Rng, cold: u64) -> u64 {
    if rng.below(100) < u64::from(HOT_SHARE) {
        rng.below(HOT_PER_KIND)
    } else {
        HOT_PER_KIND + rng.below(cold)
    }
}

/// A body of operational prose, occasionally carrying the searched-for phrase.
fn body(rng: &mut Rng) -> String {
    let mut out = String::with_capacity(256);
    let words = 24 + rng.below(24);
    for position in 0..words {
        if position > 0 {
            out.push(' ');
        }
        out.push_str(rng.one(WORDS));
    }
    if rng.below(u64::from(PHRASE_ONE_IN)) == 0 {
        out.push_str(" — ");
        out.push_str(PHRASE);
        out.push_str(" completed");
    }
    out.push('.');
    out
}

/// Where a record's file goes, relative to the memory root.
///
/// The tree's own rule, restated because it is `pub(crate)` in `yaam-core`: dated directories, and
/// an owner-visible record under a subtree of its owner's own. A generator that put a record
/// somewhere else would still be indexed by a rebuild, so this has to be right rather than close.
fn record_path(record: &ActionRecord, received_ms: i64) -> PathBuf {
    let (year, month, day) = yaam_contract::timestamp::civil_from_ms(received_ms);
    let mut path = PathBuf::from("records");
    if record.visibility == Visibility::Owner {
        path = path.join("owner").join(&record.agent);
    }
    path.join(format!("{year:04}"))
        .join(format!("{month:02}"))
        .join(format!("{day:02}"))
        .join(format!("{}.md", record.record_id.as_str()))
}

/// Writes records `from..to` into the tree under `root`, and says how many bytes it wrote.
///
/// Directories are remembered rather than re-created: the timestamps arrive in no order, so a
/// `create_dir_all` per record would be one syscall per record for no gain.
pub fn write_tree(root: &Path, from: u64, to: u64, anchor_ms: i64) -> std::io::Result<u64> {
    let mut made: HashSet<PathBuf> = HashSet::new();
    let mut bytes = 0u64;
    for index in from..to {
        let generated = generate(index, anchor_ms);
        let path = root.join(&generated.path);
        let dir = path.parent().expect("a record path has a directory");
        if made.insert(dir.to_path_buf()) {
            fs::create_dir_all(dir)?;
        }
        let text = Document {
            record: generated.record,
            body: Body::Plain(generated.body),
        }
        .render();
        bytes += u64::try_from(text.len()).unwrap_or(0);
        fs::write(&path, text)?;
    }
    Ok(bytes)
}

/// Pushes `count` of the generated records through the real write path.
///
/// The generator writes files directly, which skips validation, the attribute schema, entity
/// canonicalisation and the redaction check. This is what says the shortcut did not quietly produce
/// records the service would refuse — the figures below would then describe a store that cannot
/// exist. Runs against its own root so the measured tree is untouched.
pub fn sample_through_write_path(
    root: &Path,
    count: u64,
    anchor_ms: i64,
) -> yaam_core::Result<u64> {
    write_spec(root)?;
    let mut pipeline = yaam_core::Pipeline::new(root)?;
    let mut accepted = 0;
    for index in 0..count {
        let generated = generate(index, anchor_ms);
        pipeline.accept(generated.record, &generated.body)?;
        accepted += 1;
    }
    Ok(accepted)
}

/// What the generated store contains, tallied without touching the index.
///
/// The measurements have to name entities that exist, and naming one by guessing would silently
/// turn a point lookup into a measurement of an empty result. Tallied from the generator rather than
/// read back from the index so the choice does not depend on the thing being measured.
pub struct Census {
    /// Reference count per `(kind, id)`, counting only confident references.
    pub entities: BTreeMap<(String, String), usize>,
    /// Bodies carrying [`PHRASE`].
    pub with_phrase: usize,
}

impl Census {
    /// Tallies records `from..to`.
    #[must_use]
    pub fn of(from: u64, to: u64, anchor_ms: i64) -> Self {
        let mut entities: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut with_phrase = 0;
        for index in from..to {
            let generated = generate(index, anchor_ms);
            if generated.body.contains(PHRASE) {
                with_phrase += 1;
            }
            for reference in &generated.record.entities {
                if reference.confidence >= 1.0 {
                    *entities
                        .entry((reference.kind.clone(), reference.id.clone()))
                        .or_default() += 1;
                }
            }
        }
        Self {
            entities,
            with_phrase,
        }
    }

    /// The identifier of one kind with the most references — the "few with thousands" case.
    #[must_use]
    pub fn busiest(&self, kind: &str) -> Option<(String, usize)> {
        self.entities
            .iter()
            .filter(|((k, _), _)| k == kind)
            .max_by_key(|(_, count)| **count)
            .map(|((_, id), count)| (id.clone(), *count))
    }

    /// An identifier of one kind carrying about `want` references — the long-tail case.
    #[must_use]
    pub fn typical(&self, kind: &str, want: usize) -> Option<(String, usize)> {
        self.entities
            .iter()
            .filter(|((k, _), _)| k == kind)
            .min_by_key(|(_, count)| count.abs_diff(want))
            .map(|((_, id), count)| (id.clone(), *count))
    }
}
