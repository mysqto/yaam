//! The argument surface of all four binaries.
//!
//! One file, because they have to agree. [`StoreArgs`] is flattened into the service and the
//! operator command line, so `--root` is one declaration with one default and one help string — not
//! two that drift until a rebuild addresses a different store than the service reads.
//!
//! Neither the sidecar nor the emitter nor the reader has [`StoreArgs`], and that is a decision
//! rather than an omission: none of them ever opens the tree, the index or the key store. Handing
//! them those flags would invite a deployment to point them somewhere, and the answer to where they
//! point is "nowhere". This is also why [`EmitCli`] and [`ReadCli`] are their own binaries rather
//! than `yaam emit` and `yaam read` subcommands — the operator command line flattens [`StoreArgs`]
//! above its subcommands, so a subcommand would inherit `--root` whatever it did with it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use yaam_core::drain;

use crate::exit;

/// Where the store is. Shared by every binary that opens one.
#[derive(Debug, Args)]
pub struct StoreArgs {
    /// Root of the memory tree. Required; also read from `YAAM_ROOT`.
    #[arg(long, value_name = "PATH")]
    pub root: Option<PathBuf>,
    /// The derived index. Defaults to `<root>/index.sqlite`; also read from `YAAM_INDEX`.
    #[arg(long, value_name = "PATH")]
    pub index: Option<PathBuf>,
    /// Root of the key store. Defaults to `<root>/keystore`; also read from `YAAM_KEY_STORE`.
    #[arg(long, value_name = "PATH")]
    pub key_store: Option<PathBuf>,
    /// File holding the passphrase that protects key material at rest. Without it, subject keys are
    /// written in the clear. Also read from `YAAM_KEY_PASSPHRASE_FILE`.
    ///
    /// A file and not a value: an argument is visible in `ps` to every user on the host.
    #[arg(long, value_name = "PATH")]
    pub key_passphrase_file: Option<PathBuf>,
    /// File holding the hex-encoded secret that subject pseudonyms are derived under. Required by,
    /// and only by, a store whose `spec/subjects.yaml` says which entity kinds are erasure units.
    /// Also read from `YAAM_SUBJECT_KEY_FILE`.
    ///
    /// A file rather than a value, for the reason above, and this process's rather than a caller's:
    /// the secret cannot be rotated once its outputs are in filenames and in tombstones that are
    /// never deleted, so every host that holds a copy is a host whose compromise de-pseudonymises
    /// every backup ever taken.
    #[arg(long, value_name = "PATH")]
    pub subject_key_file: Option<PathBuf>,
}

/// Serve the memory service.
#[derive(Debug, Parser)]
#[command(name = "yaam-server", version, after_help = exit::HELP)]
pub struct ServerCli {
    /// Everything the service needs.
    #[command(flatten)]
    pub args: ServerArgs,
}

/// The service's own settings.
#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Where the store is.
    #[command(flatten)]
    pub store: StoreArgs,
    /// Address to accept on, as `host:port`. Defaults to loopback; also read from `YAAM_LISTEN`.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,
    /// Keyring file naming the callers this service authenticates. Also read from `YAAM_KEYRING`.
    #[arg(long, value_name = "PATH")]
    pub keyring: Option<PathBuf>,
    /// File holding the hex-encoded secret half of the key sidecars seal to.
    ///
    /// Without it this service accepts plain JSON only and refuses a sealed body. Also read from
    /// `YAAM_UNSEAL_KEY_FILE`.
    #[arg(long, value_name = "PATH")]
    pub unseal_key_file: Option<PathBuf>,
    /// How often the service drains fan-out and sweeps, in milliseconds.
    ///
    /// Defaults to 30 s; also read from `YAAM_MAINTENANCE_MS`. A round runs at startup whatever this
    /// says, so the interval is how long convergence can lag, not how long it waits to begin.
    #[arg(long, value_name = "MS")]
    pub maintenance_ms: Option<u64>,
}

/// Serve the local sidecar: one socket per caller, sealing and signing on their behalf.
#[derive(Debug, Parser)]
#[command(name = "yaam-agent", version, after_help = exit::HELP)]
pub struct AgentCli {
    /// Everything the sidecar needs.
    #[command(flatten)]
    pub args: AgentArgs,
}

/// The sidecar's own settings.
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// Directory holding `upstream.json` and the spool. Also read from `YAAM_AGENT_STATE`.
    #[arg(long, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
    /// Serve one caller, as `agent=path`. Repeat for several.
    ///
    /// Defaults to one caller per agent the configuration holds a signing key for, under
    /// `<state-dir>/sockets/<agent>.sock`. Each caller also gets a read socket, at the same path
    /// with `.read.sock` for its extension: records go to the first, signed HTTP reads to the
    /// second.
    #[arg(long = "socket", value_name = "AGENT=PATH")]
    pub sockets: Vec<String>,
    /// Entries the spool holds before it refuses writes. Overrides the configuration file.
    #[arg(long, value_name = "N")]
    pub spool_capacity: Option<usize>,
    /// Delay between drain attempts while the spool is backed up. Overrides the configuration file.
    #[arg(long, value_name = "MS")]
    pub retry_interval_ms: Option<u64>,
}

/// Record one thing an agent did, on a caller socket.
///
/// Everything mechanical is filled in here: the identifier, both timestamps, the schema version and
/// the empty collections. What is left to say is what only the caller knows.
///
/// The timestamps default to now and are `--at`'s to move, which is what makes history importable:
/// `--at` with `--backfilled` records something that already happened, at the instant it happened,
/// rather than at the instant a converter got round to reading it.
///
/// This binary opens no store, and has no flag that could point it at one. It writes one JSON line
/// to a sidecar socket and reads one back; the sidecar is what seals, signs and spools. A caller
/// posting to the service directly would need the service's own key and would lose the spool with
/// it, which is the difference between a record that waits out an outage and one that is gone.
///
/// `--infer-entities` is the one flag that names a directory, and it is not a store root by another
/// name. A root is where records, key material and the index are, and the only thing a process does
/// with one is open it; this reads two configuration files, `entities.yaml` and `extractors.yaml`,
/// and nothing here could turn the directory holding them into a store. They are configuration a
/// deployment hands its caller hosts, the way it hands the sidecar an upstream.
///
/// Subjects stay empty and the data class stays `internal`, and both are fixed rather than
/// defaulted. A flag inviting either would let a caller declare a record erasable that this
/// deployment cannot erase — and a caller here could not make the claim true even meaning to: the
/// secret a pseudonym is derived under lives with the service, so a subject named on this command
/// line could only be a value invented on a host that holds no key material. A subject resolver in
/// the service is what fills them in, on a store that declares which references are erasure units.
#[derive(Debug, Parser)]
#[command(name = "yaam-emit", version, after_help = exit::HELP)]
pub struct EmitCli {
    /// Everything the record and the socket need.
    #[command(flatten)]
    pub args: EmitArgs,
}

/// One record, as a caller describes it.
#[derive(Debug, Args)]
pub struct EmitArgs {
    /// The caller socket to write to. Also read from `YAAM_SOCKET`.
    ///
    /// A sidecar's record socket, at `<state-dir>/sockets/<agent>.sock` by default. Not the
    /// `.read.sock` beside it, which speaks HTTP.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Which agent this record is attributed to. Also read from `YAAM_AGENT`.
    ///
    /// Must be the agent the socket belongs to. The sidecar refuses a record claiming another,
    /// because the socket is the evidence of who is writing.
    #[arg(long, value_name = "NAME")]
    pub agent: Option<String>,
    /// Version of the agent, for attributing a change in behaviour to a release.
    #[arg(long, value_name = "VERSION")]
    pub agent_ver: Option<String>,
    /// What was done, as `spec/attrs-schema.yaml` names it.
    #[arg(long, value_name = "ACTION")]
    pub action: String,
    /// How it went.
    ///
    /// Required, and deliberately not defaulted to `success`: a default would file every failure
    /// nobody remembered to describe as a success, and no later read could tell.
    #[arg(long, value_name = "OUTCOME")]
    pub outcome: OutcomeArg,
    /// Prose describing what happened. Becomes the record's body.
    #[arg(long, value_name = "TEXT")]
    pub summary: String,
    /// A declared text attribute, as `key=value`. Repeat for several.
    ///
    /// Text, always. The type each key is declared with lives in the deployment's
    /// `spec/attrs-schema.yaml`, which this binary cannot read, and guessing from the shape of a
    /// value would send an integer wherever a build number happened to be all digits. Use
    /// `--attr-int` and `--attr-bool` to mean those.
    #[arg(long = "attr", value_name = "KEY=VALUE")]
    pub attrs: Vec<String>,
    /// A declared integer attribute, as `key=value`. Repeat for several.
    #[arg(long = "attr-int", value_name = "KEY=VALUE")]
    pub attr_ints: Vec<String>,
    /// A declared boolean attribute, as `key=true` or `key=false`. Repeat for several.
    #[arg(long = "attr-bool", value_name = "KEY=VALUE")]
    pub attr_bools: Vec<String>,
    /// An entity this record joins on, as `kind:id`. Repeat for several.
    ///
    /// Recorded as a primary reference at full confidence, because a caller naming an entity is
    /// stating a fact rather than inferring one. The other roles and every confidence below `1.0`
    /// describe references *inferred* from prose, which `--infer-entities` produces.
    #[arg(long = "entity", value_name = "KIND:ID")]
    pub entities: Vec<String>,
    /// Also read `--summary` for entity references, using the rules in this spec directory.
    ///
    /// The directory holds `entities.yaml` and `extractors.yaml`: the first says what an identifier
    /// *is*, the second when prose is evidence that one was meant. Both are read, neither is
    /// written, and nothing else in the directory is touched — see [`EmitCli`] for why that is still
    /// not a store.
    ///
    /// Opt-in, and a flag rather than a variable: what it adds are guesses about the caller's own
    /// prose, so the decision belongs at the call site that knows what that prose is. An exported
    /// variable would switch it on for every record every process on the host writes.
    ///
    /// What it infers is `related` at a confidence below `1.0`, which is what keeps it apart from a
    /// stated `--entity`. Where the two name one entity, the stated one is what is recorded.
    #[arg(long, value_name = "SPEC_DIR")]
    pub infer_entities: Option<PathBuf>,
    /// A free tag. Repeat for several.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Who may read this record.
    #[arg(long, value_name = "SCOPE", default_value = "org")]
    pub visibility: VisibilityArg,
    /// The team, required when `--visibility team`.
    #[arg(long, value_name = "TEAM")]
    pub team: Option<String>,
    /// Ties every stage of one interaction together.
    #[arg(long, value_name = "ID")]
    pub correlation_id: Option<String>,
    /// When the action happened, as an `RFC3339` timestamp. Defaults to now.
    ///
    /// A hook firing beside the action means now, which is why this is optional. Naming an instant
    /// this clock passed long ago needs `--backfilled` with it, and an instant it has not reached is
    /// refused outright: a record is something that happened.
    #[arg(long, value_name = "TIMESTAMP")]
    pub at: Option<String>,
    /// This record comes from a source rather than from watching the action happen.
    ///
    /// Requires `--at`, and makes it both timestamps: the source's own instant becomes the received
    /// time too, because there is no moment at which this deployment observed the action, and
    /// stamping one would be inventing it. That is also what puts the record where it belongs — the
    /// store orders, windows and joins on the received time, so a backfill without this lands
    /// today, however old the action it describes.
    #[arg(long)]
    pub backfilled: bool,
    /// The redaction policy this record was written under.
    ///
    /// It must name the policy the deployment *applies*, not one the caller would like: the service
    /// refuses a record that declares any other, because a record claiming a policy nobody ran is a
    /// record whose account of its own redaction is false. The name is the `policy:` field of the
    /// deployment's `spec/redaction/*.yaml`.
    #[arg(long, value_name = "NAME", default_value = crate::emit::DEFAULT_REDACTION_POLICY)]
    pub redaction_policy: String,
    /// Print the record that would be sent and stop. Needs no socket and no sidecar.
    #[arg(long)]
    pub dry_run: bool,
    /// How long to wait for the sidecar's answer, in milliseconds.
    ///
    /// The sidecar sends its backlog ahead of a new record, so the wait can legitimately be longer
    /// than one round trip. A bound all the same: a hook that blocks for ever on a wedged socket
    /// stops whatever called it.
    #[arg(long, value_name = "MS", default_value_t = crate::emit::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: u64,
}

/// How the outcome of an action is reported, as a flag.
///
/// A separate enum from [`yaam_contract::Outcome`] only because clap has to be told the spellings;
/// [`OutcomeArg::into_contract`] is the one place they are mapped, so a variant added to the
/// contract fails to compile here rather than being silently unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum OutcomeArg {
    /// The action did what it set out to do.
    Success,
    /// It failed.
    Failure,
    /// It partly succeeded, and the summary says how.
    Partial,
    /// It was refused.
    Declined,
}

impl OutcomeArg {
    /// The contract's own spelling.
    #[must_use]
    pub fn into_contract(self) -> yaam_contract::Outcome {
        match self {
            Self::Success => yaam_contract::Outcome::Success,
            Self::Failure => yaam_contract::Outcome::Failure,
            Self::Partial => yaam_contract::Outcome::Partial,
            Self::Declined => yaam_contract::Outcome::Declined,
        }
    }

    /// How a stored record spells this outcome, which is what a query is matched against.
    ///
    /// Its own function because the consequence of getting it wrong is invisible: the service
    /// compares this against an indexed column, so a misspelling matches nothing and answers `200`
    /// with an empty page. A test pins every variant to what `serde` actually writes.
    #[must_use]
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Partial => "partial",
            Self::Declined => "declined",
        }
    }
}

/// Who may read a record, as a flag. Paired with [`yaam_contract::Visibility`] as [`OutcomeArg`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum VisibilityArg {
    /// The actor only.
    Owner,
    /// A named team, which `--team` has to name.
    Team,
    /// Everyone in the deployment.
    Org,
    /// Audit records, readable only by the operator role.
    Operator,
}

impl VisibilityArg {
    /// The contract's own spelling.
    #[must_use]
    pub fn into_contract(self) -> yaam_contract::Visibility {
        match self {
            Self::Owner => yaam_contract::Visibility::Owner,
            Self::Team => yaam_contract::Visibility::Team,
            Self::Org => yaam_contract::Visibility::Org,
            Self::Operator => yaam_contract::Visibility::Operator,
        }
    }
}

/// Ask a deployment what it remembers, over a caller's read socket.
///
/// The read half of [`EmitCli`], and it holds no key either. The sidecar's read socket signs on the
/// caller's behalf: this binary sends an ordinary HTTP request over a unix socket and prints what
/// comes back, so a reader needs no signing key, no keyring and no path into anyone's tree. Teaching
/// it to sign would hand a caller exactly what the sidecar exists to keep away from it.
///
/// Like the emitter, it opens no store and has no flag that could point it at one. There is also no
/// `--agent`: the socket signs as the caller it belongs to, so who is asking is a property of the
/// socket rather than something the request gets to claim.
///
/// The service's own JSON goes to stdout unchanged. Nothing is reformatted, summarised or unwrapped
/// — the caller is a program, and an answer this rewrote would have to be parsed twice.
#[derive(Debug, Parser)]
#[command(
    name = "yaam-read",
    version,
    after_help = exit::HELP,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct ReadCli {
    /// How the request travels.
    #[command(flatten)]
    pub args: ReadArgs,
    /// Which read.
    #[command(subcommand)]
    pub query: ReadQuery,
}

/// How a read reaches the sidecar. Shared by every read, whichever one it is.
///
/// Global, so `yaam-read --socket … records` and `yaam-read records --socket …` are the same command.
/// Where a flag that belongs to no particular subcommand has to sit is not a thing a caller should
/// have to remember.
#[derive(Debug, Args)]
pub struct ReadArgs {
    /// The caller's read socket. Also read from `YAAM_READ_SOCKET`.
    ///
    /// A sidecar's read socket, at `<state-dir>/sockets/<agent>.read.sock` by default — the same
    /// path as that agent's record socket with `.read.sock` for its extension. Not the record socket
    /// itself, which speaks newline-delimited JSON and would refuse an HTTP request as a malformed
    /// record.
    #[arg(long, value_name = "PATH", global = true)]
    pub socket: Option<PathBuf>,
    /// Print the request that would be sent and stop. Needs no socket and no sidecar.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// How long to wait for the answer, in milliseconds.
    ///
    /// A bound on a wedged socket rather than a judgement about how long a query should take: the
    /// sidecar is waiting on the service, which is waiting on an index. A read is side-effect free,
    /// so a wait that runs out costs nothing but the wait — asking again is always safe.
    #[arg(long, value_name = "MS", global = true, default_value_t = crate::read::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: u64,
}

/// The reads this service answers.
///
/// Subcommands rather than one flat set of flags, because the five are five questions and not five
/// filters on one. `--query` is required for a search and meaningless to a bundle; `--entity` names
/// exactly one entity for a history and any number for a bundle; a window narrows a records query,
/// is required by a correlation, and is not a parameter of the others at all. Flattened together,
/// every one of those would be accepted here and refused a round trip later — the service answers an
/// unknown parameter with `400` rather than ignoring it — and `--help` would describe a request
/// surface that does not exist.
///
/// Every filter is optional wherever the service says it is optional, and absent means absent: this
/// sends no parameter the caller did not name, because each of them has a documented default at the
/// service and a copy of that figure here would be a second place for it to be out of date.
#[derive(Debug, Subcommand)]
pub enum ReadQuery {
    /// Query records by action, outcome, agent, attribute or time window. Newest first.
    ///
    /// Bounded whether or not `--limit` says so, so a short answer is not proof that nothing else
    /// matched. There is no cursor: page by narrowing the request.
    Records {
        /// Exact match on one action.
        #[arg(long, value_name = "ACTION")]
        action: Option<String>,
        /// Restrict to one outcome.
        #[arg(long, value_name = "OUTCOME")]
        outcome: Option<OutcomeArg>,
        /// Restrict to the records one agent wrote.
        ///
        /// The record's author, which is not the caller. What this caller may see is decided by the
        /// socket that signs the read, and no flag here widens it.
        #[arg(long, value_name = "NAME")]
        agent: Option<String>,
        /// Require a structural attribute, as `key=value`.
        ///
        /// Compared as text, so an integer matches its decimal form. Sensitive attributes live in
        /// the sealed body and are not queryable at all.
        #[arg(long, value_name = "KEY=VALUE")]
        attr: Option<String>,
        /// Inclusive start of the window, in milliseconds of the server-stamped time.
        #[arg(long, value_name = "MS")]
        from_ms: Option<i64>,
        /// Exclusive end of the window, on the same clock.
        #[arg(long, value_name = "MS")]
        to_ms: Option<i64>,
        /// Page size. Absent leaves the service's own cap in force.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// One page of what touches one entity, newest first.
    ///
    /// The identifier is canonicalised by the deployment before it is matched, so the spelling that
    /// was good enough to store is good enough to find. A kind this deployment does not configure is
    /// refused rather than answered with an empty page — no rows would be indistinguishable from an
    /// entity with no history.
    History {
        /// The entity, as `kind:id`. Percent-encoding is this command's business, not the caller's.
        #[arg(long, value_name = "KIND:ID")]
        entity: String,
        /// Tolerance for inferred references. `1.0` keeps only references read from a structured
        /// field. Absent means the service's floor, which is everything.
        #[arg(long, value_name = "FLOOR")]
        min_confidence: Option<f32>,
        /// Page size. Absent leaves the service's own cap in force.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// Inclusive start of a window over the server-stamped time, in milliseconds.
        ///
        /// One entity inside one window is the shape of a correlation: what else touched this
        /// ticket while that decline was happening. Without it the answer is the whole history and
        /// the window is applied by whoever read it — to rows the page cap already chose.
        #[arg(long, value_name = "MS")]
        from_ms: Option<i64>,
        /// Exclusive end of that window, on the same clock.
        #[arg(long, value_name = "MS")]
        to_ms: Option<i64>,
    },
    /// Which records mention something. Full text over record bodies, best match first.
    ///
    /// The needle reaches the prose and the answer does not carry it: a hit comes back as the
    /// record's structure. Sealed bodies hold no text to search, so they never match.
    ///
    /// A short page is not proof that nothing else matched — the matches examined are capped before
    /// the caller's scope is applied. Narrow the needle rather than raising `--limit`.
    Search {
        /// The needle, as the service's `q`: a word, several words, a prefix as `roll*`, or a phrase
        /// in double quotes. Required — a search for nothing is not a search for everything.
        #[arg(long, value_name = "TEXT")]
        query: String,
        /// Page size. Absent leaves the service's own cap in force.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// Which records of one shape were followed by records of another, as pairs.
    ///
    /// The join a cross-agent question reduces to: something failed, and something else happened
    /// nearby. Two filters in one read — `--left-*` for the earlier record, `--right-*` for the one
    /// that has to have followed it — and `--within-ms` for how long after still counts.
    ///
    /// Directional. A pair comes back when the right record was stamped at or after the left one, so
    /// "what was deployed just before this decline" is asked by putting the deploy on the left. There
    /// is no backwards window: swap the sides.
    ///
    /// `--left-from-ms` and `--left-to-ms` are required, which no other read here demands. They bound
    /// the side the join is driven from, and it is the only thing a request can say that stops this
    /// read costing whatever the store happens to hold.
    Correlate {
        /// Exact match on the earlier record's action.
        #[arg(long, value_name = "ACTION")]
        left_action: Option<String>,
        /// Restrict the earlier record to one outcome.
        #[arg(long, value_name = "OUTCOME")]
        left_outcome: Option<OutcomeArg>,
        /// Restrict the earlier record to one author.
        #[arg(long, value_name = "NAME")]
        left_agent: Option<String>,
        /// Require a structural attribute on the earlier record, as `key=value`.
        #[arg(long, value_name = "KEY=VALUE")]
        left_attr: Option<String>,
        /// Inclusive start of the window the earlier record is searched in, in milliseconds.
        ///
        /// Required, with `--left-to-ms`. There is deliberately no implicit "recent": a question
        /// whose meaning depends on when it ran cannot be tested.
        #[arg(long, value_name = "MS")]
        left_from_ms: Option<i64>,
        /// Exclusive end of that window, on the same clock. Required, with `--left-from-ms`.
        #[arg(long, value_name = "MS")]
        left_to_ms: Option<i64>,
        /// Exact match on the later record's action.
        #[arg(long, value_name = "ACTION")]
        right_action: Option<String>,
        /// Restrict the later record to one outcome.
        #[arg(long, value_name = "OUTCOME")]
        right_outcome: Option<OutcomeArg>,
        /// Restrict the later record to one author.
        #[arg(long, value_name = "NAME")]
        right_agent: Option<String>,
        /// Require a structural attribute on the later record, as `key=value`.
        #[arg(long, value_name = "KEY=VALUE")]
        right_attr: Option<String>,
        /// How long after the earlier record a later one still counts, in milliseconds.
        ///
        /// Required: no length of time means "nearby" to every caller. There is no window on the
        /// right side — the right side's window is the left one plus this.
        #[arg(long, value_name = "MS")]
        within_ms: i64,
        /// Most pairs to return. Absent leaves the service's own pair cap in force.
        ///
        /// Pairs, not records: a pair row is two structures, so the service's cap here is half its
        /// cap on the other reads.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// What else is connected to one entity, and by which records. The graph read.
    ///
    /// Every other read here takes entities you can already name and answers with records. This one
    /// takes one entity and answers with edges: two entities and the record naming both, so *why*
    /// two things are connected needs no second read.
    ///
    /// `--depth 2` is the point of it — it reaches entities the seed's own records never named.
    /// `--depth`, `--from-ms` and `--to-ms` are all required: the work is exponential in the depth,
    /// and the seed's history is as long as the seed is busy.
    ///
    /// An entity is *reached* however busy it is and is not walked *through* above `--max-degree`
    /// references inside the window. The ones the rule refused come back under `hubs`, so a short
    /// answer says whether nothing else is connected or everything is, through one node.
    Linked {
        /// The entity to start from, as `kind:id`. Percent-encoding is this command's business.
        #[arg(long, value_name = "KIND:ID")]
        entity: String,
        /// How many records deep to go. Required, and 1 to 2.
        ///
        /// `0` is what `history` already answers. `3` is refused rather than answered: the
        /// service's recursion fills its 200-edge frontier breadth-first, so it spends the frontier
        /// on near hops before far ones — a 30-day depth-3 traversal comes back as 115 hop-1 edges,
        /// 85 hop-2 edges and no hop-3 edges at all, which is a two-hop answer under a three-hop
        /// label. Ask for 2 and narrow the window; a per-hop budget is what would lift the cap.
        #[arg(long, value_name = "N")]
        depth: u32,
        /// Inclusive start of the window every hop is taken inside, in milliseconds. Required.
        #[arg(long, value_name = "MS")]
        from_ms: Option<i64>,
        /// Exclusive end of that window, on the same clock. Required, with `--from-ms`.
        #[arg(long, value_name = "MS")]
        to_ms: Option<i64>,
        /// Floor every reference on every hop must clear. Absent means the service's, which is
        /// full confidence.
        ///
        /// Lowering it widens what is reported and never what is routed through: an inferred
        /// reference may end a path and may not extend one.
        #[arg(long, value_name = "FLOOR")]
        min_confidence: Option<f32>,
        /// Most references an entity may carry inside the window and still be traversed through.
        ///
        /// Absent means the service's own cap. It may be lowered and not raised: raising it would
        /// be a request buying back the problem the rule exists to prevent.
        #[arg(long, value_name = "N")]
        max_degree: Option<u32>,
        /// Most edges to return. Absent leaves the service's own cap in force.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
    /// Compose context for a request: history for some entities and an actor, in one capped set.
    ///
    /// Check `degraded` in the answer before acting on it. A bundle whose sources ran out of time is
    /// safe to answer a question from and unsafe to act on, and only the caller can make that call.
    Bundle {
        /// An entity to gather history for, as `kind:id`. Repeat for several.
        ///
        /// Only references read out of a structured field reach a bundle, whatever confidence floor
        /// an entity's own history would accept: a guess in a bundle is one the caller cannot tell
        /// apart from a fact.
        #[arg(long = "entity", value_name = "KIND:ID")]
        entities: Vec<String>,
        /// An agent whose recent activity is relevant, in addition to the named entities.
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
        /// Also read `--infer-from` for entities to gather, using the rules in this spec directory.
        ///
        /// The same directory `yaam-emit --infer-entities` names, holding `entities.yaml` and
        /// `extractors.yaml`. Both are read, neither is written, and this still opens no store: two
        /// YAML files saying what an identifier looks like are configuration, not a tree.
        ///
        /// What it produces are lookup keys and nothing else. The role and confidence an inferred
        /// reference carries are the *writer's* business, and the line above still holds — a bundle
        /// gathers only what a record states at full confidence. So an entity guessed here matches
        /// records that reference it properly, or it matches nothing; the cost of a wrong guess is
        /// one wasted lookup rather than a falsehood somebody later reads back as a fact. That is
        /// why this may infer where `yaam-emit` may not.
        #[arg(long, value_name = "SPEC_DIR")]
        infer_entities: Option<PathBuf>,
        /// The prose to read, when `--infer-entities` says how to read it.
        ///
        /// Whatever the caller is about to act on: the message a turn is answering, the title of a
        /// change under review. Neither flag means anything without the other, and either one alone
        /// is refused rather than ignored — text nobody read, or rules nothing was read with, is a
        /// narrower bundle than the caller asked for and no answer says so.
        #[arg(long, value_name = "TEXT")]
        infer_from: Option<String>,
        /// Budget for the whole composition, in milliseconds. Absent means the service's own.
        ///
        /// A source not consulted in time names itself in `omitted` and sets `degraded`; it is never
        /// silently skipped, because "no history" and "never asked" call for opposite decisions.
        #[arg(long, value_name = "MS")]
        deadline_ms: Option<u64>,
        /// Most records the bundle may return. Absent means the service's own cap.
        ///
        /// Worth setting: this reaches the source reads, so a caller that wants five records is
        /// charged for five rather than for the cap.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
    },
}

/// Operate a memory store: rebuild the index, run its queued work, erase a subject, copy it, read
/// its health.
#[derive(Debug, Parser)]
#[command(
    name = "yaam",
    version,
    after_help = exit::HELP,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct OperatorCli {
    /// Where the store is.
    #[command(flatten)]
    pub store: StoreArgs,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The operator commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Rebuild the derived index from the tree and the cold manifests.
    ///
    /// The step a restored backup needs before the index means anything, and the remedy for drift.
    /// A rebuild is always whole — there is no partial one to ask for — so `--all` is accepted
    /// because the recovery procedures name it, and changes nothing.
    Reindex {
        /// Rebuild everything. The only rebuild there is; accepted for the procedures that name it.
        #[arg(long)]
        all: bool,
    },
    /// Run the queued fan-out: materialise entity timelines and subject audit records.
    ///
    /// A service does this on its maintenance timer, so a deployment needs it only to catch up in a
    /// hurry. A store driven by this command line alone has no timer, and this is what converges it:
    /// fan-out is enqueued by a write and by every rebuild, and until it runs an entity's timeline is
    /// a file that is not there.
    Drain {
        /// Jobs to settle before reporting and returning.
        ///
        /// A bound, not a target. Draining until the queue is empty can be held open indefinitely
        /// by a writer filling it, so this settles what it can and reports the remainder.
        #[arg(long, value_name = "N", default_value_t = drain::MAX_JOBS)]
        max_jobs: usize,
    },
    /// Destroy a subject's keys, making their record bodies permanently unreadable.
    ///
    /// Irreversible, and it reaches every copy including backups. Frontmatter, attributes, entity
    /// references and timelines are retained.
    Erase {
        /// The subject's pseudonym, as `s_` followed by 64 hex characters.
        #[arg(long, value_name = "HASH")]
        subject: String,
        /// Mean it. Without this the command prints what would be affected and stops.
        #[arg(long)]
        confirm_destroy_keys: bool,
    },
    /// Report whether an erasure can be asserted complete.
    ///
    /// Two-phase by necessity: destruction cannot be asserted while a backup taken before it is
    /// still inside its retention window.
    VerifyErasure {
        /// The tombstone identifier `erase` printed.
        #[arg(long, value_name = "ID")]
        tombstone: String,
    },
    /// Read one record's sealed body, writing the audit record of that reading first.
    ///
    /// The only path back to a sealed body anywhere in this workspace, and deliberately the only
    /// one: `yaam-read` and the service never unseal, so customer plaintext cannot reach an agent's
    /// context, a chat message or a log line — all places outside the reach of a key destruction.
    ///
    /// The reading is recorded before a key is fetched, in a record of `action: unseal` and
    /// `visibility: operator` naming the operator and the reason. That ordering is the command: a
    /// store that cannot record the read cannot answer it, so there is no failure that hands back a
    /// body nobody can tell was handed back.
    ///
    /// Not an endpoint, for the reason erasure's local half is not one either: the operator role
    /// here is custody of the key store, which is a property of the host and not of a signature.
    /// A record whose subjects have been erased is refused with the erasure that accounts for it,
    /// never with an empty answer that reads like a record nobody wrote.
    Unseal {
        /// The record, as the 26-character identifier it is filed under.
        #[arg(long, value_name = "ID")]
        record: String,
        /// Who is reading it. Becomes the audit record's agent.
        ///
        /// An attestation, not an authentication: whoever can reach the key store can read what it
        /// opens, so what this buys is a name in the trail beside the reason — which is what an
        /// auditor asks for and what a hash of a key would not tell them.
        #[arg(long, value_name = "NAME")]
        operator: String,
        /// Why. Becomes the audit record's body, and there is no default.
        ///
        /// It goes through the deployment's redaction policy like any other body, so a reason
        /// carrying something the policy masks fails the read rather than entering the store.
        #[arg(long, value_name = "TEXT")]
        reason: String,
        /// Mean it. Without this the command prints whose keys the read would use and stops.
        #[arg(long)]
        confirm_read_body: bool,
    },
    /// Read the store's health: schema version, index drift, sweeper backlog, quarantine depth,
    /// dead-lettered fan-out.
    ///
    /// The first command to run when something looks wrong. Degraded whenever any of it wants a
    /// person, a job set aside in `.dead-letter/` included: nothing retries one, so a store holding
    /// one is not converging however long it is left alone.
    Check,
    /// Copy the store's authoritative half into a fresh directory.
    ///
    /// What travels and what does not is declared by `yaam_core::backup::MANIFEST`, not by this
    /// command. The key store is on the excluded side, and that exclusion is what makes an erasure
    /// reach every copy instead of only the live one — so a backup that quietly picked it up would
    /// un-erase a subject on the next restore.
    Backup {
        /// Directory to write the backup into. Must be absent or empty.
        #[arg(long = "to", value_name = "PATH")]
        to: PathBuf,
    },
    /// Decide whether a set of paths is safe to commit, for a `pre-commit` hook to stop on.
    ///
    /// The layout this is for keeps a store's *backup* in a private repository, which is safe for
    /// one reason: a backup carries ciphertext and no keys, so destroying a key still makes a
    /// sealed body permanently unreadable however long the ciphertext stays in the history. That
    /// rests on the key store never being committed once, and an ignore rule is not a mechanism
    /// against a one-way door — `git add -f` overrides one, and a rule written today does not
    /// remove what was committed yesterday.
    ///
    /// What is safe is decided by `yaam_core::backup::MANIFEST`, the same list a backup is taken
    /// against, so a newly excluded entry protects a repository the moment it is declared. Opens no
    /// store: a hook runs on every commit and has no business touching an index.
    ///
    /// Every unknown refuses. Read the exit codes: 8 is a path no copy may contain, 4 is one beside
    /// the store that no manifest entry classifies, 3 is not knowing where the store is, and 1 is
    /// not being able to resolve a path at all.
    GuardCommit {
        /// Check everything in this repository's index: what the commit would contain, not only
        /// what changed. Catches a key file added before the hook existed, on every commit after.
        #[arg(long, value_name = "DIR")]
        repo: Option<PathBuf>,
        /// Check exactly this path. Repeat for several. For a check by hand.
        #[arg(long = "path", value_name = "PATH")]
        paths: Vec<PathBuf>,
        /// Print the `pre-commit` hook and stop. What `hooks/install.sh` installs.
        #[arg(long)]
        print_hook: bool,
    },
    /// Restore a backup into this store, rebuild the index, then run the fan-out that queued.
    ///
    /// The rebuild is part of the command rather than a step to remember: restored files can be
    /// older than the sweeper's own scan bound, and the rebuild is also what replays the restored
    /// tombstone log so a backup cannot resurrect erased structure. Its fan-out is drained here for
    /// the same reason: a backup carries no materialised timelines because a rebuild writes them
    /// again, and this is the command that makes that true. Refuses a store that already holds
    /// records — a restore is not a merge.
    Restore {
        /// Directory holding the backup.
        #[arg(long = "from", value_name = "PATH")]
        from: PathBuf,
    },
    /// Derive knowledge from the record tree, and read what was derived.
    ///
    /// A second tree beside the records, holding what is *true* rather than what happened: one note
    /// per entity, every line a restatement of a structured field some record declared, carrying the
    /// identifiers of the records it was read out of. Derived and disposable — delete `knowledge/`
    /// and build it again.
    ///
    /// Nothing here reads a body, and that is a property of the input rather than a rule each
    /// command has to remember: derivation is handed a record's frontmatter, which has no field for
    /// prose. It is also why a record whose body is erasable contributes nothing at all — a note is
    /// an aggregate, and destroying a key cannot reach an aggregate already written into last
    /// night's backup.
    ///
    /// Opens no index and no key store, unlike every other command that names a store. A rebuild
    /// reads the Markdown tree and the cold manifests, so it is available on a store whose index is
    /// the thing that is broken.
    Knowledge {
        /// Build it, or read what a build left.
        #[command(subcommand)]
        what: KnowledgeCommand,
    },
}

/// Most notes one listing may print before the cap decides.
///
/// A default rather than a required flag, because an operator looking for a spelling should not have
/// to choose a page size first. It is named here so `--help` prints the figure — a cap nobody can
/// see is a short answer that reads as an empty tree.
const SEARCH_LIMIT: usize = 20;

/// Building the knowledge tree, and the three reads over it.
///
/// Subcommands rather than flags on one, for the reason the reads are subcommands: `--entity` names
/// exactly one entity and `--query` names none, `--record` is meaningful only where a fact's
/// provenance is being checked, and a build takes nothing at all. Flattened together, `--help` would
/// describe a surface where every one of those was optional and the wrong combinations were quietly
/// ignored.
#[derive(Debug, Subcommand)]
pub enum KnowledgeCommand {
    /// Rebuild every note from the record tree.
    ///
    /// Wholesale, and there is no incremental one to ask for: a note's counts and bounds are
    /// aggregates, and one record's contribution cannot be taken back out of a count already
    /// written. So each build is a statement about the tree as it now stands, and a record that has
    /// left it — or a body that has been erased — is gone from knowledge without anything chasing
    /// it.
    ///
    /// Exits `4` for a source that would not parse or a stamp that would not, because those are
    /// drift between the tree and what can be derived from it. Excluded erasable and scoped records
    /// are counted and are not a fault: they are what the gate is for.
    Build,
    /// Report what the last build read, and when.
    ///
    /// Exits `4` when there is no answer, which is a definite state rather than a missing one: the
    /// state file is removed before a build swaps its tree in and written after, so its absence says
    /// this tree is mid-build or has never been built. Either way the remedy is to build it.
    Status,
    /// Print one entity's note.
    Note {
        /// The entity, as `kind:id`.
        ///
        /// As the tree spells it. Identifiers are canonicalised on the way in and nothing here
        /// canonicalises again — a second canonicaliser would eventually disagree with the one the
        /// tree was written by — so a spelling this store never stored finds nothing. `knowledge
        /// search` is how to find the spelling.
        #[arg(long, value_name = "KIND:ID")]
        entity: String,
    },
    /// List the notes whose scalars carry a term.
    Search {
        /// The term, matched as a substring and case-insensitively.
        #[arg(long, value_name = "TERM")]
        query: String,
        /// Most notes to list.
        #[arg(long, value_name = "N", default_value_t = SEARCH_LIMIT)]
        limit: usize,
    },
    /// Print the structure of the records behind a fact.
    ///
    /// The identifiers a note lists per fact, resolved back to the frontmatter they were read out
    /// of, so a fact can be checked against its evidence. Never a body: the structure has no field
    /// for prose, which is what makes checking one free of reading anybody's data.
    ///
    /// Every candidate goes back through the gate that admitted the fact, so an identifier naming a
    /// record the derivation would not have used is not answered. Otherwise this would be a way to
    /// read a scoped record's structure by guessing its identifier.
    Evidence {
        /// A record identifier. Repeat for several.
        #[arg(long = "record", value_name = "ID", required = true)]
        records: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::{CommandFactory, Parser};

    use super::{AgentCli, Command, EmitCli, KnowledgeCommand, OperatorCli, ReadCli, ServerCli};
    use crate::exit::Exit;

    /// The codes are only an interface if they are published where a reader looks.
    #[test]
    fn every_help_lists_the_exit_codes() {
        let rendered = [
            OperatorCli::command().render_long_help().to_string(),
            ServerCli::command().render_long_help().to_string(),
            AgentCli::command().render_long_help().to_string(),
            EmitCli::command().render_long_help().to_string(),
            ReadCli::command().render_long_help().to_string(),
        ];
        for help in &rendered {
            for outcome in Exit::ALL {
                let code = outcome.code();
                assert!(
                    help.contains(&format!("  {code}  ")),
                    "code {code} is missing from a --help"
                );
            }
        }
    }

    /// The shared flags are one declaration, so they have to appear on both binaries that open a
    /// store — and on none of the three that run on a caller's host, which open none.
    #[test]
    fn the_store_flags_are_on_the_two_binaries_that_open_a_store() {
        let operator = OperatorCli::command().render_long_help().to_string();
        let server = ServerCli::command().render_long_help().to_string();
        let caller_side = [
            (
                "the sidecar",
                AgentCli::command().render_long_help().to_string(),
            ),
            (
                "the emitter",
                EmitCli::command().render_long_help().to_string(),
            ),
            (
                "the reader",
                ReadCli::command().render_long_help().to_string(),
            ),
        ];
        for flag in ["--root", "--index", "--key-store"] {
            assert!(operator.contains(flag), "yaam is missing {flag}");
            assert!(server.contains(flag), "yaam-server is missing {flag}");
            for (whose, help) in &caller_side {
                assert!(
                    !help.contains(flag),
                    "{whose} opens no store, so {flag} must not be offered"
                );
            }
        }
    }

    /// A reader holds no key and names no caller of its own: the socket is the evidence of who is
    /// asking, so a flag claiming otherwise would be a flag inviting a caller to lie.
    #[test]
    fn the_reader_names_no_caller_and_no_key_of_its_own() {
        let top = ReadCli::command().render_long_help().to_string();
        assert!(!top.contains("--agent <"), "{top}");
        assert!(!top.contains("--key"), "{top}");
        assert!(top.contains("no signing key"), "{top}");

        // One read does take an `--agent`, and it filters on who *wrote* the record. The help has to
        // say which of the two it means, or a caller reads it as a way to ask as somebody else.
        let mut command = ReadCli::command();
        let records = command
            .find_subcommand_mut("records")
            .expect("the filtered query")
            .render_long_help()
            .to_string();
        assert!(records.contains("not the caller"), "{records}");
    }

    /// Each read is its own subcommand, and each demands what only it needs.
    #[test]
    fn every_read_is_its_own_subcommand_with_its_own_requirements() {
        ReadCli::try_parse_from(["yaam-read"]).expect_err("no default read: there are five");
        ReadCli::try_parse_from(["yaam-read", "records"]).expect("every filter is optional");
        ReadCli::try_parse_from(["yaam-read", "search"])
            .expect_err("a search for nothing is not a search for everything");
        ReadCli::try_parse_from(["yaam-read", "search", "--query", "rolled back"]).expect("parsed");
        ReadCli::try_parse_from(["yaam-read", "history"])
            .expect_err("an entity history has to name the entity");
        ReadCli::try_parse_from(["yaam-read", "history", "--entity", "ticket:PROJ-42"])
            .expect("parsed");
        // A filter that belongs to another read is refused here rather than answered `400` later.
        ReadCli::try_parse_from(["yaam-read", "search", "--query", "x", "--action", "deploy"])
            .expect_err("a full-text read takes no filters");
        ReadCli::try_parse_from(["yaam-read", "bundle", "--query", "x"])
            .expect_err("a bundle has no needle");
        // A correlation is the one read that demands a nearness: no length of time means "nearby" to
        // every caller, so there is nothing to default it to.
        ReadCli::try_parse_from(["yaam-read", "correlate"])
            .expect_err("a correlation has to say what nearby means");
        ReadCli::try_parse_from(["yaam-read", "correlate", "--within-ms", "1000"])
            .expect("the window is refused when the request is built, naming the flag");
        // The unprefixed filters belong to the other read: a correlation has two sides, and
        // `--action` would not say which of them it meant.
        ReadCli::try_parse_from([
            "yaam-read",
            "correlate",
            "--within-ms",
            "1000",
            "--action",
            "deploy",
        ])
        .expect_err("a correlation filters a side, not the request");
    }

    /// Each knowledge command demands what only it needs, and the group defaults to nothing.
    ///
    /// A default would be the wrong one either way round: `knowledge` defaulting to a build would
    /// rewrite a tree somebody meant to read, and defaulting to a read would answer out of a tree
    /// nobody had built.
    #[test]
    fn every_knowledge_command_is_its_own_subcommand_with_its_own_requirements() {
        OperatorCli::try_parse_from(["yaam", "knowledge"])
            .expect_err("no default: one of these writes the tree the others read");
        OperatorCli::try_parse_from(["yaam", "knowledge", "build"]).expect("a build takes nothing");
        OperatorCli::try_parse_from(["yaam", "knowledge", "status"]).expect("nor does a status");
        OperatorCli::try_parse_from(["yaam", "knowledge", "note"])
            .expect_err("a note has to name the entity it is about");
        OperatorCli::try_parse_from(["yaam", "knowledge", "note", "--entity", "ticket:PROJ-42"])
            .expect("parsed");
        OperatorCli::try_parse_from(["yaam", "knowledge", "search"])
            .expect_err("a search for nothing is not a search for everything");
        OperatorCli::try_parse_from(["yaam", "knowledge", "search", "--query", "staging"])
            .expect("the cap has a default, so a listing needs only its term");
        OperatorCli::try_parse_from(["yaam", "knowledge", "evidence"])
            .expect_err("evidence for no record is not evidence for every record");
        OperatorCli::try_parse_from([
            "yaam",
            "knowledge",
            "evidence",
            "--record",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ])
        .expect("parsed");
    }

    /// The store flags sit above the subcommands, so `knowledge` inherits `--root` and has to: it
    /// derives from the record tree, and a tree it could not be pointed at would derive nothing.
    #[test]
    fn a_knowledge_command_takes_the_root_the_other_operator_commands_take() {
        let cli =
            OperatorCli::try_parse_from(["yaam", "--root", "/srv/memory", "knowledge", "build"])
                .expect("parsed");
        assert_eq!(cli.store.root.as_deref(), Some(Path::new("/srv/memory")));
        assert!(matches!(
            cli.command,
            Command::Knowledge {
                what: KnowledgeCommand::Build
            }
        ));
    }

    /// The property that a resolver does not relax: a caller cannot declare a record erasable. A
    /// `--subject` would put a pseudonym on a host that holds no keying secret to derive one with,
    /// and the help is where a reader finds out why there is none.
    #[test]
    fn the_emitter_offers_no_way_to_name_a_subject() {
        let help = EmitCli::command().render_long_help().to_string();
        assert!(!help.contains("--subject"), "{help}");
        assert!(!help.contains("--data-class"), "{help}");
        assert!(help.contains("Subjects stay empty"), "{help}");
    }

    /// The three that only the caller can answer are required, so a record cannot be written without
    /// saying what happened or how it went.
    #[test]
    fn what_only_the_caller_knows_is_required() {
        EmitCli::try_parse_from(["yaam-emit"]).expect_err("no action, outcome or summary");
        EmitCli::try_parse_from(["yaam-emit", "--action", "deploy"])
            .expect_err("an action with no outcome");
        EmitCli::try_parse_from([
            "yaam-emit",
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "shipped it",
        ])
        .expect("everything mechanical is filled in, so this is enough");
    }

    /// An outcome nobody can report is a usage error, not a record that stores the typo.
    #[test]
    fn an_outcome_outside_the_contract_is_refused() {
        EmitCli::try_parse_from([
            "yaam-emit",
            "--action",
            "deploy",
            "--outcome",
            "probably",
            "--summary",
            "shipped it",
        ])
        .expect_err("`probably` is not an outcome the contract has");
    }

    /// Each repeatable flag collects rather than replacing, or a caller naming three entities would
    /// silently record one.
    #[test]
    fn the_repeatable_flags_collect() {
        let cli = EmitCli::try_parse_from([
            "yaam-emit",
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "shipped it",
            "--attr",
            "service=api",
            "--attr",
            "environment=staging",
            "--entity",
            "deploy:api/staging#1",
            "--entity",
            "ticket:PROJ-42",
            "--tag",
            "release",
            "--tag",
            "rollout",
        ])
        .expect("parsed");
        assert_eq!(cli.args.attrs.len(), 2);
        assert_eq!(cli.args.entities.len(), 2);
        assert_eq!(cli.args.tags.len(), 2);
    }

    #[test]
    fn the_destructive_command_needs_its_own_flag_to_be_meant() {
        let unconfirmed =
            OperatorCli::try_parse_from(["yaam", "--root", "/x", "erase", "--subject", "s_00"])
                .expect("parsed");
        assert!(matches!(
            unconfirmed.command,
            Command::Erase {
                confirm_destroy_keys: false,
                ..
            }
        ));

        let confirmed = OperatorCli::try_parse_from([
            "yaam",
            "--root",
            "/x",
            "erase",
            "--subject",
            "s_00",
            "--confirm-destroy-keys",
        ])
        .expect("parsed");
        assert!(matches!(
            confirmed.command,
            Command::Erase {
                confirm_destroy_keys: true,
                ..
            }
        ));
    }

    /// The other command that acts on one confirmation, held to the same shape.
    ///
    /// A read of a sealed body is not undoable either: the audit record naming whoever read it is
    /// permanent. So the flag is the same kind of statement `erase`'s is, and a default that meant
    /// it would be a body printed by somebody who was only looking.
    #[test]
    fn reading_a_sealed_body_needs_its_own_flag_to_be_meant() {
        let unconfirmed = OperatorCli::try_parse_from([
            "yaam",
            "--root",
            "/x",
            "unseal",
            "--record",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--operator",
            "operator_a",
            "--reason",
            "a subject asked what is retained",
        ])
        .expect("parsed");
        assert!(matches!(
            unconfirmed.command,
            Command::Unseal {
                confirm_read_body: false,
                ..
            }
        ));

        // Neither the operator nor the reason has a default: an audit line with nobody's name on it,
        // for no stated purpose, answers neither question anybody asks of the trail.
        for missing in [
            vec![
                "--record",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--operator",
                "operator_a",
            ],
            vec!["--record", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "--reason", "why"],
            vec!["--operator", "operator_a", "--reason", "why"],
        ] {
            let mut args = vec!["yaam", "--root", "/x", "unseal"];
            args.extend(missing.iter().copied());
            OperatorCli::try_parse_from(&args).expect_err(&format!("{args:?} is incomplete"));
        }
    }

    #[test]
    fn a_command_is_required_rather_than_defaulted() {
        OperatorCli::try_parse_from(["yaam", "--root", "/x"])
            .expect_err("no default command: the destructive one is in this list");
    }

    #[test]
    fn a_repeated_socket_flag_collects() {
        let cli = AgentCli::try_parse_from([
            "yaam-agent",
            "--socket",
            "a=/run/a.sock",
            "--socket",
            "b=/run/b.sock",
        ])
        .expect("parsed");
        assert_eq!(cli.args.sockets.len(), 2);
    }
}
