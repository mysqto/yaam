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
/// Everything mechanical is filled in here: the identifier, both timestamps, the schema version,
/// `backfilled: false` and the empty collections. What is left to say is what only the caller knows.
///
/// This binary opens no store, and has no flag that could point it at one. It writes one JSON line
/// to a sidecar socket and reads one back; the sidecar is what seals, signs and spools. A caller
/// posting to the service directly would need the service's own key and would lose the spool with
/// it, which is the difference between a record that waits out an outage and one that is gone.
///
/// Subjects stay empty and the data class stays `internal`. What a subject *is* — how a person
/// becomes a pseudonym, and under whose canonicalisation — is still an open decision, and a flag
/// inviting one would let a caller declare a record erasable that this deployment cannot erase.
/// A subject resolver is what will fill them in when that is settled, not an argument here.
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
    /// describe references *inferred* from prose, which are the extractor's to produce.
    #[arg(long = "entity", value_name = "KIND:ID")]
    pub entities: Vec<String>,
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
/// Subcommands rather than one flat set of flags, because the four are four questions and not four
/// filters on one. `--query` is required for a search and meaningless to a bundle; `--entity` names
/// exactly one entity for a history and any number for a bundle; a window narrows a records query
/// and is not a parameter of the others. Flattened together, every one of those would be accepted
/// here and refused a round trip later — the service answers an unknown parameter with `400` rather
/// than ignoring it — and `--help` would describe a request surface that does not exist.
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
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{AgentCli, Command, EmitCli, OperatorCli, ReadCli, ServerCli};
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
        ReadCli::try_parse_from(["yaam-read"]).expect_err("no default read: there are four");
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
    }

    /// The decision that stays open has to stay open in the argument surface too. A `--subject`
    /// would let a caller declare a record erasable under a canonicalisation nobody has chosen, and
    /// the help is where a reader finds out why there is none.
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
