//! The five entry points, and the configuration all of them agree on.
//!
//! Everything lives here rather than in the `main.rs` files for one reason: a binary-only crate
//! cannot be unit tested, and the interesting parts of a command-line tool — what it accepts, what
//! it refuses, what it prints and what it exits with — are exactly the parts worth testing. Each
//! `main` is one statement.
//!
//! # The five
//!
//! | Binary | What it is |
//! |---|---|
//! | `yaam-server` | The HTTP service, plus the maintenance its store needs. |
//! | `yaam-agent` | The local sidecar: two sockets per caller, sealing and signing on their behalf. |
//! | `yaam` | The operator command line: rebuild, drain, erase, verify, read a sealed body, back up, restore, recover a key store, read health, guard a commit, derive knowledge. |
//! | `yaam-emit` | One record, built from arguments and written to a caller socket. |
//! | `yaam-read` | One read, sent to a caller read socket; the service's answer, unchanged. |
//!
//! One crate, because the first two open the same store and have to agree about where it is. Two
//! crates would be two argument parsers, and the first setting one of them spelled differently would
//! be a service reading an index that nothing writes — which is a failure with no symptom except
//! empty answers.
//!
//! `yaam-emit` and `yaam-read` are here for the neighbouring reason. Neither opens a store at all,
//! but both report the same [`exit`] codes, and a crate of their own would be a second copy of that
//! table. They are binaries rather than `yaam emit` and `yaam read` subcommands because the operator
//! command line flattens [`cli::StoreArgs`] above its subcommands, so either would offer `--root`
//! however little it did with one — and a flag inviting a caller to open the memory tree is
//! precisely what the sidecar exists to make unnecessary.
//!
//! The cost is that the sidecar, the emitter and the reader link what the service links. It is worth
//! naming: all three run on the caller's host, and smaller ones would be better. If that footprint
//! ever matters more than the agreement does, the split to make is [`config`] into a leaf crate of
//! its own — not five copies of it.
//!
//! # Where the logic is
//!
//! Not here. Every judgement these binaries appear to make is a library call:
//! [`yaam_core::reindex::reindex_all`], [`yaam_core::drain`], [`yaam_core::erase`],
//! [`yaam_core::backup`], [`yaam_core::backup::excluded_paths`] behind [`guard`],
//! [`yaam_core::unseal::read_body`],
//! [`yaam_core::health::check`], [`yaam_knowledge::rebuild`], [`yaam_agent::listener::serve_until`],
//! [`yaam_server::routes::router`]. What is here is argument parsing, refusals that belong before
//! anything starts, signal handling, rendering and exit codes.

#![forbid(unsafe_code)]

pub mod agent;
pub mod cli;
pub mod config;
pub mod emit;
pub mod error;
pub mod exit;
pub mod guard;
pub mod infer;
pub mod keyring;
pub mod knowledge;
pub mod ops;
pub mod read;
pub mod server;
pub mod unseal;

#[cfg(test)]
mod fixtures;

use std::ffi::OsString;
use std::io::Write;

use clap::Parser;

use crate::cli::{AgentCli, Command, EmitCli, OperatorCli, ReadCli, ServerCli};
use crate::config::{
    AgentSettings, EmitSettings, Env, ReadSettings, ServerSettings, StoreSettings,
};
use crate::error::Result;
use crate::exit::Exit;

pub use error::Error;

/// Runs the operator command line, and returns the process exit code.
#[must_use]
pub fn operator<I, T>(args: I, env: &Env, out: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match parsed::<OperatorCli, _, _>(args) {
        Ok(cli) => report("yaam", run_operator(&cli, env, out)),
        Err(code) => code,
    }
}

/// Runs the service until interrupted, and returns the process exit code.
#[must_use]
pub fn service<I, T>(args: I, env: &Env) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match parsed::<ServerCli, _, _>(args) {
        Ok(cli) => {
            logging(env);
            report("yaam-server", run_service(&cli, env))
        }
        Err(code) => code,
    }
}

/// Writes one record to a caller socket, and returns the process exit code.
///
/// No logging subscriber, unlike the two long-running binaries. This is one exchange with one
/// answer: everything it has to say it says on its own output and in its exit code, and a hook that
/// found a second stream of prose on its stderr would be right to complain.
#[must_use]
pub fn emitter<I, T>(args: I, env: &Env, out: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match parsed::<EmitCli, _, _>(args) {
        Ok(cli) => report("yaam-emit", run_emitter(&cli, env, out)),
        Err(code) => code,
    }
}

/// Sends one read to a caller read socket, and returns the process exit code.
///
/// No logging subscriber, for the reason the emitter has none, and one more: this command's output
/// *is* the answer. A subscriber writing prose to stderr beside a JSON document on stdout would give
/// a caller two streams to tell apart where it asked for one.
#[must_use]
pub fn reader<I, T>(args: I, env: &Env, out: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match parsed::<ReadCli, _, _>(args) {
        Ok(cli) => report("yaam-read", run_reader(&cli, env, out)),
        Err(code) => code,
    }
}

/// Runs the sidecar until interrupted, and returns the process exit code.
#[must_use]
pub fn sidecar<I, T>(args: I, env: &Env) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match parsed::<AgentCli, _, _>(args) {
        Ok(cli) => {
            logging(env);
            report("yaam-agent", run_sidecar(&cli, env))
        }
        Err(code) => code,
    }
}

/// Parses arguments, printing clap's own report for `--help`, `--version` and a usage error.
///
/// `Err` is one of those three rather than a failure of the command, which is why it carries a code:
/// `--help` is a success and a bad flag is not, and which one it was is whether clap meant its report
/// for stderr.
fn parsed<C, I, T>(args: I) -> std::result::Result<C, i32>
where
    C: Parser,
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    C::try_parse_from(args).map_err(|report| {
        let _ = report.print();
        if report.use_stderr() {
            Exit::Usage.code()
        } else {
            Exit::Ok.code()
        }
    })
}

/// Prints a failure and turns the outcome into an exit code.
fn report(binary: &str, outcome: Result<Exit>) -> i32 {
    match outcome {
        Ok(exit) => exit.code(),
        Err(error) => {
            eprintln!("{binary}: {error}");
            error.exit().code()
        }
    }
}

/// Installs a subscriber, so the library's own warnings reach somebody.
///
/// Failure is ignored on purpose: a subscriber is already installed, which happens when a test in
/// this crate runs two of these in one process. Nothing about the run depends on it.
fn logging(env: &Env) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(config::log_level(env))
        .with_writer(std::io::stderr)
        .try_init();
}

/// The operator command, once its arguments are known.
fn run_operator(cli: &OperatorCli, env: &Env, out: &mut dyn Write) -> Result<Exit> {
    // A restore returns before the store is opened, because its destination is not a store yet:
    // `spec/` arrives inside the backup, and the refusal that protects every other command — a root
    // carrying none — would refuse the very operation that installs one.
    if let Command::Restore { from } = &cli.command {
        let settings = StoreSettings::resolve_destination(&cli.store, env)?;
        return ops::restore(&settings.paths, from, out);
    }
    // The guard returns before one is opened for a different reason: it runs on every commit, from a
    // hook, and has no business touching an index. It reads the same lenient settings a restore
    // does, because a repository holding a backup and no `spec/` yet is exactly when the first
    // commit is made — and the first commit is the dangerous one.
    if let Command::GuardCommit {
        repo,
        paths,
        print_hook,
    } = &cli.command
    {
        let subject = guard::Subject::from_flags(repo.as_deref(), paths, *print_hook)?;
        if subject == guard::Subject::Hook {
            return guard::print_hook(out);
        }
        let settings = StoreSettings::resolve_destination(&cli.store, env)?;
        return guard::guard_commit(&settings.paths, &subject, out);
    }
    // Knowledge returns before one is opened because it needs none. It is derived from the Markdown
    // records and the cold manifests alone — no index row, no key, no queue — so opening a pipeline
    // here would put a build behind a failure it does not depend on, on exactly the store where a
    // build is most worth having. The strict resolve still applies: a root carrying no `spec/` is a
    // directory whose records would be an empty tree rather than a store with nothing in it.
    if let Command::Knowledge { what } = &cli.command {
        let settings = StoreSettings::resolve(&cli.store, env)?;
        return knowledge::run(&settings.paths.root, what, out);
    }

    let settings = StoreSettings::resolve(&cli.store, env)?;
    let mut pipeline = settings.open()?;
    match &cli.command {
        // `--all` changes nothing: a rebuild reads the whole tree either way. It is accepted because
        // the recovery procedures name it, and ignoring an unknown flag would be worse.
        Command::Reindex { all: _ } => ops::reindex(&mut pipeline, out),
        Command::Drain { max_jobs } => ops::drain(&mut pipeline, *max_jobs, out),
        Command::Erase {
            subject,
            confirm_destroy_keys,
        } => ops::erase(&mut pipeline, subject, *confirm_destroy_keys, out),
        Command::VerifyErasure { tombstone } => ops::verify_erasure(&mut pipeline, tombstone, out),
        Command::Unseal {
            record,
            operator,
            reason,
            confirm_read_body,
        } => unseal::unseal(
            &mut pipeline,
            record,
            operator,
            reason,
            *confirm_read_body,
            out,
        ),
        Command::Check => ops::check(&pipeline, out),
        Command::Backup { to } => ops::backup(&pipeline, to, out),
        // Unlike `restore`, this one opens the store first and has to: the erasure log it holds the
        // recovered key material to arrives with the tree, so a key store recovered into a directory
        // that is not a store yet has nothing to be held to. The strict resolve is what says so.
        Command::RestoreKeys {
            from,
            confirm_restore_keys,
        } => ops::restore_keys(&mut pipeline, from, *confirm_restore_keys, out),
        Command::Restore { .. } | Command::GuardCommit { .. } | Command::Knowledge { .. } => {
            unreachable!("all three return before the store is opened")
        }
    }
}

/// The service, once its arguments are known.
fn run_service(cli: &ServerCli, env: &Env) -> Result<Exit> {
    let settings = ServerSettings::resolve(&cli.args, env)?;
    runtime()?.block_on(async {
        let bound = server::bind(&settings).await?;
        server::serve(bound, yaam_agent::listener::interrupted()).await?;
        Ok(Exit::Ok)
    })
}

/// One record, once its arguments are known.
///
/// A `--dry-run` still resolves the socket and the agent. The agent is part of the record it prints,
/// and refusing the same misconfiguration a real send would refuse is what makes the dry run worth
/// having: one that succeeded where the send would fail would be a rehearsal of a different play.
fn run_emitter(cli: &EmitCli, env: &Env, out: &mut dyn Write) -> Result<Exit> {
    let settings = EmitSettings::resolve(&cli.args, env)?;
    emit::emit(&settings, &cli.args, out)
}

/// One read, once its arguments are known.
///
/// Nothing is refused at the resolve, unlike the emitter, whose `--agent` is a field of the record
/// it prints and has to be known before one exists. Every setting here is about how the request
/// travels rather than what it asks, which is exactly why a dry run needs none of them.
fn run_reader(cli: &ReadCli, env: &Env, out: &mut dyn Write) -> Result<Exit> {
    let settings = ReadSettings::resolve(&cli.args, env);
    read::read(&settings, &cli.args, &cli.query, out)
}

/// The sidecar, once its arguments are known.
fn run_sidecar(cli: &AgentCli, env: &Env) -> Result<Exit> {
    let settings = AgentSettings::resolve(&cli.args, env)?;
    let planned = agent::plan(&settings)?;
    runtime()?.block_on(async {
        agent::serve(planned, yaam_agent::listener::interrupted()).await?;
        Ok(Exit::Ok)
    })
}

/// A runtime, built here rather than by an attribute on `main`.
///
/// `#[tokio::main]` would put the runtime in the binary, which is the one place a test cannot reach.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error::failed("starting a runtime", &error))
}

#[cfg(test)]
mod tests {
    use super::{Env, Exit, operator, service, sidecar};

    /// `--help` is a success, and a bad flag is a usage error. Both are clap's to print.
    #[test]
    fn help_succeeds_and_a_bad_flag_does_not() {
        let mut out = Vec::new();
        assert_eq!(
            operator(["yaam", "--help"], &Env::default(), &mut out),
            Exit::Ok.code()
        );
        assert_eq!(
            operator(["yaam", "--nonesuch"], &Env::default(), &mut out),
            Exit::Usage.code()
        );
        assert_eq!(
            operator(["yaam"], &Env::default(), &mut out),
            Exit::Usage.code(),
            "no subcommand: the destructive one is in the list, so nothing is defaulted"
        );
    }

    /// The other two binaries answer `--help` and a bad flag the same way, because a script that
    /// wraps all three should not have to learn which one it is talking to.
    #[test]
    fn the_service_and_the_sidecar_report_usage_the_same_way() {
        let env = Env::default();
        assert_eq!(service(["yaam-server", "--help"], &env), Exit::Ok.code());
        assert_eq!(service(["yaam-server", "--nope"], &env), Exit::Usage.code());
        assert_eq!(sidecar(["yaam-agent", "--help"], &env), Exit::Ok.code());
        assert_eq!(sidecar(["yaam-agent", "--nope"], &env), Exit::Usage.code());
    }

    /// Neither long-running binary starts on a misconfiguration, and neither blocks working it out.
    #[test]
    fn the_service_and_the_sidecar_refuse_a_misconfiguration_without_starting() {
        let env = Env::default();
        assert_eq!(service(["yaam-server"], &env), Exit::Config.code());
        assert_eq!(sidecar(["yaam-agent"], &env), Exit::Config.code());
    }

    /// A misconfiguration reaches the exit code, and nothing is opened.
    #[test]
    fn an_unset_root_is_a_config_exit() {
        let mut out = Vec::new();
        assert_eq!(
            operator(["yaam", "check"], &Env::default(), &mut out),
            Exit::Config.code()
        );
        assert!(out.is_empty(), "nothing was read, so nothing is reported");
    }

    /// The whole operator path, end to end, over a real tree.
    #[test]
    fn a_rebuild_and_a_check_run_against_a_real_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        crate::fixtures::copy_dir(&spec, &dir.path().join("spec"));
        let root = dir.path().to_str().expect("utf-8 path");

        let mut out = Vec::new();
        assert_eq!(
            operator(
                ["yaam", "--root", root, "reindex", "--all"],
                &Env::default(),
                &mut out
            ),
            Exit::Ok.code()
        );
        let printed = String::from_utf8_lossy(&out).into_owned();
        assert!(printed.contains("from the tree       0"), "{printed}");

        let mut out = Vec::new();
        assert_eq!(
            operator(["yaam", "--root", root, "check"], &Env::default(), &mut out),
            Exit::Ok.code()
        );
        assert!(String::from_utf8_lossy(&out).contains("index drift        0"));
    }

    /// A knowledge build runs over a store whose index has never existed.
    ///
    /// The reason these commands return before the pipeline is opened, asserted where it can
    /// actually fail: the tree here carries a `spec/` and nothing else, so a build that had gone
    /// through the open would have had to create an index it never reads.
    #[test]
    fn a_knowledge_build_runs_without_an_index_and_a_read_follows_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        crate::fixtures::copy_dir(&spec, &dir.path().join("spec"));
        let root = dir.path().to_str().expect("utf-8 path");

        let mut out = Vec::new();
        assert_eq!(
            operator(
                ["yaam", "--root", root, "knowledge", "build"],
                &Env::default(),
                &mut out
            ),
            Exit::Ok.code()
        );
        let printed = String::from_utf8_lossy(&out).into_owned();
        assert!(printed.contains("records read        0"), "{printed}");
        assert!(!dir.path().join("index.sqlite").exists(), "{printed}");

        // And the build is what makes the read answer at all: before one, there is no state to read.
        let mut out = Vec::new();
        assert_eq!(
            operator(
                ["yaam", "--root", root, "knowledge", "status"],
                &Env::default(),
                &mut out
            ),
            Exit::Ok.code()
        );
        assert!(String::from_utf8_lossy(&out).contains("records read        0"));
    }

    /// The root can come from the environment instead of a flag.
    #[test]
    fn the_environment_supplies_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        crate::fixtures::copy_dir(&spec, &dir.path().join("spec"));
        let env = Env {
            root: Some(dir.path().as_os_str().to_owned()),
            ..Env::default()
        };

        let mut out = Vec::new();
        assert_eq!(operator(["yaam", "check"], &env, &mut out), Exit::Ok.code());
    }
}
