//! The argument surface of all three binaries.
//!
//! One file, because the three have to agree. [`StoreArgs`] is flattened into the service and the
//! operator command line, so `--root` is one declaration with one default and one help string — not
//! two that drift until a rebuild addresses a different store than the service reads.
//!
//! The sidecar has no [`StoreArgs`], and that is a decision rather than an omission: it never opens
//! the tree, the index or the key store. Handing it those flags would invite a deployment to point
//! it somewhere, and the answer to where it points is "nowhere".

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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

/// Operate a memory store: rebuild the index, erase a subject, copy it, read its health.
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
    /// Read the store's health: schema version, index drift, sweeper backlog, quarantine depth.
    ///
    /// The first command to run when something looks wrong.
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
    /// Restore a backup into this store, then rebuild the index.
    ///
    /// The rebuild is part of the command rather than a step to remember: restored files can be
    /// older than the sweeper's own scan bound, and the rebuild is also what replays the restored
    /// tombstone log so a backup cannot resurrect erased structure. Refuses a store that already
    /// holds records — a restore is not a merge.
    Restore {
        /// Directory holding the backup.
        #[arg(long = "from", value_name = "PATH")]
        from: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{AgentCli, Command, OperatorCli, ServerCli};
    use crate::exit::Exit;

    /// The codes are only an interface if they are published where a reader looks.
    #[test]
    fn every_help_lists_the_exit_codes() {
        let rendered = [
            OperatorCli::command().render_long_help().to_string(),
            ServerCli::command().render_long_help().to_string(),
            AgentCli::command().render_long_help().to_string(),
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
    /// store — and on neither the sidecar, which opens none.
    #[test]
    fn the_store_flags_are_on_the_two_binaries_that_open_a_store() {
        let operator = OperatorCli::command().render_long_help().to_string();
        let server = ServerCli::command().render_long_help().to_string();
        let agent = AgentCli::command().render_long_help().to_string();
        for flag in ["--root", "--index", "--key-store"] {
            assert!(operator.contains(flag), "yaam is missing {flag}");
            assert!(server.contains(flag), "yaam-server is missing {flag}");
            assert!(
                !agent.contains(flag),
                "the sidecar opens no store, so {flag} must not be offered"
            );
        }
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
