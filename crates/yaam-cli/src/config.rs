//! Configuration, resolved once and shared.
//!
//! Two layers, in one order everywhere: a flag beats an environment variable, and an absent setting
//! either has a documented default or is a refusal. There is no third layer and no config file for
//! the store settings — the tree already carries its own configuration in `spec/`, and a second
//! place to say where the tree is would be a second place for the answer to be wrong.
//!
//! The environment arrives as a value rather than being read where it is needed. That is not
//! decoration: `std::env::set_var` is `unsafe` and this workspace forbids unsafe, so a test cannot
//! set a variable — which means precedence is only testable if reading the environment is one thin
//! function at the edge and everything below it takes an [`Env`].
//!
//! [`StoreSettings`] is shared by the service and the operator command line because they address
//! the same store; the sidecar does not have it, and must not. A sidecar never opens the tree, the
//! index or the key store — that is the whole reason a caller can hold no keys — so giving it those
//! settings would be inviting a deployment to point it at a store it has no business touching.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yaam_core::Paths;
use yaam_core::arming::Arming;
use yaam_core::resolve::{ReferenceSubjects, SubjectKinds};
use yaam_crypto::custody::{SubjectKeyFile, SubjectKeySource};
use yaam_crypto::subject::SubjectKey;

use crate::cli::{AgentArgs, EmitArgs, ReadArgs, ServerArgs, StoreArgs};
use crate::error::{Error, Result, config, failed};

/// Environment variable naming the memory tree root.
pub const ENV_ROOT: &str = "YAAM_ROOT";
/// Environment variable naming the derived index.
pub const ENV_INDEX: &str = "YAAM_INDEX";
/// Environment variable naming the key store root.
pub const ENV_KEY_STORE: &str = "YAAM_KEY_STORE";

/// Environment variable naming the file that holds the key-wrapping passphrase.
pub const ENV_KEY_PASSPHRASE_FILE: &str = "YAAM_KEY_PASSPHRASE_FILE";
/// Environment variable naming the file that holds the subject-pseudonym secret.
pub const ENV_SUBJECT_KEY_FILE: &str = "YAAM_SUBJECT_KEY_FILE";
/// Environment variable naming the address the service listens on.
pub const ENV_LISTEN: &str = "YAAM_LISTEN";
/// Environment variable naming the keyring file.
pub const ENV_KEYRING: &str = "YAAM_KEYRING";
/// Environment variable naming the file holding the service's sealing secret key.
pub const ENV_UNSEAL_KEY: &str = "YAAM_UNSEAL_KEY_FILE";
/// Environment variable setting how often the service runs maintenance, in milliseconds.
pub const ENV_MAINTENANCE_MS: &str = "YAAM_MAINTENANCE_MS";
/// Environment variable naming the sidecar's state directory.
pub const ENV_AGENT_STATE: &str = "YAAM_AGENT_STATE";
/// Environment variable naming the caller socket an emitted record is written to.
pub const ENV_SOCKET: &str = "YAAM_SOCKET";
/// Environment variable naming the agent an emitted record is attributed to.
///
/// The pair above and here is what makes a one-line hook possible: a host that exports both leaves
/// the caller with only what it alone knows to say.
pub const ENV_AGENT: &str = "YAAM_AGENT";
/// Environment variable naming the caller socket reads are sent to.
///
/// Its own variable rather than a derivation from [`ENV_SOCKET`]: that one is documented as naming
/// the record socket, and a reader that guessed the read socket from it would send HTTP into the
/// newline-JSON protocol whenever the guess was wrong. The sidecar does derive one path from the
/// other, and the help says how, so a host exporting both is exporting two spellings of one fact
/// rather than two settings.
pub const ENV_READ_SOCKET: &str = "YAAM_READ_SOCKET";
/// Environment variable setting the log level.
pub const ENV_LOG: &str = "YAAM_LOG";

/// Address the service listens on when nothing names one.
///
/// Loopback, not `0.0.0.0`. Every request is signed, but a default that is reachable from the
/// network is a deployment exposed by omission rather than by decision.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";

/// How often the service does the maintenance its store needs, when nothing names an interval.
///
/// Seconds rather than milliseconds: both halves are idempotent and bounded, and neither is on the
/// path of a request. What it costs to be late is that an entity timeline appears a moment after the
/// record it describes — those files are derived views, and a reader that needs the record itself
/// has the index.
///
/// Settable at all because the wait is the whole cost of a test that asserts convergence, and a
/// figure chosen for a deployment is the wrong one for a test.
pub const DEFAULT_MAINTENANCE_MS: u64 = 30_000;

/// The environment as the process found it.
///
/// One field per variable this workspace reads, so what is consulted is a list rather than a habit.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// [`ENV_ROOT`].
    pub root: Option<OsString>,
    /// [`ENV_INDEX`].
    pub index: Option<OsString>,
    /// [`ENV_KEY_STORE`].
    pub key_store: Option<OsString>,
    /// `YAAM_KEY_PASSPHRASE_FILE`.
    pub key_passphrase_file: Option<OsString>,
    /// [`ENV_SUBJECT_KEY_FILE`].
    pub subject_key_file: Option<OsString>,
    /// [`ENV_LISTEN`].
    pub listen: Option<OsString>,
    /// [`ENV_KEYRING`].
    pub keyring: Option<OsString>,
    /// [`ENV_UNSEAL_KEY`].
    pub unseal_key_file: Option<OsString>,
    /// [`ENV_MAINTENANCE_MS`].
    pub maintenance_ms: Option<OsString>,
    /// [`ENV_AGENT_STATE`].
    pub agent_state: Option<OsString>,
    /// [`ENV_SOCKET`].
    pub socket: Option<OsString>,
    /// [`ENV_AGENT`].
    pub agent: Option<OsString>,
    /// [`ENV_READ_SOCKET`].
    pub read_socket: Option<OsString>,
    /// [`ENV_LOG`].
    pub log: Option<OsString>,
}

impl Env {
    /// Reads every variable this workspace understands.
    ///
    /// The only place the process environment is touched. Everything below takes the result, which
    /// is what makes precedence testable at all.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            root: std::env::var_os(ENV_ROOT),
            index: std::env::var_os(ENV_INDEX),
            key_store: std::env::var_os(ENV_KEY_STORE),
            key_passphrase_file: std::env::var_os(ENV_KEY_PASSPHRASE_FILE),
            subject_key_file: std::env::var_os(ENV_SUBJECT_KEY_FILE),
            listen: std::env::var_os(ENV_LISTEN),
            keyring: std::env::var_os(ENV_KEYRING),
            unseal_key_file: std::env::var_os(ENV_UNSEAL_KEY),
            maintenance_ms: std::env::var_os(ENV_MAINTENANCE_MS),
            agent_state: std::env::var_os(ENV_AGENT_STATE),
            socket: std::env::var_os(ENV_SOCKET),
            agent: std::env::var_os(ENV_AGENT),
            read_socket: std::env::var_os(ENV_READ_SOCKET),
            log: std::env::var_os(ENV_LOG),
        }
    }
}

/// Where this deployment's store is.
///
/// Held by the service and the operator command line alike, resolved by the same function, so a
/// rebuild run from the command line addresses the file the service is reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSettings {
    /// The paths the pipeline will work over.
    pub paths: Paths,
    /// Where the wrapping passphrase is read from, if key material is protected at all.
    pub key_passphrase_file: Option<PathBuf>,
    /// Where the subject-pseudonym secret is read from, if this store keys erasure on anything.
    ///
    /// The path, never the secret. These settings are cloned into the startup log's own description
    /// and into every error that names the configuration, so the bytes are read at [`StoreSettings::open`]
    /// and go straight into the resolver that holds them.
    ///
    /// A path is also what selects a custody backend — [`SubjectKeyFile`], the only one that ships.
    /// Custody held by a keychain or a key service is a *different setting* beside this one rather
    /// than a second meaning for this one, so a deployment that names a file keeps naming a file.
    pub subject_key_file: Option<PathBuf>,
}

impl StoreSettings {
    /// Resolves the store settings from flags and the environment.
    ///
    /// Refuses rather than guessing. A root that is absent, is not a directory, or carries no
    /// `spec/` is a deployment that would come up and reject every record it was sent — with the
    /// reason arriving one write at a time, at the caller, hours later.
    pub fn resolve(flags: &StoreArgs, env: &Env) -> Result<Self> {
        let root = Self::root(flags, env)?;
        if !root.is_dir() {
            return Err(config(format!(
                "--root {} is not a directory",
                root.display()
            )));
        }
        if !root.join("spec").is_dir() {
            return Err(config(format!(
                "--root {} carries no spec/: a memory tree holds its own entity kinds, attribute \
                 schema and redaction policy, and one without them rejects every record",
                root.display()
            )));
        }
        Self::paths_of(root, flags, env)
    }

    /// Resolves the settings for a restore destination.
    ///
    /// The one place the refusals above are wrong. A restore's destination is not a store yet: it
    /// may not exist, and its `spec/` arrives inside the backup — so demanding one here would refuse
    /// exactly the operation that installs it. Everything else about the destination is checked by
    /// the restore itself, which refuses a directory already holding records.
    pub fn resolve_destination(flags: &StoreArgs, env: &Env) -> Result<Self> {
        let root = Self::root(flags, env)?;
        if root.exists() && !root.is_dir() {
            return Err(config(format!(
                "--root {} is not a directory",
                root.display()
            )));
        }
        Self::paths_of(root, flags, env)
    }

    /// The root a flag or the environment names.
    fn root(flags: &StoreArgs, env: &Env) -> Result<PathBuf> {
        pick(flags.root.as_deref(), env.root.as_deref()).ok_or_else(|| {
            config(format!(
                "the memory tree root is not set: pass --root or set {ENV_ROOT}"
            ))
        })
    }

    /// The rest of the settings, once the root is settled.
    fn paths_of(root: PathBuf, flags: &StoreArgs, env: &Env) -> Result<Self> {
        let mut paths = Paths::under(root);
        if let Some(index) = pick(flags.index.as_deref(), env.index.as_deref()) {
            if index.is_dir() {
                return Err(config(format!(
                    "--index {} is a directory; it names the index file itself",
                    index.display()
                )));
            }
            paths = paths.with_index(index);
        }
        if let Some(key_store) = pick(flags.key_store.as_deref(), env.key_store.as_deref()) {
            paths = paths.with_key_store(key_store);
        }
        let key_passphrase_file = pick(
            flags.key_passphrase_file.as_deref(),
            env.key_passphrase_file.as_deref(),
        );
        let subject_key_file = pick(
            flags.subject_key_file.as_deref(),
            env.subject_key_file.as_deref(),
        );
        Ok(Self {
            paths,
            key_passphrase_file,
            subject_key_file,
        })
    }

    /// Opens the pipeline these settings describe.
    ///
    /// An index a newer build wrote gets its own message rather than the store's. The writer refuses
    /// it — a reader that migrated would be a second writer — and the remedy is outside this process:
    /// run the build that wrote it, or delete the index and rebuild from the tree.
    pub fn open(&self) -> Result<yaam_core::Pipeline> {
        let pipeline = self.open_unwrapped()?;
        let pipeline = match &self.key_passphrase_file {
            None => pipeline,
            Some(path) => {
                let wrapper = Self::wrapper(path)?;
                pipeline
                    .with_key_wrapper(wrapper)
                    .map_err(|error| failed("fitting the key wrapper", &error))?
            }
        };
        self.with_subject_resolver(pipeline)
    }

    /// The entity kinds this store keys erasure on, or `None` if it keys erasure on nothing.
    ///
    /// Read from the tree each time rather than cached on these settings, because that is where the
    /// declaration lives and a copy of it here would be a second answer to go stale.
    ///
    /// # Errors
    /// A `spec/subjects.yaml` that will not load, in the shape [`SubjectKinds::load`] reports one.
    pub fn erasure_units(&self) -> Result<Option<SubjectKinds>> {
        SubjectKinds::load(&self.paths.root)
            .map_err(|error| failed("reading spec/subjects.yaml", &error))
    }

    /// Fits the resolver this store's `spec/subjects.yaml` asks for, or holds the two halves apart.
    ///
    /// Both halves or neither, refused rather than degraded, because each half alone is a deployment
    /// that believes something untrue about itself. A declaration with no secret is a store that
    /// cannot key the records it says are erasure units, and would say so one refused write at a
    /// time; a secret with no declaration is an operator who believes bodies are being sealed while
    /// every one of them is written in the clear — into the tree, the cold manifests and every
    /// backup, where no later decision can reach them.
    ///
    /// Neither half is the shipped state, and it leaves the store exactly as it was before any of
    /// this existed: no subject resolves, nothing is sealed.
    fn with_subject_resolver(&self, pipeline: yaam_core::Pipeline) -> Result<yaam_core::Pipeline> {
        let declared = SubjectKinds::load(&self.paths.root)
            .map_err(|error| failed("reading spec/subjects.yaml", &error))?;
        match (declared, &self.subject_key_file) {
            (None, None) => Ok(pipeline),
            (None, Some(path)) => Err(config(format!(
                "--subject-key-file {} is set and {}/spec/{} declares no erasure units, so nothing \
                 would be sealed: remove the flag, or declare the entity kinds this store keys \
                 erasure on",
                path.display(),
                self.paths.root.display(),
                SubjectKinds::SPEC_FILE
            ))),
            (Some(kinds), None) => Err(config(format!(
                "{}/spec/{} keys erasure on {}, and no --subject-key-file is set: this process \
                 cannot derive a pseudonym, so it would refuse every subject-derived record it was \
                 sent. Pass the flag or set {ENV_SUBJECT_KEY_FILE}",
                self.paths.root.display(),
                SubjectKinds::SPEC_FILE,
                kinds.kinds().join(", ")
            ))),
            (Some(kinds), Some(path)) => {
                // The one place a custody backend is chosen. A second one — a keychain, a key
                // service — is a second setting resolved above and a second arm here, and nothing
                // below this line learns which of them answered: `subject_key` takes the trait and
                // the pipeline takes the key. Fetching an unrotatable key is not a thing to be
                // changing once a store has sealed records under it.
                let source = SubjectKeyFile::at(path);
                let setting = format!("--subject-key-file {}", path.display());
                let key = Self::subject_key(&source, &setting)?;
                Self::armed(&self.paths.root, &key, &setting)?;
                tracing::info!(
                    kinds = kinds.kinds().join(", "),
                    custody = source.custody(),
                    "erasure is keyed on the references records state"
                );
                Ok(pipeline.with_subject_resolver(ReferenceSubjects::new(kinds, key)))
            }
        }
    }

    /// Fetches the subject-pseudonym secret from `source`, or refuses to start.
    ///
    /// Takes the trait rather than a backend so a failure means one thing whatever the custody is:
    /// the process does not come up. There is no retry above this and no degraded mode to fall into —
    /// a service that started without the key would refuse every subject-derived record it was sent,
    /// and the obvious remedy an operator would reach for is the one that writes bodies in the clear.
    ///
    /// `setting` is what an operator would change, which the source cannot know and this layer does:
    /// a source names its custody, a flag names itself. No message quotes what was read — a
    /// configuration error that did would put the secret into every log that captured the startup
    /// failure.
    fn subject_key(source: &dyn SubjectKeySource, setting: &str) -> Result<SubjectKey> {
        source
            .fetch()
            .map_err(|error| config(format!("{setting} does not hold a subject key: {error}")))
    }

    /// Holds the fetched key to the one this store's pseudonyms were already derived from.
    ///
    /// The check itself is `yaam_core::arming`'s, along with the argument for why a store records
    /// which key armed it and what that does and does not prove. What is decided here is what an
    /// operator is told and what it costs them, which is this layer's to decide for the reason
    /// [`StoreSettings::subject_key`] is: a source names its custody and a flag names itself.
    ///
    /// Three states, three log lines, because "the key was checked" and "the key was trusted" must
    /// not read alike. A store armed before any of this existed records nothing, adopts the key it
    /// is opened with, and comes up — the alternative would take exactly the deployments this
    /// protects down at the upgrade that introduced it.
    ///
    /// Two refusals, and their exit codes differ because the remedies do: a key that does not match
    /// is a setting to change ([`Exit::Config`](crate::exit::Exit::Config)), while a record that
    /// cannot be read is a file to restore, which no edit to a command line fixes.
    fn armed(root: &Path, key: &SubjectKey, setting: &str) -> Result<()> {
        let check = key.check_value();
        match yaam_core::arming::verify_or_arm(root, key) {
            Ok(Arming::Verified) => tracing::info!(
                check = %check,
                "the subject key is the one this store was armed with"
            ),
            Ok(Arming::Adopted) => tracing::warn!(
                check = %check,
                "this store recorded no subject key and now records this one: it was trusted at \
                 this open rather than verified, so compare the check value against the key you \
                 mean to keep"
            ),
            Ok(Arming::Unrecorded(why)) => tracing::warn!(
                check = %check,
                why = %why,
                "the subject key could not be recorded, so a later open cannot tell it from a \
                 substitute"
            ),
            Err(error) => {
                return Err(match &error {
                    yaam_core::Error::SubjectKeyMismatch { .. } => {
                        config(format!("{setting}: {error}"))
                    }
                    _ => failed("checking the subject key against the store", &error),
                });
            }
        }
        Ok(())
    }

    /// The wrapper the configured passphrase describes.
    ///
    /// Trailing newlines go, because a passphrase file written by `echo` and one written by a secret
    /// manager would otherwise derive two different keys from the same secret. Nothing else is
    /// trimmed: interior and leading whitespace is passphrase.
    fn wrapper(path: &Path) -> Result<yaam_crypto::wrapper::PassphraseWrapper> {
        let read = std::fs::read(path)
            .map_err(|e| config(format!("cannot read {}: {e}", path.display())))?;
        let passphrase = read.strip_suffix(b"\n").unwrap_or(&read);
        let passphrase = passphrase.strip_suffix(b"\r").unwrap_or(passphrase);
        if passphrase.is_empty() {
            return Err(config(format!(
                "{} is empty: a wrapper derived from nothing protects nothing",
                path.display()
            )));
        }
        yaam_crypto::wrapper::PassphraseWrapper::new(passphrase)
            .map_err(|error| failed("deriving the key-wrapping key", &error))
    }

    /// Opens the pipeline without fitting a wrapper.
    fn open_unwrapped(&self) -> Result<yaam_core::Pipeline> {
        yaam_core::Pipeline::with_paths(self.paths.clone()).map_err(|error| match &error {
            yaam_core::Error::Store(yaam_store::Error::SchemaTooNew { found, supported }) => {
                config(format!(
                    "the index at {} is at schema version {found} and this build reads up to \
                     {supported}: run the build that wrote it, or delete the index and rebuild from \
                     the tree",
                    self.paths.index.display()
                ))
            }
            _ => failed("opening the memory tree", &error),
        })
    }

    /// The effective settings, as one line per setting, for a startup log.
    ///
    /// Paths only. Nothing here may carry a key, a keyring entry or a signing secret — a startup log
    /// is the most widely copied text a deployment produces.
    #[must_use]
    pub fn describe(&self) -> Vec<(&'static str, String)> {
        vec![
            ("root", self.paths.root.display().to_string()),
            (
                "index",
                format!(
                    "{}{}",
                    self.paths.index.display(),
                    if self.paths.index_is_default() {
                        ""
                    } else {
                        " (relocated)"
                    }
                ),
            ),
            (
                "key-store",
                format!(
                    "{}{}",
                    self.paths.key_store.display(),
                    if self.paths.key_store_is_default() {
                        ""
                    } else {
                        " (relocated)"
                    }
                ),
            ),
            (
                "subject-key",
                match &self.subject_key_file {
                    Some(path) => path.display().to_string(),
                    None => "none: no body can be sealed".to_owned(),
                },
            ),
        ]
    }
}

/// Everything the service needs beyond the store.
#[derive(Debug, Clone)]
pub struct ServerSettings {
    /// Where the store is.
    pub store: StoreSettings,
    /// Address to accept on.
    pub listen: SocketAddr,
    /// The keyring file: which callers this service authenticates.
    pub keyring: PathBuf,
    /// File holding the secret half of the key sidecars seal to, hex encoded.
    ///
    /// `None` means this service accepts plain JSON only and refuses a sealed body. Legitimate for a
    /// deployment whose callers post directly, and a misconfiguration for one that runs sidecars —
    /// which is why the startup log says which of the two it is.
    pub unseal_key_file: Option<PathBuf>,
    /// How often the service runs the maintenance its store needs.
    pub maintenance: Duration,
}

impl ServerSettings {
    /// Resolves the service's settings from flags and the environment.
    pub fn resolve(flags: &ServerArgs, env: &Env) -> Result<Self> {
        let store = StoreSettings::resolve(&flags.store, env)?;
        let listen = pick_str(flags.listen.as_deref(), env.listen.as_deref())
            .unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
        let listen = listen.parse::<SocketAddr>().map_err(|error| {
            config(format!(
                "--listen {listen} is not an address as host:port ({error}); \
                 an IPv6 address needs brackets, as [::1]:8787"
            ))
        })?;
        let keyring = pick(flags.keyring.as_deref(), env.keyring.as_deref()).ok_or_else(|| {
            config(format!(
                "no keyring: pass --keyring or set {ENV_KEYRING}. A service without one \
                 authenticates nobody, so every request it received would be rejected"
            ))
        })?;
        Ok(Self {
            store,
            listen,
            keyring,
            unseal_key_file: pick(
                flags.unseal_key_file.as_deref(),
                env.unseal_key_file.as_deref(),
            ),
            maintenance: Self::maintenance(flags, env)?,
        })
    }

    /// How often maintenance runs: a flag, then the environment, then [`DEFAULT_MAINTENANCE_MS`].
    ///
    /// Only the environment half can fail to parse — clap has already refused a flag that is not a
    /// number — and an unreadable one is a refusal rather than a fall back to the default, because a
    /// deployment that set the interval and did not get it would be running on nobody's decision.
    fn maintenance(flags: &ServerArgs, env: &Env) -> Result<Duration> {
        // No flag layer in the `pick_str`: the flag is already a number, so only the text half is
        // left to pick and parse.
        let named = match flags.maintenance_ms {
            Some(ms) => Some(ms),
            None => pick_str(None, env.maintenance_ms.as_deref())
                .map(|text| {
                    text.trim().parse::<u64>().map_err(|error| {
                        config(format!(
                            "{ENV_MAINTENANCE_MS} {text} is not a count of milliseconds ({error})"
                        ))
                    })
                })
                .transpose()?,
        };
        let ms = named.unwrap_or(DEFAULT_MAINTENANCE_MS);
        if ms == 0 {
            return Err(config(
                "--maintenance-ms 0 would sweep the store in a tight loop, and the sweep walks the \
                 tree",
            ));
        }
        Ok(Duration::from_millis(ms))
    }
}

/// Everything the sidecar needs.
///
/// No store settings, deliberately: see this module's own note.
#[derive(Debug, Clone)]
pub struct AgentSettings {
    /// Directory holding `upstream.json` and the spool.
    pub state_dir: PathBuf,
    /// Sockets to serve, as `agent` and path. Empty means "one per configured signing key".
    pub sockets: Vec<(String, PathBuf)>,
    /// Spool bound, overriding the configuration file.
    pub spool_capacity: Option<usize>,
    /// Retry cadence, overriding the configuration file.
    pub retry_interval_ms: Option<u64>,
}

impl AgentSettings {
    /// Resolves the sidecar's settings from flags and the environment.
    pub fn resolve(flags: &AgentArgs, env: &Env) -> Result<Self> {
        let state_dir =
            pick(flags.state_dir.as_deref(), env.agent_state.as_deref()).ok_or_else(|| {
                config(format!(
                    "the sidecar state directory is not set: pass --state-dir or set \
                     {ENV_AGENT_STATE}"
                ))
            })?;
        if !state_dir.is_dir() {
            return Err(config(format!(
                "--state-dir {} is not a directory",
                state_dir.display()
            )));
        }
        let mut sockets = Vec::with_capacity(flags.sockets.len());
        for spec in &flags.sockets {
            sockets.push(socket_spec(spec)?);
        }
        if flags.spool_capacity == Some(0) {
            return Err(config(
                "--spool-capacity 0 would refuse every record the service cannot take right now",
            ));
        }
        if flags.retry_interval_ms == Some(0) {
            return Err(config(
                "--retry-interval-ms 0 would retry a down service in a tight loop",
            ));
        }
        Ok(Self {
            state_dir,
            sockets,
            spool_capacity: flags.spool_capacity,
            retry_interval_ms: flags.retry_interval_ms,
        })
    }
}

/// Where an emitted record goes, and who it is attributed to.
///
/// No store settings for the reason the sidecar has none, and one more: this runs in the caller's own
/// process tree, so a flag naming a tree would be a flag inviting a caller to open one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitSettings {
    /// The caller socket to write the record to, absent only for a dry run.
    ///
    /// Optional because a dry run sends nothing, and demanding a socket to print a record defeats the
    /// one thing a dry run is for: seeing the JSON before there is a sidecar to send it to.
    pub socket: Option<PathBuf>,
    /// The agent the record is attributed to. Must be the one the socket belongs to.
    pub agent: String,
}

impl EmitSettings {
    /// Resolves an emitter's settings from flags and the environment.
    ///
    /// Both are refusals rather than guesses. A default socket path would be a caller writing into
    /// a deployment it was never pointed at, and a default agent would be a record attributed to
    /// whoever the sidecar happened to serve.
    pub fn resolve(flags: &EmitArgs, env: &Env) -> Result<Self> {
        // Not refused here: a dry run has no socket to name, and the send path is where the
        // absence actually matters.
        let socket = pick(flags.socket.as_deref(), env.socket.as_deref());
        let agent = pick_str(flags.agent.as_deref(), env.agent.as_deref()).ok_or_else(|| {
            config(format!(
                "no agent: pass --agent or set {ENV_AGENT}. A record has to say who did the thing, \
                 and the sidecar refuses one naming an agent other than the socket's own"
            ))
        })?;
        if agent.trim().is_empty() {
            return Err(config(
                "--agent is blank: a record with no author attributes nothing",
            ));
        }
        Ok(Self { socket, agent })
    }
}

/// Where a read is sent.
///
/// One setting, and deliberately not two: there is no agent here. The read socket signs as the
/// caller it belongs to, so who is asking is a property of the socket rather than something a reader
/// gets to say, and a `--agent` would be an invitation to claim otherwise. No store settings either,
/// for the reason the emitter has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadSettings {
    /// The read socket to send the request to, absent only for a dry run.
    ///
    /// Optional for the reason [`EmitSettings::socket`] is: a dry run prints the request without
    /// sending it, and demanding the socket it would have gone to defeats the point of printing it.
    pub socket: Option<PathBuf>,
}

impl ReadSettings {
    /// Resolves a reader's settings from flags and the environment.
    ///
    /// The one resolve that cannot fail, and that is the whole shape of this binary. There is a
    /// single setting; it is refused at the send rather than here, because a dry run has none to
    /// name; and neither layer can supply a blank one — [`pick`] drops an empty variable, and `clap`
    /// refuses an empty path. The emitter's returns a [`Result`] because it also resolves an agent,
    /// which is a field of the record and has to be known before one can be built.
    #[must_use]
    pub fn resolve(flags: &ReadArgs, env: &Env) -> Self {
        Self {
            socket: pick(flags.socket.as_deref(), env.read_socket.as_deref()),
        }
    }
}

/// Parses one `agent=path` socket specification.
///
/// Split at the first `=`, because a path may contain one and an agent name may not: the contract's
/// agent names are identifiers, and splitting at the last `=` would put part of a path in the name.
fn socket_spec(spec: &str) -> Result<(String, PathBuf)> {
    let (agent, path) = spec.split_once('=').ok_or_else(|| {
        Error::Usage(format!(
            "--socket {spec} is not `agent=path`; the agent is what records from that socket are \
             attributed to"
        ))
    })?;
    if agent.is_empty() || path.is_empty() {
        return Err(Error::Usage(format!(
            "--socket {spec} needs both an agent and a path"
        )));
    }
    Ok((agent.to_owned(), PathBuf::from(path)))
}

/// The log level, from the environment, defaulting to `info`.
///
/// Read by hand rather than through a filter directive language: one level is what a binary of this
/// size needs, and an unparseable directive that silently disables logging is worse than no
/// configurability at all.
#[must_use]
pub fn log_level(env: &Env) -> tracing::Level {
    let named = env.log.as_ref().and_then(|value| value.to_str());
    match named.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("trace") => tracing::Level::TRACE,
        Some("debug") => tracing::Level::DEBUG,
        Some("warn") => tracing::Level::WARN,
        Some("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

/// A flag, or the environment, or nothing.
fn pick(flag: Option<&Path>, from_env: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    flag.map(Path::to_path_buf).or_else(|| {
        from_env
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

/// As [`pick`], for a setting that is text rather than a path.
fn pick_str(flag: Option<&str>, from_env: Option<&std::ffi::OsStr>) -> Option<String> {
    flag.map(str::to_owned).or_else(|| {
        from_env
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        AgentSettings, ENV_SUBJECT_KEY_FILE, Env, ServerSettings, StoreSettings, SubjectKeySource,
        SubjectKinds, log_level, socket_spec,
    };
    use crate::cli::{AgentArgs, ServerArgs, StoreArgs};
    use crate::exit::Exit;

    /// A tree that would pass the startup checks.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("spec")).expect("spec");
        dir
    }

    fn store_args(root: Option<&Path>) -> StoreArgs {
        StoreArgs {
            root: root.map(Path::to_path_buf),
            index: None,
            key_store: None,
            key_passphrase_file: None,
            subject_key_file: None,
        }
    }

    /// Store args naming a subject-key file.
    fn subject_key_args(root: &Path, file: &Path) -> StoreArgs {
        StoreArgs {
            subject_key_file: Some(file.to_path_buf()),
            ..store_args(Some(root))
        }
    }

    /// A tree that declares which entity kinds are erasure units, and a key file for them.
    fn keyed_tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tree();
        let spec = dir.path().join("spec");
        std::fs::write(
            spec.join("entities.yaml"),
            "version: 1\nkinds:\n  order_ref:\n    pattern: '^[a-z0-9]{8,24}$'\n",
        )
        .expect("written");
        std::fs::write(
            spec.join(SubjectKinds::SPEC_FILE),
            "version: 1\nkinds:\n  - order_ref\n",
        )
        .expect("written");
        let key = dir.path().join("subject.key");
        std::fs::write(&key, format!("{}\n", "5a".repeat(32))).expect("written");
        (dir, key)
    }

    /// The state every store is in until an operator decides otherwise: nothing declared, no secret,
    /// and a pipeline that resolves no subject and seals nothing.
    #[test]
    fn a_store_that_declares_no_erasure_units_needs_no_subject_key() {
        let dir = tree();
        let settings = StoreSettings::resolve(&store_args(Some(dir.path())), &Env::default())
            .expect("resolved");
        assert_eq!(settings.subject_key_file, None);
        settings.open().expect("opened, as it always did");
        assert!(
            settings
                .describe()
                .iter()
                .any(|(name, value)| *name == "subject-key" && value.starts_with("none")),
            "the startup log says which of the two states this is"
        );
    }

    #[test]
    fn a_declaration_and_a_key_together_open_the_store() {
        let (dir, key) = keyed_tree();
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        settings.open().expect("opened with a resolver fitted");
    }

    /// Half a configuration is refused rather than degraded: this half would seal nothing while an
    /// operator believed otherwise, and a body written in the clear cannot be reclassified later.
    #[test]
    fn a_subject_key_without_a_declaration_is_refused() {
        let dir = tree();
        let key = dir.path().join("subject.key");
        std::fs::write(&key, "5a".repeat(32)).expect("written");
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        let err = settings.open().expect_err("nothing to derive over");
        assert!(
            err.to_string().contains("declares no erasure units"),
            "{err}"
        );
    }

    /// And this half would refuse every subject-derived record it was sent, one write at a time, at
    /// the caller, instead of once at startup.
    #[test]
    fn a_declaration_without_a_subject_key_is_refused() {
        let (dir, _key) = keyed_tree();
        let settings = StoreSettings::resolve(&store_args(Some(dir.path())), &Env::default())
            .expect("resolved");
        let err = settings.open().expect_err("no secret to derive with");
        assert!(
            err.to_string().contains("cannot derive a pseudonym"),
            "{err}"
        );
        assert!(err.to_string().contains(ENV_SUBJECT_KEY_FILE), "{err}");
    }

    #[test]
    fn a_subject_key_file_that_holds_no_key_is_refused() {
        let (dir, key) = keyed_tree();
        for content in ["", "not hex", &"5a".repeat(16)] {
            std::fs::write(&key, content).expect("written");
            let settings =
                StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
                    .expect("resolved");
            let err = settings.open().expect_err("not a subject key");
            assert!(
                err.to_string().contains("does not hold a subject key"),
                "{content:?}: {err}"
            );
        }
        std::fs::remove_file(&key).expect("removed");
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        assert!(
            settings.open().is_err(),
            "an absent key file is refused too"
        );
    }

    /// The same refusal for custody a file cannot exhibit. A key service that is unreachable is the
    /// failure the seam exists for, and what happens to it must not depend on which backend it was:
    /// the process does not come up, and the message names the setting an operator would change.
    #[test]
    fn a_custody_backend_that_cannot_answer_refuses_at_startup() {
        struct Unreachable;
        impl SubjectKeySource for Unreachable {
            fn fetch(&self) -> yaam_crypto::Result<yaam_crypto::SubjectKey> {
                Err(yaam_crypto::Error::SubjectKeyUnavailable(
                    "cannot reach it: the request timed out".to_owned(),
                ))
            }
        }

        let err = StoreSettings::subject_key(&Unreachable, "--subject-key-file /etc/absent")
            .expect_err("custody that cannot answer is not a key");
        assert!(
            err.to_string().contains("does not hold a subject key"),
            "{err}"
        );
        assert!(err.to_string().contains("/etc/absent"), "{err}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    /// A trailing newline is not part of the secret, because a file written by `echo` and one written
    /// by a secret manager would otherwise derive two pseudonyms for one transaction.
    #[test]
    fn a_trailing_newline_is_not_part_of_the_subject_key() {
        let (dir, key) = keyed_tree();
        std::fs::write(&key, format!("{}\r\n", "5a".repeat(32))).expect("written");
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        settings.open().expect("opened");
    }

    /// The file a store records its subject key in. Held to the spelling
    /// `yaam_core::backup::MANIFEST` publishes, so a rename there fails here rather than leaving
    /// these tests asserting about a file nothing writes.
    const CHECK_FILE: &str = "subject-key-check.json";

    /// The state the live deployments are in: armed, with no record of which key armed them. It has
    /// to open — an upgrade that refused here would take down exactly the stores this protects — and
    /// it has to leave the record behind, or the next open is as blind as this one.
    #[test]
    fn a_store_armed_before_the_check_existed_opens_and_records_the_key() {
        assert_eq!(
            yaam_core::backup::disposition_of(CHECK_FILE),
            Some(yaam_core::backup::Disposition::Included),
            "the check value has to travel in a backup, and by this name"
        );

        let (dir, key) = keyed_tree();
        let recorded = dir.path().join(CHECK_FILE);
        assert!(!recorded.exists(), "nothing records the key yet");

        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        settings
            .open()
            .expect("a store armed before this still opens");
        assert!(recorded.exists(), "and now records which key armed it");
    }

    /// The defect, at the layer an operator meets it. A substituted key file used to come up clean
    /// and file a second pseudonym for a reference already on record; now it is a refusal that names
    /// the setting, the file and what running anyway would do — and the store's own key still opens.
    #[test]
    fn a_substituted_subject_key_is_refused_and_the_store_s_own_still_opens() {
        let (dir, key) = keyed_tree();
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        settings.open().expect("armed at the first open");
        settings.open().expect("and checked at the next");

        std::fs::write(&key, format!("{}\n", "5b".repeat(32))).expect("a substituted key file");
        let err = settings
            .open()
            .expect_err("a key this store was not armed with");
        assert_eq!(
            err.exit(),
            Exit::Config,
            "a wrong key is a setting to change: {err}"
        );
        let said = err.to_string();
        for expected in [
            "--subject-key-file",
            CHECK_FILE,
            "not the one this store was armed with",
            "second, unrelatable pseudonym",
        ] {
            assert!(said.contains(expected), "{expected} missing from: {said}");
        }

        std::fs::write(&key, format!("{}\n", "5a".repeat(32))).expect("the store's own key");
        settings
            .open()
            .expect("the key the store was armed with still opens it");
    }

    /// A record that cannot be read is a different finding with a different remedy, and the exit
    /// code says so: nothing an operator types into a command line repairs a file.
    #[test]
    fn a_record_that_cannot_be_read_stops_the_store_and_names_the_file() {
        let (dir, key) = keyed_tree();
        let settings = StoreSettings::resolve(&subject_key_args(dir.path(), &key), &Env::default())
            .expect("resolved");
        settings.open().expect("armed");

        std::fs::write(dir.path().join(CHECK_FILE), "not a check value at all").expect("written");
        let err = settings
            .open()
            .expect_err("nothing can be said about the key");
        assert_eq!(
            err.exit(),
            Exit::Failed,
            "an unreadable record is not a setting to change: {err}"
        );
        let said = err.to_string();
        assert!(
            said.contains("checking the subject key against the store"),
            "{said}"
        );
        assert!(said.contains(CHECK_FILE), "{said}");
        assert!(said.contains("A backup carries it"), "{said}");
    }

    /// Store args naming a passphrase file.
    /// Store args naming a passphrase file.
    fn passphrase_args(root: &Path, file: &Path) -> StoreArgs {
        StoreArgs {
            key_passphrase_file: Some(file.to_path_buf()),
            ..store_args(Some(root))
        }
    }

    /// A flag says what this process will write, and nothing about what the store already holds —
    /// which is the whole distinction: this one fits a wrapper over a key store with nothing in it.
    #[test]
    fn a_passphrase_file_fits_a_wrapper_without_claiming_anything_about_the_disk() {
        let dir = tree();
        let file = dir.path().join("pass");
        std::fs::write(&file, b"a passphrase\n").expect("written");

        let settings = StoreSettings::resolve(&passphrase_args(dir.path(), &file), &Env::default())
            .expect("resolved");
        let pipeline = settings.open().expect("opened");
        assert!(pipeline.key_wrapper_protects());
        assert!(pipeline.key_wrapper_scheme().contains("argon2id"));
        assert_eq!(
            pipeline.key_material().expect("read"),
            yaam_crypto::keystore::KeyMaterial::Absent,
            "a fitted wrapper is not key material on disk"
        );
    }

    #[test]
    fn no_passphrase_file_leaves_what_this_process_writes_in_the_clear() {
        let dir = tree();
        let settings = StoreSettings::resolve(&store_args(Some(dir.path())), &Env::default())
            .expect("resolved");
        let pipeline = settings.open().expect("opened");
        assert!(!pipeline.key_wrapper_protects());
        // And still nothing to say about the store: an absent flag is not a store in the clear.
        let state = pipeline.key_material().expect("read");
        assert_eq!(state, yaam_crypto::keystore::KeyMaterial::Absent);
        assert!(!state.exposed());
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_passphrase() {
        use yaam_crypto::keystore::KeyWrapper;

        // `echo secret > file` and a secret manager writing the same secret must derive the same
        // key, or a store opens under one and not the other.
        let dir = tree();
        let bare = dir.path().join("bare");
        let with_newline = dir.path().join("newline");
        let with_crlf = dir.path().join("crlf");
        std::fs::write(&bare, b"secret").expect("written");
        std::fs::write(&with_newline, b"secret\n").expect("written");
        std::fs::write(&with_crlf, b"secret\r\n").expect("written");

        let wrapped = |file: &Path| StoreSettings::wrapper(file).expect("derived");
        // Same secret, so a key wrapped under one unwraps under the others.
        let blob = wrapped(&bare).wrap(b"0123456789abcdef").expect("wrapped");
        for file in [&with_newline, &with_crlf] {
            assert_eq!(
                wrapped(file).unwrap(&blob).expect("unwrapped"),
                b"0123456789abcdef",
                "{} derived a different key",
                file.display()
            );
        }
    }

    #[test]
    fn an_empty_passphrase_file_is_refused() {
        let dir = tree();
        let file = dir.path().join("empty");
        std::fs::write(&file, b"\n").expect("written");

        let settings = StoreSettings::resolve(&passphrase_args(dir.path(), &file), &Env::default())
            .expect("resolved");
        let err = settings.open().expect_err("must refuse");
        assert!(format!("{err}").contains("protects nothing"), "{err}");
    }

    #[test]
    fn a_passphrase_file_that_is_not_there_is_refused() {
        let dir = tree();
        let file = dir.path().join("absent");
        let settings = StoreSettings::resolve(&passphrase_args(dir.path(), &file), &Env::default())
            .expect("resolved");
        let err = settings.open().expect_err("must refuse");
        assert!(format!("{err}").contains("cannot read"), "{err}");
    }

    #[test]
    fn a_flag_beats_the_environment() {
        let flagged = tree();
        let env_only = tree();
        let env = Env {
            root: Some(env_only.path().as_os_str().to_owned()),
            ..Env::default()
        };

        let settings =
            StoreSettings::resolve(&store_args(Some(flagged.path())), &env).expect("resolved");
        assert_eq!(settings.paths.root, flagged.path());

        let from_env = StoreSettings::resolve(&store_args(None), &env).expect("resolved");
        assert_eq!(from_env.paths.root, env_only.path());
    }

    #[test]
    fn an_empty_environment_variable_is_not_a_setting() {
        let env = Env {
            root: Some(std::ffi::OsString::new()),
            ..Env::default()
        };
        let error = StoreSettings::resolve(&store_args(None), &env).expect_err("no root");
        assert_eq!(error.exit(), Exit::Config);
        assert!(error.to_string().contains("YAAM_ROOT"), "{error}");
    }

    /// Each refusal has to name the setting that is wrong, because that is what gets edited.
    #[test]
    fn every_store_misconfiguration_names_the_setting() {
        let env = Env::default();
        let missing = StoreSettings::resolve(&store_args(None), &env).expect_err("no root");
        assert!(missing.to_string().contains("--root"), "{missing}");

        let file = tree();
        let not_a_dir = file.path().join("spec/entities.yaml");
        std::fs::write(&not_a_dir, "version: 1\n").expect("write");
        let error = StoreSettings::resolve(&store_args(Some(&not_a_dir)), &env)
            .expect_err("a file is not a tree");
        assert!(error.to_string().contains("is not a directory"), "{error}");

        let bare = tempfile::tempdir().expect("tempdir");
        let error = StoreSettings::resolve(&store_args(Some(bare.path())), &env)
            .expect_err("a tree carries its own spec");
        assert!(error.to_string().contains("spec/"), "{error}");
    }

    #[test]
    fn a_relocated_index_and_key_store_reach_the_paths_and_the_log() {
        let dir = tree();
        let flags = StoreArgs {
            root: Some(dir.path().to_path_buf()),
            index: Some(dir.path().join("elsewhere/index.sqlite")),
            key_store: Some(dir.path().join("secrets")),
            key_passphrase_file: None,
            subject_key_file: None,
        };
        let settings = StoreSettings::resolve(&flags, &Env::default()).expect("resolved");
        assert_eq!(
            settings.paths.index,
            dir.path().join("elsewhere/index.sqlite")
        );
        assert_eq!(settings.paths.key_store, dir.path().join("secrets"));

        let described = settings.describe();
        assert!(
            described
                .iter()
                .filter(|(_, value)| value.contains("(relocated)"))
                .count()
                == 2,
            "a relocated path is worth saying out loud: {described:?}"
        );
    }

    #[test]
    fn an_index_that_names_a_directory_is_refused() {
        let dir = tree();
        let flags = StoreArgs {
            root: Some(dir.path().to_path_buf()),
            index: Some(dir.path().join("spec")),
            key_store: None,
            key_passphrase_file: None,
            subject_key_file: None,
        };
        let error = StoreSettings::resolve(&flags, &Env::default()).expect_err("a directory");
        assert!(error.to_string().contains("--index"), "{error}");
    }

    fn server_args(root: &Path, listen: Option<&str>, keyring: Option<&Path>) -> ServerArgs {
        ServerArgs {
            store: store_args(Some(root)),
            listen: listen.map(str::to_owned),
            keyring: keyring.map(Path::to_path_buf),
            unseal_key_file: None,
            maintenance_ms: None,
        }
    }

    #[test]
    fn the_service_defaults_to_loopback_and_demands_a_keyring() {
        let dir = tree();
        let keyring = dir.path().join("keyring.json");
        let settings = ServerSettings::resolve(
            &server_args(dir.path(), None, Some(&keyring)),
            &Env::default(),
        )
        .expect("resolved");
        assert_eq!(settings.listen.to_string(), super::DEFAULT_LISTEN);

        let error = ServerSettings::resolve(&server_args(dir.path(), None, None), &Env::default())
            .expect_err("a service without a keyring authenticates nobody");
        assert!(error.to_string().contains("--keyring"), "{error}");
    }

    #[test]
    fn an_unparseable_listen_address_is_refused_with_the_shape_it_wanted() {
        let dir = tree();
        let keyring = dir.path().join("keyring.json");
        let error = ServerSettings::resolve(
            &server_args(dir.path(), Some("::1:8787"), Some(&keyring)),
            &Env::default(),
        )
        .expect_err("not an address");
        assert!(error.to_string().contains("[::1]:8787"), "{error}");

        // A port of zero is not a mistake: it is how a test asks the kernel for a free one.
        let ephemeral = ServerSettings::resolve(
            &server_args(dir.path(), Some("127.0.0.1:0"), Some(&keyring)),
            &Env::default(),
        )
        .expect("port zero is a legitimate ask");
        assert_eq!(ephemeral.listen.port(), 0);
    }

    /// The maintenance interval follows the one precedence every other setting follows.
    #[test]
    fn the_maintenance_interval_takes_the_flag_then_the_environment_then_the_default() {
        let dir = tree();
        let keyring = dir.path().join("keyring.json");
        let resolved = |flag: Option<u64>, from_env: Option<&str>| {
            let mut flags = server_args(dir.path(), None, Some(&keyring));
            flags.maintenance_ms = flag;
            let env = Env {
                maintenance_ms: from_env.map(Into::into),
                ..Env::default()
            };
            ServerSettings::resolve(&flags, &env).map(|settings| settings.maintenance)
        };

        assert_eq!(
            resolved(Some(50), Some("900")).expect("resolved"),
            std::time::Duration::from_millis(50),
            "the flag beats the environment, as everywhere else"
        );
        assert_eq!(
            resolved(None, Some(" 900 ")).expect("resolved"),
            std::time::Duration::from_millis(900)
        );
        assert_eq!(
            resolved(None, Some("")).expect("resolved"),
            std::time::Duration::from_millis(super::DEFAULT_MAINTENANCE_MS),
            "an empty variable is not a setting"
        );
        assert_eq!(
            resolved(None, None).expect("resolved"),
            std::time::Duration::from_millis(super::DEFAULT_MAINTENANCE_MS)
        );

        // An interval nobody chose is worse than a refusal: convergence would lag by the default
        // while the deployment that set the variable believed it had asked for something else.
        let unreadable = resolved(None, Some("half a minute")).expect_err("not a number");
        assert_eq!(unreadable.exit(), Exit::Config);
        assert!(
            unreadable.to_string().contains("YAAM_MAINTENANCE_MS"),
            "{unreadable}"
        );

        let zero = resolved(Some(0), None).expect_err("a tight loop");
        assert!(zero.to_string().contains("--maintenance-ms"), "{zero}");
    }

    fn agent_args(state: Option<&Path>) -> AgentArgs {
        AgentArgs {
            state_dir: state.map(Path::to_path_buf),
            sockets: Vec::new(),
            spool_capacity: None,
            retry_interval_ms: None,
        }
    }

    #[test]
    fn the_sidecar_needs_a_state_directory_that_is_there() {
        let error = AgentSettings::resolve(&agent_args(None), &Env::default()).expect_err("unset");
        assert!(error.to_string().contains("YAAM_AGENT_STATE"), "{error}");

        let dir = tempfile::tempdir().expect("tempdir");
        let absent = dir.path().join("nowhere");
        let error = AgentSettings::resolve(&agent_args(Some(&absent)), &Env::default())
            .expect_err("absent");
        assert!(error.to_string().contains("not a directory"), "{error}");

        let settings =
            AgentSettings::resolve(&agent_args(Some(dir.path())), &Env::default()).expect("ok");
        assert!(settings.sockets.is_empty(), "defaulted from the key list");
    }

    #[test]
    fn a_bound_of_zero_is_refused_rather_than_accepted_as_a_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut flags = agent_args(Some(dir.path()));
        flags.spool_capacity = Some(0);
        let error = AgentSettings::resolve(&flags, &Env::default()).expect_err("zero");
        assert!(error.to_string().contains("--spool-capacity"), "{error}");

        let mut flags = agent_args(Some(dir.path()));
        flags.retry_interval_ms = Some(0);
        let error = AgentSettings::resolve(&flags, &Env::default()).expect_err("zero");
        assert!(error.to_string().contains("--retry-interval-ms"), "{error}");
    }

    #[test]
    fn a_named_socket_reaches_the_settings_through_the_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut flags = agent_args(Some(dir.path()));
        flags.sockets = vec!["agent_a=/run/yaam/a.sock".to_owned()];
        let settings = AgentSettings::resolve(&flags, &Env::default()).expect("resolved");
        assert_eq!(
            settings.sockets,
            [("agent_a".to_owned(), "/run/yaam/a.sock".into())]
        );

        flags.sockets = vec!["nonsense".to_owned()];
        assert_eq!(
            AgentSettings::resolve(&flags, &Env::default())
                .expect_err("not agent=path")
                .exit(),
            Exit::Usage
        );
    }

    /// An index this build cannot read is the one refusal that has to name the remedy, because the
    /// remedy is outside the process: run the build that wrote it, or rebuild from the tree.
    #[test]
    fn an_index_a_newer_build_wrote_is_refused_with_the_remedy() {
        let dir = tree();
        let index = dir.path().join("index.sqlite");
        let conn = rusqlite::Connection::open(&index).expect("open");
        conn.execute_batch("PRAGMA user_version = 99")
            .expect("a version this build does not know");
        drop(conn);

        let settings = StoreSettings::resolve(&store_args(Some(dir.path())), &Env::default())
            .expect("resolved");
        let error = settings.open().expect_err("the writer must refuse it");
        assert_eq!(error.exit(), Exit::Config);
        assert!(error.to_string().contains("schema version 99"), "{error}");
        assert!(error.to_string().contains("rebuild"), "{error}");
    }

    #[test]
    fn a_tree_that_cannot_be_opened_says_what_was_being_attempted() {
        let dir = tree();
        // An index under a path that is a file, so the directory it needs cannot be made.
        let blocked = dir.path().join("spec/entities.yaml/index.sqlite");
        let flags = StoreArgs {
            root: Some(dir.path().to_path_buf()),
            index: Some(blocked),
            key_store: None,
            key_passphrase_file: None,
            subject_key_file: None,
        };
        std::fs::write(dir.path().join("spec/entities.yaml"), "version: 1\n").expect("write");
        let settings = StoreSettings::resolve(&flags, &Env::default()).expect("resolved");
        let error = settings.open().expect_err("no directory can be made there");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(
            error.to_string().contains("opening the memory tree"),
            "{error}"
        );
    }

    #[test]
    fn a_socket_specification_splits_at_the_first_equals() {
        assert_eq!(
            socket_spec("agent_a=/run/yaam/a=b.sock").expect("parsed"),
            ("agent_a".to_owned(), Path::new("/run/yaam/a=b.sock").into()),
            "a path may hold an equals sign; an agent name may not"
        );
        for bad in ["agent_a", "=/run/a.sock", "agent_a="] {
            let error = socket_spec(bad).expect_err(bad);
            assert_eq!(error.exit(), Exit::Usage, "{error}");
        }
    }

    #[test]
    fn the_log_level_falls_back_to_info() {
        let level = |value: Option<&str>| {
            log_level(&Env {
                log: value.map(Into::into),
                ..Env::default()
            })
        };
        assert_eq!(level(None), tracing::Level::INFO);
        assert_eq!(level(Some(" DEBUG ")), tracing::Level::DEBUG);
        assert_eq!(level(Some("trace")), tracing::Level::TRACE);
        assert_eq!(level(Some("warn")), tracing::Level::WARN);
        assert_eq!(level(Some("error")), tracing::Level::ERROR);
        assert_eq!(
            level(Some("verbose")),
            tracing::Level::INFO,
            "an unreadable level must not turn logging off"
        );
    }
}
