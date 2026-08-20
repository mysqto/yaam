//! Accepting records from local callers.
//!
//! One socket per caller, permissioned to that caller, so the sidecar knows who is on the other end
//! without being told. A single shared socket would let any local process attribute a record to any
//! agent, which would quietly undo write attribution.
//!
//! The protocol is one JSON line in, one JSON line out. A caller writes a serialised
//! [`yaam_contract::ActionRecord`] and reads back one of
//!
//! ```text
//! {"status":"accepted"}
//! {"status":"spooled"}
//! {"status":"rejected","reason":"…"}
//! {"status":"spool_full"}
//! {"status":"error","reason":"…"}
//! ```
//!
//! `accepted` means the service has the record; `spooled` means this sidecar has it and will keep
//! trying; `rejected` means the caller must fix the record, because nothing else will. A caller that
//! treats a missing answer as success has invented its own durability — the answer is the ack.
//!
//! Where the service lives is read from `upstream.json` in the state directory rather than passed
//! in, because [`serve`] takes only the sockets and that directory.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::sidecar::Sidecar;
use crate::spool::{self, Spool};
use crate::upstream::Upstream;
use crate::{Error, envelope};

/// Name of the configuration file inside the state directory.
pub const CONFIG_FILE: &str = "upstream.json";

/// Name of the spool directory inside the state directory.
pub const SPOOL_DIR: &str = "spool";

/// Longest line a caller may send, in bytes.
///
/// A record is prose and attributes, not a payload. Without a bound, one caller writing a stream
/// with no newline in it would grow the sidecar's memory until the host noticed.
const MAX_LINE: u64 = 1 << 20;

/// How long to wait before retrying a spool that could not be drained.
const DEFAULT_RETRY_MS: u64 = 5_000;

/// Pause after a failed `accept`, so a persistent error cannot become a busy loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A configured caller and the socket it owns.
#[derive(Debug, Clone)]
pub struct CallerSocket {
    /// Agent identity records from this socket are attributed to.
    pub agent: String,
    /// Filesystem path of the socket.
    pub path: std::path::PathBuf,
}

/// What the sidecar needs to know about the service it feeds.
///
/// Kept in the state directory, next to the spool it belongs with, and readable only by the sidecar.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Base URL of the service.
    pub base_url: String,
    /// Service public key, hex encoded. The sidecar seals to it and can never unseal.
    pub service_public_key: String,
    /// Delay between drain attempts while the spool is backed up.
    #[serde(default = "default_retry_ms")]
    pub retry_interval_ms: u64,
    /// Entries the spool holds before it starts refusing writes.
    #[serde(default = "default_capacity")]
    pub spool_capacity: usize,
}

/// Default for [`Config::retry_interval_ms`].
fn default_retry_ms() -> u64 {
    DEFAULT_RETRY_MS
}

/// Default for [`Config::spool_capacity`].
fn default_capacity() -> usize {
    spool::DEFAULT_CAPACITY
}

impl Config {
    /// Reads the configuration from a state directory.
    pub fn load(state_dir: &Path) -> crate::Result<Self> {
        let path = state_dir.join(CONFIG_FILE);
        let text = fs::read_to_string(&path)?;
        serde_json::from_str(&text).map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            ))
        })
    }

    /// Resolves the upstream, decoding and length-checking the service key.
    ///
    /// Checked at startup rather than at the first record: a sidecar that cannot seal cannot do its
    /// job, and finding out during a write means the caller wears a failure the operator caused.
    pub fn upstream(&self) -> crate::Result<Upstream> {
        let key = hex::decode(self.service_public_key.trim()).map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("service public key is not hex: {e}"),
            ))
        })?;
        if key.len() != envelope::KEY_LEN {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "service public key is {} bytes, expected {}",
                    key.len(),
                    envelope::KEY_LEN
                ),
            )));
        }
        Ok(Upstream {
            base_url: self.base_url.clone(),
            service_public_key: key,
        })
    }
}

/// Serves every configured caller socket until shutdown.
///
/// Returns when the process is interrupted, after removing the sockets it created — a socket file
/// outliving its sidecar is a caller writing into something that will never answer.
pub async fn serve(sockets: &[CallerSocket], state_dir: &Path) -> crate::Result<()> {
    let config = Config::load(state_dir)?;
    let spool = Spool::open_with_capacity(state_dir.join(SPOOL_DIR), config.spool_capacity)?;
    let sidecar = Arc::new(Sidecar::new(config.upstream()?, spool));

    let mut tasks = Vec::with_capacity(sockets.len() + 1);
    for socket in sockets {
        let (listener, owner) = bind(socket)?;
        tracing::info!(agent = %socket.agent, path = %socket.path.display(), "listening");
        tasks.push(tokio::spawn(accept_loop(
            listener,
            socket.agent.clone(),
            owner,
            Arc::clone(&sidecar),
        )));
    }
    tasks.push(tokio::spawn(retry_loop(
        Arc::clone(&sidecar),
        Duration::from_millis(config.retry_interval_ms),
    )));

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    for task in tasks {
        task.abort();
    }
    for socket in sockets {
        remove_socket(&socket.path);
    }
    Ok(())
}

/// Binds one caller socket, returning it with the uid that owns it.
///
/// The mode is set immediately after the bind. The window between the two is why peer credentials
/// are checked as well: a connection that slips through it still has to come from the uid the socket
/// ended up owned by.
fn bind(socket: &CallerSocket) -> crate::Result<(UnixListener, u32)> {
    match fs::symlink_metadata(&socket.path) {
        // Only this process binds this path, so an existing socket is from a run that is over.
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&socket.path)?,
        Ok(_) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", socket.path.display()),
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let listener = UnixListener::bind(&socket.path)?;
    fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))?;
    let owner = fs::metadata(&socket.path)?.uid();
    Ok((listener, owner))
}

/// Removes a socket file, treating absence as success.
fn remove_socket(path: &Path) {
    if let Err(e) = fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "could not remove socket");
    }
}

/// Accepts connections on one caller socket for as long as it lives.
async fn accept_loop(listener: UnixListener, agent: String, owner: u32, sidecar: Arc<Sidecar>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let (agent, sidecar) = (agent.clone(), Arc::clone(&sidecar));
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(stream, &agent, owner, &sidecar).await {
                        tracing::warn!(agent = %agent, error = %e, "connection ended badly");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(agent = %agent, error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

/// Drains the spool on a timer, so a backlog clears without waiting for the next caller write.
async fn retry_loop(sidecar: Arc<Sidecar>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        match sidecar.depth().await {
            Ok(0) => {}
            Ok(depth) => match sidecar.flush().await {
                Ok(sent) => tracing::info!(depth, sent, "drained spool"),
                Err(e) => tracing::warn!(depth, error = %e, "drain failed"),
            },
            Err(e) => tracing::warn!(error = %e, "cannot read spool depth"),
        }
    }
}

/// Handles one caller connection: verify who it is, then a line at a time.
async fn serve_connection(
    stream: UnixStream,
    agent: &str,
    owner: u32,
    sidecar: &Sidecar,
) -> crate::Result<()> {
    let peer = stream.peer_cred()?;
    if !peer_may_write(peer.uid(), owner) {
        tracing::warn!(
            agent,
            peer_uid = peer.uid(),
            owner,
            "refusing a connection from another user"
        );
        return Ok(());
    }

    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut line = Vec::new();
        // A fresh limit per line: a bound on the whole stream would cut off a caller's later
        // records for the sin of having sent earlier ones.
        let read = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(());
        }
        if read as u64 > MAX_LINE {
            answer(
                &mut write,
                &Err(Error::Rejected("line too long".to_owned())),
            )
            .await?;
            // No newline was found, so there is no way to tell where the next record starts.
            return Ok(());
        }

        let trimmed = trim_line(&line);
        if trimmed.is_empty() {
            continue;
        }
        let outcome = sidecar.submit(agent, trimmed).await;
        answer(&mut write, &outcome).await?;
    }
}

/// Whether a connecting process may use this socket.
///
/// The `0600` mode already turns away anyone but the owner; this checks the same fact from the other
/// side. Credentials arrive with the connection and cannot be changed after the fact, while a mode
/// can — including in the moment between binding a socket and tightening it.
fn peer_may_write(peer_uid: u32, socket_owner_uid: u32) -> bool {
    peer_uid == socket_owner_uid
}

/// Strips the line terminator a caller sent.
fn trim_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// One answer per record, so a caller never has to guess.
#[derive(Debug, Serialize)]
struct Answer {
    /// Outcome name from the module's table.
    status: &'static str,
    /// Why, when the caller can act on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Answer {
    /// Renders one submission outcome.
    fn of(outcome: &crate::Result<()>) -> Self {
        match outcome {
            Ok(()) => Self {
                status: "accepted",
                reason: None,
            },
            Err(Error::Spooled) => Self {
                status: "spooled",
                reason: None,
            },
            Err(Error::SpoolFull) => Self {
                status: "spool_full",
                reason: None,
            },
            Err(Error::Rejected(why)) => Self {
                status: "rejected",
                reason: Some(why.clone()),
            },
            // Sealing and filesystem failures are the sidecar's own. The caller still needs to know
            // its record went nowhere.
            Err(other) => Self {
                status: "error",
                reason: Some(other.to_string()),
            },
        }
    }
}

/// Writes one answer line.
async fn answer<W>(write: &mut W, outcome: &crate::Result<()>) -> crate::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = serde_json::to_vec(&Answer::of(outcome)).map_err(io::Error::other)?;
    line.push(b'\n');
    write.write_all(&line).await?;
    write.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;
    use tokio::io::AsyncBufReadExt;
    use yaam_contract::{ActionRecord, DataClass, Outcome, RecordId, SchemaVer, Visibility};

    use super::*;
    use crate::stub::Stub;

    /// A valid record line for `agent`.
    fn line(agent: &str, summary: &str) -> String {
        let record = ActionRecord {
            record_id: RecordId::generate(),
            schema_ver: SchemaVer(1),
            at: "2026-01-01T00:00:00Z".to_owned(),
            received_at: "2026-01-01T00:00:01Z".to_owned(),
            backfilled: false,
            agent: agent.to_owned(),
            agent_ver: None,
            correlation_id: None,
            action: "deploy".to_owned(),
            outcome: Outcome::Success,
            attrs: BTreeMap::new(),
            entities: Vec::new(),
            subjects: Vec::new(),
            visibility: Visibility::Org,
            team: None,
            data_class: DataClass::Internal,
            redaction_policy: "default-v1".to_owned(),
            fields_masked: Vec::new(),
            tags: Vec::new(),
            summary: summary.to_owned(),
        };
        format!("{}\n", serde_json::to_string(&record).unwrap())
    }

    /// A state directory pointed at `stub`, plus the service secret key.
    fn state_dir(stub: &Stub, retry_ms: u64, capacity: usize) -> (TempDir, [u8; 32]) {
        let dir = TempDir::new().unwrap();
        let (secret, public) = envelope::generate_keypair();
        let config = format!(
            r#"{{"base_url":"{}","service_public_key":"{}","retry_interval_ms":{retry_ms},"spool_capacity":{capacity}}}"#,
            stub.base_url,
            hex::encode(public)
        );
        fs::write(dir.path().join(CONFIG_FILE), config).unwrap();
        (dir, secret)
    }

    /// Starts [`serve`] in the background and waits for its socket to appear.
    async fn start(sockets: Vec<CallerSocket>, state: &Path) -> tokio::task::JoinHandle<()> {
        let (owned, state) = (sockets.clone(), state.to_path_buf());
        let handle = tokio::spawn(async move {
            serve(&owned, &state).await.unwrap();
        });
        // Connectability, not existence: a stale socket file from a previous run exists before
        // this sidecar has replaced it.
        for socket in &sockets {
            let mut ready = false;
            for _ in 0..200 {
                if UnixStream::connect(&socket.path).await.is_ok() {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(ready, "socket never accepted a connection");
        }
        handle
    }

    /// Writes one line to a socket and reads the answer.
    async fn round_trip(path: &Path, line: &str) -> String {
        let stream = UnixStream::connect(path).await.unwrap();
        let (read, mut write) = stream.into_split();
        write.write_all(line.as_bytes()).await.unwrap();
        let mut answer = String::new();
        BufReader::new(read).read_line(&mut answer).await.unwrap();
        answer
    }

    #[tokio::test]
    async fn a_record_written_to_a_socket_is_sealed_and_posted() {
        let stub = Stub::start(202).await;
        let (dir, secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        let socket = CallerSocket {
            agent: "writer".to_owned(),
            path: path.clone(),
        };
        let serving = start(vec![socket], dir.path()).await;

        let answer = round_trip(&path, &line("writer", "shipped it")).await;
        assert_eq!(answer.trim(), r#"{"status":"accepted"}"#);

        let posted = stub.received();
        assert_eq!(posted.len(), 1);
        let opened = envelope::open(&secret, &posted[0]).unwrap();
        let record: ActionRecord = serde_json::from_slice(&opened).unwrap();
        assert_eq!(record.summary, "shipped it");

        serving.abort();
    }

    #[tokio::test]
    async fn a_spooled_record_is_sealed_on_disk_and_drained_on_reconnect() {
        let stub = Stub::start(503).await;
        // A short retry interval so the background drain is the thing that delivers it.
        let (dir, secret) = state_dir(&stub, 50, 8);
        let path = dir.path().join("writer.sock");
        let serving = start(
            vec![CallerSocket {
                agent: "writer".to_owned(),
                path: path.clone(),
            }],
            dir.path(),
        )
        .await;

        let answer = round_trip(&path, &line("writer", "survive the outage")).await;
        assert_eq!(answer.trim(), r#"{"status":"spooled"}"#);

        let spool = dir.path().join(SPOOL_DIR);
        let entry = fs::read_dir(&spool)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = fs::read(&entry).unwrap();
        assert!(
            !bytes
                .windows("survive the outage".len())
                .any(|w| w == b"survive the outage"),
            "the spooled record is readable on disk"
        );
        // The sidecar's own key material is the public key; it opens nothing.
        let public = envelope::generate_keypair().1;
        let sealed = &bytes["writer\n".len()..];
        assert!(envelope::open(&public, sealed).is_err());
        assert!(envelope::open(&secret, sealed).is_ok(), "the service can");

        // Modes are the reason nothing on this path is exposed, so they are asserted, not assumed.
        let dir_mode = fs::metadata(&spool).unwrap().permissions().mode() & 0o777;
        let entry_mode = fs::metadata(&entry).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "{dir_mode:o}");
        assert_eq!(entry_mode, 0o600, "{entry_mode:o}");
        let socket_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(socket_mode, 0o600, "{socket_mode:o}");

        stub.respond_with(200);
        for _ in 0..200 {
            if fs::read_dir(&spool).unwrap().next().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            fs::read_dir(&spool).unwrap().next().is_none(),
            "the backlog never drained"
        );
        assert_eq!(stub.received().len(), 2, "one refusal, one acceptance");

        serving.abort();
    }

    #[tokio::test]
    async fn a_caller_cannot_write_as_another_agent() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        let serving = start(
            vec![CallerSocket {
                agent: "writer".to_owned(),
                path: path.clone(),
            }],
            dir.path(),
        )
        .await;

        let answer = round_trip(&path, &line("auditor", "not mine")).await;
        assert!(answer.contains(r#""status":"rejected""#), "{answer}");
        assert!(answer.contains("auditor"), "{answer}");
        assert!(stub.received().is_empty());

        serving.abort();
    }

    #[tokio::test]
    async fn each_caller_gets_its_own_socket() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let sockets: Vec<CallerSocket> = ["writer", "auditor"]
            .into_iter()
            .map(|agent| CallerSocket {
                agent: agent.to_owned(),
                path: dir.path().join(format!("{agent}.sock")),
            })
            .collect();
        let serving = start(sockets.clone(), dir.path()).await;

        for socket in &sockets {
            let answer = round_trip(&socket.path, &line(&socket.agent, "mine")).await;
            assert_eq!(
                answer.trim(),
                r#"{"status":"accepted"}"#,
                "{}",
                socket.agent
            );
        }
        // And the other caller's identity is refused on this socket.
        let answer = round_trip(&sockets[0].path, &line("auditor", "not mine")).await;
        assert!(answer.contains("rejected"), "{answer}");

        serving.abort();
    }

    #[tokio::test]
    async fn several_records_on_one_connection_each_get_an_answer() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        let serving = start(
            vec![CallerSocket {
                agent: "writer".to_owned(),
                path: path.clone(),
            }],
            dir.path(),
        )
        .await;

        let stream = UnixStream::connect(&path).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        // A blank line is a no-op, not an error.
        write.write_all(b"\n").await.unwrap();
        for n in 0..3 {
            write
                .write_all(line("writer", &format!("record {n}")).as_bytes())
                .await
                .unwrap();
            let mut answer = String::new();
            reader.read_line(&mut answer).await.unwrap();
            assert_eq!(answer.trim(), r#"{"status":"accepted"}"#);
        }
        assert_eq!(stub.received().len(), 3);

        serving.abort();
    }

    #[tokio::test]
    async fn the_full_spool_is_reported_to_the_caller() {
        let stub = Stub::start(503).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 1);
        let path = dir.path().join("writer.sock");
        let serving = start(
            vec![CallerSocket {
                agent: "writer".to_owned(),
                path: path.clone(),
            }],
            dir.path(),
        )
        .await;

        assert_eq!(
            round_trip(&path, &line("writer", "first")).await.trim(),
            r#"{"status":"spooled"}"#
        );
        assert_eq!(
            round_trip(&path, &line("writer", "second")).await.trim(),
            r#"{"status":"spool_full"}"#
        );

        serving.abort();
    }

    #[tokio::test]
    async fn an_over_long_line_is_refused_without_being_buffered_whole() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        let serving = start(
            vec![CallerSocket {
                agent: "writer".to_owned(),
                path: path.clone(),
            }],
            dir.path(),
        )
        .await;

        let stream = UnixStream::connect(&path).await.unwrap();
        let (read, mut write) = stream.into_split();
        let flood = vec![b'x'; usize::try_from(MAX_LINE).unwrap() + 16];
        // The write may not complete once the sidecar stops reading, which is the point.
        let _ = write.write_all(&flood).await;
        let mut answer = String::new();
        BufReader::new(read).read_line(&mut answer).await.unwrap();
        assert!(answer.contains("line too long"), "{answer}");

        serving.abort();
    }

    #[tokio::test]
    async fn a_stale_socket_from_a_previous_run_is_replaced() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        // Bind and forget, as an unclean shutdown would leave it.
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);

        let socket = CallerSocket {
            agent: "writer".to_owned(),
            path: path.clone(),
        };
        let serving = start(vec![socket], dir.path()).await;
        assert_eq!(
            round_trip(&path, &line("writer", "after a restart"))
                .await
                .trim(),
            r#"{"status":"accepted"}"#
        );

        serving.abort();
    }

    #[tokio::test]
    async fn a_path_that_is_not_a_socket_is_refused() {
        let stub = Stub::start(200).await;
        let (dir, _secret) = state_dir(&stub, 60_000, 8);
        let path = dir.path().join("writer.sock");
        fs::write(&path, b"in the way").unwrap();

        let err = serve(
            &[CallerSocket {
                agent: "writer".to_owned(),
                path,
            }],
            dir.path(),
        )
        .await
        .expect_err("an ordinary file must not be removed");
        assert!(matches!(err, Error::Io(_)), "{err}");
    }

    #[test]
    fn a_peer_that_is_not_the_socket_owner_is_refused() {
        assert!(peer_may_write(1000, 1000));
        assert!(!peer_may_write(1000, 1001));
        assert!(!peer_may_write(0, 1000), "root is not an exception");
    }

    #[test]
    fn a_missing_configuration_is_an_error_not_a_default() {
        let dir = TempDir::new().unwrap();
        assert!(Config::load(dir.path()).is_err());

        fs::write(dir.path().join(CONFIG_FILE), b"{not json").unwrap();
        let err = Config::load(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
    }

    #[test]
    fn the_configuration_defaults_the_optional_fields() {
        let dir = TempDir::new().unwrap();
        let public = envelope::generate_keypair().1;
        fs::write(
            dir.path().join(CONFIG_FILE),
            format!(
                r#"{{"base_url":"http://localhost:9","service_public_key":"{}"}}"#,
                hex::encode(public)
            ),
        )
        .unwrap();

        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.retry_interval_ms, DEFAULT_RETRY_MS);
        assert_eq!(config.spool_capacity, spool::DEFAULT_CAPACITY);
        assert_eq!(
            config.upstream().unwrap().service_public_key,
            public.to_vec()
        );
    }

    #[test]
    fn a_service_key_that_cannot_seal_fails_at_startup() {
        let short = Config {
            base_url: "http://localhost:9".to_owned(),
            service_public_key: hex::encode([0u8; 8]),
            retry_interval_ms: 1,
            spool_capacity: 1,
        };
        assert!(short.upstream().is_err());

        let not_hex = Config {
            service_public_key: "zz".to_owned(),
            ..short
        };
        assert!(not_hex.upstream().is_err());
    }

    #[test]
    fn a_line_is_trimmed_of_either_terminator() {
        assert_eq!(trim_line(b"{}\n"), b"{}");
        assert_eq!(trim_line(b"{}\r\n"), b"{}");
        assert_eq!(trim_line(b"{}"), b"{}");
        assert_eq!(trim_line(b"\n"), b"");
    }

    #[test]
    fn every_outcome_has_an_answer() {
        let rendered =
            |outcome: crate::Result<()>| serde_json::to_string(&Answer::of(&outcome)).unwrap();
        assert_eq!(rendered(Ok(())), r#"{"status":"accepted"}"#);
        assert_eq!(rendered(Err(Error::Spooled)), r#"{"status":"spooled"}"#);
        assert_eq!(
            rendered(Err(Error::SpoolFull)),
            r#"{"status":"spool_full"}"#
        );
        assert_eq!(
            rendered(Err(Error::Rejected("why".to_owned()))),
            r#"{"status":"rejected","reason":"why"}"#
        );
        assert!(rendered(Err(Error::Io(io::Error::other("disk")))).contains(r#""status":"error""#));
    }
}
