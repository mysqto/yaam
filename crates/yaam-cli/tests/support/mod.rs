//! A deployment of the built binaries, and the state to assert against afterwards.
//!
//! Shared by this crate's integration tests, which all drive the *built* binaries over a temporary
//! tree configured from this repository's own `spec/`. Everything here is about the outside of a
//! process — its arguments, its log, how it died, and the files and rows it left behind — because
//! that is the half no in-process test can see.
//!
//! The HTTP request is assembled and signed by hand rather than through a client library. That is
//! deliberate: were a test to sign by asking the service's own helper what the message is, it would
//! only prove the service agrees with itself.
//!
//! Each test binary uses a subset of these, hence the blanket allow.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use yaam_contract::{
    ActionRecord, CanonVer, DataClass, Outcome, RecordId, Role as SubjectRole, SchemaVer,
    SubjectHash, SubjectRef, Visibility, attrs,
    entity::{self, EntityRef},
};

/// The signing key the test caller and the test service share, hex encoded.
pub const SIGNING_KEY: &str = "0a0b0c0d0e0f";

/// The caller every test writes as.
pub const AGENT: &str = "agent_a";

/// Prose no configured redaction pattern matches.
pub const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// How long any wait here is allowed to take before the test gives up.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// The maintenance interval every service started here runs on, in milliseconds.
///
/// Short on purpose. What these tests wait for is a round in *another* process, and at the
/// deployment default of 30 s a handful of such waits is minutes of sitting still — which is the
/// whole cost of the crash tests. Passed through the environment rather than a flag so that half of
/// the precedence is exercised by a real process; a test may still override it, since the
/// per-test variables are applied after this one.
pub const MAINTENANCE_MS: &str = "250";

/// The declaration a store makes when it has decided to write subject-derived records.
pub const SPEC_WRITES: &str = "version: 1\nwrites: enabled\n";

/// A memory tree with this repository's own spec, a keyring, and a sealing key.
pub struct Deployment {
    dir: tempfile::TempDir,
}

impl Deployment {
    /// A store in the shipped state: the repository's `spec/` declares no erasure units, so
    /// subject-derived records are refused.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        copy_dir(&spec, &dir.path().join("spec"));
        fs::write(
            dir.path().join("keyring.json"),
            format!(r#"{{"callers":{{"{AGENT}":{{"role":"writer","key":"{SIGNING_KEY}"}}}}}}"#),
        )
        .expect("keyring");
        Self { dir }
    }

    /// The same deployment, with the operator's decision to write subject-derived records on the
    /// page.
    ///
    /// Written out rather than defaulted, because the default is the opposite and has to be: the
    /// first such record a store writes is sealed under a key that cannot be rotated, and there is
    /// no re-key, no re-seal and no delete.
    pub fn writing_subjects(self) -> Self {
        fs::write(
            self.dir.path().join("spec").join("subject-writes.yaml"),
            SPEC_WRITES,
        )
        .expect("subject-writes spec");
        self
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn root_str(&self) -> &str {
        self.root().to_str().expect("a utf-8 temporary path")
    }

    /// The keyring the service authenticates callers against.
    pub fn keyring(&self) -> PathBuf {
        self.root().join("keyring.json")
    }

    /// The derived index, where the default layout puts it.
    pub fn index(&self) -> PathBuf {
        self.root().join("index.sqlite")
    }

    /// Where a record with this deployment's fixture timestamp is published.
    pub fn published(&self, id: &RecordId) -> PathBuf {
        self.root()
            .join("records/2026/08/20")
            .join(format!("{}.md", id.as_str()))
    }

    /// Where the write-ahead copy of a record sits before it is published.
    pub fn staged(&self, id: &RecordId) -> PathBuf {
        self.root()
            .join(".staging")
            .join(format!("{}.md", id.as_str()))
    }

    /// Directory holding one entity's timeline.
    pub fn timeline_dir(&self, kind: &str, id: &str) -> PathBuf {
        self.root().join("entities").join(kind).join(id)
    }
}

/// Runs `yaam` and returns what a script would see.
pub fn yaam(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yaam"))
        .args(args)
        .output()
        .expect("run yaam")
}

/// Runs `yaam-emit` and returns what a script would see.
///
/// Nothing about the environment is inherited beyond what the caller passes: the emitter reads
/// `YAAM_SOCKET` and `YAAM_AGENT`, and a variable left over from the surrounding shell would make a
/// test pass on a setting it never named.
pub fn yaam_emit(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yaam-emit"));
    command
        .args(args)
        .env_remove("YAAM_SOCKET")
        .env_remove("YAAM_AGENT");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run yaam-emit")
}

/// Runs `yaam-read` and returns what a script would see.
///
/// Nothing about the environment is inherited beyond what the caller passes, for the reason
/// [`yaam_emit`] inherits nothing: a variable left over from the surrounding shell would make a test
/// pass on a setting it never named.
pub fn yaam_read(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yaam-read"));
    command.args(args).env_remove("YAAM_READ_SOCKET");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run yaam-read")
}

/// Starts a sidecar in its own state directory under `deployment`, pointed at `base_url`.
///
/// The sealing key is passed in rather than taken from a running service, so a sidecar can be
/// pointed at a service that does not exist — which is what the spool cases need.
///
/// Returns the caller's record socket and the process. The read socket is the same path with
/// `.read.sock` for its extension, which is [`read_socket`].
pub fn sidecar(
    deployment: &Deployment,
    name: &str,
    base_url: &str,
    public_key: &str,
) -> (PathBuf, Child) {
    let state = deployment.root().join(name);
    fs::create_dir_all(&state).expect("state dir");
    fs::write(
        state.join("upstream.json"),
        format!(
            r#"{{"base_url":"{base_url}","service_public_key":"{public_key}",
                 "signing_keys":{{"{AGENT}":"{SIGNING_KEY}"}},"retry_interval_ms":200}}"#
        ),
    )
    .expect("upstream");
    let child = spawn(
        env!("CARGO_BIN_EXE_yaam-agent"),
        &["--state-dir", state.to_str().expect("utf-8")],
    );
    let socket = state.join(format!("sockets/{AGENT}.sock"));
    drop(await_socket(&socket));
    (socket, child)
}

/// A caller's read socket, derived from its record socket exactly as the sidecar derives it.
pub fn read_socket(record: &Path) -> PathBuf {
    record.with_extension("read.sock")
}

/// Services started so far, which is what keeps their logs apart.
static STARTS: AtomicUsize = AtomicUsize::new(0);

/// A running service, and what a caller needs to reach it.
pub struct Service {
    child: Child,
    /// Where the service's own log went. Read for the startup settings, and for failure messages.
    log: PathBuf,
    /// The address the kernel gave it, read from its own startup log.
    pub address: SocketAddr,
    /// The public half of its sealing key, also read from its startup log.
    pub sealing_public_key: String,
}

impl Service {
    /// Starts the service on an ephemeral port and waits until it says which one it got.
    pub fn start(deployment: &Deployment) -> Self {
        Self::start_with_env(deployment, &[])
    }

    /// The same, with extra environment variables — which is how a crash checkpoint is armed.
    ///
    /// The log goes to a file rather than a pipe. A pipe nobody drains fills up, and a service
    /// blocked writing a log line is a service that stopped for a reason the test did not choose.
    pub fn start_with_env(deployment: &Deployment, env: &[(&str, &str)]) -> Self {
        let (secret, _) = yaam_crypto::envelope::generate_keypair();
        let key_file = deployment.root().join("unseal.key");
        fs::write(&key_file, hex::encode(secret)).expect("sealing key");

        // A fresh log per start, so a restarted service's own lines are not read as the dead one's.
        let log = deployment.root().join(format!(
            "server-{}.log",
            STARTS.fetch_add(1, Ordering::Relaxed)
        ));
        let handle = fs::File::create(&log).expect("log file");
        let mut command = Command::new(env!("CARGO_BIN_EXE_yaam-server"));
        command
            .args([
                "--root",
                deployment.root_str(),
                "--listen",
                "127.0.0.1:0",
                "--keyring",
                deployment.keyring().to_str().expect("utf-8"),
                "--unseal-key-file",
                key_file.to_str().expect("utf-8"),
            ])
            .env("YAAM_MAINTENANCE_MS", MAINTENANCE_MS)
            .stdout(Stdio::null())
            .stderr(Stdio::from(handle));
        for (name, value) in env {
            command.env(name, value);
        }
        let child = command.spawn().expect("spawn yaam-server");

        // The startup log is where the effective configuration is published, and the only place the
        // chosen port and the sealing public key exist.
        let mut service = Self {
            child,
            log,
            address: "127.0.0.1:0".parse().expect("a placeholder address"),
            sealing_public_key: String::new(),
        };
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            let text = service.log_text();
            if let (Some(listen), Some(public)) = (
                setting(&text, "listen"),
                setting(&text, "sealing-public-key"),
            ) {
                service.address = listen.parse().expect("an address in the log");
                service.sealing_public_key = public;
                return service;
            }
            assert!(
                service.child.try_wait().expect("wait").is_none(),
                "the service exited before it said what it was running with:\n{text}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "the service never announced itself:\n{}",
            service.log_text()
        );
    }

    /// Everything the service has logged so far.
    pub fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Signals the service and asserts it came down cleanly.
    pub fn stop(&mut self) {
        let status = signal_and_wait(&mut self.child, "TERM", "yaam-server");
        assert_eq!(
            status.code(),
            Some(0),
            "yaam-server did not shut down cleanly:\n{}",
            self.log_text()
        );
    }

    /// `SIGKILL`, and the status that proves the process ran no code of its own on the way out.
    ///
    /// No graceful path, no destructors, nothing flushed: this is the crash the durability argument
    /// is about, so it has to be the one signal a process cannot handle.
    pub fn kill_nine(&mut self) {
        let status = signal_and_wait(&mut self.child, "9", "yaam-server");
        assert_eq!(
            status.signal(),
            Some(9),
            "the service was meant to die by signal, not to exit: {status:?}"
        );
    }
}

/// Sends a signal by name and returns the status the process ended with.
///
/// `kill` rather than a signal call, because this workspace forbids unsafe and the libc wrapper would
/// be a dependency bought for one line.
pub fn signal_and_wait(child: &mut Child, signal: &str, name: &str) -> ExitStatus {
    let signalled = Command::new("kill")
        .args([&format!("-{signal}"), &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(signalled.success(), "could not signal {name}");

    let deadline = Instant::now() + PATIENCE;
    loop {
        match child.try_wait().expect("wait") {
            Some(status) => return status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                panic!("{name} did not exit on SIG{signal}");
            }
        }
    }
}

/// The value of one `setting=` field in a startup log.
pub fn setting(text: &str, name: &str) -> Option<String> {
    text.lines()
        .find(|line| {
            line.contains(&format!("setting=\"{name}\""))
                || line.contains(&format!("setting={name}"))
        })?
        .split("value=")
        .nth(1)?
        .split_whitespace()
        .next()
        .map(|value| value.trim_matches('"').to_owned())
}

/// Starts a binary with its output piped, so a test can read what it says.
pub fn spawn(binary: &str, args: &[&str]) -> Child {
    Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {binary}: {error}"))
}

/// Sends `SIGTERM` to a process whose output is piped, and asserts it exited cleanly.
pub fn terminate(child: &mut Child, name: &str) {
    let status = signal_and_wait(child, "TERM", name);
    assert_eq!(
        status.code(),
        Some(0),
        "{name} did not shut down cleanly: {}",
        drained(child)
    );
}

/// Whatever a process left on its pipes, for a failure message.
pub fn drained(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(err) = child.stderr.as_mut() {
        let _ = err.read_to_string(&mut text);
    }
    text
}

/// Waits until a socket answers, then connects.
///
/// Connectability, not existence: a socket file exists for a moment before anybody is accepting on
/// it, and a test that waited for the file would race the bind.
pub fn await_socket(path: &Path) -> UnixStream {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} never answered", path.display());
}

/// A service's answer to a request.
#[derive(Debug)]
pub struct Answer {
    /// HTTP status code.
    pub status: u16,
    /// Response body, whatever it turned out to be.
    pub body: String,
}

/// Writes one record over HTTP, signed as [`AGENT`], and returns the answer.
pub fn post_record(address: SocketAddr, record: &ActionRecord, body: &str) -> Answer {
    let request = write_request(record, body);
    let stream = post_unanswered(address, &request);
    answer_of(stream).unwrap_or_else(|| panic!("the service closed the connection with no answer"))
}

/// The same write, with the answer deliberately left unread.
///
/// What a crash test needs: the connection stays open while the service sits in the window, so the
/// process is killed with a request in flight rather than after one completed. The stream is
/// returned so the caller can hold it open — dropping it would close the connection.
pub fn post_unanswered(address: SocketAddr, body: &str) -> TcpStream {
    let signature = yaam_contract::request::sign(
        &hex::decode(SIGNING_KEY).expect("a hex key"),
        "POST",
        "/records",
        AGENT,
        body.as_bytes(),
    );
    let mut stream = TcpStream::connect(address).expect("connect");
    let request = format!(
        "POST /records HTTP/1.1\r\nhost: {address}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nx-yaam-agent: {AGENT}\r\nx-yaam-signature: {signature}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");
    stream
}

/// Reads an answer, or `None` if the connection closed before one arrived.
pub fn answer_of(mut stream: TcpStream) -> Option<Answer> {
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("read timeout");
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head.lines().next()?.split_whitespace().nth(1)?;
    Some(Answer {
        status: status.parse().ok()?,
        body: body.to_owned(),
    })
}

/// The JSON body of a write request.
pub fn write_request(record: &ActionRecord, body: &str) -> String {
    serde_json::json!({ "record": record, "body": body }).to_string()
}

/// A valid internal record, as a caller would write it: plaintext body, one entity, no subjects.
pub fn record() -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: "2026-08-20T09:00:00Z".to_owned(),
        received_at: "2026-08-20T09:00:00Z".to_owned(),
        backfilled: false,
        agent: AGENT.to_owned(),
        agent_ver: None,
        correlation_id: None,
        action: "deploy".to_owned(),
        outcome: Outcome::Success,
        attrs: BTreeMap::from([
            ("service".to_owned(), attrs::Value::Text("api".to_owned())),
            (
                "environment".to_owned(),
                attrs::Value::Text("staging".to_owned()),
            ),
        ]),
        entities: vec![EntityRef {
            kind: "ticket".to_owned(),
            id: "PROJ-42".to_owned(),
            role: entity::Role::Primary,
            confidence: 1.0,
        }],
        subjects: Vec::new(),
        visibility: Visibility::Org,
        team: None,
        data_class: DataClass::Internal,
        redaction_policy: "default-v1".to_owned(),
        fields_masked: Vec::new(),
        tags: Vec::new(),
        summary: BODY.to_owned(),
    }
}

/// A subject-derived record: sealed body, one named subject, an entity that is not a person.
pub fn subject_derived(subjects: &[SubjectHash]) -> ActionRecord {
    let mut record = record();
    "lookup".clone_into(&mut record.action);
    record.attrs = BTreeMap::from([(
        "target_kind".to_owned(),
        attrs::Value::Text("order_ref".to_owned()),
    )]);
    record.entities = vec![EntityRef {
        kind: "order_ref".to_owned(),
        id: "ord10014721".to_owned(),
        role: entity::Role::Primary,
        confidence: 1.0,
    }];
    record.data_class = DataClass::SubjectDerived;
    record.subjects = subjects
        .iter()
        .map(|hash| SubjectRef {
            hash: hash.clone(),
            role: SubjectRole::Principal,
            canon_ver: CanonVer(1),
        })
        .collect();
    record
}

/// A subject pseudonym, distinct per `fill`, which must be a lowercase hex digit.
pub fn subject(fill: char) -> SubjectHash {
    SubjectHash::parse(&format!("s_{}", fill.to_string().repeat(64))).expect("a valid hash")
}

/// A record as it sits in the tree, for the cases a running service cannot produce.
pub fn rendered(record: &ActionRecord) -> String {
    yaam_md::Document {
        record: record.clone(),
        body: yaam_md::Body::Plain(BODY.to_owned()),
    }
    .render()
}

/// Backdates a file's modification time, which is how a test reaches past a grace period.
pub fn age(path: &Path, by: Duration) {
    let when = std::time::SystemTime::now() - by;
    fs::File::options()
        .write(true)
        .open(path)
        .expect("open")
        .set_times(fs::FileTimes::new().set_modified(when))
        .expect("set times");
}

/// Waits until `state` holds, and says so, or gives up after `patience`.
///
/// Polling rather than sleeping for a fixed time: what these tests wait on is a maintenance round in
/// another process, and a test that slept for one interval would be a test that fails the day the
/// interval changes.
pub fn eventually(patience: Duration, mut state: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if state() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    state()
}

/// Copies a directory tree, which is how the repository's spec reaches a temporary root.
pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy");
        }
    }
}

/// Every record file in the published tree.
pub fn record_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.join("records")];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The index, opened read-only, for the assertions the query API cannot make.
pub fn index_of(deployment: &Deployment) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_with_flags(
        deployment.index(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open index");
    conn.busy_timeout(Duration::from_secs(10))
        .expect("busy timeout");
    conn
}

/// Every indexed record identifier, and the schema version the row carries.
pub fn indexed(deployment: &Deployment) -> BTreeMap<String, i64> {
    let conn = index_of(deployment);
    let mut statement = conn
        .prepare("SELECT record_id, schema_ver FROM records ORDER BY record_id")
        .expect("prepare");
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

/// Every queued fan-out job as `record_id/job_kind/state`, in a stable order.
/// The jobs in the queue, by identity and not by state.
///
/// For assertions about whether a *second* job appeared. A job's state legitimately advances while a
/// service is running -- `claimed` becomes `done` as the sweeper finishes it -- so comparing the state
/// too makes such an assertion a race, and one that only loses on a loaded machine.
pub fn fanout_jobs(deployment: &Deployment) -> Vec<String> {
    let conn = index_of(deployment);
    let mut statement = conn
        .prepare("SELECT record_id, job_kind FROM fanout_queue ORDER BY record_id, job_kind")
        .expect("prepare");
    let rows = statement
        .query_map([], |row| {
            Ok(format!(
                "{}/{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            ))
        })
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

pub fn fanout(deployment: &Deployment) -> Vec<String> {
    let conn = index_of(deployment);
    let mut statement = conn
        .prepare("SELECT record_id, job_kind, state FROM fanout_queue ORDER BY record_id, job_kind")
        .expect("prepare");
    let rows = statement
        .query_map([], |row| {
            Ok(format!(
                "{}/{}/{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?
            ))
        })
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

/// Backdates every held fan-out claim, so the next sweep sees the drain that held it as gone.
///
/// The service must not be running: this writes to the index it owns. It is how a test reaches past
/// the claim grace period without waiting out five minutes of it.
pub fn age_fanout_claims(deployment: &Deployment, by: Duration) -> usize {
    let conn = rusqlite::Connection::open(deployment.index()).expect("open index");
    conn.busy_timeout(Duration::from_secs(10))
        .expect("busy timeout");
    conn.execute(
        "UPDATE fanout_queue SET claimed_ms = claimed_ms - ?1 WHERE state = 'claimed'",
        [i64::try_from(by.as_millis()).expect("a sane duration")],
    )
    .expect("age claims")
}

/// How many times a record's wikilink appears across a timeline head and every frozen part.
///
/// One number over all the files, because "appended exactly once" is a claim about the timeline, and
/// a count per file would pass while a re-drive wrote the same line into the head and a part.
pub fn timeline_mentions(dir: &Path, id: &RecordId) -> usize {
    let needle = format!("[[record:{}", id.as_str());
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("timeline"))
        })
        .map(|entry| {
            fs::read_to_string(entry.path())
                .unwrap_or_default()
                .matches(&needle)
                .count()
        })
        .sum()
}
