//! The three binaries as a script and a caller see them.
//!
//! The unit tests exercise the same paths in process. This runs the built binaries, because two
//! things are not observable from inside: the exit code, which is the interface anything scripting
//! this branches on, and whether the three actually talk to each other over a socket and a port.
//!
//! The end-to-end test is the one that would have caught this repository having no entry points at
//! all: a record written to a caller socket, sealed by the sidecar, posted to the service, published
//! to the tree, and then found by `yaam check`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::time::{Duration, Instant};

use yaam_contract::{
    ActionRecord, DataClass, Outcome, RecordId, SchemaVer, Visibility, attrs,
    entity::{self, EntityRef},
};

/// The signing key the test caller and the test service share, hex encoded.
const SIGNING_KEY: &str = "0a0b0c0d0e0f";

/// Prose no configured redaction pattern matches.
const BODY: &str = "Rolled out the api service to staging across two of three shards.";

/// How long any wait here is allowed to take before the test gives up.
const PATIENCE: Duration = Duration::from_secs(30);

/// A memory tree with this repository's own spec, a keyring, and a sealing key.
struct Deployment {
    dir: tempfile::TempDir,
}

impl Deployment {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec");
        copy_dir(&spec, &dir.path().join("spec"));
        std::fs::write(
            dir.path().join("keyring.json"),
            format!(r#"{{"callers":{{"agent_a":{{"role":"writer","key":"{SIGNING_KEY}"}}}}}}"#),
        )
        .expect("keyring");
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn root_str(&self) -> &str {
        self.root().to_str().expect("a utf-8 temporary path")
    }
}

/// Runs `yaam` and returns what a script would see.
fn yaam(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yaam"))
        .args(args)
        .output()
        .expect("run yaam")
}

/// Every documented code has to come out of the real process, or it is not an interface.
#[test]
fn every_documented_exit_code_comes_out_of_the_binary() {
    let deployment = Deployment::new();
    let root = deployment.root_str();

    // A record in the tree with no index row: drift, which is what `check` reports as degraded.
    let dated = deployment.root().join("records/2026/08/20");
    std::fs::create_dir_all(&dated).expect("dated dir");
    let record = record();
    std::fs::write(
        dated.join(format!("{}.md", record.record_id.as_str())),
        rendered(&record),
    )
    .expect("record file");

    let pseudonym = format!("s_{}", "a".repeat(64));
    let cases: Vec<(Vec<&str>, i32, &str)> = vec![
        (vec!["--help"], 0, "help is a success"),
        (vec!["--nonesuch"], 2, "an unknown flag is a usage error"),
        (vec!["check"], 3, "no root is a configuration error"),
        (vec!["--root", root, "check"], 4, "drift is degraded"),
        (
            vec!["--root", root, "erase", "--subject", &pseudonym],
            5,
            "an unconfirmed erasure does nothing",
        ),
        (
            vec!["--root", root, "verify-erasure", "--tombstone", "tomb-x"],
            1,
            "an unknown tombstone is a failure",
        ),
        (
            vec!["--root", root, "reindex", "--all"],
            0,
            "a rebuild works",
        ),
    ];

    for (args, expected, why) in cases {
        let output = yaam(&args);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{args:?} should exit {expected} ({why}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // After the rebuild the drift is gone, so the same command that was degraded is now clean.
    // Fan-out is still queued — nothing is draining it here — so this asserts the drift line, not
    // the exit code.
    let after = yaam(&["--root", root, "check"]);
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("index drift        0"),
        "{}",
        String::from_utf8_lossy(&after.stdout)
    );
}

/// A signed record, written to a caller socket, ends up in the tree and in the index.
///
/// Every hop is a real process: the sidecar seals and signs, the service verifies and publishes, and
/// the operator command line reads the result. Nothing here is stubbed, which is the point.
#[test]
fn a_record_written_to_a_socket_reaches_the_tree_through_the_service() {
    let deployment = Deployment::new();
    let root = deployment.root_str();

    let mut service = Service::start(&deployment);
    let state = deployment.root().join("agent");
    std::fs::create_dir_all(&state).expect("state dir");
    std::fs::write(
        state.join("upstream.json"),
        format!(
            r#"{{"base_url":"http://{}","service_public_key":"{}",
                 "signing_keys":{{"agent_a":"{SIGNING_KEY}"}},"retry_interval_ms":200}}"#,
            service.address, service.sealing_public_key
        ),
    )
    .expect("upstream");

    let mut sidecar = spawn(
        env!("CARGO_BIN_EXE_yaam-agent"),
        &["--state-dir", state.to_str().expect("utf-8")],
    );
    let socket = state.join("sockets/agent_a.sock");
    let mut stream = await_socket(&socket);

    let record = record();
    let line = format!("{}\n", serde_json::to_string(&record).expect("json"));
    stream.write_all(line.as_bytes()).expect("write the record");
    let mut answer = String::new();
    BufReader::new(&stream)
        .read_line(&mut answer)
        .expect("an answer per record");
    assert_eq!(
        answer.trim(),
        r#"{"status":"accepted"}"#,
        "the service has to have taken it, not the spool"
    );

    // In the tree, which is the authoritative half.
    let published = deployment
        .root()
        .join("records/2026/08/20")
        .join(format!("{}.md", record.record_id.as_str()));
    assert!(published.is_file(), "{} is not there", published.display());

    // And in the index, which `check` reads: no drift means the row landed with the file.
    let checked = yaam(&["--root", root, "check"]);
    let printed = String::from_utf8_lossy(&checked.stdout);
    assert!(printed.contains("records indexed    1"), "{printed}");
    assert!(printed.contains("index drift        0"), "{printed}");

    // A rebuild reproduces the row from the tree alone, which is the property the whole store rests
    // on — and the command every recovery procedure names.
    let rebuilt = yaam(&["--root", root, "reindex", "--all"]);
    assert_eq!(rebuilt.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&rebuilt.stdout).contains("from the tree       1"),
        "{}",
        String::from_utf8_lossy(&rebuilt.stdout)
    );

    // Both come down on a signal, cleanly, and the sidecar takes its socket with it.
    terminate(&mut sidecar, "yaam-agent");
    assert!(
        !socket.exists(),
        "a socket outliving its sidecar is a caller writing into nothing"
    );
    service.stop();
}

/// A running service, and what a sidecar needs to reach it.
struct Service {
    child: Child,
    /// Held open for the life of the service: closing the read end would leave it writing every
    /// later log line into a broken pipe.
    _log: BufReader<ChildStderr>,
    /// The address the kernel gave it, read from its own startup log.
    address: SocketAddr,
    /// The public half of its sealing key, also read from its startup log.
    sealing_public_key: String,
}

impl Service {
    /// Starts the service on an ephemeral port and waits until it says which one it got.
    fn start(deployment: &Deployment) -> Self {
        let (secret, _) = yaam_crypto::envelope::generate_keypair();
        let key_file = deployment.root().join("unseal.key");
        std::fs::write(&key_file, hex::encode(secret)).expect("sealing key");

        let mut child = spawn(
            env!("CARGO_BIN_EXE_yaam-server"),
            &[
                "--root",
                deployment.root_str(),
                "--listen",
                "127.0.0.1:0",
                "--keyring",
                deployment
                    .root()
                    .join("keyring.json")
                    .to_str()
                    .expect("utf-8"),
                "--unseal-key-file",
                key_file.to_str().expect("utf-8"),
            ],
        );

        // The startup log is where the effective configuration is published, which is also the only
        // place the chosen port and the sealing public key exist.
        let log = child.stderr.take().expect("stderr is piped");
        let mut reader = BufReader::new(log);
        let mut address = None;
        let mut public = None;
        let mut line = String::new();
        while address.is_none() || public.is_none() {
            line.clear();
            assert!(
                reader.read_line(&mut line).expect("read the log") > 0,
                "the service exited before it said what it was running with"
            );
            if let Some(value) = setting(&line, "listen") {
                address = Some(value.parse().expect("an address in the log"));
            }
            if let Some(value) = setting(&line, "sealing-public-key") {
                public = Some(value);
            }
        }
        Self {
            child,
            _log: reader,
            address: address.expect("the listen line"),
            sealing_public_key: public.expect("the sealing key line"),
        }
    }

    /// Signals the service and asserts it came down cleanly.
    fn stop(&mut self) {
        terminate(&mut self.child, "yaam-server");
    }
}

/// The value of one `setting=` field in a startup log line.
fn setting(line: &str, name: &str) -> Option<String> {
    if !line.contains(&format!("setting=\"{name}\"")) && !line.contains(&format!("setting={name}"))
    {
        return None;
    }
    line.split("value=")
        .nth(1)?
        .split_whitespace()
        .next()
        .map(|value| value.trim_matches('"').to_owned())
}

/// Starts a binary with its output piped, so a test can read what it says.
fn spawn(binary: &str, args: &[&str]) -> Child {
    Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {binary}: {error}"))
}

/// Waits until a socket answers, then connects.
///
/// Connectability, not existence: a socket file exists for a moment before anybody is accepting on
/// it, and a test that waited for the file would race the bind.
fn await_socket(path: &Path) -> UnixStream {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} never answered", path.display());
}

/// Sends `SIGTERM` and asserts the process exited cleanly.
///
/// `kill` rather than a signal call, because this workspace forbids unsafe and the libc wrapper would
/// be a dependency bought for one line.
fn terminate(child: &mut Child, name: &str) {
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(killed.success(), "could not signal {name}");

    let deadline = Instant::now() + PATIENCE;
    loop {
        match child.try_wait().expect("wait") {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "{name} did not shut down cleanly: {}",
                    drained(child)
                );
                return;
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                panic!("{name} did not exit on SIGTERM");
            }
        }
    }
}

/// Whatever a process left on its pipes, for a failure message.
fn drained(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(err) = child.stderr.as_mut() {
        let _ = err.read_to_string(&mut text);
    }
    text
}

/// A valid internal record, as a caller would write it.
fn record() -> ActionRecord {
    ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SchemaVer(1),
        at: "2026-08-20T09:00:00Z".to_owned(),
        received_at: "2026-08-20T09:00:00Z".to_owned(),
        backfilled: false,
        agent: "agent_a".to_owned(),
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

/// A record as it sits in the tree, for the drift case that needs a file with no index row.
fn rendered(record: &ActionRecord) -> String {
    yaam_md::Document {
        record: record.clone(),
        body: yaam_md::Body::Plain(BODY.to_owned()),
    }
    .render()
}

/// Copies a directory tree, which is how the repository's spec reaches a temporary root.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}
