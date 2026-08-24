//! The emitter as a shell hook sees it: one command, and what it exits with.
//!
//! In-process tests already cover what the record comes out looking like and how each answer is read.
//! What only a real process shows is the pair a script actually depends on — the exit code, and
//! whether one command line really does put a record in the tree through a running sidecar and a
//! running service. Both were the whole reason nothing emitted records: there was no command line.
//!
//! The spool case is here rather than in the unit tests for the same reason. `spooled` is a *success*
//! for the caller, and the only way to be sure of that is to point a real sidecar at a service that
//! is not there and read what the real binary exits with.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Child;

mod support;

use support::{Deployment, SIGNING_KEY, Service, await_socket, spawn, terminate, yaam, yaam_emit};

/// Where a sidecar with this state directory puts the caller socket.
fn socket_of(state: &Path) -> PathBuf {
    state.join("sockets/agent_a.sock")
}

/// Starts a sidecar in its own state directory, pointed at `base_url`.
///
/// The sealing key is generated here rather than taken from a service, so a sidecar can be pointed at
/// a service that does not exist — which is the whole spool case.
fn sidecar(
    deployment: &Deployment,
    name: &str,
    base_url: &str,
    public_key: &str,
) -> (PathBuf, Child) {
    let state = deployment.root().join(name);
    std::fs::create_dir_all(&state).expect("state dir");
    std::fs::write(
        state.join("upstream.json"),
        format!(
            r#"{{"base_url":"{base_url}","service_public_key":"{public_key}",
                 "signing_keys":{{"agent_a":"{SIGNING_KEY}"}},"retry_interval_ms":200}}"#
        ),
    )
    .expect("upstream");
    let child = spawn(
        env!("CARGO_BIN_EXE_yaam-agent"),
        &["--state-dir", state.to_str().expect("utf-8")],
    );
    let socket = socket_of(&state);
    drop(await_socket(&socket));
    (socket, child)
}

/// The arguments a shell hook passes, over a socket named by the environment.
fn hook_env(socket: &Path) -> Vec<(String, String)> {
    vec![
        (
            "YAAM_SOCKET".to_owned(),
            socket.to_str().expect("utf-8").to_owned(),
        ),
        ("YAAM_AGENT".to_owned(), "agent_a".to_owned()),
    ]
}

/// Borrows an environment for the helper, which takes slices.
fn as_pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// A record, one command line, all the way into the tree — through a real sidecar and service.
///
/// This is the assertion the whole binary exists for. Every hop is a separate process, and the only
/// thing the caller says is what it knows: the action, the outcome, the prose, and the attributes.
#[test]
fn one_command_line_puts_a_record_in_the_tree() {
    let deployment = Deployment::new();
    let root = deployment.root_str();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let env = hook_env(&socket);

    let emitted = yaam_emit(
        &[
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "rolled the api service out to staging",
            "--attr",
            "service=api",
            "--attr",
            "environment=staging",
            "--attr",
            "build=1146",
            "--entity",
            "deploy:api/staging#1146",
            "--tag",
            "release",
        ],
        &as_pairs(&env),
    );
    assert_eq!(
        emitted.status.code(),
        Some(0),
        "the service should have taken it: {}",
        String::from_utf8_lossy(&emitted.stderr)
    );

    // `<status> <record-id>` on the first line, because a script that wants the identifier should
    // not have to parse prose for it.
    let printed = String::from_utf8_lossy(&emitted.stdout).into_owned();
    let mut first = printed.lines().next().expect("a first line").split(' ');
    assert_eq!(first.next(), Some("accepted"), "{printed}");
    let id = first.next().expect("the record identifier");
    assert_eq!(id.len(), 26, "{printed}");

    // In the tree, under the day its own timestamp names, and in the index that `check` reads.
    let files = support::record_files(deployment.root());
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(
        files[0].ends_with(format!("{id}.md")),
        "{} is not the record the command reported",
        files[0].display()
    );
    let checked = yaam(&["--root", root, "check"]);
    let health = String::from_utf8_lossy(&checked.stdout);
    assert!(health.contains("records indexed    1"), "{health}");
    assert!(health.contains("index drift        0"), "{health}");

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// With the service unreachable the record is spooled, and that exits with its own code — a success,
/// because the sidecar has it and will keep trying.
#[test]
fn a_record_the_service_cannot_take_is_spooled_and_that_is_a_success() {
    let deployment = Deployment::new();
    let (_secret, public) = yaam_crypto::envelope::generate_keypair();
    // Port 1 answers nothing on any host these tests run on, which is the point: a sidecar whose
    // service is not there is exactly what the spool is for.
    let (socket, mut agent) = sidecar(
        &deployment,
        "orphan",
        "http://127.0.0.1:1",
        &hex::encode(public),
    );
    let env = hook_env(&socket);

    let emitted = yaam_emit(
        &[
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "rolled the api service out to staging",
        ],
        &as_pairs(&env),
    );
    assert_eq!(
        emitted.status.code(),
        Some(7),
        "spooled has its own code: {}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let printed = String::from_utf8_lossy(&emitted.stdout);
    assert!(printed.starts_with("spooled "), "{printed}");
    // The wording has to say the record is safe, or a reader of the log fixes the wrong thing.
    assert!(printed.contains("keeps trying"), "{printed}");

    terminate(&mut agent, "yaam-agent");
}

/// A record the deployment will never accept exits with the code that means "fix the record", and
/// says what to fix.
#[test]
fn a_policy_the_deployment_does_not_apply_is_rejected_with_something_to_do_about_it() {
    let deployment = Deployment::new();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let env = hook_env(&socket);

    let emitted = yaam_emit(
        &[
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "rolled the api service out to staging",
            "--redaction-policy",
            "not-the-one-in-force",
        ],
        &as_pairs(&env),
    );
    assert_eq!(emitted.status.code(), Some(8), "a permanent refusal");

    // The service's own reason, plus what to do about it. A bare 422 would leave the caller nothing.
    let told = String::from_utf8_lossy(&emitted.stderr);
    assert!(told.contains("not-the-one-in-force"), "{told}");
    assert!(told.contains("default-v1"), "{told}");
    assert!(told.contains("--redaction-policy"), "{told}");
    assert!(
        support::record_files(deployment.root()).is_empty(),
        "a refused record must not reach the tree"
    );

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// The failures that happen before anything is sent, each with its own code.
#[test]
fn the_refusals_that_need_no_deployment_have_their_own_codes() {
    let deployment = Deployment::new();
    // `--agent` included: it is refused at the resolve while the socket is refused at the send, so
    // omitting it here would test the agent's absence under a name about the socket's.
    let action = [
        "--agent",
        "agent_a",
        "--action",
        "deploy",
        "--outcome",
        "success",
        "--summary",
        "x",
    ];

    // No socket named at all: a configuration fault, and it says which variable would have said.
    let unset = yaam_emit(&action, &[]);
    assert_eq!(unset.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&unset.stderr).contains("YAAM_SOCKET"),
        "{}",
        String::from_utf8_lossy(&unset.stderr)
    );

    // A socket nothing is listening on. Nothing was recorded, and the message says so, because the
    // reader's next question is whether to send it again.
    let absent = deployment.root().join("nothing.sock");
    let mut args = action.to_vec();
    args.extend(["--socket", absent.to_str().expect("utf-8")]);
    let unreachable = yaam_emit(&args, &[]);
    assert_eq!(unreachable.status.code(), Some(9));
    assert!(
        String::from_utf8_lossy(&unreachable.stderr).contains("Nothing was recorded"),
        "{}",
        String::from_utf8_lossy(&unreachable.stderr)
    );

    // A bad argument is a usage error, told apart from a record the deployment refuses.
    let mut args = action.to_vec();
    args.extend([
        "--socket",
        "/x",
        "--agent",
        "agent_a",
        "--attr",
        "no-equals",
    ]);
    assert_eq!(yaam_emit(&args, &[]).status.code(), Some(2));
}

/// The dry run needs no sidecar and no service, and prints exactly the line a socket would take.
#[test]
fn a_dry_run_prints_a_record_nothing_has_to_be_running_to_see() {
    let dry = yaam_emit(
        &[
            "--socket",
            "/definitely/not/here.sock",
            "--agent",
            "agent_a",
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "rolled the api service out to staging",
            "--dry-run",
        ],
        &[],
    );
    assert_eq!(dry.status.code(), Some(0));

    let printed = String::from_utf8_lossy(&dry.stdout).into_owned();
    assert_eq!(printed.lines().count(), 1, "the socket takes one line");
    // Every field the schema requires, from a command line that named four of them.
    let record: serde_json::Value =
        serde_json::from_str(printed.trim()).expect("the line the sidecar parses");
    let fields = record.as_object().expect("an object");
    for required in [
        "record_id",
        "schema_ver",
        "at",
        "received_at",
        "backfilled",
        "agent",
        "action",
        "outcome",
        "attrs",
        "entities",
        "subjects",
        "visibility",
        "data_class",
        "redaction_policy",
        "fields_masked",
        "tags",
        "summary",
    ] {
        assert!(fields.contains_key(required), "{required} is missing");
    }
    assert_eq!(fields["subjects"].as_array().map(Vec::len), Some(0));
    assert_eq!(fields["data_class"], "internal");
}
