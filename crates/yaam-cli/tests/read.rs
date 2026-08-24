//! The reader as a script sees it: one command, over a real sidecar, against a real service.
//!
//! In-process tests already cover what request each read turns into and how each status is reported.
//! What only real processes show is the hop in the middle: the sidecar's read socket signing on the
//! caller's behalf. Nothing in this file holds a key, and that is the assertion — a command line with
//! no key material reads a record that a command line with no key material wrote.
//!
//! The exit codes are here for the same reason they are in the emitter's tests. A script branches on
//! them, and the one that matters most is the boring one: a read that matched nothing exits zero,
//! because a deployment where nothing happened today must not look like a deployment that is down.

#![forbid(unsafe_code)]

mod support;

use support::{Deployment, Service, read_socket, sidecar, terminate, yaam_emit, yaam_read};

/// The environment a hook exports for a read: one variable, and no key.
fn hook_env(socket: &std::path::Path) -> Vec<(String, String)> {
    vec![(
        "YAAM_READ_SOCKET".to_owned(),
        socket.to_str().expect("utf-8").to_owned(),
    )]
}

/// Borrows an environment for the helper, which takes slices.
fn as_pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// The one record every read here looks for.
fn write_one(socket: &std::path::Path) -> String {
    let emitted = yaam_emit(
        &[
            "--socket",
            socket.to_str().expect("utf-8"),
            "--agent",
            "agent_a",
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
            "--entity",
            "deploy:api/staging#1146",
            "--tag",
            "release",
        ],
        &[],
    );
    assert_eq!(
        emitted.status.code(),
        Some(0),
        "the record has to land before anything can read it: {}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let printed = String::from_utf8_lossy(&emitted.stdout).into_owned();
    printed
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .expect("the record identifier")
        .to_owned()
}

/// The answer to one read, as a script would consume it.
fn answered(args: &[&str], env: &[(&str, &str)]) -> serde_json::Value {
    let read = yaam_read(args, env);
    assert_eq!(
        read.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    serde_json::from_slice(&read.stdout).unwrap_or_else(|error| {
        panic!(
            "{args:?} did not print JSON ({error}): {}",
            String::from_utf8_lossy(&read.stdout)
        )
    })
}

/// Every read the service answers, through the socket that signs for a caller holding no key.
///
/// One deployment for all four, because starting a service and a sidecar is the expensive part and
/// what is under test is the request each read makes rather than the state each one needs.
#[test]
fn every_read_is_answered_through_a_socket_the_caller_holds_no_key_for() {
    let deployment = Deployment::new();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let id = write_one(&socket);
    let reads = read_socket(&socket);
    let env = hook_env(&reads);
    let env = as_pairs(&env);

    // The filtered query: the record that was just written, as structure.
    let records = answered(&["records", "--action", "deploy", "--limit", "5"], &env);
    assert_eq!(records["records"][0]["record_id"], id, "{records}");
    assert_eq!(records["records"][0]["action"], "deploy");
    // Structure and no prose, whichever read asked: the body never crosses the wire.
    assert!(records["records"][0].get("summary").is_none(), "{records}");
    assert!(records["token_estimate"].as_u64().is_some_and(|n| n > 0));

    // The same record found by what its body says, which is the read that reaches the prose without
    // returning any of it.
    let found = answered(&["search", "--query", "staging", "--limit", "5"], &env);
    assert_eq!(found["records"][0]["record_id"], id, "{found}");

    // One entity's history, by an identifier carrying the two characters that end a path segment.
    let history = answered(&["history", "--entity", "deploy:api/staging#1146"], &env);
    assert_eq!(history["records"][0]["record_id"], id, "{history}");

    // A bundle over the same entity, which is the read a caller composes context with.
    let bundle = answered(
        &[
            "bundle",
            "--entity",
            "deploy:api/staging#1146",
            "--limit",
            "5",
        ],
        &env,
    );
    assert_eq!(bundle["records"][0]["record_id"], id, "{bundle}");
    assert_eq!(bundle["degraded"], false, "{bundle}");

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// A read that matched nothing is an answer, not a failure.
///
/// The distinction the whole exit table exists for. Folded into a failure, every quiet day would
/// look like an outage — and the monitor that noticed would be the one to fix.
#[test]
fn a_read_that_matches_nothing_exits_zero_with_an_empty_page() {
    let deployment = Deployment::new();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let env = hook_env(&read_socket(&socket));

    let read = yaam_read(&["records", "--action", "nobody-did-this"], &as_pairs(&env));
    assert_eq!(read.status.code(), Some(0), "an empty page is an answer");
    let answer: serde_json::Value = serde_json::from_slice(&read.stdout).expect("JSON");
    assert_eq!(answer["records"].as_array().map(Vec::len), Some(0));

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// A request the deployment will never answer as asked exits with the code that means "fix the
/// request", and passes the service's own reason through.
#[test]
fn a_request_the_service_refuses_exits_with_its_own_code_and_reason() {
    let deployment = Deployment::new();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let env = hook_env(&read_socket(&socket));

    // A kind this deployment does not configure. Refused rather than answered with no rows, because
    // no rows would be indistinguishable from an entity that has no history.
    let refused = yaam_read(
        &["history", "--entity", "not_a_kind:whatever"],
        &as_pairs(&env),
    );
    assert_eq!(refused.status.code(), Some(8), "a permanent refusal");
    let told = String::from_utf8_lossy(&refused.stderr);
    assert!(told.contains("not_a_kind"), "{told}");
    assert!(
        refused.stdout.is_empty(),
        "a refusal must not print an answer: {}",
        String::from_utf8_lossy(&refused.stdout)
    );

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// With no service behind it, a read fails rather than waiting: an answer that arrived later would
/// be data that was already stale, so nothing is queued and the code says to ask again.
#[test]
fn a_read_the_service_cannot_answer_is_unreachable_rather_than_queued() {
    let deployment = Deployment::new();
    let (_secret, public) = yaam_crypto::envelope::generate_keypair();
    // Port 1 answers nothing on any host these tests run on, which is the point.
    let (socket, mut agent) = sidecar(
        &deployment,
        "orphan",
        "http://127.0.0.1:1",
        &hex::encode(public),
    );
    let env = hook_env(&read_socket(&socket));

    let read = yaam_read(&["records"], &as_pairs(&env));
    assert_eq!(read.status.code(), Some(9), "nothing was read");
    let told = String::from_utf8_lossy(&read.stderr);
    assert!(told.contains("never queued"), "{told}");

    terminate(&mut agent, "yaam-agent");
}

/// The failures that happen before anything is sent, each with its own code.
#[test]
fn the_refusals_that_need_no_deployment_have_their_own_codes() {
    let deployment = Deployment::new();

    // No socket named at all: a configuration fault, and it says which variable would have said.
    let unset = yaam_read(&["records"], &[]);
    assert_eq!(unset.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&unset.stderr).contains("YAAM_READ_SOCKET"),
        "{}",
        String::from_utf8_lossy(&unset.stderr)
    );

    // A socket nothing is listening on. Nothing was read, and the message says so, because the
    // reader's next question is whether the answer might have been half-formed.
    let absent = deployment.root().join("nothing.read.sock");
    let unreachable = yaam_read(
        &["--socket", absent.to_str().expect("utf-8"), "records"],
        &[],
    );
    assert_eq!(unreachable.status.code(), Some(9));
    assert!(
        String::from_utf8_lossy(&unreachable.stderr).contains("Nothing was read"),
        "{}",
        String::from_utf8_lossy(&unreachable.stderr)
    );

    // A bad argument is a usage error, told apart from a request the service refuses.
    let usage = yaam_read(&["--socket", "/x", "records", "--attr", "no-equals"], &[]);
    assert_eq!(usage.status.code(), Some(2));

    // And an unknown read is clap's to refuse, not the service's.
    assert_eq!(
        yaam_read(&["--socket", "/x", "wander"], &[]).status.code(),
        Some(2)
    );
}

/// Pointed at the record socket by mistake, it says which socket it wanted.
///
/// The likeliest misconfiguration there is: the two sockets sit in one directory under names one
/// character apart, and the record socket's answer to an HTTP request is JSON, so it looks almost
/// right.
#[test]
fn the_record_socket_is_named_when_a_read_is_sent_to_it() {
    let deployment = Deployment::new();
    let (_secret, public) = yaam_crypto::envelope::generate_keypair();
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        "http://127.0.0.1:1",
        &hex::encode(public),
    );

    let confused = yaam_read(
        &["--socket", socket.to_str().expect("utf-8"), "records"],
        &[],
    );
    assert_eq!(confused.status.code(), Some(1), "not a verdict on the read");
    let told = String::from_utf8_lossy(&confused.stderr);
    assert!(told.contains(".read.sock"), "{told}");

    terminate(&mut agent, "yaam-agent");
}

/// The dry run needs no sidecar and no service, and prints exactly the request a socket would take.
#[test]
fn a_dry_run_prints_a_request_nothing_has_to_be_running_to_see() {
    let dry = yaam_read(
        &[
            "--dry-run",
            "records",
            "--action",
            "deploy",
            "--attr",
            "environment=staging",
            "--limit",
            "5",
        ],
        &[],
    );
    assert_eq!(dry.status.code(), Some(0));

    let printed = String::from_utf8_lossy(&dry.stdout).into_owned();
    assert_eq!(
        printed.lines().next(),
        Some("GET /records?action=deploy&attr=environment%3Dstaging&limit=5 HTTP/1.1"),
        "{printed}"
    );
    // A whole request rather than a target, so it can be piped into the socket by hand.
    assert!(printed.ends_with("\r\n\r\n"), "{printed:?}");
}
