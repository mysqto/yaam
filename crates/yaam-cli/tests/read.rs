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
/// One deployment for all five, because starting a service and a sidecar is the expensive part and
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

    a_traversal_reaches_what_no_record_named(&socket, &env, &records);

    // Last, because it needs a second record and every read above asserts on the newest one.
    // A join cannot pair a record with itself, so a correlation over one record could only ever
    // answer an empty page — which would not prove the read reaches the index at all.
    let second = write_one(&socket);
    // Two deploys inside the same second, correlated: the read whose answer is pairs rather than
    // records, and the one the service refuses to answer without a window.
    let day = 24 * 60 * 60 * 1000;
    let stamped = records["records"][0]["received_at"]
        .as_str()
        .expect("a read reports the server-stamped time");
    let at = yaam_contract::timestamp::parse_ms(stamped).expect("a contract timestamp");
    let correlated = answered(
        &[
            "correlate",
            "--left-action",
            "deploy",
            "--right-action",
            "deploy",
            "--left-from-ms",
            &(at - day).to_string(),
            "--left-to-ms",
            &(at + day).to_string(),
            "--within-ms",
            &day.to_string(),
        ],
        &env,
    );
    // Pairs, not records: which record happened near which is what the read answers, and both halves
    // are the records this test wrote.
    assert!(correlated.get("records").is_none(), "{correlated}");
    let written = [id.as_str(), second.as_str()];
    let pair = &correlated["pairs"][0];
    assert!(
        written.contains(&pair["left"]["record_id"].as_str().unwrap_or_default()),
        "{correlated}"
    );
    assert!(
        written.contains(&pair["right"]["record_id"].as_str().unwrap_or_default()),
        "{correlated}"
    );
    assert_ne!(pair["left"]["record_id"], pair["right"]["record_id"]);
    // Structure on both sides, so a correlation withholds prose twice per row.
    assert!(pair["left"].get("summary").is_none(), "{correlated}");
    assert!(pair["right"].get("summary").is_none(), "{correlated}");

    // A window is the one thing this read will not guess at, and the refusal names the flag rather
    // than a query parameter the caller never typed.
    let refused = yaam_read(&["correlate", "--within-ms", "1000"], &env);
    // `2`, the usage code, as the other refusals in this file name their codes as literals.
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--left-from-ms"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// The graph read, end to end: two records that share an entity, and a hop past both of them.
///
/// Its own function rather than more of the read above, because it needs a fixture the other reads
/// do not — a traversal is the one read whose answer is about something no record the caller named
/// contains, so a store of one record could only ever answer it an empty page.
fn a_traversal_reaches_what_no_record_named(
    socket: &std::path::Path,
    env: &[(&str, &str)],
    records: &serde_json::Value,
) {
    // The graph read, which needs two records that share an entity: it is the only read here whose
    // answer is about something no record the caller named contains, so a fixture of one record
    // could only ever answer an empty page.
    let bridge = emit(
        socket,
        &[
            "--summary",
            "linking the staging deploy to the ticket",
            "--entity",
            "deploy:api/staging#1146",
            "--entity",
            "ticket:PROJ-90",
        ],
    );
    let onward = emit(
        socket,
        &[
            "--summary",
            "linking the ticket to the order reference",
            "--entity",
            "ticket:PROJ-90",
            "--entity",
            "order_ref:ord10014733",
        ],
    );
    let stamp = records["records"][0]["received_at"]
        .as_str()
        .expect("a read reports the server-stamped time");
    let now = yaam_contract::timestamp::parse_ms(stamp).expect("a contract timestamp");
    let hop = 24 * 60 * 60 * 1000;
    let linked = answered(
        &[
            "linked",
            "--entity",
            "deploy:api/staging#1146",
            "--depth",
            "2",
            "--from-ms",
            &(now - hop).to_string(),
            "--to-ms",
            &(now + hop).to_string(),
        ],
        env,
    );
    // Edges and hubs, not records: the shape is the answer, and a graph flattened into a list would
    // leave the caller re-joining it.
    assert!(linked.get("records").is_none(), "{linked}");
    let edges = linked["edges"].as_array().expect("edges");
    assert_eq!(edges.len(), 2, "{linked}");
    assert_eq!(edges[0]["hop"], 1, "{linked}");
    assert_eq!(edges[0]["to"]["id"], "PROJ-90", "{linked}");
    assert_eq!(edges[0]["via"]["record_id"], bridge, "{linked}");
    // The second hop reaches an order reference the deploy's own record never named — which is the
    // capability, and it arrives with the record that justifies it.
    assert_eq!(edges[1]["hop"], 2, "{linked}");
    assert_eq!(edges[1]["to"]["id"], "ord10014733", "{linked}");
    assert_eq!(edges[1]["via"]["record_id"], onward, "{linked}");
    assert!(edges[1]["via"].get("summary").is_none(), "{linked}");
    assert!(
        linked["hubs"].as_array().expect("hubs").is_empty(),
        "{linked}"
    );

    // The window is the one thing this read will not guess at either, and the refusal names the flag.
    let refused = yaam_read(
        &["linked", "--entity", "ticket:PROJ-90", "--depth", "2"],
        env,
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--from-ms"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

/// The rules the workspace ships, as a caller names them.
fn spec_dir() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec")
        .to_str()
        .expect("utf-8 path")
        .to_owned()
}

/// Writes one record and returns its identifier.
fn emit(socket: &std::path::Path, extra: &[&str]) -> String {
    let mut args = vec![
        "--socket",
        socket.to_str().expect("utf-8"),
        "--agent",
        "agent_a",
        "--action",
        "note",
        "--outcome",
        "success",
    ];
    args.extend_from_slice(extra);
    let emitted = yaam_emit(&args, &[]);
    assert_eq!(
        emitted.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    String::from_utf8_lossy(&emitted.stdout)
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .expect("the record identifier")
        .to_owned()
}

/// A bundle asks about entities it read out of the request's own prose — and joins on no more than
/// it did before.
///
/// Two records, and the difference between them is the property under test. One *states*
/// `ticket:PROJ-77`; the other only mentions `ticket:PROJ-88` in prose, so its one reference was
/// inferred at the confidence an inferred reference carries. A bundle must return the first and
/// never the second: read-time inference decides what to look *for*, and is not allowed to decide
/// what counts as found.
///
/// So this is two assertions in one deployment, and neither means much alone. Without the first, an
/// empty bundle would only show that the lookup key never got there; without the second, the floor
/// could have been lowered and nothing here would notice.
#[test]
fn prose_names_the_entities_a_bundle_asks_about_without_lowering_what_it_joins_on() {
    let deployment = Deployment::new();
    let mut service = Service::start(&deployment);
    let (socket, mut agent) = sidecar(
        &deployment,
        "agent",
        &format!("http://{}", service.address),
        &service.sealing_public_key,
    );
    let spec = spec_dir();
    let stated = emit(
        &socket,
        &[
            "--summary",
            "picked the review back up",
            "--entity",
            "ticket:PROJ-77",
        ],
    );
    let inferred = emit(
        &socket,
        &[
            "--summary",
            "reopened ticket PROJ-88 after the overnight report",
            "--infer-entities",
            &spec,
        ],
    );
    assert_ne!(stated, inferred);

    let env = hook_env(&read_socket(&socket));
    let env = as_pairs(&env);

    // The inferred record is really there and really carries the reference. Its history says so,
    // because a history accepts every confidence — which is exactly what a bundle does not.
    let history = answered(&["history", "--entity", "ticket:PROJ-88"], &env);
    assert_eq!(history["records"][0]["record_id"], inferred, "{history}");

    // A sentence naming the stated entity finds the record that stated it. This is the read that
    // did not exist before: nothing here typed `ticket:PROJ-77`.
    let found = answered(
        &[
            "bundle",
            "--infer-entities",
            &spec,
            "--infer-from",
            "any news on ticket PROJ-77?",
            "--limit",
            "5",
        ],
        &env,
    );
    assert_eq!(found["records"][0]["record_id"], stated, "{found}");

    // The empty answer below has to mean the floor held, not that the key never travelled. So the
    // request itself is checked first, where a dry run can print it without a socket.
    let dry = yaam_read(
        &[
            "--dry-run",
            "bundle",
            "--infer-entities",
            &spec,
            "--infer-from",
            "any news on ticket PROJ-88?",
        ],
        &[],
    );
    let printed = String::from_utf8_lossy(&dry.stdout);
    assert!(printed.contains("entity=ticket%3APROJ-88"), "{printed}");

    // The same sentence about the inferred one asks the same question and is answered with nothing.
    let empty = answered(
        &[
            "bundle",
            "--infer-entities",
            &spec,
            "--infer-from",
            "any news on ticket PROJ-88?",
            "--limit",
            "5",
        ],
        &env,
    );
    assert_eq!(
        empty["records"].as_array().map(Vec::len),
        Some(0),
        "a reference a record only implies must not reach a bundle: {empty}"
    );

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
