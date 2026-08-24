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

use std::path::Path;

mod support;

use support::{Deployment, Service, read_socket, sidecar, terminate, yaam, yaam_emit, yaam_read};

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

/// The two shapes this deployment emits first, each as the one command line an operator would type.
///
/// Separate from the case above because what it asserts is not the command line but the *spec*: the
/// service refuses an attribute key `spec/attrs-schema.yaml` does not declare, permanently, and the
/// emitter cannot read the spec to warn anybody first. So a shape is only emittable once a real
/// service has taken a real record carrying every key the shape uses — which is what makes the
/// declaration for `review` a change with a check behind it rather than one nobody could break.
///
/// Both through one deployment, and counted at the end: two records that landed as one, or as one
/// and a duplicate, would satisfy each command's own exit code.
#[test]
fn each_of_the_two_emitted_shapes_is_a_record_the_service_takes() {
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

    // A failed rollout, carrying every attribute the `deploy` group declares — including the integer
    // one, which is the type a value passed as `--attr` would have arrived as text under.
    let deployed = yaam_emit(
        &[
            "--action",
            "deploy",
            "--outcome",
            "failure",
            "--summary",
            "the api rollout to production stalled on the second shard and was rolled back",
            "--attr",
            "service=api",
            "--attr",
            "environment=production",
            "--attr",
            "build=b1042",
            "--attr-int",
            "duration_ms=94000",
            "--entity",
            "deploy:api/production#1042",
            "--entity",
            "ticket:PROJ-42",
            "--tag",
            "release",
        ],
        &as_pairs(&env),
    );
    assert_accepted("deploy", &deployed);

    // A review that read the whole diff and asked for changes: a success carrying a blocking
    // verdict, which is the pair `review` declares `verdict` apart from `outcome` for. What it
    // reviewed is entity references, so a later read joins it to the deploy that follows.
    let reviewed = yaam_emit(
        &[
            "--action",
            "review",
            "--outcome",
            "success",
            "--summary",
            "read the whole diff and asked for two changes before it can go in",
            "--attr",
            "verdict=changes_requested",
            "--attr-int",
            "findings=2",
            "--entity",
            "pull_request:owner/repo#84",
            "--entity",
            "commit:owner/repo@3f1c9ab",
            "--tag",
            "review",
        ],
        &as_pairs(&env),
    );
    assert_accepted("review", &reviewed);

    // Both in the tree and both in the index, with nothing the index cannot account for.
    let files = support::record_files(deployment.root());
    assert_eq!(files.len(), 2, "{files:?}");
    let health = String::from_utf8_lossy(&yaam(&["--root", root, "check"]).stdout).into_owned();
    assert!(health.contains("records indexed    2"), "{health}");
    assert!(health.contains("index drift        0"), "{health}");

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// A note from three years ago, imported, and it is stored as having happened three years ago.
///
/// Built on the shapes case above because what is under test is the same round trip with two extra
/// flags, and the interesting assertion is only reachable through the whole of it: the tree files a
/// record under the day its *received* time names, so the directory the file lands in is the store's
/// own answer to where in history this record sits. A backfill that took this clock for its received
/// time would land under today — accepted, indexed, and wrong in the one place nothing rewrites.
///
/// A record with neither flag goes through the same deployment, because the emitter is in a
/// deployment's write path and a regression in the ordinary case is silent.
#[test]
fn a_backfilled_record_is_stored_and_read_back_at_the_instant_it_happened() {
    const HAPPENED: &str = "2023-05-01T12:00:00Z";
    /// The same instant as the store spells it: one spelling, always UTC, always to a millisecond.
    const STORED: &str = "2023-05-01T12:00:00.000Z";

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

    let shape = [
        "--action",
        "deploy",
        "--outcome",
        "success",
        "--attr",
        "service=api",
        "--attr",
        "environment=production",
        "--attr",
        "build=b0001",
    ];

    let mut imported = shape.to_vec();
    imported.extend([
        "--summary",
        "the api rollout an existing note recorded, lifted into this store",
        "--at",
        HAPPENED,
        "--backfilled",
    ]);
    let imported = yaam_emit(&imported, &as_pairs(&env));
    assert_accepted("a backfill", &imported);
    let historical = accepted_id(&imported);

    // Neither flag, and nothing about it has changed: still now, still not a backfill.
    let mut live = shape.to_vec();
    live.extend(["--summary", "the api rollout that happened just now"]);
    let live = yaam_emit(&live, &as_pairs(&env));
    assert_accepted("the default path", &live);
    let today = accepted_id(&live);

    // Filed under the day it happened on, which is the whole point: this is the store's own record of
    // where in history it sits, and it is derived from the received time rather than from `at`.
    let files = support::record_files(deployment.root());
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(
        files
            .iter()
            .any(|path| path.ends_with(Path::new(&format!("records/2023/05/01/{historical}.md")))),
        "{files:?}"
    );

    // Read back over the caller's read socket, which is the shape any consumer sees.
    let reads = read_socket(&socket);
    let page = answered(&reads, &["records", "--limit", "10"]);
    let of = |id: &str| -> serde_json::Value {
        page["records"]
            .as_array()
            .expect("records")
            .iter()
            .find(|record| record["record_id"] == id)
            .unwrap_or_else(|| panic!("{id} is missing from {page}"))
            .clone()
    };

    let backfilled = of(&historical);
    assert_eq!(backfilled["backfilled"], true, "{backfilled}");
    assert_eq!(backfilled["at"], STORED, "{backfilled}");
    // The rule the flag carries: the received time is the source's instant too, so every ordering,
    // window and join places this in 2023 rather than among today's records.
    assert_eq!(backfilled["received_at"], STORED, "{backfilled}");

    let ordinary = of(&today);
    assert_eq!(ordinary["backfilled"], false, "{ordinary}");
    assert_eq!(ordinary["at"], ordinary["received_at"], "{ordinary}");
    assert_ne!(ordinary["at"], STORED, "{ordinary}");

    // And it answers 2023's window, which is the query the import exists to make answerable — and
    // the one that would have come back empty had the received time been this clock's. The window is
    // exclusive at the top, so the record's own millisecond is inside it.
    let window = answered(
        &reads,
        &[
            "records",
            "--from-ms",
            "1682899200000", // 2023-05-01T00:00:00Z
            "--to-ms",
            "1682985600000", // 2023-05-02T00:00:00Z
        ],
    );
    let matched = window["records"].as_array().expect("records");
    assert_eq!(matched.len(), 1, "{window}");
    assert_eq!(matched[0]["record_id"], historical, "{window}");

    let health = String::from_utf8_lossy(&yaam(&["--root", root, "check"]).stdout).into_owned();
    assert!(health.contains("records indexed    2"), "{health}");
    assert!(health.contains("index drift        0"), "{health}");

    terminate(&mut agent, "yaam-agent");
    service.stop();
}

/// A timestamp the record cannot honestly carry is refused by the command line itself.
///
/// No deployment, and `--dry-run` so no socket either: each of these is a refusal the emitter owes
/// the caller *before* anything is sent, because a record that reached an append-only store carrying
/// a timestamp nobody chose is not something a later fix can reach.
#[test]
fn a_timestamp_the_record_cannot_honestly_carry_never_leaves_the_command_line() {
    let base = [
        "--agent",
        "agent_a",
        "--action",
        "deploy",
        "--outcome",
        "success",
        "--summary",
        "rolled the api service out to staging",
        "--dry-run",
    ];
    // Malformed, in the future, history not declaring itself, and a declaration with nothing to
    // declare — the four the two flags have to refuse, and what each message has to name.
    let cases: [(&[&str], &str); 4] = [
        (&["--at", "1 May 2023"], "RFC3339"),
        (&["--at", "2999-01-01T00:00:00Z"], "has not reached"),
        (&["--at", "2023-05-01T12:00:00Z"], "--backfilled"),
        (&["--backfilled"], "--backfilled needs --at"),
    ];
    for (extra, expected) in cases {
        let mut args = base.to_vec();
        args.extend_from_slice(extra);
        let refused = yaam_emit(&args, &[]);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{extra:?} was not a usage error"
        );
        let told = String::from_utf8_lossy(&refused.stderr);
        assert!(told.contains(expected), "{extra:?} said: {told}");
        assert!(
            refused.stdout.is_empty(),
            "{extra:?} printed a record anyway"
        );
    }
}

/// One page from a caller's read socket, as the JSON a consumer would parse.
fn answered(reads: &Path, args: &[&str]) -> serde_json::Value {
    let env = [("YAAM_READ_SOCKET", reads.to_str().expect("utf-8"))];
    let read = yaam_read(args, &env);
    assert_eq!(
        read.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    serde_json::from_slice(&read.stdout).expect("the service's own JSON")
}

/// The identifier the emitter reported, from the first line of its own output.
fn accepted_id(emitted: &std::process::Output) -> String {
    let printed = String::from_utf8_lossy(&emitted.stdout).into_owned();
    printed
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .expect("the record identifier")
        .to_owned()
}

/// Asserts one emitted record was taken, and says which shape it was when it was not.
///
/// The service's own reason is on stderr, and it is the whole of what a failure here means: an
/// undeclared key names itself, so the message says which attribute the spec is missing.
fn assert_accepted(shape: &str, emitted: &std::process::Output) {
    assert_eq!(
        emitted.status.code(),
        Some(0),
        "the service refused the `{shape}` shape: {}",
        String::from_utf8_lossy(&emitted.stderr)
    );
    let printed = String::from_utf8_lossy(&emitted.stdout).into_owned();
    assert!(printed.starts_with("accepted "), "{shape}: {printed}");
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
