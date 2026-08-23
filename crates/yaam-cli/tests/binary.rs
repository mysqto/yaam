//! The three binaries as a script and a caller see them.
//!
//! The unit tests exercise the same paths in process. This runs the built binaries, because two
//! things are not observable from inside: the exit code, which is the interface anything scripting
//! this branches on, and whether the three actually talk to each other over a socket and a port.
//!
//! The end-to-end test is the one that would have caught this repository having no entry points at
//! all: a record written to a caller socket, sealed by the sidecar, posted to the service, published
//! to the tree, and then found by `yaam check`. What a *killed* process leaves behind is the other
//! integration test in this directory.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};

mod support;

use support::{
    Deployment, MAINTENANCE_MS, SIGNING_KEY, Service, await_socket, record, rendered, setting,
    spawn, terminate, yaam,
};

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
            "a rebuild works, and drains what it re-enqueued",
        ),
        (
            vec!["--root", root, "drain"],
            0,
            "nothing is queued, because the rebuild already ran it",
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
    // The interval this harness sets through the environment, read back out of the process that was
    // given it. A variable the binary ignored would leave every convergence wait in these tests on
    // the 30-second default, and pass anyway.
    assert_eq!(
        setting(&service.log_text(), "maintenance-ms").as_deref(),
        Some(MAINTENANCE_MS),
        "the service did not take the interval it was given:\n{}",
        service.log_text()
    );

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
    let published = deployment.published(&record.record_id);
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
