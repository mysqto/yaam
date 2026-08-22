//! `SIGKILL` at each durability window, to a real service, with a real store underneath.
//!
//! The in-process tests drive the write steps one at a time and then assert the sweeper converges.
//! What they cannot show is the half that matters most: a process that *died* — no unwinding, no
//! flush, no destructor — and a *different* process starting over the state it left. Everything
//! between the two here is real: a built binary, a signed request over a socket, `kill -9`, and a
//! second binary opening the same tree.
//!
//! Each test kills the service inside one window and then asserts what the store looks like
//! afterwards, because "the process died" is not an assertion about durability. The four claims
//! being checked, in the wording of the write pipeline's own guarantees:
//!
//! - no record is half-written: a body without frontmatter, a file the tree cannot parse;
//! - nothing acknowledged is lost, and nothing durable is lost either — a staged write is durable
//!   before the caller hears anything, so the sweeper owes it a place in the tree;
//! - a replay of a write whose answer never arrived is a duplicate, not a second record;
//! - the backlog drains: the service converges without an operator running anything.
//!
//! Slow by nature. The windows are opened by a checkpoint the binary is armed with
//! ([`yaam_core::crash`]) and closed by a signal, and convergence waits on the service's own
//! maintenance timer in another process — so these are `#[ignore]`d out of `cargo test` and run
//! by name:
//!
//! ```sh
//! cargo test -p yaam-cli --test crash_injection -- --ignored
//! ```
//!
//! `ci/check.sh` runs exactly that, so the gate covers them; the ignore keeps a routine
//! `cargo test --workspace` from paying for three restarts and their timers.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::time::Duration;

use yaam_contract::RecordId;
use yaam_core::crash;

mod support;

use support::{
    BODY, Deployment, PATIENCE, Service, age, age_fanout_claims, eventually, fanout, indexed,
    post_record, post_unanswered, record, record_files, timeline_mentions, write_request, yaam,
};

/// How long a test waits for another process to converge.
///
/// Generous on purpose: what it waits for is that process's maintenance timer, and the point of the
/// wait is convergence rather than latency. A test that allowed one interval would start failing the
/// day the interval moved.
const CONVERGENCE: Duration = Duration::from_mins(3);

/// Comfortably past the sweeper's grace period for a staging file.
const PAST_THE_GRACE_PERIOD: Duration = Duration::from_mins(2);

/// Comfortably past the grace period for a fan-out claim.
const PAST_THE_CLAIM_GRACE: Duration = Duration::from_mins(10);

/// The entity every fixture record names, and whose timeline the fan-out materialises.
const ENTITY: (&str, &str) = ("ticket", "PROJ-42");

#[test]
#[ignore = "kills real processes and waits on their maintenance timers; run with --ignored"]
fn a_kill_between_staging_and_publishing_loses_no_record() {
    let deployment = Deployment::new();
    let marker = deployment.root().join("crash.marker");
    let mut service = armed(&deployment, crash::STAGED, &marker);

    let record = record();
    let id = record.record_id.clone();
    // The connection is held open across the kill: the service dies with a request in flight, which
    // is the only state in which this window exists.
    let request = write_request(&record, BODY);
    let in_flight = post_unanswered(service.address, &request);
    assert!(
        eventually(PATIENCE, || marker.exists()),
        "the service never reached the staging window:\n{}",
        service.log_text()
    );
    service.kill_nine();
    drop(in_flight);

    // What the window leaves behind: a durable write-ahead copy and nothing else. The caller was
    // told nothing, so nothing is owed to it — but the record is on disk and is owed a place.
    assert!(
        deployment.staged(&id).is_file(),
        "the staged copy is fsynced before anything else happens; without it there is no promise"
    );
    assert!(!deployment.published(&id).exists());
    assert!(
        record_files(deployment.root()).is_empty(),
        "nothing published"
    );
    assert!(indexed(&deployment).is_empty(), "and nothing indexed");
    assert!(fanout(&deployment).is_empty(), "and no work queued");
    assert!(
        parses(&deployment.staged(&id)),
        "a torn staging file is a record no re-drive can publish"
    );

    // A staging file younger than the grace period may belong to a write in flight, and the sweeper
    // leaves it alone. Nothing is in flight — the process that owned it is gone — so rather than
    // wait the period out, the file is backdated to what it will look like when the next sweep runs.
    age(&deployment.staged(&id), PAST_THE_GRACE_PERIOD);
    let backlog = yaam(&["--root", deployment.root_str(), "check"]);
    let reported = String::from_utf8_lossy(&backlog.stdout);
    assert!(
        reported.contains("staging 1"),
        "an operator has to be able to see the work that is owed:\n{reported}"
    );

    let mut restarted = Service::start(&deployment);
    assert!(
        eventually(CONVERGENCE, || deployment.published(&id).is_file()
            && indexed(&deployment).contains_key(id.as_str())),
        "the staged write never reached the tree:\n{}",
        restarted.log_text()
    );
    assert_eq!(
        record_files(deployment.root()).len(),
        1,
        "the re-drive published the record once"
    );
    assert!(
        !deployment.staged(&id).exists(),
        "the rename consumed the staged copy"
    );
    assert_eq!(
        dead_letters(&deployment),
        Vec::<String>::new(),
        "a record the sweeper can re-drive must not be set aside"
    );
    assert!(
        eventually(CONVERGENCE, || timeline_mentions(&dir(&deployment), &id)
            == 1),
        "the fan-out the re-drive enqueued never drained:\n{}",
        restarted.log_text()
    );

    converged_after_a_replay(&deployment, &mut restarted, &record);
    restarted.stop();
    let checked = yaam(&["--root", deployment.root_str(), "check"]);
    let printed = String::from_utf8_lossy(&checked.stdout);
    assert!(printed.contains("index drift        0"), "{printed}");
    assert!(printed.contains("sweeper backlog    0"), "{printed}");
}

#[test]
#[ignore = "kills real processes and waits on their maintenance timers; run with --ignored"]
fn a_kill_after_the_commit_and_before_fan_out_loses_no_work() {
    let deployment = Deployment::new();
    let marker = deployment.root().join("crash.marker");
    let mut service = armed(&deployment, crash::COMMITTED, &marker);

    let record = record();
    let id = record.record_id.clone();
    let request = write_request(&record, BODY);
    let in_flight = post_unanswered(service.address, &request);
    assert!(
        eventually(PATIENCE, || marker.exists()),
        "the service never reached the window after the commit:\n{}",
        service.log_text()
    );
    service.kill_nine();
    drop(in_flight);

    // The record is published and indexed, and its fan-out was enqueued inside that same
    // transaction — which is the correction this window exists to check. Enqueueing after the commit
    // would leave exactly this state with no queue row, and nothing would ever notice.
    assert!(deployment.published(&id).is_file());
    assert!(indexed(&deployment).contains_key(id.as_str()));
    assert_eq!(
        fanout(&deployment),
        vec![format!("{}/bundle/pending", id.as_str())],
        "a record without its fan-out jobs is work nothing will ever do"
    );
    assert!(
        !deployment.staged(&id).exists(),
        "the rename happened, so the staged copy is gone"
    );
    assert_eq!(
        timeline_mentions(&dir(&deployment), &id),
        0,
        "the drain had not run: this is the backlog the restart has to get through"
    );

    let mut restarted = Service::start(&deployment);
    assert!(
        eventually(CONVERGENCE, || timeline_mentions(&dir(&deployment), &id)
            == 1),
        "the queued fan-out never drained after the restart:\n{}",
        restarted.log_text()
    );
    assert_eq!(
        fanout(&deployment),
        vec![format!("{}/bundle/done", id.as_str())],
        "the job is settled, not left to be claimed again"
    );

    converged_after_a_replay(&deployment, &mut restarted, &record);
    restarted.stop();
}

#[test]
#[ignore = "kills real processes and waits on their maintenance timers; run with --ignored"]
fn a_kill_during_a_timeline_rollover_loses_no_history() {
    let deployment = Deployment::new();
    let timeline = dir(&deployment);
    fs::create_dir_all(&timeline).expect("timeline dir");
    // A timeline at the size that makes the next append roll it over. Written by hand because
    // reaching it through the service would mean a thousand records for a property one file states.
    let history = full_head();
    let lines = history.lines().count();
    fs::write(timeline.join("timeline.md"), &history).expect("a full head");

    let marker = deployment.root().join("crash.marker");
    let mut service = armed(&deployment, crash::ROLLED_OVER, &marker);
    let record = record();
    let id = record.record_id.clone();
    // The write itself completes: the rollover happens later, in the drain, which is where the
    // service is armed to stop. So this record is acknowledged, and losing it is not an option.
    let answer = post_record(service.address, &record, BODY);
    assert_eq!(answer.status, 201, "{}", answer.body);
    assert!(
        eventually(CONVERGENCE, || marker.exists()),
        "the drain never rolled the timeline over:\n{}",
        service.log_text()
    );
    service.kill_nine();

    // Mid-rollover: the head has been frozen into a part and nothing has taken its place.
    let part = timeline.join("timeline-0001.md");
    assert_eq!(
        fs::read_to_string(&part).expect("the frozen part"),
        history,
        "the frozen part is the old head, line for line"
    );
    assert!(
        !timeline.join("timeline.md").exists(),
        "this window is the one where the head is missing"
    );
    assert_eq!(timeline_mentions(&timeline, &id), 0, "the append never ran");
    assert_eq!(
        fanout(&deployment),
        vec![format!("{}/bundle/claimed", id.as_str())],
        "the claim is held by a process that no longer exists"
    );

    // The claim is left held for now, deliberately. It makes the job invisible to every drain, so
    // the head coming back can only be the sweeper's own repair — and the missing head is what a
    // reader trips over whether or not another record ever names this entity again.
    let mut restarted = Service::start(&deployment);
    let head = timeline.join("timeline.md");
    assert!(
        eventually(CONVERGENCE, || head.is_file()),
        "a reader expects a head, and only the sweeper can put one back here:\n{}",
        restarted.log_text()
    );
    assert_eq!(
        fs::read_to_string(&head).expect("the repaired head"),
        "",
        "the repair starts a fresh head; the frozen lines stay frozen"
    );

    // Nothing renews a claim, and nothing else may take the job until the claim is old enough for
    // its holder to be presumed dead. Five minutes is longer than a test should sit still for, so
    // the claim is backdated to what the next sweep will see.
    assert_eq!(age_fanout_claims(&deployment, PAST_THE_CLAIM_GRACE), 1);
    assert!(
        eventually(CONVERGENCE, || timeline_mentions(&timeline, &id) == 1),
        "the interrupted append never completed:\n{}",
        restarted.log_text()
    );
    assert_eq!(
        fs::read_to_string(&part).expect("the frozen part"),
        history,
        "the frozen part is still what it was: a rollover freezes history, it does not rewrite it"
    );
    assert_eq!(
        counted_lines(&timeline),
        lines + 1,
        "every seeded line survives and the interrupted append landed once"
    );

    converged_after_a_replay(&deployment, &mut restarted, &record);
    restarted.stop();
}

/// A service armed to stop at one checkpoint, with a marker naming the file it touches on the way.
fn armed(deployment: &Deployment, point: &str, marker: &std::path::Path) -> Service {
    Service::start_with_env(
        deployment,
        &[
            (crash::ENV_POINT, point),
            (crash::ENV_MARKER, marker.to_str().expect("utf-8")),
        ],
    )
}

/// Replays the write and asserts the store is where it was.
///
/// The shared tail of all three tests, because retrying is the right thing for a caller whose answer
/// never arrived to do, and two of these crashes leave a write in exactly that state. A replay has to
/// change nothing whichever it was: not the tree, not the index, not the timeline.
fn converged_after_a_replay(
    deployment: &Deployment,
    service: &mut Service,
    record: &yaam_contract::ActionRecord,
) {
    let files = record_files(deployment.root());
    let queued = fanout(deployment);
    let mentions = timeline_mentions(&dir(deployment), &record.record_id);

    let answer = post_record(service.address, record, BODY);
    assert_eq!(
        answer.status, 200,
        "a replay is a duplicate: {}",
        answer.body
    );
    assert!(
        answer.body.contains("duplicate"),
        "the caller has to be told it already landed: {}",
        answer.body
    );

    assert_eq!(record_files(deployment.root()), files, "no second file");
    assert_eq!(fanout(deployment), queued, "no second job");
    assert_eq!(
        timeline_mentions(&dir(deployment), &record.record_id),
        mentions,
        "no second timeline entry"
    );
    assert_eq!(
        indexed(deployment).len(),
        1,
        "and one row, however many times it is written"
    );
}

/// Where the fixture record's entity timeline lives.
fn dir(deployment: &Deployment) -> std::path::PathBuf {
    deployment.timeline_dir(ENTITY.0, ENTITY.1)
}

/// A timeline head at its rollover size, made of records this test does not otherwise name.
fn full_head() -> String {
    let mut text = String::new();
    while text.len() < 64 * 1024 {
        let _ = writeln!(
            text,
            "- [[record:{}]] 2026-08-19T09:00:00Z deploy success",
            RecordId::generate().as_str()
        );
    }
    text
}

/// Lines across a timeline head and every frozen part.
fn counted_lines(timeline: &std::path::Path) -> usize {
    fs::read_dir(timeline)
        .expect("timeline dir")
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
                .lines()
                .count()
        })
        .sum()
}

/// Whatever the sweeper gave up on. The directory itself is made at startup, so its existence says
/// nothing; what it holds does.
fn dead_letters(deployment: &Deployment) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(deployment.root().join(".dead-letter"))
        .expect("the dead-letter directory is made at startup")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Whether a record file on disk is a record, rather than the front half of one.
fn parses(path: &std::path::Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| yaam_md::Document::parse(&text).is_ok())
}
