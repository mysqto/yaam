//! Bringing the service up, and taking it down without dropping a request.
//!
//! Binding and serving are two steps rather than one. A caller that has bound knows the address it
//! actually got, which is what makes a test on an ephemeral port possible — and a test that cannot
//! bind an ephemeral port is a test that fights over a fixed one.
//!
//! The service also does the maintenance its store needs, at boot and then on a timer: fan-out is
//! queued inside the write transaction and drained afterwards, and the sweeper is what closes the
//! crash windows the write path leaves open. Neither has any other caller in a running deployment,
//! so a service that only answered requests would answer them correctly while its entity timelines
//! never appeared and its backlog only grew.
//!
//! At boot as well as on the timer, because what the last process left owed is owed before any
//! interval elapses. Waiting one out first means a service restarted and stopped again inside one
//! never converges at all — and a restart loop is precisely the condition under which a store has
//! work outstanding.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use yaam_crypto::keystore::KeyMaterial;
use yaam_server::routes::{self, AppState};
use yaam_server::service::CoreService;

use crate::config::ServerSettings;
use crate::error::{Result, failed};
use crate::keyring;

/// Fan-out jobs one maintenance round takes.
///
/// Bounded so one round cannot hold the write lock for an unbounded time behind a burst; what it
/// does not get through is still queued for the next.
const MAINTENANCE_JOBS: usize = 256;

/// A bound listener and everything that will serve on it.
///
/// Held rather than served immediately so the caller can learn the address first.
#[derive(Debug)]
pub struct Bound {
    /// Already accepting, so nothing can take the port between here and [`serve`].
    listener: TcpListener,
    /// The endpoints.
    router: Router,
    /// The service the maintenance timer works through.
    service: Arc<CoreService>,
    /// How often maintenance runs.
    maintenance: Duration,
    /// The address the kernel actually gave out. Not the requested one: port `0` is a request.
    pub address: SocketAddr,
}

/// Builds the service, binds the address, and says what it is running with.
///
/// Every refusal happens here, before anything is accepting: a keyring that will not load, a sealing
/// key of the wrong length and an address already taken are all misconfigurations, and a service that
/// started anyway would report them one failed request at a time.
pub async fn bind(settings: &ServerSettings) -> Result<Bound> {
    let keyring = Arc::new(keyring::load(&settings.keyring)?);
    let sealing = settings
        .unseal_key_file
        .as_deref()
        .map(keyring::unseal_key)
        .transpose()?;

    let pipeline = settings.store.open()?;
    // Read here like every other refusal: a key store whose files cannot be read is a service that
    // would fail sealed writes one request at a time.
    let keys = KeyReport {
        on_disk: pipeline
            .key_material()
            .map_err(|error| failed("reading how key material on disk is protected", &error))?,
        wrapper: pipeline.key_wrapper_scheme(),
        wrapper_protects: pipeline.key_wrapper_protects(),
    };
    let service = Arc::new(CoreService::with_pipeline(pipeline));
    let mut state = AppState::new(Arc::clone(&keyring), Arc::clone(&service) as Arc<_>);
    if let Some((secret, _)) = &sealing {
        state = state.unsealing_with(secret.to_vec());
    }

    let listener = TcpListener::bind(settings.listen)
        .await
        .map_err(|error| failed(&format!("binding {}", settings.listen), &error))?;
    let address = listener
        .local_addr()
        .map_err(|error| failed("reading the bound address", &error))?;

    announce(
        settings,
        address,
        sealing.as_ref().map(|(_, public)| *public),
        &keys,
    );

    Ok(Bound {
        listener,
        router: routes::router(state),
        service,
        maintenance: settings.maintenance,
        address,
    })
}

/// Serves until `shutdown` completes, then finishes what is in flight.
///
/// `shutdown` is a parameter rather than a signal handler reached for inside, because a shutdown path
/// only a signal can trigger is a shutdown path no test exercises.
pub async fn serve<S>(bound: Bound, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    let Bound {
        listener,
        router,
        service,
        maintenance,
        address: _,
    } = bound;

    let (closing, closed) = watch::channel(false);
    // The boot round lives in this task rather than ahead of the accept loop on purpose: a sweep
    // walks the tree, so a round awaited before serving is a startup as slow as the backlog is
    // deep — and a health check that times out restarts the very service that was converging.
    let timer = tokio::spawn(maintenance_loop(service, maintenance, closed));

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;

    // After the requests, not before: a request being finished may still enqueue fan-out, and a
    // round already in flight is the one that would have taken it. What a shutdown still leaves
    // queued is what the next boot's first round is for.
    let _ = closing.send(true);
    let _ = timer.await;
    served.map_err(|error| failed("serving", &error))
}

/// Drains fan-out and sweeps, until told to stop.
///
/// The work is filesystem and database work, so each round runs on a blocking thread: doing it on a
/// runtime worker would park that worker for the length of a sweep, and the sweep walks the tree.
///
/// A round happens before the first sleep, and a failing one is logged like any other: a store that
/// cannot be swept is a reason to say so and serve, not a reason to refuse to come up. The failure
/// this shape has to survive is the one that repeats — a round that fails at boot fails on the timer
/// too — so the loop cannot be allowed to treat either as fatal.
async fn maintenance_loop(
    service: Arc<CoreService>,
    interval: Duration,
    mut closed: watch::Receiver<bool>,
) {
    loop {
        let round = Arc::clone(&service);
        match tokio::task::spawn_blocking(move || round.maintain(MAINTENANCE_JOBS)).await {
            Ok(Ok(report)) if report.did_nothing() => {}
            Ok(Ok(report)) => tracing::info!(
                fanout_settled = report.fanout_settled,
                staged_redriven = report.sweep.staged_redriven,
                reindexed = report.sweep.reindexed,
                entities_repaired = report.sweep.entities_repaired,
                fanout_reclaimed = report.sweep.fanout_reclaimed,
                "maintenance"
            ),
            Ok(Err(error)) => tracing::warn!(%error, "maintenance round failed"),
            Err(error) => tracing::error!(%error, "maintenance round panicked"),
        }
        tokio::select! {
            biased;
            _ = closed.changed() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// What a startup log has to say about key material.
///
/// Two answers rather than one, gathered at the same moment: what the key files on disk carry, and
/// what this service would write. Held apart deliberately — treating the second as the first is the
/// mistake that reported a wrapped store as development-only.
struct KeyReport {
    /// What the key material already on disk says about its own protection.
    on_disk: KeyMaterial,
    /// How the wrapper this service holds would protect a key it writes.
    wrapper: &'static str,
    /// Whether that wrapper protects at all.
    wrapper_protects: bool,
}

/// Logs the effective configuration, once, at startup.
///
/// Paths, the address, and whether sealed bodies can be opened. No key material: the secret half is
/// never printed, and the public half is, because a sidecar has to be configured with it and a
/// service that made an operator dig it out of a file is a service configured by guesswork.
fn announce(
    settings: &ServerSettings,
    address: SocketAddr,
    sealing_public_key: Option<[u8; 32]>,
    keys: &KeyReport,
) {
    for (setting, value) in settings.store.describe() {
        tracing::info!(setting, %value, "configuration");
    }
    tracing::info!(setting = "listen", value = %address, "configuration");
    tracing::info!(
        setting = "keyring",
        value = %settings.keyring.display(),
        "configuration"
    );
    // Worth a line of its own: it is how far behind a timeline may be, and an operator reading a
    // stale one needs to know whether the interval or the sweeper is the reason.
    tracing::info!(
        setting = "maintenance-ms",
        value = settings.maintenance.as_millis(),
        "configuration"
    );
    if let Some(public) = sealing_public_key {
        tracing::info!(
            setting = "sealing-public-key",
            value = %hex::encode(public),
            "configuration: configure each sidecar with this"
        );
    } else {
        tracing::warn!(
            "no --unseal-key-file: this service accepts plain JSON only and will refuse a sealed \
             body. A sidecar posting to it would spool for ever"
        );
    }
    // Two facts, not one, and the difference between them matters: what the key files on disk carry,
    // and what this service will write. They are the same sentence on a store this service has
    // always run over, and an operator who can see both can spot a store about to end up holding
    // half of each. The first is the one `yaam check` prints, from the same place, so the two cannot
    // disagree about one store.
    tracing::info!(
        setting = "key wrapping",
        value = %keys.on_disk,
        "configuration"
    );
    tracing::info!(
        setting = "key wrapper",
        value = keys.wrapper,
        "configuration: what this service writes new keys under"
    );
    if let Some(warning) = key_warning(keys) {
        tracing::warn!("{warning}");
    }
}

/// Key material on disk that anyone who can read the files can use.
const KEYS_EXPOSED: &str = "subject keys on disk are stored unwrapped, so a key file recovered from a snapshot, a stale \
     volume or a decommissioned disk is a usable key. Fit a wrapper: until then, destroying a key \
     erases nothing that a copy of that file can still open";

/// Nothing on disk yet, and this service about to write key material in the clear.
const KEYS_WILL_BE_IN_THE_CLEAR: &str = "this store holds no key material yet, and no --key-passphrase-file: the first subject key \
     this service mints will be stored as written. Fit a wrapper before this store holds anyone's \
     data \u{2014} a wrapper fitted afterwards leaves the keys written before it unreadable rather \
     than migrating them";

/// Key material on disk this service holds no wrapper for.
const KEYS_UNREADABLE: &str = "the key material on disk is wrapped and this service was given no --key-passphrase-file: it \
     cannot unwrap a single subject key, so every sealed body it is asked for will fail to open. \
     Point it at the passphrase the store was written under";

/// What a startup log warns about key material, or nothing where nothing is wrong.
///
/// A function returning the sentence rather than a run of `if`s inside the log call: which of these
/// cases deserves a warning is exactly what this change had to decide, and a decision only a log
/// line records is a decision no test can contradict.
fn key_warning(keys: &KeyReport) -> Option<&'static str> {
    // Present tense, about the disk, and whatever this process holds: key material somebody can read
    // is there to be read either way. First, because a mixed store is exposed and unreadable at once
    // and the exposure is the half that cannot wait.
    if keys.on_disk.exposed() {
        return Some(KEYS_EXPOSED);
    }
    if keys.wrapper_protects {
        return None;
    }
    match keys.on_disk {
        // A store with no key material has nothing exposed, so the warning above would be a claim
        // about files that do not exist -- the false alarm every fresh store used to raise. Silence
        // would give up the one moment fitting a wrapper is free, so this says it in the future
        // tense instead, and only where it is true. A fresh store opened with a passphrase is quiet.
        KeyMaterial::Absent => Some(KEYS_WILL_BE_IN_THE_CLEAR),
        // Wrapped on disk, no wrapper here. Not an exposure -- the files are protected -- but this
        // service cannot read them, and that is a misconfiguration an operator would otherwise meet
        // one failed read at a time.
        KeyMaterial::Wrapped { .. } => Some(KEYS_UNREADABLE),
        // Unreachable: both are exposed, and returned above.
        KeyMaterial::Unwrapped { .. } | KeyMaterial::Mixed { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use yaam_contract::RecordId;
    use yaam_server::service::CoreService;

    use super::{KeyMaterial, KeyReport, bind, key_warning, serve};
    use crate::cli::{ServerArgs, StoreArgs};
    use crate::config::{DEFAULT_MAINTENANCE_MS, Env, ServerSettings};
    use crate::exit::Exit;
    use crate::fixtures;

    /// A tree with this repository's spec, a keyring, and a sealing key.
    struct Deployment {
        dir: tempfile::TempDir,
    }

    impl Deployment {
        fn new() -> Self {
            let dir = fixtures::tree();
            std::fs::write(
                dir.path().join("keyring.json"),
                r#"{"callers":{"agent_a":{"role":"writer","key":"aabb"}}}"#,
            )
            .expect("keyring");
            let (secret, _) = yaam_crypto::envelope::generate_keypair();
            std::fs::write(dir.path().join("unseal.key"), hex::encode(secret)).expect("key");
            Self { dir }
        }

        fn settings(&self, listen: &str) -> ServerSettings {
            self.settings_with(listen, None)
        }

        /// The same, naming an interval, which is what a test that waits on a round needs.
        fn settings_with(&self, listen: &str, maintenance_ms: Option<u64>) -> ServerSettings {
            let flags = ServerArgs {
                store: StoreArgs {
                    root: Some(self.dir.path().to_path_buf()),
                    index: None,
                    key_store: None,
                    key_passphrase_file: None,
                    subject_key_file: None,
                },
                listen: Some(listen.to_owned()),
                keyring: Some(self.dir.path().join("keyring.json")),
                unseal_key_file: Some(self.dir.path().join("unseal.key")),
                maintenance_ms,
            };
            ServerSettings::resolve(&flags, &Env::default()).expect("resolved")
        }

        /// The timeline the fixture record's entity gets, which only fan-out materialises.
        fn timeline(&self) -> std::path::PathBuf {
            self.dir.path().join("entities/ticket/PROJ-42/timeline.md")
        }
    }

    #[tokio::test]
    async fn binding_port_zero_reports_the_port_it_got() {
        // With a subscriber installed the startup log is actually rendered, so the effective
        // configuration this prints is exercised rather than merely written.
        crate::logging(&Env::default());
        let deployment = Deployment::new();
        let bound = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect("bound");
        assert_ne!(bound.address.port(), 0, "the kernel chose a real port");
        assert_eq!(
            bound.maintenance.as_millis(),
            u128::from(DEFAULT_MAINTENANCE_MS)
        );
    }

    #[tokio::test]
    async fn a_shutdown_returns_rather_than_serving_for_ever() {
        let deployment = Deployment::new();
        let bound = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect("bound");
        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(bound, async move {
            let _ = wait.await;
        }));

        stop.send(()).expect("still serving");
        tokio::time::timeout(std::time::Duration::from_secs(5), serving)
            .await
            .expect("a shutdown has to finish")
            .expect("join")
            .expect("a clean shutdown");
    }

    #[tokio::test]
    async fn an_address_already_taken_is_refused_rather_than_started_broken() {
        let deployment = Deployment::new();
        let first = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect("bound");
        let taken = format!("127.0.0.1:{}", first.address.port());

        let error = bind(&deployment.settings(&taken))
            .await
            .expect_err("the port is taken");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains(&taken), "{error}");
    }

    /// Everything the startup warning says about key material, and everything it stays quiet about.
    ///
    /// Both directions are claims. Warning on a store with nothing in its key store is the false
    /// alarm this change removed; saying nothing about key material anyone can read is the bug that
    /// would replace it.
    #[test]
    fn a_startup_warns_about_the_key_material_that_deserves_it() {
        let report = |on_disk, wrapper_protects| KeyReport {
            on_disk,
            wrapper: "either wrapper",
            wrapper_protects,
        };
        let warned = |on_disk, protects| key_warning(&report(on_disk, protects));

        // Readable on disk: a warning whatever this process holds, because the files are the keys.
        for protects in [true, false] {
            let said = warned(KeyMaterial::Unwrapped { files: 1 }, protects)
                .expect("keys in the clear must be said out loud");
            assert!(said.contains("stored unwrapped"), "{said}");
            assert!(
                warned(
                    KeyMaterial::Mixed {
                        wrapped: 1,
                        unwrapped: 1
                    },
                    protects
                )
                .is_some(),
                "one key in the clear is one key in the clear"
            );
        }

        // Wrapped and this service can read it: nothing to say.
        assert!(
            warned(
                KeyMaterial::Wrapped {
                    scheme: None,
                    files: 2
                },
                true
            )
            .is_none()
        );
        // Wrapped and it cannot: not an exposure, but every sealed read will fail.
        let said = warned(
            KeyMaterial::Wrapped {
                scheme: None,
                files: 2,
            },
            false,
        )
        .expect("a service that can read none of its keys has to say so");
        assert!(said.contains("cannot unwrap"), "{said}");

        // Nothing on disk: no claim about files that are not there. The future tense earns a line
        // only where this service is the one about to write in the clear.
        let said = warned(KeyMaterial::Absent, false).expect("about to mint keys in the clear");
        assert!(said.contains("holds no key material yet"), "{said}");
        assert!(
            warned(KeyMaterial::Absent, true).is_none(),
            "a fresh store with a wrapper fitted is not worth waking anyone for"
        );
    }

    /// The startup line an operator reads, over a store that already holds key material.
    ///
    /// A fresh store says there is nothing to report and warns about what it is about to write; this
    /// one has keys on disk in the clear, which is the state the present-tense warning is for. Both
    /// paths are rendered here under a real subscriber rather than merely constructed.
    #[tokio::test]
    async fn a_store_holding_key_material_is_announced_from_the_disk() {
        crate::logging(&Env::default());
        let deployment = Deployment::new();
        let mut pipeline = yaam_core::Pipeline::with_paths(yaam_core::Paths::under(
            deployment.dir.path().to_path_buf(),
        ))
        .expect("a pipeline over the tree");
        pipeline
            .accept(
                fixtures::subject_record("2026-08-20T09:00:00Z", &fixtures::subject('a')),
                fixtures::BODY,
            )
            .expect("accepted");
        drop(pipeline);

        bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect("a store whose keys are in the clear still comes up");
    }

    /// A service with an unusable keyring must not come up at all.
    #[tokio::test]
    async fn an_unusable_keyring_is_refused_before_anything_accepts() {
        let deployment = Deployment::new();
        std::fs::write(deployment.dir.path().join("keyring.json"), "{}").expect("write");
        let error = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect_err("no callers");
        assert_eq!(error.exit(), Exit::Config);
    }

    /// A service with no sealing key still comes up: it accepts plain JSON, and says so.
    #[tokio::test]
    async fn a_service_without_a_sealing_key_still_comes_up() {
        let deployment = Deployment::new();
        let mut settings = deployment.settings("127.0.0.1:0");
        settings.unseal_key_file = None;
        bind(&settings)
            .await
            .expect("a plain-JSON service is valid");
    }

    /// A sealing key that will not decode is a refusal, not a service that spools every record.
    #[tokio::test]
    async fn an_unusable_sealing_key_is_refused() {
        let deployment = Deployment::new();
        std::fs::write(deployment.dir.path().join("unseal.key"), "aabb").expect("write");
        let error = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect_err("too short");
        assert_eq!(error.exit(), Exit::Config);
    }

    /// A store with work outstanding converges at boot, rather than an interval later.
    ///
    /// The interval is set to ten minutes, so a timer round cannot be what drained the queue. This
    /// is the case a service that came up and went down inside one interval used to lose entirely:
    /// the fan-out a killed process left queued sat there through every restart.
    #[tokio::test]
    async fn a_store_with_work_outstanding_converges_at_boot() {
        let deployment = Deployment::new();
        let bound = bind(&deployment.settings_with("127.0.0.1:0", Some(600_000)))
            .await
            .expect("bound");
        assert_eq!(bound.maintenance, Duration::from_mins(10));

        // Queued before anything serves, which is the state a crash leaves the store in.
        write_one(&bound.service);
        let timeline = deployment.timeline();
        assert!(!timeline.exists(), "nothing has drained it yet");

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(bound, async move {
            let _ = wait.await;
        }));
        let converged = appears(&timeline).await;
        stop.send(()).expect("still serving");
        serving.await.expect("join").expect("clean shutdown");

        assert!(
            converged,
            "the round at boot is the only one that could have run"
        );
    }

    /// And the timer keeps rounds coming after the one at boot.
    ///
    /// Two writes, because one proves nothing about which round drained it: the second is written
    /// only once a round has demonstrably completed, and there is exactly one round at boot.
    #[tokio::test]
    async fn the_maintenance_timer_drains_a_queue_the_boot_round_never_saw() {
        let deployment = Deployment::new();
        let bound = bind(&deployment.settings_with("127.0.0.1:0", Some(20)))
            .await
            .expect("bound");
        let service = Arc::clone(&bound.service);
        let timeline = deployment.timeline();
        write_one(&service);

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(bound, async move {
            let _ = wait.await;
        }));
        let first = appears(&timeline).await;
        let second = write_one(&service);
        let later = mentions(&timeline, &second).await;
        stop.send(()).expect("still serving");
        serving.await.expect("join").expect("clean shutdown");

        assert!(first, "nothing else drains fan-out in a running deployment");
        assert!(later, "no round ran after the one at boot");
    }

    /// A round that cannot run is a line in the log, not a service that fails to serve.
    ///
    /// The worst shape a round at boot could have taken is one that wedges startup, so the round
    /// here is made to fail: a store the sweeper cannot walk is exactly the state somebody has to
    /// reach the service to find out about. A round drains fan-out before it sweeps, which is what
    /// makes the failure observable — the timeline says the round ran, and the error at the end says
    /// it did not finish.
    #[tokio::test]
    async fn a_failing_boot_round_still_leaves_a_service_that_answers() {
        let deployment = Deployment::new();
        let bound = bind(&deployment.settings_with("127.0.0.1:0", Some(600_000)))
            .await
            .expect("bound");
        let address = bound.address;
        let service = Arc::clone(&bound.service);
        write_one(&service);

        // A file where the staging directory should be: the sweep cannot walk it. A directory made
        // unreadable would not do — these tests may be running as a user permissions ignore.
        let staging = deployment.dir.path().join(".staging");
        std::fs::remove_dir_all(&staging).expect("the pipeline made it at startup");
        std::fs::write(&staging, b"not a directory").expect("write");

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(bound, async move {
            let _ = wait.await;
        }));
        let ran = appears(&deployment.timeline()).await;
        let answer = unsigned_request(address).await;
        stop.send(()).expect("still serving");
        serving.await.expect("join").expect("clean shutdown");

        assert!(ran, "the round at boot never got as far as the fan-out");
        assert!(
            answer.starts_with("HTTP/1.1 401"),
            "an unsigned request is refused, and a refusal is an answer: {answer}"
        );
        assert!(
            service.maintain(1).is_err(),
            "a round has to be failing in this state, or this test proves nothing"
        );
    }

    /// Writes one record, leaving the fan-out it queued for a round to drain.
    fn write_one(service: &CoreService) -> RecordId {
        let record = fixtures::record("2026-08-20T09:00:00Z");
        let id = record.record_id.clone();
        let caller = yaam_server::auth::Caller {
            agent: record.agent.clone(),
            role: yaam_server::auth::Role::Writer,
            teams: Vec::new(),
        };
        yaam_server::service::Service::write(service, &caller, record, fixtures::BODY)
            .expect("written");
        id
    }

    /// Waits for a file to turn up. Polled, because what puts it there is another task.
    async fn appears(path: &std::path::Path) -> bool {
        settles(|| path.exists()).await
    }

    /// Waits for a timeline to name a record.
    async fn mentions(timeline: &std::path::Path, id: &RecordId) -> bool {
        settles(|| std::fs::read_to_string(timeline).is_ok_and(|text| text.contains(id.as_str())))
            .await
    }

    /// Polls a condition until it holds, or gives up.
    ///
    /// Generous rather than tight: what it waits for is a round on a blocking thread, and the
    /// interval these tests set is milliseconds, so a wait that ends is a wait that ended early.
    async fn settles(mut state: impl FnMut() -> bool) -> bool {
        for _ in 0..400 {
            if state() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        state()
    }

    /// One unsigned request, and whatever came back.
    ///
    /// Unsigned deliberately: the assertion is that something answered, and a refusal is an answer.
    /// Assembled by hand on a blocking thread, because this crate's tokio carries no `io-util` and a
    /// client library bought for one request would be a dependency for one line.
    async fn unsigned_request(address: SocketAddr) -> String {
        tokio::task::spawn_blocking(move || {
            use std::io::{Read as _, Write as _};

            let mut socket = std::net::TcpStream::connect(address).expect("connect");
            socket
                .write_all(b"GET /records HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write");
            let mut answer = String::new();
            let _ = socket.read_to_string(&mut answer);
            answer
        })
        .await
        .expect("join")
    }
}
