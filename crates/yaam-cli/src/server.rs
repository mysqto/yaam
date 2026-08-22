//! Bringing the service up, and taking it down without dropping a request.
//!
//! Binding and serving are two steps rather than one. A caller that has bound knows the address it
//! actually got, which is what makes a test on an ephemeral port possible — and a test that cannot
//! bind an ephemeral port is a test that fights over a fixed one.
//!
//! The service also does the maintenance its store needs, on a timer: fan-out is queued inside the
//! write transaction and drained afterwards, and the sweeper is what closes the crash windows the
//! write path leaves open. Neither has any other caller in a running deployment, so a service that
//! only answered requests would answer them correctly while its entity timelines never appeared and
//! its backlog only grew.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use yaam_server::routes::{self, AppState};
use yaam_server::service::CoreService;

use crate::config::ServerSettings;
use crate::error::{Result, failed};
use crate::keyring;

/// How often the service does the maintenance its store needs.
///
/// Seconds rather than milliseconds: both halves are idempotent and bounded, and neither is on the
/// path of a request. What it costs to be late is that an entity timeline appears a moment after the
/// record it describes — those files are derived views, and a reader that needs the record itself
/// has the index.
pub const DEFAULT_MAINTENANCE_MS: u64 = 30_000;

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
    let key_wrapping = pipeline.key_wrapping();
    let key_protected = pipeline.key_material_protected();
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
        key_wrapping,
        key_protected,
    );

    Ok(Bound {
        listener,
        router: routes::router(state),
        service,
        maintenance: Duration::from_millis(DEFAULT_MAINTENANCE_MS),
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
    let timer = tokio::spawn(maintenance_loop(service, maintenance, closed));

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;

    // After the requests, not before: a request being finished may still enqueue fan-out, and the
    // round below is the one that would have taken it.
    let _ = closing.send(true);
    let _ = timer.await;
    served.map_err(|error| failed("serving", &error))
}

/// Drains fan-out and sweeps, until told to stop.
///
/// The work is filesystem and database work, so each round runs on a blocking thread: doing it on a
/// runtime worker would park that worker for the length of a sweep, and the sweep walks the tree.
async fn maintenance_loop(
    service: Arc<CoreService>,
    interval: Duration,
    mut closed: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = closed.changed() => return,
            () = tokio::time::sleep(interval) => {}
        }
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
    }
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
    key_wrapping: &'static str,
    key_protected: bool,
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
    // Once, clearly, and not buried -- but only when it is true. Asked of the store rather than of
    // the configuration, so a wrapper that failed to take effect still warns.
    tracing::info!(
        setting = "key wrapping",
        value = key_wrapping,
        "configuration"
    );
    if !key_protected {
        tracing::warn!(
            "subject keys are stored unwrapped: no --key-passphrase-file, so a key file recovered \
             from a snapshot, a stale volume or a decommissioned disk is a usable key. Fit a \
             wrapper before this store holds anyone's data"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAINTENANCE_MS, bind, serve};
    use crate::cli::{ServerArgs, StoreArgs};
    use crate::config::{Env, ServerSettings};
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
            let flags = ServerArgs {
                store: StoreArgs {
                    root: Some(self.dir.path().to_path_buf()),
                    index: None,
                    key_store: None,
                    key_passphrase_file: None,
                },
                listen: Some(listen.to_owned()),
                keyring: Some(self.dir.path().join("keyring.json")),
                unseal_key_file: Some(self.dir.path().join("unseal.key")),
            };
            ServerSettings::resolve(&flags, &Env::default()).expect("resolved")
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

    /// The maintenance timer is what makes fan-out and the sweeper run at all, so it has to run.
    #[tokio::test]
    async fn the_maintenance_timer_drains_the_queue_a_write_left_behind() {
        let deployment = Deployment::new();
        let mut bound = bind(&deployment.settings("127.0.0.1:0"))
            .await
            .expect("bound");
        bound.maintenance = std::time::Duration::from_millis(10);

        let pipeline_root = deployment.dir.path().to_path_buf();
        let record = fixtures::record("2026-08-20T09:00:00Z");
        let caller = yaam_server::auth::Caller {
            agent: record.agent.clone(),
            role: yaam_server::auth::Role::Writer,
            teams: Vec::new(),
        };
        yaam_server::service::Service::write(&*bound.service, &caller, record, fixtures::BODY)
            .expect("written");

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(bound, async move {
            let _ = wait.await;
        }));
        // The timeline is fan-out work, so its file only exists because the timer ran.
        let timeline = pipeline_root.join("entities/ticket/PROJ-42/timeline.md");
        for _ in 0..400 {
            if timeline.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        stop.send(()).expect("still serving");
        serving.await.expect("join").expect("clean shutdown");

        assert!(
            timeline.exists(),
            "nothing else drains fan-out in a running deployment"
        );
    }
}
