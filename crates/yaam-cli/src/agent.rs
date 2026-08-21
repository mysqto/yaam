//! Bringing the sidecar up.
//!
//! Almost all of it is the library's: [`yaam_agent::listener`] binds the sockets, seals, spools,
//! retries and shuts down. What is here is the two decisions a process has to make — which sockets
//! to serve, and where they go — and the refusals that belong before anything is listening.
//!
//! The default is one caller per agent the configuration holds a signing key for. That is not a
//! convenience: the sidecar refuses to bind a socket it cannot sign as, so deriving the socket list
//! from the key list makes the two impossible to configure out of step.
//!
//! Each caller gets two sockets: `<agent>.sock` for records and `<agent>.read.sock` for reads.
//! `--socket agent=path` names the first, and the second is derived from it — one flag, one
//! identity, no way to point a caller's reads and its records at different agents. The startup log
//! names both and says which serves what.

use std::future::Future;
use std::path::{Path, PathBuf};

use yaam_agent::listener::{self, CallerSocket, Config, Limits};

use crate::config::AgentSettings;
use crate::error::{Result, config, failed};

/// Directory the default sockets go in, under the state directory.
pub const SOCKET_DIR: &str = "sockets";

/// The sockets to serve, and the bounds to serve them within.
#[derive(Debug)]
pub struct Plan {
    /// One socket per caller.
    pub sockets: Vec<CallerSocket>,
    /// Where the service is and what to sign as.
    pub upstream: yaam_agent::upstream::Upstream,
    /// Spool bound and retry cadence.
    pub limits: Limits,
    /// The state directory holding the configuration and the spool.
    pub state_dir: PathBuf,
}

/// Reads the configuration and works out what to serve.
///
/// Every refusal is here, before a socket exists: a configuration that will not parse, a key that
/// will not decode, and a state directory naming no callers at all are all things an operator fixes
/// by editing a file, and a sidecar that bound first would have callers writing into it meanwhile.
pub fn plan(settings: &AgentSettings) -> Result<Plan> {
    let configured = Config::load(&settings.state_dir).map_err(|error| {
        config(format!(
            "{}/{}: {error}",
            settings.state_dir.display(),
            listener::CONFIG_FILE
        ))
    })?;
    let upstream = configured
        .upstream()
        .map_err(|error| config(format!("{}: {error}", listener::CONFIG_FILE)))?;

    let sockets = if settings.sockets.is_empty() {
        default_sockets(&settings.state_dir, &configured)?
    } else {
        settings
            .sockets
            .iter()
            .map(|(agent, path)| CallerSocket {
                agent: agent.clone(),
                path: path.clone(),
            })
            .collect()
    };

    let mut limits = configured.limits();
    if let Some(capacity) = settings.spool_capacity {
        limits.spool_capacity = capacity;
    }
    if let Some(interval) = settings.retry_interval_ms {
        limits.retry_interval_ms = interval;
    }

    announce(&sockets, &limits);
    Ok(Plan {
        sockets,
        upstream,
        limits,
        state_dir: settings.state_dir.clone(),
    })
}

/// Serves until `shutdown` completes.
pub async fn serve<S>(plan: Plan, shutdown: S) -> Result<()>
where
    S: Future<Output = ()>,
{
    listener::serve_until(
        &plan.sockets,
        &plan.state_dir,
        &plan.upstream,
        plan.limits,
        shutdown,
    )
    .await
    .map_err(|error| failed("serving the caller sockets", &error))
}

/// One caller per configured signing key, under the state directory.
fn default_sockets(state_dir: &Path, configured: &Config) -> Result<Vec<CallerSocket>> {
    if configured.signing_keys.is_empty() {
        return Err(config(format!(
            "{} holds no signing keys, so there is no caller to serve. Name one there, or pass \
             --socket agent=path",
            listener::CONFIG_FILE
        )));
    }
    Ok(configured
        .signing_keys
        .keys()
        .map(|agent| CallerSocket {
            agent: agent.clone(),
            path: state_dir.join(SOCKET_DIR).join(format!("{agent}.sock")),
        })
        .collect())
}

/// Logs the effective configuration, once, at startup.
///
/// Agent names and paths. No key material and no service URL secrets: an agent name is a configured
/// identity, which is exactly what a caller has to know to use its own socket.
///
/// Both of a caller's sockets are named, and each says what it carries: a caller reading the log to
/// find where to connect must not have to know the derivation rule to find its read socket.
fn announce(sockets: &[CallerSocket], limits: &Limits) {
    for socket in sockets {
        tracing::info!(
            setting = "socket",
            agent = %socket.agent,
            serves = "records",
            value = %socket.path.display(),
            "configuration"
        );
        tracing::info!(
            setting = "socket",
            agent = %socket.agent,
            serves = "reads",
            value = %socket.read_path().display(),
            "configuration"
        );
    }
    tracing::info!(
        setting = "spool-capacity",
        value = limits.spool_capacity,
        "configuration"
    );
    tracing::info!(
        setting = "retry-interval-ms",
        value = limits.retry_interval_ms,
        "configuration"
    );
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{SOCKET_DIR, plan, serve};
    use crate::cli::AgentArgs;
    use crate::config::{AgentSettings, Env};
    use crate::exit::Exit;

    /// A state directory holding an `upstream.json` a sidecar can start from.
    fn state(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("upstream.json"), body).expect("write");
        dir
    }

    /// The configuration a working sidecar has.
    fn upstream_json() -> String {
        let (_, public) = yaam_crypto::envelope::generate_keypair();
        format!(
            r#"{{"base_url":"http://127.0.0.1:8787","service_public_key":"{}",
                 "signing_keys":{{"agent_b":"bbbb","agent_a":"aaaa"}}}}"#,
            hex::encode(public)
        )
    }

    fn settings(dir: &Path, sockets: Vec<(String, std::path::PathBuf)>) -> AgentSettings {
        let flags = AgentArgs {
            state_dir: Some(dir.to_path_buf()),
            sockets: Vec::new(),
            spool_capacity: None,
            retry_interval_ms: None,
        };
        let mut settings = AgentSettings::resolve(&flags, &Env::default()).expect("resolved");
        settings.sockets = sockets;
        settings
    }

    #[test]
    fn the_default_sockets_come_from_the_configured_keys() {
        // With a subscriber installed the startup log is actually rendered, which is the only way
        // to find out that a field it names cannot be formatted.
        crate::logging(&Env::default());
        let dir = state(&upstream_json());
        let planned = plan(&settings(dir.path(), Vec::new())).expect("planned");

        let agents: Vec<&str> = planned
            .sockets
            .iter()
            .map(|socket| socket.agent.as_str())
            .collect();
        assert_eq!(
            agents,
            ["agent_a", "agent_b"],
            "sorted, so the socket list does not depend on the order of a JSON object"
        );
        assert_eq!(
            planned.sockets[0].path,
            dir.path().join(SOCKET_DIR).join("agent_a.sock")
        );
    }

    #[test]
    fn the_read_socket_sits_beside_the_record_socket() {
        let dir = state(&upstream_json());
        let planned = plan(&settings(dir.path(), Vec::new())).expect("planned");
        let sockets = dir.path().join(SOCKET_DIR);

        assert_eq!(planned.sockets[0].path, sockets.join("agent_a.sock"));
        assert_eq!(
            planned.sockets[0].read_path(),
            sockets.join("agent_a.read.sock"),
            "a caller that knows its record socket knows its read socket"
        );

        // And a named socket carries its read socket with it, rather than needing a second flag.
        let named = dir.path().join("elsewhere/a.sock");
        let planned = plan(&settings(
            dir.path(),
            vec![("agent_a".to_owned(), named.clone())],
        ))
        .expect("planned");
        assert_eq!(
            planned.sockets[0].read_path(),
            dir.path().join("elsewhere/a.read.sock")
        );
    }

    #[test]
    fn a_named_socket_wins_over_the_default() {
        let dir = state(&upstream_json());
        let named = dir.path().join("elsewhere/a.sock");
        let planned = plan(&settings(
            dir.path(),
            vec![("agent_a".to_owned(), named.clone())],
        ))
        .expect("planned");
        assert_eq!(planned.sockets.len(), 1);
        assert_eq!(planned.sockets[0].path, named);
    }

    #[test]
    fn a_configuration_with_no_keys_is_refused_with_what_to_do_about_it() {
        let (_, public) = yaam_crypto::envelope::generate_keypair();
        let dir = state(&format!(
            r#"{{"base_url":"http://127.0.0.1:8787","service_public_key":"{}"}}"#,
            hex::encode(public)
        ));
        let error = plan(&settings(dir.path(), Vec::new())).expect_err("no callers");
        assert_eq!(error.exit(), Exit::Config);
        assert!(error.to_string().contains("--socket"), "{error}");
    }

    #[test]
    fn an_unusable_configuration_is_refused_before_anything_binds() {
        let cases = [
            ("not json", "upstream.json"),
            (
                r#"{"base_url":"http://x","service_public_key":"zz"}"#,
                "not hex",
            ),
            (
                r#"{"base_url":"http://x","service_public_key":"aabb"}"#,
                "expected",
            ),
        ];
        for (body, expected) in cases {
            let dir = state(body);
            let error = plan(&settings(dir.path(), Vec::new())).expect_err(body);
            assert_eq!(error.exit(), Exit::Config, "{error}");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let missing = tempfile::tempdir().expect("tempdir");
        let error = plan(&settings(missing.path(), Vec::new())).expect_err("no config file");
        assert_eq!(error.exit(), Exit::Config);
    }

    #[test]
    fn the_flags_override_the_configured_bounds() {
        let dir = state(&upstream_json());
        let flags = AgentArgs {
            state_dir: Some(dir.path().to_path_buf()),
            sockets: Vec::new(),
            spool_capacity: Some(3),
            retry_interval_ms: Some(250),
        };
        let settings = AgentSettings::resolve(&flags, &Env::default()).expect("resolved");
        let planned = plan(&settings).expect("planned");
        assert_eq!(planned.limits.spool_capacity, 3);
        assert_eq!(planned.limits.retry_interval_ms, 250);
    }

    #[tokio::test]
    async fn serving_binds_the_sockets_and_removes_them_on_the_way_out() {
        let dir = state(&upstream_json());
        let planned = plan(&settings(dir.path(), Vec::new())).expect("planned");
        let paths: Vec<_> = planned
            .sockets
            .iter()
            .map(|socket| socket.path.clone())
            .collect();
        let read_paths: Vec<_> = planned
            .sockets
            .iter()
            .map(yaam_agent::listener::CallerSocket::read_path)
            .collect();

        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(planned, async move {
            let _ = wait.await;
        }));
        for path in paths.iter().chain(&read_paths) {
            for _ in 0..200 {
                if tokio::net::UnixStream::connect(path).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(path.exists(), "{} never appeared", path.display());
        }

        stop.send(()).expect("still serving");
        tokio::time::timeout(std::time::Duration::from_secs(5), serving)
            .await
            .expect("a shutdown has to finish")
            .expect("join")
            .expect("a clean shutdown");
        for path in &paths {
            assert!(!path.exists(), "{} outlived its sidecar", path.display());
        }
        for path in &read_paths {
            assert!(!path.exists(), "{} outlived its sidecar", path.display());
        }
    }

    #[tokio::test]
    async fn a_socket_the_sidecar_cannot_sign_as_is_refused() {
        let dir = state(&upstream_json());
        let planned = plan(&settings(
            dir.path(),
            vec![("agent_nobody".to_owned(), dir.path().join("x.sock"))],
        ))
        .expect("planned");

        let error = serve(planned, std::future::pending())
            .await
            .expect_err("no key for that agent");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("agent_nobody"), "{error}");
    }
}
