//! The sealing, spooling and retry engine behind the sockets.
//!
//! Everything a caller does not have to know about lives here: a record is sealed before it can
//! reach disk, the spool goes out strictly ahead of anything newer, and only a definitive refusal
//! from the service ever comes back as a rejection.
//!
//! Spool entries carry a one-line plaintext prefix naming the agent, ahead of the sealed body. The
//! service needs to know which caller a queued record came from before it can unseal anything, and
//! an agent name is a configured identity rather than anyone's data — unlike the record itself,
//! which is sealed and stays that way for the whole time it sits on disk.
//!
//! What gets sealed is the service's own write-request shape rather than a bare record, so a
//! spooled entry is the request the service will parse — the sidecar cannot reopen it later to
//! reshape it, which is exactly why the shape has to be right when it is sealed.

use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use yaam_contract::ActionRecord;
use yaam_contract::request::WriteRequest;

use crate::spool::Spool;
use crate::upstream::Upstream;
use crate::{Error, envelope};

/// Seals, spools and posts on a caller's behalf.
pub(crate) struct Sidecar {
    /// Where records go, and the key they are sealed to.
    upstream: Upstream,
    /// The pending queue. Only ever touched from a blocking thread, since its work is filesystem
    /// work and its ordering guarantee depends on one operation at a time.
    spool: Arc<Mutex<Spool>>,
}

impl Sidecar {
    /// Builds a sidecar around an upstream and its spool.
    pub(crate) fn new(upstream: Upstream, spool: Spool) -> Self {
        Self {
            upstream,
            spool: Arc::new(Mutex::new(spool)),
        }
    }

    /// Takes one JSON line from a caller and answers for it.
    ///
    /// `Ok(())` means the service has it. [`Error::Spooled`] means the sidecar has it and will keep
    /// trying. [`Error::Rejected`] means nobody will ever accept it, and the caller is the only one
    /// who can fix it — so it is never written to disk.
    ///
    /// The happy path does not touch the spool at all: with the service reachable, a record that is
    /// posted and accepted needs no durable copy, and one the service refuses should not leave a
    /// file behind for a retry that can only fail again.
    pub(crate) async fn submit(&self, socket_agent: &str, line: &[u8]) -> crate::Result<()> {
        let record = parse(socket_agent, line)?;
        // Re-serialised from the parsed record, not forwarded verbatim: what the service unseals is
        // then exactly what this sidecar validated, with no unknown fields riding along. The body
        // is left out so the service uses the record's own summary, which is the prose the caller
        // sent.
        let request = WriteRequest {
            record: record.clone(),
            body: None,
        };
        let body = serde_json::to_vec(&request)
            .map_err(|e| Error::Rejected(format!("unserialisable record: {e}")))?;
        let sealed = envelope::seal(&self.upstream.service_public_key, &body)?;
        let entry = frame(&record.agent, &sealed);

        // Anything already spooled predates this record, so it goes first or this one waits.
        if self.depth().await? > 0 {
            self.flush().await?;
        }
        if self.depth().await? > 0 {
            self.push(entry).await?;
            return Err(Error::Spooled);
        }

        match self.upstream.post_record(&record.agent, &sealed).await {
            Ok(()) => Ok(()),
            Err(Error::Spooled) => {
                self.push(entry).await?;
                Err(Error::Spooled)
            }
            Err(permanent) => Err(permanent),
        }
    }

    /// Replays the spool, oldest first, stopping at the first entry the service will not take now.
    ///
    /// The drain itself is synchronous filesystem work and the post is asynchronous network work, so
    /// the two hand entries and verdicts back and forth over a pair of one-slot channels. The
    /// alternative — blocking on a future from inside the blocking thread — parks a runtime worker
    /// and deadlocks on a single-threaded runtime.
    pub(crate) async fn flush(&self) -> crate::Result<usize> {
        let (entry_tx, mut entry_rx) = mpsc::channel::<Vec<u8>>(1);
        let (verdict_tx, mut verdict_rx) = mpsc::channel::<crate::Result<()>>(1);

        let spool = Arc::clone(&self.spool);
        let drain = tokio::task::spawn_blocking(move || -> crate::Result<usize> {
            locked(&spool)?.drain(|entry| {
                entry_tx
                    .blocking_send(entry.to_vec())
                    .map_err(|_| Error::Spooled)?;
                // A closed channel means the poster is gone; the entry stays for the next attempt.
                verdict_rx.blocking_recv().unwrap_or(Err(Error::Spooled))
            })
        });

        while let Some(entry) = entry_rx.recv().await {
            let verdict = match unframe(&entry) {
                Ok((agent, sealed)) => self.upstream.post_record(agent, sealed).await,
                Err(corrupt) => Err(corrupt),
            };
            if verdict_tx.send(verdict).await.is_err() {
                break;
            }
        }

        joined(drain.await)?
    }

    /// Entries still waiting.
    pub(crate) async fn depth(&self) -> crate::Result<usize> {
        let spool = Arc::clone(&self.spool);
        joined(tokio::task::spawn_blocking(move || locked(&spool)?.depth()).await)?
    }

    /// Appends one framed entry.
    async fn push(&self, entry: Vec<u8>) -> crate::Result<()> {
        let spool = Arc::clone(&self.spool);
        joined(tokio::task::spawn_blocking(move || locked(&spool)?.push(&entry)).await)?
    }
}

/// Parses and vets one caller line.
///
/// Attribution is checked here rather than upstream because the socket is the evidence: it is
/// permissioned to one caller, so the agent it belongs to is known without asking, and a record
/// naming a different agent is a caller trying to write as someone else.
fn parse(socket_agent: &str, line: &[u8]) -> crate::Result<ActionRecord> {
    let record: ActionRecord = serde_json::from_slice(line)
        .map_err(|e| Error::Rejected(format!("malformed record: {e}")))?;
    record
        .validate()
        .map_err(|e| Error::Rejected(e.to_string()))?;

    if record.agent != socket_agent {
        return Err(Error::Rejected(format!(
            "socket belongs to `{socket_agent}`, record claims `{}`",
            record.agent
        )));
    }
    // The frame is line-delimited, so a newline in an agent name would let one entry masquerade as
    // another. Refused here, where the caller still gets told why.
    if record.agent.contains(|c: char| c.is_control()) {
        return Err(Error::Rejected(
            "agent name contains a control character".to_owned(),
        ));
    }
    Ok(record)
}

/// Wraps a sealed body with the agent it belongs to.
fn frame(agent: &str, sealed: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(agent.len() + 1 + sealed.len());
    entry.extend_from_slice(agent.as_bytes());
    entry.push(b'\n');
    entry.extend_from_slice(sealed);
    entry
}

/// Splits a spool entry back into its agent and its sealed body.
///
/// A corrupt entry is [`Error::Rejected`] rather than an I/O failure, so the drain drops it and
/// keeps going: no amount of retrying will make an unparseable entry postable, and leaving it in
/// place would block every record behind it.
fn unframe(entry: &[u8]) -> crate::Result<(&str, &[u8])> {
    let at = entry
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| Error::Rejected("spool entry has no agent line".to_owned()))?;
    let agent = std::str::from_utf8(&entry[..at])
        .map_err(|_| Error::Rejected("spool entry agent is not utf-8".to_owned()))?;
    if agent.is_empty() {
        return Err(Error::Rejected("spool entry names no agent".to_owned()));
    }
    Ok((agent, &entry[at + 1..]))
}

/// Locks the spool, turning a poisoned mutex into an error rather than a second panic.
fn locked(spool: &Mutex<Spool>) -> crate::Result<std::sync::MutexGuard<'_, Spool>> {
    spool
        .lock()
        .map_err(|_| Error::Io(io::Error::other("spool lock poisoned")))
}

/// Unwraps a blocking task's result. A join failure means the task panicked, which is a bug here
/// rather than a condition to recover from — but it must not take the connection's error path with
/// it, so it surfaces as an I/O failure.
fn joined<T>(joined: Result<T, tokio::task::JoinError>) -> crate::Result<T> {
    joined.map_err(|e| Error::Io(io::Error::other(e)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;
    use yaam_contract::{DataClass, Outcome, RecordId, SchemaVer, Visibility};

    use yaam_contract::request::SigningKeys;

    use super::*;
    use crate::stub::Stub;
    use crate::upstream::Credentials;

    /// The key this sidecar and the test service share.
    const KEY: &[u8] = b"a-shared-signing-key";

    /// Credentials for every agent the tests here post as.
    fn credentials() -> Credentials {
        Credentials::new()
            .with("writer", SigningKeys::new(KEY))
            .with("auditor", SigningKeys::new(KEY))
    }

    /// The record inside a sealed entry the service would have opened.
    fn opened(secret: &[u8], sealed: &[u8]) -> ActionRecord {
        let plain = envelope::open(secret, sealed).expect("the service opens it");
        serde_json::from_slice::<WriteRequest>(&plain)
            .expect("the shape the service parses")
            .record
    }

    /// A valid record attributed to `agent`, as a caller would write it.
    fn line(agent: &str, summary: &str) -> Vec<u8> {
        let record = ActionRecord {
            record_id: RecordId::generate(),
            schema_ver: SchemaVer(1),
            at: "2026-01-01T00:00:00Z".to_owned(),
            received_at: "2026-01-01T00:00:01Z".to_owned(),
            backfilled: false,
            agent: agent.to_owned(),
            agent_ver: None,
            correlation_id: None,
            action: "deploy".to_owned(),
            outcome: Outcome::Success,
            attrs: BTreeMap::new(),
            entities: Vec::new(),
            subjects: Vec::new(),
            visibility: Visibility::Org,
            team: None,
            data_class: DataClass::Internal,
            redaction_policy: "default-v1".to_owned(),
            fields_masked: Vec::new(),
            tags: Vec::new(),
            summary: summary.to_owned(),
        };
        serde_json::to_vec(&record).unwrap()
    }

    /// A sidecar pointed at `stub`, with a service key pair and its own spool.
    fn sidecar(base_url: String, capacity: usize) -> (TempDir, [u8; 32], Sidecar) {
        let dir = TempDir::new().unwrap();
        let (secret, public) = envelope::generate_keypair();
        let spool = Spool::open_with_capacity(dir.path().join("spool"), capacity).unwrap();
        let upstream = Upstream {
            base_url,
            service_public_key: public.to_vec(),
            credentials: credentials(),
        };
        (dir, secret, Sidecar::new(upstream, spool))
    }

    #[tokio::test]
    async fn an_accepted_record_reaches_the_service_sealed() {
        let stub = Stub::start(202).await;
        let (_dir, secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        sidecar
            .submit("writer", &line("writer", "shipped it"))
            .await
            .unwrap();

        let posted = stub.received();
        assert_eq!(posted.len(), 1);
        assert!(
            !posted[0].windows(10).any(|w| w == b"shipped it"),
            "the body went out in the clear"
        );
        assert_eq!(opened(&secret, &posted[0]).summary, "shipped it");
        assert_eq!(sidecar.depth().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_rejected_record_is_never_spooled() {
        let stub = Stub::start(422).await;
        let (_dir, _secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        let err = sidecar
            .submit("writer", &line("writer", "bad"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rejected(_)), "{err}");
        assert_eq!(sidecar.depth().await.unwrap(), 0, "must not be retried");
    }

    #[tokio::test]
    async fn a_transient_failure_spools_and_then_drains_in_order() {
        let stub = Stub::start(503).await;
        let (_dir, secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        for n in 0..3 {
            let err = sidecar
                .submit("writer", &line("writer", &format!("record {n}")))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Spooled), "{err}");
        }
        assert_eq!(sidecar.depth().await.unwrap(), 3);

        // Every refused attempt is a body the stub also saw, so only what follows the recovery
        // says anything about ordering.
        let before_recovery = stub.received().len();
        stub.respond_with(200);
        assert_eq!(sidecar.flush().await.unwrap(), 3);
        assert_eq!(sidecar.depth().await.unwrap(), 0);

        let summaries: Vec<String> = stub.received()[before_recovery..]
            .iter()
            .map(|body| opened(&secret, body).summary)
            .collect();
        assert_eq!(summaries, ["record 0", "record 1", "record 2"]);
    }

    #[tokio::test]
    async fn a_backlog_goes_out_ahead_of_a_new_record() {
        let stub = Stub::start(503).await;
        let (_dir, secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        sidecar
            .submit("writer", &line("writer", "older"))
            .await
            .unwrap_err();
        let before_recovery = stub.received().len();
        stub.respond_with(200);

        // Submitting drains the backlog first, so the older record goes out ahead of the new one
        // even though the new one is the reason anything was sent.
        sidecar
            .submit("writer", &line("writer", "newer"))
            .await
            .unwrap();
        assert_eq!(sidecar.depth().await.unwrap(), 0);

        let summaries: Vec<String> = stub.received()[before_recovery..]
            .iter()
            .map(|body| opened(&secret, body).summary)
            .collect();
        assert_eq!(summaries, ["older", "newer"]);
    }

    #[tokio::test]
    async fn the_spool_bound_is_reported_to_the_caller() {
        let stub = Stub::start(503).await;
        let (_dir, _secret, sidecar) = sidecar(stub.base_url.clone(), 2);

        for _ in 0..2 {
            assert!(matches!(
                sidecar.submit("writer", &line("writer", "x")).await,
                Err(Error::Spooled)
            ));
        }
        let err = sidecar
            .submit("writer", &line("writer", "x"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SpoolFull), "{err}");
        assert_eq!(sidecar.depth().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_record_claiming_another_agent_is_refused() {
        let stub = Stub::start(200).await;
        let (_dir, _secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        let err = sidecar
            .submit("writer", &line("someone-else", "not mine"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Rejected(why) if why.contains("someone-else")),
            "{err}"
        );
        assert!(stub.received().is_empty(), "it must not be posted at all");
        assert_eq!(sidecar.depth().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_malformed_line_is_refused() {
        let stub = Stub::start(200).await;
        let (_dir, _secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        for line in [&b"not json"[..], b"{}", b"[]"] {
            let err = sidecar.submit("writer", line).await.unwrap_err();
            assert!(matches!(err, Error::Rejected(_)), "{err}");
        }
        assert!(stub.received().is_empty());
    }

    #[tokio::test]
    async fn a_record_that_breaks_the_contract_is_refused() {
        let stub = Stub::start(200).await;
        let (_dir, _secret, sidecar) = sidecar(stub.base_url.clone(), 8);

        // Internal class with a subject: the contract's own validation catches it, and the reason
        // reaches the caller rather than the log.
        let mut record: ActionRecord =
            serde_json::from_slice(&line("writer", "no action")).unwrap();
        record.action = String::new();
        let err = sidecar
            .submit("writer", &serde_json::to_vec(&record).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Rejected(why) if why.contains("action")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_misconfigured_service_key_is_not_a_silent_pass() {
        let dir = TempDir::new().unwrap();
        let spool = Spool::open(dir.path().join("spool")).unwrap();
        let sidecar = Sidecar::new(
            Upstream {
                base_url: "http://127.0.0.1:1".to_owned(),
                service_public_key: vec![0u8; 3],
                credentials: credentials(),
            },
            spool,
        );

        let err = sidecar
            .submit("writer", &line("writer", "x"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "{err}");
    }

    #[tokio::test]
    async fn a_corrupt_spool_entry_is_dropped_rather_than_wedging_the_queue() {
        let stub = Stub::start(200).await;
        let dir = TempDir::new().unwrap();
        let (_secret, public) = envelope::generate_keypair();
        let mut spool = Spool::open(dir.path().join("spool")).unwrap();
        spool.push(b"no newline here").unwrap();
        let sidecar = Sidecar::new(
            Upstream {
                base_url: stub.base_url.clone(),
                service_public_key: public.to_vec(),
                credentials: credentials(),
            },
            spool,
        );

        assert_eq!(sidecar.flush().await.unwrap(), 1);
        assert_eq!(sidecar.depth().await.unwrap(), 0);
        assert!(stub.received().is_empty());
    }

    #[test]
    fn framing_round_trips() {
        let entry = frame("writer", b"sealed");
        assert_eq!(unframe(&entry).unwrap(), ("writer", &b"sealed"[..]));
    }

    #[test]
    fn a_frame_without_an_agent_is_refused() {
        assert!(unframe(b"").is_err());
        assert!(unframe(b"\nsealed").is_err());
        assert!(unframe(&[0xff, 0xff, b'\n', 1]).is_err());
    }

    #[test]
    fn an_agent_name_cannot_smuggle_in_a_frame_boundary() {
        let mut record: ActionRecord = serde_json::from_slice(&line("a\nb", "x")).unwrap();
        record.agent = "a\nb".to_owned();
        let err = parse("a\nb", &serde_json::to_vec(&record).unwrap()).unwrap_err();
        assert!(matches!(err, Error::Rejected(_)), "{err}");
    }
}
