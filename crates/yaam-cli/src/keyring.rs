//! The key material a service is configured with, read from disk.
//!
//! Two files, both the deployment's to protect: the keyring, which says which callers this service
//! authenticates and what each may do, and the sealing secret key, which is what lets it open what a
//! sidecar sealed. Neither is ever logged, and neither is ever echoed back in an error — a message
//! that quoted the offending key would put it in every log that captured the failure.
//!
//! The format is JSON rather than the wire schemas, because this is deployment configuration and not
//! contract: nothing outside this process reads it, and it carries secrets, which is the last thing
//! that should be published as a vendorable shape.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use yaam_crypto::envelope;
use yaam_server::auth::{Credential, Keyring, Role};

use crate::error::{Result, config, failed};

/// The keyring file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// One entry per caller, keyed by the agent identity it authenticates.
    ///
    /// A map rather than a list, so one agent cannot appear twice with two roles and leave which one
    /// wins to the order of the file.
    callers: BTreeMap<String, Entry>,
}

/// One caller's credential as the file spells it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// `reader`, `writer` or `operator`.
    role: String,
    /// Current signing key, hex encoded.
    key: String,
    /// The key most recently rolled away from, still accepted. Absent before the first roll.
    #[serde(default)]
    previous_key: Option<String>,
    /// Teams whose team-visible records this caller may read.
    #[serde(default)]
    teams: Vec<String>,
    /// Whether this caller may file records classified `subject_derived`. Absent means no.
    ///
    /// Default-off, and it stays that way for a keyring written before this field existed: the
    /// grant is what makes a body sealed and a subject linkage permanent, and a store with no
    /// re-key and no delete cannot take either back, so it is the one setting that must never be
    /// acquired by upgrading.
    ///
    /// The same fact is stated on the caller's own host, in the sidecar's `files_subject_derived`
    /// list, and both are checked. This is the one that binds -- a sidecar's configuration is
    /// edited by whoever runs the caller, and this file is not.
    #[serde(default)]
    files_subject_derived: bool,
}

/// Reads the keyring, refusing anything it cannot use.
///
/// Checked at startup rather than at the first request: a caller whose key will not decode is a
/// caller that fails to authenticate for ever, and finding that out one rejected request at a time
/// puts the operator's mistake on the caller's side of the wire.
pub fn load(path: &Path) -> Result<Keyring> {
    let text = fs::read_to_string(path)
        .map_err(|error| config(format!("--keyring {}: {error}", path.display())))?;
    let file: File = serde_json::from_str(&text).map_err(|error| {
        // One line. `serde_json` reports line and column, which is what an editor needs, and the
        // rest of a multi-line render is noise on a startup line.
        config(format!("--keyring {}: {error}", path.display()))
    })?;
    if file.callers.is_empty() {
        return Err(config(format!(
            "--keyring {} names no callers, so this service would authenticate nobody",
            path.display()
        )));
    }

    let mut keyring = Keyring::new();
    for (agent, entry) in &file.callers {
        let role = role(&entry.role, agent)?;
        let current = key(&entry.key, agent, "key")?;
        let mut credential =
            Credential::new(agent.clone(), role, current).in_teams(entry.teams.clone());
        if entry.files_subject_derived {
            credential = credential.filing_subject_derived();
        }
        if let Some(previous) = &entry.previous_key {
            credential = credential.rolled_from(key(previous, agent, "previous_key")?);
        }
        keyring = keyring.with(credential);
    }
    Ok(keyring)
}

/// The secret half of the key sidecars seal to.
///
/// Returned with its public half, because a service that holds the secret is the only thing that can
/// derive the public one, and a sidecar configured with a public key from anywhere else is a sidecar
/// sealing to a service that cannot open it.
pub fn unseal_key(path: &Path) -> Result<([u8; envelope::KEY_LEN], [u8; envelope::KEY_LEN])> {
    let text = fs::read_to_string(path)
        .map_err(|error| config(format!("--unseal-key-file {}: {error}", path.display())))?;
    let secret = hex::decode(text.trim()).map_err(|_| {
        config(format!(
            "--unseal-key-file {} is not hex; it holds {} bytes of hex-encoded secret key",
            path.display(),
            envelope::KEY_LEN
        ))
    })?;
    if secret.len() != envelope::KEY_LEN {
        return Err(config(format!(
            "--unseal-key-file {} decodes to {} bytes, expected {}",
            path.display(),
            secret.len(),
            envelope::KEY_LEN
        )));
    }
    let public = envelope::public_key(&secret)
        .map_err(|error| failed("deriving the public half of the sealing key", &error))?;
    let mut owned = [0u8; envelope::KEY_LEN];
    owned.copy_from_slice(&secret);
    Ok((owned, public))
}

/// One role name, or the refusal that names the caller it belongs to.
fn role(named: &str, agent: &str) -> Result<Role> {
    match named {
        "reader" => Ok(Role::Reader),
        "writer" => Ok(Role::Writer),
        "operator" => Ok(Role::Operator),
        other => Err(config(format!(
            "caller `{agent}` has role `{other}`: expected reader, writer or operator"
        ))),
    }
}

/// One hex-encoded signing key.
///
/// The key itself never reaches the message. A configuration error that quoted the value would put a
/// live signing key into every log that captured the startup failure.
fn key(text: &str, agent: &str, field: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(text.trim())
        .map_err(|_| config(format!("caller `{agent}`: {field} is not hex")))?;
    if bytes.is_empty() {
        return Err(config(format!("caller `{agent}`: {field} is empty")));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{load, unseal_key};
    use crate::exit::Exit;
    use yaam_server::auth::Role;

    /// Writes a keyring file and returns its path, with the directory kept alive by the caller.
    fn written(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("keyring.json");
        std::fs::write(&path, body).expect("write");
        path
    }

    #[test]
    fn a_keyring_reaches_the_service_with_roles_teams_and_a_rolled_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = written(
            dir.path(),
            r#"{"callers":{
                 "agent_a":{"role":"writer","key":"aabb","teams":["platform"]},
                 "agent_ops":{"role":"operator","key":"ccdd","previous_key":"eeff"}
               }}"#,
        );

        let keyring = load(&path).expect("loaded");
        let writer = keyring.credential("agent_a").expect("agent_a");
        assert_eq!(writer.role, Role::Writer);
        assert_eq!(writer.teams, ["platform"]);
        assert_eq!(writer.keys.current, vec![0xaa, 0xbb]);
        assert!(writer.keys.previous.is_none());

        let operator = keyring.credential("agent_ops").expect("agent_ops");
        assert_eq!(operator.role, Role::Operator);
        assert_eq!(
            operator.keys.previous,
            Some(vec![0xee, 0xff]),
            "a roll has to keep working across a restart"
        );
        // Nobody in a keyring written before this field existed gains the ability to seal a body by
        // being read on a newer build. That is the one setting that must never arrive with an
        // upgrade: a sealed body and its subject linkage cannot be taken back.
        assert!(!writer.files_subject_derived);
        assert!(!operator.files_subject_derived);
    }

    /// The grant a deployment makes on purpose, and the one thing it changes about the credential.
    #[test]
    fn a_caller_the_keyring_grants_may_file_subject_derived_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = written(
            dir.path(),
            r#"{"callers":{
                 "agent_a":{"role":"writer","key":"aabb"},
                 "agent_filer":{"role":"writer","key":"ccdd","files_subject_derived":true}
               }}"#,
        );

        let keyring = load(&path).expect("loaded");
        assert!(
            !keyring
                .credential("agent_a")
                .expect("agent_a")
                .files_subject_derived
        );
        let filer = keyring.credential("agent_filer").expect("agent_filer");
        assert!(filer.files_subject_derived);
        // The grant is orthogonal to the role: this is an ordinary writer that may also seal.
        assert_eq!(filer.role, Role::Writer);
        assert_eq!(keyring.subject_filers(), vec!["agent_filer"]);
    }

    /// Every refusal names the caller, and none of them quotes the key.
    #[test]
    fn an_unusable_keyring_is_refused_without_echoing_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases = [
            r#"{"callers":{}}"#,
            r#"{"callers":{"agent_a":{"role":"auditor","key":"aabb"}}}"#,
            r#"{"callers":{"agent_a":{"role":"writer","key":"not-hex-at-all"}}}"#,
            r#"{"callers":{"agent_a":{"role":"writer","key":""}}}"#,
            r#"{"callers":{"agent_a":{"role":"writer","key":"aabb","previous_key":"zz"}}}"#,
            r#"{"callers":{"agent_a":{"role":"writer","key":"aabb","extra":1}}}"#,
            "not json at all",
        ];
        for body in cases {
            let error = load(&written(dir.path(), body)).expect_err(body);
            assert_eq!(error.exit(), Exit::Config, "{body}: {error}");
            assert!(
                !error.to_string().contains("aabb") && !error.to_string().contains("not-hex"),
                "a message must not carry key material: {error}"
            );
        }

        let absent = load(Path::new("/nonexistent/keyring.json")).expect_err("absent");
        assert_eq!(absent.exit(), Exit::Config);
    }

    #[test]
    fn a_sealing_key_is_checked_for_length_and_its_public_half_derived() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (secret, public) = yaam_crypto::envelope::generate_keypair();
        let path = dir.path().join("unseal.key");
        std::fs::write(&path, format!("{}\n", hex::encode(secret))).expect("write");

        let (read, derived) = unseal_key(&path).expect("loaded");
        assert_eq!(read, secret);
        assert_eq!(
            derived, public,
            "the halves cannot be configured out of step if only one of them is configured"
        );

        for bad in ["", "zz", "aabb"] {
            std::fs::write(&path, bad).expect("write");
            let error = unseal_key(&path).expect_err(bad);
            assert_eq!(error.exit(), Exit::Config, "{error}");
        }
        assert_eq!(
            unseal_key(Path::new("/nonexistent/unseal.key"))
                .expect_err("absent")
                .exit(),
            Exit::Config
        );
    }
}
