//! Request authentication and write attribution.
//!
//! Every request carries a signature, reads included: what a caller may see is decided per caller,
//! and an anonymous request has no caller to decide about.
//!
//! The signature is HMAC-SHA256 over the agent header and the exact body bytes, and both the
//! current and the previous key are accepted so a key roll needs no synchronised restart. The
//! comparison is constant-time — a byte-by-byte check that returns on the first mismatch hands an
//! attacker the tag one byte at a time.
//!
//! Replay is not defended against here, which is a decision rather than an omission: writes are
//! idempotent on the record id and reads mutate nothing, so replaying a captured message gains an
//! attacker nothing that the captured response did not already give them. Keeping the message
//! secret in flight is the transport's job.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

use axum::http::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// Header naming the agent a request is signed as.
pub const AGENT_HEADER: &str = "x-yaam-agent";
/// Header carrying the hex-encoded signature.
pub const SIGNATURE_HEADER: &str = "x-yaam-signature";

/// A verified caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The agent identity this caller may write as.
    pub agent: String,
    /// What the caller is allowed to do.
    pub role: Role,
}

/// Capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// May read within its visibility scope.
    Reader,
    /// May also write records attributed to itself.
    Writer,
    /// May erase, unseal with audit, and run maintenance.
    Operator,
}

impl Role {
    /// Whether this role covers everything `needed` allows.
    #[must_use]
    pub fn covers(self, needed: Self) -> bool {
        self.rank() >= needed.rank()
    }

    /// Position in the ladder. Private, so the ordering stays one statement to audit.
    fn rank(self) -> u8 {
        match self {
            Self::Reader => 0,
            Self::Writer => 1,
            Self::Operator => 2,
        }
    }
}

/// One caller's signing material and capability.
///
/// Two keys, not one. During a roll the caller and the service pick up the new key at different
/// moments, and a service that knows only the current key rejects every request signed with the old
/// one until both sides restart together.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Agent identity this credential authenticates.
    pub agent: String,
    /// What that agent may do.
    pub role: Role,
    /// Key signatures are expected under.
    pub current_key: Vec<u8>,
    /// Key retired by the most recent roll, still accepted. `None` before the first roll.
    pub previous_key: Option<Vec<u8>>,
}

impl Credential {
    /// A credential with no retired key.
    #[must_use]
    pub fn new(agent: impl Into<String>, role: Role, current_key: impl Into<Vec<u8>>) -> Self {
        Self {
            agent: agent.into(),
            role,
            current_key: current_key.into(),
            previous_key: None,
        }
    }

    /// Records the key this credential rolled away from.
    #[must_use]
    pub fn rolled_from(mut self, previous_key: impl Into<Vec<u8>>) -> Self {
        self.previous_key = Some(previous_key.into());
        self
    }
}

/// The callers a service will authenticate.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    by_agent: HashMap<String, Credential>,
}

impl Keyring {
    /// An empty keyring, which authenticates nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a credential, replacing any credential for the same agent.
    #[must_use]
    pub fn with(mut self, credential: Credential) -> Self {
        self.by_agent.insert(credential.agent.clone(), credential);
        self
    }

    /// The credential for `agent`, if the service knows it.
    #[must_use]
    pub fn credential(&self, agent: &str) -> Option<&Credential> {
        self.by_agent.get(agent)
    }
}

/// The keyring [`verify`] resolves against. Empty until installed, so a process nobody configured
/// authenticates nobody rather than authenticating everybody.
static INSTALLED: LazyLock<RwLock<Arc<Keyring>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Keyring::new())));

/// Installs the keyring [`verify`] resolves against, replacing whatever was there.
///
/// Replaceable rather than write-once so a rotation can be loaded into a running process. Together
/// with [`Credential::previous_key`], that is what makes a roll a reload instead of a restart.
pub fn install_keyring(keyring: Keyring) {
    let mut slot = INSTALLED.write().unwrap_or_else(PoisonError::into_inner);
    *slot = Arc::new(keyring);
}

/// The installed keyring.
#[must_use]
pub fn installed_keyring() -> Arc<Keyring> {
    INSTALLED
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Signs a request the way [`verify`] checks it.
///
/// Public because the signing side has to agree byte for byte with the checking side, and two
/// independent spellings of the same canonical message is how that agreement gets lost.
#[must_use]
pub fn sign(key: &[u8], agent: &str, body: &[u8]) -> String {
    hex::encode(tag(key, agent, body))
}

/// Verifies a signature over the request and resolves the caller.
pub fn verify(headers: &HeaderMap, body: &[u8]) -> Result<Caller> {
    verify_with(&installed_keyring(), headers, body)
}

/// Verifies against an explicit keyring.
///
/// The keyring is a parameter here and ambient in [`verify`]: a test — and a process serving more
/// than one keyring — needs to say which one, and the signature [`verify`] is fixed at cannot.
pub fn verify_with(keyring: &Keyring, headers: &HeaderMap, body: &[u8]) -> Result<Caller> {
    let agent = header(headers, AGENT_HEADER)?;
    // A malformed signature is reported exactly like a wrong one: telling the two apart tells a
    // prober whether it got the encoding right.
    let offered =
        hex::decode(header(headers, SIGNATURE_HEADER)?).map_err(|_| Error::Unauthenticated)?;
    let credential = keyring.credential(agent).ok_or(Error::Unauthenticated)?;

    let current = matches(&credential.current_key, agent, body, &offered);
    let previous = credential
        .previous_key
        .as_deref()
        .is_some_and(|key| matches(key, agent, body, &offered));
    // Non-short-circuiting: both keys are checked whichever one matched, so a request signed with
    // the retired key takes no longer than one signed with the current key.
    if current | previous {
        Ok(Caller {
            agent: credential.agent.clone(),
            role: credential.role,
        })
    } else {
        Err(Error::Unauthenticated)
    }
}

/// Rejects a write that attributes a record to an agent other than the caller.
///
/// Attribution is the whole value of the trail. A caller able to file history under another agent's
/// name can also file the record that explains away what it did, so a compromised caller has to
/// stay confined to its own history.
pub fn authorise_write(caller: &Caller, record_agent: &str) -> Result<()> {
    if !caller.role.covers(Role::Writer) {
        return Err(Error::Forbidden(format!(
            "`{}` may read but not write",
            caller.agent
        )));
    }
    if caller.agent != record_agent {
        return Err(Error::Forbidden(format!(
            "`{}` may not attribute a record to `{record_agent}`",
            caller.agent
        )));
    }
    Ok(())
}

/// Rejects a caller whose role does not cover `needed`.
pub fn require_role(caller: &Caller, needed: Role) -> Result<()> {
    if caller.role.covers(needed) {
        Ok(())
    } else {
        Err(Error::Forbidden(format!(
            "`{}` is not permitted this operation",
            caller.agent
        )))
    }
}

/// The canonical message: agent, a separator, then the body exactly as it arrived.
///
/// A header value cannot contain a newline, so the separator cannot be smuggled into an agent name
/// to make two different requests sign the same.
fn tag(key: &[u8], agent: &str, body: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("hmac takes a key of any length, so this cannot fail");
    mac.update(agent.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time tag comparison.
fn matches(key: &[u8], agent: &str, body: &[u8], offered: &[u8]) -> bool {
    tag(key, agent, body).ct_eq(offered).into()
}

/// Reads a header as text, treating anything missing or non-ASCII as unauthenticated.
fn header<'h>(headers: &'h HeaderMap, name: &str) -> Result<&'h str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    const CURRENT: &[u8] = b"current-signing-key";
    const RETIRED: &[u8] = b"retired-signing-key";
    const BODY: &[u8] = b"{\"action\":\"deploy\"}";

    fn keyring() -> Keyring {
        Keyring::new()
            .with(Credential::new("agent-reader", Role::Reader, CURRENT))
            .with(Credential::new("agent-writer", Role::Writer, CURRENT).rolled_from(RETIRED))
    }

    fn headers(agent: &str, signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AGENT_HEADER, HeaderValue::from_str(agent).unwrap());
        headers.insert(SIGNATURE_HEADER, HeaderValue::from_str(signature).unwrap());
        headers
    }

    fn signed(agent: &str, key: &[u8], body: &[u8]) -> HeaderMap {
        headers(agent, &sign(key, agent, body))
    }

    #[test]
    fn a_valid_signature_authenticates() {
        let caller = verify_with(&keyring(), &signed("agent-writer", CURRENT, BODY), BODY).unwrap();
        assert_eq!(
            caller,
            Caller {
                agent: "agent-writer".to_owned(),
                role: Role::Writer
            }
        );
    }

    #[test]
    fn the_retired_key_still_verifies() {
        // The point of the second key: a caller that has not yet picked up the roll keeps working.
        let caller = verify_with(&keyring(), &signed("agent-writer", RETIRED, BODY), BODY).unwrap();
        assert_eq!(caller.role, Role::Writer);

        // A key that was never configured does not verify, retired or otherwise.
        let stranger = signed("agent-writer", b"never-configured", BODY);
        assert!(matches!(
            verify_with(&keyring(), &stranger, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_credential_without_a_roll_has_nothing_to_fall_back_on() {
        let headers = signed("agent-reader", RETIRED, BODY);
        assert!(matches!(
            verify_with(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_tampered_body_fails() {
        let headers = signed("agent-writer", CURRENT, BODY);
        assert!(matches!(
            verify_with(&keyring(), &headers, b"{\"action\":\"erase\"}"),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_tampered_signature_fails() {
        let mut signature = sign(CURRENT, "agent-writer", BODY);
        signature.replace_range(0..1, if signature.starts_with('a') { "b" } else { "a" });
        assert!(matches!(
            verify_with(&keyring(), &headers("agent-writer", &signature), BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_signature_that_is_not_hex_fails() {
        let headers = headers("agent-writer", "not-a-hex-tag");
        assert!(matches!(
            verify_with(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_signature_of_the_wrong_length_fails() {
        let truncated = sign(CURRENT, "agent-writer", BODY)[..16].to_owned();
        assert!(matches!(
            verify_with(&keyring(), &headers("agent-writer", &truncated), BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn missing_headers_fail() {
        let ring = keyring();
        let complete = signed("agent-writer", CURRENT, BODY);

        let mut without_signature = complete.clone();
        without_signature.remove(SIGNATURE_HEADER);
        let mut without_agent = complete.clone();
        without_agent.remove(AGENT_HEADER);

        for headers in [HeaderMap::new(), without_signature, without_agent] {
            assert!(matches!(
                verify_with(&ring, &headers, BODY),
                Err(Error::Unauthenticated)
            ));
        }
    }

    #[test]
    fn an_unknown_agent_fails() {
        let headers = signed("agent-nobody", CURRENT, BODY);
        assert!(matches!(
            verify_with(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_non_ascii_agent_header_fails() {
        let mut headers = signed("agent-writer", CURRENT, BODY);
        headers.insert(AGENT_HEADER, HeaderValue::from_bytes(b"\xff").unwrap());
        assert!(matches!(
            verify_with(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn signing_binds_the_agent_and_the_body() {
        assert_ne!(
            sign(CURRENT, "agent-writer", BODY),
            sign(CURRENT, "agent-reader", BODY),
            "a signature must not transfer between agents"
        );
        assert_ne!(
            sign(CURRENT, "agent-writer", BODY),
            sign(CURRENT, "agent-writer", b"other"),
            "a signature must not transfer between bodies"
        );
    }

    #[test]
    fn an_agent_the_installed_keyring_does_not_know_is_refused() {
        // `verify` reads process state, so this asserts only what every deployment relies on: the
        // ambient path resolves a keyring and refuses a caller that is not in it.
        let headers = signed("agent-not-installed-anywhere", CURRENT, BODY);
        assert!(matches!(
            verify(&headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn write_attribution_is_confined_to_the_caller() {
        let writer = Caller {
            agent: "agent-writer".to_owned(),
            role: Role::Writer,
        };
        assert!(authorise_write(&writer, "agent-writer").is_ok());

        let forged = authorise_write(&writer, "agent-other");
        assert!(matches!(forged, Err(Error::Forbidden(_))), "{forged:?}");
    }

    #[test]
    fn a_reader_may_not_write_even_as_itself() {
        let reader = Caller {
            agent: "agent-reader".to_owned(),
            role: Role::Reader,
        };
        assert!(matches!(
            authorise_write(&reader, "agent-reader"),
            Err(Error::Forbidden(_))
        ));
    }

    #[test]
    fn roles_form_a_ladder() {
        assert!(Role::Operator.covers(Role::Writer));
        assert!(Role::Writer.covers(Role::Reader));
        assert!(!Role::Writer.covers(Role::Operator));
        assert!(!Role::Reader.covers(Role::Writer));
        assert!(Role::Reader.covers(Role::Reader));
    }

    #[test]
    fn require_role_names_the_caller_it_refused() {
        let writer = Caller {
            agent: "agent-writer".to_owned(),
            role: Role::Writer,
        };
        assert!(require_role(&writer, Role::Writer).is_ok());
        let Err(Error::Forbidden(message)) = require_role(&writer, Role::Operator) else {
            panic!("a writer must not pass an operator check");
        };
        assert!(message.contains("agent-writer"), "{message}");
    }

    #[test]
    fn a_later_credential_replaces_an_earlier_one_for_the_same_agent() {
        let ring = keyring().with(Credential::new("agent-writer", Role::Operator, RETIRED));
        let caller = verify_with(&ring, &signed("agent-writer", RETIRED, BODY), BODY).unwrap();
        assert_eq!(caller.role, Role::Operator);
    }
}
