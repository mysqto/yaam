//! Request authentication and write attribution.
//!
//! Every request carries a signature, reads included: what a caller may see is decided per caller,
//! and an anonymous request has no caller to decide about.
//!
//! What a signature covers, and how it is compared, is [`yaam_contract::request`] — shared with
//! everything that signs, because a service and a sidecar that spell the canonical message
//! differently cannot talk while each passes its own tests. Both the current and the previous key
//! are accepted, so a key roll needs no synchronised restart.
//!
//! The keyring is an argument, never process state. A test — and a process serving more than one
//! deployment — has to be able to say which callers it authenticates, and ambient state cannot be
//! asked that at the call site.

use std::collections::HashMap;

use axum::http::HeaderMap;
use yaam_contract::Visibility;
use yaam_store::query::Scope;

use crate::{Error, Result};

pub use yaam_contract::request::{AGENT_HEADER, SIGNATURE_HEADER, SigningKeys, sign};

/// A verified caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The agent identity this caller may write as.
    pub agent: String,
    /// What the caller is allowed to do.
    pub role: Role,
    /// Teams whose team-visible records this caller may read.
    pub teams: Vec<String>,
}

impl Caller {
    /// What this caller may read.
    ///
    /// Org-visible records for anyone the service authenticated; team-visible records only for the
    /// teams the credential names; owner-visible records only where this caller is the record's own
    /// agent; operator-visible records — the audit trail — only for the operator role.
    ///
    /// An operator's extra reach is that last level, not other teams'. Team membership is the same
    /// predicate for every role, and a read that has to see everything is a maintenance read
    /// ([`Scope::Unrestricted`]), not a caller with a wide badge.
    #[must_use]
    pub fn scope(&self) -> Scope {
        let mut visibility = vec![Visibility::Org, Visibility::Team, Visibility::Owner];
        if self.role.covers(Role::Operator) {
            visibility.push(Visibility::Operator);
        }
        Scope::Caller {
            visibility,
            agent: self.agent.clone(),
            teams: self.teams.clone(),
        }
    }
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

/// One caller's signing material, capability and read scope.
///
/// The key material is [`SigningKeys`], the same type a sidecar holds, so the two sides of a
/// deployment cannot describe one credential differently.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Agent identity this credential authenticates.
    pub agent: String,
    /// What that agent may do.
    pub role: Role,
    /// Keys signatures are accepted under.
    pub keys: SigningKeys,
    /// Teams this agent belongs to. Empty means it reads no team's records.
    pub teams: Vec<String>,
}

impl Credential {
    /// A credential with no retired key and no team.
    #[must_use]
    pub fn new(agent: impl Into<String>, role: Role, current_key: impl Into<Vec<u8>>) -> Self {
        Self {
            agent: agent.into(),
            role,
            keys: SigningKeys::new(current_key),
            teams: Vec::new(),
        }
    }

    /// Records the key this credential rolled away from.
    #[must_use]
    pub fn rolled_from(mut self, previous_key: impl Into<Vec<u8>>) -> Self {
        self.keys = self.keys.rolled_from(previous_key);
        self
    }

    /// Names the teams this agent belongs to.
    #[must_use]
    pub fn in_teams<T: Into<String>>(mut self, teams: impl IntoIterator<Item = T>) -> Self {
        self.teams = teams.into_iter().map(Into::into).collect();
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

/// Verifies a signature over the request and resolves the caller.
///
/// `method` and `path` are the request's own, query string included: they are in the signature, so a
/// captured signature cannot be lifted onto another endpoint or another set of filters.
pub fn verify(
    keyring: &Keyring,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Caller> {
    let agent = header(headers, AGENT_HEADER)?;
    // A malformed signature is reported exactly like a wrong one: telling the two apart tells a
    // prober whether it got the encoding right.
    let offered =
        hex::decode(header(headers, SIGNATURE_HEADER)?).map_err(|_| Error::Unauthenticated)?;
    let credential = keyring.credential(agent).ok_or(Error::Unauthenticated)?;

    if credential.keys.matches(method, path, agent, body, &offered) {
        Ok(Caller {
            agent: credential.agent.clone(),
            role: credential.role,
            teams: credential.teams.clone(),
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
    const PATH: &str = "/records";

    fn keyring() -> Keyring {
        Keyring::new()
            .with(Credential::new("agent-reader", Role::Reader, CURRENT).in_teams(["platform"]))
            .with(Credential::new("agent-writer", Role::Writer, CURRENT).rolled_from(RETIRED))
    }

    fn headers(agent: &str, signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AGENT_HEADER, HeaderValue::from_str(agent).unwrap());
        headers.insert(SIGNATURE_HEADER, HeaderValue::from_str(signature).unwrap());
        headers
    }

    fn signed(agent: &str, key: &[u8], body: &[u8]) -> HeaderMap {
        headers(agent, &sign(key, "POST", PATH, agent, body))
    }

    /// Verifies a `POST /records`, which is what all but the path test is about.
    fn check(keyring: &Keyring, headers: &HeaderMap, body: &[u8]) -> Result<Caller> {
        verify(keyring, "POST", PATH, headers, body)
    }

    #[test]
    fn a_valid_signature_authenticates() {
        let caller = check(&keyring(), &signed("agent-writer", CURRENT, BODY), BODY).unwrap();
        assert_eq!(
            caller,
            Caller {
                agent: "agent-writer".to_owned(),
                role: Role::Writer,
                teams: Vec::new(),
            }
        );
    }

    #[test]
    fn the_retired_key_still_verifies() {
        // The point of the second key: a caller that has not yet picked up the roll keeps working.
        let caller = check(&keyring(), &signed("agent-writer", RETIRED, BODY), BODY).unwrap();
        assert_eq!(caller.role, Role::Writer);

        // A key that was never configured does not verify, retired or otherwise.
        let stranger = signed("agent-writer", b"never-configured", BODY);
        assert!(matches!(
            check(&keyring(), &stranger, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_credential_without_a_roll_has_nothing_to_fall_back_on() {
        let headers = signed("agent-reader", RETIRED, BODY);
        assert!(matches!(
            check(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_tampered_body_fails() {
        let headers = signed("agent-writer", CURRENT, BODY);
        assert!(matches!(
            check(&keyring(), &headers, b"{\"action\":\"erase\"}"),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_tampered_signature_fails() {
        let mut signature = sign(CURRENT, "POST", PATH, "agent-writer", BODY);
        signature.replace_range(0..1, if signature.starts_with('a') { "b" } else { "a" });
        assert!(matches!(
            check(&keyring(), &headers("agent-writer", &signature), BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_signature_that_is_not_hex_fails() {
        let headers = headers("agent-writer", "not-a-hex-tag");
        assert!(matches!(
            check(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_signature_of_the_wrong_length_fails() {
        let truncated = sign(CURRENT, "POST", PATH, "agent-writer", BODY)[..16].to_owned();
        assert!(matches!(
            check(&keyring(), &headers("agent-writer", &truncated), BODY),
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
                check(&ring, &headers, BODY),
                Err(Error::Unauthenticated)
            ));
        }
    }

    #[test]
    fn an_unknown_agent_fails() {
        let headers = signed("agent-nobody", CURRENT, BODY);
        assert!(matches!(
            check(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_non_ascii_agent_header_fails() {
        let mut headers = signed("agent-writer", CURRENT, BODY);
        headers.insert(AGENT_HEADER, HeaderValue::from_bytes(b"\xff").unwrap());
        assert!(matches!(
            check(&keyring(), &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_signature_valid_for_one_request_target_is_refused_on_another() {
        let headers = signed("agent-writer", CURRENT, BODY);
        // Same body, same agent, same key — a different endpoint. Replaying it must fail.
        assert!(matches!(
            verify(&keyring(), "POST", "/erase", &headers, BODY),
            Err(Error::Unauthenticated)
        ));
        // And the same endpoint reached with a different method, or different filters.
        assert!(matches!(
            verify(&keyring(), "GET", PATH, &headers, BODY),
            Err(Error::Unauthenticated)
        ));
        assert!(matches!(
            verify(&keyring(), "POST", "/records?limit=1", &headers, BODY),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn a_readers_scope_is_its_own_teams_and_never_the_audit_trail() {
        let caller = check(&keyring(), &signed("agent-reader", CURRENT, BODY), BODY).unwrap();
        assert_eq!(caller.teams, ["platform"]);

        let Scope::Caller {
            visibility,
            agent,
            teams,
        } = caller.scope()
        else {
            panic!("a verified caller reads under its own scope");
        };
        assert_eq!(agent, "agent-reader");
        assert_eq!(teams, ["platform"]);
        assert!(!visibility.contains(&Visibility::Operator));
        for level in [Visibility::Org, Visibility::Team, Visibility::Owner] {
            assert!(visibility.contains(&level), "{level:?}");
        }
    }

    #[test]
    fn only_an_operator_reads_the_audit_trail() {
        let operator = Caller {
            agent: "agent-operator".to_owned(),
            role: Role::Operator,
            teams: vec!["platform".to_owned()],
        };
        let Scope::Caller { visibility, .. } = operator.scope() else {
            panic!("an operator reads under its own scope too");
        };
        assert!(visibility.contains(&Visibility::Operator));
    }

    #[test]
    fn write_attribution_is_confined_to_the_caller() {
        let writer = Caller {
            agent: "agent-writer".to_owned(),
            role: Role::Writer,
            teams: Vec::new(),
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
            teams: Vec::new(),
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
            teams: Vec::new(),
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
        let caller = check(&ring, &signed("agent-writer", RETIRED, BODY), BODY).unwrap();
        assert_eq!(caller.role, Role::Operator);
    }
}
