//! The signed request surface: what a write carries, and what a signature covers.
//!
//! This lives in the contract crate because it *is* contract: the bytes a signer covers and the
//! bytes a verifier recomputes are one wire rule, and the sidecar and the service both depend on
//! this crate already. Two independent spellings of that rule is how a signer and a verifier end
//! up unable to talk while each passes its own tests.
//!
//! The message is method, request target, agent and body. Method and path are in it because a
//! signature that covers neither can be lifted off one endpoint and replayed at another; the agent
//! is in it so a captured signature does not transfer between callers; the body is in it so nothing
//! in flight can be edited. The separator is a newline, which none of the first three fields can
//! contain — a method and a request target come out of the HTTP request line, and a header value
//! cannot hold one — so no field can be stuffed to look like the next.
//!
//! Replay of an *identical* request is not defended against here, and that is a decision: writes
//! are idempotent on the record id and reads mutate nothing, so replaying a captured message gains
//! an attacker nothing the captured response did not already give them. Keeping the message secret
//! in flight is the transport's job.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::ActionRecord;

/// Header naming the agent a request is signed as.
pub const AGENT_HEADER: &str = "x-yaam-agent";

/// Header carrying the hex-encoded signature.
pub const SIGNATURE_HEADER: &str = "x-yaam-signature";

/// A record and the prose stored as its body.
///
/// Here rather than in the service, because the sidecar composes exactly what the service parses.
/// Two declarations of one request body is how a sender and a receiver stop agreeing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    /// The record itself.
    pub record: ActionRecord,
    /// Body to store. Absent means the record's summary, which is the prose that becomes the body
    /// when the caller has nothing longer to add.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// One caller's signing material.
///
/// Two keys, not one. During a roll the caller and the service pick up the new key at different
/// moments, and a verifier that knows only the current key rejects every request signed with the
/// old one until both sides restart together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeys {
    /// Key requests are signed with, and the one a verifier expects first.
    pub current: Vec<u8>,
    /// Key retired by the most recent roll, still accepted. `None` before the first roll.
    pub previous: Option<Vec<u8>>,
}

impl SigningKeys {
    /// Material with no retired key.
    #[must_use]
    pub fn new(current: impl Into<Vec<u8>>) -> Self {
        Self {
            current: current.into(),
            previous: None,
        }
    }

    /// Records the key this material rolled away from.
    #[must_use]
    pub fn rolled_from(mut self, previous: impl Into<Vec<u8>>) -> Self {
        self.previous = Some(previous.into());
        self
    }

    /// Signs a request under the current key.
    #[must_use]
    pub fn sign(&self, method: &str, path: &str, agent: &str, body: &[u8]) -> String {
        sign(&self.current, method, path, agent, body)
    }

    /// Whether `offered` is a valid tag under either key.
    ///
    /// Non-short-circuiting: both keys are checked whichever one matched, so a request signed with
    /// the retired key takes no longer than one signed with the current key.
    #[must_use]
    pub fn matches(
        &self,
        method: &str,
        path: &str,
        agent: &str,
        body: &[u8],
        offered: &[u8],
    ) -> bool {
        let current = matches_key(&self.current, method, path, agent, body, offered);
        let previous = self
            .previous
            .as_deref()
            .is_some_and(|key| matches_key(key, method, path, agent, body, offered));
        current | previous
    }
}

/// Signs the canonical message, hex encoded as the signature header carries it.
///
/// `path` is the request target the signer sends and the verifier received, query string included:
/// for a read the query *is* the request, so a signature that covered only the path would let one
/// captured read be replayed as any other.
#[must_use]
pub fn sign(key: &[u8], method: &str, path: &str, agent: &str, body: &[u8]) -> String {
    hex::encode(tag(key, method, path, agent, body))
}

/// The tag over method, request target, agent and body.
fn tag(key: &[u8], method: &str, path: &str, agent: &str, body: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("hmac takes a key of any length, so this cannot fail");
    for field in [method.as_bytes(), path.as_bytes(), agent.as_bytes()] {
        mac.update(field);
        mac.update(b"\n");
    }
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time tag comparison.
///
/// A byte-by-byte check that returns on the first mismatch hands an attacker the tag one byte at a
/// time, so the comparison must not depend on where the difference is.
fn matches_key(
    key: &[u8],
    method: &str,
    path: &str,
    agent: &str,
    body: &[u8],
    offered: &[u8],
) -> bool {
    tag(key, method, path, agent, body).ct_eq(offered).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: &[u8] = b"current-signing-key";
    const RETIRED: &[u8] = b"retired-signing-key";
    const BODY: &[u8] = b"{\"action\":\"deploy\"}";

    fn keys() -> SigningKeys {
        SigningKeys::new(CURRENT).rolled_from(RETIRED)
    }

    fn offered(key: &[u8], method: &str, path: &str, agent: &str, body: &[u8]) -> Vec<u8> {
        hex::decode(sign(key, method, path, agent, body)).expect("a hex tag")
    }

    #[test]
    fn a_tag_verifies_under_either_key() {
        for key in [CURRENT, RETIRED] {
            let tag = offered(key, "POST", "/records", "agent-writer", BODY);
            assert!(keys().matches("POST", "/records", "agent-writer", BODY, &tag));
        }
    }

    #[test]
    fn a_credential_without_a_roll_has_nothing_to_fall_back_on() {
        let tag = offered(RETIRED, "POST", "/records", "agent-writer", BODY);
        assert!(!SigningKeys::new(CURRENT).matches("POST", "/records", "agent-writer", BODY, &tag));
    }

    #[test]
    fn every_field_is_bound_into_the_message() {
        let signed = sign(CURRENT, "POST", "/records", "agent-writer", BODY);
        // Each of these is a different request, so none of them may share a signature with it.
        for other in [
            sign(CURRENT, "GET", "/records", "agent-writer", BODY),
            sign(CURRENT, "POST", "/erase", "agent-writer", BODY),
            sign(CURRENT, "POST", "/records?limit=1", "agent-writer", BODY),
            sign(CURRENT, "POST", "/records", "agent-reader", BODY),
            sign(CURRENT, "POST", "/records", "agent-writer", b"other"),
        ] {
            assert_ne!(signed, other);
        }
    }

    #[test]
    fn no_field_can_be_stuffed_into_the_next() {
        // Without a separator per field, these two would sign identically.
        assert_ne!(
            sign(CURRENT, "POST", "/records", "agent", BODY),
            sign(CURRENT, "POST", "/record", "sagent", BODY),
        );
    }

    #[test]
    fn a_wrong_length_tag_fails_rather_than_matching_a_prefix() {
        let mut tag = offered(CURRENT, "POST", "/records", "agent-writer", BODY);
        tag.truncate(8);
        assert!(!keys().matches("POST", "/records", "agent-writer", BODY, &tag));
        assert!(!keys().matches("POST", "/records", "agent-writer", BODY, b""));
    }

    #[test]
    fn a_write_request_round_trips_and_omits_an_absent_body() {
        let record = crate::record::tests::internal_record();
        let request = WriteRequest {
            record: record.clone(),
            body: None,
        };
        let json = serde_json::to_string(&request).expect("serialise");
        assert!(!json.contains("\"body\""), "{json}");
        assert_eq!(
            serde_json::from_str::<WriteRequest>(&json).expect("parse"),
            request
        );

        let with_body = WriteRequest {
            record,
            body: Some("the long form".to_owned()),
        };
        let json = serde_json::to_string(&with_body).expect("serialise");
        assert_eq!(
            serde_json::from_str::<WriteRequest>(&json).expect("parse"),
            with_body
        );
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // A mistyped field that got dropped would store a record the caller did not describe.
        let json = r#"{"record":1,"bodyy":"x"}"#;
        assert!(serde_json::from_str::<WriteRequest>(json).is_err());
    }

    #[test]
    fn signing_keys_are_comparable_so_a_configuration_test_can_say_so() {
        assert_eq!(SigningKeys::new(CURRENT), SigningKeys::new(CURRENT));
        assert_ne!(SigningKeys::new(CURRENT), keys());
    }
}
