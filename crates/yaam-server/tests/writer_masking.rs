//! The two halves of redaction, checked against each other.
//!
//! The writer masks and the service only checks, so the one thing that can silently break is the
//! two reading the policy differently. This drives both over the *repository's own*
//! `spec/redaction/default.yaml`: a body the service refuses is masked by
//! [`yaam_contract::mask`] and then accepted, which is the whole reason that library exists rather
//! than a note in a README telling each writer to redact.

mod support;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use yaam_contract::mask::Policy;
use yaam_core::pipeline::Accepted;
use yaam_server::auth::Role;
use yaam_server::service::Service;

use support::{POLICY, Tree, caller, record};

/// One instance of every pattern the repository's policy names, with obviously fake secrets.
const DIRTY: &str = concat!(
    "Rolled out the api service to staging.\n",
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "authorization: Bearer not-a-real-token-0123456789\n",
    "api_key: not-a-real-key-value\n",
    "contact: someone@example.test\n",
    "card: 4111 1111 1111 1111\n",
    "order_ref: ord10014721, 12 shards\n",
);

/// The policy as this repository ships it, which is what the service loads too.
fn shipped_policy() -> Policy {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/redaction/default.yaml");
    let text = fs::read_to_string(path).expect("the repository's redaction policy");
    Policy::from_yaml(&text).expect("the shipped policy loads")
}

#[test]
fn the_service_accepts_what_the_masking_library_produces() {
    let policy = shipped_policy();
    assert_eq!(
        policy.name(),
        POLICY,
        "a record must declare the policy the deployment applies"
    );

    let tree = Tree::new();
    let service = Arc::clone(&tree.service);
    let writer = caller("agent_a", Role::Writer, &["platform"]);

    // What happens to a writer that skips masking: refused, and told which pattern to fix.
    let refusal = service
        .write(&writer, record("agent_a", "2026-08-20T09:00:00Z"), DIRTY)
        .expect_err("the service refuses a body that still matches")
        .to_string();
    assert!(refusal.contains("redaction pattern"), "{refusal}");

    let masked = policy.mask(DIRTY);
    assert_eq!(
        masked.fields_masked,
        [
            "private_key_block",
            "bearer_token",
            "generic_api_key",
            "email",
            "card_like"
        ],
        "the writer can name what it redacted rather than guessing"
    );

    let mut clean = record("agent_a", "2026-08-20T09:01:00Z");
    clean.fields_masked = masked.fields_masked.clone();
    let id = clean.record_id.clone();
    assert_eq!(
        service
            .write(&writer, clean, &masked.text)
            .expect("the service accepts a masked body"),
        Accepted::Stored(id.clone())
    );

    // The record's account of its own redaction is the writer's, and it reached the tree.
    let stored = tree.file_of(&id);
    for pattern in &masked.fields_masked {
        assert!(stored.contains(pattern), "{pattern} missing from {stored}");
    }
    assert!(!stored.contains("not-a-real-token"), "{stored}");
    assert!(!stored.contains("someone@example.test"), "{stored}");
}

#[test]
fn a_writer_retrying_masks_the_same_body_to_the_same_bytes() {
    // The service dedupes on the record id, so a retry must produce a body identical to the one
    // already published. Double-masking would make the retry a different record's worth of prose.
    let policy = shipped_policy();
    let once = policy.mask(DIRTY);
    let twice = policy.mask(&once.text);
    assert_eq!(twice.text, once.text);
    assert!(twice.fields_masked.is_empty());
    assert_eq!(policy.first_match(&once.text), None);
}
