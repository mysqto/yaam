//! A frontmatter migration must not cost a sealed record its body.
//!
//! The associated data is `record_id ‖ sealed_format_ver ‖ H(sorted subject hashes)`, recomputed at
//! unseal time and never stored. `schema_ver` is deliberately absent from it, and that absence is a
//! decision rather than an oversight: the wire contract bumps `schema_ver` on a breaking frontmatter
//! change and the index stores it per row so migrations can rewrite old records. Binding the
//! ciphertext to it would make every pre-migration body undecryptable the moment a migration ran —
//! and unrepairable for any subject already shredded, because re-sealing needs the plaintext nobody
//! can still read. The rule that falls out of it: **a schema migration must never require a
//! re-seal.**
//!
//! Two things are asserted here, and the second is what keeps the first honest. That a bumped
//! `schema_ver` still opens is worth little on its own — a build that authenticated nothing at all
//! would pass it — so the same sealed bodies are also swapped between two records that share a
//! subject, and both must refuse to open.
//!
//! The record is written through the library and the index rebuilt with the built `yaam` binary,
//! because a migration in practice is a tree rewrite followed by a rebuild.

#![forbid(unsafe_code)]

use std::fs;

use yaam_contract::{RecordId, SchemaVer};
use yaam_core::Pipeline;
use yaam_core::pipeline::Accepted;
use yaam_crypto::keystore::FsKeyStore;
use yaam_md::{Body, Document};

mod support;

use support::{BODY, Deployment, indexed, subject, subject_derived, yaam};

/// The version a breaking frontmatter change would move a record to.
const MIGRATED: SchemaVer = SchemaVer(2);

#[test]
fn a_sealed_body_still_opens_after_its_schema_version_is_bumped() {
    let deployment = Deployment::new().writing_subjects();
    let record = subject_derived(&[subject('a')]);
    let id = record.record_id.clone();
    accept(&deployment, record);

    let path = deployment.published(&id);
    let before = fs::read_to_string(&path).expect("the published record");
    let document = Document::parse(&before).expect("parsed");
    assert!(
        matches!(document.body, Body::Sealed(_)),
        "a subject-derived record with a plaintext body would make this test vacuous"
    );
    assert_eq!(
        unseal(&deployment, &id, &document).expect("the body opens before the migration"),
        BODY.as_bytes(),
        "the baseline: the record this test migrates is readable to begin with"
    );
    assert!(
        !before.contains("aad="),
        "the associated data is recomputed from the record's identity; a stored copy would travel \
         with a swapped body and authenticate it"
    );

    // The migration itself: frontmatter rewritten, body carried across untouched.
    let mut migrated = document.clone();
    migrated.record.schema_ver = MIGRATED;
    let after = migrated.render();
    fs::write(&path, &after).expect("write the migrated record");
    assert_eq!(
        sealed_block(&after),
        sealed_block(&before),
        "a frontmatter migration is not a re-seal: nonce, epoch, shares and ciphertext are the \
         bytes that were there before"
    );

    // The index follows the tree, which is where a migration is applied.
    let rebuilt = yaam(&["--root", deployment.root_str(), "reindex", "--all"]);
    assert_eq!(
        rebuilt.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    assert_eq!(
        indexed(&deployment).get(id.as_str()),
        Some(&i64::from(MIGRATED.0)),
        "the migration has to have reached the index, or this test proves nothing about one"
    );

    // The guard.
    let reread = Document::parse(&fs::read_to_string(&path).expect("read back")).expect("parsed");
    assert_eq!(
        unseal(&deployment, &id, &reread).expect("the body opens after the migration"),
        BODY.as_bytes(),
        "a schema bump left this body unreadable, which is unrecoverable for a shredded subject"
    );

    let checked = yaam(&["--root", deployment.root_str(), "check"]);
    let printed = String::from_utf8_lossy(&checked.stdout);
    assert!(printed.contains("index drift        0"), "{printed}");
}

#[test]
fn two_records_sharing_a_subject_cannot_have_their_bodies_swapped() {
    let deployment = Deployment::new().writing_subjects();
    let shared = subject('b');
    let first = subject_derived(std::slice::from_ref(&shared));
    let second = subject_derived(&[shared]);
    let (left, right) = (first.record_id.clone(), second.record_id.clone());
    accept(&deployment, first);
    accept(&deployment, second);

    // Both files are read before either is written: swapping them one at a time would have the
    // second swap read a file the first had already changed, and put each body back where it began.
    let files = [
        fs::read_to_string(deployment.published(&left)).expect("read"),
        fs::read_to_string(deployment.published(&right)).expect("read"),
    ];

    // Same subject, same epoch, so every share in one block unwraps under the key the other needs.
    // What refuses the swap is the record's own identity, bound into both the key derivation and the
    // associated data.
    for (onto, body) in [(&left, &files[1]), (&right, &files[0])] {
        let host = &files[usize::from(onto == &right)];
        let text = format!(
            "{}{}",
            &host[..host.find("```sealed").expect("a sealed block")],
            sealed_block(body)
        );
        let document = Document::parse(&text).expect("parsed");
        assert!(
            unseal(&deployment, onto, &document).is_err(),
            "another record's body opened as {}: a swap between two records sharing a subject \
             would attach one record's outcome to the other",
            onto.as_str()
        );
    }
}

/// Writes a record through the pipeline and lets go of the index.
///
/// Dropped before returning because the operator binary opens the same index for writing, and a
/// rebuild that had to wait for this process's connection would be a test hanging on itself.
fn accept(deployment: &Deployment, record: yaam_contract::ActionRecord) {
    let id = record.record_id.clone();
    let mut pipeline = Pipeline::new(deployment.root()).expect("a pipeline over the fixture spec");
    assert_eq!(
        pipeline.accept(record, BODY).expect("accepted"),
        Accepted::Stored(id)
    );
}

/// Opens a record's body with the keys the deployment's own key store holds.
fn unseal(
    deployment: &Deployment,
    id: &RecordId,
    document: &Document,
) -> yaam_crypto::Result<Vec<u8>> {
    let store = FsKeyStore::unwrapped(deployment.root().join("keystore")).expect("key store");
    let Body::Sealed(sealed) = &document.body else {
        panic!("{} is not sealed", id.as_str());
    };
    yaam_crypto::seal::unseal(&store, id, sealed)
}

/// The sealed block of a record file: everything from its fence onwards.
fn sealed_block(text: &str) -> &str {
    &text[text.find("```sealed").expect("a sealed block")..]
}
