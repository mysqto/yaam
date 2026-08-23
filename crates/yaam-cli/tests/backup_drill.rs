//! The backup and its restore, through the built binaries.
//!
//! The library tests cover the manifest and the erasure invariant in process. This is here for the
//! two things only a real invocation shows: the exit code a runbook branches on, and whether a
//! restore into a directory that is not yet a store actually produces one.

#![forbid(unsafe_code)]

mod support;

use support::{Deployment, record, rendered, yaam};

#[test]
fn a_backup_restores_into_a_fresh_store_that_answers_and_carries_no_keys() {
    let source = Deployment::new();
    let record = record();
    let dated = source.root().join("records/2026/08/20");
    std::fs::create_dir_all(&dated).expect("dated dir");
    std::fs::write(
        dated.join(format!("{}.md", record.record_id.as_str())),
        rendered(&record),
    )
    .expect("record file");
    assert_eq!(
        yaam(&["--root", source.root_str(), "reindex", "--all"])
            .status
            .code(),
        Some(0)
    );

    // Outside both stores: a backup kept inside the tree it copies is refused, and rightly.
    let held = tempfile::tempdir().expect("tempdir");
    let into = held.path().join("backup");
    let into_str = into.to_str().expect("utf-8");
    let taken = yaam(&["--root", source.root_str(), "backup", "--to", into_str]);
    // Degraded rather than clean, and correctly so: this deployment keeps its keyring beside the
    // store, the manifest classifies no such file, and a copy that guessed would have taken it.
    assert_eq!(
        taken.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&taken.stderr)
    );
    let said = String::from_utf8_lossy(&taken.stdout);
    assert!(said.contains("keyring.json"), "{said}");
    assert!(!into.join("keyring.json").exists(), "the keyring travelled");

    // The exclusion, asserted over the manifest rather than over a list repeated here: a later
    // exclusion is covered by this the moment it is declared.
    for entry in yaam_core::backup::excluded() {
        assert!(
            !into.join(entry.name).exists(),
            "`{}` reached the backup: {}",
            entry.name,
            entry.reason
        );
    }

    // A fresh store, with no spec of its own: what it reads records under has to have travelled.
    let destination = tempfile::tempdir().expect("tempdir");
    let destination_str = destination.path().to_str().expect("utf-8");
    let restored = yaam(&["--root", destination_str, "restore", "--from", into_str]);
    assert_eq!(
        restored.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(
        String::from_utf8_lossy(&restored.stdout).contains("records indexed     1"),
        "{}",
        String::from_utf8_lossy(&restored.stdout)
    );
    assert!(destination.path().join("spec/entities.yaml").is_file());

    // And it answers. `check` reads the index the restore rebuilt, so no drift means the rows are
    // there — the assertion a directory listing cannot make.
    let checked = yaam(&["--root", destination_str, "check"]);
    let printed = String::from_utf8_lossy(&checked.stdout);
    assert!(printed.contains("records indexed    1"), "{printed}");
    assert!(printed.contains("index drift        0"), "{printed}");

    // A second restore into the same store is a merge, and refused.
    let again = yaam(&["--root", destination_str, "restore", "--from", into_str]);
    assert_eq!(again.status.code(), Some(1));
}
