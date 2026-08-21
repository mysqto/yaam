//! The chore as a process, not as a function call.
//!
//! `ci/check.sh` and the CI workflow both run `cargo xtask check` and act on its exit status. A
//! chore that reported drift on stderr and still exited zero would leave both of them green, so the
//! status is what these tests assert.

use std::process::Command;

/// The binary this crate builds, whichever profile the test is running under.
const XTASK: &str = env!("CARGO_BIN_EXE_xtask");

#[test]
fn check_exits_zero_on_a_tree_whose_shapes_agree() {
    let output = Command::new(XTASK).arg("check").output().expect("runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("the shapes agree"), "{stdout}");
}

#[test]
fn emit_exits_zero_and_says_the_committed_schemas_are_current() {
    let output = Command::new(XTASK).arg("emit").output().expect("runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("already current"), "{stdout}");
}

#[test]
fn an_unknown_chore_exits_non_zero_and_names_the_ones_there_are() {
    for args in [vec![], vec!["polish"]] {
        let output = Command::new(XTASK).args(&args).output().expect("runs");
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("emit|check"), "{args:?}: {stderr}");
    }
}
