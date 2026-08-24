//! The commit guard, through a real repository and a real hook.
//!
//! The library tests cover the classification in process, over paths handed to it directly. Here for
//! the three things only a real invocation shows: that the index `git` reports is the list the guard
//! reads, that the exit codes a hook branches on are the ones a process produces, and that an
//! installed hook actually stops `git commit`.

#![forbid(unsafe_code)]

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::yaam;

/// A repository with a store's backup in a subdirectory of it.
///
/// A subdirectory because that is the layout the guard is for: everything beside the store is then
/// outside the memory root and none of its business. A store at the top level of a repository leaves
/// no such place, and the guard refuses whatever it finds there that no manifest classifies.
struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let repo = Self { dir };
        repo.git(&["init", "--quiet"]);
        // A commit needs an author, and nothing may be inherited from whoever is running the tests.
        repo.git(&["config", "user.name", "Guard"]);
        repo.git(&["config", "user.email", "guard@example.invalid"]);
        fs::create_dir_all(repo.path().join("store/spec")).expect("spec");
        fs::create_dir_all(repo.path().join("store/records/2026/08/20")).expect("records");
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn path_str(&self) -> &str {
        self.path().to_str().expect("a utf-8 temporary path")
    }

    fn root(&self) -> PathBuf {
        self.path().join("store")
    }

    /// Writes a file under the repository and returns its path.
    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("parent");
        fs::write(&path, contents).expect("write");
        path
    }

    /// Runs `git` and asserts it succeeded.
    fn git(&self, args: &[&str]) -> Output {
        let out = self.git_try(args);
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Runs `git` and returns whatever happened, hook and all.
    fn git_try(&self, args: &[&str]) -> Output {
        Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env("YAAM", env!("CARGO_BIN_EXE_yaam"))
            .output()
            .expect("run git")
    }

    /// Runs the guard over this repository's index.
    fn guard(&self) -> Output {
        yaam(&[
            "--root",
            self.root().to_str().expect("utf-8"),
            "guard-commit",
            "--repo",
            self.path_str(),
        ])
    }

    /// Installs the hook, pointed at the store subdirectory.
    fn install(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "--repo".to_owned(),
            self.path_str().to_owned(),
            "--store".to_owned(),
            "store".to_owned(),
            "--yaam".to_owned(),
            env!("CARGO_BIN_EXE_yaam").to_owned(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        Command::new("bash")
            .arg(installer())
            .args(args)
            .output()
            .expect("run the installer")
    }

    /// The hook this repository would run.
    fn hook(&self) -> PathBuf {
        self.path().join(".git/hooks/pre-commit")
    }
}

/// The installer, which lives beside the hook it installs.
fn installer() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../hooks/install.sh")
}

/// The assertion that keeps every refusal below honest: a guard that refused everything would pass
/// all of them.
#[test]
fn a_commit_of_records_and_spec_is_allowed() {
    let repo = Repo::new();
    repo.write("store/records/2026/08/20/one.md", "---\n---\nprose\n");
    repo.write("store/spec/entities.yaml", "kinds: []\n");
    repo.write("store/tombstones.jsonl", "");
    repo.write("readme.md", "a repository holding a backup\n");
    repo.git(&["add", "-A"]);

    let decided = repo.guard();
    let said = String::from_utf8_lossy(&decided.stdout);
    assert_eq!(decided.status.code(), Some(0), "{said}");
    assert!(said.contains("safe to commit"), "{said}");
    assert!(said.contains("4 of 4 path(s) are safe"), "{said}");
}

/// The case the whole thing exists for. Forced past the ignore rule, which is what makes an ignore
/// rule the wrong mechanism — and refused anyway, naming the key store and the manifest's own reason
/// for excluding it.
#[test]
fn a_commit_carrying_a_key_file_is_refused_and_named() {
    let repo = Repo::new();
    repo.write("store/records/2026/08/20/one.md", "---\n---\nprose\n");
    repo.write(".gitignore", "store/keystore/\n");
    repo.write("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
    repo.git(&["add", "-A"]);
    repo.git(&["add", "-f", "store/keystore/subjects/s_aa/epoch-1.key"]);

    let decided = repo.guard();
    let said = String::from_utf8_lossy(&decided.stdout);
    assert_eq!(decided.status.code(), Some(8), "{said}");
    assert!(
        said.contains("store/keystore/subjects/s_aa/epoch-1.key"),
        "{said}"
    );
    assert!(said.contains("it is `keystore`"), "{said}");
    assert!(
        said.contains("Erasure is key destruction"),
        "the manifest's reason is what the operator acts on: {said}"
    );
    // The commit still carries the record, and the report says so rather than only refusing.
    assert!(said.contains("records"), "{said}");
}

/// A key store that is merely present in the work tree, with nothing from it staged. Its being there
/// is the hazard, and an ignore rule does not remove it.
#[test]
fn a_key_store_in_the_work_tree_is_refused_with_nothing_from_it_staged() {
    let repo = Repo::new();
    repo.write(".gitignore", "store/keystore/\n");
    repo.write("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
    repo.write("store/records/2026/08/20/one.md", "---\n---\nprose\n");
    repo.git(&["add", "-A"]);

    let decided = repo.guard();
    let said = String::from_utf8_lossy(&decided.stdout);
    assert_eq!(decided.status.code(), Some(8), "{said}");
    assert!(said.contains("is inside this work tree"), "{said}");
    assert!(said.contains("an ignore rule is not a mechanism"), "{said}");
}

/// A file beside the store that no manifest entry classifies. Its own code, because the remedy is a
/// decision somebody has to make rather than a path to remove.
#[test]
fn a_file_beside_the_store_in_no_manifest_is_refused_with_its_own_code() {
    let repo = Repo::new();
    repo.write("store/keyring.json", "{}");
    repo.git(&["add", "-A"]);

    let decided = repo.guard();
    let said = String::from_utf8_lossy(&decided.stdout);
    assert_eq!(decided.status.code(), Some(4), "{said}");
    assert!(said.contains("keyring.json"), "{said}");
}

/// Naming no paths is a usage error, never a clean run over nothing. A guard handed no work that
/// reported success would be a guard that had allowed everything it did not look at.
#[test]
fn naming_nothing_is_a_usage_error() {
    let repo = Repo::new();
    let decided = yaam(&[
        "--root",
        repo.root().to_str().expect("utf-8"),
        "guard-commit",
    ]);
    assert_eq!(decided.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&decided.stderr).contains("nothing to refuse"),
        "{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

/// Not knowing where the store is has its own code too, and the hook prints the remedy for it.
#[test]
fn an_unset_root_is_a_config_error() {
    let repo = Repo::new();
    let decided = yaam(&["guard-commit", "--repo", repo.path_str()]);
    assert_eq!(decided.status.code(), Some(3));
}

/// The whole path: install the hook, then let `git commit` run it.
#[test]
fn the_installed_hook_stops_a_commit_that_carries_a_key() {
    let repo = Repo::new();
    let installed = repo.install(&[]);
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(repo.hook().is_file(), "no hook was written");

    // A clean commit goes through, which is what makes the refusal below mean something.
    repo.write("store/records/2026/08/20/one.md", "---\n---\nprose\n");
    repo.write("store/spec/entities.yaml", "kinds: []\n");
    repo.git(&["add", "-A"]);
    let committed = repo.git_try(&["commit", "-m", "the backup"]);
    assert!(
        committed.status.success(),
        "the hook refused a clean commit:\n{}{}",
        String::from_utf8_lossy(&committed.stdout),
        String::from_utf8_lossy(&committed.stderr)
    );

    // And then a key, forced past an ignore rule.
    repo.write("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
    repo.git(&["add", "-f", "store/keystore/subjects/s_aa/epoch-1.key"]);
    let refused = repo.git_try(&["commit", "-m", "and the keys"]);
    // Both streams together: git puts a hook's own output on its stderr, so which of the two the
    // report arrives on is git's decision and not something to assert about.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!refused.status.success(), "{said}");
    assert!(said.contains("no copy of a store may hold"), "{said}");
    assert!(said.contains("it is `keystore`"), "{said}");

    // Nothing was committed: the key is still only in the index.
    let log = repo.git(&["log", "--oneline"]);
    assert_eq!(
        String::from_utf8_lossy(&log.stdout).lines().count(),
        1,
        "the refused commit was made anyway"
    );
}

/// A hook missing its own guard blocks the commit. "Nothing checked it" is not a pass.
#[test]
fn a_hook_whose_guard_is_not_runnable_refuses() {
    let repo = Repo::new();
    repo.install(&[]);
    repo.write("store/records/2026/08/20/one.md", "---\n---\nprose\n");
    repo.git(&["add", "-A"]);

    let refused = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["commit", "-m", "no guard"])
        .env("YAAM", repo.path().join("no-such-binary"))
        .output()
        .expect("run git");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("nothing checked this commit"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

/// Installing twice changes nothing, and installing over somebody else's hook changes nothing
/// either: it says what to add instead. Replacing a hook would remove a check to add one.
#[test]
fn the_installer_is_idempotent_and_refuses_to_clobber() {
    let repo = Repo::new();
    repo.install(&[]);
    let written = fs::read_to_string(repo.hook()).expect("the hook");

    let again = repo.install(&[]);
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already this hook"),
        "{}",
        String::from_utf8_lossy(&again.stdout)
    );
    assert_eq!(
        fs::read_to_string(repo.hook()).expect("the hook"),
        written,
        "a second install rewrote the hook"
    );

    // Somebody else's hook, which is not this one.
    let theirs = "#!/bin/sh\necho mine\n";
    fs::write(repo.hook(), theirs).expect("their hook");
    let beside = repo.install(&[]);
    let said = String::from_utf8_lossy(&beside.stdout);
    assert!(said.contains("kept existing"), "{said}");
    assert!(said.contains("pre-commit.guard-commit"), "{said}");
    assert_eq!(
        fs::read_to_string(repo.hook()).expect("their hook"),
        theirs,
        "the existing hook was clobbered"
    );
    let aside = repo.path().join(".git/hooks/pre-commit.guard-commit");
    assert_eq!(
        fs::read_to_string(&aside).expect("the hook beside it"),
        written
    );
}

/// The installed hook is the one the binary carries, so an installer can tell an unmodified hook
/// from an edited one and the script cannot drift from the command it calls.
#[test]
fn the_installed_hook_is_the_one_the_binary_prints() {
    let printed = yaam(&["guard-commit", "--print-hook"]);
    assert_eq!(printed.status.code(), Some(0));
    let printed = String::from_utf8_lossy(&printed.stdout).into_owned();
    assert_eq!(printed, yaam_cli::guard::HOOK);

    let repo = Repo::new();
    repo.install(&[]);
    assert_eq!(fs::read_to_string(repo.hook()).expect("the hook"), printed);
}
