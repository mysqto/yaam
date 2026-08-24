//! Deciding whether a set of paths is safe to commit, and the pre-commit hook that asks.
//!
//! # Why a guard and not an ignore rule
//!
//! Keeping a store's backup in a private repository is safe, and one thing makes it safe: a backup
//! carries ciphertext and no keys ([`yaam_core::backup`]). Destroying a key still makes a sealed
//! body permanently unreadable, even though the ciphertext is in the history for ever. That is the
//! whole argument, and it rests on the key store never being committed once.
//!
//! An ignore file cannot hold it. `git add -f` overrides an ignore rule, a rule written today does
//! not remove what was committed yesterday, and a store configured with `--key-store` pointing
//! inside the work tree is ignored by nothing. A one-way door needs a mechanism rather than
//! discipline, so this is a check with an exit code a hook stops on.
//!
//! # Where the judgement comes from
//!
//! Not from here. Every decision is [`yaam_core::backup::MANIFEST`], read through
//! [`yaam_core::backup::excluded_paths`] — the same list a backup is taken against, resolved to
//! where this deployment actually keeps each entry. A second list would be the bug this exists to
//! prevent: it would agree with the first right up until an exclusion was added to one of them.
//!
//! # Fail closed
//!
//! Every unknown refuses. A path the filesystem will not resolve, a path under the memory root with
//! nothing in the tree behind it, an entry beside the store that the manifest does not classify, an
//! invocation naming no paths at all — each of those is the guard not knowing, and a guard that does
//! not know must not allow. The failure being avoided is specific and has happened before: a guard
//! whose input defaulted to empty exited 0 over every payload it had not understood.
//!
//! # What it catches, and what it cannot
//!
//! A path is read twice, because the two readings see different things. Its **spelling**, reduced
//! textually, catches `records/../keystore/x` and a path in the index with no file behind it. Its
//! **identity**, from [`std::fs::canonicalize`], catches a symlink into a key store and a key store
//! this deployment relocated under `records/` — neither of which any amount of reading the spelling
//! would find. Either reading is enough to refuse.
//!
//! Two more things are refused without waiting for a staged path. An excluded entry that *exists*
//! inside the work tree is refused on every commit, ignored or not, because its being there is the
//! hazard. And a file hardlinked to one inside an excluded entry is refused by comparing inode
//! identity, since a hardlink has no path to read and nothing else would see it.
//!
//! What this cannot see is worth stating plainly, because a documented limit is worth more than an
//! assumed guarantee:
//!
//! - `git commit --no-verify` skips every pre-commit hook. Nothing running at commit time can
//!   prevent that. What catches it is a `pre-receive` hook on the remote, or a required job that
//!   runs this same command over the pushed tree.
//! - A *copy* of a key file is a different file with the same bytes. Neither a path nor an inode
//!   sees one; content scanning on the remote does.
//! - This is only as good as the paths it is told about. A deployment whose real `--key-store` is
//!   somewhere the invocation does not name is outside what it can reason about, which is why the
//!   hook passes the deployment's own `--root` and `--key-store` rather than assuming defaults.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use yaam_core::Paths;
use yaam_core::backup::{self, Disposition, Entry};

use crate::error::{Error, Result, config, failed};
use crate::exit::Exit;

/// The `pre-commit` hook, as `--print-hook` writes it and `hooks/install.sh` installs it.
///
/// The text lives in the binary so the script and the command it calls cannot drift, and so an
/// installer can tell an unmodified hook from an edited one by comparing bytes.
pub const HOOK: &str = include_str!("../../../hooks/pre-commit");

/// Where the guard gets the paths it decides about.
///
/// Exactly one of these, and never a default. This is the failure worth naming in a type: a guard
/// whose set of things to check can arrive empty by accident is a guard that exits 0 over whatever
/// it did not look at. An explicitly empty index is a commit with nothing in it, which is a
/// different statement and a safe one.
#[derive(Debug, PartialEq, Eq)]
pub enum Subject {
    /// Everything in a repository's index: what the commit would contain, not only what changed.
    Index(PathBuf),
    /// Exactly these paths, resolved against the working directory.
    Named(Vec<PathBuf>),
    /// Print [`HOOK`] and decide nothing.
    Hook,
}

impl Subject {
    /// Reads the subject out of the flags, refusing anything that does not name exactly one.
    ///
    /// A usage error rather than a guess. Two of them together is an operator asking for two
    /// different checks; none of them is an operator who has not said what to check. Answering
    /// either with a default would be answering a question nobody asked.
    pub fn from_flags(repo: Option<&Path>, named: &[PathBuf], print_hook: bool) -> Result<Self> {
        let asked =
            usize::from(repo.is_some()) + usize::from(!named.is_empty()) + usize::from(print_hook);
        if asked > 1 {
            return Err(Error::Usage(
                "--repo, --path and --print-hook ask for different things; name one".to_owned(),
            ));
        }
        if let Some(repo) = repo {
            return Ok(Self::Index(repo.to_owned()));
        }
        if !named.is_empty() {
            return Ok(Self::Named(named.to_vec()));
        }
        if print_hook {
            return Ok(Self::Hook);
        }
        Err(Error::Usage(
            "nothing to check: pass --repo to read a repository's index, or --path for one path. \
             There is no default, because an empty set of paths is nothing to refuse"
                .to_owned(),
        ))
    }
}

/// Writes the `pre-commit` hook, for an installer to place.
///
/// Its own entry point as well as a [`Subject`], because printing it needs no store: a caller that
/// had to name a memory root to get a copy of a shell script would be a caller answering a question
/// the script itself is what answers.
pub fn print_hook(out: &mut dyn Write) -> Result<Exit> {
    emit(out, HOOK).map(|()| Exit::Ok)
}

/// Decides whether what `subject` names is safe to commit.
///
/// [`Exit::Ok`] only when every path was classified and none of them is anything a copy may not
/// contain. Every refusal has its own code, so a hook can say which kind it was without matching on
/// text: [`Exit::Rejected`] for a path the manifest excludes, [`Exit::Degraded`] for one beside the
/// store that no manifest entry classifies, [`Exit::Failed`] for one the guard could not resolve at
/// all, and [`Exit::Config`] for a store it could not locate.
pub fn guard_commit(paths: &Paths, subject: &Subject, out: &mut dyn Write) -> Result<Exit> {
    if matches!(subject, Subject::Hook) {
        return print_hook(out);
    }

    // Where a relative path is resolved from, and it differs by subject: git reports index paths
    // relative to the top of the work tree, and a `--path` means whatever the operator's shell did.
    let (tree, base, candidates) = match subject {
        Subject::Index(repo) => {
            let tree = work_tree(repo)?;
            let base = tree.said.clone();
            (Some(tree), base, indexed(repo)?)
        }
        Subject::Named(named) => (None, working_directory()?, named.clone()),
        Subject::Hook => unreachable!("printed above"),
    };

    let ground = Ground::new(paths, base)?;
    let mut report = GuardReport::default();
    if let Some(tree) = tree {
        report.standing = ground.standing(&tree);
        report.tree = Some(tree.said);
    }
    for candidate in candidates {
        let verdict = ground.classify(&candidate);
        report.findings.push((candidate, verdict));
    }
    ground.refuse_hardlinks(&mut report);

    let exit = report.exit();
    emit(out, &report.render(paths, exit))?;
    Ok(exit)
}

/// The store this guard reasons about, in the two readings every check needs.
struct Ground {
    /// Where a relative candidate path is resolved from.
    base: PathBuf,
    /// The memory root.
    root: Place,
    /// Every path a copy may not contain, with the manifest entry that says why.
    forbidden: Vec<(Place, &'static Entry)>,
}

impl Ground {
    /// Reads the deployment's excluded paths, refusing a store the filesystem will not resolve.
    ///
    /// A root that is not there yet is allowed through: nothing is under it, so nothing can be store
    /// content, and its spelling still places every path relative to it. A root that *is* there and
    /// cannot be resolved is a different matter — the identity half of every check below would
    /// quietly be missing, so it is a configuration failure instead of a clean run.
    fn new(paths: &Paths, base: PathBuf) -> Result<Self> {
        let root = Place::of(&base, &paths.root).map_err(|error| {
            config(format!(
                "--root {} cannot be resolved ({error}), so nothing could be checked against it",
                paths.root.display()
            ))
        })?;
        let mut forbidden = Vec::new();
        for (path, entry) in backup::excluded_paths(paths) {
            let place = Place::of(&base, &path).map_err(|error| {
                config(format!(
                    "`{}` cannot be resolved ({error}), and it is where `{}` is excluded",
                    path.display(),
                    entry.name
                ))
            })?;
            forbidden.push((place, entry));
        }
        Ok(Self {
            base,
            root,
            forbidden,
        })
    }

    /// What the manifest says about one candidate path.
    fn classify(&self, candidate: &Path) -> Verdict {
        let place = match Place::of(&self.base, candidate) {
            Ok(place) => place,
            Err(error) => {
                return Verdict::Opaque(format!("the filesystem would not resolve it: {error}"));
            }
        };

        // The exclusions first, and by either reading: a path that resolves inside the key store is
        // the key store however it is written, and one spelled inside it is refused even with no
        // file behind it to resolve.
        for (forbidden, entry) in &self.forbidden {
            if let Some(reach) = place.within(forbidden) {
                return Verdict::Excluded {
                    entry,
                    at: Some(forbidden.said.clone()),
                    reach,
                };
            }
        }

        // Outside the root no manifest entry governs it, and the repository is free to hold
        // whatever else it holds.
        let Some(name) = place.under(&self.root) else {
            return Verdict::Outside;
        };
        if place.real.is_none() {
            // Under the root and not in the tree, so its identity cannot be read — and identity is
            // the half that sees a symlink. An index entry with no file behind it is exactly how a
            // staged symlink into a key store would arrive looking like a record.
            return Verdict::Opaque(
                "it is under the memory root and not in the tree, so what it points at cannot be \
                 checked"
                    .to_owned(),
            );
        }
        match manifest_entry(&name) {
            Some(entry) if entry.disposition == Disposition::Included => Verdict::Included(entry),
            // Two readings of one manifest disagreed about where this entry is. Refuse rather than
            // pick one: whichever is right, the guard no longer knows which.
            Some(entry) => Verdict::Excluded {
                entry,
                at: None,
                reach: Reach::Spelling,
            },
            None => Verdict::Unclassified(name),
        }
    }

    /// Excluded entries that exist inside the work tree, whatever is staged today.
    ///
    /// The check that does not wait for the mistake. A key store inside a work tree is one
    /// `git add -f` from permanent, and an ignore rule is no mechanism against that: a flag
    /// overrides one, and a rule written today does not remove what was committed yesterday.
    ///
    /// Gated on existence, because the layout this protects keeps a *backup* under version control
    /// — and a backup's `keystore/` is a name with nothing behind it.
    fn standing(&self, tree: &Place) -> Vec<(PathBuf, &'static Entry)> {
        self.forbidden
            .iter()
            .filter(|(forbidden, _)| std::fs::symlink_metadata(&forbidden.said).is_ok())
            .filter(|(forbidden, _)| forbidden.within(tree).is_some())
            .map(|(forbidden, entry)| (forbidden.said.clone(), *entry))
            .collect()
    }

    /// Refuses any candidate that is a hardlink to a file inside an excluded entry.
    ///
    /// A hardlink has no path of its own to read, so both readings above see an ordinary file under
    /// `records/`. What it shares with the original is inode identity, which is the only thing left
    /// to compare.
    ///
    /// The excluded trees are walked only when some candidate is a file with more than one link,
    /// which is the cheap necessary condition: an ordinary commit pays one `stat` per path and never
    /// opens a directory.
    fn refuse_hardlinks(&self, report: &mut GuardReport) {
        let suspect: Vec<usize> = report
            .findings
            .iter()
            .enumerate()
            .filter(|(_, (path, verdict))| verdict.severity() == 0 && self.multiply_linked(path))
            .map(|(position, _)| position)
            .collect();
        if suspect.is_empty() {
            return;
        }
        let inodes = self.forbidden_inodes();
        for position in suspect {
            let (path, verdict) = &mut report.findings[position];
            let Ok(meta) = std::fs::symlink_metadata(self.base.join(&*path)) else {
                continue;
            };
            if let Some(entry) = inodes
                .iter()
                .find(|(id, _)| *id == (meta.dev(), meta.ino()))
                .map(|(_, entry)| *entry)
            {
                *verdict = Verdict::Excluded {
                    entry,
                    at: None,
                    reach: Reach::Inode,
                };
            }
        }
    }

    /// Whether a candidate is a file the filesystem holds under more than one name.
    fn multiply_linked(&self, candidate: &Path) -> bool {
        std::fs::symlink_metadata(self.base.join(candidate))
            .is_ok_and(|meta| meta.is_file() && meta.nlink() > 1)
    }

    /// Every file inside an excluded entry, by inode identity.
    fn forbidden_inodes(&self) -> Vec<((u64, u64), &'static Entry)> {
        let mut found = Vec::new();
        for (forbidden, entry) in &self.forbidden {
            let mut pending = vec![forbidden.said.clone()];
            while let Some(path) = pending.pop() {
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(&path) {
                        pending.extend(entries.flatten().map(|child| child.path()));
                    }
                } else if meta.is_file() {
                    found.push(((meta.dev(), meta.ino()), *entry));
                }
            }
        }
        found
    }
}

/// One manifest entry by name, or `None` when the manifest says nothing about it.
fn manifest_entry(name: &str) -> Option<&'static Entry> {
    backup::MANIFEST.iter().find(|entry| entry.name == name)
}

/// A path in both readings a check needs: what it says, and what the filesystem makes of it.
///
/// Two forms, because each sees what the other cannot. The spelling exists for a path with no file
/// behind it, and reduces `..` textually — which is *not* what the kernel does when the component
/// before it is a symlink. The identity is the kernel's own answer, and the only one that sees a
/// symlink or a relocated entry.
#[derive(Debug, Clone)]
struct Place {
    /// Absolute, with `.` and `..` reduced textually.
    said: PathBuf,
    /// The same place with every symlink followed, or `None` when nothing is there.
    real: Option<PathBuf>,
}

impl Place {
    /// Reads both forms of a path, or reports one the filesystem refuses to speak about.
    ///
    /// Absence is not a refusal: a path that is not there yet has a spelling and no identity, which
    /// is a fact rather than a failure. Anything else — a directory on the way that cannot be read,
    /// a resolution that will not terminate — is the filesystem declining to answer, and a caller
    /// has to treat that as not knowing.
    fn of(base: &Path, path: &Path) -> std::io::Result<Self> {
        let said = reduced(base, path);
        match std::fs::canonicalize(&said) {
            Ok(real) => Ok(Self {
                said,
                real: Some(real),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self { said, real: None })
            }
            Err(error) => Err(error),
        }
    }

    /// How this place is at or inside `outer`, or `None` when it is not.
    fn within(&self, outer: &Self) -> Option<Reach> {
        if self.said.starts_with(&outer.said) {
            return Some(Reach::Spelling);
        }
        match (&self.real, &outer.real) {
            (Some(mine), Some(theirs)) if mine.starts_with(theirs) => Some(Reach::Identity),
            _ => None,
        }
    }

    /// The first component of this place under `outer`, or `None` when it is not inside it.
    ///
    /// Identity first, because a symlink's spelling says where it is written and not what it is. The
    /// spelling still answers for a place with no identity to read.
    fn under(&self, outer: &Self) -> Option<String> {
        if let (Some(mine), Some(theirs)) = (&self.real, &outer.real)
            && let Some(name) = first_under(theirs, mine)
        {
            return Some(name);
        }
        first_under(&outer.said, &self.said)
    }
}

/// The first path component of `path` below `root`, or `None` when `path` is not below it.
fn first_under(root: &Path, path: &Path) -> Option<String> {
    let rest = path.strip_prefix(root).ok()?;
    let first = rest.components().next()?;
    Some(first.as_os_str().to_string_lossy().into_owned())
}

/// A path made absolute and textually reduced, without asking the filesystem anything.
fn reduced(base: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The directory a `--path` is resolved against.
fn working_directory() -> Result<PathBuf> {
    std::env::current_dir().map_err(|error| {
        failed(
            "reading the working directory to resolve paths against",
            &error,
        )
    })
}

/// The top level of a repository's work tree, as `git` reports it.
fn work_tree(repo: &Path) -> Result<Place> {
    let out = git(
        repo,
        &["rev-parse", "--show-toplevel"],
        "finding the work tree",
    )?;
    let top = String::from_utf8_lossy(&out).trim().to_owned();
    if top.is_empty() {
        return Err(failed(
            "finding the work tree",
            &format!("`{}` has no work tree", repo.display()),
        ));
    }
    Place::of(Path::new("/"), Path::new(&top))
        .map_err(|error| failed("resolving the work tree", &error))
}

/// Every path in a repository's index, as `git` itself reports them.
///
/// The index and not the staged diff, because the index is what the commit will contain: a key file
/// added before this hook existed is then refused by every commit after it rather than by none.
/// `-z`, because a path is bytes and a newline is a legal one.
fn indexed(repo: &Path) -> Result<Vec<PathBuf>> {
    let out = git(
        repo,
        &["ls-files", "--cached", "--full-name", "-z"],
        "asking git what this commit would contain",
    )?;
    Ok(out
        .split(|byte| *byte == 0)
        .filter(|slice| !slice.is_empty())
        .map(|slice| PathBuf::from(OsStr::from_bytes(slice)))
        .collect())
}

/// Runs `git` in a repository and returns its output, or the failure that is not knowing.
///
/// A `git` that could not be run, or that ran and failed, leaves the guard with no list of paths —
/// which is the one thing it must never read as an empty one.
fn git(repo: &Path, args: &[&str], doing: &'static str) -> Result<Vec<u8>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|error| failed(doing, &error))?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(failed(doing, &said));
    }
    Ok(out.stdout)
}

/// How a path was found to be something no copy may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Its spelling says so, with `.` and `..` reduced.
    Spelling,
    /// The filesystem says so whatever it is spelled: a symlink, or an entry this deployment
    /// relocated.
    Identity,
    /// It is the same file, by inode: a hardlink, which has no path to read.
    Inode,
}

impl Reach {
    /// How an operator should read the match.
    fn why(self) -> &'static str {
        match self {
            Self::Spelling => "matched by its spelling",
            Self::Identity => {
                "matched by identity: it resolves there whatever it is spelled — a symlink, or an \
                 entry this deployment relocated"
            }
            Self::Inode => {
                "matched by inode: it is a hardlink to a file inside it, and shares that file's \
                 bytes for ever"
            }
        }
    }
}

/// What the guard decided about one path.
#[derive(Debug)]
enum Verdict {
    /// Outside the memory root, so no manifest entry governs it.
    Outside,
    /// Under an entry a backup copies. Safe: this is what the repository is for.
    Included(&'static Entry),
    /// Under an entry no copy may contain.
    Excluded {
        /// The manifest entry, which carries the reason.
        entry: &'static Entry,
        /// Where that entry is for this deployment, when a path is what matched.
        at: Option<PathBuf>,
        /// Which reading found it.
        reach: Reach,
    },
    /// Under the root, and the manifest classifies nothing it is under.
    Unclassified(String),
    /// The guard could not decide, and says why.
    Opaque(String),
}

impl Verdict {
    /// The exit this verdict alone would produce.
    fn exit(&self) -> Exit {
        match self {
            Self::Outside | Self::Included(_) => Exit::Ok,
            Self::Excluded { .. } => Exit::Rejected,
            Self::Unclassified(_) => Exit::Degraded,
            Self::Opaque(_) => Exit::Failed,
        }
    }

    /// How serious this is, so a report ends on the worst thing it found.
    fn severity(&self) -> u8 {
        match self {
            Self::Outside | Self::Included(_) => 0,
            Self::Unclassified(_) => 1,
            Self::Opaque(_) => 2,
            Self::Excluded { .. } => 3,
        }
    }
}

/// What the guard found, path by path.
#[derive(Debug, Default)]
struct GuardReport {
    /// One verdict per path examined, in the order they were given.
    findings: Vec<(PathBuf, Verdict)>,
    /// Excluded entries that exist inside the work tree, whatever is staged.
    standing: Vec<(PathBuf, &'static Entry)>,
    /// The top of the work tree, when there was one.
    tree: Option<PathBuf>,
}

impl GuardReport {
    /// The worst outcome in the report.
    fn exit(&self) -> Exit {
        if !self.standing.is_empty() {
            return Exit::Rejected;
        }
        self.findings
            .iter()
            .max_by_key(|(_, verdict)| verdict.severity())
            .map_or(Exit::Ok, |(_, verdict)| verdict.exit())
    }

    /// The report as an operator reads it.
    ///
    /// Every refusal names the path, the entry it fell under, and that entry's own reason from the
    /// manifest — because the operator's next question is what to do about it, and the reason is the
    /// answer. What was allowed is counted too: a guard that refused everything would otherwise
    /// look exactly like one that was working.
    fn render(&self, paths: &Paths, exit: Exit) -> String {
        let mut text = if exit.is_success() {
            "guard-commit: safe to commit\n".to_owned()
        } else {
            "guard-commit: refused\n".to_owned()
        };
        let _ = writeln!(text, "store  {}", paths.root.display());
        if let Some(tree) = &self.tree {
            let _ = writeln!(text, "repo   {}", tree.display());
        }
        self.describe_standing(&mut text);
        self.describe_refusals(&mut text);
        self.describe_allowed(&mut text);
        if !exit.is_success() {
            text.push_str(
                "nothing was committed. Take each refused path out of the index and try again:\n  \
                 git rm --cached -- <path>\n",
            );
        }
        text
    }

    /// The refusals that are about the deployment rather than about a staged path.
    fn describe_standing(&self, text: &mut String) {
        for (path, entry) in &self.standing {
            let _ = writeln!(text, "\n{} is inside this work tree", path.display());
            let _ = writeln!(text, "  manifest: `{}` — {}", entry.name, entry.reason);
            let _ = writeln!(
                text,
                "  an ignore rule is not a mechanism here: `git add -f` overrides one, and a rule \
                 written today does not remove what was committed yesterday. Move it out of the \
                 work tree"
            );
        }
    }

    /// One paragraph per refused path.
    fn describe_refusals(&self, text: &mut String) {
        for (path, verdict) in &self.findings {
            if verdict.severity() == 0 {
                continue;
            }
            let _ = writeln!(text, "\n{}", path.display());
            match verdict {
                Verdict::Outside | Verdict::Included(_) => unreachable!("counted above"),
                Verdict::Excluded { entry, at, reach } => {
                    let _ = writeln!(text, "  refused: it is `{}`", entry.name);
                    if let Some(at) = at {
                        let _ = writeln!(text, "  which this deployment keeps at {}", at.display());
                    }
                    let _ = writeln!(text, "  {}", reach.why());
                    let _ = writeln!(text, "  manifest: {}", entry.reason);
                }
                Verdict::Unclassified(name) => {
                    let _ = writeln!(
                        text,
                        "  refused: `{name}` sits under the memory root and no manifest entry \
                         classifies it. Either it belongs in the manifest or it belongs outside the \
                         store — a keyring or an unsealing key parked there is exactly what a check \
                         that guessed would wave through"
                    );
                }
                Verdict::Opaque(why) => {
                    let _ = writeln!(
                        text,
                        "  refused: {why}. A guard that cannot say what a path is does not allow it"
                    );
                }
            }
        }
    }

    /// A tally of the paths that were fine, by the manifest entry each fell under.
    ///
    /// Printed on a refusal too. A guard that refused everything would otherwise be
    /// indistinguishable from one that was working, and this is the line that tells them apart.
    fn describe_allowed(&self, text: &mut String) {
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, verdict) in &self.findings {
            match verdict {
                Verdict::Included(entry) => *tally.entry(entry.name).or_default() += 1,
                Verdict::Outside => *tally.entry(OUTSIDE).or_default() += 1,
                Verdict::Excluded { .. } | Verdict::Unclassified(_) | Verdict::Opaque(_) => {}
            }
        }
        let safe: usize = tally.values().sum();
        let _ = writeln!(
            text,
            "\n{safe} of {} path(s) are safe to commit",
            self.findings.len()
        );
        for (name, count) in tally {
            let _ = writeln!(text, "  {name:<20}{count}");
        }
    }
}

/// How a path outside the memory root is tallied: not store content, and governed by no entry.
const OUTSIDE: &str = "(not store content)";

/// Writes a report, turning a broken pipe into a failure that names itself.
fn emit(out: &mut dyn Write, text: &str) -> Result<()> {
    out.write_all(text.as_bytes())
        .map_err(|error| failed("writing the report", &error))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use yaam_core::Paths;
    use yaam_core::backup;

    use super::{Ground, HOOK, Place, Subject, guard_commit};
    use crate::exit::Exit;

    /// A repository holding a store's backup, with the store in a subdirectory.
    ///
    /// A subdirectory because that is the layout this guard is for: everything beside it — a readme,
    /// the hook itself — is then outside the memory root and is nobody's business here. A store at
    /// the top level of a repository leaves no such place, and the guard says so by refusing every
    /// unclassified file it finds there.
    struct Repo {
        dir: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().expect("temp dir");
            fs::create_dir_all(dir.path().join("store/spec")).expect("spec");
            fs::create_dir_all(dir.path().join("store/records/2026/08/20")).expect("records");
            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().join("store")
        }

        fn paths(&self) -> Paths {
            Paths::under(self.root())
        }

        /// Writes a file under the repository and returns its path.
        fn file(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.dir.path().join(relative);
            fs::create_dir_all(path.parent().expect("a parent")).expect("parent");
            fs::write(&path, contents).expect("write");
            path
        }
    }

    /// Runs the guard over named paths and returns its exit and what it printed.
    fn decide(paths: &Paths, named: &[PathBuf]) -> (Exit, String) {
        let subject = Subject::from_flags(None, named, false).expect("a subject");
        let mut out = Vec::new();
        let exit = guard_commit(paths, &subject, &mut out).expect("a decision");
        (exit, String::from_utf8_lossy(&out).into_owned())
    }

    /// The case the whole thing exists for, and the reason the manifest's own sentence has to be in
    /// the refusal: the operator's next question is what to do about it.
    #[test]
    fn a_key_file_is_refused_and_the_manifest_says_why() {
        let repo = Repo::new();
        let key = repo.file("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
        let (exit, said) = decide(&repo.paths(), &[key]);
        assert_eq!(exit, Exit::Rejected, "{said}");
        assert!(said.contains("it is `keystore`"), "{said}");
        assert!(
            said.contains("Erasure is key destruction"),
            "the refusal has to carry the manifest's reason: {said}"
        );
    }

    /// The assertion that keeps every other one honest. A guard that refused everything would pass
    /// all the refusal tests here.
    #[test]
    fn records_and_spec_alone_are_allowed() {
        let repo = Repo::new();
        let record = repo.file("store/records/2026/08/20/one.md", "---\n---\nprose\n");
        let spec = repo.file("store/spec/entities.yaml", "kinds: []\n");
        let tombstones = repo.file("store/tombstones.jsonl", "");
        let beside = repo.file("readme.md", "a repository holding a backup\n");
        let (exit, said) = decide(&repo.paths(), &[record, spec, tombstones, beside]);
        assert_eq!(exit, Exit::Ok, "{said}");
        assert!(said.contains("safe to commit"), "{said}");
        assert!(said.contains("4 of 4 path(s) are safe"), "{said}");
        assert!(said.contains("records             1"), "{said}");
    }

    /// Every exclusion, one file each, over the list itself. A newly excluded entry is covered by
    /// this the moment it is declared, which is the property that keeps the manifest the only list.
    #[test]
    fn every_excluded_entry_refuses_a_file_under_it() {
        let repo = Repo::new();
        let paths = repo.paths();
        for (path, entry) in backup::excluded_paths(&paths) {
            // A file inside it for a directory entry and the entry itself for a file one. Which it
            // is follows from the manifest name, so this needs no list of its own either.
            let candidate = if Path::new(entry.name).extension().is_some() {
                path.clone()
            } else {
                path.join("something")
            };
            fs::create_dir_all(candidate.parent().expect("a parent")).expect("parent");
            fs::write(&candidate, "contents").expect("write");
            let (exit, said) = decide(&paths, &[candidate]);
            assert_eq!(
                exit,
                Exit::Rejected,
                "`{}` is excluded and was not refused: {said}",
                entry.name
            );
            assert!(
                said.contains(entry.reason),
                "the refusal of `{}` carried no reason: {said}",
                entry.name
            );
        }
    }

    /// A key store relocated into an entry a backup copies. Its spelling says `records/`, which a
    /// check reading the spelling alone would call the authoritative half and wave through.
    #[test]
    fn a_key_store_relocated_inside_records_is_refused() {
        let repo = Repo::new();
        let paths = repo
            .paths()
            .with_key_store(repo.root().join("records/keys"));
        let key = repo.file("store/records/keys/s_aa/epoch-1.key", "not a real key");
        let (exit, said) = decide(&paths, &[key]);
        assert_eq!(exit, Exit::Rejected, "{said}");
        assert!(said.contains("it is `keystore`"), "{said}");
        assert!(said.contains("records/keys"), "{said}");
    }

    /// A path spelled inside a relocated key store, with nothing in the tree behind it. Identity
    /// has nothing to read and the placement under the root says `records/`, so its spelling is the
    /// only reading that sees what it is — and that is what a key file staged and then deleted from
    /// the work tree looks like on the next commit.
    #[test]
    fn a_path_spelled_inside_a_relocated_key_store_is_refused_with_nothing_behind_it() {
        let repo = Repo::new();
        let paths = repo
            .paths()
            .with_key_store(repo.root().join("records/keys"));
        let absent = repo.root().join("records/keys/s_aa/epoch-1.key");
        let (exit, said) = decide(&paths, &[absent]);
        assert_eq!(exit, Exit::Rejected, "{said}");
        assert!(said.contains("matched by its spelling"), "{said}");
    }

    /// A symlink into a key store, written where a record belongs. Its spelling is `records/`; only
    /// the filesystem knows what it is.
    #[test]
    fn a_symlink_pointing_at_a_key_store_is_refused() {
        let repo = Repo::new();
        repo.file("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
        let link = repo
            .root()
            .join("records/2026/08/20/looks-like-a-record.md");
        std::os::unix::fs::symlink(
            repo.root().join("keystore/subjects/s_aa/epoch-1.key"),
            &link,
        )
        .expect("symlink");
        let (exit, said) = decide(&repo.paths(), &[link]);
        assert_eq!(exit, Exit::Rejected, "{said}");
        assert!(said.contains("matched by identity"), "{said}");
    }

    /// The same place reached by `..`, which a check comparing the string it was handed would miss.
    #[test]
    fn a_key_store_reached_by_dot_dot_is_refused() {
        let repo = Repo::new();
        repo.file("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
        let sneaked = repo
            .root()
            .join("records/../keystore/subjects/s_aa/epoch-1.key");
        let (exit, said) = decide(&repo.paths(), &[sneaked]);
        assert_eq!(exit, Exit::Rejected, "{said}");
    }

    /// A hardlink shares the original's bytes and has no path that says so.
    #[test]
    fn a_hardlink_to_a_key_file_is_refused() {
        let repo = Repo::new();
        let key = repo.file("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
        let twin = repo.root().join("records/2026/08/20/twin.md");
        fs::hard_link(&key, &twin).expect("hard link");
        let (exit, said) = decide(&repo.paths(), &[twin]);
        assert_eq!(exit, Exit::Rejected, "{said}");
        assert!(said.contains("matched by inode"), "{said}");
    }

    /// A path under the root with nothing behind it. Its identity cannot be read, and identity is
    /// the half that sees a symlink — so this is the guard not knowing, and it does not allow.
    #[test]
    fn a_path_under_the_root_that_is_not_in_the_tree_is_refused() {
        let repo = Repo::new();
        let absent = repo.root().join("records/2026/08/20/gone.md");
        let (exit, said) = decide(&repo.paths(), &[absent]);
        assert_eq!(exit, Exit::Failed, "{said}");
        assert!(said.contains("not in the tree"), "{said}");
    }

    /// The same absence outside the root is a fact and not a failure: nothing there can be store
    /// content, whatever appears later.
    #[test]
    fn an_absent_path_outside_the_root_is_not_store_content() {
        let repo = Repo::new();
        let outside = repo.dir.path().join("notes/whatever.md");
        let (exit, said) = decide(&repo.paths(), &[outside]);
        assert_eq!(exit, Exit::Ok, "{said}");
    }

    /// A file beside the store that no manifest entry classifies. Its own code, because the remedy
    /// differs: a key store is never committed, and this is a decision somebody has to make.
    #[test]
    fn a_file_beside_the_store_in_no_manifest_is_refused() {
        let repo = Repo::new();
        let keyring = repo.file("store/keyring.json", "{}");
        let (exit, said) = decide(&repo.paths(), &[keyring]);
        assert_eq!(exit, Exit::Degraded, "{said}");
        assert!(said.contains("no manifest entry"), "{said}");
    }

    /// A directory on the way that cannot be read. Skipped when the process can read it anyway,
    /// which is what a test run as root does — the case is real and mode bits are not the mechanism
    /// there.
    #[test]
    fn a_path_the_filesystem_will_not_resolve_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let repo = Repo::new();
        let hidden = repo.file("store/records/2026/08/20/shut/one.md", "prose");
        let shut = hidden.parent().expect("a parent").to_owned();
        fs::set_permissions(&shut, fs::Permissions::from_mode(0o000)).expect("chmod");
        let decided = fs::read_dir(&shut)
            .is_err()
            .then(|| decide(&repo.paths(), &[hidden]));
        // Restored before asserting, so a failing assertion does not leave a directory the harness
        // cannot clean up.
        fs::set_permissions(&shut, fs::Permissions::from_mode(0o755)).expect("chmod back");
        if let Some((exit, said)) = decided {
            assert_eq!(exit, Exit::Failed, "{said}");
            assert!(said.contains("would not resolve it"), "{said}");
        }
    }

    /// A key store that is simply *there* inside the work tree, with nothing staged from it. Its
    /// being there is the hazard, and waiting for the mistake is what this refuses to do.
    #[test]
    fn a_key_store_inside_the_work_tree_is_refused_with_nothing_staged() {
        let repo = Repo::new();
        repo.file("store/keystore/subjects/s_aa/epoch-1.key", "not a real key");
        let tree = Place::of(Path::new("/"), repo.dir.path()).expect("a place");
        let ground =
            Ground::new(&repo.paths(), repo.dir.path().to_owned()).expect("a resolvable store");
        let standing = ground.standing(&tree);
        assert_eq!(standing.len(), 1, "{standing:?}");
        assert_eq!(standing[0].1.name, "keystore");
    }

    /// Naming nothing is a usage error and never an empty allow. This gets a test of its own
    /// because it is the shape of the failure: a guard handed no work reports success over
    /// everything it did not look at.
    #[test]
    fn a_subject_has_to_be_named() {
        let error = Subject::from_flags(None, &[], false).expect_err("nothing was named");
        assert_eq!(error.exit(), Exit::Usage, "{error}");
        assert!(error.to_string().contains("nothing to refuse"), "{error}");

        let both = Subject::from_flags(
            Some(Path::new("/")),
            std::slice::from_ref(&PathBuf::from("x")),
            false,
        )
        .expect_err("two subjects");
        assert_eq!(both.exit(), Exit::Usage, "{both}");

        assert_eq!(
            Subject::from_flags(None, &[], true).expect("the hook"),
            Subject::Hook
        );
        assert_eq!(
            Subject::from_flags(Some(Path::new("/")), &[], false).expect("an index"),
            Subject::Index(PathBuf::from("/"))
        );
    }

    /// The hook is printed and nothing is decided, so an installer has one copy of the text to
    /// compare an installed hook against.
    #[test]
    fn the_hook_is_printed_verbatim() {
        let repo = Repo::new();
        let mut out = Vec::new();
        let exit = guard_commit(&repo.paths(), &Subject::Hook, &mut out).expect("printed");
        assert_eq!(exit, Exit::Ok);
        assert_eq!(String::from_utf8_lossy(&out), HOOK);
        assert!(HOOK.starts_with("#!"), "a hook needs an interpreter line");
        assert!(
            HOOK.contains("guard-commit --repo"),
            "the hook has to call the guard: {HOOK}"
        );
    }

    /// A store the guard cannot resolve is a configuration failure, not a clean run over nothing.
    #[test]
    fn an_unresolvable_root_is_a_config_failure() {
        let repo = Repo::new();
        let file = repo.file("store/spec/entities.yaml", "kinds: []\n");
        // A file where a directory belongs: canonicalising a path *through* one is not `NotFound`.
        let paths = Paths::under(repo.root().join("spec/entities.yaml/below"));
        let subject =
            Subject::from_flags(None, std::slice::from_ref(&file), false).expect("a subject");
        let mut out = Vec::new();
        let error = guard_commit(&paths, &subject, &mut out).expect_err("no decision");
        assert_eq!(error.exit(), Exit::Config, "{error}");
    }
}
