//! Copying a store, and the manifest that decides what a copy may contain.
//!
//! # Why this is a manifest and not a function
//!
//! Erasure here is key destruction: a record's ciphertext may outlive the request, but without its
//! key nothing can read it again ([`crate::erase`]). That holds in every copy — cold archives, old
//! snapshots, last night's backup — for exactly one reason: **no copy contains the key store.** A
//! backup that picked the key store up would restore keys along with ciphertext, and the restored
//! store would answer questions a data subject had already had answered by their erasure. Worse, it
//! would do so while [`crate::erase::confirm_erasure`] still passed, because that checks the live
//! key root and cannot see a tarball.
//!
//! So the exclusion list is not an implementation detail of a copy routine. It is the argument the
//! erasure guarantee rests on, and it is written here as data — [`MANIFEST`] — so that it can be
//! read by an operator, asserted over by a test, and extended in one place. A new excluded
//! directory becomes covered by the drill below by being added to the list, not by somebody
//! remembering to write a second test.
//!
//! # What travels
//!
//! The authoritative half and the configuration it is read under. Everything derived is left
//! behind and rebuilt: [`restore`] ends in [`crate::reindex::reindex_all`], which is not a
//! convenience but a requirement — restored files can carry modification times older than the
//! sweeper's own bound, and a rebuild is also what replays the tombstone log so that a backup
//! predating an erasure cannot re-index the structure that erasure removed.
//!
//! `subject-key-check.json` travels for a reason worth separating from the rest: it is not content
//! but a check on the key that produced content. A restore installs a tree full of pseudonyms and
//! then wants a key entered by hand, which is the moment a wrong one is most likely and its
//! consequence — a second pseudonym space, unrelatable for ever — least reversible. See
//! [`crate::arming`].
//!
//! `audit/` is the one derived thing that travels anyway, and its entry says why: reproducing it
//! needs a drain to run, and an account of which records named which subjects is not worth
//! betting on one.
//!
//! # What does not, and why each one
//!
//! Every exclusion carries its reason in [`Entry::reason`], stated where the exclusion is made
//! rather than in a runbook nobody reads at the moment of restoring.
//!
//! `entities/` is on that list and used not to be. Its reason for travelling was that a rebuild did
//! not reproduce a materialised timeline — true while an append decided for itself whether it had
//! already happened, and false now that the index records each line and a rebuild drops the files
//! and those rows together. A copy of them would be deleted by the rebuild [`restore`] ends in,
//! which is a copy worth nothing and a promise worth less.
//!
//! One exclusion is worth reading twice: nothing beside the key store has to travel either. Key
//! material wrapped at rest is self-describing — [`yaam_crypto::wrapper`] puts the salt and the
//! cost parameters in the blob — precisely so that recovery needs a passphrase and the blob, and
//! not a parameters file kept next to the keys. A salt file beside a key store is the thing a
//! backup drops by accident, and this manifest has no line for one because there is nothing to
//! name.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Paths, Pipeline, Result, fsutil, layout};

/// Name of the manifest written into a backup, beside what it copied.
///
/// A copy of a store is otherwise indistinguishable from a directory that happens to contain one,
/// and [`restore`] refuses to read a directory that does not say what it is.
pub const MANIFEST_FILE: &str = "backup-manifest.json";

/// Format version of [`MANIFEST_FILE`].
const MANIFEST_VERSION: u32 = 1;

/// Whether an entry of the store's layout belongs in a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Copied by [`back_up`] and restored by [`restore`].
    Included,
    /// Never copied, and refused on the way back in.
    Excluded,
}

/// One entry directly under the memory root, and what a backup does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Name of the entry, relative to the memory root.
    pub name: &'static str,
    /// What a backup does with it.
    pub disposition: Disposition,
    /// Why it is treated that way.
    ///
    /// Part of the interface rather than a comment: an operator asked to trust that a directory was
    /// left out of their disaster recovery is owed the argument at the point where it is left out.
    pub reason: &'static str,
}

/// What a backup may contain, and what it must not.
///
/// Declarative on purpose. The three properties this file claims — that the authoritative half
/// travels, that the key store never does, and that a restored store is queryable — are each
/// asserted by walking this list, so a later entry is covered by the existing tests instead of
/// needing new ones.
pub const MANIFEST: &[Entry] = &[
    Entry {
        name: layout::SPEC_DIR,
        disposition: Disposition::Included,
        reason: "configuration the tree is read under: entity kinds, the attribute surface, the \
                 redaction policy. A restored tree whose spec did not travel is a store that \
                 rejects the records it already holds",
    },
    Entry {
        name: layout::RECORDS_DIR,
        disposition: Disposition::Included,
        reason: "the authoritative half. Every indexed row is derived from these files, so this is \
                 the one entry whose loss is not recoverable from anything else",
    },
    Entry {
        name: layout::COLD_DIR,
        disposition: Disposition::Included,
        reason: "manifests of archived records. Their record files are gone from the tree, so a \
                 manifest is the last local copy of what they held",
    },
    Entry {
        name: layout::AUDIT_DIR,
        disposition: Disposition::Included,
        reason: "the subject-to-record linkage: which records named which subjects, in which role. \
                 The most legally interesting residue an erasure leaves standing — retained by \
                 design rather than erased, which is also what makes carrying it safe, since it \
                 resurrects nothing an erasure destroyed — and whether it is retained is a \
                 documented decision somebody owns, not this routine's to take. A drain does \
                 reproduce it, archived records included, but only if `cold/` travelled too and \
                 only if a drain actually runs: an audit trail is not worth betting on either",
    },
    Entry {
        name: layout::TOMBSTONE_LOG,
        disposition: Disposition::Included,
        reason: "the erasure log, and it travels *because* a restore replays it. Without it a \
                 backup taken before an erasure re-indexes the structure that erasure removed",
    },
    Entry {
        name: layout::SUBJECT_CHECK_FILE,
        disposition: Disposition::Included,
        reason: "which subject key the tree's pseudonyms were derived from, as a check value that \
                 is not the key. It travels because the pseudonyms do: a restored tree armed with \
                 a different subject key would file a second, unrelatable pseudonym for every \
                 subject already in it, and re-entering a key by hand is exactly what a restore \
                 involves. Safe to carry for the reason the key store is not — a fixed-label HMAC \
                 names the key without revealing it, and resurrects nothing an erasure destroyed",
    },
    Entry {
        name: layout::SUBJECT_CHECK_TEMP,
        disposition: Disposition::Excluded,
        reason: "half a check value, from an arming interrupted between the write and the rename. \
                 Named rather than left unclassified so a crash cannot make every later backup \
                 report a file nobody decided about; the value it was becoming is what travels",
    },
    Entry {
        name: layout::KEYSTORE_DIR,
        disposition: Disposition::Excluded,
        reason: "the key store. Erasure is key destruction, so a key surviving in a copy makes the \
                 destruction a fiction while live verification still passes — this exclusion is \
                 what the whole erasure guarantee rests on",
    },
    Entry {
        name: layout::QUARANTINE_DIR,
        disposition: Disposition::Excluded,
        reason: "sealed copies of records whose subjects have not resolved. Their key is still \
                 live and still recoverable, so a copy of one is a recoverable body; governed \
                 exactly like the key store",
    },
    Entry {
        name: layout::STAGING_DIR,
        disposition: Disposition::Excluded,
        reason: "write-ahead copies of records that were never published. Restoring one would \
                 publish a record this store never accepted, and the sweeper that would have \
                 settled it is not running in a backup",
    },
    Entry {
        name: layout::DEAD_LETTER_DIR,
        disposition: Disposition::Excluded,
        reason: "copies set aside for an operator to look at. Unpublished, unindexed, and pointing \
                 at a failure that belongs to the store they came from",
    },
    Entry {
        name: layout::ENTITIES_DIR,
        disposition: Disposition::Excluded,
        reason: "materialised timelines, and derived after all: a rebuild removes them and the \
                 index rows that account for their lines together, so a copy carried here would be \
                 deleted by the rebuild a restore ends in. Fan-out writes them again from the tree",
    },
    Entry {
        name: layout::KNOWLEDGE_DIR,
        disposition: Disposition::Excluded,
        reason: "notes derived from record structure, reproduced wholesale from the record tree by \
                 `yaam knowledge build`. Unlike a timeline its absence announces itself — `yaam \
                 knowledge status` reports that no build has completed — so a restore is not left \
                 owing a rebuild nobody can see is missing. Carrying a copy would also carry facts \
                 aggregated out of records the restored tree no longer holds",
    },
    Entry {
        name: layout::INDEX_FILE,
        disposition: Disposition::Excluded,
        reason: "derived, and disposable by design. A restore rebuilds it, which is cheaper than \
                 the alternative: copying a database from under its own write-ahead log is how a \
                 backup acquires a torn one",
    },
    // The two files the write-ahead journal keeps beside the index. Named rather than matched by
    // prefix, so an unclassified entry stays a real signal instead of appearing on every backup of
    // a store whose writer has run.
    Entry {
        name: "index.sqlite-wal",
        disposition: Disposition::Excluded,
        reason: "the index's write-ahead log, and meaningless without the index it belongs to",
    },
    Entry {
        name: "index.sqlite-shm",
        disposition: Disposition::Excluded,
        reason: "the index's shared-memory file: live coordination state, not content",
    },
];

/// What a backup copied, and what it deliberately did not.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackupReport {
    /// Files copied.
    pub files: usize,
    /// Bytes copied.
    pub bytes: u64,
    /// Excluded entries that were present and were left behind. Reported so an operator sees the
    /// exclusion happening rather than trusting that it did.
    pub excluded: Vec<String>,
    /// Entries under the root that [`MANIFEST`] does not classify.
    ///
    /// Left behind and named, which is the only safe way round: silently copying an unknown file
    /// would sweep up whatever a deployment parked beside its store — a keyring, an unsealing key —
    /// and silently dropping one without saying so would lose data nobody knew was in scope.
    pub unclassified: Vec<String>,
}

/// What a restore put back.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Files copied in.
    pub files: usize,
    /// Records the mandatory rebuild indexed, from the tree and from cold manifests.
    pub records_indexed: usize,
    /// Erasures the rebuild replayed out of the restored tombstone log.
    pub erasures_replayed: usize,
    /// What reconciling the destination's key store against the restored log found.
    ///
    /// Ordinarily all zeroes, because a restore installs no key material. It is not always zero, and
    /// the case where it is not is the one worth having: a destination whose key store was recovered
    /// *before* the tree, which is one of the two orders an operator can do a disaster recovery in.
    pub keys_reconciled: crate::restore::Reconciliation,
}

/// Every entry a backup copies.
pub fn included() -> impl Iterator<Item = &'static Entry> {
    MANIFEST
        .iter()
        .filter(|entry| entry.disposition == Disposition::Included)
}

/// Every entry a backup must never contain.
pub fn excluded() -> impl Iterator<Item = &'static Entry> {
    MANIFEST
        .iter()
        .filter(|entry| entry.disposition == Disposition::Excluded)
}

/// What the manifest says about one entry under the root, or `None` when it says nothing.
#[must_use]
pub fn disposition_of(name: &str) -> Option<Disposition> {
    MANIFEST
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.disposition)
}

/// Every path a copy of this deployment must never contain, each with the entry that says why.
///
/// The manifest names entries *under the root*, and two of them are relocatable
/// ([`Paths::with_key_store`], [`Paths::with_index`]) — so "the key store is excluded" is a claim
/// about a path and not about a spelling. That is the reasoning
/// [`refuse_excluded_inside_included`] applies to a backup destination; this is the same reasoning
/// offered to anything else that has to decide whether a path is one of these, a guard over a
/// version-controlled copy included.
///
/// Derived from [`MANIFEST`] rather than listed again, because a second list is how one of these
/// stops being protected: a newly excluded entry is covered by every caller of this the moment it
/// is declared.
#[must_use]
pub fn excluded_paths(paths: &Paths) -> Vec<(PathBuf, &'static Entry)> {
    excluded()
        .map(|entry| (resolved(paths, entry), entry))
        .collect()
}

/// Where one excluded entry actually sits for this deployment.
///
/// The journal files are matched by the suffix they add to [`layout::INDEX_FILE`] rather than by
/// their own names, so a relocated index takes them with it — and an entry added for a third
/// journal file needs nothing here.
fn resolved(paths: &Paths, entry: &Entry) -> PathBuf {
    if entry.name == layout::KEYSTORE_DIR {
        return paths.key_store.clone();
    }
    if let Some(suffix) = entry.name.strip_prefix(layout::INDEX_FILE) {
        let mut path = paths.index.clone().into_os_string();
        path.push(suffix);
        return PathBuf::from(path);
    }
    paths.root.join(entry.name)
}

/// Copies the store's authoritative half into `into`.
///
/// Refuses rather than merges: a directory already holding something is left alone, because two
/// backups in one directory cannot be told apart afterwards and a restore would mix them.
///
/// Modification times are not preserved, which is deliberate. The sweeper's scan is bounded by
/// modification time, so a faithfully dated restore can leave records permanently unswept — and the
/// rebuild [`restore`] runs is what covers it either way.
pub fn back_up(pipeline: &Pipeline, into: &Path) -> Result<BackupReport> {
    let root = pipeline.root();
    refuse_occupied(into)?;
    refuse_destination_inside(root, into)?;
    refuse_excluded_inside_included(pipeline.paths())?;

    let mut report = BackupReport::default();
    // Owner-only, like the store it copies: a backup of a tree holding owner-visible records is as
    // sensitive as the tree.
    fsutil::create_private_dir_all(into)?;
    for entry in included() {
        let from = root.join(entry.name);
        if from.exists() {
            copy_tree(
                &from,
                &into.join(entry.name),
                &mut report.files,
                &mut report.bytes,
            )?;
        }
    }
    for entry in excluded() {
        if root.join(entry.name).exists() {
            report.excluded.push(entry.name.to_owned());
        }
    }
    report.unclassified = unclassified(root)?;
    write_manifest(into)?;
    Ok(report)
}

/// Restores a backup into `paths`, then rebuilds the index.
///
/// Takes paths rather than an open store, and opens one itself once the files are in place. That
/// ordering is the point: a store reads its `spec/` at open, and the `spec/` a restore installs is
/// the backup's — so a pipeline opened first would spend the rest of its life holding the
/// configuration of the empty directory it started as.
///
/// The rebuild is part of the operation rather than a step in a runbook, because a restore without
/// one is a store answering from a stale index over a tombstone log nothing has replayed. It needs
/// no key material and mints none — a rebuild reads the shares the tree already carries — so the
/// store it opens here is deliberately plain, whatever wrapper the deployment fits afterwards.
///
/// What gets copied is decided by [`MANIFEST`] in this build, never by the manifest file in the
/// backup: reading the list out of the backup would let a hand-assembled directory nominate the key
/// store for restoration. The file is read only to confirm the directory is a backup at all, and
/// one this build understands.
///
/// It ends in [`crate::restore::reconcile`] as well as in a rebuild, and the two are not the same
/// pass. The rebuild replays the *tree's* log, which is what stops restored records re-indexing
/// erased structure. The reconcile holds the *key store* to that same log and to its own blocklist,
/// which is what stops a key store recovered before the tree from outliving the erasure the tree has
/// just told it about. Running it here makes the order of a recovery stop mattering: whichever half
/// is put back second reconciles the pair.
pub fn restore(paths: &Paths, from: &Path) -> Result<RestoreReport> {
    read_manifest(from)?;
    refuse_excluded_present(from)?;
    refuse_occupied_store(&paths.root)?;

    let mut files = 0;
    let mut bytes = 0;
    fsutil::create_private_dir_all(&paths.root)?;
    for entry in included() {
        let source = from.join(entry.name);
        if source.exists() {
            copy_tree(
                &source,
                &paths.root.join(entry.name),
                &mut files,
                &mut bytes,
            )?;
        }
    }

    let mut pipeline = Pipeline::with_paths(paths.clone())?;
    let rebuilt = crate::reindex::reindex_all(&mut pipeline)?;
    let keys_reconciled = crate::restore::reconcile(&pipeline)?;
    Ok(RestoreReport {
        files,
        records_indexed: rebuilt.from_tree + rebuilt.from_manifests,
        erasures_replayed: rebuilt.tombstones_replayed,
        keys_reconciled,
    })
}

/// The manifest file as it sits in a backup.
///
/// The reasons are carried along with the names. An operator reading a backup months later is the
/// person who most needs to know why their key store is not in it, and the argument being in the
/// source tree is no help to them at that moment.
#[derive(Debug, Serialize, Deserialize)]
struct ManifestFile {
    /// Format version, so a backup written by a later build is refused rather than half-read.
    version: u32,
    /// When the backup was taken, in milliseconds since the Unix epoch.
    taken_ms: i64,
    /// Every manifest entry, with its disposition and its reason.
    entries: Vec<ManifestEntry>,
}

/// One line of [`ManifestFile::entries`].
#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    /// Name under the memory root.
    name: String,
    /// What the backup did with it.
    disposition: Disposition,
    /// Why.
    reason: String,
}

/// Writes [`MANIFEST_FILE`] into a finished backup.
fn write_manifest(into: &Path) -> Result<()> {
    let manifest = ManifestFile {
        version: MANIFEST_VERSION,
        taken_ms: fsutil::now_ms(),
        entries: MANIFEST
            .iter()
            .map(|entry| ManifestEntry {
                name: entry.name.to_owned(),
                disposition: entry.disposition,
                reason: entry.reason.to_owned(),
            })
            .collect(),
    };
    let text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| crate::pipeline::invalid(error.to_string()))?;
    fsutil::write_sync(&into.join(MANIFEST_FILE), text.as_bytes())?;
    fsutil::sync_dir(into)?;
    Ok(())
}

/// Reads a backup's manifest, refusing anything that is not one this build restores.
fn read_manifest(from: &Path) -> Result<ManifestFile> {
    let path = from.join(MANIFEST_FILE);
    let Some(text) = fsutil::read_to_string_opt(&path)? else {
        return Err(refused(format!(
            "`{}` holds no {MANIFEST_FILE}, so it is not a backup this can restore",
            from.display()
        )));
    };
    let manifest: ManifestFile = serde_json::from_str(&text)
        .map_err(|error| refused(format!("{} is unreadable: {error}", path.display())))?;
    if manifest.version > MANIFEST_VERSION {
        return Err(refused(format!(
            "{} is version {}; this build restores up to {MANIFEST_VERSION}",
            path.display(),
            manifest.version
        )));
    }
    Ok(manifest)
}

/// Refuses a destination that already holds something.
fn refuse_occupied(into: &Path) -> Result<()> {
    let mut entries = match fs::read_dir(into) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if entries.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "`{}` is not empty; a second backup written over a first cannot be told from it",
                into.display()
            ),
        )
        .into());
    }
    Ok(())
}

/// Refuses a destination inside the store being copied.
///
/// A backup living in the tree it copies is picked up by the next snapshot of that tree, and grows
/// one nesting level per run. It is also the one place a copy of the authoritative half must not be:
/// whatever governs the store now governs the backup too, including a disk that fails.
fn refuse_destination_inside(root: &Path, into: &Path) -> Result<()> {
    let (root, into) = (absolute(root), absolute(into));
    if into.starts_with(&root) {
        return Err(refused(format!(
            "`{}` is inside the store it would copy; a backup kept there shares the failure it \
             exists for",
            into.display()
        )));
    }
    Ok(())
}

/// A path made absolute without requiring it to exist, for a containment test.
///
/// [`fs::canonicalize`] would be stricter and cannot be used: the destination does not exist yet,
/// which is the normal case.
fn absolute(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        return path.to_owned();
    }
    std::env::current_dir().map_or_else(|_| path.to_owned(), |dir| dir.join(path))
}

/// Refuses to restore into a store that already holds records.
///
/// A restore is not a merge. Two record sets in one tree index cleanly and are indistinguishable
/// afterwards, and one of them may be a set an erasure has already been run against.
fn refuse_occupied_store(root: &Path) -> Result<()> {
    let existing = fsutil::walk_files(&root.join(layout::RECORDS_DIR), layout::RECORD_EXT)?;
    if !existing.is_empty() {
        return Err(refused(format!(
            "`{}` already holds {} record(s); a restore is not a merge",
            root.display(),
            existing.len()
        )));
    }
    Ok(())
}

/// Refuses a backup that carries anything the manifest excludes.
///
/// The check that makes the exclusion mutual. A backup is normally produced by [`back_up`], which
/// never writes these, but a restore is exactly where a hand-assembled directory — or one copied
/// out of a snapshot by a well-meaning operator — would put the key store back.
fn refuse_excluded_present(from: &Path) -> Result<()> {
    for entry in excluded() {
        let path = from.join(entry.name);
        if path.exists() {
            return Err(refused(format!(
                "`{}` carries `{}`, which no backup may contain: {}",
                from.display(),
                entry.name,
                entry.reason
            )));
        }
    }
    Ok(())
}

/// Refuses a deployment whose key store or index sits inside an entry a backup copies.
///
/// Both are relocatable ([`Paths::with_key_store`]), so "the key store is excluded" is a claim
/// about a path and not only about a name. A key store under `records/` would be copied by the
/// walk that copies the tree, and the exclusion would be a spelling rather than a boundary.
fn refuse_excluded_inside_included(paths: &Paths) -> Result<()> {
    for entry in included() {
        let inside = paths.root.join(entry.name);
        for (label, path) in [("key store", &paths.key_store), ("index", &paths.index)] {
            if path.starts_with(&inside) {
                return Err(refused(format!(
                    "the {label} `{}` sits inside `{}`, which a backup copies; move it before \
                     taking one",
                    path.display(),
                    inside.display()
                )));
            }
        }
    }
    Ok(())
}

/// Entries under the root that the manifest does not classify, in a stable order.
fn unclassified(root: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if disposition_of(&name).is_none() {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// Copies a file or a whole directory, counting what it moved.
///
/// [`fs::copy`] carries permission bits over, which matters: an owner-visible record is stored
/// `0600`, and a copy of it under the process umask would widen who may read the restored store.
fn copy_tree(from: &Path, to: &Path, files: &mut usize, bytes: &mut u64) -> Result<()> {
    if from.is_dir() {
        fsutil::create_private_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_tree(&entry.path(), &to.join(entry.file_name()), files, bytes)?;
        }
        // Directory modes are set on create, so a directory that already existed keeps its own.
        return Ok(());
    }
    if let Some(parent) = to.parent() {
        fsutil::create_private_dir_all(parent)?;
    }
    *bytes += fs::copy(from, to)?;
    *files += 1;
    Ok(())
}

/// A refusal about the shape of a backup or a store.
///
/// The crate's error type has no arm for one, and these *are* statements about the filesystem — a
/// directory that is not empty, a copy carrying a key store — so they are reported as such rather
/// than dressed up as a contract violation.
///
/// Shared with [`crate::restore`], which refuses the same kinds of thing about the other half of a
/// recovery: one spelling of "this directory is not what you meant" rather than two.
pub(crate) fn refused(detail: String) -> crate::Error {
    crate::Error::Io(io::Error::other(detail))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use yaam_contract::{RecordId, SubjectHash};
    use yaam_crypto::keystore::FsKeyStore;
    use yaam_md::{Body, Document};
    use yaam_store::query::{self, Filter, Scope};

    use super::{
        BackupReport, Disposition, MANIFEST_FILE, back_up, disposition_of, excluded, restore,
    };
    use crate::testkit::{self, BODY, Harness};
    use crate::{Paths, Pipeline, layout};

    /// A server time whose dated directory the fixtures agree on.
    const T09: &str = "2026-08-20T09:14:03.117Z";

    /// Somewhere to put a backup, and somewhere to restore it to.
    ///
    /// The destination does not exist and has no `spec/` of its own, which is the honest starting
    /// point: a restore into a directory that was already a store proves nothing about whether the
    /// backup carried what a store needs.
    struct Drill {
        dir: tempfile::TempDir,
    }

    impl Drill {
        fn new() -> Self {
            Self {
                dir: tempfile::TempDir::new().expect("temp dir"),
            }
        }

        fn backup(&self) -> PathBuf {
            self.dir.path().join("backup")
        }

        fn destination(&self) -> Paths {
            Paths::under(self.dir.path().join("restored"))
        }
    }

    /// Every file under a directory, as paths relative to it.
    fn contents(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        collect(root, root, &mut found);
        found.sort();
        found
    }

    /// Recursive half of [`contents`].
    fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                collect(root, &path, out);
            } else {
                out.push(path.strip_prefix(root).expect("under the root").to_owned());
            }
        }
    }

    /// The record file in a tree, given a store root and a record.
    fn record_path(root: &Path, record: &RecordId, at: &str) -> PathBuf {
        let stamp = layout::stamp(at).expect("a readable stamp");
        root.join(format!(
            "records/{:04}/{:02}/{:02}/{}.md",
            stamp.year,
            stamp.month,
            stamp.day,
            record.as_str()
        ))
    }

    /// Attempts to unseal a record's body with the key store beside it.
    ///
    /// The real unseal, not a proxy for one. Asserting that a file "looks sealed" would pass for a
    /// body whose key travelled in the backup next to it, which is the failure this whole module
    /// exists to prevent.
    fn unseal_attempt(paths: &Paths, record: &RecordId, at: &str) -> yaam_crypto::Result<Vec<u8>> {
        let path = record_path(&paths.root, record, at);
        let document =
            Document::parse(&std::fs::read_to_string(&path).expect("the record file")).expect("md");
        let Body::Sealed(sealed) = document.body else {
            panic!("`{}` carries no sealed body", path.display());
        };
        let keys = FsKeyStore::unwrapped(&paths.key_store).expect("key store");
        yaam_crypto::seal::unseal(&keys, &document.record.record_id, &sealed)
    }

    /// A subject-derived record in a store, sealed and published.
    fn seal_one(harness: &mut Harness, subject: &SubjectHash) -> RecordId {
        let record = testkit::subject_derived(T09, std::slice::from_ref(subject));
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");
        id
    }

    /// The manifest has to cover the layout, or an entry nothing classifies is an entry a backup
    /// silently drops. Asserted against the directories a live store actually creates rather than
    /// against a second hand-written list, which would only ever agree with the first.
    #[test]
    fn the_manifest_classifies_every_entry_a_live_store_creates() {
        let mut harness = Harness::new();
        let subject = testkit::subject('a');
        seal_one(&mut harness, &subject);
        // An erasure, so the tombstone log and the key-store tombstones exist too.
        crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");

        for entry in std::fs::read_dir(harness.root()).expect("read dir") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy();
            assert!(
                disposition_of(&name).is_some(),
                "`{name}` is under the root and the manifest says nothing about it"
            );
        }
    }

    /// The exclusions the erasure guarantee rests on, named one at a time.
    ///
    /// The list above is data, and data can be edited. This is the assertion that an edit flipping
    /// one of these to `Included` fails loudly rather than passing a drill that walks the list.
    #[test]
    fn the_key_store_and_the_spools_are_excluded() {
        for name in [
            layout::KEYSTORE_DIR,
            layout::QUARANTINE_DIR,
            layout::STAGING_DIR,
            layout::DEAD_LETTER_DIR,
            layout::INDEX_FILE,
        ] {
            assert_eq!(
                disposition_of(name),
                Some(Disposition::Excluded),
                "`{name}` must never travel in a backup"
            );
        }
        assert_eq!(
            disposition_of(layout::TOMBSTONE_LOG),
            Some(Disposition::Included),
            "the erasure log has to travel, or a restore resurrects erased structure"
        );
    }

    /// Every exclusion has a path, and the two relocatable ones follow the deployment.
    ///
    /// Asserted over the list rather than over a handful of names, so a later exclusion arrives
    /// with a path the moment it is declared. The relocations are what make this more than
    /// `root.join(name)`: a key store under `records/` is still the key store, and an index moved
    /// out of the tree takes its journal with it.
    #[test]
    fn every_exclusion_resolves_to_where_this_deployment_keeps_it() {
        let root = Path::new("/srv/memory");
        let paths = Paths::under(root)
            .with_key_store(root.join("records/keys"))
            .with_index("/var/lib/memory/derived.sqlite");
        let resolved = super::excluded_paths(&paths);
        assert_eq!(
            resolved.len(),
            excluded().count(),
            "every exclusion needs a path, or one of them is unprotected"
        );
        for (path, entry) in &resolved {
            assert!(
                path.is_absolute(),
                "`{}` resolved to a relative path",
                entry.name
            );
        }
        let path_of = |name: &str| {
            resolved
                .iter()
                .find(|(_, entry)| entry.name == name)
                .map(|(path, _)| path.clone())
                .expect("the manifest names it")
        };
        assert_eq!(path_of(layout::KEYSTORE_DIR), paths.key_store);
        assert_eq!(path_of(layout::INDEX_FILE), paths.index);
        assert_eq!(
            path_of("index.sqlite-wal"),
            Path::new("/var/lib/memory/derived.sqlite-wal"),
            "the journal follows the index, or a relocated one leaves its write-ahead log behind"
        );
        assert_eq!(path_of(layout::QUARANTINE_DIR), root.join(".quarantine"));
    }

    /// Nothing on the exclusion list travels, asserted over the list itself.
    ///
    /// Mechanical on purpose: a later exclusion is covered by this test the moment it is added to
    /// the manifest, with nothing to remember.
    #[test]
    fn nothing_on_the_exclusion_list_reaches_a_backup() {
        let mut harness = Harness::new();
        let subject = testkit::subject('b');
        seal_one(&mut harness, &subject);
        // Something in every excluded place: a quarantined copy, a staged copy, a set-aside one, a
        // note. The knowledge tree is written by `yaam-knowledge` and by nothing in this crate, so
        // the directory is made here rather than found — what is asserted below is that a copy does
        // not take it, and that holds whatever the file inside it says.
        for dir in [
            layout::QUARANTINE_DIR,
            layout::STAGING_DIR,
            layout::DEAD_LETTER_DIR,
            layout::KNOWLEDGE_DIR,
        ] {
            let held = harness.root().join(dir);
            std::fs::create_dir_all(&held).expect("a directory to leave behind");
            std::fs::write(held.join("held.md"), "---\n---\nx\n").expect("a file to leave behind");
        }
        // And half a subject-key check value, as an arming interrupted before its rename leaves.
        std::fs::write(harness.root().join(layout::SUBJECT_CHECK_TEMP), "{\n")
            .expect("a temporary to leave behind");

        let drill = Drill::new();
        let report = back_up(&harness.pipeline, &drill.backup()).expect("backed up");

        let copied = contents(&drill.backup());
        for entry in excluded() {
            assert!(
                report.excluded.iter().any(|name| name == entry.name),
                "`{}` was present and the report does not say it was left behind",
                entry.name
            );
            assert!(
                !copied
                    .iter()
                    .any(|path| path.components().any(|part| part.as_os_str() == entry.name)),
                "`{}` reached the backup: {}",
                entry.name,
                entry.reason
            );
        }
        assert!(copied.contains(&PathBuf::from(MANIFEST_FILE)));
    }

    /// A restore is where a subject key gets re-entered by hand, so the record of which key armed
    /// the tree has to be in the copy. Asserted end to end rather than by reading the manifest: a
    /// classification is a claim about a copy, and this is the copy.
    #[test]
    fn a_restored_tree_still_refuses_a_key_it_was_not_armed_with() {
        let mut harness = Harness::new();
        let armed = yaam_crypto::SubjectKey::from_bytes(&[0x5a; 32]).expect("32 bytes");
        crate::arming::verify_or_arm(harness.root(), &armed).expect("armed");
        harness
            .pipeline
            .accept(testkit::internal(T09), BODY)
            .expect("accepted");

        let drill = Drill::new();
        back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        assert!(
            contents(&drill.backup()).contains(&PathBuf::from(layout::SUBJECT_CHECK_FILE)),
            "the check value has to travel, or arming a restored tree is silent again"
        );

        let destination = drill.destination();
        restore(&destination, &drill.backup()).expect("restored");
        let substitute = yaam_crypto::SubjectKey::from_bytes(&[0x5b; 32]).expect("32 bytes");
        assert!(
            matches!(
                crate::arming::verify_or_arm(&destination.root, &substitute),
                Err(crate::Error::SubjectKeyMismatch { .. })
            ),
            "a restored tree armed under a second key would file a second pseudonym for every \
             subject in it"
        );
        crate::arming::verify_or_arm(&destination.root, &armed)
            .expect("and the key that armed the tree still opens the copy");
    }

    /// The drill, and the half of it that is easy to get wrong: a restored store has to *answer*.
    /// The drill, and the half of it that is easy to get wrong: a restored store has to *answer*.
    ///
    /// Files existing is not the property. A tree restored beside an index nothing rebuilt looks
    /// perfect and returns nothing, which is exactly the shape of failure this asserts against.
    #[test]
    fn a_restored_store_answers_the_query_it_was_backed_up_for() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");

        let drill = Drill::new();
        back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        let restored = restore(&drill.destination(), &drill.backup()).expect("restored");
        assert_eq!(restored.records_indexed, 1);

        let store =
            yaam_store::Store::open_read(&drill.destination().index).expect("the restored index");
        let found = query::by_filter(
            &store,
            &Filter {
                action: Some("deploy".to_owned()),
                scope: Scope::Unrestricted,
                ..Filter::default()
            },
        )
        .expect("queried");
        assert_eq!(
            found.iter().map(RecordId::as_str).collect::<Vec<_>>(),
            vec![id.as_str()],
            "the restored store has to come back with the record, not merely hold its file"
        );

        // And the entity read a caller would actually make, which needs the derived rows a rebuild
        // reproduces rather than the file the copy carried.
        let by_entity = query::by_entity(
            &store,
            "ticket",
            "PROJ-42",
            1.0,
            None,
            None,
            &Scope::Unrestricted,
        )
        .expect("queried");
        assert_eq!(by_entity.len(), 1, "the entity index did not come back");
    }

    /// The manifest moved `entities/` from included to excluded, and this is the claim that move
    /// rests on: nothing carries a materialised timeline, and a restored store produces it again.
    ///
    /// The drain is the second half and is not optional to the argument. A restore rebuilds the
    /// index, which re-enqueues the fan-out; until something drains it the timelines are files that
    /// are not there, which is exactly what `yaam check` reports as a backlog.
    #[test]
    fn a_restored_store_re_materialises_the_timeline_nothing_carried() {
        let mut harness = Harness::new();
        let record = testkit::internal(T09);
        let id = record.record_id.clone();
        harness.pipeline.accept(record, BODY).expect("accepted");
        harness.pipeline.drain_fanout(100).expect("drained");
        let relative = Path::new(layout::ENTITIES_DIR).join("ticket/PROJ-42/timeline.md");
        assert!(
            harness.root().join(&relative).is_file(),
            "nothing is proved if the source store has no timeline either"
        );

        let drill = Drill::new();
        let report = back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        assert!(
            report
                .excluded
                .iter()
                .any(|name| name == layout::ENTITIES_DIR),
            "the timelines were present and the report does not say they were left behind"
        );
        assert!(!drill.backup().join(&relative).exists());

        let paths = drill.destination();
        restore(&paths, &drill.backup()).expect("restored");
        assert!(
            !paths.root.join(&relative).exists(),
            "a restore rebuilds the timelines; it does not carry them"
        );

        let mut pipeline =
            Pipeline::with_paths(paths.clone()).expect("a pipeline over the restore");
        assert_eq!(pipeline.drain_fanout(100).expect("drained"), 1);
        let rebuilt = std::fs::read_to_string(paths.root.join(&relative)).expect("the timeline");
        assert_eq!(
            rebuilt
                .matches(&format!("[[record:{}", id.as_str()))
                .count(),
            1,
            "the restored store has to list the record, once: {rebuilt}"
        );
    }

    /// **The invariant, in one test.** A backup taken while a record was readable, restored after
    /// its subject was erased, must not make the body readable again.
    ///
    /// This is the hard ordering deliberately: the backup carries the ciphertext and carries no
    /// tombstone, because it predates the erasure. The only thing standing between the restored
    /// copy and a readable body is that the key store was never in the backup.
    #[test]
    fn an_erased_record_stays_unreadable_after_a_restore() {
        let mut harness = Harness::new();
        let subject = testkit::subject('c');
        let id = seal_one(&mut harness, &subject);

        // First: the body *is* readable now. Without this the assertion below would also pass for a
        // ciphertext that was never decryptable in the first place.
        let live =
            unseal_attempt(harness.pipeline.paths(), &id, T09).expect("readable while keyed");
        assert_eq!(String::from_utf8(live).expect("utf-8"), BODY);

        let drill = Drill::new();
        back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");

        let restored = restore(&drill.destination(), &drill.backup()).expect("restored");
        assert_eq!(
            restored.erasures_replayed, 0,
            "this backup predates the erasure, so there is no tombstone in it to replay"
        );

        let paths = drill.destination();
        let error = unseal_attempt(&paths, &id, T09)
            .expect_err("a restored backup must not make an erased body readable");
        assert!(
            matches!(error, yaam_crypto::Error::KeyAbsent(..)),
            "unsealing failed for the wrong reason: {error}"
        );

        // And the reason is the absence, not a lucky failure: the restored key store holds nothing.
        assert!(
            contents(&paths.key_store).is_empty(),
            "the restored store has key material in it"
        );
    }

    /// The other ordering: a backup taken *after* an erasure carries the tombstone, and the restore
    /// replays it.
    ///
    /// Both orderings matter and they fail differently. Without the log a rebuild would re-derive
    /// the erased subject's rows from whatever the tree still held.
    #[test]
    fn a_restore_replays_the_erasure_its_backup_carried() {
        let mut harness = Harness::new();
        let subject = testkit::subject('d');
        let id = seal_one(&mut harness, &subject);
        crate::erase::erase_subject(&mut harness.pipeline, &subject).expect("erased");

        let drill = Drill::new();
        back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        let restored = restore(&drill.destination(), &drill.backup()).expect("restored");
        assert_eq!(restored.erasures_replayed, 1);

        // The body was already dropped from the tree before the copy, so what is restored carries
        // no ciphertext at all — and the subject is tombstoned in the restored key store, so a late
        // replay of the same record could not mint a key for it either.
        let root = drill.destination().root;
        let document = Document::parse(
            &std::fs::read_to_string(record_path(&root, &id, T09)).expect("the record file"),
        )
        .expect("md");
        assert!(matches!(document.body, Body::Plain(body) if body.is_empty()));
        let keys = FsKeyStore::unwrapped(&drill.destination().key_store).expect("key store");
        assert!(
            yaam_crypto::keystore::KeyStore::is_tombstoned(&keys, &subject).expect("read"),
            "the replay has to leave the subject unmintable in the restored store"
        );
    }

    /// A wrapped key store needs nothing beside it, so the manifest needs no line for one.
    ///
    /// The property the wrapper's self-describing header buys: salt and cost live in the blob, so
    /// there is no parameters file next to the keys — which is the file a backup would have had to
    /// carry, and the one it would have dropped by accident.
    #[test]
    fn a_wrapped_key_store_keeps_nothing_a_backup_would_have_to_carry() {
        let mut harness = Harness::new().wrapping_keys_with(
            yaam_crypto::wrapper::PassphraseWrapper::with_salt(
                b"a passphrase",
                [7u8; 16],
                // Cheap on purpose: this asserts what the key store keeps on disk, not how long
                // argon2 takes to get there.
                yaam_crypto::wrapper::Cost {
                    memory_kib: 8,
                    passes: 1,
                    lanes: 1,
                },
            )
            .expect("wrapper"),
        );
        let subject = testkit::subject('e');
        seal_one(&mut harness, &subject);

        let key_store = harness.pipeline.paths().key_store.clone();
        let held = contents(&key_store);
        assert!(
            !held.is_empty(),
            "nothing was written, so nothing is proved"
        );
        for path in held {
            let first = path
                .components()
                .next()
                .expect("a first component")
                .as_os_str()
                .to_string_lossy()
                .into_owned();
            assert!(
                first == "keys" || first == "tombstones",
                "`{}` sits beside the keys, so a backup would have had to decide about it",
                path.display()
            );
        }
    }

    /// A relocated key store is excluded by path, not by spelling.
    #[test]
    fn a_key_store_inside_the_tree_refuses_the_backup() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let root = dir.path().join("store");
        let paths = Paths::under(&root).with_key_store(root.join("records/keys"));
        let pipeline = Pipeline::with_paths(paths).expect("pipeline");
        let error = back_up(&pipeline, &dir.path().join("out"))
            .expect_err("a key store under records/ would be copied by the walk");
        assert!(error.to_string().contains("key store"), "{error}");
    }

    /// A backup inside the store it copies shares whatever fails the store.
    #[test]
    fn a_destination_inside_the_store_refuses_the_backup() {
        let harness = Harness::new();
        let error = back_up(&harness.pipeline, &harness.root().join("backup"))
            .expect_err("inside the tree it copies");
        assert!(error.to_string().contains("inside the store"), "{error}");
    }

    /// Every refusal, because each one is the last check before a store is quietly wrong.
    #[test]
    fn a_backup_and_a_restore_refuse_what_they_cannot_do_safely() {
        let mut harness = Harness::new();
        seal_one(&mut harness, &testkit::subject('f'));
        let drill = Drill::new();
        back_up(&harness.pipeline, &drill.backup()).expect("backed up");

        // A second backup into the same directory: the two could not be told apart afterwards.
        let again = back_up(&harness.pipeline, &drill.backup()).expect_err("not empty");
        assert!(again.to_string().contains("not empty"), "{again}");

        // A directory that is not a backup.
        let bare = drill.backup().parent().expect("parent").join("bare");
        std::fs::create_dir_all(&bare).expect("dir");
        let unknown = restore(&drill.destination(), &bare).expect_err("not a backup");
        assert!(unknown.to_string().contains(MANIFEST_FILE), "{unknown}");

        // A backup a well-meaning operator put a key store back into.
        std::fs::create_dir_all(drill.backup().join(layout::KEYSTORE_DIR)).expect("dir");
        let smuggled = restore(&drill.destination(), &drill.backup()).expect_err("carries keys");
        assert!(
            smuggled.to_string().contains(layout::KEYSTORE_DIR),
            "{smuggled}"
        );
        std::fs::remove_dir(drill.backup().join(layout::KEYSTORE_DIR)).expect("undo");

        // A restore into a store that already holds records is a merge, not a restore.
        restore(harness.pipeline.paths(), &drill.backup()).expect_err("already holds records");

        // A manifest from a later build.
        std::fs::write(
            drill.backup().join(MANIFEST_FILE),
            r#"{"version":99,"taken_ms":0,"entries":[]}"#,
        )
        .expect("manifest");
        let newer = restore(&drill.destination(), &drill.backup()).expect_err("too new");
        assert!(newer.to_string().contains("version 99"), "{newer}");
    }

    /// An unknown file beside the store is named rather than copied or silently dropped.
    #[test]
    fn a_file_the_manifest_does_not_classify_is_reported_and_left() {
        let harness = Harness::new();
        std::fs::write(harness.root().join("unseal.key"), "aabb").expect("a key beside the store");
        let drill = Drill::new();
        let report = back_up(&harness.pipeline, &drill.backup()).expect("backed up");
        assert_eq!(
            report,
            BackupReport {
                unclassified: vec!["unseal.key".to_owned()],
                excluded: report.excluded.clone(),
                files: report.files,
                bytes: report.bytes,
            }
        );
        assert!(!drill.backup().join("unseal.key").exists());
    }
}
