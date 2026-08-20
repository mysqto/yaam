//! The sealed outbound queue.
//!
//! Sidecar-local, not part of the memory tree: the tree belongs to the service, and a sidecar on a
//! different host has no tree at all. Excluded from host backups, drained on reconnect, never
//! archived.
//!
//! One file per entry, named by a zero-padded sequence number, so replay order is the lexical order
//! of a directory listing and survives a restart without a manifest to keep consistent. The
//! directory itself is the only source of truth about what is pending — an in-memory count would be
//! a second one, and the two would disagree after a crash.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Error;

/// Suffix every entry file carries, so a stray file in the directory is ignored rather than posted.
const ENTRY_SUFFIX: &str = ".entry";

/// Width of the sequence number in a file name. Twenty digits hold any `u64`, which is what makes
/// lexical order and numeric order the same order.
const SEQ_WIDTH: usize = 20;

/// Entries the spool holds before it starts refusing writes.
///
/// A bound, not a guess at a good size: an unbounded spool turns a long outage into a full disk,
/// and a caller told [`Error::SpoolFull`] can shed load or stop, which a caller told nothing cannot.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// An append-only queue of sealed records awaiting upstream.
#[derive(Debug)]
pub struct Spool {
    /// Directory holding one file per pending entry.
    dir: PathBuf,
    /// Sequence number the next push will use.
    next: u64,
    /// Entries allowed before pushes are refused.
    capacity: usize,
}

impl Spool {
    /// Opens or creates a spool with [`DEFAULT_CAPACITY`].
    pub fn open(dir: impl AsRef<Path>) -> crate::Result<Self> {
        Self::open_with_capacity(dir, DEFAULT_CAPACITY)
    }

    /// Opens or creates a spool holding at most `capacity` entries.
    ///
    /// The directory is `0700` and every entry `0600`. That is not belt-and-braces: it is the
    /// reason a caller's records never sit where another local process can read them.
    pub fn open_with_capacity(dir: impl AsRef<Path>, capacity: usize) -> crate::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        create_private_dir(&dir)?;
        // Resuming from the highest name on disk keeps sequence numbers monotonic across restarts,
        // so a replay never interleaves a new entry ahead of an older one.
        let next = entries(&dir)?.last().map_or(0, |(seq, _)| seq + 1);
        Ok(Self {
            dir,
            next,
            capacity,
        })
    }

    /// Appends a sealed record, fsyncing before returning.
    ///
    /// Both the file and the directory are fsynced: without the second one the entry's *name* can
    /// be lost in a crash, which is an entry that exists on disk and is invisible to the drain.
    pub fn push(&mut self, sealed: &[u8]) -> crate::Result<()> {
        if self.depth()? >= self.capacity {
            return Err(Error::SpoolFull);
        }

        let path = self
            .dir
            .join(format!("{:0SEQ_WIDTH$}{ENTRY_SUFFIX}", self.next));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        file.write_all(sealed)?;
        file.sync_all()?;
        sync_dir(&self.dir)?;

        self.next += 1;
        Ok(())
    }

    /// Replays in order, removing each entry only once upstream has accepted it.
    ///
    /// Returns the number of entries removed. A transient failure stops the drain with that entry
    /// and everything behind it still on disk, so order is preserved for the next attempt. A
    /// permanent rejection removes the entry instead: retrying a record the service will never
    /// accept would wedge every record behind it, which loses far more than the one being dropped.
    pub fn drain<F>(&mut self, mut send: F) -> crate::Result<usize>
    where
        F: FnMut(&[u8]) -> crate::Result<()>,
    {
        let mut removed = 0;
        for (_, path) in entries(&self.dir)? {
            let sealed = fs::read(&path)?;
            match send(&sealed) {
                Ok(()) => {}
                Err(Error::Rejected(why)) => {
                    tracing::warn!(entry = %path.display(), why, "dropping a rejected entry");
                }
                Err(Error::Spooled) => return Ok(removed),
                Err(other) => return Err(other),
            }
            fs::remove_file(&path)?;
            sync_dir(&self.dir)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Number of entries waiting.
    pub fn depth(&self) -> crate::Result<usize> {
        Ok(entries(&self.dir)?.len())
    }
}

/// Pending entries, oldest first.
///
/// A file that does not carry a sequence-numbered name was not written by this spool, so it is
/// skipped rather than posted upstream as if it were a record.
fn entries(dir: &Path) -> crate::Result<Vec<(u64, PathBuf)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let seq = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(ENTRY_SUFFIX))
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(seq) = seq {
            found.push((seq, path));
        } else {
            tracing::debug!(path = %path.display(), "ignoring a foreign file in the spool");
        }
    }
    found.sort_unstable_by_key(|(seq, _)| *seq);
    Ok(found)
}

/// Creates a directory only the owner can traverse, tightening one that already exists.
fn create_private_dir(path: &Path) -> crate::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    // `recursive` leaves an existing directory's mode alone, which would silently keep a
    // world-readable spool world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Flushes a directory entry, so a created or removed name survives a crash.
fn sync_dir(dir: &Path) -> crate::Result<()> {
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// A spool in a fresh temporary directory, kept alive by the returned handle.
    fn spool() -> (TempDir, Spool) {
        let dir = TempDir::new().unwrap();
        let spool = Spool::open(dir.path().join("spool")).unwrap();
        (dir, spool)
    }

    #[test]
    fn an_entry_survives_a_push_and_is_counted() {
        let (_dir, mut spool) = spool();
        assert_eq!(spool.depth().unwrap(), 0);
        spool.push(b"one").unwrap();
        spool.push(b"two").unwrap();
        assert_eq!(spool.depth().unwrap(), 2);
    }

    #[test]
    fn ordering_survives_a_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spool");

        let mut spool = Spool::open(&path).unwrap();
        for n in 0..5u8 {
            spool.push(&[n]).unwrap();
        }
        drop(spool);

        let mut reopened = Spool::open(&path).unwrap();
        let mut seen = Vec::new();
        let drained = reopened
            .drain(|sealed| {
                seen.push(sealed.to_vec());
                Ok(())
            })
            .unwrap();

        assert_eq!(drained, 5);
        assert_eq!(seen, (0..5u8).map(|n| vec![n]).collect::<Vec<_>>());
        assert_eq!(reopened.depth().unwrap(), 0);
    }

    #[test]
    fn a_reopened_spool_does_not_reuse_a_sequence_number() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spool");

        Spool::open(&path).unwrap().push(b"first").unwrap();
        Spool::open(&path).unwrap().push(b"second").unwrap();

        let seqs: Vec<u64> = entries(&path)
            .unwrap()
            .into_iter()
            .map(|(seq, _)| seq)
            .collect();
        assert_eq!(seqs, [0, 1]);
    }

    #[test]
    fn an_entry_is_retained_until_upstream_accepts_it() {
        let (_dir, mut spool) = spool();
        spool.push(b"record").unwrap();

        let drained = spool.drain(|_| Err(Error::Spooled)).unwrap();
        assert_eq!(drained, 0);
        assert_eq!(spool.depth().unwrap(), 1, "a failed send must retain it");

        let drained = spool.drain(|_| Ok(())).unwrap();
        assert_eq!(drained, 1);
        assert_eq!(spool.depth().unwrap(), 0, "acceptance must remove it");
    }

    #[test]
    fn a_transient_failure_stops_the_drain_where_it_happened() {
        let (_dir, mut spool) = spool();
        for n in 0..4u8 {
            spool.push(&[n]).unwrap();
        }

        let mut sent = Vec::new();
        let drained = spool
            .drain(|sealed| {
                if sealed == [2] {
                    return Err(Error::Spooled);
                }
                sent.push(sealed[0]);
                Ok(())
            })
            .unwrap();

        assert_eq!(drained, 2);
        assert_eq!(sent, [0, 1]);
        // The failing entry and its successor are both still pending, in order.
        assert_eq!(spool.depth().unwrap(), 2);
        let mut rest = Vec::new();
        spool
            .drain(|sealed| {
                rest.push(sealed[0]);
                Ok(())
            })
            .unwrap();
        assert_eq!(rest, [2, 3]);
    }

    #[test]
    fn a_rejected_entry_does_not_wedge_the_queue() {
        let (_dir, mut spool) = spool();
        spool.push(b"bad").unwrap();
        spool.push(b"good").unwrap();

        let mut accepted = Vec::new();
        let drained = spool
            .drain(|sealed| {
                if sealed == b"bad" {
                    return Err(Error::Rejected("unprocessable".to_owned()));
                }
                accepted.push(sealed.to_vec());
                Ok(())
            })
            .unwrap();

        assert_eq!(drained, 2, "both entries leave the spool");
        assert_eq!(accepted, [b"good".to_vec()]);
        assert_eq!(spool.depth().unwrap(), 0);
    }

    #[test]
    fn an_unexpected_send_failure_propagates() {
        let (_dir, mut spool) = spool();
        spool.push(b"record").unwrap();

        let err = spool
            .drain(|_| Err(Error::SpoolFull))
            .expect_err("an unclassified failure is not a drain outcome");
        assert!(matches!(err, Error::SpoolFull));
        assert_eq!(spool.depth().unwrap(), 1);
    }

    #[test]
    fn the_bound_is_enforced() {
        let dir = TempDir::new().unwrap();
        let mut spool = Spool::open_with_capacity(dir.path().join("spool"), 2).unwrap();
        spool.push(b"one").unwrap();
        spool.push(b"two").unwrap();

        let err = spool
            .push(b"three")
            .expect_err("the bound must be enforced");
        assert!(matches!(err, Error::SpoolFull));
        assert_eq!(spool.depth().unwrap(), 2);

        // Draining makes room again.
        spool.drain(|_| Ok(())).unwrap();
        spool.push(b"three").unwrap();
    }

    #[test]
    fn the_spool_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spool");
        let mut spool = Spool::open(&path).unwrap();
        spool.push(b"record").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "spool directory mode {mode:o}");

        let (_, entry) = entries(&path).unwrap().pop().unwrap();
        let mode = fs::metadata(entry).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "entry mode {mode:o}");
    }

    #[test]
    fn a_loose_mode_on_an_existing_spool_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spool");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();

        Spool::open(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "mode {mode:o}");
    }

    #[test]
    fn a_foreign_file_is_not_mistaken_for_an_entry() {
        let (_dir, mut spool) = spool();
        spool.push(b"record").unwrap();
        fs::write(spool.dir.join("README"), b"not an entry").unwrap();
        fs::write(spool.dir.join("nan.entry"), b"not a sequence").unwrap();

        assert_eq!(spool.depth().unwrap(), 1);
        let mut seen = 0;
        spool
            .drain(|_| {
                seen += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_spool() {
        let dir = TempDir::new().unwrap();
        let spool = Spool::open(dir.path().join("spool")).unwrap();
        fs::remove_dir_all(dir.path()).unwrap();
        assert!(matches!(spool.depth(), Err(Error::Io(_))));
    }
}
