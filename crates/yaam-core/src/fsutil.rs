//! Filesystem primitives with the durability step included.
//!
//! Every write in this crate goes through one of these, because the difference between a write and a
//! durable write is one call that is easy to leave out and impossible to notice missing until a
//! machine loses power. Directory syncs matter as much as file syncs: a renamed file whose parent
//! directory entry never reached the platter is a file that is not there after a crash.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Writes a file and fsyncs it, replacing any existing content.
///
/// The directory entry is *not* synced here: the callers that need it also create the directory, and
/// pairing the two calls at the call site keeps it visible that both are required.
pub(crate) fn write_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_sync_mode(path, bytes, None)
}

/// As [`write_sync`], with a mode to create the file under where the platform has modes.
///
/// The mode is applied to an existing file too. A record that has to be owner-only has to be
/// owner-only on the second write as well, and a replaced file keeps the mode it already had.
pub(crate) fn write_sync_mode(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Creates a directory and its parents, traversable only by the owner.
///
/// Every level is created private, because a dated directory inside an owner's subtree is as much
/// part of the boundary as the subtree itself.
pub(crate) fn create_private_dir_all(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Restricts an existing directory to its owner.
///
/// Separate from creating one because a recursive create leaves an existing directory's mode alone,
/// which is exactly the case that would keep a restored or older tree readable.
#[cfg(unix)]
pub(crate) fn make_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Nothing to restrict where directories carry no mode.
#[cfg(not(unix))]
pub(crate) fn make_private(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Fsyncs a directory, so a rename or creation inside it survives a crash.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Replaces a file's content through a temporary sibling and a rename.
///
/// A reader therefore sees either the old bytes or the new ones, never a half-written file. The
/// temporary lives beside the target rather than in a temp directory, because a rename across
/// filesystems is a copy and stops being atomic.
/// The replacement inherits the target's mode: a fresh temporary file would otherwise publish a
/// restricted record under the process umask, silently widening who can read it.
pub(crate) fn replace_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = parent_of(path)?;
    let temp = path.with_extension("tmp");
    write_sync_mode(&temp, bytes, existing_mode(path)?)?;
    fs::rename(&temp, path)?;
    sync_dir(parent)
}

/// The mode a file already carries, or `None` when there is no file yet.
#[cfg(unix)]
fn existing_mode(path: &Path) -> io::Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(meta.permissions().mode() & 0o777)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Nothing to preserve where files carry no mode.
#[cfg(not(unix))]
fn existing_mode(_path: &Path) -> io::Result<Option<u32>> {
    Ok(None)
}

/// Appends one line to a file, creating it if absent, and fsyncs before returning.
///
/// Used for the tombstone log and entity timelines: both are append-only, and both are read back by
/// a rebuild, so an append that is not durable is an erasure or a timeline entry that silently
/// un-happens.
pub(crate) fn append_line_sync(path: &Path, line: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

/// The parent directory of a path, as an error rather than a panic when there is none.
pub(crate) fn parent_of(path: &Path) -> io::Result<&Path> {
    path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` has no parent directory", path.display()),
        )
    })
}

/// Removes a file, treating absence as success.
///
/// Every caller here is re-driving work that may already have completed, and for those an absent
/// file is the good outcome rather than a failure.
pub(crate) fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Reads a file, returning `None` when it does not exist.
pub(crate) fn read_to_string_opt(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Every file under `dir` with the given extension, recursively, in a stable order.
///
/// Sorted so a sweep or a rebuild processes the tree the same way twice, which is what makes their
/// reports comparable between runs.
pub(crate) fn walk_files(dir: &Path, extension: &str) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    collect(dir, extension, &mut found)?;
    found.sort();
    Ok(found)
}

/// Recursive half of [`walk_files`]. A missing root is an empty tree, not an error.
fn collect(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect(&path, extension, out)?;
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
    Ok(())
}

/// Immediate subdirectories of `dir`, in a stable order. A missing root yields none.
pub(crate) fn subdirs(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Modification time in milliseconds since the Unix epoch.
///
/// Modification time rather than creation time: creation time is not available on every filesystem
/// this has to run on, and a sweeper that silently sees no timestamps would skip every file.
pub(crate) fn mtime_ms(path: &Path) -> io::Result<i64> {
    Ok(system_ms(fs::metadata(path)?.modified()?))
}

/// Wall-clock now, in milliseconds since the Unix epoch.
///
/// The only clock read in this crate outside the sweeper's age comparison. Record timestamps are
/// stamped upstream and carried in the record, so nothing derived from a record depends on this.
pub(crate) fn now_ms() -> i64 {
    system_ms(SystemTime::now())
}

/// Converts a [`SystemTime`] to milliseconds, keeping pre-epoch times negative rather than clamping.
fn system_ms(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::FileTimes;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{
        append_line_sync, mtime_ms, now_ms, parent_of, read_to_string_opt, remove_if_present,
        replace_atomically, subdirs, walk_files, write_sync,
    };

    #[test]
    fn a_written_file_reads_back() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("a.md");
        write_sync(&path, b"one").expect("write");
        assert_eq!(
            read_to_string_opt(&path).expect("read").as_deref(),
            Some("one")
        );

        replace_atomically(&path, b"two").expect("replace");
        assert_eq!(
            read_to_string_opt(&path).expect("read").as_deref(),
            Some("two")
        );
        // The temporary must not survive as a second copy of the record.
        assert!(!path.with_extension("tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_replacement_keeps_the_mode_it_replaced() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("restricted.md");
        super::write_sync_mode(&path, b"one", Some(0o600)).expect("write");

        // A fresh temporary file would arrive under the umask, publishing a restricted record wide
        // open — and every erasure rewrites a record file this way.
        replace_atomically(&path, b"two").expect("replace");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn an_absent_file_is_not_an_error_to_read_or_remove() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("missing.md");
        assert!(read_to_string_opt(&path).expect("read").is_none());
        remove_if_present(&path).expect("absence is success");
    }

    #[test]
    fn appending_builds_a_line_per_call() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("log.jsonl");
        append_line_sync(&path, "first").expect("append");
        append_line_sync(&path, "second").expect("append");
        assert_eq!(
            read_to_string_opt(&path).expect("read").as_deref(),
            Some("first\nsecond\n")
        );
    }

    #[test]
    fn a_walk_finds_nested_files_of_one_extension_only() {
        let dir = TempDir::new().expect("temp dir");
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).expect("dirs");
        write_sync(&nested.join("keep.md"), b"").expect("write");
        write_sync(&nested.join("skip.tmp"), b"").expect("write");
        write_sync(&dir.path().join("top.md"), b"").expect("write");

        let found = walk_files(dir.path(), "md").expect("walk");
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .all(|p| p.extension().is_some_and(|e| e == "md"))
        );

        assert_eq!(
            subdirs(dir.path()).expect("subdirs"),
            vec![dir.path().join("a")]
        );
    }

    #[test]
    fn a_missing_tree_walks_to_nothing() {
        let dir = TempDir::new().expect("temp dir");
        let absent = dir.path().join("nope");
        assert!(walk_files(&absent, "md").expect("walk").is_empty());
        assert!(subdirs(&absent).expect("subdirs").is_empty());
    }

    #[test]
    fn a_root_path_has_no_parent() {
        assert!(parent_of(std::path::Path::new("/")).is_err());
    }

    #[test]
    fn modification_time_is_read_not_guessed() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("aged.md");
        write_sync(&path, b"").expect("write");
        assert!((mtime_ms(&path).expect("mtime") - now_ms()).abs() < 60_000);

        // Ageing a file is how the sweeper tests reach past the grace period without waiting.
        let long_ago = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_times(FileTimes::new().set_modified(long_ago))
            .expect("set times");
        assert_eq!(mtime_ms(&path).expect("mtime"), 1_600_000_000_000);
    }
}
