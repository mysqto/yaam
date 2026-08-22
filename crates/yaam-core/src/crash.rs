//! Checkpoints, so a test can kill a real process inside a durability window.
//!
//! Every boundary in [`crate::pipeline`] is a window a crash can land in, and each is microseconds
//! wide. A test that killed a running service by timing would land outside all of them practically
//! every run, so the windows have only ever been tested in process — with the steps driven one at a
//! time by a test that never dies. That leaves the interesting half untested: what a *killed*
//! process leaves on disk, and whether a fresh one converges from it.
//!
//! A checkpoint makes one window as wide as the test needs and keeps the kill external: the process
//! stops in the window, the test signals it, and what is exercised afterwards is the real on-disk
//! state rather than a reconstruction of it.
//!
//! Inert unless [`ENV_POINT`] names a checkpoint. The environment is read once, on the first
//! checkpoint any thread reaches, and arming is logged at `warn`: a service that stops mid-write is
//! not something anybody should discover by accident. A `#[cfg(test)]` seam would be cheaper and
//! would not reach the shipped binaries, which is the one thing these tests are for.

use std::sync::OnceLock;
use std::time::Duration;

/// Environment variable naming the checkpoint this process stops at.
pub const ENV_POINT: &str = "YAAM_CRASH_AT";

/// Environment variable naming a file the stopped process creates.
///
/// How a test waits for the window instead of guessing at it: the file appears once, from inside the
/// window, and the process is still sitting there when it does.
pub const ENV_MARKER: &str = "YAAM_CRASH_MARKER";

/// Staged and fsynced — file *and* directory — and not yet renamed into the tree.
pub const STAGED: &str = "staged";

/// Published and committed, with the fan-out enqueued in that same transaction not yet drained.
pub const COMMITTED: &str = "committed";

/// A timeline head frozen into a part, with no new head yet in its place.
pub const ROLLED_OVER: &str = "rolled-over";

/// How long a stopped process sleeps between doing nothing and doing nothing again.
const PARK_TICK: Duration = Duration::from_millis(25);

/// Stops this process if `point` is the armed checkpoint. Otherwise does nothing at all.
pub(crate) fn checkpoint(point: &str) {
    if armed() == Some(point) {
        park(point);
    }
}

/// The armed checkpoint, read from the environment once per process.
///
/// Once rather than per call, because a write path that consulted the environment for every record
/// would pay for a facility no deployment enables — and a checkpoint that could be armed part way
/// through a process's life is one more state to reason about for nothing.
fn armed() -> Option<&'static str> {
    static ARMED: OnceLock<Option<String>> = OnceLock::new();
    ARMED
        .get_or_init(|| {
            let point = std::env::var(ENV_POINT)
                .ok()
                .filter(|point| !point.is_empty());
            if let Some(point) = &point {
                tracing::warn!(
                    point,
                    "a crash checkpoint is armed: this process will stop there and not come back"
                );
            }
            point
        })
        .as_deref()
}

/// Sits in the window until something kills the process.
///
/// The marker is written and fsynced before the wait: a test watching for a name the kernel has not
/// placed yet would race the very window it is trying to observe. Nothing here returns, because a
/// return would finish the write the test needs left half done.
fn park(point: &str) -> ! {
    if let Some(marker) = std::env::var_os(ENV_MARKER) {
        let path = std::path::PathBuf::from(marker);
        if let Err(error) = crate::fsutil::write_sync(&path, point.as_bytes()) {
            tracing::error!(%error, "crash marker unwritable; whatever waits on it will time out");
        }
    }
    tracing::warn!(point, "stopped at a crash checkpoint, waiting to be killed");
    loop {
        std::thread::sleep(PARK_TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::{COMMITTED, ROLLED_OVER, STAGED, armed, checkpoint};

    /// The three windows are three distinct names, or arming one would stop at another.
    #[test]
    fn the_checkpoints_are_distinguishable() {
        let names = [STAGED, COMMITTED, ROLLED_OVER];
        for (index, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(!names[index + 1..].contains(name), "{name} is not unique");
        }
    }

    /// Nothing is armed in this process, so every checkpoint has to be a no-op that returns.
    ///
    /// The assertion is that control comes back at all: a build that parked here — or that armed
    /// itself from an environment variable a test run happens to carry — would hang the suite rather
    /// than fail it.
    #[test]
    fn an_unarmed_checkpoint_returns() {
        assert_eq!(armed(), None, "the test suite must not arm a checkpoint");
        checkpoint(STAGED);
        checkpoint(COMMITTED);
        checkpoint(ROLLED_OVER);
        checkpoint("a name no window has");
    }
}
