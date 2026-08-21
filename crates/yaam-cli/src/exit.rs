//! Exit codes.
//!
//! A script branches on these, so they are as much part of the interface as what gets printed, and
//! they must not shift. Nothing here collapses onto `1`, because the reactions differ: a
//! misconfiguration is fixed by editing a file, drift is fixed by a rebuild, a refusal for want of
//! a confirmation flag is fixed by meaning it, and "the window has not passed yet" is fixed by
//! waiting. A monitor that could only tell those apart by matching on message text would break the
//! first time a message was reworded.

/// One outcome a command can exit with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Everything asked for was done.
    Ok,
    /// Something went wrong that none of the codes below describes.
    Failed,
    /// The arguments did not make sense.
    Usage,
    /// A setting is missing, unreadable, or does not say what is needed.
    Config,
    /// The store answered, and something in it wants an operator: index drift, or a backlog nothing
    /// is draining.
    Degraded,
    /// A destructive command was asked for without the flag that confirms it. Nothing was done.
    Unconfirmed,
    /// An erasure is real but not yet assertable: a key copy remains, or the backup window has not
    /// passed. Not a failure — a "not yet".
    Incomplete,
}

impl Exit {
    /// Every outcome, so the drift test can iterate them.
    pub const ALL: [Self; 7] = [
        Self::Ok,
        Self::Failed,
        Self::Usage,
        Self::Config,
        Self::Degraded,
        Self::Unconfirmed,
        Self::Incomplete,
    ];

    /// The number the process exits with.
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Usage => 2,
            Self::Config => 3,
            Self::Degraded => 4,
            Self::Unconfirmed => 5,
            Self::Incomplete => 6,
        }
    }
}

/// The table `--help` prints, so the documented codes and the real ones cannot drift.
pub const HELP: &str = "\
Exit codes:
  0  success
  1  failed — anything the codes below do not describe
  2  usage error — bad arguments
  3  config error — a setting is missing, unreadable, or incomplete
  4  degraded — the store answered, and something in it wants attention
  5  unconfirmed — a destructive command was not confirmed; nothing was done
  6  incomplete — the erasure is real but cannot be asserted complete yet";

#[cfg(test)]
mod tests {
    use super::{Exit, HELP};

    /// The interface is the numbers, and `--help` is where they are published.
    #[test]
    fn every_code_is_distinct_and_documented() {
        for (position, outcome) in Exit::ALL.iter().enumerate() {
            let code = outcome.code();
            assert!(
                !Exit::ALL[position + 1..]
                    .iter()
                    .any(|other| other.code() == code),
                "{outcome:?} shares its code with another outcome"
            );
            assert!(
                HELP.contains(&format!("  {code}  ")),
                "code {code} ({outcome:?}) is missing from --help"
            );
        }
    }

    /// Success has to be zero, whatever else moves.
    #[test]
    fn success_is_zero() {
        assert_eq!(Exit::Ok.code(), 0);
    }
}
