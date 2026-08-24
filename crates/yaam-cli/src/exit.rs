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
    /// The store answered, and something in it wants an operator: index drift, a backlog nothing
    /// is draining, or a file beside the store that no backup manifest classifies.
    Degraded,
    /// A destructive command was asked for without the flag that confirms it. Nothing was done.
    Unconfirmed,
    /// An erasure is real but not yet assertable: a key copy remains, or the backup window has not
    /// passed. Not a failure — a "not yet".
    Incomplete,
    /// A record reached the sidecar but not the service, and the sidecar is still trying. Not a
    /// failure — the record is durable, and nothing is owed by whoever sent it.
    ///
    /// Distinct from [`Self::Ok`] rather than folded into it, because the two say different things
    /// about the same record: one is stored, the other is owed. A deployment whose service has been
    /// down all afternoon is invisible to a caller that cannot tell them apart.
    Spooled,
    /// A record will never be accepted as written. Retrying changes nothing; the caller is the only
    /// one who can fix it.
    Rejected,
    /// A socket did not answer: nothing is listening, or the path names no socket. Nothing was
    /// recorded, so the record is still the caller's to send.
    Unreachable,
}

impl Exit {
    /// Every outcome, so the drift test can iterate them.
    pub const ALL: [Self; 10] = [
        Self::Ok,
        Self::Failed,
        Self::Usage,
        Self::Config,
        Self::Degraded,
        Self::Unconfirmed,
        Self::Incomplete,
        Self::Spooled,
        Self::Rejected,
        Self::Unreachable,
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
            Self::Spooled => 7,
            Self::Rejected => 8,
            Self::Unreachable => 9,
        }
    }

    /// Whether this outcome means the record or the operation is safe: nothing was lost, and the
    /// caller has nothing left to do.
    ///
    /// Two codes answer yes, which is the whole reason this predicate exists rather than a `== 0`
    /// at every call site. A shell hook that treated [`Self::Spooled`] as a failure would report an
    /// unreachable service as a lost record, which is the one thing the spool exists to prevent.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Ok | Self::Spooled)
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
  6  incomplete — the erasure is real but cannot be asserted complete yet
  7  spooled — the sidecar holds the record and is still delivering it; a success
  8  rejected — the record will never be accepted as written; only its sender can fix it
  9  unreachable — a socket did not answer; nothing was recorded";

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

    /// A spooled record is safe and a lost one is not, and the predicate is what says which.
    #[test]
    fn only_a_stored_or_spooled_record_counts_as_success() {
        for outcome in Exit::ALL {
            assert_eq!(
                outcome.is_success(),
                matches!(outcome, Exit::Ok | Exit::Spooled),
                "{outcome:?} is on the wrong side of success"
            );
        }
    }
}
