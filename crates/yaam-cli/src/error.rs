//! Failures, and the exit code each one reports.
//!
//! The variants are chosen by what the operator has to do about them rather than by which layer
//! they came from — which is why a missing index is not lumped in with every other store failure:
//! one is fixed by a rebuild and the other by reading the message.

use thiserror::Error;

use crate::exit::Exit;

/// Result alias for command operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a command stopped.
#[derive(Debug, Error)]
pub enum Error {
    /// The arguments did not make sense.
    #[error("usage: {0}")]
    Usage(String),
    /// A setting is missing, unreadable, or does not say enough. Names the setting, because the
    /// operator's next act is to edit it.
    #[error("config: {0}")]
    Config(String),
    /// A destructive command was asked for without its confirmation flag.
    #[error("{0}")]
    Unconfirmed(String),
    /// Anything else that stopped the command.
    #[error("{0}")]
    Failed(String),
}

impl Error {
    /// The exit code this failure reports.
    #[must_use]
    pub fn exit(&self) -> Exit {
        match self {
            Self::Usage(_) => Exit::Usage,
            Self::Config(_) => Exit::Config,
            Self::Unconfirmed(_) => Exit::Unconfirmed,
            Self::Failed(_) => Exit::Failed,
        }
    }
}

/// A configuration fault, naming the setting that is wrong.
pub fn config(message: impl Into<String>) -> Error {
    Error::Config(message.into())
}

/// A failure carrying what was being attempted.
///
/// The context is not decoration. A bare `No such file or directory` from three layers down names
/// neither the file nor the operation, and the operator is the one who has to guess.
pub fn failed(context: &str, cause: &dyn std::fmt::Display) -> Error {
    Error::Failed(format!("{context}: {cause}"))
}

#[cfg(test)]
mod tests {
    use super::{Error, config, failed};
    use crate::exit::Exit;

    /// Every variant reports its own code, because a monitor branches on them.
    #[test]
    fn each_failure_reports_its_own_code() {
        let cases = [
            (Error::Usage("x".to_owned()), Exit::Usage),
            (Error::Config("x".to_owned()), Exit::Config),
            (Error::Unconfirmed("x".to_owned()), Exit::Unconfirmed),
            (Error::Failed("x".to_owned()), Exit::Failed),
        ];
        for (error, expected) in cases {
            assert_eq!(error.exit(), expected, "{error}");
        }
    }

    #[test]
    fn a_failure_names_what_was_being_attempted() {
        let error = failed("opening the tree", &"no such directory");
        assert_eq!(
            error.to_string(),
            "opening the tree: no such directory",
            "the context is what the operator acts on"
        );
        assert!(config("--root is not set").to_string().contains("--root"));
    }
}
