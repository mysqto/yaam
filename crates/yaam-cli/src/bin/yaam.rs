//! The operator command line: rebuild the index, erase a subject, verify an erasure, read the health.
//!
//! Argument parsing, an exit code, and nothing else. Everything worth testing is in the library,
//! because a binary-only crate cannot be unit tested.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let env = yaam_cli::config::Env::from_process();
    let mut out = std::io::stdout().lock();
    let code = yaam_cli::operator(std::env::args_os(), &env, &mut out);
    // Clamped because `ExitCode` takes a byte, and every code this crate produces is a small
    // positive number: see `yaam_cli::exit`.
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
