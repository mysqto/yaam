//! The local sidecar: one socket per caller, sealing and signing on their behalf.
//!
//! Argument parsing, an exit code, and nothing else: see `yaam_cli::agent` for what it runs.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let env = yaam_cli::config::Env::from_process();
    let code = yaam_cli::sidecar(std::env::args_os(), &env);
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
