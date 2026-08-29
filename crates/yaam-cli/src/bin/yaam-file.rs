//! File one record about a transaction: build the record, write it to a caller socket, report what
//! became of it.
//!
//! `yaam-emit` with one constant changed. Argument parsing, an exit code, and nothing else: see
//! `yaam_cli::emit` for what it does and `yaam_cli::cli::FileCli` for why it is a separate program
//! rather than a flag on the other one.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let env = yaam_cli::config::Env::from_process();
    let mut out = std::io::stdout().lock();
    let code = yaam_cli::filer(std::env::args_os(), &env, &mut out);
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
