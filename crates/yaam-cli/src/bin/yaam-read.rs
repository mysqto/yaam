//! Ask a deployment what it remembers: build one read, send it to a caller's read socket, print
//! the answer.
//!
//! Argument parsing, an exit code, and nothing else: see `yaam_cli::read` for what it does.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let env = yaam_cli::config::Env::from_process();
    let mut out = std::io::stdout().lock();
    let code = yaam_cli::reader(std::env::args_os(), &env, &mut out);
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
