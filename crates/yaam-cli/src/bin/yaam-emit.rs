//! Record one thing an agent did: build the record, write it to a caller socket, report what
//! became of it.
//!
//! Argument parsing, an exit code, and nothing else: see `yaam_cli::emit` for what it does.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let env = yaam_cli::config::Env::from_process();
    let mut out = std::io::stdout().lock();
    let code = yaam_cli::emitter(std::env::args_os(), &env, &mut out);
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
