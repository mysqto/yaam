//! `cargo xtask <emit|check>`: generates `spec/schemas/`, and checks the shapes behind it.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if xtask::run(&args) {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
