use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command>

Commands:
  (none yet)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help") | Some("-h") | Some("--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}
