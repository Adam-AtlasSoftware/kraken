use std::io::Write;

use kraken_cli::{CliEnv, run};
use kraken_host::KrakenConfig;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("KRAKEN_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = match KrakenConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            std::process::exit(5);
        }
    };
    let env = CliEnv::standard(config);
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let code = runtime.block_on(run(std::env::args_os().collect(), &env, &mut out, &mut err));
    let _ = out.flush();
    let _ = err.flush();
    std::process::exit(code);
}
