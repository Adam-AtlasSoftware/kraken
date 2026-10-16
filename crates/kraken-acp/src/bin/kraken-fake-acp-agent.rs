//! Test support: a fake ACP agent on stdio. See `kraken_acp::fake_agent`.

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = kraken_acp::fake_agent::serve(stdin.lock(), stdout.lock()) {
        eprintln!("kraken-fake-acp-agent: {e}");
        std::process::exit(1);
    }
}
