//! `cargo xtask bench`: the performance benchmarks, run in release mode, each printing Markdown
//! tables. They are `#[ignore]` tests, so `cargo test` never runs them. See `docs/performance.md`.

use std::process::Command;

use crate::{Result, workspace_root};

/// The benchmarks: name, package, cargo test selector, test name filter.
const SUITES: &[(&str, &str, &[&str], &str)] = &[
    (
        "engine",
        "engine-native",
        &["--test", "bench"],
        "bench_large_binaries",
    ),
    (
        "daemon",
        "kraken-viewmodel",
        &["--test", "bench_daemon"],
        "bench_daemon",
    ),
    ("gui", "kraken-gui", &["--bin", "kraken-gui"], "bench_gui"),
    (
        "widgets",
        "kraken-gui-widgets",
        &["--test", "graph_view"],
        "stress_frame_time",
    ),
];

pub fn bench(args: &[String]) -> Result<()> {
    let (suite, binaries) = match args.first().map(String::as_str) {
        Some(s @ ("engine" | "daemon" | "gui" | "widgets" | "all")) => (s, &args[1..]),
        _ => ("engine", args),
    };
    let root = workspace_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let chosen: Vec<_> = SUITES
        .iter()
        .filter(|(name, ..)| suite == "all" || *name == suite)
        .collect();
    if chosen.iter().any(|(n, ..)| matches!(*n, "daemon" | "gui")) {
        // the daemon and the native worker next to it
        run(Command::new(&cargo)
            .args([
                "build",
                "--release",
                "-p",
                "krakend",
                "-p",
                "engine-native",
                "-p",
                "kraken-cli",
            ])
            .current_dir(&root))?;
    }
    for (name, package, selector, filter) in chosen {
        println!("\n## {name}\n");
        let mut cmd = Command::new(&cargo);
        cmd.args(["test", "--release", "-p", package])
            .args(*selector)
            .args(["--", "--ignored", "--nocapture", "--test-threads=1", filter])
            .current_dir(&root)
            .env("CARGO_INCREMENTAL", "0")
            .env("KRAKEN_KRAKEND", root.join("target/release/krakend"));
        if !binaries.is_empty() {
            cmd.env("KRAKEN_BENCH_BINS", binaries.join(":"));
        }
        run(&mut cmd)?;
    }
    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| format!("cannot run {cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {status}"))
    }
}
