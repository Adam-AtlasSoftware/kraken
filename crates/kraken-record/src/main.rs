//! `kraken-record`: record corpus fixtures with a real Ghidra, or check them for drift.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use engine_fake::FixtureFile;
use engine_ghidra::GhidraInstall;
use kraken_record::{DEFAULT_TYPE_CAP, RecordOptions, compare, record_binary, render_fixture};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const USAGE: &str = "\
usage: kraken-record [--check] [--jobs N] [--function-cap N] [--type-cap N]
                     [--corpus DIR] [--fixtures DIR] [BINARY...]

Records an engine-fake fixture per corpus binary into <corpus>/fixtures/<binary>.json: functions
with their decompilation, listing, control-flow graph and references, plus types, the memory map,
strings and imports/exports. The function cap is 200, or 96 for the static_* binaries; override it
with --function-cap.
With --check nothing is written: each binary is re-recorded in memory and compared structurally
(functions, names, signatures, sizes, token kinds, type names, listing, CFG, references, memory
map, strings, symbols) with the committed fixture;
the exit status is 1 on drift. Without BINARY arguments every file in <corpus>/bin is used.
Needs KRAKEN_GHIDRA_HOME, KRAKEN_JAVA_HOME and the extension built by `cargo xtask ghidra-ext`.";

struct Args {
    check: bool,
    jobs: usize,
    function_cap: Option<usize>,
    type_cap: usize,
    corpus: PathBuf,
    fixtures: Option<PathBuf>,
    binaries: Vec<PathBuf>,
}

fn parse_args() -> Result<Option<Args>> {
    let mut a = Args {
        check: false,
        jobs: 4,
        function_cap: None,
        type_cap: DEFAULT_TYPE_CAP,
        corpus: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus"),
        fixtures: None,
        binaries: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().with_context(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--check" => a.check = true,
            "--jobs" => a.jobs = value("--jobs")?.parse().context("--jobs")?,
            "--function-cap" => a.function_cap = Some(value("--function-cap")?.parse()?),
            "--type-cap" => a.type_cap = value("--type-cap")?.parse()?,
            "--corpus" => a.corpus = value("--corpus")?.into(),
            "--fixtures" => a.fixtures = Some(value("--fixtures")?.into()),
            s if s.starts_with("--") => bail!("unknown option {s}"),
            s => a.binaries.push(s.into()),
        }
    }
    a.jobs = a.jobs.max(1);
    Ok(Some(a))
}

fn default_binaries(corpus: &Path) -> Result<Vec<PathBuf>> {
    let dir = corpus.join("bin");
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    Ok(v)
}

fn main() -> std::process::ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("kraken-record: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    match rt.block_on(run()) {
        Ok(0) => std::process::ExitCode::SUCCESS,
        Ok(_) => std::process::ExitCode::from(1),
        Err(e) => {
            eprintln!("kraken-record: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}

/// Returns the number of failed binaries (drift or errors).
async fn run() -> Result<usize> {
    let Some(args) = parse_args()? else {
        println!("{USAGE}");
        return Ok(0);
    };
    let install = GhidraInstall::from_env().context("locating Ghidra")?;
    let binaries = if args.binaries.is_empty() {
        default_binaries(&args.corpus)?
    } else {
        args.binaries.clone()
    };
    let fixtures = args
        .fixtures
        .clone()
        .unwrap_or_else(|| args.corpus.join("fixtures"));
    if !args.check {
        std::fs::create_dir_all(&fixtures)
            .with_context(|| format!("creating {}", fixtures.display()))?;
    }
    let opts = RecordOptions {
        function_cap: args.function_cap,
        type_cap: args.type_cap,
        ..RecordOptions::default()
    };

    let gate = Arc::new(Semaphore::new(args.jobs));
    let mut set = JoinSet::new();
    for binary in binaries {
        let (gate, install, opts) = (gate.clone(), install.clone(), opts.clone());
        set.spawn(async move {
            let _permit = gate.acquire_owned().await;
            let started = std::time::Instant::now();
            let res = record_binary(&install, &binary, &opts).await;
            (binary, started.elapsed(), res)
        });
    }

    let mut failures = 0usize;
    let mut results = Vec::new();
    while let Some(joined) = set.join_next().await {
        results.push(joined.context("recording task")?);
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    for (binary, took, res) in results {
        let name = binary
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path = fixtures.join(format!("{name}.json"));
        let fresh = match res {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FAIL {name}: {e}");
                failures += 1;
                continue;
            }
        };
        if args.check {
            match FixtureFile::from_path(&path) {
                Err(e) => {
                    eprintln!("FAIL {name}: cannot read {}: {e}", path.display());
                    failures += 1;
                }
                Ok(committed) => {
                    let drift = compare(&committed, &fresh);
                    if committed.ghidra_version != fresh.ghidra_version {
                        println!(
                            "note {name}: ghidra {} -> {}",
                            committed.ghidra_version, fresh.ghidra_version
                        );
                    }
                    if drift.is_empty() {
                        println!("ok   {name} ({:.0?})", took);
                    } else {
                        failures += 1;
                        println!("DRIFT {name}: {} difference(s)", drift.len());
                        for d in drift.iter().take(25) {
                            println!("  {d}");
                        }
                        if drift.len() > 25 {
                            println!("  ... and {} more", drift.len() - 25);
                        }
                    }
                }
            }
        } else {
            let text = render_fixture(&fresh)?;
            std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
            let n = fresh.functions.len();
            println!("wrote {} ({n} functions, {:.0?})", path.display(), took);
        }
    }
    if failures > 0 {
        eprintln!("{failures} binary(ies) failed");
    }
    Ok(failures)
}
