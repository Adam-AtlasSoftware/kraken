//! Performance benchmark of the native engine on large binaries. Run it with
//!
//! ```text
//! cargo xtask bench
//! ```
//!
//! (which is `cargo test --release -p engine-native --test bench -- --ignored --nocapture`). It
//! prints one table per binary. Binaries: `KRAKEN_BENCH_BINS` (a `:`-separated list of paths; they
//! are copied to a temp dir first), by default the system's libpython, cargo and libQt6Widgets when
//! present. `KRAKEN_BENCH_SAMPLES` is the number of functions sampled per query kind (default
//! 200), `KRAKEN_BENCH_ANALYZE=1` also times the analysis job, `KRAKEN_BENCH_IN_PROCESS=1` runs
//! the engine in-process instead of in the worker, `KRAKEN_BENCH_STATE` is a directory to keep the
//! engines' state directories in (so a second run starts from the saved analysis).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Decompiler, DisasmRequest, Disassembler,
    FlowGraph, FunctionLister, Loader, LoaderSpec, StringLister, StringsRequest, SymbolLister,
    XrefProvider, XrefRequest,
};
use kraken_proto::{DisasmScope, Hex64, Locator, PageRequest, XrefDirection};

fn default_bins() -> Vec<PathBuf> {
    // python3 itself is a small launcher: its library is the program
    let python = std::fs::read_dir("/usr/lib")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("libpython3") && n.contains(".so."))
        })
        .min();
    python
        .into_iter()
        .chain(
            ["/usr/bin/cargo", "/usr/lib/libQt6Widgets.so.6"]
                .iter()
                .map(PathBuf::from),
        )
        .filter(|p| p.is_file())
        .collect()
}

fn bins() -> Vec<PathBuf> {
    match std::env::var("KRAKEN_BENCH_BINS") {
        Ok(v) => v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => default_bins(),
    }
}

#[derive(Default)]
struct Samples(Vec<Duration>);

impl Samples {
    fn push(&mut self, d: Duration) {
        self.0.push(d);
    }
    fn pct(&self, p: f64) -> Duration {
        let mut v = self.0.clone();
        v.sort();
        if v.is_empty() {
            return Duration::ZERO;
        }
        v[(((v.len() - 1) as f64) * p).round() as usize]
    }
}

fn ms(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64() * 1000.0)
}

/// `VmHWM` (peak) or `VmRSS` (current) of a process in KiB.
fn rss_kb(pid: u32, field: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = s.lines().find(|l| l.starts_with(field))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn offset(l: &Locator) -> u64 {
    match l {
        Locator::Native { offset, .. } => offset.0,
        _ => 0,
    }
}

#[derive(Default)]
struct Table {
    rows: Vec<[String; 6]>,
}

impl Table {
    fn row(&mut self, name: &str, s: &Samples, total: Duration) {
        eprintln!("  done: {name} in {} ms", ms(total));
        self.rows.push([
            name.to_string(),
            s.0.len().to_string(),
            ms(s.pct(0.5)),
            ms(s.pct(0.95)),
            ms(s.pct(1.0)),
            ms(total),
        ]);
    }
    fn print(&self, title: &str) {
        println!("\n### {title}\n");
        println!("| stage | n | p50 ms | p95 ms | max ms | total ms |");
        println!("|---|---:|---:|---:|---:|---:|");
        for r in &self.rows {
            println!(
                "| {} | {} | {} | {} | {} | {} |",
                r[0], r[1], r[2], r[3], r[4], r[5]
            );
        }
    }
}

fn page(limit: u32) -> PageRequest {
    PageRequest {
        cursor: None,
        limit: Some(limit),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark; run explicitly"]
async fn bench_large_binaries() {
    let Some(mut cfg) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs (cargo xtask native-sla)");
        return;
    };
    if !NativeEngine::is_usable(&cfg) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    cfg.decompile_timeout = Some(Duration::from_secs(60));
    let in_process = std::env::var_os("KRAKEN_BENCH_IN_PROCESS").is_some();
    let samples: usize = std::env::var("KRAKEN_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let analyze = std::env::var_os("KRAKEN_BENCH_ANALYZE").is_some();
    let tmp = tempfile::tempdir().expect("tempdir");
    let cancel = CancellationToken::new();
    for src in bins() {
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        let dst: PathBuf = tmp.path().join(&name);
        std::fs::copy(&src, &dst).expect("copy binary");
        let size = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
        let mut c = cfg.clone();
        c.isolation = if in_process {
            Isolation::InProcess
        } else {
            Isolation::Worker(WorkerOptions::with_program(env!(
                "CARGO_BIN_EXE_kraken-native-worker"
            )))
        };
        // the state directory keeps the analysis of the first open for the second
        c.state_dir = Some(match std::env::var_os("KRAKEN_BENCH_STATE") {
            Some(d) => PathBuf::from(d).join(format!("state-{name}")),
            None => tmp.path().join(format!("state-{name}")),
        });
        let e = NativeEngine::new(c.clone());
        let mut t = Table::default();

        eprintln!("{name}: opening");
        let st = Instant::now();
        let info = e
            .open_binary(Path::new(&dst), &LoaderSpec::default(), &cancel)
            .await;
        let open = st.elapsed();
        if let Err(err) = info {
            println!("{name}: open failed: {err:?}");
            continue;
        }
        let mut s = Samples::default();
        s.push(open);
        t.row("open_binary (load + discovery)", &s, open);
        let pid = e.worker_pid().unwrap_or(std::process::id());
        let after_open = format!(
            "RSS after open: {:.0} MB (peak {:.0} MB)",
            rss_kb(pid, "VmRSS:").unwrap_or(0) as f64 / 1024.0,
            rss_kb(pid, "VmHWM:").unwrap_or(0) as f64 / 1024.0
        );

        // list_functions: full paging in 500s, as the GUI's function list does
        let mut pages = Samples::default();
        let mut funcs = Vec::new();
        let mut cursor = None;
        let st = Instant::now();
        loop {
            let p0 = Instant::now();
            let pg = e
                .list_functions(
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(500),
                    },
                    &cancel,
                )
                .await
                .expect("list");
            pages.push(p0.elapsed());
            funcs.extend(pg.items);
            cursor = pg.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        t.row(
            &format!("list_functions pages of 500 ({} funcs)", funcs.len()),
            &pages,
            st.elapsed(),
        );
        if funcs.is_empty() {
            t.print(&format!("{name} ({} MB)", size / 1_000_000));
            continue;
        }

        let step = (funcs.len() / samples.max(1)).max(1);
        let picks: Vec<_> = funcs.iter().step_by(step).take(samples).collect();

        let mut s = Samples::default();
        let st = Instant::now();
        for f in &picks {
            let t0 = Instant::now();
            let _ = e.get_function(&f.locator, &cancel).await;
            s.push(t0.elapsed());
        }
        t.row("get_function", &s, st.elapsed());

        let mut s = Samples::default();
        let st = Instant::now();
        let mut failed = 0;
        for f in &picks {
            let t0 = Instant::now();
            if e.decompile(&f.locator, &cancel).await.is_err() {
                failed += 1;
            }
            s.push(t0.elapsed());
        }
        t.row(&format!("decompile ({failed} failed)"), &s, st.elapsed());

        let mut s = Samples::default();
        let st = Instant::now();
        // the most recent ones, as when going back to a function just looked at
        for f in picks.iter().rev().take(50) {
            let t0 = Instant::now();
            let _ = e.decompile(&f.locator, &cancel).await;
            s.push(t0.elapsed());
        }
        t.row("decompile again (last 50)", &s, st.elapsed());

        for (label, dir) in [
            ("xrefs to entry", XrefDirection::To),
            ("xrefs from function", XrefDirection::From),
        ] {
            let mut s = Samples::default();
            let st = Instant::now();
            for f in &picks {
                let t0 = Instant::now();
                let _ = e
                    .xrefs(
                        &XrefRequest {
                            address: Hex64(offset(&f.locator)),
                            direction: dir,
                            kind: None,
                            whole_function: dir == XrefDirection::From,
                        },
                        &page(200),
                        &cancel,
                    )
                    .await;
                s.push(t0.elapsed());
            }
            t.row(label, &s, st.elapsed());
        }

        let mut s = Samples::default();
        let st = Instant::now();
        for f in &picks {
            let t0 = Instant::now();
            let _ = e.cfg(&f.locator, &cancel).await;
            s.push(t0.elapsed());
        }
        t.row("cfg", &s, st.elapsed());

        let mut s = Samples::default();
        let st = Instant::now();
        for f in &picks {
            let t0 = Instant::now();
            let _ = e
                .disassemble(
                    &DisasmRequest {
                        start: Hex64(offset(&f.locator)),
                        scope: DisasmScope::Function,
                    },
                    &page(500),
                    &cancel,
                )
                .await;
            s.push(t0.elapsed());
        }
        t.row("disassemble function (500 rows)", &s, st.elapsed());

        // strings: the whole listing paged by 500, then a filtered query
        let mut pages = Samples::default();
        let mut cursor = None;
        let mut n = 0usize;
        let st = Instant::now();
        loop {
            let p0 = Instant::now();
            let pg = e
                .strings(
                    &StringsRequest {
                        min_len: 4,
                        filter: None,
                    },
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(500),
                    },
                    &cancel,
                )
                .await
                .expect("strings");
            pages.push(p0.elapsed());
            n += pg.items.len();
            cursor = pg.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        t.row(
            &format!("strings pages of 500 ({n} strings)"),
            &pages,
            st.elapsed(),
        );
        let mut s = Samples::default();
        let st = Instant::now();
        for _ in 0..5 {
            let t0 = Instant::now();
            let _ = e
                .strings(
                    &StringsRequest {
                        min_len: 4,
                        filter: Some("error".into()),
                    },
                    &page(100),
                    &cancel,
                )
                .await;
            s.push(t0.elapsed());
        }
        t.row("strings filter \"error\"", &s, st.elapsed());

        let mut s = Samples::default();
        let st = Instant::now();
        for _ in 0..3 {
            let t0 = Instant::now();
            let _ = e.imports(&page(500), &cancel).await;
            let _ = e.exports(&page(500), &cancel).await;
            s.push(t0.elapsed());
        }
        t.row("imports + exports (first page)", &s, st.elapsed());

        if analyze {
            let st = Instant::now();
            let mut job = e
                .analyze(AnalyzeRequest::default(), cancel.clone())
                .await
                .expect("analyze");
            // the time of each stage, from the progress events
            let mut stage = None;
            let mut began = Instant::now();
            let mut stages: Vec<(String, Duration)> = Vec::new();
            while let Some(p) = job.next_progress().await {
                if stage != Some(p.stage) {
                    if let Some(prev) = stage {
                        stages.push((format!("{prev:?}"), began.elapsed()));
                    }
                    stage = Some(p.stage);
                    began = Instant::now();
                }
            }
            if let Some(last) = stage {
                stages.push((format!("{last:?}"), began.elapsed()));
            }
            let _ = job.wait().await;
            for (name, d) in stages {
                let mut s = Samples::default();
                s.push(d);
                t.row(&format!("analysis stage {}", name.to_lowercase()), &s, d);
            }
            let d = st.elapsed();
            let mut s = Samples::default();
            s.push(d);
            t.row("analysis job (all stages)", &s, d);
        }

        t.print(&format!(
            "{name} ({:.1} MB, {} functions, {})",
            size as f64 / 1e6,
            funcs.len(),
            if in_process { "in-process" } else { "worker" }
        ));
        println!(
            "\n{after_open}; peak RSS at the end: {:.0} MB",
            rss_kb(pid, "VmHWM:").unwrap_or(0) as f64 / 1024.0
        );
        drop(e);

        // opening again with the state directory of the first open
        let e2 = NativeEngine::new(c);
        let st = Instant::now();
        let again = e2
            .open_binary(Path::new(&dst), &LoaderSpec::default(), &cancel)
            .await;
        println!(
            "\nreopen with saved state: {} ms{}",
            ms(st.elapsed()),
            if again.is_ok() { "" } else { " (failed)" }
        );
        let _ = e2.list_functions(&page(1), &cancel).await;
    }
}
