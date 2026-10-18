//! Daemon round trips and the view-model's latencies on large binaries, through a spawned
//! `krakend` with the native engine. Run with `cargo xtask bench daemon [binary...]`, or
//!
//! ```text
//! cargo build --release -p krakend -p engine-native
//! KRAKEN_KRAKEND=target/release/krakend \
//!   cargo test --release -p kraken-viewmodel --test bench_daemon -- --ignored --nocapture
//! ```
//!
//! `KRAKEN_BENCH_ENGINE=ghidra` runs the same steps on the Ghidra engine (set
//! `KRAKEN_GHIDRA_HOME` and `KRAKEN_JAVA_HOME`, and build the extension with `cargo xtask
//! ghidra-ext`), to compare the two. Binaries: `KRAKEN_BENCH_BINS` (`:`-separated; copied to a temp dir), by default the system's
//! libpython and libQt6Widgets when present. `KRAKEN_BENCH_SAMPLES` is the number of functions
//! sampled per query (default 100). The daemon runs in a private runtime directory and is
//! stopped at the end.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_host::daemon::{StartOptions, find_krakend, wait_until_stopped};
use kraken_ipc::{DaemonInfo, RuntimeDir};
use kraken_viewmodel::{
    Backend, BackendOptions, Connection, DaemonClientBackend, ViewModel, start_connector,
};
use serde_json::{Value, json};

const SLOW: Duration = Duration::from_secs(3 * 3600);

fn default_bins() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/usr/lib") {
        let mut py: Vec<PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("libpython3") && n.contains(".so."))
            })
            .collect();
        py.sort();
        v.extend(py.into_iter().take(1));
    }
    v.push(PathBuf::from("/usr/lib/libQt6Widgets.so.6"));
    v.into_iter().filter(|p| p.is_file()).collect()
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

fn row(name: &str, s: &Samples, total: Duration) {
    eprintln!("  done: {name} in {} ms", ms(total));
    println!(
        "| {name} | {} | {} | {} | {} | {} |",
        s.0.len(),
        ms(s.pct(0.5)),
        ms(s.pct(0.95)),
        ms(s.pct(1.0)),
        ms(total)
    );
}

fn one(name: &str, d: Duration) {
    let mut s = Samples::default();
    s.push(d);
    row(name, &s, d);
}

fn status_kb(pid: u32, field: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = s.lines().find(|l| l.starts_with(field))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The native workers among the descendants of `pid`.
fn workers(pid: u32) -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let descends = |mut p: u32| {
        for _ in 0..8 {
            match status_kb(p, "PPid:") {
                Some(parent) if parent == u64::from(pid) => return true,
                Some(parent) if parent > 1 => p = parent as u32,
                _ => return false,
            }
        }
        false
    };
    rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|c| {
            std::fs::read_to_string(format!("/proc/{c}/status"))
                .is_ok_and(|s| s.starts_with("Name:\tkraken-native-w"))
                && descends(*c)
        })
        .collect()
}

struct Daemon {
    rt: Arc<tokio::runtime::Runtime>,
    dir: RuntimeDir,
    backend: Arc<DaemonClientBackend>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let b = self.backend.clone();
        self.rt.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(5), b.shutdown_daemon()).await;
        });
        let stopped = self
            .rt
            .block_on(wait_until_stopped(&self.dir, Duration::from_secs(30)));
        if !stopped && let Ok(Some(info)) = DaemonInfo::read(&self.dir.info_path()) {
            let _ = std::process::Command::new("kill")
                .arg(info.pid.to_string())
                .status();
        }
    }
}

/// A running daemon and the client of the benchmark.
struct Rig {
    rt: Arc<tokio::runtime::Runtime>,
    _daemon: Daemon,
    backend: Arc<DaemonClientBackend>,
    pid: Option<u32>,
    runtime_dir: PathBuf,
    config: PathBuf,
}

impl Rig {
    fn start(rt: &Arc<tokio::runtime::Runtime>, base: &Path, krakend: &Path, n: u32) -> Rig {
        let config = base.join("config.toml");
        std::fs::write(&config, "").expect("empty config");
        let dir = RuntimeDir::from_dir(base.join(format!("rt{n}"))).expect("runtime dir");
        let start = StartOptions {
            krakend: Some(krakend.to_path_buf()),
            env: vec![
                ("KRAKEN_RUNTIME_DIR".into(), dir.path().into()),
                ("KRAKEN_CONFIG".into(), config.into()),
                ("KRAKEN_DAEMON_IDLE_SECS".into(), "86400".into()),
                (
                    "KRAKEN_NATIVE_WORKER".into(),
                    krakend.with_file_name("kraken-native-worker").into(),
                ),
            ],
            timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let backend = Arc::new(
            rt.block_on(DaemonClientBackend::connect(
                start_connector(dir.clone(), start),
                BackendOptions::default(),
            ))
            .expect("the client reaches krakend"),
        );
        let pid = DaemonInfo::read(&dir.info_path())
            .ok()
            .flatten()
            .map(|i| i.pid);
        Rig {
            rt: rt.clone(),
            runtime_dir: dir.path().to_path_buf(),
            config: base.join("config.toml"),
            _daemon: Daemon {
                rt: rt.clone(),
                dir,
                backend: backend.clone(),
            },
            backend,
            pid,
        }
    }

    fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        self.rt
            .block_on(self.backend.call(cmd, args))
            .map_err(|e| format!("{e:?}"))
    }
}

fn address(v: &Value) -> Option<String> {
    v["locator"]["offset"]
        .as_str()
        .or_else(|| v["address"].as_str())
        .map(str::to_string)
}

#[test]
#[ignore = "benchmark; run explicitly"]
fn bench_daemon() {
    let Ok(krakend) = find_krakend() else {
        eprintln!("skipped: no krakend (cargo build --release -p krakend -p engine-native)");
        return;
    };
    let engine = std::env::var("KRAKEN_BENCH_ENGINE").unwrap_or_else(|_| "native".into());
    if engine == "native" && !krakend.with_file_name("kraken-native-worker").is_file() {
        eprintln!("skipped: no kraken-native-worker next to krakend");
        return;
    }
    let samples: usize = std::env::var("KRAKEN_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let tmp = tempfile::Builder::new()
        .prefix("kb")
        .tempdir_in("/tmp")
        .expect("temp dir");
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let mut generation = 0;
    for src in bins() {
        generation += 1;
        let rig = Rig::start(&rt, tmp.path(), &krakend, generation);
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        let copy = tmp.path().join(&name);
        std::fs::copy(&src, &copy).expect("copy");
        let project = tmp.path().join(format!("proj-{name}"));
        println!("\n### {name} through krakend ({engine} engine)\n");
        println!("| step | n | p50 ms | p95 ms | max ms | total ms |");
        println!("|---|---:|---:|---:|---:|---:|");

        // project create: load, discovery, the first open
        let t = Instant::now();
        let created = rig.call(
            "project_create",
            json!({"binary": copy, "project_dir": project, "engine": engine}),
        );
        let d = t.elapsed();
        if let Err(e) = created {
            println!("| project_create | failed: {e} | | | | |");
            continue;
        }
        one("project_create (first open)", d);

        // the analysis job: the native engine decompiles every function, Ghidra runs its analyzers
        if std::env::var_os("KRAKEN_BENCH_ANALYZE").is_some() {
            let t = Instant::now();
            let job = rig.call("analyze", json!({}));
            let finished = match job {
                Ok(j) => {
                    let id = j["job_id"].as_str().unwrap_or_default().to_string();
                    loop {
                        match rig.call("job_await", json!({"job_id": id, "timeout_ms": 30000})) {
                            Ok(v) if v["timed_out"].as_bool() == Some(true) => continue,
                            Ok(v) => break v["status"].as_str() == Some("succeeded"),
                            Err(_) => break false,
                        }
                    }
                }
                Err(_) => false,
            };
            one(
                if finished {
                    "analyze (job, to completion)"
                } else {
                    "analyze (job, DID NOT SUCCEED)"
                },
                t.elapsed(),
            );
        }

        // the cheapest command: the IPC and registry overhead alone
        let mut s = Samples::default();
        let t = Instant::now();
        for _ in 0..200 {
            let t0 = Instant::now();
            let _ = rig.call("project_info", json!({}));
            s.push(t0.elapsed());
        }
        row("project_info (round trip)", &s, t.elapsed());

        // function list paging as the GUI does it
        let mut s = Samples::default();
        let mut funcs: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let t = Instant::now();
        loop {
            let mut args = json!({"limit": 200});
            if let Some(c) = &cursor {
                args["cursor"] = json!(c);
            }
            let t0 = Instant::now();
            let Ok(page) = rig.call("list_functions", args) else {
                break;
            };
            s.push(t0.elapsed());
            for it in page["items"].as_array().into_iter().flatten() {
                if let Some(a) = address(it) {
                    funcs.push(a);
                }
            }
            cursor = page["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        row(
            &format!("list_functions pages of 200 ({} funcs)", funcs.len()),
            &s,
            t.elapsed(),
        );

        // the name filter, as typing in the function list does
        let mut s = Samples::default();
        let t = Instant::now();
        for q in ["a", "py", "sys", "Qt", "zzzz-no-such-name"] {
            let t0 = Instant::now();
            let _ = rig.call("list_functions", json!({"limit": 200, "name_filter": q}));
            s.push(t0.elapsed());
        }
        row("list_functions name_filter", &s, t.elapsed());
        if funcs.is_empty() {
            continue;
        }
        let step = (funcs.len() / samples.max(1)).max(1);
        let picks: Vec<&String> = funcs.iter().step_by(step).take(samples).collect();

        type Query = (&'static str, &'static str, fn(&str) -> Value);
        let queries: [Query; 6] = [
            ("get_function", "get_function", |a| json!({"address": a})),
            ("decompile", "decompile", |a| json!({"address": a})),
            ("cfg", "cfg", |a| json!({"function": a})),
            (
                "xrefs to",
                "xrefs",
                |a| json!({"address": a, "direction": "to", "limit": 200}),
            ),
            ("callees", "callees", |a| json!({"address": a})),
            (
                "disassemble function",
                "disassemble",
                |a| json!({"function": a, "max_instructions": 200}),
            ),
        ];
        for (label, cmd, args) in queries {
            let mut s = Samples::default();
            let mut failed = 0;
            let t = Instant::now();
            for a in &picks {
                let t0 = Instant::now();
                if rig.call(cmd, args(a)).is_err() {
                    failed += 1;
                }
                s.push(t0.elapsed());
            }
            row(
                &if failed > 0 {
                    format!("{label} ({failed} failed)")
                } else {
                    label.to_string()
                },
                &s,
                t.elapsed(),
            );
        }

        let mut s = Samples::default();
        let t = Instant::now();
        let mut cursor: Option<String> = None;
        loop {
            let mut args = json!({"limit": 200});
            if let Some(c) = &cursor {
                args["cursor"] = json!(c);
            }
            let t0 = Instant::now();
            let Ok(page) = rig.call("strings", args) else {
                break;
            };
            s.push(t0.elapsed());
            cursor = page["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() || s.0.len() >= 50 {
                break;
            }
        }
        row("strings (first 50 pages of 200)", &s, t.elapsed());

        // an edit and its undo: a structural edit rebuilds the reference index
        if let Some(a) = picks.first() {
            let mut s = Samples::default();
            let t = Instant::now();
            for new_name in ["bench_renamed_a", "bench_renamed_b"] {
                let t0 = Instant::now();
                let _ = rig.call("rename_symbol", json!({"address": a, "new_name": new_name}));
                s.push(t0.elapsed());
            }
            row("rename_symbol", &s, t.elapsed());
            let mut s = Samples::default();
            let t = Instant::now();
            for _ in 0..2 {
                let t0 = Instant::now();
                let _ = rig.call("undo", json!({}));
                s.push(t0.elapsed());
            }
            row("undo", &s, t.elapsed());
        }

        if let Some(pid) = rig.pid {
            let mb = |kb: Option<u64>| kb.unwrap_or(0) as f64 / 1024.0;
            println!(
                "\nafter the first open: krakend RSS {:.0} MB; native workers: {}",
                mb(status_kb(pid, "VmRSS:")),
                workers(pid)
                    .iter()
                    .map(|w| format!(
                        "{:.0} MB (peak {:.0} MB)",
                        mb(status_kb(*w, "VmRSS:")),
                        mb(status_kb(*w, "VmHWM:"))
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // a new daemon: the project opens again from the state the first open saved
        generation += 1;
        drop(rig);
        let rig = Rig::start(&rt, tmp.path(), &krakend, generation);
        let t = Instant::now();
        let reopened = rig.call("project_open", json!({"project_dir": project}));
        one(
            if reopened.is_ok() {
                "project_open (new daemon, saved state)"
            } else {
                "project_open (new daemon, FAILED)"
            },
            t.elapsed(),
        );

        // the command line client: a process per command, talking to the same daemon
        let cli = krakend.with_file_name("kraken");
        if cli.is_file() {
            let mut s = Samples::default();
            let t = Instant::now();
            for _ in 0..20 {
                let t0 = Instant::now();
                let _ = std::process::Command::new(&cli)
                    .args(["--json", "--project"])
                    .arg(&project)
                    .arg("project-info")
                    .env("KRAKEN_RUNTIME_DIR", &rig.runtime_dir)
                    .env("KRAKEN_CONFIG", &rig.config)
                    .output();
                s.push(t0.elapsed());
            }
            row(
                "kraken --json project-info (process per call)",
                &s,
                t.elapsed(),
            );
            let mut s = Samples::default();
            let t = Instant::now();
            for a in picks.iter().take(20) {
                let t0 = Instant::now();
                let _ = std::process::Command::new(&cli)
                    .args(["--json", "--project"])
                    .arg(&project)
                    .args(["decompile", "--address", a])
                    .env("KRAKEN_RUNTIME_DIR", &rig.runtime_dir)
                    .env("KRAKEN_CONFIG", &rig.config)
                    .output();
                s.push(t0.elapsed());
            }
            row(
                "kraken --json decompile (process per call)",
                &s,
                t.elapsed(),
            );
        }

        // the view-model, as the GUI uses it: selecting a function until its panels are ready
        let mut vm = ViewModel::new(rig.backend.clone(), rt.handle().clone());
        vm.open_project(project.to_string_lossy().into_owned());
        let t = Instant::now();
        let opened = vm.block_until(SLOW, |v| {
            !matches!(v.connection, Connection::Opening(_)) && !v.busy()
        });
        one(
            if opened && vm.connection == Connection::Open {
                "view-model: open project (first page of functions)"
            } else {
                "view-model: open project (FAILED)"
            },
            t.elapsed(),
        );
        let mut s_dec = Samples::default();
        let mut s_all = Samples::default();
        let t = Instant::now();
        for a in picks.iter().take(30) {
            let Ok(offset) = u64::from_str_radix(a.trim_start_matches("0x"), 16) else {
                continue;
            };
            let t0 = Instant::now();
            vm.select_function(offset);
            vm.ensure_graph();
            vm.ensure_xrefs();
            let dec_at = std::cell::Cell::new(None);
            vm.block_until(Duration::from_secs(300), |v| {
                if dec_at.get().is_none()
                    && v.current
                        .as_ref()
                        .is_some_and(|c| c.address == offset && c.decompiled.ready().is_some())
                {
                    dec_at.set(Some(t0.elapsed()));
                }
                !v.busy()
            });
            s_dec.push(dec_at.get().unwrap_or_else(|| t0.elapsed()));
            s_all.push(t0.elapsed());
        }
        row("view-model: select, decompiler ready", &s_dec, t.elapsed());
        row("view-model: select, all panels ready", &s_all, t.elapsed());
    }
}
