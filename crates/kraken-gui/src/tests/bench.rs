//! GUI frame times while browsing a large binary through a real `krakend` with the native
//! engine. `#[ignore]`: run with `cargo xtask bench gui [binary...]` (see `docs/performance.md`).
//! Every phase prints the cost of a frame (the whole app: layout, painting into egui's shapes,
//! the view-model's polling) as p50 / p95 / max in milliseconds. 16.7 ms is 60 frames a second.

use std::path::PathBuf;

use egui::{MouseWheelUnit, vec2};
use kraken_host::daemon::{StartOptions, find_krakend};
use kraken_ipc::RuntimeDir;
use kraken_viewmodel::{Backend, BackendOptions, DaemonClientBackend, start_connector};
use serde_json::json;

use super::*;

fn bins() -> Vec<PathBuf> {
    match std::env::var("KRAKEN_BENCH_BINS") {
        Ok(v) => v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => [
            "/usr/lib/libpython3.14.so.1.0",
            "/usr/lib/libQt6Widgets.so.6",
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .collect(),
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn pct(v: &mut [Duration], p: f64) -> f64 {
    v.sort();
    v.get(((v.len().max(1) - 1) as f64 * p).round() as usize)
        .map_or(0.0, |d| ms(*d))
}

fn report(phase: &str, v: &mut [Duration]) {
    let total: Duration = v.iter().sum();
    println!(
        "| {phase} | {} | {:.2} | {:.2} | {:.2} | {:.0} |",
        v.len(),
        pct(v, 0.5),
        pct(v, 0.95),
        pct(v, 1.0),
        ms(total)
    );
}

impl Harness {
    fn timed_frame(&mut self, events: Vec<Event>) -> Duration {
        let t = Instant::now();
        self.step_with(events);
        t.elapsed()
    }

    /// `n` frames, each given the events of `events(i)`.
    fn frames(
        &mut self,
        phase: &str,
        n: usize,
        events: impl Fn(usize) -> Vec<Event>,
    ) -> Vec<Duration> {
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(self.timed_frame(events(i)));
        }
        report(phase, &mut v);
        v
    }
}

fn wheel(x: f32, y: f32, dy: f32) -> Vec<Event> {
    vec![
        Event::PointerMoved(pos2(x, y)),
        Event::MouseWheel {
            unit: MouseWheelUnit::Point,
            delta: vec2(0.0, dy),
            phase: egui::TouchPhase::Move,
            modifiers: Modifiers::NONE,
        },
    ]
}

#[test]
#[ignore = "benchmark; run explicitly"]
fn bench_gui() {
    let Ok(krakend) = find_krakend() else {
        eprintln!("skipped: no krakend (cargo build --release -p krakend -p engine-native)");
        return;
    };
    let worker = krakend.with_file_name("kraken-native-worker");
    if !worker.is_file() {
        eprintln!("skipped: no kraken-native-worker next to krakend");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("kg")
        .tempdir_in("/tmp")
        .expect("temp dir");
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "").expect("config");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let start = StartOptions {
        krakend: Some(krakend),
        env: vec![
            ("KRAKEN_RUNTIME_DIR".into(), dir.path().into()),
            ("KRAKEN_CONFIG".into(), config.clone().into()),
            ("KRAKEN_DAEMON_IDLE_SECS".into(), "86400".into()),
            ("KRAKEN_NATIVE_WORKER".into(), worker.into()),
        ],
        timeout: Duration::from_secs(60),
        ..Default::default()
    };
    let connector = start_connector(dir.clone(), start);
    let mut services = Services::offline();
    services.connector = Some(connector.clone());
    services.prefs_file = Some(tmp.path().join("cfg/gui.json"));
    let mut h = Harness::with_services(false, services);
    // the project is made through a client of the benchmark; the GUI then opens it
    let backend = h
        ._rt
        .block_on(DaemonClientBackend::connect(
            connector,
            BackendOptions::default(),
        ))
        .expect("the client reaches krakend");
    let backend = Arc::new(backend);

    for src in bins() {
        let name = src.file_name().unwrap().to_string_lossy().to_string();
        let copy = tmp.path().join(&name);
        std::fs::copy(&src, &copy).expect("copy");
        let project = tmp.path().join(format!("proj-{name}"));
        let t = Instant::now();
        let created = h._rt.block_on(backend.call(
            "project_create",
            json!({"binary": copy, "project_dir": project, "engine": "native"}),
        ));
        println!("\n### {name}: GUI frame times (native engine through krakend)\n");
        if let Err(e) = created {
            println!("project_create failed: {e:?}");
            continue;
        }
        println!(
            "project_create through the daemon: {:.0} ms\n",
            ms(t.elapsed())
        );
        // the largest function, found with plain queries
        let mut biggest = (0u64, 0u64);
        let mut cursor: Option<String> = None;
        loop {
            let mut args = json!({"limit": 200});
            if let Some(c) = &cursor {
                args["cursor"] = json!(c);
            }
            let Ok(page) = h._rt.block_on(backend.call("list_functions", args)) else {
                break;
            };
            for it in page["items"].as_array().into_iter().flatten() {
                let size = it["size"].as_u64().unwrap_or(0);
                let a = it["locator"]["offset"]
                    .as_str()
                    .or_else(|| it["address"].as_str())
                    .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok());
                if let Some(a) = a
                    && size > biggest.1
                {
                    biggest = (a, size);
                }
            }
            cursor = page["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        println!("largest function: {:#x}, {} bytes\n", biggest.0, biggest.1);
        println!("| phase | frames | p50 ms | p95 ms | max ms | total ms |");
        println!("|---|---:|---:|---:|---:|---:|");

        let ctx = h.ctx.clone();
        h.app
            .start_real(Choice::OpenProject(project.to_string_lossy().into()), &ctx);
        let mut open = Vec::new();
        let t = Instant::now();
        while !h.app.view_model().is_some_and(|vm| {
            vm.connection == Connection::Open && !vm.functions.items.is_empty() && !vm.busy()
        }) {
            assert!(t.elapsed() < Duration::from_secs(3600), "project opens");
            open.push(h.timed_frame(Vec::new()));
            std::thread::sleep(Duration::from_millis(2));
        }
        let opened = t.elapsed();
        report("frames while opening", &mut open);
        h.frames("idle, function list", 100, |_| Vec::new());
        let before = h.app.view_model().unwrap().functions.items.len();
        h.frames("scroll the function list (wheel, 300 frames)", 300, |i| {
            wheel(110.0, 400.0, if i % 2 == 0 { -240.0 } else { -120.0 })
        });
        let after = h.app.view_model().unwrap().functions.items.len();
        h.frames("scroll the function list back up", 100, |_| {
            wheel(110.0, 400.0, 500.0)
        });

        // a big function in the decompiler and the listing
        let t = Instant::now();
        h.app.view_model_mut().unwrap().select_function(biggest.0);
        let mut waiting = Vec::new();
        while !h.app.view_model().is_some_and(|vm| {
            vm.current
                .as_ref()
                .is_some_and(|c| c.address == biggest.0 && matches!(c.decompiled, Load::Ready(_)))
                && !vm.busy()
        }) {
            assert!(t.elapsed() < Duration::from_secs(900), "decompiles");
            waiting.push(h.timed_frame(Vec::new()));
            std::thread::sleep(Duration::from_millis(2));
        }
        let decompiled = t.elapsed();
        report("frames while it decompiles", &mut waiting);
        h.frames("idle, large function", 100, |_| Vec::new());
        h.frames("scroll the decompiler (200 frames)", 200, |i| {
            wheel(420.0, 250.0, if i < 100 { -200.0 } else { 200.0 })
        });
        h.frames("scroll the listing (200 frames)", 200, |i| {
            wheel(950.0, 650.0, if i < 100 { -200.0 } else { 200.0 })
        });

        // the graph of the large function, next to the decompiler
        h.app.set_dock(workspace::graph_dock());
        h.app.bring_to_front(Tab::Graph);
        let t = Instant::now();
        h.step();
        h.app.view_model_mut().unwrap().ensure_graph();
        let mut loading = Vec::new();
        while t.elapsed() < Duration::from_secs(120)
            && !h
                .app
                .view_model()
                .is_some_and(|vm| vm.views.graph.data.is_some() && !vm.busy())
        {
            loading.push(h.timed_frame(Vec::new()));
            std::thread::sleep(Duration::from_millis(2));
        }
        let graph_ready = t.elapsed();
        let blocks = h
            .app
            .view_model()
            .and_then(|vm| vm.views.graph.data.as_ref().map(|g| g.blocks.len()))
            .unwrap_or(0);
        report("frames while the graph loads", &mut loading);
        h.frames("graph, laying out (20 ms apart)", 30, |_| {
            std::thread::sleep(Duration::from_millis(20));
            Vec::new()
        });
        h.frames("graph, steady", 100, |_| {
            vec![Event::PointerMoved(pos2(900.0, 350.0))]
        });
        h.frames("graph, zoom in and out", 100, |i| {
            vec![
                Event::PointerMoved(pos2(900.0, 350.0)),
                Event::Zoom(if i % 2 == 0 { 1.05 } else { 0.95 }),
            ]
        });
        h.frames("graph, pan by wheel", 100, |_| wheel(900.0, 350.0, -30.0));
        h.app.set_dock(workspace::initial_dock());
        h.frames("back to the default layout", 30, |_| Vec::new());

        println!(
            "\nopen in the GUI (project_open and the first page of functions): {:.0} ms",
            ms(opened)
        );
        println!("functions loaded by scrolling: {before} -> {after}");
        println!(
            "largest function selected until decompiled: {:.0} ms",
            ms(decompiled)
        );
        println!(
            "graph of the largest function: {blocks} blocks, data ready after {:.0} ms",
            ms(graph_ready)
        );
    }
    // stop the private daemon (it would otherwise idle for a day)
    let _ = h._rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), backend.shutdown_daemon()).await
    });
}

/// The function list with as many rows as the biggest programs have, in the demo project (no
/// engine): what a frame costs when the list is long and fully loaded.
#[test]
#[ignore = "benchmark; run explicitly"]
fn bench_gui_long_function_list() {
    println!("\n### GUI frame times with a long function list (demo project)\n");
    println!("| phase | frames | p50 ms | p95 ms | max ms | total ms |");
    println!("|---|---:|---:|---:|---:|---:|");
    for n in [1_000usize, 50_000, 200_000] {
        let mut h = Harness::ready_demo();
        {
            let vm = h.app.view_model_mut().unwrap();
            vm.functions.items = (0..n as u64)
                .map(|i| kraken_viewmodel::FunctionItem {
                    address: 0x10_0000 + i * 16,
                    name: format!("FUN_{:08x}", 0x10_0000 + i * 16),
                    size: Some(16),
                    signature: None,
                    partial: false,
                    stub: i % 50 == 0,
                })
                .collect();
            vm.functions.next_cursor = None;
            vm.functions.total = Some(n as u64);
        }
        h.frames(&format!("{n} functions, idle"), 100, |_| Vec::new());
        h.frames(&format!("{n} functions, scrolling"), 300, |i| {
            wheel(110.0, 400.0, if i % 3 == 0 { -400.0 } else { -150.0 })
        });
        h.app
            .view_model_mut()
            .unwrap()
            .select_function(0x10_0000 + (n as u64 / 2) * 16);
        h.frames(&format!("{n} functions, one selected"), 100, |_| Vec::new());
    }
}
