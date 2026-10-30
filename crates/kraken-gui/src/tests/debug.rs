//! The Debug tab with a live emulator session on a corpus program.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kraken_viewmodel::debug::DebugStep;
use kraken_viewmodel::{AnalysisPhase, Connection};

use super::shell::{Kit, kit_with};
use crate::workspace::Tab;

fn until(k: &mut Kit, what: &str, cond: impl Fn(&crate::app::KrakenApp) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        k.h.run_steps(1);
        if cond(k.h.state()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; the debug panel says {:?}",
            k.h.state().view_model().map(|vm| (
                vm.debug.status.clone(),
                vm.debug.error.clone(),
                vm.debug.busy
            ))
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn vm(k: &mut Kit) -> &mut kraken_viewmodel::ViewModel {
    k.h.state_mut().view_model_mut().expect("view model")
}

fn save(k: &mut Kit, dir: &Path, name: &str) {
    k.h.state_mut().hide_notices();
    k.h.run_steps(6);
    let img = k.h.render().expect("render");
    let path = dir.join(name);
    std::fs::create_dir_all(dir).expect("dir");
    img.save(&path).expect("save png");
    println!("saved {}", path.display());
}

/// Needs the SLEIGH tree (`KRAKEN_NATIVE_SPECS`), Landlock and
/// `cargo build -p kraken-emu --bin kraken-emu-run`. With `KRAKEN_SHOT_DIR` set it renders on the
/// GPU and saves `debug-main.png` and `debug-done.png` there.
#[test]
#[ignore = "needs the SLEIGH specs, Landlock and the kraken-emu-run binary"]
fn the_debug_tab_steps_a_live_program() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runner = std::env::var_os("KRAKEN_EMU_RUN")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/debug/kraken-emu-run"));
    assert!(runner.is_file(), "build kraken-emu-run first");
    // SAFETY: set before the harness starts any thread; the test is ignored by default and the
    // only one that touches these variables.
    unsafe {
        std::env::set_var("KRAKEN_EMU_RUN", &runner);
        std::env::set_var(
            "KRAKEN_DEMO_BINARY",
            root.join("corpus/bin/static_strops-O0"),
        );
    }
    let shots = std::env::var_os("KRAKEN_SHOT_DIR").map(PathBuf::from);
    let mut k = kit_with(true, shots.is_some());
    until(&mut k, "the demo to load", |a| {
        a.view_model().is_some_and(|vm| {
            vm.connection == Connection::Open
                && vm.analysis.phase == AnalysisPhase::Complete
                && !vm.functions.items.is_empty()
                && !vm.busy()
        })
    });

    vm(&mut k).show_debug();
    k.h.run_steps(4);
    assert!(k.h.state().dock().find_tab(&Tab::Debug).is_some());

    vm(&mut k).debug_start();
    until(&mut k, "the session to start", |a| {
        a.view_model()
            .is_some_and(|vm| vm.debug.session.is_some() && !vm.debug.regs.is_empty())
    });
    let entry = vm(&mut k).debug.pc;

    vm(&mut k).debug_run_to_main();
    until(&mut k, "main", |a| {
        a.view_model()
            .is_some_and(|vm| !vm.debug.busy && vm.debug.status.starts_with("Reached"))
    });
    until(&mut k, "main's registers and disassembly", |a| {
        a.view_model().is_some_and(|vm| {
            vm.debug
                .disasm
                .first()
                .is_some_and(|i| i.is_pc && i.address == vm.debug.pc)
        })
    });
    let (main_pc, second) = {
        let d = &vm(&mut k).debug;
        assert_ne!(d.pc, entry);
        (d.pc, d.disasm[1].address)
    };
    assert!(!vm(&mut k).debug.regs.is_empty());
    assert!(!vm(&mut k).debug.memory.bytes.is_empty(), "the stack dump");
    // Breakpoints toggle (as the context menu and F9 do) and the listing row follows.
    vm(&mut k).debug_toggle_breakpoint(second);
    assert!(vm(&mut k).debug.has_breakpoint(second));
    if let Some(dir) = &shots {
        save(&mut k, dir, "debug-main.png");
    }

    // "Attach gdb..." serves the session and shows the commands.
    vm(&mut k).debug_gdb_serve();
    until(&mut k, "the gdb server", |a| {
        a.view_model().is_some_and(|vm| vm.debug.gdb.is_some())
    });
    {
        let g = vm(&mut k).debug.gdb.clone().expect("gdb");
        assert!(g.gdb_command.contains(&g.socket), "{g:?}");
        let port = g.tcp_port.expect("port");
        assert_eq!(
            g.gdb_tcp_command.as_deref(),
            Some(format!("gdb -ex 'target remote 127.0.0.1:{port}'").as_str())
        );
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    }
    k.h.run_steps(4);
    if let Some(dir) = &shots {
        save(&mut k, dir, "debug-gdb.png");
    }

    vm(&mut k).debug_step(DebugStep::Continue);
    until(&mut k, "the breakpoint", |a| {
        a.view_model()
            .is_some_and(|vm| !vm.debug.busy && vm.debug.status.starts_with("Hit a breakpoint"))
    });
    assert_eq!(vm(&mut k).debug.pc, second);
    assert_ne!(second, main_pc);

    vm(&mut k).debug_toggle_breakpoint(second);
    vm(&mut k).debug_step(DebugStep::Continue);
    until(&mut k, "the program to end", |a| {
        a.view_model().is_some_and(|vm| vm.debug.finished)
    });
    assert!(vm(&mut k).debug.stdout.contains("hash=6490"));
    k.h.run_steps(4);
    if let Some(dir) = &shots {
        save(&mut k, dir, "debug-done.png");
    }
    vm(&mut k).debug_stop();
    until(&mut k, "the session to end", |a| {
        a.view_model().is_some_and(|vm| vm.debug.session.is_none())
    });
}
