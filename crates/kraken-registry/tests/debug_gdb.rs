//! `debug_gdb_serve`: a corpus program's debug session driven over the GDB remote protocol, by a
//! minimal RSP client and (when installed) by the real gdb.
#![cfg(unix)]

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use kraken_proto::ErrorCode;
use serde_json::json;

fn runner() -> PathBuf {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("exe");
    let dir = exe.parent().and_then(Path::parent).expect("target dir");
    dir.join("kraken-emu-run")
}

struct Rsp(UnixStream);

impl Rsp {
    fn connect(path: &str) -> Rsp {
        let s = UnixStream::connect(path).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");
        Rsp(s)
    }

    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.0.read_exact(&mut b).expect("read");
        b[0]
    }

    /// Sends one packet and returns the reply payload.
    fn call(&mut self, payload: &str) -> String {
        let sum = payload.bytes().fold(0u8, |a, b| a.wrapping_add(b));
        write!(self.0, "${payload}#{sum:02x}").expect("write");
        loop {
            match self.byte() {
                b'$' => break,
                b'+' => {}
                other => panic!("unexpected byte {other:#x}"),
            }
        }
        let mut body = Vec::new();
        loop {
            let b = self.byte();
            if b == b'#' {
                break;
            }
            body.push(b);
        }
        self.byte();
        self.byte();
        let _ = self.0.write_all(b"+");
        // Run-length encoding: `c*n` repeats `c` another n - 29 times.
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            if body[i] == b'*' && i + 1 < body.len() {
                let last = *out.last().expect("a byte before *");
                out.extend(std::iter::repeat_n(last, usize::from(body[i + 1] - 29)));
                i += 2;
            } else {
                out.push(body[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("utf8")
    }
}

/// A little-endian register of `bytes` bytes at `index` in the 'g' reply of x86-64 slots.
fn le_hex(g: &str, byte_offset: usize, bytes: usize) -> u64 {
    let mut v = 0u64;
    for i in (0..bytes).rev() {
        let at = (byte_offset + i) * 2;
        v = v << 8 | u64::from_str_radix(&g[at..at + 2], 16).expect("hex");
    }
    v
}

#[tokio::test]
#[ignore = "needs KRAKEN_NATIVE_SPECS=~/.cache/kraken-dev/native-sla/Ghidra_12.2_build, Landlock \
            and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn gdb_reads_registers_sets_a_breakpoint_and_hits_it() {
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/static_strops-O0"),
        &env.binary,
    )
    .expect("copy corpus binary");
    // SAFETY: this test is the only one in the binary that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let u = user();

    let id = env.ok(&u, "debug_start", json!({"argv": ["x"]})).await["session"]
        .as_u64()
        .expect("session");
    let main = env
        .ok(
            &u,
            "debug_break_set",
            json!({"session": id, "symbol": "main"}),
        )
        .await["breakpoints"][0]
        .as_str()
        .expect("main")
        .to_string();
    env.ok(
        &u,
        "debug_break_remove",
        json!({"session": id, "address": main}),
    )
    .await;
    let main_addr = u64::from_str_radix(main.trim_start_matches("0x"), 16).expect("hex");

    let served = env
        .ok(&u, "debug_gdb_serve", json!({"session": id, "tcp": true}))
        .await;
    let socket = served["socket"].as_str().expect("socket").to_string();
    assert!(
        served["gdb_command"]
            .as_str()
            .expect("cmd")
            .contains(&socket),
        "{served}"
    );
    assert!(served["tcp_port"].as_u64().is_some(), "{served}");
    let again = env.ok(&u, "debug_gdb_serve", json!({"session": id})).await;
    assert_eq!(again["socket"], served["socket"]);
    let e = env.err(&u, "debug_gdb_serve", json!({"session": 99})).await;
    assert_eq!(e.code, ErrorCode::NotFound);

    let mut c = Rsp::connect(&socket);
    let sup = c.call("qSupported:swbreak+;hwbreak+;xmlRegisters=i386");
    assert!(sup.contains("qXfer:features:read+"), "{sup}");
    assert!(sup.contains("swbreak+"), "{sup}");
    let xml = c.call("qXfer:features:read:target.xml:0,fff");
    assert!(
        xml.contains("i386:x86-64") || xml.contains("<architecture>"),
        "{xml}"
    );
    assert!(c.call("?").starts_with('T') || c.call("?").starts_with('S'));

    // rax..r15 are 17 * 8 bytes with rip last; at the start rip is the entry point.
    let g = c.call("g");
    let entry = le_hex(&g, 16 * 8, 8);
    assert_ne!(entry, 0, "{g}");
    assert_ne!(entry, main_addr);
    let mem = c.call(&format!("m{entry:x},4"));
    assert_eq!(mem.len(), 8, "{mem}");

    assert_eq!(c.call(&format!("Z0,{main_addr:x},1")), "OK");
    let stop = c.call("c");
    assert!(stop.starts_with("T05"), "{stop}");
    assert!(stop.contains("swbreak"), "{stop}");
    let g = c.call("g");
    assert_eq!(le_hex(&g, 16 * 8, 8), main_addr, "stopped at main");

    // The same stop through the ordinary commands.
    let state = env.ok(&u, "debug_state", json!({"session": id})).await;
    assert_eq!(state["pc"], json!(main));

    let step = c.call("s");
    assert!(step.starts_with("T05") || step == "S05", "{step}");
    let g = c.call("g");
    assert_ne!(le_hex(&g, 16 * 8, 8), main_addr);

    // A register write and a memory write land in the guest.
    let rax = "efbeadde00000000";
    assert_eq!(c.call(&format!("P0={rax}")), "");
    let mut g2 = g.clone();
    g2.replace_range(0..16, rax);
    assert_eq!(c.call(&format!("G{g2}")), "OK");
    assert_eq!(le_hex(&c.call("g"), 0, 8), 0xdead_beef);
    let sp = le_hex(&c.call("g"), 7 * 8, 8);
    assert_eq!(c.call(&format!("M{:x},2:abcd", sp - 64)), "OK");
    assert_eq!(c.call(&format!("m{:x},2", sp - 64)), "abcd");

    assert_eq!(c.call(&format!("z0,{main_addr:x},1")), "OK");
    let end = c.call("c");
    assert!(end.starts_with('W'), "{end}");
    let state = env.ok(&u, "debug_state", json!({"session": id})).await;
    assert_eq!(state["finished"], true, "{state}");
    env.ok(&u, "debug_stop", json!({"session": id})).await;
}

#[tokio::test]
#[ignore = "needs KRAKEN_NATIVE_SPECS, Landlock, kraken-emu-run and gdb"]
async fn real_gdb_stops_at_main() {
    if !Path::new("/usr/bin/gdb").exists() {
        eprintln!("gdb is not installed; skipping");
        return;
    }
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/static_strops-O0"),
        &env.binary,
    )
    .expect("copy corpus binary");
    // SAFETY: this test is the only one in the binary that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let u = user();
    let id = env.ok(&u, "debug_start", json!({"argv": ["x"]})).await["session"]
        .as_u64()
        .expect("session");
    let main = env
        .ok(
            &u,
            "debug_break_set",
            json!({"session": id, "symbol": "main"}),
        )
        .await["breakpoints"][0]
        .as_str()
        .expect("main")
        .to_string();
    env.ok(
        &u,
        "debug_break_remove",
        json!({"session": id, "address": main}),
    )
    .await;
    let served = env
        .ok(&u, "debug_gdb_serve", json!({"session": id, "tcp": true}))
        .await;
    let port = served["tcp_port"].as_u64().expect("port");
    let binary = env.binary.clone();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/usr/bin/gdb")
            .args(["-batch", "-nx"])
            .arg(&binary)
            .arg("-ex")
            .arg(format!("target remote 127.0.0.1:{port}"))
            .args(["-ex", &format!("break *{main}"), "-ex", "continue"])
            .args([
                "-ex",
                "info registers rip",
                "-ex",
                "x/2i $pc",
                "-ex",
                "detach",
            ])
            .output()
            .expect("gdb")
    })
    .await
    .expect("join");
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{text}");
    assert!(text.contains("Breakpoint 1, "), "{text}");
    assert!(text.contains("<main"), "{text}");
}
