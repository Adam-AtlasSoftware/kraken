//! Smoke test of the shim against the corpus. Needs the native build and a Ghidra install for the
//! `.sla` files (`KRAKEN_GHIDRA_HOME` or `~/.cache/kraken-dev/ghidra/*`); skips otherwise.

use std::path::{Path, PathBuf};

use std::sync::atomic::Ordering;
use std::time::Duration;

use engine_native_sys::{Flow, Image, NativeError, RefKind, Segment, Session, TokenKind};

fn ghidra_home() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_GHIDRA_HOME") {
        return Some(PathBuf::from(p));
    }
    let dir = PathBuf::from(std::env::var_os("HOME")?).join(".cache/kraken-dev/ghidra");
    let mut kids: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.join("Ghidra/Processors/x86/data/languages/x86-64.sla")
                .is_file()
        })
        .collect();
    kids.sort();
    kids.pop()
}

fn session() -> Option<Session> {
    if !engine_native_sys::available() {
        eprintln!("skipped: built without the native decompiler");
        return None;
    }
    let Some(home) = ghidra_home() else {
        eprintln!("skipped: no Ghidra install with .sla files");
        return None;
    };
    engine_native_sys::start(&home).expect("start");
    assert!(engine_native_sys::has_language("x86:LE:64:default").expect("languages"));
    // pie_list's text segment has file offset == virtual address, so mapping the file at 0 is
    // enough to reach its code
    let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/pie_list-O0");
    let data = std::fs::read(bin).expect("corpus binary");
    let img = Image {
        segments: vec![Segment {
            start: 0,
            mem_size: data.len() as u64,
            data,
            readonly: true,
        }],
    };
    Some(Session::new("x86:LE:64:default", "gcc", img).expect("session"))
}

#[test]
fn decodes_and_decompiles_cmp_id() {
    let Some(mut s) = session() else { return };
    s.add_function(0x124e, "cmp_id").expect("symbol");
    let insns = s.decode(0x124e, 64).expect("decode");
    assert!(!insns.is_empty());
    assert_eq!(insns[0].addr, 0x124e);
    assert!(insns.iter().any(|i| i.flow == Flow::Return), "{insns:#?}");

    let ops = s.lift(0x124e, 0x124e + 30).expect("lift");
    assert!(ops.iter().any(|o| o.opcode == "INT_SUB"), "{ops:#?}");

    let d = s.decompile(0x124e, None).expect("decompile");
    eprintln!("{}", d.text);
    assert!(d.text.contains("cmp_id"));
    assert!(d.text.contains("return"));
    for t in &d.tokens {
        assert!(t.start <= t.end && (t.end as usize) <= d.text.len());
        assert!(d.text.is_char_boundary(t.start as usize));
    }
    let f = d
        .tokens
        .iter()
        .find(|t| t.kind == TokenKind::Function)
        .expect("function token");
    assert_eq!(f.symbol.as_deref(), Some("cmp_id"));
    assert_eq!(f.target, Some(0x124e));
    // twice in a row works (analysis state is cleared between runs)
    let again = s.decompile(0x124e, None).expect("decompile again");
    assert_eq!(again.text, d.text);
}

#[test]
fn two_sessions_coexist() {
    let (Some(mut a), Some(mut b)) = (session(), session()) else {
        return;
    };
    let x = a.decompile(0x124e, None).expect("a");
    let y = b.decompile(0x124e, None).expect("b");
    assert_eq!(x.text, y.text);
    drop(a);
    assert!(b.decompile(0x126c, None).is_ok());
}

#[test]
fn references_are_typed() {
    let Some(mut s) = session() else { return };
    // main of pie_list (linked at 0): `movsd xmm0, [rip+..]` reads a double from .rodata and
    // `lea rax, [rip+..]` takes the address of the string "gamma"
    let insns = s.decode(0x14da, 64).expect("decode");
    let refs: Vec<_> = insns.iter().flat_map(|i| i.refs.iter().copied()).collect();
    assert!(
        refs.iter()
            .any(|r| r.addr == 0x2070 && r.kind == RefKind::Read),
        "{refs:x?}"
    );
    assert!(
        refs.iter()
            .any(|r| r.addr == 0x2021 && r.kind == RefKind::Data),
        "{refs:x?}"
    );
}

#[test]
fn stop_flag_and_timeout_abandon_a_decompile() {
    let Some(mut s) = session() else { return };
    let stop = s.stop_flag();
    stop.store(true, Ordering::Relaxed);
    assert_eq!(
        s.decompile(0x14da, None).unwrap_err(),
        NativeError::Interrupted
    );
    stop.store(false, Ordering::Relaxed);
    // the abandoned analysis leaves no state behind
    let full = s
        .decompile(0x14da, None)
        .expect("decompile after an interrupt");
    assert!(full.text.contains("return"), "{}", full.text);
    // main takes several milliseconds, far more than the limit
    let r = s.decompile(0x14da, Some(Duration::from_millis(1)));
    assert!(matches!(r, Err(NativeError::Timeout(_))), "{r:?}");
    assert_eq!(s.decompile(0x14da, None).expect("again").text, full.text);
}

#[test]
fn prototypes_and_types_reach_the_output() {
    let Some(mut s) = session() else { return };
    s.add_function(0x124e, "cmp_id").expect("symbol");
    s.add_function(0x1050, "printf").expect("symbol");
    s.declare_type("struct record { int id; char name[12]; };")
        .expect("struct");
    s.declare_type("typedef record record_t;").expect("typedef");
    s.set_prototype(0x124e, "int cmp_id(record_t *a,record_t *b)")
        .expect("prototype");
    let d = s.decompile(0x124e, None).expect("decompile");
    assert!(d.text.contains("record_t *a"), "{}", d.text);
    assert!(d.text.contains("->id"), "{}", d.text);

    s.set_prototype(0x1050, "int printf(char *format,...)")
        .expect("printf");
    let main = s.decompile(0x14da, None).expect("main");
    assert!(main.text.contains("printf(\""), "{}", main.text);
    assert!(
        s.set_prototype(0x1050, "int printf(no_such_type x)")
            .is_err()
    );
}
