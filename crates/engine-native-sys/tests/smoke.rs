//! Smoke test of the shim against the corpus. Needs the native build and a Ghidra install for the
//! `.sla` files (`KRAKEN_GHIDRA_HOME` or `~/.cache/kraken-dev/ghidra/*`); skips otherwise.

use std::path::{Path, PathBuf};

use engine_native_sys::{Flow, Image, Segment, Session, TokenKind};

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

    let d = s.decompile(0x124e).expect("decompile");
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
    let again = s.decompile(0x124e).expect("decompile again");
    assert_eq!(again.text, d.text);
}

#[test]
fn two_sessions_coexist() {
    let (Some(mut a), Some(mut b)) = (session(), session()) else {
        return;
    };
    let x = a.decompile(0x124e).expect("a");
    let y = b.decompile(0x124e).expect("b");
    assert_eq!(x.text, y.text);
    drop(a);
    assert!(b.decompile(0x126c).is_ok());
}
