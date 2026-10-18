//! Function-level calls on every architecture: functions of the cross-architecture corpus (by
//! their symbols, which the truth files list) called with arguments under each C calling
//! convention, compared with the x86-64 build's results; and hand-assembled snippets that pass
//! and return `double`s and 64-bit integers.

mod common;

use common::*;
use kraken_emu::call::{
    CallOutcome, CallSpec, CallTermination, Callee, FunctionCaller, RetKind, Value,
};
use kraken_emu::{Arch, SpecRoots};

const BUDGET: u64 = 1_000_000;

fn caller(path: &std::path::Path) -> FunctionCaller {
    let data = std::fs::read(path).expect("read");
    let arch = Arch::from_elf(&data).expect("arch");
    FunctionCaller::load_elf(&data, 0x5555_5555_0000, &specs(arch)).expect("load")
}

fn call(fc: &mut FunctionCaller, sym: &str, args: Vec<Value>, ret: RetKind) -> CallOutcome {
    let out = fc
        .call(&CallSpec {
            callee: Callee::Symbol(sym.into()),
            args,
            ret,
            max_instructions: BUDGET,
        })
        .unwrap_or_else(|e| panic!("{sym}: {e}"));
    assert_eq!(out.termination, CallTermination::Returned, "{sym}: {out:?}");
    out
}

fn int(v: i32) -> Value {
    Value::i32(v)
}

fn u32v(v: u32) -> Value {
    Value::Int {
        bits: 32,
        signed: false,
        value: u64::from(v),
    }
}

/// What the switch_vm checks observe: per program, the result and the VM's `sp`, `pc` and
/// `steps` afterwards.
fn switch_vm_results(path: &std::path::Path) -> Vec<(u64, u32, u32, u32)> {
    let mut fc = caller(path);
    let arch = fc.machine().arch();
    let programs: [&[u8]; 3] = [
        &[1, 5, 1, 7, 2, 1, 3, 4, 0],
        &[1, 10, 10, 5, 9, 2, 0],
        &[1, 0xfb, 8, 1, 4, 3, 0],
    ];
    let mut out = Vec::new();
    for code in programs {
        fc.reset().expect("reset");
        let vm = fc.alloc(&[0u8; 144]).expect("vm");
        let c = fc.alloc(code).expect("code");
        let r = call(
            &mut fc,
            "vm_run",
            vec![
                Value::ptr(arch, vm),
                Value::ptr(arch, c),
                u32v(code.len() as u32),
            ],
            RetKind::Int { bits: 32 },
        );
        let m = fc.machine();
        let sp = m.read_uint(vm + 128, 4).expect("sp") as u32;
        let pc = m.read_uint(vm + 132, 4).expect("pc") as u32;
        let steps = m.read_uint(vm + 136, 4).expect("steps") as u32;
        out.push((r.ret.expect("ret"), sp, pc, steps));
    }
    out
}

fn op_names(path: &std::path::Path) -> Vec<String> {
    let mut fc = caller(path);
    let mut out = Vec::new();
    for op in [0u32, 2, 11, 14, 99] {
        let bits = fc.machine().arch().bits() as u8;
        let r = call(&mut fc, "op_name", vec![u32v(op)], RetKind::Int { bits });
        let s = fc
            .machine()
            .read_cstr(r.ret.expect("ret"), 64)
            .expect("string");
        out.push(String::from_utf8_lossy(&s).into_owned());
    }
    out
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn switch_vm_functions_agree_with_x86_64_on_every_architecture() {
    let reference = switch_vm_results(&corpus().join("bin/switch_vm-O0"));
    assert_eq!(reference[0].0, 36);
    assert_eq!(reference[1].0, 0);
    assert_eq!(reference[2].0, 1);
    let names = op_names(&corpus().join("bin/switch_vm-O0"));
    assert_eq!(names[0], "halt");
    let mut targets: Vec<std::path::PathBuf> = Vec::new();
    for set in ["arm32", "aarch64", "riscv64", "riscv32"] {
        for opt in ["O0", "O2"] {
            targets.push(bin(set, &format!("switch_vm-{set}-{opt}")));
        }
    }
    for opt in ["O0", "O2"] {
        targets.push(bin("arm32", &format!("switch_vm-arm32-thumb-{opt}")));
        targets.push(corpus().join(format!("elf32/bin/switch_vm-i386-{opt}")));
        targets.push(corpus().join(format!("bin/switch_vm-{opt}")));
    }
    for t in targets {
        let name = t.file_name().unwrap().to_string_lossy().into_owned();
        let got = switch_vm_results(&t);
        eprintln!("{name}: vm_run {got:?}");
        assert_eq!(got, reference, "{name}: vm_run");
        assert_eq!(op_names(&t), names, "{name}: op_name");
    }
}

/// The exported helpers of static_strops (and a pointer-array argument). The binaries are
/// static, so their C library (`strlen` behind an `IRELATIVE` relocation) only works once it
/// started: the calls run in the process stopped at `main`.
fn strops_results(path: &std::path::Path) -> Vec<String> {
    let data = std::fs::read(path).expect("read");
    let _ = specs(Arch::from_elf(&data).expect("arch"));
    let mut fc = FunctionCaller::after_startup(&kraken_emu::RunSpec::new(path), "main", 20_000_000)
        .expect("start to main");
    let arch = fc.machine().arch();
    let p = |v| Value::ptr(arch, v);
    let mut out = Vec::new();
    fc.reset().expect("reset");
    let s = fc.alloc(b"mississippi is in it\0").expect("s");
    let r = call(
        &mut fc,
        "str_count_char",
        vec![
            p(s),
            Value::Int {
                bits: 8,
                signed: true,
                value: u64::from(b'i'),
            },
        ],
        RetKind::Int { bits: 32 },
    );
    out.push(format!("count={}", r.ret.unwrap()));
    for word in [&b"level\0"[..], b"buf\0"] {
        let w = fc.alloc(word).expect("w");
        let r = call(
            &mut fc,
            "is_palindrome",
            vec![p(w)],
            RetKind::Int { bits: 32 },
        );
        out.push(format!("pal={}", r.ret.unwrap()));
    }
    let buf = fc.alloc(b"Hello, world\0").expect("buf");
    call(&mut fc, "str_upper", vec![p(buf)], RetKind::Void);
    out.push(String::from_utf8_lossy(&fc.machine().read_cstr(buf, 64).unwrap()).into_owned());
    call(&mut fc, "str_reverse", vec![p(buf)], RetKind::Void);
    out.push(String::from_utf8_lossy(&fc.machine().read_cstr(buf, 64).unwrap()).into_owned());
    // join_words(out, cap, words, n, sep): an array of pointers in the target's width.
    let words: Vec<u64> = [&b"static\0"[..], b"linking\0", b"keeps\0"]
        .iter()
        .map(|w| fc.alloc(w).expect("word"))
        .collect();
    let ps = arch.ptr_size();
    let table: Vec<u8> = words
        .iter()
        .flat_map(|w| w.to_le_bytes()[..ps].to_vec())
        .collect();
    let t = fc.alloc(&table).expect("table");
    let dst = fc.alloc(&[0u8; 64]).expect("dst");
    let r = call(
        &mut fc,
        "join_words",
        vec![
            p(dst),
            Value::ptr(arch, 64),
            p(t),
            int(3),
            Value::Int {
                bits: 8,
                signed: true,
                value: u64::from(b'-'),
            },
        ],
        RetKind::Int { bits: 32 },
    );
    out.push(format!(
        "join={} {}",
        r.ret.unwrap(),
        String::from_utf8_lossy(&fc.machine().read_cstr(dst, 64).unwrap())
    ));
    out
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn static_strops_helpers_agree_with_x86_64_on_every_architecture() {
    let reference = strops_results(&corpus().join("bin/static_strops-O0"));
    assert_eq!(
        reference,
        vec![
            "count=7",
            "pal=1",
            "pal=0",
            "HELLO, WORLD",
            "DLROW ,OLLEH",
            "join=20 static-linking-keeps"
        ]
    );
    for set in ["arm32", "aarch64", "riscv64", "riscv32"] {
        for opt in ["O0", "O2"] {
            let name = format!("static_strops-{set}-{opt}");
            let got = strops_results(&bin(set, &name));
            eprintln!("{name}: {got:?}");
            assert_eq!(got, reference, "{name}");
        }
    }
}

/// pie_list's comparators on two records (pointer arguments into structs).
fn comparators(path: &std::path::Path) -> (u64, u64) {
    let mut fc = caller(path);
    let arch = fc.machine().arch();
    let record = |id: i32, x: i32, y: i32| {
        let mut r = vec![0u8; 40];
        r[0..4].copy_from_slice(&id.to_le_bytes());
        r[20..24].copy_from_slice(&x.to_le_bytes());
        r[24..28].copy_from_slice(&y.to_le_bytes());
        r
    };
    let a = fc.alloc(&record(7, 3, 4)).expect("a");
    let b = fc.alloc(&record(2, 1, 1)).expect("b");
    let args = vec![Value::ptr(arch, a), Value::ptr(arch, b)];
    let id = call(&mut fc, "cmp_id", args.clone(), RetKind::Int { bits: 32 });
    let dist = call(&mut fc, "cmp_dist", args, RetKind::Int { bits: 32 });
    (id.ret.unwrap(), dist.ret.unwrap())
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn pie_list_comparators_agree_on_every_architecture() {
    let reference = comparators(&corpus().join("bin/pie_list-O0"));
    assert_eq!(reference, (5, 23));
    let mut targets = vec![corpus().join("elf32/bin/pie_list-i386-O0")];
    for set in ["arm32", "aarch64", "riscv64", "riscv32"] {
        targets.push(bin(set, &format!("pie_list-{set}-O0")));
    }
    for t in targets {
        let got = comparators(&t);
        eprintln!("{}: cmp_id/cmp_dist {got:?}", t.display());
        assert_eq!(got, reference, "{}", t.display());
    }
}

/// A snippet per architecture computing `d * i` from `(int i, double d)` (RISC-V 32 has no FPU
/// in the corpus's ABI: it adds two 64-bit integers passed in register pairs instead).
fn snippet(arch: Arch) -> (Vec<u8>, &'static str) {
    let words = |w: &[u32]| w.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    match arch {
        Arch::X86_64 => (
            vec![0xf2, 0x0f, 0x2a, 0xcf, 0xf2, 0x0f, 0x59, 0xc1, 0xc3],
            "MULSD",
        ),
        Arch::X86 => (
            vec![0xdb, 0x44, 0x24, 0x04, 0xdc, 0x4c, 0x24, 0x08, 0xc3],
            "FMUL",
        ),
        Arch::Aarch64 => (words(&[0x1E620001, 0x1E610800, 0xD65F03C0]), "fmul"),
        Arch::Riscv64 => (words(&[0xD20505D3, 0x12B57553, 0x00008067]), "fmul.d"),
        Arch::Arm => (
            words(&[0xEE010A10, 0xEEB81BC1, 0xEE200B01, 0xE12FFF1E]),
            "vmul",
        ),
        Arch::Riscv32 => (
            words(&[0x00C50533, 0x00C532B3, 0x00D585B3, 0x005585B3, 0x00008067]),
            "sltu",
        ),
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn doubles_and_wide_integers_cross_every_calling_convention() {
    let specs = SpecRoots::discover();
    for arch in Arch::ALL {
        let (code, mnemonic) = snippet(arch);
        let base = 0x10000;
        let mut fc = FunctionCaller::with_code(arch, base, &code, &specs).expect("caller");
        let mut text = String::new();
        let mut at = base;
        while at < base + code.len() as u64 {
            let (t, len) = fc.machine().disasm_at(at, Some(false)).expect("disasm");
            text.push_str(&t);
            text.push_str("; ");
            at += len;
        }
        assert!(text.contains(mnemonic), "{arch}: {text}");
        let spec = if arch == Arch::Riscv32 {
            let a = Value::Int {
                bits: 64,
                signed: false,
                value: 0x1_ffff_fff0,
            };
            let b = Value::Int {
                bits: 64,
                signed: false,
                value: 0x2_0000_0020,
            };
            CallSpec {
                callee: Callee::Address(base),
                args: vec![a, b],
                ret: RetKind::Int { bits: 64 },
                max_instructions: 100,
            }
        } else {
            CallSpec {
                callee: Callee::Address(base),
                args: vec![int(-3), Value::f64(2.5)],
                ret: RetKind::F64,
                max_instructions: 100,
            }
        };
        let out = fc.call(&spec).expect("call");
        assert_eq!(
            out.termination,
            CallTermination::Returned,
            "{arch}: {out:?}"
        );
        let ret = out.ret.expect("ret");
        if arch == Arch::Riscv32 {
            assert_eq!(ret, 0x4_0000_0010, "{arch}");
        } else {
            assert_eq!(f64::from_bits(ret), -7.5, "{arch}: {text}");
        }
        eprintln!("{arch}: {text}-> {ret:#x}");
    }
}
