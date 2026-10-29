//! The native assembler on corpus binaries, through the worker and in-process: encodings, labels,
//! symbols, relative branches, NOP padding and the Sleigh decode-back. Skips (with a note)
//! without the native build or specs.

use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{
    Assembler, CancellationToken, DisasmRequest, Disassembler, FunctionLister, Loader, LoaderSpec,
};
use kraken_proto::{DisasmScope, ErrorCode, Hex64, Locator, PageRequest};

/// `cmp_id` in `pie_list-O0` (loaded at 0x100000).
const CMP_ID: u64 = 0x10124e;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config(worker: bool) -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs (cargo xtask native-sla or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = if worker {
        Isolation::Worker(WorkerOptions::with_program(env!(
            "CARGO_BIN_EXE_kraken-native-worker"
        )))
    } else {
        Isolation::InProcess
    };
    Some(c)
}

async fn open(bin: &str, worker: bool, state: &Path) -> Option<NativeEngine> {
    let mut c = config(worker)?;
    c.state_dir = Some(state.to_path_buf());
    let e = NativeEngine::new(c);
    e.open_binary(
        &root().join(bin),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open_binary");
    Some(e)
}

fn at(a: u64) -> Locator {
    Locator::ram(a)
}

async fn first_rows(e: &NativeEngine, start: u64, n: u32) -> Vec<(u64, usize)> {
    let page = e
        .disassemble(
            &DisasmRequest {
                start: Hex64(start),
                scope: DisasmScope::Linear,
            },
            &PageRequest {
                limit: Some(n),
                cursor: None,
            },
            &CancellationToken::new(),
        )
        .await
        .expect("disassemble");
    page.items
        .iter()
        .map(|r| (r.address.0, r.bytes.len() / 2))
        .collect()
}

async fn x86_64_suite(worker: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(e) = open("corpus/bin/pie_list-O0", worker, dir.path()).await else {
        return;
    };
    let c = CancellationToken::new();

    let enc = e
        .assemble(&at(CMP_ID), "mov eax, 0x7", &c)
        .await
        .expect("mov");
    assert_eq!(enc[0], [0xb8, 7, 0, 0, 0]);
    assert!(enc.len() >= 2, "{enc:?}");

    // labels and a backward branch
    let b = e
        .assemble_block(
            &at(CMP_ID),
            "xor eax, eax; again: inc eax; cmp eax, 3; jne again; ret",
            &c,
        )
        .await
        .expect("loop");
    assert_eq!(
        &b.bytes[..b.line_lengths.iter().sum::<u32>() as usize],
        [0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x03, 0x75, 0xf9, 0xc3]
    );

    // symbols by name, and a call encoded for the address it sits at
    let funcs = e
        .list_functions(&PageRequest::default(), &c)
        .await
        .expect("functions");
    let f = funcs
        .items
        .iter()
        .find(|f| f.name == "cmp_id")
        .expect("cmp_id");
    assert_eq!(f.locator, Locator::ram(CMP_ID));
    let here = CMP_ID + 0x40;
    let call = e
        .assemble(&at(here), "call cmp_id", &c)
        .await
        .expect("call");
    let rel = (CMP_ID as i64 - (here as i64 + 5)) as i32;
    let mut want = vec![0xe8];
    want.extend(rel.to_le_bytes());
    assert_eq!(call[0], want);

    let err = e
        .assemble(&at(here), "call no_such_function", &c)
        .await
        .expect_err("unknown symbol");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("no_such_function"), "{}", err.message);
    let err = e
        .assemble(&at(here), "mov eax, rbx", &c)
        .await
        .expect_err("bad operands");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    // padding to the next instruction boundary and the overwrite count
    let rows = first_rows(&e, CMP_ID, 12).await;
    let (a0, l0) = rows[0];
    let one = e.assemble_block(&at(a0), "ret", &c).await.expect("ret");
    assert_eq!(one.bytes.len(), l0, "padded to the instruction");
    assert_eq!(one.pad as usize, l0 - 1);
    assert_eq!(one.overwritten, 0);
    let many = e
        .assemble_block(&at(a0), "mov rax, 0x1122334455667788; ret", &c)
        .await
        .expect("long");
    let need = 11;
    assert!(many.bytes.len() >= need, "{many:?}");
    let mut covered = 0;
    let mut count = 0;
    for (_, l) in &rows {
        covered += l;
        count += 1;
        if covered >= need {
            break;
        }
    }
    assert_eq!(many.bytes.len(), covered);
    assert_eq!(many.overwritten, count - 1);
    assert_eq!(many.covered as usize, covered);
}

#[tokio::test]
async fn x86_64_in_the_worker() {
    x86_64_suite(true).await;
}

#[tokio::test]
async fn x86_64_in_process() {
    x86_64_suite(false).await;
}

#[tokio::test]
async fn x86_32() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Ok(rd) = std::fs::read_dir(root().join("corpus/elf32/bin")) else {
        return;
    };
    let Some(bin) = rd.flatten().map(|e| e.path()).find(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with("-O0"))
    }) else {
        return;
    };
    let rel = bin.strip_prefix(root()).expect("under root").to_path_buf();
    let Some(e) = open(&rel.to_string_lossy(), false, dir.path()).await else {
        return;
    };
    let c = CancellationToken::new();
    let enc = e
        .assemble(&at(0x8049000), "push ebp; mov ebp, esp; sub esp, 0x10", &c)
        .await
        .expect("x86");
    assert_eq!(enc[0], [0x55, 0x89, 0xe5, 0x83, 0xec, 0x10]);
}

#[tokio::test]
async fn aarch64_through_llvm_mc_or_a_clear_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(e) = open("corpus/aarch64/bin/pie_list-aarch64-O0", true, dir.path()).await else {
        return;
    };
    let c = CancellationToken::new();
    let funcs = e
        .list_functions(&PageRequest::default(), &c)
        .await
        .expect("functions");
    let Locator::Native { offset, .. } = &funcs.items[0].locator else {
        panic!("native locator")
    };
    let start = offset.0;
    match e.assemble_block(&at(start), "mov x0, #1; ret", &c).await {
        // llvm-mc may be found under a versioned name or an LLVM directory, not only on PATH.
        Ok(b) => {
            assert_eq!(
                &b.bytes[..8],
                [0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]
            );
        }
        Err(err) => {
            assert_eq!(err.code, ErrorCode::Unsupported);
            assert!(err.message.contains("llvm-mc"), "{}", err.message);
        }
    }
}
