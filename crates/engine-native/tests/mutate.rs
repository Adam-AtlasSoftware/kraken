//! The native engine's mutator on `pie_list-O0`: every edit-log op shows in the function list,
//! the listing and the decompiler, a save names the applied ops, and a reopened engine with the
//! same state directory replays them. Skips (with a note) without the native build or specs.
//!
//! The engines run in the confined worker (the default), which writes the state directory;
//! `KRAKEN_NATIVE_TEST_IN_PROCESS=1` runs them in-process instead.

use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{
    CancellationToken, Decompiler, DisasmRequest, Disassembler, FlowGraph, FunctionLister, Loader,
    LoaderSpec, Mutator, SymbolLister, TypeStore, XrefProvider, XrefRequest,
};
use kraken_proto::{
    AddressRange, Anchor, CodeData, CommentKind, Composite, DisasmRow, DisasmScope, ErrorCode,
    Field, FunctionPrototype, FunctionSummary, Hex64, Locator, LogOp, PageRequest, Param,
    Primitive, PrimitiveClass, TypeDef, TypeRef, VersionedLogOp, Xref, XrefDirection,
};

/// `cmp_id` in `pie_list-O0` (loaded at 0x100000).
const CMP_ID: u64 = 0x10124e;
/// Start of `.rodata`, which holds no function.
const RODATA: u64 = 0x102000;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config(state: &Path) -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs (cargo xtask native-sla or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.state_dir = Some(state.to_path_buf());
    c.isolation = if std::env::var_os("KRAKEN_NATIVE_TEST_IN_PROCESS").is_some_and(|v| v == "1") {
        Isolation::InProcess
    } else {
        Isolation::Worker(WorkerOptions::with_program(env!(
            "CARGO_BIN_EXE_kraken-native-worker"
        )))
    };
    Some(c)
}

async fn open(state: &Path) -> Option<NativeEngine> {
    let e = NativeEngine::new(config(state)?);
    e.open_binary(
        &root().join("corpus/bin/pie_list-O0"),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open_binary");
    Some(e)
}

fn int() -> TypeRef {
    TypeRef::Primitive(Primitive {
        class: PrimitiveClass::Int,
        size: 4,
        signed: true,
    })
}

fn anchor(at: u64, f: Option<&FunctionSummary>) -> Anchor {
    Anchor::Native {
        space: "ram".into(),
        offset: Hex64(at),
        fn_entry: Hex64(f.map_or(at, |f| match &f.locator {
            Locator::Native { offset, .. } => offset.0,
            _ => at,
        })),
        fn_hash: f.and_then(|f| f.fn_hash.clone()).unwrap_or_default(),
    }
}

async fn apply(e: &NativeEngine, op: LogOp) -> Result<(), ErrorCode> {
    e.apply(&VersionedLogOp::new(op), &CancellationToken::new())
        .await
        .map_err(|r| r.code)
}

async fn function(e: &NativeEngine, at: u64) -> Result<FunctionSummary, ErrorCode> {
    e.get_function(&Locator::ram(at), &CancellationToken::new())
        .await
        .map_err(|e| e.code)
}

async fn total(e: &NativeEngine) -> Option<u64> {
    e.list_functions(
        &PageRequest {
            cursor: None,
            limit: Some(1),
        },
        &CancellationToken::new(),
    )
    .await
    .expect("list")
    .total
}

async fn decompiled(e: &NativeEngine, at: u64) -> String {
    let r = e
        .decompile(&Locator::ram(at), &CancellationToken::new())
        .await
        .expect("decompile");
    r.validate_tokens().expect("token spans");
    r.text
}

async fn rows(e: &NativeEngine, at: u64, scope: DisasmScope, limit: u32) -> Vec<DisasmRow> {
    e.disassemble(
        &DisasmRequest {
            start: Hex64(at),
            scope,
        },
        &PageRequest {
            cursor: None,
            limit: Some(limit),
        },
        &CancellationToken::new(),
    )
    .await
    .expect("disassemble")
    .items
}

fn record_proto() -> FunctionPrototype {
    let rec = || TypeRef::Pointer {
        target: Box::new(TypeRef::Named {
            name: "record".into(),
        }),
        size: 8,
    };
    FunctionPrototype {
        name: None,
        return_type: Box::new(int()),
        params: vec![
            Param {
                name: Some("lhs".into()),
                ty: rec(),
                storage: None,
            },
            Param {
                name: Some("rhs".into()),
                ty: rec(),
                storage: None,
            },
        ],
        calling_convention: String::new(),
        varargs: false,
        noreturn: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn edits_show_everywhere_and_replay_on_reopen() {
    let state = tempfile::tempdir().expect("state dir");
    let Some(e) = open(state.path()).await else {
        return;
    };
    let c = CancellationToken::new();
    let f = function(&e, CMP_ID).await.expect("cmp_id");
    assert_eq!(f.name, "cmp_id");

    // rename: listing, decompiler, tokens; idempotent; stale old name
    let rename = |old: &str, new: &str| LogOp::Rename {
        anchor: anchor(CMP_ID, Some(&f)),
        old_name: Some(old.into()),
        new_name: new.into(),
    };
    apply(&e, rename("cmp_id", "by_id")).await.expect("rename");
    apply(&e, rename("cmp_id", "by_id")).await.expect("again");
    assert_eq!(
        apply(&e, rename("nope", "other")).await,
        Err(ErrorCode::ConflictStaleRead)
    );
    assert_eq!(function(&e, CMP_ID).await.expect("renamed").name, "by_id");
    let text = decompiled(&e, CMP_ID).await;
    assert!(
        text.contains("by_id(") && !text.contains("cmp_id"),
        "{text}"
    );
    // callers print a renamed callee's new name
    let all = e
        .list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &c,
        )
        .await
        .expect("list")
        .items;
    let at_of = |name: &str| {
        let f = all.iter().find(|f| f.name == name).expect(name);
        match &f.locator {
            Locator::Native { offset, .. } => (offset.0, f.clone()),
            _ => unreachable!(),
        }
    };
    let (main_at, _) = at_of("main");
    let (node_new, nf) = at_of("node_new");
    apply(
        &e,
        LogOp::Rename {
            anchor: anchor(node_new, Some(&nf)),
            old_name: Some("node_new".into()),
            new_name: "make_node".into(),
        },
    )
    .await
    .expect("rename node_new");
    let main_text = decompiled(&e, main_at).await;
    assert!(
        main_text.contains("make_node(") && !main_text.contains("node_new"),
        "{main_text}"
    );

    // comments: plate and pre in the decompiler, end-of-line in the listing
    let body = rows(&e, CMP_ID, DisasmScope::Function, 50).await;
    let second = body[1].address.0;
    for (at, kind, text) in [
        (CMP_ID, CommentKind::Plate, "compares two records by id"),
        (second, CommentKind::Eol, "load the first id"),
        (body[2].address.0, CommentKind::Pre, "kraken pre note"),
    ] {
        apply(
            &e,
            LogOp::SetComment {
                anchor: anchor(at, None),
                comment_kind: kind,
                old: None,
                new: Some(text.into()),
            },
        )
        .await
        .expect("comment");
    }
    let text = decompiled(&e, CMP_ID).await;
    assert!(text.contains("compares two records by id"), "{text}");
    let body = rows(&e, CMP_ID, DisasmScope::Function, 50).await;
    assert_eq!(body[1].comment.as_deref(), Some("load the first id"));
    assert_eq!(body[2].comment.as_deref(), Some("kraken pre note"));

    // a label inside the body shows in the listing
    apply(
        &e,
        LogOp::Rename {
            anchor: anchor(second, None),
            old_name: None,
            new_name: "after_prologue".into(),
        },
    )
    .await
    .expect("label");
    let body = rows(&e, CMP_ID, DisasmScope::Function, 50).await;
    assert_eq!(body[1].labels, vec!["after_prologue".to_string()]);
    assert_eq!(body[0].labels, vec!["by_id".to_string()]);

    // set_type: a prototype over a user struct reaches the decompiler and the signature
    e.define_type(
        TypeDef::Struct(Composite {
            name: "record".into(),
            size: 16,
            align: 4,
            fields: vec![Field {
                name: "id".into(),
                offset: 0,
                ty: int(),
                bitfield: None,
            }],
        }),
        &c,
    )
    .await
    .expect("struct");
    let f = function(&e, CMP_ID).await.expect("cmp_id");
    let typed = LogOp::SetType {
        anchor: anchor(CMP_ID, Some(&f)),
        old: None,
        new: TypeRef::Function(Box::new(record_proto())),
    };
    apply(&e, typed.clone()).await.expect("set_type");
    let text = decompiled(&e, CMP_ID).await;
    assert!(text.contains("by_id(record *lhs,record *rhs)"), "{text}");
    assert!(text.contains("lhs->id - rhs->id"), "{text}");
    let sig = function(&e, CMP_ID).await.expect("f").signature;
    assert_eq!(sig.as_deref(), Some("int by_id(record *lhs,record *rhs)"));
    // a prototype naming an unknown type by value is refused
    let mut bad = record_proto();
    bad.params[0].ty = TypeRef::Named {
        name: "no_such_type".into(),
    };
    assert_eq!(
        apply(
            &e,
            LogOp::SetType {
                anchor: anchor(CMP_ID, None),
                old: None,
                new: TypeRef::Function(Box::new(bad)),
            }
        )
        .await,
        Err(ErrorCode::InvalidArgument)
    );
    assert!(decompiled(&e, CMP_ID).await.contains("lhs->id - rhs->id"));

    // calling convention: MSABI moves the parameters to RCX and RDX
    let cc = |name: &str| LogOp::SetCallingConvention {
        anchor: anchor(CMP_ID, None),
        old: None,
        new: name.into(),
    };
    assert_eq!(
        apply(&e, cc("__no_such_cc")).await,
        Err(ErrorCode::InvalidArgument)
    );
    apply(&e, cc("MSABI")).await.expect("MSABI");
    apply(&e, cc("")).await.expect("default convention");

    // data: an int in .rodata is one listing row
    apply(
        &e,
        LogOp::SetCodeData {
            anchor: anchor(RODATA, None),
            old: None,
            new: CodeData::Data {
                data_type: Some(int()),
            },
            length: None,
        },
    )
    .await
    .expect("data");
    let linear = rows(&e, RODATA, DisasmScope::Linear, 3).await;
    assert_eq!(linear[0].mnemonic, "int");
    assert_eq!(linear[1].address.0, RODATA + 4);
    assert_eq!(
        apply(
            &e,
            LogOp::SetCodeData {
                anchor: anchor(second, None),
                old: None,
                new: CodeData::Data { data_type: None },
                length: None,
            }
        )
        .await,
        Err(ErrorCode::EngineRejected),
        "no data over a function's code"
    );

    // bounds: a shorter body, then the found one back
    let size = f.size.expect("size");
    apply(
        &e,
        LogOp::SetFunctionBounds {
            anchor: anchor(CMP_ID, None),
            old: None,
            new: AddressRange {
                space: "ram".into(),
                start: Hex64(CMP_ID),
                end: Hex64(CMP_ID + 8),
            },
        },
    )
    .await
    .expect("bounds");
    assert_eq!(function(&e, CMP_ID).await.expect("f").size, Some(8));
    apply(
        &e,
        LogOp::SetFunctionBounds {
            anchor: anchor(CMP_ID, None),
            old: None,
            new: AddressRange {
                space: "ram".into(),
                start: Hex64(0),
                end: Hex64(0),
            },
        },
    )
    .await
    .expect("bounds back");
    assert_eq!(function(&e, CMP_ID).await.expect("f").size, Some(size));

    // delete and create
    let n = total(&e).await;
    let delete = LogOp::DeleteFunction {
        anchor: anchor(CMP_ID, Some(&f)),
        old_body: None,
    };
    apply(&e, delete.clone()).await.expect("delete");
    assert_eq!(function(&e, CMP_ID).await, Err(ErrorCode::NotFound));
    assert_eq!(apply(&e, delete).await, Err(ErrorCode::NotFound));
    assert_eq!(total(&e).await, n.map(|n| n - 1));
    apply(
        &e,
        LogOp::CreateFunction {
            anchor: anchor(CMP_ID, None),
            name: Some("by_id".into()),
            body: None,
        },
    )
    .await
    .expect("create");
    let back = function(&e, CMP_ID).await.expect("created");
    assert_eq!((back.name.as_str(), back.size), ("by_id", Some(size)));
    // the prototype went with the deleted function; set it again
    apply(&e, typed).await.expect("set_type again");
    // a function in data, with an explicit body
    apply(
        &e,
        LogOp::CreateFunction {
            anchor: anchor(RODATA + 0x40, None),
            name: Some("scratch".into()),
            body: Some(AddressRange {
                space: "ram".into(),
                start: Hex64(RODATA + 0x40),
                end: Hex64(RODATA + 0x50),
            }),
        },
    )
    .await
    .expect("create in data");
    assert_eq!(
        function(&e, RODATA + 0x40).await.expect("scratch").size,
        Some(0x10)
    );

    // save, then a fresh engine over the same state directory has every edit
    let w1 = e.save(&c).await.expect("save");
    apply(
        &e,
        LogOp::SetComment {
            anchor: anchor(CMP_ID, None),
            comment_kind: CommentKind::Repeatable,
            old: None,
            new: Some("r".into()),
        },
    )
    .await
    .expect("comment");
    let w2 = e.save(&c).await.expect("save");
    assert_ne!(w1, w2);
    let edits = e.stats().await.expect("stats").edits;
    drop(e);

    let e = open(state.path()).await.expect("reopen");
    let stats = e.stats().await.expect("stats");
    assert_eq!((stats.edits, stats.replay_failed), (edits, 0));
    let f = function(&e, CMP_ID).await.expect("cmp_id");
    assert_eq!(f.name, "by_id");
    assert_eq!(
        f.signature.as_deref(),
        Some("int by_id(record *lhs,record *rhs)")
    );
    let text = decompiled(&e, CMP_ID).await;
    assert!(text.contains("compares two records by id"), "{text}");
    assert!(text.contains("lhs->id - rhs->id"), "{text}");
    let body = rows(&e, CMP_ID, DisasmScope::Function, 50).await;
    assert_eq!(body[1].labels, vec!["after_prologue".to_string()]);
    assert_eq!(
        rows(&e, RODATA, DisasmScope::Linear, 1).await[0].mnemonic,
        "int"
    );
    assert!(function(&e, RODATA + 0x40).await.is_ok());
    assert_eq!(e.save(&c).await.expect("save"), w2);

    // undoing the prototype (the log's "undefined") goes back to the inferred signature
    apply(
        &e,
        LogOp::SetType {
            anchor: anchor(CMP_ID, None),
            old: None,
            new: TypeRef::Named {
                name: "undefined".into(),
            },
        },
    )
    .await
    .expect("clear type");
    // ... which for this binary is the prototype from its DWARF
    let text = decompiled(&e, CMP_ID).await;
    assert!(text.contains("by_id(record *a,record *b)"), "{text}");
    let sig = function(&e, CMP_ID).await.expect("f").signature;
    assert_eq!(sig.as_deref(), Some("int by_id(record *a, record *b)"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_what_it_cannot_apply() {
    let state = tempfile::tempdir().expect("state dir");
    let Some(e) = open(state.path()).await else {
        return;
    };
    let managed = LogOp::Rename {
        anchor: Anchor::Managed {
            token: "m:0x06000001".into(),
        },
        old_name: None,
        new_name: "x".into(),
    };
    assert_eq!(apply(&e, managed).await, Err(ErrorCode::Unsupported));
    let mut future = VersionedLogOp::new(LogOp::SetComment {
        anchor: anchor(CMP_ID, None),
        comment_kind: CommentKind::Eol,
        old: None,
        new: Some("x".into()),
    });
    future.schema_version = u32::MAX;
    assert_eq!(
        e.apply(&future, &CancellationToken::new())
            .await
            .map_err(|r| r.code),
        Err(ErrorCode::Unsupported)
    );
    assert_eq!(
        apply(
            &e,
            LogOp::SetComment {
                anchor: anchor(0x10, None),
                comment_kind: CommentKind::Eol,
                old: None,
                new: Some("x".into()),
            }
        )
        .await,
        Err(ErrorCode::NotFound),
        "unmapped"
    );
    assert_eq!(
        apply(
            &e,
            LogOp::Rename {
                anchor: anchor(CMP_ID, None),
                old_name: None,
                new_name: "has space".into(),
            }
        )
        .await,
        Err(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        apply(
            &e,
            LogOp::CreateFunction {
                anchor: anchor(CMP_ID, None),
                name: Some("other".into()),
                body: None,
            }
        )
        .await,
        Err(ErrorCode::EngineRejected),
        "a function already exists"
    );
    assert_eq!(
        apply(
            &e,
            LogOp::SetType {
                anchor: anchor(CMP_ID, None),
                old: None,
                new: int(),
            }
        )
        .await,
        Err(ErrorCode::InvalidArgument),
        "a function takes a prototype only"
    );
    assert_eq!(
        apply(
            &e,
            LogOp::Rename {
                anchor: Anchor::Native {
                    space: "ram".into(),
                    offset: Hex64(CMP_ID),
                    fn_entry: Hex64(CMP_ID),
                    fn_hash: "not-the-hash".into(),
                },
                old_name: None,
                new_name: "x".into(),
            }
        )
        .await,
        Err(ErrorCode::ConflictStaleRead)
    );
    // nothing was applied, so nothing was journaled
    assert_eq!(e.stats().await.expect("stats").edits, 0);
}

/// `node_new` (static): calls `calloc`, `exit` (on failure, at 0x1011c2) and `strncpy`.
const NODE_NEW: u64 = 0x101189;
/// `list_push` (exported); `main` calls it.
const LIST_PUSH: u64 = 0x101214;
/// `list_sort` (exported); `main` calls it at 0x101635.
const LIST_SORT: u64 = 0x1012ff;
/// `main` (exported).
const MAIN: u64 = 0x1014da;
/// The PLT stub of `exit`.
const EXIT: u64 = 0x101080;
/// `mov edi,1` before the `call exit` in `node_new`'s failure path.
const NODE_NEW_FAIL: u64 = 0x1011bd;

async fn xrefs(e: &NativeEngine, at: u64, direction: XrefDirection, whole: bool) -> Vec<Xref> {
    e.xrefs(
        &XrefRequest {
            address: Hex64(at),
            direction,
            kind: None,
            whole_function: whole,
        },
        &PageRequest {
            cursor: None,
            limit: Some(500),
        },
        &CancellationToken::new(),
    )
    .await
    .expect("xrefs")
    .items
}

async fn export_name(e: &NativeEngine, at: u64) -> Option<String> {
    e.exports(
        &PageRequest {
            cursor: None,
            limit: Some(500),
        },
        &CancellationToken::new(),
    )
    .await
    .expect("exports")
    .items
    .into_iter()
    .find(|s| s.address == Some(Hex64(at)))
    .map(|s| s.name)
}

async fn exit_callers(e: &NativeEngine) -> Vec<u64> {
    xrefs(e, EXIT, XrefDirection::To, false)
        .await
        .iter()
        .map(|x| x.from.0)
        .collect()
}

async fn targets(e: &NativeEngine, at: u64) -> Vec<u64> {
    xrefs(e, at, XrefDirection::From, true)
        .await
        .iter()
        .map(|x| x.to.0)
        .collect()
}

/// Structural edits rebuild the references, the exports and the noreturn set: code a deleted
/// function leaves behind stays code (as in Ghidra), data defined over it drops its references,
/// a created function's references come back and its callers name it, an export follows a
/// renamed or recreated function, a bounds change moves references out of the function, and a
/// created function over a failure path never returns.
#[tokio::test(flavor = "multi_thread")]
async fn structural_edits_rebuild_references_exports_and_noreturn() {
    let state = tempfile::tempdir().expect("state dir");
    let Some(e) = open(state.path()).await else {
        return;
    };
    let c = CancellationToken::new();

    assert!(exit_callers(&e).await.contains(&0x1011c2));
    apply(
        &e,
        LogOp::DeleteFunction {
            anchor: anchor(NODE_NEW, None),
            old_body: None,
        },
    )
    .await
    .expect("delete node_new");
    let calls = xrefs(&e, NODE_NEW, XrefDirection::To, false).await;
    assert!(!calls.is_empty() && calls.iter().all(|x| x.to_function.is_none()));
    assert!(exit_callers(&e).await.contains(&0x1011c2), "the code stays");
    apply(
        &e,
        LogOp::SetCodeData {
            anchor: anchor(NODE_NEW, None),
            old: None,
            new: CodeData::Data { data_type: None },
            length: Some(Hex64(LIST_PUSH - NODE_NEW)),
        },
    )
    .await
    .expect("data over the old body");
    assert!(
        !exit_callers(&e).await.contains(&0x1011c2),
        "data has no references"
    );

    apply(
        &e,
        LogOp::CreateFunction {
            anchor: anchor(NODE_NEW, None),
            name: Some("make_node".into()),
            body: None,
        },
    )
    .await
    .expect("create make_node");
    assert!(exit_callers(&e).await.contains(&0x1011c2));
    let calls = xrefs(&e, NODE_NEW, XrefDirection::To, false).await;
    assert!(
        !calls.is_empty()
            && calls.iter().all(|x| {
                x.to_function
                    .as_ref()
                    .is_some_and(|f| f.name == "make_node")
                    && x.from_function
                        .as_ref()
                        .is_some_and(|f| f.address.0 == MAIN)
            }),
        "{calls:?}"
    );

    assert_eq!(
        export_name(&e, LIST_PUSH).await.as_deref(),
        Some("list_push")
    );
    apply(
        &e,
        LogOp::DeleteFunction {
            anchor: anchor(LIST_PUSH, None),
            old_body: None,
        },
    )
    .await
    .expect("delete list_push");
    assert_eq!(
        export_name(&e, LIST_PUSH).await.as_deref(),
        Some("list_push"),
        "the symbol stays exported"
    );
    apply(
        &e,
        LogOp::CreateFunction {
            anchor: anchor(LIST_PUSH, None),
            name: Some("push_node".into()),
            body: None,
        },
    )
    .await
    .expect("recreate");
    assert_eq!(
        export_name(&e, LIST_PUSH).await.as_deref(),
        Some("push_node")
    );
    apply(
        &e,
        LogOp::Rename {
            anchor: anchor(MAIN, None),
            old_name: Some("main".into()),
            new_name: "entry_main".into(),
        },
    )
    .await
    .expect("rename main");
    assert_eq!(export_name(&e, MAIN).await.as_deref(), Some("entry_main"));

    assert!(targets(&e, MAIN).await.contains(&LIST_SORT));
    apply(
        &e,
        LogOp::SetFunctionBounds {
            anchor: anchor(MAIN, None),
            old: None,
            new: AddressRange {
                space: "ram".into(),
                start: Hex64(MAIN),
                end: Hex64(0x101530),
            },
        },
    )
    .await
    .expect("shrink main");
    let t = targets(&e, MAIN).await;
    assert!(t.contains(&NODE_NEW) && !t.contains(&LIST_SORT), "{t:x?}");
    let sort_calls = xrefs(&e, LIST_SORT, XrefDirection::To, false).await;
    assert!(
        sort_calls
            .iter()
            .any(|x| x.from.0 == 0x101635 && x.from_function.is_none()),
        "the call stays, outside any function: {sort_calls:?}"
    );

    apply(
        &e,
        LogOp::CreateFunction {
            anchor: anchor(NODE_NEW_FAIL, None),
            name: Some("die".into()),
            body: None,
        },
    )
    .await
    .expect("create die");
    let stats = e.stats().await.expect("stats");
    assert!(
        stats.noreturn.contains(&NODE_NEW_FAIL),
        "{:x?}",
        stats.noreturn
    );
    let cfg = e.cfg(&Locator::ram(NODE_NEW_FAIL), &c).await.expect("cfg");
    assert!(cfg.edges.is_empty(), "the call to exit ends it: {cfg:?}");
    apply(
        &e,
        LogOp::DeleteFunction {
            anchor: anchor(NODE_NEW_FAIL, None),
            old_body: None,
        },
    )
    .await
    .expect("delete die");
    let stats = e.stats().await.expect("stats");
    assert!(!stats.noreturn.contains(&NODE_NEW_FAIL));

    // a reopened engine replays the edits and rebuilds once
    e.save(&c).await.expect("save");
    drop(e);
    let Some(e) = open(state.path()).await else {
        return;
    };
    assert_eq!(
        export_name(&e, LIST_PUSH).await.as_deref(),
        Some("push_node")
    );
    assert!(!targets(&e, MAIN).await.contains(&LIST_SORT));
    assert!(exit_callers(&e).await.contains(&0x1011c2));
}

/// With DWARF, the type store has the program's types and functions their prototypes, so
/// `cmp_id` decompiles as Ghidra shows it with DWARF.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf_types_and_prototypes() {
    let state = tempfile::tempdir().expect("state dir");
    let Some(e) = open(state.path()).await else {
        return;
    };
    let c = CancellationToken::new();
    match e.get_type("record", &c).await.expect("record") {
        TypeDef::Struct(s) => assert_eq!(s.size, 40),
        other => panic!("{other:?}"),
    }
    let f = function(&e, CMP_ID).await.expect("cmp_id");
    assert_eq!(
        f.signature.as_deref(),
        Some("int cmp_id(record *a, record *b)")
    );
    assert_eq!(f.mangled, None);
    let text = decompiled(&e, CMP_ID).await;
    assert!(text.contains("int cmp_id(record *a,record *b)"), "{text}");
    assert!(text.contains("a->id - b->id"), "{text}");
}
