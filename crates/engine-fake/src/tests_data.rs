//! Program-data views: synthetic fallbacks, recorded data, perturbation.

use kraken_engine::testing::run_contract_suite;
use kraken_engine::{CancellationToken, DisasmRequest, Engine, StringsRequest, XrefRequest};
use kraken_proto::{
    Cfg, CfgBlock, CfgEdge, CfgEdgeKind, DisasmRow, DisasmScope, ErrorCode, FlowKind, FunctionRef,
    Hex64, Locator, MemoryBlock, MemoryKind, PageRequest, StringEncoding, StringEntry, SymbolEntry,
    SymbolKind, Xref, XrefDirection, XrefKind, hex_bytes,
};

use crate::{FakeEngine, FixtureFile, Perturb};

const TINY: &str = include_str!("../fixtures/tiny.json");

fn tiny() -> FixtureFile {
    FixtureFile::from_json(TINY).unwrap()
}

fn row(address: u64, len: usize, mnemonic: &str, flow: FlowKind) -> DisasmRow {
    DisasmRow {
        address: Hex64(address),
        bytes: hex_bytes(&vec![0x90; len]),
        mnemonic: mnemonic.into(),
        operands: vec![],
        comment: None,
        labels: vec![],
        flow,
    }
}

/// `main` with a recorded listing, graph and references; everything else synthetic.
fn recorded() -> FixtureFile {
    let mut fx = tiny();
    let main = &mut fx.functions[0];
    main.disassembly = Some(vec![
        row(0x401000, 1, "push", FlowKind::Fallthrough),
        row(0x401001, 3, "cmp", FlowKind::Fallthrough),
        row(0x401004, 2, "je", FlowKind::ConditionalJump),
        row(0x401006, 5, "mov", FlowKind::Fallthrough),
        row(0x40100b, 1, "ret", FlowKind::Return),
    ]);
    main.cfg = Some(Cfg {
        function: Hex64(0x401000),
        blocks: vec![
            CfgBlock {
                start: Hex64(0x401000),
                end: Hex64(0x401006),
                instructions: 3,
            },
            CfgBlock {
                start: Hex64(0x401006),
                end: Hex64(0x40100b),
                instructions: 1,
            },
            CfgBlock {
                start: Hex64(0x40100b),
                end: Hex64(0x40100c),
                instructions: 1,
            },
        ],
        edges: vec![
            CfgEdge {
                from: Hex64(0x401000),
                to: Hex64(0x401006),
                kind: CfgEdgeKind::ConditionalFalse,
            },
            CfgEdge {
                from: Hex64(0x401000),
                to: Hex64(0x40100b),
                kind: CfgEdgeKind::ConditionalTrue,
            },
            CfgEdge {
                from: Hex64(0x401006),
                to: Hex64(0x40100b),
                kind: CfgEdgeKind::Fallthrough,
            },
        ],
    });
    main.xrefs = Some(vec![Xref {
        from: Hex64(0x401006),
        to: Hex64(0x402000),
        kind: XrefKind::Read,
        from_function: Some(FunctionRef {
            address: Hex64(0x401000),
            name: "main".into(),
        }),
        to_function: None,
    }]);
    fx.memory = Some(vec![
        MemoryBlock {
            name: ".text".into(),
            space: "ram".into(),
            start: Hex64(0x401000),
            end: Hex64(0x402000),
            perms: "r-x".into(),
            initialized: true,
            kind: MemoryKind::Default,
        },
        MemoryBlock {
            name: ".bss".into(),
            space: "ram".into(),
            start: Hex64(0x402000),
            end: Hex64(0x403000),
            perms: "rw-".into(),
            initialized: false,
            kind: MemoryKind::Default,
        },
    ]);
    fx.strings = Some(vec![StringEntry {
        address: Hex64(0x402010),
        value: "recorded".into(),
        encoding: StringEncoding::Utf8,
        length: 9,
    }]);
    fx.imports = Some(vec![SymbolEntry {
        name: "puts".into(),
        address: Some(Hex64(0x401f00)),
        library: Some("libc.so.6".into()),
        kind: SymbolKind::Function,
        mangled: None,
    }]);
    fx.exports = Some(vec![]);
    fx
}

fn page(limit: u32) -> PageRequest {
    PageRequest {
        cursor: None,
        limit: Some(limit),
    }
}

#[tokio::test]
async fn hand_written_fixtures_get_synthetic_data_that_agrees_with_itself() {
    let engine = FakeEngine::new(tiny());
    let cancel = CancellationToken::new();
    let dis = engine.disassembler().unwrap();
    let rows = dis
        .disassemble(
            &DisasmRequest {
                start: Hex64(0x401000),
                scope: DisasmScope::Function,
            },
            &page(100),
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(rows.items.len(), 16);
    // bytes of the listing are the bytes of memory
    let read = engine
        .memory_reader()
        .unwrap()
        .read_bytes(&Locator::ram(0x401000), 64, &cancel)
        .await
        .unwrap();
    let listed: String = rows.items.iter().map(|r| r.bytes.as_str()).collect();
    assert_eq!(hex_bytes(&read.bytes), listed);
    // the main -> helper call shows up as a row and as a reference
    assert_eq!(rows.items[1].flow, FlowKind::Call);
    let to = engine
        .xref_provider()
        .unwrap()
        .xrefs(
            &XrefRequest {
                address: Hex64(0x401040),
                direction: XrefDirection::To,
                kind: Some(XrefKind::Call),
                whole_function: false,
            },
            &page(10),
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(to.items.len(), 1);
    assert_eq!(to.items[0].from, Hex64(0x401004));
}

#[tokio::test]
async fn recorded_data_is_served_as_recorded() {
    let engine = FakeEngine::new(recorded());
    let cancel = CancellationToken::new();
    let rows = engine
        .disassembler()
        .unwrap()
        .disassemble(
            &DisasmRequest {
                start: Hex64(0x401004),
                scope: DisasmScope::Function,
            },
            &page(100),
            &cancel,
        )
        .await
        .unwrap();
    let mnemonics: Vec<_> = rows.items.iter().map(|r| r.mnemonic.as_str()).collect();
    assert_eq!(mnemonics, ["push", "cmp", "je", "mov", "ret"]);
    let cfg = engine
        .flow_graph()
        .unwrap()
        .cfg(&Locator::ram(0x401004), &cancel)
        .await
        .unwrap();
    assert_eq!(cfg.blocks.len(), 3);
    assert_eq!(cfg.edges[1].kind, CfgEdgeKind::ConditionalTrue);
    let map = engine
        .memory_reader()
        .unwrap()
        .memory_map(&cancel)
        .await
        .unwrap();
    assert_eq!(map.len(), 2);
    // recorded bytes beat the synthetic filler, uninitialized memory is flagged
    let read = engine
        .memory_reader()
        .unwrap()
        .read_bytes(&Locator::ram(0x401ffc), 8, &cancel)
        .await
        .unwrap();
    assert_eq!(read.bytes.len(), 8);
    assert_eq!(read.uninitialized.len(), 1);
    assert_eq!(read.uninitialized[0].start, Hex64(0x402000));
    let r = engine
        .memory_reader()
        .unwrap()
        .read_bytes(&Locator::ram(0x401000), 12, &cancel)
        .await
        .unwrap();
    assert_eq!(&r.bytes[..6], &[0x90; 6]);
    let strings = engine
        .string_lister()
        .unwrap()
        .strings(&StringsRequest::default(), &page(10), &cancel)
        .await
        .unwrap();
    assert_eq!(strings.items.len(), 1);
    let exports = engine
        .symbol_lister()
        .unwrap()
        .exports(&page(10), &cancel)
        .await
        .unwrap();
    assert!(
        exports.items.is_empty(),
        "an empty recorded list is not replaced by a fallback"
    );
    let imports = engine
        .symbol_lister()
        .unwrap()
        .imports(&page(10), &cancel)
        .await
        .unwrap();
    assert_eq!(imports.items[0].name, "puts");
}

#[tokio::test]
async fn bad_requests_use_the_contract_error_codes() {
    let engine = FakeEngine::new(tiny());
    let cancel = CancellationToken::new();
    let mem = engine.memory_reader().unwrap();
    assert_eq!(
        mem.read_bytes(&Locator::ram(0x10), 4, &cancel)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        mem.read_bytes(&Locator::ram(0x401000), 0, &cancel)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let e = engine
        .disassembler()
        .unwrap()
        .disassemble(
            &DisasmRequest {
                start: Hex64(0x401000),
                scope: DisasmScope::Linear,
            },
            &PageRequest {
                cursor: Some("zz".into()),
                limit: None,
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn contract_suite_on_recorded_data_normal_and_perturbed() {
    let fx = recorded();
    let engine = FakeEngine::new(fx.clone());
    run_contract_suite(&engine, &fx.expectations("tiny.elf"))
        .await
        .unwrap();

    let perturb = Perturb {
        base_shift: 0x2000,
        split: vec![Hex64(0x401000)],
        merge: vec![(Hex64(0x401040), Hex64(0x401080))],
    };
    let expected = perturb.apply(&fx);
    let engine = FakeEngine::perturbed(fx, perturb);
    run_contract_suite(&engine, &expected.expectations("tiny.elf"))
        .await
        .unwrap();
}

#[test]
fn perturbation_shifts_and_splits_recorded_data() {
    let fx = recorded();
    let shifted = Perturb {
        base_shift: 0x1000,
        ..Perturb::default()
    }
    .apply(&fx);
    let main = &shifted.functions[0];
    assert_eq!(
        main.disassembly.as_ref().unwrap()[0].address,
        Hex64(0x402000)
    );
    assert_eq!(main.cfg.as_ref().unwrap().blocks[1].start, Hex64(0x402006));
    assert_eq!(main.xrefs.as_ref().unwrap()[0].to, Hex64(0x403000));
    assert_eq!(shifted.memory.as_ref().unwrap()[0].start, Hex64(0x402000));
    assert_eq!(
        shifted.strings.as_ref().unwrap()[0].address,
        Hex64(0x403010)
    );
    assert_eq!(
        shifted.imports.as_ref().unwrap()[0].address,
        Some(Hex64(0x402f00))
    );

    let split = Perturb {
        split: vec![Hex64(0x401000)],
        ..Perturb::default()
    }
    .apply(&fx);
    // main is 64 bytes: the cut is at 0x401020, past every recorded row, so the second half has
    // no recorded rows and the first keeps them all but loses its graph
    let first = &split.functions[0];
    assert_eq!(first.disassembly.as_ref().unwrap().len(), 5);
    assert!(first.cfg.is_none());
    let second = split.functions.last().unwrap();
    assert_eq!(second.summary.name, "main_part2");
    assert!(second.disassembly.is_none() && second.xrefs.is_none());
}

#[tokio::test]
async fn renaming_follows_recorded_labels_and_references() {
    use kraken_proto::{Anchor, LogOp, VersionedLogOp};
    let mut fx = recorded();
    fx.functions[0].disassembly.as_mut().unwrap()[0].labels = vec!["main".into()];
    let engine = FakeEngine::new(fx);
    let cancel = CancellationToken::new();
    kraken_engine::Mutator::apply(
        &engine,
        &VersionedLogOp::new(LogOp::Rename {
            anchor: Anchor::Native {
                space: "ram".into(),
                offset: Hex64(0x401000),
                fn_entry: Hex64(0x401000),
                fn_hash: String::new(),
            },
            old_name: Some("main".into()),
            new_name: "entry_point".into(),
        }),
        &cancel,
    )
    .await
    .unwrap();
    let rows = engine
        .disassembler()
        .unwrap()
        .disassemble(
            &DisasmRequest {
                start: Hex64(0x401000),
                scope: DisasmScope::Function,
            },
            &page(10),
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(rows.items[0].labels, ["entry_point"]);
    let x = engine
        .xref_provider()
        .unwrap()
        .xrefs(
            &XrefRequest {
                address: Hex64(0x401000),
                direction: XrefDirection::From,
                kind: None,
                whole_function: true,
            },
            &page(10),
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(
        x.items[0].from_function.as_ref().unwrap().name,
        "entry_point"
    );
}

#[tokio::test]
async fn a_switch_block_shared_by_two_functions_is_one_jump_table() {
    let mut fx = recorded();
    let switch = |to: u64| CfgEdge {
        from: Hex64(0x401006),
        to: Hex64(to),
        kind: CfgEdgeKind::Switch,
    };
    let main = &mut fx.functions[0];
    let cfg = main.cfg.as_mut().unwrap();
    cfg.edges.push(switch(0x40100b));
    let (listing, mut shared) = (main.disassembly.clone(), cfg.clone());
    shared.function = Hex64(0x401040);
    shared.edges.push(switch(0x401000));
    let other = &mut fx.functions[1];
    other.disassembly = listing;
    other.cfg = Some(shared);

    let engine = FakeEngine::new(fx);
    let cancel = CancellationToken::new();
    let tables = engine
        .jump_tables()
        .unwrap()
        .list_jump_tables(&page(50), &cancel)
        .await
        .unwrap()
        .items;
    assert_eq!(tables.len(), 1, "{tables:?}");
    assert_eq!(tables[0].jump, Hex64(0x401006));
    assert_eq!(tables[0].targets, vec![Hex64(0x401000), Hex64(0x40100b)]);
}
