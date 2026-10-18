//! One JSON sample per top-level kraken-proto type and variant. The Java sidecar parses and
//! re-serializes every file as a wire-conformance check.

use std::fmt::Debug;

use kraken_proto::{
    AddressRange, Anchor, Bitfield, Capability, CodeData, CommentKind, Completeness, Composite,
    DecompileResult, EnumDef, EnumVariant, ErrorCode, Field, FunctionPrototype, FunctionSummary,
    Handshake, Hex64, Locator, LogOp, LogStatus, PROTOCOL_VERSION, Page, PageRequest, Param,
    Primitive, PrimitiveClass, ProtoError, Provenance, SyncState, Token, TokenKind, TypeDef,
    TypeRef, TypedefDef, Untrusted, VersionedLogOp,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub type Samples = Vec<(String, Value)>;

fn add<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    out: &mut Samples,
    name: &str,
    value: T,
) -> Result<(), String> {
    let json = serde_json::to_value(&value).map_err(|e| format!("{name}: {e}"))?;
    let back: T = serde_json::from_value(json.clone()).map_err(|e| format!("{name}: {e}"))?;
    if back != value {
        return Err(format!("{name}: does not round-trip in Rust"));
    }
    out.push((format!("{name}.json"), json));
    Ok(())
}

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

fn anchor() -> Anchor {
    Anchor::Native {
        space: "ram".into(),
        offset: Hex64(0x401010),
        fn_entry: Hex64(0x401000),
        fn_hash: "0f".repeat(32),
    }
}

fn range(start: u64, end: u64) -> AddressRange {
    AddressRange {
        space: "ram".into(),
        start: Hex64(start),
        end: Hex64(end),
    }
}

fn prototype() -> FunctionPrototype {
    FunctionPrototype {
        name: Some("add".into()),
        return_type: Box::new(prim(PrimitiveClass::Int, 4, true)),
        params: vec![
            Param {
                name: Some("a".into()),
                ty: prim(PrimitiveClass::Int, 4, true),
                storage: Some("edi".into()),
            },
            Param {
                name: None,
                ty: TypeRef::Pointer {
                    target: Box::new(TypeRef::Named {
                        name: "node".into(),
                    }),
                    size: 8,
                },
                storage: None,
            },
        ],
        calling_convention: "__cdecl".into(),
        varargs: true,
        noreturn: false,
    }
}

fn composite(name: &str) -> Composite {
    Composite {
        name: name.into(),
        size: 16,
        align: 8,
        fields: vec![
            Field {
                name: "next".into(),
                offset: 0,
                ty: TypeRef::Pointer {
                    target: Box::new(TypeRef::Named { name: name.into() }),
                    size: 8,
                },
                bitfield: None,
            },
            Field {
                name: "buf".into(),
                offset: 8,
                ty: TypeRef::Array {
                    element: Box::new(prim(PrimitiveClass::Char, 1, true)),
                    count: 4,
                },
                bitfield: None,
            },
            Field {
                name: "flags".into(),
                offset: 12,
                ty: prim(PrimitiveClass::Int, 4, false),
                bitfield: Some(Bitfield {
                    bit_offset: 3,
                    bit_size: 5,
                }),
            },
        ],
    }
}

pub fn samples() -> Result<Samples, String> {
    let mut o = Samples::new();
    let o = &mut o;

    add(o, "locator.native", Locator::ram(0x401000))?;
    add(
        o,
        "locator.managed",
        Locator::managed("61a35c05-1940-4673-81a7-f2157a66b75c", 0x0600_000a),
    )?;
    add(o, "anchor.native", anchor())?;
    add(
        o,
        "anchor.managed",
        Anchor::Managed {
            token: "0x06000001".into(),
        },
    )?;
    add(
        o,
        "anchor.banked",
        Anchor::Banked {
            bank: "2".into(),
            space: "rom".into(),
            offset: Hex64(0x8000),
        },
    )?;
    add(o, "address_range", range(0x401000, 0x401040))?;

    add(
        o,
        "type_ref.named",
        TypeRef::Named {
            name: "size_t".into(),
        },
    )?;
    add(
        o,
        "type_ref.primitive",
        prim(PrimitiveClass::Float, 8, true),
    )?;
    add(
        o,
        "type_ref.pointer",
        TypeRef::Pointer {
            target: Box::new(prim(PrimitiveClass::Void, 0, false)),
            size: 8,
        },
    )?;
    add(
        o,
        "type_ref.array",
        TypeRef::Array {
            element: Box::new(prim(PrimitiveClass::Int, 2, false)),
            count: 16,
        },
    )?;
    add(
        o,
        "type_ref.function",
        TypeRef::Function(Box::new(prototype())),
    )?;

    add(o, "type_def.struct", TypeDef::Struct(composite("node")))?;
    add(
        o,
        "type_def.union",
        TypeDef::Union(Composite {
            name: "value".into(),
            size: 8,
            align: 8,
            fields: vec![
                Field {
                    name: "i".into(),
                    offset: 0,
                    ty: prim(PrimitiveClass::Int, 8, true),
                    bitfield: None,
                },
                Field {
                    name: "d".into(),
                    offset: 0,
                    ty: prim(PrimitiveClass::Float, 8, true),
                    bitfield: None,
                },
            ],
        }),
    )?;
    add(
        o,
        "type_def.enum",
        TypeDef::Enum(EnumDef {
            name: "color".into(),
            size: 4,
            variants: vec![
                EnumVariant {
                    name: "RED".into(),
                    value: 0,
                },
                EnumVariant {
                    name: "NEG".into(),
                    value: -5,
                },
            ],
        }),
    )?;
    add(
        o,
        "type_def.typedef",
        TypeDef::Typedef(TypedefDef {
            name: "u32".into(),
            target: prim(PrimitiveClass::Int, 4, false),
        }),
    )?;
    add(o, "type_def.function", TypeDef::Function(prototype()))?;

    let a = anchor();
    let ops = [
        (
            "rename",
            LogOp::Rename {
                anchor: a.clone(),
                old_name: Some("FUN_00401000".into()),
                new_name: "main".into(),
            },
        ),
        (
            "set_type",
            LogOp::SetType {
                anchor: a.clone(),
                old: Some(prim(PrimitiveClass::Undefined, 4, false)),
                new: TypeRef::Function(Box::new(prototype())),
            },
        ),
        (
            "set_comment",
            LogOp::SetComment {
                anchor: a.clone(),
                comment_kind: CommentKind::Eol,
                old: Some("old".into()),
                new: Some("new".into()),
            },
        ),
        (
            "set_comment_clear",
            LogOp::SetComment {
                anchor: a.clone(),
                comment_kind: CommentKind::Plate,
                old: Some("old".into()),
                new: None,
            },
        ),
        (
            "create_function",
            LogOp::CreateFunction {
                anchor: a.clone(),
                name: Some("f".into()),
                body: Some(range(0x401000, 0x401040)),
            },
        ),
        (
            "create_function_min",
            LogOp::CreateFunction {
                anchor: a.clone(),
                name: None,
                body: None,
            },
        ),
        (
            "delete_function",
            LogOp::DeleteFunction {
                anchor: a.clone(),
                old_body: Some(range(0x401000, 0x401040)),
            },
        ),
        (
            "set_function_bounds",
            LogOp::SetFunctionBounds {
                anchor: a.clone(),
                old: Some(range(0x401000, 0x401040)),
                new: range(0x401000, 0x401080),
            },
        ),
        (
            "set_code_data",
            LogOp::SetCodeData {
                anchor: a.clone(),
                old: Some(CodeData::Undefined),
                new: CodeData::Data {
                    data_type: Some(prim(PrimitiveClass::Int, 4, true)),
                },
                length: Some(Hex64(4)),
            },
        ),
        (
            "set_code_data_code",
            LogOp::SetCodeData {
                anchor: a.clone(),
                old: None,
                new: CodeData::Code,
                length: None,
            },
        ),
        (
            "set_calling_convention",
            LogOp::SetCallingConvention {
                anchor: a,
                old: Some("__cdecl".into()),
                new: "__stdcall".into(),
            },
        ),
    ];
    for (name, op) in ops {
        add(o, &format!("log_op.{name}"), VersionedLogOp::new(op))?;
    }

    add(o, "provenance.user", Provenance::User)?;
    add(o, "provenance.agent", Provenance::Agent)?;
    add(
        o,
        "provenance.agent_from_binary_text",
        Provenance::AgentFromBinaryText,
    )?;
    add(o, "log_status.applied", LogStatus::Applied)?;
    add(
        o,
        "log_status.rejected",
        LogStatus::Rejected {
            reason: "stale".into(),
        },
    )?;
    add(o, "log_status.orphaned", LogStatus::Orphaned)?;
    add(o, "sync_state.pending", SyncState::Pending)?;
    add(o, "sync_state.pushed", SyncState::Pushed)?;
    add(
        o,
        "sync_state.engine_rejected",
        SyncState::EngineRejected {
            reason: "no".into(),
        },
    )?;
    add(o, "completeness.complete", Completeness::Complete)?;
    add(
        o,
        "completeness.partial",
        Completeness::Partial {
            reason: "decompiler timeout".into(),
        },
    )?;
    add(o, "completeness.not_analyzed", Completeness::NotAnalyzed)?;

    let summary = FunctionSummary {
        locator: Locator::ram(0x401000),
        name: "main".into(),
        size: Some(64),
        signature: Some("int main(int argc, char **argv)".into()),
        fn_hash: Some("ab".repeat(32)),
        completeness: Completeness::Complete,
        mangled: None,
    };
    add(o, "function_summary", summary.clone())?;
    add(
        o,
        "decompile_result",
        DecompileResult {
            function: Locator::ram(0x401000),
            language: "c".into(),
            text: "int main(void) { return 0; }".into(),
            tokens: vec![
                Token {
                    start: 0,
                    end: 3,
                    kind: TokenKind::Type,
                    target: None,
                    symbol: None,
                    varnode: None,
                },
                Token {
                    start: 4,
                    end: 8,
                    kind: TokenKind::Function,
                    target: Some(Locator::ram(0x401000)),
                    symbol: Some("main".into()),
                    varnode: Some("(ram, 0x401000, 1)".into()),
                },
            ],
            warnings: vec!["w".into()],
            completeness: Completeness::Partial { reason: "r".into() },
        },
    )?;
    add(
        o,
        "error",
        ProtoError::new(ErrorCode::EngineRejected, "name exists")
            .with_details(json!({"name": "x"})),
    )?;
    add(
        o,
        "handshake",
        Handshake {
            protocol: PROTOCOL_VERSION,
            build: "kraken-ghidra 0.0.0 (ghidra 12.1.4)".into(),
            capabilities: vec![Capability {
                name: "decompile".into(),
                version: 1,
            }],
        },
    )?;
    add(
        o,
        "page_request",
        PageRequest {
            cursor: Some("0x401000".into()),
            limit: Some(10),
        },
    )?;
    add(
        o,
        "function_page",
        Page {
            items: vec![summary],
            next_cursor: Some("0x402000".into()),
            total: Some(562),
        },
    )?;
    add(
        o,
        "untrusted_string",
        Untrusted("evil \u{1b}[31m text".to_string()),
    )?;
    program_samples(o)?;
    Ok(o.clone())
}

/// Samples of the program-data types (memory map, bytes, listing, xrefs, CFG, strings, symbols).
fn program_samples(o: &mut Samples) -> Result<(), String> {
    use kraken_proto::{
        BytesRead, Cfg, CfgBlock, CfgEdge, CfgEdgeKind, DisasmRow, FlowKind, FunctionRef,
        MemoryBlock, MemoryKind, OperandKind, OperandToken, StringEncoding, StringEntry,
        SymbolEntry, SymbolKind, Xref, XrefKind,
    };

    add(
        o,
        "memory_block",
        MemoryBlock {
            name: ".text".into(),
            space: "ram".into(),
            start: Hex64(0x401000),
            end: Hex64(0x402000),
            perms: "r-x".into(),
            initialized: true,
            kind: MemoryKind::Default,
        },
    )?;
    add(
        o,
        "bytes_read",
        BytesRead {
            start: Hex64(0x401000),
            bytes: vec![0x55, 0x48, 0x89, 0xe5, 0, 0],
            uninitialized: vec![range(0x401004, 0x401006)],
        },
    )?;
    add(
        o,
        "disasm_row",
        DisasmRow {
            address: Hex64(0x401004),
            bytes: "e8f7ffffff".into(),
            mnemonic: "call".into(),
            operands: vec![OperandToken {
                text: "helper".into(),
                kind: OperandKind::Symbol,
                target: Some(Locator::ram(0x401000)),
            }],
            comment: Some("calls the helper".into()),
            labels: vec!["loop_top".into()],
            flow: FlowKind::Call,
        },
    )?;
    add(
        o,
        "xref",
        Xref {
            from: Hex64(0x401004),
            to: Hex64(0x401000),
            kind: XrefKind::Call,
            from_function: Some(FunctionRef {
                address: Hex64(0x401000),
                name: "main".into(),
            }),
            to_function: None,
        },
    )?;
    add(
        o,
        "cfg",
        Cfg {
            function: Hex64(0x401000),
            blocks: vec![
                CfgBlock {
                    start: Hex64(0x401000),
                    end: Hex64(0x401010),
                    instructions: 4,
                },
                CfgBlock {
                    start: Hex64(0x401010),
                    end: Hex64(0x401018),
                    instructions: 2,
                },
            ],
            edges: vec![
                CfgEdge {
                    from: Hex64(0x401000),
                    to: Hex64(0x401010),
                    kind: CfgEdgeKind::ConditionalFalse,
                },
                CfgEdge {
                    from: Hex64(0x401000),
                    to: Hex64(0x401000),
                    kind: CfgEdgeKind::Switch,
                },
            ],
        },
    )?;
    add(
        o,
        "string_entry",
        StringEntry {
            address: Hex64(0x402000),
            value: "hello \u{1b}[31mworld".into(),
            encoding: StringEncoding::Ascii,
            length: 18,
        },
    )?;
    add(
        o,
        "symbol_entry",
        SymbolEntry {
            name: "printf".into(),
            address: Some(Hex64(0x401030)),
            library: Some("libc.so.6".into()),
            kind: SymbolKind::Function,
            mangled: None,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_samples_are_current() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema/samples");
        let samples = samples().expect("samples build");
        for (name, value) in &samples {
            let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
            let committed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            assert_eq!(
                &committed, value,
                "{name} is stale: run cargo xtask samples"
            );
        }
        let count = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(count, samples.len(), "stray files in schema/samples");
    }
}
