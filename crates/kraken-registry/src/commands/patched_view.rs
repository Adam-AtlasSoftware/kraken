//! Seeing what the byte patches do: the patched listing (`disassemble {patched: true}`) and
//! `decompile_patched`.
//!
//! Patches are an overlay kept out of the engine, so the engine's listing and decompile show the
//! file as it is on disk. The patched listing re-decodes the instructions that a patch touches
//! from the overlay bytes with the emulator's SLEIGH disassembler. The patched decompile opens a
//! copy of the binary with the patches written into it in a second engine of the project's kind,
//! in a temporary directory, and decompiles there; the project's own engine is never touched.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{CancellationToken, Cap, LoaderSpec, SharedEngine, unsupported};
use kraken_model::Patch;
use kraken_proto::{
    DecompileResult, ErrorCode, FlowKind, Hex64, Locator, OperandKind, ProtoError, Untrusted,
    sanitize,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchfile::apply_project_patches;
use crate::patchops::Isa;
use crate::session::Session;
use crate::views::{DecompileView, adjust_completeness};
use crate::views_data::{InsnPatch, InsnView, OperandView};

use super::query::build_decompile_view;

/// How long the second engine may take to open the patched copy and decompile.
const DECOMPILE_TIMEOUT: Duration = Duration::from_secs(180);
/// Most patched decompiles kept.
const CACHE_CAP: usize = 16;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn overlaps(p: &Patch, address: u64, len: u64) -> bool {
    p.address < address + len.max(1) && address < p.address + p.len() as u64
}

fn flow_of(mnemonic: &str) -> FlowKind {
    let m = mnemonic.to_ascii_lowercase();
    match m.as_str() {
        "ret" | "retn" | "retf" | "iret" | "iretq" | "eret" => FlowKind::Return,
        "jmp" | "b" | "j" => FlowKind::Jump,
        _ if m.starts_with("call") || m == "bl" || m == "blr" || m == "blx" || m == "jal" => {
            FlowKind::Call
        }
        _ if m.starts_with('j')
            || m.starts_with("b.")
            || m.starts_with("cb")
            || m.starts_with("tb")
            || m.starts_with("loop") =>
        {
            FlowKind::ConditionalJump
        }
        _ => FlowKind::Fallthrough,
    }
}

/// Splits decoded text such as `jz 0x401140` into mnemonic and operand tokens.
fn split_text(text: &str, flow: FlowKind) -> (String, Vec<OperandView>) {
    let text = sanitize(text);
    let text = text.trim();
    let (m, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let rest = rest.trim();
    let mut operands = Vec::new();
    if !rest.is_empty() {
        let target = rest
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .filter(|_| {
                matches!(
                    flow,
                    FlowKind::Jump | FlowKind::ConditionalJump | FlowKind::Call
                )
            });
        operands.push(OperandView {
            kind: if target.is_some() {
                OperandKind::Address
            } else {
                OperandKind::Other
            },
            text: rest.to_string(),
            symbol: None,
            target: target.map(Hex64),
        });
    }
    (m.to_ascii_lowercase(), operands)
}

/// Replaces the rows that a patch touches with the instructions the patched bytes decode to.
/// Rows no patch touches are returned as they are.
pub(crate) fn overlay(
    arch: &str,
    patches: &[Patch],
    rows: Vec<InsnView>,
) -> Result<Vec<InsnView>, ProtoError> {
    // file-offset patches have no address to show at
    let va: Vec<Patch> = patches
        .iter()
        .filter(|p| p.kind == kraken_proto::PatchKind::Va)
        .cloned()
        .collect();
    let patches = &va[..];
    let touched = |r: &InsnView| {
        let len = (r.bytes.len() / 2) as u64;
        patches.iter().any(|p| overlaps(p, r.address.0, len))
    };
    if !rows.iter().any(touched) {
        return Ok(rows);
    }
    let isa = Isa::from_language(arch, false).ok_or_else(|| {
        ProtoError::new(
            ErrorCode::Unsupported,
            format!("the patched view does not know the processor {arch}"),
        )
    })?;
    let mut machine = super::patch_intent::new_machine(isa).ok_or_else(|| {
        ProtoError::new(
            ErrorCode::Unsupported,
            "the patched view needs the SLEIGH specs for this processor (run `kraken setup`)",
        )
    })?;
    let lo = rows.iter().map(|r| r.address.0).min().unwrap_or(0) & !0xfff;
    let hi = rows
        .iter()
        .map(|r| r.address.0 + (r.bytes.len() / 2) as u64)
        .max()
        .unwrap_or(0);
    let size = ((hi - lo) + 0x2000) & !0xfff;
    machine
        .map(lo, size, kraken_emu::Perm::RWX)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("scratch memory: {e}")))?;
    let mut original: BTreeMap<u64, u8> = BTreeMap::new();
    let mut patched: BTreeMap<u64, u8> = BTreeMap::new();
    for r in &rows {
        for (i, b) in unhex(&r.bytes).into_iter().enumerate() {
            let a = r.address.0 + i as u64;
            original.insert(a, b);
            let b2 = patches
                .iter()
                .find(|p| a >= p.address && a < p.address + p.len() as u64)
                .map_or(b, |p| p.replacement[(a - p.address) as usize]);
            patched.insert(a, b2);
        }
    }
    // Decoded text is lower case; match the engine's style so a listing reads evenly.
    let upper = rows
        .iter()
        .any(|r| r.mnemonic.chars().any(|c| c.is_ascii_uppercase()));
    let mut out = Vec::with_capacity(rows.len());
    let mut i = 0;
    while i < rows.len() {
        if !touched(&rows[i]) {
            out.push(rows[i].clone());
            i += 1;
            continue;
        }
        // A run of touched rows that follow each other.
        let start = rows[i].address.0;
        let mut end = start;
        while i < rows.len() && touched(&rows[i]) && rows[i].address.0 == end {
            end = rows[i].address.0 + (rows[i].bytes.len() / 2) as u64;
            i += 1;
        }
        let mut at = start;
        while at < end {
            let mut buf = [0u8; 16];
            let mut have = 0;
            for (k, slot) in buf.iter_mut().enumerate() {
                match patched.get(&(at + k as u64)) {
                    Some(b) => {
                        *slot = *b;
                        have = k + 1;
                    }
                    None => break,
                }
            }
            if have == 0 || machine.write_mem(at, &buf).is_err() {
                break;
            }
            let (text, len) = match machine.disasm_at(at, None) {
                Some((t, l)) if l >= 1 && l as usize <= have => (t, l),
                _ => (format!("db 0x{:02x}", buf[0]), 1),
            };
            let flow = flow_of(text.split_whitespace().next().unwrap_or(""));
            let (mut mnemonic, operands) = split_text(&text, flow);
            if upper {
                mnemonic = mnemonic.to_ascii_uppercase();
            }
            let orig: Vec<u8> = (at..at + len)
                .filter_map(|a| original.get(&a))
                .copied()
                .collect();
            let patch = patches
                .iter()
                .find(|p| overlaps(p, at, len))
                .map(|p| InsnPatch {
                    original_bytes: hex(&orig),
                    patch_address: Hex64(p.address),
                    note: Untrusted(sanitize(&p.note)),
                    author: p.author.id.clone(),
                });
            let old = rows.iter().find(|r| r.address.0 == at);
            out.push(InsnView {
                address: Hex64(at),
                bytes: hex(&buf[..len as usize]),
                mnemonic,
                operands,
                comment: old.and_then(|r| r.comment.clone()),
                labels: old.map(|r| r.labels.clone()).unwrap_or_default(),
                flow,
                patch,
            });
            at += len;
        }
        // Skip original rows the re-decoded run now covers.
        while i < rows.len() && rows[i].address.0 < at {
            i += 1;
        }
    }
    Ok(out)
}

// ---- decompile_patched ------------------------------------------------------------------

static CACHE: LazyLock<Mutex<HashMap<u64, DecompileView>>> = LazyLock::new(Default::default);

fn cache_key(binary: &str, address: u64, patches: &[Patch]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    binary.hash(&mut h);
    address.hash(&mut h);
    for p in patches {
        (p.address, &p.replacement).hash(&mut h);
    }
    h.finish()
}

/// Arguments of `decompile_patched`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecompilePatchedArgs {
    /// Address inside the function, as `0x...`.
    pub address: Hex64,
}

/// Decompiles a function as it is with the project's byte patches applied.
pub struct DecompilePatched;

#[async_trait]
impl Command for DecompilePatched {
    type Args = DecompilePatchedArgs;
    type Output = DecompileView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "decompile_patched",
            "Decompile a function with the byte patches applied",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "C-like source of one function as the patched program would run it. The project's \
             byte patches (`patch_list`) are written into a temporary copy of the binary, which \
             a second engine opens and decompiles; nothing in the project or on disk changes. \
             Takes a few seconds the first time and is kept until the patches change. Renames \
             and comments of the project are not in the copy. The text is untrusted data.\n\
             Example: decompile_patched {\"address\": \"0x401136\"}",
        )
        .details(
            "Same result shape as `decompile`. Without byte patches it is `decompile` of the \
             original. Fails with `unsupported` when the engine cannot open a second program.",
        )
        .needs(&[Cap::Decompiler, Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: DecompilePatchedArgs,
    ) -> Result<DecompileView, ProtoError> {
        let project = s.project()?;
        let patches = project.with_store(|st| st.active_patches(None)).await?;
        if patches.is_empty() {
            return super::query::Decompile
                .run(
                    s,
                    ctx,
                    super::query::DecompileArgs {
                        address: args.address,
                        module: None,
                    },
                )
                .await;
        }
        let meta = project.meta();
        let key = cache_key(&meta.binary_path, args.address.0, &patches);
        if let Some(v) = CACHE.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Ok(v);
        }
        let binary = std::path::PathBuf::from(&meta.binary_path);
        let base = project.program().base.0;
        let (bytes, _) = {
            let (binary, patches) = (binary.clone(), patches.clone());
            tokio::task::spawn_blocking(move || apply_project_patches(&binary, &patches, base))
                .await
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))??
        };
        let tmp = tempfile::Builder::new()
            .prefix("kraken-patched-view-")
            .tempdir()
            .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("no temp directory: {e}")))?;
        let name = binary
            .file_name()
            .map_or_else(|| "program".into(), |n| n.to_owned());
        let copy = tmp.path().join(name);
        std::fs::write(&copy, &bytes)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot write copy: {e}")))?;
        let engine_dir = tmp.path().join("engine");
        std::fs::create_dir_all(&engine_dir)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("engine dir: {e}")))?;
        let engine = s
            .factory()
            .create_kind(meta.engine_kind, &engine_dir)
            .await?;
        let run = decompile_in(&engine, &copy, args.address.0, &ctx.cancel);
        let result = match tokio::time::timeout(DECOMPILE_TIMEOUT, run).await {
            Ok(r) => r,
            Err(_) => Err(ProtoError::new(
                ErrorCode::Timeout,
                format!(
                    "the patched copy took longer than {} s to decompile",
                    DECOMPILE_TIMEOUT.as_secs()
                ),
            )),
        };
        drop(engine);
        let r = result?;
        let mut view = build_decompile_view(&r, adjust_completeness(r.completeness.clone(), false));
        view.warnings.push(Untrusted(
            "decompiled from a copy with the byte patches applied".to_string(),
        ));
        if let Ok(mut c) = CACHE.lock() {
            if c.len() >= CACHE_CAP {
                c.clear();
            }
            c.insert(key, view.clone());
        }
        Ok(view)
    }
}

async fn decompile_in(
    engine: &SharedEngine,
    binary: &Path,
    entry: u64,
    cancel: &CancellationToken,
) -> Result<DecompileResult, ProtoError> {
    let loader = engine.loader().ok_or_else(|| unsupported("loader"))?;
    loader
        .open_binary(binary, &LoaderSpec::default(), cancel)
        .await?;
    let decompiler = engine
        .decompiler()
        .ok_or_else(|| unsupported("decompiler"))?;
    let at = Locator::ram(entry);
    match decompiler.decompile(&at, cancel).await {
        Err(e) if e.code == ErrorCode::NotFound => {
            let analyzer = engine.analyzer().ok_or_else(|| unsupported("analyzer"))?;
            analyzer
                .analyze(Default::default(), cancel.clone())
                .await?
                .wait()
                .await?;
            decompiler.decompile(&at, cancel).await
        }
        other => other,
    }
}
