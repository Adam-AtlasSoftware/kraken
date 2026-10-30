//! `patch_nop`, `patch_branch`, `patch_return`, `patch_fill`, `patch_constant`: patch intents.
//!
//! Each one reads the instruction(s) at an address, computes the replacement bytes for the
//! program's own instruction set (see `patchops`, no assembler involved), shows the old and new
//! disassembly and then records an ordinary byte patch through the same path as `patch_set`, so
//! the edit is logged, attributed, undoable and follows the agent policy. With `preview` set
//! nothing is recorded: the answer is what would be written.

use async_trait::async_trait;
use kraken_engine::{Cap, DisasmRequest, unsupported};
use kraken_proto::{
    DisasmRow, DisasmScope, ErrorCode, Hex64, PageRequest, ProtoError, hex_bytes, sanitize,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchops::{self, BranchMode, Isa};
use crate::session::{Project, Session};

use super::patch::{MAX_PATCH_BYTES, MAX_PATCH_NOTE, PatchEditOut, parse_hex, set_patch};

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn from_intent(e: patchops::IntentError) -> ProtoError {
    invalid(e.0)
}

/// Longest run of instructions `patch_nop` covers.
const MAX_NOP_INSTRUCTIONS: u32 = 256;

/// What an intent would write, and what it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchIntentOut {
    /// The intent: `nop`, `branch_invert`, `branch_always`, `branch_never`, `return`, `fill` or
    /// `constant`.
    pub intent: String,
    /// The first patched address.
    pub address: Hex64,
    /// Number of bytes the patch covers.
    pub length: u32,
    /// The bytes there now, as lower-case hex.
    pub original: String,
    /// The bytes the patch writes, as lower-case hex.
    pub replacement: String,
    /// The instructions being replaced, one per line (`0x401136  jne 0x40114a`).
    pub old_disassembly: Vec<String>,
    /// The new bytes decoded, one instruction per line; empty when the emulator's SLEIGH
    /// specs are not installed.
    pub new_disassembly: Vec<String>,
    /// Things to know: assumptions made, bytes padded.
    pub notes: Vec<String>,
    /// True when `preview` was set and nothing was recorded.
    pub preview: bool,
    /// The edit as the log took it; absent for a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit: Option<PatchEditOut>,
}

/// The arguments every intent shares are repeated on each command so the schemas stay flat.
struct Planned {
    intent: &'static str,
    address: Hex64,
    original: Vec<u8>,
    replacement: Vec<u8>,
    old: Vec<DisasmRow>,
    notes: Vec<String>,
    isa: Option<Isa>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
        .collect()
}

fn line(row: &DisasmRow) -> String {
    let ops: String = row.operands.iter().map(|t| t.text.as_str()).collect();
    format!("{:#x}  {} {}", row.address.0, row.mnemonic, ops)
        .trim_end()
        .to_string()
}

/// The `count` instructions that start at `address`. The first must start exactly there.
async fn instructions(
    project: &Project,
    ctx: &CallContext,
    address: Hex64,
    count: u32,
) -> Result<Vec<DisasmRow>, ProtoError> {
    let engine = project.engine();
    let dis = engine
        .disassembler()
        .ok_or_else(|| unsupported("disassembler"))?;
    let page = dis
        .disassemble(
            &DisasmRequest {
                start: address,
                scope: DisasmScope::Linear,
            },
            &PageRequest {
                cursor: None,
                limit: Some(count),
            },
            &ctx.cancel,
        )
        .await?;
    let mut rows = page.items;
    rows.truncate(count as usize);
    if rows.first().is_none_or(|r| r.address != address) {
        return Err(invalid(format!(
            "there is no instruction at {}; define code there first (define_code)",
            address.to_hex()
        )));
    }
    Ok(rows)
}

fn instruction_bytes(rows: &[DisasmRow]) -> Vec<u8> {
    rows.iter().flat_map(|r| unhex(&r.bytes)).collect()
}

fn isa_for(project: &Project, rows: &[DisasmRow]) -> Result<Isa, ProtoError> {
    let arch = project.program().arch;
    let thumb = rows.first().is_some_and(|r| r.bytes.len() == 4);
    Isa::from_language(&arch, thumb).ok_or_else(|| {
        ProtoError::new(
            ErrorCode::Unsupported,
            format!("patch intents do not know the processor {arch} (x86, ARM, AArch64 and RISC-V, little endian)"),
        )
    })
}

/// A scratch emulator machine for `isa`; the caller maps memory.
pub(crate) fn new_machine(isa: Isa) -> Option<kraken_emu::Machine> {
    use kraken_emu::{Arch, Machine, SpecRoots};
    let arch = match isa {
        Isa::X86 => Arch::X86,
        Isa::X86_64 => Arch::X86_64,
        Isa::Arm | Isa::Thumb => Arch::Arm,
        Isa::Aarch64 => Arch::Aarch64,
        Isa::Riscv32 => Arch::Riscv32,
        Isa::Riscv64 => Arch::Riscv64,
    };
    Machine::new(arch, &SpecRoots::discover()).ok()
}

/// Decodes `bytes` placed at `address` with the emulator's SLEIGH disassembler. `None` when the
/// specs for the architecture are not installed.
fn decode_new(isa: Isa, address: u64, bytes: &[u8]) -> Option<Vec<String>> {
    use kraken_emu::Perm;
    let mut m = new_machine(isa)?;
    let page = address & !0xfff;
    m.map(page, 0x3000, Perm::RWX).ok()?;
    m.write_mem(address, bytes).ok()?;
    let end = address + bytes.len() as u64;
    let mode = (isa == Isa::Thumb).then_some(true);
    let mut at = address;
    let mut out = Vec::new();
    while at < end && out.len() < 64 {
        let (text, len) = m.disasm_at(at, mode)?;
        out.push(format!("{at:#x}  {text}"));
        at += len.max(1);
    }
    Some(out)
}

async fn finish(
    s: &Session,
    ctx: &CallContext,
    plan: Planned,
    note: Option<String>,
    preview: bool,
) -> Result<PatchIntentOut, ProtoError> {
    if plan.replacement.len() > MAX_PATCH_BYTES {
        return Err(invalid(format!(
            "a patch covers at most {MAX_PATCH_BYTES} bytes"
        )));
    }
    let note = sanitize(note.as_deref().unwrap_or("")).trim().to_string();
    if note.chars().count() > MAX_PATCH_NOTE {
        return Err(invalid(format!(
            "note is longer than {MAX_PATCH_NOTE} characters"
        )));
    }
    let note = if note.is_empty() {
        plan.intent.replace('_', " ")
    } else {
        note
    };
    let new_disassembly = match plan.isa {
        Some(isa) => {
            let (address, bytes) = (plan.address.0, plan.replacement.clone());
            tokio::task::spawn_blocking(move || decode_new(isa, address, &bytes))
                .await
                .ok()
                .flatten()
                .unwrap_or_default()
        }
        None => Vec::new(),
    };
    let edit = if preview {
        None
    } else {
        Some(set_patch(s, ctx, plan.address, plan.replacement.clone(), note).await?)
    };
    Ok(PatchIntentOut {
        intent: plan.intent.to_string(),
        address: plan.address,
        length: plan.replacement.len() as u32,
        original: hex_bytes(&plan.original),
        replacement: hex_bytes(&plan.replacement),
        old_disassembly: plan.old.iter().map(line).collect(),
        new_disassembly,
        notes: plan.notes,
        preview,
        edit,
    })
}

// ---- patch_nop --------------------------------------------------------------------------

/// Arguments of `patch_nop`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchNopArgs {
    /// Address of the first instruction, as `0x...`.
    pub address: Hex64,
    /// How many instructions to NOP (default 1, at most 256).
    #[serde(default)]
    pub count: Option<u32>,
    /// Alternatively the number of bytes to cover; it must end on an instruction boundary.
    #[serde(default)]
    pub length: Option<u32>,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Replaces instructions with NOPs.
pub struct PatchNop;

#[async_trait]
impl Command for PatchNop {
    type Args = PatchNopArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_nop",
            "Patch instructions out with NOPs in the processor's own encoding",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Replaces one instruction (or `count` instructions, or `length` bytes) with NOPs: \
             x86 gets the multi-byte forms, ARM, Thumb, AArch64 and RISC-V their own. Records a \
             byte patch like `patch_set` (logged, undoable; nothing on disk changes until \
             `patch_export`). `preview` shows the old and new disassembly without recording.\n\
             Example: patch_nop {\"address\": \"0x401136\", \"count\": 2, \"preview\": true}",
        )
        .details(
            "The range always covers whole instructions. A range that overlaps another patch is \
             refused. The new disassembly is decoded with the emulator's SLEIGH specs and is \
             empty when those are not installed.",
        )
        .needs(&[Cap::Memory, Cap::Disassembler])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchNopArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        let project = s.project()?;
        let want = match (args.count, args.length) {
            (Some(_), Some(_)) => return Err(invalid("give count or length, not both")),
            (_, Some(0)) | (Some(0), _) => return Err(invalid("nothing to NOP: it is 0")),
            (_, Some(n)) => n.min(MAX_PATCH_BYTES as u32),
            (c, None) => c.unwrap_or(1).min(MAX_NOP_INSTRUCTIONS),
        };
        let fetched = instructions(&project, ctx, args.address, want).await?;
        let rows: Vec<DisasmRow> = if args.length.is_some() {
            let mut taken = Vec::new();
            let mut total = 0usize;
            for r in fetched {
                if total >= want as usize {
                    break;
                }
                total += r.bytes.len() / 2;
                taken.push(r);
            }
            if total != want as usize {
                return Err(invalid(format!(
                    "a range of {want} bytes ends inside an instruction; whole instructions cover \
                     {total} bytes"
                )));
            }
            taken
        } else {
            if fetched.len() < want as usize {
                return Err(invalid(format!(
                    "only {} instruction(s) follow {}",
                    fetched.len(),
                    args.address.to_hex()
                )));
            }
            fetched
        };
        let isa = isa_for(&project, &rows)?;
        let original = instruction_bytes(&rows);
        let replacement = patchops::nop(isa, original.len()).map_err(from_intent)?;
        let plan = Planned {
            intent: "nop",
            address: args.address,
            original,
            replacement,
            old: rows,
            notes: Vec::new(),
            isa: Some(isa),
        };
        finish(s, ctx, plan, args.note, args.preview).await
    }
}

// ---- patch_branch -----------------------------------------------------------------------

/// What `patch_branch` does to the branch.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BranchChange {
    /// Take the branch exactly when it was not taken.
    Invert,
    /// Always take it.
    Always,
    /// Never take it.
    Never,
}

/// Arguments of `patch_branch`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchBranchArgs {
    /// Address of the conditional branch, as `0x...`.
    pub address: Hex64,
    /// `invert`, `always` or `never`.
    pub mode: BranchChange,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Inverts, forces or removes a conditional branch.
pub struct PatchBranch;

#[async_trait]
impl Command for PatchBranch {
    type Args = PatchBranchArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_branch",
            "Invert, always take or never take a conditional branch",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Rewrites the conditional branch at `address`: `invert` flips its condition, \
             `always` turns it into a jump to the same target, `never` NOPs it out. Handles x86 \
             jcc (short and near), ARM and Thumb b<cond>/cbz/cbnz, AArch64 b.cond/cbz/cbnz/\
             tbz/tbnz and RISC-V branches. An instruction that is not a conditional branch is \
             refused with the reason. Records a byte patch (logged, undoable); `preview` \
             records nothing.\n\
             Example: patch_branch {\"address\": \"0x401136\", \"mode\": \"invert\"}",
        )
        .details(
            "The new instruction has the same length as the old one, except that an x86 near jcc \
             made `always` becomes a 5-byte jmp plus a 1-byte NOP. ARM 32-bit instructions of \
             4 bytes are read as A32; 4-byte Thumb-2 branches are refused.",
        )
        .needs(&[Cap::Memory, Cap::Disassembler])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchBranchArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        let project = s.project()?;
        let rows = instructions(&project, ctx, args.address, 1).await?;
        let isa = isa_for(&project, &rows)?;
        let original = instruction_bytes(&rows);
        let (mode, intent) = match args.mode {
            BranchChange::Invert => (BranchMode::Invert, "branch_invert"),
            BranchChange::Always => (BranchMode::Always, "branch_always"),
            BranchChange::Never => (BranchMode::Never, "branch_never"),
        };
        let replacement = patchops::branch(isa, &original, mode).map_err(from_intent)?;
        let mut notes = Vec::new();
        if replacement.len() == original.len()
            && matches!(isa, Isa::X86 | Isa::X86_64)
            && original.len() == 6
            && matches!(mode, BranchMode::Always)
        {
            notes.push("a 5-byte jmp followed by a 1-byte NOP; same target".into());
        }
        let plan = Planned {
            intent,
            address: args.address,
            original,
            replacement,
            old: rows,
            notes,
            isa: Some(isa),
        };
        finish(s, ctx, plan, args.note, args.preview).await
    }
}

// ---- patch_return -----------------------------------------------------------------------

/// Arguments of `patch_return`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchReturnArgs {
    /// Address of the function's entry, as `0x...`.
    pub address: Hex64,
    /// The value the function returns (default 0); negative values are two's complement.
    #[serde(default)]
    pub value: Option<i64>,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Makes a function return a constant.
pub struct PatchReturn;

#[async_trait]
impl Command for PatchReturn {
    type Args = PatchReturnArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_return",
            "Make a function return a constant right away",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Overwrites the start of the function at `address` with code that puts `value` in \
             the return register and returns, padding what is left of the covered instructions \
             with NOPs. Uses the platform's C convention (x86, x86-64 System V and Windows, \
             ARM, AArch64, RISC-V). Records a byte patch (logged, undoable); `preview` records \
             nothing.\n\
             Example: patch_return {\"address\": \"0x401136\", \"value\": 1}",
        )
        .details(
            "A 32-bit x86 function that pops its own arguments (stdcall) needs `ret N`; this \
             writes a plain `ret`, so use `patch_set` for those. The patch must fit in the \
             function's first instructions: it covers whole instructions only.",
        )
        .needs(&[Cap::Memory, Cap::Disassembler])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchReturnArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        let project = s.project()?;
        let rows = instructions(&project, ctx, args.address, 16).await?;
        let isa = isa_for(&project, &rows)?;
        let code = patchops::return_value(isa, args.value.unwrap_or(0)).map_err(from_intent)?;
        let lens: Vec<usize> = rows.iter().map(|r| r.bytes.len() / 2).collect();
        let covered = patchops::cover(&lens, code.len()).ok_or_else(|| {
            invalid("the function's first instructions are too short to hold the return code")
        })?;
        let used = lens
            .iter()
            .scan(0, |t, l| {
                *t += l;
                Some(*t)
            })
            .position(|t| t >= covered)
            .map_or(rows.len(), |i| i + 1);
        let rows: Vec<DisasmRow> = rows.into_iter().take(used).collect();
        let mut replacement = code;
        let mut notes = Vec::new();
        if covered > replacement.len() {
            let pad = covered - replacement.len();
            replacement.extend(patchops::nop(isa, pad).map_err(from_intent)?);
            notes.push(format!("padded with {pad} byte(s) of NOP"));
        }
        if isa == Isa::X86 {
            notes.push("plain ret: a stdcall function needs ret N (use patch_set)".into());
        }
        let plan = Planned {
            intent: "return",
            address: args.address,
            original: instruction_bytes(&rows),
            replacement,
            old: rows,
            notes,
            isa: Some(isa),
        };
        finish(s, ctx, plan, args.note, args.preview).await
    }
}

// ---- patch_fill -------------------------------------------------------------------------

/// Arguments of `patch_fill`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchFillArgs {
    /// First address to fill, as `0x...`.
    pub address: Hex64,
    /// Number of bytes to fill, 1 to 4096.
    pub length: u32,
    /// Hex bytes repeated to fill the range, such as `cc` or `0000` (default `00`).
    #[serde(default)]
    pub pattern: Option<String>,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Fills a range with a byte pattern.
pub struct PatchFill;

#[async_trait]
impl Command for PatchFill {
    type Args = PatchFillArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_fill",
            "Fill a range of bytes with a repeated pattern",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Overwrites `length` bytes at `address` with `pattern` repeated (cut to length), for \
             example `cc` to trap or `00` to blank data. Records a byte patch (logged, \
             undoable); `preview` records nothing. For NOPs that suit the processor use \
             `patch_nop`.\n\
             Example: patch_fill {\"address\": \"0x402000\", \"length\": 16, \"pattern\": \"cc\"}",
        )
        .needs(&[Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchFillArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        if args.length == 0 || args.length as usize > MAX_PATCH_BYTES {
            return Err(invalid(format!(
                "length is 1 to {MAX_PATCH_BYTES} bytes, got {}",
                args.length
            )));
        }
        let pattern = parse_hex(args.pattern.as_deref().unwrap_or("00"))?;
        let replacement: Vec<u8> = pattern
            .iter()
            .copied()
            .cycle()
            .take(args.length as usize)
            .collect();
        let project = s.project()?;
        let original =
            super::patch::read_original(&project, ctx, args.address, args.length as usize).await?;
        let plan = Planned {
            intent: "fill",
            address: args.address,
            original,
            replacement,
            old: Vec::new(),
            notes: Vec::new(),
            isa: None,
        };
        finish(s, ctx, plan, args.note, args.preview).await
    }
}

// ---- patch_constant ---------------------------------------------------------------------

/// Arguments of `patch_constant`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchConstantArgs {
    /// Address of the instruction holding the constant, as `0x...`.
    pub address: Hex64,
    /// The new constant (negative values are two's complement).
    pub value: i64,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Changes the immediate operand of an instruction.
pub struct PatchConstant;

#[async_trait]
impl Command for PatchConstant {
    type Args = PatchConstantArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_constant",
            "Change the constant (immediate) an instruction uses",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Rewrites the immediate operand of the instruction at `address` to `value` while \
             keeping its length: x86 mov/cmp/add/sub/and/or/xor/test/push/imul immediates, \
             AArch64 mov, add, sub and cmp, ARM and Thumb data-processing immediates, RISC-V \
             addi, lui and the compressed forms. A value the encoding cannot hold is refused \
             (it would need a longer instruction). Records a byte patch (logged, undoable); \
             `preview` records nothing.\n\
             Example: patch_constant {\"address\": \"0x401136\", \"value\": 100}",
        )
        .needs(&[Cap::Memory, Cap::Disassembler])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchConstantArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        let project = s.project()?;
        let rows = instructions(&project, ctx, args.address, 1).await?;
        let isa = isa_for(&project, &rows)?;
        let original = instruction_bytes(&rows);
        let edit = patchops::set_constant(isa, &original, args.value).map_err(from_intent)?;
        let plan = Planned {
            intent: "constant",
            address: args.address,
            original,
            replacement: edit.bytes,
            old: rows,
            notes: vec![format!("constant {} becomes {}", edit.old, args.value)],
            isa: Some(isa),
        };
        finish(s, ctx, plan, args.note, args.preview).await
    }
}
