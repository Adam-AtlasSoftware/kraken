//! `patch_asm` and `patch_string`: patches written as assembly lines or as text.
//!
//! `patch_asm` assembles one or several instructions with the engine's assembler, pads the result
//! with NOPs to the next instruction boundary of the code already there and reports which
//! following instructions it replaces. `patch_string` rewrites a NUL-terminated string in place:
//! the new text must fit in the old one's bytes, the rest is NUL padding. Both record an ordinary
//! byte patch (`patch_set`: logged, undoable, nothing on disk until `patch_export`).

use async_trait::async_trait;
use kraken_engine::{Cap, unsupported};
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted, hex_bytes, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

use super::locator;
use super::patch::{
    MAX_ASSEMBLY_LINE, MAX_ASSEMBLY_LINES, MAX_PATCH_BYTES, MAX_PATCH_NOTE, PatchEditOut,
    sanitize_multiline, set_patch,
};
use super::patch_intent::{PatchIntentOut, Planned, finish, instructions, isa_for};

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

// ---- patch_asm --------------------------------------------------------------------------

/// Arguments of `patch_asm`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchAsmArgs {
    /// Address of the first instruction to replace, as `0x...`.
    pub address: Hex64,
    /// One instruction or several, separated by `;` or newlines, in the syntax the Listing shows.
    pub text: String,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// The patch set to put the patch in (see `patch_group_set`).
    #[serde(default)]
    pub group: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Replaces instructions with assembled ones.
pub struct PatchAsm;

#[async_trait]
impl Command for PatchAsm {
    type Args = PatchAsmArgs;
    type Output = PatchIntentOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_asm",
            "Replace instructions with assembly you type, padded with NOPs to an instruction boundary",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Assembles one or several instructions (separated by `;` or newlines) for the \
             program's processor at `address` and records them as a byte patch like `patch_set`. \
             When the new code is shorter than the instructions it replaces, the rest is filled \
             with NOPs so no half instruction is left behind; when it is longer, the following \
             instructions it overwrites are listed in `notes` and `old_disassembly`. `preview` \
             shows the old and new disassembly and the bytes without recording.\n\
             Example: patch_asm {\"address\": \"0x401136\", \"text\": \"xor eax, eax; ret\", \"preview\": true}",
        )
        .details(
            "Uses the engine's assembler (see `assemble`): Ghidra's SLEIGH assembler on the Ghidra \
             engine, iced for x86 and x86-64 on the native engine, which resolves function and \
             label names in operands. Branches are encoded for the address they are placed at. At \
             most 64 instructions of 200 characters. Nothing on disk changes until `patch_export`.",
        )
        .needs(&[Cap::Assembler, Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchAsmArgs,
    ) -> Result<PatchIntentOut, ProtoError> {
        let text = sanitize_multiline(&args.text).trim().to_string();
        let lines = text
            .split([';', '\n'])
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>();
        if lines.is_empty() {
            return Err(invalid("text is empty; give an instruction such as `nop`"));
        }
        if lines.len() > MAX_ASSEMBLY_LINES
            || lines.iter().any(|l| l.chars().count() > MAX_ASSEMBLY_LINE)
        {
            return Err(invalid(format!(
                "give at most {MAX_ASSEMBLY_LINES} instructions of at most {MAX_ASSEMBLY_LINE} \
                 characters each"
            )));
        }
        let project = s.project()?;
        let engine = project.engine();
        let asm = engine.assembler().ok_or_else(|| unsupported("assembler"))?;
        let block = asm
            .assemble_block(&locator(args.address), &text, &ctx.cancel)
            .await?;
        if block.bytes.is_empty() {
            return Err(invalid("the text assembled to no bytes"));
        }
        if block.bytes.len() > MAX_PATCH_BYTES {
            return Err(invalid(format!(
                "the code is {} bytes; a patch covers at most {MAX_PATCH_BYTES}",
                block.bytes.len()
            )));
        }
        let original =
            super::patch::read_original(&project, ctx, args.address, block.bytes.len()).await?;
        // The instructions the bytes land on, for the before/after listing; none when the
        // address is not code the engine knows.
        let count = 1 + block.overwritten;
        let old = instructions(&project, ctx, args.address, count)
            .await
            .unwrap_or_default();
        let isa = isa_for(&project, &old).ok();
        let mut notes = vec![format!(
            "{} instruction{} assembled to {} byte{}",
            lines.len(),
            if lines.len() == 1 { "" } else { "s" },
            block.bytes.len() - block.pad as usize,
            if block.bytes.len() - block.pad as usize == 1 {
                ""
            } else {
                "s"
            }
        )];
        if block.pad > 0 {
            notes.push(format!(
                "padded with {} byte{} of NOP up to the next instruction boundary",
                block.pad,
                if block.pad == 1 { "" } else { "s" }
            ));
        }
        if block.overwritten > 0 {
            notes.push(format!(
                "overwrites {} following instruction{} (listed under old_disassembly)",
                block.overwritten,
                if block.overwritten == 1 { "" } else { "s" }
            ));
        }
        let plan = Planned {
            intent: "asm",
            address: args.address,
            original,
            replacement: block.bytes,
            old,
            notes,
            isa,
        };
        finish(s, ctx, plan, args.note, args.preview, args.group).await
    }
}

// ---- patch_string -----------------------------------------------------------------------

/// How the characters of a string are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatchStringEncoding {
    /// Look at the bytes there: 16-bit characters with zero high bytes mean UTF-16LE, anything
    /// else UTF-8.
    Auto,
    /// 7-bit ASCII, one byte per character.
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 little endian, two bytes per unit, ended by two zero bytes.
    Utf16le,
}

impl PatchStringEncoding {
    fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16le => "utf16le",
        }
    }
}

/// Longest string `patch_string` handles, in bytes.
pub const MAX_STRING_BYTES: usize = MAX_PATCH_BYTES;

/// Arguments of `patch_string`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchStringArgs {
    /// Address of the string's first byte, as `0x...`.
    pub address: Hex64,
    /// The new text. At most as many bytes as the old text (in the chosen encoding).
    pub text: String,
    /// How the string is stored (default `auto`).
    #[serde(default)]
    pub encoding: Option<PatchStringEncoding>,
    /// A short note on why, at most 1000 characters.
    #[serde(default)]
    pub note: Option<String>,
    /// The patch set to put the patch in (see `patch_group_set`).
    #[serde(default)]
    pub group: Option<String>,
    /// Only report what would be written; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// Result of `patch_string`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchStringOut {
    /// The string's address.
    pub address: Hex64,
    /// The encoding used: `ascii`, `utf8` or `utf16le`.
    pub encoding: String,
    /// The string there now (binary-derived text, decoded lossily): untrusted data.
    pub old_text: Untrusted<String>,
    /// The new text.
    pub new_text: String,
    /// Bytes the old text takes, terminator not counted: the room the new text has.
    pub capacity: u32,
    /// Bytes the new text takes.
    pub used: u32,
    /// Bytes of NUL padding after the new text, terminator included.
    pub padding: u32,
    /// The bytes there now, as lower-case hex (text, terminator).
    pub original: String,
    /// The bytes the patch writes, as lower-case hex.
    pub replacement: String,
    /// True when `preview` was set and nothing was recorded.
    pub preview: bool,
    /// The edit as the log took it; absent for a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit: Option<PatchEditOut>,
}

/// Encodes `text` for `enc`, refusing characters the encoding cannot hold.
pub fn encode_string(text: &str, enc: PatchStringEncoding) -> Result<Vec<u8>, ProtoError> {
    if text.contains('\0') {
        return Err(invalid(
            "the text contains a NUL character; the terminator is added for you",
        ));
    }
    match enc {
        PatchStringEncoding::Ascii => {
            if let Some(c) = text.chars().find(|c| !c.is_ascii()) {
                return Err(invalid(format!(
                    "{c:?} is not ASCII; use encoding utf8 or utf16le"
                )));
            }
            Ok(text.as_bytes().to_vec())
        }
        PatchStringEncoding::Utf16le => {
            Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect())
        }
        PatchStringEncoding::Utf8 | PatchStringEncoding::Auto => Ok(text.as_bytes().to_vec()),
    }
}

/// What `auto` means for the bytes at the start of a string.
pub fn detect_encoding(bytes: &[u8]) -> PatchStringEncoding {
    let wide = bytes.len() >= 4 && bytes[0] != 0 && bytes[1] == 0 && bytes[2] != 0 && bytes[3] == 0;
    if wide {
        PatchStringEncoding::Utf16le
    } else {
        PatchStringEncoding::Utf8
    }
}

/// The plan for rewriting the string at the start of `bytes`: the bytes to write over the old
/// text and its terminator, and the figures. `bytes` is what is mapped from the string's address
/// on. Pure, so the GUI's counter and the command agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPlan {
    /// The encoding used.
    pub encoding: PatchStringEncoding,
    /// The old text, decoded lossily.
    pub old_text: String,
    /// Bytes of the old text without its terminator.
    pub capacity: usize,
    /// Bytes of the new text.
    pub used: usize,
    /// The bytes now at the address (old text and terminator).
    pub original: Vec<u8>,
    /// The bytes to write.
    pub replacement: Vec<u8>,
}

/// Plans the rewrite, or says why the text does not fit.
pub fn plan_string(
    bytes: &[u8],
    text: &str,
    enc: PatchStringEncoding,
) -> Result<StringPlan, ProtoError> {
    let enc = if enc == PatchStringEncoding::Auto {
        detect_encoding(bytes)
    } else {
        enc
    };
    let width = if enc == PatchStringEncoding::Utf16le {
        2
    } else {
        1
    };
    let capacity = bytes
        .chunks_exact(width)
        .position(|u| u.iter().all(|b| *b == 0))
        .map(|n| n * width)
        .ok_or_else(|| {
            invalid(format!(
                "no string terminator within the {} bytes at this address; is it a string?",
                bytes.len()
            ))
        })?;
    let new = encode_string(text, enc)?;
    if new.len() > capacity {
        return Err(invalid(format!(
            "the new text takes {} bytes as {} but the string here holds {capacity}; shorten it by \
             {} byte{} (patch_string never moves other data)",
            new.len(),
            enc.name(),
            new.len() - capacity,
            if new.len() - capacity == 1 { "" } else { "s" }
        )));
    }
    let old_text = match enc {
        PatchStringEncoding::Utf16le => String::from_utf16_lossy(
            &bytes[..capacity]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        ),
        _ => String::from_utf8_lossy(&bytes[..capacity]).into_owned(),
    };
    let total = capacity + width;
    let mut replacement = new.clone();
    replacement.resize(total, 0);
    Ok(StringPlan {
        encoding: enc,
        old_text,
        capacity,
        used: new.len(),
        original: bytes[..total].to_vec(),
        replacement,
    })
}

/// Rewrites a string in place.
pub struct PatchString;

#[async_trait]
impl Command for PatchString {
    type Args = PatchStringArgs;
    type Output = PatchStringOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_string",
            "Rewrite a NUL-terminated string in place, same length or shorter",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Replaces the text of the string at `address` and fills what is left of the old text \
             with NULs, so the terminator stays and nothing after the string moves. The text must \
             fit in the old text's bytes in the chosen encoding (`ascii`, `utf8`, `utf16le`; \
             `auto` looks at the bytes); a longer one is refused with how many bytes to cut. \
             Records a byte patch like `patch_set` (logged, undoable, nothing on disk until \
             `patch_export`); `preview` records nothing.\n\
             Example: patch_string {\"address\": \"0x402010\", \"text\": \"Hello\", \"preview\": true}",
        )
        .details(
            "The old string is the run of characters from `address` to the first zero unit (one \
             byte, or two for utf16le) within 4096 bytes. The patch covers that run and its \
             terminator. Characters the encoding cannot hold (non-ASCII under `ascii`) and NUL \
             characters in the text are refused.",
        )
        .needs(&[Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchStringArgs,
    ) -> Result<PatchStringOut, ProtoError> {
        let note = sanitize(args.note.as_deref().unwrap_or(""))
            .trim()
            .to_string();
        if note.chars().count() > MAX_PATCH_NOTE {
            return Err(invalid(format!(
                "note is longer than {MAX_PATCH_NOTE} characters"
            )));
        }
        let project = s.project()?;
        let engine = project.engine();
        let reader = engine
            .memory_reader()
            .ok_or_else(|| unsupported("memory_reader"))?;
        let read = reader
            .read_bytes(
                &locator(args.address),
                (MAX_STRING_BYTES + 2) as u32,
                &ctx.cancel,
            )
            .await?;
        if read.bytes.is_empty() {
            return Err(invalid(format!("{} is not mapped", args.address.to_hex())));
        }
        let mapped = read
            .uninitialized
            .iter()
            .map(|r| r.start.0.saturating_sub(args.address.0) as usize)
            .min()
            .map_or(read.bytes.len(), |n| n.min(read.bytes.len()));
        let plan = plan_string(
            &read.bytes[..mapped],
            &args.text,
            args.encoding.unwrap_or(PatchStringEncoding::Auto),
        )?;
        if !args.preview && plan.original == plan.replacement {
            return Err(invalid("the string already reads that way"));
        }
        let edit = if args.preview {
            None
        } else {
            let note = if note.is_empty() {
                format!("string: {}", short(&args.text))
            } else {
                note
            };
            Some(
                set_patch(
                    s,
                    ctx,
                    args.address,
                    plan.replacement.clone(),
                    note,
                    args.group,
                )
                .await?,
            )
        };
        Ok(PatchStringOut {
            address: args.address,
            encoding: plan.encoding.name().into(),
            old_text: crate::validate::untrusted(&plan.old_text),
            new_text: args.text.clone(),
            capacity: plan.capacity as u32,
            used: plan.used as u32,
            padding: (plan.replacement.len() - plan.used) as u32,
            original: hex_bytes(&plan.original),
            replacement: hex_bytes(&plan.replacement),
            preview: args.preview,
            edit,
        })
    }
}

fn short(text: &str) -> String {
    let t: String = text.chars().take(40).collect();
    if text.chars().count() > 40 {
        format!("{t}...")
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_shorter_is_nul_padded_and_longer_is_refused() {
        let p = plan_string(b"Hello, world\0rest", "Hi", PatchStringEncoding::Auto).expect("fits");
        assert_eq!(p.encoding, PatchStringEncoding::Utf8);
        assert_eq!(p.capacity, 12);
        assert_eq!(p.replacement, b"Hi\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(p.original, b"Hello, world\0");
        let e = plan_string(b"Hi\0", "Hello", PatchStringEncoding::Utf8).expect_err("too long");
        assert!(e.message.contains("shorten it by 3"), "{}", e.message);
    }

    #[test]
    fn utf16_units_are_two_bytes_and_auto_detects_them() {
        let old = b"A\0B\0C\0\0\0zz";
        assert_eq!(detect_encoding(old), PatchStringEncoding::Utf16le);
        let p = plan_string(old, "Hi", PatchStringEncoding::Auto).expect("fits");
        assert_eq!(p.capacity, 6);
        assert_eq!(p.replacement, b"H\0i\0\0\0\0\0");
        assert_eq!(p.old_text, "ABC");
        let e = plan_string(old, "ABCD", PatchStringEncoding::Utf16le).expect_err("too long");
        assert!(e.message.contains("8 bytes as utf16le"), "{}", e.message);
    }

    #[test]
    fn ascii_refuses_other_characters_and_nul() {
        assert!(encode_string("caf\u{e9}", PatchStringEncoding::Ascii).is_err());
        assert_eq!(
            encode_string("caf\u{e9}", PatchStringEncoding::Utf8)
                .expect("utf8")
                .len(),
            5
        );
        assert!(encode_string("a\0b", PatchStringEncoding::Utf8).is_err());
    }

    #[test]
    fn a_run_with_no_terminator_is_not_a_string() {
        assert!(plan_string(b"abc", "a", PatchStringEncoding::Utf8).is_err());
    }
}
