//! `Assembler` for the native engine: x86 and x86-64 through iced, the other processors through
//! `llvm-mc`; every result decoded back through Sleigh (`asm/`).

use async_trait::async_trait;
use engine_native_sys::{Image, Segment, Session};
use kraken_engine::{AsmBlock, Assembler, CancellationToken, EngineResult};
use kraken_proto::{ErrorCode, Locator, ProtoError};

use crate::asm::{self, Decoded, Env, llvm_mc};
use crate::engine::{InProcessEngine, Program, native, ram_offset};

fn is_thumb(p: &Program, at: u64) -> bool {
    p.loaded
        .image
        .context
        .iter()
        .any(|c| c.name == "TMode" && c.value == 1 && (c.start..c.end).contains(&at))
}

/// Sleigh's reading of `bytes` placed at `at`, from a session over just those bytes.
fn decode_scratch(
    p: &Program,
    at: u64,
    bytes: &[u8],
    max: usize,
) -> Result<Vec<Decoded>, ProtoError> {
    let mut data = bytes.to_vec();
    let mem_size = data.len() as u64 + 16;
    data.resize(mem_size as usize, 0);
    let image = Image {
        segments: vec![Segment {
            start: at,
            data,
            mem_size,
            readonly: false,
        }],
        context: p.loaded.image.context.clone(),
    };
    let lang = &p.loaded.language;
    let mut s = Session::new(lang.id, lang.compiler, image).map_err(native)?;
    Ok(s.decode(at, max as u32)
        .map_err(native)?
        .into_iter()
        .map(|i| Decoded {
            length: i.length,
            mnemonic: i.mnemonic,
            body: i.body,
            targets: i.targets,
        })
        .collect())
}

impl InProcessEngine {
    /// The language of the open program and whether `at` is Thumb code (for `llvm-mc`).
    pub(crate) fn asm_context(&self, at: u64) -> EngineResult<(String, bool)> {
        let p = self.program()?;
        Ok((p.loaded.language.id.to_string(), is_thumb(&p, at)))
    }

    /// Checks `lines` (already encoded by an external assembler) against Sleigh and pads them.
    pub(crate) fn asm_finish(&self, at: u64, lines: Vec<Vec<u8>>) -> EngineResult<AsmBlock> {
        let p = self.program()?;
        let nop = llvm_mc::target(p.loaded.language.id, is_thumb(&p, at))
            .map(|t| t.nop)
            .ok_or_else(|| {
                ProtoError::new(ErrorCode::Unsupported, "this processor has no assembler")
            })?;
        let bytes: Vec<u8> = lines.iter().flatten().copied().collect();
        let decoded = decode_scratch(&p, at, &bytes, lines.len())?;
        if decoded.len() < lines.len() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "Sleigh cannot read the assembled bytes back as instructions",
            ));
        }
        for (l, d) in lines.iter().zip(&decoded) {
            if d.length as usize != l.len() {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "assembled {} bytes but Sleigh reads {} of them as `{} {}`",
                        l.len(),
                        d.length,
                        d.mnemonic,
                        d.body
                    ),
                ));
            }
        }
        let mut covered = 0usize;
        let mut count = 0u32;
        let mut known = true;
        while covered < bytes.len() {
            match p.existing_len(at + covered as u64) {
                Some(l) if l > 0 => {
                    covered += l as usize;
                    count += 1;
                }
                _ => {
                    known = false;
                    break;
                }
            }
        }
        let mut out = bytes;
        let mut pad = 0;
        if known {
            pad = covered - out.len();
            if pad % nop.len() != 0 {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "the instructions here do not leave room for whole NOPs after the new code",
                ));
            }
            for _ in 0..pad / nop.len() {
                out.extend_from_slice(nop);
            }
        } else {
            covered = 0;
            count = 0;
        }
        Ok(AsmBlock {
            line_lengths: lines.iter().map(|l| l.len() as u32).collect(),
            bytes: out,
            pad: pad as u32,
            overwritten: count.saturating_sub(1),
            covered: covered as u32,
        })
    }

    /// Assembles `text` at `at`: the block and, for one instruction, every encoding.
    pub(crate) fn asm_run(&self, at: u64, text: &str) -> EngineResult<(AsmBlock, Vec<Vec<u8>>)> {
        let p = self.program()?;
        let id = p.loaded.language.id;
        if id.starts_with("x86:LE:") {
            let env = Env {
                bitness: if id.starts_with("x86:LE:64") { 64 } else { 32 },
                at,
                symbol: &|n| p.asm_symbol(n),
                existing: &|a| p.existing_len(a),
                decode: &|a, b, n| decode_scratch(&p, a, b, n),
            };
            return asm::assemble_x86(&env, text);
        }
        let Some(target) = llvm_mc::target(id, is_thumb(&p, at)) else {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "the native assembler covers x86, ARM, AArch64 and RISC-V; {id} is not one of them"
                ),
            ));
        };
        let exe = llvm_mc::find().ok_or_else(|| llvm_mc::missing(id))?;
        let lines = llvm_mc::assemble(&exe, &target, text)?;
        let block = self.asm_finish(at, lines.clone())?;
        let alt = if lines.len() == 1 { lines } else { Vec::new() };
        Ok((block, alt))
    }
}

#[async_trait]
impl Assembler for InProcessEngine {
    async fn assemble(
        &self,
        at: &Locator,
        text: &str,
        _cancel: &CancellationToken,
    ) -> EngineResult<Vec<Vec<u8>>> {
        let (block, alternatives) = self.asm_run(ram_offset(at)?, text)?;
        Ok(if alternatives.is_empty() {
            vec![block.bytes]
        } else {
            alternatives
        })
    }

    async fn assemble_block(
        &self,
        at: &Locator,
        text: &str,
        _cancel: &CancellationToken,
    ) -> EngineResult<AsmBlock> {
        Ok(self.asm_run(ram_offset(at)?, text)?.0)
    }
}
