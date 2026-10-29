//! The native engine's assembler. x86 and x86-64 go through iced's encoder (`x86.rs`); the other
//! processors go to `llvm-mc` when one is installed (`llvm_mc.rs`). Every result is decoded back
//! through Sleigh (the engine's own disassembler), so the bytes mean what was typed.

use std::collections::BTreeMap;

use kraken_engine::AsmBlock;
use kraken_proto::{ErrorCode, ProtoError};

pub mod llvm_mc;
pub mod x86;

/// One instruction as Sleigh reads it back.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub length: u32,
    pub mnemonic: String,
    pub body: String,
    pub targets: Vec<u64>,
}

/// Decodes bytes placed at an address with Sleigh.
pub type DecodeFn<'a> = dyn Fn(u64, &[u8], usize) -> Result<Vec<Decoded>, ProtoError> + 'a;

/// What the assembler asks of the engine.
pub struct Env<'a> {
    pub bitness: u32,
    pub at: u64,
    /// A symbol, label or default name (`FUN_00401136`) as an address.
    pub symbol: &'a dyn Fn(&str) -> Option<u64>,
    /// Length of the instruction already at an address, if the program has one.
    pub existing: &'a dyn Fn(u64) -> Option<u32>,
    /// Decodes `bytes` placed at `at` with Sleigh, up to `max` instructions.
    pub decode: &'a DecodeFn<'a>,
}

fn invalid(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, m)
}

/// One assembled line.
struct Enc {
    enc: Vec<Vec<u8>>,
    text: String,
    typed: x86::Parsed,
}

/// A typed line: a label definition, an instruction, or both.
struct Line {
    label: Option<String>,
    text: String,
}

fn is_label_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '@' | '?'))
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

fn split_lines(text: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for raw in text.split([';', '\n']) {
        let mut t = raw.trim();
        if let Some(i) = t.find("//") {
            t = t[..i].trim();
        }
        if t.is_empty() {
            continue;
        }
        let mut label = None;
        if let Some((l, rest)) = t.split_once(':')
            && is_label_name(l.trim())
            && x86::register(l.trim()).is_none_or(|r| !r.is_segment_register())
        {
            label = Some(l.trim().to_string());
            t = rest.trim();
        }
        out.push(Line {
            label,
            text: t.to_string(),
        });
    }
    out
}

/// Assembles an x86 block. With one instruction, `alternatives` holds every verified encoding.
pub fn assemble_x86(env: &Env, text: &str) -> Result<(AsmBlock, Vec<Vec<u8>>), ProtoError> {
    let lines = split_lines(text);
    if lines.iter().all(|l| l.text.is_empty()) {
        return Err(invalid("nothing to assemble"));
    }
    let declared: Vec<&str> = lines.iter().filter_map(|l| l.label.as_deref()).collect();
    let mut labels: BTreeMap<String, u64> =
        declared.iter().map(|l| (l.to_string(), env.at)).collect();
    let mut result = None;
    for _ in 0..6 {
        let resolve = |n: &str| labels.get(n).copied().or_else(|| (env.symbol)(n));
        let mut pc = env.at;
        let mut next = labels.clone();
        let mut encoded: Vec<Enc> = Vec::new();
        for l in &lines {
            if let Some(name) = &l.label {
                next.insert(name.clone(), pc);
            }
            if l.text.is_empty() {
                continue;
            }
            let p = x86::parse_line(&l.text, &resolve)
                .map_err(|e| invalid(format!("`{}`: {e}", l.text)))?;
            let enc = x86::encode(&p, pc, env.bitness)
                .map_err(|e| invalid(format!("`{}`: {e}", l.text)))?;
            pc += enc[0].len() as u64;
            encoded.push(Enc {
                enc,
                text: l.text.clone(),
                typed: p,
            });
        }
        if next == labels {
            result = Some(encoded);
            break;
        }
        labels = next;
    }
    let encoded = result
        .ok_or_else(|| invalid("the branches in this block do not settle on a size; add a nop"))?;

    let mut bytes = Vec::new();
    let mut line_lengths = Vec::new();
    for e in &encoded {
        line_lengths.push(e.enc[0].len() as u32);
        bytes.extend_from_slice(&e.enc[0]);
    }
    let decoded = (env.decode)(env.at, &bytes, encoded.len())?;
    verify(env, &encoded, &decoded)?;

    let mut alternatives = Vec::new();
    if encoded.len() == 1 {
        for enc in &encoded[0].enc {
            let d = (env.decode)(env.at, enc, 1)?;
            let one = Enc {
                enc: vec![enc.clone()],
                text: encoded[0].text.clone(),
                typed: encoded[0].typed.clone(),
            };
            if verify(env, &[one], &d).is_ok() {
                alternatives.push(enc.clone());
            }
        }
    }

    let (pad, overwritten, covered) = padding(env, bytes.len());
    if pad > 0 {
        bytes.extend(x86::nop(pad));
    }
    Ok((
        AsmBlock {
            bytes,
            line_lengths,
            pad: pad as u32,
            overwritten,
            covered,
        },
        alternatives,
    ))
}

/// NOP bytes needed to reach the next instruction boundary of the code at `at`, the number of
/// instructions after the first that the bytes cover, and the bytes covered.
fn padding(env: &Env, len: usize) -> (usize, u32, u32) {
    let mut covered = 0usize;
    let mut count = 0u32;
    while covered < len {
        match (env.existing)(env.at + covered as u64) {
            Some(l) if l > 0 => {
                covered += l as usize;
                count += 1;
            }
            _ => return (0, 0, 0),
        }
    }
    (covered - len, count.saturating_sub(1), covered as u32)
}

fn verify(env: &Env, encoded: &[Enc], decoded: &[Decoded]) -> Result<(), ProtoError> {
    if decoded.len() < encoded.len() {
        return Err(invalid(
            "Sleigh cannot read the assembled bytes back as instructions",
        ));
    }
    for (e, d) in encoded.iter().zip(decoded) {
        let want_len = e.enc[0].len() as u32;
        let (text, typed) = (&e.text, &e.typed);
        let read = format!("{} {}", d.mnemonic, d.body);
        if d.length != want_len {
            return Err(invalid(format!(
                "`{text}` assembled to {want_len} bytes but Sleigh reads {} of them as `{}`",
                d.length,
                read.trim()
            )));
        }
        let same = x86::canonical(&typed.mnemonic) == x86::canonical(&d.mnemonic)
            || d.mnemonic.to_ascii_lowercase().starts_with(&typed.mnemonic);
        if !same {
            return Err(invalid(format!(
                "`{text}` assembled to bytes that Sleigh reads as `{}`",
                read.trim()
            )));
        }
        let seen = x86::registers_in(&d.body);
        for op in &typed.ops {
            let regs: Vec<_> = match op {
                x86::Op::Reg(r) => vec![*r],
                x86::Op::Mem(m) => [m.base, m.index, m.seg].into(),
                x86::Op::Imm(_) => vec![],
            };
            for r in regs {
                use iced_x86::Register as R;
                if matches!(r, R::None | R::RIP | R::EIP) {
                    continue;
                }
                if !seen.contains(&r) {
                    return Err(invalid(format!(
                        "`{text}` assembled to bytes that Sleigh reads as `{}`",
                        read.trim()
                    )));
                }
            }
        }
        if let [x86::Op::Imm(v)] = typed.ops.as_slice()
            && let Some(t) = d.targets.first()
            && (typed.mnemonic.starts_with('j')
                || typed.mnemonic.starts_with("call")
                || typed.mnemonic.starts_with("loop"))
            && (*v as u64) & mask(env.bitness) != *t & mask(env.bitness)
        {
            return Err(invalid(format!(
                "`{text}` assembled to a branch to {t:#x}, not {v:#x}"
            )));
        }
    }
    Ok(())
}

fn mask(bitness: u32) -> u64 {
    if bitness == 64 {
        u64::MAX
    } else {
        u32::MAX as u64
    }
}
