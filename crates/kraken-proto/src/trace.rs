//! Execution traces and coverage: the stored shapes and the export formats (drcov for coverage
//! plugins, a step trace as text).

use std::fmt::Write as _;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Hex64;

/// One basic block that ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageBlock {
    /// Address of the first instruction (listing address).
    pub start: Hex64,
    /// Length of the block in bytes.
    pub size: u32,
    /// How many times control entered the block.
    pub hits: u64,
}

/// A register an instruction changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RegisterDelta {
    /// Register name as the processor spec spells it.
    pub name: String,
    /// Value before the instruction.
    pub before: Hex64,
    /// Value after it.
    pub after: Hex64,
}

/// Memory an instruction wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWrite {
    /// Emulator address of the first byte.
    pub address: Hex64,
    /// The bytes now there, as hex (at most 16 bytes).
    pub bytes: String,
}

/// One executed instruction of a step trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceStepRecord {
    /// Instructions executed before this one.
    pub index: u64,
    /// Listing address of the instruction.
    pub address: Hex64,
    /// Disassembly. Program bytes decoded by the emulator, so untrusted.
    pub text: String,
    /// Registers it changed.
    pub registers: Vec<RegisterDelta>,
    /// Memory it wrote (when memory writes were asked for).
    pub writes: Vec<MemoryWrite>,
}

/// A step trace as text: one line per instruction with its register and memory deltas.
pub fn step_trace_text(program: &str, steps: &[TraceStepRecord]) -> String {
    let mut out = format!(
        "# KRAKEN step trace v1: {program}, {} instruction{}\n",
        steps.len(),
        if steps.len() == 1 { "" } else { "s" }
    );
    for s in steps {
        let _ = write!(out, "{:>8}  {:#x}  {}", s.index, s.address.0, s.text);
        for r in &s.registers {
            let _ = write!(out, "  {}: {:#x} -> {:#x}", r.name, r.before.0, r.after.0);
        }
        for w in &s.writes {
            let _ = write!(out, "  [{:#x}] <- {}", w.address.0, w.bytes);
        }
        out.push('\n');
    }
    out
}

/// A drcov (DynamoRIO coverage) file of one module: `blocks` are listing addresses, written as
/// offsets from `base`.
pub fn drcov_bytes(module: &str, base: u64, end: u64, blocks: &[CoverageBlock]) -> Vec<u8> {
    let mut out = format!(
        "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 2, count 1\n\
         Columns: id, base, end, entry, checksum, timestamp, path\n\
         0, {base:#018x}, {end:#018x}, 0x0000000000000000, 0x00000000, 0x00000000, {module}\n\
         BB Table: {} bbs\n",
        blocks.len()
    )
    .into_bytes();
    for b in blocks {
        let off = b.start.0.wrapping_sub(base) as u32;
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(b.size.min(u32::from(u16::MAX)) as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    out
}

/// A module row of a drcov file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrcovModule {
    /// The id blocks refer to.
    pub id: u32,
    /// Load address.
    pub base: u64,
    /// End address.
    pub end: u64,
    /// Path or name.
    pub path: String,
}

/// A parsed drcov file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drcov {
    /// The modules.
    pub modules: Vec<DrcovModule>,
    /// Blocks: offset from the module base, size, module id.
    pub blocks: Vec<(u32, u16, u16)>,
}

/// Reads a drcov v2 file (what [`drcov_bytes`] writes and the plugins read).
pub fn parse_drcov(data: &[u8]) -> Result<Drcov, String> {
    let mut pos = 0;
    let mut line = || -> Result<String, String> {
        let rest = &data[pos..];
        let n = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("truncated header")?;
        pos += n + 1;
        Ok(String::from_utf8_lossy(&rest[..n]).into_owned())
    };
    if line()? != "DRCOV VERSION: 2" {
        return Err("not a drcov version 2 file".into());
    }
    line()?;
    let head = line()?;
    let count: usize = head
        .strip_prefix("Module Table: version 2, count ")
        .and_then(|c| c.trim().parse().ok())
        .ok_or("bad module table header")?;
    line()?;
    let mut modules = Vec::new();
    for _ in 0..count {
        let l = line()?;
        let f: Vec<&str> = l.splitn(7, ", ").collect();
        if f.len() != 7 {
            return Err(format!("bad module row `{l}`"));
        }
        let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16);
        modules.push(DrcovModule {
            id: f[0].parse().map_err(|_| "bad module id")?,
            base: hex(f[1]).map_err(|_| "bad module base")?,
            end: hex(f[2]).map_err(|_| "bad module end")?,
            path: f[6].to_string(),
        });
    }
    let bb = line()?;
    let n: usize = bb
        .strip_prefix("BB Table: ")
        .and_then(|r| r.strip_suffix(" bbs"))
        .and_then(|c| c.parse().ok())
        .ok_or("bad BB table header")?;
    let body = &data[pos..];
    if body.len() != n * 8 {
        return Err(format!(
            "BB table holds {} bytes, expected {}",
            body.len(),
            n * 8
        ));
    }
    let blocks = body
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            (
                u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                u16::from_le_bytes([c[4], c[5]]),
                u16::from_le_bytes([c[6], c[7]]),
            )
        })
        .collect();
    Ok(Drcov { modules, blocks })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drcov_round_trips() {
        let blocks = vec![
            CoverageBlock {
                start: Hex64(0x100010),
                size: 7,
                hits: 3,
            },
            CoverageBlock {
                start: Hex64(0x100040),
                size: 12,
                hits: 1,
            },
        ];
        let bytes = drcov_bytes("prog", 0x100000, 0x102000, &blocks);
        let d = parse_drcov(&bytes).expect("parses");
        assert_eq!(d.modules[0].path, "prog");
        assert_eq!(d.modules[0].base, 0x100000);
        assert_eq!(d.blocks, [(0x10, 7, 0), (0x40, 12, 0)]);
        assert!(parse_drcov(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn step_text_shows_deltas() {
        let s = TraceStepRecord {
            index: 4,
            address: Hex64(0x401000),
            text: "MOV EAX,0x5".into(),
            registers: vec![RegisterDelta {
                name: "RAX".into(),
                before: Hex64(0),
                after: Hex64(5),
            }],
            writes: vec![MemoryWrite {
                address: Hex64(0x7ff0),
                bytes: "0500".into(),
            }],
        };
        let t = step_trace_text("p", &[s]);
        assert!(t.contains("0x401000  MOV EAX,0x5  RAX: 0x0 -> 0x5  [0x7ff0] <- 0500"));
    }
}
