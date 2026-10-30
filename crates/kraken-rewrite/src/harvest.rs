//! Harvesting test inputs from a real run: the program runs in the emulator with a breakpoint on
//! the function's entry, and at every hit the argument registers and the memory they point to are
//! recorded as a case. A pointer argument becomes a buffer (or, when the memory holds pointers to
//! more memory, a graph of objects) of bounded depth and size.
//!
//! What is recorded is what the function was handed. State it reads through globals is not part
//! of a case; the program image the runner installs gives those their initial values.

use std::collections::BTreeSet;

use kraken_emu::confined::{DebugChild, DebugReply, DebugRequest};
use kraken_emu::session::SessionStop;

use crate::abi::{Arg, Callback, Link, Param, Signature};
use crate::error::RewriteError;

/// Limits of a harvest.
#[derive(Debug, Clone)]
pub struct HarvestOptions {
    /// Most distinct cases kept.
    pub max_cases: usize,
    /// Most bytes recorded for one pointed-to object.
    pub max_bytes: usize,
    /// How many pointer hops are followed from a pointer argument (0: the argument's own memory).
    pub depth: usize,
    /// Most objects in one argument's graph.
    pub max_objects: usize,
    /// Instruction budget of the whole run.
    pub budget: u64,
    /// Wall-clock limit of the whole run in milliseconds.
    pub wall_ms: u64,
}

impl Default for HarvestOptions {
    fn default() -> Self {
        HarvestOptions {
            max_cases: 200,
            max_bytes: 64,
            depth: 2,
            max_objects: 16,
            budget: 200_000_000,
            wall_ms: 120_000,
        }
    }
}

/// What a harvest run found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestRun {
    /// The distinct cases, in the order the program made the calls.
    pub cases: Vec<Vec<Arg>>,
    /// How many times the function was entered.
    pub hits: u64,
    /// Hits that could not be recorded (a null or unreadable pointer argument).
    pub skipped: u64,
    /// Hits whose case equalled an earlier one.
    pub duplicates: u64,
    /// How the run ended.
    pub ended: String,
    /// Facts worth showing to the person.
    pub notes: Vec<String>,
}

/// The integer argument registers of the System V AMD64 convention.
const INT_REGS: [&str; 6] = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"];
const SSE_REGS: [&str; 8] = [
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
];

/// Reads guest memory: the bytes at `addr`, or `None` when unmapped.
pub type ReadMem<'a> = &'a mut dyn FnMut(u64, usize) -> Option<Vec<u8>>;

fn read_up_to(read: ReadMem<'_>, addr: u64, want: usize) -> Option<Vec<u8>> {
    let mut len = want;
    while len >= 8 {
        if let Some(b) = read(addr, len) {
            return Some(b);
        }
        len /= 2;
    }
    None
}

fn word(data: &[u8], at: usize) -> Option<u64> {
    let b = data.get(at..at + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

/// The memory behind pointer `ptr` as an argument: a plain buffer, or a graph when it holds
/// pointers to more memory. `None` for a null or unreadable pointer.
pub fn pointer_arg(ptr: u64, read: ReadMem<'_>, opts: &HarvestOptions) -> Option<Arg> {
    if ptr < 0x1000 {
        return None;
    }
    let first = read_up_to(read, ptr, opts.max_bytes)?;
    // (address, bytes, hop count)
    let mut objects: Vec<(u64, Vec<u8>, usize)> = vec![(ptr, first, 0)];
    let mut links: Vec<Link> = Vec::new();
    let mut at = 0;
    while at < objects.len() {
        let (base, depth) = (objects[at].0, objects[at].2);
        let len = objects[at].1.len();
        if depth < opts.depth {
            for off in (0..len.saturating_sub(7)).step_by(8) {
                let Some(w) = word(&objects[at].1, off) else {
                    continue;
                };
                if w < 0x10000 || w == base {
                    continue;
                }
                let inside = objects
                    .iter()
                    .position(|(a, d, _)| w >= *a && w < a.saturating_add(d.len() as u64));
                if let Some(j) = inside {
                    links.push(Link {
                        from: at,
                        offset: off,
                        to: j,
                        to_offset: (w - objects[j].0) as usize,
                    });
                } else if objects.len() < opts.max_objects
                    && let Some(bytes) = read_up_to(read, w, opts.max_bytes)
                {
                    objects.push((w, bytes, depth + 1));
                    links.push(Link {
                        from: at,
                        offset: off,
                        to: objects.len() - 1,
                        to_offset: 0,
                    });
                }
            }
        }
        at += 1;
    }
    if links.is_empty() {
        let (_, data, _) = objects.swap_remove(0);
        Some(Arg::Buf { data })
    } else {
        Some(Arg::Graph {
            objects: objects.into_iter().map(|(_, d, _)| d).collect(),
            links,
        })
    }
}

/// Registers the call convention reads for `sig`.
pub fn wanted_registers(sig: &Signature) -> Vec<&'static str> {
    let ints = sig.params.iter().filter(|p| !p.is_sse()).count();
    let sse = sig.params.iter().filter(|p| p.is_sse()).count();
    INT_REGS
        .iter()
        .take(ints)
        .chain(SSE_REGS.iter().take(sse))
        .copied()
        .collect()
}

/// The case for one entry of the function: `reg` gives a register by name.
pub fn case_from_registers(
    sig: &Signature,
    reg: &dyn Fn(&str) -> Option<u64>,
    read: ReadMem<'_>,
    opts: &HarvestOptions,
) -> Option<Vec<Arg>> {
    let (mut ints, mut sse) = (0usize, 0usize);
    let mut args = Vec::with_capacity(sig.params.len());
    for p in &sig.params {
        let arg = match p {
            Param::Int { bits, signed } => {
                let v = reg(INT_REGS.get(ints).copied()?)?;
                ints += 1;
                Arg::Int {
                    value: normalise(v, *bits, *signed),
                }
            }
            Param::Buf => {
                let v = reg(INT_REGS.get(ints).copied()?)?;
                ints += 1;
                pointer_arg(v, read, opts)?
            }
            Param::FnPtr => {
                ints += 1;
                // The program's own function pointer cannot be reproduced; both sides get the
                // same stand-in.
                Arg::FnPtr {
                    callback: Callback::Ascending,
                }
            }
            Param::Double => {
                let v = reg(SSE_REGS.get(sse).copied()?).unwrap_or(0);
                sse += 1;
                Arg::Double { bits: v }
            }
            Param::Float => {
                let v = reg(SSE_REGS.get(sse).copied()?).unwrap_or(0);
                sse += 1;
                Arg::Float { bits: v as u32 }
            }
        };
        args.push(arg);
    }
    Some(args)
}

/// A register value as the integer argument of the given width: masked, and sign-extended for
/// signed types.
fn normalise(v: u64, bits: u8, signed: bool) -> u64 {
    if bits >= 64 {
        return v;
    }
    let masked = v & ((1u64 << bits) - 1);
    if signed && masked >> (bits - 1) & 1 == 1 {
        masked | (u64::MAX << bits)
    } else {
        masked
    }
}

fn emu(e: kraken_emu::EmuError) -> RewriteError {
    RewriteError::Unsupported(format!("the emulator: {e}"))
}

/// Runs the child until it exits (or a limit is hit), recording a case at every entry of the
/// function at `entry` (an address in the emulator's address space).
pub fn harvest_child(
    child: &mut DebugChild,
    sig: &Signature,
    entry: u64,
    opts: &HarvestOptions,
) -> Result<HarvestRun, RewriteError> {
    if !child.initial.arch.starts_with("x86_64") {
        return Err(RewriteError::Unsupported(format!(
            "harvesting reads the System V AMD64 argument registers; this program is {}",
            child.initial.arch
        )));
    }
    if !sig.fits_registers() {
        return Err(RewriteError::Unsupported(
            "the function takes more arguments than fit in registers".into(),
        ));
    }
    child
        .request(&DebugRequest::AddBreakpoint { addr: entry })
        .map_err(emu)?;
    let wanted = wanted_registers(sig);
    let mut run = HarvestRun {
        cases: Vec::new(),
        hits: 0,
        skipped: 0,
        duplicates: 0,
        ended: String::new(),
        notes: Vec::new(),
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut spent = 0u64;
    loop {
        let left = opts.budget.saturating_sub(spent);
        if left == 0 {
            run.ended = "the instruction budget ran out".into();
            break;
        }
        let reply = child
            .request(&DebugRequest::Run {
                budget: left,
                wall_ms: opts.wall_ms,
            })
            .map_err(emu)?;
        let DebugReply::Stop { stop, state } = reply else {
            return Err(RewriteError::Unsupported(
                "unexpected answer to a run request".into(),
            ));
        };
        spent = state.icount;
        match stop {
            SessionStop::Breakpoint { pc } if pc == entry => {}
            SessionStop::Exited { exit } => {
                run.ended = format!("the program ended ({exit:?})");
                break;
            }
            SessionStop::Breakpoint { pc } => {
                run.ended = format!("stopped at an unexpected breakpoint {pc:#x}");
                break;
            }
            SessionStop::Budget => {
                run.ended = "the instruction budget ran out".into();
                break;
            }
            SessionStop::Fault { detail, pc } => {
                run.ended = format!("the program faulted at {pc:#x}: {detail}");
                break;
            }
            other => {
                run.ended = format!("the run stopped: {other:?}");
                break;
            }
        }
        run.hits += 1;
        let regs = match child
            .request(&DebugRequest::ReadRegs {
                names: wanted.iter().map(|s| s.to_string()).collect(),
            })
            .map_err(emu)?
        {
            DebugReply::Registers { regs } => regs,
            _ => Vec::new(),
        };
        let mut failed: Option<RewriteError> = None;
        let case = {
            let mut read = |addr: u64, len: usize| -> Option<Vec<u8>> {
                match child.request(&DebugRequest::ReadMemory { addr, len }) {
                    Ok(DebugReply::Bytes { bytes }) => Some(bytes),
                    Err(kraken_emu::EmuError::Io(m)) => {
                        failed = Some(RewriteError::Unsupported(format!("the emulator: {m}")));
                        None
                    }
                    _ => None,
                }
            };
            let lookup = |n: &str| regs.iter().find(|(r, _)| r == n).map(|(_, v)| *v);
            case_from_registers(sig, &lookup, &mut read, opts)
        };
        if let Some(e) = failed {
            return Err(e);
        }
        match case {
            None => run.skipped += 1,
            Some(c) => {
                let key = serde_json::to_string(&c).unwrap_or_default();
                if seen.insert(key) {
                    run.cases.push(c);
                    if run.cases.len() >= opts.max_cases {
                        run.ended = format!("stopped after {} distinct cases", opts.max_cases);
                        break;
                    }
                } else {
                    run.duplicates += 1;
                }
            }
        }
    }
    if run.hits == 0 {
        run.notes.push(
            "the function was never entered with this input; give arguments or input that reach it"
                .into(),
        );
    }
    if sig.params.iter().any(|p| matches!(p, Param::FnPtr)) {
        run.notes
            .push("function pointer arguments are replaced by the oracle's own callback".into());
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Ret;

    fn mem(map: Vec<(u64, Vec<u8>)>) -> impl FnMut(u64, usize) -> Option<Vec<u8>> {
        move |addr, len| {
            map.iter().find_map(|(a, d)| {
                (addr >= *a && addr + len as u64 <= a + d.len() as u64)
                    .then(|| d[(addr - a) as usize..(addr - a) as usize + len].to_vec())
            })
        }
    }

    fn sig(params: Vec<Param>) -> Signature {
        Signature {
            name: "f".into(),
            params,
            ret: Ret::Void,
        }
    }

    #[test]
    fn a_pointer_to_plain_bytes_is_a_buffer() {
        let mut m = mem(vec![(0x7000_0000, (0..32).collect())]);
        let a = pointer_arg(0x7000_0000, &mut m, &HarvestOptions::default()).expect("arg");
        assert_eq!(
            a,
            Arg::Buf {
                data: (0..32).collect()
            }
        );
        assert!(pointer_arg(0, &mut m, &HarvestOptions::default()).is_none());
        assert!(pointer_arg(0x5000_0000, &mut m, &HarvestOptions::default()).is_none());
    }

    #[test]
    fn pointers_inside_memory_become_a_bounded_graph() {
        // A list of three nodes: [value u64][next u64]; the third points back to the first.
        let node = |v: u64, next: u64| {
            let mut d = v.to_le_bytes().to_vec();
            d.extend(next.to_le_bytes());
            d
        };
        let mut m = mem(vec![
            (0x7000_0000, node(1, 0x7000_0100)),
            (0x7000_0100, node(2, 0x7000_0200)),
            (0x7000_0200, node(3, 0x7000_0000)),
        ]);
        let opts = HarvestOptions {
            depth: 5,
            ..HarvestOptions::default()
        };
        let Some(Arg::Graph { objects, links }) = pointer_arg(0x7000_0000, &mut m, &opts) else {
            panic!("expected a graph");
        };
        assert_eq!(objects.len(), 3);
        assert_eq!(links.len(), 3);
        assert!(links.contains(&Link {
            from: 2,
            offset: 8,
            to: 0,
            to_offset: 0
        }));
        // The depth bounds the graph.
        let shallow = HarvestOptions {
            depth: 1,
            ..HarvestOptions::default()
        };
        let Some(Arg::Graph { objects, .. }) = pointer_arg(0x7000_0000, &mut m, &shallow) else {
            panic!("expected a graph");
        };
        assert_eq!(objects.len(), 2);
    }

    #[test]
    fn registers_become_typed_arguments() {
        let s = sig(vec![
            Param::Int {
                bits: 32,
                signed: true,
            },
            Param::Buf,
            Param::Double,
        ]);
        assert_eq!(wanted_registers(&s), vec!["RDI", "RSI", "XMM0"]);
        let regs = |n: &str| match n {
            "RDI" => Some(0xffff_fffe),
            "RSI" => Some(0x7000_0000),
            "XMM0" => Some(1.5f64.to_bits()),
            _ => None,
        };
        let mut m = mem(vec![(0x7000_0000, vec![9; 16])]);
        let c = case_from_registers(&s, &regs, &mut m, &HarvestOptions::default()).expect("case");
        assert_eq!(
            c,
            vec![
                Arg::Int {
                    value: (-2i64) as u64
                },
                Arg::Buf { data: vec![9; 16] },
                Arg::Double {
                    bits: 1.5f64.to_bits()
                }
            ]
        );
    }
}
