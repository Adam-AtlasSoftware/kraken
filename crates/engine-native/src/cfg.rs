//! Control-flow graphs from a function body, in the shape of Ghidra's `SimpleBlockModel`: a block
//! ends at every instruction that changes flow (calls included) and starts at every branch,
//! switch and landing-pad target, so the graph lines up with Ghidra's for the same function.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction};
use kraken_proto::{Cfg, CfgBlock, CfgEdge, CfgEdgeKind, Hex64};

use crate::discover::Func;

fn rank(k: CfgEdgeKind) -> u8 {
    match k {
        CfgEdgeKind::Fallthrough => 0,
        CfgEdgeKind::Jump => 1,
        CfgEdgeKind::ConditionalTrue => 2,
        CfgEdgeKind::ConditionalFalse => 3,
        CfgEdgeKind::Switch => 4,
    }
}

/// The CFG of `f`. `noreturn` says whether a call target never returns (no fall-through edge
/// after such a call); `pads` are the function's landing pads (block starts without a branch).
pub fn build(
    f: &Func,
    insns: &BTreeMap<u64, Instruction>,
    pads: &[u64],
    noreturn: &dyn Fn(u64) -> bool,
) -> Cfg {
    let body: BTreeSet<u64> = f.insns.iter().copied().collect();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(f.entry);
    leaders.extend(pads.iter().copied().filter(|p| body.contains(p)));
    for (op, targets) in &f.switches {
        leaders.extend(targets.iter().copied().filter(|t| body.contains(t)));
        // Ghidra's block model gives a recovered switch's computed jump a block of its own
        leaders.insert(*op);
    }
    for a in &f.insns {
        let Some(i) = insns.get(a) else { continue };
        if matches!(i.flow, Flow::Jump | Flow::ConditionalJump) {
            leaders.extend(i.targets.iter().copied().filter(|t| body.contains(t)));
        }
        if i.flow != Flow::Fallthrough {
            leaders.insert(a + u64::from(i.length));
        }
    }

    // blocks: (start, end, count, last instruction)
    let mut blocks: Vec<(u64, u64, u32, u64)> = Vec::new();
    let mut prev_end: Option<u64> = None;
    for a in &f.insns {
        let len = insns.get(a).map_or(1, |i| u64::from(i.length));
        let new_block = leaders.contains(a) || prev_end != Some(*a) || blocks.is_empty();
        if new_block {
            blocks.push((*a, a + len, 1, *a));
        } else if let Some(b) = blocks.last_mut() {
            b.1 = a + len;
            b.2 += 1;
            b.3 = *a;
        }
        prev_end = Some(a + len);
    }
    let starts: BTreeSet<u64> = blocks.iter().map(|b| b.0).collect();

    let mut edges: BTreeSet<(u64, u64, u8)> = BTreeSet::new();
    let mut add = |from: u64, to: u64, kind: CfgEdgeKind| {
        if starts.contains(&to) {
            edges.insert((from, to, rank(kind)));
        }
    };
    for (start, end, _, last) in &blocks {
        let Some(i) = insns.get(last) else { continue };
        match i.flow {
            Flow::Fallthrough => add(*start, *end, CfgEdgeKind::Fallthrough),
            Flow::Call | Flow::IndirectCall => {
                if i.fallthrough && !i.targets.iter().any(|t| noreturn(*t)) {
                    add(*start, *end, CfgEdgeKind::Fallthrough);
                }
            }
            Flow::ConditionalJump => {
                for t in &i.targets {
                    add(*start, *t, CfgEdgeKind::ConditionalTrue);
                }
                add(*start, *end, CfgEdgeKind::ConditionalFalse);
            }
            Flow::Jump => {
                // an instruction that branches to itself (`HLT` in Sleigh) ends the flow
                for t in i.targets.iter().filter(|t| **t != *last) {
                    add(*start, *t, CfgEdgeKind::Jump);
                }
            }
            Flow::IndirectJump => {
                for t in f.switches.get(last).into_iter().flatten() {
                    add(*start, *t, CfgEdgeKind::Switch);
                }
            }
            Flow::Return => {}
        }
    }
    let kind_of = |r: u8| match r {
        0 => CfgEdgeKind::Fallthrough,
        1 => CfgEdgeKind::Jump,
        2 => CfgEdgeKind::ConditionalTrue,
        3 => CfgEdgeKind::ConditionalFalse,
        _ => CfgEdgeKind::Switch,
    };
    Cfg {
        function: Hex64(f.entry),
        blocks: blocks
            .iter()
            .map(|(s, e, n, _)| CfgBlock {
                start: Hex64(*s),
                end: Hex64(*e),
                instructions: *n,
            })
            .collect(),
        edges: edges
            .into_iter()
            .map(|(from, to, k)| CfgEdge {
                from: Hex64(from),
                to: Hex64(to),
                kind: kind_of(k),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(addr: u64, length: u32, flow: Flow, targets: Vec<u64>) -> Instruction {
        Instruction {
            addr,
            length,
            mnemonic: "X".into(),
            body: String::new(),
            flow,
            fallthrough: matches!(
                flow,
                Flow::Fallthrough | Flow::Call | Flow::IndirectCall | Flow::ConditionalJump
            ),
            via_pointer: false,
            targets,
            refs: Vec::new(),
            reg_reads: Vec::new(),
            reg_writes: Vec::new(),
        }
    }

    #[test]
    fn blocks_split_at_flow_and_targets() {
        // 0: cmp; 2: jz 8; 4: call 0x100; 9: jmp 0xc ... 8 is mid-way? use clean layout:
        // 0 cmp(2) | 2 jz 0xa (2) | 4 call 0x100 (5) | 9 nop(1) | 0xa ret(1)
        let list = vec![
            insn(0, 2, Flow::Fallthrough, vec![]),
            insn(2, 2, Flow::ConditionalJump, vec![0xa]),
            insn(4, 5, Flow::Call, vec![0x100]),
            insn(9, 1, Flow::Fallthrough, vec![]),
            insn(0xa, 1, Flow::Return, vec![]),
        ];
        let insns: BTreeMap<u64, Instruction> = list.into_iter().map(|i| (i.addr, i)).collect();
        let f = Func {
            entry: 0,
            name: "f".into(),
            insns: insns.keys().copied().collect(),
            ranges: vec![(0, 0xb)],
            switches: BTreeMap::new(),
            tail_calls: Vec::new(),
            noreturn: false,
            returns: true,
        };
        let cfg = build(&f, &insns, &[], &|_| false);
        let blocks: Vec<(u64, u64, u32)> = cfg
            .blocks
            .iter()
            .map(|b| (b.start.0, b.end.0, b.instructions))
            .collect();
        assert_eq!(
            blocks,
            vec![(0, 4, 2), (4, 9, 1), (9, 0xa, 1), (0xa, 0xb, 1)]
        );
        let edges: Vec<(u64, u64, CfgEdgeKind)> = cfg
            .edges
            .iter()
            .map(|e| (e.from.0, e.to.0, e.kind))
            .collect();
        assert_eq!(
            edges,
            vec![
                (0, 4, CfgEdgeKind::ConditionalFalse),
                (0, 0xa, CfgEdgeKind::ConditionalTrue),
                (4, 9, CfgEdgeKind::Fallthrough),
                (9, 0xa, CfgEdgeKind::Fallthrough),
            ]
        );
        // a call that never returns has no fall-through edge
        let cfg = build(&f, &insns, &[], &|t| t == 0x100);
        assert!(!cfg.edges.iter().any(|e| e.from.0 == 4));
    }
}
