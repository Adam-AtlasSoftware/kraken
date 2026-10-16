//! The corpus functions the spike translates: where they live, their ABI, how to generate test
//! inputs for them, and the checked-in reference translations.
//!
//! The reference Rust is hand-written from the C in `corpus/src` (and checked against the
//! decompile); it is what the cassette-backed tasks return so tests are deterministic.

use crate::abi::{Arg, Param, Ret, Signature};
use crate::difftest::{FieldGen, Generator, InputSpec, IntGen, ParamGen, Rng};

/// One function the spike handles.
#[derive(Debug, Clone)]
pub struct Target {
    /// Short id.
    pub id: &'static str,
    /// Corpus binary file name (under `corpus/bin`) and its fixture (`corpus/fixtures/<bin>.json`).
    pub binary: &'static str,
    /// Function name (the binary is not stripped, so symbols give the oracle its entry).
    pub function: &'static str,
    /// Callees whose decompile is given to the model as context.
    pub callees: &'static [&'static str],
    /// The ABI.
    pub signature: Signature,
    /// Layout facts for the prompt (trusted operator text).
    pub layout_notes: &'static str,
    /// The hand-written translation.
    pub reference: &'static str,
    /// Input generation.
    pub inputs: InputSpec,
}

fn i32s() -> Ret {
    Ret::Int {
        bits: 32,
        signed: true,
    }
}

fn record_gen() -> ParamGen {
    ParamGen::Struct {
        size: 40,
        fields: vec![
            FieldGen {
                offset: 0,
                value: IntGen::full(32, true),
            },
            FieldGen {
                offset: 20,
                value: IntGen::full(32, true),
            },
            FieldGen {
                offset: 24,
                value: IntGen::full(32, true),
            },
        ],
    }
}

fn record(id: i32, x: i32, y: i32) -> Arg {
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&id.to_le_bytes());
    b[20..24].copy_from_slice(&x.to_le_bytes());
    b[24..28].copy_from_slice(&y.to_le_bytes());
    Arg::Buf { data: b }
}

const RECORD_NOTES: &str = "struct point { int x, y; };\n\
struct record { int id; char name[16]; struct point pos; double weight; };\n\
sizeof(struct record) == 40: id at 0, name at 4, pos.x at 20, pos.y at 24, weight at 32.";

const VM_NOTES: &str = "enum op { HALT=0, PUSH, ADD, SUB, MUL, DUP, SWAP, DROP, NEG, JNZ, DEC, \
PRINT, AND, OR, XOR }; STACK_MAX is 32.\n\
struct vm { int32_t stack[32]; int sp; unsigned pc; unsigned long steps; };\n\
sizeof(struct vm) == 144: stack at 0, sp at 128, pc at 132, steps at 136.\n\
`code` is readable one byte past `len`. vm_fail prints to stderr and calls exit(42).";

const CALC_NOTES: &str = "struct parser { const char *p; int err; };\n\
The expression grammar is the usual one: expr = term (('+'|'-') term)*, term = atom \
(('*'|'/'|'%') atom)*, atom = '(' expr ')' | '-' atom | number. Whitespace is skipped with \
isspace (C locale), digits with isdigit. `text` is NUL terminated; `out` points to a `long` \
(8 bytes). The translation must cover the whole parser (the callees below), not only `evaluate`.";

/// The targets, in a stable order.
pub fn targets() -> Vec<Target> {
    vec![
        Target {
            id: "cmp_id",
            binary: "pie_list-O0",
            function: "cmp_id",
            callees: &[],
            signature: Signature {
                name: "cmp_id".into(),
                params: vec![Param::Buf, Param::Buf],
                ret: i32s(),
            },
            layout_notes: RECORD_NOTES,
            reference: include_str!("../references/cmp_id.rs"),
            inputs: InputSpec {
                fixed: vec![
                    vec![record(7, 0, 0), record(3, 0, 0)],
                    vec![record(3, 0, 0), record(7, 0, 0)],
                    vec![record(5, 0, 0), record(5, 9, 9)],
                    vec![record(i32::MIN, 0, 0), record(1, 0, 0)],
                    vec![record(i32::MAX, 0, 0), record(-1, 0, 0)],
                ],
                generator: Generator::Params(vec![record_gen(), record_gen()]),
            },
        },
        Target {
            id: "cmp_dist",
            binary: "pie_list-O0",
            function: "cmp_dist",
            callees: &[],
            signature: Signature {
                name: "cmp_dist".into(),
                params: vec![Param::Buf, Param::Buf],
                ret: i32s(),
            },
            layout_notes: RECORD_NOTES,
            reference: include_str!("../references/cmp_dist.rs"),
            inputs: InputSpec {
                fixed: vec![
                    vec![record(0, 3, 4), record(0, 1, 2)],
                    vec![record(0, 0, 0), record(0, 0, 0)],
                    vec![record(0, 46341, 0), record(0, 0, 0)],
                    vec![record(0, i32::MIN, i32::MAX), record(0, -1, 1)],
                ],
                generator: Generator::Params(vec![record_gen(), record_gen()]),
            },
        },
        Target {
            id: "vm_run",
            binary: "switch_vm-O0",
            function: "vm_run",
            callees: &["push", "pop", "vm_fail"],
            signature: Signature {
                name: "vm_run".into(),
                params: vec![
                    Param::Buf,
                    Param::Buf,
                    Param::Int {
                        bits: 32,
                        signed: false,
                    },
                ],
                ret: i32s(),
            },
            layout_notes: VM_NOTES,
            reference: include_str!("../references/vm_run.rs"),
            inputs: InputSpec {
                fixed: vec![
                    vm_case(&[1, 6, 1, 7, 4, 0], 0, &[]),
                    vm_case(&[1, 0xfb, 11, 0], 0, &[]),
                    vm_case(&[2, 0], 0, &[]),
                    vm_case(&[1, 3, 10, 5, 9, 2, 0], 0, &[]),
                    vm_case(&[1, 9, 1, 4, 3, 0], 0, &[]),
                    vm_case(&[200], 0, &[]),
                    vm_case(&[1, 1], 0, &[]),
                ],
                generator: Generator::Custom(gen_vm),
            },
        },
        Target {
            id: "evaluate",
            binary: "stripped_calc-O0",
            function: "evaluate",
            callees: &[
                "parse_expr",
                "parse_term",
                "parse_atom",
                "parse_number",
                "skip_ws",
            ],
            signature: Signature {
                name: "evaluate".into(),
                params: vec![Param::Buf, Param::Buf],
                ret: i32s(),
            },
            layout_notes: CALC_NOTES,
            reference: include_str!("../references/evaluate.rs"),
            inputs: InputSpec {
                fixed: [
                    "1 + 2 * 3",
                    "(1 + 2) * 3",
                    "100 / (5 - 5)",
                    "-(4 + 6) % 7",
                    "2 * (3 + 4) * 5",
                    "12 +",
                    "((7))",
                    "",
                    "  42  ",
                    "-7 % 3",
                    "7 % -3",
                    "-7 / 2",
                    "9223372036854775807 + 1",
                    "1 2",
                ]
                .iter()
                .map(|s| calc_case(s))
                .collect(),
                generator: Generator::Custom(gen_calc),
            },
        },
    ]
}

/// Looks a target up by id.
pub fn target(id: &str) -> Option<Target> {
    targets().into_iter().find(|t| t.id == id)
}

fn vm_state(sp: usize, stack: &[i32], pc: u32, steps: u64) -> Arg {
    let mut b = vec![0u8; 144];
    for (i, v) in stack.iter().enumerate().take(32) {
        b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    b[128..132].copy_from_slice(&(sp as i32).to_le_bytes());
    b[132..136].copy_from_slice(&pc.to_le_bytes());
    b[136..144].copy_from_slice(&steps.to_le_bytes());
    Arg::Buf { data: b }
}

/// A `vm_run` case: program, starting pc and starting stack.
fn vm_case(code: &[u8], pc: u32, stack: &[i32]) -> Vec<Arg> {
    let mut padded = code.to_vec();
    padded.extend_from_slice(&[0; 8]);
    vec![
        vm_state(stack.len(), stack, pc, 0),
        Arg::Buf { data: padded },
        Arg::Int {
            value: code.len() as u64,
        },
    ]
}

fn gen_vm(rng: &mut Rng) -> Vec<Arg> {
    const HALT: u8 = 0;
    const PUSH: u8 = 1;
    let sp = usize::try_from(rng.below(6)).unwrap_or(0);
    let stack: Vec<i32> = (0..sp)
        .map(|_| match rng.below(6) {
            0 => i32::MAX,
            1 => i32::MIN,
            _ => rng.range(-1000, 1000) as i32,
        })
        .collect();
    let mut depth = sp as i32;
    let mut code: Vec<u8> = Vec::new();
    let ops = 1 + rng.below(24);
    for _ in 0..ops {
        if rng.chance(1, 14) {
            // Deep DUP chain: reaches "stack overflow".
            code.push(PUSH);
            code.push(1);
            code.extend(std::iter::repeat_n(5u8, 36));
            depth = 32;
            continue;
        }
        if rng.chance(1, 10) {
            // Chaos: any opcode, valid or not, whatever the stack looks like.
            code.push(rng.below(18) as u8);
            if code.last() == Some(&PUSH) {
                code.push(rng.next_u64() as u8);
            }
            if code.last() == Some(&9) {
                // Never emit a free-standing JNZ: it could jump anywhere, including backwards.
                code.pop();
            }
            continue;
        }
        let choice = rng.below(100);
        if depth < 2 || choice < 30 {
            if depth < 30 {
                let imm = match rng.below(6) {
                    0 => 127u8,
                    1 => 0x80,
                    _ => rng.next_u64() as u8,
                };
                code.push(PUSH);
                code.push(imm);
                depth += 1;
            }
        } else if choice < 70 {
            code.push([2u8, 3, 4, 12, 13, 14][rng.below(6) as usize]);
            depth -= 1;
        } else if choice < 78 {
            code.push(5);
            depth += 1;
        } else if choice < 84 {
            code.push(6);
        } else if choice < 88 {
            code.push(7);
            depth -= 1;
        } else if choice < 92 {
            code.push(8);
        } else if choice < 96 {
            code.push(10);
        } else {
            code.push(11);
        }
    }
    if rng.chance(1, 8) {
        // A bounded countdown loop: PUSH n; top: DEC; DUP; JNZ top.
        code.push(PUSH);
        code.push(1 + rng.below(6) as u8);
        let top = code.len() as u8;
        code.extend_from_slice(&[10, 5, 9, top]);
    }
    if !rng.chance(1, 12) {
        code.push(HALT);
    }
    let pc = if rng.chance(1, 8) {
        rng.below(3) as u32
    } else {
        0
    };
    let mut args = vm_case(&code, pc, &stack);
    if let Arg::Buf { data } = &mut args[0] {
        data[136..144].copy_from_slice(&rng.below(100).to_le_bytes());
    }
    args
}

fn calc_case(text: &str) -> Vec<Arg> {
    let mut data = text.as_bytes().to_vec();
    data.push(0);
    data.extend_from_slice(&[0; 8]);
    vec![
        Arg::Buf { data },
        Arg::Buf {
            data: vec![0xaa; 8],
        },
    ]
}

fn ws(rng: &mut Rng, out: &mut String) {
    for _ in 0..rng.below(3) {
        out.push(if rng.chance(1, 5) { '\t' } else { ' ' });
    }
}

fn gen_atom(rng: &mut Rng, depth: u32, out: &mut String) {
    ws(rng, out);
    match rng.below(10) {
        0 | 1 if depth > 0 => {
            out.push('(');
            gen_expr(rng, depth - 1, out);
            ws(rng, out);
            out.push(')');
        }
        2 if depth > 0 => {
            out.push('-');
            gen_atom(rng, depth - 1, out);
        }
        _ => {
            let digits = 1 + rng.below(6);
            if rng.chance(1, 8) {
                out.push('0');
            }
            for _ in 0..digits {
                out.push((b'0' + rng.below(10) as u8) as char);
            }
        }
    }
}

fn gen_expr(rng: &mut Rng, depth: u32, out: &mut String) {
    gen_atom(rng, depth, out);
    for _ in 0..rng.below(4) {
        ws(rng, out);
        out.push(['+', '-', '*', '/', '%'][rng.below(5) as usize]);
        gen_atom(rng, depth, out);
    }
}

fn gen_calc(rng: &mut Rng) -> Vec<Arg> {
    let mut s = String::new();
    gen_expr(rng, 3, &mut s);
    ws(rng, &mut s);
    match rng.below(14) {
        0 => s.push_str(" +"),
        1 => s.push(')'),
        2 => s.insert(0, '('),
        3 => s.push_str("/0"),
        4 => s.push('x'),
        5 => s.clear(),
        _ => {}
    }
    calc_case(&s)
}
