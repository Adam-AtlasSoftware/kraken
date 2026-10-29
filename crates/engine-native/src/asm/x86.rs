//! Intel-syntax x86 and x86-64 assembly over iced's encoder. iced has no text parser, so this
//! parses the syntax the listing prints (`mov eax, 0x7`, `dword ptr [rbp + -0x4]`), then looks
//! for the `Code` values of the mnemonic whose operand kinds fit and encodes each one.

use std::collections::HashMap;
use std::sync::OnceLock;

use iced_x86::{
    Code, Encoder, EncodingKind, Instruction, OpCodeOperandKind, OpKind, Register, RepPrefixKind,
};

/// A parsed operand.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Reg(Register),
    Imm(i128),
    Mem(Mem),
}

/// A memory operand.
#[derive(Debug, Clone, PartialEq)]
pub struct Mem {
    /// Bytes named by `dword ptr` and friends.
    pub size: Option<u32>,
    pub seg: Register,
    pub base: Register,
    pub index: Register,
    pub scale: u32,
    pub disp: i64,
    /// Whether a symbol is in the expression: an absolute address, even next to `rip`.
    pub symbolic: bool,
}

/// One instruction as typed.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub mnemonic: String,
    pub prefixes: Vec<String>,
    pub ops: Vec<Op>,
}

/// Resolves a symbol or label to an address.
pub type Resolver<'a> = &'a dyn Fn(&str) -> Option<u64>;

fn reg_table() -> &'static HashMap<String, Register> {
    static T: OnceLock<HashMap<String, Register>> = OnceLock::new();
    T.get_or_init(|| {
        Register::values()
            .filter(|r| *r != Register::None)
            .map(|r| (format!("{r:?}").to_lowercase(), r))
            .collect()
    })
}

pub fn register(name: &str) -> Option<Register> {
    reg_table().get(&name.to_ascii_lowercase()).copied()
}

/// Every register named in `text`.
pub fn registers_in(text: &str) -> Vec<Register> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(register)
        .collect()
}

fn mnemonic_table() -> &'static HashMap<String, Vec<Code>> {
    static T: OnceLock<HashMap<String, Vec<Code>>> = OnceLock::new();
    T.get_or_init(|| {
        let mut m: HashMap<String, Vec<Code>> = HashMap::new();
        for c in Code::values() {
            if c.op_code().encoding() == EncodingKind::Legacy {
                m.entry(format!("{:?}", c.mnemonic()).to_lowercase())
                    .or_default()
                    .push(c);
            }
        }
        m
    })
}

fn size_word(w: &str) -> Option<u32> {
    Some(match w {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "fword" => 6,
        "qword" => 8,
        "tbyte" => 10,
        "oword" | "xmmword" => 16,
        "ymmword" => 32,
        _ => return None,
    })
}

fn parse_number(t: &str) -> Option<i128> {
    let t = t.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i128::from_str_radix(h, 16).ok()?
    } else if t.starts_with(|c: char| c.is_ascii_digit()) && t.ends_with(['h', 'H']) {
        i128::from_str_radix(&t[..t.len() - 1], 16).ok()?
    } else if t.chars().count() == 3 && t.starts_with('\'') && t.ends_with('\'') {
        t.chars().nth(1)? as i128
    } else {
        t.parse::<i128>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// Splits `a + b - c` into signed terms.
fn terms(expr: &str) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut neg = false;
    for c in expr.chars() {
        if c == '+' || c == '-' {
            if cur.trim().is_empty() {
                if c == '-' {
                    neg = !neg;
                }
                cur.clear();
            } else {
                out.push((neg, cur.trim().to_string()));
                cur.clear();
                neg = c == '-';
            }
            continue;
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push((neg, cur.trim().to_string()));
    }
    out
}

fn is_symbol(t: &str) -> bool {
    t.starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '_' | '.' | '$' | '?' | '@'))
}

/// A numeric expression with symbols resolved; the flag says whether a symbol was used.
fn eval(expr: &str, sym: Resolver) -> Result<(i128, bool), String> {
    let ts = terms(expr);
    if ts.is_empty() {
        return Err(format!("`{expr}` is not a value"));
    }
    let mut total = 0i128;
    let mut symbolic = false;
    for (neg, t) in ts {
        let v = if let Some(n) = parse_number(&t) {
            n
        } else if is_symbol(&t) {
            symbolic = true;
            sym(&t).ok_or_else(|| format!("unknown symbol `{t}`"))? as i128
        } else {
            return Err(format!("`{t}` is not a number or a symbol"));
        };
        total += if neg { -v } else { v };
    }
    Ok((total, symbolic))
}

fn parse_mem(text: &str, sym: Resolver) -> Result<Mem, String> {
    let mut rest = text.trim();
    let mut size = None;
    loop {
        let (w, r) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let lw = w.to_ascii_lowercase();
        if let Some(n) = size_word(&lw) {
            size = Some(n);
        } else if lw != "ptr" {
            break;
        }
        rest = r.trim_start();
    }
    let mut seg = Register::None;
    if let Some((s, r)) = rest.split_once(':')
        && let Some(reg) = register(s.trim())
        && reg.is_segment_register()
    {
        seg = reg;
        rest = r.trim();
    }
    let inner = rest
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or_else(|| format!("`{text}` is not a memory operand"))?;
    let mut inner = inner;
    if let Some((sg, r)) = inner.split_once(':')
        && let Some(reg) = register(sg.trim())
        && reg.is_segment_register()
    {
        seg = reg;
        inner = r;
    }
    let mut m = Mem {
        size,
        seg,
        base: Register::None,
        index: Register::None,
        scale: 1,
        disp: 0,
        symbolic: false,
    };
    for (neg, t) in terms(inner) {
        if let Some((a, b)) = t.split_once('*') {
            let (r, s) = if register(a.trim()).is_some() {
                (a.trim(), b.trim())
            } else {
                (b.trim(), a.trim())
            };
            let reg = register(r).ok_or_else(|| format!("`{t}` is not a scaled register"))?;
            let sc = parse_number(s).ok_or_else(|| format!("bad scale in `{t}`"))?;
            if !matches!(sc, 1 | 2 | 4 | 8) || neg {
                return Err(format!("bad scale in `{t}`"));
            }
            m.index = reg;
            m.scale = sc as u32;
        } else if let Some(reg) = register(&t) {
            if neg {
                return Err("a register cannot be subtracted".into());
            }
            if m.base == Register::None {
                m.base = reg;
            } else if m.index == Register::None {
                m.index = reg;
            } else {
                return Err("too many registers in the address".into());
            }
        } else {
            let (v, s) = eval(&t, sym)?;
            m.symbolic |= s;
            m.disp = m.disp.wrapping_add(if neg { -v } else { v } as i64);
        }
    }
    Ok(m)
}

fn parse_operand(text: &str, sym: Resolver) -> Result<Op, String> {
    let t = text.trim();
    if let Some(r) = register(t) {
        return Ok(Op::Reg(r));
    }
    if t.contains('[') {
        return parse_mem(t, sym).map(Op::Mem);
    }
    let t = ["offset ", "short ", "near "]
        .iter()
        .find_map(|p| t.strip_prefix(p))
        .unwrap_or(t);
    eval(t, sym).map(|(v, _)| Op::Imm(v))
}

/// Splits operands at top-level commas.
fn split_operands(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

pub fn parse_line(line: &str, sym: Resolver) -> Result<Parsed, String> {
    let mut rest = line.trim();
    let mut prefixes = Vec::new();
    let mnemonic = loop {
        let (w, r) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let lw = w.to_ascii_lowercase();
        if matches!(
            lw.as_str(),
            "rep" | "repe" | "repz" | "repne" | "repnz" | "lock"
        ) && !r.trim().is_empty()
        {
            prefixes.push(lw);
            rest = r.trim_start();
            continue;
        }
        rest = r;
        break lw;
    };
    if mnemonic.is_empty() {
        return Err("empty instruction".into());
    }
    let ops = split_operands(rest)
        .iter()
        .map(|o| parse_operand(o, sym))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Parsed {
        mnemonic: alias(&mnemonic),
        prefixes,
        ops,
    })
}

/// Spellings iced does not use for the mnemonic.
fn alias(m: &str) -> String {
    match m {
        "jz" => "je",
        "jnz" => "jne",
        "jnae" | "jc" => "jb",
        "jnb" | "jnc" => "jae",
        "jna" => "jbe",
        "jnbe" => "ja",
        "jpe" => "jp",
        "jpo" => "jnp",
        "jnge" => "jl",
        "jnl" => "jge",
        "jng" => "jle",
        "jnle" => "jg",
        "setz" => "sete",
        "setnz" => "setne",
        "cmovz" => "cmove",
        "cmovnz" => "cmovne",
        "sal" => "shl",
        "retn" => "ret",
        "movabs" => "mov",
        other => other,
    }
    .to_string()
}

/// A mnemonic with condition synonyms folded, to compare with Sleigh's spelling.
pub fn canonical(m: &str) -> String {
    let m = m.to_ascii_lowercase();
    let m = m.split('.').next().unwrap_or("").to_string();
    for stem in ["j", "set", "cmov"] {
        if let Some(c) = m.strip_prefix(stem) {
            let cond = match c {
                "z" | "e" => "e",
                "nz" | "ne" => "ne",
                "c" | "b" | "nae" => "b",
                "nc" | "ae" | "nb" => "ae",
                "na" | "be" => "be",
                "a" | "nbe" => "a",
                "pe" | "p" => "p",
                "po" | "np" => "np",
                "l" | "nge" => "l",
                "ge" | "nl" => "ge",
                "le" | "ng" => "le",
                "g" | "nle" => "g",
                _ => continue,
            };
            return format!("{stem}{cond}");
        }
    }
    match m.as_str() {
        "sal" => "shl".into(),
        "retn" => "ret".into(),
        _ => m,
    }
}

fn fits(v: i128, lo: i128, hi: i128) -> bool {
    (lo..=hi).contains(&v)
}

fn reg_matches(kind: OpCodeOperandKind, r: Register) -> bool {
    use OpCodeOperandKind as K;
    match kind {
        K::r8_reg | K::r8_opcode | K::r8_or_mem => r.is_gpr8(),
        K::r16_reg | K::r16_reg_mem | K::r16_rm | K::r16_opcode | K::r16_or_mem => r.is_gpr16(),
        K::r32_reg
        | K::r32_reg_mem
        | K::r32_rm
        | K::r32_opcode
        | K::r32_or_mem
        | K::r32_or_mem_mpx => r.is_gpr32(),
        K::r64_reg
        | K::r64_reg_mem
        | K::r64_rm
        | K::r64_opcode
        | K::r64_or_mem
        | K::r64_or_mem_mpx => r.is_gpr64(),
        K::seg_reg => r.is_segment_register(),
        K::xmm_reg | K::xmm_rm | K::xmm_or_mem => r.is_xmm(),
        K::al => r == Register::AL,
        K::cl => r == Register::CL,
        K::ax => r == Register::AX,
        K::dx => r == Register::DX,
        K::eax => r == Register::EAX,
        K::rax => r == Register::RAX,
        K::es => r == Register::ES,
        K::cs => r == Register::CS,
        K::ss => r == Register::SS,
        K::ds => r == Register::DS,
        K::fs => r == Register::FS,
        K::gs => r == Register::GS,
        _ => false,
    }
}

/// The memory size a kind demands (`Some(None)`: memory of the code's own size).
fn mem_kind_size(kind: OpCodeOperandKind) -> Option<Option<u32>> {
    use OpCodeOperandKind as K;
    match kind {
        K::r8_or_mem => Some(Some(1)),
        K::r16_or_mem => Some(Some(2)),
        K::r32_or_mem | K::r32_or_mem_mpx => Some(Some(4)),
        K::r64_or_mem | K::r64_or_mem_mpx => Some(Some(8)),
        K::xmm_or_mem | K::mem => Some(None),
        _ => None,
    }
}

fn matches_op(kind: OpCodeOperandKind, op: &Op, bitness: u32) -> bool {
    use OpCodeOperandKind as K;
    match op {
        Op::Reg(r) => reg_matches(kind, *r),
        Op::Mem(m) => {
            let Some(want) = mem_kind_size(kind) else {
                return false;
            };
            if bitness == 32 && matches!(m.base, Register::RIP | Register::EIP) {
                return false;
            }
            match (m.size, want) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
        }
        Op::Imm(v) => {
            let v = *v;
            match kind {
                K::imm8 => fits(v, -128, 255),
                K::imm8sex16 | K::imm8sex32 | K::imm8sex64 => fits(v, -128, 127),
                K::imm16 => fits(v, -32768, 65535),
                K::imm32 => fits(v, -(1 << 31), (1 << 32) - 1),
                K::imm32sex64 => fits(v, -(1 << 31), (1 << 31) - 1),
                K::imm64 => fits(v, i64::MIN as i128, u64::MAX as i128),
                K::imm8_const_1 => v == 1,
                K::br64_1 | K::br64_4 => bitness == 64,
                K::br32_1 | K::br32_4 => bitness == 32,
                _ => false,
            }
        }
    }
}

fn build(
    code: Code,
    p: &Parsed,
    ip: u64,
    bitness: u32,
    rip_disp: &mut Option<i64>,
) -> Option<Instruction> {
    use OpCodeOperandKind as K;
    let info = code.op_code();
    let mut ins = Instruction::default();
    ins.set_code(code);
    for (i, op) in p.ops.iter().enumerate() {
        let kind = info.op_kind(i as u32);
        let i = i as u32;
        match op {
            Op::Reg(r) => {
                ins.set_op_kind(i, OpKind::Register);
                ins.set_op_register(i, *r);
            }
            Op::Imm(v) => match kind {
                K::imm8 => {
                    ins.set_op_kind(i, OpKind::Immediate8);
                    ins.set_immediate8(*v as u8);
                }
                K::imm8sex16 => {
                    ins.set_op_kind(i, OpKind::Immediate8to16);
                    ins.set_immediate8to16(*v as i16);
                }
                K::imm8sex32 => {
                    ins.set_op_kind(i, OpKind::Immediate8to32);
                    ins.set_immediate8to32(*v as i32);
                }
                K::imm8sex64 => {
                    ins.set_op_kind(i, OpKind::Immediate8to64);
                    ins.set_immediate8to64(*v as i64);
                }
                K::imm16 => {
                    ins.set_op_kind(i, OpKind::Immediate16);
                    ins.set_immediate16(*v as u16);
                }
                K::imm32 => {
                    ins.set_op_kind(i, OpKind::Immediate32);
                    ins.set_immediate32(*v as u32);
                }
                K::imm32sex64 => {
                    ins.set_op_kind(i, OpKind::Immediate32to64);
                    ins.set_immediate32to64(*v as i64);
                }
                K::imm64 => {
                    ins.set_op_kind(i, OpKind::Immediate64);
                    ins.set_immediate64(*v as u64);
                }
                K::imm8_const_1 => {
                    ins.set_op_kind(i, OpKind::Immediate8);
                    ins.set_immediate8(1);
                }
                K::br64_1 | K::br64_4 => {
                    ins.set_op_kind(i, OpKind::NearBranch64);
                    ins.set_near_branch64(*v as u64);
                }
                K::br32_1 | K::br32_4 => {
                    ins.set_op_kind(i, OpKind::NearBranch32);
                    ins.set_near_branch32(*v as u32);
                }
                _ => return None,
            },
            Op::Mem(m) => {
                ins.set_op_kind(i, OpKind::Memory);
                ins.set_memory_base(m.base);
                ins.set_memory_index(m.index);
                ins.set_memory_index_scale(m.scale);
                ins.set_segment_prefix(m.seg);
                if matches!(m.base, Register::RIP | Register::EIP) {
                    ins.set_memory_displ_size(if m.base == Register::RIP { 8 } else { 4 });
                    if m.symbolic {
                        ins.set_memory_displacement64(m.disp as u64);
                    } else {
                        *rip_disp = Some(m.disp);
                        ins.set_memory_displacement64(ip.wrapping_add(m.disp as u64));
                    }
                } else {
                    let must_have_disp = matches!(
                        m.base,
                        Register::RBP | Register::EBP | Register::R13 | Register::R13D
                    );
                    let size = if m.base == Register::None && m.index == Register::None {
                        if bitness == 64 { 8 } else { 4 }
                    } else if m.base == Register::None {
                        4
                    } else if m.disp == 0 && !must_have_disp {
                        0
                    } else if fits(m.disp as i128, -128, 127) {
                        1
                    } else {
                        4
                    };
                    ins.set_memory_displ_size(size);
                    ins.set_memory_displacement64(m.disp as u64);
                }
            }
        }
    }
    for pre in &p.prefixes {
        match pre.as_str() {
            "rep" | "repe" | "repz" => ins.set_has_repe_prefix(true),
            "repne" | "repnz" => ins.set_has_repne_prefix(true),
            "lock" => ins.set_has_lock_prefix(true),
            _ => {}
        }
    }
    Some(ins)
}

/// `movsb`, `stosd`, `rep scasb` and the other string instructions without operands.
fn string_op(p: &Parsed, bitness: u32) -> Option<Instruction> {
    let rep = if p.prefixes.iter().any(|x| x == "repne" || x == "repnz") {
        RepPrefixKind::Repne
    } else if p.prefixes.iter().any(|x| x.starts_with("rep")) {
        RepPrefixKind::Repe
    } else {
        RepPrefixKind::None
    };
    let n = Register::None;
    let a = bitness;
    let m = p.mnemonic.as_str();
    let i = match m {
        "movsb" => Instruction::with_movsb(a, n, rep),
        "movsw" => Instruction::with_movsw(a, n, rep),
        "movsd" => Instruction::with_movsd(a, n, rep),
        "movsq" => Instruction::with_movsq(a, n, rep),
        "stosb" => Instruction::with_stosb(a, rep),
        "stosw" => Instruction::with_stosw(a, rep),
        "stosd" => Instruction::with_stosd(a, rep),
        "stosq" => Instruction::with_stosq(a, rep),
        "lodsb" => Instruction::with_lodsb(a, n, rep),
        "lodsw" => Instruction::with_lodsw(a, n, rep),
        "lodsd" => Instruction::with_lodsd(a, n, rep),
        "lodsq" => Instruction::with_lodsq(a, n, rep),
        "scasb" => Instruction::with_scasb(a, rep),
        "scasw" => Instruction::with_scasw(a, rep),
        "scasd" => Instruction::with_scasd(a, rep),
        "scasq" => Instruction::with_scasq(a, rep),
        "cmpsb" => Instruction::with_cmpsb(a, n, rep),
        "cmpsw" => Instruction::with_cmpsw(a, n, rep),
        "cmpsd" => Instruction::with_cmpsd(a, n, rep),
        "cmpsq" => Instruction::with_cmpsq(a, n, rep),
        _ => return None,
    };
    i.ok()
}

/// Every encoding of the instruction at `ip`, shortest first (iced's table order among equals,
/// so the form compilers emit comes first).
pub fn encode(p: &Parsed, ip: u64, bitness: u32) -> Result<Vec<Vec<u8>>, String> {
    let codes = mnemonic_table()
        .get(&p.mnemonic)
        .ok_or_else(|| format!("`{}` is not an x86 instruction", p.mnemonic))?;
    let mut found: Vec<Vec<u8>> = Vec::new();
    let mut tried = false;
    if p.ops.is_empty()
        && let Some(ins) = string_op(p, bitness)
    {
        let mut enc = Encoder::new(bitness);
        if enc.encode(&ins, ip).is_ok() {
            return Ok(vec![enc.take_buffer()]);
        }
    }
    for &code in codes {
        let info = code.op_code();
        let mode_ok = if bitness == 64 {
            info.mode64()
        } else {
            info.mode32()
        };
        if !mode_ok || info.op_count() as usize != p.ops.len() {
            continue;
        }
        if !p
            .ops
            .iter()
            .enumerate()
            .all(|(i, op)| matches_op(info.op_kind(i as u32), op, bitness))
        {
            continue;
        }
        let rep = p.prefixes.iter().any(|x| x.starts_with("rep"));
        if (rep && !info.can_use_rep_prefix() && !info.can_use_repne_prefix())
            || (p.prefixes.iter().any(|x| x == "lock") && !info.can_use_lock_prefix())
        {
            continue;
        }
        tried = true;
        let mut rip_disp = None;
        let Some(mut ins) = build(code, p, ip, bitness, &mut rip_disp) else {
            continue;
        };
        let ms = ins.memory_size().size() as u32;
        if p.ops
            .iter()
            .any(|o| matches!(o, Op::Mem(Mem { size: Some(n), .. }) if ms != 0 && ms != *n))
        {
            continue;
        }
        let mut enc = Encoder::new(bitness);
        let Ok(len) = enc.encode(&ins, ip) else {
            continue;
        };
        let bytes = if let Some(d) = rip_disp {
            ins.set_memory_displacement64(ip.wrapping_add(len as u64).wrapping_add(d as u64));
            let mut again = Encoder::new(bitness);
            match again.encode(&ins, ip) {
                Ok(l) if l == len => again.take_buffer(),
                _ => continue,
            }
        } else {
            enc.take_buffer()
        };
        if !found.contains(&bytes) {
            found.push(bytes);
        }
    }
    if found.is_empty() {
        return Err(if tried {
            format!(
                "`{}` does not fit here (an operand is out of range or a branch is too far)",
                p.mnemonic
            )
        } else {
            format!("no form of `{}` takes these operands", p.mnemonic)
        });
    }
    found.sort_by_key(Vec::len);
    Ok(found)
}

/// A NOP of `n` bytes, from the recommended multi-byte forms.
pub fn nop(n: usize) -> Vec<u8> {
    const FORMS: [&[u8]; 9] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    let mut out = Vec::new();
    let mut left = n;
    while left > 0 {
        let k = left.min(9);
        out.extend_from_slice(FORMS[k - 1]);
        left -= k;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(line: &str, ip: u64, bits: u32) -> Vec<u8> {
        let sym = |s: &str| (s == "target").then_some(0x401100u64);
        let p = parse_line(line, &sym).unwrap();
        encode(&p, ip, bits).unwrap().remove(0)
    }

    #[test]
    fn x64_vectors() {
        let v: &[(&str, u64, &[u8])] = &[
            ("nop", 0, &[0x90]),
            ("ret", 0, &[0xc3]),
            ("push rbp", 0, &[0x55]),
            ("pop rbp", 0, &[0x5d]),
            ("mov rbp, rsp", 0, &[0x48, 0x89, 0xe5]),
            ("MOV EAX,0x7", 0, &[0xb8, 7, 0, 0, 0]),
            ("xor eax, eax", 0, &[0x31, 0xc0]),
            (
                "mov dword ptr [rbp + -0x4], 0x0",
                0,
                &[0xc7, 0x45, 0xfc, 0, 0, 0, 0],
            ),
            ("mov eax, dword ptr [rbp - 8]", 0, &[0x8b, 0x45, 0xf8]),
            ("sub rsp, 0x20", 0, &[0x48, 0x83, 0xec, 0x20]),
            (
                "lea rax, [rbx + rcx*4 + 0x10]",
                0,
                &[0x48, 0x8d, 0x44, 0x8b, 0x10],
            ),
            ("mov eax, [rbp]", 0, &[0x8b, 0x45, 0x00]),
            ("jmp target", 0x4010f0, &[0xeb, 0x0e]),
            ("jmp target", 0x400000, &[0xe9, 0xfb, 0x10, 0x00, 0x00]),
            ("call target", 0x401000, &[0xe8, 0xfb, 0x00, 0x00, 0x00]),
            ("je target", 0x401100, &[0x74, 0xfe]),
            ("jnz 0x401000", 0x401000, &[0x75, 0xfe]),
            (
                "mov rax, -1",
                0,
                &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff],
            ),
            (
                "mov rax, 0x1122334455",
                0,
                &[0x48, 0xb8, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0, 0],
            ),
            (
                "lea rax, [rip + 0x10]",
                0x1000,
                &[0x48, 0x8d, 0x05, 0x10, 0, 0, 0],
            ),
            (
                "lea rax, [rip + target]",
                0x401000,
                &[0x48, 0x8d, 0x05, 0xf9, 0x00, 0x00, 0x00],
            ),
            ("call rax", 0, &[0xff, 0xd0]),
            ("call qword ptr [rax + 8]", 0, &[0xff, 0x50, 0x08]),
            ("add al, 5", 0, &[0x04, 0x05]),
            ("shl eax, 1", 0, &[0xd1, 0xe0]),
            ("movzx eax, byte ptr [rdi]", 0, &[0x0f, 0xb6, 0x07]),
            ("rep movsb", 0, &[0xf3, 0xa4]),
            ("int3", 0, &[0xcc]),
            ("syscall", 0, &[0x0f, 0x05]),
            ("pxor xmm0, xmm0", 0, &[0x66, 0x0f, 0xef, 0xc0]),
            ("endbr64", 0, &[0xf3, 0x0f, 0x1e, 0xfa]),
            (
                "cmp byte ptr [fs:0x28], 0",
                0,
                &[0x64, 0x80, 0x3c, 0x25, 0x28, 0, 0, 0, 0],
            ),
        ];
        for (line, ip, want) in v {
            assert_eq!(asm(line, *ip, 64), *want, "{line}");
        }
    }

    #[test]
    fn x86_vectors() {
        assert_eq!(asm("push ebp", 0, 32), [0x55]);
        assert_eq!(asm("mov ebp, esp", 0, 32), [0x89, 0xe5]);
        assert_eq!(asm("mov eax, [ebp + 8]", 0, 32), [0x8b, 0x45, 0x08]);
        assert_eq!(
            asm("call target", 0x401000, 32),
            [0xe8, 0xfb, 0x00, 0x00, 0x00]
        );
        assert_eq!(asm("inc eax", 0, 32), [0x40]);
        assert_eq!(asm("int 0x80", 0, 32), [0xcd, 0x80]);
    }

    #[test]
    fn errors_are_plain() {
        let none = |_: &str| None;
        assert!(
            parse_line("jmp nowhere", &none)
                .unwrap_err()
                .contains("unknown symbol")
        );
        let p = parse_line("mov eax, rbx", &none).unwrap();
        assert!(
            encode(&p, 0, 64)
                .unwrap_err()
                .contains("takes these operands")
        );
        let p = parse_line("frobnicate eax", &none).unwrap();
        assert!(
            encode(&p, 0, 64)
                .unwrap_err()
                .contains("not an x86 instruction")
        );
        let p = parse_line("mov al, 0x1ff", &none).unwrap();
        assert!(encode(&p, 0, 64).is_err());
    }

    #[test]
    fn nops_have_the_right_length() {
        for n in 1..40 {
            assert_eq!(nop(n).len(), n);
        }
    }
}
