//! AArch64 Advanced SIMD operations that Ghidra's spec leaves as pseudo-ops (`NEON_*`) and
//! icicle does not implement; glibc's string and memory routines use several of them. Each helper
//! works lane by lane on the operand bytes. The element size is the last constant argument: in
//! `cpu.args[0]` for three-operand forms, the second operand for two-operand ones.

use icicle_cpu::{Cpu, ExceptionCode, ValueSource};
use pcode::{Value, VarNode};

type Helper = fn(&mut Cpu, VarNode, [Value; 2]);

/// The helpers by SLEIGH user-op name.
pub(crate) const HELPERS: &[(&str, Helper)] = &[
    ("NEON_ext", ext),
    ("NEON_umaxp", umaxp),
    ("NEON_uminp", uminp),
    ("NEON_smaxp", smaxp),
    ("NEON_sminp", sminp),
    ("NEON_umax", umax),
    ("NEON_umin", umin),
    ("NEON_smax", smax),
    ("NEON_smin", smin),
    ("NEON_uabd", uabd),
    ("NEON_uhadd", uhadd),
    ("NEON_urhadd", urhadd),
    ("NEON_uqadd", uqadd),
    ("NEON_uqsub", uqsub),
    ("NEON_sqadd", sqadd),
    ("NEON_sqsub", sqsub),
    ("NEON_ushl", ushl),
    ("NEON_sshl", sshl),
    ("NEON_uaddlv", uaddlv),
    ("NEON_saddlv", saddlv),
    ("NEON_rev16", rev16),
    ("NEON_rev32", rev32),
    ("NEON_rev64", rev64),
    ("NEON_rbit", rbit),
    ("NEON_cls", cls),
    ("NEON_sshr", sshr_scalar),
    ("NEON_shl", shl_scalar),
];

fn bad_size(cpu: &mut Cpu) {
    cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
    cpu.exception.value = 0;
}

fn lane(cpu: &mut Cpu, v: Value, i: u8, size: u8) -> u64 {
    cpu.read_dynamic(v.slice(i * size, size)).zxt()
}

fn lane_s(cpu: &mut Cpu, v: Value, i: u8, size: u8) -> i64 {
    let x: u64 = cpu.read_dynamic(v.slice(i * size, size)).sxt();
    x as i64
}

fn put(cpu: &mut Cpu, dst: VarNode, i: u8, size: u8, v: u64) {
    if (i + 1) * size <= dst.size {
        cpu.write_trunc(dst.slice(i * size, size), v);
    }
}

fn esize3(cpu: &mut Cpu) -> Option<u8> {
    match cpu.args[0] as u8 {
        s @ (1 | 2 | 4 | 8) => Some(s),
        _ => {
            bad_size(cpu);
            None
        }
    }
}

fn esize2(cpu: &mut Cpu, v: Value) -> Option<u8> {
    match cpu.read::<u8>(v) {
        s @ (1 | 2 | 4 | 8) => Some(s),
        _ => {
            bad_size(cpu);
            None
        }
    }
}

fn mask(size: u8) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// `EXT Vd, Vn, Vm, #imm`: bytes `imm..` of the concatenation `Vm:Vn` (`Vn` low).
fn ext(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let imm = cpu.args[0] as u8;
    let n = args[0].size();
    let mut out = [0u8; 32];
    for i in 0..n.min(32) {
        let k = i + imm;
        out[i as usize] = if k < n {
            lane(cpu, args[0], k, 1) as u8
        } else if k < 2 * n {
            lane(cpu, args[1], k - n, 1) as u8
        } else {
            0
        };
    }
    for i in 0..dst.size.min(n).min(32) {
        put(cpu, dst, i, 1, u64::from(out[i as usize]));
    }
}

/// Pairwise: the low half of the result from adjacent pairs of the first operand, the high half
/// from the second.
fn pairwise(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(u64, u64, u8) -> u64) {
    let Some(size) = esize3(cpu) else { return };
    let lanes = args[0].size() / size;
    let mut out = [0u64; 16];
    for j in 0..lanes.min(16) {
        let (src, k) = if j < lanes / 2 {
            (args[0], 2 * j)
        } else {
            (args[1], 2 * (j - lanes / 2))
        };
        let a = lane(cpu, src, k, size);
        let b = lane(cpu, src, k + 1, size);
        out[j as usize] = f(a, b, size);
    }
    for j in 0..lanes.min(16) {
        put(cpu, dst, j, size, out[j as usize]);
    }
}

fn sext(v: u64, size: u8) -> i64 {
    let s = 64 - u32::from(size) * 8;
    ((v << s) as i64) >> s
}

fn umaxp(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    pairwise(c, d, a, |x, y, _| x.max(y));
}
fn uminp(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    pairwise(c, d, a, |x, y, _| x.min(y));
}
fn smaxp(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    pairwise(
        c,
        d,
        a,
        |x, y, s| if sext(x, s) >= sext(y, s) { x } else { y },
    );
}
fn sminp(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    pairwise(
        c,
        d,
        a,
        |x, y, s| if sext(x, s) <= sext(y, s) { x } else { y },
    );
}

/// Element-wise over two operands.
fn elementwise(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(u64, u64, u8) -> u64) {
    let Some(size) = esize3(cpu) else { return };
    let lanes = args[0].size() / size;
    for j in 0..lanes {
        let a = lane(cpu, args[0], j, size);
        let b = lane(cpu, args[1], j, size);
        put(cpu, dst, j, size, f(a, b, size) & mask(size));
    }
}

fn umax(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| x.max(y));
}
fn umin(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| x.min(y));
}
fn smax(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(
        c,
        d,
        a,
        |x, y, s| if sext(x, s) >= sext(y, s) { x } else { y },
    );
}
fn smin(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(
        c,
        d,
        a,
        |x, y, s| if sext(x, s) <= sext(y, s) { x } else { y },
    );
}
fn uabd(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| x.abs_diff(y));
}
fn uhadd(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| {
        ((u128::from(x) + u128::from(y)) >> 1) as u64
    });
}
fn urhadd(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| {
        ((u128::from(x) + u128::from(y) + 1) >> 1) as u64
    });
}
fn uqadd(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, s| x.saturating_add(y).min(mask(s)));
}
fn uqsub(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, _| x.saturating_sub(y));
}
fn sat_s(v: i128, size: u8) -> u64 {
    let bits = u32::from(size) * 8;
    let (lo, hi) = (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1);
    (v.clamp(lo, hi) as i64) as u64
}
fn sqadd(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, s| {
        sat_s(i128::from(sext(x, s)) + i128::from(sext(y, s)), s)
    });
}
fn sqsub(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, s| {
        sat_s(i128::from(sext(x, s)) - i128::from(sext(y, s)), s)
    });
}
/// Shift by the signed low byte of the second operand's lane (left when positive).
fn ushl(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, s| {
        let sh = i64::from(y as u8 as i8);
        let bits = i64::from(s) * 8;
        if sh >= bits || sh <= -bits {
            0
        } else if sh >= 0 {
            x << sh
        } else {
            x >> (-sh)
        }
    });
}
fn sshl(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    elementwise(c, d, a, |x, y, s| {
        let sh = i64::from(y as u8 as i8);
        let bits = i64::from(s) * 8;
        let v = sext(x, s);
        if sh >= bits {
            0
        } else if sh <= -bits {
            if v < 0 { u64::MAX } else { 0 }
        } else if sh >= 0 {
            (v << sh) as u64
        } else {
            (v >> (-sh)) as u64
        }
    });
}

fn add_lanes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], signed: bool) {
    let Some(size) = esize2(cpu, args[1]) else {
        return;
    };
    let lanes = args[0].size() / size;
    let mut sum: i128 = 0;
    for j in 0..lanes {
        sum += if signed {
            i128::from(lane_s(cpu, args[0], j, size))
        } else {
            i128::from(lane(cpu, args[0], j, size))
        };
    }
    let bytes = dst.size;
    if let Some(b) = cpu.regs.get_mut(dst) {
        b.fill(0);
    }
    cpu.write_trunc(dst.slice(0, bytes.min(8)), sum as u64);
}

fn uaddlv(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    add_lanes(c, d, a, false);
}
fn saddlv(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    add_lanes(c, d, a, true);
}

/// Reverses the `size`-byte elements inside each `group`-byte container.
fn rev_in(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], group: u8) {
    let Some(size) = esize2(cpu, args[1]) else {
        return;
    };
    let n = args[0].size();
    if size >= group {
        bad_size(cpu);
        return;
    }
    let per = group / size;
    let mut out = [0u64; 16];
    let lanes = n / size;
    for j in 0..lanes.min(16) {
        let g = j / per;
        let k = j % per;
        out[j as usize] = lane(cpu, args[0], g * per + (per - 1 - k), size);
    }
    for j in 0..lanes.min(16) {
        put(cpu, dst, j, size, out[j as usize]);
    }
}

fn rev16(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    rev_in(c, d, a, 2);
}
fn rev32(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    rev_in(c, d, a, 4);
}
fn rev64(c: &mut Cpu, d: VarNode, a: [Value; 2]) {
    rev_in(c, d, a, 8);
}

fn rbit(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let n = args[0].size();
    for j in 0..n {
        let b = lane(cpu, args[0], j, 1) as u8;
        put(cpu, dst, j, 1, u64::from(b.reverse_bits()));
    }
}

fn cls(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let Some(size) = esize2(cpu, args[1]) else {
        return;
    };
    let lanes = args[0].size() / size;
    for j in 0..lanes {
        let v = lane_s(cpu, args[0], j, size);
        let bits = u32::from(size) * 8;
        let x = (if v < 0 { !v } else { v }) as u64 & mask(size);
        let lz = x.leading_zeros() - (64 - bits);
        put(cpu, dst, j, size, u64::from(lz.saturating_sub(1)));
    }
}

/// Scalar `SSHR Dd, Dn, #imm`.
fn sshr_scalar(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let v: u64 = cpu.read_dynamic(args[0]).zxt();
    let sh = u32::from(cpu.read::<u8>(args[1])).min(63);
    cpu.write_trunc(dst, ((v as i64) >> sh) as u64);
}

/// Scalar `SHL Dd, Dn, #imm`.
fn shl_scalar(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let v: u64 = cpu.read_dynamic(args[0]).zxt();
    let sh = u32::from(cpu.read::<u8>(args[1])).min(63);
    cpu.write_trunc(dst, v << sh);
}
