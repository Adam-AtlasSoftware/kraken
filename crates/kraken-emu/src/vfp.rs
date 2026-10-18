//! ARM VFP integer/floating-point conversions that Ghidra's spec leaves as pseudo-ops and
//! icicle does not implement (`vcvt.f64.s32`, `vcvt.s32.f64`, ...). Every C program that turns
//! an `int` into a `double` on armhf needs them.

use icicle_cpu::{Cpu, ExceptionCode, ValueSource};
use pcode::{Value, VarNode};

type Helper = fn(&mut Cpu, VarNode, [Value; 2]);

/// The helpers by SLEIGH user-op name.
pub(crate) const HELPERS: &[(&str, Helper)] = &[
    ("VectorSignedToFloat", signed_to_float),
    ("VectorUnsignedToFloat", unsigned_to_float),
    ("VectorFloatToSigned", float_to_signed),
    ("VectorFloatToUnsigned", float_to_unsigned),
];

fn unsupported(cpu: &mut Cpu) {
    cpu.exception.code = ExceptionCode::InvalidFloatSize as u32;
    cpu.exception.value = 0;
}

fn put_float(cpu: &mut Cpu, dst: VarNode, v: f64) {
    match dst.size {
        8 => cpu.write_var(dst, v.to_bits()),
        4 => cpu.write_var(dst, (v as f32).to_bits()),
        _ => unsupported(cpu),
    }
}

fn signed_to_float(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u64 = cpu.read_dynamic(args[0]).sxt();
    put_float(cpu, dst, x as i64 as f64);
}

fn unsigned_to_float(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u64 = cpu.read_dynamic(args[0]).zxt();
    put_float(cpu, dst, x as f64);
}

/// Reads a `float` or `double` operand.
fn get_float(cpu: &mut Cpu, v: Value) -> Option<f64> {
    match v.size() {
        8 => Some(f64::from_bits(cpu.read_dynamic(v).zxt())),
        4 => {
            let b: u64 = cpu.read_dynamic(v).zxt();
            Some(f64::from(f32::from_bits(b as u32)))
        }
        _ => None,
    }
}

/// Rounds per the ARM rounding mode: 0 nearest (ties to even), 1 towards +inf, 2 towards -inf,
/// 3 towards zero.
fn round(v: f64, mode: u8) -> f64 {
    match mode & 3 {
        0 => {
            let r = v.round();
            if (v - v.trunc()).abs() == 0.5 && r % 2.0 != 0.0 {
                r - v.signum()
            } else {
                r
            }
        }
        1 => v.ceil(),
        2 => v.floor(),
        _ => v.trunc(),
    }
}

fn float_to_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let Some(v) = get_float(cpu, args[0]) else {
        return unsupported(cpu);
    };
    let mode = cpu.read::<u8>(args[1]);
    let bits = u32::from(dst.size) * 8;
    let (lo, hi) = (
        -(2f64.powi(bits as i32 - 1)),
        2f64.powi(bits as i32 - 1) - 1.0,
    );
    // Saturating, NaN to zero (as the hardware does).
    let r = if v.is_nan() {
        0.0
    } else {
        round(v, mode).clamp(lo, hi)
    };
    cpu.write_trunc(dst, r as i64 as u64);
}

fn float_to_unsigned(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let Some(v) = get_float(cpu, args[0]) else {
        return unsupported(cpu);
    };
    let mode = cpu.read::<u8>(args[1]);
    let bits = u32::from(dst.size) * 8;
    let hi = 2f64.powi(bits as i32) - 1.0;
    let r = if v.is_nan() {
        0.0
    } else {
        round(v, mode).clamp(0.0, hi)
    };
    cpu.write_trunc(dst, r as u64);
}

#[cfg(test)]
mod tests {
    use super::round;

    #[test]
    fn rounding_modes() {
        assert_eq!(round(2.5, 0), 2.0);
        assert_eq!(round(3.5, 0), 4.0);
        assert_eq!(round(-2.5, 0), -2.0);
        assert_eq!(round(2.4, 1), 3.0);
        assert_eq!(round(-2.4, 2), -3.0);
        assert_eq!(round(-2.7, 3), -2.0);
    }
}
