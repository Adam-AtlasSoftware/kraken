//! The x86-64-v3 instruction set of the x86 CPU: SSSE3, SSE4, AVX, AVX2, FMA, F16C and the parts
//! of BMI that need it.
//!
//! Ghidra's spec describes most of these with pseudo-ops (`vpand_avx2(...)`) that icicle does not
//! implement, and icicle's lifter takes no value wider than 128 bits into or out of a pseudo-op or
//! through arithmetic. Everything here is applied when the patched spec is written
//! ([`crate::specs`]):
//!
//! * [`rewrite_sinc`] turns each pseudo-op statement into calls of one pseudo-op,
//!   `kvec(op, half, a0, a1, b0, b1, c0, c1)`: operands travel as two 128-bit halves and a 256-bit
//!   result comes back one half per call. [`kvec`] runs the operation in [`OPS`] on whole
//!   operands. Legacy SSE forms ([`LEGACY`]) share those operations.
//! * [`BODIES`], [`spec_fixes`] and the small rewrites in [`rewrite_sinc`] replace statements that
//!   icicle cannot lift, and those a run against a real CPU found wrong in the spec
//!   (`corpus/linux-rt/src/vex_ops.c`).
//! * [`kgather`] does the gathers, whose memory access the spec leaves out, and [`kmask`] the
//!   masked moves, which touch only the elements their mask selects.
//!
//! Floating-point results follow the default MXCSR: round to nearest, exceptions masked, status
//! flags not recorded. A pseudo-op missing from [`OPS`] keeps Ghidra's name and stops the program
//! with `Exit::Unsupported`.

use icicle_cpu::mem::perm;
use icicle_cpu::{Cpu, ExceptionCode, ValueSource};
use pcode::{Value, VarNode};

/// A 256-bit value, least significant byte first. 128-bit operands use the low half.
type V = [u8; 32];

/// The operands of one operation (`n` of them were given).
pub(crate) struct In {
    a: V,
    b: V,
    c: V,
    n: u8,
    /// Bytes of the destination.
    width: u8,
}

impl In {
    /// The trailing immediate of a two- or three-operand form.
    fn imm(&self) -> u8 {
        if self.n >= 3 { self.c[0] } else { self.b[0] }
    }
}

trait El: Copy {
    const SIZE: usize;
    fn get(b: &[u8]) -> Self;
    fn put(self, b: &mut [u8]);
}

macro_rules! el {
    ($($t:ty),*) => {$(
        impl El for $t {
            const SIZE: usize = size_of::<$t>();
            fn get(b: &[u8]) -> Self {
                let mut x = [0u8; size_of::<$t>()];
                x.copy_from_slice(&b[..size_of::<$t>()]);
                <$t>::from_le_bytes(x)
            }
            fn put(self, b: &mut [u8]) {
                b[..size_of::<$t>()].copy_from_slice(&self.to_le_bytes());
            }
        }
    )*};
}
el!(u8, i8, u16, i16, u32, i32, u64, i64, f32, f64);

fn at<T: El>(v: &V, i: usize) -> T {
    T::get(&v[i * T::SIZE..])
}

fn set<T: El>(v: &mut V, i: usize, x: T) {
    x.put(&mut v[i * T::SIZE..]);
}

/// `f` over every element of `a`.
fn map<T: El, R: El>(a: &V, f: impl Fn(T) -> R) -> V {
    let mut r = [0; 32];
    for i in 0..32 / T::SIZE.max(R::SIZE) {
        set(&mut r, i, f(at(a, i)));
    }
    r
}

/// `f` over the element pairs of `a` and `b`.
fn zip<T: El>(x: &In, f: impl Fn(T, T) -> T) -> V {
    let mut r = [0; 32];
    for i in 0..32 / T::SIZE {
        set(&mut r, i, f(at(&x.a, i), at(&x.b, i)));
    }
    r
}

/// `f` once per 128-bit lane of `a` and `b`.
fn lanes(x: &In, f: impl Fn(&[u8], &[u8], &mut [u8])) -> V {
    let mut r = [0; 32];
    for l in [0, 16] {
        f(&x.a[l..l + 16], &x.b[l..l + 16], &mut r[l..l + 16]);
    }
    r
}

fn ones(on: bool) -> u8 {
    if on { 0xff } else { 0 }
}

/// A comparison that sets every bit of an element when it holds.
fn cmp<T: El + PartialOrd>(x: &In, f: impl Fn(T, T) -> bool) -> V {
    let mut r = [0; 32];
    for i in 0..32 / T::SIZE {
        let on = f(at(&x.a, i), at(&x.b, i));
        r[i * T::SIZE..(i + 1) * T::SIZE].fill(ones(on));
    }
    r
}

/// Shift count of `vpsll`-style forms: the low 64 bits of `b` (a register or an immediate).
fn count(x: &In) -> u64 {
    at::<u64>(&x.b, 0)
}

macro_rules! shift {
    ($x:expr, $t:ty, $bits:expr, |$v:ident, $n:ident| $e:expr) => {{
        let $n = count($x);
        map::<$t, $t>(&$x.a, |$v| if $n >= $bits { 0 } else { $e })
    }};
}

/// Shifts each element by the matching element of `b`.
fn var_shift<T: El + Into<u64>>(x: &In, bits: u64, f: impl Fn(T, u32) -> T, over: T) -> V {
    zip(x, |v: T, n: T| {
        let n: u64 = n.into();
        if n >= bits { over } else { f(v, n as u32) }
    })
}

/// `vpunpckl*` (`high` false) and `vpunpckh*`, per lane.
fn unpack<T: El>(x: &In, high: bool) -> V {
    let n = 16 / T::SIZE;
    lanes(x, |a, b, r| {
        let from = if high { n / 2 } else { 0 };
        for i in 0..n / 2 {
            let (p, q) = (2 * i * T::SIZE, (2 * i + 1) * T::SIZE);
            T::get(&a[(from + i) * T::SIZE..]).put(&mut r[p..]);
            T::get(&b[(from + i) * T::SIZE..]).put(&mut r[q..]);
        }
    })
}

/// `vpack*`, per lane: `a`'s elements then `b`'s, each saturated.
fn pack<T: El, R: El>(x: &In, f: impl Fn(T) -> R) -> V {
    let n = 16 / T::SIZE;
    lanes(x, |a, b, r| {
        for i in 0..n {
            f(T::get(&a[i * T::SIZE..])).put(&mut r[i * R::SIZE..]);
            f(T::get(&b[i * T::SIZE..])).put(&mut r[(n + i) * R::SIZE..]);
        }
    })
}

/// Horizontal operations, per lane: pairs of `a`, then pairs of `b`.
fn horizontal<T: El>(x: &In, f: impl Fn(T, T) -> T) -> V {
    let n = 16 / T::SIZE;
    lanes(x, |a, b, r| {
        for i in 0..n / 2 {
            let p = |s: &[u8]| {
                f(
                    T::get(&s[2 * i * T::SIZE..]),
                    T::get(&s[(2 * i + 1) * T::SIZE..]),
                )
            };
            p(a).put(&mut r[i * T::SIZE..]);
            p(b).put(&mut r[(n / 2 + i) * T::SIZE..]);
        }
    })
}

/// `vpmovzx*` and `vpmovsx*`: the low elements of `a`, widened.
fn widen<T: El, R: El>(x: &In, f: impl Fn(T) -> R) -> V {
    let mut r = [0; 32];
    for i in 0..32 / R::SIZE {
        set(&mut r, i, f(at(&x.a, i)));
    }
    r
}

/// The operands of `vphsub*`: Ghidra's VEX forms pass the destination first.
fn drop_first(x: &In) -> In {
    if x.n < 3 {
        return In {
            a: x.a,
            b: x.b,
            c: x.c,
            n: x.n,
            width: x.width,
        };
    }
    In {
        a: x.b,
        b: x.c,
        c: [0; 32],
        n: 2,
        width: x.width,
    }
}

/// Element `i` of `T` chosen by a mask bit: from `b` when set, else from `a`.
fn blend<T: El>(x: &In, on: impl Fn(usize) -> bool) -> V {
    let mut r = x.a;
    for i in 0..32 / T::SIZE {
        if on(i) {
            set(&mut r, i, at::<T>(&x.b, i));
        }
    }
    r
}

/// `a`'s element with the scalar result in its low element, as VEX scalar forms keep the rest.
fn scalar<T: El>(x: &In, v: T) -> V {
    let mut r = x.a;
    r[16..].fill(0);
    set(&mut r, 0, v);
    r
}

/// x86 `minps`: the second operand when either is NaN or both are zero.
fn fmin<T: PartialOrd>(a: T, b: T) -> T {
    if a < b { a } else { b }
}

fn fmax<T: PartialOrd>(a: T, b: T) -> T {
    if a > b { a } else { b }
}

/// One of the 32 `vcmpps` predicates. The negated comparisons are the point: they hold for NaN.
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn fcmp<T: PartialOrd + Copy>(p: u8, a: T, b: T) -> bool {
    #[allow(clippy::eq_op)]
    let nan = a != a || b != b;
    match p & 7 {
        0 => {
            if p & 8 != 0 {
                a == b || nan
            } else {
                a == b
            }
        }
        1 => {
            if p & 8 != 0 {
                !(a >= b)
            } else {
                a < b
            }
        }
        2 => {
            if p & 8 != 0 {
                !(a > b)
            } else {
                a <= b
            }
        }
        3 => {
            if p & 8 != 0 {
                false
            } else {
                nan
            }
        }
        4 => {
            if p & 8 != 0 {
                a != b && !nan
            } else {
                a != b
            }
        }
        5 => {
            if p & 8 != 0 {
                a >= b
            } else {
                !(a < b)
            }
        }
        6 => {
            if p & 8 != 0 {
                a > b
            } else {
                !(a <= b)
            }
        }
        _ => {
            if p & 8 != 0 {
                true
            } else {
                !nan
            }
        }
    }
}

fn fcmp_all<T: El + PartialOrd>(x: &In) -> V {
    let p = x.c[0];
    let mut r = [0; 32];
    for i in 0..32 / T::SIZE {
        let on = fcmp::<T>(p, at(&x.a, i), at(&x.b, i));
        r[i * T::SIZE..(i + 1) * T::SIZE].fill(ones(on));
    }
    r
}

/// Rounds per `vroundps`' immediate (bit 2 set: the MXCSR mode, which is always to nearest).
fn round64(v: f64, imm: u8) -> f64 {
    match if imm & 4 != 0 { 0 } else { imm & 3 } {
        0 => v.round_ties_even(),
        1 => v.floor(),
        2 => v.ceil(),
        _ => v.trunc(),
    }
}

fn round32(v: f32, imm: u8) -> f32 {
    match if imm & 4 != 0 { 0 } else { imm & 3 } {
        0 => v.round_ties_even(),
        1 => v.floor(),
        2 => v.ceil(),
        _ => v.trunc(),
    }
}

/// `cvtps2dq`-style conversion: nearest, and the integer-indefinite value when out of range.
fn to_i32(v: f64) -> i32 {
    let r = v.round_ties_even();
    if r.is_nan() || !(-2147483648.0..2147483648.0).contains(&r) {
        i32::MIN
    } else {
        r as i32
    }
}

fn sat_i8(v: i16) -> i8 {
    v.clamp(-128, 127) as i8
}
fn sat_u8(v: i16) -> u8 {
    v.clamp(0, 255) as u8
}
fn sat_i16(v: i32) -> i16 {
    v.clamp(-32768, 32767) as i16
}
fn sat_u16(v: i32) -> u16 {
    v.clamp(0, 65535) as u16
}

/// The 32- or 64-bit integer form of a scalar conversion, by the destination's size.
fn float_to_int(x: &In, v: f64, truncate: bool) -> V {
    let mut r = [0; 32];
    let v = if truncate {
        v.trunc()
    } else {
        v.round_ties_even()
    };
    if x.width == 8 {
        let out = if v.is_nan() || !((i64::MIN as f64)..-(i64::MIN as f64)).contains(&v) {
            i64::MIN
        } else {
            v as i64
        };
        set(&mut r, 0, out);
    } else {
        set(&mut r, 0, to_i32(v));
    }
    r
}

/// One element of the FMA family: `s1 * a * b + s2 * c` with a single rounding, on the
/// destination's element size. A NaN operand comes through quieted, its sign kept.
fn fused(x: &In, s1: f64, s2: f64) -> V {
    let mut r = [0; 32];
    if x.width == 4 {
        let (a, b, c) = (at::<f32>(&x.a, 0), at::<f32>(&x.b, 0), at::<f32>(&x.c, 0));
        let v = match [a, b, c].into_iter().find(|v| v.is_nan()) {
            Some(n) => f32::from_bits(n.to_bits() | 0x40_0000),
            None => (s1 as f32 * a).mul_add(b, s2 as f32 * c),
        };
        set(&mut r, 0, v);
    } else {
        let (a, b, c) = (at::<f64>(&x.a, 0), at::<f64>(&x.b, 0), at::<f64>(&x.c, 0));
        let v = match [a, b, c].into_iter().find(|v| v.is_nan()) {
            Some(n) => f64::from_bits(n.to_bits() | 0x8_0000_0000_0000),
            None => (s1 * a).mul_add(b, s2 * c),
        };
        set(&mut r, 0, v);
    }
    r
}

/// `crc32` of `size` bytes of `b` (reflected polynomial 0x82f63b78) on the running value in `a`.
fn crc32c(x: &In, size: usize) -> V {
    let mut crc = at::<u32>(&x.a, 0);
    for &byte in &x.b[..size] {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    let mut r = [0; 32];
    set(&mut r, 0, crc);
    r
}

/// A one-byte flag result: whether every element of `f` has a clear sign bit.
fn sign_clear<T: El + Into<u64>>(f: impl Fn(usize) -> T) -> V {
    let mut r = [0; 32];
    let top = 8 * T::SIZE - 1;
    r[0] = u8::from((0..32 / T::SIZE).all(|i| f(i).into() >> top == 0));
    r
}

fn half_to_f32(h: u16) -> f32 {
    let sign = u32::from(h >> 15) << 31;
    let exp = u32::from(h >> 10) & 0x1f;
    let frac = u32::from(h & 0x3ff);
    let bits = match (exp, frac) {
        (0, 0) => sign,
        (0, _) => {
            let shift = frac.leading_zeros() - 21;
            sign | ((113 - shift) << 23) | (((frac << shift) & 0x3ff) << 13)
        }
        (31, _) => {
            sign | 0x7f80_0000 | (0x0040_0000 * u32::from(frac != 0 && frac < 0x200)) | (frac << 13)
        }
        _ => sign | ((exp + 112) << 23) | (frac << 13),
    };
    f32::from_bits(bits)
}

/// `vcvtps2ph` with the rounding of `imm` (bit 2 set: the MXCSR mode, which is to nearest).
fn f32_to_half(v: f32, imm: u8) -> u16 {
    let bits = v.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = (bits >> 23) & 0xff;
    let frac = bits & 0x7f_ffff;
    if exp == 255 {
        return sign
            | 0x7c00
            | if frac != 0 {
                0x200 | (frac >> 13) as u16
            } else {
                0
            };
    }
    let mode = if imm & 4 != 0 { 0 } else { imm & 3 };
    let negative = sign != 0;
    let e = exp as i32 - 127 + 15;
    let (mantissa, shift) = if exp == 0 {
        (0, 25)
    } else if e > 0 {
        (0x80_0000 | frac, 13)
    } else {
        (0x80_0000 | frac, (14 - e).min(25) as u32)
    };
    let kept = mantissa >> shift;
    let lost = mantissa & ((1 << shift) - 1);
    let half = 1u32 << (shift - 1);
    let up = match mode {
        0 => lost > half || (lost == half && kept & 1 != 0),
        1 => negative && lost != 0,
        2 => !negative && lost != 0,
        _ => false,
    };
    let rounded = kept + u32::from(up);
    if e <= 0 {
        return sign | rounded as u16;
    }
    let packed = ((e as u32) << 10) + (rounded - 0x400);
    if packed >= 0x7c00 {
        let keep = mode == 3 || (mode == 1 && !negative) || (mode == 2 && negative);
        return sign | if keep { 0x7bff } else { 0x7c00 };
    }
    sign | packed as u16
}

pub(crate) type Impl = fn(&In) -> V;

/// The operations `kvec` knows, by Ghidra's pseudo-op name without `_avx`/`_avx2`. The position
/// is the number the rewritten spec passes.
pub(crate) const OPS: &[(&str, Impl)] = &[
    // Bitwise.
    ("vpand", |x| zip::<u64>(x, |a, b| a & b)),
    ("vpandn", |x| zip::<u64>(x, |a, b| !a & b)),
    ("vpor", |x| zip::<u64>(x, |a, b| a | b)),
    // Integer arithmetic.
    ("vpaddq", |x| zip::<u64>(x, u64::wrapping_add)),
    ("vpsubb", |x| zip::<u8>(x, u8::wrapping_sub)),
    ("vpsubw", |x| zip::<u16>(x, u16::wrapping_sub)),
    ("vpsubd", |x| zip::<u32>(x, u32::wrapping_sub)),
    ("vpsubq", |x| zip::<u64>(x, u64::wrapping_sub)),
    ("vpaddsb", |x| zip::<i8>(x, i8::saturating_add)),
    ("vpaddsw", |x| zip::<i16>(x, i16::saturating_add)),
    ("vpaddusb", |x| zip::<u8>(x, u8::saturating_add)),
    ("vpaddusw", |x| zip::<u16>(x, u16::saturating_add)),
    ("vpsubsb", |x| zip::<i8>(x, i8::saturating_sub)),
    ("vpsubsw", |x| zip::<i16>(x, i16::saturating_sub)),
    ("vpsubusb", |x| zip::<u8>(x, u8::saturating_sub)),
    ("vpsubusw", |x| zip::<u16>(x, u16::saturating_sub)),
    ("vpavgb", |x| {
        zip::<u8>(x, |a, b| ((u16::from(a) + u16::from(b) + 1) >> 1) as u8)
    }),
    ("vpavgw", |x| {
        zip::<u16>(x, |a, b| ((u32::from(a) + u32::from(b) + 1) >> 1) as u16)
    }),
    ("vpmaxsb", |x| zip::<i8>(x, Ord::max)),
    ("vpmaxsw", |x| zip::<i16>(x, Ord::max)),
    ("vpmaxsd", |x| zip::<i32>(x, Ord::max)),
    ("vpmaxub", |x| zip::<u8>(x, Ord::max)),
    ("vpmaxuw", |x| zip::<u16>(x, Ord::max)),
    ("vpmaxud", |x| zip::<u32>(x, Ord::max)),
    ("vpminsb", |x| zip::<i8>(x, Ord::min)),
    ("vpminsw", |x| zip::<i16>(x, Ord::min)),
    ("vpminsd", |x| zip::<i32>(x, Ord::min)),
    ("vpminub", |x| zip::<u8>(x, Ord::min)),
    ("vpminuw", |x| zip::<u16>(x, Ord::min)),
    ("vpminud", |x| zip::<u32>(x, Ord::min)),
    ("vpabsb", |x| map::<i8, i8>(&x.a, i8::wrapping_abs)),
    ("vpabsw", |x| map::<i16, i16>(&x.a, i16::wrapping_abs)),
    ("vpabsd", |x| map::<i32, i32>(&x.a, i32::wrapping_abs)),
    ("vpsignb", |x| {
        zip::<i8>(x, |a, b| a.wrapping_mul(b.signum()))
    }),
    ("vpsignw", |x| {
        zip::<i16>(x, |a, b| a.wrapping_mul(b.signum()))
    }),
    ("vpsignd", |x| {
        zip::<i32>(x, |a, b| a.wrapping_mul(b.signum()))
    }),
    // Multiplication.
    ("vpmullw", |x| zip::<u16>(x, u16::wrapping_mul)),
    ("vpmulld", |x| zip::<u32>(x, u32::wrapping_mul)),
    ("vpmulhw", |x| {
        zip::<i16>(x, |a, b| ((i32::from(a) * i32::from(b)) >> 16) as i16)
    }),
    ("vpmulhuw", |x| {
        zip::<u16>(x, |a, b| ((u32::from(a) * u32::from(b)) >> 16) as u16)
    }),
    ("vpmulhrsw", |x| {
        zip::<i16>(x, |a, b| {
            ((((i32::from(a) * i32::from(b)) >> 14) + 1) >> 1) as i16
        })
    }),
    ("vpmuldq", |x| {
        zip::<u64>(x, |a, b| {
            (i64::from(a as u32 as i32) * i64::from(b as u32 as i32)) as u64
        })
    }),
    ("vpmuludq", |x| {
        zip::<u64>(x, |a, b| u64::from(a as u32) * u64::from(b as u32))
    }),
    ("vpmaddwd", |x| {
        let mut r = [0; 32];
        for i in 0..8 {
            // Two pairs of 0x8000 sum to 2^31, which the instruction wraps.
            let v = (i32::from(at::<i16>(&x.a, 2 * i)) * i32::from(at::<i16>(&x.b, 2 * i)))
                .wrapping_add(
                    i32::from(at::<i16>(&x.a, 2 * i + 1)) * i32::from(at::<i16>(&x.b, 2 * i + 1)),
                );
            set::<i32>(&mut r, i, v);
        }
        r
    }),
    ("vpmaddubsw", |x| {
        let mut r = [0; 32];
        for i in 0..16 {
            let f = |k: usize| i32::from(x.a[k]) * i32::from(x.b[k] as i8);
            set::<i16>(&mut r, i, sat_i16(f(2 * i) + f(2 * i + 1)));
        }
        r
    }),
    ("vpsadbw", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            let sum: u64 = (0..8)
                .map(|k| u64::from(x.a[8 * i + k].abs_diff(x.b[8 * i + k])))
                .sum();
            set::<u64>(&mut r, i, sum);
        }
        r
    }),
    // Comparisons.
    ("vpcmpeqb", |x| cmp::<u8>(x, |a, b| a == b)),
    ("vpcmpeqw", |x| cmp::<u16>(x, |a, b| a == b)),
    ("vpcmpeqd", |x| cmp::<u32>(x, |a, b| a == b)),
    ("vpcmpgtb", |x| cmp::<i8>(x, |a, b| a > b)),
    ("vpcmpgtw", |x| cmp::<i16>(x, |a, b| a > b)),
    ("vpcmpgtd", |x| cmp::<i32>(x, |a, b| a > b)),
    ("vpcmpgtq", |x| cmp::<i64>(x, |a, b| a > b)),
    // Shifts.
    ("vpsllw", |x| shift!(x, u16, 16, |v, n| v << n)),
    ("vpslld", |x| shift!(x, u32, 32, |v, n| v << n)),
    ("vpsllq", |x| shift!(x, u64, 64, |v, n| v << n)),
    ("vpsrlw", |x| shift!(x, u16, 16, |v, n| v >> n)),
    ("vpsrld", |x| shift!(x, u32, 32, |v, n| v >> n)),
    ("vpsrlq", |x| shift!(x, u64, 64, |v, n| v >> n)),
    ("vpsraw", |x| {
        let n = count(x).min(15);
        map::<i16, i16>(&x.a, |v| v >> n)
    }),
    ("vpsrad", |x| {
        let n = count(x).min(31);
        map::<i32, i32>(&x.a, |v| v >> n)
    }),
    ("vpsllvd", |x| var_shift::<u32>(x, 32, |v, n| v << n, 0)),
    ("vpsllvq", |x| var_shift::<u64>(x, 64, |v, n| v << n, 0)),
    ("vpsrlvd", |x| var_shift::<u32>(x, 32, |v, n| v >> n, 0)),
    ("vpsrlvq", |x| var_shift::<u64>(x, 64, |v, n| v >> n, 0)),
    ("vpsravd", |x| {
        zip::<u32>(x, |v, n| ((v as i32) >> n.min(31)) as u32)
    }),
    ("vpslldq", |x| {
        let n = usize::from(x.imm());
        lanes(x, |a, _, r| {
            if n < 16 {
                r[n..].copy_from_slice(&a[..16 - n]);
            }
        })
    }),
    ("vpsrldq", |x| {
        let n = usize::from(x.imm());
        lanes(x, |a, _, r| {
            if n < 16 {
                r[..16 - n].copy_from_slice(&a[n..]);
            }
        })
    }),
    // Shuffles.
    ("vpunpcklbw", |x| unpack::<u8>(x, false)),
    ("vpunpcklwd", |x| unpack::<u16>(x, false)),
    ("vpunpckldq", |x| unpack::<u32>(x, false)),
    ("vpunpcklqdq", |x| unpack::<u64>(x, false)),
    ("vpunpckhbw", |x| unpack::<u8>(x, true)),
    ("vpunpckhwd", |x| unpack::<u16>(x, true)),
    ("vpunpckhdq", |x| unpack::<u32>(x, true)),
    ("vpunpckhqdq", |x| unpack::<u64>(x, true)),
    ("vunpcklps", |x| unpack::<u32>(x, false)),
    ("vunpcklpd", |x| unpack::<u64>(x, false)),
    ("vunpckhps", |x| unpack::<u32>(x, true)),
    ("vunpckhpd", |x| unpack::<u64>(x, true)),
    ("vpacksswb", |x| pack::<i16, i8>(x, sat_i8)),
    ("vpackuswb", |x| pack::<i16, u8>(x, sat_u8)),
    ("vpackssdw", |x| pack::<i32, i16>(x, sat_i16)),
    ("vpackusdw", |x| pack::<i32, u16>(x, sat_u16)),
    ("vpalignr", |x| {
        let n = usize::from(x.c[0]);
        lanes(x, |a, b, r| {
            for (i, o) in r.iter_mut().enumerate() {
                *o = match i + n {
                    k @ 0..16 => b[k],
                    k @ 16..32 => a[k - 16],
                    _ => 0,
                };
            }
        })
    }),
    ("vpshufb", |x| {
        lanes(x, |a, b, r| {
            for i in 0..16 {
                r[i] = if b[i] & 0x80 != 0 {
                    0
                } else {
                    a[usize::from(b[i] & 15)]
                };
            }
        })
    }),
    ("vpshufd", |x| {
        let imm = usize::from(x.imm());
        lanes(x, |a, _, r| {
            for i in 0..4 {
                let k = (imm >> (2 * i)) & 3;
                r[4 * i..4 * i + 4].copy_from_slice(&a[4 * k..4 * k + 4]);
            }
        })
    }),
    ("vpshuflw", |x| {
        let imm = usize::from(x.imm());
        lanes(x, |a, _, r| {
            r.copy_from_slice(a);
            for i in 0..4 {
                let k = (imm >> (2 * i)) & 3;
                r[2 * i..2 * i + 2].copy_from_slice(&a[2 * k..2 * k + 2]);
            }
        })
    }),
    ("vpshufhw", |x| {
        let imm = usize::from(x.imm());
        lanes(x, |a, _, r| {
            r.copy_from_slice(a);
            for i in 0..4 {
                let k = (imm >> (2 * i)) & 3;
                r[8 + 2 * i..10 + 2 * i].copy_from_slice(&a[8 + 2 * k..10 + 2 * k]);
            }
        })
    }),
    ("vshufps", |x| {
        let imm = usize::from(x.c[0]);
        lanes(x, |a, b, r| {
            for i in 0..4 {
                let k = (imm >> (2 * i)) & 3;
                let s = if i < 2 { a } else { b };
                r[4 * i..4 * i + 4].copy_from_slice(&s[4 * k..4 * k + 4]);
            }
        })
    }),
    ("vshufpd", |x| {
        let imm = usize::from(x.c[0]);
        let mut r = [0; 32];
        for i in 0..4 {
            let s = if i % 2 == 0 { &x.a } else { &x.b };
            let k = (i & !1) + ((imm >> i) & 1);
            set(&mut r, i, at::<u64>(s, k));
        }
        r
    }),
    ("vpermilps", |x| {
        let mut r = [0; 32];
        for i in 0..8 {
            let lane = i & !3;
            let k = if x.n >= 2 && !is_imm(x) {
                (at::<u32>(&x.b, i) & 3) as usize
            } else {
                (usize::from(x.b[0]) >> (2 * (i & 3))) & 3
            };
            set(&mut r, i, at::<u32>(&x.a, lane + k));
        }
        r
    }),
    ("vpermilpd", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            let lane = i & !1;
            let k = if is_imm(x) {
                (usize::from(x.b[0]) >> i) & 1
            } else {
                ((at::<u64>(&x.b, i) >> 1) & 1) as usize
            };
            set(&mut r, i, at::<u64>(&x.a, lane + k));
        }
        r
    }),
    ("vpermd", permd),
    ("vpermps", permd),
    ("vpermq", permq),
    ("vpermpd", permq),
    ("vperm2i128", perm2),
    ("vperm2f128", perm2),
    ("vpblendw", |x| {
        let imm = x.c[0];
        blend::<u16>(x, |i| imm >> (i & 7) & 1 != 0)
    }),
    ("vpblendd", |x| {
        let imm = x.c[0];
        blend::<u32>(x, |i| imm >> i & 1 != 0)
    }),
    ("vblendps", |x| {
        let imm = x.c[0];
        blend::<u32>(x, |i| imm >> i & 1 != 0)
    }),
    ("vblendpd", |x| {
        let imm = x.c[0];
        blend::<u64>(x, |i| imm >> i & 1 != 0)
    }),
    ("vpblendvb", |x| blend::<u8>(x, |i| x.c[i] & 0x80 != 0)),
    ("vblendvps", |x| {
        blend::<u32>(x, |i| at::<u32>(&x.c, i) >> 31 != 0)
    }),
    ("vblendvpd", |x| {
        blend::<u64>(x, |i| at::<u64>(&x.c, i) >> 63 != 0)
    }),
    ("vphaddw", |x| horizontal::<u16>(x, u16::wrapping_add)),
    ("vphaddd", |x| horizontal::<u32>(x, u32::wrapping_add)),
    ("vphaddsw", |x| horizontal::<i16>(x, i16::saturating_add)),
    ("vphsubw", |x| {
        horizontal::<u16>(&drop_first(x), u16::wrapping_sub)
    }),
    ("vphsubd", |x| {
        horizontal::<u32>(&drop_first(x), u32::wrapping_sub)
    }),
    ("vphsubsw", |x| {
        horizontal::<i16>(&drop_first(x), i16::saturating_sub)
    }),
    // Widening moves.
    ("vpmovzxbw", |x| widen::<u8, u16>(x, u16::from)),
    ("vpmovzxbd", |x| widen::<u8, u32>(x, u32::from)),
    ("vpmovzxbq", |x| widen::<u8, u64>(x, u64::from)),
    ("vpmovzxwd", |x| widen::<u16, u32>(x, u32::from)),
    ("vpmovzxwq", |x| widen::<u16, u64>(x, u64::from)),
    ("vpmovzxdq", |x| widen::<u32, u64>(x, u64::from)),
    ("vpmovsxbw", |x| widen::<i8, i16>(x, i16::from)),
    ("vpmovsxbd", |x| widen::<i8, i32>(x, i32::from)),
    ("vpmovsxbq", |x| widen::<i8, i64>(x, i64::from)),
    ("vpmovsxwd", |x| widen::<i16, i32>(x, i32::from)),
    ("vpmovsxwq", |x| widen::<i16, i64>(x, i64::from)),
    ("vpmovsxdq", |x| widen::<i32, i64>(x, i64::from)),
    // Moves Ghidra spells as pseudo-ops.
    ("vlddqu", |x| x.a),
    ("vmovntdq", |x| x.a),
    ("vmovntdqa", |x| x.a),
    ("vmovntpd", |x| x.a),
    ("vmovntps", |x| x.a),
    ("vmovshdup", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            let v = at::<u32>(&x.a, 2 * i + 1);
            set(&mut r, 2 * i, v);
            set(&mut r, 2 * i + 1, v);
        }
        r
    }),
    ("vmovsldup", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            let v = at::<u32>(&x.a, 2 * i);
            set(&mut r, 2 * i, v);
            set(&mut r, 2 * i + 1, v);
        }
        r
    }),
    ("vmovhlps", |x| {
        let mut r = x.a;
        set(&mut r, 0, at::<u64>(&x.b, 1));
        r
    }),
    ("vmovlhps", |x| {
        let mut r = x.a;
        set(&mut r, 1, at::<u64>(&x.b, 0));
        r
    }),
    ("vmovhpd", movh),
    ("vmovhps", movh),
    ("vmovlpd", movl),
    ("vmovlps", movl),
    ("vpinsrb", |x| {
        let mut r = x.a;
        r[usize::from(x.c[0] & 15)] = x.b[0];
        r
    }),
    ("vpinsrw", |x| {
        let mut r = x.a;
        set(&mut r, usize::from(x.c[0] & 7), at::<u16>(&x.b, 0));
        r
    }),
    ("vinsertps", |x| {
        let imm = usize::from(x.c[0]);
        let mut r = x.a;
        set(&mut r, (imm >> 4) & 3, at::<u32>(&x.b, (imm >> 6) & 3));
        for i in 0..4 {
            if imm >> i & 1 != 0 {
                set(&mut r, i, 0u32);
            }
        }
        r
    }),
    ("vextractps", |x| {
        let mut r = [0; 32];
        set(&mut r, 0, at::<u32>(&x.a, usize::from(x.b[0] & 3)));
        r
    }),
    ("vpmovmskb", |x| {
        let mut r = [0; 32];
        let m = (0..32).fold(0u32, |m, i| m | u32::from(x.a[i] >> 7) << i);
        set(&mut r, 0, m);
        r
    }),
    ("vmovmskps", |x| {
        let mut r = [0; 32];
        r[0] = (0..8).fold(0, |m, i| m | ((at::<u32>(&x.a, i) >> 31) as u8) << i);
        r
    }),
    ("vmovmskpd", |x| {
        let mut r = [0; 32];
        r[0] = (0..4).fold(0, |m, i| m | ((at::<u64>(&x.a, i) >> 63) as u8) << i);
        r
    }),
    ("vpcmpistri", |x| pcmpstr(x, false).index),
    ("vpcmpestri", |x| pcmpstr(x, true).index),
    ("vpcmpistrm", |x| pcmpstr(x, false).mask),
    ("vpcmpestrm", |x| pcmpstr(x, true).mask),
    ("kflags_istr", |x| pcmpstr(x, false).flags),
    ("kflags_estr", |x| pcmpstr(x, true).flags),
    ("vmpsadbw", |x| {
        let imm = usize::from(x.c[0]);
        let mut r = [0; 32];
        for l in 0..2 {
            let sel = imm >> (3 * l);
            let (block, offs) = ((sel & 3) * 4, ((sel >> 2) & 1) * 4);
            let (a, b) = (&x.a[16 * l..], &x.b[16 * l..]);
            for i in 0..8 {
                let sum: u16 = (0..4)
                    .map(|k| u16::from(a[offs + i + k].abs_diff(b[block + k])))
                    .sum();
                set(&mut r, 8 * l + i, sum);
            }
        }
        r
    }),
    ("vphminposuw", |x| {
        let (mut best, mut at_) = (u16::MAX, 0);
        for i in (0..8).rev() {
            let v = at::<u16>(&x.a, i);
            if v <= best {
                (best, at_) = (v, i);
            }
        }
        let mut r = [0; 32];
        set(&mut r, 0, best);
        set(&mut r, 1, at_ as u16);
        r
    }),
    // Floating point.
    ("vdpps", |x| {
        let imm = x.c[0];
        let mut r = [0; 32];
        for l in 0..2 {
            let term = |i: usize| {
                if imm >> (4 + i) & 1 != 0 {
                    at::<f32>(&x.a, 4 * l + i) * at::<f32>(&x.b, 4 * l + i)
                } else {
                    0.0
                }
            };
            let sum = (term(0) + term(1)) + (term(2) + term(3));
            for i in 0..4 {
                set(&mut r, 4 * l + i, if imm >> i & 1 != 0 { sum } else { 0.0 });
            }
        }
        r
    }),
    ("vdppd", |x| {
        let imm = x.c[0];
        let term = |i: usize| {
            if imm >> (4 + i) & 1 != 0 {
                at::<f64>(&x.a, i) * at::<f64>(&x.b, i)
            } else {
                0.0
            }
        };
        let sum = term(0) + term(1);
        let mut r = [0; 32];
        for i in 0..2 {
            set(&mut r, i, if imm >> i & 1 != 0 { sum } else { 0.0 });
        }
        r
    }),
    ("ktestzps", |x| {
        sign_clear::<u32>(|i| at::<u32>(&x.a, i) & at::<u32>(&x.b, i))
    }),
    ("ktestcps", |x| {
        sign_clear::<u32>(|i| at::<u32>(&x.a, i) & !at::<u32>(&x.b, i))
    }),
    ("ktestzpd", |x| {
        sign_clear::<u64>(|i| at::<u64>(&x.a, i) & at::<u64>(&x.b, i))
    }),
    ("ktestcpd", |x| {
        sign_clear::<u64>(|i| at::<u64>(&x.a, i) & !at::<u64>(&x.b, i))
    }),
    ("kpinsrd", |x| {
        let mut r = x.a;
        set(&mut r, usize::from(x.c[0] & 3), at::<u32>(&x.b, 0));
        r
    }),
    ("ksqrtss", |x| scalar(x, at::<f32>(&x.b, 0).sqrt())),
    ("ksqrtsd", |x| scalar(x, at::<f64>(&x.b, 0).sqrt())),
    ("vcvttps2dq", |x| {
        map::<f32, i32>(&x.a, |v| to_i32(f64::from(v).trunc()))
    }),
    ("vcvttpd2dq", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            set(&mut r, i, to_i32(at::<f64>(&x.a, i).trunc()));
        }
        r
    }),
    ("kcvtsd2si", |x| float_to_int(x, at(&x.a, 0), false)),
    ("kcvtss2si", |x| {
        float_to_int(x, f64::from(at::<f32>(&x.a, 0)), false)
    }),
    ("kcvttsd2si", |x| float_to_int(x, at(&x.a, 0), true)),
    ("kcvttss2si", |x| {
        float_to_int(x, f64::from(at::<f32>(&x.a, 0)), true)
    }),
    ("kfmadd", |x| fused(x, 1.0, 1.0)),
    ("kfmsub", |x| fused(x, 1.0, -1.0)),
    ("kfnmadd", |x| fused(x, -1.0, 1.0)),
    ("kfnmsub", |x| fused(x, -1.0, -1.0)),
    ("kcrc8", |x| crc32c(x, 1)),
    ("kcrc16", |x| crc32c(x, 2)),
    ("kcrc32", |x| crc32c(x, 4)),
    ("kcrc64", |x| crc32c(x, 8)),
    ("vcvtph2ps", |x| widen::<u16, f32>(x, half_to_f32)),
    ("vcvtps2ph", |x| {
        let mode = x.b[0];
        let mut r = [0; 32];
        for i in 0..8 {
            set(&mut r, i, f32_to_half(at(&x.a, i), mode));
        }
        r
    }),
    ("vrcpps", |x| map::<f32, f32>(&x.a, |v| 1.0 / v)),
    ("vrsqrtps", |x| map::<f32, f32>(&x.a, |v| 1.0 / v.sqrt())),
    ("vrcpss", |x| scalar(x, 1.0 / at::<f32>(&x.b, 0))),
    ("vrsqrtss", |x| scalar(x, 1.0 / at::<f32>(&x.b, 0).sqrt())),
    ("vsubps", |x| zip::<f32>(x, |a, b| a - b)),
    ("vsubpd", |x| zip::<f64>(x, |a, b| a - b)),
    ("vdivps", |x| zip::<f32>(x, |a, b| a / b)),
    ("vdivpd", |x| zip::<f64>(x, |a, b| a / b)),
    ("vminps", |x| zip::<f32>(x, fmin)),
    ("vminpd", |x| zip::<f64>(x, fmin)),
    ("vmaxps", |x| zip::<f32>(x, fmax)),
    ("vmaxpd", |x| zip::<f64>(x, fmax)),
    ("vminss", |x| {
        scalar(x, fmin(at::<f32>(&x.a, 0), at(&x.b, 0)))
    }),
    ("vminsd", |x| {
        scalar(x, fmin(at::<f64>(&x.a, 0), at(&x.b, 0)))
    }),
    ("vmaxss", |x| {
        scalar(x, fmax(at::<f32>(&x.a, 0), at(&x.b, 0)))
    }),
    ("vmaxsd", |x| {
        scalar(x, fmax(at::<f64>(&x.a, 0), at(&x.b, 0)))
    }),
    ("vsqrtps", |x| map::<f32, f32>(&x.a, f32::sqrt)),
    ("vsqrtpd", |x| map::<f64, f64>(&x.a, f64::sqrt)),
    ("vhaddps", |x| horizontal::<f32>(x, |a, b| a + b)),
    ("vhsubps", |x| horizontal::<f32>(x, |a, b| a - b)),
    ("vhsubpd", |x| horizontal::<f64>(x, |a, b| a - b)),
    ("vaddsubps", |x| {
        let mut r = [0; 32];
        for i in 0..8 {
            let (a, b) = (at::<f32>(&x.a, i), at::<f32>(&x.b, i));
            set(&mut r, i, if i % 2 == 0 { a - b } else { a + b });
        }
        r
    }),
    ("vaddsubpd", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            let (a, b) = (at::<f64>(&x.a, i), at::<f64>(&x.b, i));
            set(&mut r, i, if i % 2 == 0 { a - b } else { a + b });
        }
        r
    }),
    ("vcmpps", fcmp_all::<f32>),
    ("vcmppd", fcmp_all::<f64>),
    ("vcmpss", |x| {
        let on = fcmp::<f32>(x.c[0], at(&x.a, 0), at(&x.b, 0));
        scalar(x, if on { u32::MAX } else { 0 })
    }),
    ("vcmpsd", |x| {
        let on = fcmp::<f64>(x.c[0], at(&x.a, 0), at(&x.b, 0));
        scalar(x, if on { u64::MAX } else { 0 })
    }),
    ("vroundps", |x| {
        let imm = x.b[0];
        map::<f32, f32>(&x.a, |v| round32(v, imm))
    }),
    ("vroundpd", |x| {
        let imm = x.b[0];
        map::<f64, f64>(&x.a, |v| round64(v, imm))
    }),
    ("vroundss", |x| scalar(x, round32(at(&x.b, 0), x.c[0]))),
    ("vroundsd", |x| scalar(x, round64(at(&x.b, 0), x.c[0]))),
    ("vcvtdq2ps", |x| map::<i32, f32>(&x.a, |v| v as f32)),
    ("vcvtdq2pd", |x| widen::<i32, f64>(x, f64::from)),
    ("vcvtps2pd", |x| widen::<f32, f64>(x, f64::from)),
    ("vcvtps2dq", |x| {
        map::<f32, i32>(&x.a, |v| to_i32(f64::from(v)))
    }),
    ("vcvtpd2ps", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            set(&mut r, i, at::<f64>(&x.a, i) as f32);
        }
        r
    }),
    ("vcvtpd2dq", |x| {
        let mut r = [0; 32];
        for i in 0..4 {
            set(&mut r, i, to_i32(at(&x.a, i)));
        }
        r
    }),
];

/// Whether the second operand of a `vpermil` form is an immediate, marked by [`rewrite_stmt`].
fn is_imm(x: &In) -> bool {
    x.c[1] == 1
}

fn permd(x: &In) -> V {
    let mut r = [0; 32];
    for i in 0..8 {
        let k = (at::<u32>(&x.a, i) & 7) as usize;
        set(&mut r, i, at::<u32>(&x.b, k));
    }
    r
}

fn permq(x: &In) -> V {
    let imm = usize::from(x.b[0]);
    let mut r = [0; 32];
    for i in 0..4 {
        set(&mut r, i, at::<u64>(&x.a, (imm >> (2 * i)) & 3));
    }
    r
}

fn perm2(x: &In) -> V {
    let imm = x.c[0];
    let mut r = [0; 32];
    for (i, sel) in [(0, imm & 15), (16, imm >> 4)] {
        if sel & 8 == 0 {
            let s = if sel & 2 == 0 { &x.a } else { &x.b };
            let from = usize::from(sel & 1) * 16;
            r[i..i + 16].copy_from_slice(&s[from..from + 16]);
        }
    }
    r
}

/// The load form takes `a` and a value for the high half; the store form returns `a`'s high half.
fn movh(x: &In) -> V {
    let mut r = x.a;
    if x.n >= 2 {
        set(&mut r, 1, at::<u64>(&x.b, 0));
    } else {
        set(&mut r, 0, at::<u64>(&x.a, 1));
    }
    r
}

fn movl(x: &In) -> V {
    let mut r = x.a;
    if x.n >= 2 {
        set(&mut r, 0, at::<u64>(&x.b, 0));
    }
    r
}

/// What the `pcmp?str?` family computes.
struct StrMatch {
    index: V,
    mask: V,
    flags: V,
}

/// `pcmpistri` and friends. The explicit-length forms carry RAX and RDX in the unused high
/// halves of `a` and `b` (see [`rewrite_line`]). `flags` holds CF, ZF, SF, OF, AF, PF, one byte
/// each.
fn pcmpstr(x: &In, explicit: bool) -> StrMatch {
    let imm = x.c[0];
    let (words, signed) = (imm & 1 != 0, imm & 2 != 0);
    let n = if words { 8 } else { 16 };
    let get = |v: &V, i: usize| -> i32 {
        match (words, signed) {
            (false, false) => i32::from(at::<u8>(v, i)),
            (false, true) => i32::from(at::<i8>(v, i)),
            (true, false) => i32::from(at::<u16>(v, i)),
            (true, true) => i32::from(at::<i16>(v, i)),
        }
    };
    let length = |v: &V, high: &V| -> usize {
        if explicit {
            let l = i64::from_le_bytes(high[16..24].try_into().unwrap_or([0; 8]));
            let l = l.unsigned_abs().min(n as u64);
            l as usize
        } else {
            (0..n).find(|&i| get(v, i) == 0).unwrap_or(n)
        }
    };
    let (la, lb) = (length(&x.a, &x.a), length(&x.b, &x.b));
    let mode = (imm >> 2) & 3;
    // Element `i` of the result compares `b[i]` with the elements of `a`.
    let eq = |ai: usize, bi: usize| get(&x.a, ai) == get(&x.b, bi);
    let mut res: u32 = 0;
    for i in 0..n {
        let bit = match mode {
            0 => (i < lb) && (0..la).any(|k| eq(k, i)),
            1 => {
                (i < lb)
                    && (0..la / 2).any(|k| {
                        get(&x.a, 2 * k) <= get(&x.b, i) && get(&x.b, i) <= get(&x.a, 2 * k + 1)
                    })
            }
            2 => match (i < la, i < lb) {
                (true, true) => eq(i, i),
                (false, false) => true,
                _ => false,
            },
            _ => (0..n - i).all(|k| {
                if k >= la {
                    true
                } else if i + k >= lb {
                    false
                } else {
                    eq(k, i + k)
                }
            }),
        };
        res |= u32::from(bit) << i;
    }
    let negate = imm >> 4 & 3;
    let all = (1u32 << n) - 1;
    let valid = (1u32 << lb) - 1;
    let out = match negate {
        1 => res ^ all,
        3 => res ^ valid,
        _ => res,
    };
    let first = if imm & 0x40 != 0 {
        (0..n).rev().find(|&i| out >> i & 1 != 0)
    } else {
        (0..n).find(|&i| out >> i & 1 != 0)
    };
    let mut index = [0; 32];
    set(&mut index, 0, first.unwrap_or(n) as u32);
    let mut mask = [0; 32];
    if imm & 0x40 != 0 {
        let size = if words { 2 } else { 1 };
        for i in 0..n {
            if out >> i & 1 != 0 {
                mask[i * size..(i + 1) * size].fill(0xff);
            }
        }
    } else {
        mask[..4].copy_from_slice(&out.to_le_bytes());
    }
    let mut flags = [0; 32];
    flags[0] = u8::from(out != 0);
    flags[1] = u8::from(lb < n);
    flags[2] = u8::from(la < n);
    flags[3] = (out & 1) as u8;
    StrMatch { index, mask, flags }
}

/// The helpers by SLEIGH user-op name.
pub(crate) const HELPERS: &[(&str, icicle_cpu::exec::helpers::PcodeOpHelper)] =
    &[("kvec", kvec), ("kgather", kgather), ("kmask", kmask)];

/// Bits 12-14 of `kvec`'s operation number hold the operand count.
const COUNT_SHIFT: u32 = 12;

/// `kvec(op, half, a0, a1, b0, b1, c0, c1)`.
pub(crate) fn kvec(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let id: u32 = cpu.read_dynamic(args[0]).zxt();
    let half: u32 = cpu.read_dynamic(args[1]).zxt();
    let wide = |lo: u128, hi: u128| {
        let mut v = [0; 32];
        v[..16].copy_from_slice(&lo.to_le_bytes());
        v[16..].copy_from_slice(&hi.to_le_bytes());
        v
    };
    let s = cpu.args;
    let x = In {
        a: wide(s[0], s[1]),
        b: wide(s[2], s[3]),
        c: wide(s[4], s[5]),
        n: (id >> COUNT_SHIFT) as u8,
        width: dst.size,
    };
    let Some((_, f)) = OPS.get((id & 0xfff) as usize) else {
        cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
        return;
    };
    let r = f(&x);
    let at = if half == 0 { 0 } else { 16 };
    let mut lane = [0; 16];
    lane.copy_from_slice(&r[at..at + 16]);
    let v = u128::from_le_bytes(lane);
    match dst.size {
        16 => cpu.write_var(dst, v),
        0 => {}
        1..=8 => cpu.write_trunc(dst, v as u64),
        _ => {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
        }
    }
}

/// In the first operand of [`kmask`], above the element size: the move is a store.
const MASK_STORE: u32 = 0x100;

/// `kmask(size, half, address, 0, mask0, mask1, data0, data1)`: one 128-bit half of `vmaskmov*`
/// and `vpmaskmov*`. Only the elements whose mask bit is set reach memory, so a clear element
/// neither faults nor rewrites its bytes, which is what code at the end of a page relies on. A
/// load returns the half with the other elements zero.
pub(crate) fn kmask(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let flags: u32 = cpu.read_dynamic(args[0]).zxt();
    let half: u32 = cpu.read_dynamic(args[1]).zxt();
    let half = half as usize & 1;
    let size = (flags & 0xff) as usize;
    let store = flags & MASK_STORE != 0;
    let s = cpu.args;
    let (mask, data) = (s[2 + half].to_le_bytes(), s[4 + half].to_le_bytes());
    let base = (s[0] as u64).wrapping_add(16 * half as u64);
    let mut out = [0u8; 16];
    for at in (0..16).step_by(size.max(1)) {
        if mask[at + size - 1] >> 7 == 0 {
            continue;
        }
        let addr = base.wrapping_add(at as u64);
        let done = if store {
            cpu.mem
                .write_bytes(addr, &data[at..at + size], perm::WRITE)
                .map_err(ExceptionCode::from_store_error)
        } else {
            cpu.mem
                .read_bytes(addr, &mut out[at..at + size], perm::READ)
                .map_err(ExceptionCode::from_load_error)
        };
        if let Err(code) = done {
            cpu.exception.code = code as u32;
            cpu.exception.value = addr;
            return;
        }
    }
    if !store {
        cpu.write_var(dst, u128::from_le_bytes(out));
    }
}

/// The element size of a masked move, for [`kmask`].
fn mask_element(op: &str) -> Option<u32> {
    match op {
        "vmaskmovps" | "vpmaskmovd" => Some(4),
        "vmaskmovpd" | "vpmaskmovq" => Some(8),
        _ => None,
    }
}

/// The registers of the emulated CPU by encoding number.
fn gpr(cpu: &Cpu, n: usize) -> Option<VarNode> {
    const LONG: [&str; 16] = [
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15",
    ];
    const SHORT: [&str; 8] = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"];
    let s = &cpu.arch.sleigh;
    s.get_varnode(LONG[n & 15])
        .or_else(|| s.get_varnode(SHORT[n & 7]))
}

/// `kgather(inst_start, inst_start)`: the `vgather*` and `vpgather*` family. Ghidra leaves their
/// memory access out and computes the address with 256-bit arithmetic icicle cannot lift, so the
/// helper decodes the instruction itself.
pub(crate) fn kgather(cpu: &mut Cpu, _dst: VarNode, args: [Value; 2]) {
    let pc: u64 = cpu.read_dynamic(args[0]).zxt();
    let mut b = [0u8; 16];
    // Byte by byte: the instruction may end just before unmapped memory.
    for (i, x) in b.iter_mut().enumerate() {
        let mut one = [0u8; 1];
        if cpu
            .mem
            .read_bytes(pc + i as u64, &mut one, perm::NONE)
            .is_err()
        {
            break;
        }
        *x = one[0];
    }
    // Skip segment and size prefixes; a gather is always in a three-byte VEX.
    let at_vex = b.iter().position(|x| *x == 0xc4).unwrap_or(0);
    let v = &b[at_vex..];
    if v.len() < 6 {
        cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
        return;
    }
    let (p1, p2, opcode, modrm, sib) = (v[1], v[2], v[3], v[4], v[5]);
    let long = gpr(cpu, 8).is_some();
    let ext = |bit: u8, inverted: u8| usize::from(long && inverted & bit == 0) * 8;
    let dest = usize::from(modrm >> 3 & 7) + ext(0x80, p1);
    let index = usize::from(sib >> 3 & 7) + ext(0x40, p1);
    let base_field = usize::from(sib & 7);
    let base = base_field + ext(0x20, p1);
    let mask = usize::from(!p2 >> 3 & 15);
    let (data, wide) = (if p2 & 0x80 != 0 { 8 } else { 4 }, p2 & 4 != 0);
    let ibytes = if opcode & 1 != 0 { 8 } else { 4 };
    let vl: usize = if wide { 32 } else { 16 };
    let count = vl / data.max(ibytes);
    let mode = modrm >> 6;
    let mut disp: i64 = 0;
    let disp_at = 6;
    if mode == 1 {
        disp = i64::from(v[disp_at] as i8);
    } else if mode == 2 || base_field == 5 {
        let mut d = [0u8; 4];
        d.copy_from_slice(&v[disp_at..disp_at + 4]);
        disp = i64::from(i32::from_le_bytes(d));
    }
    let addr_base = if base_field == 5 && mode == 0 {
        0
    } else {
        gpr(cpu, base).map_or(0, |r| cpu.read_reg(r))
    };
    // icicle keeps no register wider than 128 bits, so a `ymm` register is two varnodes.
    let ymm = |cpu: &Cpu, n: usize| {
        let s = &cpu.arch.sleigh;
        Some([
            s.get_varnode(&format!("XMM{n}"))?,
            s.get_varnode(&format!("YMM{n}_H"))?,
        ])
    };
    let (Some(dreg), Some(ireg), Some(mreg)) = (ymm(cpu, dest), ymm(cpu, index), ymm(cpu, mask))
    else {
        cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
        return;
    };
    let read = |cpu: &mut Cpu, r: [VarNode; 2], i: usize, size: usize| -> u64 {
        let at = i * size;
        let v = r[at / 16].slice((at % 16) as u8, size as u8);
        cpu.read_dynamic(v.into()).zxt()
    };
    let scale = sib >> 6;
    let mut out = [0u8; 32];
    for (i, cell) in out.chunks_mut(8).enumerate().take(4) {
        cell.copy_from_slice(&read(cpu, dreg, i, 8).to_le_bytes());
    }
    for i in 0..count {
        if read(cpu, mreg, i, data) >> (8 * data - 1) == 0 {
            continue;
        }
        let raw = read(cpu, ireg, i, ibytes);
        let idx = if ibytes == 4 {
            i64::from(raw as u32 as i32)
        } else {
            raw as i64
        };
        let addr = addr_base
            .wrapping_add(idx.wrapping_shl(u32::from(scale)) as u64)
            .wrapping_add(disp as u64);
        let mut word = [0u8; 8];
        if let Err(e) = cpu.mem.read_bytes(addr, &mut word[..data], perm::READ) {
            cpu.exception.code = ExceptionCode::from_load_error(e) as u32;
            cpu.exception.value = addr;
            return;
        }
        out[i * data..(i + 1) * data].copy_from_slice(&word[..data]);
    }
    // The elements past `count` read as zero, as does the top half of a 128-bit destination.
    out[(count * data)..].fill(0);
    for (half, cell) in out.chunks(16).enumerate() {
        let mut w = [0u8; 16];
        w.copy_from_slice(cell);
        cpu.write_var(dreg[half], u128::from_le_bytes(w));
        cpu.write_var(mreg[half], 0u128);
    }
}

/// Splits `a, b, c` at top-level commas.
fn split_args(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut from) = (0i32, 0);
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[from..i].trim());
                from = i + 1;
            }
            _ => {}
        }
    }
    let last = s[from..].trim();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

fn is_wide(operand: &str) -> bool {
    operand.contains("Ymm") || operand.contains("m256")
}

/// Ghidra's names of the legacy (non-VEX) forms that compute what an operation of [`OPS`] does;
/// `true` when the pseudo-op's first operand is only the destination's old value, which the
/// operation does not read.
const LEGACY: &[(&str, &str, bool)] = &[
    ("blendpd", "vblendpd", false),
    ("blendps", "vblendps", false),
    ("blendvpd", "vblendvpd", false),
    ("blendvps", "vblendvps", false),
    ("cmppd", "vcmppd", false),
    ("cmpps", "vcmpps", false),
    ("cmpsd", "vcmpsd", false),
    ("cmpss", "vcmpss", false),
    ("divpd", "vdivpd", false),
    ("divps", "vdivps", false),
    ("dppd", "vdppd", false),
    ("dpps", "vdpps", false),
    ("extractps", "vextractps", false),
    ("insertps", "vinsertps", false),
    ("lddqu", "vlddqu", true),
    ("maxpd", "vmaxpd", false),
    ("maxps", "vmaxps", false),
    ("minpd", "vminpd", false),
    ("minps", "vminps", false),
    ("movmskpd", "vmovmskpd", true),
    ("movmskps", "vmovmskps", true),
    ("movntdqa", "vmovntdqa", true),
    ("mpsadbw", "vmpsadbw", false),
    ("pabsb", "vpabsb", true),
    ("pabsd", "vpabsd", true),
    ("pabsw", "vpabsw", true),
    ("packssdw", "vpackssdw", false),
    ("packsswb", "vpacksswb", false),
    ("packusdw", "vpackusdw", false),
    ("paddsb", "vpaddsb", false),
    ("paddsw", "vpaddsw", false),
    ("paddusb", "vpaddusb", false),
    ("paddusw", "vpaddusw", false),
    ("pavgb", "vpavgb", false),
    ("pavgw", "vpavgw", false),
    ("pblendvb", "vpblendvb", false),
    ("pblendw", "vpblendw", false),
    ("pcmpestri", "vpcmpestri", false),
    ("pcmpestrm", "vpcmpestrm", false),
    ("pcmpistri", "vpcmpistri", false),
    ("pcmpistrm", "vpcmpistrm", false),
    ("phaddd", "vphaddd", false),
    ("phaddsw", "vphaddsw", false),
    ("phaddw", "vphaddw", false),
    ("phminposuw", "vphminposuw", false),
    ("phsubd", "vphsubd", false),
    ("phsubsw", "vphsubsw", false),
    ("phsubw", "vphsubw", false),
    ("pmaddubsw", "vpmaddubsw", false),
    ("pmaddwd", "vpmaddwd", false),
    ("pmovsxbd", "vpmovsxbd", true),
    ("pmovsxbq", "vpmovsxbq", true),
    ("pmovsxbw", "vpmovsxbw", true),
    ("pmovsxdq", "vpmovsxdq", true),
    ("pmovsxwd", "vpmovsxwd", true),
    ("pmovsxwq", "vpmovsxwq", true),
    ("pmovzxbd", "vpmovzxbd", true),
    ("pmovzxbq", "vpmovzxbq", true),
    ("pmovzxbw", "vpmovzxbw", true),
    ("pmovzxdq", "vpmovzxdq", true),
    ("pmovzxwd", "vpmovzxwd", true),
    ("pmovzxwq", "vpmovzxwq", true),
    ("pmuldq", "vpmuldq", false),
    ("pmulhrsw", "vpmulhrsw", false),
    ("pmulhuw", "vpmulhuw", false),
    ("pmulhw", "vpmulhw", false),
    ("pmulld", "vpmulld", false),
    ("psadbw", "vpsadbw", false),
    ("pshufb", "vpshufb", false),
    ("pshufhw", "vpshufhw", true),
    ("pshuflw", "vpshuflw", true),
    ("psignb", "vpsignb", false),
    ("psignd", "vpsignd", false),
    ("psignw", "vpsignw", false),
    ("psllw", "vpsllw", false),
    ("psraw", "vpsraw", false),
    ("psubsb", "vpsubsb", false),
    ("psubsw", "vpsubsw", false),
    ("psubusb", "vpsubusb", false),
    ("psubusw", "vpsubusw", false),
    ("rcpps", "vrcpps", true),
    ("rcpss", "vrcpss", false),
    ("roundpd", "vroundpd", true),
    ("roundps", "vroundps", true),
    ("roundsd", "vroundsd", false),
    ("roundss", "vroundss", false),
    ("rsqrtps", "vrsqrtps", true),
    ("rsqrtss", "vrsqrtss", false),
    ("sqrtpd", "vsqrtpd", true),
    ("sqrtps", "vsqrtps", true),
];

/// The number in [`OPS`] of operation `name`.
fn op_id(name: &str) -> Option<usize> {
    OPS.iter().position(|(o, _)| *o == name)
}

/// One statement `lhs = v..._avx( args )` (or a legacy `lhs = name( args )` on `xmm` registers)
/// as `kvec` calls; `None` for any other statement or an operation outside [`OPS`]. `n` keeps the
/// temporaries of different statements apart.
fn rewrite_stmt(stmt: &str, n: usize) -> Option<String> {
    let (lhs, rhs) = stmt.split_once('=')?;
    let (lhs, rhs) = (lhs.trim(), rhs.trim());
    if lhs.is_empty() || lhs.contains(['<', '>', '!', '(']) {
        return None;
    }
    let open = rhs.find('(')?;
    let inner = rhs.strip_suffix(')')?;
    let name = rhs[..open].trim();
    let mut args = split_args(&inner[open + 1..]);
    let vex = name
        .strip_suffix("_avx2")
        .or_else(|| name.strip_suffix("_avx"))
        .or_else(|| name.strip_suffix("_f16c"));
    let op = match vex {
        Some(base) => base.to_string(),
        None if name == "crc32" => {
            let bits = args.get(1)?.strip_prefix("rm")?;
            format!("kcrc{bits}")
        }
        None => {
            let (_, op, drop) = LEGACY.iter().find(|(l, _, _)| *l == name)?;
            let xmm = |s: &str| s.contains("Xmm") || s.contains("xmm") || s.contains("XMM");
            if !xmm(lhs) && !args.iter().any(|a| xmm(a)) {
                return None;
            }
            if *drop && args.len() > 1 {
                args.remove(0);
            }
            (*op).to_string()
        }
    };
    let mask_size = mask_element(&op);
    let store = mask_size.is_some() && matches!(lhs, "m128" | "m256");
    let id = match mask_size {
        Some(size) => (size | if store { MASK_STORE } else { 0 }) as usize,
        None => op_id(&op)?,
    };
    let explicit = matches!(op.as_str(), "vpcmpestri" | "vpcmpestrm");
    let lengths: Vec<&str> = if explicit {
        vec![args.get(3)?, args.get(4)?]
    } else {
        Vec::new()
    };
    let mut pre = String::new();
    if explicit {
        args.truncate(3);
    }
    let address = format!("ka{n}");
    if mask_size.is_some() {
        // The constructor passes the address (see `rewrite_sinc`); memory is `kmask`'s to read.
        pre.push_str(&format!("local {address} = Mem; "));
        if !store {
            args.truncate(1);
        }
        args.insert(0, &address);
    }
    let imm = format!("kim{n}");
    if op == "vinsertps" && args.get(1) == Some(&"m32") {
        // A memory source has only the one element: the source index does not apply.
        pre.push_str(&format!("local {imm}:1 = imm8:1 & 0x3f; "));
        args[2] = &imm;
    }
    if args.is_empty() || args.len() > 3 {
        return None;
    }
    let imm_form = args.len() == 2 && args[1].starts_with("imm8");
    let mut slots = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if is_wide(a) {
            pre.push_str(&format!("local kv{n}_{i}:32 = {a}; "));
            slots.push(format!("kv{n}_{i}[0,128]"));
            slots.push(format!("kv{n}_{i}[128,128]"));
        } else {
            slots.push((*a).to_string());
            slots.push("0:1".to_string());
        }
    }
    while slots.len() < 6 {
        slots.push("0:1".to_string());
    }
    if explicit {
        for (i, length) in lengths.iter().enumerate() {
            // The length is signed, and the form without REX.W takes 32 bits of it.
            slots[2 * i + 1] = if length.starts_with('E') {
                pre.push_str(&format!("local kl{n}_{i}:8 = sext({length}); "));
                format!("kl{n}_{i}")
            } else {
                (*length).to_string()
            };
        }
    }
    if imm_form {
        // `c[1]` tells `vpermil*` that the second operand is an immediate.
        slots[4] = "256:2".to_string();
    }
    let number = id | (args.len() << COUNT_SHIFT);
    let helper = if mask_size.is_some() { "kmask" } else { "kvec" };
    let call = |half: u8| format!("{helper}({number}:2, {half}:1, {})", slots.join(", "));
    if store {
        let upper = if lhs == "m256" {
            format!("; {}", call(1))
        } else {
            String::new()
        };
        return Some(format!("{pre}{}{upper}", call(0)));
    }
    let string_compare = matches!(
        op.as_str(),
        "vpcmpistri" | "vpcmpestri" | "vpcmpistrm" | "vpcmpestrm"
    );
    if string_compare {
        // Before the result: the mask forms write XMM0, which may be an operand.
        let flag_op = if explicit {
            "kflags_estr"
        } else {
            "kflags_istr"
        };
        let number = op_id(flag_op)? | (args.len() << COUNT_SHIFT);
        pre.push_str(&format!(
            "local kf{n}:8 = kvec({number}:2, 0:1, {}); ",
            slots.join(", ")
        ));
    }
    let mut text = if is_wide(lhs) || lhs.ends_with(":32") {
        format!(
            "{pre}local kr{n}:32 = 0; kr{n}[0,128] = {}; kr{n}[128,128] = {}; {lhs} = kr{n}",
            call(0),
            call(1),
        )
    } else {
        format!("{pre}{lhs} = {}", call(0))
    };
    if vex.is_some() && lhs == "XMM0" {
        text.push_str("; YMM0_H = zext(0:1)");
    }
    if string_compare {
        text.push_str(&format!(
            "; CF = kf{n}[0,8]; ZF = kf{n}[8,8]; SF = kf{n}[16,8]; OF = kf{n}[24,8]; AF = 0; \
             PF = 0"
        ));
    }
    Some(text)
}

/// Rewrites every statement of one line.
fn rewrite_line(line: &str, n: usize) -> Option<String> {
    let mut out = String::new();
    let mut rest = line;
    let mut changed = false;
    let mut index = 0;
    while let Some(end) = rest.find(';') {
        let segment = &rest[..end];
        let from = segment.rfind(['{', '}']).map_or(0, |i| i + 1);
        match rewrite_stmt(segment[from..].trim(), n * 8 + index) {
            Some(new) => {
                out.push_str(&segment[..from]);
                out.push(' ');
                out.push_str(&new);
                changed = true;
            }
            None => out.push_str(segment),
        }
        out.push(';');
        rest = &rest[end + 1..];
        index += 1;
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Declares `kvec`; the file with `CPUID` holds the other pseudo-op declarations.
pub(crate) const DECLARE: &str =
    "define pcodeop kvec;\ndefine pcodeop kgather;\ndefine pcodeop kmask;\n";

/// A line of a `VTESTPS`/`VTESTPD` constructor on `ymm` registers (`pd` for the second). Ghidra
/// picks single bits out of a 256-bit value, which icicle cannot lift.
fn vtest_line(line: &str, pd: bool) -> Option<String> {
    let flag = |reg: &str, op: &str| {
        let name = format!("{op}{}", if pd { "pd" } else { "ps" });
        let number = op_id(&name)? | (2 << COUNT_SHIFT);
        Some(format!(
            "\t{reg} = kvec({number}:2, 0:1, val1[0,128], val1[128,128], val2[0,128], \
             val2[128,128], 0:1, 0:1);"
        ))
    };
    match line.trim() {
        "local val1 = YmmReg2_m256;" => Some("\tlocal val1:32 = YmmReg2_m256;".into()),
        "local val2 = YmmReg1;" => Some("\tlocal val2:32 = YmmReg1;".into()),
        "local ztest = val1 & val2;" | "local ctest = val1 & ~val2;" => Some(String::new()),
        l if l.starts_with("ZF = (ztest[") => flag("ZF", "ktestz"),
        l if l.starts_with("CF = (ctest[") => flag("CF", "ktestc"),
        _ => None,
    }
}

/// A shift of 64 bits of an `xmm` register by a 64-bit count, as the instruction defines it: a
/// count of 64 or more clears the value, where icicle's shift would use the count modulo 64.
fn wide_count_shift(line: &str) -> Option<String> {
    let body = line.trim().strip_suffix(';')?;
    let (lhs, rhs) = body.split_once(" = ")?;
    let shifted = rhs
        .strip_suffix(" << count")
        .or_else(|| rhs.strip_suffix(" >> count"))?;
    let (lhs, shifted) = (lhs.trim(), shifted.trim());
    if !lhs.ends_with(",64]") || !shifted.ends_with(",64]") {
        return None;
    }
    Some(format!("  {lhs} = ({rhs}) * zext(count < 64);"))
}

/// The source operand of a constructor that reads it again after writing its destination, which
/// goes wrong when the destination is also the source or part of its address (`lzcnt r10, [r10]`
/// in glibc). `None` for every other constructor.
fn rereads_source(head: &str) -> Option<&'static str> {
    let name = head.split_whitespace().next()?;
    if !matches!(name, ":LZCNT" | ":TZCNT" | ":BLSI" | ":BLSMSK" | ":BLSR") {
        return None;
    }
    let last = head.split_whitespace().take_while(|w| *w != "is").last()?;
    ["rm16", "rm32", "rm64"].into_iter().find(|rm| last == *rm)
}

/// Applies the rewrite to one `.sinc` file: pseudo-ops in [`OPS`], and the zero extensions of
/// 32- and 64-bit values into a whole `zmm` register, which icicle cannot lift in one step (it
/// splits the zero fill into 128-bit pieces). A `local` holding the 128-bit value fixes that.
pub(crate) fn rewrite_sinc(text: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut narrow_tmp = false;
    let mut vtest = false;
    let mut pd = false;
    let mut movmsk = false;
    let mut skipping = false;
    let mut source = None;
    let mut head = 0;
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if skipping {
            if t.starts_with('}') {
                skipping = false;
                lines.push(line.to_string());
            }
            continue;
        }
        if t.starts_with(':')
            && let Some((_, body)) = BODIES.iter().find(|(h, _)| t.starts_with(h))
        {
            lines.push(head_fix(line));
            lines.push("{".into());
            for (i, stmt) in body.iter().enumerate() {
                match rewrite_line(stmt, n * 8 + i) {
                    Some(new) => lines.push(new),
                    None => lines.push(format!("\t{stmt}")),
                }
            }
            skipping = true;
            continue;
        }
        // `kmask` needs the address, where the operand's table hands over the value.
        let line = if t.starts_with(":VMASKMOVP") || t.starts_with(":VPMASKMOV") {
            line.replace("m128", "Mem").replace("m256", "Mem")
        } else {
            line.to_string()
        };
        let line = line.as_str();
        // The source index of `vinsertps` only applies to a register, and an operand table
        // cannot tell the two apart: one constructor each.
        if t.starts_with(":VINSERTPS XmmReg1, vexVVVV_XmmReg, XmmReg2_m32") {
            let body = |source: &str, tmp: usize| {
                let stmt =
                    format!("local tmp:16 = vinsertps_avx( vexVVVV_XmmReg, {source}, imm8:1 );");
                let call = rewrite_line(&stmt, n * 8 + tmp).unwrap_or(stmt);
                format!("{{\n{call}\n\tZmmReg1 = zext(tmp);")
            };
            lines.push(line.replace("XmmReg2_m32", "m32"));
            lines.push(format!("{}\n}}", body("m32", 0)));
            lines.push(
                line.replace(", XmmReg2_m32, imm8 is", ", XmmReg2, imm8 is")
                    .replace(
                        "(XmmReg1 & ZmmReg1) ... & XmmReg2_m32",
                        "mod=3 & XmmReg1 & ZmmReg1 & XmmReg2",
                    ),
            );
            lines.push(body("XmmReg2", 1));
            skipping = true;
            continue;
        }
        // The gathers do not read these tables (`kgather`), and icicle cannot lift them.
        if t.starts_with("vaddr") {
            let line = match line.find('{') {
                Some(at) => format!("{}{{ local tmp:8 = 0; export tmp; }}", &line[..at]),
                None => line.to_string(),
            };
            lines.push(line);
            continue;
        }
        if let Some(rm) = source {
            if t.starts_with('}') {
                source = None;
            } else if t.starts_with('{') {
                lines.push(format!("{{\n\tlocal ksrc = {rm};"));
                continue;
            } else if !t.starts_with("build") {
                lines.push(line.replace(rm, "ksrc"));
                continue;
            }
        }
        if let Some(rm) = t.starts_with(':').then(|| rereads_source(t)).flatten() {
            source = Some(rm);
            if line.trim_end().ends_with('{') {
                lines.push(format!("{line}\n\tlocal ksrc = {rm};"));
            } else {
                lines.push(line.to_string());
            }
            continue;
        }
        if t.starts_with(":VGATHER") || t.starts_with(":VPGATHER") {
            lines.push(line.trim_end().trim_end_matches('{').to_string());
            lines.push("{\n\tkgather(inst_start, inst_start);".into());
            skipping = true;
            continue;
        }
        if t.starts_with(':') {
            narrow_tmp = false;
            vtest = t.starts_with(":VTESTP") && t.contains(" YmmReg1,");
            pd = t.starts_with(":VTESTPD");
            movmsk = t.starts_with(":VPMOVMSKB Reg32, YmmReg2 ");
            head = lines.len();
        }
        if t.starts_with("local tmp:4 ") || t.starts_with("local tmp:8 ") {
            narrow_tmp = true;
        }
        if movmsk && t.starts_with("byte_mask[") {
            continue;
        }
        if movmsk && t.starts_with("local byte_mask:4") {
            let number = op_id("vpmovmskb").unwrap_or(0) | (1 << COUNT_SHIFT);
            lines.push(format!(
                "\tlocal byte_mask:4 = kvec({number}:2, 0:1, YmmReg2[0,128], YmmReg2[128,128], \
                 0:1, 0:1, 0:1, 0:1);"
            ));
        } else if let Some(new) = vtest.then(|| vtest_line(line, pd)).flatten() {
            lines.push(new);
        } else if let Some(new) = rewrite_line(line, n) {
            if let Some(keep) = new.strip_suffix(";").and_then(|l| {
                let at = l.rfind("vexVVVV_XmmReg = ")?;
                Some((
                    l[..at].to_string(),
                    l[at + "vexVVVV_XmmReg = ".len()..].to_string(),
                ))
            }) {
                // A VEX write clears the rest of the destination, which this form leaves out.
                lines[head] = lines[head]
                    .replace(" & vexVVVV_XmmReg;", " & vexVVVV_XmmReg & vexVVVV_YmmReg;");
                lines.push(format!(
                    "{}local kx{n}:16 = {}; vexVVVV_YmmReg = zext(kx{n});",
                    keep.0, keep.1
                ));
            } else {
                lines.push(new);
            }
        } else if narrow_tmp
            && t.starts_with("ZmmReg1 = zext(tmp)")
            && lines[head].contains(", vexVVVV_XmmReg, ")
        {
            // A scalar VEX form keeps the rest of the first source; Ghidra's clears it.
            let bits = lines[head + 2..]
                .iter()
                .find_map(|l| {
                    let l = l.trim_start().strip_prefix("local tmp:")?;
                    Some(l.starts_with('4'))
                })
                .map_or(64, |four| if four { 32 } else { 64 });
            lines.push(format!(
                "\tlocal kz{n}:16 = vexVVVV_XmmReg; kz{n}[0,{bits}] = tmp; ZmmReg1 = zext(kz{n});"
            ));
        } else if let Some(new) = narrow_zext(t, narrow_tmp, n) {
            lines.push(format!("\t{new}"));
        } else if let Some(new) = wide_count_shift(line) {
            lines.push(new);
        } else {
            lines.push(line.to_string());
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `ZmmRegN = zext(value);` for a value of 4 or 8 bytes, in two steps.
fn narrow_zext(line: &str, narrow_tmp: bool, n: usize) -> Option<String> {
    let body = line.trim_end().strip_suffix(';')?;
    let (lhs, rhs) = body.split_once('=')?;
    let lhs = lhs.trim();
    if !lhs.starts_with("ZmmReg") {
        return None;
    }
    let v = rhs.trim().strip_prefix("zext(")?.strip_suffix(')')?.trim();
    let narrow = matches!(v, "rm32" | "rm64" | "m32" | "m64")
        || v.ends_with("[0,64]")
        || v.ends_with("[0,32]")
        || (v == "tmp" && narrow_tmp);
    narrow.then(|| format!("local kz{n}:16 = zext({v}); {lhs} = zext(kz{n});"))
}

/// Constructor bodies replaced whole, by the start of the constructor: wrong or incomplete in
/// Ghidra's spec, as checked against a real CPU (`corpus/linux-rt/src/vex_ops.c`). The statements
/// go through [`rewrite_line`].
const BODIES: &[(&str, &[&str])] = &[
    (":VLDMXCSR m32", &["MXCSR = m32;"]),
    (":VSTMXCSR m32", &["m32 = MXCSR;"]),
    (
        ":VPINSRD XmmReg1, vexVVVV_XmmReg, rm32, imm8",
        &[
            "local tmp:16 = kpinsrd_avx( vexVVVV_XmmReg, rm32, imm8:1 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VSQRTSD XmmReg1, vexVVVV_XmmReg, XmmReg2_m64",
        &[
            "local tmp:16 = ksqrtsd_avx( vexVVVV_XmmReg, XmmReg2_m64 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VSQRTSS XmmReg1, vexVVVV_XmmReg, XmmReg2_m32",
        &[
            "local tmp:16 = ksqrtss_avx( vexVVVV_XmmReg, XmmReg2_m32 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VCVTTPS2DQ XmmReg1, XmmReg2_m128",
        &[
            "local tmp:16 = vcvttps2dq_avx( XmmReg2_m128 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VCVTTPS2DQ YmmReg1, YmmReg2_m256",
        &[
            "local tmp:32 = vcvttps2dq_avx( YmmReg2_m256 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VCVTTPD2DQ XmmReg1, XmmReg2_m128",
        &[
            "local tmp:16 = vcvttpd2dq_avx( XmmReg2_m128 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VCVTTPD2DQ XmmReg1, YmmReg2_m256",
        &[
            "local tmp:16 = vcvttpd2dq_avx( YmmReg2_m256 );",
            "ZmmReg1 = zext(tmp);",
        ],
    ),
    (
        ":VCVTSD2SI Reg32, XmmReg2_m64",
        &[
            "Reg32 = kcvtsd2si_avx( XmmReg2_m64 );",
            "build check_Reg32_dest;",
        ],
    ),
    (
        ":VCVTSD2SI Reg64, XmmReg2_m64",
        &["Reg64 = kcvtsd2si_avx( XmmReg2_m64 );"],
    ),
    (
        ":VCVTSS2SI Reg32, XmmReg2_m32",
        &[
            "Reg32 = kcvtss2si_avx( XmmReg2_m32 );",
            "build check_Reg32_dest;",
        ],
    ),
    (
        ":VCVTSS2SI Reg64, XmmReg2_m32",
        &["Reg64 = kcvtss2si_avx( XmmReg2_m32 );"],
    ),
    (
        ":VCVTTSD2SI Reg32, XmmReg2_m64",
        &[
            "Reg32 = kcvttsd2si_avx( XmmReg2_m64 );",
            "build check_Reg32_dest;",
        ],
    ),
    (
        ":VCVTTSD2SI Reg64, XmmReg2_m64",
        &["Reg64 = kcvttsd2si_avx( XmmReg2_m64 );"],
    ),
    (
        ":VCVTTSS2SI Reg32, XmmReg2_m32",
        &[
            "Reg32 = kcvttss2si_avx( XmmReg2_m32 );",
            "build check_Reg32_dest;",
        ],
    ),
    (
        ":VCVTTSS2SI Reg64, XmmReg2_m32",
        &["Reg64 = kcvttss2si_avx( XmmReg2_m32 );"],
    ),
    (
        ":VEXTRACTPS rm32, XmmReg1, imm8",
        &[
            "rm32 = vextractps_avx( XmmReg1, imm8:1 );",
            "build check_rm32_dest;",
        ],
    ),
];

/// Operands the replaced bodies of [`BODIES`] build, added to the constructor's pattern.
fn head_fix(head: &str) -> String {
    if head.starts_with(":VEXTRACTPS rm32") {
        return head.replace(
            "XmmReg1 ... & rm32;",
            "XmmReg1 ... & rm32 & check_rm32_dest ...;",
        );
    }
    let t = head.trim_end();
    for from in [" Reg32 ... & XmmReg2_m32", " Reg32 ... & XmmReg2_m64"] {
        if t.ends_with(from) {
            return head.replace(
                from,
                &from.replace("Reg32 ...", "(Reg32 & check_Reg32_dest) ..."),
            );
        }
    }
    head.to_string()
}

/// `dest = kvec(...)` for the macros of `fma.sinc`, one rounding instead of Ghidra's two.
pub(crate) fn fma_macro(name: &str) -> String {
    let number = op_id(name).unwrap_or(0) | (3 << COUNT_SHIFT);
    format!("\tdest = kvec({number}:2, 0:1, src1, 0:1, src2, 0:1, src3, 0:1);\n")
}

/// Wide arithmetic Ghidra wrote out in p-code, replaced whole: `(file, from, to)`.
pub(crate) fn spec_fixes() -> Vec<(&'static str, &'static str, String)> {
    let test = "\tZF = ((val1[0,128] & val2[0,128]) == 0) && ((val1[128,128] & val2[128,128]) == 0);\n\tCF = ((val1[0,128] & ~val2[0,128]) == 0) && ((val1[128,128] & ~val2[128,128]) == 0);\n";
    vec![
        (
            "avx.sinc",
            "\tlocal val1 = YmmReg2_m256;\n\tlocal val2 = YmmReg1;\n\tZF = (val1 & val2) == 0;\n\tCF = (val1 & ~val2) == 0;\n",
            format!("\tlocal val1:32 = YmmReg2_m256;\n\tlocal val2:32 = YmmReg1;\n{test}"),
        ),
        (
            "avx2.sinc",
            "\tlocal tmp:32 = vexVVVV_YmmReg ^ YmmReg2_m256;\n",
            "\tlocal kb:32 = YmmReg2_m256;\n\tlocal tmp:32 = 0;\n\ttmp[0,128] = vexVVVV_YmmReg[0,128] ^ kb[0,128];\n\ttmp[128,128] = vexVVVV_YmmReg[128,128] ^ kb[128,128];\n".into(),
        ),
        (
            "avx.sinc",
            ":VCVTPS2PH XmmReg2_m64, XmmReg1, imm8 is",
            ":VCVTPS2PH XmmReg2, XmmReg1, imm8 is $(VEX_NONE) & $(VEX_L128) & $(VEX_PRE_66) & $(VEX_0F3A) & $(VEX_W0); byte=0x1D; XmmReg1 & (mod=3 & XmmReg2 & ZmmReg2); imm8\n{\n\tlocal tmp:16 = vcvtps2ph_f16c( XmmReg1, imm8:1 );\n\tZmmReg2 = zext(tmp);\n}\n\n:VCVTPS2PH XmmReg2_m64, XmmReg1, imm8 is".into(),
        ),
        (
            "fma.sinc",
            "\tdest = (src1 f* src2) f+ src3;\n",
            fma_macro("kfmadd"),
        ),
        (
            "fma.sinc",
            "\tdest = (src1 f* src2) f- src3;\n",
            fma_macro("kfmsub"),
        ),
        (
            "fma.sinc",
            "\tdest = f- (src1 f* src2) f+ src3;\n",
            fma_macro("kfnmadd"),
        ),
        (
            "fma.sinc",
            "\tdest = f- (src1 f* src2) f- src3;\n",
            fma_macro("kfnmsub"),
        ),
    ]
}

/// `XGETBV`: x87, SSE and AVX state enabled, as `CPUID` says.
pub(crate) const X86_XGETBV: &str =
    ":XGETBV         is vexMode=0 & byte=0x0F; byte=0x01; byte=0xD0  {
@ifdef IA64
\tRAX = 7;
\tRDX = 0;
@else
\tEAX = 7;
\tEDX = 0;
@endif
}";

/// The memory accesses of `XSAVE` (`save`) or `XRSTOR` for registers `from..to`.
fn state_moves(from: usize, to: usize, save: bool, high: bool) -> String {
    let mut out = String::new();
    for i in from..to {
        let (name, base) = if high {
            (format!("YMM{i}_H"), 576)
        } else {
            (format!("XMM{i}"), 160)
        };
        let at = format!("*:16 (p + {})", base + 16 * i);
        if save {
            out.push_str(&format!("\t{at} = {name};\n"));
        } else {
            out.push_str(&format!("\t{name} = {at};\n"));
        }
    }
    out
}

/// One constructor of `XSAVE`/`XRSTOR`. The SSE and AVX components are handled, plus MXCSR; the
/// x87 stack is not saved (`fxsave` does that; nothing the C library switches with this does).
fn state_constructor(head: &str, reg_opcode: u8, rex: &str, save: bool) -> String {
    let moves = |high: bool| {
        format!(
            "{}@ifdef IA64\n{}@endif\n",
            state_moves(0, 8, save, high),
            state_moves(8, 16, save, high)
        )
    };
    let (xmm, ymm) = (moves(false), moves(true));
    if save {
        format!(
            "{head} Mem is {rex}$(PRE_NO) & vexMode=0 & byte=0x0F; byte=0xAE; ( mod != 0b11 & reg_opcode={reg_opcode} ) ... & Mem {{
\tlocal p = Mem;
\t*:4 (p + 24) = MXCSR;
\t*:8 (p + 512) = zext(EAX & 6);
\tif ((EAX & 2) == 0) goto <skip_sse>;
{xmm}<skip_sse>
\tif ((EAX & 4) == 0) goto <skip_avx>;
{ymm}<skip_avx>
}}
"
        )
    } else {
        format!(
            "{head} Mem is {rex}$(PRE_NO) & vexMode=0 & byte=0x0F; byte=0xAE; ( mod != 0b11 & reg_opcode={reg_opcode} ) ... & Mem {{
\tlocal p = Mem;
\tlocal present:8 = *:8 (p + 512);
\tMXCSR = *:4 (p + 24);
\tif ((EAX & 2) == 0 || (present & 2) == 0) goto <skip_sse>;
{xmm}<skip_sse>
\tif ((EAX & 4) == 0 || (present & 4) == 0) goto <skip_avx>;
{ymm}<skip_avx>
}}
"
        )
    }
}

/// `XSAVE` and `XSAVE64`.
pub(crate) fn xsave_text() -> String {
    format!(
        "{}@ifdef IA64\n{}@endif\n\n",
        state_constructor(":XSAVE", 4, "", true),
        state_constructor(":XSAVE64", 4, "$(LONGMODE_ON) & $(REX_W) & ", true)
    )
}

/// `XRSTOR` and `XRSTOR64`.
pub(crate) fn xrstor_text() -> String {
    format!(
        "{}@ifdef IA64\n{}@endif\n\n",
        state_constructor(":XRSTOR", 5, "", false),
        state_constructor(":XRSTOR64", 5, "$(LONGMODE_ON) & $(REX_W) & ", false)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_statement_becomes_two_half_calls() {
        let id = OPS.iter().position(|(n, _)| *n == "vpand").unwrap() | 2 << COUNT_SHIFT;
        let s = rewrite_line(
            "\tlocal tmp:32 = vpand_avx2( vexVVVV_YmmReg, YmmReg2_m256 );",
            7,
        )
        .unwrap();
        assert!(s.contains("local kv56_0:32 = vexVVVV_YmmReg;"), "{s}");
        assert!(
            s.contains(&format!("kvec({id}:2, 1:1, kv56_0[0,128]")),
            "{s}"
        );
        assert!(s.ends_with("local tmp:32 = kr56;"), "{s}");
    }

    #[test]
    fn string_compares_take_their_flags_before_the_result() {
        let s = rewrite_line("XMM0 = vpcmpistrm_avx( XmmReg1, XmmReg2_m128, imm8:1 );", 1).unwrap();
        let flags = s.find("local kf8:8 = kvec(").expect("flags");
        let result = s.find("XMM0 = kvec(").expect("result");
        assert!(flags < result, "{s}");
    }

    #[test]
    fn the_short_explicit_lengths_are_signed() {
        let s = rewrite_line(
            "ECX = vpcmpestri_avx( XmmReg1, XmmReg2_m128, imm8:1, EAX, EDX );",
            1,
        )
        .unwrap();
        assert!(s.contains("local kl8_0:8 = sext(EAX);"), "{s}");
        assert!(s.contains("local kl8_1:8 = sext(EDX);"), "{s}");
        let wide = rewrite_line(
            "ECX = vpcmpestri_avx( XmmReg1, XmmReg2_m128, imm8:1, RAX, RDX );",
            1,
        )
        .unwrap();
        assert!(!wide.contains("sext"), "{wide}");
    }

    #[test]
    fn masked_moves_pass_the_address_and_never_touch_the_operand() {
        let load = rewrite_line("local tmp:32 = vmaskmovps_avx( vexVVVV_YmmReg, m256 );", 1);
        let load = load.unwrap();
        assert!(load.contains("local ka8 = Mem;"), "{load}");
        let number = 4 | 2 << COUNT_SHIFT;
        assert!(
            load.contains(&format!("kmask({number}:2, 1:1, ka8, 0:1")),
            "{load}"
        );
        assert!(!load.contains("m256"), "{load}");
        let store = rewrite_line("m128 = vpmaskmovq_avx2( vexVVVV_XmmReg, XmmReg1 );", 1);
        let store = store.unwrap();
        let number = 8 | MASK_STORE | 3 << COUNT_SHIFT;
        assert!(store.contains(&format!("kmask({number}:2, 0:1")), "{store}");
        assert!(!store.contains("m128"), "{store}");
    }

    #[test]
    fn the_masked_move_constructors_name_their_address() {
        let s = rewrite_sinc(
            ":VMASKMOVPS m256, vexVVVV_YmmReg, YmmReg1 is x; YmmReg1 ... & m256\n{\n\
             \tm256 = vmaskmovps_avx( vexVVVV_YmmReg, YmmReg1 );\n}\n",
        );
        assert!(s.contains("YmmReg1 ... & Mem"), "{s}");
        assert!(s.contains("kmask("), "{s}");
    }

    #[test]
    fn insertps_from_memory_has_no_source_index() {
        let s = rewrite_sinc(
            ":VINSERTPS XmmReg1, vexVVVV_XmmReg, XmmReg2_m32, imm8 is x; (XmmReg1 & ZmmReg1) ... \
             & XmmReg2_m32; imm8\n{\n\tlocal tmp:16 = vinsertps_avx( vexVVVV_XmmReg, \
             XmmReg2_m32, imm8:1 );\n\tZmmReg1 = zext(tmp);\n}\n",
        );
        assert_eq!(s.matches(":VINSERTPS").count(), 2, "{s}");
        assert_eq!(s.matches("imm8:1 & 0x3f").count(), 1, "{s}");
        assert!(s.contains("mod=3 & XmmReg1 & ZmmReg1 & XmmReg2"), "{s}");
    }

    #[test]
    fn narrow_values_are_extended_in_two_steps() {
        let s = narrow_zext("ZmmReg1 = zext( rm64 );", false, 3).unwrap();
        assert_eq!(s, "local kz3:16 = zext(rm64); ZmmReg1 = zext(kz3);");
        assert_eq!(narrow_zext("ZmmReg1 = zext(tmp);", false, 3), None);
        assert!(narrow_zext("ZmmReg1 = zext(tmp);", true, 3).is_some());
    }

    #[test]
    fn unknown_ops_keep_their_name() {
        assert_eq!(
            rewrite_line("\tlocal tmp:32 = vgibberish_avx( a );", 1),
            None
        );
    }

    #[test]
    fn legacy_forms_rewrite_only_on_xmm_registers() {
        let xmm = ":PSHUFB x is y { XmmReg1=pshufb(XmmReg1,XmmReg2_m128); }";
        assert!(rewrite_line(xmm, 1).unwrap().contains("kvec("));
        let mmx = ":PSHUFB x is y { mmxreg=pshufb(mmxreg,m64); }";
        assert_eq!(rewrite_line(mmx, 1), None);
    }
}
