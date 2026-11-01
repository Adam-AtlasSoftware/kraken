//! How `float` and `double` results of the original and the translation are compared.
//!
//! A translation of floating-point code can differ from the original in the last bits without
//! being wrong (a fused multiply-add the compiler chose, an evaluation order, a libm that rounds
//! the last place differently). The default is exact: bit patterns must be equal, so a result
//! of `-0.0` against `0.0` or two different NaN payloads is a difference. `[rewrite] float_ulp = n`
//! accepts results up to `n` units in the last place apart; two NaNs always agree, a NaN never
//! agrees with a number, and infinities agree only with themselves (they are one step from the
//! largest finite number, which the distance would otherwise count).

use serde::{Deserialize, Serialize};

use crate::abi::{Ret, Scalar, StructShape};

/// The comparison of floating-point values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FloatPolicy {
    /// Bit for bit.
    #[default]
    Exact,
    /// At most this many units in the last place apart.
    Ulp { max: u32 },
}

impl FloatPolicy {
    /// `Exact` for 0, else `Ulp`.
    pub fn from_ulps(n: u32) -> Self {
        if n == 0 {
            FloatPolicy::Exact
        } else {
            FloatPolicy::Ulp { max: n }
        }
    }

    /// Whether two `double` bit patterns agree.
    pub fn f64_agree(self, a: u64, b: u64) -> bool {
        if a == b {
            return true;
        }
        let FloatPolicy::Ulp { max } = self else {
            return false;
        };
        let (x, y) = (f64::from_bits(a), f64::from_bits(b));
        if x.is_nan() || y.is_nan() {
            return x.is_nan() && y.is_nan();
        }
        if x.is_infinite() || y.is_infinite() {
            return false;
        }
        let key = |bits: u64| {
            let mag = i128::from(bits & !(1 << 63));
            if bits >> 63 == 1 { -mag } else { mag }
        };
        (key(a) - key(b)).unsigned_abs() <= u128::from(max)
    }

    /// Whether two `float` bit patterns agree.
    pub fn f32_agree(self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        let FloatPolicy::Ulp { max } = self else {
            return false;
        };
        let (x, y) = (f32::from_bits(a), f32::from_bits(b));
        if x.is_nan() || y.is_nan() {
            return x.is_nan() && y.is_nan();
        }
        if x.is_infinite() || y.is_infinite() {
            return false;
        }
        let key = |bits: u32| {
            let mag = i64::from(bits & !(1 << 31));
            if bits >> 31 == 1 { -mag } else { mag }
        };
        (key(a) - key(b)).unsigned_abs() <= u64::from(max)
    }

    /// Whether two return values (masked to the return width) agree for result type `ret`.
    pub fn ret_agree(self, ret: &Ret, a: Option<u64>, b: Option<u64>) -> bool {
        match (ret, a, b) {
            (Ret::Double, Some(x), Some(y)) => self.f64_agree(x, y),
            (Ret::Float, Some(x), Some(y)) => self.f32_agree(x as u32, y as u32),
            _ => a == b,
        }
    }

    /// Whether two structure results (padding zeroed) agree: floating-point fields by the
    /// policy, everything else byte for byte.
    pub fn struct_agree(self, shape: &StructShape, a: &[u8], b: &[u8]) -> bool {
        if a == b {
            return true;
        }
        if a.len() != b.len() || a.len() != shape.size() {
            return false;
        }
        let (offsets, _, _) = shape.layout();
        let mut covered = vec![false; a.len()];
        for (f, &off) in shape.fields.iter().zip(&offsets) {
            match f {
                Scalar::Double => {
                    let w =
                        |s: &[u8]| u64::from_le_bytes(s[off..off + 8].try_into().unwrap_or([0; 8]));
                    if !self.f64_agree(w(a), w(b)) {
                        return false;
                    }
                    covered[off..off + 8].fill(true);
                }
                Scalar::Float => {
                    let w =
                        |s: &[u8]| u32::from_le_bytes(s[off..off + 4].try_into().unwrap_or([0; 4]));
                    if !self.f32_agree(w(a), w(b)) {
                        return false;
                    }
                    covered[off..off + 4].fill(true);
                }
                Scalar::Int { .. } => {}
            }
        }
        a.iter()
            .zip(b)
            .zip(&covered)
            .all(|((x, y), c)| *c || x == y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_is_bitwise() {
        let p = FloatPolicy::Exact;
        assert!(p.f64_agree(1.5f64.to_bits(), 1.5f64.to_bits()));
        assert!(!p.f64_agree(0.0f64.to_bits(), (-0.0f64).to_bits()));
        assert!(!p.f64_agree(1.0f64.to_bits(), (1.0f64 + f64::EPSILON).to_bits()));
    }

    #[test]
    fn ulp_counts_steps_across_zero_and_binades() {
        let p = FloatPolicy::from_ulps(2);
        let next = |x: f64, n: u64| f64::from_bits(x.to_bits() + n).to_bits();
        assert!(p.f64_agree(1.0f64.to_bits(), next(1.0, 2)));
        assert!(!p.f64_agree(1.0f64.to_bits(), next(1.0, 3)));
        // +0 and -0 are no steps apart; the smallest subnormals on either side are two.
        assert!(p.f64_agree(0.0f64.to_bits(), (-0.0f64).to_bits()));
        assert!(p.f64_agree(1u64, (1u64 << 63) | 1));
        assert!(!p.f64_agree(2u64, (1u64 << 63) | 1));
        let q = FloatPolicy::from_ulps(1);
        assert!(q.f32_agree(1.0f32.to_bits(), 1.0f32.to_bits() + 1));
        assert!(!q.f32_agree(1.0f32.to_bits(), 1.0f32.to_bits() + 2));
    }

    #[test]
    fn nan_and_infinity() {
        let p = FloatPolicy::from_ulps(4);
        assert!(p.f64_agree(f64::NAN.to_bits(), (-f64::NAN).to_bits()));
        assert!(!p.f64_agree(f64::NAN.to_bits(), 1.0f64.to_bits()));
        assert!(!p.f64_agree(f64::INFINITY.to_bits(), f64::MAX.to_bits()));
        assert!(p.f64_agree(f64::INFINITY.to_bits(), f64::INFINITY.to_bits()));
        assert!(!FloatPolicy::Exact.f64_agree(f64::NAN.to_bits(), (-f64::NAN).to_bits()));
    }

    #[test]
    fn struct_fields_use_the_policy() {
        let shape = StructShape {
            name: "P".into(),
            fields: vec![
                Scalar::Int {
                    bits: 32,
                    signed: true,
                },
                Scalar::Double,
            ],
        };
        let mk = |i: i32, d: u64| {
            let mut v = vec![0u8; 16];
            v[..4].copy_from_slice(&i.to_le_bytes());
            v[8..].copy_from_slice(&d.to_le_bytes());
            v
        };
        let one = 1.0f64.to_bits();
        let p = FloatPolicy::from_ulps(1);
        assert!(p.struct_agree(&shape, &mk(3, one), &mk(3, one + 1)));
        assert!(!p.struct_agree(&shape, &mk(3, one), &mk(4, one)));
        assert!(!FloatPolicy::Exact.struct_agree(&shape, &mk(3, one), &mk(3, one + 1)));
    }
}
