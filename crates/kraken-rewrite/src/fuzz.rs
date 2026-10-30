//! Deterministic mutation of recorded cases. A case from a real run reaches the function's real
//! logic; a few small changes to it (a flipped bit, a neighbouring number, a swapped byte) probe
//! the paths next to it. The same seed on the same cases always gives the same mutants, so a
//! counterexample can be reproduced.

use std::collections::BTreeSet;

use crate::abi::{Arg, Callback};
use crate::inputs::Rng;

/// What to make.
#[derive(Debug, Clone)]
pub struct FuzzOptions {
    /// Seed of the mutations.
    pub seed: u64,
    /// Mutants tried per recorded case.
    pub per_case: usize,
    /// Most mutants returned in all.
    pub max_total: usize,
}

impl Default for FuzzOptions {
    fn default() -> Self {
        FuzzOptions {
            seed: 0x4b52_4655_5a5a,
            per_case: 3,
            max_total: 100,
        }
    }
}

const BYTE_EDGES: [u8; 5] = [0x00, 0x01, 0x7f, 0x80, 0xff];

fn mutate_int(value: u64, rng: &mut Rng) -> u64 {
    let small = (value as i64) >= i64::from(i32::MIN) && (value as i64) <= i64::from(i32::MAX);
    match rng.below(3) {
        0 => {
            let d = rng.range(-2, 2);
            if small {
                i64::from((value as i64 as i32).wrapping_add(d as i32)) as u64
            } else {
                value.wrapping_add(d as u64)
            }
        }
        1 => {
            // Stay inside the width the value was in: a 32-bit value keeps its upper half.
            let bit = rng.below(if small { 31 } else { 63 });
            value ^ (1u64 << bit)
        }
        _ => [0u64, 1][rng.below(2) as usize],
    }
}

fn mutate_bytes(data: &mut [u8], protected: &BTreeSet<usize>, rng: &mut Rng) {
    if data.is_empty() {
        return;
    }
    let free: Vec<usize> = (0..data.len()).filter(|i| !protected.contains(i)).collect();
    if free.is_empty() {
        return;
    }
    let pick = |rng: &mut Rng| free[rng.below(free.len() as u64) as usize];
    match rng.below(3) {
        0 => {
            let i = pick(rng);
            data[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = pick(rng);
            data[i] = BYTE_EDGES[rng.below(BYTE_EDGES.len() as u64) as usize];
        }
        _ => {
            let (i, j) = (pick(rng), pick(rng));
            data.swap(i, j);
        }
    }
}

fn mutate_arg(arg: &mut Arg, rng: &mut Rng) {
    match arg {
        Arg::Int { value } => *value = mutate_int(*value, rng),
        Arg::Buf { data } => mutate_bytes(data, &BTreeSet::new(), rng),
        Arg::Double { bits } => *bits ^= 1 << rng.below(20),
        Arg::Float { bits } => *bits ^= 1 << rng.below(12),
        Arg::FnPtr { callback } => {
            *callback = if *callback == Callback::Ascending {
                Callback::Descending
            } else {
                Callback::Ascending
            };
        }
        Arg::Graph { objects, links } => {
            if objects.is_empty() {
                return;
            }
            let k = rng.below(objects.len() as u64) as usize;
            // The bytes of an embedded pointer stay as they are.
            let protected: BTreeSet<usize> = links
                .iter()
                .filter(|l| l.from == k)
                .flat_map(|l| l.offset..l.offset + 8)
                .collect();
            mutate_bytes(&mut objects[k], &protected, rng);
        }
    }
}

/// Mutants of `base`: up to `per_case` per case, one or two changes each, never equal to a
/// recorded case or to each other.
pub fn fuzz_cases(base: &[Vec<Arg>], opts: &FuzzOptions) -> Vec<Vec<Arg>> {
    let mut seen: BTreeSet<String> = base
        .iter()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .collect();
    let mut out = Vec::new();
    'cases: for (i, case) in base.iter().enumerate() {
        if case.is_empty() {
            continue;
        }
        let mut rng = Rng::new(opts.seed ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        for _ in 0..opts.per_case {
            let mut m = case.clone();
            for _ in 0..1 + rng.below(2) {
                let k = rng.below(m.len() as u64) as usize;
                mutate_arg(&mut m[k], &mut rng);
            }
            if seen.insert(serde_json::to_string(&m).unwrap_or_default()) {
                out.push(m);
                if out.len() >= opts.max_total {
                    break 'cases;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Link;

    fn base() -> Vec<Vec<Arg>> {
        vec![
            vec![Arg::Int { value: 7 }, Arg::Buf { data: vec![1; 16] }],
            vec![
                Arg::Int {
                    value: (-3i64) as u64,
                },
                Arg::Graph {
                    objects: vec![vec![5; 16], vec![6; 16]],
                    links: vec![Link {
                        from: 0,
                        offset: 8,
                        to: 1,
                        to_offset: 0,
                    }],
                },
            ],
        ]
    }

    #[test]
    fn the_same_seed_gives_the_same_mutants() {
        let o = FuzzOptions::default();
        assert_eq!(fuzz_cases(&base(), &o), fuzz_cases(&base(), &o));
        let other = FuzzOptions {
            seed: 1,
            ..FuzzOptions::default()
        };
        assert_ne!(fuzz_cases(&base(), &o), fuzz_cases(&base(), &other));
    }

    #[test]
    fn mutants_differ_keep_their_shape_and_respect_the_cap() {
        let b = base();
        let m = fuzz_cases(&b, &FuzzOptions::default());
        assert!(!m.is_empty());
        for c in &m {
            assert!(!b.contains(c));
            assert_eq!(c.len(), 2);
            if let Arg::Graph { objects, .. } = &c[1] {
                assert_eq!(objects[0].len(), 16);
                // The 8 bytes holding the embedded pointer are never touched.
                assert_eq!(&objects[0][8..], &[5u8; 8]);
            }
        }
        let capped = fuzz_cases(
            &b,
            &FuzzOptions {
                max_total: 2,
                ..FuzzOptions::default()
            },
        );
        assert_eq!(capped.len(), 2);
    }
}
