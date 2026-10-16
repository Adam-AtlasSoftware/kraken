//! The differential test harness: generate inputs, run the original under emulation and the Rust
//! translation natively, compare, and report counterexamples.

use serde::{Deserialize, Serialize};

use crate::abi::{Arg, Observation, Param, Signature, Termination};
use crate::error::RewriteError;
use crate::native::{Build, NativeRunner, build};
use crate::oracle::FunctionOracle;
use crate::sandbox::Confinement;

/// A small deterministic generator (SplitMix64), so seeds reproduce cases exactly.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator for `seed`.
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        let span = (hi as i128 - lo as i128 + 1).max(1) as u128;
        (lo as i128 + (u128::from(self.next_u64()) % span) as i128) as i64
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

/// How one integer field or parameter is generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntGen {
    /// Width in bits.
    pub bits: u8,
    /// Signedness.
    pub signed: bool,
    /// Inclusive range to stay within, if narrower than the type.
    pub range: Option<(i64, i64)>,
}

impl IntGen {
    /// Any value of the type.
    pub fn full(bits: u8, signed: bool) -> Self {
        IntGen {
            bits,
            signed,
            range: None,
        }
    }

    fn bounds(&self) -> (i64, i64) {
        let (lo, hi) = match (self.signed, self.bits) {
            (true, b) if b >= 64 => (i64::MIN, i64::MAX),
            (true, b) => (-(1i64 << (b - 1)), (1i64 << (b - 1)) - 1),
            (false, b) if b >= 63 => (0, i64::MAX),
            (false, b) => (0, (1i64 << b) - 1),
        };
        match self.range {
            Some((a, b)) => (a.max(lo), b.min(hi)),
            None => (lo, hi),
        }
    }

    /// Boundary values worth trying.
    pub fn edges(&self) -> Vec<i64> {
        let (lo, hi) = self.bounds();
        let mut v: Vec<i64> = [
            0,
            1,
            -1,
            2,
            -2,
            7,
            10,
            100,
            lo,
            lo.saturating_add(1),
            hi,
            hi.saturating_sub(1),
        ]
        .into_iter()
        .filter(|x| (lo..=hi).contains(x))
        .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn random(&self, rng: &mut Rng) -> i64 {
        let (lo, hi) = self.bounds();
        match rng.below(4) {
            0 => rng.range(lo.max(-300), hi.min(300).max(lo.max(-300))),
            _ => rng.range(lo, hi),
        }
    }

    fn to_arg(&self, v: i64) -> u64 {
        v as u64
    }
}

/// One field of a struct buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldGen {
    /// Byte offset in the buffer.
    pub offset: usize,
    /// How the value is generated (little endian, `bits / 8` bytes).
    pub value: IntGen,
}

/// How one parameter is generated.
#[derive(Debug, Clone)]
pub enum ParamGen {
    /// An integer.
    Int(IntGen),
    /// A zeroed buffer of `size` bytes with random little-endian fields.
    Struct {
        /// Buffer size.
        size: usize,
        /// Fields to randomise.
        fields: Vec<FieldGen>,
    },
    /// Random bytes (from `alphabet` when given), optionally NUL terminated, plus `pad` zero
    /// bytes after the logical content so a sloppy read stays inside defined memory.
    Bytes {
        /// Shortest content.
        min_len: usize,
        /// Longest content.
        max_len: usize,
        /// Allowed byte values.
        alphabet: Option<Vec<u8>>,
        /// Append a NUL.
        terminator: bool,
        /// Zero bytes after the content (and terminator).
        pad: usize,
    },
    /// The logical content length of buffer parameter `param` (an earlier `Bytes`).
    LenOf(usize),
}

/// How cases are produced.
#[derive(Debug, Clone)]
pub struct InputSpec {
    /// Hand-picked cases, always run first.
    pub fixed: Vec<Vec<Arg>>,
    /// The generator for the rest.
    pub generator: Generator,
}

/// A case generator.
#[derive(Debug, Clone)]
pub enum Generator {
    /// Independent per-parameter generation, with automatic edge cases.
    Params(Vec<ParamGen>),
    /// Whole-case generation for coupled arguments (for example a program and its length).
    Custom(fn(&mut Rng) -> Vec<Arg>),
}

fn gen_param(
    g: &ParamGen,
    rng: &mut Rng,
    made: &[(Arg, usize)],
    edge: Option<i64>,
) -> (Arg, usize) {
    match g {
        ParamGen::Int(ig) => {
            let v = edge.unwrap_or_else(|| ig.random(rng));
            (
                Arg::Int {
                    value: ig.to_arg(v),
                },
                0,
            )
        }
        ParamGen::Struct { size, fields } => {
            let mut data = vec![0u8; *size];
            for f in fields {
                let n = usize::from(f.value.bits / 8);
                let v = f.value.random(rng);
                if f.offset + n <= data.len() {
                    data[f.offset..f.offset + n].copy_from_slice(&v.to_le_bytes()[..n]);
                }
            }
            (Arg::Buf { data }, *size)
        }
        ParamGen::Bytes {
            min_len,
            max_len,
            alphabet,
            terminator,
            pad,
        } => {
            let len =
                *min_len + usize::try_from(rng.below((max_len - min_len + 1) as u64)).unwrap_or(0);
            let mut data: Vec<u8> = (0..len)
                .map(|_| match alphabet {
                    Some(a) if !a.is_empty() => {
                        a[usize::try_from(rng.below(a.len() as u64)).unwrap_or(0)]
                    }
                    _ => rng.next_u64() as u8,
                })
                .collect();
            if *terminator {
                data.push(0);
            }
            data.extend(std::iter::repeat_n(0u8, *pad));
            (Arg::Buf { data }, len)
        }
        ParamGen::LenOf(i) => {
            let n = made.get(*i).map_or(0, |(_, logical)| *logical);
            (Arg::Int { value: n as u64 }, 0)
        }
    }
}

impl InputSpec {
    /// All cases: fixed, then (for `Params`) edge cases per parameter, then `random` seeded ones.
    pub fn cases(&self, seed: u64, random: usize) -> Vec<Vec<Arg>> {
        let mut out = self.fixed.clone();
        let mut rng = Rng::new(seed);
        match &self.generator {
            Generator::Params(params) => {
                let build = |rng: &mut Rng, edge_at: Option<(usize, i64)>| {
                    let mut made: Vec<(Arg, usize)> = Vec::new();
                    for (i, g) in params.iter().enumerate() {
                        let edge = edge_at.filter(|(p, _)| *p == i).map(|(_, v)| v);
                        let m = gen_param(g, rng, &made, edge);
                        made.push(m);
                    }
                    made.into_iter().map(|(a, _)| a).collect::<Vec<_>>()
                };
                for (i, g) in params.iter().enumerate() {
                    if let ParamGen::Int(ig) = g {
                        for e in ig.edges() {
                            out.push(build(&mut rng, Some((i, e))));
                        }
                    }
                }
                for _ in 0..random {
                    out.push(build(&mut rng, None));
                }
            }
            Generator::Custom(f) => {
                for _ in 0..random {
                    out.push(f(&mut rng));
                }
            }
        }
        out
    }
}

/// Test settings.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Seed of the random cases.
    pub seed: u64,
    /// How many random cases.
    pub random_cases: usize,
    /// Most counterexamples kept.
    pub max_counterexamples: usize,
    /// Sandbox settings for building and running the translation.
    pub confinement: Confinement,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            seed: 0x4b52_414b_454e,
            random_cases: 200,
            max_counterexamples: 3,
            confinement: Confinement::default(),
        }
    }
}

/// The outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// Every case agreed.
    Pass,
    /// At least one case differed; see the counterexamples.
    Fail,
    /// The translation was refused or did not compile.
    Rejected { reason: String },
    /// The oracle could not run the original on enough cases to say anything.
    Inconclusive { reason: String },
}

/// A case on which the two sides disagreed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    /// The arguments.
    pub args: Vec<Arg>,
    /// What the original did.
    pub original: Observation,
    /// What the translation did.
    pub translation: Observation,
    /// Human-readable list of differences.
    pub differences: Vec<String>,
}

/// One executed case with what the original did (kept in the unit record as the oracle's
/// expected results).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseRecord {
    /// The arguments.
    pub args: Vec<Arg>,
    /// What the original did.
    pub expected: Observation,
}

/// The full result of a differential run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    /// Overall verdict.
    pub verdict: Verdict,
    /// Seed used for the random cases.
    pub seed: u64,
    /// Cases run on both sides.
    pub cases_run: usize,
    /// Cases that agreed.
    pub passed: usize,
    /// Cases the oracle could not evaluate (unmodelled import and the like).
    pub skipped: usize,
    /// Disagreements, smallest input first.
    pub counterexamples: Vec<Counterexample>,
    /// Every executed case with the oracle's observation (capped by the caller when stored).
    pub cases: Vec<CaseRecord>,
    /// How the translation was confined while building and running.
    pub sandbox: String,
}

fn same_class(a: &Termination, b: &Termination) -> bool {
    match (a, b) {
        (Termination::Fault { .. }, Termination::Fault { .. }) => true,
        _ => a == b,
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .or_else(|| (a.len() != b.len()).then_some(a.len().min(b.len())))
}

/// Compares what the original and the translation did.
pub fn compare(orig: &Observation, native: &Observation) -> Vec<String> {
    let mut d = Vec::new();
    if !same_class(&orig.termination, &native.termination) {
        d.push(format!(
            "termination: original {:?}, translation {:?}",
            orig.termination, native.termination
        ));
        return d;
    }
    if orig.stdout != native.stdout {
        d.push(format!(
            "stdout: original {:?}, translation {:?}",
            String::from_utf8_lossy(&orig.stdout),
            String::from_utf8_lossy(&native.stdout)
        ));
    }
    if orig.stderr != native.stderr {
        d.push(format!(
            "stderr: original {:?}, translation {:?}",
            String::from_utf8_lossy(&orig.stderr),
            String::from_utf8_lossy(&native.stderr)
        ));
    }
    if orig.termination == Termination::Returned {
        if orig.ret != native.ret {
            d.push(format!(
                "return value: original {:?}, translation {:?}",
                orig.ret, native.ret
            ));
        }
        for (i, (a, b)) in orig.buffers.iter().zip(&native.buffers).enumerate() {
            if let Some(at) = first_diff(a, b) {
                d.push(format!(
                    "buffer {i} differs at byte {at}: original {:#04x?}, translation {:#04x?}",
                    a.get(at),
                    b.get(at)
                ));
            }
        }
        if orig.buffers.len() != native.buffers.len() {
            d.push("number of buffers differs".into());
        }
    }
    if !orig.global_writes.is_empty() {
        d.push(format!(
            "the original writes {} global location(s), which a translation cannot reproduce",
            orig.global_writes.len()
        ));
    }
    d
}

fn input_size(args: &[Arg]) -> usize {
    args.iter()
        .map(|a| match a {
            Arg::Int { .. } => 1,
            Arg::Buf { data } => data.len(),
        })
        .sum()
}

/// Runs the differential test of `rust_code` against the original function at ELF virtual
/// address `entry` of `oracle`'s program.
pub fn run_differential(
    oracle: &mut FunctionOracle,
    entry: u64,
    sig: &Signature,
    rust_code: &str,
    spec: &InputSpec,
    opts: &DiffOptions,
) -> Result<DiffReport, RewriteError> {
    let mut report = DiffReport {
        verdict: Verdict::Pass,
        seed: opts.seed,
        cases_run: 0,
        passed: 0,
        skipped: 0,
        counterexamples: Vec::new(),
        cases: Vec::new(),
        sandbox: String::new(),
    };
    let runner: NativeRunner = match build(sig, rust_code, &opts.confinement)? {
        Build::Ready(r) => r,
        Build::Rejected(reason) => {
            report.verdict = Verdict::Rejected { reason };
            return Ok(report);
        }
    };
    report.sandbox = runner.build_confinement.label();
    check_shapes(sig, spec)?;
    for args in spec.cases(opts.seed, opts.random_cases) {
        let orig = oracle.call(entry, sig, &args)?;
        if let Termination::Unsupported { .. } = orig.termination {
            report.skipped += 1;
            continue;
        }
        let native = runner.run(&args)?;
        report.cases_run += 1;
        let differences = compare(&orig, &native);
        if differences.is_empty() {
            report.passed += 1;
        } else {
            report.counterexamples.push(Counterexample {
                args: args.clone(),
                original: orig.clone(),
                translation: native,
                differences,
            });
        }
        report.cases.push(CaseRecord {
            args,
            expected: orig,
        });
    }
    report.counterexamples.sort_by_key(|c| input_size(&c.args));
    report.counterexamples.truncate(opts.max_counterexamples);
    report.verdict = if report.cases_run == 0 {
        Verdict::Inconclusive {
            reason: format!(
                "the oracle could not evaluate any of {} cases",
                report.skipped
            ),
        }
    } else if report.passed < report.cases_run {
        Verdict::Fail
    } else if report.skipped > 0 && report.skipped * 2 > report.cases_run + report.skipped {
        Verdict::Inconclusive {
            reason: format!(
                "{} of {} cases could not be evaluated",
                report.skipped,
                report.skipped + report.cases_run
            ),
        }
    } else {
        Verdict::Pass
    };
    Ok(report)
}

fn check_shapes(sig: &Signature, spec: &InputSpec) -> Result<(), RewriteError> {
    if let Generator::Params(p) = &spec.generator
        && p.len() != sig.params.len()
    {
        return Err(RewriteError::Unsupported(format!(
            "{} generators for {} parameters",
            p.len(),
            sig.params.len()
        )));
    }
    for case in &spec.fixed {
        let ok = case.len() == sig.params.len()
            && case.iter().zip(&sig.params).all(|(a, p)| {
                matches!(
                    (a, p),
                    (Arg::Int { .. }, Param::Int { .. }) | (Arg::Buf { .. }, Param::Buf)
                )
            });
        if !ok {
            return Err(RewriteError::Unsupported(
                "a fixed case does not match the signature".into(),
            ));
        }
    }
    Ok(())
}
