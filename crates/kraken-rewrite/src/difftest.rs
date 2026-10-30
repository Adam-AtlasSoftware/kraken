//! The differential test harness: generate inputs, run the original under emulation and the Rust
//! translation natively, compare, and report counterexamples.

use serde::{Deserialize, Serialize};

use crate::abi::{Arg, Observation, Signature, Termination};
use crate::error::RewriteError;
use crate::native::{Build, NativeRunner, RunnerImage, build_full};
use crate::oracle::FunctionOracle;
use crate::sandbox::Confinement;

pub use crate::inputs::{
    Chain, FieldGen, GENERIC_ALPHABET, Generator, InputSource, InputSpec, IntGen, ObjectGen,
    ParamGen, Recorded, Rng, SlotGen, TextGen, case_fits,
};

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
    /// KRAKEN's own source compiled in front of the translation without the translation lint (the
    /// runtime shim).
    pub trusted_prelude: String,
    /// The program image the runner installs, so translations can use the program's globals.
    pub image: Option<RunnerImage>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            seed: 0x4b52_414b_454e,
            random_cases: 200,
            max_counterexamples: 3,
            confinement: Confinement::default(),
            trusted_prelude: String::new(),
            image: None,
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

/// A pointer description shortened for a verdict: the block and its first differing bytes are
/// what matter.
fn clip_desc(d: Option<&str>) -> String {
    match d {
        None => "nothing".into(),
        Some(t) if t.chars().count() > 120 => {
            format!("{}...", t.chars().take(120).collect::<String>())
        }
        Some(t) => t.to_string(),
    }
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
        if orig.ret_object != native.ret_object {
            d.push(format!(
                "returned pointer: original points at {}, translation at {}",
                clip_desc(orig.ret_object.as_deref()),
                clip_desc(native.ret_object.as_deref())
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
    if orig.callbacks != native.callbacks {
        let at = orig
            .callbacks
            .iter()
            .zip(&native.callbacks)
            .position(|(a, b)| a != b)
            .unwrap_or(orig.callbacks.len().min(native.callbacks.len()));
        d.push(format!(
            "calls to the callback differ from call {at} on: original {:?}, translation {:?} \
             ({} vs {} calls)",
            orig.callbacks.get(at),
            native.callbacks.get(at),
            orig.callbacks.len(),
            native.callbacks.len()
        ));
    }
    if native.global_writes_observed {
        // Writes are compared for a call that returned; one that exited or faulted has already
        // been compared by how it ended and what it printed.
        if orig.termination != Termination::Returned {
            return d;
        }
        let shown = |w: &[crate::abi::GlobalWrite]| -> Vec<(u64, Vec<u8>)> {
            w.iter().map(|g| (g.vaddr, g.after.clone())).collect()
        };
        let (a, b) = (shown(&orig.global_writes), shown(&native.global_writes));
        if a != b {
            let at = a
                .iter()
                .zip(&b)
                .position(|(x, y)| x != y)
                .unwrap_or(a.len().min(b.len()));
            let describe = |w: Option<&(u64, Vec<u8>)>| match w {
                Some((v, bytes)) => format!(
                    "{} byte(s) at {v:#x} set to {}",
                    bytes.len(),
                    crate::abi::to_hex(&bytes[..bytes.len().min(16)])
                ),
                None => "nothing".to_string(),
            };
            d.push(format!(
                "writes to globals differ ({} vs {} changed ranges): original {}, translation {}",
                a.len(),
                b.len(),
                describe(a.get(at)),
                describe(b.get(at))
            ));
        }
    } else if !orig.global_writes.is_empty() {
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
            Arg::Int { .. } | Arg::Double { .. } | Arg::Float { .. } | Arg::FnPtr { .. } => 1,
            Arg::Buf { data } => data.len(),
            Arg::Graph { objects, .. } => objects.iter().map(Vec::len).sum(),
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
    spec: &dyn InputSource,
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
    let runner: NativeRunner = match build_full(sig, rust_code, opts)? {
        Build::Ready(r) => r,
        Build::Rejected(reason) => {
            report.verdict = Verdict::Rejected { reason };
            return Ok(report);
        }
    };
    report.sandbox = runner.build_confinement.label();
    spec.check_shapes(sig)?;
    let mut faults = 0usize;
    for args in spec.cases(opts.seed, opts.random_cases) {
        let orig = oracle.call(entry, sig, &args)?;
        if let Termination::Unsupported { .. } = orig.termination {
            report.skipped += 1;
            continue;
        }
        let native = runner.run(&args)?;
        report.cases_run += 1;
        if matches!(orig.termination, Termination::Fault { .. }) {
            faults += 1;
        }
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
    } else if faults * 10 >= report.cases_run * 9 {
        // Both sides crashed on (nearly) every input: they agree, but nothing about the
        // function's logic was compared. Typical for a struct with pointers inside, which random
        // bytes cannot build.
        Verdict::Inconclusive {
            reason: format!(
                "the original faulted on {faults} of {} cases, so the inputs do not reach the \
                 function's logic; it needs a curated input generator",
                report.cases_run
            ),
        }
    } else {
        Verdict::Pass
    };
    Ok(report)
}

/// Lints and builds `rust_code` at `sig` without running a single case, for functions the oracle
/// cannot compare (or when the caller did not ask for the comparison). The verdict is `Rejected`
/// when the code is refused or does not compile and `Inconclusive` with `reason` when it builds:
/// compiling is not evidence that it is right.
pub fn compile_only(
    sig: &Signature,
    rust_code: &str,
    opts: &DiffOptions,
    reason: &str,
) -> Result<DiffReport, RewriteError> {
    let mut report = DiffReport {
        verdict: Verdict::Inconclusive {
            reason: reason.to_string(),
        },
        seed: opts.seed,
        cases_run: 0,
        passed: 0,
        skipped: 0,
        counterexamples: Vec::new(),
        cases: Vec::new(),
        sandbox: String::new(),
    };
    match build_full(sig, rust_code, opts)? {
        Build::Ready(r) => report.sandbox = r.build_confinement.label(),
        Build::Rejected(reason) => report.verdict = Verdict::Rejected { reason },
    }
    Ok(report)
}
