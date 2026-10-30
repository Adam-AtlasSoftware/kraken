//! Human control over rewrite units: the work behind `rewrite_reject`, `rewrite_unaccept`,
//! `rewrite_add_case`, `rewrite_spec_edit` and `rewrite_verify`.
//!
//! A replay rebuilds the stored Rust in the sandbox and runs every stored case on it, comparing
//! with what the oracle recorded for the original. The emulator is only needed to answer a new
//! case and to measure coverage; a replay without it still finds regressions.

use std::collections::BTreeSet;

use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use kraken_registry::commands::{
    CfgArgs, CfgCommand, CoverageView, Prereq, PrereqLevel, RewriteAddCaseArgs, RewriteCheckOut,
    RewriteRejectArgs, RewriteSpecEditArgs, RewriteSpecResult, RewriteUnaccept, RewriteVerifyArgs,
    RewriteVerifyResult, UnitChangeOut, UnitStatus,
};
use kraken_registry::{CallContext, Command, JobReporter, Session};
use serde_json::Value;

use super::{
    OracleThread, RewriteService, hex, invalid, progress, proto, render_arg, verdict_name,
    with_store,
};
use crate::abi::{Arg, Callback, Param, Signature};
use crate::difftest::{CaseRecord, Counterexample, DiffOptions, Verdict, compare};
use crate::error::RewriteError;
use crate::lift::Lift;
use crate::native::{Build, build_full};
use crate::oracle::FunctionOracle;
use crate::reuse::{ReusedCallee, prelude_with};
use crate::store::{NewSpec, Replay, RewriteStore, StoredSpec};
use crate::unit::{Coverage, RewriteUnit, sha256_hex};

fn not_found(id: &str) -> ProtoError {
    ProtoError::new(ErrorCode::NotFound, format!("no rewrite unit `{id}`"))
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn change_out(u: &RewriteUnit) -> UnitChangeOut {
    UnitChangeOut {
        status: u.status,
        unit: u.id.clone(),
        address: Hex64(hex(&u.anchor.address)),
        version: u.version,
    }
}

/// Reads one JSON value as the argument for `param`.
fn parse_arg(i: usize, param: &Param, v: &Value) -> Result<Arg, ProtoError> {
    let bad = |why: &str| invalid(format!("argument {} {why}", i + 1));
    if let Value::Object(o) = v
        && o.contains_key("kind")
    {
        return serde_json::from_value::<Arg>(v.clone()).map_err(|e| bad(&e.to_string()));
    }
    let int = |v: &Value| -> Option<u64> {
        match v {
            Value::Number(n) => n.as_u64().or_else(|| n.as_i64().map(|x| x as u64)),
            Value::String(s) => {
                let t = s.trim();
                match t.strip_prefix("0x") {
                    Some(h) => u64::from_str_radix(h, 16).ok(),
                    None => t
                        .parse::<u64>()
                        .ok()
                        .or_else(|| t.parse::<i64>().ok().map(|x| x as u64)),
                }
            }
            _ => None,
        }
    };
    match param {
        Param::Int { .. } => int(v)
            .map(|value| Arg::Int { value })
            .ok_or_else(|| bad("must be an integer (a number or a \"0x..\" string)")),
        Param::Double => v
            .as_f64()
            .map(|f| Arg::Double { bits: f.to_bits() })
            .ok_or_else(|| bad("must be a number")),
        Param::Float => v
            .as_f64()
            .map(|f| Arg::Float {
                bits: (f as f32).to_bits(),
            })
            .ok_or_else(|| bad("must be a number")),
        Param::FnPtr => match v.as_str() {
            Some("ascending") => Ok(Arg::FnPtr {
                callback: Callback::Ascending,
            }),
            Some("descending") => Ok(Arg::FnPtr {
                callback: Callback::Descending,
            }),
            _ => Err(bad("must be \"ascending\" or \"descending\"")),
        },
        Param::Buf => {
            if let Some(h) = v.get("hex").and_then(Value::as_str) {
                let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
                if !clean.len().is_multiple_of(2) || !clean.is_ascii() {
                    return Err(bad("has an odd or non-hex `hex` string"));
                }
                let data = (0..clean.len() / 2)
                    .map(|k| u8::from_str_radix(&clean[2 * k..2 * k + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| bad("has a non-hex digit in `hex`"))?;
                Ok(Arg::Buf { data })
            } else if let Some(t) = v.get("text").and_then(Value::as_str) {
                Ok(Arg::Buf {
                    data: t.as_bytes().to_vec(),
                })
            } else {
                Err(bad("must be {\"hex\": \"..\"} or {\"text\": \"..\"}"))
            }
        }
    }
}

/// The arguments of a case for `sig` from JSON values.
pub(crate) fn parse_case(sig: &Signature, values: &[Value]) -> Result<Vec<Arg>, ProtoError> {
    if values.len() != sig.params.len() {
        return Err(invalid(format!(
            "the function takes {} argument(s), {} given",
            sig.params.len(),
            values.len()
        )));
    }
    sig.params
        .iter()
        .zip(values)
        .enumerate()
        .map(|(i, (p, v))| parse_arg(i, p, v))
        .collect()
}

/// The callees `unit` called as accepted Rust, as the translation was tested with them: the
/// version recorded in the unit must still be the accepted one.
fn recorded_callees(
    store: &RewriteStore,
    unit: &RewriteUnit,
) -> Result<Vec<ReusedCallee>, RewriteError> {
    let mut all: Vec<ReusedCallee> = Vec::new();
    let mut seen = BTreeSet::new();
    collect_reused(store, unit, &mut all, &mut seen, 0)?;
    Ok(all)
}

fn collect_reused(
    store: &RewriteStore,
    unit: &RewriteUnit,
    out: &mut Vec<ReusedCallee>,
    seen: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), RewriteError> {
    if depth > 8 {
        return Err(RewriteError::Unsupported(
            "reused callees are nested too deeply".into(),
        ));
    }
    for c in unit.callees.iter().filter(|c| c.reused.is_some()) {
        let Some(r) = &c.reused else { continue };
        let Some(dep) = store.get(&r.unit)? else {
            return Err(RewriteError::Unsupported(format!(
                "the callee unit `{}` this version called is gone",
                r.unit
            )));
        };
        collect_reused(store, &dep, out, seen, depth + 1)?;
        if seen.insert(dep.id.clone()) {
            let requires = dep
                .callees
                .iter()
                .filter_map(|d| {
                    d.reused.as_ref().map(|ru| {
                        (
                            u64::from_str_radix(d.address.trim_start_matches("0x"), 16)
                                .unwrap_or(0),
                            ru.symbol.clone(),
                        )
                    })
                })
                .collect();
            out.push(ReusedCallee {
                name: c.name.clone(),
                address: u64::from_str_radix(c.address.trim_start_matches("0x"), 16).unwrap_or(0),
                decompile_hash: c.decompile_hash.clone(),
                reused: r.clone(),
                prototype: dep.rust_prototype.clone(),
                code: dep.rust_code.clone(),
                requires,
            });
        }
    }
    Ok(())
}

/// What a replay of the cases found, before it is stored.
struct Replayed {
    replay: Replay,
    sandbox: String,
}

/// Builds `unit`'s code and runs `cases` on it, comparing with the recorded results.
fn replay_cases(
    unit: &RewriteUnit,
    prelude: &str,
    cases: &[CaseRecord],
    opts: &DiffOptions,
) -> Result<Replayed, RewriteError> {
    let code = if prelude.is_empty() {
        unit.rust_code.clone()
    } else {
        format!("{prelude}\n{}", unit.rust_code)
    };
    let mut replay = Replay {
        verdict: Verdict::Pass,
        cases_run: 0,
        passed: 0,
        skipped: unit.summary.skipped,
        counterexamples: Vec::new(),
        coverage: None,
    };
    let runner = match build_full(&unit.signature, &code, opts)? {
        Build::Ready(r) => r,
        Build::Rejected(reason) => {
            replay.verdict = Verdict::Rejected { reason };
            return Ok(Replayed {
                replay,
                sandbox: String::new(),
            });
        }
    };
    let sandbox = runner.build_confinement.label();
    for case in cases {
        let native = runner.run(&case.args)?;
        replay.cases_run += 1;
        let differences = compare(&case.expected, &native);
        if differences.is_empty() {
            replay.passed += 1;
        } else {
            replay.counterexamples.push(Counterexample {
                args: case.args.clone(),
                original: case.expected.clone(),
                translation: native,
                differences,
            });
        }
    }
    replay.counterexamples.sort_by_key(|c| {
        c.args
            .iter()
            .map(|a| match a {
                Arg::Buf { data } => data.len(),
                _ => 1,
            })
            .sum::<usize>()
    });
    replay.counterexamples.truncate(opts.max_counterexamples);
    replay.verdict = if replay.cases_run == 0 {
        Verdict::Inconclusive {
            reason: "the version has no stored cases".into(),
        }
    } else if replay.passed < replay.cases_run {
        Verdict::Fail
    } else {
        Verdict::Pass
    };
    Ok(Replayed { replay, sandbox })
}

fn view_of(unit: &RewriteUnit, note: Option<String>, sandbox: String) -> RewriteVerifyResult {
    let (verdict, detail) = verdict_name(&unit.verdict);
    RewriteVerifyResult {
        unit: unit.id.clone(),
        address: Hex64(hex(&unit.anchor.address)),
        version: unit.version,
        status: unit.status,
        verdict: verdict.to_string(),
        verdict_detail: detail.map(Untrusted::sanitized),
        cases_run: count(unit.summary.cases_run),
        passed: count(unit.summary.passed),
        skipped: count(unit.summary.skipped),
        counterexample: unit.counterexamples.first().map(|c| {
            kraken_registry::commands::CounterexampleView {
                args: c.args.iter().map(render_arg).collect(),
                differences: c
                    .differences
                    .iter()
                    .map(|d| Untrusted::sanitized(d))
                    .collect(),
            }
        }),
        coverage: unit.coverage.as_ref().map(coverage_view),
        coverage_note: if unit.coverage.is_none() { note } else { None },
        user_cases: unit.user_cases,
        sandbox,
    }
}

/// The wire form of a stored coverage.
pub(crate) fn coverage_view(c: &Coverage) -> CoverageView {
    CoverageView {
        blocks: c.blocks,
        hit: c.hit,
        missed: c.missed.iter().map(|a| Hex64(*a)).collect(),
        cases: c.cases,
    }
}

impl RewriteService {
    pub(crate) async fn reject_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteRejectArgs,
    ) -> Result<UnitChangeOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let (sha, _) = Lift::new(s, ctx).program().map_err(proto)?;
        let actor = ctx.author.id.clone();
        let unit = with_store(dir, move |st| {
            let u = check_unit(st, &args.unit, &sha)?;
            match u.status {
                UnitStatus::Accepted => {
                    return Err(RewriteError::Command(invalid(format!(
                        "unit `{}` is accepted; unaccept it before rejecting it",
                        args.unit
                    ))));
                }
                UnitStatus::Failed => {
                    return Err(RewriteError::Command(invalid(format!(
                        "unit `{}` is already failed",
                        args.unit
                    ))));
                }
                _ => {}
            }
            st.reject(&args.unit, &actor, args.reason.as_deref())
        })
        .await?;
        Ok(change_out(&unit))
    }

    pub(crate) async fn unaccept_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteUnaccept,
    ) -> Result<UnitChangeOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let (sha, _) = Lift::new(s, ctx).program().map_err(proto)?;
        let actor = ctx.author.id.clone();
        let unit = with_store(dir, move |st| {
            let u = check_unit(st, &args.unit, &sha)?;
            if u.status != UnitStatus::Accepted {
                return Err(RewriteError::Command(invalid(format!(
                    "unit `{}` is {}, not accepted",
                    args.unit,
                    u.status.as_str()
                ))));
            }
            st.unaccept(&args.unit, &actor)
        })
        .await?;
        Ok(change_out(&unit))
    }

    pub(crate) async fn spec_edit_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecEditArgs,
    ) -> Result<RewriteSpecResult, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let lift = Lift::new(s, ctx);
        let (f, callees) = self.function_with_callees(&lift, args.address.0).await?;
        let task = super::function_spec_task(&f, &callees, &self.cfg.budget);
        let spec = task.parse(&args.markdown).map_err(proto)?;
        let source_hash = sha256_hex(
            &std::iter::once(f.decompile_hash.as_str())
                .chain(callees.iter().map(|c| c.decompile_hash.as_str()))
                .collect::<Vec<_>>()
                .join("|"),
        );
        let mut stored = StoredSpec {
            id: 0,
            scope: "function".into(),
            address: Some(format!("{:#x}", f.address)),
            markdown: spec.markdown,
            citations: spec.citations,
            facts: count(spec.facts),
            functions: count(task.functions.len()),
            source_hash,
            provider: "user".into(),
            model: "edit".into(),
            prompt_hash: String::new(),
        };
        let new = NewSpec {
            program_sha256: f.program_sha256.clone(),
            spec: stored.clone(),
        };
        stored.id = with_store(dir, move |st| st.put_spec(new)).await?;
        Ok(super::spec_result(
            &stored,
            kraken_registry::commands::PlanScope::Function,
            Some(f.address),
        ))
    }

    /// The body of `rewrite_verify` (`extra` is `None`) and of `rewrite_add_case`.
    pub(crate) async fn verify_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        unit_id: String,
        extra: Option<(Vec<Value>, Option<String>)>,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        self.require_sandbox_inner()?;
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let binary_path = project.meta().binary_path;
        let lift = Lift::new(s, ctx);
        let (sha, image_base) = lift.program().map_err(proto)?;
        progress(job, "load", 0, 5, "reading the unit");
        let (id2, sha2) = (unit_id.clone(), sha.clone());
        let unit = with_store(dir.clone(), move |st| check_unit(st, &id2, &sha2)).await?;
        if unit.rust_code.contains("rt::") {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                "this version belongs to a whole-program rewrite; replaying its cases needs the \
                 program image, which rewrite_verify does not set up yet",
            ));
        }
        let address = hex(&unit.anchor.address);
        let entry = unit.oracle.elf_vaddr;
        let sig = unit.signature.clone();
        let oracle_cfg = self.cfg.oracle.clone();
        let oracle = OracleThread::spawn(std::path::PathBuf::from(&binary_path), oracle_cfg);

        // Which blocks the function has: the coverage target, and the addresses to watch.
        let cfg_blocks: Option<Vec<u64>> = CfgCommand
            .run(
                s,
                ctx,
                CfgArgs {
                    function: Hex64(address),
                },
            )
            .await
            .ok()
            .map(|o| o.cfg.blocks.iter().map(|b| b.start.0).collect());
        let watch: Vec<u64> = cfg_blocks.clone().unwrap_or_default();
        let watch2 = watch.clone();
        // The first oracle job installs the watch; a load failure shows up here.
        let oracle_ready: Result<(), RewriteError> = oracle
            .run(move |o: &mut FunctionOracle| {
                let elf: Vec<u64> = watch2.iter().map(|a| o.elf_vaddr(*a, image_base)).collect();
                o.watch_addresses(&elf);
                Ok(())
            })
            .await;
        let mut note: Option<String> = None;
        if let Err(e) = &oracle_ready {
            note = Some(match e {
                RewriteError::NoProcessors => {
                    "the emulator needs the SLEIGH spec files (KRAKEN_NATIVE_SPECS or a Ghidra install)"
                        .to_string()
                }
                other => format!("the emulator could not be set up: {other}"),
            });
        }

        if let Some((values, case_note)) = extra {
            if oracle_ready.is_err() {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "a new case needs the emulator to run the original: {}",
                        note.unwrap_or_default()
                    ),
                ));
            }
            let args = parse_case(&sig, &values)?;
            progress(job, "case", 1, 5, "running the original on the new case");
            let (sig2, args2) = (sig.clone(), args.clone());
            let expected = oracle
                .run(move |o| o.call(entry, &sig2, &args2))
                .await
                .map_err(proto)?;
            if let crate::abi::Termination::Unsupported { detail } = &expected.termination {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!("the emulator cannot evaluate the original on this input: {detail}"),
                ));
            }
            let (id3, rec) = (unit_id.clone(), CaseRecord { args, expected });
            with_store(dir.clone(), move |st| {
                st.add_cases(&id3, std::slice::from_ref(&rec), case_note.as_deref())
            })
            .await?;
        }

        progress(
            job,
            "build",
            2,
            5,
            "building the Rust and replaying the cases",
        );
        let id4 = unit_id.clone();
        let (unit, prelude) = with_store(dir.clone(), move |st| {
            let u = st
                .get(&id4)?
                .ok_or_else(|| RewriteError::Command(not_found(&id4)))?;
            let callees = recorded_callees(st, &u)?;
            let prelude = prelude_with(&callees, &direct_of(&u, &callees), false);
            Ok((u, prelude))
        })
        .await?;
        let defaults = DiffOptions::default();
        let opts = DiffOptions {
            confinement: self.cfg.confinement.clone(),
            ..defaults
        };
        let (unit2, cases) = (unit.clone(), unit.test_cases.clone());
        let replayed =
            tokio::task::spawn_blocking(move || replay_cases(&unit2, &prelude, &cases, &opts))
                .await
                .map_err(|e| internal_task(&e))?
                .map_err(proto)?;
        let Replayed {
            mut replay,
            sandbox,
        } = replayed;

        // Coverage: run the cases through the oracle with the watch on.
        if oracle_ready.is_ok()
            && cfg_blocks.is_some()
            && !matches!(replay.verdict, Verdict::Rejected { .. })
        {
            progress(job, "coverage", 3, 5, "measuring what the cases reach");
            let cases: Vec<Vec<Arg>> = unit.test_cases.iter().map(|c| c.args.clone()).collect();
            let sig3 = sig.clone();
            let hit = oracle
                .run(move |o| {
                    let _ = o.take_watched();
                    let mut all: BTreeSet<u64> = BTreeSet::new();
                    for args in &cases {
                        o.call(entry, &sig3, args)?;
                        all.extend(o.take_watched());
                    }
                    Ok(all)
                })
                .await;
            match hit {
                Ok(hit) => {
                    let starts = cfg_blocks.clone().unwrap_or_default();
                    let mut missed = Vec::new();
                    let mut n_hit = 0u32;
                    for a in &starts {
                        let elf = if image_base != 0
                            && a >= &image_base
                            && unit_is_pie(&unit, image_base)
                        {
                            a - image_base
                        } else {
                            *a
                        };
                        if hit.contains(&elf) {
                            n_hit += 1;
                        } else {
                            missed.push(*a);
                        }
                    }
                    replay.coverage = Some(Coverage {
                        blocks: count(starts.len()),
                        hit: n_hit,
                        missed,
                        cases: count(unit.test_cases.len()),
                    });
                }
                Err(e) => note = Some(format!("coverage could not be measured: {e}")),
            }
        } else if cfg_blocks.is_none() && note.is_none() {
            note = Some("the engine has no control-flow graph for this function".into());
        }

        progress(job, "store", 4, 5, "storing the result");
        let actor = ctx.author.id.clone();
        let id5 = unit_id.clone();
        let stored = with_store(dir, move |st| st.record_replay(&id5, &replay, &actor)).await?;
        progress(job, "done", 5, 5, "finished");
        let sandbox = if sandbox.is_empty() {
            stored.summary.sandbox.clone()
        } else {
            sandbox
        };
        Ok(view_of(&stored, note, sandbox))
    }

    fn require_sandbox_inner(&self) -> Result<(), ProtoError> {
        use kraken_registry::commands::RewriteBackend;
        self.require_sandbox()
    }
}

/// Is the address of the function inside the image base the engine loaded? A position-
/// independent program's KRAKEN addresses include the image base; a fixed one's do not.
fn unit_is_pie(unit: &RewriteUnit, image_base: u64) -> bool {
    hex(&unit.anchor.address).wrapping_sub(image_base) == unit.oracle.elf_vaddr
}

/// The callees the unit called directly (those that are not only needed by other callees).
fn direct_of(unit: &RewriteUnit, all: &[ReusedCallee]) -> Vec<ReusedCallee> {
    all.iter()
        .filter(|r| {
            unit.callees
                .iter()
                .any(|c| c.reused.as_ref().is_some_and(|ru| ru.unit == r.reused.unit))
        })
        .cloned()
        .collect()
}

fn internal_task(e: &tokio::task::JoinError) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, format!("replay task failed: {e}"))
}

/// The unit `id`, which must belong to the program `sha`.
fn check_unit(st: &RewriteStore, id: &str, sha: &str) -> Result<RewriteUnit, RewriteError> {
    let Some(u) = st.get(id)? else {
        return Err(RewriteError::Command(not_found(id)));
    };
    if u.anchor.program_sha256 != sha {
        return Err(RewriteError::Command(invalid(
            "that unit was made for a different binary",
        )));
    }
    Ok(u)
}

impl RewriteService {
    pub(crate) async fn add_case_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAddCaseArgs,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        self.verify_job(s, ctx, args.unit, Some((args.args, args.note)), job)
            .await
    }

    pub(crate) async fn verify_unit_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteVerifyArgs,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        self.verify_job(s, ctx, args.unit, None, job).await
    }
}

/// What the first bytes of a program file say it is.
fn program_kind(head: &[u8]) -> (String, bool) {
    let le16 = |at: usize| {
        head.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    if head.starts_with(b"\x7fELF") {
        let bits = match head.get(4) {
            Some(1) => "32-bit",
            Some(2) => "64-bit",
            _ => "",
        };
        let machine = match le16(0x12) {
            Some(62) => "x86-64",
            Some(3) => "x86",
            Some(40) => "ARM",
            Some(183) => "AArch64",
            Some(243) => "RISC-V",
            _ => "an unknown architecture",
        };
        let ok = machine == "x86-64" && bits == "64-bit";
        (format!("a Linux {bits} ELF program for {machine}"), ok)
    } else if head.starts_with(b"MZ") {
        ("a Windows PE program".into(), false)
    } else if head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        ("a macOS Mach-O program".into(), false)
    } else {
        ("a file of an unknown kind".into(), false)
    }
}

fn prereq(
    id: &str,
    title: &str,
    level: PrereqLevel,
    detail: impl Into<String>,
    fix: Option<&str>,
) -> Prereq {
    Prereq {
        id: id.into(),
        title: title.into(),
        level,
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

impl RewriteService {
    /// The rows of `rewrite_check`.
    pub(crate) async fn check_prereqs(
        &self,
        s: &Session,
        ctx: &CallContext,
    ) -> Result<RewriteCheckOut, ProtoError> {
        let mut checks = Vec::new();
        checks.push(if crate::sandbox::enforced() {
            prereq(
                "sandbox",
                "Sandbox",
                PrereqLevel::Ok,
                "Generated code is built and run confined: Landlock, no network, limited time and memory.",
                None,
            )
        } else {
            prereq(
                "sandbox",
                "Sandbox",
                PrereqLevel::Blocked,
                "This computer cannot confine generated code (Landlock ABI 4 or newer and a network barrier are needed).",
                Some("Use Linux 6.7 or newer. There is no setting to run generated code unconfined."),
            )
        });
        let tool = tokio::task::spawn_blocking(|| {
            let t = crate::sandbox::toolchain()?;
            let v = std::process::Command::new(&t.rustc)
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            Ok::<_, RewriteError>(v)
        })
        .await
        .unwrap_or_else(|e| Err(RewriteError::Compile(format!("probe failed: {e}"))));
        checks.push(match tool {
            Ok(v) => prereq(
                "toolchain",
                "Rust toolchain",
                PrereqLevel::Ok,
                if v.is_empty() {
                    "rustc and cargo were found.".to_string()
                } else {
                    format!("{v}; cargo was found.")
                },
                None,
            ),
            Err(e) => prereq(
                "toolchain",
                "Rust toolchain",
                PrereqLevel::Blocked,
                format!("The generated code is built with rustc and cargo, which could not be run: {e}"),
                Some("Run setup_rust (`kraken setup --rust`, or Help > Setup status): KRAKEN installs its own toolchain in its data directory and leaves ~/.cargo alone. Or install Rust with rustup (https://rustup.rs) so that `rustc` and `cargo` are on PATH."),
            ),
        });
        let specs = crate::oracle::find_processors(&self.cfg.oracle);
        checks.push(match specs {
            Ok(_) => prereq(
                "specs",
                "Spec files",
                PrereqLevel::Ok,
                "The SLEIGH files the emulator runs the original with were found.",
                None,
            ),
            Err(_) => prereq(
                "specs",
                "Spec files",
                PrereqLevel::Warn,
                "The SLEIGH spec files were not found, so the original cannot be run for comparison: a translation is only built, never checked against the program.",
                Some("Run `kraken setup --native`, or `cargo xtask native-sla` in a source checkout, or point KRAKEN_NATIVE_SPECS at a compiled tree."),
            ),
        });
        let program = match Lift::new(s, ctx).binary() {
            Ok((path, _)) => {
                let head = tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut buf = vec![0u8; 64];
                    let n = std::fs::File::open(&path)
                        .and_then(|mut f| f.read(&mut buf))
                        .unwrap_or(0);
                    buf.truncate(n);
                    buf
                })
                .await
                .unwrap_or_default();
                let (what, ok) = program_kind(&head);
                if ok {
                    prereq(
                        "program",
                        "Program",
                        PrereqLevel::Ok,
                        format!("This is {what}, the kind that can be rewritten."),
                        None,
                    )
                } else {
                    prereq(
                        "program",
                        "Program",
                        PrereqLevel::Blocked,
                        format!(
                            "This is {what}. The rewrite handles Linux x86-64 ELF programs today."
                        ),
                        Some(
                            "Open a Linux x86-64 program, or use the decompiler and the patch tools for this one.",
                        ),
                    )
                }
            }
            Err(_) => prereq(
                "program",
                "Program",
                PrereqLevel::Blocked,
                "No program is open.",
                Some("Open or create a project first."),
            ),
        };
        checks.push(program);
        let ready = checks.iter().all(|c| c.level != PrereqLevel::Blocked);
        Ok(RewriteCheckOut { checks, ready })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Param, Ret};

    fn sig() -> Signature {
        Signature {
            name: "f".into(),
            params: vec![
                Param::Int {
                    bits: 32,
                    signed: true,
                },
                Param::Buf,
            ],
            ret: Ret::Void,
        }
    }

    #[test]
    fn the_program_kind_comes_from_the_header() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[0x12] = 62;
        assert!(program_kind(&elf).1);
        elf[0x12] = 183;
        let (what, ok) = program_kind(&elf);
        assert!(!ok && what.contains("AArch64"), "{what}");
        assert!(!program_kind(b"MZ\x90\x00").1);
        assert!(program_kind(b"MZ\x90\x00").0.contains("PE"));
    }

    #[test]
    fn case_values_follow_the_signature() {
        let args = parse_case(
            &sig(),
            &[serde_json::json!(-3), serde_json::json!({"text": "ab"})],
        )
        .expect("case");
        assert_eq!(
            args,
            vec![
                Arg::Int {
                    value: (-3i64) as u64
                },
                Arg::Buf {
                    data: b"ab".to_vec()
                }
            ]
        );
        let hex = parse_case(
            &sig(),
            &[
                serde_json::json!("0x10"),
                serde_json::json!({"hex": "00 ff"}),
            ],
        )
        .expect("hex");
        assert_eq!(hex[0], Arg::Int { value: 16 });
        assert_eq!(hex[1], Arg::Buf { data: vec![0, 255] });
        assert!(parse_case(&sig(), &[serde_json::json!(1)]).is_err());
        assert!(
            parse_case(
                &sig(),
                &[serde_json::json!("x"), serde_json::json!({"hex": "0"})]
            )
            .is_err()
        );
    }
}
