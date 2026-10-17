//! `rewrite_program` and `rewrite_program_status` (ADR 0013): the whole-program mode of
//! [`RewriteService`].
//!
//! The run, in order: plan the program bottom-up; translate each function with the shared
//! translate-check-repair loop, giving every function the translations already made for its
//! callees; write a standalone crate from the chosen translations; build it in the sandbox; run
//! the original and the rewrite on the same inputs and compare. The function-level verdicts
//! decide which translations are used (a failed one is not); the program-level verdict is the
//! only one that says the program as a whole behaves the same.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};

use kraken_registry::commands::{
    ProgramFunctionRow, RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatusArgs,
    RewriteProgramStatusOut,
};

use super::*;
use crate::infer::infer_signature_for_program;
use crate::pipeline::COMPILE_ONLY_KIND;
use crate::process::{CaseSeed, corpus_source, derive_cases};
use crate::program::{
    AssembleInfo, ProgramVerdict, ProgramVerdictKind, assemble, build_program, check_target,
    verify_program,
};
use crate::reuse::ReusedCallee;
use crate::targets::curated;

/// Most callees without a usable translation that one translation is asked to include.
const MAX_INLINE: usize = 12;
/// Default number of generated program-level cases.
const DEFAULT_GENERATED_CASES: u32 = 8;
/// Runs listed by `rewrite_program_status`.
const LISTED_RUNS: u32 = 20;

const ENTRY_NOTE: &str = "This function is the program's `main`. The generated program calls \
it once, with argc, argv and envp built as the C runtime builds them, and exits with its return \
value. Everything the program prints goes to the real standard output and standard error.";

const CAST_NOTE: &str = "Every translated function is its own Rust module with its own struct \
definitions. When you call another translated function, cast pointer arguments with `as _` \
(for example `callee(ps as _, n)`), because its pointer parameter types are not the same Rust \
type as yours.";

fn parse_addr(a: &str) -> u64 {
    u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn sha256_bytes(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The unit chosen for the function at `address` (`0x...`), unless it failed.
fn chosen_unit(
    st: &RewriteStore,
    chosen: &BTreeMap<u64, String>,
    address: &str,
) -> Result<Option<RewriteUnit>, RewriteError> {
    let Some(id) = chosen.get(&parse_addr(address)) else {
        return Ok(None);
    };
    Ok(st.get(id)?.filter(|u| u.status != UnitStatus::Failed))
}

/// The row of a function with no usable translation.
fn row_without_unit(
    order: u32,
    p: &PlannedFunction,
    status: UnitStatus,
    check: &str,
    note: &str,
    attempts: u32,
) -> ProgramFunctionRow {
    ProgramFunctionRow {
        order,
        address: Hex64(p.address),
        name: Untrusted::sanitized(&p.name),
        unit: String::new(),
        version: 0,
        status,
        verdict: "none".into(),
        check: check.into(),
        check_note: (!note.is_empty()).then(|| Untrusted::sanitized(note)),
        attempts,
        reused_callees: Vec::new(),
        included: false,
    }
}

fn row_for_unit(
    order: u32,
    p: &PlannedFunction,
    u: &RewriteUnit,
    check: &str,
    attempts: u32,
) -> ProgramFunctionRow {
    let (verdict, detail) = verdict_name(&u.verdict);
    ProgramFunctionRow {
        order,
        address: Hex64(p.address),
        name: Untrusted::sanitized(&p.name),
        unit: u.id.clone(),
        version: u.version,
        status: u.status,
        verdict: verdict.to_string(),
        check: check.into(),
        check_note: detail.map(Untrusted::sanitized),
        attempts,
        reused_callees: reused_symbols(u),
        included: false,
    }
}

impl RewriteService {
    /// The function with the decompile `address` belongs to, read once per run.
    async fn context_of(
        &self,
        lift: &Lift<'_>,
        cache: &mut BTreeMap<u64, FunctionContext>,
        address: u64,
    ) -> Result<FunctionContext, ProtoError> {
        if let Some(f) = cache.get(&address) {
            return Ok(f.clone());
        }
        let f = lift.function(address).await.map_err(proto)?;
        cache.insert(address, f.clone());
        Ok(f)
    }

    /// The entry point: the given address, else `main`, else the function that
    /// `__libc_start_main` is handed in the decompile of `entry` / `_start`.
    async fn find_entry(
        &self,
        lift: &Lift<'_>,
        plan: &StoredPlan,
        given: Option<Hex64>,
    ) -> Result<u64, ProtoError> {
        if let Some(a) = given {
            let f = lift.listed(a.0).await.map_err(proto)?;
            return plan
                .entries
                .iter()
                .find(|p| p.address == f.address)
                .map(|p| p.address)
                .ok_or_else(|| invalid(format!("`{}` is not a function of the plan", f.name)));
        }
        if let Some(p) = plan.entries.iter().find(|p| p.name == "main") {
            return Ok(p.address);
        }
        let (all, _) = lift
            .functions(MAX_PLAN_FUNCTIONS as usize)
            .await
            .map_err(proto)?;
        for start in all
            .iter()
            .filter(|f| matches!(f.name.as_str(), "entry" | "_start"))
        {
            let text = lift.function(start.address).await.map_err(proto)?.decompile;
            let Some(i) = text.find("__libc_start_main(") else {
                continue;
            };
            let arg: String = text[i + "__libc_start_main(".len()..]
                .split(',')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if let Some(p) = plan.entries.iter().find(|p| p.name == arg) {
                return Ok(p.address);
            }
            if let Some(hex) = arg.strip_prefix("FUN_")
                && let Ok(a) = u64::from_str_radix(hex, 16)
                && let Some(p) = plan.entries.iter().find(|p| p.address == a)
            {
                return Ok(p.address);
            }
        }
        Err(invalid(
            "cannot tell which function is `main`; pass `entry` (the program has no function \
             named `main`, and the decompile of its entry stub does not name one)",
        ))
    }

    /// The body of a `rewrite_program` job.
    pub(crate) async fn run_program(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteProgramArgs,
        job: &JobReporter,
    ) -> Result<RewriteProgramResult, ProtoError> {
        self.require_sandbox()?;
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let binary_path = PathBuf::from(project.meta().binary_path);
        let lift = Lift::new(s, ctx);
        let (sha, _) = lift.program().map_err(proto)?;
        // The command refuses `accept_verified` from anything but a user before the job starts.
        let accept = args.accept_verified == Some(true);
        let verify_functions = args.verify_functions.unwrap_or(true);
        let build = args.build.unwrap_or(true);
        let out_dir = {
            let given = PathBuf::from(
                args.dir
                    .clone()
                    .unwrap_or_else(|| kraken_registry::commands::DEFAULT_PROGRAM_DIR.into()),
            );
            if given.is_absolute() {
                given
            } else {
                dir.join(given)
            }
        };
        {
            let out2 = out_dir.clone();
            tokio::task::spawn_blocking(move || check_target(&out2))
                .await
                .map_err(|e| internal(format!("check task failed: {e}")))?
                .map_err(|e| invalid(e.to_string()))?;
        }
        // The program that runs as "the original" must be the one that was analysed.
        let on_disk = std::fs::read(&binary_path)
            .map_err(|e| invalid(format!("cannot read {}: {e}", binary_path.display())))?;
        if !sha256_bytes(&on_disk).eq_ignore_ascii_case(&sha) {
            return Err(invalid(format!(
                "{} is not the binary this project analysed (SHA-256 differs); the program-level \
                 test would compare against the wrong program",
                binary_path.display()
            )));
        }
        drop(on_disk);
        let binary_file = file_name(&binary_path.display().to_string());

        // 1. Plan.
        progress(job, "plan", 0, 1, "ordering the functions");
        let collected = collect(s, ctx, MAX_PLAN_FUNCTIONS as usize)
            .await
            .map_err(proto)?;
        let plan = to_plan(&collected);
        if plan.truncated {
            return Err(unsupported(format!(
                "the program has more than {MAX_PLAN_FUNCTIONS} functions"
            )));
        }
        if plan.entries.is_empty() {
            return Err(invalid("the program has no functions to rewrite"));
        }
        {
            let (sha2, p2) = (sha.clone(), plan.clone());
            with_store(dir.clone(), move |st| st.save_plan(&sha2, &p2)).await?;
        }
        let entry_addr = self.find_entry(&lift, &plan, args.entry).await?;
        let entry_name = plan
            .entries
            .iter()
            .find(|p| p.address == entry_addr)
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let by_addr: BTreeMap<u64, &PlannedFunction> =
            plan.entries.iter().map(|p| (p.address, p)).collect();

        // What the entry point reaches by direct calls; the rest (glue in a binary without
        // names, dead code) is left alone.
        let reachable: BTreeSet<u64> = {
            let mut seen = BTreeSet::from([entry_addr]);
            let mut queue = VecDeque::from([entry_addr]);
            while let Some(a) = queue.pop_front() {
                for c in by_addr.get(&a).map_or(&[][..], |p| p.callees.as_slice()) {
                    if seen.insert(*c) {
                        queue.push_back(*c);
                    }
                }
            }
            seen
        };

        // 2. Translate, callees first.
        let provider = self.providers.provider()?;
        let provider_info = provider.info();
        let defaults = DiffOptions::default();
        let opts = DiffOptions {
            seed: args.seed.unwrap_or(defaults.seed),
            random_cases: args.cases.map_or(defaults.random_cases, |c| c as usize),
            confinement: self.cfg.confinement.clone(),
            ..defaults
        };
        let max_attempts = args.max_attempts.unwrap_or(self.cfg.max_attempts);
        let oracle = OracleThread::spawn(binary_path.clone(), self.cfg.oracle.clone());
        let actor = ctx.author.id.clone();
        let total = plan.entries.len() as u64;
        let mut chosen: BTreeMap<u64, String> = BTreeMap::new();
        let mut rows: Vec<ProgramFunctionRow> = Vec::new();
        let mut cache: BTreeMap<u64, FunctionContext> = BTreeMap::new();
        let (mut translated, mut from_store) = (0u32, 0u32);
        for (i, p) in plan.entries.iter().enumerate() {
            if job.cancel_token().is_cancelled() {
                return Err(ProtoError::new(ErrorCode::Cancelled, "job cancelled"));
            }
            progress(job, "translate", i as u64, total, &p.name);
            let order = p.order;
            if !reachable.contains(&p.address) {
                rows.push(row_without_unit(
                    order,
                    p,
                    UnitStatus::Planned,
                    "skipped",
                    "the entry point does not reach this function by direct calls",
                    0,
                ));
                continue;
            }
            let f = self.context_of(&lift, &mut cache, p.address).await?;

            // An accepted translation made from this decompile, with its callees as they are.
            {
                let (sha2, addr, hash, cm) = (
                    sha.clone(),
                    format!("{:#x}", p.address),
                    f.decompile_hash.clone(),
                    chosen.clone(),
                );
                let stored = with_store(dir.clone(), move |st| {
                    let Some(u) = st.accepted(&sha2, &addr)? else {
                        return Ok(None);
                    };
                    let consistent = u.source_decompile_hash == hash
                        && u.callees
                            .iter()
                            .filter_map(|c| c.reused.as_ref().map(|r| (c, r)))
                            .all(|(c, r)| {
                                cm.get(&parse_addr(&c.address))
                                    .is_some_and(|id| *id == r.unit)
                            });
                    Ok(consistent.then_some(u))
                })
                .await?;
                if let Some(u) = stored {
                    chosen.insert(p.address, u.id.clone());
                    rows.push(row_for_unit(order, p, &u, "stored", 0));
                    from_store += 1;
                    continue;
                }
            }

            let rname = rust_name(&f.name, f.address);
            let Some(sig_text) = f.signature.clone() else {
                rows.push(row_without_unit(
                    order,
                    p,
                    UnitStatus::Failed,
                    "none",
                    "the function has no signature; set one with set_type before rewriting",
                    0,
                ));
                continue;
            };
            let (signature, ptr_note) = match infer_signature_for_program(&sig_text, &rname) {
                Ok(x) => x,
                Err(e) => {
                    rows.push(row_without_unit(
                        order,
                        p,
                        UnitStatus::Failed,
                        "none",
                        &format!("cannot translate yet: {e}"),
                        0,
                    ));
                    continue;
                }
            };
            let curated = curated(&binary_file, &f.name);
            let check = if !verify_functions {
                Check::CompileOnly("the function-level differential test was not requested".into())
            } else if let Some(n) = ptr_note {
                Check::CompileOnly(n)
            } else {
                Check::Differential
            };
            let (inputs, mut notes) = match curated {
                Some(c) => (c.inputs, c.notes),
                None => (generic_inputs(&signature), generic_notes(&signature)),
            };
            if p.address == entry_addr {
                notes.push_str(&format!("\n\n{ENTRY_NOTE}"));
            }
            notes.push_str(&format!("\n\n{}\n\n{CAST_NOTE}", crate::RT_PROMPT));

            // What the translation includes (callees without a usable translation, with the
            // callees of those in turn) and what it calls (callees that have one).
            let mut inline: Vec<FunctionContext> = Vec::new();
            let mut all: Vec<ReusedCallee> = Vec::new();
            let mut direct: Vec<ReusedCallee> = Vec::new();
            let mut visited: BTreeSet<u64> = BTreeSet::from([p.address]);
            let mut queue: VecDeque<u64> = p.callees.iter().copied().collect();
            let mut too_many = false;
            while let Some(a) = queue.pop_front() {
                if !visited.insert(a) {
                    continue;
                }
                let c = self.context_of(&lift, &mut cache, a).await?;
                let (sha2, cm, c2, own) = (sha.clone(), chosen.clone(), c.clone(), p.address);
                let r = with_store(dir.clone(), move |st| {
                    reuse::resolve_with(
                        &|addr| chosen_unit(st, &cm, addr),
                        &sha2,
                        own,
                        std::slice::from_ref(&c2),
                    )
                })
                .await?;
                if r.direct.is_empty() {
                    inline.push(c);
                    if inline.len() > MAX_INLINE {
                        too_many = true;
                        break;
                    }
                    if let Some(pc) = by_addr.get(&a) {
                        queue.extend(pc.callees.iter().copied());
                    }
                } else {
                    for x in r.all {
                        if !all.iter().any(|y| y.address == x.address) {
                            all.push(x);
                        }
                    }
                    for x in r.direct {
                        if !direct.iter().any(|y| y.address == x.address) {
                            direct.push(x);
                        }
                    }
                }
            }
            if too_many {
                rows.push(row_without_unit(
                    order,
                    p,
                    UnitStatus::Failed,
                    "none",
                    &format!(
                        "more than {MAX_INLINE} callees have no usable translation yet, too many \
                         to translate together with this function"
                    ),
                    0,
                ));
                continue;
            }
            {
                let seen: Vec<(String, String)> = visited
                    .iter()
                    .filter_map(|a| cache.get(a))
                    .map(|c| (format!("{:#x}", c.address), c.decompile_hash.clone()))
                    .collect();
                let sha2 = sha.clone();
                with_store(dir.clone(), move |st| st.observe(&sha2, &seen)).await?;
            }
            let task = RewriteTask {
                function: f.clone(),
                callees: inline.clone(),
                signature: signature.clone(),
                layout_notes: notes,
                spec: None,
                reused: direct.clone(),
                repairs: Vec::new(),
                budget: self.cfg.budget.clone(),
            };
            let work = Work {
                function: f.clone(),
                signature,
                inputs,
                task,
                reuse: Resolved {
                    direct,
                    all,
                    remaining: inline,
                },
                mode: RewriteMode::Incremental,
                spec_id: None,
                check,
                shim: true,
                opts: opts.clone(),
                max_attempts,
            };
            let run = match self
                .translate(
                    work,
                    &dir,
                    &binary_path.display().to_string(),
                    provider.as_ref(),
                    &oracle,
                    None,
                )
                .await
            {
                Ok(run) => run,
                // A reply that could not be used is this function's failure; anything else (the
                // provider is down, the job was cancelled) ends the run.
                Err(RewriteError::Output(why)) => {
                    rows.push(row_without_unit(
                        order,
                        p,
                        UnitStatus::Failed,
                        "none",
                        &format!("the model's reply could not be used: {why}"),
                        1,
                    ));
                    continue;
                }
                Err(e) => return Err(proto(e)),
            };
            translated += 1;
            let attempts = u32::try_from(run.attempts.len()).unwrap_or(u32::MAX);
            let (last, _) = run.last();
            let mut unit = last.clone();
            if accept && unit.status == UnitStatus::Verified {
                let (id, who) = (unit.id.clone(), actor.clone());
                let (accepted, _) = with_store(dir.clone(), move |st| st.accept(&id, &who)).await?;
                unit = accepted;
            }
            let kind = if unit.oracle.kind == COMPILE_ONLY_KIND {
                "compile_only"
            } else {
                "differential"
            };
            if unit.status != UnitStatus::Failed {
                chosen.insert(p.address, unit.id.clone());
            }
            rows.push(row_for_unit(order, p, &unit, kind, attempts));
        }

        // 3. The functions the program needs: the entry and what its translation calls.
        let verdict: ProgramVerdict;
        let mut crate_dir = String::new();
        let mut crate_sha256 = String::new();
        let mut built = false;
        let needed = {
            let (cm, entry) = (chosen.clone(), entry_addr);
            with_store(dir.clone(), move |st| {
                let mut done: BTreeMap<u64, RewriteUnit> = BTreeMap::new();
                let mut need = vec![entry];
                while let Some(a) = need.pop() {
                    if done.contains_key(&a) {
                        continue;
                    }
                    let Some(u) = chosen_unit(st, &cm, &format!("{a:#x}"))? else {
                        return Ok(Err(a));
                    };
                    need.extend(
                        u.callees
                            .iter()
                            .filter(|c| c.reused.is_some())
                            .map(|c| parse_addr(&c.address)),
                    );
                    done.insert(a, u);
                }
                Ok(Ok(done))
            })
            .await?
        };
        match needed {
            Err(missing) => {
                let name = by_addr.get(&missing).map_or("?", |p| p.name.as_str());
                verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Incomplete(format!(
                    "`{name}` is needed by the program and has no usable translation"
                )));
            }
            Ok(units) => {
                for r in &mut rows {
                    r.included = units.contains_key(&r.address.0);
                }
                let entry_unit = units[&entry_addr].clone();
                let list: Vec<RewriteUnit> = units.into_values().collect();
                // 4. Write the crate.
                progress(job, "assemble", 0, 1, "writing the Rust crate");
                let binary_name = binary_file.clone();
                let (sha2, out2) = (sha.clone(), out_dir.clone());
                let assembled = tokio::task::spawn_blocking(move || {
                    assemble(
                        &out2,
                        &AssembleInfo {
                            binary_name: &binary_name,
                            program_sha256: &sha2,
                        },
                        &entry_unit,
                        &list,
                    )
                })
                .await
                .map_err(|e| internal(format!("assemble task failed: {e}")))?;
                match assembled {
                    Err(e) => {
                        verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Incomplete(
                            format!("cannot write the crate: {e}"),
                        ));
                    }
                    Ok(a) => {
                        crate_dir = out_dir.display().to_string();
                        crate_sha256 = a.crate_sha256.clone();
                        if !build {
                            verdict =
                                ProgramVerdict::without_cases(ProgramVerdictKind::Inconclusive(
                                    "the crate was written but not built or run (`build` was off)"
                                        .into(),
                                ));
                        } else {
                            // 5. Build and verify.
                            progress(job, "build", 0, 1, "building the crate in the sandbox");
                            let (out2, bin, conf) = (
                                out_dir.clone(),
                                a.bin_name.clone(),
                                self.cfg.confinement.clone(),
                            );
                            let built_program = tokio::task::spawn_blocking(move || {
                                build_program(&out2, &bin, &conf)
                            })
                            .await
                            .map_err(|e| internal(format!("build task failed: {e}")))?;
                            match built_program {
                                Err(RewriteError::Compile(why)) => {
                                    verdict = ProgramVerdict::without_cases(
                                        ProgramVerdictKind::Incomplete(why),
                                    );
                                }
                                Err(e) => return Err(proto(e)),
                                Ok(bp) => {
                                    built = true;
                                    let source = corpus_source(&binary_path);
                                    let cases = derive_cases(&CaseSeed {
                                        source: source.as_ref().map(|(_, t)| t.as_str()),
                                        seed: opts.seed,
                                        generated: args
                                            .generated_cases
                                            .unwrap_or(DEFAULT_GENERATED_CASES)
                                            as usize,
                                        user: &args.inputs,
                                    });
                                    let n = cases.len();
                                    progress(job, "verify", 0, n as u64, "running both programs");
                                    let (orig, conf, job2) = (
                                        binary_path.clone(),
                                        self.cfg.confinement.clone(),
                                        job.clone(),
                                    );
                                    verdict = tokio::task::spawn_blocking(move || {
                                        let cancel = job2.cancel_token();
                                        let v = verify_program(
                                            &orig,
                                            &bp.exe,
                                            &cases,
                                            &conf,
                                            &|done, total| {
                                                progress(
                                                    &job2,
                                                    "verify",
                                                    done as u64,
                                                    total as u64,
                                                    "running both programs",
                                                );
                                                !cancel.is_cancelled()
                                            },
                                        );
                                        drop(bp);
                                        v
                                    })
                                    .await
                                    .map_err(|e| internal(format!("verify task failed: {e}")))?
                                    .map_err(proto)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        let functions_planned = u32::try_from(rows.len()).unwrap_or(u32::MAX);
        let included = u32::try_from(rows.iter().filter(|r| r.included).count()).unwrap_or(0);
        let skipped =
            u32::try_from(rows.iter().filter(|r| r.check == "skipped").count()).unwrap_or(0);
        let failed = u32::try_from(
            rows.iter()
                .filter(|r| {
                    r.check != "skipped" && (r.unit.is_empty() || r.status == UnitStatus::Failed)
                })
                .count(),
        )
        .unwrap_or(0);
        let result = RewriteProgramResult {
            run: 0,
            program_sha256: sha.clone(),
            entry: Hex64(entry_addr),
            entry_name: Untrusted::sanitized(&entry_name),
            functions_planned,
            skipped,
            translated,
            reused_from_store: from_store,
            failed,
            included,
            functions: rows,
            crate_dir,
            built,
            crate_sha256,
            provider: provider_info.id,
            model: provider_info.model,
            created: 0,
            verdict: verdict.view(),
        };
        progress(job, "store", 0, 1, "storing the result");
        let sha2 = sha;
        let stored = with_store(dir, move |st| st.put_program_run(&sha2, result)).await?;
        progress(job, "done", 1, 1, "finished");
        Ok(stored)
    }

    /// `rewrite_program_status`.
    pub(crate) async fn run_program_status(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteProgramStatusArgs,
    ) -> Result<RewriteProgramStatusOut, ProtoError> {
        let project = s.project()?;
        let (sha, _) = Lift::new(s, ctx).program().map_err(proto)?;
        let (sha2, run) = (sha.clone(), args.run);
        let (runs, mut shown) = with_store(project.dir().to_path_buf(), move |st| {
            Ok((
                st.program_runs(&sha2, LISTED_RUNS)?,
                st.program_run(&sha2, run)?,
            ))
        })
        .await?;
        if shown.is_none()
            && let Some(id) = args.run
        {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no program rewrite run {id} for this binary"),
            ));
        }
        if !args.all_cases
            && let Some(r) = shown.as_mut()
        {
            r.verdict.cases.retain(|c| !c.agree);
        }
        Ok(RewriteProgramStatusOut {
            program_sha256: sha,
            present: !runs.is_empty(),
            runs,
            run: shown,
        })
    }
}
