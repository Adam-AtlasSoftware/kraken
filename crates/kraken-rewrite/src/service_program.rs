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
use std::sync::Arc;

use sha2::{Digest, Sha256};

use kraken_registry::commands::{
    DEFAULT_REPAIR_ROUNDS, MAX_REPAIR_ROUNDS, ProgramFunctionRow, ProgramRepairView,
    RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatusArgs, RewriteProgramStatusOut,
};

use super::*;
use crate::blame::{
    Candidate, FeedbackInput, TraceSpec, feedback_text, parse_stack, rank, trace_for,
};
use crate::collect::collect_program;
use crate::export::cargo_build_with;
use crate::image::ProgramImage;
use crate::infer::{infer_signature_for_program, program_names, qualified_name};
use crate::native::RunnerImage;
use crate::pipeline::COMPILE_ONLY_KIND;
use crate::process::{CaseSeed, ProgramCase, corpus_source, derive_cases, run_case_with_env};
use crate::program::{
    AssembleInfo, ProgramVerdict, ProgramVerdictKind, assemble, build_program, check_target,
    verify_program,
};
use crate::repair::{Feedback, MAX_FEEDBACK, RepairRound, cut_text, previous_code};
use crate::reuse::ReusedCallee;
use crate::targets::curated;

/// Most callees without a usable translation that one translation is asked to include. Callees
/// are translated first, and a translation that only fails its function-level check is usable,
/// so this is reached only by recursion through functions that cannot be translated at all.
const MAX_INLINE: usize = 24;
/// Output budget of one translation in a program run: a whole `main` is long.
const PROGRAM_MAX_TOKENS: u32 = 16_384;
/// Default number of generated program-level cases.
const DEFAULT_GENERATED_CASES: u32 = 8;
/// Runs listed by `rewrite_program_status`.
const LISTED_RUNS: u32 = 20;
/// Functions translated again in one program-level repair round.
const SUSPECTS_PER_ROUND: usize = 3;
/// Translation attempts per function in a program-level repair round.
const REPAIR_ATTEMPTS: u32 = 2;

const TAKEN_NOTE_HEAD: &str = "This function takes the address of other functions of the \
program without calling them: they are handed to another function as callbacks or stored in a \
table (a decompile shows such a table as a global like `main::orders`, whose entries are \
functions): ";

fn taken_note(names: &[String]) -> String {
    format!(
        "{TAKEN_NOTE_HEAD}{}. Where the decompile uses such a pointer, pass the translated \
         function itself as a function pointer of the shape its callee expects, for example \
         `Some(name as unsafe extern \"C\" fn(*mut u8, *mut u8) -> i32)`; a table of them is a \
         `static` array of those pointers, in the order of the original table. Do not call them \
         unless the decompile does.",
        names.join(", ")
    )
}

fn cut_feedback(text: &str) -> String {
    cut_text(text, MAX_FEEDBACK)
}

/// What one program run keeps while it translates and repairs.
struct ProgramRun<'a> {
    lift: Lift<'a>,
    sha: String,
    dir: PathBuf,
    binary_path: PathBuf,
    binary_file: String,
    plan: StoredPlan,
    /// Functions whose address a function takes (see `collect::address_taken`).
    taken: BTreeMap<u64, BTreeSet<u64>>,
    entry_addr: u64,
    backend: Arc<dyn AssistBackend>,
    oracle: OracleThread,
    opts: DiffOptions,
    max_attempts: u32,
    verify_functions: bool,
    accept: bool,
    actor: String,
    cache: BTreeMap<u64, FunctionContext>,
    /// The Rust name of every function of the plan (unique; C++ methods carry their class).
    names: BTreeMap<u64, String>,
    /// The original program's data, which the translations reach their globals through.
    image: Option<Arc<ProgramImage>>,
    /// Data addresses each function refers to, read once.
    data_refs: BTreeMap<u64, Vec<u64>>,
}

/// Whether a stored unit can go into a program crate: it compiled. A translation that failed
/// only its function-level comparison is used (the program-level test judges it); one that was
/// refused or did not build is not.
pub(crate) fn usable(u: &RewriteUnit) -> bool {
    u.status != UnitStatus::Failed || u.verdict == Verdict::Fail
}

/// The attempt of a run to use: the newest one that passed or could not be compared, else the
/// newest that at least compiled, else the last.
fn best_attempt(run: &repair::RepairRun) -> RewriteUnit {
    let units: Vec<&RewriteUnit> = run.attempts.iter().map(|(u, _)| u).collect();
    units
        .iter()
        .rev()
        .find(|u| u.status != UnitStatus::Failed)
        .or_else(|| units.iter().rev().find(|u| usable(u)))
        .or_else(|| units.last())
        .map(|u| (*u).clone())
        .unwrap_or_else(|| run.last().0.clone())
}

/// How a function's own check is shown on its row: `unchecked` when the translation is used
/// although the function-level test failed or could not run it.
fn check_kind(u: &RewriteUnit) -> &'static str {
    if u.oracle.kind == COMPILE_ONLY_KIND {
        "compile_only"
    } else if matches!(u.verdict, Verdict::Fail | Verdict::Inconclusive { .. }) {
        "unchecked"
    } else {
        "differential"
    }
}

/// What translating one function came to.
enum FunctionOutcome {
    /// A stored unit (its status may be `failed`).
    Unit {
        unit: Box<RewriteUnit>,
        attempts: u32,
        kind: &'static str,
    },
    /// No unit could be made.
    None {
        status: UnitStatus,
        check: &'static str,
        note: String,
        attempts: u32,
    },
}

/// The crate of one assembly and its program-level verdict.
struct Stage {
    verdict: ProgramVerdict,
    crate_dir: String,
    crate_sha256: String,
    built: bool,
    bin_name: String,
    /// The units in the crate, by entry address (empty when a needed function has none).
    units: BTreeMap<u64, RewriteUnit>,
}

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
    Ok(st.get(id)?.filter(usable))
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
        let mut f = lift.function(address).await.map_err(proto)?;
        // A C++ method goes by `Class::name` in prompts and records, as the decompile calls it.
        f.name = qualified_name(&f.name, f.signature.as_deref());
        cache.insert(address, f.clone());
        Ok(f)
    }

    /// Data addresses the function at `address` refers to (reads, writes, addresses taken).
    async fn data_refs_of(
        &self,
        pc: &mut ProgramRun<'_>,
        address: u64,
    ) -> Result<Vec<u64>, ProtoError> {
        if let Some(r) = pc.data_refs.get(&address) {
            return Ok(r.clone());
        }
        let refs: Vec<u64> = pc
            .lift
            .data_refs(address)
            .await
            .map_err(proto)?
            .into_iter()
            .map(|r| r.to)
            .collect();
        pc.data_refs.insert(address, refs.clone());
        Ok(refs)
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
        ai: &crate::metering::JobAi,
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
        let repair_rounds = args
            .repair_rounds
            .unwrap_or(DEFAULT_REPAIR_ROUNDS)
            .min(MAX_REPAIR_ROUNDS);
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

        // 1. Plan. Functions that are only reached through a pointer (a callback handed to
        // another function, an entry of a dispatch table) are callees of the function that
        // takes their address.
        progress(job, "plan", 0, 1, "ordering the functions");
        let (collected, taken) = collect_program(s, ctx, MAX_PLAN_FUNCTIONS as usize)
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

        // The original's data, for the translations' globals (an ELF the image can hold).
        let image: Option<Arc<ProgramImage>> = {
            let (path, base) = (binary_path.clone(), lift.program().map_err(proto)?.1);
            tokio::task::spawn_blocking(move || ProgramImage::load(&path, base).ok())
                .await
                .map_err(|e| internal(format!("image task failed: {e}")))?
                .map(Arc::new)
        };
        let names = {
            let (listed, _) = lift
                .functions(MAX_PLAN_FUNCTIONS as usize)
                .await
                .map_err(proto)?;
            let sigs: BTreeMap<u64, Option<String>> = listed
                .into_iter()
                .map(|f| (f.address, f.signature))
                .collect();
            program_names(
                &plan
                    .entries
                    .iter()
                    .map(|p| {
                        (
                            p.address,
                            p.name.clone(),
                            sigs.get(&p.address).cloned().flatten(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };

        // What the entry point reaches (by calls, by function pointers it hands on, through
        // tables of function pointers in the data, and the static constructors that run before
        // it); the rest (glue in a binary without names, dead code) is left alone.
        let planned: BTreeSet<u64> = plan.entries.iter().map(|p| p.address).collect();
        let mut roots = vec![entry_addr];
        if let Some(img) = &image {
            // Static constructors by their compiler-given names (a stripped binary's are not
            // told apart from the C runtime's own entries).
            roots.extend(img.init.iter().copied().filter(|a| {
                plan.entries.iter().any(|p| {
                    p.address == *a
                        && (p.name.starts_with("_GLOBAL__sub_I")
                            || p.name.starts_with("__static_initialization"))
                })
            }));
        }
        let mut data_refs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let reachable: BTreeSet<u64> = {
            let by_addr: BTreeMap<u64, &PlannedFunction> =
                plan.entries.iter().map(|p| (p.address, p)).collect();
            let mut seen: BTreeSet<u64> = roots.iter().copied().collect();
            let mut queue: VecDeque<u64> = roots.iter().copied().collect();
            let pointers: Vec<(u64, u64)> = image
                .as_ref()
                .map(|img| img.function_pointers(&planned))
                .unwrap_or_default();
            loop {
                while let Some(a) = queue.pop_front() {
                    for c in by_addr.get(&a).map_or(&[][..], |p| p.callees.as_slice()) {
                        if seen.insert(*c) {
                            queue.push_back(*c);
                        }
                    }
                }
                // A table of function pointers in the data (a vtable, a dispatch table) counts
                // when a function that runs refers to it.
                let Some(img) = &image else { break };
                for a in &seen {
                    if !data_refs.contains_key(a) {
                        let refs: Vec<u64> = lift
                            .data_refs(*a)
                            .await
                            .map_err(proto)?
                            .into_iter()
                            .map(|r| r.to)
                            .collect();
                        data_refs.insert(*a, refs);
                    }
                }
                for (slot, target) in &pointers {
                    if seen.contains(target) {
                        continue;
                    }
                    let used = seen.iter().any(|f| {
                        data_refs
                            .get(f)
                            .is_some_and(|refs| refs.iter().any(|r| img.same_table(*r, *slot)))
                    });
                    if used && seen.insert(*target) {
                        queue.push_back(*target);
                    }
                }
                if queue.is_empty() {
                    break;
                }
            }
            seen
        };

        // 2. Translate, callees first.
        let backend = ai.backend()?;
        let provider_info = backend.provider_info();
        let defaults = DiffOptions::default();
        let opts = DiffOptions {
            seed: args.seed.unwrap_or(defaults.seed),
            random_cases: args.cases.map_or(defaults.random_cases, |c| c as usize),
            confinement: self.cfg.confinement.clone(),
            // The runner installs the image where the emulator loads the same bytes.
            image: image.as_ref().map(|img| RunnerImage {
                image: img.clone(),
                at: img.low_vaddr
                    + if img.is_pie {
                        self.cfg.oracle.load_base
                    } else {
                        0
                    },
            }),
            ..defaults
        };
        let mut pc = ProgramRun {
            lift: Lift::new(s, ctx),
            sha: sha.clone(),
            dir: dir.clone(),
            binary_path: binary_path.clone(),
            binary_file: binary_file.clone(),
            plan: plan.clone(),
            taken,
            entry_addr,
            backend,
            oracle: OracleThread::spawn(binary_path.clone(), self.cfg.oracle.clone()),
            opts: opts.clone(),
            max_attempts: args.max_attempts.unwrap_or(self.cfg.max_attempts),
            verify_functions,
            accept,
            actor: ctx.author.id.clone(),
            cache: BTreeMap::new(),
            names,
            image,
            data_refs,
        };
        let total = plan.entries.len() as u64;
        let mut chosen: BTreeMap<u64, String> = BTreeMap::new();
        let mut rows: Vec<ProgramFunctionRow> = Vec::new();
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
                    "the entry point does not reach this function: no direct call, no function \
                     pointer handed on, no table of function pointers in the program's data",
                    0,
                ));
                continue;
            }
            let f = self.context_of(&pc.lift, &mut pc.cache, p.address).await?;

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
            // A translation an earlier run made from this decompile, with the same Rust name and
            // its callees as they are now, that passed its own test or could not be compared: a
            // run that is started again picks up where the last one stopped. One that failed its
            // test is translated again.
            {
                let (sha2, addr, hash, cm, name) = (
                    sha.clone(),
                    format!("{:#x}", p.address),
                    f.decompile_hash.clone(),
                    chosen.clone(),
                    pc.names.get(&p.address).cloned().unwrap_or_default(),
                );
                let earlier = with_store(dir.clone(), move |st| {
                    let found = st.versions(&sha2, &addr)?.into_iter().rev().find(|u| {
                        matches!(u.status, UnitStatus::Translated | UnitStatus::Verified)
                            && u.source_decompile_hash == hash
                            && u.signature.name == name
                            && u.callees
                                .iter()
                                .filter_map(|c| c.reused.as_ref().map(|r| (c, r)))
                                .all(|(c, r)| {
                                    cm.get(&parse_addr(&c.address))
                                        .is_some_and(|id| *id == r.unit)
                                })
                    });
                    Ok(found)
                })
                .await?;
                if let Some(u) = earlier {
                    let u = self.maybe_accept(&pc, u).await?;
                    chosen.insert(p.address, u.id.clone());
                    rows.push(row_for_unit(order, p, &u, check_kind(&u), 0));
                    from_store += 1;
                    continue;
                }
            }

            let max_attempts = pc.max_attempts;
            match self
                .translate_function(&mut pc, p, &chosen, Vec::new(), max_attempts)
                .await?
            {
                FunctionOutcome::None {
                    status,
                    check,
                    note,
                    attempts,
                } => rows.push(row_without_unit(order, p, status, check, &note, attempts)),
                FunctionOutcome::Unit {
                    unit,
                    attempts,
                    kind,
                } => {
                    translated += 1;
                    let unit = self.maybe_accept(&pc, *unit).await?;
                    if usable(&unit) {
                        chosen.insert(p.address, unit.id.clone());
                    }
                    rows.push(row_for_unit(order, p, &unit, kind, attempts));
                }
            }
        }

        // 3. The crate, built and compared with the original.
        let mut stage = self
            .assemble_and_verify(&pc, &chosen, &out_dir, build, &args, job)
            .await?;

        // 4. A failed verdict is fed back: find the functions responsible and translate them
        // again with the first differing case as evidence.
        let mut repairs: Vec<ProgramRepairView> = Vec::new();
        if build && repair_rounds > 0 {
            repairs = self
                .repair_program(
                    &mut pc,
                    &mut chosen,
                    &mut rows,
                    &mut stage,
                    &out_dir,
                    &args,
                    repair_rounds,
                    job,
                )
                .await?;
        }

        for r in &mut rows {
            r.included = stage.units.contains_key(&r.address.0);
        }
        let functions_planned = u32::try_from(rows.len()).unwrap_or(u32::MAX);
        let included = u32::try_from(rows.iter().filter(|r| r.included).count()).unwrap_or(0);
        let skipped =
            u32::try_from(rows.iter().filter(|r| r.check == "skipped").count()).unwrap_or(0);
        let failed = u32::try_from(
            rows.iter()
                .filter(|r| {
                    r.check != "skipped"
                        && (r.unit.is_empty()
                            || (r.status == UnitStatus::Failed && r.check != "unchecked"))
                })
                .count(),
        )
        .unwrap_or(0);
        let count_of = |f: &dyn Fn(&ProgramFunctionRow) -> bool| {
            u32::try_from(rows.iter().filter(|r| f(r)).count()).unwrap_or(0)
        };
        let verified = count_of(&|r| r.verdict == "pass" && r.check != "compile_only");
        let unchecked = count_of(&|r| r.check == "unchecked");
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
            verified,
            unchecked,
            included,
            functions: rows,
            crate_dir: stage.crate_dir.clone(),
            built: stage.built,
            crate_sha256: stage.crate_sha256.clone(),
            provider: provider_info.id,
            model: provider_info.model,
            created: 0,
            verdict: stage.verdict.view(),
            repairs,
        };
        progress(job, "store", 0, 1, "storing the result");
        let sha2 = sha;
        let stored = with_store(dir, move |st| st.put_program_run(&sha2, result)).await?;
        progress(job, "done", 1, 1, "finished");
        Ok(stored)
    }

    /// Accepts a verified unit when the run was asked to (users only; the command checked).
    async fn maybe_accept(
        &self,
        pc: &ProgramRun<'_>,
        unit: RewriteUnit,
    ) -> Result<RewriteUnit, ProtoError> {
        if pc.accept && unit.status == UnitStatus::Verified {
            let (id, who) = (unit.id.clone(), pc.actor.clone());
            let (accepted, _) = with_store(pc.dir.clone(), move |st| st.accept(&id, &who)).await?;
            Ok(accepted)
        } else {
            Ok(unit)
        }
    }

    /// Translates the function `p` with the translations in `chosen` for its callees, and
    /// repairs the translation while that helps (the loop of `rewrite_function`). `seeded` are
    /// repair rounds to start from: the earlier code and what is wrong with it.
    async fn translate_function(
        &self,
        pc: &mut ProgramRun<'_>,
        p: &PlannedFunction,
        chosen: &BTreeMap<u64, String>,
        seeded: Vec<RepairRound>,
        max_attempts: u32,
    ) -> Result<FunctionOutcome, ProtoError> {
        let none = |status, check, note: &str, attempts| {
            Ok(FunctionOutcome::None {
                status,
                check,
                note: note.to_string(),
                attempts,
            })
        };
        let f = self.context_of(&pc.lift, &mut pc.cache, p.address).await?;
        let rname = pc
            .names
            .get(&p.address)
            .cloned()
            .unwrap_or_else(|| rust_name(&f.name, f.address));
        let Some(sig_text) = f.signature.clone() else {
            return none(
                UnitStatus::Failed,
                "none",
                "the function has no signature; set one with set_type before rewriting",
                0,
            );
        };
        let read = match infer_signature_for_program(&sig_text, &rname, &p.name) {
            Ok(x) => x,
            Err(e) => {
                return none(
                    UnitStatus::Failed,
                    "none",
                    &format!("cannot translate yet: {e}"),
                    0,
                );
            }
        };
        let signature = read.signature;
        let curated = curated(&pc.binary_file, &f.name);
        let check = if !pc.verify_functions {
            Check::CompileOnly("the function-level differential test was not requested".into())
        } else if let Some(n) = read.compile_only {
            Check::CompileOnly(n)
        } else {
            Check::Differential
        };
        let (inputs, mut notes) = match curated {
            Some(c) => (c.inputs, c.notes),
            None => (generic_inputs(&signature), generic_notes(&signature)),
        };
        if !read.guesses.is_empty() {
            notes.push_str(&format!(
                "\n\nThe prototype was read from a signature the decompiler could not fully type: \
                 {}.",
                read.guesses.join("; ")
            ));
        }
        if p.address == pc.entry_addr {
            notes.push_str(&format!("\n\n{ENTRY_NOTE}"));
        }
        notes.push_str(&format!("\n\n{}\n\n{CAST_NOTE}", crate::RT_PROMPT));
        if let Some(gs) = pc.taken.get(&p.address) {
            let names: Vec<String> = gs
                .iter()
                .filter_map(|g| pc.plan.entries.iter().find(|e| e.address == *g))
                .map(|e| format!("`{}`", e.name.replace('`', "")))
                .collect();
            if !names.is_empty() {
                notes.push_str(&format!("\n\n{}", taken_note(&names)));
            }
        }

        // What the translation includes (callees without a usable translation, with the
        // callees of those in turn) and what it calls (callees that have one).
        let by_addr: BTreeMap<u64, PlannedFunction> = pc
            .plan
            .entries
            .iter()
            .map(|e| (e.address, e.clone()))
            .collect();
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
            let c = self.context_of(&pc.lift, &mut pc.cache, a).await?;
            let (sha2, cm, c2, own) = (pc.sha.clone(), chosen.clone(), c.clone(), p.address);
            let r = with_store(pc.dir.clone(), move |st| {
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
                if let Some(pcallee) = by_addr.get(&a) {
                    queue.extend(pcallee.callees.iter().copied());
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
            return none(
                UnitStatus::Failed,
                "none",
                &format!(
                    "more than {MAX_INLINE} callees have no usable translation yet, too many to \
                     translate together with this function"
                ),
                0,
            );
        }
        {
            let seen: Vec<(String, String)> = visited
                .iter()
                .filter_map(|a| pc.cache.get(a))
                .map(|c| (format!("{:#x}", c.address), c.decompile_hash.clone()))
                .collect();
            let sha2 = pc.sha.clone();
            with_store(pc.dir.clone(), move |st| st.observe(&sha2, &seen)).await?;
        }
        // The globals the code refers to, by name and address, and how to reach them.
        if let Some(img) = pc.image.clone() {
            let mut addresses = Vec::new();
            for a in std::iter::once(p.address).chain(inline.iter().map(|c| c.address)) {
                addresses.extend(self.data_refs_of(pc, a).await?);
            }
            if addresses.iter().any(|a| img.contains(*a)) {
                notes.push_str(&format!("\n\n{}", img.prompt_notes(&addresses)));
            }
        }
        let mut budget = self.cfg.budget.clone();
        budget.max_tokens = Some(budget.max_tokens.unwrap_or(0).max(PROGRAM_MAX_TOKENS));
        let mut task = RewriteTask {
            function: f.clone(),
            callees: inline.clone(),
            signature: signature.clone(),
            layout_notes: notes,
            spec: None,
            reused: direct.clone(),
            repairs: seeded,
            hints: None,
            hints_from_agent: false,
            budget,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        crate::service::add_layouts(pc.lift.session(), &mut task, &cancel).await;
        crate::hints::add_hints(&pc.dir, &mut task).await?;
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
            opts: pc.opts.clone(),
            max_attempts,
        };
        let run = match self
            .translate(
                work,
                &pc.dir,
                &pc.binary_path.display().to_string(),
                pc.backend.as_ref(),
                &pc.oracle,
                None,
            )
            .await
        {
            Ok(run) => run,
            // A reply that could not be used is this function's failure; anything else (the
            // provider is down, the job was cancelled) ends the run.
            Err(RewriteError::Output(why)) => {
                return none(
                    UnitStatus::Failed,
                    "none",
                    &format!("the model's reply could not be used: {why}"),
                    1,
                );
            }
            Err(e) => return Err(proto(e)),
        };
        let attempts = u32::try_from(run.attempts.len()).unwrap_or(u32::MAX);
        let unit = best_attempt(&run);
        let kind = check_kind(&unit);
        Ok(FunctionOutcome::Unit {
            unit: Box::new(unit),
            attempts,
            kind,
        })
    }

    /// Writes the crate for the entry point and the translations it needs, builds it and runs
    /// it next to the original on every case.
    async fn assemble_and_verify(
        &self,
        pc: &ProgramRun<'_>,
        chosen: &BTreeMap<u64, String>,
        out_dir: &Path,
        build: bool,
        args: &RewriteProgramArgs,
        job: &JobReporter,
    ) -> Result<Stage, ProtoError> {
        let mut stage = Stage {
            verdict: ProgramVerdict::without_cases(ProgramVerdictKind::Inconclusive(
                "nothing was run".into(),
            )),
            crate_dir: String::new(),
            crate_sha256: String::new(),
            built: false,
            bin_name: String::new(),
            units: BTreeMap::new(),
        };
        let entry_addr = pc.entry_addr;
        // Besides what the entry point calls: the static constructors and the functions whose
        // address sits in a table of the data, when they and what they call have translations.
        let optional: Vec<u64> = pc
            .image
            .as_ref()
            .map(|img| {
                let planned: BTreeSet<u64> = pc.plan.entries.iter().map(|p| p.address).collect();
                img.init
                    .iter()
                    .copied()
                    .chain(img.function_pointers(&planned).into_iter().map(|(_, t)| t))
                    .collect()
            })
            .unwrap_or_default();
        let needed = {
            let (cm, entry) = (chosen.clone(), entry_addr);
            with_store(pc.dir.clone(), move |st| {
                let closure = |root: u64,
                               done: &BTreeMap<u64, RewriteUnit>|
                 -> Result<Result<BTreeMap<u64, RewriteUnit>, u64>, RewriteError> {
                    let mut found: BTreeMap<u64, RewriteUnit> = BTreeMap::new();
                    let mut need = vec![root];
                    while let Some(a) = need.pop() {
                        if done.contains_key(&a) || found.contains_key(&a) {
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
                        found.insert(a, u);
                    }
                    Ok(Ok(found))
                };
                let mut done = match closure(entry, &BTreeMap::new())? {
                    Ok(d) => d,
                    Err(missing) => return Ok(Err(missing)),
                };
                for root in optional {
                    if let Ok(more) = closure(root, &done)? {
                        done.extend(more);
                    }
                }
                Ok(Ok(done))
            })
            .await?
        };
        let units = match needed {
            Err(missing) => {
                let name = pc
                    .plan
                    .entries
                    .iter()
                    .find(|p| p.address == missing)
                    .map_or("?", |p| p.name.as_str());
                stage.verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Incomplete(
                    format!("`{name}` is needed by the program and has no usable translation"),
                ));
                return Ok(stage);
            }
            Ok(units) => units,
        };
        stage.units = units.clone();
        let entry_unit = units[&entry_addr].clone();
        let list: Vec<RewriteUnit> = units.into_values().collect();
        // Write the crate.
        progress(job, "assemble", 0, 1, "writing the Rust crate");
        let (binary_name, sha2, out2, image) = (
            pc.binary_file.clone(),
            pc.sha.clone(),
            out_dir.to_path_buf(),
            pc.image.clone(),
        );
        let assembled = tokio::task::spawn_blocking(move || {
            assemble(
                &out2,
                &AssembleInfo {
                    binary_name: &binary_name,
                    program_sha256: &sha2,
                    image: image.as_deref(),
                },
                &entry_unit,
                &list,
            )
        })
        .await
        .map_err(|e| internal(format!("assemble task failed: {e}")))?;
        let a = match assembled {
            Err(e) => {
                stage.verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Incomplete(
                    format!("cannot write the crate: {e}"),
                ));
                return Ok(stage);
            }
            Ok(a) => a,
        };
        stage.crate_dir = out_dir.display().to_string();
        stage.crate_sha256 = a.crate_sha256.clone();
        stage.bin_name = a.bin_name.clone();
        if !build {
            stage.verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Inconclusive(
                "the crate was written but not built or run (`build` was off)".into(),
            ));
            return Ok(stage);
        }
        // Build and verify.
        progress(job, "build", 0, 1, "building the crate in the sandbox");
        let (out2, bin, conf) = (
            out_dir.to_path_buf(),
            a.bin_name.clone(),
            self.cfg.confinement.clone(),
        );
        let built_program = tokio::task::spawn_blocking(move || build_program(&out2, &bin, &conf))
            .await
            .map_err(|e| internal(format!("build task failed: {e}")))?;
        let bp = match built_program {
            Err(RewriteError::Compile(why)) => {
                stage.verdict = ProgramVerdict::without_cases(ProgramVerdictKind::Incomplete(why));
                return Ok(stage);
            }
            Err(e) => return Err(proto(e)),
            Ok(bp) => bp,
        };
        stage.built = true;
        let source = corpus_source(&pc.binary_path);
        let cases = derive_cases(&CaseSeed {
            source: source.as_ref().map(|(_, t)| t.as_str()),
            seed: pc.opts.seed,
            generated: args.generated_cases.unwrap_or(DEFAULT_GENERATED_CASES) as usize,
            user: &args.inputs,
        });
        progress(
            job,
            "verify",
            0,
            cases.len() as u64,
            "running both programs",
        );
        let (orig, conf, job2) = (
            pc.binary_path.clone(),
            self.cfg.confinement.clone(),
            job.clone(),
        );
        stage.verdict = tokio::task::spawn_blocking(move || {
            let cancel = job2.cancel_token();
            let v = verify_program(&orig, &bp.exe, &cases, &conf, &|done, total| {
                progress(
                    &job2,
                    "verify",
                    done as u64,
                    total as u64,
                    "running both programs",
                );
                !cancel.is_cancelled()
            });
            drop(bp);
            v
        })
        .await
        .map_err(|e| internal(format!("verify task failed: {e}")))?
        .map_err(proto)?;
        Ok(stage)
    }

    /// Runs the rewritten program again on `case` with the trace armed and returns the
    /// translated functions on its stack at `spec`, innermost first. The crate is rebuilt for
    /// this with optimisation off and line tables on so the frames are not inlined away.
    async fn trace_program(
        &self,
        out_dir: &Path,
        bin_name: &str,
        case: ProgramCase,
        spec: TraceSpec,
        modules: BTreeMap<String, String>,
    ) -> Result<Vec<String>, ProtoError> {
        let (dir, bin, conf) = (
            out_dir.to_path_buf(),
            bin_name.to_string(),
            self.cfg.confinement.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let built = cargo_build_with(
                &dir,
                &conf,
                "the traced program",
                &[
                    ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0"),
                    ("CARGO_PROFILE_RELEASE_DEBUG", "line-tables-only"),
                    ("CARGO_PROFILE_RELEASE_STRIP", "none"),
                ],
            )?;
            let exe = built.target.join("release").join(&bin);
            let (out, _) = run_case_with_env(
                &exe,
                &case,
                &conf,
                &[
                    ("KRAKEN_TRACE_AT", spec.env_value()),
                    ("RUST_BACKTRACE", "1".to_string()),
                ],
            )?;
            Ok(parse_stack(&out.stderr, &modules))
        })
        .await
        .map_err(|e| internal(format!("trace task failed: {e}")))?
        .map_err(|e: RewriteError| proto(e))
    }

    /// Program-level repair (see [`crate::blame`] for the heuristic). Up to `rounds` rounds:
    /// take the first differing case, find the suspects, translate them again with that case as
    /// evidence, rebuild, run every case again. Stops when the verdict is no longer `fail`, when
    /// a round changed no function, or when the rounds are used up.
    #[allow(clippy::too_many_arguments)]
    async fn repair_program(
        &self,
        pc: &mut ProgramRun<'_>,
        chosen: &mut BTreeMap<u64, String>,
        rows: &mut [ProgramFunctionRow],
        stage: &mut Stage,
        out_dir: &Path,
        args: &RewriteProgramArgs,
        rounds: u32,
        job: &JobReporter,
    ) -> Result<Vec<ProgramRepairView>, ProtoError> {
        let mut views: Vec<ProgramRepairView> = Vec::new();
        let attempts = pc.max_attempts.min(REPAIR_ATTEMPTS);
        for round in 1..=rounds {
            if stage.verdict.kind != ProgramVerdictKind::Fail {
                break;
            }
            if job.cancel_token().is_cancelled() {
                return Err(ProtoError::new(ErrorCode::Cancelled, "job cancelled"));
            }
            let Some(report) = stage
                .verdict
                .reports
                .iter()
                .find(|r| !r.differences.is_empty())
                .cloned()
            else {
                break;
            };
            progress(
                job,
                "repair",
                u64::from(round - 1),
                u64::from(rounds),
                "tracing the first differing case",
            );
            // Where the rewritten program was when it produced the first difference.
            let spec = trace_for(&report.original, &report.rewritten);
            let modules: BTreeMap<String, String> = stage
                .units
                .values()
                .map(|u| (format!("u_{}", u.signature.name), u.signature.name.clone()))
                .collect();
            let stack = match spec.clone() {
                Some(spec) => self
                    .trace_program(out_dir, &stage.bin_name, report.case.clone(), spec, modules)
                    .await
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            // Who to blame.
            let candidates: Vec<Candidate> = stage
                .units
                .iter()
                .map(|(addr, u)| {
                    let row = rows.iter().find(|r| r.address.0 == *addr);
                    Candidate {
                        address: *addr,
                        name: pc
                            .plan
                            .entries
                            .iter()
                            .find(|e| e.address == *addr)
                            .map(|e| e.name.clone())
                            .unwrap_or_default(),
                        symbol: u.signature.name.clone(),
                        verified: row.is_some_and(|r| {
                            r.verdict == "pass"
                                && (r.check == "differential" || r.check == "stored")
                        }),
                        callees: pc
                            .plan
                            .entries
                            .iter()
                            .find(|e| e.address == *addr)
                            .map(|e| {
                                e.callees
                                    .iter()
                                    .copied()
                                    .filter(|c| stage.units.contains_key(c))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        tried: u32::try_from(views.iter().filter(|v| v.address.0 == *addr).count())
                            .unwrap_or(u32::MAX),
                    }
                })
                .collect();
            let suspects = rank(&stack, &candidates, SUSPECTS_PER_ROUND);
            let first = views.len();
            let mut changed = false;
            for sus in &suspects {
                progress(
                    job,
                    "repair",
                    u64::from(round - 1),
                    u64::from(rounds),
                    &format!("translating `{}` again", sus.name),
                );
                let Some(old) = stage.units.get(&sus.address).cloned() else {
                    continue;
                };
                let Some(planned) = pc
                    .plan
                    .entries
                    .iter()
                    .find(|e| e.address == sus.address)
                    .cloned()
                else {
                    continue;
                };
                let own = rows
                    .iter()
                    .find(|r| r.address.0 == sus.address)
                    .map(|r| match r.check.as_str() {
                        "differential" if r.verdict == "pass" => {
                            "it passed the function-level test".to_string()
                        }
                        "compile_only" => "it was only compiled".to_string(),
                        other => format!("function-level check: {other}, {}", r.verdict),
                    })
                    .unwrap_or_default();
                let text = feedback_text(&FeedbackInput {
                    case_name: &report.case.name,
                    argv: &report.case.argv,
                    stdin: &report.case.stdin,
                    original: &report.original,
                    rewritten: &report.rewritten,
                    differences: &report.differences,
                    trace: spec.as_ref(),
                    stack: &stack,
                    suspect: sus,
                    own_check: &own,
                });
                let seeded = vec![RepairRound {
                    previous_code: previous_code(&old.rust_code),
                    feedback: Feedback {
                        kind: "program",
                        text: cut_feedback(&text),
                    },
                }];
                let outcome = self
                    .translate_function(pc, &planned, chosen, seeded, attempts)
                    .await?;
                let mut view = ProgramRepairView {
                    round,
                    address: Hex64(sus.address),
                    name: Untrusted::sanitized(&sus.name),
                    case: report.case.name.clone(),
                    at: spec.as_ref().map(|s| s.describe()).unwrap_or_default(),
                    stack: stack.clone(),
                    why: Untrusted::sanitized(&sus.why),
                    outcome: "no_reply".into(),
                    version_before: old.version,
                    version_after: old.version,
                    verdict_after: String::new(),
                };
                if let FunctionOutcome::Unit {
                    unit,
                    attempts: n,
                    kind,
                } = outcome
                {
                    let unit = self.maybe_accept(pc, *unit).await?;
                    // A new translation that does not build is not used, nor one that fails its
                    // own test where the one in the crate passed it.
                    let worse = unit.verdict == Verdict::Fail && old.verdict == Verdict::Pass;
                    if !usable(&unit) || worse {
                        view.outcome = "kept".into();
                    } else {
                        view.outcome = "replaced".into();
                        view.version_after = unit.version;
                        chosen.insert(sus.address, unit.id.clone());
                        if let Some(row) = rows.iter_mut().find(|r| r.address.0 == sus.address) {
                            let before = row.attempts;
                            let order = row.order;
                            *row = row_for_unit(order, &planned, &unit, kind, before + n);
                        }
                        changed = true;
                    }
                }
                views.push(view);
            }
            if !changed {
                break;
            }
            *stage = self
                .assemble_and_verify(pc, chosen, out_dir, true, args, job)
                .await?;
            let after = stage.verdict.kind.name().to_string();
            for v in &mut views[first..] {
                v.verdict_after = after.clone();
            }
        }
        Ok(views)
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
