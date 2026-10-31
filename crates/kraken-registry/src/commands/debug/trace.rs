//! `debug_trace` (a job), `coverage_list`, `coverage_blocks` and `coverage_clear`: run the program
//! in the confined emulator recording the basic blocks that execute (and optionally every
//! instruction with its register and memory deltas), keep the coverage in the project and export
//! it as drcov, a step trace text or JSON.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use kraken_emu::confined::{DebugChild, DebugReply, DebugRequest, RUNNER, find_runner};
use kraken_emu::{RunSpec, SessionStop};
use kraken_proto::trace::{
    CoverageBlock, MemoryWrite, RegisterDelta, TraceStepRecord, drcov_bytes, step_trace_text,
};
use kraken_proto::{ErrorCode, Hex64, Locator, Page, PageRequest, ProtoError, sanitize};
use kraken_sidecar::ConfinementOptions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DEFAULT_BUDGET, MAX_BUDGET, MAX_WALL_SECONDS, is_pie, limits};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::commands::emulate::{invalid, problem, with_sysroot};
use crate::commands::{JobStarted, NoArgs};
use crate::context::CallContext;
use crate::jobs::JobProgress;
use crate::session::{Project, Session, blocking};

/// Longest step trace one run records.
pub const MAX_TRACE_STEPS: u64 = 200_000;
/// Default length of a step trace when `step_trace` is true-ish (a count is given).
const PREVIEW_STEPS: usize = 16;
/// Coverage runs kept per project; the oldest go first.
pub const MAX_RUNS: usize = 20;
/// Functions whose blocks one trace watches.
const MAX_FUNCTIONS: usize = 100_000;
const FILE: &str = "coverage.json";

static FILE_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------------------------
// storage

/// What `coverage_list` says about one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageRunSummary {
    /// The id other commands take.
    pub id: u64,
    /// The label given at the start (default: the program name).
    pub label: String,
    /// When it ran, seconds since the Unix epoch.
    pub created: u64,
    /// The architecture.
    pub arch: String,
    /// How the run ended.
    pub exit: String,
    /// Instructions executed.
    pub instructions: u64,
    /// Basic blocks the engine knows (the ones watched).
    pub blocks_total: u64,
    /// Basic blocks that ran at least once.
    pub blocks_hit: u64,
    /// Instructions recorded in the step trace (0 when none was asked for).
    pub steps_recorded: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRun {
    summary: CoverageRunSummary,
    blocks: Vec<CoverageBlock>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    next_id: u64,
    runs: Vec<StoredRun>,
}

fn read_store(dir: &Path) -> Result<Stored, ProtoError> {
    match std::fs::read(dir.join(FILE)) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|e| problem(ErrorCode::Internal, format!("{FILE} is damaged: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Stored::default()),
        Err(e) => Err(problem(ErrorCode::Internal, format!("reading {FILE}: {e}"))),
    }
}

fn write_store(dir: &Path, st: &Stored) -> Result<(), ProtoError> {
    let tmp = dir.join(format!("{FILE}.tmp"));
    let body = serde_json::to_vec(st).map_err(|e| problem(ErrorCode::Internal, e.to_string()))?;
    std::fs::write(&tmp, body)
        .and_then(|()| std::fs::rename(&tmp, dir.join(FILE)))
        .map_err(|e| problem(ErrorCode::Internal, format!("writing {FILE}: {e}")))
}

fn with_file<T>(
    dir: &Path,
    f: impl FnOnce(&mut Stored) -> Result<T, ProtoError>,
) -> Result<T, ProtoError> {
    let _g = FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut st = read_store(dir)?;
    let r = f(&mut st)?;
    write_store(dir, &st)?;
    Ok(r)
}

/// One more run in the project's coverage.
fn add_run(
    dir: &Path,
    mut summary: CoverageRunSummary,
    blocks: Vec<CoverageBlock>,
) -> Result<CoverageRunSummary, ProtoError> {
    with_file(dir, |st| {
        st.next_id += 1;
        summary.id = st.next_id;
        st.runs.push(StoredRun {
            summary: summary.clone(),
            blocks,
        });
        while st.runs.len() > MAX_RUNS {
            st.runs.remove(0);
        }
        Ok(summary)
    })
}

// ---------------------------------------------------------------------------------------------
// debug_trace

/// Arguments of `debug_trace`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugTraceArgs {
    /// Command-line arguments after `argv[0]` (at most 64, each at most 4096 bytes).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Text for the program's standard input (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// A name for this run in `coverage_list` (default the program's name; at most 80
    /// characters).
    #[serde(default)]
    pub label: Option<String>,
    /// Instruction budget of the whole run (default 100 million, at most 1 billion).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit in seconds (default 10, at most 120).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Also record this many executed instructions one by one with their register changes (at
    /// most 200000; default 0, none).
    #[serde(default)]
    pub step_trace: Option<u64>,
    /// Record the memory the traced instructions wrote (default false).
    #[serde(default)]
    pub memory: bool,
    /// Start the step trace when this function symbol is reached (default: the first
    /// instruction).
    #[serde(default)]
    pub from_symbol: Option<String>,
    /// Start the step trace at this listing address.
    #[serde(default)]
    pub from_address: Option<Hex64>,
    /// Write an export: `drcov` (for Lighthouse and other coverage plugins), `text` (the step
    /// trace) or `json` (everything). Needs `export_path`.
    #[serde(default)]
    pub format: Option<String>,
    /// Where to write the export (people only); an existing file is replaced, a link is not
    /// followed.
    #[serde(default)]
    pub export_path: Option<String>,
}

/// A file `debug_trace` wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceExport {
    /// `drcov`, `text` or `json`.
    pub format: String,
    /// The file.
    pub path: String,
    /// Its size in bytes.
    pub bytes: u64,
}

/// Result of `debug_trace` (the job's result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugTraceOut {
    /// The coverage run that was stored.
    pub run: CoverageRunSummary,
    /// The export, when one was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported: Option<TraceExport>,
    /// The first instructions of the step trace (all of them are in the export).
    pub steps_preview: Vec<TraceStepRecord>,
    /// Facts about the run.
    pub notes: Vec<String>,
}

/// Records which basic blocks of the program run.
pub struct DebugTrace;

#[async_trait]
impl Command for DebugTrace {
    type Args = DebugTraceArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_trace",
            "Run the program in the emulator and record the basic blocks that execute (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Runs the project's program to its end in the confined emulator and counts how often \
             each basic block the engine knows ran. The coverage is stored in the project \
             (`coverage_list`, `coverage_clear`) and the GUI shades executed blocks and lines. \
             Add `step_trace` for the first N instructions one by one with register changes, \
             `memory` for the bytes they wrote. `format` and `export_path` write `drcov` (for \
             coverage plugins), `text` or `json`. Returns a `job_id`; the result is a \
             `DebugTraceOut`.\n\
             Example: debug_trace {\"stdin\": \"hello\\n\", \"format\": \"drcov\", \"export_path\": \"/tmp/run.drcov\"}",
        )
        .details(
            "Linux ELF programs in the emulator, like `debug_start`; a dynamic program needs a \
             sysroot or this computer's libraries. Only blocks of the program itself are \
             watched, not the loader or libraries. Block coverage costs little; a step trace \
             runs one instruction at a time, so keep it short and use `from_symbol` to skip \
             start-up. The drcov file lists blocks as offsets from the program's image base. At \
             most 20 runs are kept per project, oldest first out. Nothing in the project \
             changes except the coverage store.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: DebugTraceArgs,
    ) -> Result<JobStarted, ProtoError> {
        let plan = validate(&args)?;
        let export = match (&args.format, &args.export_path) {
            (None, None) => None,
            (Some(_), Some(_)) if ctx.needs_user_approval() => {
                return Err(ProtoError::new(
                    ErrorCode::RejectedHumanPriority,
                    "an agent reads the coverage with `coverage_blocks`; writing a file is for \
                     people",
                ));
            }
            (Some(f), Some(p)) => Some((f.clone(), PathBuf::from(p))),
            _ => return Err(invalid("format and export_path go together")),
        };
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        if !binary.is_file() {
            return Err(problem(
                ErrorCode::NotFound,
                format!(
                    "the project's binary {} is not there any more",
                    binary.display()
                ),
            ));
        }
        let id = s.jobs().spawn("debug_trace", move |reporter| async move {
            let progress = |phase: &str, message: &str| {
                reporter.progress(JobProgress {
                    phase: phase.to_string(),
                    message: message.to_string(),
                    ..Default::default()
                });
            };
            progress("blocks", "collecting the basic blocks");
            let blocks = collect_blocks(&project, &reporter.cancel_token()).await?;
            progress("running", "running the program");
            let base = project.program().base.0;
            let work = (project.clone(), binary, args, plan, blocks, base, export);
            let out = blocking(move || {
                let (project, binary, args, plan, blocks, base, export) = work;
                trace_run(&project, &binary, &args, plan, &blocks, base, export)
            })
            .await?;
            serde_json::to_value(out).map_err(|e| problem(ErrorCode::Internal, e.to_string()))
        });
        Ok(JobStarted { job_id: id.0 })
    }
}

#[derive(Debug, Clone, Copy)]
struct Plan {
    budget: u64,
    wall_ms: u64,
    steps: u64,
}

fn validate(args: &DebugTraceArgs) -> Result<Plan, ProtoError> {
    if args.stdin.len() > super::super::emulate::MAX_STDIN_BYTES {
        return Err(invalid("stdin is longer than 1 MiB"));
    }
    if args.argv.len() > super::super::emulate::MAX_ARGS {
        return Err(invalid("argv has more than 64 entries"));
    }
    if args
        .argv
        .iter()
        .any(|a| a.len() > super::super::emulate::MAX_ARG_BYTES || a.contains('\0'))
    {
        return Err(invalid("an argv entry is too long or contains a NUL byte"));
    }
    if args.label.as_ref().is_some_and(|l| l.chars().count() > 80) {
        return Err(invalid("label is longer than 80 characters"));
    }
    let steps = args.step_trace.unwrap_or(0);
    if steps > MAX_TRACE_STEPS {
        return Err(invalid(format!(
            "step_trace is at most {MAX_TRACE_STEPS} instructions"
        )));
    }
    if (args.from_symbol.is_some() || args.from_address.is_some() || args.memory) && steps == 0 {
        return Err(invalid(
            "from_symbol, from_address and memory need step_trace",
        ));
    }
    if args.from_symbol.is_some() && args.from_address.is_some() {
        return Err(invalid("give from_symbol or from_address, not both"));
    }
    if let Some(f) = &args.format {
        if !matches!(f.as_str(), "drcov" | "text" | "json") {
            return Err(invalid("format is `drcov`, `text` or `json`"));
        }
        if f == "text" && steps == 0 {
            return Err(invalid("the text format is the step trace: set step_trace"));
        }
    }
    let (budget, wall_ms) = limits(args.max_steps, args.timeout_seconds)?;
    debug_assert!(budget <= MAX_BUDGET && wall_ms <= MAX_WALL_SECONDS * 1000);
    let _ = DEFAULT_BUDGET;
    Ok(Plan {
        budget,
        wall_ms,
        steps,
    })
}

/// The `[start, end)` listing ranges of every basic block of every function.
async fn collect_blocks(
    project: &Project,
    cancel: &kraken_engine::CancellationToken,
) -> Result<Vec<(u64, u64)>, ProtoError> {
    let engine = project.engine();
    let lister = engine
        .function_lister()
        .ok_or_else(|| kraken_engine::unsupported("function_lister"))?;
    let graph = engine
        .flow_graph()
        .ok_or_else(|| kraken_engine::unsupported("flow_graph"))?;
    let mut out = std::collections::BTreeMap::new();
    let mut cursor = None;
    let mut functions = 0;
    loop {
        let page = lister
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(500),
                },
                cancel,
            )
            .await?;
        for f in &page.items {
            functions += 1;
            if functions > MAX_FUNCTIONS {
                break;
            }
            if !matches!(f.locator, Locator::Native { .. }) {
                continue;
            }
            // A function whose graph the engine cannot build simply adds no blocks.
            if let Ok(cfg) = graph.cfg(&f.locator, cancel).await {
                for b in cfg.blocks {
                    out.insert(b.start.0, b.end.0.max(b.start.0 + 1));
                }
            }
        }
        match page.next_cursor {
            Some(c) if functions <= MAX_FUNCTIONS => cursor = Some(c),
            _ => break,
        }
    }
    if out.is_empty() {
        return Err(problem(
            ErrorCode::Unsupported,
            "the engine found no basic blocks to watch (is the analysis finished?)",
        ));
    }
    Ok(out.into_iter().collect())
}

fn describe(stop: &SessionStop) -> String {
    match stop {
        SessionStop::Exited { exit } => exit.describe(),
        SessionStop::Budget | SessionStop::Stepped => "instruction budget exhausted".into(),
        SessionStop::Interrupted => "timeout".into(),
        SessionStop::Fault { detail, pc } => format!("fault at {pc:#x}: {}", sanitize(detail)),
        other => format!("{other:?}"),
    }
}

fn trace_run(
    project: &Project,
    binary: &Path,
    args: &DebugTraceArgs,
    plan: Plan,
    blocks: &[(u64, u64)],
    base: u64,
    export: Option<(String, PathBuf)>,
) -> Result<DebugTraceOut, ProtoError> {
    let runner = find_runner().filter(|p| p.is_file()).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            format!(
                "the emulator's child program `{RUNNER}` was not found next to this executable: \
                 build it (`cargo build -p kraken-emu --bin {RUNNER}`) or set KRAKEN_EMU_RUN to \
                 its path"
            ),
        )
    })?;
    let work = tempfile::Builder::new()
        .prefix("kraken-trace-")
        .tempdir()
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    let mut spec = RunSpec::new(binary);
    spec.args = args.argv.clone();
    spec.stdin = args.stdin.clone().into_bytes();
    spec.output_cap = 64 * 1024;
    spec.workdir = Some(work.path().to_path_buf());
    let mut notes = Vec::new();
    let start = |spec: &RunSpec| DebugChild::start(spec, &runner, ConfinementOptions::default());
    let (mut child, _libs) = with_sysroot(&mut spec, binary, binary, &mut notes, start)?;
    let initial = child.initial.clone();
    let delta = if is_pie(binary) {
        initial.main_bias.wrapping_sub(base)
    } else {
        initial.main_bias
    };
    let emu = |a: u64| a.wrapping_add(delta);
    let to_listing = |a: u64| a.wrapping_sub(delta);
    let ask = |child: &mut DebugChild, req: DebugRequest| {
        child
            .request(&req)
            .map_err(|e| problem(ErrorCode::Unsupported, e.to_string()))
    };

    ask(
        &mut child,
        DebugRequest::Track {
            addrs: blocks.iter().map(|(s, _)| emu(*s)).collect(),
        },
    )?;

    let mut stop = None;
    let mut steps = Vec::new();
    if plan.steps > 0 {
        let from = match (&args.from_symbol, args.from_address) {
            (Some(name), _) => {
                match ask(&mut child, DebugRequest::Symbol { name: name.clone() })? {
                    DebugReply::Symbol { addr: Some(a) } => Some(a),
                    _ => {
                        return Err(problem(
                            ErrorCode::NotFound,
                            format!(
                                "the program has no function symbol `{name}`; give from_address"
                            ),
                        ));
                    }
                }
            }
            (None, Some(a)) => Some(emu(a.0)),
            (None, None) => None,
        };
        if let Some(addr) = from {
            let DebugReply::Stop { stop: s, .. } = ask(
                &mut child,
                DebugRequest::RunTo {
                    addr,
                    budget: plan.budget,
                    wall_ms: plan.wall_ms,
                },
            )?
            else {
                return Err(problem(ErrorCode::Internal, "unexpected reply"));
            };
            if !matches!(s, SessionStop::Reached { .. }) {
                notes.push(format!(
                    "the program ended ({}) before the step trace start",
                    describe(&s)
                ));
                stop = Some(s);
            }
        }
        if stop.is_none() {
            let DebugReply::Trace {
                steps: recorded,
                stop: s,
                ..
            } = ask(
                &mut child,
                DebugRequest::TraceSteps {
                    max: plan.steps,
                    memory: args.memory,
                    wall_ms: plan.wall_ms,
                },
            )?
            else {
                return Err(problem(ErrorCode::Internal, "unexpected reply"));
            };
            steps = recorded
                .into_iter()
                .map(|r| TraceStepRecord {
                    index: r.icount,
                    address: Hex64(to_listing(r.pc)),
                    text: sanitize(&r.text),
                    registers: r
                        .regs
                        .into_iter()
                        .map(|(name, b, a)| RegisterDelta {
                            name,
                            before: Hex64(b),
                            after: Hex64(a),
                        })
                        .collect(),
                    writes: r
                        .writes
                        .into_iter()
                        .map(|(a, b)| MemoryWrite {
                            address: Hex64(a),
                            bytes: kraken_proto::hex_bytes(&b),
                        })
                        .collect(),
                })
                .collect();
            if matches!(s, SessionStop::Stepped) {
                notes.push(format!(
                    "the step trace stopped after {} instructions; the rest of the run is counted \
                     as coverage only",
                    steps.len()
                ));
            } else {
                stop = Some(s);
            }
        }
    }
    let stop = match stop {
        Some(s) => s,
        None => match ask(
            &mut child,
            DebugRequest::Run {
                budget: plan.budget,
                wall_ms: plan.wall_ms,
            },
        )? {
            DebugReply::Stop { stop, .. } => stop,
            _ => return Err(problem(ErrorCode::Internal, "unexpected reply")),
        },
    };
    let state = match ask(&mut child, DebugRequest::State)? {
        DebugReply::State { state } => state,
        _ => return Err(problem(ErrorCode::Internal, "unexpected reply")),
    };
    let counts = match ask(&mut child, DebugRequest::Coverage)? {
        DebugReply::Coverage { blocks } => blocks,
        _ => return Err(problem(ErrorCode::Internal, "unexpected reply")),
    };
    drop(child);

    let size_of: std::collections::BTreeMap<u64, u64> = blocks.iter().copied().collect();
    let hit: Vec<CoverageBlock> = counts
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(a, n)| {
            let start = to_listing(a);
            let end = size_of.get(&start).copied().unwrap_or(start + 1);
            CoverageBlock {
                start: Hex64(start),
                size: end.saturating_sub(start).min(u64::from(u32::MAX)) as u32,
                hits: n,
            }
        })
        .collect();
    let program = binary
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .unwrap_or_default();
    let summary = CoverageRunSummary {
        id: 0,
        label: args
            .label
            .as_deref()
            .map(sanitize)
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| program.clone()),
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        arch: initial.arch.clone(),
        exit: describe(&stop),
        instructions: state.icount,
        blocks_total: blocks.len() as u64,
        blocks_hit: hit.len() as u64,
        steps_recorded: steps.len() as u64,
    };
    let exported = match export {
        Some((format, path)) => {
            let image_end = blocks.iter().map(|(_, e)| *e).max().unwrap_or(base);
            let bytes = match format.as_str() {
                "drcov" => drcov_bytes(&program, base, image_end, &hit),
                "text" => step_trace_text(&program, &steps).into_bytes(),
                _ => serde_json::to_vec_pretty(&serde_json::json!({
                    "program": program,
                    "run": summary,
                    "blocks": hit,
                    "steps": steps,
                }))
                .map_err(|e| problem(ErrorCode::Internal, e.to_string()))?,
            };
            write_export(&path, &bytes).map_err(|e| {
                problem(
                    ErrorCode::InvalidArgument,
                    format!("cannot write {}: {e}", path.display()),
                )
            })?;
            Some(TraceExport {
                format,
                path: path.to_string_lossy().into_owned(),
                bytes: bytes.len() as u64,
            })
        }
        None => None,
    };
    let run = add_run(project.dir(), summary, hit)?;
    Ok(DebugTraceOut {
        run,
        exported,
        steps_preview: steps.into_iter().take(PREVIEW_STEPS).collect(),
        notes,
    })
}

// ---------------------------------------------------------------------------------------------
// coverage_list / coverage_blocks / coverage_clear

/// Result of `coverage_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageListOut {
    /// The stored runs, oldest first.
    pub runs: Vec<CoverageRunSummary>,
}

/// Lists the stored coverage runs.
pub struct CoverageList;

#[async_trait]
impl Command for CoverageList {
    type Args = NoArgs;
    type Output = CoverageListOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "coverage_list",
            "List the coverage runs stored in the project",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "One row per `debug_trace` run: id, label, how it ended, instructions, and how many \
             of the known basic blocks ran. `coverage_blocks` has the blocks themselves.\n\
             Example: coverage_list {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<CoverageListOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        blocking(move || {
            let _g = FILE_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(CoverageListOut {
                runs: read_store(&dir)?
                    .runs
                    .into_iter()
                    .map(|r| r.summary)
                    .collect(),
            })
        })
        .await
    }
}

/// Arguments of `coverage_blocks`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageBlocksArgs {
    /// One run (default: all runs together, hits added up).
    #[serde(default)]
    pub run: Option<u64>,
    /// Cursor from the previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size (default 100, at most 5000).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Most blocks of one `coverage_blocks` page.
pub const BLOCKS_PAGE_CAP: u32 = 5000;

/// Lists the blocks that ran.
pub struct CoverageBlocks;

#[async_trait]
impl Command for CoverageBlocks {
    type Args = CoverageBlocksArgs;
    type Output = Page<CoverageBlock>;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "coverage_blocks",
            "List the basic blocks that ran, from one stored run or all of them",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Blocks by address with their hit counts, paginated. Without `run` the runs are \
             merged (hits added). The GUI overlay reads this.\n\
             Example: coverage_blocks {\"run\": 1, \"limit\": 500}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: CoverageBlocksArgs,
    ) -> Result<Page<CoverageBlock>, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let offset: usize = match &args.cursor {
            Some(c) => c
                .parse()
                .map_err(|_| invalid("cursor is not one this command gave"))?,
            None => 0,
        };
        let limit = args.limit.unwrap_or(100).clamp(1, BLOCKS_PAGE_CAP) as usize;
        blocking(move || {
            let _g = FILE_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let st = read_store(&dir)?;
            let mut merged: std::collections::BTreeMap<u64, (u32, u64)> = Default::default();
            let mut any = false;
            for r in &st.runs {
                if args.run.is_some_and(|id| id != r.summary.id) {
                    continue;
                }
                any = true;
                for b in &r.blocks {
                    let e = merged.entry(b.start.0).or_insert((b.size, 0));
                    e.1 += b.hits;
                }
            }
            if let Some(id) = args.run
                && !any
            {
                return Err(problem(
                    ErrorCode::NotFound,
                    format!("no coverage run {id}; `coverage_list` shows them"),
                ));
            }
            let total = merged.len();
            let items: Vec<CoverageBlock> = merged
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(a, (size, hits))| CoverageBlock {
                    start: Hex64(a),
                    size,
                    hits,
                })
                .collect();
            let next = (offset + items.len() < total).then(|| (offset + items.len()).to_string());
            Ok(Page {
                items,
                next_cursor: next,
                total: Some(total as u64),
            })
        })
        .await
    }
}

/// Arguments of `coverage_clear`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageClearArgs {
    /// Remove only this run (default: all).
    #[serde(default)]
    pub run: Option<u64>,
}

/// Result of `coverage_clear`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageClearOut {
    /// Runs removed.
    pub removed: u64,
    /// Runs left.
    pub remaining: u64,
}

/// Removes stored coverage.
pub struct CoverageClear;

#[async_trait]
impl Command for CoverageClear {
    type Args = CoverageClearArgs;
    type Output = CoverageClearOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "coverage_clear",
            "Remove one stored coverage run or all of them",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Deletes coverage kept by `debug_trace`; the overlay in the GUI goes with it. \
             Exports already written are not touched.\n\
             Example: coverage_clear {\"run\": 2}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: CoverageClearArgs,
    ) -> Result<CoverageClearOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        blocking(move || {
            with_file(&dir, |st| {
                let before = st.runs.len();
                st.runs
                    .retain(|r| args.run.is_some_and(|id| id != r.summary.id));
                Ok(CoverageClearOut {
                    removed: (before - st.runs.len()) as u64,
                    remaining: st.runs.len() as u64,
                })
            })
        })
        .await
    }
}

/// Writes an export, replacing a regular file but never following a link at `path`.
fn write_export(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other("it is a link"));
    }
    opts.open(path)?.write_all(bytes)
}

#[cfg(all(test, unix))]
mod export_tests {
    use super::write_export;

    #[test]
    fn an_export_replaces_a_file_but_never_follows_a_link() {
        let d = tempfile::tempdir().expect("tmp");
        let real = d.path().join("real");
        std::fs::write(&real, "old").expect("write");
        write_export(&real, b"new").expect("replace");
        assert_eq!(std::fs::read_to_string(&real).expect("read"), "new");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        assert!(write_export(&link, b"evil").is_err());
        assert_eq!(std::fs::read_to_string(&real).expect("read"), "new");
    }
}
