//! The analysis job. Loading already discovers functions, follows exception landing pads,
//! propagates noreturn, builds the reference index and the symbol lists, and applies known
//! prototypes, so the stages here report and complete that work:
//!
//! - `load`: the image and the function list (done by the loader; reported),
//! - `core`: references, imports and exports (built at load; reported) and the string scan,
//! - `expensive`: every function through the decompiler with the per-function limit, which
//!   fills in the signature of each function that had none and counts timeouts and failures.
//!
//! The expensive stage runs on several decompiler sessions at once (as many as discovery uses):
//! each is a fork of the program's session ([`engine_native_sys::Session::fork`]), made from
//! its journal of edits, so it decompiles every function exactly as the program's session would,
//! and it replays the edits made while the job runs before its next function. The program's own
//! session stays free for the decompiles the user asks for. Each function's signature depends
//! only on its own decompile, so the result does not depend on the number of sessions
//! (`tests/parallel.rs`).
//!
//! Cancelling the job stops it between functions, and a decompile in flight at its next action
//! break point. With a state directory the finished job saves the signatures there.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use engine_native_sys::{Journal, NativeError, Session};
use kraken_engine::{
    AnalysisJob, AnalysisSummary, AnalyzeRequest, Analyzer, EngineResult, Progress, ProgressSender,
    Stage,
};
use kraken_proto::{ErrorCode, ProtoError};
use tokio_util::sync::CancellationToken;

use crate::engine::{InProcessEngine, Program, blocking, check, native, signature_of};

/// Strings reported by the core stage are at least this long (the default of the CLI).
const CORE_STRING_MIN: u32 = 4;

/// Programs with fewer functions are decompiled on the program's own session: setting up
/// another costs about a second.
const PARALLEL_MIN_FUNCTIONS: usize = 32;

#[async_trait]
impl Analyzer for InProcessEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        let p = self.program()?;
        let timeout = self.config.decompile_timeout;
        let state = self.config.state_dir.clone();
        let threads = self
            .config
            .discovery_threads
            .unwrap_or_else(crate::discover::default_threads);
        Ok(AnalysisJob::spawn(cancel, move |tx, token| async move {
            let summary = run(p.clone(), req, timeout, threads, tx, token).await?;
            // the signatures are the expensive part; a reopened project keeps them
            if let Some(dir) = state {
                blocking(move || crate::engine::persist(&p, &dir)).await?;
            }
            Ok(summary)
        }))
    }
}

fn progress(tx: &ProgressSender, stage: Stage, done: u64, total: u64, message: String) {
    tx.send(Progress {
        stage,
        done,
        total,
        message,
        step: None,
    });
}

async fn run(
    p: Arc<Program>,
    req: AnalyzeRequest,
    timeout: Option<Duration>,
    threads: usize,
    tx: ProgressSender,
    token: CancellationToken,
) -> Result<AnalysisSummary, ProtoError> {
    let first = req.resume_from.unwrap_or(Stage::Load);
    let mut completed = Vec::new();
    for stage in Stage::ALL.into_iter().filter(|s| *s >= first) {
        check(&token)?;
        match stage {
            Stage::Load => {
                progress(
                    &tx,
                    stage,
                    1,
                    1,
                    format!(
                        "{} memory blocks, {} functions ({} never return), {} landing pads",
                        p.loaded.blocks.len(),
                        p.funcs().len(),
                        p.noreturn().len(),
                        p.loaded.landing_pads.values().map(Vec::len).sum::<usize>()
                    ),
                );
            }
            Stage::Core => {
                progress(&tx, stage, 1, 3, format!("{} references", p.refs().len()));
                check(&token)?;
                progress(
                    &tx,
                    stage,
                    2,
                    3,
                    format!("{} imports, {} exports", p.imports.len(), p.exports().len()),
                );
                check(&token)?;
                let q = p.clone();
                let n = blocking(move || Ok(q.strings(CORE_STRING_MIN).len())).await?;
                progress(&tx, stage, 3, 3, format!("{n} strings"));
            }
            Stage::Expensive => {
                let todo = in_address_order(&p);
                let total = todo.len() as u64;
                progress(&tx, stage, 0, total, "decompiling".into());
                let lanes = if todo.len() >= PARALLEL_MIN_FUNCTIONS {
                    threads.max(1)
                } else {
                    1
                };
                let counts = if lanes > 1 {
                    decompile_side_by_side(&p, todo, lanes, timeout, &tx, &token).await?
                } else {
                    None
                };
                let Tally { timeouts, failures } = match counts {
                    Some(t) => t,
                    // one session, or no other session could be set up
                    None => decompile_in_turn(&p, timeout, &tx, &token).await?,
                };
                progress(
                    &tx,
                    stage,
                    total,
                    total,
                    format!(
                        "{total} functions decompiled, {timeouts} timed out, {failures} failed"
                    ),
                );
            }
        }
        completed.push(stage);
    }
    Ok(AnalysisSummary {
        stages_completed: completed,
        function_count: p.funcs().len() as u64,
    })
}

/// Functions the expensive stage could not decompile.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    timeouts: u64,
    failures: u64,
}

/// The functions to decompile, in address order. (Biggest first was measured too: it made the job
/// on Qt Core 28 % slower, with every session in a huge function at the same time.)
fn in_address_order(p: &Program) -> Vec<(u64, String)> {
    p.funcs()
        .map
        .values()
        .map(|f| (f.entry, f.name.clone()))
        .collect()
}

/// Records the signature a decompile shows for a function that has none yet.
fn note_signature(p: &Program, at: u64, name: &str, text: &str) {
    if let Some(sig) = signature_of(text, name) {
        p.signatures().entry(at).or_insert(sig);
    }
}

/// Decompiles every function on the program's session, one after the other.
async fn decompile_in_turn(
    p: &Arc<Program>,
    timeout: Option<Duration>,
    tx: &ProgressSender,
    token: &CancellationToken,
) -> Result<Tally, ProtoError> {
    let todo = in_address_order(p);
    let total = todo.len() as u64;
    let mut tally = Tally::default();
    for (i, (at, name)) in todo.into_iter().enumerate() {
        check(token)?;
        match p.decompile(at, timeout, false, token).await {
            Ok(d) => note_signature(p, at, &name, &d.text),
            Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
            Err(e) if e.code == ErrorCode::Timeout => tally.timeouts += 1,
            Err(_) => tally.failures += 1,
        }
        progress(tx, Stage::Expensive, i as u64 + 1, total, name);
    }
    Ok(tally)
}

/// What every lane of [`decompile_side_by_side`] reads.
struct Shared<'a> {
    p: &'a Program,
    todo: &'a [(u64, String)],
    timeout: Option<Duration>,
    tx: &'a ProgressSender,
    token: &'a CancellationToken,
    /// The program session's journal when the job began, and the edit count it goes with.
    origin: engine_native_sys::Origin,
    journal: Journal,
    synced: (usize, u64),
    /// The stop flags of the sessions set up so far, raised when the job is cancelled.
    stops: &'a Mutex<Vec<Arc<AtomicBool>>>,
    next: AtomicUsize,
    active: AtomicUsize,
    /// Functions done, behind the lock the progress reports are sent under (so they arrive in
    /// order).
    done: Mutex<u64>,
    tally: Mutex<Tally>,
    /// Set by a lane that met an error that ends the job.
    failed: Mutex<Option<ProtoError>>,
    started: AtomicUsize,
}

/// Decompiles every function on `lanes` forks of the program's session at once. `None` when not
/// one fork could be set up (the caller then decompiles on the program's session).
async fn decompile_side_by_side(
    p: &Arc<Program>,
    todo: Vec<(u64, String)>,
    lanes: usize,
    timeout: Option<Duration>,
    tx: &ProgressSender,
    token: &CancellationToken,
) -> Result<Option<Tally>, ProtoError> {
    let stops: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::default();
    let watcher = {
        let stops = stops.clone();
        let token = token.clone();
        tokio::spawn(async move {
            token.cancelled().await;
            for s in stops.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                s.store(true, Ordering::Relaxed);
            }
        })
    };
    let (q, tx, token2) = (p.clone(), tx.clone(), token.clone());
    let lanes = lanes.min(todo.len());
    let r = blocking(move || {
        let (origin, journal, synced) = {
            let s = q.session();
            // the edit count first: an edit that lands after it is replayed by the lanes
            let epoch = q.epoch();
            (s.origin(), s.journal_since(0), (s.journal_len(), epoch))
        };
        let shared = Shared {
            p: &q,
            todo: &todo,
            timeout,
            tx: &tx,
            token: &token2,
            origin,
            journal,
            synced,
            stops: &stops,
            next: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            done: Mutex::new(0),
            tally: Mutex::new(Tally::default()),
            failed: Mutex::new(None),
            started: AtomicUsize::new(0),
        };
        std::thread::scope(|s| {
            for _ in 0..lanes {
                let shared = &shared;
                // fewer lanes are slower, not wrong
                let _ = std::thread::Builder::new()
                    .name("kraken-analyze".into())
                    .stack_size(crate::discover::WALK_STACK)
                    .spawn_scoped(s, move || lane(shared));
            }
        });
        // the forks are gone; give their memory back
        crate::engine::release_free_memory();
        if let Some(e) = shared
            .failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return Err(e);
        }
        check(&token2)?;
        if shared.started.load(Ordering::SeqCst) == 0 {
            return Ok(None);
        }
        let all_done = *shared.done.lock().unwrap_or_else(|e| e.into_inner()) as usize;
        if all_done < todo.len() {
            return Err(ProtoError::new(
                ErrorCode::Internal,
                format!(
                    "the analysis sessions stopped after {all_done} of {} functions",
                    todo.len()
                ),
            ));
        }
        let tally = *shared.tally.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Some(tally))
    })
    .await;
    watcher.abort();
    r
}

/// One lane: sets up its fork, then decompiles the next function not taken until none is left.
fn lane(sh: &Shared) {
    let mut session = match Session::from_origin(&sh.origin) {
        Ok(s) => s,
        Err(_) => return,
    };
    if session.replay(&sh.journal).is_err() {
        return;
    }
    let stop = session.stop_flag();
    sh.stops
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(stop.clone());
    if sh.token.is_cancelled() {
        return;
    }
    sh.started.fetch_add(1, Ordering::SeqCst);
    let (mut journal_at, mut epoch) = sh.synced;
    let fail = |e: ProtoError| {
        sh.failed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert(e);
        sh.next.store(sh.todo.len(), Ordering::SeqCst);
    };
    loop {
        // one decompile can take gigabytes: with little memory left a lane waits for the
        // others (one always goes on)
        while sh.active.load(Ordering::SeqCst) > 0 && crate::discover::low_on_memory() {
            if sh.token.is_cancelled() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let i = sh.next.fetch_add(1, Ordering::SeqCst);
        let Some((at, name)) = sh.todo.get(i) else {
            return;
        };
        if sh.token.is_cancelled() {
            return;
        }
        // edits made since the fork (or the last function) are made here too
        if sh.p.epoch() != epoch {
            let tail = {
                let s = sh.p.session();
                epoch = sh.p.epoch();
                let tail = s.journal_since(journal_at);
                journal_at = s.journal_len();
                tail
            };
            if let Err(e) = session.replay(&tail) {
                fail(native(e));
                return;
            }
        }
        let comments = {
            let funcs = sh.p.funcs();
            let edits = sh.p.edits();
            funcs
                .get(*at)
                .map(|f| edits.decompiler_comments(f))
                .unwrap_or_default()
        };
        sh.active.fetch_add(1, Ordering::SeqCst);
        let r = session
            .set_comments(*at, &comments)
            .and_then(|()| session.decompile(*at, sh.timeout));
        sh.active.fetch_sub(1, Ordering::SeqCst);
        match r {
            Ok(d) => note_signature(sh.p, *at, name, &d.text),
            Err(NativeError::Interrupted) => {
                stop.store(false, Ordering::Relaxed);
                if sh.token.is_cancelled() {
                    return;
                }
                sh.tally.lock().unwrap_or_else(|p| p.into_inner()).failures += 1;
            }
            Err(NativeError::Timeout(_)) => {
                sh.tally.lock().unwrap_or_else(|p| p.into_inner()).timeouts += 1;
            }
            Err(e @ NativeError::Unavailable(_)) => {
                fail(native(e));
                return;
            }
            Err(NativeError::Native(_)) => {
                sh.tally.lock().unwrap_or_else(|p| p.into_inner()).failures += 1;
            }
        }
        let mut done = sh.done.lock().unwrap_or_else(|p| p.into_inner());
        *done += 1;
        progress(
            sh.tx,
            Stage::Expensive,
            *done,
            sh.todo.len() as u64,
            name.clone(),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use kraken_engine::{Loader, LoaderSpec};

    use super::*;
    use crate::{Isolation, NativeConfig};

    /// Binaries with switches, C++, static C library code, 32-bit x86 PIC and PE.
    const BINARIES: &[&str] = &[
        "bin/switch_vm-O2-stripped",
        "bin/cpp_shapes-O2",
        "bin/static_strops-O2",
        "elf32/bin/switch_vm-i386-O2-stripped",
        "pe/bin/switch_vm-x64-O2.exe",
        "pe/bin/win_tls-x86-O2-stripped.exe",
    ];

    fn corpus(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(name)
    }

    fn config() -> Option<NativeConfig> {
        let mut c = NativeConfig::discover()?;
        if !InProcessEngine::is_usable(&c) {
            return None;
        }
        c.isolation = Isolation::InProcess;
        Some(c)
    }

    async fn open(c: &NativeConfig, name: &str) -> Arc<Program> {
        let e = InProcessEngine::new(c.clone());
        e.open_binary(
            &corpus(name),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open");
        e.program().expect("program")
    }

    fn texts(s: &mut Session, entries: &[u64]) -> BTreeMap<u64, String> {
        entries
            .iter()
            .map(|a| {
                let t = s
                    .decompile(*a, None)
                    .map(|d| d.text)
                    .unwrap_or_else(|e| format!("error: {e}"));
                (*a, t)
            })
            .collect()
    }

    /// A fork decompiles every function exactly as the session it came from, in any order, and
    /// an edit replayed from the journal reaches it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fork_decompiles_like_its_session() {
        let Some(c) = config() else {
            eprintln!("skipped: no native decompiler or spec tree");
            return;
        };
        for name in BINARIES {
            let p = open(&c, name).await;
            let entries: Vec<u64> = p.funcs().map.keys().copied().collect();
            let mut main = p.session();
            let mine = texts(&mut main, &entries);
            let mut fork = main.fork().expect("fork");
            let mut backwards = entries.clone();
            backwards.reverse();
            let theirs = texts(&mut fork, &backwards);
            for (a, t) in &mine {
                assert_eq!(Some(t), theirs.get(a), "{name}: {a:#x}");
            }

            // a rename on the session, replayed on the fork from the journal
            let callee = p
                .funcs()
                .map
                .values()
                .rev()
                .find(|f| !f.name.starts_with('_'))
                .map(|f| f.entry)
                .expect("a function");
            let at = main.journal_len();
            main.add_function(callee, "renamed_by_the_test")
                .expect("rename");
            fork.replay(&main.journal_since(at)).expect("replay");
            let mine = texts(&mut main, &entries);
            let theirs = texts(&mut fork, &entries);
            assert_eq!(mine, theirs, "{name}: after the rename");
            assert!(
                mine.values().any(|t| t.contains("renamed_by_the_test")),
                "{name}: the rename shows"
            );
        }
    }

    /// The expensive stage finds the same signatures on four sessions as on the program's own.
    #[tokio::test(flavor = "multi_thread")]
    async fn lanes_do_not_change_the_signatures() {
        let Some(c) = config() else {
            eprintln!("skipped: no native decompiler or spec tree");
            return;
        };
        for name in BINARIES {
            let one = open(&c, name).await;
            let four = open(&c, name).await;
            let tallies: Arc<Mutex<Vec<Tally>>> = Arc::default();
            let out = tallies.clone();
            let (p1, p4) = (one.clone(), four.clone());
            let job = AnalysisJob::spawn(CancellationToken::new(), move |tx, token| async move {
                let t1 = decompile_in_turn(&p1, None, &tx, &token).await?;
                let todo = in_address_order(&p4);
                let t4 = decompile_side_by_side(&p4, todo, 4, None, &tx, &token)
                    .await?
                    .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "no lanes"))?;
                out.lock().expect("tallies").extend([t1, t4]);
                Ok(AnalysisSummary {
                    stages_completed: vec![Stage::Expensive],
                    function_count: 0,
                })
            });
            job.wait().await.expect("both runs");
            let t = tallies.lock().expect("tallies");
            assert_eq!(
                (t[0].timeouts, t[0].failures),
                (t[1].timeouts, t[1].failures),
                "{name}"
            );
            assert!(!one.signatures().is_empty(), "{name}");
            assert_eq!(*one.signatures(), *four.signatures(), "{name}");
        }
    }
}
