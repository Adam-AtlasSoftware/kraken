//! The analysis job. Loading already discovers functions, follows exception landing pads,
//! propagates noreturn, builds the reference index and the symbol lists, and applies known
//! prototypes, so the stages here report and complete that work:
//!
//! - `load`: the image and the function list (done by the loader; reported),
//! - `core`: references, imports and exports (built at load; reported) and the string scan,
//! - `expensive`: every function through the decompiler with the per-function limit, which
//!   fills in the signature of each function that had none and counts timeouts and failures.
//!
//! Cancelling the job stops it between functions, and a decompile in flight at its next action
//! break point.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{
    AnalysisJob, AnalysisSummary, AnalyzeRequest, Analyzer, EngineResult, Progress, ProgressSender,
    Stage,
};
use kraken_proto::{ErrorCode, ProtoError};
use tokio_util::sync::CancellationToken;

use crate::engine::{NativeEngine, Program, blocking, check, signature_of};

/// Strings reported by the core stage are at least this long (the default of the CLI).
const CORE_STRING_MIN: u32 = 4;

#[async_trait]
impl Analyzer for NativeEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        let p = self.program()?;
        let timeout = self.config.decompile_timeout;
        Ok(AnalysisJob::spawn(cancel, move |tx, token| {
            run(p, req, timeout, tx, token)
        }))
    }
}

fn progress(tx: &ProgressSender, stage: Stage, done: u64, total: u64, message: String) {
    tx.send(Progress {
        stage,
        done,
        total,
        message,
    });
}

async fn run(
    p: Arc<Program>,
    req: AnalyzeRequest,
    timeout: Option<Duration>,
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
                        p.functions.len(),
                        p.noreturn.len(),
                        p.loaded.landing_pads.values().map(Vec::len).sum::<usize>()
                    ),
                );
            }
            Stage::Core => {
                progress(&tx, stage, 1, 3, format!("{} references", p.refs.len()));
                check(&token)?;
                progress(
                    &tx,
                    stage,
                    2,
                    3,
                    format!("{} imports, {} exports", p.imports.len(), p.exports.len()),
                );
                check(&token)?;
                let q = p.clone();
                let n = blocking(move || Ok(q.strings(CORE_STRING_MIN).len())).await?;
                progress(&tx, stage, 3, 3, format!("{n} strings"));
            }
            Stage::Expensive => {
                let todo: Vec<(u64, String)> = p
                    .functions
                    .values()
                    .map(|f| (f.entry, f.name.clone()))
                    .collect();
                let total = todo.len() as u64;
                let (mut timeouts, mut failures) = (0u64, 0u64);
                progress(&tx, stage, 0, total, "decompiling".into());
                for (i, (at, name)) in todo.into_iter().enumerate() {
                    check(&token)?;
                    match p.decompile(at, timeout, &token).await {
                        Ok(d) => {
                            if let Some(sig) = signature_of(&d.text, &name) {
                                p.signatures().entry(at).or_insert(sig);
                            }
                        }
                        Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
                        Err(e) if e.code == ErrorCode::Timeout => timeouts += 1,
                        Err(_) => failures += 1,
                    }
                    progress(&tx, stage, i as u64 + 1, total, name);
                }
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
        function_count: p.functions.len() as u64,
    })
}
