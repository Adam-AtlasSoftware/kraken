//! The bounded repair loop of a translation.
//!
//! A translation that does not compile, is refused by the source lint or disagrees with the
//! original is not final: the compiler output or the smallest counterexample goes back to the
//! model together with its previous code, for up to a fixed number of attempts. Every attempt is
//! stored as a version (see [`crate::unit::RepairLink`]), so the history shows what was tried.
//! A passing attempt ends the loop. An `inconclusive` verdict does not repair: the model cannot
//! fix what the oracle could not run.
//!
//! The loop does not know how verification works: the caller passes a closure that checks and
//! stores one attempt. That keeps the loop testable with a cassette and a fake verifier, and the
//! service passes the sandboxed differential test.

use std::future::Future;

use kraken_agent::ChatProvider;
use kraken_registry::commands::UnitStatus;
use tokio_util::sync::CancellationToken;

use crate::abi::Arg;
use crate::difftest::{Counterexample, Verdict};
use crate::error::RewriteError;
use crate::task::{ModelReply, RewriteOutput, RewriteTask};
use crate::unit::{Provenance, RepairLink, RewriteUnit};

/// Default number of attempts of `rewrite_function`.
pub const DEFAULT_ATTEMPTS: u32 = 3;
/// Most attempts a caller may ask for.
pub const MAX_ATTEMPTS: u32 = 8;
/// Longest feedback text sent back (compiler output or counterexample), in bytes.
pub const MAX_FEEDBACK: usize = 4000;
/// Longest previous code sent back, in bytes.
pub const MAX_PREVIOUS_CODE: usize = 16_000;

/// What went wrong with an attempt, as told to the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feedback {
    /// `compile` (rustc rejected it), `rejected` (the source lint refused it), `counterexample`
    /// (it ran and disagreed) or `reply` (the answer could not be used).
    pub kind: &'static str,
    /// The details: compiler output, the lint's reason, the counterexample or the parse error.
    /// Compiler output and counterexamples come from running model code against the binary, so
    /// they go into the prompt only inside an untrusted block.
    pub text: String,
}

/// One failed attempt and why it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRound {
    /// The code of the failed attempt.
    pub previous_code: String,
    /// What to fix.
    pub feedback: Feedback,
}

/// `text` cut to `max` bytes at a character boundary, with a note of what was cut.
pub fn cut_text(text: &str, max: usize) -> String {
    cut(text, max)
}

fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[... {} more bytes cut]",
        &text[..end],
        text.len() - end
    )
}

/// Renders the counterexample for the model: arguments, then what each side did.
pub fn describe_counterexample(c: &Counterexample) -> String {
    let args: Vec<String> = c
        .args
        .iter()
        .map(|a| match a {
            Arg::Int { value } => format!("{} ({value:#x})", *value as i64),
            Arg::Buf { data } => {
                let shown: String = data.iter().take(64).map(|b| format!("{b:02x}")).collect();
                let more = if data.len() > 64 { "..." } else { "" };
                format!("buffer of {} bytes {shown}{more}", data.len())
            }
            Arg::Double { bits } => format!("{} (bits {bits:#x})", f64::from_bits(*bits)),
            Arg::FnPtr { callback } => format!("the host callback {callback:?}"),
            Arg::Graph { objects, links } => {
                let mut s = String::from("pointer graph:");
                for (i, o) in objects.iter().enumerate() {
                    let shown: String = o.iter().take(48).map(|b| format!("{b:02x}")).collect();
                    let more = if o.len() > 48 { "..." } else { "" };
                    s.push_str(&format!("\n  object {i}: {} bytes {shown}{more}", o.len()));
                }
                for l in links {
                    s.push_str(&format!(
                        "\n  object {} offset {} points to object {} offset {}",
                        l.from, l.offset, l.to, l.to_offset
                    ));
                }
                s
            }
        })
        .collect();
    format!(
        "arguments: {}\nthe original and your translation differ:\n- {}",
        args.join(", "),
        c.differences.join("\n- ")
    )
}

/// The feedback a failed unit gives, or `None` when it is not a failure the model can repair
/// (passed, or inconclusive).
pub fn feedback_for(unit: &RewriteUnit) -> Option<Feedback> {
    if unit.status != UnitStatus::Failed {
        return None;
    }
    match &unit.verdict {
        Verdict::Rejected { reason } => {
            let kind = if reason.starts_with("does not compile") {
                "compile"
            } else {
                "rejected"
            };
            Some(Feedback {
                kind,
                text: cut(reason, MAX_FEEDBACK),
            })
        }
        Verdict::Fail => {
            let text = unit.counterexamples.first().map_or_else(
                || "the test found a difference".to_string(),
                describe_counterexample,
            );
            Some(Feedback {
                kind: "counterexample",
                text: cut(&text, MAX_FEEDBACK),
            })
        }
        _ => None,
    }
}

/// Previous code, cut to the prompt limit.
pub fn previous_code(code: &str) -> String {
    cut(code, MAX_PREVIOUS_CODE)
}

/// What the closure of [`run`] is asked to check.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// The parsed reply.
    pub output: RewriteOutput,
    /// Who wrote it (`task` is `rewrite_function` for the first attempt and
    /// `rewrite_function/repair` for the later ones).
    pub provenance: Provenance,
    /// Where it stands in the run.
    pub link: RepairLink,
}

/// A finished run.
#[derive(Debug, Clone)]
pub struct RepairRun {
    /// Each attempt's stored unit and parsed reply, in order. Never empty.
    pub attempts: Vec<(RewriteUnit, RewriteOutput)>,
}

impl RepairRun {
    /// The last attempt, which is the result of the run.
    pub fn last(&self) -> &(RewriteUnit, RewriteOutput) {
        self.attempts
            .last()
            .expect("a repair run has at least one attempt")
    }
}

/// Runs the loop: ask for a translation, have `check` verify and store it, and while the result
/// is a repairable failure and attempts remain, ask again with the failure fed back.
///
/// A reply that cannot be parsed fails the run on the first attempt (the same error as before
/// the loop existed). Later it costs an attempt: the model is told what was wrong with its
/// reply and asked again.
pub async fn run<F, Fut>(
    task: &RewriteTask,
    provider: &dyn ChatProvider,
    cancel: CancellationToken,
    max_attempts: u32,
    mut check: F,
) -> Result<RepairRun, RewriteError>
where
    F: FnMut(Attempt) -> Fut,
    Fut: Future<Output = Result<RewriteUnit, RewriteError>>,
{
    let max = max_attempts.clamp(1, MAX_ATTEMPTS);
    let mut task = task.clone();
    let mut attempts: Vec<(RewriteUnit, RewriteOutput)> = Vec::new();
    for n in 1..=max {
        if cancel.is_cancelled() {
            return Err(RewriteError::Cancelled);
        }
        let reply: ModelReply =
            crate::task::complete_text(provider, task.request(), cancel.clone()).await?;
        let output = match task.parse(&reply.text) {
            Ok(o) => o,
            Err(e @ RewriteError::Output(_)) if n > 1 => {
                let (last, _) = attempts.last().expect("attempt 1 produced a unit");
                task.repairs.push(RepairRound {
                    previous_code: previous_code(&last.rust_code),
                    feedback: Feedback {
                        kind: "reply",
                        text: format!("your reply could not be used: {e}"),
                    },
                });
                continue;
            }
            Err(e) => return Err(e),
        };
        let link = RepairLink {
            attempt: n,
            repair_of: attempts.last().map(|(u, _)| u.version),
            feedback: task.repairs.last().map(|r| r.feedback.kind.to_string()),
        };
        let provenance = Provenance {
            author: "model".into(),
            provider: Some(reply.provider.id.clone()),
            model: Some(reply.provider.model.clone()),
            task: if n == 1 {
                "rewrite_function".into()
            } else {
                "rewrite_function/repair".into()
            },
            prompt_hash: reply.prompt_hash.clone(),
        };
        let unit = check(Attempt {
            output: output.clone(),
            provenance,
            link,
        })
        .await?;
        let next = feedback_for(&unit);
        let code = unit.rust_code.clone();
        attempts.push((unit, output));
        match next {
            Some(feedback) if n < max => task.repairs.push(RepairRound {
                previous_code: previous_code(&code),
                feedback,
            }),
            _ => break,
        }
    }
    if attempts.is_empty() {
        return Err(RewriteError::Output(
            "no usable reply within the allowed attempts".into(),
        ));
    }
    Ok(RepairRun { attempts })
}
