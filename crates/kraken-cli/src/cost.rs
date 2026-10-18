//! Asking before spending: the estimate printed before AI work starts, the question, and the
//! usage line printed after it.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;

use kraken_assist::{
    AiPolicy, AssistBackend, Meter, MeterSpec, RewriteModel, provider_config_path, rewrite_choice,
    rewrite_max_calls,
};
use kraken_model::{DailyLedger, ProjectLedger};
use kraken_proto::{AiEstimate, AiFeature, AiOrigin, ErrorCode, ProtoError};
use serde_json::Value;

use crate::app::{CliEnv, emit};

/// The registry commands that call a model.
pub(crate) const AI_COMMANDS: [&str; 3] = ["rewrite_function", "rewrite_spec", "rewrite_program"];

/// The config file the CLI reads.
pub(crate) fn config_path(env: &CliEnv) -> Option<PathBuf> {
    provider_config_path(&|k| env.var(k).map(OsString::from))
}

/// The models, prices and limits of the config file.
pub(crate) fn policy(env: &CliEnv) -> AiPolicy {
    AiPolicy::load(config_path(env).as_deref())
}

/// The daily totals file.
pub(crate) fn daily(env: &CliEnv) -> Option<DailyLedger> {
    DailyLedger::from_env(&|k| env.var(k).map(OsString::from))
}

/// Refuses when today's budget is used up, prints `estimate` (when there is one) and asks
/// whether to go on. `yes` answers for the person; without it a run that needs an answer is
/// refused when there is no terminal to ask on.
pub(crate) fn confirm(
    env: &CliEnv,
    policy: &AiPolicy,
    estimate: Option<&AiEstimate>,
    yes: bool,
    err: &mut dyn Write,
) -> Result<(), ProtoError> {
    if let Some(d) = daily(env)
        && let Some(msg) = policy.daily_refusal(d.today().cost_usd)
    {
        return Err(ProtoError::new(ErrorCode::Cancelled, msg));
    }
    let Some(e) = estimate else {
        return Ok(());
    };
    emit(
        err,
        &format!("This uses AI. {}\n", e.text().replace('\n', " ")),
    );
    if !policy.needs_confirm(e) || yes {
        return Ok(());
    }
    if !(env.interactive && std::io::stdin().is_terminal()) {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!(
                "this starts AI work that may cost money ({}); run it in a terminal to answer \
                 the question, or pass --yes to go ahead",
                e.cost_text()
            ),
        ));
    }
    emit(err, "Go ahead? [y/N] ");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(ProtoError::new(
            ErrorCode::Cancelled,
            "not started: you did not confirm the AI work",
        ))
    }
}

/// The refusal [`confirm`] would give for lack of a terminal, without asking anything: lets a
/// multi-step command fail before its first step.
pub(crate) fn refuse_unattended(
    env: &CliEnv,
    policy: &AiPolicy,
    estimate: Option<&AiEstimate>,
    yes: bool,
) -> Result<(), ProtoError> {
    if let Some(d) = daily(env)
        && let Some(msg) = policy.daily_refusal(d.today().cost_usd)
    {
        return Err(ProtoError::new(ErrorCode::Cancelled, msg));
    }
    match estimate {
        Some(e)
            if policy.needs_confirm(e)
                && !yes
                && !(env.interactive && std::io::stdin().is_terminal()) =>
        {
            Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "this starts AI work that may cost money ({}); run it in a terminal to \
                     answer the question, or pass --yes to go ahead",
                    e.cost_text()
                ),
            ))
        }
        _ => Ok(()),
    }
}

/// The estimate of a registry command that calls a model; `functions` is the number of
/// functions in the stored plan (for `rewrite_program`).
pub(crate) fn command_estimate(
    env: &CliEnv,
    policy: &AiPolicy,
    name: &str,
    args: &Value,
    functions: Option<u64>,
) -> Option<AiEstimate> {
    let text = |k: &str| args.get(k).and_then(Value::as_str);
    let which = RewriteModel::parse(text("provider").unwrap_or("")).ok()?;
    let choice = rewrite_choice(config_path(env).as_deref(), which, text("model")).ok()?;
    let attempts = args
        .get("max_attempts")
        .and_then(Value::as_u64)
        .and_then(|a| u32::try_from(a).ok())
        .unwrap_or(kraken_assist::REWRITE_ATTEMPTS);
    let (min, max) = match name {
        "rewrite_function" => (
            1,
            rewrite_max_calls(1, attempts, text("mode") == Some("spec"), 0),
        ),
        "rewrite_spec" => (1, 1),
        "rewrite_program" => {
            let rounds = args
                .get("repair_rounds")
                .and_then(Value::as_u64)
                .and_then(|r| u32::try_from(r).ok())
                .unwrap_or(kraken_registry::commands::DEFAULT_REPAIR_ROUNDS);
            let n = functions.unwrap_or(1).max(1);
            (n, rewrite_max_calls(n, attempts, false, rounds))
        }
        _ => return None,
    };
    Some(policy.estimate_with(AiFeature::Rewrite, &choice, min, max))
}

/// A meter for an assistant task run from the command line: the project ledger, the daily
/// totals, the prices and the limits of the config file.
pub(crate) fn task_meter(
    env: &CliEnv,
    policy: &AiPolicy,
    feature: AiFeature,
    run_id: Option<String>,
    project: Option<&std::path::Path>,
    daily_totals: bool,
) -> Meter {
    let mut spec = MeterSpec::new(feature, AiOrigin::Cli);
    if let Some(r) = run_id {
        spec = spec.run(r);
    }
    let mut b = Meter::builder(spec)
        .pricing(policy.pricing.clone())
        .limits(policy.limits.clone())
        .daily(if daily_totals { daily(env) } else { None });
    if let Some(c) = policy.choice_for(feature) {
        b = b.kind(c.kind);
    }
    if let Some(dir) = project {
        b = b.sink(Arc::new(ProjectLedger::new(
            dir.join(kraken_registry::session::DB_FILE),
        )));
    }
    b.build()
}

/// `engine` with `meter` around it.
pub(crate) fn metered(meter: &Meter, engine: Arc<dyn AssistBackend>) -> Arc<dyn AssistBackend> {
    meter.wrap(engine)
}
