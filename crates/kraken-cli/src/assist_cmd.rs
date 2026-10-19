//! `kraken explain | overview | auto-name | glossary`: the assistant beside the registry commands.
//!
//! Text streams to stdout, tool calls to stderr, `--json` prints one structured result to stdout
//! (the model's text is then not streamed). The provider comes from the `[provider]` table of
//! `config.toml`; see `docs/assistant.md`.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::ArgMatches;
use kraken_acp::McpServerConfig;
use kraken_agent::{AgentEvent, ChatProvider, EnvSecrets, StopReason};
use kraken_assist::{
    AcpBackend, AgentChoice, ApiBackend, Arch, AssistBackend, Assistant, AutoNameOptions,
    AutoNameReport, Explanation, Glossary, GlossaryMatch, Outcome, Overview, ResultTagFilter, Task,
    TaskOutput, TaskResult, UnusedBackend, load_provider_config, plan_agent, provider_config_path,
};
use kraken_engine::CancellationToken;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::Surface;
use serde_json::json;

use crate::app::{CliEnv, bad, emit, fail, save};

/// What the `[provider]` table selects.
pub(crate) enum Selection {
    /// A chat model API.
    Api(Arc<dyn ChatProvider>),
    /// A terminal agent (`kind = "terminal_agent"`).
    Agent(AgentChoice),
}

pub(crate) fn selection_from_config(env: &CliEnv) -> Result<Selection, ProtoError> {
    let path = provider_config_path(&|k| env.var(k).map(OsString::from));
    let cfg = load_provider_config(path.as_deref()).map_err(|e| bad(e.to_string()))?;
    if let Some(choice) = AgentChoice::from_config(&cfg) {
        return Ok(Selection::Agent(choice));
    }
    kraken_assist::build_provider(&cfg, &EnvSecrets)
        .map(Selection::Api)
        .map_err(|e| bad(format!("provider: {e}")))
}

/// Builds the terminal-agent backend for `choice` on the project directory `project`, after the
/// one-time notice.
/// The terminal agent backend. Its MCP server runs `kraken mcp`: through the daemon when this
/// command uses one, through the daemon in `private_daemon` (a runtime directory) when given,
/// else with its own in-process session.
pub(crate) fn agent_backend(
    env: &CliEnv,
    sm: &ArgMatches,
    choice: &AgentChoice,
    project: Option<&str>,
    private_daemon: Option<&std::path::Path>,
    err: &mut dyn Write,
) -> Result<Arc<dyn AssistBackend>, ProtoError> {
    let dir = match project {
        Some(p) => std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p)),
        None => env
            .session
            .as_ref()
            .and_then(|s| s.project().ok())
            .map(|p| p.dir().to_path_buf())
            .ok_or_else(|| bad("no project: pass --project <dir> or set KRAKEN_PROJECT"))?,
    };
    if !dir.is_dir() {
        return Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("project directory {} does not exist", dir.display()),
        ));
    }
    let profiles = crate::agents_cmd::catalogue(env)?;
    let resolver = crate::agents_cmd::resolver(env)?;
    let exe = env
        .var("KRAKEN_EXE")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "cannot find the kraken executable"))?;
    let use_daemon = private_daemon.is_some()
        || (!env.no_daemon(sm)
            && env.session.is_none()
            && !matches!(env.daemon, crate::app::DaemonMode::Direct));
    let mut mcp = if use_daemon {
        McpServerConfig::daemon(exe, Some(&dir))
    } else {
        McpServerConfig::project(exe, &dir)
    };
    if let Some(runtime) = private_daemon {
        mcp = mcp.with_env("KRAKEN_RUNTIME_DIR", runtime.to_string_lossy());
    } else {
        for key in ["KRAKEN_RUNTIME_DIR", "KRAKEN_NO_DAEMON"] {
            if let Some(v) = env.var(key) {
                mcp = mcp.with_env(key, v);
            }
        }
        // The agent is not given `XDG_RUNTIME_DIR`, so its MCP server is told where the daemon
        // is.
        if use_daemon
            && env.var("KRAKEN_RUNTIME_DIR").is_none()
            && let Some((k, v)) = kraken_host::daemon::mcp_runtime_env()
        {
            mcp = mcp.with_env(k, v);
        }
    }
    let settings = plan_agent(&resolver, &profiles, choice, &dir, mcp).map_err(|e| {
        let code = match e {
            kraken_assist::PlanError::NeedsSetup { .. } => ErrorCode::InvalidArgument,
            kraken_assist::PlanError::Unavailable { .. } => ErrorCode::Unsupported,
        };
        ProtoError::new(code, e.to_string())
    })?;
    crate::agents_cmd::show_notice_once(env, err);
    Ok(Arc::new(AcpBackend::new(settings, env.registry.clone())))
}

fn clip(s: &str, max: usize) -> String {
    let one_line = s.replace(['\n', '\r', '\t'], " ");
    if one_line.chars().count() > max {
        let cut: String = one_line.chars().take(max).collect();
        format!("{cut}...")
    } else {
        one_line
    }
}

fn build_task(env: &CliEnv, sub: &str, sm: &ArgMatches) -> Result<Task, ProtoError> {
    match sub {
        "explain" => {
            let address = sm
                .get_one::<String>("address")
                .ok_or_else(|| bad("missing ADDRESS"))?;
            Task::explain_function(&env.registry, address).map_err(|e| bad(e.to_string()))
        }
        "overview" => Ok(Task::overview(&env.registry)),
        _ => {
            let limit = sm.get_one::<usize>("limit").copied().unwrap_or(10);
            if limit == 0 || limit > kraken_assist::tasks::MAX_AUTONAME_LIMIT {
                return Err(bad(format!(
                    "--limit must be between 1 and {}",
                    kraken_assist::tasks::MAX_AUTONAME_LIMIT
                )));
            }
            Ok(Task::auto_name(
                &env.registry,
                AutoNameOptions {
                    limit,
                    dry_run: sm.get_flag("dry-run"),
                },
            ))
        }
    }
}

/// Runs one assistant task and returns the exit code.
pub(crate) async fn run_assist(
    env: &CliEnv,
    sub: &str,
    sm: &ArgMatches,
    json_out: bool,
    provider: Option<Arc<dyn ChatProvider>>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let provider_injected = provider.is_some();
    let selection = match provider {
        Some(p) => Selection::Api(p),
        None => match selection_from_config(env) {
            Ok(s) => s,
            Err(e) => return fail(&e, json_out, err),
        },
    };
    let task = match build_task(env, sub, sm) {
        Ok(t) => t,
        Err(e) => return fail(&e, json_out, err),
    };
    let project = sm
        .get_one::<String>("project")
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"));
    if project.is_none() && !env.session.as_ref().is_some_and(|s| s.project().is_ok()) {
        return fail(
            &bad("no project: pass --project <dir> or set KRAKEN_PROJECT"),
            json_out,
            err,
        );
    }
    execute_task(
        env,
        sm,
        project.as_deref(),
        None,
        None,
        selection,
        task,
        json_out,
        provider_injected,
        out,
        err,
    )
    .await
    .0
}

/// A command backend already in use, with its session when it runs in this process.
pub(crate) type SharedBackend = (
    Arc<dyn kraken_host::backend::CommandBackend>,
    Option<Arc<kraken_registry::Session>>,
);

/// Runs `task` on the assistant `selection` names and prints the result. With `shared`, a model
/// API runs its tools through that backend (the caller keeps it open and shuts the engines
/// down); without it this opens its own and cleans up. Returns the exit code and the result.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_task(
    env: &CliEnv,
    sm: &ArgMatches,
    project: Option<&str>,
    shared: Option<SharedBackend>,
    private_daemon: Option<&std::path::Path>,
    selection: Selection,
    task: Task,
    json_out: bool,
    provider_injected: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> (i32, Option<TaskResult>) {
    let owns_backend = shared.is_none();
    // Ask before spending. A provider handed in by embedding code (tests) is not the person's
    // configured one, so there is nothing to estimate.
    let policy = crate::cost::policy(env);
    let feature = task.kind.feature();
    if !provider_injected {
        let estimate = policy.estimate(feature, 1, task.max_model_calls());
        if let Err(e) =
            crate::cost::confirm(env, &policy, estimate.as_ref(), sm.get_flag("yes"), err)
        {
            return (fail(&e, json_out, err), None);
        }
    }
    // A terminal agent reaches the project through its own `kraken mcp` server, so this process
    // does not open it; a model API runs its tools through this process's backend.
    let (engine, backend, local_session): (
        Arc<dyn AssistBackend>,
        Arc<dyn kraken_host::backend::CommandBackend>,
        _,
    ) = match selection {
        Selection::Api(p) => {
            let (backend, session) = match shared {
                Some(s) => s,
                None => match env.backend(project, env.no_daemon(sm), err).await {
                    Ok(b) => b,
                    Err(e) => {
                        env.factory.shutdown().await;
                        return (fail(&e, json_out, err), None);
                    }
                },
            };
            (Arc::new(ApiBackend::new(p)), backend, session)
        }
        Selection::Agent(choice) => {
            match agent_backend(env, sm, &choice, project, private_daemon, err) {
                Ok(engine) => (engine, Arc::new(UnusedBackend), None),
                Err(e) => return (fail(&e, json_out, err), None),
            }
        }
    };

    let project_dir = project
        .map(|p| std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p)))
        .or_else(|| {
            env.session
                .as_ref()
                .and_then(|s| s.project().ok())
                .map(|p| p.dir().to_path_buf())
        });
    let meter = crate::cost::task_meter(
        env,
        &policy,
        feature,
        None,
        project_dir.as_deref(),
        !provider_injected,
    );
    let engine = crate::cost::metered(&meter, engine);
    let info = engine.info();
    match info.kind {
        kraken_assist::BackendKind::Api => emit(
            err,
            &format!(
                "provider: {} ({})\n",
                info.id,
                info.model.as_deref().unwrap_or("")
            ),
        ),
        kraken_assist::BackendKind::TerminalAgent => emit(
            err,
            &format!(
                "terminal agent: {} ({})\n",
                info.name,
                info.model.as_deref().unwrap_or("model chosen by the agent")
            ),
        ),
    }
    let writes = !task.read_only;
    let assistant = Assistant::with_engine(env.registry.clone(), backend.clone(), engine.clone())
        .with_surface(Surface::Cli);

    let cancel = CancellationToken::new();
    let ctrl_c = env.interactive.then(|| {
        let c = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                c.cancel();
            }
        })
    });

    let mut filter = ResultTagFilter::new();
    let mut streamed_text = false;
    let mut at_line_start = true;
    let result = {
        let mut on_event = |ev: &AgentEvent| match ev {
            AgentEvent::TextDelta { text } if !json_out => {
                let shown = filter.push(text);
                if !shown.trim().is_empty() {
                    streamed_text = true;
                }
                if !shown.is_empty() {
                    at_line_start = shown.ends_with('\n');
                    emit(out, &shown);
                }
            }
            AgentEvent::ToolCallStarted {
                name, arguments, ..
            } => {
                if !json_out {
                    let rest = filter.finish();
                    emit(out, &rest);
                    if !rest.is_empty() {
                        at_line_start = rest.ends_with('\n');
                    }
                    if !at_line_start {
                        emit(out, "\n");
                        at_line_start = true;
                    }
                    filter.reset();
                }
                emit(
                    err,
                    &format!("  > {name} {}\n", clip(&arguments.to_string(), 120)),
                );
            }
            AgentEvent::ToolCallFinished {
                summary, is_error, ..
            } => {
                let tag = if *is_error { "error" } else { "ok" };
                emit(err, &format!("    {tag}: {}\n", clip(summary, 100)));
            }
            AgentEvent::ApprovalRequired { name, .. } => {
                emit(
                    err,
                    &format!(
                        "  ! the agent asked to use its own tool ({}): declined, because this command runs unattended\n",
                        clip(name, 80)
                    ),
                );
            }
            AgentEvent::ProposalCreated { tool, proposal, .. } => {
                emit(
                    err,
                    &format!(
                        "  ! {tool} became a proposal for you to review: {}\n",
                        clip(&proposal.to_string(), 100)
                    ),
                );
            }
            _ => {}
        };
        assistant.run(task, &cancel, &mut on_event).await
    };
    if let Some(h) = ctrl_c {
        h.abort();
    }
    if !json_out {
        emit(out, &filter.finish());
    }

    let code = finish(&result, json_out, streamed_text, out, err);
    if !json_out && meter.totals().calls > 0 {
        emit(err, &format!("AI usage: {}\n", meter.totals().line()));
    }
    if let Some(m) = meter.limit_message() {
        emit(err, &format!("{m}\n"));
    }
    if writes
        && owns_backend
        && let Some(session) = &local_session
    {
        save(session, err).await;
    }
    for w in backend.take_warnings() {
        emit(err, &format!("warning: {w}\n"));
    }
    engine.close();
    if owns_backend {
        env.factory.shutdown().await;
    }
    (code, Some(result))
}

fn finish(
    r: &TaskResult,
    json_out: bool,
    streamed_text: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    for n in &r.notes {
        emit(err, &format!("note: {n}\n"));
    }
    for w in &r.warnings {
        emit(err, &format!("warning: {w}\n"));
    }
    if json_out {
        let v = serde_json::to_string(r).unwrap_or_else(|_| "{}".into());
        emit(out, &format!("{v}\n"));
    } else {
        if streamed_text {
            emit(out, "\n");
        }
        match &r.output {
            Some(TaskOutput::Explanation(e)) => emit(out, &render_explanation(e, streamed_text)),
            Some(TaskOutput::Overview(o)) => emit(out, &render_overview(o, streamed_text)),
            Some(TaskOutput::AutoName(a)) => emit(out, &render_autoname(a)),
            None => {}
        }
        if !r.proposals.is_empty() {
            emit(
                err,
                &format!(
                    "{} change(s) need your decision: run `kraken proposals-list`.\n",
                    r.proposals.len()
                ),
            );
        }
        let used = match r.backend {
            kraken_assist::BackendKind::Api => format!("{} tokens", r.usage.total()),
            kraken_assist::BackendKind::TerminalAgent => "token use not reported".to_string(),
        };
        emit(
            err,
            &format!(
                "run {} ({used}). Undo this run's edits with `kraken undo-run --run-id {}`.\n",
                r.run_id, r.run_id
            ),
        );
    }
    match r.stop {
        StopReason::Error => {
            let e = ProtoError::new(
                ErrorCode::Internal,
                r.error
                    .clone()
                    .unwrap_or_else(|| "the model run failed".into()),
            );
            fail(&e, json_out, err)
        }
        StopReason::Cancelled => {
            emit(err, "cancelled\n");
            6
        }
        _ => 0,
    }
}

fn bullets(out: &mut String, title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title}\n"));
    for i in items {
        out.push_str(&format!("  - {i}\n"));
    }
}

/// Shown after the streamed text; when the model streamed no prose, this is the answer.
fn render_explanation(e: &Explanation, had_prose: bool) -> String {
    let mut s = String::new();
    if !had_prose && !e.summary.is_empty() {
        s.push_str(&format!("{}\n", e.summary));
    }
    bullets(&mut s, "What it does:", &e.key_behaviours);
    if !e.suggested_names.is_empty() {
        s.push_str("\nNames to consider (nothing was renamed):\n");
        for n in &e.suggested_names {
            s.push_str(&format!("  - {}: {}\n", n.name, n.reason));
        }
    }
    bullets(&mut s, "Not sure about:", &e.caveats);
    s
}

fn render_overview(o: &Overview, had_prose: bool) -> String {
    let mut s = String::new();
    if !had_prose && !o.what_it_is.is_empty() {
        s.push_str(&format!("{}\n", o.what_it_is));
    }
    if !o.components.is_empty() {
        s.push_str("\nMain parts:\n");
        for c in &o.components {
            s.push_str(&format!("  - {}: {}\n", c.name, c.description));
        }
    }
    if !o.interesting_functions.is_empty() {
        s.push_str("\nWhere to look first:\n");
        for f in &o.interesting_functions {
            let name = f.name.as_deref().unwrap_or("");
            s.push_str(&format!("  - {} {}: {}\n", f.address, name, f.reason));
        }
    }
    bullets(&mut s, "Next steps:", &o.next_steps);
    bullets(&mut s, "Could not check:", &o.missing_data);
    s
}

fn outcome_word(o: Option<Outcome>) -> &'static str {
    match o {
        Some(Outcome::Applied) => "applied",
        Some(Outcome::Queued) => "queued",
        Some(Outcome::Proposed) => "proposed (needs your decision)",
        Some(Outcome::Rejected) => "refused",
        Some(Outcome::NotAttempted) | None => "not applied",
    }
}

fn render_autoname(a: &AutoNameReport) -> String {
    let mut s = String::new();
    if a.suggestions.is_empty() {
        s.push_str("No naming suggestions.\n");
        return s;
    }
    s.push_str(&format!(
        "\n{} suggestion(s){}: {} applied, {} queued, {} proposed, {} failed.\n",
        a.suggestions.len(),
        if a.dry_run {
            " (dry run, nothing written)"
        } else {
            ""
        },
        a.applied,
        a.queued,
        a.proposed,
        a.failed
    ));
    for g in &a.suggestions {
        let name = g.new_name.as_deref().unwrap_or("(comment only)");
        let was = g.current_name.as_deref().unwrap_or("");
        s.push_str(&format!(
            "  {} {} -> {}  [{:?} evidence: {}]\n",
            g.address, was, name, g.confidence, g.confidence_basis
        ));
        if let Some(c) = &g.comment {
            s.push_str(&format!("      comment: {c}\n"));
        }
        if !a.dry_run {
            s.push_str(&format!(
                "      rename: {}; comment: {}\n",
                outcome_word(g.rename_outcome),
                outcome_word(g.comment_outcome)
            ));
        }
    }
    s.push_str(&format!("\n{}\n", a.note));
    s
}

/// `kraken glossary <term>`.
pub(crate) fn run_glossary(
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let words: Vec<&str> = sm
        .get_many::<String>("term")
        .map(|v| v.map(String::as_str).collect())
        .unwrap_or_default();
    let query = words.join(" ");
    let arch = sm
        .get_one::<String>("arch")
        .and_then(|a| Arch::from_name(a));
    let g = Glossary::builtin();
    let mut found: Vec<GlossaryMatch> = g.lookup(&query, 8);
    if let Some(a) = arch {
        // Mnemonics of the other architecture are noise when one was asked for.
        found.retain(|m| m.entry.arch.is_none() || m.entry.arch == Some(a));
        if let Some(m) = g.mnemonic(a, &query)
            && !found.iter().any(|f| f.entry == *m)
        {
            found.insert(
                0,
                GlossaryMatch {
                    entry: m.clone(),
                    how: kraken_assist::MatchKind::Exact,
                    distance: 0,
                },
            );
        }
    }
    if found.is_empty() {
        let e = ProtoError::new(
            ErrorCode::NotFound,
            format!("no glossary entry for `{}`", clip(&query, 60)),
        );
        return fail(&e, json_out, err);
    }
    if json_out {
        let v = json!({"query": query, "matches": found});
        emit(out, &format!("{v}\n"));
        return 0;
    }
    for (i, m) in found.iter().enumerate() {
        let e = &m.entry;
        let arch = match e.arch {
            Some(Arch::X86_64) => ", x86-64",
            Some(Arch::Aarch64) => ", AArch64",
            None => "",
        };
        let kind = match e.kind {
            kraken_assist::GlossaryKind::Concept => "term",
            kraken_assist::GlossaryKind::Mnemonic => "instruction",
        };
        if i == 0 {
            emit(out, &format!("{} ({kind}{arch})\n  {}\n", e.term, e.short));
            if let Some(n) = &e.note {
                emit(out, &format!("  {n}\n"));
            }
            if found.len() > 1 {
                emit(out, "\nRelated or similar:\n");
            }
        } else {
            emit(out, &format!("  {} ({kind}{arch}): {}\n", e.term, e.short));
        }
    }
    0
}
