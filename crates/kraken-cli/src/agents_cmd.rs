//! `kraken agents list | setup | run`: terminal agents over the Agent Client Protocol
//! (see the `kraken-acp` crate and `docs/agents.md`).

use std::ffi::OsString;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use clap::ArgMatches;
use kraken_acp::{
    AcpError, AcpEvent, AcpHost, AgentPaths, AgentProfile, AgentSetup, AgentStatus, AllowAll,
    DenyAll, HostConfig, McpServerConfig, NodeRuntime, NoticeStore, PermissionDecision,
    PermissionHandler, PermissionPolicy, PermissionRequest, Platform, Resolver, TurnEnd,
    WARNING_TEXT, WARNING_TITLE, config_dir_with, install_adapter, load_catalogue, report,
};
use kraken_host::provision::{HttpsFetcher, Progress};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::json;

use crate::app::{CliEnv, bad, emit, fail};

fn os_env(env: &CliEnv) -> impl Fn(&str) -> Option<OsString> + '_ {
    move |k| env.var(k).map(OsString::from)
}

fn catalogue(env: &CliEnv) -> Result<Vec<AgentProfile>, ProtoError> {
    let dir = config_dir_with(&os_env(env));
    load_catalogue(dir.as_deref()).map_err(|e| bad(e.to_string()))
}

fn resolver(env: &CliEnv) -> Result<Resolver, ProtoError> {
    let paths = AgentPaths::from_env_with(&os_env(env)).ok_or_else(|| {
        ProtoError::new(
            ErrorCode::Internal,
            "cannot place agent files: neither XDG_DATA_HOME nor HOME is set",
        )
    })?;
    Ok(Resolver {
        paths,
        platform: Platform::current(),
        path_env: env.var("PATH").map(OsString::from),
    })
}

fn find<'a>(profiles: &'a [AgentProfile], id: &str) -> Result<&'a AgentProfile, ProtoError> {
    profiles.iter().find(|p| p.id == id).ok_or_else(|| {
        let known: Vec<&str> = profiles.iter().map(|p| p.id.as_str()).collect();
        ProtoError::new(
            ErrorCode::NotFound,
            format!(
                "no agent called `{id}`; known agents: {} (see `kraken agents list`)",
                known.join(", ")
            ),
        )
    })
}

pub(crate) async fn run_agents(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let result = match sm.subcommand() {
        Some(("list", _)) => list(env, json_out, out),
        Some(("setup", m)) => setup(env, m, json_out, out, err).await,
        Some(("run", m)) => run_agent(env, m, json_out, out, err).await,
        Some(("__fake-agent", _)) => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            return match kraken_acp::fake_agent::serve(stdin.lock(), stdout.lock()) {
                Ok(()) => 0,
                Err(e) => {
                    emit(err, &format!("fake agent: {e}\n"));
                    5
                }
            };
        }
        _ => Err(bad("choose one of: list, setup, run")),
    };
    match result {
        Ok(code) => code,
        Err(e) => fail(&e, json_out, err),
    }
}

fn list(env: &CliEnv, json_out: bool, out: &mut dyn Write) -> Result<i32, ProtoError> {
    let profiles = catalogue(env)?;
    let r = resolver(env)?;
    let rows = report(&r, &profiles);
    let platform = r.platform.report();
    if json_out {
        emit(
            out,
            &format!("{}\n", json!({ "platform": platform, "agents": rows })),
        );
        return Ok(0);
    }
    emit(
        out,
        &format!("Terminal agents on {}\n\n", platform.platform),
    );
    if let Some(why) = &platform.unsupported_reason {
        emit(out, &format!("{why}\n\n"));
    }
    let id_w = rows.iter().map(|r| r.id.len()).max().unwrap_or(2);
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4);
    for row in &rows {
        emit(
            out,
            &format!(
                "{:<id_w$}  {:<name_w$}  {:<11}  {}\n",
                row.id, row.name, row.status, row.detail
            ),
        );
    }
    emit(
        out,
        "\ndetected    ready to use: `kraken agents run <id> --project <dir> \"<prompt>\"`\n\
         available   not installed yet: `kraken agents setup <id>` installs it\n\
         missing     cannot run until you install what the detail says\n\
         unsupported this computer cannot run it\n",
    );
    Ok(0)
}

fn confirm(question: &str, yes: bool, err: &mut dyn Write) -> Result<bool, ProtoError> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(bad(
            "this needs your approval to download files; run it in a terminal or pass --yes",
        ));
    }
    emit(err, &format!("{question} [y/N] "));
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

async fn setup(
    env: &CliEnv,
    m: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let id = m.get_one::<String>("id").cloned().unwrap_or_default();
    let yes = m.get_flag("yes");
    let profiles = catalogue(env)?;
    let profile = find(&profiles, &id)?.clone();
    let r = resolver(env)?;
    let AgentSetup::NodeAdapter(spec) = profile.setup else {
        return Err(bad(format!(
            "{} is a custom agent started by `{}`; there is nothing to set up",
            profile.display_name, profile.command
        )));
    };
    let finish = |out: &mut dyn Write, what: &str| {
        if json_out {
            emit(
                out,
                &format!(
                    "{}\n",
                    json!({"id": profile.id, "ready": true, "detail": what})
                ),
            );
        } else {
            emit(
                out,
                &format!(
                    "{} is ready ({what}).\nTry: kraken agents run {} --project <dir> \"<prompt>\"\n",
                    profile.display_name, profile.id
                ),
            );
        }
    };
    match r.status(&profile) {
        AgentStatus::Unsupported { reason } => {
            return Err(ProtoError::new(ErrorCode::Unsupported, reason));
        }
        AgentStatus::Detected(l) => {
            finish(out, &l.via);
            return Ok(0);
        }
        AgentStatus::Missing { reason } => return Err(bad(reason)),
        AgentStatus::Available { .. } => {}
    }
    let node = r.node(spec.min_node_major);
    let mut plan = Vec::new();
    if node.is_none() {
        let dl = kraken_acp::node_download_for(&r.platform)
            .ok_or_else(|| bad("Node.js is needed and cannot be downloaded for this platform"))?;
        plan.push(format!(
            "Node.js {} (about {} MB) from nodejs.org, checked against a built-in SHA-256 before it is unpacked",
            kraken_acp::NODE_VERSION, dl.approx_mib
        ));
    }
    plan.push(format!(
        "{}@{} and its dependencies from the npm registry (pinned lockfile with integrity hashes, install scripts disabled)",
        spec.package, spec.version
    ));
    emit(
        err,
        &format!(
            "Setting up {} will download:\n{}\ninto {}\n",
            profile.display_name,
            plan.iter()
                .map(|p| format!("  - {p}\n"))
                .collect::<String>(),
            r.paths.root().display()
        ),
    );
    if !confirm("Download now?", yes, err)? {
        return Err(ProtoError::new(
            ErrorCode::Cancelled,
            "nothing was downloaded",
        ));
    }
    let node = match node {
        Some(n) => n,
        None => {
            let fetcher = HttpsFetcher::new()
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
            let data_dir = r
                .paths
                .root()
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_default();
            let mut last = None;
            NodeRuntime::provision(&data_dir, &fetcher, &mut |p| match p {
                Progress::Downloading { done, total, .. } => {
                    let pct = total.filter(|t| *t > 0).map(|t| done * 100 / t / 10 * 10);
                    if pct != last {
                        last = pct;
                        eprintln!("downloading Node.js: {}%", pct.unwrap_or(0));
                    }
                }
                Progress::Verifying { .. } => eprintln!("verifying Node.js (sha256)"),
                Progress::Extracting { .. } => eprintln!("extracting Node.js"),
                _ => {}
            })
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?
        }
    };
    emit(
        err,
        &format!("installing {}@{}\n", spec.package, spec.version),
    );
    install_adapter(&profile, &r.paths, &node)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
    finish(
        out,
        &format!(
            "{}@{}, Node.js {}",
            spec.package, spec.version, node.version
        ),
    );
    Ok(0)
}

/// Asks on the terminal. Without a terminal it declines.
struct TerminalPermission;

#[async_trait]
impl PermissionHandler for TerminalPermission {
    async fn decide(&self, request: &PermissionRequest) -> PermissionDecision {
        let req = request.clone();
        if !std::io::stdin().is_terminal() {
            eprintln!(
                "agent asks: {} -- declined (no terminal; use --auto-approve to allow)",
                req.title
            );
            return req.reject();
        }
        tokio::task::spawn_blocking(move || {
            let mut e = std::io::stderr();
            let _ = writeln!(e, "\nThe agent asks permission: {}", req.title);
            if let Some(k) = &req.tool_kind {
                let _ = writeln!(e, "  kind:  {k}");
            }
            for p in &req.paths {
                let _ = writeln!(e, "  file:  {p}");
            }
            if let Some(i) = &req.input {
                let _ = writeln!(e, "  input: {i}");
            }
            for (n, o) in req.options.iter().enumerate() {
                let _ = writeln!(e, "  [{}] {}", n + 1, o.name);
            }
            let _ = write!(e, "Choose a number (anything else declines): ");
            let _ = e.flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            match line.trim().parse::<usize>() {
                Ok(n) if n >= 1 && n <= req.options.len() => {
                    PermissionDecision::Select(req.options[n - 1].id.clone())
                }
                _ => req.reject(),
            }
        })
        .await
        .unwrap_or(PermissionDecision::Cancel)
    }
}

fn print_event(ev: &AcpEvent, json_out: bool, out: &mut dyn Write, err: &mut dyn Write) {
    if json_out {
        if let Ok(line) = serde_json::to_string(ev) {
            emit(out, &format!("{line}\n"));
        }
        return;
    }
    match ev {
        AcpEvent::AgentText { text } => emit(out, text),
        AcpEvent::ToolCall(c) => emit(err, &format!("\n[tool] {} ({})\n", c.title, c.kind)),
        AcpEvent::ToolCallUpdate(u) => {
            if let Some(s) = &u.status
                && matches!(s.as_str(), "completed" | "failed")
            {
                emit(err, &format!("[tool] {}\n", s.replace('_', " ")));
            }
        }
        AcpEvent::Plan { steps } => {
            emit(err, "\n[plan]\n");
            for s in steps {
                emit(err, &format!("  {} {}\n", s.status, s.content));
            }
        }
        AcpEvent::PermissionResolved { selected, .. } => {
            emit(
                err,
                &format!(
                    "[permission] {}\n",
                    if selected.is_some() {
                        "answered"
                    } else {
                        "declined"
                    }
                ),
            );
        }
        _ => {}
    }
}

async fn run_agent(
    env: &CliEnv,
    m: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let id = m.get_one::<String>("id").cloned().unwrap_or_default();
    let prompt = m.get_one::<String>("prompt").cloned().unwrap_or_default();
    let profiles = catalogue(env)?;
    let profile = find(&profiles, &id)?.clone();
    let r = resolver(env)?;
    let launch = match r.status(&profile) {
        AgentStatus::Detected(l) => l,
        AgentStatus::Available { reason, .. } => {
            return Err(bad(format!(
                "{} is not set up yet ({reason}); run `kraken agents setup {id}`",
                profile.display_name
            )));
        }
        AgentStatus::Missing { reason } | AgentStatus::Unsupported { reason } => {
            return Err(ProtoError::new(ErrorCode::Unsupported, reason));
        }
    };
    let project = m
        .get_one::<String>("project")
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"))
        .ok_or_else(|| bad("--project <dir> is required (or set KRAKEN_PROJECT)"))?;
    let project = std::path::absolute(&project).unwrap_or_else(|_| PathBuf::from(&project));
    if !project.is_dir() {
        return Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("project directory {} does not exist", project.display()),
        ));
    }

    // Decision 50: warn once, do not block.
    let store = config_dir_with(&os_env(env)).map(|d| NoticeStore::in_config_dir(&d));
    if !store.as_ref().is_some_and(NoticeStore::is_acknowledged) {
        emit(err, &format!("{WARNING_TITLE}\n\n{WARNING_TEXT}\n\n"));
        if let Some(s) = &store
            && let Err(e) = s.acknowledge()
        {
            emit(
                err,
                &format!("warning: cannot remember that this was shown: {e}\n"),
            );
        }
    }

    let exe = env
        .var("KRAKEN_EXE")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "cannot find the kraken executable"))?;
    let mut mcp = if m.get_flag("daemon") {
        McpServerConfig::daemon(exe, Some(&project))
    } else {
        McpServerConfig::project(exe, &project)
    };
    for key in ["KRAKEN_RUNTIME_DIR", "KRAKEN_NO_DAEMON"] {
        if let Some(v) = env.var(key) {
            mcp = mcp.with_env(key, v);
        }
    }
    // The agent is not given `XDG_RUNTIME_DIR`, so its MCP server is told where the daemon is.
    if m.get_flag("daemon")
        && env.var("KRAKEN_RUNTIME_DIR").is_none()
        && let Some((k, v)) = kraken_host::daemon::mcp_runtime_env()
    {
        mcp = mcp.with_env(k, v);
    }
    let mut cfg = HostConfig::new(profile.clone(), launch, project, Some(mcp));
    cfg.permission = PermissionPolicy::Handler(if m.get_flag("auto-approve") {
        Arc::new(AllowAll)
    } else if std::io::stdin().is_terminal() {
        Arc::new(TerminalPermission)
    } else {
        Arc::new(DenyAll)
    });
    let host_err = |e: AcpError| {
        let code = match e {
            AcpError::AuthRequired { .. } => ErrorCode::Unsupported,
            AcpError::StartTimeout { .. } => ErrorCode::Timeout,
            _ => ErrorCode::Internal,
        };
        ProtoError::new(code, e.to_string())
    };
    emit(err, &format!("starting {}...\n", profile.display_name));
    let (host, mut rx) = AcpHost::start(cfg).await.map_err(host_err)?;

    let turn = {
        let fut = host.prompt(&prompt);
        tokio::pin!(fut);
        let mut interrupted = false;
        loop {
            tokio::select! {
                Some(ev) = rx.recv() => print_event(&ev, json_out, out, err),
                res = &mut fut => break res,
                _ = tokio::signal::ctrl_c(), if !interrupted => {
                    interrupted = true;
                    emit(err, "\ncancelling...\n");
                    let _ = host.cancel();
                }
            }
        }
    };
    while let Ok(ev) = rx.try_recv() {
        print_event(&ev, json_out, out, err);
    }
    if !json_out {
        emit(out, "\n");
    }
    let stderr_tail = host.stderr_tail();
    host.shutdown().await;
    match turn {
        Ok(TurnEnd::EndTurn) => Ok(0),
        Ok(TurnEnd::Cancelled) => Err(ProtoError::new(
            ErrorCode::Cancelled,
            "the turn was cancelled",
        )),
        Ok(other) => Err(ProtoError::new(
            ErrorCode::Internal,
            format!("the agent stopped early ({other:?})"),
        )),
        Err(e) => {
            let mut pe = host_err(e);
            if !stderr_tail.is_empty() && !pe.message.contains(&stderr_tail) {
                pe.message = format!("{}\nthe agent said:\n{stderr_tail}", pe.message);
            }
            Err(pe)
        }
    }
}
