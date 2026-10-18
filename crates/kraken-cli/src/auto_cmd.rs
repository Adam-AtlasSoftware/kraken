//! `kraken auto <binary>`: open, analyse, and optionally name the functions and rewrite the
//! program in Rust, in one command.
//!
//! Steps print as progress lines on stderr; a short summary goes to stdout (`--json`: one object).
//! The person running the command is the one deciding, so `--accept-verified` may accept the
//! functions that passed their own test; without it, accepting stays a separate step.
//!
//! A terminal agent edits through its own `kraken mcp` process. That process and this one must
//! share one session, or each holds its own engine and the one that saves last drops the other's
//! edits. Through the daemon they do; without one (`--no-daemon`, or no `krakend` to connect to)
//! this command runs a private daemon of its own for the run, in this process, with a private
//! runtime directory, and points the agent's MCP server at it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use kraken_agent::ChatProvider;
use kraken_assist::{AutomateGoal, Task, TaskResult};
use kraken_host::backend::{CommandBackend, DaemonBackend};
use kraken_host::daemon::DaemonClient;
use kraken_ipc::{ClientKind, RuntimeDir, SystemClock};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};

use crate::app::{CliEnv, absolute, bad, emit, fail, fill_project_dir, save, wait_for_job};
use crate::assist_cmd::{Selection, execute_task, selection_from_config};

/// Most explicit program cases `--cases` takes (the same as `rewrite_program`).
const MAX_CASES: usize = 64;
/// Where the Rust workspace is exported, inside the project directory.
const EXPORT_DIR: &str = "rewrite-export";

pub(crate) fn command() -> Command {
    Command::new("auto")
        .about("Open a binary, analyse it, and optionally name its functions and rewrite it in Rust")
        .long_about(
            "Does the whole flow for one binary: checks the file, creates a project, runs the \
             analysis and waits for it. Then, on request:\n\n\
             --names    lets the configured assistant (an AI model or a terminal agent, see \
             docs/assistant.md) look the program over and give its important functions names \
             and comments. New names apply; replacing a name someone chose becomes a proposal \
             (`kraken proposals-list`). Undo the run with `kraken undo-run`.\n\
             --rewrite  plans a Rust rewrite of the whole program, translates it with the \
             configured provider, runs the original and the rewrite on the same inputs in a \
             sandbox, and reports whether they agree. With --accept-verified the functions that \
             passed their own test are accepted (you are the person deciding) and the Rust \
             workspace is exported to <project>/rewrite-export. Without it the command tells you \
             how to accept them.\n\n\
             Progress goes to stderr, a summary to stdout (--json: one object). Exit status: 0 \
             when every requested step worked and the rewrite verdict is `pass`, 4 when the \
             rewrite verdict is not `pass`, otherwise the usual codes.",
        )
        .arg(
            Arg::new("binary")
                .required(true)
                .value_name("BINARY")
                .help("The program to analyse (ELF, PE, Mach-O or .NET assembly)"),
        )
        .arg(
            Arg::new("project-dir")
                .long("project-dir")
                .value_name("DIR")
                .help("Directory for the new project. Default: --project, else <projects root>/<binary name>"),
        )
        .arg(
            Arg::new("engine")
                .long("engine")
                .value_name("ENGINE")
                .value_parser(PossibleValuesParser::new(["ghidra", "native", "auto"]))
                .help("Analysis engine for native code (default: the `engine` setting, else ghidra)"),
        )
        .arg(
            Arg::new("names")
                .long("names")
                .action(ArgAction::SetTrue)
                .help("Have the assistant name and comment the important functions"),
        )
        .arg(
            Arg::new("rewrite")
                .long("rewrite")
                .action(ArgAction::SetTrue)
                .help("Rewrite the whole program in Rust and check it against the original"),
        )
        .arg(
            Arg::new("accept-verified")
                .long("accept-verified")
                .action(ArgAction::SetTrue)
                .requires("rewrite")
                .help("Accept the rewritten functions that passed their test, then export the Rust workspace"),
        )
        .arg(
            Arg::new("cases")
                .long("cases")
                .value_name("JSON")
                .requires("rewrite")
                .help("Program test cases as a JSON array of {name, argv, stdin}"),
        )
        .arg(
            Arg::new("no-function-tests")
                .long("no-function-tests")
                .action(ArgAction::SetTrue)
                .requires("rewrite")
                .help("Only compile each rewritten function; the program-level test is then the only evidence"),
        )
}

/// What the first bytes of the file say it is.
fn probe(path: &Path) -> Result<(String, u64), ProtoError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    if !meta.is_file() {
        return Err(bad(format!("{} is not a file", path.display())));
    }
    let mut head = [0u8; 4];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .map_err(|e| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
    let kind = match head[..n] {
        [0x7f, b'E', b'L', b'F'] => "ELF",
        [b'M', b'Z', ..] => "PE (Windows) or .NET",
        [0xfe, 0xed, 0xfa, _] | [0xcf | 0xce, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe] => {
            "Mach-O"
        }
        _ => "unknown format (the engine decides)",
    };
    Ok((kind.to_string(), meta.len()))
}

fn cases_arg(sm: &ArgMatches) -> Result<Vec<Value>, ProtoError> {
    let Some(text) = sm.get_one::<String>("cases") else {
        return Ok(Vec::new());
    };
    let v: Value =
        serde_json::from_str(text).map_err(|e| bad(format!("--cases: not valid JSON ({e})")))?;
    let list = v
        .as_array()
        .filter(|l| l.len() <= MAX_CASES && l.iter().all(|c| c.get("name").is_some_and(Value::is_string)))
        .ok_or_else(|| {
            bad(format!(
                "--cases: expected a JSON array of at most {MAX_CASES} objects like {{\"name\": \"help\", \"argv\": [\"--help\"]}}"
            ))
        })?;
    Ok(list.clone())
}

fn step(err: &mut dyn Write, n: usize, total: usize, what: &str) {
    emit(err, &format!("[{n}/{total}] {what}\n"));
}

/// A daemon this run starts in its own process so that a terminal agent's MCP server shares the
/// run's session; stopped (which saves the project) when the run ends.
pub(crate) struct PrivateDaemon {
    daemon: krakend::Daemon,
    dir: RuntimeDir,
}

impl PrivateDaemon {
    async fn start(env: &CliEnv) -> Result<(PrivateDaemon, DaemonClient), ProtoError> {
        let refuse = |why: String| {
            ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "--names with a terminal agent needs one session that the agent's own `kraken \
                     mcp` shares with this run, and starting a private daemon for it failed: \
                     {why}. Start krakend (`kraken daemon start`) and run without --no-daemon, or \
                     configure an AI model provider instead"
                ),
            )
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path: PathBuf =
            std::env::temp_dir().join(format!("kraken-auto-{}-{nanos:08x}", std::process::id()));
        let dir = RuntimeDir::from_dir(path).map_err(|e| refuse(e.to_string()))?;
        let daemon = krakend::start_with(
            krakend::DaemonOptions {
                runtime_dir: dir.clone(),
                factory: env.factory.clone(),
                registry: env.registry.clone(),
                settings: env.config.daemon.clone(),
                session_config: env.config.session_config(),
                clock: Arc::new(SystemClock::new()),
                poll: Duration::from_millis(100),
                build: crate::app::BUILD.into(),
            },
            env.rewrite.clone(),
        )
        .map_err(|e| refuse(e.to_string()))?;
        let me = PrivateDaemon { daemon, dir };
        match DaemonClient::connect_running(&me.dir, ClientKind::Cli, crate::app::BUILD).await {
            Ok(Some(c)) => Ok((me, c)),
            Ok(None) => {
                me.stop().await;
                Err(refuse("it did not accept connections".into()))
            }
            Err(e) => {
                me.stop().await;
                Err(refuse(e.to_string()))
            }
        }
    }

    /// The runtime directory the agent's MCP server connects through.
    fn runtime_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Stops the daemon: it saves and closes the project, then removes its runtime files.
    pub(crate) async fn stop(self) {
        self.daemon.shutdown();
        self.daemon.wait().await;
        let _ = std::fs::remove_dir_all(self.dir.path());
    }
}

pub(crate) async fn run_auto(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    provider: Option<Arc<dyn ChatProvider>>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut private = None;
    let result = auto(env, sm, json_out, provider, &mut private, out, err).await;
    if let Some(p) = private {
        p.stop().await;
    }
    env.factory.shutdown().await;
    match result {
        Ok(code) => code,
        Err(e) => fail(&e, json_out, err),
    }
}

async fn job_result(
    env: &CliEnv,
    backend: &dyn CommandBackend,
    ctx: &kraken_registry::CallContext,
    command: &str,
    args: Value,
    err: &mut dyn Write,
) -> Result<Value, ProtoError> {
    let started = backend.call(command, ctx, args).await?;
    let view = wait_for_job(env, backend, ctx, &started, err).await?;
    Ok(view.get("result").cloned().unwrap_or(Value::Null))
}

async fn auto(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    provider: Option<Arc<dyn ChatProvider>>,
    private: &mut Option<PrivateDaemon>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let binary = sm
        .get_one::<String>("binary")
        .ok_or_else(|| bad("missing BINARY"))?;
    let want_names = sm.get_flag("names");
    let want_rewrite = sm.get_flag("rewrite");
    let accept = sm.get_flag("accept-verified");
    let cases = cases_arg(sm)?;
    // Fail before any work when the assistant or the rewrite cannot run.
    let selection = if want_names {
        Some(match provider.clone() {
            Some(p) => Selection::Api(p),
            None => selection_from_config(env)?,
        })
    } else {
        None
    };
    let total = 2 + usize::from(want_names) + if want_rewrite { 2 } else { 0 };
    let mut n = 0;

    n += 1;
    let path = absolute(Path::new(binary));
    let (format_guess, size) = probe(&path)?;
    step(
        err,
        n,
        total,
        &format!("checked {}: {format_guess}, {size} bytes", path.display()),
    );

    let project_flag = sm
        .get_one::<String>("project-dir")
        .or_else(|| sm.get_one::<String>("project"))
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"));
    let mut create = json!({"binary": path.to_string_lossy()});
    if let Some(engine) = sm.get_one::<String>("engine") {
        create["engine"] = json!(engine);
    }
    fill_project_dir(env, "project_create", &mut create, project_flag.as_deref())?;
    let dir = create["project_dir"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let ctx = env.context(sm.get_flag("yes"));
    let (mut backend, mut session) = env.backend(Some(&dir), env.no_daemon(sm), err).await?;
    if session.is_some() && matches!(selection, Some(Selection::Agent(_))) {
        // Running in this process, a terminal agent's own MCP server would open the project in
        // a second session: give both one session through a daemon of this run.
        let (daemon, client) = PrivateDaemon::start(env).await?;
        emit(
            err,
            "    no daemon to share the project with the agent: running a private one for this run\n",
        );
        backend = Arc::new(DaemonBackend::new(
            Arc::new(client),
            env.registry.clone(),
            Some(PathBuf::from(&dir)),
        ));
        session = None;
        *private = Some(daemon);
    }

    n += 1;
    step(err, n, total, "creating the project and analysing it");
    let info = backend.call("project_create", &ctx, create).await?;
    let format = info["program"]["format"]
        .as_str()
        .unwrap_or("?")
        .to_string();
    let arch = info["program"]["arch"].as_str().unwrap_or("?").to_string();
    let analysis = job_result(env, backend.as_ref(), &ctx, "analyze", json!({}), err).await?;
    let functions = analysis["function_count"].as_u64().unwrap_or(0);
    emit(
        err,
        &format!("    {format} {arch}: {functions} functions found\n"),
    );

    let mut summary = json!({
        "binary": path.to_string_lossy(),
        "project_dir": dir,
        "format": format,
        "arch": arch,
        "functions": functions,
    });
    let mut code = 0;

    if let Some(selection) = selection {
        n += 1;
        step(
            err,
            n,
            total,
            "the assistant is naming the important functions",
        );
        let task = Task::automate(&env.registry, AutomateGoal::Understand);
        let mut sink: Vec<u8> = Vec::new();
        let shown: &mut dyn Write = if json_out { &mut sink } else { &mut *out };
        let (c, result) = execute_task(
            env,
            sm,
            Some(&dir),
            Some((backend.clone(), session.clone())),
            private.as_ref().map(PrivateDaemon::runtime_dir),
            selection,
            task,
            false,
            shown,
            err,
        )
        .await;
        let renamed = match &result {
            Some(r) => renamed_by(backend.as_ref(), &ctx, r).await,
            None => 0,
        };
        emit(err, &format!("    {renamed} function(s) renamed\n"));
        summary["renamed"] = json!(renamed);
        if let Some(r) = &result {
            summary["names_run"] = json!(r.run_id);
            summary["proposals"] = json!(r.proposals.len());
        }
        if c != 0 {
            code = c;
            return finish(&session, summary, json_out, out, err, code).await;
        }
    }

    if want_rewrite {
        n += 1;
        step(err, n, total, "planning the Rust rewrite");
        let plan = backend
            .call("rewrite_plan", &ctx, json!({"scope": "all", "limit": 1}))
            .await?;
        emit(
            err,
            &format!(
                "    {} of {} functions planned\n",
                plan["functions_planned"], plan["functions_total"]
            ),
        );
        n += 1;
        step(
            err,
            n,
            total,
            "rewriting the program and testing it against the original (this takes a while)",
        );
        let mut args = json!({"scope": "all", "generated_cases": 8});
        if !cases.is_empty() {
            args["inputs"] = json!(cases);
        }
        if accept {
            args["accept_verified"] = json!(true);
        }
        if sm.get_flag("no-function-tests") {
            args["verify_functions"] = json!(false);
        }
        let run = job_result(env, backend.as_ref(), &ctx, "rewrite_program", args, err).await?;
        let verdict = run["verdict"]["verdict"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let passed = run["verdict"]["passed"].as_u64().unwrap_or(0);
        let cases_run = run["verdict"]["cases_run"].as_u64().unwrap_or(0);
        let crate_dir = run["crate_dir"].as_str().unwrap_or("").to_string();
        emit(
            err,
            &format!("    verdict {verdict}: {passed} of {cases_run} cases agreed\n"),
        );
        summary["rewrite"] = json!({
            "verdict": verdict,
            "cases_run": cases_run,
            "cases_agreed": passed,
            "functions_included": run["included"],
            "functions_failed": run["failed"],
            "crate_dir": crate_dir,
        });
        if verdict != "pass" {
            code = 4;
        }

        let status = backend
            .call("rewrite_status", &ctx, json!({"limit": 1}))
            .await?;
        let accepted = status["counts"]["accepted"].as_u64().unwrap_or(0);
        let verified = status["counts"]["verified"].as_u64().unwrap_or(0);
        summary["rewrite"]["accepted"] = json!(accepted);
        summary["rewrite"]["verified_waiting"] = json!(verified);
        if accept && accepted > 0 {
            emit(
                err,
                &format!("    exporting {accepted} accepted function(s) to {EXPORT_DIR}\n"),
            );
            let export = job_result(
                env,
                backend.as_ref(),
                &ctx,
                "rewrite_export",
                json!({"dir": EXPORT_DIR}),
                err,
            )
            .await;
            match export {
                Ok(e) => summary["rewrite"]["export_dir"] = e["dir"].clone(),
                Err(e) if e.code == ErrorCode::Cancelled => return Err(e),
                Err(e) => {
                    // Not every function could be accepted (a callee that cannot be compared,
                    // for example): say so, and let the rest of the summary through.
                    emit(err, &format!("    could not export: {}\n", e.message));
                    summary["rewrite"]["export_error"] = json!(e.message);
                    code = 4;
                }
            }
        } else if verified > 0 {
            emit(
                err,
                &format!(
                    "    {verified} function(s) passed their test and wait for you: \
                     `kraken --project {dir} rewrite-status`, then `kraken --project {dir} \
                     rewrite-accept --unit <id>` (or run this again with --accept-verified)\n"
                ),
            );
        }
    }

    finish(&session, summary, json_out, out, err, code).await
}

/// How many functions the assistant's run renamed, from the history.
async fn renamed_by(
    backend: &dyn CommandBackend,
    ctx: &kraken_registry::CallContext,
    r: &TaskResult,
) -> usize {
    let Ok(page) = backend.call("history", ctx, json!({"limit": 200})).await else {
        return 0;
    };
    page["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|i| i["run_id"].as_str() == Some(r.run_id.as_str()) && i["op"] == "rename")
                .count()
        })
        .unwrap_or(0)
}

async fn finish(
    session: &Option<Arc<kraken_registry::Session>>,
    summary: Value,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
    code: i32,
) -> Result<i32, ProtoError> {
    if let Some(s) = session {
        save(s, err).await;
    }
    if json_out {
        emit(out, &format!("{summary}\n"));
        return Ok(code);
    }
    let get = |k: &str| summary[k].as_str().unwrap_or("").to_string();
    let mut text = String::from("\nSummary\n");
    text.push_str(&format!(
        "  program:    {} ({} {})\n  project:    {}\n  functions:  {}\n",
        get("binary"),
        get("format"),
        get("arch"),
        get("project_dir"),
        summary["functions"]
    ));
    if let Some(n) = summary["renamed"].as_u64() {
        text.push_str(&format!("  renamed:    {n}\n"));
    }
    if let Some(r) = summary.get("rewrite") {
        text.push_str(&format!(
            "  rewrite:    {} ({} of {} cases agreed)\n  rust crate: {}\n",
            r["verdict"].as_str().unwrap_or("?"),
            r["cases_agreed"],
            r["cases_run"],
            r["crate_dir"].as_str().unwrap_or("")
        ));
        if let Some(d) = r["export_dir"].as_str() {
            text.push_str(&format!("  exported:   {d} ({} accepted)\n", r["accepted"]));
        }
        if let Some(e) = r["export_error"].as_str() {
            text.push_str(&format!("  not exported: {e}\n"));
        }
    }
    emit(out, &text);
    Ok(code)
}
