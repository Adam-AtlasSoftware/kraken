//! The clap tree, argument building and command execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use kraken_engine::CancellationToken;
use kraken_host::{
    GhidraEngineFactory, KrakenConfig, ManagedFactory, default_project_dir, finalize_output,
    user_id,
};
use kraken_mcp::{KrakenMcp, McpOptions, serve_stdio};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, AutoApprove, CallContext, CommandKind,
    DenyApprover, Entry, Registry, Session, Surface,
};
use serde_json::{Map, Value, json};

use crate::exit::exit_code;
use crate::render::render;
use crate::schema::{FlagKind, FlagSpec, flags_from_schema, kebab, parse_flag_value};

const ABOUT: &str = "KRAKEN reverse-engineering workbench";
const LONG_ABOUT: &str = "KRAKEN reverse-engineering workbench.\n\n\
Every command of the KRAKEN command registry is a subcommand. Use --project <dir> (or set \
KRAKEN_PROJECT) to choose the project, --json for machine output (exactly the command's output \
JSON; errors are printed to stderr as JSON), and `kraken commands --json` for all commands with \
their JSON Schemas. `kraken mcp` serves the same commands as MCP tools over stdio.\n\n\
Objects and arrays are passed as JSON text (--<flag> '<json>'); --args-json '<json>' supplies the \
whole argument object.\n\n\
Exit codes: 0 ok, 2 invalid arguments, 3 not found, 4 conflict or rejected, 5 engine or internal \
error, 6 cancelled or timed out.";

/// Who the CLI acts as.
#[derive(Debug, Clone)]
pub enum CliAuthor {
    /// A person (the OS user by default).
    User(String),
    /// An agent run, for scripts and tests that drive the CLI as an agent.
    Agent {
        /// Agent id.
        id: String,
        /// Run id.
        run_id: String,
    },
}

/// Looks up an environment variable.
pub type EnvLookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Everything `run` needs besides the command line.
pub struct CliEnv {
    /// The commands.
    pub registry: Arc<Registry>,
    /// Creates (and stops) engines.
    pub factory: Arc<dyn ManagedFactory>,
    /// Configuration.
    pub config: KrakenConfig,
    /// Who edits are logged under.
    pub author: CliAuthor,
    /// Environment lookup (`KRAKEN_PROJECT`).
    pub vars: EnvLookup,
    /// True in the real binary: Ctrl-C cancels jobs and dangerous commands may prompt on a
    /// terminal. Tests leave it false.
    pub interactive: bool,
    /// An existing session to run against instead of opening the project (tests, embedding).
    pub session: Option<Arc<Session>>,
}

impl CliEnv {
    /// The environment of the real binary.
    pub fn standard(config: KrakenConfig) -> Self {
        CliEnv {
            registry: Arc::new(Registry::standard()),
            factory: Arc::new(GhidraEngineFactory::new(config.clone())),
            config,
            author: CliAuthor::User(user_id()),
            vars: Box::new(|k| std::env::var(k).ok()),
            interactive: true,
            session: None,
        }
    }

    fn var(&self, k: &str) -> Option<String> {
        (self.vars)(k).filter(|v| !v.is_empty())
    }

    fn new_session(&self) -> Arc<Session> {
        self.session.clone().unwrap_or_else(|| {
            Arc::new(Session::new(self.factory.clone()).with_config(self.config.session_config()))
        })
    }

    fn context(&self, yes: bool) -> CallContext {
        let ctx = match &self.author {
            CliAuthor::User(id) => CallContext::user(id.clone(), Surface::Cli),
            CliAuthor::Agent { id, run_id } => {
                CallContext::agent(id.clone(), run_id.clone(), Surface::Cli)
            }
        };
        let approval: Arc<dyn ApprovalRequester> = if yes {
            Arc::new(AutoApprove)
        } else if self.interactive && std::io::stdin().is_terminal() {
            Arc::new(PromptApprover)
        } else {
            Arc::new(DenyApprover)
        };
        ctx.with_approval(approval)
    }
}

/// Asks on the terminal before a dangerous command.
struct PromptApprover;

#[async_trait]
impl ApprovalRequester for PromptApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        let prompt = format!(
            "`{}` is a dangerous command: {}\narguments: {}\nAllow? [y/N] ",
            req.command, req.summary, req.args
        );
        let answer = tokio::task::spawn_blocking(move || {
            let mut e = std::io::stderr();
            let _ = e.write_all(prompt.as_bytes());
            let _ = e.flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map(|_| line)
        })
        .await;
        match answer {
            Ok(Ok(l)) if matches!(l.trim().to_ascii_lowercase().as_str(), "y" | "yes") => {
                ApprovalDecision::Allow
            }
            _ => ApprovalDecision::Deny {
                reason: "not approved at the prompt".into(),
            },
        }
    }
}

fn flag_help(f: &FlagSpec) -> String {
    let mut h = f.help.clone();
    if f.required {
        h.push_str(if h.is_empty() {
            "Required."
        } else {
            " (required)"
        });
    }
    if f.kind == FlagKind::Json {
        h.push_str(" Pass JSON text.");
    }
    h
}

/// The flags of `entry`. `project_dir` of project_create / project_open is optional on the
/// command line: it defaults to `--project`, and for project_create to
/// `<projects root>/<binary name>`.
fn flags_of(entry: &Entry) -> Vec<FlagSpec> {
    let mut flags = flags_from_schema(entry.args_schema());
    if matches!(
        entry.spec().name.as_str(),
        "project_create" | "project_open"
    ) {
        for f in flags.iter_mut().filter(|f| f.prop == "project_dir") {
            f.required = false;
            f.help = if entry.spec().name == "project_create" {
                "Directory for the new project. Default: --project, else <projects root>/<binary name>."
            } else {
                "Directory of the project. Default: --project."
            }
            .into();
        }
    }
    flags
}

fn sub_for(entry: &Entry) -> Command {
    let spec = entry.spec();
    let mut sub = Command::new(kebab(&spec.name)).about(spec.summary.clone());
    let long = if spec.doc.trim().is_empty() {
        spec.summary.clone()
    } else {
        format!("{}\n\n{}", spec.summary, spec.doc)
    };
    sub = sub.long_about(long);
    for f in flags_of(entry) {
        let mut a = Arg::new(f.prop.clone())
            .long(f.flag.clone())
            .help(flag_help(&f))
            .value_name(match &f.kind {
                FlagKind::Str => "TEXT",
                FlagKind::Int => "INT",
                FlagKind::Num => "NUM",
                FlagKind::Bool => "BOOL",
                FlagKind::Enum(_) => "VALUE",
                FlagKind::Json => "JSON",
            });
        a = match &f.kind {
            FlagKind::Bool => a.num_args(0..=1).default_missing_value("true"),
            FlagKind::Enum(values) => a.value_parser(PossibleValuesParser::new(values.clone())),
            _ => a,
        };
        sub = sub.arg(a);
    }
    sub = sub.arg(
        Arg::new("args-json")
            .long("args-json")
            .value_name("JSON")
            .help("The whole argument object as JSON; individual flags override its fields"),
    );
    if spec.kind == CommandKind::Job {
        sub = sub.arg(
            Arg::new("no-wait")
                .long("no-wait")
                .action(ArgAction::SetTrue)
                .hide(true)
                .help("Print the started job instead of waiting for it (jobs live in this process only)"),
        );
    }
    sub
}

/// The full command tree for `registry`.
pub fn build_cli(registry: &Registry) -> Command {
    let mut root = Command::new("kraken")
        .version(env!("CARGO_PKG_VERSION"))
        .about(ABOUT)
        .long_about(LONG_ABOUT)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("project")
                .long("project")
                .value_name("DIR")
                .global(true)
                .help("Project directory (default: $KRAKEN_PROJECT)"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Machine output: exactly the command's output JSON"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Approve dangerous commands without asking"),
        );
    for entry in registry.iter() {
        root = root.subcommand(sub_for(entry));
    }
    root.subcommand(
        Command::new("commands")
            .about("List all commands with their argument and output JSON Schemas"),
    )
    .subcommand(Command::new("mcp").about("Serve the commands as MCP tools over stdio"))
}

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// The JSON arguments of `entry` from `--args-json` and the flags in `sm`.
pub fn build_args(entry: &Entry, sm: &ArgMatches) -> Result<Value, ProtoError> {
    let mut obj = Map::new();
    if let Ok(Some(text)) = sm.try_get_one::<String>("args-json") {
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(m)) => obj = m,
            Ok(_) => return Err(bad("--args-json: expected a JSON object")),
            Err(e) => return Err(bad(format!("--args-json: invalid JSON ({e})"))),
        }
    }
    for f in flags_of(entry) {
        if let Ok(Some(text)) = sm.try_get_one::<String>(&f.prop) {
            obj.insert(f.prop.clone(), parse_flag_value(&f, text)?);
        }
    }
    Ok(Value::Object(obj))
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

fn emit(w: &mut dyn Write, s: &str) {
    // A closed pipe (`| head`) is not an error worth reporting.
    let _ = w.write_all(s.as_bytes());
}

fn fail(e: &ProtoError, json: bool, err: &mut dyn Write) -> i32 {
    if json {
        let v = serde_json::to_string(e).unwrap_or_else(|_| "{\"code\":\"internal\"}".into());
        emit(err, &format!("{v}\n"));
    } else {
        emit(err, &format!("error: {}\n", e.message));
        if let Some(d) = &e.details {
            emit(err, &format!("  ({}: {})\n", e.code.as_str(), d));
        } else {
            emit(err, &format!("  ({})\n", e.code.as_str()));
        }
    }
    exit_code(e)
}

/// Adds `project_dir` to project_create / project_open args from `--project` / the default.
fn fill_project_dir(
    env: &CliEnv,
    name: &str,
    args: &mut Value,
    project: Option<&str>,
) -> Result<(), ProtoError> {
    let Some(obj) = args.as_object_mut() else {
        return Ok(());
    };
    let dir = match obj.get("project_dir").and_then(Value::as_str) {
        Some(d) => PathBuf::from(d),
        None => match project {
            Some(p) => PathBuf::from(p),
            None if name == "project_create" => {
                let stem = obj
                    .get("binary")
                    .and_then(Value::as_str)
                    .and_then(|b| Path::new(b).file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .ok_or_else(|| bad("missing --binary"))?;
                default_project_dir(&env.config, &stem)?
            }
            None => return Err(bad("no project: pass --project-dir or --project <dir>")),
        },
    };
    obj.insert(
        "project_dir".into(),
        Value::String(absolute(&dir).to_string_lossy().into_owned()),
    );
    Ok(())
}

fn commands_json(registry: &Registry) -> Value {
    let list: Vec<Value> = registry
        .iter()
        .map(|e| {
            let mut v = serde_json::to_value(e.spec()).unwrap_or(Value::Null);
            let flags: Vec<Value> = flags_of(e)
                .into_iter()
                .map(|f| {
                    let mut o = json!({
                        "flag": format!("--{}", f.flag),
                        "property": f.prop,
                        "type": f.kind.label(),
                        "required": f.required,
                        "description": f.help,
                    });
                    if let FlagKind::Enum(values) = &f.kind {
                        o["values"] = json!(values);
                    }
                    o
                })
                .collect();
            if let Some(m) = v.as_object_mut() {
                m.insert(
                    "cli".into(),
                    json!({"subcommand": kebab(&e.spec().name), "flags": flags}),
                );
                m.insert("args_schema".into(), e.args_schema().clone());
                m.insert("output_schema".into(), e.output_schema().clone());
            }
            v
        })
        .collect();
    Value::Array(list)
}

fn commands_table(registry: &Registry) -> String {
    let rows: Vec<Vec<String>> = registry
        .iter()
        .map(|e| {
            let s = e.spec();
            vec![
                kebab(&s.name),
                serde_json::to_value(s.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                serde_json::to_value(s.permission)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                s.summary.clone(),
            ]
        })
        .collect();
    crate::render::table(&["command", "kind", "permission", "summary"], &rows)
}

async fn wait_for_job(
    env: &CliEnv,
    session: &Session,
    ctx: &CallContext,
    started: &Value,
    err: &mut dyn Write,
) -> Result<Value, ProtoError> {
    let id = started
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "job command returned no job_id"))?
        .to_string();
    let mut last: Option<Value> = None;
    loop {
        let wait = env.registry.call_json(
            "job_await",
            session,
            ctx,
            json!({"job_id": id, "timeout_ms": 500}),
        );
        let view = if env.interactive {
            tokio::select! {
                v = wait => v?,
                _ = tokio::signal::ctrl_c() => {
                    emit(err, "cancelling...\n");
                    let _ = env.registry.call_json("job_cancel", session, ctx, json!({"job_id": id})).await;
                    continue;
                }
            }
        } else {
            wait.await?
        };
        if let Some(p) = view.get("progress")
            && last.as_ref() != Some(p)
        {
            emit(
                err,
                &format!(
                    "[{}] {}/{} {}\n",
                    p["phase"].as_str().unwrap_or(""),
                    p["done"],
                    p["total"],
                    p["message"].as_str().unwrap_or("")
                ),
            );
            last = Some(p.clone());
        }
        match view.get("status").and_then(Value::as_str) {
            Some("running") => {}
            Some("failed") | Some("cancelled") => {
                let status = view["status"].as_str().unwrap_or("failed").to_string();
                return Err(view
                    .get("error")
                    .and_then(|e| serde_json::from_value::<ProtoError>(e.clone()).ok())
                    .unwrap_or_else(|| {
                        let code = if status == "cancelled" {
                            ErrorCode::Cancelled
                        } else {
                            ErrorCode::Internal
                        };
                        ProtoError::new(code, format!("job {id} {status}"))
                    }));
            }
            _ => return Ok(view),
        }
    }
}

async fn run_registry_command(
    env: &CliEnv,
    name: &str,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let Some(entry) = env.registry.get(name) else {
        return fail(
            &ProtoError::new(ErrorCode::NotFound, format!("unknown command `{name}`")),
            json_out,
            err,
        );
    };
    let mut args = match build_args(entry, sm) {
        Ok(a) => a,
        Err(e) => return fail(&e, json_out, err),
    };
    let project = sm
        .get_one::<String>("project")
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"));
    let yes = sm.get_flag("yes");
    let no_wait = sm.try_get_one::<bool>("no-wait").ok().flatten().copied() == Some(true);
    let session = env.new_session();
    let creating = matches!(name, "project_create" | "project_open");

    let setup: Result<(), ProtoError> = async {
        if creating {
            fill_project_dir(env, name, &mut args, project.as_deref())
        } else if session.project().is_err() {
            let dir = project
                .as_deref()
                .ok_or_else(|| bad("no project: pass --project <dir> or set KRAKEN_PROJECT"))?;
            let p = session.open_project(&absolute(Path::new(dir))).await?;
            if !p.epoch_mismatch().is_empty() {
                emit(
                    err,
                    &format!(
                        "warning: the engine cache is stale ({}); run `kraken rebuild`\n",
                        p.epoch_mismatch().join(", ")
                    ),
                );
            }
            Ok(())
        } else {
            Ok(())
        }
    }
    .await;

    let ctx = env.context(yes);
    let result = match setup {
        Err(e) => Err(e),
        Ok(()) => {
            let first = env.registry.call_json(name, &session, &ctx, args).await;
            match first {
                Ok(v) if entry.spec().kind == CommandKind::Job && !no_wait => {
                    wait_for_job(env, &session, &ctx, &v, err).await
                }
                other => other,
            }
        }
    };

    let code = match result {
        Ok(v) => {
            let v = finalize_output(v);
            if json_out {
                emit(out, &format!("{v}\n"));
            } else {
                let r = render(name, &v);
                emit(out, &r.stdout);
                emit(err, &r.stderr);
            }
            0
        }
        Err(e) => fail(&e, json_out, err),
    };

    if code == 0 && entry.spec().kind != CommandKind::Query {
        save(&session, err).await;
    }
    env.factory.shutdown().await;
    code
}

async fn save(session: &Session, err: &mut dyn Write) {
    let Ok(engine) = session.engine() else {
        return;
    };
    if let Some(m) = engine.mutator()
        && let Err(e) = m.save(&CancellationToken::new()).await
    {
        emit(
            err,
            &format!("warning: saving the project failed: {}\n", e.message),
        );
    }
}

async fn run_mcp(env: &CliEnv, sm: &ArgMatches, json_out: bool, err: &mut dyn Write) -> i32 {
    let session = env.new_session();
    let project = sm
        .get_one::<String>("project")
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"));
    if let Some(dir) = project
        && session.project().is_err()
        && let Err(e) = session.open_project(&absolute(Path::new(&dir))).await
    {
        env.factory.shutdown().await;
        return fail(&e, json_out, err);
    }
    let server = KrakenMcp::new(env.registry.clone(), session, McpOptions::default());
    tracing::info!(run_id = server.run_id(), "starting MCP server on stdio");
    let result = serve_stdio(server).await;
    env.factory.shutdown().await;
    match result {
        Ok(()) => 0,
        Err(e) => fail(
            &ProtoError::new(ErrorCode::Internal, e.to_string()),
            json_out,
            err,
        ),
    }
}

/// Runs the CLI: parses `args` (including the program name), writes to `out` and `err`, and
/// returns the exit code.
pub async fn run(
    args: Vec<OsString>,
    env: &CliEnv,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let cli = build_cli(&env.registry);
    let matches = match cli.try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            let text = e.render().to_string();
            if e.use_stderr() {
                emit(err, &text);
            } else {
                emit(out, &text);
            }
            return e.exit_code();
        }
    };
    let Some((sub, sm)) = matches.subcommand() else {
        return 2;
    };
    let json_out = sm.get_flag("json");
    match sub {
        "commands" => {
            if json_out {
                emit(out, &format!("{}\n", commands_json(&env.registry)));
            } else {
                emit(out, &commands_table(&env.registry));
            }
            0
        }
        "mcp" => run_mcp(env, sm, json_out, err).await,
        other => {
            let names: BTreeMap<String, String> = env
                .registry
                .iter()
                .map(|e| (kebab(&e.spec().name), e.spec().name.clone()))
                .collect();
            match names.get(other) {
                Some(name) => run_registry_command(env, name, sm, json_out, out, err).await,
                None => fail(&bad(format!("unknown subcommand `{other}`")), json_out, err),
            }
        }
    }
}
