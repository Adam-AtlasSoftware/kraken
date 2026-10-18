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
use kraken_host::backend::{CommandBackend, DaemonBackend, LocalBackend};
use kraken_host::daemon::{DaemonClient, StartOptions};
use kraken_host::{
    HostEngineFactory, KrakenConfig, ManagedFactory, default_project_dir, finalize_output, user_id,
};
use kraken_ipc::{ClientKind, RuntimeDir};
use kraken_mcp::{KrakenMcp, McpOptions, serve_stdio};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, AutoApprove, CallContext, CommandKind,
    DenyApprover, Entry, Registry, Session, Surface,
};
use serde_json::{Map, Value, json};

use crate::exit::exit_code;
use crate::progress::ProgressPrinter;
use crate::render::render;
use crate::schema::{FlagKind, FlagSpec, flags_from_schema, kebab, parse_flag_value};

const ABOUT: &str = "KRAKEN reverse-engineering workbench";
const LONG_ABOUT: &str = "KRAKEN reverse-engineering workbench.\n\n\
Every command of the KRAKEN command registry is a subcommand. Use --project <dir> (or set \
KRAKEN_PROJECT) to choose the project, --json for machine output (exactly the command's output \
JSON; errors are printed to stderr as JSON), and `kraken commands --json` for all commands with \
their JSON Schemas. `kraken mcp` serves the same commands as MCP tools over stdio.\n\n\
Commands run in the `krakend` daemon, which is started on demand, keeps projects and the Ghidra \
sidecar warm between invocations and exits when idle (`kraken daemon status|stop|start`). \
`--no-daemon` runs the command in this process instead. `kraken setup` downloads Ghidra and a JDK.\n\n\
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

/// The build string `kraken` announces to the daemon (and expects `krakend` to report).
pub const BUILD: &str = env!("CARGO_PKG_VERSION");

/// How to reach (or start) the daemon.
#[derive(Debug, Clone, Default)]
pub struct DaemonAuto {
    /// The runtime directory; `None` resolves the per-user default (`KRAKEN_RUNTIME_DIR` wins).
    pub runtime_dir: Option<RuntimeDir>,
    /// How `krakend` is found and started when none runs.
    pub start: StartOptions,
}

impl DaemonAuto {
    fn dir(&self) -> Result<RuntimeDir, ProtoError> {
        match &self.runtime_dir {
            Some(d) => Ok(d.clone()),
            None => RuntimeDir::resolve()
                .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("runtime dir: {e}"))),
        }
    }

    /// Connects to the running daemon, starting it when needed.
    pub async fn connect(
        &self,
        kind: ClientKind,
    ) -> Result<DaemonClient, kraken_host::daemon::DaemonError> {
        let dir = self.dir().map_err(|e| {
            kraken_host::daemon::DaemonError::Runtime(kraken_ipc::IpcError::NoRuntimeDir(e.message))
        })?;
        DaemonClient::connect_or_start(&dir, kind, BUILD, &self.start).await
    }

    /// Connects to the daemon only if one is already running; never starts one.
    pub async fn connect_running(
        &self,
        kind: ClientKind,
    ) -> Result<Option<DaemonClient>, kraken_host::daemon::DaemonError> {
        let dir = self.dir().map_err(|e| {
            kraken_host::daemon::DaemonError::Runtime(kraken_ipc::IpcError::NoRuntimeDir(e.message))
        })?;
        DaemonClient::connect_running(&dir, kind, BUILD).await
    }
}

/// Where commands run.
#[derive(Clone)]
pub enum DaemonMode {
    /// In this process, one session per invocation (the 0.1a behaviour).
    Direct,
    /// Through `krakend`: connect to the running daemon or start it; fall back to
    /// [`Direct`](DaemonMode::Direct) with a warning when that is impossible.
    Auto(DaemonAuto),
    /// Through an already connected daemon (tests, embedding).
    Connected(Arc<DaemonClient>),
}

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
    /// Commands then run in this process whatever `daemon` says.
    pub session: Option<Arc<Session>>,
    /// Where commands run; `--no-daemon` and `KRAKEN_NO_DAEMON` force direct mode.
    pub daemon: DaemonMode,
    /// The rewrite pipeline attached to sessions that run in this process (`rewrite_*`
    /// commands). Through the daemon, the daemon's own pipeline runs them.
    pub rewrite: Option<Arc<dyn RewriteBackend>>,
}

/// Commands that need no open project.
const PROJECTLESS: [&str; 1] = ["binary_probe"];

impl CliEnv {
    /// The environment of the real binary.
    pub fn standard(config: KrakenConfig) -> Self {
        CliEnv {
            registry: Arc::new(Registry::standard()),
            factory: Arc::new(HostEngineFactory::new(config.clone())),
            config,
            author: CliAuthor::User(user_id()),
            vars: Box::new(|k| std::env::var(k).ok()),
            interactive: true,
            session: None,
            daemon: DaemonMode::Auto(DaemonAuto::default()),
            rewrite: Some(kraken_rewrite::RewriteService::standard().into_backend()),
        }
    }

    pub(crate) fn var(&self, k: &str) -> Option<String> {
        (self.vars)(k).filter(|v| !v.is_empty())
    }

    fn new_session(&self) -> Arc<Session> {
        self.session.clone().unwrap_or_else(|| {
            let mut s =
                Session::new(self.factory.clone()).with_config(self.config.session_config());
            if let Some(r) = &self.rewrite {
                s = s.with_rewrite(r.clone());
            }
            Arc::new(s)
        })
    }

    /// True when the person asked for in-process execution.
    pub(crate) fn no_daemon(&self, sm: &ArgMatches) -> bool {
        sm.try_get_one::<bool>("no-daemon").ok().flatten().copied() == Some(true)
            || self
                .var("KRAKEN_NO_DAEMON")
                .is_some_and(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
    }

    /// The backend for one invocation, and its session when it runs in this process.
    pub(crate) async fn backend(
        &self,
        project: Option<&str>,
        no_daemon: bool,
        err: &mut dyn Write,
    ) -> Result<(Arc<dyn CommandBackend>, Option<Arc<Session>>), ProtoError> {
        let project = project.map(PathBuf::from);
        let local = |this: &Self, project: Option<PathBuf>| {
            let session = this.new_session();
            let backend: Arc<dyn CommandBackend> = Arc::new(LocalBackend::new(
                this.registry.clone(),
                session.clone(),
                project,
            ));
            (backend, Some(session))
        };
        if self.session.is_some() || no_daemon {
            return Ok(local(self, project));
        }
        match &self.daemon {
            DaemonMode::Direct => Ok(local(self, project)),
            DaemonMode::Connected(c) => Ok((
                Arc::new(DaemonBackend::new(
                    c.clone(),
                    self.registry.clone(),
                    project,
                )),
                None,
            )),
            DaemonMode::Auto(auto) => match auto.connect(ClientKind::Cli).await {
                Ok(c) => Ok((
                    Arc::new(DaemonBackend::new(
                        Arc::new(c),
                        self.registry.clone(),
                        project,
                    )),
                    None,
                )),
                Err(e) if e.restart_required() => Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!("{e}; run `kraken daemon stop` and retry"),
                )),
                Err(e) => {
                    emit(
                        err,
                        &format!(
                            "warning: cannot use krakend ({e}); running in this process \
                             (--no-daemon silences this)\n"
                        ),
                    );
                    Ok(local(self, project))
                }
            },
        }
    }

    pub(crate) fn context(&self, yes: bool) -> CallContext {
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
    let mut long = spec.tool_description();
    if !spec.details.trim().is_empty() {
        long = format!("{long}\n\n{}", spec.details.trim());
    }
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
        )
        .arg(
            Arg::new("no-daemon")
                .long("no-daemon")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Run in this process instead of through krakend (also KRAKEN_NO_DAEMON=1)"),
        );
    for entry in registry.iter() {
        root = root.subcommand(sub_for(entry));
    }
    root.subcommand(
        Command::new("commands")
            .about("List all commands with their argument and output JSON Schemas"),
    )
    .subcommand(
        Command::new("mcp")
            .about("Serve the commands as MCP tools over stdio")
            .long_about(
                "Serve the commands as MCP tools over stdio. By default the server keeps its own \
                 in-process session (0.1b) unless krakend is already running, in which case it joins it; \
                 with --daemon the commands always run in krakend (started on demand), sharing \
                 projects and the Ghidra sidecar with the CLI and the GUI.",
            )
            .arg(
                Arg::new("daemon")
                    .long("daemon")
                    .action(ArgAction::SetTrue)
                    .help("Route the commands through krakend (started on demand)"),
            )
            .arg(
                Arg::new("run-id")
                    .long("run-id")
                    .value_name("ID")
                    .hide(true)
                    .help("Log this connection's edits under this run id (set by the assistant when it launches a terminal agent, so `undo-run` finds them)"),
            ),
    )
    .subcommand(
        Command::new("setup")
            .about("Download and install the pinned Ghidra and JDK, and build the Ghidra extension")
            .long_about(
                "Downloads Ghidra 12.1.4 and Temurin JDK 21 (HTTPS only, SHA-256 checked before \
                 anything is extracted), unpacks them into the runtime directory \
                 ($XDG_DATA_HOME/kraken/runtime) and compiles the KRAKEN extension with the \
                 downloaded JDK. Interrupted downloads resume; a finished setup is left alone unless \
                 --force is given. KRAKEN_GHIDRA_HOME / KRAKEN_JAVA_HOME (or the config file) take \
                 precedence over this copy. With --dotnet it installs the .NET engine instead: a \
                 pinned .NET runtime and the prebuilt kraken-dotnet sidecar shipped with the \
                 release, which open .NET assemblies. With --native it prepares the JVM-free native \
                 engine instead: from a source checkout it runs `cargo xtask native-src` and \
                 `cargo xtask native-sla` (the pinned Ghidra sources and the compiled Sleigh \
                 files); anywhere else it prints the exact commands, because the decompiler \
                 library is linked when kraken is built. Pick the engine per project with \
                 `kraken project-create --engine ghidra|native|auto`.",
            )
            .arg(
                Arg::new("dotnet")
                    .long("dotnet")
                    .action(ArgAction::SetTrue)
                    .conflicts_with("native")
                    .help("Install the .NET runtime and sidecar (for .NET assemblies) instead of Ghidra"),
            )
            .arg(
                Arg::new("native")
                    .long("native")
                    .action(ArgAction::SetTrue)
                    .help("Fetch the native engine's sources and compile its Sleigh files instead of installing Ghidra"),
            )
            .arg(
                Arg::new("force")
                    .long("force")
                    .action(ArgAction::SetTrue)
                    .help("Download, extract and build again even if everything is in place"),
            ),
    )
    .subcommand(
        Command::new("explain")
            .about("Explain a function in plain language (needs an AI model or terminal agent)")
            .long_about(
                "Explain the function at ADDRESS in plain language: what it does, its key \
                 behaviours and names worth considering. The assistant reads the function through \
                 the same commands as everyone else and changes nothing. Needs a [provider] table (an AI model or a terminal agent) \
                 in config.toml; see docs/assistant.md. Text streams to stdout, tool calls to \
                 stderr; --json prints one structured result instead.",
            )
            .arg(
                Arg::new("address")
                    .required(true)
                    .value_name("ADDRESS")
                    .help("Address of the function, as hex (for example 0x401000)"),
            ),
    )
    .subcommand(
        Command::new("overview")
            .about("Guided first look at the program: what it is, main parts, where to start")
            .long_about(
                "A guided first look at the open project: what the program appears to be, its main \
                 parts, which functions to open first and why, and what to do next. Reads only. \
                 Needs an AI model or terminal agent; see docs/assistant.md.",
            ),
    )
    .subcommand(
        Command::new("auto-name")
            .about("Suggest names and comments for default-named functions (needs an AI model or terminal agent)")
            .long_about(
                "Look at functions that still have default names (FUN_...) and suggest names and \
                 comments with the evidence for each. Without --dry-run the suggestions are \
                 written under the agent `kraken-assistant`: additive edits are applied (and can \
                 be undone with `kraken undo-run`), anything that would overwrite a person's work \
                 becomes a proposal. The confidence shown counts independent kinds of evidence; it \
                 is not a probability.",
            )
            .arg(
                Arg::new("limit")
                    .long("limit")
                    .value_name("N")
                    .default_value("10")
                    .value_parser(clap::value_parser!(usize))
                    .help("Most functions to look at (at most 50)"),
            )
            .arg(
                Arg::new("dry-run")
                    .long("dry-run")
                    .action(ArgAction::SetTrue)
                    .help("Only suggest; write nothing"),
            ),
    )
    .subcommand(crate::auto_cmd::command())
    .subcommand(crate::eval_cmd::command())
    .subcommand(
        Command::new("glossary")
            .about("Look up a reverse-engineering term or an instruction mnemonic")
            .long_about(
                "Plain-language definitions of reverse-engineering terms and of common x86-64 and \
                 AArch64 mnemonics. Works offline and needs no project or provider.",
            )
            .arg(
                Arg::new("term")
                    .required(true)
                    .num_args(1..)
                    .value_name("TERM")
                    .help("A term (stack frame) or mnemonic (jne); typos are forgiven"),
            )
            .arg(
                Arg::new("arch")
                    .long("arch")
                    .value_name("ARCH")
                    .value_parser(PossibleValuesParser::new(["x86_64", "aarch64"]))
                    .help("Prefer mnemonics of this architecture"),
            ),
    )
    .subcommand(
        Command::new("agents")
            .about("Terminal agents (Claude Code, Codex, Gemini CLI) connected to KRAKEN over ACP")
            .long_about(
                "Run terminal coding agents over the Agent Client Protocol, pre-connected to \
                 KRAKEN's MCP server so they can use KRAKEN's tools. The agents also bring their \
                 own shell and file tools, which are outside KRAKEN's safety model; a warning is \
                 shown on first use. See the terminal agents section of docs/assistant.md.",
            )
            .subcommand_required(true)
            .subcommand(Command::new("list").about("Show which agents are detected, available, missing or unsupported"))
            .subcommand(
                Command::new("setup")
                    .about("Download Node.js if needed and install an agent's adapter")
                    .arg(Arg::new("id").required(true).value_name("AGENT").help("claude, codex, gemini or a custom id"))
                    .arg(
                        Arg::new("yes")
                            .long("yes")
                            .short('y')
                            .action(ArgAction::SetTrue)
                            .help("Download without asking first"),
                    ),
            )
            .subcommand(
                Command::new("run")
                    .about("Send one prompt to an agent and stream its answer")
                    .arg(Arg::new("id").required(true).value_name("AGENT").help("claude, codex, gemini or a custom id"))
                    .arg(Arg::new("prompt").required(true).value_name("PROMPT").help("What to ask the agent"))
                    .arg(
                        Arg::new("daemon")
                            .long("daemon")
                            .action(ArgAction::SetTrue)
                            .help("Connect the agent to `kraken mcp --daemon` instead of its own session"),
                    )
                    .arg(
                        Arg::new("auto-approve")
                            .long("auto-approve")
                            .action(ArgAction::SetTrue)
                            .help("Allow every permission request the agent makes (dangerous)"),
                    ),
            )
            .subcommand(Command::new("__fake-agent").hide(true).about("Test support: a fake ACP agent on stdio")),
    )
    .subcommand(infer_command())
    .subcommand(
        Command::new("daemon")
            .about("Inspect and control the krakend daemon")
            .subcommand_required(true)
            .subcommand(Command::new("status").about("Show whether krakend runs, its sessions and sidecars"))
            .subcommand(Command::new("stop").about("Ask krakend to exit (it closes projects and stops Ghidra first)"))
            .subcommand(Command::new("start").about("Start krakend if it is not running"))
            .subcommand(
                Command::new("approvals")
                    .about("List what agents wait to do until you approve it, and answer")
                    .long_about(
                        "An agent that asks to open a project, or to work on one you have not \
                         opened yourself, waits for your approval. The KRAKEN window shows a \
                         dialog; without one, list the waiting requests here and answer with \
                         --approve or --deny.",
                    )
                    .arg(
                        Arg::new("approve")
                            .long("approve")
                            .value_name("ID")
                            .value_parser(clap::value_parser!(u64))
                            .conflicts_with("deny")
                            .help("Allow the request with this id"),
                    )
                    .arg(
                        Arg::new("deny")
                            .long("deny")
                            .value_name("ID")
                            .value_parser(clap::value_parser!(u64))
                            .help("Refuse the request with this id"),
                    ),
            ),
    )
}

/// `kraken infer ...`: run a model on this computer.
fn infer_command() -> Command {
    Command::new("infer")
        .about("Run a language model on this computer (llama.cpp or another engine)")
        .long_about(
            "Run a model on this computer and point the assistant at it. The model runs as a \
             supervised process of krakend and keeps running between commands; with --no-daemon \
             it only lives as long as the command. KRAKEN never downloads models: pass a GGUF \
             file you chose yourself. See docs/local-models.md.",
        )
        .subcommand_required(true)
        .subcommand(Command::new("list").about("Show the engines this computer can run, with their settings and the memory left"))
        .subcommand(
            Command::new("start")
                .about("Start a model")
                .arg(Arg::new("engine").required(true).value_name("ENGINE").help("An id from `kraken infer list`, for example llama-server"))
                .arg(
                    Arg::new("model")
                        .long("model")
                        .short('m')
                        .value_name("FILE")
                        .help("Model file (sets the engine's model setting)"),
                )
                .arg(
                    Arg::new("set")
                        .long("set")
                        .value_name("KEY=VALUE")
                        .action(ArgAction::Append)
                        .help("An engine setting, repeatable (see `kraken infer list`), for example --set gpu_layers=99 --set n_cpu_moe=30"),
                )
                .arg(
                    Arg::new("use")
                        .long("use")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("no-wait")
                        .help("Make the assistant use this model: writes [provider] (openai_compatible) to config.toml once the model is ready"),
                )
                .arg(
                    Arg::new("no-wait")
                        .long("no-wait")
                        .action(ArgAction::SetTrue)
                        .help("Return as soon as the process is started instead of waiting until the model is loaded"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_name("SECONDS")
                        .help("How long to wait for the model to load (default 900)"),
                ),
        )
        .subcommand(Command::new("status").about("Show the running model and how far loading is"))
        .subcommand(Command::new("stop").about("Stop the running model"))
        .subcommand(
            Command::new("logs")
                .about("Show the model process's output")
                .arg(Arg::new("tail").long("tail").short('n').value_name("LINES").help("Lines to show (default 100)"))
                .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue).help("Keep printing new lines")),
        )
        .subcommand(
            Command::new("setup")
                .about("Download an engine")
                .subcommand_required(true)
                .subcommand(
                    Command::new("llama")
                        .about("Download the pinned llama.cpp release build (llama-server) into KRAKEN's data directory")
                        .arg(
                            Arg::new("variant")
                                .long("variant")
                                .value_name("VARIANT")
                                .help("cpu, vulkan (Linux, Windows) or metal (macOS); default: the first for this computer"),
                        )
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .action(ArgAction::SetTrue)
                                .help("Download and install again even if it is installed"),
                        ),
                ),
        )
}

pub(crate) fn bad(msg: impl Into<String>) -> ProtoError {
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

pub(crate) fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

pub(crate) fn emit(w: &mut dyn Write, s: &str) {
    // A closed pipe (`| head`) is not an error worth reporting.
    let _ = w.write_all(s.as_bytes());
}

pub(crate) fn fail(e: &ProtoError, json: bool, err: &mut dyn Write) -> i32 {
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
pub(crate) fn fill_project_dir(
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

pub(crate) async fn wait_for_job(
    env: &CliEnv,
    backend: &dyn CommandBackend,
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
    let mut printer = ProgressPrinter::new(env.interactive && std::io::stderr().is_terminal());
    loop {
        let wait = backend.call("job_await", ctx, json!({"job_id": id, "timeout_ms": 500}));
        let view = if env.interactive {
            tokio::select! {
                v = wait => v?,
                _ = tokio::signal::ctrl_c() => {
                    emit(err, "cancelling...\n");
                    let _ = backend.call("job_cancel", ctx, json!({"job_id": id})).await;
                    continue;
                }
            }
        } else {
            wait.await?
        };
        if let Some(p) = view.get("progress")
            && last.as_ref() != Some(p)
        {
            printer.job(
                p["phase"].as_str().unwrap_or(""),
                p["done"].as_u64().unwrap_or(0),
                p["total"].as_u64().unwrap_or(0),
                p["message"].as_str().unwrap_or(""),
                err,
            );
            last = Some(p.clone());
        }
        let status = view.get("status").and_then(Value::as_str);
        if status != Some("running") {
            printer.finish(err);
        }
        match status {
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

/// Runs `project_create` / `project_open` with a progress display on stderr. Ctrl+C cancels
/// the open (the engine stops and nothing of the project stays open).
async fn run_open(
    env: &CliEnv,
    backend: &dyn CommandBackend,
    ctx: CallContext,
    name: &str,
    args: Value,
    err: &mut dyn Write,
) -> Result<Value, ProtoError> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<kraken_proto::OpenProgress>();
    let cancel = CancellationToken::new();
    let ctx = ctx
        .with_cancel(cancel.clone())
        .with_open_progress(Arc::new(move |p| {
            let _ = tx.send(p.clone());
        }));
    let mut printer = ProgressPrinter::new(env.interactive && std::io::stderr().is_terminal());
    let call = backend.call(name, &ctx, args);
    tokio::pin!(call);
    let mut cancelling = false;
    let result = loop {
        tokio::select! {
            r = &mut call => break r,
            Some(p) = rx.recv() => printer.open(&p, err),
            _ = tokio::signal::ctrl_c(), if env.interactive && !cancelling => {
                cancelling = true;
                printer.finish(err);
                emit(err, "cancelling...\n");
                cancel.cancel();
            }
        }
    };
    while let Ok(p) = rx.try_recv() {
        printer.open(&p, err);
    }
    printer.finish(err);
    result
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
    let creating = matches!(name, "project_create" | "project_open");

    let setup = if creating {
        fill_project_dir(env, name, &mut args, project.as_deref())
    } else if project.is_none()
        && !PROJECTLESS.contains(&name)
        && !env.session.as_ref().is_some_and(|s| s.project().is_ok())
    {
        Err(bad(
            "no project: pass --project <dir> or set KRAKEN_PROJECT",
        ))
    } else {
        Ok(())
    };
    if let Err(e) = setup {
        env.factory.shutdown().await;
        return fail(&e, json_out, err);
    }

    let ctx = env.context(yes);
    let (backend, local_session) = match env
        .backend(project.as_deref(), env.no_daemon(sm), err)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            env.factory.shutdown().await;
            return fail(&e, json_out, err);
        }
    };
    let first = if creating {
        run_open(env, backend.as_ref(), ctx.clone(), name, args, err).await
    } else {
        backend.call(name, &ctx, args).await
    };
    let result = match first {
        Ok(v) if entry.spec().kind == CommandKind::Job && !no_wait => {
            wait_for_job(env, backend.as_ref(), &ctx, &v, err).await
        }
        other => other,
    };
    for w in backend.take_warnings() {
        emit(err, &format!("warning: {w}\n"));
    }

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

    if code == 0
        && entry.spec().kind != CommandKind::Query
        && let Some(session) = &local_session
    {
        save(session, err).await;
    }
    env.factory.shutdown().await;
    code
}

pub(crate) async fn save(session: &Session, err: &mut dyn Write) {
    let Ok(project) = session.project() else {
        return;
    };
    if let Err(e) = project.save(&CancellationToken::new()).await {
        emit(
            err,
            &format!("warning: saving the project failed: {}\n", e.message),
        );
    }
}

async fn run_mcp(env: &CliEnv, sm: &ArgMatches, json_out: bool, err: &mut dyn Write) -> i32 {
    let project = sm
        .get_one::<String>("project")
        .cloned()
        .or_else(|| env.var("KRAKEN_PROJECT"));
    // A project chosen on the command line binds the server to it (no project_create or
    // project_open for the agent to point the engine elsewhere).
    let options = McpOptions {
        bound_project: project.is_some(),
        run_id: sm.get_one::<String>("run-id").cloned(),
        ..McpOptions::default()
    };
    if sm.get_flag("daemon") {
        return run_mcp_via_daemon(env, project, options, json_out, err).await;
    }
    // A running krakend may already hold the project (the CLI starts it on demand), and a
    // Ghidra project can only be open in one process, so join the daemon when it is up.
    if env.session.is_none()
        && !env.no_daemon(sm)
        && let DaemonMode::Auto(auto) = &env.daemon
        && let Ok(Some(client)) = auto.connect_running(ClientKind::Mcp).await
    {
        tracing::info!("krakend is running; serving MCP through it");
        return run_mcp_with_client(env, Arc::new(client), project, options, json_out, err).await;
    }
    let session = env.new_session();
    if let Some(dir) = project
        && session.project().is_err()
        && let Err(e) = session.open_project(&absolute(Path::new(&dir))).await
    {
        env.factory.shutdown().await;
        return fail(&e, json_out, err);
    }
    let server = KrakenMcp::new(env.registry.clone(), session, options);
    tracing::info!(run_id = server.run_id(), "starting MCP server on stdio");
    let result = serve_stdio(server).await;
    env.factory.shutdown().await;
    finish_mcp(result, json_out, err)
}

fn finish_mcp(
    result: Result<(), kraken_mcp::ServeError>,
    json_out: bool,
    err: &mut dyn Write,
) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => fail(
            &ProtoError::new(ErrorCode::Internal, e.to_string()),
            json_out,
            err,
        ),
    }
}

/// `kraken mcp --daemon`: the same tools, but the commands run in `krakend`.
async fn run_mcp_via_daemon(
    env: &CliEnv,
    project: Option<String>,
    options: McpOptions,
    json_out: bool,
    err: &mut dyn Write,
) -> i32 {
    let client = match &env.daemon {
        DaemonMode::Connected(c) => Ok(c.clone()),
        DaemonMode::Auto(auto) => auto.connect(ClientKind::Mcp).await.map(Arc::new),
        DaemonMode::Direct => DaemonAuto::default()
            .connect(ClientKind::Mcp)
            .await
            .map(Arc::new),
    };
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            let hint = if e.restart_required() {
                "; run `kraken daemon stop` and retry"
            } else {
                ""
            };
            return fail(
                &ProtoError::new(ErrorCode::Unsupported, format!("{e}{hint}")),
                json_out,
                err,
            );
        }
    };
    run_mcp_with_client(env, client, project, options, json_out, err).await
}

/// Serves MCP with every command routed through an already connected daemon.
async fn run_mcp_with_client(
    env: &CliEnv,
    client: Arc<DaemonClient>,
    project: Option<String>,
    options: McpOptions,
    json_out: bool,
    err: &mut dyn Write,
) -> i32 {
    let backend = Arc::new(DaemonBackend::new(
        client,
        env.registry.clone(),
        project.clone().map(PathBuf::from),
    ));
    if project.is_some() {
        // Fail early on a bad project, as the in-process server does.
        let ctx = CallContext::user(user_id(), Surface::Mcp);
        if let Err(e) = backend.call("project_info", &ctx, Value::Null).await {
            return fail(&e, json_out, err);
        }
    }
    let server = KrakenMcp::with_backend(env.registry.clone(), backend, options);
    tracing::info!(
        run_id = server.run_id(),
        "starting MCP server on stdio (via krakend)"
    );
    finish_mcp(serve_stdio(server).await, json_out, err)
}

/// Runs the CLI: parses `args` (including the program name), writes to `out` and `err`, and
/// returns the exit code.
pub async fn run(
    args: Vec<OsString>,
    env: &CliEnv,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    run_with_provider(args, env, None, out, err).await
}

/// [`run`] with the assistant's chat provider supplied instead of read from `config.toml`
/// (tests, embedding). `None` loads the `[provider]` table as the real binary does.
pub async fn run_with_provider(
    args: Vec<OsString>,
    env: &CliEnv,
    provider: Option<Arc<dyn kraken_agent::ChatProvider>>,
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
        "agents" => crate::agents_cmd::run_agents(env, sm, json_out, out, err).await,
        "infer" => crate::infer_cmd::run_infer(env, sm, json_out, out, err).await,
        "setup" => crate::setup::run_setup(env, sm, json_out, out, err).await,
        "daemon" => crate::daemon_cmd::run_daemon(env, sm, json_out, out, err).await,
        "glossary" => crate::assist_cmd::run_glossary(sm, json_out, out, err),
        "eval" => crate::eval_cmd::run_eval(env, sm, json_out, provider, out, err).await,
        "auto" => crate::auto_cmd::run_auto(env, sm, json_out, provider, out, err).await,
        "explain" | "overview" | "auto-name" => {
            crate::assist_cmd::run_assist(env, sub, sm, json_out, provider, out, err).await
        }
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
