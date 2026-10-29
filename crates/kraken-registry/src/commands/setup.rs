//! Machine-global setup: what is installed and ready, and the installs as cancellable jobs.
//!
//! None of these needs a project. `setup_status` reports each tool KRAKEN uses (the engines'
//! runtimes, the Rust toolchain, emulators, local inference) with a hint for fixing what is
//! missing. `setup_ghidra`, `setup_native`, `setup_dotnet` and `integration_install_start` do the
//! installs as jobs (`job-gN`): progress in `job_status`, stop with `job_cancel`. The work is done
//! by a [`SetupBackend`] that `kraken-host` provides; `kraken setup` runs the same code.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::integrations::{IntegrationInstallArgs, IntegrationsBackend, vet_install};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::jobs::JobProgress;
use crate::session::{Session, blocking};

/// How ready one part is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    /// Installed and usable.
    Ready,
    /// Not installed.
    Missing,
    /// Some pieces are there, others are not.
    Partial,
    /// Cannot be set up on this computer or build.
    Unavailable,
}

/// One tool or runtime KRAKEN can use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SetupItem {
    /// Stable id: `ghidra`, `native`, `dotnet`, `rust`, `emulators`, `llama`, `strata`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// What it is for, in one line.
    pub purpose: String,
    /// Where it stands.
    pub state: SetupState,
    /// What was found (versions, paths) or what is wrong.
    pub detail: String,
    /// What to do when it is not ready, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// The registry command that fixes it, when there is one (`setup_ghidra`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_command: Option<String>,
}

/// What a `setup_*` job installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetupTask {
    /// Ghidra, a JDK and the KRAKEN extension.
    Ghidra,
    /// The native engine's Sleigh files (and sources).
    Native,
    /// The .NET runtime and the sidecar.
    Dotnet,
}

impl SetupTask {
    /// The command that runs it.
    pub fn command(self) -> &'static str {
        match self {
            SetupTask::Ghidra => "setup_ghidra",
            SetupTask::Native => "setup_native",
            SetupTask::Dotnet => "setup_dotnet",
        }
    }
}

/// Probes the machine and runs the installs; provided by `kraken-host`.
#[async_trait]
pub trait SetupBackend: Send + Sync + std::fmt::Debug {
    /// Every part and how ready it is. Blocking: it looks at files and runs version probes.
    fn status(&self) -> Result<Vec<SetupItem>, ProtoError>;
    /// Installs `task`, reporting through `progress`. Dropping the future cancels it; a partial
    /// download stays for the next run to resume.
    async fn run(
        &self,
        task: SetupTask,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError>;
}

impl Session {
    /// The attached setup backend.
    pub fn setup(&self) -> Result<&Arc<dyn SetupBackend>, ProtoError> {
        self.setup_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "setup is not attached to this session; use the kraken CLI, krakend or the GUI",
            )
        })
    }
}

/// Output of `setup_status`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetupStatusOut {
    /// One row per part.
    pub items: Vec<SetupItem>,
    /// Parts that are ready.
    pub ready: u32,
    /// Parts that are not.
    pub not_ready: u32,
}

/// Reports what is installed and ready.
pub struct SetupStatus;

#[async_trait]
impl Command for SetupStatus {
    type Args = super::NoArgs;
    type Output = SetupStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "setup_status",
            "Show what is installed and ready on this computer, with a fix for what is not",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Needs no project. One row per part KRAKEN uses: the Ghidra engine (Ghidra and a \
             JDK), the native engine (Sleigh files), the .NET engine, the Rust toolchain (for \
             rewrites), emulators and local inference (llama.cpp, Strata). `state` is `ready`, \
             `missing`, `partial` or `unavailable`; `fix` says what to do and `fix_command` names \
             the command that does it.\n\
             Example: setup_status {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<SetupStatusOut, ProtoError> {
        let backend = s.setup()?.clone();
        let items = blocking(move || backend.status()).await?;
        let ready = items
            .iter()
            .filter(|i| i.state == SetupState::Ready)
            .count() as u32;
        Ok(SetupStatusOut {
            not_ready: items.len() as u32 - ready,
            ready,
            items,
        })
    }
}

/// Output of the commands that start a global job.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GlobalJobOut {
    /// The job: `job_status`, `job_await` and `job_cancel` take it (`job-g1`, ...).
    pub job_id: String,
}

/// Arguments of the `setup_*` commands.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetupArgs {
    /// Install again even when it looks complete.
    #[serde(default)]
    pub force: bool,
}

fn start_setup(s: &Session, task: SetupTask, force: bool) -> Result<GlobalJobOut, ProtoError> {
    let backend = s.setup()?.clone();
    let id = s.jobs().spawn(task.command(), move |reporter| async move {
        let token = reporter.cancel_token();
        let on = move |p: JobProgress| reporter.progress(p);
        tokio::select! {
            biased;
            () = token.cancelled() => Err(ProtoError::new(ErrorCode::Cancelled, "setup cancelled")),
            r = backend.run(task, force, &on) => r,
        }
    });
    Ok(GlobalJobOut { job_id: id.0 })
}

macro_rules! setup_command {
    ($ty:ident, $task:expr, $name:literal, $summary:literal, $doc:literal, $details:literal) => {
        #[doc = $summary]
        pub struct $ty;

        #[async_trait]
        impl Command for $ty {
            type Args = SetupArgs;
            type Output = GlobalJobOut;

            fn spec() -> CommandSpec {
                CommandSpec::new($name, $summary, CommandKind::Job, Permission::Mutating)
                    .global()
                    .doc($doc)
                    .details($details)
            }

            async fn run(
                &self,
                s: &Session,
                ctx: &CallContext,
                args: SetupArgs,
            ) -> Result<GlobalJobOut, ProtoError> {
                s.setup()?;
                ctx.require_approval(
                    $name,
                    $summary.to_string(),
                    serde_json::json!({ "force": args.force }),
                )
                .await?;
                start_setup(s, $task, args.force)
            }
        }
    };
}

setup_command!(
    SetupGhidra,
    SetupTask::Ghidra,
    "setup_ghidra",
    "Download Ghidra, a JDK and build the KRAKEN extension (job)",
    "Needs no project. Downloads the pinned Ghidra release and a JDK from their upstream \
     hosts over HTTPS (about 700 MiB), checks their SHA-256 and installs them with the \
     KRAKEN extension under KRAKEN's data directory. Returns a `job_id` (`job-gN`): watch it \
     with `job_status`, wait with `job_await`, stop it with `job_cancel` (a partial download \
     is kept and resumed next time). Agents and MCP callers are asked first.\n\
     Example: setup_ghidra {}",
    "The same work as `kraken setup`. Skips parts that are installed unless `force` is true."
);

setup_command!(
    SetupNative,
    SetupTask::Native,
    "setup_native",
    "Fetch the native engine's sources and compile its Sleigh files (job)",
    "Needs no project. Makes the native engine usable: fetches the pinned Ghidra sources and \
     compiles the Sleigh processor files with `cargo xtask`. That needs the source checkout this \
     build came from; otherwise the job fails with the exact commands to run. Returns a \
     `job_id`: `job_status`, `job_await`, `job_cancel`. Agents and MCP callers are asked first.\n\
     Example: setup_native {}",
    "The same work as `kraken setup --native`."
);

setup_command!(
    SetupDotnet,
    SetupTask::Dotnet,
    "setup_dotnet",
    "Download the .NET runtime and install the managed-code sidecar (job)",
    "Needs no project. Downloads the pinned .NET runtime over HTTPS, checks its SHA-256 and \
     installs it with the KRAKEN .NET sidecar under KRAKEN's data directory. Returns a `job_id`: \
     `job_status`, `job_await`, `job_cancel`. Agents and MCP callers are asked first.\n\
     Example: setup_dotnet {}",
    "The same work as `kraken setup --dotnet`."
);

/// Starts the install of a catalogue entry as a job.
pub struct IntegrationInstallStart;

#[async_trait]
impl Command for IntegrationInstallStart {
    type Args = IntegrationInstallArgs;
    type Output = GlobalJobOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "integration_install_start",
            "Install an emulator or tool from the catalogue as a cancellable job",
            CommandKind::Job,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Like `integration_install`, but returns a `job_id` at once: the download reports \
             its progress in `job_status`, `job_cancel` stops it (the partial file is kept). \
             `accept_licence` must be true; agents and MCP callers are asked first.\n\
             Example: integration_install_start {\"id\": \"mgba\", \"accept_licence\": true}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: IntegrationInstallArgs,
    ) -> Result<GlobalJobOut, ProtoError> {
        let backend = s.integrations()?.clone();
        vet_install(&backend, ctx, "integration_install_start", &args).await?;
        let id = s
            .jobs()
            .spawn("integration_install_start", move |reporter| async move {
                run_install(backend, args, reporter).await
            });
        Ok(GlobalJobOut { job_id: id.0 })
    }
}

async fn run_install(
    backend: Arc<dyn IntegrationsBackend>,
    args: IntegrationInstallArgs,
    reporter: crate::jobs::JobReporter,
) -> Result<Value, ProtoError> {
    let token = reporter.cancel_token();
    let install = backend.install(&args.id, args.accept_licence);
    tokio::pin!(install);
    let mut tick = tokio::time::interval(Duration::from_millis(300));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let started = std::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                return Err(ProtoError::new(ErrorCode::Cancelled, "install cancelled"));
            }
            r = &mut install => {
                let view = r?;
                return serde_json::to_value(view)
                    .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()));
            }
            _ = tick.tick() => {
                let b = backend.clone();
                let id = args.id.clone();
                let found = blocking(move || b.list()).await.ok().and_then(|l| {
                    l.into_iter().find(|e| e.id == id).and_then(|e| e.progress.map(|p| (e.name, p)))
                });
                if let Some((name, p)) = found {
                    reporter.progress(JobProgress {
                        message: format!("{} {name}", p.phase),
                        phase: p.phase,
                        done: p.done,
                        total: p.total,
                        elapsed_ms: Some(started.elapsed().as_millis() as u64),
                        ..Default::default()
                    });
                }
            }
        }
    }
}
