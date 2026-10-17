//! `project_create`, `project_open`, `project_info`.

use std::path::Path;

use async_trait::async_trait;
use kraken_proto::{PageRequest, ProtoError, Untrusted, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{AnalysisPhase, Epoch, Project, Session, peek_binary};
use crate::trust;
use crate::views::ProgramView;

use super::NoArgs;

/// Analysis state of the project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisView {
    /// `not_started`, `running`, `complete`, `failed` or `cancelled`.
    pub phase: AnalysisPhase,
    /// Functions known after the last finished analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_count: Option<u64>,
    /// The running or last analysis job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Why the last run failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Untrusted<String>>,
}

/// Facts about the open project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectInfoOut {
    /// Project directory.
    pub project_dir: String,
    /// Absolute path of the analysed binary. The file name is chosen by whoever supplied the
    /// binary, so it is marked untrusted.
    pub binary_path: Untrusted<String>,
    /// SHA-256 of the binary recorded at creation.
    pub binary_sha256: String,
    /// What the engine reported when loading it.
    pub program: ProgramView,
    /// Engine build identifier (includes the Ghidra version).
    pub engine_build: String,
    /// Engine capabilities such as `decompiler`.
    pub capabilities: Vec<String>,
    /// Epoch recorded for the engine cache.
    pub epoch: Epoch,
    /// True when the engine cache no longer matches the epoch; run `rebuild`.
    pub epoch_stale: bool,
    /// Which epoch fields differ.
    pub stale_fields: Vec<String>,
    /// Analysis state.
    pub analysis: AnalysisView,
    /// Log entries waiting to be pushed to the engine.
    pub pending_entries: u64,
    /// Total log entries, including rejected ones.
    pub log_entries: u64,
    /// Proposals waiting for a decision.
    pub open_proposals: u64,
}

pub(crate) async fn info_of(project: &Project) -> Result<ProjectInfoOut, ProtoError> {
    let (pending, log_entries, open_proposals) = project
        .with_store(|st| {
            let one = PageRequest {
                cursor: None,
                limit: Some(1),
            };
            Ok((
                st.pending_entries()?.len() as u64,
                st.history(&one, &Default::default())?.total.unwrap_or(0),
                st.list_proposals(&one, Some(kraken_model::ProposalStatus::Open))?
                    .total
                    .unwrap_or(0),
            ))
        })
        .await?;
    let engine = project.engine();
    let caps = engine.capabilities();
    let meta = project.meta();
    let a = project.analysis();
    Ok(ProjectInfoOut {
        project_dir: project.dir().to_string_lossy().into_owned(),
        binary_path: Untrusted::sanitized(&meta.binary_path),
        binary_sha256: meta.binary_sha256.clone(),
        program: (&project.program()).into(),
        engine_build: sanitize(&caps.handshake.build),
        capabilities: caps.present.iter().map(|c| c.name().to_string()).collect(),
        epoch: meta.epoch.clone(),
        epoch_stale: !project.epoch_mismatch().is_empty(),
        stale_fields: project.epoch_mismatch().to_vec(),
        analysis: AnalysisView {
            phase: a.phase,
            function_count: a.function_count,
            job_id: a.job.map(|j| j.0),
            error: a.error.as_deref().map(Untrusted::sanitized),
        },
        pending_entries: pending,
        log_entries,
        open_proposals,
    })
}

/// The policy and approval an agent (or the MCP surface) must pass before `project_create` or
/// `project_open` may run (H3): the engine reads the file it is pointed at and the model sees
/// it through `read_bytes`, so credentials by location are refused and a person approves the
/// rest. People on the CLI and GUI pass untouched, and so does a call that already went through
/// the gate (the daemon runs it before it creates a session; [`CallContext::gate_passed`]).
///
/// `args` are the command's arguments (`binary` and `project_dir`, or `project_dir`).
pub async fn project_gate(
    command: &str,
    args: &serde_json::Value,
    ctx: &CallContext,
) -> Result<(), ProtoError> {
    if !ctx.needs_user_approval() || ctx.gate_passed {
        return Ok(());
    }
    let text = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    let dir = trust::check_agent_path("project_dir", Path::new(text("project_dir")))?;
    let shown = |p: &Path| sanitize(&p.display().to_string());
    if command == "project_create" {
        let binary = trust::check_agent_path("binary", Path::new(text("binary")))?;
        ctx.require_approval(
            command,
            format!(
                "create a project in {} for the binary {}",
                shown(&dir),
                shown(&binary)
            ),
            json!({"binary": shown(&binary), "project_dir": shown(&dir)}),
        )
        .await
    } else {
        // The metadata inside the project, which an agent can write, names the file read.
        let binary = peek_binary(&dir).await?;
        let binary = trust::check_agent_path("the project's binary", Path::new(&binary))?;
        ctx.require_approval(
            command,
            format!(
                "open the project in {} (it analyses {})",
                shown(&dir),
                shown(&binary)
            ),
            json!({"project_dir": shown(&dir), "binary": shown(&binary)}),
        )
        .await
    }
}

/// Arguments of `project_create`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCreateArgs {
    /// Path of the binary to analyse.
    pub binary: String,
    /// Directory for the new project; created if missing and must not hold a project yet.
    pub project_dir: String,
}

/// Creates a project for a binary.
pub struct ProjectCreate;

#[async_trait]
impl Command for ProjectCreate {
    type Args = ProjectCreateArgs;
    type Output = ProjectInfoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "project_create",
            "Create a project for a binary and make it the current project",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Creates the project directory layout (`project.kraken.sqlite`, `ghidra/`, \
             `meta.json`), starts the engine and loads the binary. Analysis is separate: run \
             `analyze`. Replaces the currently open project.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ProjectCreateArgs,
    ) -> Result<ProjectInfoOut, ProtoError> {
        project_gate(
            "project_create",
            &json!({"binary": args.binary, "project_dir": args.project_dir}),
            ctx,
        )
        .await?;
        let project = s
            .create_project(Path::new(&args.project_dir), Path::new(&args.binary))
            .await?;
        info_of(&project).await
    }
}

/// Arguments of `project_open`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOpenArgs {
    /// Directory of an existing project.
    pub project_dir: String,
}

/// Opens an existing project.
pub struct ProjectOpen;

#[async_trait]
impl Command for ProjectOpen {
    type Args = ProjectOpenArgs;
    type Output = ProjectInfoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "project_open",
            "Open an existing project and make it the current project",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Opens the project database and the engine cache. If the engine build, options or \
             binary differ from the recorded epoch the result reports `epoch_stale`; run \
             `rebuild` to recreate the engine project from the log. Replaces the open project.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ProjectOpenArgs,
    ) -> Result<ProjectInfoOut, ProtoError> {
        project_gate(
            "project_open",
            &json!({"project_dir": args.project_dir}),
            ctx,
        )
        .await?;
        let project = s.open_project(Path::new(&args.project_dir)).await?;
        info_of(&project).await
    }
}

/// Describes the open project.
pub struct ProjectInfo;

#[async_trait]
impl Command for ProjectInfo {
    type Args = NoArgs;
    type Output = ProjectInfoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "project_info",
            "Show the current project, engine and analysis state",
            CommandKind::Query,
            Permission::Safe,
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<ProjectInfoOut, ProtoError> {
        let project = s.project()?;
        info_of(&project).await
    }
}
