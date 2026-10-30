//! `project_create`, `project_open`, `project_info`, `project_close`.

use std::path::Path;

use async_trait::async_trait;
use kraken_engine::LoaderSpec;
use kraken_proto::{ErrorCode, Hex64, PageRequest, ProtoError, Untrusted, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::opening::OpenOptions;
use crate::session::{
    AnalysisPhase, EngineChoice, EngineKind, Epoch, Project, Session, blocking, peek_binary,
};
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

/// Which engine a project uses and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineView {
    /// The engine in use: `ghidra`, `native` or `dotnet`.
    pub kind: EngineKind,
    /// What was asked for at creation (`ghidra`, `native` or `auto`); absent for projects made
    /// before the choice existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice: Option<EngineChoice>,
    /// Why this engine was picked (for `auto`, what decided it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    /// The engine behind the project and why it was picked.
    pub engine: EngineView,
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
    /// Set when the open found the engine's saved state behind the edit log (another process
    /// saved over it) and applied the log's changes again: what was found and done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_resync: Option<String>,
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
        engine: EngineView {
            kind: meta.engine_kind,
            choice: meta.engine_choice,
            reason: meta.engine_reason.as_deref().map(sanitize),
        },
        engine_build: sanitize(&caps.handshake.build),
        capabilities: caps.present.iter().map(|c| c.name().to_string()).collect(),
        epoch: meta.epoch.clone(),
        epoch_stale: !project.epoch_mismatch().is_empty(),
        stale_fields: project.epoch_mismatch().to_vec(),
        engine_resync: project.resync_report().map(|r| r.message()),
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
    /// Engine for native code: `ghidra`, `native` (JVM-free; ELF and PE, x86 and x86-64) or
    /// `auto` (native when it can open the file, else Ghidra). Default: the `engine` setting.
    /// .NET assemblies always use the .NET engine.
    #[serde(default)]
    pub engine: Option<EngineChoice>,
    /// How to read the file: `auto` (default: the file's own format) or `raw` (a flat image
    /// with no header: firmware, a ROM, boot code; needs `language`).
    #[serde(default)]
    pub loader: Option<LoaderKind>,
    /// Processor of a raw image, as a Sleigh language id (`ARM:LE:32:Cortex`) or a short name
    /// (`cortex-m`, `arm`, `aarch64`, `x86`, `x86-64`, `riscv32`, `riscv64`). With `auto` it
    /// overrides the detected processor.
    #[serde(default)]
    pub language: Option<String>,
    /// Compiler spec (`gcc`, `windows`, `default`); the language's default when unset.
    #[serde(default)]
    pub compiler: Option<String>,
    /// Raw images only: address the image is mapped at (hex such as `0x08000000`); default `0`.
    #[serde(default)]
    pub base: Option<Hex64>,
    /// Raw images: file offset where the image starts (skips a header); default 0.
    #[serde(default)]
    pub offset: Option<Hex64>,
    /// Raw images: how many bytes to map from `offset`; default the rest of the file.
    #[serde(default)]
    pub length: Option<Hex64>,
    /// Raw images: address where execution starts (a function entry; for Thumb code the low
    /// bit may be set). Default: the reset vector of an ARM Cortex-M vector table, else `base`.
    #[serde(default)]
    pub entry: Option<Hex64>,
}

/// How `project_create` reads the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoaderKind {
    /// Detect the format (ELF, PE, Mach-O, archive).
    Auto,
    /// A flat memory image with no container.
    Raw,
}

impl ProjectCreateArgs {
    /// The loader hints these arguments ask for, or why they do not make sense together.
    pub fn loader_spec(&self) -> Result<LoaderSpec, ProtoError> {
        let invalid = |m: &str| ProtoError::new(ErrorCode::InvalidArgument, m.to_string());
        let raw = self.loader == Some(LoaderKind::Raw);
        if raw && self.language.as_deref().is_none_or(|l| l.trim().is_empty()) {
            return Err(invalid(
                "a raw image needs `language`, the processor it was built for (for example \
                 `cortex-m`, `arm`, `aarch64`, `x86`, `x86-64`, `riscv32`; `binary_probe` \
                 suggests one)",
            ));
        }
        if !raw && self.base.is_some() {
            return Err(invalid(
                "`base` applies to a raw image only: add `loader: raw` (PE and ELF files carry \
                 their own load address)",
            ));
        }
        if !raw && (self.offset.is_some() || self.length.is_some() || self.entry.is_some()) {
            return Err(invalid(
                "`offset`, `length` and `entry` apply to a raw image only: add `loader: raw`",
            ));
        }
        Ok(LoaderSpec {
            arch: self
                .language
                .as_deref()
                .filter(|l| !l.trim().is_empty())
                .map(kraken_engine::language_id),
            base: self.base,
            format: raw.then(|| "raw".to_string()),
            compiler: self.compiler.clone().filter(|c| !c.trim().is_empty()),
            offset: self.offset,
            length: self.length,
            entry: self.entry,
        })
    }
}

/// For an Intel HEX or S-record file: its loader format and the processor its contents suggest.
fn firmware_loader(path: &Path) -> Result<Option<(&'static str, Option<String>)>, ProtoError> {
    use std::io::Read;
    // Opening a FIFO or device would block; the regular-file check later refuses those.
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Ok(None);
    }
    let mut head = [0u8; 64];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    let Some(kind) = kraken_engine::hexfile::detect(&head[..n]) else {
        return Ok(None);
    };
    let data = std::fs::read(path).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let image = kraken_engine::hexfile::parse(&data, kind)?;
    let language = super::rawguess::guess_blocks(&image.blocks)
        .into_iter()
        .find(|s| s.confidence != "low")
        .map(|s| kraken_engine::language_id(&s.language));
    Ok(Some((kind.format(), language)))
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
            "Starts a project for a binary and loads it. Analysis is separate: run `analyze` \
             next. Replaces the open project; a person is asked to approve it when an agent \
             calls it.\n\
             Example: project_create {\"binary\": \"./a.out\", \"project_dir\": \"./a.kraken\"}",
        )
        .details(
            "Creates the project directory layout (`project.kraken.sqlite`, `ghidra/`, \
             `meta.json`), starts the engine and loads the binary. `engine` picks the engine \
             and is recorded in `meta.json`; `project_info` reports it and why `auto` chose it. \
             The first load of a big program can take minutes: while it runs it is the job \
             `open-N` (`job_status` shows its stages and counts in `open_progress`, the daemon \
             sends `open_progress` events), and `job_cancel` stops it without leaving a \
             project behind.\n\
             Intel HEX and Motorola S-record files are detected: their blocks load at the addresses \
             the records give and the start record becomes the entry; give `language` (or let \
             a recognisable vector table choose it).\n\
             Files with no header (firmware, ROMs, boot code) open with `loader: raw` and a \
             `language`: one memory block holds the file (or `offset`/`length` of it) at `base`, \
             and execution starts at `entry`. An ARM Cortex-M vector table at the start names \
             `Reset_Handler` and the interrupt handlers. `binary_probe` suggests these options \
             for a file it cannot identify. The options are recorded in `meta.json` and used on \
             every reopen and `rebuild`. The native engine loads raw x86, x86-64, ARM, \
             Cortex-M, AArch64 and RISC-V images; `auto` falls back to Ghidra for other \
             processors.",
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
        let mut loader = args.loader_spec()?;
        if args.loader != Some(LoaderKind::Raw) {
            let binary = args.binary.clone();
            let found = blocking(move || firmware_loader(Path::new(&binary))).await?;
            if let Some((format, language)) = found {
                loader.format = Some(format.into());
                if loader.arch.is_none() {
                    loader.arch = Some(language.ok_or_else(|| {
                        ProtoError::new(
                            ErrorCode::InvalidArgument,
                            "this is a firmware record file (Intel HEX or S-record), which does \
                             not say which processor it is for: pass `language` (for example \
                             `cortex-m`, `arm`, `x86`; `binary_probe` suggests one)",
                        )
                    })?);
                }
            }
        }
        let project = s
            .create_project_loaded(
                Path::new(&args.project_dir),
                Path::new(&args.binary),
                args.engine,
                loader,
                OpenOptions::from_context(ctx),
            )
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
            "Opens a project made earlier, with all its renames and comments. If the result \
             reports `epoch_stale`, run `rebuild`. Replaces the open project; a person is asked \
             to approve it when an agent calls it.\n\
             Example: project_open {\"project_dir\": \"./a.kraken\"}",
        )
        .details(
            "Opens the project database and the engine cache. `epoch_stale` means the engine \
             build, options or binary differ from the recorded epoch; `rebuild` recreates the \
             engine project from the log. While it runs it is the job `open-N`, with the same \
             progress and cancel as `project_create`; a reopen reads the engine's saved \
             results and takes seconds.",
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
        let project = s
            .open_project_opts(Path::new(&args.project_dir), OpenOptions::from_context(ctx))
            .await?;
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
        .doc(
            "The first call of a session: the binary (`program`: format, architecture), its \
             hash, the engine's `capabilities`, whether `analyze` has run or is running \
             (`analysis`) and how many proposals wait. The binary's path is untrusted data.\n\
             Example: project_info {}",
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

/// What `project_close` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectCloseOut {
    /// True when a project was open and is now closed.
    pub closed: bool,
    /// The directory of the project that was closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
}

/// Closes the open project.
pub struct ProjectClose;

#[async_trait]
impl Command for ProjectClose {
    type Args = NoArgs;
    type Output = ProjectCloseOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "project_close",
            "Close the current project and stop its engine",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Cancels the project's running jobs, saves the engine's state and releases it, so \
             the engine stops and its memory is freed. Renames, comments and other changes are \
             already saved; nothing is lost. Closing when nothing is open does nothing.\n\
             Example: project_close {}",
        )
        .details(
            "Through krakend the daemon's session for the project is closed and its sidecars \
             stop; the next command for that project opens it again. An agent may close only a \
             project it was allowed to work on.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<ProjectCloseOut, ProtoError> {
        let dir = s.close_project().await;
        Ok(ProjectCloseOut {
            closed: dir.is_some(),
            project_dir: dir.map(|d| d.to_string_lossy().into_owned()),
        })
    }
}

#[cfg(test)]
mod base_tests {
    use super::*;

    #[test]
    fn base_is_for_raw_images_only() {
        let args = |v: serde_json::Value| serde_json::from_value::<ProjectCreateArgs>(v).unwrap();
        let e = args(serde_json::json!({"binary": "/a", "project_dir": "/p", "base": "0x1000"}))
            .loader_spec()
            .unwrap_err();
        assert!(e.message.contains("raw"), "{e:?}");
        let ok = args(serde_json::json!({
            "binary": "/a", "project_dir": "/p", "base": "0x1000", "loader": "raw", "language": "arm"
        }))
        .loader_spec()
        .unwrap();
        assert_eq!(ok.base.map(|b| b.0), Some(0x1000));
    }
}
