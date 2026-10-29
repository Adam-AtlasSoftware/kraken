//! The integrations catalogue and `emulator_run`.
//!
//! Nothing here is bundled. A catalogue entry names an emulator (or another external tool) and,
//! where upstream publishes a Linux build, a pinned release with its SHA-256; `integration_install`
//! downloads that release on the user's machine, `integration_use_path` points at a copy the user
//! already has, and `integration_remove` deletes what KRAKEN installed. `emulator_run` hands the
//! project's binary (original or patched) or any other file to an emulator through the argv
//! template of its manifest. The work is done by an [`IntegrationsBackend`] that `kraken-host`
//! provides; this module is the command surface and the pure parts (argument templates, the
//! launch).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError, Untrusted, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::commands::NoArgs;
use crate::context::CallContext;
use crate::patchfile::{FilePatch, PatchError, patch_file_bytes_at};
use crate::session::{Session, blocking};

/// Where a usable copy of the tool comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationSource {
    /// Downloaded by KRAKEN from the upstream's release.
    Downloaded,
    /// Found on this computer (on `PATH` or in a well-known place).
    System,
    /// A path the person chose.
    UserPath,
}

/// How far along an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    /// Usable now.
    Ready,
    /// Not on this computer; `Install` downloads upstream's release.
    NotInstalled,
    /// Not on this computer and upstream publishes no build KRAKEN can download for this
    /// platform: install it yourself, then `integration_use_path`.
    ManualOnly,
    /// A download is running; see `progress`.
    Installing,
}

/// Progress of a running install.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InstallProgress {
    /// `downloading`, `verifying` or `extracting`.
    pub phase: String,
    /// Bytes received so far.
    pub done: u64,
    /// Bytes expected, 0 when unknown.
    pub total: u64,
}

/// One catalogue entry, as shown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationView {
    /// Stable id (`xemu`, `pcsx2`, or the id of a user manifest).
    pub id: String,
    /// Display name.
    pub name: String,
    /// `emulator`, `compat_layer` or `tool`.
    pub kind: String,
    /// One line on what it is.
    pub summary: String,
    /// Upstream web page.
    pub homepage: String,
    /// Systems or program kinds it runs (`Original Xbox`, `Windows programs`, ...).
    pub platforms: Vec<String>,
    /// File extensions it opens, lower case without the dot.
    pub formats: Vec<String>,
    /// Current state.
    pub status: IntegrationStatus,
    /// Where the usable copy comes from, when there is one.
    pub source: Option<IntegrationSource>,
    /// Version of the usable copy (installed release, or what the copy reported).
    pub version: Option<String>,
    /// The release `Install` would download.
    pub pinned_version: Option<String>,
    /// The program that runs.
    pub path: Option<String>,
    /// Bytes `Install` downloads.
    pub download_bytes: u64,
    /// Bytes KRAKEN's copy uses on disk.
    pub disk_bytes: u64,
    /// SPDX identifier of the licence (`GPL-2.0-or-later`, `Proprietary`, `Non-commercial`, ...).
    pub license: String,
    /// What to read before installing: licence terms, anything embedded in the download.
    pub notice: String,
    /// True for a download that embeds key material (never installed on an agent's say-so).
    pub contains_key_material: bool,
    /// True when a manifest from the user's config directory defined it ("user-supplied, not
    /// reviewed").
    pub user_supplied: bool,
    /// True when the emulator offers a GDB stub for `emulator_run --debug`.
    pub debuggable: bool,
    /// What the `Run` action executes: the argv template, with `{exe}` the program.
    pub argv: Vec<String>,
    /// Running install, when there is one.
    pub progress: Option<InstallProgress>,
}

/// What to run for an emulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Entry id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// The emulator's program.
    pub exe: PathBuf,
    /// Argument template; `{exe}`, `{binary}`, `{dir}` and `{port}` are replaced.
    pub argv: Vec<String>,
    /// Template used instead of `argv` for a debug launch.
    pub gdb_argv: Option<Vec<String>>,
    /// Port of the GDB stub.
    pub gdb_port: Option<u16>,
    /// A windowed program that keeps running (true) or one that runs and exits (false).
    pub gui: bool,
    /// Extra environment.
    pub env: Vec<(String, String)>,
}

/// Result of `integration_remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationRemoveOut {
    /// Entry id.
    pub id: String,
    /// Bytes freed.
    pub freed_bytes: u64,
    /// What was removed or forgotten.
    pub note: String,
}

/// Works the catalogue; provided by `kraken-host`, attached by the daemon, the CLI and the GUI.
#[async_trait]
pub trait IntegrationsBackend: Send + Sync + std::fmt::Debug {
    /// Every entry, with detection and progress.
    fn list(&self) -> Result<Vec<IntegrationView>, ProtoError>;
    /// Downloads and installs the pinned release of `id`. `accept_licence` says the person read
    /// the notice.
    async fn install(&self, id: &str, accept_licence: bool) -> Result<IntegrationView, ProtoError>;
    /// Uses the program at `path` for `id`.
    fn use_path(&self, id: &str, path: &Path) -> Result<IntegrationView, ProtoError>;
    /// Deletes KRAKEN's copy of `id` and forgets a chosen path.
    fn remove(&self, id: &str) -> Result<IntegrationRemoveOut, ProtoError>;
    /// What to run for `id`; fails when it is not usable.
    fn launch_spec(&self, id: &str) -> Result<LaunchSpec, ProtoError>;
}

impl Session {
    /// The attached integrations backend.
    pub fn integrations(&self) -> Result<&Arc<dyn IntegrationsBackend>, ProtoError> {
        self.integrations_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "the integrations catalogue is not attached to this session; use the kraken CLI, krakend or the GUI",
            )
        })
    }
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Result of `integrations_list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationsListOut {
    /// Entries in catalogue order.
    pub integrations: Vec<IntegrationView>,
}

/// Lists the catalogue.
pub struct IntegrationsList;

#[async_trait]
impl Command for IntegrationsList {
    type Args = NoArgs;
    type Output = IntegrationsListOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "integrations_list",
            "List the emulators and tools KRAKEN can use, with what is installed",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Every catalogue entry (xemu, xenia-canary, shadPS4, RPCS3, PCSX2, PPSSPP, Dolphin, \
             DuckStation, mGBA, melonDS, Ryubing, Cemu, QEMU, Wine and the manifests in your \
             config directory) with its `status` (ready, not_installed, manual_only, installing), \
             where the usable copy comes from, its version, the licence and the notice to read \
             before installing. Nothing is bundled with KRAKEN; `integration_install` downloads \
             upstream's own release.\n\
             Example: integrations_list {}",
        )
        .details(
            "Detection looks at a path the person chose, then KRAKEN's own installs, then \
             `PATH` and well-known places (`~/Applications`, `~/.local/bin`, Flatpak exports). \
             Custom emulators are TOML manifests in `<config dir>/emulators.d/`; see \
             `docs/integrations.md`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<IntegrationsListOut, ProtoError> {
        let backend = s.integrations()?.clone();
        let integrations = blocking(move || backend.list()).await?;
        Ok(IntegrationsListOut { integrations })
    }
}

/// Arguments of `integration_install`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationInstallArgs {
    /// Catalogue id (see `integrations_list`).
    pub id: String,
    /// Say you read the licence and notice of the entry (default false: the install is refused
    /// until it is true).
    #[serde(default)]
    pub accept_licence: bool,
}

/// Downloads and installs a catalogue entry.
pub struct IntegrationInstall;

#[async_trait]
impl Command for IntegrationInstall {
    type Args = IntegrationInstallArgs;
    type Output = IntegrationView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "integration_install",
            "Download upstream's release of an emulator or tool and install it under KRAKEN's data directory",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Fetches the pinned upstream release of the catalogue entry `id` over HTTPS, checks \
             its SHA-256 and unpacks it under KRAKEN's data directory. `accept_licence` must be \
             true: read `notice` and `license` of `integrations_list` first. Agents and MCP \
             callers are asked first, and an entry that embeds key material is never installed \
             on an agent's say-so. KRAKEN never ships the program, keys, firmware or games.\n\
             Example: integration_install {\"id\": \"mgba\", \"accept_licence\": true}",
        )
        .details(
            "Only catalogue ids are accepted, never a URL. The download resumes from a partial \
             file, the hash is checked before anything is unpacked, and an archive that holds an \
             unsafe path is refused. Progress is in the `progress` field of `integrations_list`. \
             Files go to `<data dir>/integrations/<id>/<version>/`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: IntegrationInstallArgs,
    ) -> Result<IntegrationView, ProtoError> {
        let backend = s.integrations()?.clone();
        vet_install(&backend, ctx, "integration_install", &args).await?;
        backend.install(&args.id, args.accept_licence).await
    }
}

/// The checks every install passes before it downloads: the entry exists, key material is not
/// installed on an agent's say-so, the licence is accepted and the approval is given.
pub(crate) async fn vet_install(
    backend: &Arc<dyn IntegrationsBackend>,
    ctx: &CallContext,
    command: &str,
    args: &IntegrationInstallArgs,
) -> Result<(), ProtoError> {
    let id = args.id.clone();
    let list = {
        let b = backend.clone();
        blocking(move || b.list()).await?
    };
    let entry = list
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no entry `{id}`")))?;
    if ctx.needs_user_approval() && entry.contains_key_material {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "`{id}` embeds key material: a person has to install it from Tools > Integrations or `kraken integration-install`"
            ),
        ));
    }
    if !args.accept_licence {
        return Err(invalid(format!(
            "read the licence ({}) and the notice of `{id}` and pass accept_licence: true. {}",
            entry.license, entry.notice
        )));
    }
    ctx.require_approval(
        command,
        format!(
            "Download {} {} ({:.1} MiB) from its upstream release and install it",
            entry.name,
            entry.pinned_version.clone().unwrap_or_default(),
            entry.download_bytes as f64 / (1 << 20) as f64
        ),
        serde_json::json!({ "id": id, "download_bytes": entry.download_bytes }),
    )
    .await
}

/// Arguments of `integration_use_path`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationUsePathArgs {
    /// Catalogue id.
    pub id: String,
    /// Absolute path of the program to use.
    pub path: String,
}

/// Uses a copy the person already has.
pub struct IntegrationUsePath;

#[async_trait]
impl Command for IntegrationUsePath {
    type Args = IntegrationUsePathArgs;
    type Output = IntegrationView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "integration_use_path",
            "Use an emulator or tool you already have, at a path you choose",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Points the entry `id` at an existing program (an AppImage, a binary, a wrapper \
             script). It must be an executable file. Nothing is downloaded or copied. Agents and \
             MCP callers are asked first, because the program is what `emulator_run` runs.\n\
             Example: integration_use_path {\"id\": \"pcsx2\", \"path\": \"/opt/pcsx2/pcsx2-qt\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: IntegrationUsePathArgs,
    ) -> Result<IntegrationView, ProtoError> {
        let backend = s.integrations()?.clone();
        let path = PathBuf::from(&args.path);
        if !path.is_absolute() {
            return Err(invalid("path must be absolute"));
        }
        ctx.require_approval(
            "integration_use_path",
            format!(
                "Use {} as `{}`; emulator_run will execute it",
                args.path, args.id
            ),
            serde_json::json!({ "id": args.id, "path": args.path }),
        )
        .await?;
        let id = args.id;
        blocking(move || backend.use_path(&id, &path)).await
    }
}

/// Arguments of `integration_remove`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRemoveArgs {
    /// Catalogue id.
    pub id: String,
}

/// Removes KRAKEN's copy of an entry.
pub struct IntegrationRemove;

#[async_trait]
impl Command for IntegrationRemove {
    type Args = IntegrationRemoveArgs;
    type Output = IntegrationRemoveOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "integration_remove",
            "Delete KRAKEN's installed copy of an emulator or tool and forget a chosen path",
            CommandKind::Query,
            Permission::Dangerous,
        )
        .global()
        .doc(
            "Deletes the files KRAKEN installed for `id` (only what its receipt lists) and drops \
             a path chosen with `integration_use_path`. A copy on your system is never touched. \
             Asks first.\n\
             Example: integration_remove {\"id\": \"mgba\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: IntegrationRemoveArgs,
    ) -> Result<IntegrationRemoveOut, ProtoError> {
        let backend = s.integrations()?.clone();
        blocking(move || backend.remove(&args.id)).await
    }
}

/// Which file `emulator_run` hands to the emulator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunTarget {
    /// The executable the project was made from.
    #[default]
    Original,
    /// A copy with the project's byte patches applied.
    Patched,
    /// Any file you name with `file` (a KRAKEN export, a rebuilt image, a rewrite's build).
    File,
}

/// Arguments of `emulator_run`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulatorRunArgs {
    /// Catalogue id of the emulator (see `integrations_list`).
    pub id: String,
    /// What to run: `original` (default), `patched` or `file`.
    #[serde(default)]
    pub target: RunTarget,
    /// The file for `target: file`; absolute.
    #[serde(default)]
    pub file: Option<String>,
    /// Start the emulator's GDB stub and wait for a debugger (only for emulators that have one).
    #[serde(default)]
    pub debug: bool,
    /// Extra arguments appended to the emulator's command line (at most 32).
    #[serde(default)]
    pub args: Vec<String>,
    /// For a program that runs and exits: seconds to wait for it (default 20, at most 120).
    #[serde(default)]
    pub wait_seconds: Option<u64>,
}

/// Result of `emulator_run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmulatorRunOut {
    /// Emulator name.
    pub emulator: String,
    /// The command line that ran.
    pub command: Vec<String>,
    /// The file handed to the emulator.
    pub file: String,
    /// Process id; a windowed emulator keeps running after the command returns.
    pub pid: u32,
    /// True when the process had ended when the command returned.
    pub exited: bool,
    /// Exit code of a program that ended.
    pub exit_code: Option<i32>,
    /// True when the wait ran out and the process was stopped.
    pub timed_out: bool,
    /// Where the output is logged.
    pub log: String,
    /// The first 4000 characters of output (program data, so untrusted).
    pub output: Untrusted<String>,
    /// `127.0.0.1:<port>` of the GDB stub when `debug` was set.
    pub gdb: Option<String>,
    /// Facts about the run.
    pub notes: Vec<String>,
}

const MAX_EXTRA_ARGS: usize = 32;
const OUTPUT_CHARS: usize = 4000;

/// Runs an emulator on a file.
pub struct EmulatorRun;

#[async_trait]
impl Command for EmulatorRun {
    type Args = EmulatorRunArgs;
    type Output = EmulatorRunOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "emulator_run",
            "Run the project's binary (original or patched), or any file, in an installed emulator",
            CommandKind::Query,
            Permission::Dangerous,
        )
        .doc(
            "Hands the project's original executable, a copy with its byte patches, or any file \
             you name to the emulator `id` through its manifest's argv template, and starts it. \
             Unlike `emulate_run` this is the real emulator on this computer, not KRAKEN's \
             confined interpreter: an emulator or compatibility layer such as Wine or QEMU user \
             mode runs the program with this computer's resources, so it always asks first. A \
             windowed emulator keeps running (the result has its pid and log); a command-line one \
             is waited for. `debug: true` adds the emulator's GDB stub flags and returns its \
             address.\n\
             Example: emulator_run {\"id\": \"xemu\", \"target\": \"patched\"}",
        )
        .details(
            "The patched copy and the log are in a private directory under the system temporary \
             directory, named in `log`; KRAKEN does not delete it, so the emulator can keep \
             using it. The emulator is not confined: its own save data and settings live where it \
             keeps them. Register or list emulators with `integrations_list`; add your own as a \
             manifest in `<config dir>/emulators.d/`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: EmulatorRunArgs,
    ) -> Result<EmulatorRunOut, ProtoError> {
        if args.args.len() > MAX_EXTRA_ARGS {
            return Err(invalid(format!("at most {MAX_EXTRA_ARGS} extra arguments")));
        }
        if args.args.iter().any(|a| a.contains('\0') || a.len() > 4096) {
            return Err(invalid("an argument is too long or holds a NUL byte"));
        }
        let wait = args.wait_seconds.unwrap_or(20);
        if wait == 0 || wait > 120 {
            return Err(invalid("wait_seconds must be between 1 and 120"));
        }
        let backend = s.integrations()?.clone();
        let spec = {
            let (b, id) = (backend.clone(), args.id.clone());
            blocking(move || b.launch_spec(&id)).await?
        };
        if args.debug && spec.gdb_argv.is_none() {
            return Err(invalid(format!(
                "{} has no GDB stub flags in its manifest",
                spec.name
            )));
        }
        let (file, patches, base) = match args.target {
            RunTarget::File => {
                let f = args
                    .file
                    .clone()
                    .ok_or_else(|| invalid("target `file` needs `file`"))?;
                (PathBuf::from(f), Vec::new(), 0)
            }
            RunTarget::Original | RunTarget::Patched => {
                let project = s.project()?;
                let binary = PathBuf::from(project.meta().binary_path);
                let patches = if args.target == RunTarget::Patched {
                    project.with_store(|st| st.active_patches(None)).await?
                } else {
                    Vec::new()
                };
                (binary, patches, project.program().base.0)
            }
        };
        if !file.is_absolute() {
            return Err(invalid("file must be an absolute path"));
        }
        blocking(move || {
            launch(
                &spec,
                &file,
                &patches,
                base,
                &args,
                Duration::from_secs(wait),
            )
        })
        .await
    }
}

/// Replaces the placeholders of one template argument.
pub fn expand_arg(template: &str, exe: &Path, binary: &Path, dir: &Path, port: u16) -> String {
    template
        .replace("{exe}", &exe.to_string_lossy())
        .replace("{binary}", &binary.to_string_lossy())
        .replace("{dir}", &dir.to_string_lossy())
        .replace("{port}", &port.to_string())
}

/// The command line for `spec` on `file`.
pub fn command_line(
    spec: &LaunchSpec,
    file: &Path,
    dir: &Path,
    debug: bool,
    extra: &[String],
) -> Vec<String> {
    let template = if debug {
        spec.gdb_argv.as_ref().unwrap_or(&spec.argv)
    } else {
        &spec.argv
    };
    let port = spec.gdb_port.unwrap_or(1234);
    let mut out: Vec<String> = template
        .iter()
        .map(|a| expand_arg(a, &spec.exe, file, dir, port))
        .collect();
    out.extend(extra.iter().cloned());
    out
}

fn launch(
    spec: &LaunchSpec,
    file: &Path,
    patches: &[kraken_model::Patch],
    engine_base: u64,
    args: &EmulatorRunArgs,
    wait: Duration,
) -> Result<EmulatorRunOut, ProtoError> {
    if !file.is_file() {
        return Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("{} is not a file", file.display()),
        ));
    }
    let dir = tempfile::Builder::new()
        .prefix(&format!("kraken-emulator-{}-", spec.id))
        .tempdir()
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("run directory: {e}")))?
        .keep();
    let mut notes = Vec::new();
    let mut target = file.to_path_buf();
    if args.target == RunTarget::Patched {
        if patches.is_empty() {
            notes.push("the project has no byte patches; ran the original".into());
        } else {
            target = patched_copy(file, patches, &dir, engine_base)?;
            notes.push(format!(
                "ran a copy with {} byte patch{} applied",
                patches.len(),
                if patches.len() == 1 { "" } else { "es" }
            ));
        }
    }
    let argv = command_line(spec, &target, &dir, args.debug, &args.args);
    let Some((program, rest)) = argv.split_first() else {
        return Err(invalid(format!("{} has an empty command line", spec.name)));
    };
    let log = dir.join("emulator.log");
    let log_file = std::fs::File::create(&log)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("log file: {e}")))?;
    let err_file = log_file
        .try_clone()
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("log file: {e}")))?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(rest)
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .stdout(log_file)
        .stderr(err_file);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|e| {
        ProtoError::new(
            ErrorCode::Unsupported,
            format!("cannot start {}: {e}", program),
        )
    })?;
    let pid = child.id();
    let started = Instant::now();
    // A windowed emulator is given a moment to fail (missing library, bad flag), then left running.
    // A debug launch waits for the debugger, so it is left running like a windowed one.
    let keep = spec.gui || args.debug;
    let limit = if keep {
        Duration::from_millis(1500)
    } else {
        wait
    };
    let (mut exited, mut exit_code, mut timed_out) = (false, None, false);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exited = true;
                exit_code = status.code();
                break;
            }
            Ok(None) if started.elapsed() >= limit => {
                if !keep {
                    #[cfg(unix)]
                    if let Ok(pid) = i32::try_from(pid) {
                        // SAFETY: plain kill(2) on the process group the child leads.
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    exited = true;
                }
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                return Err(ProtoError::new(
                    ErrorCode::Internal,
                    format!("waiting for {program}: {e}"),
                ));
            }
        }
    }
    if keep && !exited {
        // Reaped by a thread so the finished emulator does not stay a zombie of the daemon.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        notes.push(if spec.gui {
            "still running; close its window to end it".into()
        } else {
            format!("still running, waiting for a debugger; stop it with `kill -- -{pid}`")
        });
    }
    let mut raw = Vec::new();
    if let Ok(f) = std::fs::File::open(&log) {
        use std::io::Read;
        let _ = f.take(64 * 1024).read_to_end(&mut raw);
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let cut = text.chars().count() > OUTPUT_CHARS;
    let output: String = sanitize(&text.chars().take(OUTPUT_CHARS).collect::<String>());
    if cut {
        notes.push(format!(
            "output cut to {OUTPUT_CHARS} characters; see the log"
        ));
    }
    let gdb = args.debug.then(|| {
        let socket = dir.join("gdb.sock");
        if argv.iter().any(|a| a.contains(&*socket.to_string_lossy())) {
            socket.display().to_string()
        } else {
            notes.push(
                "the debugger stub is a TCP port; the emulator may listen on all interfaces, not only 127.0.0.1"
                    .into(),
            );
            format!("127.0.0.1:{}", spec.gdb_port.unwrap_or(1234))
        }
    });
    Ok(EmulatorRunOut {
        emulator: spec.name.clone(),
        command: argv,
        file: target.display().to_string(),
        pid,
        exited,
        exit_code,
        timed_out,
        log: log.display().to_string(),
        output: Untrusted(output),
        gdb,
        notes,
    })
}

fn patched_copy(
    binary: &Path,
    patches: &[kraken_model::Patch],
    dir: &Path,
    engine_base: u64,
) -> Result<PathBuf, ProtoError> {
    let image = std::fs::read(binary).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", binary.display()),
        )
    })?;
    let file_patches: Vec<FilePatch> = patches
        .iter()
        .map(|p| FilePatch {
            address: p.address,
            original: p.original.clone(),
            replacement: p.replacement.clone(),
        })
        .collect();
    let (patched, _) =
        patch_file_bytes_at(&image, &file_patches, Some(engine_base)).map_err(|e| match e {
            PatchError::NotAnObject(_) => ProtoError::new(ErrorCode::Unsupported, e.to_string()),
            PatchError::NoMapping(_) => invalid(e.to_string()),
        })?;
    let name = binary
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "program".into());
    let out = dir.join(name);
    std::fs::write(&out, &patched).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("cannot write the patched copy: {e}"),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> LaunchSpec {
        LaunchSpec {
            id: "t".into(),
            name: "T".into(),
            exe: "/opt/t/t".into(),
            argv: vec!["{exe}".into(), "-f".into(), "{binary}".into()],
            gdb_argv: Some(vec![
                "{exe}".into(),
                "-gdb".into(),
                "tcp::{port}".into(),
                "{binary}".into(),
            ]),
            gdb_port: Some(2345),
            gui: false,
            env: Vec::new(),
        }
    }

    #[test]
    fn the_template_fills_exe_file_and_port() {
        let line = command_line(&spec(), Path::new("/x/a.xex"), Path::new("/d"), false, &[]);
        assert_eq!(line, ["/opt/t/t", "-f", "/x/a.xex"]);
        let dbg = command_line(
            &spec(),
            Path::new("/x/a.xex"),
            Path::new("/d"),
            true,
            &["--extra".into()],
        );
        assert_eq!(
            dbg,
            ["/opt/t/t", "-gdb", "tcp::2345", "/x/a.xex", "--extra"]
        );
    }

    #[cfg(unix)]
    fn pid_alive(pid: u32) -> bool {
        // SAFETY: signal 0 only probes the process.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[cfg(unix)]
    #[test]
    fn a_debug_launch_stays_alive_and_a_timeout_kills_the_group() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("prog");
        std::fs::write(&file, b"x").unwrap();
        let sock = |s: &mut LaunchSpec| {
            s.exe = "/bin/sh".into();
            s.argv = vec!["{exe}".into(), "-c".into(), "sleep 30 & wait".into()];
            s.gdb_argv = Some(vec![
                "{exe}".into(),
                "-c".into(),
                "sleep 30 & wait # {dir}/gdb.sock".into(),
            ]);
        };
        let mut s = spec();
        sock(&mut s);
        let args = EmulatorRunArgs {
            id: "t".into(),
            debug: true,
            ..Default::default()
        };
        let out = launch(&s, &file, &[], 0, &args, Duration::from_millis(100)).unwrap();
        assert!(!out.exited && !out.timed_out, "{out:?}");
        assert!(out.gdb.as_deref().unwrap().ends_with("gdb.sock"));
        assert!(pid_alive(out.pid));
        // SAFETY: kills the group of the process this test started.
        unsafe { libc::kill(-(out.pid as i32), libc::SIGKILL) };

        let args = EmulatorRunArgs {
            id: "t".into(),
            ..Default::default()
        };
        let out = launch(&s, &file, &[], 0, &args, Duration::from_millis(300)).unwrap();
        assert!(out.timed_out, "{out:?}");
        std::thread::sleep(Duration::from_millis(200));
        // The shell's child (`sleep`) was in the group and is gone with it.
        assert!(!pid_alive(out.pid));
        let g = std::process::Command::new("pgrep")
            .args(["-g", &out.pid.to_string()])
            .output();
        if let Ok(g) = g {
            assert!(g.stdout.is_empty(), "group survivors");
        }
    }
}
