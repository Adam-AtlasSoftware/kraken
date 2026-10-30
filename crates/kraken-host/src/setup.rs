//! The machine-global setup behind `setup_status` and the `setup_*` jobs: what is installed
//! ([`HostSetup::status`]) and the installs themselves, which `kraken setup` and the registry
//! commands both run. Dropping the future of [`SetupBackend::run`] cancels an install; a partial
//! download stays for the next run.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    IntegrationStatus, IntegrationView, IntegrationsBackend, SetupBackend, SetupItem, SetupState,
    SetupTask,
};
use kraken_registry::jobs::JobProgress;
use serde_json::{Value, json};

use crate::config::KrakenConfig;
use crate::dotnet_setup::{bundled_sidecar, pinned_dotnet, setup_dotnet};
use crate::integrations::Integrations;
use crate::provision::{
    Fetcher, HttpsFetcher, Layout, Progress, ProvisionError, SetupOptions, pinned, setup,
};
use crate::{llama_setup, native, strata_setup};

/// Maps a provisioning error to the wire error.
pub fn to_proto(e: ProvisionError) -> ProtoError {
    let code = match e {
        ProvisionError::UnsupportedPlatform(_) => ErrorCode::Unsupported,
        ProvisionError::NotHttps(_) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    ProtoError::new(code, e.to_string())
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// The job progress of a provisioning step.
pub fn job_progress(p: &Progress, started: std::time::Instant) -> JobProgress {
    let (phase, done, total, message) = match p {
        Progress::Downloading {
            name, done, total, ..
        } => (
            "download",
            *done,
            total.unwrap_or(0),
            match total {
                Some(t) => format!("downloading {name}: {:.1} / {:.1} MiB", mib(*done), mib(*t)),
                None => format!("downloading {name}: {:.1} MiB", mib(*done)),
            },
        ),
        Progress::Verifying { name } => ("verify", 0, 0, format!("verifying {name} (sha256)")),
        Progress::Extracting { name } => ("extract", 0, 0, format!("extracting {name}")),
        Progress::BuildingExtension => (
            "build",
            0,
            0,
            "building the Ghidra extension with the downloaded JDK".to_string(),
        ),
        Progress::InstallingBundledExtension => (
            "install",
            0,
            0,
            "installing the bundled Ghidra extension".to_string(),
        ),
        Progress::Skipped { name } => ("skip", 0, 0, format!("{name} is already installed")),
    };
    JobProgress {
        phase: phase.into(),
        done,
        total,
        message,
        elapsed_ms: Some(started.elapsed().as_millis() as u64),
        ..Default::default()
    }
}

/// [`SetupBackend`] over this machine. Tests give it a layout and a fetcher of their own.
#[derive(Clone)]
pub struct HostSetup {
    layout: Option<Layout>,
    fetcher: Option<Arc<dyn Fetcher>>,
    config: Option<KrakenConfig>,
}

impl std::fmt::Debug for HostSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSetup")
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl HostSetup {
    /// The user's runtime directory, the network and the configuration file.
    pub fn system() -> Self {
        HostSetup {
            layout: Layout::from_env(),
            fetcher: None,
            config: None,
        }
    }

    /// A setup in `layout` that downloads through `fetcher` and reads `config`.
    pub fn with(layout: Layout, fetcher: Arc<dyn Fetcher>, config: KrakenConfig) -> Self {
        HostSetup {
            layout: Some(layout),
            fetcher: Some(fetcher),
            config: Some(config),
        }
    }

    fn config(&self) -> KrakenConfig {
        self.config
            .clone()
            .unwrap_or_else(|| KrakenConfig::load().unwrap_or_default())
    }

    fn layout(&self) -> Result<&Layout, ProtoError> {
        self.layout.as_ref().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Internal,
                "cannot place the runtime: neither XDG_DATA_HOME nor HOME is set",
            )
        })
    }

    fn fetcher(&self) -> Result<Arc<dyn Fetcher>, ProtoError> {
        match &self.fetcher {
            Some(f) => Ok(f.clone()),
            None => Ok(Arc::new(HttpsFetcher::new().map_err(to_proto)?)),
        }
    }

    async fn run_ghidra(
        &self,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        let specs = pinned().map_err(to_proto)?;
        let layout = self.layout()?;
        let fetcher = self.fetcher()?;
        let opts = SetupOptions::with_bundled(force);
        let started = std::time::Instant::now();
        let p = setup(layout, fetcher.as_ref(), &specs, &opts, &mut |p| {
            progress(job_progress(&p, started))
        })
        .await
        .map_err(to_proto)?;
        let show = |o: &Option<PathBuf>| o.as_ref().map(|p| p.display().to_string());
        Ok(json!({
            "runtime_dir": layout.root(),
            "ghidra_home": show(&p.ghidra_home),
            "java_home": show(&p.java_home),
            "ext_jar": show(&p.ext_jar),
        }))
    }

    async fn run_dotnet(
        &self,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        let spec = pinned_dotnet().map_err(to_proto)?;
        let layout = self.layout()?;
        let fetcher = self.fetcher()?;
        let bundled = bundled_sidecar();
        let started = std::time::Instant::now();
        let p = setup_dotnet(
            layout,
            fetcher.as_ref(),
            &spec,
            bundled.as_deref(),
            force,
            &mut |p| progress(job_progress(&p, started)),
        )
        .await
        .map_err(to_proto)?;
        let show = |o: &Option<PathBuf>| o.as_ref().map(|p| p.display().to_string());
        Ok(json!({
            "runtime_dir": layout.root(),
            "dotnet_root": show(&p.dotnet_root),
            "dotnet_ext": show(&p.ext_dll),
        }))
    }

    /// The catalogue, with real downloads and the real `PATH`; tests give the setup a layout and a
    /// fetcher, and the catalogue then lives in the layout.
    fn integrations(&self) -> Result<Integrations, ProtoError> {
        match (&self.layout, &self.fetcher) {
            (Some(l), Some(f)) => Ok(Integrations::new(
                l.root().join("integrations"),
                None,
                f.clone(),
            )),
            _ => Integrations::system(),
        }
    }

    async fn run_rust(
        &self,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        let integ = self.integrations()?;
        let before = find_view(&integ, "rust-toolchain")?;
        if before.status == IntegrationStatus::Ready && !force {
            return Ok(json!({
                "cargo": before.path,
                "version": before.version,
                "installed": false,
                "note": "a Rust toolchain is already available (cargo on PATH or KRAKEN's own); nothing to install",
            }));
        }
        let view = install_with_progress(&integ, "rust-toolchain", progress).await?;
        Ok(json!({
            "cargo": view.path,
            "version": view.version,
            "installed": true,
            "note": "KRAKEN's own toolchain is installed in its data directory; rewrites use it when there is no rustc on PATH. A C linker (cc) is still needed for host-target builds.",
        }))
    }

    async fn run_sysroots(
        &self,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        let integ = self.integrations()?;
        let mut done = Vec::new();
        for id in SYSROOT_IDS {
            let before = find_view(&integ, id)?;
            if before.status == IntegrationStatus::Ready && !force {
                done.push(format!(
                    "{id}: already installed at {}",
                    before.path.unwrap_or_default()
                ));
                continue;
            }
            let view = install_with_progress(&integ, id, progress).await?;
            done.push(format!("{id}: {}", view.path.unwrap_or_default()));
        }
        Ok(json!({ "installed": done }))
    }

    async fn run_native(
        &self,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        use native::{SetupPlan, SetupStep};
        let configured = self.config().native_specs;
        let probe = native::NativeProbe::detect(configured.as_deref());
        let plan = native::plan_setup(
            &probe,
            native::sources_dir().is_some(),
            native::find_checkout(),
            force,
        );
        match plan {
            SetupPlan::Ready => Ok(json!({
                "ready": true,
                "library": true,
                "specs": probe.specs.map(|p| p.display().to_string()),
            })),
            SetupPlan::Instructions(cmds) => Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "this kraken was not built from a source checkout reachable from here, and \
                     the native engine's decompiler is linked at build time. In a checkout of \
                     the repository run:\n  {}",
                    cmds.join("\n  ")
                ),
            )),
            SetupPlan::InCheckout { root, steps } => {
                let started = std::time::Instant::now();
                for step in steps {
                    let SetupStep::Xtask(task) = step else {
                        continue;
                    };
                    progress(JobProgress {
                        phase: "xtask".into(),
                        message: format!("running `cargo xtask {task}`"),
                        elapsed_ms: Some(started.elapsed().as_millis() as u64),
                        ..Default::default()
                    });
                    run_xtask(&root, task).await?;
                }
                let after = native::NativeProbe::detect(configured.as_deref());
                Ok(json!({
                    "ready": after.problem().is_none(),
                    "library": after.library,
                    "specs": after.specs.as_ref().map(|p| p.display().to_string()),
                    "rebuild": (!after.library).then_some(native::SETUP_COMMANDS[2]),
                }))
            }
        }
    }
}

/// The sysroot entries of the integrations catalogue, one per architecture with a Debian port.
pub const SYSROOT_IDS: [&str; 5] = [
    "sysroot-aarch64",
    "sysroot-armhf",
    "sysroot-riscv64",
    "sysroot-i386",
    "sysroot-x86-64",
];

fn find_view(integ: &Integrations, id: &str) -> Result<IntegrationView, ProtoError> {
    integ
        .list()?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no catalogue entry `{id}`")))
}

/// Installs the catalogue entry `id` (the setup command is the consent to its notice) and reports
/// the entry's own progress as job progress.
async fn install_with_progress(
    integ: &Integrations,
    id: &str,
    progress: &(dyn Fn(JobProgress) + Send + Sync),
) -> Result<IntegrationView, ProtoError> {
    let started = std::time::Instant::now();
    let mut last: Option<(String, u64)> = None;
    let install = integ.install(id, true);
    tokio::pin!(install);
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(300));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = &mut install => return r,
            _ = tick.tick() => {
                if let Ok(Some(p)) = find_view(integ, id).map(|v| v.progress)
                    && last.as_ref() != Some(&(p.phase.clone(), p.done))
                {
                    last = Some((p.phase.clone(), p.done));
                    progress(JobProgress {
                        message: format!("{id}: {}", p.phase),
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

/// Runs `cargo xtask <task>` in `root`; the child is killed when the future is dropped.
async fn run_xtask(root: &Path, task: &'static str) -> Result<(), ProtoError> {
    let status = tokio::process::Command::new("cargo")
        .args(["xtask", task])
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("cannot run `cargo xtask {task}`: {e}"),
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProtoError::new(
            ErrorCode::Internal,
            format!("`cargo xtask {task}` failed ({status})"),
        ))
    }
}

fn item(
    id: &str,
    name: &str,
    purpose: &str,
    state: SetupState,
    detail: impl Into<String>,
) -> SetupItem {
    SetupItem {
        id: id.into(),
        name: name.into(),
        purpose: purpose.into(),
        state,
        detail: detail.into(),
        fix: None,
        fix_command: None,
    }
}

trait Fixable {
    fn fixed(self, fix: &str, command: Option<&str>) -> Self;
}

impl Fixable for SetupItem {
    fn fixed(mut self, fix: &str, command: Option<&str>) -> Self {
        if self.state != SetupState::Ready {
            self.fix = Some(fix.into());
            self.fix_command = command.map(str::to_string);
        }
        self
    }
}

fn file_value(file: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix('=')?;
        Some(v.trim().trim_matches('"').to_string())
    })
}

fn tool_version(program: &str) -> Option<String> {
    let out = std::process::Command::new(program)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    })
}

fn ghidra_item(layout: Option<&Layout>, cfg: &KrakenConfig) -> SetupItem {
    let purpose = "Decompiler and analysis engine for native code (Ghidra with a JDK)";
    if let Err(e) = pinned() {
        return item(
            "ghidra",
            "Ghidra engine",
            purpose,
            SetupState::Unavailable,
            e.to_string(),
        );
    }
    let have = layout.map(Layout::provisioned).unwrap_or_default();
    let ghidra = cfg.ghidra_home.clone().or(have.ghidra_home);
    let java = cfg.java_home.clone().or(have.java_home);
    let jar = cfg.ext_jar.clone().or(have.ext_jar);
    let gv = ghidra.as_deref().and_then(|g| {
        file_value(
            &g.join("Ghidra/application.properties"),
            "application.version",
        )
    });
    let jv = java
        .as_deref()
        .and_then(|j| file_value(&j.join("release"), "JAVA_VERSION"));
    let parts = [ghidra.is_some(), java.is_some(), jar.is_some()];
    let state = match parts.iter().filter(|p| **p).count() {
        3 => SetupState::Ready,
        0 => SetupState::Missing,
        _ => SetupState::Partial,
    };
    let detail = if state == SetupState::Ready {
        format!(
            "Ghidra {} at {}; JDK {} at {}",
            gv.unwrap_or_else(|| "?".into()),
            ghidra.unwrap_or_default().display(),
            jv.unwrap_or_else(|| "?".into()),
            java.unwrap_or_default().display()
        )
    } else {
        let miss: Vec<&str> = ["Ghidra", "a JDK", "the KRAKEN extension"]
            .into_iter()
            .zip(parts)
            .filter(|(_, p)| !p)
            .map(|(n, _)| n)
            .collect();
        format!("missing: {}", miss.join(", "))
    };
    item("ghidra", "Ghidra engine", purpose, state, detail).fixed(
        "Download them (about 700 MiB) with setup_ghidra or `kraken setup`, or set KRAKEN_GHIDRA_HOME and KRAKEN_JAVA_HOME",
        Some("setup_ghidra"),
    )
}

fn native_item(cfg: &KrakenConfig) -> SetupItem {
    let purpose = "JVM-free engine (decompiler library and compiled Sleigh files)";
    let probe = native::NativeProbe::detect(cfg.native_specs.as_deref());
    let problem = probe.problem();
    let state = match (&problem, probe.library, probe.specs.is_some()) {
        (None, ..) => SetupState::Ready,
        (_, false, false) => SetupState::Missing,
        _ => SetupState::Partial,
    };
    let detail = match problem {
        None => format!(
            "Sleigh files at {}",
            probe
                .specs
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Some(p) => p,
    };
    item("native", "Native engine", purpose, state, detail).fixed(
        "Run setup_native or `kraken setup --native` from a source checkout; release builds ship the library",
        Some("setup_native"),
    )
}

fn dotnet_item(layout: Option<&Layout>, cfg: &KrakenConfig) -> SetupItem {
    let purpose = "Managed-code engine for .NET assemblies (runtime and ILSpy sidecar)";
    if let Err(e) = pinned_dotnet() {
        return item(
            "dotnet",
            ".NET engine",
            purpose,
            SetupState::Unavailable,
            e.to_string(),
        );
    }
    let have = layout.map(Layout::dotnet_provisioned).unwrap_or_default();
    let root = cfg.dotnet_root.clone().or(have.dotnet_root);
    let dll = cfg.dotnet_ext.clone().or(have.ext_dll);
    let (state, detail) = match (&root, &dll) {
        (Some(r), Some(_)) => (SetupState::Ready, format!("runtime at {}", r.display())),
        (None, None) => (SetupState::Missing, "no runtime and no sidecar".to_string()),
        (None, _) => (
            SetupState::Partial,
            "the sidecar is there, the runtime is not".into(),
        ),
        (_, None) => (
            SetupState::Partial,
            "the runtime is there, the sidecar is not".into(),
        ),
    };
    item("dotnet", ".NET engine", purpose, state, detail).fixed(
        "Download the runtime (about 35 MB) with setup_dotnet or `kraken setup --dotnet`",
        Some("setup_dotnet"),
    )
}

fn rust_item(integ: Option<&Integrations>) -> SetupItem {
    let purpose = "Compiles and tests the Rust rewrites";
    let managed = integ
        .and_then(|i| find_view(i, "rust-toolchain").ok())
        .filter(|v| {
            v.status == IntegrationStatus::Ready
                && v.source == Some(kraken_registry::commands::IntegrationSource::Downloaded)
        });
    let (state, detail) = match (tool_version("rustc"), tool_version("cargo")) {
        (Some(r), Some(c)) => (SetupState::Ready, format!("{r}; {c}")),
        _ if managed.is_some() => (
            SetupState::Ready,
            format!(
                "installed by KRAKEN at {}",
                managed.and_then(|v| v.path).unwrap_or_default()
            ),
        ),
        (None, None) => (
            SetupState::Missing,
            "rustc and cargo are not on PATH".into(),
        ),
        _ => (
            SetupState::Partial,
            "only one of rustc and cargo is on PATH".into(),
        ),
    };
    item("rust", "Rust toolchain", purpose, state, detail).fixed(
        "Install it with setup_rust or `kraken setup --rust` (KRAKEN's own copy, about 800 MB on disk, your ~/.cargo is not touched), or install the stable toolchain from https://rustup.rs",
        Some("setup_rust"),
    )
}

fn emulators_item(integ: Option<&Integrations>) -> SetupItem {
    let missing: Vec<String> = integ
        .map(|i| {
            SYSROOT_IDS
                .iter()
                .filter(|id| find_view(i, id).is_ok_and(|v| v.status != IntegrationStatus::Ready))
                .map(|id| id.trim_start_matches("sysroot-").to_string())
                .collect()
        })
        .unwrap_or_default();
    let dev = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cache/kraken-dev/emu-sysroots"))
        .filter(|p| p.is_dir());
    let mut detail = "built-in emulator (x86, ARM, AArch64, RISC-V)".to_string();
    if let Some(p) = &dev {
        detail.push_str(&format!("; developer sysroots at {}", p.display()));
    }
    let (state, fix) = if missing.is_empty() || dev.is_some() {
        detail.push_str("; libraries for dynamically linked programs are installed");
        (SetupState::Ready, None)
    } else {
        detail.push_str(&format!(
            "; libraries for dynamically linked programs missing: {} (statically linked programs run without them; there is no riscv32 sysroot)",
            missing.join(", ")
        ));
        (
            SetupState::Partial,
            Some(
                "Install them with setup_sysroots or `kraken setup --sysroots` (pinned Debian packages, about 20 MB)",
            ),
        )
    };
    let it = item(
        "emulators",
        "Emulators",
        "Runs functions and programs for rewrites and debugging",
        state,
        detail,
    );
    match fix {
        Some(f) => it.fixed(f, Some("setup_sysroots")),
        None => it,
    }
}

fn llama_item() -> SetupItem {
    let purpose = "llama.cpp server for local models";
    let installed = llama_setup::LlamaLayout::from_env_with(&|k| std::env::var_os(k))
        .and_then(|l| l.installed());
    let (state, detail) = match installed {
        Some(i) => (
            SetupState::Ready,
            format!("{} ({}) at {}", i.tag, i.variant, i.binary.display()),
        ),
        None => (SetupState::Missing, "llama-server is not installed".into()),
    };
    item("llama", "llama.cpp", purpose, state, detail).fixed(
        "Run local_model_setup (Tools > Local models) to download an engine and a model",
        Some("local_model_setup"),
    )
}

fn strata_item() -> SetupItem {
    let purpose = "Strata inference engine for local models";
    let layout = llama_setup::data_dir_with(&|k| std::env::var_os(k))
        .map(|d| strata_setup::StrataLayout::in_data_dir(&d));
    let (state, detail) = match layout {
        Some(l) if l.python().is_file() && l.backend_manifest().is_file() => (
            SetupState::Ready,
            format!("installed at {}", l.root().display()),
        ),
        _ => (SetupState::Missing, "not installed (optional)".into()),
    };
    item("strata", "Strata", purpose, state, detail).fixed(
        "Optional: set it up with local_model_setup when your hardware suits it",
        Some("local_model_setup"),
    )
}

#[async_trait]
impl SetupBackend for HostSetup {
    fn status(&self) -> Result<Vec<SetupItem>, ProtoError> {
        let cfg = self.config();
        let layout = self.layout.as_ref();
        let integ = self.integrations().ok();
        Ok(vec![
            ghidra_item(layout, &cfg),
            native_item(&cfg),
            dotnet_item(layout, &cfg),
            rust_item(integ.as_ref()),
            emulators_item(integ.as_ref()),
            llama_item(),
            strata_item(),
        ])
    }

    async fn run(
        &self,
        task: SetupTask,
        force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        match task {
            SetupTask::Ghidra => self.run_ghidra(force, progress).await,
            SetupTask::Native => self.run_native(force, progress).await,
            SetupTask::Dotnet => self.run_dotnet(force, progress).await,
            SetupTask::Rust => self.run_rust(force, progress).await,
            SetupTask::Sysroots => self.run_sysroots(force, progress).await,
        }
    }
}
