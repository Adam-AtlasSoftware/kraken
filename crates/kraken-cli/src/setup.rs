//! `kraken setup`: provision Ghidra, a JDK and the extension (see `kraken_host::provision`), or
//! with `--dotnet` the .NET runtime and sidecar (see `kraken_host::dotnet_setup`), with
//! `--native` the native engine's sources and Sleigh files (see `kraken_host::native`).

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use clap::ArgMatches;
use kraken_host::dotnet_setup::{bundled_sidecar, pinned_dotnet, setup_dotnet};
use kraken_host::provision::{
    HttpsFetcher, Layout, Progress, ProvisionError, SetupOptions, pinned, setup,
};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::json;

use crate::app::{CliEnv, emit, fail};

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Prints download progress to stderr: a rewritten line on a terminal, a line per 10% otherwise.
pub(crate) struct Printer {
    tty: bool,
    last_decile: HashMap<String, u64>,
    in_line: bool,
}

impl Printer {
    pub(crate) fn new() -> Self {
        Printer {
            tty: std::io::stderr().is_terminal(),
            last_decile: HashMap::new(),
            in_line: false,
        }
    }

    pub(crate) fn end_line(&mut self) {
        if self.in_line {
            let _ = writeln!(std::io::stderr());
            self.in_line = false;
        }
    }

    pub(crate) fn show(&mut self, p: Progress) {
        let mut e = std::io::stderr();
        match p {
            Progress::Downloading {
                name,
                done,
                total,
                resumed_from,
            } => {
                let pct = total.filter(|t| *t > 0).map(|t| done * 100 / t);
                let finished = total.is_some_and(|t| done >= t);
                if self.tty {
                    let line = match total {
                        Some(t) => format!(
                            "downloading {name}: {:.1} / {:.1} MiB ({}%)",
                            mib(done),
                            mib(t),
                            pct.unwrap_or(0)
                        ),
                        None => format!("downloading {name}: {:.1} MiB", mib(done)),
                    };
                    let _ = write!(e, "\r{line}\x1b[K");
                    self.in_line = true;
                    if finished {
                        self.end_line();
                    }
                } else {
                    let decile = pct.map_or(0, |p| p / 10);
                    let first = !self.last_decile.contains_key(&name);
                    if first && resumed_from > 0 {
                        let _ = writeln!(
                            e,
                            "downloading {name}: resuming at {:.1} MiB",
                            mib(resumed_from)
                        );
                    }
                    if first || self.last_decile.get(&name) != Some(&decile) || finished {
                        let _ = match total {
                            Some(t) => writeln!(
                                e,
                                "downloading {name}: {:.1} / {:.1} MiB ({}%)",
                                mib(done),
                                mib(t),
                                pct.unwrap_or(0)
                            ),
                            None => writeln!(e, "downloading {name}: {:.1} MiB", mib(done)),
                        };
                    }
                    self.last_decile.insert(name, decile);
                }
            }
            Progress::Verifying { name } => {
                self.end_line();
                let _ = writeln!(e, "verifying {name} (sha256)");
            }
            Progress::Extracting { name } => {
                self.end_line();
                let _ = writeln!(e, "extracting {name}");
            }
            Progress::InstallingBundledExtension => {
                self.end_line();
                let _ = writeln!(e, "installing the bundled Ghidra extension");
            }
            Progress::BuildingExtension => {
                self.end_line();
                let _ = writeln!(e, "building the Ghidra extension with the downloaded JDK");
            }
            Progress::Skipped { name } => {
                let _ = writeln!(e, "{name} is already installed");
            }
        }
    }
}

fn to_proto(e: ProvisionError) -> ProtoError {
    let code = match e {
        ProvisionError::UnsupportedPlatform(_) => ErrorCode::Unsupported,
        ProvisionError::NotHttps(_) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    ProtoError::new(code, e.to_string())
}

pub(crate) async fn run_setup(
    _env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if sm.try_get_one::<bool>("dotnet").ok().flatten().copied() == Some(true) {
        return run_setup_dotnet(sm, json_out, out, err).await;
    }
    if sm.try_get_one::<bool>("native").ok().flatten().copied() == Some(true) {
        return run_setup_native(sm, json_out, out, err).await;
    }
    let specs = match pinned() {
        Ok(s) => s,
        Err(e) => return fail(&to_proto(e), json_out, err),
    };
    let Some(layout) = Layout::from_env() else {
        return fail(
            &ProtoError::new(
                ErrorCode::Internal,
                "cannot place the runtime: neither XDG_DATA_HOME nor HOME is set",
            ),
            json_out,
            err,
        );
    };
    let fetcher = match HttpsFetcher::new() {
        Ok(f) => f,
        Err(e) => return fail(&to_proto(e), json_out, err),
    };
    let opts = SetupOptions::with_bundled(
        sm.try_get_one::<bool>("force").ok().flatten().copied() == Some(true),
    );
    let mut printer = Printer::new();
    let result = setup(&layout, &fetcher, &specs, &opts, &mut |p| printer.show(p)).await;
    printer.end_line();
    match result {
        Ok(p) => {
            let show = |o: &Option<std::path::PathBuf>| {
                o.as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            if json_out {
                emit(
                    out,
                    &format!(
                        "{}\n",
                        json!({
                            "runtime_dir": layout.root(),
                            "ghidra_home": show(&p.ghidra_home),
                            "java_home": show(&p.java_home),
                            "ext_jar": show(&p.ext_jar),
                        })
                    ),
                );
            } else {
                emit(
                    out,
                    &format!(
                        "Ghidra:    {}\nJDK:       {}\nExtension: {}\nReady: KRAKEN finds these on its own (KRAKEN_GHIDRA_HOME and KRAKEN_JAVA_HOME take precedence).\n",
                        show(&p.ghidra_home),
                        show(&p.java_home),
                        show(&p.ext_jar)
                    ),
                );
            }
            0
        }
        Err(e) => fail(&to_proto(e), json_out, err),
    }
}

async fn run_setup_dotnet(
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let spec = match pinned_dotnet() {
        Ok(s) => s,
        Err(e) => return fail(&to_proto(e), json_out, err),
    };
    let Some(layout) = Layout::from_env() else {
        return fail(
            &ProtoError::new(
                ErrorCode::Internal,
                "cannot place the runtime: neither XDG_DATA_HOME nor HOME is set",
            ),
            json_out,
            err,
        );
    };
    let fetcher = match HttpsFetcher::new() {
        Ok(f) => f,
        Err(e) => return fail(&to_proto(e), json_out, err),
    };
    let force = sm.try_get_one::<bool>("force").ok().flatten().copied() == Some(true);
    let bundled = bundled_sidecar();
    let mut printer = Printer::new();
    let result = setup_dotnet(
        &layout,
        &fetcher,
        &spec,
        bundled.as_deref(),
        force,
        &mut |p| printer.show(p),
    )
    .await;
    printer.end_line();
    match result {
        Ok(p) => {
            let show = |o: &Option<std::path::PathBuf>| {
                o.as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            if json_out {
                emit(
                    out,
                    &format!(
                        "{}\n",
                        json!({
                            "runtime_dir": layout.root(),
                            "dotnet_root": show(&p.dotnet_root),
                            "dotnet_ext": show(&p.ext_dll),
                        })
                    ),
                );
            } else {
                emit(
                    out,
                    &format!(
                        ".NET runtime: {}\nSidecar:      {}\nReady: KRAKEN opens .NET assemblies with these (KRAKEN_DOTNET_ROOT and KRAKEN_DOTNET_EXT_DLL take precedence).\n",
                        show(&p.dotnet_root),
                        show(&p.ext_dll)
                    ),
                );
            }
            0
        }
        Err(e) => fail(&to_proto(e), json_out, err),
    }
}

/// `kraken setup --native`: makes the native engine usable. The decompiler library is linked at
/// build time, so a binary can only fetch the pinned sources and compile the Sleigh files
/// (`cargo xtask native-src` / `native-sla`) when it can find the source checkout it was built
/// from; otherwise it prints the exact commands.
pub(crate) async fn run_setup_native(
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    use kraken_host::native::{self, SetupPlan, SetupStep};

    let force = sm.try_get_one::<bool>("force").ok().flatten().copied() == Some(true);
    let configured = kraken_host::KrakenConfig::load()
        .ok()
        .and_then(|c| c.native_specs);
    let probe = native::NativeProbe::detect(configured.as_deref());
    let plan = native::plan_setup(
        &probe,
        native::sources_dir().is_some(),
        native::find_checkout(),
        force,
    );
    match plan {
        SetupPlan::Ready => {
            let specs = probe.specs.map(|p| p.display().to_string());
            if json_out {
                emit(
                    out,
                    &format!(
                        "{}\n",
                        json!({"ready": true, "library": true, "specs": specs})
                    ),
                );
            } else {
                emit(
                    out,
                    &format!(
                        "The native engine is ready.\nSleigh files: {}\nUse it with `kraken project-create --engine native` (or `auto`).\n",
                        specs.unwrap_or_default()
                    ),
                );
            }
            0
        }
        SetupPlan::Instructions(cmds) => {
            let msg = format!(
                "this kraken was not built from a source checkout reachable from here, and the \
                 native engine's decompiler is linked at build time. In a checkout of the \
                 repository run:\n  {}",
                cmds.join("\n  ")
            );
            fail(&ProtoError::new(ErrorCode::Unsupported, msg), json_out, err)
        }
        SetupPlan::InCheckout { root, steps } => {
            for step in steps {
                let SetupStep::Xtask(task) = step else {
                    continue;
                };
                let _ = writeln!(err, "running `cargo xtask {task}` in {}", root.display());
                if let Err(e) = run_xtask(&root, task).await {
                    return fail(&ProtoError::new(ErrorCode::Internal, e), json_out, err);
                }
            }
            let after = native::NativeProbe::detect(configured.as_deref());
            let specs = after.specs.as_ref().map(|p| p.display().to_string());
            let cmd = native::SETUP_COMMANDS[2];
            if json_out {
                emit(
                    out,
                    &format!(
                        "{}\n",
                        json!({
                            "ready": after.problem().is_none(),
                            "library": after.library,
                            "specs": specs,
                            "rebuild": (!after.library).then_some(cmd),
                        })
                    ),
                );
            } else if after.library {
                emit(
                    out,
                    &format!(
                        "Sleigh files: {}\nThe native engine is ready.\n",
                        specs.unwrap_or_default()
                    ),
                );
            } else {
                emit(
                    out,
                    &format!(
                        "Sleigh files: {}\nThis kraken still links the stub decompiler. Rebuild it so the library is compiled in:\n  {cmd}\n",
                        specs.unwrap_or_default()
                    ),
                );
            }
            0
        }
    }
}

/// Runs `cargo xtask <task>` in `root`, its output going to stderr.
async fn run_xtask(root: &std::path::Path, task: &'static str) -> Result<(), String> {
    let dir = root.to_path_buf();
    let status = tokio::task::spawn_blocking(move || {
        let to_err = std::process::Stdio::from(std::io::stderr());
        std::process::Command::new("cargo")
            .args(["xtask", task])
            .current_dir(dir)
            .stdout(to_err)
            .status()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("cannot run `cargo xtask {task}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`cargo xtask {task}` failed ({status})"))
    }
}
