//! `kraken setup`: a thin wrapper over the backend of the `setup_ghidra`, `setup_dotnet` and
//! `setup_native` commands (`kraken_host::setup`), printing their progress. Plain `kraken setup`
//! installs Ghidra, a JDK and the extension, `--dotnet` the .NET runtime and sidecar, `--native`
//! the native engine's sources and Sleigh files. Ctrl-C stops the install; a partial download is
//! kept.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use clap::ArgMatches;
use kraken_host::provision::Progress;
use kraken_host::setup::HostSetup;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{SetupBackend, SetupTask};
use kraken_registry::jobs::JobProgress;
use serde_json::Value;

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

    /// Shows a progress report from the setup backend.
    pub(crate) fn show_job(&mut self, p: &JobProgress) {
        if p.phase == "download" {
            let name = p
                .message
                .strip_prefix("downloading ")
                .and_then(|m| m.split(':').next())
                .unwrap_or("file")
                .to_string();
            self.show(Progress::Downloading {
                name,
                done: p.done,
                total: (p.total > 0).then_some(p.total),
                resumed_from: 0,
            });
        } else {
            self.end_line();
            let _ = writeln!(std::io::stderr(), "{}", p.message);
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

fn field<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

pub(crate) async fn run_setup(
    _env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let flag = |n: &str| sm.try_get_one::<bool>(n).ok().flatten().copied() == Some(true);
    let task = if flag("dotnet") {
        SetupTask::Dotnet
    } else if flag("native") {
        SetupTask::Native
    } else {
        SetupTask::Ghidra
    };
    let backend = HostSetup::system();
    let printer = std::sync::Mutex::new(Printer::new());
    let on = |p: JobProgress| {
        if let Ok(mut pr) = printer.lock() {
            pr.show_job(&p);
        }
    };
    let result = tokio::select! {
        r = backend.run(task, flag("force"), &on) => r,
        _ = tokio::signal::ctrl_c() => Err(ProtoError::new(
            ErrorCode::Cancelled,
            "setup cancelled; a partial download is kept and resumed next time",
        )),
    };
    if let Ok(mut pr) = printer.lock() {
        pr.end_line();
    }
    let v = match result {
        Ok(v) => v,
        Err(e) => return fail(&e, json_out, err),
    };
    if json_out {
        emit(out, &format!("{v}\n"));
        return 0;
    }
    let text = match task {
        SetupTask::Ghidra => format!(
            "Ghidra:    {}\nJDK:       {}\nExtension: {}\nReady: KRAKEN finds these on its own (KRAKEN_GHIDRA_HOME and KRAKEN_JAVA_HOME take precedence).\n",
            field(&v, "ghidra_home"),
            field(&v, "java_home"),
            field(&v, "ext_jar")
        ),
        SetupTask::Dotnet => format!(
            ".NET runtime: {}\nSidecar:      {}\nReady: KRAKEN opens .NET assemblies with these (KRAKEN_DOTNET_ROOT and KRAKEN_DOTNET_EXT_DLL take precedence).\n",
            field(&v, "dotnet_root"),
            field(&v, "dotnet_ext")
        ),
        SetupTask::Native => {
            let specs = field(&v, "specs");
            if v.get("ready").and_then(Value::as_bool) == Some(true) {
                format!(
                    "Sleigh files: {specs}\nThe native engine is ready.\nUse it with `kraken project-create --engine native` (or `auto`).\n"
                )
            } else if let Some(cmd) = v.get("rebuild").and_then(Value::as_str) {
                format!(
                    "Sleigh files: {specs}\nThis kraken still links the stub decompiler. Rebuild it so the library is compiled in:\n  {cmd}\n"
                )
            } else {
                format!("Sleigh files: {specs}\n")
            }
        }
    };
    emit(out, &text);
    0
}
