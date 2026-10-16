//! `kraken setup`: provision Ghidra, a JDK and the extension (see `kraken_host::provision`).

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use clap::ArgMatches;
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
struct Printer {
    tty: bool,
    last_decile: HashMap<String, u64>,
    in_line: bool,
}

impl Printer {
    fn new() -> Self {
        Printer {
            tty: std::io::stderr().is_terminal(),
            last_decile: HashMap::new(),
            in_line: false,
        }
    }

    fn end_line(&mut self) {
        if self.in_line {
            let _ = writeln!(std::io::stderr());
            self.in_line = false;
        }
    }

    fn show(&mut self, p: Progress) {
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
