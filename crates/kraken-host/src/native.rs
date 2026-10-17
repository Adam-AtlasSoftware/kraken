//! Choosing and provisioning the native engine (ADR 0014, phase 4).
//!
//! A project's engine is `ghidra`, `native` or `auto`. `auto` means native when this build
//! contains the decompiler library, the compiled Sleigh (`.sla`) files are installed and the
//! binary is one the native loader opens; otherwise Ghidra. The decision is a pure function
//! ([`choose`]) over a [`NativeProbe`] and a [`BinaryFit`], so it is testable without either
//! engine; the factory only supplies the real probe.
//!
//! The engine runs in its confined worker process (`kraken-native-worker`, built with
//! `engine-native`) unless `native_in_process` is set in the configuration, and keeps its state
//! (`native-state.json`: applied edits, defined types, analysed signatures) in the project's
//! engine directory, the one directory the worker may write.

use std::io::Read;
use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions, has_specs};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{EngineChoice, EngineKind, EngineSelection};

/// The commands that make the native engine usable from a source checkout.
pub const SETUP_COMMANDS: [&str; 3] = [
    "cargo xtask native-src",
    "cargo xtask native-sla",
    "cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native",
];

/// What this machine and this build can offer the native engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProbe {
    /// This build contains the decompiler library (not the stub).
    pub library: bool,
    /// A spec tree with the compiled x86-64 `.sla` file.
    pub specs: Option<PathBuf>,
    /// The engine can run: the `kraken-native-worker` executable was found (next to this
    /// executable or through `KRAKEN_NATIVE_WORKER`), or the engine is configured to run
    /// in-process.
    pub worker: bool,
}

impl NativeProbe {
    /// Probes the running build and the machine. `configured` is `native_specs` from the
    /// configuration; `KRAKEN_NATIVE_SPECS` and the `cargo xtask native-sla` tree are tried
    /// after it. The worker executable is looked up as the engine looks it up.
    pub fn detect(configured: Option<&Path>) -> NativeProbe {
        let specs = configured
            .map(Path::to_path_buf)
            .into_iter()
            .chain(NativeConfig::discover().map(|c| c.spec_root))
            .find(|p| has_specs(p));
        NativeProbe {
            library: engine_native_sys::available(),
            specs,
            worker: WorkerOptions::default().locate().is_ok(),
        }
    }

    /// Why the native engine cannot run here, or `None` when it can.
    pub fn problem(&self) -> Option<String> {
        if !self.library {
            return Some(format!(
                "this build of kraken has no native decompiler library (it was built without the \
                 pinned Ghidra sources); run `{}`, `{}` and rebuild with `{}`",
                SETUP_COMMANDS[0], SETUP_COMMANDS[1], SETUP_COMMANDS[2]
            ));
        }
        if self.specs.is_none() {
            return Some(
                "the compiled Sleigh (.sla) files are not installed; run `kraken setup --native` \
                 (or `cargo xtask native-sla` in a source checkout)"
                    .into(),
            );
        }
        if !self.worker {
            return Some(format!(
                "its worker `kraken-native-worker` was not found next to this executable; build                  it with `{}` (or set KRAKEN_NATIVE_WORKER, or `native_in_process = true` in the                  configuration to run the decompiler unconfined inside this process)",
                SETUP_COMMANDS[2]
            ));
        }
        None
    }
}

/// Whether the native loader opens a binary.
pub type BinaryFit = Result<(), String>;

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Reads the ELF header of `path`: the native engine opens 64-bit little-endian x86-64 and
/// AArch64 ELF files and nothing else yet. Unreadable files are reported as fitting, so the
/// engine itself says what is wrong with them.
pub fn binary_fit(path: &Path) -> BinaryFit {
    let mut head = [0u8; 20];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };
    fit_of_header(&head[..n])
}

/// [`binary_fit`] over the first bytes of a file.
pub fn fit_of_header(head: &[u8]) -> BinaryFit {
    if head.get(..4) != Some(b"\x7fELF") {
        return Err("it is not an ELF file (the native engine opens ELF only for now)".into());
    }
    if head.get(4) != Some(&2) {
        return Err("it is a 32-bit ELF file (the native engine opens 64-bit ELF only)".into());
    }
    if head.get(5) != Some(&1) {
        return Err(
            "it is a big-endian ELF file (the native engine opens little-endian only)".into(),
        );
    }
    let machine = head
        .get(18..20)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    if machine != EM_X86_64 && machine != EM_AARCH64 {
        return Err(format!(
            "its machine type is {machine} (the native engine opens x86-64 and AArch64 only)"
        ));
    }
    Ok(())
}

/// The engine for a native-code binary under `choice`. Managed assemblies are decided by the
/// caller (the .NET engine opens them whatever the choice).
pub fn choose(
    choice: EngineChoice,
    probe: &NativeProbe,
    fit: &BinaryFit,
) -> Result<EngineSelection, ProtoError> {
    let native_problem = probe.problem().or_else(|| {
        fit.as_ref()
            .err()
            .map(|e| format!("the binary cannot use it: {e}"))
    });
    match choice {
        EngineChoice::Ghidra => Ok(EngineSelection {
            kind: EngineKind::Ghidra,
            choice,
            reason: "ghidra was requested".into(),
        }),
        EngineChoice::Native => match native_problem {
            None => Ok(EngineSelection {
                kind: EngineKind::Native,
                choice,
                reason: "native was requested".into(),
            }),
            Some(why) => Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("the native engine was requested but {why}; use `--engine ghidra` instead"),
            )),
        },
        EngineChoice::Auto => Ok(match native_problem {
            None => EngineSelection {
                kind: EngineKind::Native,
                choice,
                reason: "auto picked native: the native library and the compiled .sla files are \
                         available and the binary is a 64-bit little-endian x86-64 or AArch64 ELF"
                    .into(),
            },
            Some(why) => EngineSelection {
                kind: EngineKind::Ghidra,
                choice,
                reason: format!("auto picked Ghidra: {why}"),
            },
        }),
    }
}

/// The native engine over the specs in `probe`, keeping its state in `engine_dir` and running
/// where `isolation` says, or the reason there is none (including the recorded-engine hint, for
/// projects reopened later).
pub fn open_engine(
    probe: &NativeProbe,
    engine_dir: &Path,
    isolation: Isolation,
) -> Result<NativeEngine, ProtoError> {
    if let Some(why) = probe.problem() {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("this project uses the native engine but {why}"),
        ));
    }
    let mut config = NativeConfig::new(probe.specs.clone().unwrap_or_default());
    config.state_dir = Some(engine_dir.to_path_buf());
    config.isolation = isolation;
    Ok(NativeEngine::new(config))
}

/// One step of `kraken setup --native`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupStep {
    /// Run `cargo xtask <task>` in the checkout.
    Xtask(&'static str),
    /// Tell the person to rebuild so the binary links the decompiler.
    Rebuild,
}

/// What `kraken setup --native` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupPlan {
    /// Everything is in place.
    Ready,
    /// Run these steps in the source checkout.
    InCheckout {
        /// The checkout root (holds `xtask/`).
        root: PathBuf,
        /// Steps in order.
        steps: Vec<SetupStep>,
    },
    /// This binary was not built from a checkout reachable from here; the commands to run.
    Instructions(Vec<String>),
}

/// Plans the setup. `sources` is whether the pinned source tree is already fetched.
pub fn plan_setup(
    probe: &NativeProbe,
    sources: bool,
    checkout: Option<PathBuf>,
    force: bool,
) -> SetupPlan {
    let mut steps = Vec::new();
    if force || (!sources && (probe.specs.is_none() || !probe.library)) {
        steps.push(SetupStep::Xtask("native-src"));
    }
    if force || probe.specs.is_none() {
        steps.push(SetupStep::Xtask("native-sla"));
    }
    if !probe.library || !probe.worker {
        steps.push(SetupStep::Rebuild);
    }
    if steps.is_empty() {
        return SetupPlan::Ready;
    }
    match checkout {
        Some(root) => SetupPlan::InCheckout { root, steps },
        None => SetupPlan::Instructions(
            steps
                .iter()
                .map(|s| match s {
                    SetupStep::Xtask(t) => format!("cargo xtask {t}"),
                    SetupStep::Rebuild => SETUP_COMMANDS[2].to_string(),
                })
                .collect(),
        ),
    }
}

/// The source checkout this binary was built from, or the current directory's, when it still
/// holds `xtask/src/native_src.rs`.
pub fn find_checkout() -> Option<PathBuf> {
    let built_from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cwd = std::env::current_dir().ok();
    std::iter::once(built_from)
        .chain(
            cwd.iter()
                .flat_map(|d| d.ancestors().map(Path::to_path_buf)),
        )
        .find(|root| root.join("xtask/src/native_src.rs").is_file())
        .and_then(|root| root.canonicalize().ok())
}

/// Where `cargo xtask native-src` puts the pinned sources.
pub fn sources_dir() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("HOME")?)
            .join(".cache/kraken-dev/ghidra-src")
            .join(engine_native::SOURCE_TAG)
            .join("decompile/cpp/slgh_compile.cc"),
    )
    .filter(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(library: bool, specs: bool) -> NativeProbe {
        NativeProbe {
            library,
            specs: specs.then(|| PathBuf::from("/specs")),
            worker: true,
        }
    }

    fn elf_head(class: u8, data: u8, machine: u16) -> Vec<u8> {
        let mut h = vec![0x7f, b'E', b'L', b'F', class, data, 1];
        h.resize(18, 0);
        h.extend_from_slice(&machine.to_le_bytes());
        h
    }

    #[test]
    fn auto_picks_native_only_when_everything_is_there() {
        let fit = fit_of_header(&elf_head(2, 1, EM_X86_64));
        let s = choose(EngineChoice::Auto, &probe(true, true), &fit).unwrap();
        assert_eq!(s.kind, EngineKind::Native);
        assert!(s.reason.starts_with("auto picked native"), "{}", s.reason);

        let s = choose(EngineChoice::Auto, &probe(false, true), &fit).unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        assert!(
            s.reason.contains("no native decompiler library"),
            "{}",
            s.reason
        );
        assert!(s.reason.contains("cargo xtask native-src"), "{}", s.reason);

        let s = choose(EngineChoice::Auto, &probe(true, false), &fit).unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        assert!(s.reason.contains("kraken setup --native"), "{}", s.reason);
        assert_eq!(s.choice, EngineChoice::Auto);
    }

    #[test]
    fn auto_falls_back_for_binaries_the_loader_cannot_open() {
        for (head, needle) in [
            (b"MZ\x90\0".to_vec(), "not an ELF"),
            (elf_head(1, 1, 3), "32-bit"),
            (elf_head(2, 2, EM_X86_64), "big-endian"),
            (elf_head(2, 1, 8), "machine type is 8"),
        ] {
            let s = choose(
                EngineChoice::Auto,
                &probe(true, true),
                &fit_of_header(&head),
            )
            .unwrap();
            assert_eq!(s.kind, EngineKind::Ghidra);
            assert!(s.reason.contains(needle), "{}", s.reason);
        }
        assert!(fit_of_header(&elf_head(2, 1, EM_AARCH64)).is_ok());
    }

    #[test]
    fn explicit_choices_are_honoured_or_refused_with_a_way_out() {
        let fit = Ok(());
        let g = choose(EngineChoice::Ghidra, &probe(false, false), &fit).unwrap();
        assert_eq!(g.kind, EngineKind::Ghidra);
        let n = choose(EngineChoice::Native, &probe(true, true), &fit).unwrap();
        assert_eq!(n.kind, EngineKind::Native);
        assert_eq!(n.choice, EngineChoice::Native);

        let e = choose(EngineChoice::Native, &probe(true, false), &fit).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("kraken setup --native"), "{}", e.message);
        assert!(e.message.contains("--engine ghidra"), "{}", e.message);

        let pe = fit_of_header(b"MZ");
        let e = choose(EngineChoice::Native, &probe(true, true), &pe).unwrap_err();
        assert!(e.message.contains("not an ELF"), "{}", e.message);
    }

    #[test]
    fn reopening_without_the_native_engine_says_why() {
        let Err(e) = open_engine(&probe(true, false), Path::new("/e"), Isolation::InProcess) else {
            panic!("expected an error");
        };
        assert!(e.message.starts_with("this project uses the native engine"));
        assert!(e.message.contains("kraken setup --native"));
    }

    #[test]
    fn a_missing_worker_is_a_problem_auto_avoids() {
        let no_worker = NativeProbe {
            worker: false,
            ..probe(true, true)
        };
        let why = no_worker.problem().expect("a problem");
        assert!(why.contains("kraken-native-worker"), "{why}");
        assert!(why.contains("-p engine-native"), "{why}");
        let s = choose(EngineChoice::Auto, &no_worker, &Ok(())).unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        let SetupPlan::InCheckout { steps, .. } =
            plan_setup(&no_worker, true, Some(PathBuf::from("/src")), false)
        else {
            panic!("expected steps");
        };
        assert_eq!(steps, vec![SetupStep::Rebuild]);
    }

    #[test]
    fn the_engine_keeps_its_state_in_the_engine_directory() {
        let e = open_engine(
            &probe(true, true),
            Path::new("/p/ghidra"),
            Isolation::InProcess,
        )
        .expect("engine");
        assert!(!e.is_isolated());
        let e = open_engine(
            &probe(true, true),
            Path::new("/p/ghidra"),
            Isolation::default(),
        )
        .expect("engine");
        assert_eq!(e.is_isolated(), cfg!(unix));
    }

    #[test]
    fn setup_plans() {
        let root = PathBuf::from("/src/kraken");
        assert_eq!(
            plan_setup(&probe(true, true), true, None, false),
            SetupPlan::Ready
        );

        // Fresh machine, built from a checkout: fetch, compile the specs, rebuild.
        let SetupPlan::InCheckout { steps, .. } =
            plan_setup(&probe(false, false), false, Some(root.clone()), false)
        else {
            panic!("expected steps");
        };
        assert_eq!(
            steps,
            vec![
                SetupStep::Xtask("native-src"),
                SetupStep::Xtask("native-sla"),
                SetupStep::Rebuild
            ]
        );

        // Library present, only the specs are missing.
        let SetupPlan::InCheckout { steps, .. } =
            plan_setup(&probe(true, false), true, Some(root.clone()), false)
        else {
            panic!("expected steps");
        };
        assert_eq!(steps, vec![SetupStep::Xtask("native-sla")]);

        // Sources and specs fetched earlier but the binary links the stub.
        let SetupPlan::InCheckout { steps, .. } =
            plan_setup(&probe(false, true), true, Some(root), false)
        else {
            panic!("expected steps");
        };
        assert_eq!(steps, vec![SetupStep::Rebuild]);

        // No checkout: the exact commands.
        let SetupPlan::Instructions(cmds) = plan_setup(&probe(false, false), false, None, false)
        else {
            panic!("expected instructions");
        };
        assert_eq!(cmds, SETUP_COMMANDS.map(String::from).to_vec());
    }
}
