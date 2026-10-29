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
                "its worker `kraken-native-worker` was not found next to this executable; build \
                 it with `{}` (or set KRAKEN_NATIVE_WORKER, or `native_in_process = true` in the \
                 configuration to run the decompiler unconfined inside this process)",
                SETUP_COMMANDS[2]
            ));
        }
        None
    }
}

/// Whether the native loader opens a binary.
pub type BinaryFit = Result<(), String>;

const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;
const PE_I386: u16 = 0x014c;
const PE_AMD64: u16 = 0x8664;

/// Reads the header of `path`: the native engine opens little-endian ELF files for x86-64,
/// 32-bit x86, ARM (A32 and Thumb), AArch64, RISC-V 64 and RISC-V 32, and PE images for x86
/// and x86-64, and nothing else yet. Unreadable files are reported as fitting, so the engine
/// itself says what is wrong with them.
pub fn binary_fit(path: &Path) -> BinaryFit {
    let mut head = vec![0u8; 4096];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };
    fit_of_header(&head[..n])
}

/// [`binary_fit`], and whether the spec tree `specs` has the Sleigh specification the file's
/// processor needs: a tree compiled before ARM and RISC-V were added holds x86 and AArch64
/// only (`cargo xtask native-sla` again, or `kraken setup --native`, adds them).
pub fn binary_fit_in(path: &Path, specs: Option<&Path>) -> BinaryFit {
    binary_fit(path)?;
    let mut head = [0u8; 20];
    let Ok(n) = std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) else {
        return Ok(());
    };
    match (specs, sla_of_header(&head[..n])) {
        (Some(root), Some((processor, sla))) => {
            let file = root
                .join("Ghidra/Processors")
                .join(processor)
                .join("data/languages")
                .join(sla);
            if file.is_file() {
                Ok(())
            } else {
                Err(format!(
                    "the compiled Sleigh files under {} lack {processor} ({sla}); run `kraken \
                     setup --native` (or `cargo xtask native-sla` in a source checkout) to \
                     compile them",
                    root.display()
                ))
            }
        }
        _ => Ok(()),
    }
}

/// The processor directory and `.sla` file an ELF header needs, for the processors added after
/// the first spec trees (ARM, RISC-V); `None` for the rest.
fn sla_of_header(head: &[u8]) -> Option<(&'static str, &'static str)> {
    if head.get(..4) != Some(b"\x7fELF") {
        return None;
    }
    let machine = head.get(18..20).map(|b| u16::from_le_bytes([b[0], b[1]]))?;
    match (machine, head.get(4)) {
        (EM_ARM, _) => Some(("ARM", "ARM8_le.sla")),
        (EM_RISCV, Some(2)) => Some(("RISCV", "riscv.lp64d.sla")),
        (EM_RISCV, _) => Some(("RISCV", "riscv.ilp32d.sla")),
        _ => None,
    }
}

/// [`binary_fit`] over the first bytes of a file (the PE header has to be among them).
pub fn fit_of_header(head: &[u8]) -> BinaryFit {
    if head.get(..2) == Some(b"MZ") {
        return pe_fit(head);
    }
    // archives (static and import libraries) and COFF objects: the loader checks the members
    if native_only_header(head).is_some() || coff_object(head) {
        return Ok(());
    }
    if head.get(..4) != Some(b"\x7fELF") {
        return Err(
            "it is not an ELF or PE file, object file or library archive (the native engine \
             opens those only)"
                .into(),
        );
    }
    let machine = head
        .get(18..20)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    if head.get(5) != Some(&1) {
        return Err(
            "it is a big-endian ELF file (the native engine opens little-endian only)".into(),
        );
    }
    if head.get(4) != Some(&2) {
        if matches!(machine, EM_386 | EM_ARM | EM_RISCV) {
            return Ok(());
        }
        return Err(format!(
            "it is a 32-bit ELF file for machine type {machine} (the native engine opens 32-bit \
             x86, ARM and RISC-V 32 only)"
        ));
    }
    if !matches!(machine, EM_X86_64 | EM_AARCH64 | EM_RISCV) {
        return Err(format!(
            "its machine type is {machine} (the native engine opens x86-64, AArch64 and RISC-V \
             64 only)"
        ));
    }
    Ok(())
}

/// A COFF object for x86 or x86-64: the machine, a sane section count and no optional header.
fn coff_object(head: &[u8]) -> bool {
    let word = |o: usize| head.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    matches!(word(0), Some(PE_I386 | PE_AMD64))
        && word(2).is_some_and(|n| n > 0 && n < 0x1000)
        && word(16) == Some(0)
}

/// What a file is when only the native engine opens it: an `ar` archive (a static or import
/// library), a big-object COFF file or a single import member (both start `00 00 ff ff`).
pub fn native_only(path: &Path) -> Option<&'static str> {
    let mut head = [0u8; 8];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .ok()?;
    native_only_header(&head[..n])
}

fn native_only_header(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"!<arch>\n") {
        return Some("a static or import library");
    }
    if head.get(..4) == Some(&[0, 0, 0xff, 0xff]) {
        return Some("a big COFF object or an import member");
    }
    None
}

/// A PE image: the `PE\0\0` header the DOS stub points at, for x86 or x86-64.
fn pe_fit(head: &[u8]) -> BinaryFit {
    let at = head
        .get(0x3c..0x40)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let machine = at
        .and_then(|o| head.get(o..o + 6))
        .filter(|h| h.starts_with(b"PE\0\0"))
        .map(|h| u16::from_le_bytes([h[4], h[5]]));
    match machine {
        Some(PE_I386 | PE_AMD64) => Ok(()),
        Some(m) => Err(format!(
            "its PE machine type is {m:#06x} (the native engine opens x86 and x86-64 PE only)"
        )),
        None => Err("it is an MS-DOS program or a damaged PE file (no PE header)".into()),
    }
}

/// [`choose`] for a file only the native engine opens (`what` says what it is, see
/// [`native_only`]): native whatever the choice, or an error that says what is missing.
pub fn choose_native_only(
    choice: EngineChoice,
    probe: &NativeProbe,
    fit: &BinaryFit,
    what: &str,
) -> Result<EngineSelection, ProtoError> {
    let problem = probe.problem().or_else(|| {
        fit.as_ref()
            .err()
            .map(|e| format!("the file cannot use it: {e}"))
    });
    match problem {
        None => Ok(EngineSelection {
            kind: EngineKind::Native,
            choice,
            reason: format!(
                "the file is {what}, which only the native engine opens (Ghidra does not load \
                 archives)"
            ),
        }),
        Some(why) => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("the file is {what}, which only the native engine opens, but {why}"),
        )),
    }
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
                         available and the binary is an ELF file (x86-64, 32-bit x86, ARM, \
                         AArch64, RISC-V), a PE image or an object file (x86, x86-64, or an ELF \
                         object of those processors)"
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

/// Whether the native engine has a raw loader for `language` (a short name or a Sleigh id).
pub fn raw_native_supported(language: &str) -> bool {
    engine_native::raw::resolve(language).is_some()
}

/// The engine for a raw image of `language` under `choice`: native for the processors it has a
/// raw loader and compiled Sleigh files for, else Ghidra (an error under `native`).
pub fn choose_raw(
    choice: EngineChoice,
    probe: &NativeProbe,
    language: &str,
) -> Result<EngineSelection, ProtoError> {
    let language = kraken_engine::language_id(language);
    let problem = probe
        .problem()
        .or_else(|| match engine_native::raw::sla_file(&language) {
            None => Some(format!(
                "it has no raw loader for {language} (it loads {})",
                engine_native::raw::languages().join(", ")
            )),
            Some((dir, sla)) => probe.specs.as_deref().and_then(|root| {
                let f = root
                    .join("Ghidra/Processors")
                    .join(dir)
                    .join("data/languages")
                    .join(sla);
                (!f.is_file()).then(|| {
                format!(
                    "the compiled Sleigh files under {} lack {sla}; run `kraken setup --native`",
                    root.display()
                )
            })
            }),
        });
    match (choice, problem) {
        (EngineChoice::Ghidra, _) => Ok(EngineSelection {
            kind: EngineKind::Ghidra,
            choice,
            reason: "ghidra was requested".into(),
        }),
        (EngineChoice::Native, None) | (EngineChoice::Auto, None) => Ok(EngineSelection {
            kind: EngineKind::Native,
            choice,
            reason: format!("a raw {language} image: the native engine has a raw loader for it"),
        }),
        (EngineChoice::Native, Some(why)) => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("the native engine was requested but {why}; use `--engine ghidra` instead"),
        )),
        (EngineChoice::Auto, Some(why)) => Ok(EngineSelection {
            kind: EngineKind::Ghidra,
            choice,
            reason: format!("auto picked Ghidra for a raw {language} image: native {why}"),
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
    // a tree `cargo xtask native-sla` compiled before ARM and RISC-V were added is compiled
    // again
    let stale = probe.specs.as_deref().is_some_and(|s| {
        engine_native::compiled_specs_dir().as_deref() == Some(s) && !has_all_processors(s)
    });
    if force || probe.specs.is_none() || stale {
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

/// Whether the spec tree at `root` has every processor the native engine opens: x86, AArch64,
/// ARM and RISC-V.
pub fn has_all_processors(root: &Path) -> bool {
    [
        "x86/data/languages/x86-64.sla",
        "x86/data/languages/x86.sla",
        "AARCH64/data/languages/AARCH64.sla",
        "ARM/data/languages/ARM8_le.sla",
        "RISCV/data/languages/riscv.lp64d.sla",
        "RISCV/data/languages/riscv.ilp32d.sla",
    ]
    .iter()
    .all(|f| root.join("Ghidra/Processors").join(f).is_file())
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

/// `binary_probe` for a person's tools (the GUI's import dialog) without a session: what
/// `path` is and which engine of this machine should open it, under `cfg`. Blocking.
pub fn probe_binary(
    cfg: &crate::KrakenConfig,
    path: &Path,
) -> Result<kraken_registry::commands::BinaryProbeOut, ProtoError> {
    let factory = crate::HostEngineFactory::new(cfg.clone());
    kraken_registry::commands::probe_binary(&factory, path)
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
    fn raw_images_go_native_for_its_processors_and_to_ghidra_for_the_rest() {
        let tree = tempfile::tempdir().unwrap();
        let langs = tree.path().join("Ghidra/Processors/ARM/data/languages");
        std::fs::create_dir_all(&langs).unwrap();
        std::fs::write(langs.join("ARM7_le.sla"), b"").unwrap();
        let p = NativeProbe {
            library: true,
            specs: Some(tree.path().to_path_buf()),
            worker: true,
        };
        let s = choose_raw(EngineChoice::Auto, &p, "cortex-m").unwrap();
        assert_eq!(s.kind, EngineKind::Native, "{}", s.reason);
        // the tree lacks the x86 file
        let s = choose_raw(EngineChoice::Auto, &p, "x86").unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        assert!(s.reason.contains("lack"), "{}", s.reason);
        let s = choose_raw(EngineChoice::Auto, &p, "z80").unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        assert!(s.reason.contains("no raw loader"), "{}", s.reason);
        let e = choose_raw(EngineChoice::Native, &p, "z80").unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
        let s = choose_raw(EngineChoice::Ghidra, &p, "arm").unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        // no library: native is out for every processor
        let s = choose_raw(EngineChoice::Auto, &probe(false, false), "arm").unwrap();
        assert_eq!(s.kind, EngineKind::Ghidra);
        assert!(raw_native_supported("x86-64") && !raw_native_supported("mips"));
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
            (b"MZ\x90\0".to_vec(), "no PE header"),
            (b"\xca\xfe\xba\xbe".to_vec(), "not an ELF or PE file"),
            (pe_head(0x1c0), "PE machine type is 0x01c0"),
            (elf_head(1, 1, 8), "32-bit ELF file for machine type 8"),
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
        assert!(fit_of_header(&elf_head(1, 1, EM_386)).is_ok());
        assert!(fit_of_header(&elf_head(1, 1, EM_ARM)).is_ok());
        assert!(fit_of_header(&elf_head(1, 1, EM_RISCV)).is_ok());
        assert!(fit_of_header(&elf_head(2, 1, EM_RISCV)).is_ok());
        assert!(
            fit_of_header(&elf_head(1, 2, EM_ARM)).is_err(),
            "big-endian ARM"
        );
        assert!(fit_of_header(&pe_head(PE_I386)).is_ok());
        assert!(fit_of_header(&pe_head(PE_AMD64)).is_ok());
    }

    #[test]
    fn arm_and_riscv_need_their_compiled_specs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let elf = dir.path().join("arm.elf");
        std::fs::write(&elf, elf_head(1, 1, EM_ARM)).expect("write");
        let specs = dir.path().join("specs");
        let langs = specs.join("Ghidra/Processors/ARM/data/languages");
        std::fs::create_dir_all(&langs).expect("mkdir");
        let e = binary_fit_in(&elf, Some(&specs)).expect_err("no ARM .sla yet");
        assert!(
            e.contains("lack ARM") && e.contains("kraken setup --native"),
            "{e}"
        );
        std::fs::write(langs.join("ARM8_le.sla"), b"").expect("write");
        assert!(binary_fit_in(&elf, Some(&specs)).is_ok());
        assert_eq!(
            sla_of_header(&elf_head(2, 1, EM_RISCV)),
            Some(("RISCV", "riscv.lp64d.sla"))
        );
        assert_eq!(
            sla_of_header(&elf_head(1, 1, EM_RISCV)),
            Some(("RISCV", "riscv.ilp32d.sla"))
        );
        assert_eq!(sla_of_header(&elf_head(2, 1, EM_X86_64)), None);
    }

    fn pe_head(machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 0x80];
        h[..2].copy_from_slice(b"MZ");
        h[0x3c] = 0x40;
        h[0x40..0x44].copy_from_slice(b"PE\0\0");
        h[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        h
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

        let dos = fit_of_header(b"MZ");
        let e = choose(EngineChoice::Native, &probe(true, true), &dos).unwrap_err();
        assert!(e.message.contains("no PE header"), "{}", e.message);
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

#[cfg(test)]
mod probe_tests {
    use std::path::{Path, PathBuf};

    use kraken_registry::EngineKind;
    use kraken_registry::commands::BinaryFormat;

    use crate::KrakenConfig;

    fn corpus(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(rel)
    }

    fn bare() -> KrakenConfig {
        KrakenConfig {
            ghidra_home: Some("/nonexistent/ghidra".into()),
            java_home: Some("/nonexistent/jdk".into()),
            ext_jar: Some("/nonexistent/k.jar".into()),
            dotnet_root: Some("/nonexistent/kraken-dotnet".into()),
            dotnet_ext: Some("/nonexistent/kraken-dotnet.dll".into()),
            native_specs: Some("/nonexistent/specs".into()),
            ..Default::default()
        }
    }

    #[test]
    fn every_engine_is_listed_with_what_it_lacks() {
        let out = super::probe_binary(&bare(), &corpus("bin/pie_list-O0")).unwrap();
        assert_eq!(out.format, BinaryFormat::Elf);
        let kinds: Vec<_> = out.engines.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [EngineKind::Ghidra, EngineKind::Native, EngineKind::Dotnet]
        );
        let ghidra = &out.engines[0];
        assert!(!ghidra.usable);
        assert!(
            ghidra
                .problem
                .as_deref()
                .is_some_and(|p| p.contains("kraken setup"))
        );
        let dotnet = &out.engines[2];
        assert!(!dotnet.usable && dotnet.problem.is_some());
        // Ghidra is missing in this configuration; the native engine may still be found (the
        // spec tree of `cargo xtask native-sla` and a built worker), and then auto picks it.
        if out.engines[1].usable {
            assert_eq!(out.recommended_engine, Some(EngineKind::Native));
        } else {
            assert!(out.problem.is_some());
        }
    }

    #[test]
    fn libraries_name_the_native_engine_whether_or_not_it_is_ready() {
        let a = super::probe_binary(&bare(), &corpus("lib/bin/kr-x86.lib")).unwrap();
        assert_eq!(a.format, BinaryFormat::Archive);
        assert_eq!(a.description, "Windows static library with 2 objects");
        assert_eq!(a.recommended_engine, Some(EngineKind::Native));
        assert!(
            a.recommended_reason
                .contains("only the native engine opens"),
            "{}",
            a.recommended_reason
        );
        if !a.engines[1].usable {
            assert!(
                a.problem
                    .as_deref()
                    .is_some_and(|p| p.contains("native engine is not ready"))
            );
        }
        let o = super::probe_binary(&bare(), &corpus("lib/bin/kr-x64.obj")).unwrap();
        assert_eq!(o.format, BinaryFormat::Coff);
        assert_eq!(o.bits, Some(64));
        let want = if o.engines[1].usable {
            EngineKind::Native
        } else {
            EngineKind::Ghidra
        };
        assert_eq!(o.recommended_engine, Some(want));
        let obj = std::fs::read(corpus("lib/bin/kr-x64.obj")).unwrap();
        assert!(super::fit_of_header(&obj).is_ok());
        assert!(super::fit_of_header(b"!<arch>\nrest").is_ok());
        assert_eq!(super::native_only(&corpus("lib/bin/kr.o")), None);
        assert!(super::native_only(&corpus("lib/bin/libkr.a")).is_some());
    }

    #[test]
    fn pe_dotnet_and_text_files_get_the_right_engine() {
        let pe =
            super::probe_binary(&bare(), &corpus("pe/bin/win_tls-x64-O2-stripped.exe")).unwrap();
        assert_eq!(pe.format, BinaryFormat::Pe);
        assert_eq!(pe.arch.as_deref(), Some("x86-64"));
        if pe.engines[1].usable {
            assert_eq!(pe.recommended_engine, Some(EngineKind::Native));
        } else {
            assert_eq!(pe.recommended_engine, Some(EngineKind::Ghidra));
            assert!(pe.recommended_reason.contains("auto picked Ghidra"));
        }

        let net = super::probe_binary(&bare(), &corpus("dotnet/bin/kraken-corpus.dll")).unwrap();
        assert_eq!(net.format, BinaryFormat::Dotnet);
        assert_eq!(net.recommended_engine, Some(EngineKind::Dotnet));
        assert!(net.recommended_reason.contains("kraken setup --dotnet"));

        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("readme.txt");
        std::fs::write(&txt, "hello").unwrap();
        let t = super::probe_binary(&bare(), &txt).unwrap();
        assert_eq!(t.format, BinaryFormat::Unknown);
        assert!(!t.supported);
    }
}
