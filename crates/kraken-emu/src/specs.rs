//! Where the SLEIGH sources come from. icicle compiles a language from its `.slaspec` at start-up,
//! so a spec root must hold the sources, not just compiled `.sla` files. The roots tried are the
//! ones engine-native uses: `KRAKEN_NATIVE_SPECS`, the tree `cargo xtask native-sla` builds, the
//! tree a release ships in `share/kraken/native-sla`, a Ghidra install (`KRAKEN_GHIDRA_HOME`, else the newest under `~/.cache/kraken-dev/ghidra`), plus
//! any the caller adds first. Each architecture takes the first root that has its files (the
//! `native-sla` tree, for one, holds only x86 and AArch64).

use std::path::{Path, PathBuf};

use crate::arch::Arch;
use crate::error::EmuError;

/// The source tag of the pinned Ghidra sources (`cargo xtask native-sla` names its tree after it).
const SOURCE_TAG: &str = "Ghidra_12.2_build";

/// The tree a release ships beside the programs: `share/kraken/native-sla` in the prefix of the
/// running executable, or `native-sla` next to it.
fn bundled() -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let exe = exe.canonicalize().unwrap_or(exe);
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let mut out = vec![dir.join("native-sla")];
    if let Some(prefix) = dir.parent() {
        out.push(prefix.join("share/kraken/native-sla"));
    }
    out.retain(|p| p.join("Ghidra/Processors").is_dir());
    out
}

/// An ordered list of spec roots (each a directory that contains `Ghidra/Processors`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpecRoots {
    roots: Vec<PathBuf>,
}

impl SpecRoots {
    /// Exactly these roots, nothing discovered.
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        SpecRoots {
            roots: roots.into_iter().collect(),
        }
    }

    /// `first` (when given) followed by the discovered roots.
    pub fn discover_with(first: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut roots: Vec<PathBuf> = first.into_iter().collect();
        roots.extend(Self::discover().roots);
        roots.dedup();
        SpecRoots { roots }
    }

    /// The default roots, in order.
    pub fn discover() -> Self {
        let mut roots = Vec::new();
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        if let Some(p) = env("KRAKEN_NATIVE_SPECS") {
            roots.push(p);
        }
        let home = env("HOME");
        if let Some(h) = &home {
            roots.push(h.join(".cache/kraken-dev/native-sla").join(SOURCE_TAG));
        }
        roots.extend(bundled());
        if let Some(p) = env("KRAKEN_GHIDRA_HOME") {
            roots.push(p);
        }
        if let Some(h) = &home
            && let Ok(dir) = std::fs::read_dir(h.join(".cache/kraken-dev/ghidra"))
        {
            let mut kids: Vec<PathBuf> = dir
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join("Ghidra/Processors").is_dir())
                .collect();
            kids.sort();
            roots.extend(kids.into_iter().rev());
        }
        SpecRoots { roots }
    }

    /// The roots, in order.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The `Ghidra/Processors` directory to build `arch` from (for ARM and RISC-V a patched copy,
    /// see [`overlay`]).
    pub fn processors_for(&self, arch: Arch) -> Result<PathBuf, EmuError> {
        let (ldefs, slaspec) = arch.spec_files();
        for r in &self.roots {
            let p = r.join("Ghidra/Processors");
            if has_sources(&p, ldefs, slaspec) {
                return overlay(&p, arch);
            }
        }
        Err(EmuError::NoSpecs {
            arch,
            ldefs,
            tried: if self.roots.is_empty() {
                "(none)".into()
            } else {
                self.roots
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        })
    }

    /// The architectures some root can build.
    pub fn available(&self) -> Vec<Arch> {
        Arch::ALL
            .into_iter()
            .filter(|a| self.processors_for(*a).is_ok())
            .collect()
    }
}

/// Where a RISC-V CSR lives in guest memory under the patched spec (CSR `n` at
/// `RISCV_CSR_BASE + n * XLEN/8`); the emulator maps this range for RISC-V programs.
pub const RISCV_CSR_BASE: u64 = 0xfff0_0000;
/// Bytes of the CSR range (4096 registers of up to 8 bytes).
pub const RISCV_CSR_SIZE: u64 = 0x8000;
/// Marks a directory as an overlay this module wrote.
const OVERLAY_MARK: &str = "KRAKEN-EMU-OVERLAY";

/// One textual patch of a spec file: `from` must occur in the file (else the overlay refuses,
/// so a changed spec is noticed instead of silently mis-emulated).
struct Patch {
    file: &'static str,
    from: &'static str,
    /// When set, the text from `from` up to (not including) `until` is replaced.
    until: Option<&'static str>,
    to: String,
}

/// The patches icicle needs for an architecture's Ghidra spec, and the processor directory they
/// apply to. Empty when the spec builds as it is.
///
/// * RISC-V: the control and status registers live in a second RAM space (`csreg`), which icicle's
///   SLEIGH compiler does not support (one RAM space per language). The named CSRs become
///   ordinary registers and the generic `csr` operand addresses [`RISCV_CSR_BASE`] in RAM.
/// * x86: `CPUID` (see [`X86_CPUID`]).
/// * AArch64: the 32-bit `BFXIL` mask (a constant icicle folds sign-extended).
/// * ARM: the A32 `blx <imm>` operand sets the decoder context of its target to Thumb
///   (`TMode=1; globalset(reloc,TMode)`), which icicle's decoder rejects, so every A32-to-Thumb
///   call faulted. The patch drops it: the instruction still sets `TB`, and icicle picks the
///   decoder context of the target from `TB` (see `machine::ArmEnv`).
fn patches(arch: Arch) -> (&'static str, Vec<Patch>) {
    match arch {
        Arch::Riscv32 | Arch::Riscv64 => (
            "RISCV",
            vec![
                Patch {
                    file: "riscv.reg.sinc",
                    from: "define space csreg type=ram_space size=2 wordsize=$(XLEN);",
                    until: None,
                    to: "# csreg folded away by KRAKEN (icicle supports one ram space)".into(),
                },
                Patch {
                    file: "riscv.reg.sinc",
                    from: "define csreg offset=$(CSR_REG_START) size=$(XLEN) [",
                    until: None,
                    to: "define register offset=0x10000 size=$(XLEN) [".into(),
                },
                Patch {
                    file: "riscv.table.sinc",
                    from: "csr: csr_reg is op2031 [ csr_reg = $(CSR_REG_START) + op2031; ] { export *[csreg]:$(XLEN) csr_reg; }",
                    until: None,
                    to: format!(
                        "csr: csr_reg is op2031 [ csr_reg = {RISCV_CSR_BASE:#x} + op2031 * $(XLEN); ] {{ export *[ram]:$(XLEN) csr_reg; }}"
                    ),
                },
                // `fmv.x.d` and `fmv.x.w` read the source through a pointer into the register
                // space, which icicle cannot load from; read the register directly
                // (`fmv.x.w` sign-extends, as the ISA says).
                Patch {
                    file: "riscv.rv64d.sinc",
                    from: "\tlocal tmpreg:4 = &frs1D;\n\tlocal tmp:8 = *[register]:8 tmpreg;\n\trdL = tmp;",
                    until: None,
                    to: "\trdL = frs1D;".into(),
                },
                Patch {
                    file: "riscv.rv32f.sinc",
                    from: "\tlocal tmpreg:4 = &frs1S;\n\tlocal tmp:4 = *[register]:4 tmpreg;\n\trd = zext(tmp);",
                    until: None,
                    to: "\trd = sext(frs1S);".into(),
                },
            ],
        ),
        Arch::Arm => (
            "ARM",
            vec![Patch {
                file: "ARMinstructions.sinc",
                from: "[ reloc = ((inst_next+4) + (4*addr24) + (2*H24)) & 0xFFFFFFFF; TMode=1; globalset(reloc,TMode); ]",
                until: None,
                to: "[ reloc = ((inst_next+4) + (4*addr24) + (2*H24)) & 0xFFFFFFFF; ]".into(),
            }],
        ),
        Arch::X86 | Arch::X86_64 => (
            "x86",
            vec![Patch {
                file: "ia.sinc",
                from: ":CPUID          is vexMode=0 & byte=0xf; byte=0xa2                  {",
                until: Some(":DAA            is vexMode=0"),
                to: X86_CPUID.into(),
            }],
        ),
        // icicle folds the constant of `0xffffffff >> (32 - width)` as a sign-extended 64-bit
        // value, so the 32-bit BFXIL mask came out all ones and the instruction cleared every
        // bit it should keep (glibc's ld.so lost `l_relocated` that way).
        Arch::Aarch64 => (
            "AARCH64",
            vec![Patch {
                file: "AARCH64base.sinc",
                from: "\tmask:4 = (0xffffffff >> (32 - BFextractWidth32));",
                until: None,
                to: "\tmask:4 = ~(0xffffffff:4 << BFextractWidth32);".into(),
            }],
        ),
    }
}

/// `CPUID` as one user op that returns the four result registers (leaf in `EAX`, sub-leaf in
/// `ECX`), answered by the emulator (`machine::x86_cpuid`). Ghidra's version returns a pointer
/// into memory that does not exist.
const X86_CPUID: &str = ":CPUID          is vexMode=0 & byte=0xf; byte=0xa2                  {
    local info:16 = cpuid(EAX, ECX);
@ifdef IA64
\tRAX = zext(info[0,32]);
\tRBX = zext(info[32,32]);
\tRDX = zext(info[64,32]);
\tRCX = zext(info[96,32]);
@else
\tEAX = info[0,32];
\tEBX = info[32,32];
\tEDX = info[64,32];
\tECX = info[96,32];
@endif
}

";

/// The `Ghidra/Processors` directory to build `arch` from, given the one that has its sources:
/// the same directory when icicle builds the spec as it is, else a patched copy of the
/// processor's `data/languages` in a cache directory keyed by the sources (see [`patches`]). A
/// spec that already has the patches, or an overlay, is used directly.
pub fn overlay(processors: &Path, arch: Arch) -> Result<PathBuf, EmuError> {
    let (dir, patches) = patches(arch);
    if patches.is_empty() || processors.join(OVERLAY_MARK).is_file() {
        return Ok(processors.to_path_buf());
    }
    let src = processors.join(dir).join("data/languages");
    let io = |e: std::io::Error| EmuError::Io(format!("{} spec overlay: {e}", src.display()));
    let mut files: std::collections::BTreeMap<&str, String> = Default::default();
    for p in &patches {
        if !files.contains_key(p.file) {
            files.insert(
                p.file,
                std::fs::read_to_string(src.join(p.file)).map_err(io)?,
            );
        }
    }
    if patches
        .iter()
        .all(|p| !files[p.file].contains(p.from) && files[p.file].contains(p.to.as_str()))
    {
        return Ok(processors.to_path_buf());
    }
    let key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        src.hash(&mut h);
        files.hash(&mut h);
        format!("{dir}-{:016x}", h.finish())
    };
    let mut patched = files.clone();
    for p in &patches {
        let text = patched
            .get_mut(p.file)
            .ok_or_else(|| EmuError::Io("patch".into()))?;
        if !text.contains(p.from) {
            return Err(EmuError::Unsupported(format!(
                "the {dir} spec in {} does not have the shape kraken-emu patches ({}); use the \
                 pinned Ghidra 12.2 sources",
                src.display(),
                p.file
            )));
        }
        match p.until {
            None => *text = text.replace(p.from, &p.to),
            Some(until) => {
                let start = text.find(p.from).unwrap_or(0);
                let end = text[start..]
                    .find(until)
                    .map(|e| start + e)
                    .ok_or_else(|| EmuError::Unsupported(format!("{}: no `{until}`", p.file)))?;
                text.replace_range(start..end, &p.to);
            }
        }
    }
    let base = overlay_cache().join(key);
    let out = base.join("Ghidra/Processors");
    if out.join(OVERLAY_MARK).is_file() {
        return Ok(out);
    }
    let tmp = overlay_cache().join(format!("tmp-{}-{}", std::process::id(), key_suffix()));
    let langs = tmp
        .join("Ghidra/Processors")
        .join(dir)
        .join("data/languages");
    std::fs::create_dir_all(&langs).map_err(io)?;
    for e in std::fs::read_dir(&src).map_err(io)?.flatten() {
        let p = e.path();
        if !p.is_file() || p.extension().is_some_and(|x| x == "sla") {
            continue;
        }
        let name = e.file_name();
        let dst = langs.join(&name);
        match name.to_str().and_then(|n| patched.get(n)) {
            Some(text) => std::fs::write(&dst, text).map_err(io)?,
            None => {
                std::fs::copy(&p, &dst).map_err(io)?;
            }
        }
    }
    std::fs::write(
        tmp.join("Ghidra/Processors").join(OVERLAY_MARK),
        src.display().to_string(),
    )
    .map_err(io)?;
    if let Some(parent) = base.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    // Another process may have won the race; both copies are the same.
    if std::fs::rename(&tmp, &base).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    if out.join(OVERLAY_MARK).is_file() {
        Ok(out)
    } else {
        Err(EmuError::Io(format!(
            "spec overlay missing at {}",
            out.display()
        )))
    }
}

fn key_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// `KRAKEN_EMU_SPEC_CACHE`, else `~/.cache/kraken/emu-specs`, else the temp directory.
fn overlay_cache() -> PathBuf {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_SPEC_CACHE").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        Some(h) => PathBuf::from(h).join(".cache/kraken/emu-specs"),
        None => std::env::temp_dir().join("kraken-emu-specs"),
    }
}

fn has_sources(processors: &Path, ldefs: &str, slaspec: &str) -> bool {
    processors.join(ldefs).is_file() && processors.join(slaspec).is_file()
}
