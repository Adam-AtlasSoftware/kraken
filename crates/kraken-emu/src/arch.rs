//! The architecture model: which CPU a program is for, the SLEIGH language that describes it, its
//! registers for display, and the facts the calling conventions and the Linux layer need.

use serde::{Deserialize, Serialize};

use crate::error::EmuError;

/// A CPU KRAKEN can emulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// 32-bit x86 (i386), cdecl.
    X86,
    /// x86-64, System V AMD64.
    X86_64,
    /// 32-bit ARM, A32 and Thumb-2, AAPCS hard-float (armhf).
    Arm,
    /// AArch64, AAPCS64.
    Aarch64,
    /// RV32 (IMAC is enough for the corpus), ilp32.
    Riscv32,
    /// RV64GC, lp64d.
    Riscv64,
}

impl Arch {
    /// Every architecture.
    pub const ALL: [Arch; 6] = [
        Arch::X86,
        Arch::X86_64,
        Arch::Arm,
        Arch::Aarch64,
        Arch::Riscv32,
        Arch::Riscv64,
    ];

    /// Short stable name (`x86`, `x86_64`, `arm`, `aarch64`, `riscv32`, `riscv64`).
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Aarch64 => "aarch64",
            Arch::Riscv32 => "riscv32",
            Arch::Riscv64 => "riscv64",
        }
    }

    /// Parses [`Arch::name`] (and a few common aliases).
    pub fn from_name(name: &str) -> Option<Arch> {
        Some(match name.to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" | "x86_32" => Arch::X86,
            "x86_64" | "x86-64" | "amd64" | "x64" => Arch::X86_64,
            "arm" | "arm32" | "armhf" | "armv7" | "thumb" => Arch::Arm,
            "aarch64" | "arm64" => Arch::Aarch64,
            "riscv32" | "rv32" => Arch::Riscv32,
            "riscv64" | "rv64" => Arch::Riscv64,
            _ => return None,
        })
    }

    /// Pointer width in bits.
    pub fn bits(self) -> u32 {
        match self {
            Arch::X86 | Arch::Arm | Arch::Riscv32 => 32,
            Arch::X86_64 | Arch::Aarch64 | Arch::Riscv64 => 64,
        }
    }

    /// Pointer size in bytes.
    pub fn ptr_size(self) -> usize {
        self.bits() as usize / 8
    }

    /// Mask of a pointer-sized value.
    pub fn ptr_mask(self) -> u64 {
        if self.bits() == 64 {
            u64::MAX
        } else {
            0xffff_ffff
        }
    }

    /// The architecture of an ELF file (`e_machine` and class); only little-endian files.
    pub fn from_elf(data: &[u8]) -> Result<Arch, EmuError> {
        if data.len() < 20 || &data[0..4] != b"\x7fELF" {
            return Err(EmuError::Image("not an ELF file".into()));
        }
        if data[5] != 1 {
            return Err(EmuError::Unsupported(
                "big-endian ELF files are not emulated".into(),
            ));
        }
        let class64 = data[4] == 2;
        let machine = u16::from_le_bytes([data[18], data[19]]);
        Self::from_elf_machine(machine, class64)
    }

    /// The architecture of an ELF `e_machine` value.
    pub fn from_elf_machine(machine: u16, class64: bool) -> Result<Arch, EmuError> {
        use object::elf;
        Ok(match (machine, class64) {
            (elf::EM_386, false) => Arch::X86,
            (elf::EM_X86_64, true) => Arch::X86_64,
            (elf::EM_ARM, false) => Arch::Arm,
            (elf::EM_AARCH64, true) => Arch::Aarch64,
            (elf::EM_RISCV, false) => Arch::Riscv32,
            (elf::EM_RISCV, true) => Arch::Riscv64,
            _ => {
                return Err(EmuError::Unsupported(format!(
                    "ELF machine {machine} ({}-bit) is not one of the emulated architectures",
                    if class64 { 64 } else { 32 }
                )));
            }
        })
    }

    /// The architecture of a PE image (`IMAGE_FILE_HEADER.Machine`).
    pub fn from_pe_machine(machine: u16) -> Result<Arch, EmuError> {
        use object::pe;
        Ok(match machine {
            pe::IMAGE_FILE_MACHINE_I386 => Arch::X86,
            pe::IMAGE_FILE_MACHINE_AMD64 => Arch::X86_64,
            pe::IMAGE_FILE_MACHINE_ARMNT | pe::IMAGE_FILE_MACHINE_THUMB => Arch::Arm,
            pe::IMAGE_FILE_MACHINE_ARM64 => Arch::Aarch64,
            pe::IMAGE_FILE_MACHINE_RISCV32 => Arch::Riscv32,
            pe::IMAGE_FILE_MACHINE_RISCV64 => Arch::Riscv64,
            other => {
                return Err(EmuError::Unsupported(format!(
                    "PE machine {other:#x} is not one of the emulated architectures"
                )));
            }
        })
    }

    /// The architecture of a program file (ELF or PE).
    pub fn detect(data: &[u8]) -> Result<Arch, EmuError> {
        if data.starts_with(b"\x7fELF") {
            return Self::from_elf(data);
        }
        if data.starts_with(b"MZ") && data.len() >= 0x40 {
            let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if let Some(h) = data.get(off..off + 6)
                && &h[0..4] == b"PE\0\0"
            {
                return Self::from_pe_machine(u16::from_le_bytes([h[4], h[5]]));
            }
        }
        Err(EmuError::Image("neither an ELF nor a PE file".into()))
    }

    /// The architecture of an engine language id (Ghidra's `PROCESSOR:ENDIAN:SIZE:VARIANT`, e.g.
    /// `ARM:LE:32:v8`, `AARCH64:LE:64:v8A`, `RISCV:LE:32:AndeStar_v5`, `x86:LE:64:default`).
    pub fn from_language_id(id: &str) -> Result<Arch, EmuError> {
        let parts: Vec<&str> = id.split(':').collect();
        let (proc_, endian, size) = match parts.as_slice() {
            [p, e, s, ..] => (*p, *e, *s),
            _ => {
                return Err(EmuError::Unsupported(format!(
                    "`{id}` is not a PROCESSOR:ENDIAN:SIZE:VARIANT language id"
                )));
            }
        };
        if endian != "LE" {
            return Err(EmuError::Unsupported(format!(
                "language `{id}`: only little-endian code is emulated"
            )));
        }
        Ok(match (proc_.to_ascii_lowercase().as_str(), size) {
            ("x86", "32") => Arch::X86,
            ("x86", "64") => Arch::X86_64,
            ("arm", "32") => Arch::Arm,
            ("aarch64", "64") => Arch::Aarch64,
            ("riscv", "32") => Arch::Riscv32,
            ("riscv", "64") => Arch::Riscv64,
            _ => {
                return Err(EmuError::Unsupported(format!(
                    "language `{id}` is not one of the emulated architectures"
                )));
            }
        })
    }

    /// The target triple icicle builds its CPU for (it picks the SLEIGH language from it).
    pub(crate) fn icicle_triple(self) -> &'static str {
        match self {
            Arch::X86 => "i686-unknown-linux",
            Arch::X86_64 => "x86_64-unknown-linux",
            Arch::Arm => "arm-unknown-linux-gnueabihf",
            Arch::Aarch64 => "aarch64-unknown-linux",
            Arch::Riscv32 => "riscv32-unknown-linux",
            Arch::Riscv64 => "riscv64-unknown-linux",
        }
    }

    /// The SLEIGH language KRAKEN emulates this architecture with (icicle picks the same one).
    pub fn language_id(self) -> &'static str {
        match self {
            Arch::X86 => "x86:LE:32:default",
            Arch::X86_64 => "x86:LE:64:default",
            Arch::Arm => "ARM:LE:32:v8",
            Arch::Aarch64 => "AARCH64:LE:64:v8A",
            Arch::Riscv32 => "RISCV:LE:32:default",
            Arch::Riscv64 => "RISCV:LE:64:default",
        }
    }

    /// The `.ldefs` file under `Ghidra/Processors`, and the `.slaspec` it names for
    /// [`Arch::language_id`] (both must exist in a spec root).
    pub fn spec_files(self) -> (&'static str, &'static str) {
        match self {
            Arch::X86 => (
                "x86/data/languages/x86.ldefs",
                "x86/data/languages/x86.slaspec",
            ),
            Arch::X86_64 => (
                "x86/data/languages/x86.ldefs",
                "x86/data/languages/x86-64.slaspec",
            ),
            Arch::Arm => (
                "ARM/data/languages/ARM.ldefs",
                "ARM/data/languages/ARM8_le.slaspec",
            ),
            Arch::Aarch64 => (
                "AARCH64/data/languages/AARCH64.ldefs",
                "AARCH64/data/languages/AARCH64.slaspec",
            ),
            Arch::Riscv32 => (
                "RISCV/data/languages/riscv.ldefs",
                "RISCV/data/languages/riscv.ilp32d.slaspec",
            ),
            Arch::Riscv64 => (
                "RISCV/data/languages/riscv.ldefs",
                "RISCV/data/languages/riscv.lp64d.slaspec",
            ),
        }
    }

    /// SLEIGH name of the program counter.
    pub fn pc_reg(self) -> &'static str {
        match self {
            Arch::X86 => "EIP",
            Arch::X86_64 => "RIP",
            Arch::Arm | Arch::Aarch64 | Arch::Riscv32 | Arch::Riscv64 => "pc",
        }
    }

    /// SLEIGH name of the stack pointer.
    pub fn sp_reg(self) -> &'static str {
        match self {
            Arch::X86 => "ESP",
            Arch::X86_64 => "RSP",
            Arch::Arm | Arch::Aarch64 | Arch::Riscv32 | Arch::Riscv64 => "sp",
        }
    }

    /// The register a call leaves its return address in; `None` on x86 (pushed on the stack).
    pub fn link_reg(self) -> Option<&'static str> {
        match self {
            Arch::X86 | Arch::X86_64 => None,
            Arch::Arm => Some("lr"),
            Arch::Aarch64 => Some("x30"),
            Arch::Riscv32 | Arch::Riscv64 => Some("ra"),
        }
    }

    /// The general purpose registers in display order (SLEIGH names).
    pub fn display_regs(self) -> &'static [&'static str] {
        match self {
            Arch::X86 => &[
                "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
            ],
            Arch::X86_64 => &[
                "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
                "R12", "R13", "R14", "R15", "RIP",
            ],
            Arch::Arm => &[
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
                "sp", "lr", "pc", "NG", "ZR", "CY", "OV", "TB",
            ],
            Arch::Aarch64 => &[
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc", "NG", "ZR", "CY", "OV",
            ],
            Arch::Riscv32 | Arch::Riscv64 => &[
                "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
                "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
                "t3", "t4", "t5", "t6", "pc",
            ],
        }
    }

    /// Integer argument registers of the C calling convention (empty for cdecl x86).
    pub fn int_arg_regs(self) -> &'static [&'static str] {
        match self {
            Arch::X86 => &[],
            Arch::X86_64 => &["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
            Arch::Arm => &["r0", "r1", "r2", "r3"],
            Arch::Aarch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            Arch::Riscv32 | Arch::Riscv64 => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        }
    }

    /// Integer result registers (low part first).
    pub fn int_ret_regs(self) -> &'static [&'static str] {
        match self {
            Arch::X86 => &["EAX", "EDX"],
            Arch::X86_64 => &["RAX", "RDX"],
            Arch::Arm => &["r0", "r1"],
            Arch::Aarch64 => &["x0", "x1"],
            Arch::Riscv32 | Arch::Riscv64 => &["a0", "a1"],
        }
    }

    /// Whether the address bit 0 selects an instruction set (ARM/Thumb interworking).
    pub fn has_thumb(self) -> bool {
        self == Arch::Arm
    }

    /// The instruction alignment in bytes (for a sanity check of breakpoint addresses).
    pub fn insn_align(self) -> u64 {
        match self {
            Arch::X86 | Arch::X86_64 => 1,
            Arch::Arm | Arch::Riscv32 | Arch::Riscv64 => 2,
            Arch::Aarch64 => 4,
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_ids_map_to_architectures() {
        let cases = [
            ("ARM:LE:32:v8", Arch::Arm),
            ("ARM:LE:32:v8T", Arch::Arm),
            ("AARCH64:LE:64:v8A", Arch::Aarch64),
            ("RISCV:LE:64:default", Arch::Riscv64),
            ("RISCV:LE:32:AndeStar_v5", Arch::Riscv32),
            ("RISCV:LE:32:default", Arch::Riscv32),
            ("x86:LE:64:default", Arch::X86_64),
            ("x86:LE:32:default", Arch::X86),
        ];
        for (id, want) in cases {
            assert_eq!(Arch::from_language_id(id).expect(id), want, "{id}");
        }
        assert!(Arch::from_language_id("ARM:BE:32:v8").is_err());
        assert!(Arch::from_language_id("MIPS:LE:32:default").is_err());
        assert!(Arch::from_language_id("nonsense").is_err());
    }

    #[test]
    fn names_round_trip() {
        for a in Arch::ALL {
            assert_eq!(Arch::from_name(a.name()), Some(a));
        }
    }
}
