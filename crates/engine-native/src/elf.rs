//! ELF loading with the `object` crate: segments for the decompiler's image, sections for the
//! memory map, function symbols, PLT stubs and the entry point. Addresses follow Ghidra's
//! convention so anchors stay compatible with Ghidra projects: a position-independent image whose
//! lowest address is 0 is loaded at 0x100000 (0x10000 for 32-bit x86).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::elf::{
    PF_W, PF_X, ProgramFlags, R_386_IRELATIVE, R_386_JMP_SLOT, R_AARCH64_IRELATIVE,
    R_ARM_IRELATIVE, R_RISCV_IRELATIVE, R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT, SHF_ALLOC,
    SHF_EXECINSTR, SHF_WRITE, SectionFlags as ElfSectionFlags,
};
use object::read::{Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable};
use object::{
    Architecture, BinaryFormat, Endianness, ObjectKind, RelocationFlags, RelocationTarget,
    SectionFlags, SectionKind, SegmentFlags, SymbolKind,
};

/// Ghidra's default image base for 64-bit ELF objects linked at 0.
pub const PIE_BASE: u64 = 0x10_0000;
/// Ghidra's default image base for 32-bit ELF objects linked at 0.
pub const PIE_BASE_32: u64 = 0x1_0000;

/// The byte order of a program's data and code words.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Endian {
    /// Least significant byte first.
    #[default]
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// The unsigned word of up to 8 bytes in `b`.
    pub fn word(self, b: &[u8]) -> u64 {
        let b = &b[..b.len().min(8)];
        let fold = |a: u64, x: &u8| a << 8 | u64::from(*x);
        match self {
            Endian::Little => b.iter().rev().fold(0, fold),
            Endian::Big => b.iter().fold(0, fold),
        }
    }

    /// The low `out.len()` bytes of `v`, in this order.
    pub fn write(self, v: u64, out: &mut [u8]) {
        let n = out.len().min(8);
        match self {
            Endian::Little => out[..n].copy_from_slice(&v.to_le_bytes()[..n]),
            Endian::Big => out[..n].copy_from_slice(&v.to_be_bytes()[8 - n..]),
        }
    }

    /// The order of a file by whether it is big-endian.
    pub fn from_big(big: bool) -> Endian {
        if big { Endian::Big } else { Endian::Little }
    }

    /// The `object` crate's name for this order.
    pub fn of_file(file: &object::File<'_>) -> Endian {
        match file.endianness() {
            Endianness::Little => Endian::Little,
            Endianness::Big => Endian::Big,
        }
    }

    /// gimli's name for this order.
    pub fn gimli(self) -> gimli::RunTimeEndian {
        match self {
            Endian::Little => gimli::RunTimeEndian::Little,
            Endian::Big => gimli::RunTimeEndian::Big,
        }
    }
}

/// Sleigh language and compiler spec for a supported architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Language {
    /// Language id such as `x86:LE:64:default`.
    pub id: &'static str,
    /// Compiler spec id such as `gcc`.
    pub compiler: &'static str,
    /// Pointer size in bytes.
    pub pointer_size: u32,
}

/// A symbol naming code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSymbol {
    /// Address after rebasing.
    pub addr: u64,
    /// Name as in the symbol table.
    pub name: String,
}

/// A symbol the program imports from a shared library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSymbol {
    /// Name as in the dynamic symbol table, or the PE import's name (`Ordinal_<n>` for an
    /// import by ordinal, as Ghidra names them).
    pub name: String,
    /// Function (`STT_FUNC` and untyped symbols, as Ghidra treats them) or data.
    pub kind: ProtoSymbolKind,
    /// The library a PE import comes from (`KERNEL32.DLL`); ELF does not say.
    pub library: Option<String>,
}

/// A symbol other modules can see (global or weak, defined).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSymbol {
    /// Name as in the symbol table.
    pub name: String,
    /// From the symbol type: function, data object or anything else.
    pub kind: ProtoSymbolKind,
    /// The archive member that defines it (a static library); `None` elsewhere.
    pub member: Option<String>,
}

/// Everything the engine needs from the file.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The family the code follows: `elf`, or `pe` for Windows code (PE images and COFF
    /// objects).
    pub format: &'static str,
    /// The file's own format: `elf`, `pe`, `coff` (an object file) or `ar` (an archive).
    pub container: &'static str,
    /// What the file is, in plain words (`Linux shared library`).
    pub description: String,
    /// The members of an archive, in file order; empty for other files.
    pub members: Vec<String>,
    /// Language for Sleigh and the decompiler.
    pub language: Language,
    /// Byte order of the program's words.
    pub endian: Endian,
    /// Image base (0 or [`PIE_BASE`]).
    pub base: u64,
    /// Bytes the decompiler and disassembler read.
    pub image: Image,
    /// Memory map ordered by start.
    pub blocks: Vec<MemoryBlock>,
    /// Defined function symbols (static and dynamic), by address; first name wins. Names are
    /// as in the symbol table (mangled for C++).
    pub functions: BTreeMap<u64, String>,
    /// Every name of a defined function symbol, by address, in symbol-table order.
    pub code_symbols: BTreeMap<u64, Vec<String>>,
    /// Types and function prototypes from DWARF, with the function addresses rebased.
    pub debug: crate::dwarf::Debug,
    /// PLT stubs (ELF) and import thunks (PE: a `jmp [IAT slot]`), by address, named after the
    /// imported symbol.
    pub plt: BTreeMap<u64, String>,
    /// PE import address table slots, by address, with the import each one holds. The loaded
    /// image holds [`Loaded::externals`] addresses in them, so a `call [slot]` reaches a named
    /// function in the decompiler.
    pub import_slots: BTreeMap<u64, String>,
    /// Synthetic addresses past the image that stand for imported functions (Ghidra's
    /// `EXTERNAL` block), by address; not mapped memory.
    pub externals: BTreeMap<u64, String>,
    /// Function starts from the PE exception directory (`.pdata`), ascending; like FDE starts
    /// they cover stripped binaries.
    pub pdata_starts: Vec<u64>,
    /// The value 32-bit x86 position-independent code keeps in its PIC register (`ebx` after
    /// `call __x86.get_pc_thunk.bx; add ebx, ...`): the start of `.got.plt` (else `.got`),
    /// after rebasing. PLT entries address through it.
    pub pic_base: Option<u64>,
    /// Calling conventions known for functions, by entry: from x86 COFF decorations
    /// (`_f@12` is `__stdcall`, `@f@8` `__fastcall`) and from the library prototypes applied.
    pub conventions: BTreeMap<u64, String>,
    /// Entry point after rebasing, if any.
    pub entry: Option<u64>,
    /// Function pointers from `.init_array`, `.fini_array` and `.preinit_array`, and the start
    /// of `.plt` (the resolver stub).
    pub init_pointers: Vec<u64>,
    /// Ranges of the ELF segments mapped executable, which may hold more than the code (MIPS and
    /// PowerPC linkers put `.rodata` in the text segment).
    pub exec_segments: Vec<(u64, u64)>,
    /// Pointer-sized values in data that may point at code: relative-relocation addends and, for
    /// images without them, aligned words of the data sections. Weak function candidates.
    pub data_pointers: Vec<u64>,
    /// Pointers stored in the image that the loader relocates: (slot, target) after rebasing,
    /// ordered by slot. These are the data references of the image.
    pub pointer_slots: Vec<(u64, u64)>,
    /// Imported symbols ordered by name.
    pub imports: Vec<ImportSymbol>,
    /// Exported symbols by address (one per address: functions before data, global before weak).
    pub exports: BTreeMap<u64, ExportSymbol>,
    /// Start of every `.eh_frame` FDE (and on ARM every `.ARM.exidx` entry) after rebasing,
    /// ascending.
    pub fde_starts: Vec<u64>,
    /// Exception landing pads after rebasing, by the start of the FDE whose LSDA lists them.
    pub landing_pads: BTreeMap<u64, Vec<u64>>,
    /// Code the GOT slots of imported functions point at before binding (the lazy PLT entries),
    /// after rebasing. Reached only through data, it belongs to no function.
    pub got_code: Vec<u64>,
    /// Names for functions without a symbol, as Ghidra gives them: `_DT_INIT`, `_DT_FINI`,
    /// `_INIT_<n>`, `_FINI_<n>`.
    pub default_names: BTreeMap<u64, String>,
    /// The global pointer `gp` holds, after rebasing: RISC-V's `__global_pointer$`, MIPS' `_gp`.
    pub global_pointer: Option<u64>,
    /// PowerPC's small-data bases: (register number, value), `r13` from `_SDA_BASE_` and `r2`
    /// from `_SDA2_BASE_` (32-bit) or `.TOC.` (64-bit).
    pub small_data: Vec<(u8, u64)>,
    /// Defined object symbols (variables) by address, for the decompiler's global scope.
    pub data_symbols: BTreeMap<u64, DataSymbol>,
}

/// A variable the symbol table names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol {
    pub name: String,
    /// `st_size`; zero when unknown.
    pub size: u64,
}

impl Loaded {
    /// The size the decompiler gives the variable at `at`: the symbol's, else (COFF symbols carry
    /// none) the room before the next named variable, at most four bytes, a power of two and aligned.
    pub fn data_size(&self, at: u64) -> u64 {
        if let Some(n) = self
            .data_symbols
            .get(&at)
            .map(|s| s.size)
            .filter(|n| *n > 0)
        {
            return n.min(4096);
        }
        let next = self
            .data_symbols
            .range(at + 1..)
            .map(|(a, _)| *a)
            .chain(self.debug.globals.range(at + 1..).map(|(a, _)| *a))
            .min();
        let block_end = self
            .blocks
            .iter()
            .find(|b| b.start.0 <= at && at < b.end.0)
            .map(|b| b.end.0);
        let room = [next, block_end]
            .into_iter()
            .flatten()
            .min()
            .map_or(1, |e| e - at);
        let size = match room {
            0 | 1 => 1,
            2 | 3 => 2,
            _ => 4,
        };
        size.min(1 << at.trailing_zeros().min(2))
    }

    /// Whether `addr` lies in an executable, initialized block.
    pub fn is_code(&self, addr: u64) -> bool {
        self.blocks
            .iter()
            .any(|b| b.initialized && b.perms.ends_with('x') && b.start.0 <= addr && addr < b.end.0)
    }

    /// Pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        self.language.pointer_size as usize
    }

    /// The C data model: ILP32 on 32-bit targets, LLP64 for 64-bit Windows, else LP64.
    pub fn data_model(&self) -> crate::ctypes::DataModel {
        use crate::ctypes::DataModel;
        match (self.language.pointer_size, self.format) {
            (4, _) => DataModel::ILP32,
            (_, "pe") => DataModel::LLP64,
            _ => DataModel::LP64,
        }
    }

    /// Whether this is a Windows (PE) image.
    pub fn is_pe(&self) -> bool {
        self.format == "pe"
    }

    /// Whether this is 32-bit ARM code, where a code address with the low bit set means Thumb.
    pub fn is_arm(&self) -> bool {
        self.language.id.starts_with("ARM:")
    }

    /// Whether this is MIPS code (32 or 64 bit, either byte order).
    pub fn is_mips(&self) -> bool {
        self.language.id.starts_with("MIPS:")
    }

    /// Whether the code at `addr` decodes as Thumb (ARM only).
    pub fn is_thumb(&self, addr: u64) -> bool {
        self.is_arm() && crate::arm::is_thumb(&self.image.context, addr)
    }

    /// A code pointer as an instruction address: ARM's Thumb bit is cleared where the even
    /// address is code.
    pub fn code_address(&self, addr: u64) -> u64 {
        if self.is_arm() && addr & 1 == 1 && self.is_code(addr & !1) {
            addr & !1
        } else {
            addr
        }
    }

    /// The prefix of the default function name (`FUN_`), as Ghidra writes it: RISC-V images,
    /// which have more than one memory space, name the space too (`FUN_ram_`).
    pub fn default_prefix(&self) -> &'static str {
        if self.language.id.starts_with("RISCV:") {
            "FUN_ram_"
        } else {
            "FUN_"
        }
    }

    /// Whether `addr` lies in a PLT section.
    pub fn in_plt(&self, addr: u64) -> bool {
        self.blocks.iter().any(|b| {
            (b.name.starts_with(".plt") || b.name == ".MIPS.stubs")
                && b.start.0 <= addr
                && addr < b.end.0
        })
    }
}

const PT_LOAD: u32 = 1;
const PT_GNU_RELRO: u32 = 0x6474_e552;

struct ProgramHeader {
    kind: u32,
    flags: u32,
    vaddr: u64,
    memsz: u64,
}

/// The program header table of an ELF file, in file order (the numbering Ghidra's
/// `segment_<n>.<m>` blocks use).
fn program_headers(data: &[u8], endian: Endian) -> Vec<ProgramHeader> {
    let word = |at: usize, n: usize| -> Option<u64> {
        let b = data.get(at..at.checked_add(n)?)?;
        Some(endian.word(b))
    };
    let is64 = data.get(4) == Some(&2);
    let (phoff, entsize, num) = if is64 {
        (word(0x20, 8), word(0x36, 2), word(0x38, 2))
    } else {
        (word(0x1c, 4), word(0x2a, 2), word(0x2c, 2))
    };
    let (Some(phoff), Some(entsize), Some(num)) = (phoff, entsize, num) else {
        return Vec::new();
    };
    (0..num)
        .map_while(|i| {
            let at = (phoff + i * entsize) as usize;
            Some(if is64 {
                ProgramHeader {
                    kind: word(at, 4)? as u32,
                    flags: word(at + 4, 4)? as u32,
                    vaddr: word(at + 16, 8)?,
                    memsz: word(at + 40, 8)?,
                }
            } else {
                ProgramHeader {
                    kind: word(at, 4)? as u32,
                    vaddr: word(at + 8, 4)?,
                    memsz: word(at + 20, 4)?,
                    flags: word(at + 24, 4)? as u32,
                }
            })
        })
        .collect()
}

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// The language of an ELF file: its machine and byte order, and for MIPS the architecture
/// level and ABI in `e_flags`.
fn elf_language(file: &object::File<'_>) -> Result<Language, ProtoError> {
    const EF_MIPS_ABI2: u32 = 0x20;
    const EF_MIPS_ARCH: u32 = 0xf000_0000;
    const EF_MIPS_ARCH_32R6: u32 = 0x9000_0000;
    let flags = match file.flags() {
        object::FileFlags::Elf { e_flags, .. } => e_flags.0,
        _ => 0,
    };
    let big = file.endianness() == Endianness::Big;
    let pick = |be: &'static str, le: &'static str, pointer_size| Language {
        id: if big { be } else { le },
        compiler: "default",
        pointer_size,
    };
    match file.architecture() {
        Architecture::Mips if flags & EF_MIPS_ARCH == EF_MIPS_ARCH_32R6 => {
            Ok(pick("MIPS:BE:32:R6", "MIPS:LE:32:R6", 4))
        }
        Architecture::Mips => Ok(pick("MIPS:BE:32:default", "MIPS:LE:32:default", 4)),
        Architecture::Mips64 if flags & EF_MIPS_ABI2 != 0 => {
            Ok(pick("MIPS:BE:64:64-32addr", "MIPS:LE:64:64-32addr", 4))
        }
        Architecture::Mips64 => Ok(pick("MIPS:BE:64:default", "MIPS:LE:64:default", 8)),
        Architecture::PowerPc => Ok(pick("PowerPC:BE:32:default", "PowerPC:LE:32:default", 4)),
        Architecture::PowerPc64 => Ok(pick("PowerPC:BE:64:default", "PowerPC:LE:64:default", 8)),
        arch if big => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("big-endian {arch:?} is not supported by the native engine yet"),
        )),
        arch => language(arch),
    }
}

pub(crate) fn language(arch: Architecture) -> Result<Language, ProtoError> {
    match arch {
        Architecture::X86_64 => Ok(Language {
            id: "x86:LE:64:default",
            compiler: "gcc",
            pointer_size: 8,
        }),
        Architecture::I386 => Ok(Language {
            id: "x86:LE:32:default",
            compiler: "gcc",
            pointer_size: 4,
        }),
        Architecture::Aarch64 => Ok(Language {
            id: "AARCH64:LE:64:v8A",
            compiler: "default",
            pointer_size: 8,
        }),
        // A32 and Thumb in one language; `TMode` tells them apart
        Architecture::Arm => Ok(Language {
            id: "ARM:LE:32:v8",
            compiler: "default",
            pointer_size: 4,
        }),
        Architecture::Riscv64 => Ok(Language {
            id: "RISCV:LE:64:default",
            compiler: "gcc",
            pointer_size: 8,
        }),
        // Ghidra's opinion file leaves RV32 open between `default` and `AndeStar_v5` (a
        // superset with Andes' custom instructions) and its loader takes the latter; standard
        // RV32 code (rv32imac) decodes the same in both, and `default` has no vendor opcodes to
        // mistake data for
        Architecture::Riscv32 => Ok(Language {
            id: "RISCV:LE:32:default",
            compiler: "gcc",
            pointer_size: 4,
        }),
        other => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("architecture {other:?} is not supported by the native engine yet"),
        )),
    }
}

/// Parses an ELF or PE file, a relocatable object (ELF or COFF) or an archive of them. Other
/// formats are `unsupported`. Objects and archives are laid out at Ghidra's base and take no
/// `base_override`.
pub fn load(data: &[u8], base_override: Option<u64>) -> Result<Loaded, ProtoError> {
    load_with(data, base_override, None)
}

/// [`load`] with the contents of the program's separate debug file (`crate::debugfile`), whose
/// DWARF is used when the program has none of its own.
pub fn load_with(
    data: &[u8],
    base_override: Option<u64>,
    external_debug: Option<&[u8]>,
) -> Result<Loaded, ProtoError> {
    if crate::objfile::handles(data) {
        return crate::objfile::load(data);
    }
    let file = object::File::parse(data).map_err(|e| bad(format!("cannot parse binary: {e}")))?;
    if file.format() == BinaryFormat::Pe {
        return crate::pe::load_with(data, base_override, external_debug);
    }
    if file.format() != BinaryFormat::Elf {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "{:?} binaries are not supported by the native engine yet",
                file.format()
            ),
        ));
    }
    let endian = Endian::of_file(&file);
    let language = elf_language(&file)?;
    let ptr = language.pointer_size as usize;

    let lowest = file
        .segments()
        .filter(|s| s.size() > 0)
        .map(|s| s.address())
        .min()
        .unwrap_or(0);
    let default_base = if matches!(file.kind(), ObjectKind::Dynamic) && lowest == 0 {
        if ptr == 4 { PIE_BASE_32 } else { PIE_BASE }
    } else {
        lowest
    };
    let base = base_override.unwrap_or(default_base);
    let bias = base.wrapping_sub(lowest);
    let at = |a: u64| a.wrapping_add(bias);

    let phdrs = program_headers(data, endian);
    let relro = phdrs
        .iter()
        .find(|h| h.kind == PT_GNU_RELRO && h.memsz > 0)
        .map(|h| (at(h.vaddr), at(h.vaddr + h.memsz)));
    let mut segments = Vec::new();
    for seg in file.segments() {
        if seg.size() == 0 {
            continue;
        }
        let flags = match seg.flags() {
            SegmentFlags::Elf { p_flags, .. } => p_flags,
            _ => ProgramFlags(0),
        };
        let bytes = seg.data().map_err(|e| bad(format!("bad segment: {e}")))?;
        let whole = Segment {
            start: at(seg.address()),
            data: bytes.to_vec(),
            mem_size: seg.size().max(bytes.len() as u64),
            readonly: !flags.contains(PF_W),
        };
        // RELRO stays writable here, unlike its blocks: the GOT slots of imports hold 0, not
        // Ghidra's EXTERNAL addresses, so folding them would drop code a weak import guards
        segments.push(whole);
    }
    segments.sort_by_key(|s| s.start);
    let mut image = Image {
        segments,
        context: Vec::new(),
        entry_registers: Vec::new(),
    };
    let arm = language.id.starts_with("ARM:");

    let mut blocks = Vec::new();
    for sec in file.sections() {
        let sh_flags = match sec.flags() {
            SectionFlags::Elf { sh_flags, .. } => sh_flags,
            _ => ElfSectionFlags(0),
        };
        // Ghidra gives .tbss no block: its range overlaps the sections that follow it
        if !sh_flags.contains(SHF_ALLOC)
            || sec.size() == 0
            || sec.kind() == SectionKind::UninitializedTls
        {
            continue;
        }
        let name = sec.name().unwrap_or("").to_string();
        // Ghidra's MIPS loader marks the GOT constant
        let mips_got = file_is_mips(&file) && name == ".got";
        // the loader makes the RELRO range read-only once it has relocated it
        let in_relro =
            relro.is_some_and(|(lo, hi)| lo <= at(sec.address()) && at(sec.address()) < hi);
        blocks.push(MemoryBlock {
            name: if name.is_empty() {
                format!("section_{:x}", sec.address())
            } else {
                name
            },
            space: "ram".into(),
            start: at(sec.address()).into(),
            end: at(sec.address() + sec.size()).into(),
            perms: MemoryBlock::perms_string(
                true,
                sh_flags.contains(SHF_WRITE) && !in_relro && !mips_got,
                sh_flags.contains(SHF_EXECINSTR),
            ),
            initialized: sec.kind() != SectionKind::UninitializedData,
            kind: MemoryKind::Default,
        });
    }
    // Ghidra fills the part of a loaded segment that lies before its first section
    for (i, h) in phdrs.iter().enumerate() {
        if h.kind != PT_LOAD || h.memsz == 0 {
            continue;
        }
        let (lo, hi) = (at(h.vaddr), at(h.vaddr + h.memsz));
        let first = blocks
            .iter()
            .map(|b| b.start.0)
            .filter(|s| (lo..hi).contains(s))
            .min()
            .unwrap_or(hi);
        if first > lo {
            blocks.push(MemoryBlock {
                name: format!("segment_{i}.1"),
                space: "ram".into(),
                start: lo.into(),
                end: first.into(),
                perms: MemoryBlock::perms_string(
                    true,
                    ProgramFlags(h.flags).contains(PF_W),
                    // the gap before the first section holds headers, never code; a
                    // segment with no section at all (sstrip'd or packed) keeps PF_X
                    first == hi && ProgramFlags(h.flags).contains(PF_X),
                ),
                initialized: true,
                kind: MemoryKind::Default,
            });
        }
    }
    blocks.sort_by_key(|b| (b.start, b.end));
    let exec: Vec<(u64, u64)> = blocks
        .iter()
        .filter(|b| b.initialized && b.perms.ends_with('x'))
        .map(|b| (b.start.0, b.end.0))
        .collect();
    let in_exec = |a: u64| exec.iter().any(|(s, e)| *s <= a && a < *e);
    // ARM: a code address with the low bit set is Thumb code at the even address
    let mut seeds: Vec<crate::arm::Seed> = Vec::new();
    let mut code_at = |a: u64, rank: u8| -> u64 {
        if !arm || !in_exec(a & !1) {
            return a;
        }
        seeds.push(crate::arm::Seed {
            rank,
            addr: a & !1,
            thumb: a & 1 == 1,
        });
        a & !1
    };

    let mut functions = BTreeMap::new();
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut mapping: Vec<(u64, crate::arm::Mapping)> = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if arm
            && sym.kind() == SymbolKind::Unknown
            && sym.is_local()
            && let Some(m) = sym.name().ok().and_then(crate::arm::mapping_kind)
        {
            mapping.push((at(sym.address()), m));
            continue;
        }
        if sym.kind() != SymbolKind::Text || !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let addr = code_at(at(sym.address()), crate::arm::rank::SYMBOL);
        functions.entry(addr).or_insert_with(|| name.to_string());
        let names = code_symbols.entry(addr).or_default();
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    let mut debug = crate::dwarf::parse(&file);
    if debug.functions.is_empty()
        && let Some(ext) = external_debug
        && let Ok(f) = object::File::parse(ext)
    {
        debug = crate::dwarf::parse(&f);
    }
    debug.functions = std::mem::take(&mut debug.functions)
        .into_iter()
        .map(|(a, f)| (at(a), f))
        .collect();
    debug.globals = std::mem::take(&mut debug.globals)
        .into_iter()
        .map(|(a, g)| (at(a), g))
        .collect();
    let mut data_symbols: BTreeMap<u64, DataSymbol> = BTreeMap::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.kind() != SymbolKind::Data || !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        let name = name.split('@').next().unwrap_or(name);
        if name.is_empty() || name.starts_with('$') || name.starts_with('.') {
            continue;
        }
        data_symbols
            .entry(at(sym.address()))
            .or_insert_with(|| DataSymbol {
                name: name.to_string(),
                size: sym.size(),
            });
    }

    let plt = plt_entries(&file, data, bias, &functions, ptr);
    for a in plt.keys() {
        // PLT entries are A32 code
        if arm {
            code_at(*a, crate::arm::rank::KNOWN);
        }
    }

    let entry = (file.entry() != 0).then(|| code_at(at(file.entry()), crate::arm::rank::SYMBOL));

    let exec_segments = phdrs
        .iter()
        .filter(|h| h.kind == PT_LOAD && ProgramFlags(h.flags).contains(PF_X))
        .map(|h| (at(h.vaddr), at(h.vaddr + h.memsz)))
        .collect();
    let mut init_pointers = Vec::new();
    let mut default_names: BTreeMap<u64, String> = BTreeMap::new();
    // REL relocations (32-bit x86) keep the addend in the slot
    let slot_word = |off: u64| -> i64 {
        let mut buf = vec![0u8; ptr];
        if image.read(at(off), &mut buf) {
            endian.word(&buf) as i64
        } else {
            0
        }
    };
    let relative: BTreeMap<u64, i64> = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .filter(|(_, r)| matches!(r.target(), RelocationTarget::Absolute))
        // (MIPS `.rel.dyn` starts with an empty entry)
        .filter(|(_, r)| !matches!(r.flags(), RelocationFlags::Elf { r_type } if r_type.0 == 0))
        .map(|(off, r)| {
            let addend = if r.has_implicit_addend() {
                slot_word(off)
            } else {
                r.addend()
            };
            (off, addend)
        })
        .collect();
    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !matches!(name, ".init_array" | ".fini_array" | ".preinit_array") {
            continue;
        }
        let Ok(bytes) = sec.data() else { continue };
        let prefix = match name {
            ".init_array" => "_INIT_",
            ".fini_array" => "_FINI_",
            _ => "_PREINIT_",
        };
        let all_ones = if ptr == 4 { 0xffff_ffff } else { u64::MAX };
        for (i, chunk) in bytes.chunks_exact(ptr).enumerate() {
            let slot = sec.address() + (i * ptr) as u64;
            let mut v = endian.word(chunk);
            if v == 0 {
                v = relative.get(&slot).map(|a| *a as u64).unwrap_or(0);
            }
            if v != 0 && v != all_ones {
                let v = code_at(at(v), crate::arm::rank::KNOWN);
                init_pointers.push(v);
                // Ghidra names the targets only of pointers a relocation produced, which a
                // fixed-address executable has none of
                if file.kind() != ObjectKind::Executable {
                    default_names
                        .entry(v)
                        .or_insert_with(|| format!("{prefix}{i}"));
                }
            }
        }
    }
    // DT_INIT and DT_FINI of the dynamic section
    if let Some(dynamic) = file.section_by_name(".dynamic")
        && let Ok(bytes) = dynamic.data()
    {
        for e in bytes.chunks_exact(2 * ptr) {
            let (tag, val) = (endian.word(&e[..ptr]), endian.word(&e[ptr..]));
            let name = match tag {
                12 => "_DT_INIT",
                13 => "_DT_FINI",
                0 => break,
                _ => continue,
            };
            if val != 0 {
                let val = code_at(at(val), crate::arm::rank::KNOWN);
                init_pointers.push(val);
                default_names.entry(val).or_insert_with(|| name.into());
            }
        }
    }

    if let Some(plt) = file.section_by_name(".plt")
        && plt.size() > 0
    {
        init_pointers.push(at(plt.address()));
    }

    // odd code pointers are Thumb functions; even ones may be A32 functions, or not code at all
    let pointer_rank = |a: u64| {
        if a & 1 == 1 {
            crate::arm::rank::POINTER
        } else {
            crate::arm::rank::WEAK
        }
    };
    let mut data_pointers: Vec<u64> = relative
        .values()
        .map(|a| at(*a as u64))
        .map(|a| code_at(a, pointer_rank(a)))
        .collect();
    // a static RISC executable (no dynamic section) has its final pointers in place, IRELATIVE
    // slots aside; its code reaches them through the GOT, where x86 code names them directly
    let static_risc = !language.id.starts_with("x86") && file.section_by_name(".dynamic").is_none();
    if relative.is_empty() || static_risc {
        for sec in file.sections() {
            let sh_flags = match sec.flags() {
                SectionFlags::Elf { sh_flags, .. } => sh_flags,
                _ => ElfSectionFlags(0),
            };
            let alloc = sh_flags.contains(SHF_ALLOC);
            let exec = sh_flags.contains(SHF_EXECINSTR);
            if !alloc || exec || sec.kind() == SectionKind::UninitializedData {
                continue;
            }
            let Ok(bytes) = sec.data() else { continue };
            let skip = (sec.address() % ptr as u64) as usize;
            for chunk in bytes.get(skip..).unwrap_or_default().chunks_exact(ptr) {
                let v = endian.word(chunk);
                if v != 0 {
                    // these are guesses, and so are the modes they suggest (a walk that does
                    // not look like code drops an even one)
                    let a = at(v);
                    let a = code_at(a, pointer_rank(a));
                    data_pointers.push(a);
                }
            }
        }
    }
    data_pointers.sort_unstable();
    data_pointers.dedup();

    let mut pointer_slots: Vec<(u64, u64)> = relative
        .iter()
        .filter(|(_, a)| **a != 0)
        .map(|(slot, a)| {
            let t = at(*a as u64);
            let t = if arm && in_exec(t & !1) { t & !1 } else { t };
            (at(*slot), t)
        })
        .collect();
    // RISC code loads the addresses of its data through GOT slots that name a symbol of the
    // image itself (a copy-relocated `stderr`, a protected global): the slot holds it
    if !language.id.starts_with("x86")
        && let Some(dynsyms) = file.dynamic_symbol_table()
    {
        for (off, r) in file.dynamic_relocations().into_iter().flatten() {
            let RelocationTarget::Symbol(idx) = r.target() else {
                continue;
            };
            let Ok(sym) = dynsyms.symbol_by_index(idx) else {
                continue;
            };
            let jump_slot = matches!(r.flags(), RelocationFlags::Elf { r_type }
                if matches!(r_type.0, 5 | 22 | 1026));
            if !sym.is_definition() || sym.address() == 0 || jump_slot {
                continue;
            }
            let addend = if r.has_implicit_addend() {
                0
            } else {
                r.addend()
            };
            let t = at(sym.address()).wrapping_add_signed(addend);
            let t = if arm && in_exec(t & !1) { t & !1 } else { t };
            pointer_slots.push((at(off), t));
        }
    }
    let mips = file_is_mips(&file);
    let ppc = matches!(
        file.architecture(),
        Architecture::PowerPc | Architecture::PowerPc64
    );
    // MIPS and PowerPC code reaches its imports through the GOT, so the slots get the addresses
    // of Ghidra's EXTERNAL block: one word per undefined dynamic symbol, in table order
    let mut externals: BTreeMap<u64, String> = BTreeMap::new();
    if mips || ppc {
        let top = blocks.iter().map(|b| b.end.0).max().unwrap_or(0);
        let start = top.div_ceil(0x1000) * 0x1000;
        let undefined = file
            .dynamic_symbols()
            .filter(|s| s.is_undefined())
            .filter_map(|s| s.name().ok().filter(|n| !n.is_empty()));
        for (i, name) in undefined.enumerate() {
            externals.insert(start + (i * ptr) as u64, name.to_string());
        }
        let external = |name: &str| externals.iter().find(|(_, n)| *n == name).map(|(a, _)| *a);
        if mips {
            for (slot, value) in mips_got_slots(&file, endian, ptr) {
                let value = match value {
                    GotValue::Image(v) => Some(at(v)),
                    GotValue::Import(n) => external(&n),
                };
                pointer_slots.extend(value.map(|v| (at(slot), v)));
            }
        }
        if let Some(dynsyms) = file.dynamic_symbol_table() {
            for (off, r) in file.dynamic_relocations().into_iter().flatten() {
                let RelocationTarget::Symbol(idx) = r.target() else {
                    continue;
                };
                let name = dynsyms
                    .symbol_by_index(idx)
                    .ok()
                    .filter(|s| s.is_undefined());
                let slot = name.and_then(|s| external(s.name().ok()?));
                if !matches!(r.flags(), RelocationFlags::Elf { r_type } if r_type.0 == 21) {
                    pointer_slots.extend(slot.map(|v| (at(off), v)));
                }
            }
        }
    }
    pointer_slots.sort_unstable();
    pointer_slots.dedup_by_key(|(s, _)| *s);
    // the decompiler reads what the loader leaves in the image: PowerPC's `.got2` and MIPS' GOT
    if mips || ppc {
        for (slot, value) in &pointer_slots {
            let mut w = vec![0u8; ptr];
            endian.write(*value, &mut w);
            image.write(*slot, &w);
        }
    }
    // only constant slots fold into named targets in the decompiler: Ghidra's MIPS loader marks
    // the GOT constant, and on PowerPC `.got2` is RELRO
    if mips || ppc {
        let name = if mips { ".got" } else { ".got2" };
        let section = file
            .section_by_name(name)
            .map(|s| (at(s.address()), at(s.address() + s.size())));
        for (lo, hi) in section.into_iter().chain(relro.filter(|_| ppc)) {
            keep_constant(&mut image, lo, hi);
        }
    }

    let mut imports: Vec<ImportSymbol> = file
        .dynamic_symbols()
        .filter(|s| s.is_undefined())
        .filter_map(|s| {
            let name = s.name().ok().filter(|n| !n.is_empty())?;
            let kind = match s.kind() {
                SymbolKind::Data | SymbolKind::Tls => ProtoSymbolKind::Data,
                _ => ProtoSymbolKind::Function,
            };
            Some(ImportSymbol {
                name: name.to_string(),
                kind,
                library: None,
            })
        })
        .collect();
    imports.sort_by(|a, b| a.name.cmp(&b.name));
    imports.dedup_by(|a, b| a.name == b.name);

    // exported addresses come from global and weak definitions; the name shown for an address
    // is its first symbol of any binding in symbol-table order, which is the label Ghidra makes
    // primary (locals come first, and the linker turns hidden globals into locals)
    let mut exported: BTreeSet<u64> = BTreeSet::new();
    let mut best: BTreeMap<u64, ExportSymbol> = BTreeMap::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let kind = match sym.kind() {
            SymbolKind::Text => ProtoSymbolKind::Function,
            SymbolKind::Data | SymbolKind::Tls => ProtoSymbolKind::Data,
            SymbolKind::Unknown => ProtoSymbolKind::Other,
            _ => continue,
        };
        let Ok(name) = sym.name() else { continue };
        // `stderr@GLIBC_2.2.5` (a copy-relocated import) is shown as `stderr`
        let name = name.split('@').next().unwrap_or(name);
        if name.is_empty() || name.starts_with('$') {
            continue;
        }
        let addr = at(sym.address());
        let addr = if arm && kind == ProtoSymbolKind::Function {
            addr & !1
        } else {
            addr
        };
        if !sym.is_local() {
            exported.insert(addr);
        }
        // a typed symbol (function or object) wins over an untyped one at the same address
        let typed = kind != ProtoSymbolKind::Other;
        match best.get(&addr) {
            Some(e) if typed <= (e.kind != ProtoSymbolKind::Other) => {}
            _ => {
                best.insert(
                    addr,
                    ExportSymbol {
                        name: name.to_string(),
                        kind,
                        member: None,
                    },
                );
            }
        }
    }
    let exports = best
        .into_iter()
        .filter(|(a, _)| exported.contains(a))
        .collect();

    // lazy binding: a GOT slot of an imported function first holds the address of code in the
    // PLT that pushes the slot index and jumps to the resolver
    let mut got_code: Vec<u64> = Vec::new();
    let jump_slot = if ptr == 4 {
        R_386_JMP_SLOT
    } else {
        R_X86_64_JUMP_SLOT
    };
    for (off, rel) in file.dynamic_relocations().into_iter().flatten() {
        if !matches!(rel.flags(), RelocationFlags::Elf { r_type } if r_type == jump_slot)
            || !language.id.starts_with("x86")
        {
            continue;
        }
        let mut buf = vec![0u8; ptr];
        if image.read(at(off), &mut buf) {
            let v = endian.word(&buf);
            if v != 0 {
                got_code.push(at(v));
            }
        }
    }
    got_code.sort_unstable();
    got_code.dedup();

    let frames = match file.section_by_name(".eh_frame") {
        Some(sec) => {
            let bytes = sec.data().unwrap_or_default();
            let read = |a: u64, n: usize| -> Option<Vec<u8>> {
                let mut buf = vec![0u8; n];
                image.read(at(a), &mut buf).then_some(buf)
            };
            crate::eh::parse(&crate::eh::Sections {
                eh_frame: (sec.address(), bytes),
                text: file.section_by_name(".text").map(|s| s.address()),
                got: file
                    .section_by_name(".got.plt")
                    .or_else(|| file.section_by_name(".got"))
                    .map(|s| s.address()),
                read: &read,
                address_size: ptr as u8,
                endian,
            })
        }
        None => crate::eh::Frames::default(),
    };
    let mut fde_starts: Vec<u64> = frames.fde_starts.iter().map(|a| at(*a)).collect();
    if arm {
        fde_starts.extend(exidx_starts(&file).into_iter().map(|a| at(a) & !1));
        fde_starts.sort_unstable();
        fde_starts.dedup();
    }
    if arm {
        image.context = if mapping
            .iter()
            .any(|(a, m)| *m != crate::arm::Mapping::Data && in_exec(*a))
        {
            crate::arm::paint_mapping(&mapping, &exec)
        } else {
            let noreturn: BTreeSet<u64> = functions
                .iter()
                .chain(&plt)
                .filter(|(_, n)| crate::discover::NORETURN.contains(&n.as_str()))
                .map(|(a, _)| *a)
                .collect();
            let walked = crate::arm::Modes::new(&image, exec.clone(), noreturn).walk(seeds);
            crate::arm::paint(&walked, &exec)
        };
    }
    let landing_pads = frames
        .landing_pads
        .iter()
        .map(|(f, pads)| (at(*f), pads.iter().map(|p| at(*p)).collect()))
        .collect();

    let interp = file.section_by_name(".interp").is_some();
    let description = match file.kind() {
        ObjectKind::Dynamic if !interp => "Linux shared library",
        ObjectKind::Core => "Linux core dump",
        _ if !interp => "Linux program (statically linked)",
        _ => "Linux program",
    };
    let named = |want: &str| {
        file.symbols()
            .chain(file.dynamic_symbols())
            .find(|s| s.name() == Ok(want))
            .map(|s| at(s.address()))
    };
    let global_pointer = if mips {
        mips_gp(&file, endian).map(at).or_else(|| named("_gp"))
    } else {
        named("__global_pointer$")
    };
    let small_data: Vec<(u8, u64)> = if file.architecture() == Architecture::PowerPc {
        [(13, named("_SDA_BASE_")), (2, named("_SDA2_BASE_"))]
            .into_iter()
            .filter_map(|(r, v)| Some((r, v?)))
            .collect()
    } else if file.architecture() == Architecture::PowerPc64 {
        named(".TOC.").map(|t| (2, t)).into_iter().collect()
    } else {
        Vec::new()
    };
    // what every function may assume on entry: functions that do not set the global pointer up
    // themselves use the one the program's start-up code left
    if mips {
        image
            .entry_registers
            .extend(global_pointer.map(|gp| ("gp".to_string(), gp)));
    }
    image
        .entry_registers
        .extend(small_data.iter().map(|(r, v)| (format!("r{r}"), *v)));
    // Ghidra stands the imported symbols up as one pointer-sized slot each in an EXTERNAL block on
    // the next page after the image
    if !imports.is_empty() {
        let top = blocks.iter().map(|b| b.end.0).max().unwrap_or(0);
        let start = top.div_ceil(0x1000) * 0x1000;
        blocks.push(MemoryBlock {
            name: "EXTERNAL".into(),
            space: "ram".into(),
            start: start.into(),
            end: (start + (imports.len() * ptr) as u64).into(),
            perms: "rw-".into(),
            initialized: false,
            kind: MemoryKind::External,
        });
    }
    Ok(Loaded {
        global_pointer,
        small_data,
        format: "elf",
        container: "elf",
        description: description.into(),
        members: Vec::new(),
        language,
        endian,
        base,
        image,
        blocks,
        functions,
        code_symbols,
        data_symbols,
        debug,
        plt,
        import_slots: BTreeMap::new(),
        externals,
        pdata_starts: Vec::new(),
        conventions: BTreeMap::new(),
        pic_base: (ptr == 4)
            .then(|| {
                file.section_by_name(".got.plt")
                    .or_else(|| file.section_by_name(".got"))
                    .map(|s| at(s.address()))
            })
            .flatten(),
        entry,
        exec_segments,
        init_pointers,
        data_pointers,
        pointer_slots,
        imports,
        exports,
        fde_starts,
        landing_pads,
        got_code,
        default_names,
    })
}

/// The entries of `.plt`, `.plt.sec`, `.plt.got` and `.iplt`, named after the symbol of the GOT
/// slot each one jumps through (see [`x86_plt`] and [`risc_plt`]). In a static binary the slots
/// carry IRELATIVE relocations instead, and an entry is named after the IFUNC symbol at the
/// relocation's resolver (as Ghidra names them), or `FUN_<address>`.
fn plt_entries(
    file: &object::File<'_>,
    data: &[u8],
    bias: u64,
    functions: &BTreeMap<u64, String>,
    ptr: usize,
) -> BTreeMap<u64, String> {
    if file_is_mips(file) {
        return mips_stubs(file, bias);
    }
    let irelative = match file.architecture() {
        Architecture::PowerPc => object::elf::R_PPC_IRELATIVE,
        Architecture::X86_64 => R_X86_64_IRELATIVE,
        Architecture::I386 => R_386_IRELATIVE,
        Architecture::Arm => R_ARM_IRELATIVE,
        Architecture::Aarch64 => R_AARCH64_IRELATIVE,
        Architecture::Riscv32 | Architecture::Riscv64 => R_RISCV_IRELATIVE,
        _ => return BTreeMap::new(),
    };
    let arm = file.architecture() == Architecture::Arm;
    let endian = Endian::of_file(file);
    let ifuncs = ifunc_names(file, bias);
    let mut slots: BTreeMap<u64, Option<String>> = BTreeMap::new();
    let dynsyms = file.dynamic_symbol_table();
    for (off, rel) in file.dynamic_relocations().into_iter().flatten() {
        let RelocationTarget::Symbol(idx) = rel.target() else {
            continue;
        };
        let Some(name) = dynsyms
            .as_ref()
            .and_then(|t| t.symbol_by_index(idx).ok())
            .and_then(|s| s.name().ok().map(str::to_string))
        else {
            continue;
        };
        if !name.is_empty() {
            slots.insert(off, Some(name));
        }
    }
    for sec in file.sections() {
        let (rela, irelative) = match sec.name() {
            Ok(".rela.plt" | ".rela.iplt") => (true, irelative),
            Ok(".rel.plt" | ".rel.iplt") => (false, irelative),
            _ => continue,
        };
        let Ok(bytes) = sec.data() else { continue };
        let size = if rela { 3 * ptr } else { 2 * ptr };
        for r in bytes.chunks_exact(size) {
            let word = |i: usize| endian.word(&r[i * ptr..(i + 1) * ptr]);
            // the relocation type is the low byte of a 32-bit r_info, the low word of a 64-bit one
            let mask = if ptr == 4 { 0xff } else { 0xffff_ffff };
            if word(1) & mask != u64::from(irelative.0) {
                continue;
            }
            // REL keeps the resolver in the slot
            let resolver = if rela {
                word(2)
            } else {
                file.sections()
                    .find_map(|s| {
                        let (lo, hi) = (s.address(), s.address() + s.size());
                        if !(lo..hi).contains(&word(0)) {
                            return None;
                        }
                        let b = file_bytes(data, &s)?;
                        let at = (word(0) - lo) as usize;
                        b.get(at..at + ptr).map(|w| endian.word(w))
                    })
                    .unwrap_or(0)
            }
            .wrapping_add(bias);
            // a Thumb resolver has the low bit set
            let resolver = if arm { resolver & !1 } else { resolver };
            slots.entry(word(0)).or_insert_with(|| {
                ifuncs
                    .get(&resolver)
                    .or_else(|| functions.get(&resolver))
                    .cloned()
                    .or_else(|| Some(format!("thunk_FUN_{resolver:08x}")))
            });
        }
    }
    match file.architecture() {
        Architecture::X86_64 | Architecture::I386 => x86_plt(file, data, bias, &slots, ptr),
        Architecture::PowerPc => ppc_stubs(file, data, bias, &slots),
        _ => risc_plt(file, data, bias, &slots, ptr),
    }
}

fn file_is_mips(file: &object::File<'_>) -> bool {
    matches!(
        file.architecture(),
        Architecture::Mips | Architecture::Mips64
    )
}

/// The value of a tag of the `.dynamic` section.
fn dynamic_tag(file: &object::File<'_>, endian: Endian, ptr: usize, tag: u64) -> Option<u64> {
    let bytes = file.section_by_name(".dynamic")?.data().ok()?;
    bytes
        .chunks_exact(2 * ptr)
        .find_map(|e| (endian.word(&e[..ptr]) == tag).then(|| endian.word(&e[ptr..])))
}

/// The lazy stubs of a MIPS image, named after their imports: an undefined dynamic function
/// symbol with a value is the address of its stub.
fn mips_stubs(file: &object::File<'_>, bias: u64) -> BTreeMap<u64, String> {
    file.dynamic_symbols()
        .filter(|s| s.is_undefined() && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok()?;
            Some((s.address().wrapping_add(bias), name.to_string()))
        })
        .collect()
}

/// The global pointer of a MIPS image at link time: `ri_gp_value` of `.reginfo`, else the GOT's
/// address plus the 0x7ff0 the ABI fixes.
fn mips_gp(file: &object::File<'_>, endian: Endian) -> Option<u64> {
    let reginfo = file
        .section_by_name(".reginfo")
        .and_then(|s| s.data().ok()?.get(20..24).map(|b| endian.word(b)))
        .filter(|v| *v != 0);
    reginfo.or_else(|| Some(file.section_by_name(".got")?.address() + 0x7ff0))
}

/// What a GOT slot holds once the program runs.
enum GotValue {
    /// An address in the image, at link time.
    Image(u64),
    /// The address of the named import.
    Import(String),
}

/// What the dynamic linker puts in the GOT of a MIPS image, as (slot, value) at link time. There
/// are no relocations for it: after the two reserved entries `DT_MIPS_LOCAL_GOTNO` slots hold
/// addresses in the image, and one slot follows per dynamic symbol from `DT_MIPS_GOTSYM`, which
/// gets the symbol's value (a stub's address for an undefined function that has one).
fn mips_got_slots(file: &object::File<'_>, endian: Endian, ptr: usize) -> Vec<(u64, GotValue)> {
    const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
    const DT_MIPS_SYMTABNO: u64 = 0x7000_0011;
    const DT_MIPS_GOTSYM: u64 = 0x7000_0013;
    const DT_PLTGOT: u64 = 3;
    let tag = |t| dynamic_tag(file, endian, ptr, t);
    let (Some(got), Some(local), Some(gotsym), Some(symtabno)) = (
        tag(DT_PLTGOT),
        tag(DT_MIPS_LOCAL_GOTNO),
        tag(DT_MIPS_GOTSYM),
        tag(DT_MIPS_SYMTABNO),
    ) else {
        return Vec::new();
    };
    let w = ptr as u64;
    let Some(section) = file
        .sections()
        .find(|s| (s.address()..s.address() + s.size()).contains(&got))
    else {
        return Vec::new();
    };
    let Ok(bytes) = section.data() else {
        return Vec::new();
    };
    let slot_value = |i: u64| {
        let off = (got - section.address() + i * w) as usize;
        bytes.get(off..off + ptr).map(|b| endian.word(b))
    };
    let mut out = Vec::new();
    for i in 2..local {
        // (a page entry of an image linked at 0 holds 0)
        if let Some(v) = slot_value(i) {
            out.push((got + i * w, GotValue::Image(v)));
        }
    }
    let Some(table) = file.dynamic_symbol_table() else {
        return out;
    };
    for (n, index) in (gotsym..symtabno).enumerate() {
        let Ok(sym) = table.symbol_by_index(object::SymbolIndex(index as usize)) else {
            continue;
        };
        let slot = got + (local + n as u64) * w;
        if sym.address() != 0 {
            out.push((slot, GotValue::Image(sym.address())));
        } else if let Ok(name) = sym.name() {
            out.push((slot, GotValue::Import(name.to_string())));
        }
    }
    out
}

/// Makes the initialized bytes in `lo..hi` read-only for the decompiler.
fn keep_constant(image: &mut Image, lo: u64, hi: u64) {
    let mut parts = Vec::with_capacity(image.segments.len() + 2);
    for s in std::mem::take(&mut image.segments) {
        let end = s.start + s.mem_size;
        if s.readonly || hi <= s.start || end <= lo || s.start + s.data.len() as u64 <= lo {
            parts.push(s);
            continue;
        }
        let a = (lo.max(s.start) - s.start) as usize;
        let b = ((hi.min(end) - s.start) as usize).min(s.data.len());
        let split_at = s.start + b as u64;
        if a > 0 {
            parts.push(Segment {
                start: s.start,
                data: s.data[..a].to_vec(),
                mem_size: a as u64,
                readonly: false,
            });
        }
        parts.push(Segment {
            start: s.start + a as u64,
            data: s.data[a..b].to_vec(),
            mem_size: (b - a) as u64,
            readonly: true,
        });
        if end > split_at {
            parts.push(Segment {
                start: split_at,
                data: s.data[b..].to_vec(),
                mem_size: end - split_at,
                readonly: false,
            });
        }
    }
    image.segments = parts;
}

/// The values PowerPC position-independent functions put in `r30`: `bcl 20,31,.+4`, then
/// `mflr r30; addis r30,r30,hi; addi r30,r30,lo` among the prologue's instructions.
fn ppc_pic_bases(file: &object::File<'_>, data: &[u8]) -> Vec<u64> {
    const BCL_NEXT: u64 = 0x429f_0005;
    const ADDIS_R30: u64 = 0x3fde;
    const ADDI_R30: u64 = 0x3bde;
    let endian = Endian::of_file(file);
    let mut out = BTreeSet::new();
    for sec in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some(bytes) = file_bytes(data, &sec) else {
            continue;
        };
        let words: Vec<u64> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| endian.word(b))
            .collect();
        for (i, _) in words.iter().enumerate().filter(|(_, w)| **w == BCL_NEXT) {
            let after = &words[i + 1..words.len().min(i + 16)];
            let part = |op: u64| {
                after
                    .iter()
                    .find(|w| *w >> 16 == op)
                    .map(|w| i64::from(*w as u16 as i16))
            };
            if let (Some(hi), Some(lo)) = (part(ADDIS_R30), part(ADDI_R30)) {
                let lr = sec.address() + 4 * (i as u64 + 1);
                out.insert(lr.wrapping_add_signed((hi << 16) + lo) & 0xffff_ffff);
            }
        }
    }
    out.into_iter().collect()
}

/// Names the call stubs of a 32-bit PowerPC image after their `.plt` slots. The linker leaves
/// them in `.text` or `.glink`, and each loads the slot and jumps through `ctr`: `lwz r11,d(r30)`
/// or `addis r11,r30,hi; lwz r11,lo(r11)` in position-independent code (`r30` is the GOT pointer
/// `DT_PPC_GOT`, or the middle of an object's part of `.got2`, which only the functions that
/// set it up tell), `lis r11,hi; lwz r11,lo(r11)` elsewhere.
fn ppc_stubs(
    file: &object::File<'_>,
    data: &[u8],
    bias: u64,
    slots: &BTreeMap<u64, Option<String>>,
) -> BTreeMap<u64, String> {
    const DT_PPC_GOT: u64 = 0x7000_0000;
    const MTCTR_R11: u64 = 0x7d69_03a6;
    const BCTR: u64 = 0x4e80_0420;
    let endian = Endian::of_file(file);
    let mut bases = ppc_pic_bases(file, data);
    bases.extend(dynamic_tag(file, endian, 4, DT_PPC_GOT));
    let lo16 = |w: u64| i64::from(w as u16 as i16);
    // (entry, offset from r30 or the slot's address)
    let mut stubs: Vec<(u64, Result<i64, u64>)> = Vec::new();
    for sec in file.sections() {
        let Ok(".text" | ".glink" | ".iplt" | ".plt") = sec.name() else {
            continue;
        };
        if sec.kind() != SectionKind::Text {
            continue;
        }
        let Some(bytes) = file_bytes(data, &sec) else {
            continue;
        };
        let word = |i: usize| bytes.get(i * 4..i * 4 + 4).map(|b| endian.word(b));
        for i in 0..bytes.len() / 4 {
            let (Some(a), Some(b), Some(c)) = (word(i), word(i + 1), word(i + 2)) else {
                break;
            };
            let at = sec.address() + (i * 4) as u64;
            if a >> 16 == 0x817e && b == MTCTR_R11 && c == BCTR {
                stubs.push((at, Ok(lo16(a))));
            } else if word(i + 3) == Some(BCTR) && c == MTCTR_R11 && b >> 16 == 0x816b {
                let high = lo16(a) << 16;
                match a >> 16 {
                    0x3d7e => stubs.push((at, Ok(high + lo16(b)))),
                    0x3d60 => stubs.push((at, Err((high + lo16(b)) as u64 & 0xffff_ffff))),
                    _ => {}
                }
            }
        }
    }
    let relative = |base: u64, offset: i64| slots.get(&base.wrapping_add_signed(offset));
    // a wrong base only hits a slot by chance: the base that reaches the most slots goes first
    bases.sort_by_key(|b| {
        let hits = stubs
            .iter()
            .filter(|(_, s)| matches!(s, Ok(o) if relative(*b, *o).is_some()));
        std::cmp::Reverse(hits.count())
    });
    let mut out = BTreeMap::new();
    for (at, stub) in stubs {
        let name = match stub {
            Ok(o) => bases.iter().find_map(|b| relative(*b, o)),
            Err(slot) => slots.get(&slot),
        };
        let Some(n) = name else { continue };
        let entry = at.wrapping_add(bias);
        out.insert(
            entry,
            n.clone().unwrap_or_else(|| format!("FUN_{entry:08x}")),
        );
    }
    out
}

/// The name Ghidra gives the IRELATIVE stub of each resolver: of the IFUNC symbols at an address
/// the last one in symbol-table order, preferring those with the fewest leading underscores.
fn ifunc_names(file: &object::File<'_>, bias: u64) -> BTreeMap<u64, String> {
    let mut best: BTreeMap<u64, (usize, String)> = BTreeMap::new();
    for sym in file.symbols() {
        let object::SymbolFlags::Elf { st_info, .. } = sym.flags() else {
            continue;
        };
        let Ok(name) = sym.name() else { continue };
        if st_info.st_type() != object::elf::STT_GNU_IFUNC || name.is_empty() {
            continue;
        }
        let rank = name.len() - name.trim_start_matches('_').len();
        let at = sym.address().wrapping_add(bias);
        if best.get(&at).is_none_or(|(r, _)| rank <= *r) {
            best.insert(at, (rank, name.to_string()));
        }
    }
    best.into_iter().map(|(a, (_, n))| (a, n)).collect()
}

/// The section's bytes as in the file (none for `SHT_NOBITS`).
fn file_bytes<'d>(data: &'d [u8], sec: &object::Section<'d, '_>) -> Option<&'d [u8]> {
    let (foff, fsize) = sec.file_range()?;
    data.get(foff as usize..(foff + fsize) as usize)
}

/// Names ARM, AArch64 and RISC-V PLT entries after their GOT slots (`slots`, by the slot's
/// link-time address): each entry computes its slot's address from its own (see
/// [`crate::arm::arm_plt_slot`] and its siblings). An AArch64 entry with a `bti c` in front
/// starts there.
fn risc_plt(
    file: &object::File<'_>,
    data: &[u8],
    bias: u64,
    slots: &BTreeMap<u64, Option<String>>,
    ptr: usize,
) -> BTreeMap<u64, String> {
    let arch = file.architecture();
    let mut out = BTreeMap::new();
    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
            continue;
        }
        let Some(bytes) = file_bytes(data, &sec) else {
            continue;
        };
        let lo = sec.address();
        let read = |a: u64| -> Option<u32> {
            let off = usize::try_from(a.checked_sub(lo)?).ok()?;
            let b = bytes.get(off..off + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let mut a = lo;
        while a + 4 <= lo + bytes.len() as u64 {
            let (slot, len) = match arch {
                Architecture::Arm => match crate::arm::arm_plt_slot(&read, a) {
                    Some((s, n)) => (Some(s), n),
                    None => (None, 4),
                },
                Architecture::Aarch64 => (crate::arm::aarch64_plt_slot(&read, a), 16),
                _ => (crate::arm::riscv_plt_slot(&read, a, ptr), 16),
            };
            let Some(n) = slot.and_then(|s| slots.get(&s)) else {
                a += 4;
                continue;
            };
            let start =
                if arch == Architecture::Aarch64 && a > lo && read(a - 4) == Some(0xd503_245f) {
                    a - 4
                } else {
                    a
                };
            let entry = start.wrapping_add(bias);
            out.insert(
                entry,
                n.clone().unwrap_or_else(|| format!("FUN_{entry:08x}")),
            );
            a += len;
        }
    }
    out
}

/// The function starts of `.ARM.exidx` (link-time addresses; a Thumb start may carry the low
/// bit): each entry's first word is a 31-bit place-relative offset to the function.
fn exidx_starts(file: &object::File<'_>) -> Vec<u64> {
    let Some(sec) = file.section_by_name(".ARM.exidx") else {
        return Vec::new();
    };
    let Ok(bytes) = sec.data() else {
        return Vec::new();
    };
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let w = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            let off = i64::from(((w << 1) as i32) >> 1);
            (sec.address() + 8 * i as u64).wrapping_add_signed(off) & 0xffff_ffff
        })
        .collect()
}

/// Names x86 PLT entries after the symbol of the GOT slot their indirect `jmp` reads: `jmp
/// [rip+disp32]` on x86-64, `jmp [abs32]` (`ff 25`) or `jmp [ebx+disp32]` (`ff a3`, position
/// independent, relative to `.got.plt`) on 32-bit x86.
fn x86_plt(
    file: &object::File<'_>,
    data: &[u8],
    bias: u64,
    slots: &BTreeMap<u64, Option<String>>,
    ptr: usize,
) -> BTreeMap<u64, String> {
    let got_plt = file
        .section_by_name(".got.plt")
        .or_else(|| file.section_by_name(".got"))
        .map(|s| s.address());
    let mut out = BTreeMap::new();
    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
            continue;
        }
        let Some(bytes) = file_bytes(data, &sec) else {
            continue;
        };
        // every indirect jump through a known slot starts an entry, together with the `bnd`
        // prefix and `endbr64`/`endbr32` in front of it (`.plt.sec`)
        let mut j = 0;
        while j + 6 <= bytes.len() {
            let modrm = bytes[j + 1];
            if bytes[j] != 0xff || !(modrm == 0x25 || (ptr == 4 && modrm == 0xa3)) {
                j += 1;
                continue;
            }
            let mut d = [0u8; 4];
            d.copy_from_slice(&bytes[j + 2..j + 6]);
            let got = match (ptr, modrm) {
                (8, _) => (sec.address() + j as u64 + 6)
                    .wrapping_add_signed(i64::from(i32::from_le_bytes(d))),
                (_, 0x25) => u64::from(u32::from_le_bytes(d)),
                _ => match got_plt {
                    Some(g) => {
                        (g.wrapping_add_signed(i64::from(i32::from_le_bytes(d)))) & 0xffff_ffff
                    }
                    None => {
                        j += 6;
                        continue;
                    }
                },
            };
            if let Some(n) = slots.get(&got) {
                let mut start = j;
                if start >= 1 && bytes[start - 1] == 0xf2 {
                    start -= 1;
                }
                if start >= 4 && matches!(bytes[start - 4..start], [0xf3, 0x0f, 0x1e, 0xfa | 0xfb])
                {
                    start -= 4;
                }
                let entry = (sec.address() + start as u64).wrapping_add(bias);
                out.insert(
                    entry,
                    n.clone().unwrap_or_else(|| format!("FUN_{entry:08x}")),
                );
            }
            j += 6;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/bin")
            .join(name);
        std::fs::read(p).expect("corpus binary")
    }

    fn block<'a>(l: &'a Loaded, name: &str) -> &'a MemoryBlock {
        l.blocks.iter().find(|b| b.name == name).expect(name)
    }

    fn set(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(name);
        std::fs::read(p).expect("corpus binary")
    }

    #[test]
    fn words_read_and_write_in_either_byte_order() {
        assert_eq!(Endian::Little.word(&[1, 2, 3, 4]), 0x0403_0201);
        assert_eq!(Endian::Big.word(&[1, 2, 3, 4]), 0x0102_0304);
        assert_eq!(Endian::Big.word(&[0xff]), 0xff);
        let mut b = [0u8; 4];
        Endian::Big.write(0x1122_3344, &mut b);
        assert_eq!(b, [0x11, 0x22, 0x33, 0x44]);
        Endian::Little.write(0x1122_3344, &mut b);
        assert_eq!(b, [0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn a_big_endian_mips_program_loads_with_its_got_and_stubs() {
        let l = load(&set("mips/bin/switch_vm-mips-O0"), None).expect("load");
        assert_eq!(l.language.id, "MIPS:BE:32:default");
        assert_eq!(l.endian, Endian::Big);
        assert_eq!(l.base, PIE_BASE_32);
        assert_eq!(l.functions.get(&0x1114c).map(String::as_str), Some("main"));
        assert_eq!(l.plt.get(&0x11240).map(String::as_str), Some("printf"));
        // `_gp` is 0x7ff0 past the start of the GOT
        let got = block(&l, ".got");
        assert_eq!(l.global_pointer, Some(got.start.0 + 0x7ff0));
        assert_eq!(got.perms, "r--");
        // a local slot holds a page of the rebased image, an imported function's slot its stub,
        // and the image shows what the dynamic linker leaves there
        let slot = |at: u64| {
            let mut b = [0u8; 4];
            assert!(l.image.read(at, &mut b));
            Endian::Big.word(&b)
        };
        let k = l
            .pointer_slots
            .iter()
            .find(|(_, t)| *t == 0x11240)
            .expect("printf slot");
        assert!(got.start.0 <= k.0 && k.0 < got.end.0);
        assert_eq!(slot(k.0), 0x11240);
        assert!(
            l.pointer_slots
                .iter()
                .any(|(s, t)| *t == PIE_BASE_32 && slot(*s) == *t)
        );
        // the code of an import without a stub goes to Ghidra's EXTERNAL block
        let ext = block(&l, "EXTERNAL");
        assert!(
            l.externals
                .keys()
                .all(|a| ext.start.0 <= *a && *a < ext.end.0)
        );
        assert!(l.externals.values().any(|n| n == "__cxa_finalize"));
    }

    #[test]
    fn powerpc_call_stubs_take_the_names_of_their_plt_slots() {
        let l = load(&set("ppc32/bin/switch_vm-ppc32-O2-stripped"), None).expect("load");
        assert_eq!(l.language.id, "PowerPC:BE:32:default");
        assert_eq!(l.endian, Endian::Big);
        assert_eq!(l.plt.get(&0x10d60).map(String::as_str), Some("printf"));
        assert_eq!(l.plt.get(&0x10db0).map(String::as_str), Some("memset"));
        assert_eq!(
            l.plt.get(&0x10d50).map(String::as_str),
            Some("__libc_start_main")
        );
    }

    #[test]
    fn memory_blocks_match_ghidra() {
        let l = load(&corpus("stripped_calc-O0-stripped"), None).expect("load");
        let seg = block(&l, "segment_2.1");
        assert_eq!((seg.start.0, seg.end.0), (0x100000, 0x100318));
        assert_eq!(seg.perms, "r--");
        // the RELRO range is read-only, including the GOT under BIND_NOW
        for n in [
            ".init_array",
            ".data.rel.ro",
            ".dynamic",
            ".got",
            ".got.plt",
        ] {
            assert_eq!(block(&l, n).perms, "r--", "{n}");
        }
        assert_eq!(block(&l, ".data").perms, "rw-");
        let ext = block(&l, "EXTERNAL");
        assert_eq!((ext.start.0, ext.end.0), (0x105000, 0x105038));
        assert_eq!(ext.kind, MemoryKind::External);
        let got = l
            .image
            .segments
            .iter()
            .find(|s| s.start <= 0x103fb8 && 0x103fb8 < s.start + s.mem_size);
        assert!(got.is_some_and(|s| !s.readonly));
    }

    #[test]
    fn sectionless_elf_keeps_executable_segments() {
        // sstrip'd and packed files have no section headers: the PT_LOAD flags decide
        let mut data = corpus("stripped_calc-O0-stripped");
        data[0x28..0x30].fill(0); // e_shoff
        data[0x3c..0x40].fill(0); // e_shnum, e_shstrndx
        let l = load(&data, None).expect("load");
        let entry = l.entry.expect("entry");
        assert!(
            l.is_code(entry),
            "entry {entry:#x} not in an executable block"
        );
        assert!(
            l.blocks
                .iter()
                .any(|b| b.perms == "r-x" && b.start.0 <= entry && entry < b.end.0)
        );
        assert!(l.blocks.iter().any(|b| b.perms == "r--"));
    }

    #[test]
    fn static_ifunc_stubs_take_the_ifunc_symbol_name() {
        let l = load(&corpus("static_strops-O0"), None).expect("load");
        assert_eq!(l.plt.get(&0x401018).map(String::as_str), Some("strcpy"));
        assert_eq!(l.plt.get(&0x401040).map(String::as_str), Some("rindex"));
        assert!(l.blocks.iter().all(|b| b.name != ".tbss"));
        let s = load(&corpus("static_strops-O0-stripped"), None).expect("load");
        assert_eq!(
            s.plt.get(&0x401018).map(String::as_str),
            Some("thunk_FUN_004174b0")
        );
    }

    #[test]
    fn pie_is_rebased_like_ghidra() {
        let l = load(&corpus("pie_list-O0"), None).expect("load");
        assert_eq!(l.base, PIE_BASE);
        assert_eq!(l.language.id, "x86:LE:64:default");
        assert_eq!(
            l.functions.get(&0x10124e).map(String::as_str),
            Some("cmp_id")
        );
        assert_eq!(l.entry, Some(0x1010a0));
        assert_eq!(l.plt.get(&0x101030).map(String::as_str), Some("free"));
        assert_eq!(
            l.plt.get(&0x101090).map(String::as_str),
            Some("__cxa_finalize")
        );
        let text = l.blocks.iter().find(|b| b.name == ".text").expect(".text");
        assert_eq!((text.start.0, text.end.0), (0x1010a0, 0x1016b7));
        assert_eq!(text.perms, "r-x");
        let bss = l.blocks.iter().find(|b| b.name == ".bss").expect(".bss");
        assert!(!bss.initialized);
        assert!(
            l.init_pointers.contains(&0x101180),
            "{:x?}",
            l.init_pointers
        );
        assert!(l.fde_starts.contains(&0x10124e), "{:x?}", l.fde_starts);
        assert!(
            l.imports
                .iter()
                .any(|i| i.name == "printf" && i.kind == ProtoSymbolKind::Function)
        );
        assert_eq!(
            l.exports.get(&0x1014da).map(|e| e.name.as_str()),
            Some("main")
        );
        assert!(!l.exports.values().any(|e| e.name == "cmp_id"), "static");
        // .init_array holds frame_dummy through a relative relocation
        assert!(l.pointer_slots.iter().any(|(_, t)| *t == 0x101180));
    }

    #[test]
    fn landing_pads_are_found_in_cpp_code() {
        let l = load(&corpus("cpp_shapes-O0"), None).expect("load");
        let pads: usize = l.landing_pads.values().map(Vec::len).sum();
        assert!(pads > 0, "no landing pads in cpp_shapes");
        for (fde, list) in &l.landing_pads {
            assert!(l.fde_starts.contains(fde));
            assert!(list.iter().all(|p| l.is_code(*p)), "{list:x?}");
        }
    }

    #[test]
    fn other_formats_are_unsupported() {
        let e = load(b"MZ\x90\x00not really a pe", None).unwrap_err();
        assert!(matches!(
            e.code,
            ErrorCode::InvalidArgument | ErrorCode::Unsupported
        ));
    }
}
