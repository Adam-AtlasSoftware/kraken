//! ELF loading with the `object` crate: segments for the decompiler's image, sections for the
//! memory map, function symbols, PLT stubs and the entry point. Addresses follow Ghidra's
//! convention so anchors stay compatible with Ghidra projects: a position-independent image whose
//! lowest address is 0 is loaded at 0x100000 (0x10000 for 32-bit x86).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::elf::{
    PF_W, ProgramFlags, R_386_IRELATIVE, R_386_JMP_SLOT, R_AARCH64_IRELATIVE, R_ARM_IRELATIVE,
    R_RISCV_IRELATIVE, R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE,
    SectionFlags as ElfSectionFlags,
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
    /// RISC-V's global pointer (`__global_pointer$`, which `gp` holds), after rebasing.
    pub global_pointer: Option<u64>,
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
        self.blocks
            .iter()
            .any(|b| b.name.starts_with(".plt") && b.start.0 <= addr && addr < b.end.0)
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

/// The program header table of a little-endian ELF file, in file order (the numbering Ghidra's
/// `segment_<n>.<m>` blocks use).
fn program_headers(data: &[u8]) -> Vec<ProgramHeader> {
    let word = |at: usize, n: usize| -> Option<u64> {
        let b = data.get(at..at.checked_add(n)?)?;
        Some(b.iter().rev().fold(0u64, |a, x| a << 8 | u64::from(*x)))
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

/// Splits a writable segment so the part inside `[lo, hi)` (the RELRO range) is read-only.
fn split_relro(seg: Segment, lo: u64, hi: u64) -> Vec<Segment> {
    let end = seg.start + seg.mem_size;
    let (cut_lo, cut_hi) = (lo.max(seg.start), hi.min(end));
    if cut_lo >= cut_hi {
        return vec![seg];
    }
    let piece = |from: u64, to: u64, readonly: bool| Segment {
        start: from,
        data: seg
            .data
            .get((from - seg.start) as usize..(to - seg.start).min(seg.data.len() as u64) as usize)
            .unwrap_or(&[])
            .to_vec(),
        mem_size: to - from,
        readonly,
    };
    let mut out = Vec::new();
    if seg.start < cut_lo {
        out.push(piece(seg.start, cut_lo, false));
    }
    out.push(piece(cut_lo, cut_hi, true));
    if cut_hi < end {
        out.push(piece(cut_hi, end, false));
    }
    out
}

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
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
    if file.endianness() != Endianness::Little {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            "big-endian ELF is not supported by the native engine yet",
        ));
    }
    let language = language(file.architecture())?;
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

    let phdrs = program_headers(data);
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
        match relro {
            Some((lo, hi)) if !whole.readonly => segments.extend(split_relro(whole, lo, hi)),
            _ => segments.push(whole),
        }
    }
    segments.sort_by_key(|s| s.start);
    let mut image = Image {
        segments,
        context: Vec::new(),
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
                sh_flags.contains(SHF_WRITE) && !in_relro,
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
                    // headers are never code, whatever the segment says
                    false,
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

    let mut init_pointers = Vec::new();
    let mut default_names: BTreeMap<u64, String> = BTreeMap::new();
    // REL relocations (32-bit x86) keep the addend in the slot
    let slot_word = |off: u64| -> i64 {
        let mut buf = vec![0u8; ptr];
        if image.read(at(off), &mut buf) {
            le_word(&buf) as i64
        } else {
            0
        }
    };
    let relative: BTreeMap<u64, i64> = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .filter(|(_, r)| matches!(r.target(), RelocationTarget::Absolute))
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
            let mut v = le_word(chunk);
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
            let (tag, val) = (le_word(&e[..ptr]), le_word(&e[ptr..]));
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
                let v = le_word(chunk);
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
    pointer_slots.sort_unstable();

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
            let v = le_word(&buf);
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
    let global_pointer = file
        .symbols()
        .chain(file.dynamic_symbols())
        .find(|s| s.name() == Ok("__global_pointer$"))
        .map(|s| at(s.address()));
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
        format: "elf",
        container: "elf",
        description: description.into(),
        members: Vec::new(),
        language,
        base,
        image,
        blocks,
        functions,
        code_symbols,
        data_symbols,
        debug,
        plt,
        import_slots: BTreeMap::new(),
        externals: BTreeMap::new(),
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

/// A little-endian word of up to 8 bytes.
pub(crate) fn le_word(b: &[u8]) -> u64 {
    let n = b.len().min(8);
    let mut w = [0u8; 8];
    w[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(w)
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
    let irelative = match file.architecture() {
        Architecture::X86_64 => R_X86_64_IRELATIVE,
        Architecture::I386 => R_386_IRELATIVE,
        Architecture::Arm => R_ARM_IRELATIVE,
        Architecture::Aarch64 => R_AARCH64_IRELATIVE,
        Architecture::Riscv32 | Architecture::Riscv64 => R_RISCV_IRELATIVE,
        _ => return BTreeMap::new(),
    };
    let arm = file.architecture() == Architecture::Arm;
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
            let word = |i: usize| le_word(&r[i * ptr..(i + 1) * ptr]);
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
                        b.get(at..at + ptr).map(le_word)
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
        _ => risc_plt(file, data, bias, &slots, ptr),
    }
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
        assert!(got.is_some_and(|s| s.readonly));
        let data = l
            .image
            .segments
            .iter()
            .find(|s| s.start <= 0x104010 && 0x104010 < s.start + s.mem_size);
        assert!(data.is_some_and(|s| !s.readonly));
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
