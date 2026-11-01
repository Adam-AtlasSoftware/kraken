//! The types Ghidra's loaders put into a program's data type manager as header markup: the
//! ELF structures of `ElfHeader`/`ElfProgramHeader`/`ElfSectionHeader`/`ElfSymbol`/`ElfDynamic`
//! and the note and `.eh_frame_hdr` structures for ELF, and the DOS header and section header
//! for PE. Names, field names, offsets and sizes are those Ghidra shows (taken from the
//! recorded fixtures), so the listing of types agrees with it.
//!
//! The structures are modelled on Ghidra's `ghidra.app.util.bin.format.elf` and
//! `ghidra.app.util.bin.format.pe` classes (Apache-2.0, (c) the Ghidra authors, NSA Research
//! Directorate); only the layouts are used, no code.
//!
//! As Ghidra does, a structure is registered only when the file has what it describes: `Rela`
//! with a `SHT_RELA` section, `Dyn` with a dynamic section, the symbol structure with a symbol
//! table, the notes and `eh_frame_hdr` with their sections. x86, x86-64, MIPS and PowerPC ELF
//! files are covered; MIPS and PowerPC tag and type enums carry the processor's name and values,
//! and ARM, AArch64 and RISC-V ones are left out.
//! The headers are read with `object`. These types are listed, never given to the decompiler.

use std::collections::BTreeSet;

use kraken_proto::{
    Composite, EnumDef, EnumVariant, Field, Primitive, PrimitiveClass, TypeDef, TypeRef, TypedefDef,
};
use object::Endianness;
use object::read::elf::{ElfFile, FileHeader, SectionHeader};
use object::{Object, ObjectSection, ObjectSymbol};

const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_X86_64: u16 = 62;
const SHT_RELA: u32 = 4;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNAMIC: u32 = 6;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

const DYN_TAGS_MIPS: &[(&str, u64)] = &[
    ("DT_MIPS_RLD_VERSION", 0x70000001),
    ("DT_MIPS_TIME_STAMP", 0x70000002),
    ("DT_MIPS_ICHECKSUM", 0x70000003),
    ("DT_MIPS_IVERSION", 0x70000004),
    ("DT_MIPS_FLAGS", 0x70000005),
    ("DT_MIPS_BASE_ADDRESS", 0x70000006),
    ("DT_MIPS_MSYM", 0x70000007),
    ("DT_MIPS_CONFLICT", 0x70000008),
    ("DT_MIPS_LIBLIST", 0x70000009),
    ("DT_MIPS_LOCAL_GOTNO", 0x7000000a),
    ("DT_MIPS_CONFLICTNO", 0x7000000b),
    ("DT_MIPS_LIBLISTNO", 0x70000010),
    ("DT_MIPS_SYMTABNO", 0x70000011),
    ("DT_MIPS_UNREFEXTNO", 0x70000012),
    ("DT_MIPS_GOTSYM", 0x70000013),
    ("DT_MIPS_HIPAGENO", 0x70000014),
    ("DT_MIPS_RLD_MAP", 0x70000016),
    ("DT_MIPS_DELTA_CLASS", 0x70000017),
    ("DT_MIPS_DELTA_CLASS_NO", 0x70000018),
    ("DT_MIPS_DELTA_INSTANCE", 0x70000019),
    ("DT_MIPS_DELTA_INSTANCE_NO", 0x7000001a),
    ("DT_MIPS_DELTA_RELOC", 0x7000001b),
    ("DT_MIPS_DELTA_RELOC_NO", 0x7000001c),
    ("DT_MIPS_DELTA_SYM", 0x7000001d),
    ("DT_MIPS_DELTA_SYM_NO", 0x7000001e),
    ("DT_MIPS_DELTA_CLASSSYM", 0x70000020),
    ("DT_MIPS_DELTA_CLASSSYM_NO", 0x70000021),
    ("DT_MIPS_CXX_FLAGS", 0x70000022),
    ("DT_MIPS_PIXIE_INIT", 0x70000023),
    ("DT_MIPS_SYMBOL_LIB", 0x70000024),
    ("DT_MIPS_LOCALPAGE_GOTIDX", 0x70000025),
    ("DT_MIPS_LOCAL_GOTIDX", 0x70000026),
    ("DT_MIPS_HIDDEN_GOTIDX", 0x70000027),
    ("DT_MIPS_PROTECTED_GOTIDX", 0x70000028),
    ("DT_MIPS_OPTIONS", 0x70000029),
    ("DT_MIPS_INTERFACE", 0x7000002a),
    ("DT_MIPS_DYNSTR_ALIGN", 0x7000002b),
    ("DT_MIPS_INTERFACE_SIZE", 0x7000002c),
    ("DT_MIPS_RLD_TEXT_RESOLVE_ADDR", 0x7000002d),
    ("DT_MIPS_PERF_SUFFIX", 0x7000002e),
    ("DT_MIPS_COMPACT_SIZE", 0x7000002f),
    ("DT_MIPS_GP_VALUE", 0x70000030),
    ("DT_MIPS_AUX_DYNAMIC", 0x70000031),
    ("DT_MIPS_PLTGOT", 0x70000032),
    ("DT_MIPS_RWPLT", 0x70000034),
    ("DT_MIPS_RLD_MAP_REL", 0x70000035),
];

const DYN_TAGS_PPC: &[(&str, u64)] = &[("DT_PPC_GOT", 0x70000000), ("DT_PPC_OPT", 0x70000001)];

const PROGRAM_HEADER_TYPES_MIPS: &[(&str, u64)] = &[
    ("PT_MIPS_REGINFO", 0x70000000),
    ("PT_MIPS_RTPROC", 0x70000001),
    ("PT_MIPS_OPTIONS", 0x70000002),
    ("PT_MIPS_ABIFLAGS", 0x70000003),
    ("PT_MIPS_PSPREL1", 0x700000a0),
    ("PT_MIPS_PSPREL2", 0x700000a1),
];

const SECTION_HEADER_TYPES_MIPS: &[(&str, u64)] = &[
    ("SHT_MIPS_LIBLIST", 0x70000000),
    ("SHT_MIPS_MSYM", 0x70000001),
    ("SHT_MIPS_CONFLICT", 0x70000002),
    ("SHT_MIPS_GPTAB", 0x70000003),
    ("SHT_MIPS_UCODE", 0x70000004),
    ("SHT_MIPS_DEBUG", 0x70000005),
    ("SHT_MIPS_REGINFO", 0x70000006),
    ("SHT_MIPS_PACKAGE", 0x70000007),
    ("SHT_MIPS_PACKSYM", 0x70000008),
    ("SHT_MIPS_RELD", 0x70000009),
    ("", 0x7000000b),
    ("SHT_MIPS_CONTENT", 0x7000000c),
    ("SHT_MIPS_OPTIONS", 0x7000000d),
    ("SHT_MIPS_SHDR", 0x70000010),
    ("SHT_MIPS_FDESC", 0x70000011),
    ("SHT_MIPS_EXTSYM", 0x70000012),
    ("SHT_MIPS_DENSE", 0x70000013),
    ("SHT_MIPS_PDESC", 0x70000014),
    ("SHT_MIPS_LOCSYM", 0x70000015),
    ("SHT_MIPS_AUXSYM", 0x70000016),
    ("SHT_MIPS_OPTSYM", 0x70000017),
    ("SHT_MIPS_LOCSTR", 0x70000018),
    ("SHT_MIPS_LINE", 0x70000019),
    ("SHT_MIPS_RFDESC", 0x7000001a),
    ("SHT_MIPS_DELTASYM", 0x7000001b),
    ("SHT_MIPS_DELTAINST", 0x7000001c),
    ("SHT_MIPS_DELTACLASS", 0x7000001d),
    ("SHT_MIPS_DWARF", 0x7000001e),
    ("SHT_MIPS_DELTADECL", 0x7000001f),
    ("SHT_MIPS_SYMBOL_LIB", 0x70000020),
    ("SHT_MIPS_EVENTS", 0x70000021),
    ("SHT_MIPS_TRANSLATE", 0x70000022),
    ("SHT_MIPS_PIXIE", 0x70000023),
    ("SHT_MIPS_XLATE", 0x70000024),
    ("SHT_MIPS_XLATE_DEBUG", 0x70000025),
    ("SHT_MIPS_WHIRL", 0x70000026),
    ("SHT_MIPS_EH_REGION", 0x70000027),
    ("SHT_MIPS_XLATE_OLD", 0x70000028),
    ("SHT_MIPS_PDR_EXCEPTION", 0x70000029),
    ("SHT_MIPS_ABIFLAGS", 0x7000002a),
    ("SHT_MIPS_PSPREL", 0x700000a0),
];

const GPR_MASK_MIPS: &[(&str, u64)] = &[
    ("gpr_zero", 0x1),
    ("gpr_at", 0x2),
    ("gpr_v0", 0x4),
    ("gpr_v1", 0x8),
    ("gpr_a0", 0x10),
    ("gpr_a1", 0x20),
    ("gpr_a2", 0x40),
    ("gpr_a3", 0x80),
    ("gpr_t0", 0x100),
    ("gpr_t1", 0x200),
    ("gpr_t2", 0x400),
    ("gpr_t3", 0x800),
    ("gpr_t4", 0x1000),
    ("gpr_t5", 0x2000),
    ("gpr_t6", 0x4000),
    ("gpr_t7", 0x8000),
    ("gpr_s0", 0x10000),
    ("gpr_s1", 0x20000),
    ("gpr_s2", 0x40000),
    ("gpr_s3", 0x80000),
    ("gpr_s4", 0x100000),
    ("gpr_s5", 0x200000),
    ("gpr_s6", 0x400000),
    ("gpr_s7", 0x800000),
    ("gpr_t8", 0x1000000),
    ("gpr_t9", 0x2000000),
    ("gpr_k0", 0x4000000),
    ("gpr_k1", 0x8000000),
    ("gpr_gp", 0x10000000),
    ("gpr_sp", 0x20000000),
    ("gpr_fp", 0x40000000),
    ("gpr_ra", 0x80000000),
];

const DYN_TAGS: &[(&str, u64)] = &[
    ("DT_NULL", 0),
    ("DT_NEEDED", 1),
    ("DT_PLTRELSZ", 2),
    ("DT_PLTGOT", 3),
    ("DT_HASH", 4),
    ("DT_STRTAB", 5),
    ("DT_SYMTAB", 6),
    ("DT_RELA", 7),
    ("DT_RELASZ", 8),
    ("DT_RELAENT", 9),
    ("DT_STRSZ", 10),
    ("DT_SYMENT", 11),
    ("DT_INIT", 12),
    ("DT_FINI", 13),
    ("DT_SONAME", 14),
    ("DT_RPATH", 15),
    ("DT_SYMBOLIC", 16),
    ("DT_REL", 17),
    ("DT_RELSZ", 18),
    ("DT_RELENT", 19),
    ("DT_PLTREL", 20),
    ("DT_DEBUG", 21),
    ("DT_TEXTREL", 22),
    ("DT_JMPREL", 23),
    ("DT_BIND_NOW", 24),
    ("DT_INIT_ARRAY", 25),
    ("DT_FINI_ARRAY", 26),
    ("DT_INIT_ARRAYSZ", 27),
    ("DT_FINI_ARRAYSZ", 28),
    ("DT_RUNPATH", 29),
    ("DT_FLAGS", 30),
    ("DT_PREINIT_ARRAY", 32),
    ("DT_PREINIT_ARRAYSZ", 33),
    ("DT_RELRSZ", 35),
    ("DT_RELR", 36),
    ("DT_RELRENT", 37),
    ("DT_ANDROID_REL", 1610612751),
    ("DT_ANDROID_RELSZ", 1610612752),
    ("DT_ANDROID_RELA", 1610612753),
    ("DT_ANDROID_RELASZ", 1610612754),
    ("DT_ANDROID_RELR", 1879040000),
    ("DT_ANDROID_RELRSZ", 1879040001),
    ("DT_ANDROID_RELRENT", 1879040003),
    ("DT_GNU_PRELINKED", 1879047669),
    ("DT_GNU_CONFLICTSZ", 1879047670),
    ("DT_GNU_LIBLISTSZ", 1879047671),
    ("DT_CHECKSUM", 1879047672),
    ("DT_PLTPADSZ", 1879047673),
    ("DT_MOVEENT", 1879047674),
    ("DT_MOVESZ", 1879047675),
    ("DT_FEATURE_1", 1879047676),
    ("DT_POSFLAG_1", 1879047677),
    ("DT_SYMINSZ", 1879047678),
    ("DT_SYMINENT", 1879047679),
    ("DT_GNU_XHASH", 1879047924),
    ("DT_GNU_HASH", 1879047925),
    ("DT_TLSDESC_PLT", 1879047926),
    ("DT_TLSDESC_GOT", 1879047927),
    ("DT_GNU_CONFLICT", 1879047928),
    ("DT_GNU_LIBLIST", 1879047929),
    ("DT_CONFIG", 1879047930),
    ("DT_DEPAUDIT", 1879047931),
    ("DT_AUDIT", 1879047932),
    ("DT_PLTPAD", 1879047933),
    ("DT_MOVETAB", 1879047934),
    ("DT_SYMINFO", 1879047935),
    ("DT_VERSYM", 1879048176),
    ("DT_RELACOUNT", 1879048185),
    ("DT_RELCOUNT", 1879048186),
    ("DT_FLAGS_1", 1879048187),
    ("DT_VERDEF", 1879048188),
    ("DT_VERDEFNUM", 1879048189),
    ("DT_VERNEED", 1879048190),
    ("DT_VERNEEDNUM", 1879048191),
    ("DT_AUXILIARY", 2147483645),
    ("DT_FILTER", 2147483647),
];
const PROGRAM_HEADER_TYPES: &[(&str, u64)] = &[
    ("PT_NULL", 0),
    ("PT_LOAD", 1),
    ("PT_DYNAMIC", 2),
    ("PT_INTERP", 3),
    ("PT_NOTE", 4),
    ("PT_SHLIB", 5),
    ("PT_PHDR", 6),
    ("PT_TLS", 7),
    ("PT_GNU_EH_FRAME", 1685382480),
    ("PT_GNU_STACK", 1685382481),
    ("PT_GNU_RELRO", 1685382482),
];
const SECTION_HEADER_TYPES: &[(&str, u64)] = &[
    ("SHT_NULL", 0),
    ("SHT_PROGBITS", 1),
    ("SHT_SYMTAB", 2),
    ("SHT_STRTAB", 3),
    ("SHT_RELA", 4),
    ("SHT_HASH", 5),
    ("SHT_DYNAMIC", 6),
    ("SHT_NOTE", 7),
    ("SHT_NOBITS", 8),
    ("SHT_REL", 9),
    ("SHT_SHLIB", 10),
    ("SHT_DYNSYM", 11),
    ("SHT_INIT_ARRAY", 14),
    ("SHT_FINI_ARRAY", 15),
    ("SHT_PREINIT_ARRAY", 16),
    ("SHT_GROUP", 17),
    ("SHT_SYMTAB_SHNDX", 18),
    ("SHT_ANDROID_REL", 1610612737),
    ("SHT_ANDROID_RELA", 1610612738),
    ("SHT_GNU_ATTRIBUTES", 1879048181),
    ("SHT_GNU_HASH", 1879048182),
    ("SHT_GNU_LIBLIST", 1879048183),
    ("SHT_CHECKSUM", 1879048184),
    ("SHT_SUNW_move", 1879048186),
    ("SHT_SUNW_COMDAT", 1879048187),
    ("SHT_SUNW_syminfo", 1879048188),
    ("SHT_GNU_verdef", 1879048189),
    ("SHT_GNU_verneed", 1879048190),
    ("SHT_GNU_versym", 1879048191),
];
const SECTION_FLAGS: &[(&str, u64)] = &[
    ("IMAGE_SCN_TYPE_NO_PAD", 8),
    ("IMAGE_SCN_RESERVED_0001", 16),
    ("IMAGE_SCN_CNT_CODE", 32),
    ("IMAGE_SCN_CNT_INITIALIZED_DATA", 64),
    ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 128),
    ("IMAGE_SCN_LNK_OTHER", 256),
    ("IMAGE_SCN_LNK_INFO", 512),
    ("IMAGE_SCN_RESERVED_0040", 1024),
    ("IMAGE_SCN_LNK_REMOVE", 2048),
    ("IMAGE_SCN_LNK_COMDAT", 4096),
    ("IMAGE_SCN_GPREL", 32768),
    ("IMAGE_SCN_MEM_16BIT", 131072),
    ("IMAGE_SCN_MEM_PURGEABLE", 131072),
    ("IMAGE_SCN_MEM_LOCKED", 262144),
    ("IMAGE_SCN_MEM_PRELOAD", 524288),
    ("IMAGE_SCN_ALIGN_1BYTES", 1048576),
    ("IMAGE_SCN_ALIGN_2BYTES", 2097152),
    ("IMAGE_SCN_ALIGN_4BYTES", 3145728),
    ("IMAGE_SCN_ALIGN_8BYTES", 4194304),
    ("IMAGE_SCN_ALIGN_16BYTES", 5242880),
    ("IMAGE_SCN_ALIGN_32BYTES", 6291456),
    ("IMAGE_SCN_ALIGN_64BYTES", 7340032),
    ("IMAGE_SCN_ALIGN_128BYTES", 8388608),
    ("IMAGE_SCN_ALIGN_256BYTES", 9437184),
    ("IMAGE_SCN_ALIGN_512BYTES", 10485760),
    ("IMAGE_SCN_ALIGN_1024BYTES", 11534336),
    ("IMAGE_SCN_ALIGN_2048BYTES", 12582912),
    ("IMAGE_SCN_ALIGN_4096BYTES", 13631488),
    ("IMAGE_SCN_ALIGN_8192BYTES", 14680064),
    ("IMAGE_SCN_LNK_NRELOC_OVFL", 16777216),
    ("IMAGE_SCN_MEM_DISCARDABLE", 33554432),
    ("IMAGE_SCN_MEM_NOT_CACHED", 67108864),
    ("IMAGE_SCN_MEM_NOT_PAGED", 134217728),
    ("IMAGE_SCN_MEM_SHARED", 268435456),
    ("IMAGE_SCN_MEM_EXECUTE", 536870912),
    ("IMAGE_SCN_MEM_READ", 1073741824),
    ("IMAGE_SCN_MEM_WRITE", 2147483648),
];

fn int(size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class: PrimitiveClass::Int,
        size,
        signed,
    })
}

fn uint(size: u32) -> TypeRef {
    int(size, false)
}

fn named(n: &str) -> TypeRef {
    TypeRef::Named { name: n.into() }
}

fn array(element: TypeRef, count: u64) -> TypeRef {
    TypeRef::Array {
        element: Box::new(element),
        count,
    }
}

fn char1() -> TypeRef {
    TypeRef::Primitive(Primitive {
        class: PrimitiveClass::Char,
        size: 1,
        signed: true,
    })
}

/// A field: name, type and size in bytes.
type Slot = (String, TypeRef, u64);

fn slot(name: &str, ty: TypeRef, size: u64) -> Slot {
    (name.to_string(), ty, size)
}

/// A struct whose fields follow one another from offset 0.
fn packed(name: &str, fields: Vec<Slot>) -> TypeDef {
    let mut at = 0;
    let mut out = Vec::new();
    for (name, ty, size) in fields {
        out.push(Field {
            name,
            offset: at,
            ty,
            bitfield: None,
        });
        at += size;
    }
    TypeDef::Struct(Composite {
        name: name.into(),
        size: at,
        align: 1,
        fields: out,
    })
}

fn enumeration(name: &str, size: u32, variants: &[(&str, u64)]) -> TypeDef {
    TypeDef::Enum(EnumDef {
        name: name.into(),
        size,
        variants: variants
            .iter()
            .map(|(n, v)| EnumVariant {
                name: (*n).into(),
                value: *v as i64,
            })
            .collect(),
    })
}

/// What the markup depends on: the class of the file and the sections it has.
struct ElfFacts {
    is64: bool,
    machine: u16,
    has_program_headers: bool,
    has_section_headers: bool,
    section_types: BTreeSet<u32>,
    section_names: BTreeSet<String>,
    /// The names of the functions the file imports.
    imports: BTreeSet<String>,
    /// `namesz` and `descsz` of the `.note.package` note.
    package_note: Option<(u32, u32)>,
}

fn elf_facts<Elf: FileHeader<Endian = Endianness>>(data: &[u8], is64: bool) -> Option<ElfFacts> {
    let file = ElfFile::<Elf>::parse(data).ok()?;
    let e = file.endian();
    let h = file.elf_header();
    Some(ElfFacts {
        is64,
        machine: h.e_machine(e).0,
        has_program_headers: h.e_phnum(e) > 0,
        has_section_headers: h.e_shnum(e) > 0,
        section_types: file
            .elf_section_table()
            .iter()
            .map(|s| s.sh_type(e).0)
            .collect(),
        section_names: file
            .sections()
            .filter_map(|s| s.name().ok().map(str::to_string))
            .collect(),
        package_note: file
            .section_by_name(".note.package")
            .and_then(|s| s.data().ok())
            .and_then(|b| {
                let word = |at: usize| {
                    b.get(at..at + 4)
                        .map(|w| crate::elf::Endian::from_big(e == Endianness::Big).word(w) as u32)
                };
                Some((word(0)?, word(4)?))
            }),
        imports: object::File::parse(data)
            .map(|o| {
                o.dynamic_symbols()
                    .filter(|s| s.is_undefined())
                    .filter_map(|s| s.name().ok().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// The markup types of the ELF file `data`; none for machines other than x86, MIPS and PowerPC.
fn elf_markup(data: &[u8]) -> Vec<TypeDef> {
    let facts = match data.get(4) {
        Some(1) => elf_facts::<object::elf::FileHeader32<Endianness>>(data, false),
        Some(2) => elf_facts::<object::elf::FileHeader64<Endianness>>(data, true),
        _ => None,
    };
    let Some(f) = facts else {
        return Vec::new();
    };
    if !matches!(f.machine, EM_386 | EM_X86_64 | EM_MIPS | EM_PPC | EM_PPC64) {
        return Vec::new();
    }
    // Ghidra's enums of processor-specific values carry the processor's name
    let suffix = match f.machine {
        EM_MIPS => "_MIPS",
        EM_PPC | EM_PPC64 => "_PPC",
        _ => "",
    };
    let extended = |base: &[(&'static str, u64)], extra: &[(&'static str, u64)]| {
        let mut all: Vec<(&'static str, u64)> = base.to_vec();
        all.extend_from_slice(extra);
        all.sort_by_key(|(_, v)| *v);
        all
    };
    let dyn_extra = match f.machine {
        EM_MIPS => DYN_TAGS_MIPS,
        EM_PPC | EM_PPC64 => DYN_TAGS_PPC,
        _ => &[],
    };
    let (ph_extra, sh_extra) = match f.machine {
        EM_MIPS => (PROGRAM_HEADER_TYPES_MIPS, SECTION_HEADER_TYPES_MIPS),
        _ => (&[][..], &[][..]),
    };
    let w: u32 = if f.is64 { 8 } else { 4 };
    let c = if f.is64 { "Elf64" } else { "Elf32" };
    let word = |n: &str| slot(n, uint(w), u64::from(w));
    let words = |names: &[&str]| -> Vec<Slot> { names.iter().map(|n| word(n)).collect() };
    let u4 = |n: &str| slot(n, uint(4), 4);
    let u2 = |n: &str| slot(n, uint(2), 2);
    let has_type = |t: u32| f.section_types.contains(&t);
    let has_section = |n: &str| f.section_names.contains(n);
    let mut out = Vec::new();

    let mut ehdr = vec![
        slot("e_ident_magic_num", uint(1), 1),
        slot("e_ident_magic_str", named("string"), 3),
        slot("e_ident_class", uint(1), 1),
        slot("e_ident_data", uint(1), 1),
        slot("e_ident_version", uint(1), 1),
        slot("e_ident_osabi", uint(1), 1),
        slot("e_ident_abiversion", uint(1), 1),
        slot("e_ident_pad", array(uint(1), 7), 7),
        u2("e_type"),
        u2("e_machine"),
        u4("e_version"),
    ];
    ehdr.extend(words(&["e_entry", "e_phoff", "e_shoff"]));
    ehdr.push(u4("e_flags"));
    for n in [
        "e_ehsize",
        "e_phentsize",
        "e_phnum",
        "e_shentsize",
        "e_shnum",
        "e_shstrndx",
    ] {
        ehdr.push(u2(n));
    }
    out.push(packed(&format!("{c}_Ehdr"), ehdr));

    if f.has_program_headers {
        let ph_type = format!("Elf_ProgramHeaderType{suffix}");
        let mut fields = vec![slot("p_type", named(&ph_type), 4)];
        if f.is64 {
            fields.push(u4("p_flags"));
            fields.extend(words(&[
                "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align",
            ]));
        } else {
            fields.extend(words(&[
                "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz",
            ]));
            fields.push(u4("p_flags"));
            fields.push(word("p_align"));
        }
        out.push(packed(&format!("{c}_Phdr"), fields));
        out.push(enumeration(
            &ph_type,
            4,
            &extended(PROGRAM_HEADER_TYPES, ph_extra),
        ));
    }
    if f.has_section_headers {
        let sh_type = format!("Elf_SectionHeaderType{suffix}");
        let mut fields = vec![u4("sh_name"), slot("sh_type", named(&sh_type), 4)];
        fields.extend(words(&["sh_flags", "sh_addr", "sh_offset", "sh_size"]));
        fields.push(u4("sh_link"));
        fields.push(u4("sh_info"));
        fields.extend(words(&["sh_addralign", "sh_entsize"]));
        out.push(packed(&format!("{c}_Shdr"), fields));
        out.push(enumeration(
            &sh_type,
            4,
            &extended(SECTION_HEADER_TYPES, sh_extra),
        ));
    }
    if has_type(SHT_RELA) {
        let mut fields = words(&["r_offset", "r_info"]);
        fields.push(word("r_addend"));
        out.push(packed(&format!("{c}_Rela"), fields));
    }
    if has_type(SHT_REL) {
        out.push(packed(&format!("{c}_Rel"), words(&["r_offset", "r_info"])));
    }
    if has_type(SHT_SYMTAB) || has_type(SHT_DYNSYM) {
        let tail = [
            slot("st_info", uint(1), 1),
            slot("st_other", uint(1), 1),
            u2("st_shndx"),
        ];
        let mut fields = vec![u4("st_name")];
        if f.is64 {
            fields.extend(tail);
            fields.extend(words(&["st_value", "st_size"]));
        } else {
            fields.extend(words(&["st_value", "st_size"]));
            fields.extend(tail);
        }
        out.push(packed(&format!("{c}_Sym"), fields));
    }
    if has_type(SHT_DYNAMIC) {
        let tag = format!("{c}_DynTag{suffix}");
        out.push(packed(
            &format!("{c}_Dyn{suffix}"),
            vec![slot("d_tag", named(&tag), u64::from(w)), word("d_val")],
        ));
        out.push(enumeration(&tag, w, &extended(DYN_TAGS, dyn_extra)));
    }
    if has_section(".reginfo") {
        out.push(enumeration("Elf32_GPRMask_MIPS", 4, GPR_MASK_MIPS));
        out.push(packed(
            "Elf32_RegInfo_MIPS",
            vec![
                slot("ri_gprmask", named("Elf32_GPRMask_MIPS"), 4),
                slot("field1_0x4", array(uint(4), 4), 16),
                u4("ri_gp_value"),
            ],
        ));
    }
    if let Some((namesz, descsz)) = f.package_note {
        out.push(packed(
            &format!("ElfNote_{namesz}_{descsz}"),
            vec![
                u4("namesz"),
                u4("descsz"),
                u4("type"),
                slot("name", named("string"), u64::from(namesz)),
                slot(
                    "description",
                    array(uint(1), u64::from(descsz)),
                    u64::from(descsz),
                ),
            ],
        ));
    }
    if has_section(".note.ABI-tag") {
        out.push(packed(
            "NoteAbiTag",
            vec![
                u4("namesz"),
                u4("descsz"),
                u4("type"),
                slot("name", named("string"), 4),
                u4("abiType"),
                slot("requiredKernelVersion", array(uint(4), 3), 12),
            ],
        ));
    }
    if has_section(".note.gnu.property") {
        out.push(packed(
            "NoteGnuProperty_4",
            vec![
                u4("namesz"),
                u4("descsz"),
                u4("type"),
                slot("name", named("string"), 4),
            ],
        ));
        out.push(packed(
            "NoteGnuPropertyElement_4",
            vec![
                u4("prType"),
                u4("prDatasz"),
                slot("data", array(uint(1), 4), 4),
            ],
        ));
    }
    if has_section(".eh_frame_hdr") {
        let enc = |n: &str| slot(n, named("dwfenc"), 1);
        out.push(packed(
            "eh_frame_hdr",
            vec![
                slot("eh_frame_hdr_version", uint(1), 1),
                enc("eh_frame_pointer_encoding"),
                enc("eh_frame_desc_entry_count_encoding"),
                enc("eh_frame_table_encoding"),
            ],
        ));
        out.push(packed(
            "fde_table_entry",
            vec![u4("initial_loc"), u4("data_loc")],
        ));
    }
    if has_section(".debug_info") {
        // carried in by Ghidra's data type archive into every ELF program with DWARF
        out.push(TypeDef::Typedef(TypedefDef {
            name: "EVP_PKEY_CTX".into(),
            target: named("evp_pkey_ctx_st"),
        }));
        out.push(TypeDef::Struct(Composite {
            name: "evp_pkey_ctx_st".into(),
            size: 1,
            align: 1,
            fields: Vec::new(),
        }));
    } else if uses_stdio(&f.imports) {
        out.extend(glibc_stdio(w));
    }
    out
}

/// Whether one of the imports takes a `FILE *` (by the engine's own library prototypes).
fn uses_stdio(imports: &BTreeSet<String>) -> bool {
    crate::libc::PROTOTYPES
        .iter()
        .filter(|p| p.contains("FILE *"))
        .filter_map(|p| p.split('(').next()?.rsplit([' ', '*']).next())
        .any(|n| imports.contains(n))
}

/// glibc's `struct _IO_FILE` with the typedefs it uses, which Ghidra shows for the library's
/// stdio calls (without debug information); `w` is the pointer size.
fn glibc_stdio(w: u32) -> Vec<TypeDef> {
    let is64 = w == 8;
    let ptr = |t: TypeRef| TypeRef::Pointer {
        target: Box::new(t),
        size: w,
    };
    let char_t = char1();
    let off_t = "__off_t";
    let fields: Vec<(&str, TypeRef, u32)> = vec![
        ("_flags", int(4, true), 4),
        ("_IO_read_ptr", ptr(char_t.clone()), w),
        ("_IO_read_end", ptr(char_t.clone()), w),
        ("_IO_read_base", ptr(char_t.clone()), w),
        ("_IO_write_base", ptr(char_t.clone()), w),
        ("_IO_write_ptr", ptr(char_t.clone()), w),
        ("_IO_write_end", ptr(char_t.clone()), w),
        ("_IO_buf_base", ptr(char_t.clone()), w),
        ("_IO_buf_end", ptr(char_t.clone()), w),
        ("_IO_save_base", ptr(char_t.clone()), w),
        ("_IO_backup_base", ptr(char_t.clone()), w),
        ("_IO_save_end", ptr(char_t.clone()), w),
        ("_markers", ptr(named("_IO_marker")), w),
        ("_chain", ptr(named("_IO_FILE")), w),
        ("_fileno", int(4, true), 4),
        ("_flags2", int(4, true), 4),
        ("_old_offset", named(off_t), w),
        ("_cur_column", uint(2), 2),
        ("_vtable_offset", char_t.clone(), 1),
        ("_shortbuf", array(char_t.clone(), 1), 1),
        ("_lock", ptr(named("_IO_lock_t")), w),
        ("_offset", named("__off64_t"), 8),
        ("__pad1", ptr(void()), w),
        ("__pad2", ptr(void()), w),
        ("__pad3", ptr(void()), w),
        ("__pad4", ptr(void()), w),
        ("__pad5", named("size_t"), w),
        ("_mode", int(4, true), 4),
        (
            "_unused2",
            array(char_t, if is64 { 20 } else { 40 }),
            if is64 { 20 } else { 40 },
        ),
    ];
    let mut at = 0u64;
    let mut out_fields = Vec::new();
    for (name, ty, size) in fields {
        let align = u64::from(size.min(w)).max(1);
        at = at.div_ceil(align) * align;
        out_fields.push(Field {
            name: name.into(),
            offset: at,
            ty,
            bitfield: None,
        });
        at += u64::from(size);
    }
    let align = u64::from(w);
    let td = |name: &str, target: TypeRef| {
        TypeDef::Typedef(TypedefDef {
            name: name.into(),
            target,
        })
    };
    let mut out = vec![
        TypeDef::Struct(Composite {
            name: "_IO_FILE".into(),
            size: at.div_ceil(align) * align,
            align: w,
            fields: out_fields,
        }),
        TypeDef::Struct(Composite {
            name: "_IO_marker".into(),
            size: 3 * u64::from(w),
            align: w,
            fields: vec![
                Field {
                    name: "_next".into(),
                    offset: 0,
                    ty: ptr(named("_IO_marker")),
                    bitfield: None,
                },
                Field {
                    name: "_sbuf".into(),
                    offset: u64::from(w),
                    ty: ptr(named("_IO_FILE")),
                    bitfield: None,
                },
                Field {
                    name: "_pos".into(),
                    offset: 2 * u64::from(w),
                    ty: int(4, true),
                    bitfield: None,
                },
            ],
        }),
        td("_IO_lock_t", void()),
        td("__off_t", int(w, true)),
    ];
    if is64 {
        out.push(td("__off64_t", int(8, true)));
    } else {
        out.push(td("__off64_t", named("__quad_t")));
        out.push(td("__quad_t", int(8, true)));
    }
    out
}

fn void() -> TypeRef {
    TypeRef::Primitive(Primitive {
        class: PrimitiveClass::Void,
        size: 0,
        signed: false,
    })
}

/// The markup types of a PE file: the DOS header and the section header (with its flags),
/// which Ghidra's loader lays over every PE.
fn pe_markup() -> Vec<TypeDef> {
    let u2 = |n: &str| slot(n, uint(2), 2);
    let u4 = |n: &str| slot(n, uint(4), 4);
    let mut dos = vec![slot("e_magic", array(char1(), 2), 2)];
    for n in [
        "e_cblp",
        "e_cp",
        "e_crlc",
        "e_cparhdr",
        "e_minalloc",
        "e_maxalloc",
        "e_ss",
        "e_sp",
        "e_csum",
        "e_ip",
        "e_cs",
        "e_lfarlc",
        "e_ovno",
    ] {
        dos.push(u2(n));
    }
    dos.push(slot("e_res[4]", array(uint(2), 4), 8));
    dos.push(u2("e_oemid"));
    dos.push(u2("e_oeminfo"));
    dos.push(slot("e_res2[10]", array(uint(2), 10), 20));
    dos.push(u4("e_lfanew"));
    dos.push(slot("e_program", array(uint(1), 64), 64));
    let section = vec![
        slot("Name", array(char1(), 8), 8),
        slot("Misc", named("Misc"), 4),
        slot("VirtualAddress", named("ImageBaseOffset32"), 4),
        u4("SizeOfRawData"),
        u4("PointerToRawData"),
        u4("PointerToRelocations"),
        u4("PointerToLinenumbers"),
        u2("NumberOfRelocations"),
        u2("NumberOfLinenumbers"),
        slot("Characteristics", named("SectionFlags"), 4),
    ];
    let misc = TypeDef::Union(Composite {
        name: "Misc".into(),
        size: 4,
        align: 1,
        fields: ["PhysicalAddress", "VirtualSize"]
            .iter()
            .map(|n| Field {
                name: (*n).into(),
                offset: 0,
                ty: uint(4),
                bitfield: None,
            })
            .collect(),
    });
    let offset = TypeDef::Typedef(TypedefDef {
        name: "ImageBaseOffset32".into(),
        target: TypeRef::Pointer {
            target: Box::new(TypeRef::Primitive(Primitive {
                class: PrimitiveClass::Void,
                size: 0,
                signed: false,
            })),
            size: 4,
        },
    });
    vec![
        packed("IMAGE_DOS_HEADER", dos),
        packed("IMAGE_SECTION_HEADER", section),
        misc,
        offset,
        enumeration("SectionFlags", 4, SECTION_FLAGS),
    ]
}

/// The markup types Ghidra's loader adds for the program in `data`; empty for other formats.
pub fn definitions(data: &[u8]) -> Vec<TypeDef> {
    match data.get(..4) {
        Some([0x7f, b'E', b'L', b'F']) => elf_markup(data),
        Some([b'M', b'Z', _, _]) => match object::File::parse(data) {
            Ok(f) if matches!(f.format(), object::BinaryFormat::Pe) => pe_markup(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(file: &str) -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(file);
        let data = std::fs::read(&path).ok();
        if data.is_none() {
            eprintln!("skipped: {} is not built", path.display());
        }
        data
    }

    fn names(file: &str) -> Option<Vec<String>> {
        let mut out: Vec<String> = definitions(&read(file)?)
            .iter()
            .filter_map(|d| kraken_engine::type_def_name(d).map(str::to_string))
            .collect();
        out.sort();
        Some(out)
    }

    #[test]
    fn a_stripped_dynamic_elf_gets_every_header_type() {
        let Some(got) = names("bin/stripped_calc-O0-stripped") else {
            return;
        };
        let want = [
            "Elf64_Dyn",
            "Elf64_DynTag",
            "Elf64_Ehdr",
            "Elf64_Phdr",
            "Elf64_Rela",
            "Elf64_Shdr",
            "Elf64_Sym",
            "Elf_ProgramHeaderType",
            "Elf_SectionHeaderType",
            "NoteAbiTag",
            "NoteGnuPropertyElement_4",
            "NoteGnuProperty_4",
            "eh_frame_hdr",
            "fde_table_entry",
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn a_static_elf_without_dynamic_sections_gets_fewer() {
        let Some(got) = names("bin/static_strops-O0-stripped") else {
            return;
        };
        assert!(got.contains(&"Elf64_Ehdr".to_string()));
        for absent in ["Elf64_Dyn", "Elf64_Sym", "eh_frame_hdr"] {
            assert!(!got.contains(&absent.to_string()), "{absent}");
        }
    }

    #[test]
    fn layouts_are_ghidras() {
        let Some(data) = read("bin/stripped_calc-O0-stripped") else {
            return;
        };
        let defs = definitions(&data);
        let size = |n: &str| {
            defs.iter().find_map(|d| match d {
                TypeDef::Struct(c) if c.name == n => Some(c.size),
                _ => None,
            })
        };
        assert_eq!(size("Elf64_Ehdr"), Some(64));
        assert_eq!(size("Elf64_Phdr"), Some(56));
        assert_eq!(size("Elf64_Shdr"), Some(64));
        assert_eq!(size("Elf64_Sym"), Some(24));
        assert_eq!(size("Elf64_Dyn"), Some(16));
        assert_eq!(size("Elf64_Rela"), Some(24));
        assert_eq!(size("NoteAbiTag"), Some(32));
        assert_eq!(size("eh_frame_hdr"), Some(4));
    }

    #[test]
    fn a_pe_gets_the_dos_and_section_headers() {
        let Some(got) = names("pe/bin/win_dll-x64-O0.dll") else {
            return;
        };
        let want = [
            "IMAGE_DOS_HEADER",
            "IMAGE_SECTION_HEADER",
            "ImageBaseOffset32",
            "Misc",
            "SectionFlags",
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn an_x86_elf_with_stdio_imports_gets_glibc_file_types() {
        let Some(got) = names("elf32/bin/switch_vm-i386-O0-stripped") else {
            return;
        };
        for want in [
            "Elf32_Ehdr",
            "_IO_FILE",
            "_IO_marker",
            "__off64_t",
            "__quad_t",
        ] {
            assert!(got.contains(&want.to_string()), "{want}: {got:?}");
        }
    }

    #[test]
    fn other_formats_get_none() {
        assert!(definitions(b"not an executable").is_empty());
    }
}
