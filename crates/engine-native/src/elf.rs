//! ELF loading with the `object` crate: segments for the decompiler's image, sections for the
//! memory map, function symbols, PLT stubs and the entry point. Addresses follow Ghidra's
//! convention so anchors stay compatible with Ghidra projects: a position-independent image whose
//! lowest address is 0 is loaded at 0x100000.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::elf::{
    PF_W, PF_X, R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE,
};
use object::read::{Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable};
use object::{
    Architecture, BinaryFormat, Endianness, ObjectKind, RelocationFlags, RelocationTarget,
    SectionFlags, SectionKind, SegmentFlags, SymbolKind,
};

/// Ghidra's default image base for ELF objects linked at 0.
pub const PIE_BASE: u64 = 0x10_0000;

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
    /// Name as in the dynamic symbol table.
    pub name: String,
    /// Function (`STT_FUNC` and untyped symbols, as Ghidra treats them) or data.
    pub kind: ProtoSymbolKind,
}

/// A symbol other modules can see (global or weak, defined).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSymbol {
    /// Name as in the symbol table.
    pub name: String,
    /// From the symbol type: function, data object or anything else.
    pub kind: ProtoSymbolKind,
}

/// Everything the engine needs from the file.
#[derive(Debug, Clone)]
pub struct Loaded {
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
    /// PLT stubs, by address, named after the imported symbol.
    pub plt: BTreeMap<u64, String>,
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
    /// Start of every `.eh_frame` FDE after rebasing, ascending.
    pub fde_starts: Vec<u64>,
    /// Exception landing pads after rebasing, by the start of the FDE whose LSDA lists them.
    pub landing_pads: BTreeMap<u64, Vec<u64>>,
    /// Code the GOT slots of imported functions point at before binding (the lazy PLT entries),
    /// after rebasing. Reached only through data, it belongs to no function.
    pub got_code: Vec<u64>,
    /// Names for functions without a symbol, as Ghidra gives them: `_DT_INIT`, `_DT_FINI`,
    /// `_INIT_<n>`, `_FINI_<n>`.
    pub default_names: BTreeMap<u64, String>,
}

impl Loaded {
    /// Whether `addr` lies in an executable, initialized block.
    pub fn is_code(&self, addr: u64) -> bool {
        self.blocks
            .iter()
            .any(|b| b.initialized && b.perms.ends_with('x') && b.start.0 <= addr && addr < b.end.0)
    }

    /// Whether `addr` lies in a PLT section.
    pub fn in_plt(&self, addr: u64) -> bool {
        self.blocks
            .iter()
            .any(|b| b.name.starts_with(".plt") && b.start.0 <= addr && addr < b.end.0)
    }
}

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn language(arch: Architecture) -> Result<Language, ProtoError> {
    match arch {
        Architecture::X86_64 => Ok(Language {
            id: "x86:LE:64:default",
            compiler: "gcc",
            pointer_size: 8,
        }),
        Architecture::Aarch64 => Ok(Language {
            id: "AARCH64:LE:64:v8A",
            compiler: "default",
            pointer_size: 8,
        }),
        other => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("architecture {other:?} is not supported by the native engine yet"),
        )),
    }
}

/// Parses an ELF file. Other formats are `unsupported`.
pub fn load(data: &[u8], base_override: Option<u64>) -> Result<Loaded, ProtoError> {
    let file = object::File::parse(data).map_err(|e| bad(format!("cannot parse binary: {e}")))?;
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

    let lowest = file
        .segments()
        .filter(|s| s.size() > 0)
        .map(|s| s.address())
        .min()
        .unwrap_or(0);
    let default_base = if matches!(file.kind(), ObjectKind::Dynamic) && lowest == 0 {
        PIE_BASE
    } else {
        lowest
    };
    let base = base_override.unwrap_or(default_base);
    let bias = base.wrapping_sub(lowest);
    let at = |a: u64| a.wrapping_add(bias);

    let mut segments = Vec::new();
    for seg in file.segments() {
        if seg.size() == 0 {
            continue;
        }
        let flags = match seg.flags() {
            SegmentFlags::Elf { p_flags } => p_flags,
            _ => 0,
        };
        let bytes = seg.data().map_err(|e| bad(format!("bad segment: {e}")))?;
        segments.push(Segment {
            start: at(seg.address()),
            data: bytes.to_vec(),
            mem_size: seg.size().max(bytes.len() as u64),
            readonly: flags & PF_W == 0,
        });
    }
    segments.sort_by_key(|s| s.start);
    let image = Image { segments };

    let mut blocks = Vec::new();
    for sec in file.sections() {
        let sh_flags = match sec.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };
        if sh_flags & u64::from(SHF_ALLOC) == 0 || sec.size() == 0 {
            continue;
        }
        let name = sec.name().unwrap_or("").to_string();
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
                sh_flags & u64::from(SHF_WRITE) != 0,
                sh_flags & u64::from(SHF_EXECINSTR) != 0,
            ),
            initialized: sec.kind() != SectionKind::UninitializedData,
            kind: MemoryKind::Default,
        });
    }
    if blocks.is_empty() {
        for (i, seg) in file.segments().filter(|s| s.size() > 0).enumerate() {
            let flags = match seg.flags() {
                SegmentFlags::Elf { p_flags } => p_flags,
                _ => 0,
            };
            blocks.push(MemoryBlock {
                name: format!("segment_{i}"),
                space: "ram".into(),
                start: at(seg.address()).into(),
                end: at(seg.address() + seg.size()).into(),
                perms: MemoryBlock::perms_string(true, flags & PF_W != 0, flags & PF_X != 0),
                initialized: true,
                kind: MemoryKind::Default,
            });
        }
    }
    blocks.sort_by_key(|b| (b.start, b.end));

    let mut functions = BTreeMap::new();
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.kind() != SymbolKind::Text || !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        functions
            .entry(at(sym.address()))
            .or_insert_with(|| name.to_string());
        let names = code_symbols.entry(at(sym.address())).or_default();
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    let mut debug = crate::dwarf::parse(&file);
    debug.functions = std::mem::take(&mut debug.functions)
        .into_iter()
        .map(|(a, f)| (at(a), f))
        .collect();

    let plt = if language.id.starts_with("x86") {
        x86_plt(&file, data, bias, &functions)
    } else {
        BTreeMap::new()
    };

    let entry = (file.entry() != 0).then(|| at(file.entry()));

    let mut init_pointers = Vec::new();
    let mut default_names: BTreeMap<u64, String> = BTreeMap::new();
    let relative: BTreeMap<u64, i64> = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .filter(|(_, r)| matches!(r.target(), RelocationTarget::Absolute))
        .map(|(off, r)| (off, r.addend()))
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
        for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let slot = sec.address() + (i as u64) * 8;
            let mut v = u64::from_le_bytes(*chunk);
            if v == 0 {
                v = relative.get(&slot).map(|a| *a as u64).unwrap_or(0);
            }
            if v != 0 && v != u64::MAX {
                init_pointers.push(at(v));
                default_names
                    .entry(at(v))
                    .or_insert_with(|| format!("{prefix}{i}"));
            }
        }
    }
    // DT_INIT and DT_FINI of the dynamic section
    if let Some(dynamic) = file.section_by_name(".dynamic")
        && let Ok(bytes) = dynamic.data()
    {
        for e in bytes.as_chunks::<16>().0 {
            let mut tag = [0u8; 8];
            let mut val = [0u8; 8];
            tag.copy_from_slice(&e[..8]);
            val.copy_from_slice(&e[8..]);
            let (tag, val) = (u64::from_le_bytes(tag), u64::from_le_bytes(val));
            let name = match tag {
                12 => "_DT_INIT",
                13 => "_DT_FINI",
                0 => break,
                _ => continue,
            };
            if val != 0 {
                init_pointers.push(at(val));
                default_names.entry(at(val)).or_insert_with(|| name.into());
            }
        }
    }

    if let Some(plt) = file.section_by_name(".plt")
        && plt.size() > 0
    {
        init_pointers.push(at(plt.address()));
    }

    let mut data_pointers: Vec<u64> = relative.values().map(|a| at(*a as u64)).collect();
    if relative.is_empty() {
        for sec in file.sections() {
            let sh_flags = match sec.flags() {
                SectionFlags::Elf { sh_flags } => sh_flags,
                _ => 0,
            };
            let alloc = sh_flags & u64::from(SHF_ALLOC) != 0;
            let exec = sh_flags & u64::from(SHF_EXECINSTR) != 0;
            if !alloc || exec || sec.kind() == SectionKind::UninitializedData {
                continue;
            }
            let Ok(bytes) = sec.data() else { continue };
            let skip = (sec.address() % 8) as usize;
            for chunk in bytes.get(skip..).unwrap_or_default().as_chunks::<8>().0 {
                let v = u64::from_le_bytes(*chunk);
                if v != 0 {
                    data_pointers.push(at(v));
                }
            }
        }
    }
    data_pointers.sort_unstable();
    data_pointers.dedup();

    let mut pointer_slots: Vec<(u64, u64)> = relative
        .iter()
        .filter(|(_, a)| **a != 0)
        .map(|(slot, a)| (at(*slot), at(*a as u64)))
        .collect();
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
    for (off, rel) in file.dynamic_relocations().into_iter().flatten() {
        if !matches!(rel.flags(), RelocationFlags::Elf { r_type } if r_type == R_X86_64_JUMP_SLOT)
            || !language.id.starts_with("x86")
        {
            continue;
        }
        let mut buf = [0u8; 8];
        if image.read(at(off), &mut buf) {
            let v = u64::from_le_bytes(buf);
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
            })
        }
        None => crate::eh::Frames::default(),
    };
    let fde_starts = frames.fde_starts.iter().map(|a| at(*a)).collect();
    let landing_pads = frames
        .landing_pads
        .iter()
        .map(|(f, pads)| (at(*f), pads.iter().map(|p| at(*p)).collect()))
        .collect();

    Ok(Loaded {
        language,
        base,
        image,
        blocks,
        functions,
        code_symbols,
        debug,
        plt,
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

/// Names x86-64 PLT entries after the symbol of the GOT slot their `jmp [rip+disp32]` reads.
/// In a static binary the slots carry IRELATIVE relocations instead, and an entry is named after
/// the IFUNC symbol at the relocation's resolver (as Ghidra names them), or `FUN_<address>`.
fn x86_plt(
    file: &object::File<'_>,
    data: &[u8],
    bias: u64,
    functions: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
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
        if !matches!(sec.name(), Ok(".rela.plt" | ".rela.iplt")) {
            continue;
        }
        let Ok(bytes) = sec.data() else { continue };
        for r in bytes.as_chunks::<24>().0 {
            let word = |i: usize| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&r[i..i + 8]);
                u64::from_le_bytes(b)
            };
            if word(8) & 0xffff_ffff == u64::from(R_X86_64_IRELATIVE) {
                let resolver = word(16).wrapping_add(bias);
                slots
                    .entry(word(0))
                    .or_insert_with(|| functions.get(&resolver).cloned());
            }
        }
    }
    let mut out = BTreeMap::new();
    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
            continue;
        }
        let Some((foff, fsize)) = sec.file_range() else {
            continue;
        };
        let Some(bytes) = data.get(foff as usize..(foff + fsize) as usize) else {
            continue;
        };
        // every `jmp [rip+disp32]` through a known slot starts an entry, together with the
        // `bnd` prefix and `endbr64` in front of it (`.plt.sec`)
        let mut j = 0;
        while j + 6 <= bytes.len() {
            if bytes[j] != 0xff || bytes[j + 1] != 0x25 {
                j += 1;
                continue;
            }
            let mut d = [0u8; 4];
            d.copy_from_slice(&bytes[j + 2..j + 6]);
            let disp = i64::from(i32::from_le_bytes(d));
            let got = (sec.address() + j as u64 + 6).wrapping_add_signed(disp);
            if let Some(n) = slots.get(&got) {
                let mut start = j;
                if start >= 1 && bytes[start - 1] == 0xf2 {
                    start -= 1;
                }
                if start >= 4 && bytes[start - 4..start] == [0xf3, 0x0f, 0x1e, 0xfa] {
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
