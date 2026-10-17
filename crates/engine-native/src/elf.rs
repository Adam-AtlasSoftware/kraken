//! ELF loading with the `object` crate: segments for the decompiler's image, sections for the
//! memory map, function symbols, PLT stubs and the entry point. Addresses follow Ghidra's
//! convention so anchors stay compatible with Ghidra projects: a position-independent image whose
//! lowest address is 0 is loaded at 0x100000.

use std::collections::BTreeMap;

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError};
use object::elf::{PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use object::read::{Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable};
use object::{
    Architecture, BinaryFormat, Endianness, ObjectKind, RelocationTarget, SectionFlags,
    SectionKind, SegmentFlags, SymbolKind,
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
    /// Defined function symbols (static and dynamic), by address; first name wins.
    pub functions: BTreeMap<u64, String>,
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
    }

    let plt = if language.id.starts_with("x86") {
        x86_plt(&file, data, bias)
    } else {
        BTreeMap::new()
    };

    let entry = (file.entry() != 0).then(|| at(file.entry()));

    let mut init_pointers = Vec::new();
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
        for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let slot = sec.address() + (i as u64) * 8;
            let mut v = u64::from_le_bytes(*chunk);
            if v == 0 {
                v = relative.get(&slot).map(|a| *a as u64).unwrap_or(0);
            }
            if v != 0 && v != u64::MAX {
                init_pointers.push(at(v));
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

    Ok(Loaded {
        language,
        base,
        image,
        blocks,
        functions,
        plt,
        entry,
        init_pointers,
        data_pointers,
    })
}

/// Names x86-64 PLT entries after the symbol of the GOT slot their `jmp [rip+disp32]` reads.
fn x86_plt(file: &object::File<'_>, data: &[u8], bias: u64) -> BTreeMap<u64, String> {
    let mut slots: BTreeMap<u64, String> = BTreeMap::new();
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
            slots.insert(off, name);
        }
    }
    let mut out = BTreeMap::new();
    for sec in file.sections() {
        let Ok(name) = sec.name() else { continue };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got") {
            continue;
        }
        let Some((foff, fsize)) = sec.file_range() else {
            continue;
        };
        let Some(bytes) = data.get(foff as usize..(foff + fsize) as usize) else {
            continue;
        };
        let entry_size: usize = if name == ".plt.got" { 8 } else { 16 };
        for (i, entry) in bytes.chunks(entry_size).enumerate() {
            let entry_addr = sec.address() + (i * entry_size) as u64;
            for j in 0..entry.len().saturating_sub(5) {
                if entry[j] != 0xff || entry[j + 1] != 0x25 {
                    continue;
                }
                let mut d = [0u8; 4];
                d.copy_from_slice(&entry[j + 2..j + 6]);
                let disp = i64::from(i32::from_le_bytes(d));
                let next = entry_addr + j as u64 + 6;
                let got = next.wrapping_add_signed(disp);
                if let Some(n) = slots.get(&got) {
                    out.insert(entry_addr.wrapping_add(bias), n.clone());
                }
                break;
            }
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
