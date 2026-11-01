//! Mach-O loading (64-bit x86-64 and AArch64) with the `object` crate, in the shape Ghidra's
//! `MachoProgramBuilder` gives a program: the segments at their own addresses, each cut into
//! blocks named after its sections (`__text`, `__cstring`) with Ghidra's section permissions, the
//! rest of a segment under the segment's name; the language and compiler spec of Ghidra's
//! `.opinion` files (`AARCH64:LE:64:AppleSilicon` with its Apple calling convention).
//!
//! Symbols keep the leading underscore (`_printf`), as they do in Ghidra. The function at the
//! program's entry point is called `entry` and keeps `_main` as a second name. Each entry of a
//! `__stubs` section is an import thunk named after the import.
//!
//! Binding is applied to the image, chained fixups (`LC_DYLD_CHAINED_FIXUPS`) and the older
//! `LC_DYLD_INFO` tables alike: a slot of an import that has a stub holds the stub's address, as
//! in Ghidra, and any other import stands in Ghidra's `EXTERNAL` block; rebased pointers hold
//! their targets. Function seeds come from `LC_FUNCTION_STARTS`, `__unwind_info` and `__eh_frame`.
//! A universal binary is cut down to one slice before it gets here (`kraken_engine::fat`).
//!
//! Hostile input: every count and range comes from the file, so segments must fit the address
//! space and may not overlap, walks are capped and anything outside the file ends the walk.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::macho;
use object::read::macho::{
    DyldChainedFixups, ExportData, Fixup, LoadCommandVariant, MachHeader, MachOFile64, Nlist,
    Section as _, Segment as _,
};
use object::{Endianness, FileKind};

use crate::elf::{DataSymbol, ExportSymbol, ImportSymbol, Language, Loaded};

/// The most address space a program may span (from its first segment to the end of its last).
const MAX_SPAN: u64 = 1 << 34;
/// Room above the image for the import stand-ins, so address sums cannot overflow.
const ADDRESS_HEADROOM: u64 = 1 << 33;
/// Most segments and sections taken; binding tables index segments with one byte.
const MAX_SEGMENTS: usize = 256;
const MAX_SECTIONS: usize = 4096;
/// Most fixups, binds, exports and function starts read from one table.
const MAX_WALK: usize = 1 << 22;
/// Most stand-ins for imports without a stub; they are mapped, and the symbol table is the
/// file's to choose.
const MAX_EXTERNALS: usize = 1 << 16;
/// Ghidra's distance between the import stand-ins in `EXTERNAL`.
const EXTERNAL_SPACING: u64 = 0x100;

const X86_RET: u8 = 0xc3;
const AARCH64_RET: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn unsupported(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, msg)
}

fn text(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// Ghidra's `SymbolUtilities.replaceInvalidChars`: names hold no whitespace.
fn symbol_name(name: &[u8]) -> String {
    text(name)
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
}

struct Seg {
    name: String,
    vm: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    prot: macho::VmProt,
}

struct Sect {
    name: String,
    segment: String,
    addr: u64,
    size: u64,
    offset: u32,
    flags: macho::SectionFlags,
    kind: macho::SectionType,
    reserved1: u32,
    reserved2: u32,
}

impl Sect {
    /// Ghidra's `Section.isWrite`.
    fn writable(&self) -> bool {
        if self.name.starts_with("__got") {
            return true;
        }
        !matches!(
            self.segment.as_str(),
            "__TEXT" | "__TEXT_EXEC" | "__PRELINK_TEXT"
        ) && self.name != "__const"
    }

    /// Ghidra's `Section.isExecute`.
    fn executable(&self) -> bool {
        self.name == "__text"
            || self.segment == "__TEXT_EXEC"
            || self.flags.contains(macho::S_ATTR_PURE_INSTRUCTIONS)
            || self.flags.contains(macho::S_ATTR_SOME_INSTRUCTIONS)
    }

    fn holds(&self, addr: u64) -> bool {
        addr >= self.addr && addr - self.addr < self.size
    }
}

/// A piece of a segment on its way to being a memory block.
#[derive(Clone)]
struct Part {
    name: String,
    lo: u64,
    hi: u64,
    writable: bool,
    exec: bool,
    init: bool,
}

/// The language and compiler spec of a CPU type, as Ghidra's opinion files map them.
fn language(cpu: macho::CpuType) -> Result<Language, ProtoError> {
    match cpu {
        macho::CPU_TYPE_X86_64 => Ok(Language {
            id: "x86:LE:64:default",
            compiler: "gcc",
            pointer_size: 8,
        }),
        macho::CPU_TYPE_ARM64 => Ok(Language {
            id: "AARCH64:LE:64:AppleSilicon",
            compiler: "default",
            pointer_size: 8,
        }),
        other => Err(unsupported(format!(
            "this Mach-O file is for processor {:#x}; the native engine opens x86-64 and AArch64",
            other.0
        ))),
    }
}

/// Parses a thin Mach-O file; `base_override` moves it (Mach-O images are relocatable).
pub fn load(data: &[u8], base_override: Option<u64>) -> Result<Loaded, ProtoError> {
    match FileKind::parse(data) {
        Ok(FileKind::MachO64) => load_64(data, base_override),
        Ok(FileKind::MachO32) => Err(unsupported(
            "32-bit Mach-O files are not supported by the native engine",
        )),
        Ok(FileKind::MachOFat32 | FileKind::MachOFat64) => {
            Err(bad("a universal binary has to be cut to one slice first"))
        }
        _ => Err(bad("not a Mach-O file")),
    }
}

/// Reads the bytes at a virtual address (before any rebasing) from the segments.
fn read_at<'d>(segs: &[Seg], data: &'d [u8], addr: u64, n: usize) -> Option<&'d [u8]> {
    let s = segs
        .iter()
        .find(|s| addr >= s.vm && addr - s.vm < s.filesize)?;
    let at = s.fileoff.checked_add(addr - s.vm)?;
    let end = at.checked_add(n as u64)?;
    if addr - s.vm + n as u64 > s.filesize {
        return None;
    }
    data.get(at as usize..end as usize)
}

fn patch(segments: &mut [Segment], addr: u64, bytes: &[u8]) {
    for s in segments.iter_mut() {
        if addr >= s.start && addr - s.start < s.data.len() as u64 {
            let at = (addr - s.start) as usize;
            if let Some(d) = s.data.get_mut(at..at + bytes.len()) {
                d.copy_from_slice(bytes);
            }
            return;
        }
    }
}

/// What the binding tables say about pointer slots, at link addresses.
#[derive(Default)]
struct Binding {
    /// Slot and the name it binds to; the first wins.
    binds: BTreeMap<u64, String>,
    /// Slot and its target.
    rebases: BTreeMap<u64, u64>,
    /// Bound names and the library each comes from (a one-based ordinal, as dyld counts them).
    libraries: BTreeMap<String, Option<usize>>,
}

/// One-based ordinals index the `LC_LOAD_DYLIB` commands; the special ones (self, main
/// executable, flat lookup, weak) are zero or negative.
fn ordinal(dylib: macho::BindDylib) -> Option<usize> {
    let v = dylib.0;
    (v > 0).then_some(v as usize)
}

fn walk_chained(
    fixups: &DyldChainedFixups<'_, Endianness>,
    endian: Endianness,
    segs: &[Seg],
    data: &[u8],
    link: u64,
    out: &mut Binding,
) -> Result<(), object::Error> {
    let mut names: Vec<(String, Option<usize>)> = Vec::new();
    let mut imports = fixups.imports(endian)?;
    while let Some(i) = imports.next()? {
        if names.len() >= MAX_WALK {
            break;
        }
        names.push((symbol_name(i.name), ordinal(i.dylib)));
    }
    let mut chains = fixups.segments(endian)?;
    while let Some(chain) = chains.next()? {
        let Some(seg) = segs.get(chain.index() as usize) else {
            continue;
        };
        let end = seg.fileoff.saturating_add(seg.filesize);
        let Some(bytes) = data.get(seg.fileoff as usize..end as usize) else {
            continue;
        };
        let mut walk = chain.fixups(endian, link, bytes);
        let mut seen = 0;
        // a damaged chain ends here; what was read stays
        while let Ok(Some((offset, fixup))) = walk.next() {
            seen += 1;
            if seen > MAX_WALK {
                break;
            }
            let slot = seg.vm.wrapping_add(offset);
            match fixup {
                Fixup::Rebase(r) => {
                    out.rebases.insert(slot, link.wrapping_add(r.target_offset));
                }
                Fixup::Bind(b) => {
                    if let Some((name, lib)) = names.get(b.ordinal as usize) {
                        out.binds.entry(slot).or_insert_with(|| name.clone());
                        out.libraries.entry(name.clone()).or_insert(*lib);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn walk_dyld_info(
    info: &macho::DyldInfoCommand<Endianness>,
    endian: Endianness,
    segs: &[Seg],
    data: &[u8],
    out: &mut Binding,
) {
    let vm = |index: u8, offset: u64| {
        segs.get(usize::from(index))
            .map(|s| s.vm.wrapping_add(offset))
    };
    if let Ok(mut it) = info.rebases(endian, data, 8) {
        for _ in 0..MAX_WALK {
            let Ok(Some(r)) = it.next() else { break };
            if let Some(slot) = vm(r.segment_index, r.segment_offset)
                && let Some(b) = read_at(segs, data, slot, 8)
            {
                let target = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                out.rebases.insert(slot, target);
            }
        }
    }
    let tables = [
        info.binds(endian, data, 8),
        info.lazy_binds(endian, data, 8),
        info.weak_binds(endian, data, 8),
    ];
    for table in tables {
        let Ok(mut it) = table else { continue };
        for _ in 0..MAX_WALK {
            let Ok(Some(b)) = it.next() else { break };
            let name = symbol_name(b.symbol);
            let lib = ordinal(b.dylib);
            if let Some(slot) = vm(b.segment_index, b.segment_offset) {
                out.binds.entry(slot).or_insert_with(|| name.clone());
                let known = out.libraries.entry(name).or_insert(lib);
                if known.is_none() {
                    *known = lib;
                }
            }
        }
    }
}

/// Function offsets (from `__TEXT`) listed in a `__unwind_info` section.
fn unwind_starts(info: &[u8]) -> Vec<u32> {
    let word = |o: usize| {
        info.get(o..o.checked_add(4)?)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let half = |o: usize| {
        info.get(o..o.checked_add(2)?)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let mut out = Vec::new();
    if word(0) != Some(1) {
        return out;
    }
    let (Some(index), Some(count)) = (word(20), word(24)) else {
        return out;
    };
    for i in 0..count as usize {
        let at = index as usize + i * 12;
        let (Some(first), Some(page)) = (word(at), word(at + 4)) else {
            break;
        };
        // the last index entry only marks the end of the range
        if page == 0 {
            continue;
        }
        let page = page as usize;
        let (Some(kind), Some(entries), Some(n)) = (word(page), half(page + 4), half(page + 6))
        else {
            continue;
        };
        let entries = page + entries as usize;
        for k in 0..n as usize {
            if out.len() >= MAX_WALK {
                return out;
            }
            match kind {
                2 => match word(entries + k * 8) {
                    Some(f) => out.push(f),
                    None => break,
                },
                3 => match word(entries + k * 4) {
                    Some(e) => out.push(first.wrapping_add(e & 0x00ff_ffff)),
                    None => break,
                },
                _ => break,
            }
        }
    }
    out
}

fn thread_entry(cpu: macho::CpuType, state: &[u8]) -> Option<u64> {
    // flavor and count, then the registers: `rip` after 16 of them, `pc` after 32
    let pc = match cpu {
        macho::CPU_TYPE_X86_64 => 8 + 16 * 8,
        macho::CPU_TYPE_ARM64 => 8 + 32 * 8,
        _ => return None,
    };
    let b = state.get(pc..pc + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn load_64(data: &[u8], base_override: Option<u64>) -> Result<Loaded, ProtoError> {
    let parse = |e: object::Error| bad(format!("cannot parse Mach-O file: {e}"));
    let file = MachOFile64::<Endianness, _>::parse(data).map_err(parse)?;
    let endian = file.endian();
    if endian != Endianness::Little {
        return Err(unsupported(
            "big-endian Mach-O files are not supported by the native engine",
        ));
    }
    let header = file.macho_header();
    let language = language(header.cputype(endian))?;
    let filetype = header.filetype(endian);
    let description = match filetype {
        macho::MH_EXECUTE => "macOS program",
        macho::MH_DYLIB => "macOS library",
        macho::MH_BUNDLE => "macOS plug-in",
        macho::MH_DYLINKER => "macOS dynamic linker",
        macho::MH_KEXT_BUNDLE => "macOS kernel extension",
        macho::MH_OBJECT => {
            return Err(unsupported(
                "Mach-O object files are not supported by the native engine; open a linked \
                 program or library",
            ));
        }
        _ => {
            return Err(unsupported(
                "this kind of Mach-O file (a debug companion, core file or similar) is not \
                 supported by the native engine",
            ));
        }
    };

    // the load commands, in file order: segment indices in the fixups count them
    let mut segs: Vec<Seg> = Vec::new();
    let mut sects: Vec<Sect> = Vec::new();
    let mut libraries: Vec<String> = Vec::new();
    let mut entry_offset = None;
    let mut thread = None;
    let mut chained = None;
    let mut dyld_info = None;
    let mut exports_trie = None;
    let mut function_starts = None;
    let mut dysymtab = None;
    let mut commands = file.macho_load_commands().map_err(parse)?;
    while let Some(cmd) = commands.next().map_err(parse)? {
        match cmd.variant().map_err(parse)? {
            LoadCommandVariant::Segment64(seg, section_data) => {
                if segs.len() >= MAX_SEGMENTS {
                    return Err(bad("too many segments"));
                }
                let name = text(seg.name());
                for s in seg.sections(endian, section_data).map_err(parse)? {
                    if sects.len() >= MAX_SECTIONS {
                        return Err(bad("too many sections"));
                    }
                    sects.push(Sect {
                        name: text(s.name()),
                        segment: text(s.segment_name()),
                        addr: s.addr(endian),
                        size: s.size(endian),
                        offset: s.offset(endian),
                        flags: s.flags(endian),
                        kind: s.section_type(endian),
                        reserved1: s.reserved1(endian),
                        reserved2: s.reserved2(endian),
                    });
                }
                let (fileoff, filesize) = seg.file_range(endian);
                segs.push(Seg {
                    name,
                    vm: seg.vmaddr(endian),
                    vmsize: seg.vmsize(endian),
                    fileoff,
                    filesize,
                    prot: seg.initprot(endian),
                });
            }
            LoadCommandVariant::Dylib(d) => {
                libraries.push(text(cmd.string(endian, d.dylib.name).map_err(parse)?));
            }
            LoadCommandVariant::EntryPoint(e) => entry_offset = Some(e.entryoff.get(endian)),
            LoadCommandVariant::Thread(_, state) => {
                thread = thread.or(thread_entry(header.cputype(endian), state));
            }
            LoadCommandVariant::Dysymtab(d) => dysymtab = Some(d),
            LoadCommandVariant::DyldInfo(d) => dyld_info = Some(d),
            LoadCommandVariant::LinkeditData(l) => match cmd.cmd() {
                macho::LC_DYLD_CHAINED_FIXUPS => chained = Some(l),
                macho::LC_DYLD_EXPORTS_TRIE => exports_trie = Some(l),
                macho::LC_FUNCTION_STARTS => function_starts = Some(l),
                _ => {}
            },
            _ => {}
        }
    }

    // the image: everything but __PAGEZERO, which maps nothing
    let mapped: Vec<&Seg> = segs
        .iter()
        .filter(|s| s.name != "__PAGEZERO" && s.vmsize > 0)
        .collect();
    let mut by_addr = mapped.clone();
    by_addr.sort_by_key(|s| s.vm);
    let lowest = mapped
        .iter()
        .filter(|s| s.filesize > 0)
        .map(|s| s.vm)
        .min()
        .unwrap_or(0);
    let floor = by_addr.first().map_or(0, |s| s.vm);
    for s in &by_addr {
        let Some(end) = s.vm.checked_add(s.vmsize) else {
            return Err(bad("a segment does not fit the address space"));
        };
        if end - floor > MAX_SPAN {
            return Err(bad("the segments span more memory than KRAKEN maps"));
        }
    }
    if by_addr.windows(2).any(|w| w[0].vm + w[0].vmsize > w[1].vm) {
        return Err(bad("two segments of this file overlap"));
    }
    let link_end = by_addr.last().map_or(lowest, |s| s.vm + s.vmsize);
    let base = base_override.unwrap_or(lowest);
    let span = link_end - floor;
    if base
        .checked_add(span)
        .and_then(|e| e.checked_add(ADDRESS_HEADROOM))
        .is_none()
    {
        return Err(bad("the load address does not leave room for the program"));
    }
    let bias = base.wrapping_sub(lowest);
    let at = |a: u64| a.wrapping_add(bias);

    let mut segments = Vec::with_capacity(mapped.len());
    let mut blocks: Vec<MemoryBlock> = Vec::new();
    let block = |name: &str, lo: u64, hi: u64, w: bool, x: bool, init: bool| MemoryBlock {
        name: name.to_string(),
        space: "ram".into(),
        start: lo.into(),
        end: hi.into(),
        perms: MemoryBlock::perms_string(true, w, x),
        initialized: init,
        kind: MemoryKind::Default,
    };
    for s in &by_addr {
        let bytes = s
            .fileoff
            .checked_add(s.filesize)
            .and_then(|e| data.get(s.fileoff as usize..e as usize))
            .ok_or_else(|| bad(format!("segment {} lies outside the file", s.name)))?;
        // a segment that claims more file than memory is cut to its memory
        let bytes = &bytes[..bytes.len().min(s.vmsize as usize)];
        let writable = s.prot.contains(macho::VM_PROT_WRITE);
        segments.push(Segment {
            start: at(s.vm),
            data: bytes.to_vec(),
            mem_size: s.vmsize,
            readonly: !writable,
        });
        let exec = s.prot.contains(macho::VM_PROT_EXECUTE);
        let init_end = s.vm + bytes.len() as u64;
        let end = s.vm + s.vmsize;
        // Ghidra cuts the segment's block section by section, in file order. A section that
        // starts where a block starts takes its own size; one that starts inside a block takes
        // the rest of that block, so a gap after a section stays with it and sections end where
        // the next one begins.
        let mut parts = vec![Part {
            name: s.name.clone(),
            lo: s.vm,
            hi: init_end,
            writable,
            exec,
            init: true,
        }];
        if init_end < end {
            parts.push(Part {
                lo: init_end,
                hi: end,
                init: false,
                ..parts[0].clone()
            });
        }
        parts.retain(|p| p.lo < p.hi);
        let inner = sects.iter().filter(|c| {
            c.segment == s.name
                && c.size > 0
                && c.addr >= s.vm
                && c.addr.checked_add(c.size).is_some_and(|e| e <= end)
                && (c.offset > 0 || c.kind == macho::S_ZEROFILL)
        });
        for c in inner {
            let Some(i) = parts.iter().position(|p| p.lo <= c.addr && c.addr < p.hi) else {
                continue;
            };
            let old = parts[i].clone();
            let mut section = Part {
                name: c.name.clone(),
                lo: c.addr,
                hi: old.hi,
                writable: c.writable(),
                exec: c.executable(),
                init: old.init && c.kind != macho::S_ZEROFILL,
            };
            if c.addr > old.lo {
                parts[i].hi = c.addr;
                parts.insert(i + 1, section);
            } else {
                section.hi = (c.addr + c.size).min(old.hi);
                parts[i].lo = section.hi;
                if parts[i].lo == parts[i].hi {
                    parts[i] = section;
                } else {
                    parts.insert(i, section);
                }
            }
        }
        blocks.extend(
            parts
                .iter()
                .map(|p| block(&p.name, at(p.lo), at(p.hi), p.writable, p.exec, p.init)),
        );
    }

    // __TEXT holds the Mach-O header; offsets in the load commands count from it
    let link = segs
        .iter()
        .find(|s| s.name == "__TEXT")
        .map_or(lowest, |s| s.vm);

    // the symbol table
    let table = file.macho_symbol_table();
    let strings = table.strings();
    let exec_sects: Vec<&Sect> = sects.iter().filter(|c| c.executable()).collect();
    let in_exec = |a: u64| exec_sects.iter().any(|c| c.holds(a));
    let mut functions: BTreeMap<u64, String> = BTreeMap::new();
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut data_symbols: BTreeMap<u64, DataSymbol> = BTreeMap::new();
    let mut defined_exports: BTreeMap<u64, ExportSymbol> = BTreeMap::new();
    let mut undefined: Vec<String> = Vec::new();
    let mut undefined_seen: BTreeSet<String> = BTreeSet::new();
    for sym in table.iter() {
        if sym.is_stab() {
            continue;
        }
        let Ok(name) = sym.name(endian, strings) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = symbol_name(name);
        let kind = sym.n_type().typ();
        if kind == macho::N_UNDF {
            if undefined_seen.insert(name.clone()) {
                undefined.push(name);
            }
            continue;
        }
        if kind != macho::N_SECT {
            continue;
        }
        let addr = sym.n_value(endian);
        if in_exec(addr) {
            functions.entry(at(addr)).or_insert_with(|| name.clone());
            code_symbols.entry(at(addr)).or_default().push(name.clone());
            if sym.n_type().contains(macho::N_EXT) {
                defined_exports.entry(at(addr)).or_insert(ExportSymbol {
                    name,
                    kind: ProtoSymbolKind::Function,
                    member: None,
                });
            }
        } else {
            data_symbols.entry(at(addr)).or_insert(DataSymbol {
                name: name.clone(),
                size: 0,
            });
            if sym.n_type().contains(macho::N_EXT) {
                defined_exports.entry(at(addr)).or_insert(ExportSymbol {
                    name,
                    kind: ProtoSymbolKind::Data,
                    member: None,
                });
            }
        }
    }

    // binding
    let mut binding = Binding::default();
    if let Some(cmd) = chained {
        // an empty or damaged table leaves the pointers as the file has them
        if let Ok(f) = cmd.chained_fixups(endian, data) {
            let _ = walk_chained(&f, endian, &segs, data, link, &mut binding);
        }
    } else if let Some(info) = dyld_info {
        walk_dyld_info(info, endian, &segs, data, &mut binding);
    }

    // the indirect table: stubs, and symbol pointers older files bind by it alone
    let indirect: Vec<u32> = dysymtab
        .and_then(|d| d.indirect_symbols(endian, data).ok())
        .map(|s| s.iter().map(|e| e.get(endian).0).collect())
        .unwrap_or_default();
    let indirect_name = |i: usize| -> Option<String> {
        let index = *indirect.get(i)?;
        if index & (macho::INDIRECT_SYMBOL_LOCAL.0 | macho::INDIRECT_SYMBOL_ABS.0) != 0 {
            return None;
        }
        let sym = table.symbols().get(index as usize)?;
        let name = sym.name(endian, strings).ok()?;
        (!name.is_empty()).then(|| symbol_name(name))
    };
    let mut plt: BTreeMap<u64, String> = BTreeMap::new();
    let mut stub_of: BTreeMap<String, u64> = BTreeMap::new();
    let mut got_code = Vec::new();
    for c in &sects {
        let first = c.reserved1 as usize;
        match c.kind {
            macho::S_SYMBOL_STUBS if c.reserved2 > 0 => {
                let stride = u64::from(c.reserved2);
                let count = (c.size / stride).min(MAX_WALK as u64) as usize;
                for i in 0..count {
                    if let Some(name) = indirect_name(first + i) {
                        let stub = c.addr.wrapping_add(i as u64 * stride);
                        plt.insert(at(stub), name.clone());
                        stub_of.entry(name).or_insert(at(stub));
                    }
                }
            }
            macho::S_LAZY_SYMBOL_POINTERS | macho::S_NON_LAZY_SYMBOL_POINTERS => {
                let count = (c.size / 8).min(MAX_WALK as u64) as usize;
                for i in 0..count {
                    let slot = c.addr.wrapping_add(i as u64 * 8);
                    if let Some(b) = read_at(&segs, data, slot, 8) {
                        let v =
                            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                        // the lazy pointers of older files start out at their `__stub_helper` entry
                        if c.kind == macho::S_LAZY_SYMBOL_POINTERS && in_exec(v) {
                            got_code.push(at(v));
                        }
                    }
                    if let Some(name) = indirect_name(first + i) {
                        binding.binds.entry(slot).or_insert(name);
                    }
                }
            }
            _ => {}
        }
    }

    // imports: a function when it has a stub, else data, and with the library it binds from
    let mut names: Vec<String> = undefined;
    for n in binding.binds.values().chain(binding.libraries.keys()) {
        if undefined_seen.insert(n.clone()) {
            names.push(n.clone());
        }
    }
    let library_of = |n: &str| {
        binding
            .libraries
            .get(n)
            .copied()
            .flatten()
            .and_then(|o| libraries.get(o - 1).cloned())
    };
    let mut imports: Vec<ImportSymbol> = names
        .iter()
        .map(|n| ImportSymbol {
            name: n.clone(),
            kind: if stub_of.contains_key(n) {
                ProtoSymbolKind::Function
            } else {
                ProtoSymbolKind::Data
            },
            library: library_of(n),
        })
        .collect();
    imports.sort_by(|a, b| a.name.cmp(&b.name));

    // stand-ins for the imports without a stub, on the next page after the image
    let top = blocks.iter().map(|b| b.end.0).max().unwrap_or(base);
    let externals_start = top.div_ceil(0x1000) * 0x1000;
    let mut externals: BTreeMap<u64, String> = BTreeMap::new();
    let mut external_of: BTreeMap<&str, u64> = BTreeMap::new();
    for n in names
        .iter()
        .filter(|n| !stub_of.contains_key(*n))
        .take(MAX_EXTERNALS)
    {
        let ext = externals_start + external_of.len() as u64 * EXTERNAL_SPACING;
        external_of.insert(n, ext);
        externals.insert(ext, n.clone());
    }
    if !externals.is_empty() {
        let len = externals.len() as u64 * EXTERNAL_SPACING;
        blocks.push(MemoryBlock {
            name: "EXTERNAL".into(),
            space: "ram".into(),
            start: externals_start.into(),
            end: (externals_start + len).into(),
            perms: "rw-".into(),
            initialized: false,
            kind: MemoryKind::External,
        });
        // the decompiler reads a few bytes at a call target
        let fill: Vec<u8> = match language.id {
            "x86:LE:64:default" => vec![X86_RET; len as usize],
            _ => AARCH64_RET
                .iter()
                .copied()
                .cycle()
                .take(len as usize)
                .collect(),
        };
        segments.push(Segment {
            start: externals_start,
            data: fill,
            mem_size: len,
            readonly: false,
        });
    }

    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut pointer_slots: Vec<(u64, u64)> = Vec::new();
    for (slot, name) in &binding.binds {
        let target = stub_of
            .get(name)
            .copied()
            .or_else(|| external_of.get(name.as_str()).copied());
        import_slots.insert(at(*slot), name.clone());
        // Ghidra's pointer label, which the stub's body prints
        data_symbols.entry(at(*slot)).or_insert(DataSymbol {
            name: format!("PTR_{name}_{:08x}", at(*slot)),
            size: 8,
        });
        if let Some(t) = target {
            patch(&mut segments, at(*slot), &t.to_le_bytes());
            pointer_slots.push((at(*slot), t));
        }
    }
    for (slot, target) in &binding.rebases {
        if binding.binds.contains_key(slot) {
            continue;
        }
        patch(&mut segments, at(*slot), &at(*target).to_le_bytes());
        pointer_slots.push((at(*slot), at(*target)));
    }
    pointer_slots.sort_unstable();
    got_code.sort_unstable();
    got_code.dedup();

    // exports: the trie when there is one
    let mut exports: BTreeMap<u64, ExportSymbol> = BTreeMap::new();
    let trie = exports_trie
        .and_then(|t| t.exports_trie(endian, data).ok())
        .or_else(|| dyld_info.and_then(|d| d.exports_trie(endian, data).ok()));
    if let Some(mut it) = trie {
        for _ in 0..MAX_WALK {
            let Ok(Some(e)) = it.next() else { break };
            let offset = match e.data() {
                ExportData::Regular { address } => *address,
                ExportData::StubAndResolver { stub_address, .. } => *stub_address,
                _ => continue,
            };
            let addr = link.wrapping_add(offset);
            let kind = if in_exec(addr) {
                ProtoSymbolKind::Function
            } else {
                ProtoSymbolKind::Data
            };
            exports.entry(at(addr)).or_insert(ExportSymbol {
                name: symbol_name(e.name()),
                kind,
                member: None,
            });
        }
    }
    if exports.is_empty() {
        exports = defined_exports;
    }

    // the entry point: LC_MAIN counts from __TEXT
    let entry = entry_offset
        .map(|o| link.wrapping_add(o))
        .or(thread)
        .filter(|a| *a != 0 && in_exec(*a))
        .map(at);
    if let Some(e) = entry {
        // Ghidra names the entry first; `_main` stays a second label
        functions.insert(e, "entry".to_string());
        if let Some(x) = exports.get_mut(&e) {
            x.name = "entry".to_string();
        }
    }

    // function starts
    let mut starts: Vec<u64> = Vec::new();
    if let Some(mut it) = function_starts.and_then(|c| c.function_starts(endian, data, link).ok()) {
        for _ in 0..MAX_WALK {
            let Ok(Some(a)) = it.next() else { break };
            if in_exec(a) {
                starts.push(at(a));
            }
        }
    }
    let section_bytes = |c: &Sect| -> Option<&[u8]> {
        let end = u64::from(c.offset).checked_add(c.size)?;
        data.get(c.offset as usize..end as usize)
    };
    if let Some(info) = sects.iter().find(|c| c.name == "__unwind_info")
        && let Some(bytes) = section_bytes(info)
    {
        for o in unwind_starts(bytes) {
            let a = link.wrapping_add(u64::from(o));
            if in_exec(a) {
                starts.push(at(a));
            }
        }
    }
    starts.sort_unstable();
    starts.dedup();

    let mut fde_starts = Vec::new();
    let mut landing_pads = BTreeMap::new();
    if let Some(eh) = sects.iter().find(|c| c.name == "__eh_frame")
        && let Some(bytes) = section_bytes(eh)
    {
        let read = |a: u64, n: usize| -> Option<Vec<u8>> {
            read_at(&segs, data, a, n).map(<[u8]>::to_vec)
        };
        let code = sects.iter().find(|c| c.name == "__text").map(|c| c.addr);
        let frames = crate::eh::parse(&crate::eh::Sections {
            eh_frame: (eh.addr, bytes),
            text: code,
            got: None,
            read: &read,
            address_size: 8,
            endian: crate::elf::Endian::Little,
        });
        fde_starts = frames
            .fde_starts
            .iter()
            .filter(|a| in_exec(**a))
            .map(|a| at(*a))
            .collect();
        landing_pads = frames
            .landing_pads
            .iter()
            .map(|(f, pads)| (at(*f), pads.iter().map(|p| at(*p)).collect()))
            .collect();
    }

    // static constructors: pointers or, in newer files, offsets from __TEXT
    let mut init_pointers = Vec::new();
    for c in &sects {
        let (step, count) = match c.kind {
            macho::S_MOD_INIT_FUNC_POINTERS => (8, c.size / 8),
            macho::S_INIT_FUNC_OFFSETS => (4, c.size / 4),
            _ => continue,
        };
        for i in 0..count.min(4096) {
            let slot = c.addr.wrapping_add(i * step);
            let target = if step == 8 {
                binding.rebases.get(&slot).copied()
            } else {
                read_at(&segs, data, slot, 4).map(|b| {
                    link.wrapping_add(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
                })
            };
            if let Some(t) = target.filter(|t| in_exec(*t)) {
                init_pointers.push(at(t));
            }
        }
    }

    let mut data_pointers: Vec<u64> = pointer_slots.iter().map(|(_, t)| *t).collect();
    data_pointers.sort_unstable();
    data_pointers.dedup();

    // DWARF, for the rare file that carries it in its own __DWARF segment
    let mut debug = match object::File::parse(data) {
        Ok(f) => crate::dwarf::parse(&f),
        Err(_) => crate::dwarf::Debug::default(),
    };
    debug.functions = std::mem::take(&mut debug.functions)
        .into_iter()
        .map(|(a, f)| (at(a), f))
        .collect();
    debug.globals = std::mem::take(&mut debug.globals)
        .into_iter()
        .map(|(a, g)| (at(a), g))
        .collect();

    blocks.sort_by_key(|b| b.start.0);
    Ok(Loaded {
        format: "macho",
        container: "macho",
        description: description.into(),
        members: Vec::new(),
        language,
        base,
        image: Image {
            segments,
            context: Vec::new(),
            entry_registers: Vec::new(),
        },
        blocks,
        functions,
        code_symbols,
        data_symbols,
        debug,
        plt,
        import_slots,
        externals,
        pdata_starts: starts,
        conventions: BTreeMap::new(),
        pic_base: None,
        entry,
        init_pointers,
        data_pointers,
        pointer_slots,
        imports,
        exports,
        fde_starts,
        landing_pads,
        got_code,
        default_names: BTreeMap::new(),
        global_pointer: None,
        exec_segments: Vec::new(),
        small_data: Vec::new(),
        endian: crate::elf::Endian::Little,
    })
}
