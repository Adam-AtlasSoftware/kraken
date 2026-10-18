//! PE loading (PE32 and PE32+, x86 and x86-64) with the `object` crate, in Ghidra's shape: the
//! image at its preferred base, a `Headers` block and one block per section (named by the
//! 8-byte section header name, as Ghidra does), imports by name and by ordinal (`Ordinal_<n>`)
//! with the library they come from, exports, base relocations, the entry point, TLS callbacks
//! (`tls_callback_<n>`) and, on x86-64, the function starts of the exception directory
//! (`.pdata`). Names come from the COFF symbol table when the image has one (mingw-w64 keeps
//! it unless stripped) and from the export table.
//!
//! Imported functions are reached through the import address table. The decompiler gets a
//! copy of the image in which every IAT slot holds a synthetic address past the image (Ghidra's
//! `EXTERNAL` block), where a function of the import's name stands, so `call [slot]` decompiles
//! as a call to `GetModuleHandleA`; the slots are read-only so the load folds. Thunks (`jmp
//! [slot]`, which mingw-w64 emits for imports not declared `dllimport`) are named after their
//! import, like ELF PLT stubs.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::LittleEndian as LE;
use object::pe;
use object::read::pe::{
    ExportTarget, ImageNtHeaders, ImageOptionalHeader, ImageThunkData, Import, PeFile,
};
use object::read::{Object, ObjectSection, ObjectSymbol};
use object::{FileKind, SymbolKind};

use crate::discover::{in_ranges, merge_ranges};
use crate::elf::{ExportSymbol, ImportSymbol, Language, Loaded, le_word};

/// Largest image (`SizeOfImage`) the loader lays out; every section is cut to the image.
const MAX_IMAGE: u64 = 1 << 30;
/// Room above the image for the import stand-ins, so address sums cannot overflow.
const ADDRESS_HEADROOM: u64 = 1 << 33;
/// Most sections the loader takes (the Windows loader stops at 96).
const MAX_SECTIONS: usize = 1024;

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Parses a PE image; `base_override` rebases it (applying its base relocations).
pub fn load(data: &[u8], base_override: Option<u64>) -> Result<Loaded, ProtoError> {
    match FileKind::parse(data) {
        Ok(FileKind::Pe32) => load_pe::<pe::ImageNtHeaders32>(data, base_override),
        Ok(FileKind::Pe64) => load_pe::<pe::ImageNtHeaders64>(data, base_override),
        _ => Err(bad("not a PE image")),
    }
}

/// The C name of an x86 COFF symbol: `_by_key` -> `by_key`, `_on_tls@12` -> `on_tls`; `None` for
/// names that are not decorated that way (`__x`, fastcall `@f@8`, C++).
pub fn undecorate(name: &str) -> Option<String> {
    let rest = name.strip_prefix('_')?;
    if rest.starts_with('_') || rest.is_empty() || rest.starts_with('?') {
        return None;
    }
    let base = match rest.rsplit_once('@') {
        Some((b, n)) if !b.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => b,
        _ => rest,
    };
    Some(base.to_string())
}

/// Whether `name` has a prototype in the library tables (C library or Win32 and the C runtime).
pub(crate) fn known_library_name(name: &str) -> bool {
    use std::sync::OnceLock;
    static NAMES: OnceLock<BTreeSet<String>> = OnceLock::new();
    NAMES
        .get_or_init(|| {
            crate::libc::PROTOTYPES
                .iter()
                .chain(crate::win32::PROTOTYPES)
                .filter_map(|p| crate::ctypes::parse_prototype(p).ok().map(|(n, _)| n))
                .chain(
                    [
                        "main",
                        "wmain",
                        "WinMain",
                        "wWinMain",
                        "DllMain",
                        "DllMainCRTStartup",
                        "DllEntryPoint",
                        "WinMainCRTStartup",
                    ]
                    .map(String::from),
                )
                .collect()
        })
        .contains(name)
}

/// The bytes a 32-bit `__stdcall` function of the Win32 table pops on return.
fn stdcall_purge(name: &str) -> Option<u16> {
    use kraken_proto::TypeRef;
    let src = crate::win32::PROTOTYPES.iter().find(|p| {
        p.split('(')
            .next()
            .and_then(|h| h.split_whitespace().last())
            == Some(name)
    })?;
    let (_, proto) =
        crate::ctypes::parse_prototype_in(src, crate::ctypes::DataModel::ILP32).ok()?;
    if proto.calling_convention != "__stdcall" || proto.varargs {
        return None;
    }
    let size = |t: &TypeRef| match t {
        TypeRef::Primitive(p) if p.size > 4 => 8,
        _ => 4,
    };
    Some(proto.params.iter().map(|p| size(&p.ty)).sum())
}

/// One COFF function symbol.
struct CoffSymbol {
    addr: u64,
    name: String,
    global: bool,
}

/// Bytes of the file at a relative virtual address, from the section that holds it.
struct Rva<'d> {
    data: &'d [u8],
    sections: Vec<(u32, u32, u32, u32)>, // (rva, virtual size, file offset, raw size)
    headers: u32,
}

impl Rva<'_> {
    fn bytes(&self, rva: u32, n: usize) -> Option<&[u8]> {
        if rva < self.headers {
            return self.data.get(rva as usize..rva as usize + n);
        }
        for (va, vsize, off, raw) in &self.sections {
            let len = (*vsize).max(*raw);
            if rva >= *va && u64::from(rva) < u64::from(*va) + u64::from(len) {
                let at = (rva - va) as usize;
                if at + n > *raw as usize {
                    return None;
                }
                return self.data.get(*off as usize + at..*off as usize + at + n);
            }
        }
        None
    }

    fn word(&self, rva: u32, ptr: usize) -> Option<u64> {
        self.bytes(rva, ptr).map(le_word)
    }
}

fn load_pe<Pe: ImageNtHeaders>(
    data: &[u8],
    base_override: Option<u64>,
) -> Result<Loaded, ProtoError> {
    let file = PeFile::<Pe>::parse(data).map_err(|e| bad(format!("cannot parse PE: {e}")))?;
    let nt = file.nt_headers();
    let machine = nt.file_header().machine.get(LE);
    let (language, ptr) = match machine {
        pe::IMAGE_FILE_MACHINE_I386 => (
            Language {
                id: "x86:LE:32:default",
                compiler: "windows",
                pointer_size: 4,
            },
            4usize,
        ),
        pe::IMAGE_FILE_MACHINE_AMD64 => (
            Language {
                id: "x86:LE:64:default",
                compiler: "windows",
                pointer_size: 8,
            },
            8usize,
        ),
        other => {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("PE machine {other:#06x} is not supported by the native engine yet"),
            ));
        }
    };
    let opt = nt.optional_header();
    let link_base = opt.image_base();
    let base = base_override.unwrap_or(link_base);
    let image_size = u64::from(opt.size_of_image());
    if image_size > MAX_IMAGE {
        return Err(bad(format!(
            "PE image of {image_size} bytes is larger than the {MAX_IMAGE} bytes the native engine lays out"
        )));
    }
    if link_base.checked_add(ADDRESS_HEADROOM).is_none()
        || base.checked_add(ADDRESS_HEADROOM).is_none()
    {
        return Err(bad("PE image base is out of range"));
    }
    let bias = base.wrapping_sub(link_base);
    // link-time virtual address -> loaded address
    let at = |va: u64| va.wrapping_add(bias);
    let mask = if ptr == 4 { 0xffff_ffff } else { u64::MAX };
    let headers_size = opt.size_of_headers().min(image_size as u32);
    let section_table = file.section_table();
    if section_table.len() > MAX_SECTIONS {
        return Err(bad(format!(
            "PE image has {} sections, more than the {MAX_SECTIONS} the native engine takes",
            section_table.len()
        )));
    }
    // (rva, virtual size, file offset, raw size), cut to the image as the Windows loader
    // requires; a section outside it is dropped
    let fitted: Vec<Option<(u32, u32, u32, u32)>> = section_table
        .iter()
        .map(|s| {
            let va = s.virtual_address.get(LE);
            let room = image_size.checked_sub(u64::from(va)).filter(|r| *r > 0)? as u32;
            Some((
                va,
                s.virtual_size.get(LE).min(room),
                s.pointer_to_raw_data.get(LE),
                s.size_of_raw_data.get(LE).min(room),
            ))
        })
        .collect();
    let rva = Rva {
        data,
        sections: fitted.iter().flatten().copied().collect(),
        headers: headers_size,
    };
    let dirs = file.data_directories();
    let dir_range = |id: usize| {
        dirs.get(id)
            .map(|d| (d.virtual_address.get(LE), d.size.get(LE)))
            .filter(|(a, s)| *a != 0 && *s != 0)
    };

    // imports: the slots of the import address table, by name or ordinal
    let mut imports: Vec<ImportSymbol> = Vec::new();
    let mut slots: BTreeMap<u64, (String, String)> = BTreeMap::new(); // link VA -> (name, library)
    if let Ok(Some(table)) = dirs.import_table(data, &section_table)
        && let Ok(mut descriptors) = table.descriptors()
    {
        while let Ok(Some(desc)) = descriptors.next() {
            let library = table
                .name(desc.name.get(LE))
                .map(|n| String::from_utf8_lossy(n).to_ascii_uppercase())
                .unwrap_or_default();
            let first = desc.first_thunk.get(LE);
            let lookup = match desc.original_first_thunk.get(LE) {
                0 => first,
                a => a,
            };
            let Ok(mut thunks) = table.thunks(lookup) else {
                continue;
            };
            let mut i = 0u64;
            while let Ok(Some(thunk)) = thunks.next::<Pe>() {
                let name = match table.import::<Pe>(thunk) {
                    Ok(Import::Name(_, n)) => String::from_utf8_lossy(n).into_owned(),
                    Ok(Import::Ordinal(o)) => format!("Ordinal_{o}"),
                    Err(_) if thunk.is_ordinal() => format!("Ordinal_{}", thunk.ordinal()),
                    Err(_) => {
                        i += 1;
                        continue;
                    }
                };
                let slot = link_base + u64::from(first) + i * ptr as u64;
                slots.insert(slot, (name, library.clone()));
                i += 1;
            }
        }
    }

    // the image the decompiler reads: headers and sections at the loaded base
    let iat = dir_range(pe::IMAGE_DIRECTORY_ENTRY_IAT);
    let import_dir = dir_range(pe::IMAGE_DIRECTORY_ENTRY_IMPORT);
    let holds = |va: u32, len: u32, r: Option<(u32, u32)>| {
        r.is_some_and(|(a, s)| a < va.saturating_add(len) && va < a.saturating_add(s))
    };
    let mut segments = Vec::new();
    let mut blocks = Vec::new();
    let mut exec_ranges: Vec<(u64, u64)> = Vec::new(); // link VAs
    let mut exec_bytes: Vec<(u64, &[u8])> = Vec::new(); // link VA, raw bytes
    let long_names: Vec<String> = file
        .sections()
        .map(|s| s.name().unwrap_or_default().to_string())
        .collect();
    let mut eh_frame: Option<(u64, &[u8])> = None;
    let header_bytes = data
        .get(..(headers_size as usize).min(data.len()))
        .unwrap_or_default();
    segments.push(Segment {
        start: base,
        data: header_bytes.to_vec(),
        mem_size: u64::from(headers_size).max(header_bytes.len() as u64),
        readonly: true,
    });
    blocks.push(MemoryBlock {
        name: "Headers".into(),
        space: "ram".into(),
        start: base.into(),
        end: (base + u64::from(headers_size)).into(),
        perms: "r--".into(),
        initialized: true,
        kind: MemoryKind::Default,
    });
    let mut section_names: Vec<(u64, u64, String)> = Vec::new(); // link VA range, long name
    for (i, s) in section_table.iter().enumerate() {
        let Some((va, vsize, off, raw)) = fitted[i] else {
            continue;
        };
        let off = off as usize;
        let flags = s.characteristics.get(LE);
        let size = vsize.max(raw);
        if size == 0 {
            continue;
        }
        let bytes = if raw == 0 {
            &[][..]
        } else {
            data.get(off..off.saturating_add(raw as usize).min(data.len()))
                .unwrap_or_default()
        };
        let exec = flags & pe::IMAGE_SCN_MEM_EXECUTE != 0;
        // the import tables are read-only once bound (Ghidra shows `.idata` as r--)
        let write = flags & pe::IMAGE_SCN_MEM_WRITE != 0
            && !holds(va, size, iat)
            && !holds(va, size, import_dir);
        let start = base + u64::from(va);
        segments.push(Segment {
            start,
            data: bytes.to_vec(),
            mem_size: u64::from(size),
            readonly: !write,
        });
        let raw_name = s.raw_name();
        let short = String::from_utf8_lossy(raw_name).into_owned();
        let short = if short.is_empty() {
            format!("section_{i}")
        } else {
            short
        };
        let long = long_names.get(i).cloned().unwrap_or_else(|| short.clone());
        let in_memory = &bytes[..bytes
            .len()
            .min(if vsize == 0 { raw } else { vsize } as usize)];
        if long == ".eh_frame" || long == ".eh_fram" {
            eh_frame = Some((link_base + u64::from(va), in_memory));
        }
        section_names.push((
            link_base + u64::from(va),
            link_base + u64::from(va + size),
            long,
        ));
        blocks.push(MemoryBlock {
            name: short,
            space: "ram".into(),
            start: start.into(),
            end: (start + u64::from(size)).into(),
            perms: MemoryBlock::perms_string(true, write, exec),
            initialized: raw != 0,
            kind: MemoryKind::Default,
        });
        if exec {
            exec_ranges.push((link_base + u64::from(va), link_base + u64::from(va + size)));
            exec_bytes.push((link_base + u64::from(va), in_memory));
        }
    }
    segments.sort_by_key(|s| s.start);
    blocks.sort_by_key(|b| (b.start, b.end));

    let patch = |segments: &mut Vec<Segment>, addr: u64, bytes: &[u8]| {
        for s in segments.iter_mut() {
            let fits = addr
                .checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= s.start + s.data.len() as u64);
            if addr >= s.start && fits {
                let o = (addr - s.start) as usize;
                s.data[o..o + bytes.len()].copy_from_slice(bytes);
                return;
            }
        }
    };

    // base relocations: the pointers the loader adjusts are the image's data references
    let mut pointer_slots: Vec<(u64, u64)> = Vec::new();
    if let Ok(Some(mut blocks_it)) = dirs.relocation_blocks(data, &section_table) {
        while let Ok(Some(block)) = blocks_it.next() {
            for r in block {
                let width = match r.typ {
                    pe::IMAGE_REL_BASED_HIGHLOW => 4,
                    pe::IMAGE_REL_BASED_DIR64 => 8,
                    _ => continue,
                };
                let Some(v) = rva.word(r.virtual_address, width) else {
                    continue;
                };
                let slot = at(link_base + u64::from(r.virtual_address));
                let target = v.wrapping_add(bias) & mask;
                if bias != 0 {
                    let b = target.to_le_bytes();
                    patch(&mut segments, slot, &b[..width]);
                }
                if target != 0 {
                    pointer_slots.push((slot, target));
                }
            }
        }
    }
    pointer_slots.sort_unstable();
    pointer_slots.dedup();

    // imported functions get synthetic addresses past the image; the slots point there
    let image_end = base + u64::from(opt.size_of_image());
    let externals_start = (image_end + 0xfff) & !0xfff;
    let mut externals: BTreeMap<u64, String> = BTreeMap::new();
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut external_of: BTreeMap<String, u64> = BTreeMap::new();
    for (slot, (name, _)) in &slots {
        let next = externals_start + (external_of.len() as u64) * ptr as u64;
        let ext = *external_of.entry(name.clone()).or_insert(next);
        externals.insert(ext, name.clone());
        import_slots.insert(at(*slot), name.clone());
        let b = ext.to_le_bytes();
        patch(&mut segments, at(*slot), &b[..ptr]);
    }
    // the decompiler reads a few bytes at a call target, so the stand-ins hold returns: `ret`,
    // or on x86 `ret <n>` for a `__stdcall` function of the Win32 table, which pops its
    // arguments. They are in no memory block, and writable, so a load through a data import
    // (`kr_counter`) stays a load instead of folding to those bytes.
    if !externals.is_empty() {
        let len = external_of.len() * ptr + 16;
        let mut bytes = vec![0xc3; len];
        if ptr == 4 {
            for (name, ext) in &external_of {
                if let Some(n) = stdcall_purge(name) {
                    let o = (ext - externals_start) as usize;
                    bytes[o..o + 3].copy_from_slice(&[0xc2, n as u8, (n >> 8) as u8]);
                }
            }
        }
        segments.push(Segment {
            start: externals_start,
            data: bytes,
            mem_size: len as u64,
            readonly: false,
        });
    }
    let image = Image {
        segments,
        context: Vec::new(),
    };

    // thunks: `jmp [slot]` (rip-relative on x86-64, absolute on x86)
    let mut plt: BTreeMap<u64, String> = BTreeMap::new();
    for (lo, bytes) in &exec_bytes {
        let mut j = 0;
        while j + 6 <= bytes.len() {
            if bytes[j] != 0xff || bytes[j + 1] != 0x25 {
                j += 1;
                continue;
            }
            let d = i32::from_le_bytes([bytes[j + 2], bytes[j + 3], bytes[j + 4], bytes[j + 5]]);
            let here = lo + j as u64;
            let slot = if ptr == 8 {
                (here + 6).wrapping_add_signed(i64::from(d))
            } else {
                u64::from(d as u32)
            };
            if let Some((name, _)) = slots.get(&slot) {
                plt.insert(at(here), name.clone());
                j += 6;
            } else {
                j += 1;
            }
        }
    }
    let thunked: BTreeSet<&str> = plt.values().map(String::as_str).collect();
    let mut listed: BTreeSet<&str> = BTreeSet::new();
    for (name, library) in slots.values() {
        if !listed.insert(name.as_str()) {
            continue;
        }
        // an import without a thunk is data or a `dllimport` function called through its slot;
        // Ghidra's typing tells them apart, here a thunk does
        let kind = if thunked.contains(name.as_str()) || name.starts_with("Ordinal_") {
            ProtoSymbolKind::Function
        } else {
            ProtoSymbolKind::Data
        };
        imports.push(ImportSymbol {
            name: name.clone(),
            kind,
            library: Some(library.clone()),
        });
    }
    imports.sort_by(|a, b| a.name.cmp(&b.name));

    // COFF symbols: functions, and untyped symbols in code (assembly such as `___chkstk_ms`)
    let exec_merged = merge_ranges(exec_ranges);
    let in_exec = |va: u64| in_ranges(&exec_merged, va);
    let mut coff: Vec<CoffSymbol> = Vec::new();
    for sym in file.symbols() {
        let code = match sym.kind() {
            SymbolKind::Text => true,
            SymbolKind::Data | SymbolKind::Unknown => in_exec(sym.address()),
            _ => false,
        };
        if !code || !sym.is_definition() || sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || name.starts_with('.') {
            continue;
        }
        coff.push(CoffSymbol {
            addr: at(sym.address()),
            name: name.to_string(),
            global: sym.is_global(),
        });
    }
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for s in &coff {
        let names = code_symbols.entry(s.addr).or_default();
        if !names.contains(&s.name) {
            names.push(s.name.clone());
        }
    }
    // the name of an address: a library function's own name first (`_fpreset` over
    // `__fpreset`), then its first global symbol, else its first static one. On x86 a static C
    // name loses its decoration (`_by_key` -> `by_key`) unless it is a library function's, and
    // an Itanium name its extra underscore (`__ZN..`), as Ghidra shows them.
    let mut functions: BTreeMap<u64, String> = BTreeMap::new();
    let known =
        |n: &str| known_library_name(n) || undecorate(n).is_some_and(|c| known_library_name(&c));
    for pass in 0..3 {
        for s in &coff {
            let take = match pass {
                0 => s.global && known(&s.name),
                1 => s.global,
                _ => true,
            };
            if !take || functions.contains_key(&s.addr) {
                continue;
            }
            let mut name = s.name.clone();
            if ptr == 4 {
                if let Some(itanium) = name.strip_prefix("__Z") {
                    name = format!("_Z{itanium}");
                } else if !s.global
                    && let Some(c) = undecorate(&name)
                    && !known_library_name(&c)
                {
                    name = c;
                }
            }
            functions.insert(s.addr, name);
        }
    }
    // x86 decorations tell the convention
    let mut conventions: BTreeMap<u64, String> = BTreeMap::new();
    if ptr == 4 {
        for s in &coff {
            let decorated = s.name.rsplit_once('@').is_some_and(|(b, n)| {
                !b.is_empty() && !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())
            });
            if !decorated {
                continue;
            }
            let c = if s.name.starts_with('@') {
                "__fastcall"
            } else if s.name.starts_with('_') && !s.name.starts_with("__Z") {
                "__stdcall"
            } else {
                continue;
            };
            conventions.entry(s.addr).or_insert_with(|| c.to_string());
        }
    }
    // a thunk is named after its import, or on x86 after its symbol without the decoration
    // (`___getmainargs` stays, `_abort` is `abort`)
    for (a, n) in &plt {
        // the first symbol at the address, as `coff` lists them
        let name = match (ptr, code_symbols.get(a).and_then(|v| v.first())) {
            (4, Some(s)) => undecorate(s).unwrap_or_else(|| s.clone()),
            _ => n.clone(),
        };
        functions.insert(*a, name);
    }
    let exec_at = |a: u64| in_exec(a.wrapping_sub(bias));

    // exports: names from the export table win
    let mut exports: BTreeMap<u64, ExportSymbol> = BTreeMap::new();
    let mut default_names: BTreeMap<u64, String> = BTreeMap::new();
    if let Ok(Some(table)) = dirs.export_table(data, &section_table)
        && let Ok(list) = table.exports()
    {
        for e in list {
            let ExportTarget::Address(r) = e.target else {
                continue;
            };
            let addr = at(link_base + u64::from(r));
            let exec = exec_at(addr);
            let kind = if exec {
                ProtoSymbolKind::Function
            } else {
                ProtoSymbolKind::Data
            };
            let name = match e.name {
                Some(n) => {
                    let n = String::from_utf8_lossy(n).into_owned();
                    if exec {
                        functions.insert(addr, n.clone());
                        let names = code_symbols.entry(addr).or_default();
                        if !names.contains(&n) {
                            names.push(n.clone());
                        }
                    }
                    n
                }
                None => {
                    let n = format!("Ordinal_{}", e.ordinal);
                    default_names.entry(addr).or_insert_with(|| n.clone());
                    functions.get(&addr).cloned().unwrap_or(n)
                }
            };
            exports.entry(addr).or_insert(ExportSymbol { name, kind });
        }
    }

    let entry_rva = opt.address_of_entry_point();
    let entry = (entry_rva != 0).then(|| base + u64::from(entry_rva));
    // the entry point and the exports keep no decoration either (`mainCRTStartup`)
    if ptr == 4 {
        let addrs: Vec<u64> = entry.iter().chain(exports.keys()).copied().collect();
        for a in &addrs {
            if let Some(n) = functions.get_mut(a)
                && let Some(c) = undecorate(n)
                && !known_library_name(&c)
            {
                if let Some(e) = exports.get_mut(a).filter(|e| e.name == *n) {
                    e.name = c.clone();
                }
                *n = c;
            }
        }
    }

    // TLS callbacks: an array of absolute pointers ending with 0
    let mut init_pointers = Vec::new();
    if let Some((tls, _)) = dir_range(pe::IMAGE_DIRECTORY_ENTRY_TLS)
        && let Some(callbacks) = tls
            .checked_add(3 * ptr as u32)
            .and_then(|a| rva.word(a, ptr))
        && callbacks != 0
    {
        let mut i = 0u32;
        while let Some(v) = callbacks
            .checked_sub(link_base)
            .and_then(|r| rva.word((r as u32).wrapping_add(i * ptr as u32), ptr))
        {
            if v == 0 || i >= 64 {
                break;
            }
            let addr = at(v) & mask;
            init_pointers.push(addr);
            let name = format!("tls_callback_{i}");
            // Ghidra's label wins over the symbol names on x86-64; on x86 its demangler
            // renames the decorated ones again
            if ptr == 8 {
                functions.insert(addr, name.clone());
            }
            default_names.entry(addr).or_insert(name);
            i += 1;
        }
    }

    // x86-64 exception directory: one RUNTIME_FUNCTION per function (or part, chained)
    let mut pdata_starts = Vec::new();
    if ptr == 8
        && let Some((exc, size)) = dir_range(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    {
        for k in 0..size / 12 {
            let Some(e) = exc.checked_add(k * 12).and_then(|a| rva.bytes(a, 12)) else {
                break;
            };
            let begin = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            let unwind = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
            if begin == 0 {
                continue;
            }
            // UNW_FLAG_CHAININFO: a part of the function of the chained entry
            let chained = rva
                .bytes(unwind & !1, 1)
                .is_some_and(|b| (b[0] >> 3) & 0x4 != 0);
            if !chained {
                pdata_starts.push(base + u64::from(begin));
            }
        }
        pdata_starts.sort_unstable();
        pdata_starts.dedup();
    }

    // mingw-w64's 32-bit code carries DWARF unwind tables in `.eh_frame`
    let mut fde_starts = Vec::new();
    let mut landing_pads = BTreeMap::new();
    if let Some((lo, bytes)) = eh_frame {
        let read = |a: u64, n: usize| -> Option<Vec<u8>> {
            let r = a.checked_sub(link_base)?;
            rva.bytes(r as u32, n).map(<[u8]>::to_vec)
        };
        let text = section_names
            .iter()
            .find(|(_, _, n)| n == ".text")
            .map(|(a, _, _)| *a);
        let frames = crate::eh::parse(&crate::eh::Sections {
            eh_frame: (lo, bytes),
            text,
            got: None,
            read: &read,
            address_size: ptr as u8,
        });
        fde_starts = frames.fde_starts.iter().map(|a| at(*a) & mask).collect();
        landing_pads = frames
            .landing_pads
            .iter()
            .map(|(f, pads)| (at(*f) & mask, pads.iter().map(|p| at(*p) & mask).collect()))
            .collect();
    }

    let mut data_pointers: Vec<u64> = pointer_slots.iter().map(|(_, t)| *t).collect();
    data_pointers.sort_unstable();
    data_pointers.dedup();

    // DWARF, when a mingw-w64 build kept it
    let mut debug = match object::File::parse(data) {
        Ok(f) => crate::dwarf::parse(&f),
        Err(_) => crate::dwarf::Debug::default(),
    };
    debug.functions = std::mem::take(&mut debug.functions)
        .into_iter()
        .map(|(a, f)| (at(a), f))
        .collect();

    let dll = nt.file_header().characteristics.get(LE) & pe::IMAGE_FILE_DLL != 0;
    Ok(Loaded {
        format: "pe",
        container: "pe",
        description: if dll {
            "Windows DLL"
        } else {
            "Windows program"
        }
        .into(),
        members: Vec::new(),
        language,
        base,
        image,
        blocks,
        functions,
        code_symbols,
        debug,
        plt,
        import_slots,
        externals,
        pdata_starts,
        conventions,
        pic_base: None,
        entry,
        init_pointers,
        data_pointers,
        pointer_slots,
        imports,
        exports,
        fde_starts,
        landing_pads,
        got_code: Vec::new(),
        default_names,
        global_pointer: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/pe/bin")
            .join(name);
        std::fs::read(p).expect("corpus binary")
    }

    /// Offsets of (optional header, section table, section count) in a PE file.
    fn headers(d: &[u8]) -> (usize, usize, usize) {
        let pe = u32::from_le_bytes(d[0x3c..0x40].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(d[pe + 6..pe + 8].try_into().unwrap()) as usize;
        let opt_size = u16::from_le_bytes(d[pe + 20..pe + 22].try_into().unwrap()) as usize;
        (pe + 24, pe + 24 + opt_size, count)
    }

    #[test]
    fn hostile_sizes_stay_inside_the_image() {
        let mut d = corpus("win_tls-x64-O0.exe");
        let (opt, table, count) = headers(&d);
        let image_size = u32::from_le_bytes(d[opt + 56..opt + 60].try_into().unwrap());
        // every section claims 4 GiB in memory
        for i in 0..count {
            let s = table + 40 * i;
            d[s + 8..s + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let l = load(&d, None).expect("load");
        let end = l.base + u64::from(image_size);
        assert!(l.blocks.iter().all(|b| b.end.0 <= end), "{:?}", l.blocks);
        // and the string scan reads no more than the file holds
        let strings = crate::strings::scan(&l.image, &l.blocks, 4, &[]);
        assert!(!strings.is_empty());

        let mut big = corpus("win_tls-x64-O0.exe");
        big[opt + 56..opt + 60].copy_from_slice(&0xffff_f000u32.to_le_bytes());
        assert!(load(&big, None).is_err());

        let mut high = corpus("win_tls-x64-O0.exe");
        high[opt + 24..opt + 32].copy_from_slice(&(u64::MAX - 0x1000).to_le_bytes());
        assert!(load(&high, None).is_err());
        assert!(load(&corpus("win_tls-x64-O0.exe"), Some(u64::MAX - 0x1000)).is_err());
    }

    #[test]
    fn decorations_come_off_c_names() {
        assert_eq!(undecorate("_by_key").as_deref(), Some("by_key"));
        assert_eq!(undecorate("_on_tls@12").as_deref(), Some("on_tls"));
        assert_eq!(undecorate("___main"), None);
        assert_eq!(undecorate("main"), None);
        assert_eq!(undecorate("_a@b").as_deref(), Some("a@b"));
    }

    #[test]
    fn pe32_plus_loads_like_ghidra() {
        let l = load(&corpus("win_tls-x64-O0.exe"), None).expect("load");
        assert_eq!(l.format, "pe");
        assert_eq!(l.language.id, "x86:LE:64:default");
        assert_eq!(l.language.compiler, "windows");
        assert_eq!(l.base, 0x1_4000_0000);
        let names: Vec<(&str, u64, u64)> = l
            .blocks
            .iter()
            .map(|b| (b.name.as_str(), b.start.0, b.end.0))
            .collect();
        assert_eq!(names[0], ("Headers", 0x1_4000_0000, 0x1_4000_0400));
        assert!(
            names.contains(&(".text", 0x1_4000_1000, 0x1_4000_8400)),
            "{names:x?}"
        );
        assert!(
            names.contains(&(".bss", 0x1_4000_d000, 0x1_4000_dba0)),
            "{names:x?}"
        );
        let idata = l
            .blocks
            .iter()
            .find(|b| b.name == ".idata")
            .expect(".idata");
        assert_eq!(idata.perms, "r--");
        assert_eq!(l.entry, Some(0x1_4000_13f0));
        assert_eq!(
            l.functions.get(&0x1_4000_13f0).map(String::as_str),
            Some("mainCRTStartup")
        );
        assert_eq!(
            l.functions.get(&0x1_4000_17c7).map(String::as_str),
            Some("main")
        );
        // thunks are named after their import
        assert_eq!(
            l.plt.get(&0x1_4000_81d0).map(String::as_str),
            Some("GetModuleHandleA")
        );
        assert_eq!(l.plt.get(&0x1_4000_8118).map(String::as_str), Some("qsort"));
        // imports by name and by ordinal, with their library
        let ord = l
            .imports
            .iter()
            .find(|i| i.name == "Ordinal_3")
            .expect("ordinal import");
        assert_eq!(ord.library.as_deref(), Some("WIN_DLL.DLL"));
        let k32 = l
            .imports
            .iter()
            .find(|i| i.name == "VirtualAlloc")
            .expect("VirtualAlloc");
        assert_eq!(k32.library.as_deref(), Some("KERNEL32.DLL"));
        // TLS callbacks, named as Ghidra names them on x86-64
        assert_eq!(l.init_pointers.len(), 3, "{:x?}", l.init_pointers);
        assert_eq!(
            l.functions.get(&0x1_4000_14a4).map(String::as_str),
            Some("tls_callback_0")
        );
        // `.pdata` gives function starts, the IAT slots hold external addresses
        assert!(
            l.pdata_starts.contains(&0x1_4000_14e2),
            "{:x?}",
            l.pdata_starts
        );
        assert!(!l.import_slots.is_empty());
        let (slot, name) = l.import_slots.iter().next().expect("slot");
        let mut b = [0u8; 8];
        assert!(l.image.read(*slot, &mut b));
        let ext = u64::from_le_bytes(b);
        assert_eq!(l.externals.get(&ext), Some(name));
        assert!(!l.blocks.iter().any(|b| b.start.0 <= ext && ext < b.end.0));
    }

    #[test]
    fn pe32_loads_with_x86_names() {
        let l = load(&corpus("win_tls-x86-O0.exe"), None).expect("load");
        assert_eq!(l.language.id, "x86:LE:32:default");
        assert_eq!(l.base, 0x40_0000);
        // statics lose their decoration, library and global names keep it
        assert_eq!(
            l.functions.get(&0x40_152c).map(String::as_str),
            Some("on_tls")
        );
        assert_eq!(
            l.functions.get(&0x40_1556).map(String::as_str),
            Some("by_key")
        );
        assert_eq!(
            l.functions.get(&0x40_14f0).map(String::as_str),
            Some("_printf")
        );
        assert_eq!(
            l.functions.get(&0x40_1799).map(String::as_str),
            Some("_main")
        );
        assert_eq!(l.plt.get(&0x40_8398).map(String::as_str), Some("qsort"));
        let blocks: Vec<&str> = l.blocks.iter().map(|b| b.name.as_str()).collect();
        assert!(blocks.contains(&".eh_fram"), "{blocks:?}");
        assert!(!l.fde_starts.is_empty());
        assert_eq!(l.init_pointers.len(), 3, "{:x?}", l.init_pointers);
    }

    #[test]
    fn dll_exports_and_rebasing() {
        let data = corpus("win_dll-x64-O0.dll");
        let l = load(&data, None).expect("load");
        assert_eq!(l.base, 0x2_ca15_0000);
        let by_name: BTreeMap<&str, u64> = l
            .exports
            .iter()
            .map(|(a, e)| (e.name.as_str(), *a))
            .collect();
        assert_eq!(by_name.get("kr_add"), Some(&0x2_ca15_13bb));
        // exported by ordinal only, named by the COFF symbol
        assert_eq!(by_name.get("kr_secret"), Some(&0x2_ca15_1421));
        assert_eq!(
            l.exports.get(&0x2_ca15_7020).map(|e| e.kind),
            Some(ProtoSymbolKind::Data)
        );
        assert!(!l.pointer_slots.is_empty());
        // rebased: everything moves, and the relocated pointers follow
        let r = load(&data, Some(0x1000_0000)).expect("rebase");
        let delta = 0x1000_0000u64.wrapping_sub(0x2_ca15_0000);
        assert_eq!(
            r.exports.keys().next().map(|a| a.wrapping_sub(delta)),
            l.exports.keys().next().copied()
        );
        let (slot, target) = r.pointer_slots[0];
        let mut b = [0u8; 8];
        assert!(r.image.read(slot, &mut b));
        assert_eq!(u64::from_le_bytes(b), target);
    }
}
