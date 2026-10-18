//! Relocatable objects and archives: ELF objects (`.o`, `ET_REL`), COFF objects (`.obj`), static
//! libraries (`ar` archives of either, `.a` and `.lib`) and Windows import libraries.
//!
//! Nothing in an object has an address yet, so the loader links it the way Ghidra lays one out:
//! the allocated sections one after another from the image base Ghidra uses for ELF objects
//! (0x100000, 0x10000 on 32-bit x86), each at its alignment, then a GOT for the GOT-relative
//! relocations, an import slot for every `__imp_` symbol, and a stand-in address past the image
//! for every external symbol (as PE imports get them, so a call to `puts` decompiles as a call to
//! `puts`). The common x86-64 and i386 relocations of ELF and COFF are applied, and those of ARM,
//! AArch64 and RISC-V ELF objects (see [`crate::relocs`]), to the image and to the DWARF
//! sections, so names, types and unwind tables read as in a linked program. ARM objects say with
//! their mapping symbols (`$a`, `$t`) which code is Thumb.
//!
//! A static library loads every member into one program, member after member, with the block
//! names prefixed by the member (`kr_core.o:.text`); a definition in one member resolves the
//! references of the others. An import library has no code: it opens as the list of symbols it
//! imports, with their DLL.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Image, Segment};
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError, SymbolKind as ProtoSymbolKind};
use object::pe;
use object::read::archive::ArchiveFile;
use object::read::coff::{ImportFile, ImportName, ImportType};
use object::read::{
    Object, ObjectComdat, ObjectSection, ObjectSymbol, RelocationTarget, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, FileKind, RelocationFlags, SectionFlags, SectionKind, SymbolFlags,
    SymbolIndex, SymbolKind,
};

use crate::elf::{ExportSymbol, ImportSymbol, Language, Loaded, PIE_BASE, PIE_BASE_32, le_word};

/// Most bytes the sections of all objects may take together.
const MAX_LAYOUT: u64 = 1 << 30;
/// Most members an archive may have.
const MAX_MEMBERS: usize = 200_000;
/// Largest section alignment honoured.
const MAX_ALIGN: u64 = 1 << 16;

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn unsupported(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, msg)
}

/// What kind of relocatable input this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Elf,
    Coff,
}

fn language(arch: Architecture, family: Family) -> Result<Language, ProtoError> {
    let compiler = match family {
        Family::Elf => "gcc",
        Family::Coff => "windows",
    };
    match arch {
        Architecture::X86_64 => Ok(Language {
            id: "x86:LE:64:default",
            compiler,
            pointer_size: 8,
        }),
        Architecture::I386 => Ok(Language {
            id: "x86:LE:32:default",
            compiler,
            pointer_size: 4,
        }),
        Architecture::Arm
        | Architecture::Aarch64
        | Architecture::Riscv32
        | Architecture::Riscv64
            if family == Family::Elf =>
        {
            // the languages of linked ELF files of the same processors
            crate::elf::language(arch)
        }
        other => Err(unsupported(format!(
            "object files for {other:?} are not supported by the native engine yet (x86, \
             x86-64, ARM, AArch64 and RISC-V ELF only)"
        ))),
    }
}

/// Whether the processor's relocations are those of [`crate::relocs`].
fn risc(arch: Architecture) -> bool {
    matches!(
        arch,
        Architecture::Arm | Architecture::Aarch64 | Architecture::Riscv32 | Architecture::Riscv64
    )
}

/// Whether `data` is a relocatable object or an archive this module loads.
pub fn handles(data: &[u8]) -> bool {
    if data.starts_with(b"!<arch>\n") || data.starts_with(b"!<thin>\n") {
        return true;
    }
    match FileKind::parse(data) {
        Ok(FileKind::Archive | FileKind::Coff | FileKind::CoffBig | FileKind::CoffImport) => true,
        Ok(FileKind::Elf32 | FileKind::Elf64) => {
            object::File::parse(data).is_ok_and(|f| f.kind() == object::ObjectKind::Relocatable)
        }
        _ => false,
    }
}

/// Loads a relocatable object, an archive or a short import member.
pub fn load(data: &[u8]) -> Result<Loaded, ProtoError> {
    if data.starts_with(b"!<arch>\n") || data.starts_with(b"!<thin>\n") {
        return load_archive(data);
    }
    match FileKind::parse(data) {
        Ok(FileKind::CoffImport) => {
            let imp =
                ImportFile::parse(data).map_err(|e| bad(format!("bad import member: {e}")))?;
            import_library(vec![short_import(&imp)], imp.architecture(), Vec::new())
        }
        _ => {
            let file =
                object::File::parse(data).map_err(|e| bad(format!("cannot parse object: {e}")))?;
            let family = family_of(&file)?;
            link(vec![(None, file)], family)
        }
    }
}

fn family_of(file: &object::File<'_>) -> Result<Family, ProtoError> {
    match file.format() {
        BinaryFormat::Elf if file.kind() == object::ObjectKind::Relocatable => {
            if !file.is_little_endian() {
                return Err(unsupported(
                    "big-endian ELF is not supported by the native engine yet",
                ));
            }
            Ok(Family::Elf)
        }
        BinaryFormat::Coff => Ok(Family::Coff),
        other => Err(bad(format!("{other:?} file is not a relocatable object"))),
    }
}

/// One imported symbol of an import library.
#[derive(Debug, Clone)]
struct LibImport {
    /// The name the DLL exports (`Ordinal_<n>` for an import by ordinal).
    name: String,
    dll: String,
    data: bool,
}

fn short_import(imp: &ImportFile<'_>) -> LibImport {
    let name = match imp.import() {
        ImportName::Name(n) => String::from_utf8_lossy(n).into_owned(),
        // an import by ordinal goes by its symbol's name
        ImportName::Ordinal(o) => {
            let symbol = String::from_utf8_lossy(imp.symbol()).into_owned();
            let x86 = imp.architecture() == Architecture::I386;
            match strip_imp(&symbol, x86) {
                n if n.is_empty() => format!("Ordinal_{o}"),
                n => n,
            }
        }
    };
    LibImport {
        name,
        dll: String::from_utf8_lossy(imp.dll()).into_owned(),
        data: imp.import_type() != ImportType::Code,
    }
}

/// A member of a GNU (dlltool, `ld --out-implib`) import library: a small COFF object with
/// `.idata$` sections. Returns the import it describes, the DLL name it carries (the library's
/// last member holds it in `.idata$7`), or neither.
enum LongImport {
    Import { name: String, data: bool },
    DllName(String),
    Other,
}

fn long_import(file: &object::File<'_>) -> Option<LongImport> {
    let idata = |n: &str| file.section_by_name(n);
    if !file
        .sections()
        .any(|s| s.name().is_ok_and(|n| n.starts_with(".idata$")))
    {
        return None;
    }
    let imp_symbol = file.symbols().find_map(|s| {
        let n = s.name().ok()?;
        (s.is_definition() && n.starts_with("__imp_")).then(|| n.to_string())
    });
    if let Some(symbol) = imp_symbol {
        // `.idata$6` holds a hint and the name the DLL exports; an import by ordinal has none
        // and goes by its symbol's name
        let by_name = idata(".idata$6")
            .and_then(|s| s.data().ok())
            .and_then(|d| d.get(2..))
            .map(|d| {
                let end = d.iter().position(|b| *b == 0).unwrap_or(d.len());
                String::from_utf8_lossy(&d[..end]).into_owned()
            })
            .filter(|n| !n.is_empty());
        let plain = strip_imp(&symbol, file.architecture() == Architecture::I386);
        // a function import comes with a thunk (`jmp [__imp_f]`) in `.text`
        let data = file.section_by_name(".text").is_none_or(|s| s.size() == 0);
        return Some(LongImport::Import {
            name: by_name.unwrap_or(plain),
            data,
        });
    }
    if let Some(d) = idata(".idata$7").and_then(|s| s.data().ok())
        && file
            .symbols()
            .any(|s| s.is_definition() && s.name().is_ok_and(|n| n.ends_with("_iname")))
    {
        let end = d.iter().position(|b| *b == 0).unwrap_or(d.len());
        let name = String::from_utf8_lossy(&d[..end]).into_owned();
        if !name.is_empty() {
            return Some(LongImport::DllName(name));
        }
    }
    Some(LongImport::Other)
}

/// `__imp_puts` -> `puts`; on x86 also without the decoration (`__imp__Sleep@4` -> `Sleep`).
fn strip_imp(symbol: &str, x86: bool) -> String {
    let rest = symbol.strip_prefix("__imp_").unwrap_or(symbol);
    if x86 {
        crate::pe::undecorate(rest).unwrap_or_else(|| rest.to_string())
    } else {
        rest.to_string()
    }
}

/// What the members of an archive are, as the probe and the summary report them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveSummary {
    /// Member names in file order (the symbol tables of the archive format left out).
    pub members: Vec<String>,
    /// Members that are ELF objects.
    pub elf: usize,
    /// Members that are COFF objects with code or data.
    pub coff: usize,
    /// Members that describe imports from a DLL (short import members and GNU `.idata$` ones).
    pub imports: usize,
    /// The DLLs imported from, in first-seen order.
    pub dlls: Vec<String>,
}

impl ArchiveSummary {
    /// Whether the archive only imports (an import library).
    pub fn is_import_library(&self) -> bool {
        self.imports > 0 && self.elf == 0 && self.coff == 0
    }

    /// The archive in plain words: `Linux static library with 2 objects`, `import library for
    /// KERNEL32.dll`.
    pub fn describe(&self) -> String {
        if self.is_import_library() {
            return match self.dlls.as_slice() {
                [] => "import library".into(),
                [one] => format!("import library for {one}"),
                [first, rest @ ..] => format!(
                    "import library for {first} and {} more DLL{}",
                    rest.len(),
                    if rest.len() == 1 { "" } else { "s" }
                ),
            };
        }
        let objects = self.elf + self.coff;
        let platform = if self.elf >= self.coff {
            "Linux"
        } else {
            "Windows"
        };
        let plural = if objects == 1 { "" } else { "s" };
        format!("{platform} static library with {objects} object{plural}")
    }
}

/// Reads the member list of an `ar` archive without loading it.
pub fn summarize_archive(data: &[u8]) -> Result<ArchiveSummary, ProtoError> {
    let mut out = ArchiveSummary::default();
    for_each_member(data, |name, bytes| {
        out.members.push(name.to_string());
        match FileKind::parse(bytes) {
            Ok(FileKind::CoffImport) => {
                out.imports += 1;
                if let Ok(imp) = ImportFile::parse(bytes) {
                    push_dll(&mut out.dlls, &String::from_utf8_lossy(imp.dll()));
                }
            }
            Ok(FileKind::Elf32 | FileKind::Elf64) => out.elf += 1,
            Ok(FileKind::Coff | FileKind::CoffBig) => {
                if let Ok(f) = object::File::parse(bytes) {
                    match long_import(&f) {
                        Some(LongImport::Import { .. }) => out.imports += 1,
                        Some(LongImport::DllName(d)) => push_dll(&mut out.dlls, &d),
                        Some(LongImport::Other) => {}
                        None => out.coff += 1,
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

fn push_dll(dlls: &mut Vec<String>, dll: &str) {
    if !dll.is_empty() && !dlls.iter().any(|d| d.eq_ignore_ascii_case(dll)) {
        dlls.push(dll.to_string());
    }
}

fn for_each_member<'d>(
    data: &'d [u8],
    mut f: impl FnMut(&str, &'d [u8]) -> Result<(), ProtoError>,
) -> Result<(), ProtoError> {
    let archive =
        ArchiveFile::parse(data).map_err(|e| bad(format!("cannot parse archive: {e}")))?;
    if archive.is_thin() {
        return Err(unsupported(
            "thin archives (whose members are separate files) are not supported",
        ));
    }
    for (i, member) in archive.members().enumerate() {
        if i >= MAX_MEMBERS {
            return Err(bad(format!("archive has more than {MAX_MEMBERS} members")));
        }
        let member = member.map_err(|e| bad(format!("bad archive member: {e}")))?;
        let name = String::from_utf8_lossy(member.name()).into_owned();
        let name = name.trim_end_matches('/').to_string();
        let bytes = member
            .data(data)
            .map_err(|e| bad(format!("bad archive member {name}: {e}")))?;
        f(&name, bytes)?;
    }
    Ok(())
}

fn load_archive(data: &[u8]) -> Result<Loaded, ProtoError> {
    let mut objects: Vec<(Option<String>, object::File<'_>)> = Vec::new();
    let mut imports: Vec<LibImport> = Vec::new();
    let mut pending: Vec<(String, bool)> = Vec::new(); // GNU imports waiting for their DLL name
    let mut dll_name: Option<String> = None;
    let mut arch: Option<Architecture> = None;
    let mut members: Vec<String> = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for_each_member(data, |name, bytes| {
        members.push(name.to_string());
        match FileKind::parse(bytes) {
            Ok(FileKind::CoffImport) => {
                if let Ok(imp) = ImportFile::parse(bytes) {
                    arch.get_or_insert(imp.architecture());
                    imports.push(short_import(&imp));
                }
            }
            Ok(FileKind::Elf32 | FileKind::Elf64 | FileKind::Coff | FileKind::CoffBig) => {
                let Ok(file) = object::File::parse(bytes) else {
                    return Ok(());
                };
                if file.format() == BinaryFormat::Coff {
                    match long_import(&file) {
                        Some(LongImport::Import { name, data, .. }) => {
                            arch.get_or_insert(file.architecture());
                            pending.push((name, data));
                            return Ok(());
                        }
                        Some(LongImport::DllName(d)) => {
                            dll_name.get_or_insert(d);
                            return Ok(());
                        }
                        Some(LongImport::Other) => return Ok(()),
                        None => {}
                    }
                } else if file.kind() != object::ObjectKind::Relocatable {
                    return Ok(());
                }
                // members of the same name (`ar q` allows them) stay apart in the block names
                let n = seen.entry(name.to_string()).or_insert(0);
                *n += 1;
                let label = if *n == 1 {
                    name.to_string()
                } else {
                    format!("{name}#{n}")
                };
                objects.push((Some(label), file));
            }
            _ => {}
        }
        Ok(())
    })?;
    let dll = dll_name.unwrap_or_default();
    imports.extend(pending.into_iter().map(|(name, data)| LibImport {
        name,
        dll: dll.clone(),
        data,
    }));
    if objects.is_empty() {
        if imports.is_empty() {
            return Err(bad(
                "the archive holds no object files the native engine can load",
            ));
        }
        return import_library(imports, arch.unwrap_or(Architecture::Unknown), members);
    }
    let family = family_of(&objects[0].1)?;
    let first = objects[0].1.architecture();
    if let Some((name, _)) = objects
        .iter()
        .find(|(_, f)| f.architecture() != first || family_of(f).ok() != Some(family))
    {
        return Err(unsupported(format!(
            "the archive mixes object kinds or processors ({} differs from the first member); \
             the native engine loads archives of one kind",
            name.as_deref().unwrap_or("a member")
        )));
    }
    let objects_count = objects.len();
    let mut loaded = link(objects, family)?;
    let summary = ArchiveSummary {
        elf: if family == Family::Elf {
            objects_count
        } else {
            0
        },
        coff: if family == Family::Coff {
            objects_count
        } else {
            0
        },
        ..ArchiveSummary::default()
    };
    loaded.container = "ar";
    loaded.description = summary.describe();
    loaded.members = members;
    // imports a mixed library also carries (mingw's `libmsvcrt.a`)
    for imp in imports {
        if !loaded.imports.iter().any(|i| i.name == imp.name) {
            loaded.imports.push(ImportSymbol {
                name: imp.name,
                kind: if imp.data {
                    ProtoSymbolKind::Data
                } else {
                    ProtoSymbolKind::Function
                },
                library: Some(imp.dll),
            });
        }
    }
    loaded.imports.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(loaded)
}

/// An import library: the imported symbols, no code.
fn import_library(
    imports: Vec<LibImport>,
    arch: Architecture,
    members: Vec<String>,
) -> Result<Loaded, ProtoError> {
    let language = language(arch, Family::Coff)?;
    let mut summary = ArchiveSummary {
        imports: imports.len(),
        ..ArchiveSummary::default()
    };
    for i in &imports {
        push_dll(&mut summary.dlls, &i.dll);
    }
    let mut list: Vec<ImportSymbol> = imports
        .into_iter()
        .map(|i| ImportSymbol {
            name: i.name,
            kind: if i.data {
                ProtoSymbolKind::Data
            } else {
                ProtoSymbolKind::Function
            },
            library: Some(i.dll),
        })
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list.dedup_by(|a, b| a.name == b.name && a.library == b.library);
    let mut loaded = empty_loaded(language);
    loaded.container = "ar";
    loaded.description = format!(
        "{} (no code: only the list of imported symbols)",
        summary.describe()
    );
    loaded.members = members;
    loaded.imports = list;
    Ok(loaded)
}

fn empty_loaded(language: Language) -> Loaded {
    let base = if language.pointer_size == 4 {
        PIE_BASE_32
    } else {
        PIE_BASE
    };
    Loaded {
        format: "pe",
        container: "coff",
        description: String::new(),
        members: Vec::new(),
        language,
        base,
        image: Image {
            segments: Vec::new(),
            context: Vec::new(),
        },
        blocks: Vec::new(),
        functions: BTreeMap::new(),
        code_symbols: BTreeMap::new(),
        debug: crate::dwarf::Debug::default(),
        plt: BTreeMap::new(),
        import_slots: BTreeMap::new(),
        externals: BTreeMap::new(),
        pdata_starts: Vec::new(),
        pic_base: None,
        conventions: BTreeMap::new(),
        entry: None,
        init_pointers: Vec::new(),
        data_pointers: Vec::new(),
        pointer_slots: Vec::new(),
        imports: Vec::new(),
        exports: BTreeMap::new(),
        fde_starts: Vec::new(),
        landing_pads: BTreeMap::new(),
        got_code: Vec::new(),
        default_names: BTreeMap::new(),
        global_pointer: None,
    }
}

/// One section placed in the layout.
struct Placed {
    obj: usize,
    index: usize,
    addr: u64,
    size: u64,
    name: String,
    /// The block it goes in: the member and the section name without its suffix.
    group: String,
    write: bool,
    exec: bool,
    init: bool,
    data: Vec<u8>,
}

/// Whether a section takes part in the layout.
fn loadable(sec: &object::Section<'_, '_>, family: Family) -> bool {
    match (family, sec.flags()) {
        (Family::Elf, SectionFlags::Elf { sh_flags }) => {
            sh_flags & u64::from(object::elf::SHF_ALLOC) != 0
        }
        (Family::Coff, SectionFlags::Coff { characteristics }) => {
            let content = pe::IMAGE_SCN_CNT_CODE
                | pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            let dropped =
                pe::IMAGE_SCN_LNK_REMOVE | pe::IMAGE_SCN_LNK_INFO | pe::IMAGE_SCN_MEM_DISCARDABLE;
            characteristics & content != 0
                && characteristics & dropped == 0
                && !sec.name().is_ok_and(|n| n.starts_with(".debug"))
        }
        _ => false,
    }
}

fn perms(sec: &object::Section<'_, '_>) -> (bool, bool) {
    match sec.flags() {
        SectionFlags::Elf { sh_flags } => (
            sh_flags & u64::from(object::elf::SHF_WRITE) != 0,
            sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
        ),
        SectionFlags::Coff { characteristics } => (
            characteristics & pe::IMAGE_SCN_MEM_WRITE != 0,
            characteristics & (pe::IMAGE_SCN_MEM_EXECUTE | pe::IMAGE_SCN_CNT_CODE) != 0,
        ),
        _ => (false, false),
    }
}

fn is_init(sec: &object::Section<'_, '_>) -> bool {
    !matches!(
        sec.kind(),
        SectionKind::UninitializedData | SectionKind::UninitializedTls
    )
}

/// The block a section goes in: `.text.f` and `.text$f` go in `.text`, `.rodata.str1.1` in
/// `.rodata`.
fn group_name(name: &str) -> String {
    let base = name.split('$').next().unwrap_or(name);
    let cut = base
        .char_indices()
        .filter(|(_, c)| *c == '.')
        .nth(1)
        .map_or(base.len(), |(i, _)| i);
    match &base[..cut] {
        "" => "section".to_string(),
        b => b.to_string(),
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    let a = a.clamp(1, MAX_ALIGN);
    v.div_ceil(a) * a
}

/// The relocation types that address the GOT.
fn got_relative(family: Family, ptr: usize, r_type: u32) -> (bool, bool) {
    use object::elf::*;
    if family != Family::Elf {
        return (false, false);
    }
    // (needs a slot, needs the GOT base)
    if ptr == 8 {
        match r_type {
            R_X86_64_GOT32
            | R_X86_64_GOTPCREL
            | R_X86_64_GOTPCRELX
            | R_X86_64_REX_GOTPCRELX
            | R_X86_64_GOTPCREL64
            | R_X86_64_GOT64 => (true, true),
            R_X86_64_GOTOFF64 | R_X86_64_GOTPC32 | R_X86_64_GOTPC64 => (false, true),
            _ => (false, false),
        }
    } else {
        match r_type {
            R_386_GOT32 | R_386_GOT32X => (true, true),
            R_386_GOTOFF | R_386_GOTPC => (false, true),
            _ => (false, false),
        }
    }
}

/// Everything resolution needs.
struct Layout<'a> {
    family: Family,
    ptr: usize,
    base: u64,
    placed: &'a [BTreeMap<usize, u64>],
    discarded: &'a [BTreeSet<usize>],
    common: &'a BTreeMap<(usize, usize), u64>,
    globals: &'a BTreeMap<String, u64>,
    externals_of: &'a BTreeMap<String, u64>,
    slots_of: &'a BTreeMap<String, u64>,
    got_of: &'a BTreeMap<u64, u64>,
    got: Option<u64>,
}

impl Layout<'_> {
    /// The address of symbol `sym` of object `obj`, and the start of its section (for
    /// section-relative relocations). A symbol in a section outside the layout (DWARF) is its
    /// offset in that section, as in a linked file.
    fn symbol(&self, obj: usize, sym: &object::Symbol<'_, '_>) -> Option<(u64, u64)> {
        match sym.section() {
            SymbolSection::Section(idx) => match self.placed[obj].get(&idx.0) {
                Some(start) => Some((start + sym.address(), *start)),
                None if self.discarded[obj].contains(&idx.0) => {
                    self.globals.get(sym.name().ok()?).map(|a| (*a, 0))
                }
                None => Some((sym.address(), 0)),
            },
            SymbolSection::Absolute => Some((sym.address(), 0)),
            SymbolSection::Common => self.common.get(&(obj, sym.index().0)).map(|a| (*a, *a)),
            _ => {
                let name = sym.name().ok()?;
                if name == "_GLOBAL_OFFSET_TABLE_" {
                    return self.got.map(|g| (g, g));
                }
                self.globals
                    .get(name)
                    .or_else(|| self.slots_of.get(name))
                    .or_else(|| self.externals_of.get(name))
                    .map(|a| (*a, 0))
            }
        }
    }
}

/// Applies the relocations of section `sec` (object `obj`) to `bytes`, which sit at `at`.
fn relocate(
    layout: &Layout<'_>,
    obj: usize,
    file: &object::File<'_>,
    sec: &object::Section<'_, '_>,
    bytes: &mut [u8],
    at: u64,
    pointer_slots: &mut Vec<(u64, u64)>,
) {
    use object::elf::*;
    if risc(file.architecture()) {
        relocate_risc(layout, obj, file, sec, bytes, at, pointer_slots);
        return;
    }
    let ptr = layout.ptr;
    for (offset, rel) in sec.relocations() {
        let RelocationTarget::Symbol(si) = rel.target() else {
            continue;
        };
        let Ok(sym) = file.symbol_by_index(si) else {
            continue;
        };
        let Some((s, sec_start)) = layout.symbol(obj, &sym) else {
            continue;
        };
        let p = at.wrapping_add(offset);
        let got = layout.got.unwrap_or(0);
        let slot = layout.got_of.get(&s).copied().unwrap_or(0);
        // (value, width in bytes, whether it is an absolute pointer)
        let computed: Option<(i128, usize, bool)> = match (layout.family, rel.flags()) {
            (Family::Elf, RelocationFlags::Elf { r_type }) => {
                let width = match (ptr, r_type) {
                    (8, R_X86_64_64 | R_X86_64_PC64 | R_X86_64_GOTOFF64 | R_X86_64_GOTPC64)
                    | (8, R_X86_64_GOTPCREL64 | R_X86_64_GOT64 | R_X86_64_SIZE64) => 8,
                    (8, R_X86_64_16 | R_X86_64_PC16) | (4, R_386_16 | R_386_PC16) => 2,
                    (8, R_X86_64_8 | R_X86_64_PC8) | (4, R_386_8 | R_386_PC8) => 1,
                    _ => 4,
                };
                let a = if rel.has_implicit_addend() {
                    read_signed(bytes, offset, width)
                } else {
                    i128::from(rel.addend())
                };
                let (s, p, got, slot) = (s as i128, p as i128, got as i128, slot as i128);
                let size = sym.size() as i128;
                match (ptr, r_type) {
                    (8, R_X86_64_64) => Some((s + a, 8, true)),
                    (8, R_X86_64_32 | R_X86_64_32S | R_X86_64_16 | R_X86_64_8) => {
                        Some((s + a, width, width == ptr))
                    }
                    (8, R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_PC64)
                    | (8, R_X86_64_PC16 | R_X86_64_PC8) => Some((s + a - p, width, false)),
                    (8, R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX)
                    | (8, R_X86_64_GOTPCREL64) => Some((slot + a - p, width, false)),
                    (8, R_X86_64_GOT32 | R_X86_64_GOT64) => Some((slot - got + a, width, false)),
                    (8, R_X86_64_GOTOFF64) => Some((s + a - got, 8, false)),
                    (8, R_X86_64_GOTPC32 | R_X86_64_GOTPC64) => Some((got + a - p, width, false)),
                    (8, R_X86_64_SIZE32 | R_X86_64_SIZE64) => Some((size + a, width, false)),
                    (4, R_386_32) => Some((s + a, 4, true)),
                    (4, R_386_16 | R_386_8) => Some((s + a, width, false)),
                    (4, R_386_PC32 | R_386_PLT32 | R_386_PC16 | R_386_PC8) => {
                        Some((s + a - p, width, false))
                    }
                    (4, R_386_GOT32 | R_386_GOT32X) => Some((slot - got + a, 4, false)),
                    (4, R_386_GOTOFF) => Some((s + a - got, 4, false)),
                    (4, R_386_GOTPC) => Some((got + a - p, 4, false)),
                    _ => None,
                }
            }
            (Family::Coff, RelocationFlags::Coff { typ }) => {
                let (s, p, base, sec_start) =
                    (s as i128, p as i128, layout.base as i128, sec_start as i128);
                let a4 = read_signed(bytes, offset, 4);
                if ptr == 8 {
                    match typ {
                        pe::IMAGE_REL_AMD64_ADDR64 => {
                            Some((s + read_signed(bytes, offset, 8), 8, true))
                        }
                        pe::IMAGE_REL_AMD64_ADDR32 => Some((s + a4, 4, false)),
                        pe::IMAGE_REL_AMD64_ADDR32NB => Some((s - base + a4, 4, false)),
                        pe::IMAGE_REL_AMD64_REL32..=pe::IMAGE_REL_AMD64_REL32_5 => {
                            let k = i128::from(typ - pe::IMAGE_REL_AMD64_REL32);
                            Some((s - (p + 4 + k) + a4, 4, false))
                        }
                        pe::IMAGE_REL_AMD64_SECREL => Some((s - sec_start + a4, 4, false)),
                        _ => None,
                    }
                } else {
                    match typ {
                        pe::IMAGE_REL_I386_DIR32 => Some((s + a4, 4, true)),
                        pe::IMAGE_REL_I386_DIR32NB => Some((s - base + a4, 4, false)),
                        pe::IMAGE_REL_I386_REL32 => Some((s - (p + 4) + a4, 4, false)),
                        pe::IMAGE_REL_I386_SECREL => Some((s - sec_start + a4, 4, false)),
                        _ => None,
                    }
                }
            }
            _ => None,
        };
        let Some((value, width, pointer)) = computed else {
            continue;
        };
        let Some(dst) = usize::try_from(offset)
            .ok()
            .and_then(|o| bytes.get_mut(o..o.checked_add(width)?))
        else {
            continue;
        };
        let v = value as u64;
        dst.copy_from_slice(&v.to_le_bytes()[..width]);
        if pointer && v != 0 {
            pointer_slots.push((p, v & if ptr == 4 { 0xffff_ffff } else { u64::MAX }));
        }
    }
}

/// [`relocate`] for ARM, AArch64 and RISC-V objects. RISC-V's `%pcrel_lo` relocations name the
/// `auipc` they complete, so the `%pcrel_hi` offsets are worked out first.
fn relocate_risc(
    layout: &Layout<'_>,
    obj: usize,
    file: &object::File<'_>,
    sec: &object::Section<'_, '_>,
    bytes: &mut [u8],
    at: u64,
    pointer_slots: &mut Vec<(u64, u64)>,
) {
    let arch = file.architecture();
    let mask = if layout.ptr == 4 {
        0xffff_ffff
    } else {
        u64::MAX
    };
    let target = |rel: &object::Relocation| -> Option<crate::relocs::Target> {
        let RelocationTarget::Symbol(si) = rel.target() else {
            return None;
        };
        let sym = file.symbol_by_index(si).ok()?;
        let (s, _) = layout.symbol(obj, &sym)?;
        Some(crate::relocs::Target {
            s,
            slot: layout.got_of.get(&s).copied().unwrap_or(0),
            got: layout.got.unwrap_or(0),
            addend: (!rel.has_implicit_addend()).then(|| rel.addend()),
        })
    };
    let rels: Vec<(u64, object::Relocation)> = sec.relocations().collect();
    let mut hi: BTreeMap<u64, i64> = BTreeMap::new();
    for (offset, rel) in &rels {
        let RelocationFlags::Elf { r_type } = rel.flags() else {
            continue;
        };
        let p = at.wrapping_add(*offset);
        if let Some(t) = target(rel)
            && let Some(o) = crate::relocs::riscv_hi(r_type, p, &t)
        {
            hi.insert(p, o);
        }
    }
    for (offset, rel) in &rels {
        let RelocationFlags::Elf { r_type } = rel.flags() else {
            continue;
        };
        let (Some(t), Ok(off)) = (target(rel), usize::try_from(*offset)) else {
            continue;
        };
        let p = at.wrapping_add(*offset);
        if let crate::relocs::Applied::Done(Some(v)) =
            crate::relocs::apply(arch, r_type, bytes, off, p, &t, &hi)
            && v != 0
        {
            pointer_slots.push((p, v & mask));
        }
    }
}

fn read_signed(bytes: &[u8], offset: u64, width: usize) -> i128 {
    let Some(b) = usize::try_from(offset)
        .ok()
        .and_then(|o| bytes.get(o..o.checked_add(width)?))
    else {
        return 0;
    };
    let v = le_word(b);
    let shift = 64 - 8 * width as u32;
    i128::from(((v << shift) as i64) >> shift)
}

/// Lays out and relocates `objects` (all of `family` and one processor) into one program.
fn link(
    objects: Vec<(Option<String>, object::File<'_>)>,
    family: Family,
) -> Result<Loaded, ProtoError> {
    let arch = objects
        .first()
        .map(|(_, f)| f.architecture())
        .unwrap_or(Architecture::Unknown);
    let language = language(arch, family)?;
    let ptr = language.pointer_size as usize;
    let x86 = arch == Architecture::I386;
    let base = if ptr == 4 { PIE_BASE_32 } else { PIE_BASE };
    let arm = arch == Architecture::Arm;
    let prefix = |obj: usize, name: &str| match &objects[obj].0 {
        Some(m) => format!("{m}:{name}"),
        None => name.to_string(),
    };

    // sections, member after member
    let mut cursor = base;
    let mut sections: Vec<Placed> = Vec::new();
    let mut placed: Vec<BTreeMap<usize, u64>> = vec![BTreeMap::new(); objects.len()];
    // a COMDAT group (an inline function, a template instance) that an earlier member already
    // brought is dropped, as a linker drops it; its symbols resolve to the kept copy
    let mut groups_seen: BTreeSet<String> = BTreeSet::new();
    let mut discarded: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); objects.len()];
    for (oi, (_, file)) in objects.iter().enumerate() {
        for comdat in file.comdats() {
            let Ok(name) = comdat.name() else { continue };
            if name.is_empty() || groups_seen.insert(name.to_string()) {
                continue;
            }
            discarded[oi].extend(comdat.sections().map(|s| s.0));
        }
    }
    for (oi, (_, file)) in objects.iter().enumerate() {
        // sections of one kind (`.text`, `.text.f`, `.text$g`) go together, as a linker puts
        // them, so a file built with one section per function still has a few blocks
        let mut order: Vec<(String, bool, bool, bool)> = Vec::new();
        let mut wanted: Vec<(usize, object::Section<'_, '_>)> = Vec::new();
        for sec in file.sections() {
            if !loadable(&sec, family) || sec.size() == 0 || discarded[oi].contains(&sec.index().0)
            {
                continue;
            }
            let (write, exec) = perms(&sec);
            let key = (
                group_name(sec.name().unwrap_or("")),
                write,
                exec,
                is_init(&sec),
            );
            let rank = match order.iter().position(|k| *k == key) {
                Some(r) => r,
                None => {
                    order.push(key);
                    order.len() - 1
                }
            };
            wanted.push((rank, sec));
        }
        wanted.sort_by_key(|(rank, _)| *rank);
        for (rank, sec) in wanted {
            let init = order[rank].3;
            let data = if init {
                sec.data()
                    .map_err(|e| bad(format!("bad section: {e}")))?
                    .to_vec()
            } else {
                Vec::new()
            };
            cursor = align_up(cursor, sec.align());
            let (write, exec) = (order[rank].1, order[rank].2);
            placed[oi].insert(sec.index().0, cursor);
            sections.push(Placed {
                obj: oi,
                index: sec.index().0,
                addr: cursor,
                size: sec.size(),
                name: prefix(oi, sec.name().unwrap_or("section")),
                group: prefix(oi, &order[rank].0),
                write,
                exec,
                init,
                data,
            });
            cursor += sec.size();
            if cursor - base > MAX_LAYOUT {
                return Err(bad(format!(
                    "the objects need more than the {MAX_LAYOUT} bytes the native engine lays out"
                )));
            }
        }
    }

    // common symbols (`int x;` without `-fno-common`) get room in a block of their own
    let mut common: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    let mut common_named: BTreeMap<String, u64> = BTreeMap::new();
    let common_start = align_up(cursor, 16);
    let mut common_end = common_start;
    for (oi, (_, file)) in objects.iter().enumerate() {
        for sym in file.symbols() {
            if sym.section() != SymbolSection::Common {
                continue;
            }
            let name = sym.name().unwrap_or_default().to_string();
            if let Some(a) = common_named.get(&name) {
                common.insert((oi, sym.index().0), *a);
                continue;
            }
            let size = sym.size().clamp(1, 1 << 20);
            let align = match family {
                Family::Elf => sym.address().clamp(1, 64),
                Family::Coff => size.next_power_of_two().min(16),
            };
            common_end = align_up(common_end, align);
            common.insert((oi, sym.index().0), common_end);
            common_named.insert(name, common_end);
            common_end += size;
        }
    }
    cursor = common_end;

    // definitions other members can see; a strong one wins over a weak one
    let mut globals: BTreeMap<String, u64> = BTreeMap::new();
    let mut weak: BTreeSet<String> = BTreeSet::new();
    for (oi, (_, file)) in objects.iter().enumerate() {
        for sym in file.symbols() {
            if sym.is_local() || !sym.is_definition() {
                continue;
            }
            let SymbolSection::Section(idx) = sym.section() else {
                continue;
            };
            let Some(start) = placed[oi].get(&idx.0) else {
                continue;
            };
            let Ok(name) = sym.name() else { continue };
            if name.is_empty() {
                continue;
            }
            let addr = start + sym.address();
            let replace = !globals.contains_key(name) || (weak.contains(name) && !sym.is_weak());
            if replace {
                globals.insert(name.to_string(), addr);
                if sym.is_weak() {
                    weak.insert(name.to_string());
                } else {
                    weak.remove(name);
                }
            }
        }
    }
    for (name, addr) in &common_named {
        globals.entry(name.clone()).or_insert(*addr);
    }

    // what is left undefined: `__imp_` slots and externals
    let mut externals_named: Vec<(String, String, ProtoSymbolKind)> = Vec::new(); // (symbol, shown name, kind)
    let mut imp_named: Vec<(String, String)> = Vec::new(); // (symbol, target name)
    let mut undefined_seen: BTreeSet<String> = BTreeSet::new();
    for (_, file) in &objects {
        for sym in file.symbols() {
            if !matches!(
                sym.section(),
                SymbolSection::Undefined | SymbolSection::Unknown
            ) || sym.kind() == SymbolKind::File
            {
                continue;
            }
            let Ok(name) = sym.name() else { continue };
            if name.is_empty()
                || name == "_GLOBAL_OFFSET_TABLE_"
                || globals.contains_key(name)
                || !undefined_seen.insert(name.to_string())
            {
                continue;
            }
            if family == Family::Coff && name.starts_with("__imp_") {
                imp_named.push((name.to_string(), strip_imp(name, x86)));
                continue;
            }
            let shown = if family == Family::Coff && x86 {
                crate::pe::undecorate(name).unwrap_or_else(|| name.to_string())
            } else {
                name.to_string()
            };
            let kind = match sym.kind() {
                SymbolKind::Data | SymbolKind::Tls => ProtoSymbolKind::Data,
                _ => ProtoSymbolKind::Function,
            };
            externals_named.push((name.to_string(), shown, kind));
        }
    }

    // GOT slots, by the address they hold
    let mut got_targets: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut needs_got = false;
    for (oi, (_, file)) in objects.iter().enumerate() {
        for sec in file.sections() {
            if !placed[oi].contains_key(&sec.index().0) {
                continue;
            }
            for (_, rel) in sec.relocations() {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    continue;
                };
                let (slot, base_rel) = if risc(arch) {
                    crate::relocs::got_use(arch, r_type)
                } else {
                    got_relative(family, ptr, r_type)
                };
                needs_got |= base_rel;
                if slot && let RelocationTarget::Symbol(si) = rel.target() {
                    got_targets.insert((oi, si.0));
                }
            }
        }
    }

    // the synthetic blocks: import slots, then the GOT; the externals go past the image
    let idata_start = align_up(cursor, ptr as u64);
    let mut slots_of: BTreeMap<String, u64> = BTreeMap::new();
    for (i, (symbol, _)) in imp_named.iter().enumerate() {
        slots_of.insert(symbol.clone(), idata_start + (i * ptr) as u64);
    }
    let idata_end = idata_start + (imp_named.len() * ptr) as u64;
    let got_start = align_up(idata_end, ptr as u64);
    let got = needs_got.then_some(got_start);
    let mut externals_of: BTreeMap<String, u64> = BTreeMap::new();
    let mut external_names: BTreeMap<String, u64> = BTreeMap::new(); // shown name -> stand-in
    // the stand-ins sit past the GOT, whose size is not known yet: one slot per target at most
    let got_room = (got_targets.len().max(1) * ptr) as u64;
    let externals_start = align_up(got_start + got_room, 0x1000);
    let next_external = |shown: &str, external_names: &mut BTreeMap<String, u64>| -> u64 {
        let n = external_names.len() as u64;
        *external_names
            .entry(shown.to_string())
            .or_insert(externals_start + n * ptr as u64)
    };
    for (symbol, shown, _) in &externals_named {
        let at = next_external(shown, &mut external_names);
        externals_of.insert(symbol.clone(), at);
    }
    // an `__imp_` slot holds its function: defined here, or another stand-in
    let mut slot_targets: Vec<(u64, u64, String)> = Vec::new();
    for (symbol, target) in &imp_named {
        let decorated = symbol.strip_prefix("__imp_").unwrap_or(symbol);
        let value = match globals.get(decorated) {
            Some(a) => *a,
            None => next_external(target, &mut external_names),
        };
        slot_targets.push((slots_of[symbol], value, target.clone()));
    }

    let empty_got: BTreeMap<u64, u64> = BTreeMap::new();
    let mut layout = Layout {
        family,
        ptr,
        base,
        placed: &placed,
        discarded: &discarded,
        common: &common,
        globals: &globals,
        externals_of: &externals_of,
        slots_of: &slots_of,
        got_of: &empty_got,
        got,
    };
    let mut got_of: BTreeMap<u64, u64> = BTreeMap::new();
    for (oi, si) in &got_targets {
        let Ok(sym) = objects[*oi].1.symbol_by_index(SymbolIndex(*si)) else {
            continue;
        };
        if let Some((s, _)) = layout.symbol(*oi, &sym) {
            let n = got_of.len() as u64;
            got_of.entry(s).or_insert(got_start + n * ptr as u64);
        }
    }
    let got_end = got_start + (got_of.len().max(usize::from(needs_got)) * ptr) as u64;
    layout.got_of = &got_of;

    // relocate the sections
    let mut pointer_slots: Vec<(u64, u64)> = Vec::new();
    let by_index: BTreeMap<(usize, usize), usize> = sections
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.obj, p.index), i))
        .collect();
    for (oi, (_, file)) in objects.iter().enumerate() {
        for sec in file.sections() {
            let Some(&i) = by_index.get(&(oi, sec.index().0)) else {
                continue;
            };
            if !sections[i].init {
                continue;
            }
            let at = sections[i].addr;
            let mut bytes = std::mem::take(&mut sections[i].data);
            relocate(&layout, oi, file, &sec, &mut bytes, at, &mut pointer_slots);
            sections[i].data = bytes;
        }
    }
    pointer_slots.sort_unstable();
    pointer_slots.dedup();

    // segments and blocks
    let mut segments: Vec<Segment> = Vec::new();
    let mut blocks: Vec<MemoryBlock> = Vec::new();
    // one block (and segment) per run of sections of a group; alignment gaps are zeros
    let mut i = 0;
    while i < sections.len() {
        let first = &sections[i];
        let mut j = i + 1;
        while j < sections.len()
            && sections[j].obj == first.obj
            && sections[j].group == first.group
            && (sections[j].write, sections[j].exec, sections[j].init)
                == (first.write, first.exec, first.init)
        {
            j += 1;
        }
        let start = first.addr;
        let end = sections[j - 1].addr + sections[j - 1].size;
        let mut data = Vec::new();
        if first.init {
            data = vec![0u8; (end - start) as usize];
            for p in &sections[i..j] {
                let o = (p.addr - start) as usize;
                let n = p.data.len().min(data.len() - o);
                data[o..o + n].copy_from_slice(&p.data[..n]);
            }
        }
        segments.push(Segment {
            start,
            data,
            mem_size: end - start,
            readonly: !first.write,
        });
        blocks.push(MemoryBlock {
            name: first.group.clone(),
            space: "ram".into(),
            start: start.into(),
            end: end.into(),
            perms: MemoryBlock::perms_string(true, first.write, first.exec),
            initialized: first.init,
            kind: MemoryKind::Default,
        });
        i = j;
    }
    let mut synthetic = |name: &str, start: u64, data: Vec<u8>, init: bool, write: bool| {
        let size = data.len() as u64;
        if size == 0 {
            return;
        }
        segments.push(Segment {
            start,
            data: if init { data } else { Vec::new() },
            mem_size: size,
            readonly: !write,
        });
        blocks.push(MemoryBlock {
            name: name.into(),
            space: "ram".into(),
            start: start.into(),
            end: (start + size).into(),
            perms: MemoryBlock::perms_string(true, write, false),
            initialized: init,
            kind: MemoryKind::Default,
        });
    };
    synthetic(
        "COMMON",
        common_start,
        vec![0; (common_end - common_start) as usize],
        false,
        true,
    );
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut idata = vec![0u8; (idata_end - idata_start) as usize];
    for (slot, value, name) in &slot_targets {
        let o = (slot - idata_start) as usize;
        idata[o..o + ptr].copy_from_slice(&value.to_le_bytes()[..ptr]);
        import_slots.insert(*slot, name.clone());
    }
    // read-only, like a bound import table, so a load through a slot folds to its function
    synthetic(".idata", idata_start, idata, true, false);
    let mut got_bytes = vec![0u8; (got_end - got_start) as usize];
    for (value, slot) in &got_of {
        let o = (slot - got_start) as usize;
        got_bytes[o..o + ptr].copy_from_slice(&value.to_le_bytes()[..ptr]);
        pointer_slots.push((*slot, *value));
    }
    synthetic(".got", got_start, got_bytes, true, false);
    pointer_slots.sort_unstable();

    let mut externals: BTreeMap<u64, String> = BTreeMap::new();
    for (name, at) in &external_names {
        externals.insert(*at, name.clone());
    }
    if !externals.is_empty() {
        // the decompiler reads a few bytes at a call target: returns, in no block
        let len = external_names.len() * ptr + 16;
        let ret: &[u8] = match arch {
            Architecture::Arm => &[0x1e, 0xff, 0x2f, 0xe1],
            Architecture::Aarch64 => &[0xc0, 0x03, 0x5f, 0xd6],
            Architecture::Riscv32 | Architecture::Riscv64 => &[0x67, 0x80, 0x00, 0x00],
            _ => &[0xc3],
        };
        segments.push(Segment {
            start: externals_start,
            data: ret.iter().copied().cycle().take(len).collect(),
            mem_size: len as u64,
            readonly: false,
        });
    }
    segments.sort_by_key(|s| s.start);
    // the decompiler reads ahead (16 bytes for a string), so the alignment gaps between
    // segments and a little room after the last one read as zeros, as in a linked image
    let starts: Vec<u64> = segments.iter().skip(1).map(|s| s.start).collect();
    for (i, s) in segments.iter_mut().enumerate() {
        let room = match starts.get(i) {
            Some(next) => next.saturating_sub(s.start),
            None => s.mem_size + 16,
        };
        s.mem_size = s.mem_size.max(room.min(s.mem_size + 0x1000));
    }
    blocks.sort_by_key(|b| (b.start, b.end));
    let mut image = Image {
        segments,
        context: Vec::new(),
    };
    // ARM: the mapping symbols say which code is Thumb
    if arm {
        let mut mapping: Vec<(u64, crate::arm::Mapping)> = Vec::new();
        for (oi, (_, file)) in objects.iter().enumerate() {
            for sym in file.symbols() {
                let (SymbolSection::Section(idx), Some(m)) = (
                    sym.section(),
                    sym.name().ok().and_then(crate::arm::mapping_kind),
                ) else {
                    continue;
                };
                if let Some(start) = placed[oi].get(&idx.0) {
                    mapping.push((start + sym.address(), m));
                }
            }
        }
        let exec: Vec<(u64, u64)> = blocks
            .iter()
            .filter(|b| b.initialized && b.perms.ends_with('x'))
            .map(|b| (b.start.0, b.end.0))
            .collect();
        image.context = crate::arm::paint_mapping(&mapping, &exec);
    }

    // symbols: functions, exports, conventions
    let exec_at = |a: u64| {
        blocks
            .iter()
            .any(|b| b.perms.ends_with('x') && b.start.0 <= a && a < b.end.0)
    };
    let mut code: Vec<(u64, String, bool)> = Vec::new(); // (address, name, global)
    let mut exports: BTreeMap<u64, ExportSymbol> = BTreeMap::new();
    for (oi, (_, file)) in objects.iter().enumerate() {
        for sym in file.symbols() {
            let SymbolSection::Section(idx) = sym.section() else {
                continue;
            };
            let Some(start) = placed[oi].get(&idx.0) else {
                continue;
            };
            let Ok(name) = sym.name() else { continue };
            if name.is_empty() || name.starts_with('.') || name.starts_with('$') {
                continue;
            }
            let raw = start + sym.address();
            // a Thumb function's symbol has the low bit set
            let addr = if arm && sym.kind() == SymbolKind::Text {
                raw & !1
            } else {
                raw
            };
            let is_code = match sym.kind() {
                SymbolKind::Text => true,
                SymbolKind::Data | SymbolKind::Unknown => {
                    family == Family::Coff && exec_at(addr) && sym.is_definition()
                }
                _ => false,
            };
            if !matches!(
                sym.kind(),
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Tls | SymbolKind::Unknown
            ) {
                continue;
            }
            if is_code {
                code.push((addr, name.to_string(), !sym.is_local()));
            }
            // a hidden ELF symbol (`__x86.get_pc_thunk.bx`) stays inside whatever links it
            let hidden = matches!(sym.flags(), SymbolFlags::Elf { st_other, .. }
                if st_other & 3 == object::elf::STV_HIDDEN || st_other & 3 == object::elf::STV_INTERNAL);
            if !sym.is_local() && !hidden && sym.is_definition() && globals.get(name) == Some(&raw)
            {
                let kind = if is_code {
                    ProtoSymbolKind::Function
                } else if sym.kind() == SymbolKind::Unknown {
                    ProtoSymbolKind::Other
                } else {
                    ProtoSymbolKind::Data
                };
                // x86 COFF exports go by their C name, as a DLL's export table names them
                let shown = match (family, x86) {
                    (Family::Coff, true) => {
                        crate::pe::undecorate(name).unwrap_or_else(|| name.to_string())
                    }
                    _ => name.to_string(),
                };
                exports
                    .entry(addr)
                    .or_insert(ExportSymbol { name: shown, kind });
            }
        }
    }
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (a, n, _) in &code {
        let names = code_symbols.entry(*a).or_default();
        if !names.contains(n) {
            names.push(n.clone());
        }
    }
    // the name of an address: its first global symbol, else its first static one; COFF x86
    // names follow the PE loader (a static C name loses its decoration)
    let mut functions: BTreeMap<u64, String> = BTreeMap::new();
    for pass in 0..2 {
        for (a, n, global) in &code {
            if (pass == 0 && !global) || functions.contains_key(a) {
                continue;
            }
            let mut name = n.clone();
            if family == Family::Coff && x86 {
                if let Some(itanium) = name.strip_prefix("__Z") {
                    name = format!("_Z{itanium}");
                } else if !global
                    && let Some(c) = crate::pe::undecorate(&name)
                    && !crate::pe::known_library_name(&c)
                {
                    name = c;
                }
            }
            functions.insert(*a, name);
        }
    }
    let mut conventions: BTreeMap<u64, String> = BTreeMap::new();
    if family == Family::Coff && x86 {
        for (a, n, _) in &code {
            let decorated = n.rsplit_once('@').is_some_and(|(b, d)| {
                !b.is_empty() && !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())
            });
            if !decorated {
                continue;
            }
            let c = if n.starts_with('@') {
                "__fastcall"
            } else if n.starts_with('_') && !n.starts_with("__Z") {
                "__stdcall"
            } else {
                continue;
            };
            conventions.entry(*a).or_insert_with(|| c.to_string());
        }
    }

    let mut imports: Vec<ImportSymbol> = externals_named
        .iter()
        .map(|(_, shown, kind)| ImportSymbol {
            name: shown.clone(),
            kind: *kind,
            library: None,
        })
        .chain(imp_named.iter().map(|(_, target)| ImportSymbol {
            name: target.clone(),
            kind: ProtoSymbolKind::Function,
            library: None,
        }))
        .collect();
    imports.sort_by(|a, b| a.name.cmp(&b.name));
    imports.dedup_by(|a, b| a.name == b.name);

    // the relocated unwind tables and DWARF
    let read = |a: u64, n: usize| -> Option<Vec<u8>> {
        let mut buf = vec![0u8; n];
        image.read(a, &mut buf).then_some(buf)
    };
    let mut fde_starts: Vec<u64> = Vec::new();
    let mut landing_pads: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut pdata_starts: Vec<u64> = Vec::new();
    let mut debug_sets: Vec<BTreeMap<String, Vec<u8>>> = Vec::new();
    for (oi, (_, file)) in objects.iter().enumerate() {
        let start_of = |name: &str| {
            file.section_by_name(name)
                .and_then(|s| placed[oi].get(&s.index().0).copied())
        };
        for p in sections.iter().filter(|p| p.obj == oi) {
            let short = p.name.rsplit(':').next().unwrap_or(&p.name);
            if short == ".ARM.exidx" {
                // prel31 offsets to the functions (relocated above)
                for (i, e) in p.data.as_chunks::<8>().0.iter().enumerate() {
                    let w = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                    let off = i64::from(((w << 1) as i32) >> 1);
                    fde_starts.push((p.addr + 8 * i as u64).wrapping_add_signed(off) & !1);
                }
            } else if short == ".eh_frame" {
                let frames = crate::eh::parse(&crate::eh::Sections {
                    eh_frame: (p.addr, &p.data),
                    text: start_of(".text"),
                    got,
                    read: &read,
                    address_size: ptr as u8,
                });
                fde_starts.extend(frames.fde_starts);
                landing_pads.extend(frames.landing_pads);
            } else if family == Family::Coff && ptr == 8 && short.starts_with(".pdata") {
                // RUNTIME_FUNCTION entries: begin, end, unwind info (image-relative)
                for e in p.data.as_chunks::<12>().0 {
                    let begin = u64::from(u32::from_le_bytes([e[0], e[1], e[2], e[3]]));
                    let unwind = u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]]));
                    let chained =
                        read(base + (unwind & !1), 1).is_some_and(|b| (b[0] >> 3) & 0x4 != 0);
                    if begin != 0 && !chained {
                        pdata_starts.push(base + begin);
                    }
                }
            }
        }
        let mut set: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for sec in file.sections() {
            let Ok(name) = sec.name() else { continue };
            if !name.starts_with(".debug_") || placed[oi].contains_key(&sec.index().0) {
                continue;
            }
            let Ok(data) = sec.data() else { continue };
            let mut bytes = data.to_vec();
            let mut ignored = Vec::new();
            relocate(&layout, oi, file, &sec, &mut bytes, 0, &mut ignored);
            set.insert(name.to_string(), bytes);
        }
        if set.contains_key(".debug_info") {
            debug_sets.push(set);
        }
    }
    fde_starts.sort_unstable();
    fde_starts.dedup();
    pdata_starts.sort_unstable();
    pdata_starts.dedup();
    let debug = crate::dwarf::parse_sets(&debug_sets);

    let mut data_pointers: Vec<u64> = pointer_slots.iter().map(|(_, t)| *t).collect();
    data_pointers.sort_unstable();
    data_pointers.dedup();

    let single = objects.len() == 1 && objects[0].0.is_none();
    let description = match (family, single) {
        (Family::Elf, true) => "Linux object file".to_string(),
        (Family::Coff, true) => "COFF object (a Windows object file)".to_string(),
        _ => String::new(),
    };
    Ok(Loaded {
        format: match family {
            Family::Elf => "elf",
            Family::Coff => "pe",
        },
        container: match family {
            Family::Elf => "elf",
            Family::Coff => "coff",
        },
        description,
        members: Vec::new(),
        language,
        base,
        image,
        blocks,
        functions,
        code_symbols,
        debug,
        plt: BTreeMap::new(),
        import_slots,
        externals,
        pdata_starts,
        pic_base: if x86 { got } else { None },
        conventions,
        entry: None,
        init_pointers: Vec::new(),
        data_pointers,
        pointer_slots,
        imports,
        exports,
        fde_starts,
        landing_pads,
        got_code: Vec::new(),
        default_names: BTreeMap::new(),
        global_pointer: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `ar` member: header and data, padded to an even size.
    fn member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            644,
            data.len()
        )
        .into_bytes();
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// A short import member (the format of Microsoft's import libraries).
    fn short_import(symbol: &str, dll: &str, data: bool, ordinal: Option<u16>) -> Vec<u8> {
        let mut names = format!("{symbol}\0{dll}\0").into_bytes();
        let ty = u16::from(data);
        let name_type = if ordinal.is_some() {
            pe::IMPORT_OBJECT_ORDINAL
        } else {
            pe::IMPORT_OBJECT_NAME
        };
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(names.len() as u32).to_le_bytes());
        out.extend_from_slice(&ordinal.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&(ty | (name_type << 2)).to_le_bytes());
        out.append(&mut names);
        out
    }

    #[test]
    fn short_import_members_make_an_import_library() {
        let mut lib = b"!<arch>\n".to_vec();
        lib.extend(member(
            "a.o",
            &short_import("Sleep", "KERNEL32.dll", false, None),
        ));
        lib.extend(member(
            "b.o",
            &short_import("GetTickCount", "KERNEL32.dll", false, None),
        ));
        lib.extend(member(
            "c.o",
            &short_import("ord_only", "KERNEL32.dll", false, Some(7)),
        ));
        lib.extend(member(
            "d.o",
            &short_import("_iob", "MSVCRT.dll", true, None),
        ));
        let summary = summarize_archive(&lib).expect("summary");
        assert!(summary.is_import_library());
        assert_eq!(summary.members, ["a.o", "b.o", "c.o", "d.o"]);
        assert_eq!(
            summary.describe(),
            "import library for KERNEL32.dll and 1 more DLL"
        );
        let l = load(&lib).expect("load");
        assert_eq!(l.container, "ar");
        assert!(l.functions.is_empty() && l.blocks.is_empty());
        assert_eq!(l.language.id, "x86:LE:64:default");
        let got: Vec<(&str, Option<&str>, ProtoSymbolKind)> = l
            .imports
            .iter()
            .map(|i| (i.name.as_str(), i.library.as_deref(), i.kind))
            .collect();
        assert_eq!(
            got,
            [
                (
                    "GetTickCount",
                    Some("KERNEL32.dll"),
                    ProtoSymbolKind::Function
                ),
                ("Sleep", Some("KERNEL32.dll"), ProtoSymbolKind::Function),
                ("_iob", Some("MSVCRT.dll"), ProtoSymbolKind::Data),
                ("ord_only", Some("KERNEL32.dll"), ProtoSymbolKind::Function),
            ]
        );
        // one member on its own
        let one = load(&short_import("Sleep", "KERNEL32.dll", false, None)).expect("member");
        assert_eq!(one.imports.len(), 1);
    }

    #[test]
    fn archives_without_objects_and_other_formats_are_refused() {
        let mut lib = b"!<arch>\n".to_vec();
        lib.extend(member("notes.txt", b"just text"));
        assert_eq!(load(&lib).unwrap_err().code, ErrorCode::InvalidArgument);
        assert!(!handles(b"\x7fELF not really"));
        assert!(handles(b"!<arch>\n"));
    }

    #[test]
    fn sections_group_by_their_base_name() {
        assert_eq!(group_name(".text"), ".text");
        assert_eq!(group_name(".text.kr_report"), ".text");
        assert_eq!(group_name(".text$mn"), ".text");
        assert_eq!(group_name(".rodata.str1.1"), ".rodata");
        assert_eq!(group_name(".rdata$zzz"), ".rdata");
        assert_eq!(group_name("UPX0"), "UPX0");
        assert_eq!(group_name(""), "section");
    }

    #[test]
    fn decorated_imports_lose_their_decoration() {
        assert_eq!(strip_imp("__imp_puts", false), "puts");
        assert_eq!(strip_imp("__imp__Sleep@4", true), "Sleep");
        assert_eq!(strip_imp("__imp__puts", true), "puts");
    }

    #[test]
    fn relocations_are_applied_to_an_elf_object() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/lib/bin");
        let l = load(&std::fs::read(path.join("kr.o")).expect("kr.o")).expect("load");
        let at = |n: &str| {
            *l.functions
                .iter()
                .find(|(_, f)| f.as_str() == n)
                .unwrap_or_else(|| panic!("{n}"))
                .0
        };
        // every `call rel32` in kr_report lands on a function or an external stand-in
        let report = at("kr_report");
        let mut code = vec![0u8; 202];
        assert!(l.image.read(report, &mut code));
        let mut calls = 0;
        for i in 0..code.len() - 5 {
            if code[i] != 0xe8 {
                continue;
            }
            let d = i32::from_le_bytes(code[i + 1..i + 5].try_into().expect("rel32"));
            let target = (report + i as u64 + 5).wrapping_add_signed(i64::from(d));
            if l.functions.contains_key(&target) || l.externals.contains_key(&target) {
                calls += 1;
            }
        }
        assert!(calls >= 6, "{calls} calls resolved");
        assert!(l.externals.values().any(|n| n == "puts"));
        // the GOT slot of the PIC reference to `kr_calls` holds its address
        let calls_var = l
            .exports
            .iter()
            .find(|(_, e)| e.name == "kr_calls")
            .map(|(a, _)| *a)
            .expect("kr_calls");
        assert!(l.pointer_slots.iter().any(|(_, t)| *t == calls_var));
        assert!(!l.debug.functions.is_empty(), "DWARF read after relocation");
    }
}
