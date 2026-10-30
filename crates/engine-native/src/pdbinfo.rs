//! PDB import (`pdb2`): public and global symbols, procedures with their sizes, and the type
//! stream mapped onto the neutral type model, the way `dwarf.rs` does for DWARF.
//!
//! - Procedures (`S_GPROC32`/`S_LPROC32`) give a function's name, size and prototype: the type
//!   index names the return type and parameter types, `S_LOCAL` records flagged as parameters
//!   give the parameter names. Public symbols that no procedure covers name code or data.
//! - Structs, classes, unions and enums become type definitions after the types they hold by
//!   value; forward references resolve to their definition by name; pointers, references,
//!   arrays, modifiers and procedure types become [`TypeRef`]s. Names that are not C identifiers
//!   (`std::vector<int>`, `<unnamed-tag>`) are spelled with underscores; a user-defined type
//!   symbol names an anonymous type, or becomes a typedef.
//!
//! Addresses are link-time virtual addresses (`link_base + rva`); the caller rebases them. The
//! input is hostile: every count and recursion is bounded, and a panic inside the PDB reader
//! (it asserts on malformed attributes) turns into an empty result.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Cursor;

use kraken_proto::{
    Bitfield, Composite, EnumDef, EnumVariant, Field, FunctionPrototype, Param, Primitive,
    PrimitiveClass, TypeDef, TypeRef, TypedefDef,
};
use pdb2::{
    FallibleIterator, ItemFinder, PDB, PrimitiveKind, SymbolData, SymbolIter, TypeData, TypeIndex,
    Variant,
};

use crate::dwarf::{Debug, DebugFunction, DebugGlobal};

/// Largest PDB file read.
pub const MAX_PDB_BYTES: u64 = 1 << 30;
/// Type records read.
const MAX_TYPES: usize = 4_000_000;
/// Symbol records read.
const MAX_SYMBOLS: usize = 8_000_000;
/// Fields (and enumerators) read per type, and field-list continuations followed.
const MAX_FIELDS: usize = 65_536;
const MAX_CONTINUATIONS: usize = 256;
/// Parameters per prototype.
const MAX_PARAMS: usize = 1024;
/// Typedefs from user-defined type symbols.
const MAX_TYPEDEFS: usize = 65_536;
/// Nesting of type references followed.
const MAX_DEPTH: usize = 48;
/// Longest name kept.
const MAX_NAME: usize = 512;
/// Elements of an array type (larger counts are a corrupt record).
const MAX_ARRAY: u64 = 1 << 28;

/// What a PDB says about a program.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    /// Types, function prototypes and typed globals, keyed by link-time address.
    pub debug: Debug,
    /// Entry address of every procedure with its size.
    pub procs: BTreeMap<u64, u32>,
    /// Public code symbols no procedure covers, by address.
    pub code_names: BTreeMap<u64, Vec<String>>,
    /// Data symbols (publics and globals) with the size their type gives (0 when unknown).
    pub data: BTreeMap<u64, (String, u64)>,
    /// `__stdcall`, `__fastcall` and `__thiscall` procedures of 32-bit code.
    pub conventions: BTreeMap<u64, String>,
}

/// The GUID and age a PDB file carries; `None` when it is not a readable PDB.
pub fn identity(data: &[u8]) -> Option<([u8; 16], u32)> {
    if data.len() as u64 > MAX_PDB_BYTES {
        return None;
    }
    std::panic::catch_unwind(|| {
        let mut pdb = PDB::open(Cursor::new(data)).ok()?;
        let info = pdb.pdb_information().ok()?;
        let age = pdb
            .debug_information()
            .ok()
            .map_or(info.age, |d| d.age().unwrap_or(info.age));
        Some((info.guid.to_bytes_le(), age))
    })
    .ok()
    .flatten()
}

/// Whether `data` starts like a PDB file.
pub fn is_pdb(data: &[u8]) -> bool {
    data.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")
}

/// Reads the PDB `data` of a program linked at `link_base` with `ptr`-byte pointers. Empty
/// when it does not parse.
pub fn parse(data: &[u8], link_base: u64, ptr: u32) -> Parsed {
    if data.len() as u64 > MAX_PDB_BYTES {
        return Parsed::default();
    }
    std::panic::catch_unwind(|| read(data, link_base, ptr).unwrap_or_default()).unwrap_or_default()
}

fn read(data: &[u8], link_base: u64, ptr: u32) -> pdb2::Result<Parsed> {
    let mut pdb = PDB::open(Cursor::new(data))?;
    let map = pdb.address_map()?;
    let types = pdb.type_information()?;
    let mut finder = types.finder();
    let mut iter = types.iter();
    let mut indices = Vec::new();
    while let Some(item) = iter.next().ok().flatten() {
        finder.update(&iter);
        indices.push(item.index());
        if indices.len() >= MAX_TYPES {
            break;
        }
    }
    let mut conv = Conv::new(finder, &indices, ptr);

    let mut out = Parsed::default();
    let mut procs: Vec<ProcRecord> = Vec::new();
    let mut globals: Vec<(u64, String, TypeIndex)> = Vec::new();
    let mut udts: Vec<(String, TypeIndex)> = Vec::new();
    let mut publics: Vec<(u64, String, bool)> = Vec::new();
    let va =
        |off: pdb2::PdbInternalSectionOffset| off.to_rva(&map).map(|r| link_base + u64::from(r.0));
    let mut budget = MAX_SYMBOLS;

    let table = pdb.global_symbols()?;
    scan(
        table.iter(),
        &mut budget,
        &va,
        &mut procs,
        &mut globals,
        &mut udts,
        &mut publics,
    );
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next().ok().flatten() {
        if budget == 0 {
            break;
        }
        let Ok(Some(info)) = pdb.module_info(&module) else {
            continue;
        };
        let Ok(symbols) = info.symbols() else {
            continue;
        };
        scan(
            symbols,
            &mut budget,
            &va,
            &mut procs,
            &mut globals,
            &mut udts,
            &mut publics,
        );
    }

    // a user-defined type symbol names an anonymous type before anything uses the type
    for (name, index) in &udts {
        conv.name_anonymous(*index, name);
    }

    for p in &procs {
        if out.procs.contains_key(&p.addr) {
            continue;
        }
        out.procs.insert(p.addr, p.len);
        let proto = conv.prototype(p.type_index, &p.params);
        let name = function_name(&p.name);
        if ptr == 4
            && let Some(c) = conv.convention(p.type_index)
        {
            out.conventions.insert(p.addr, c.to_string());
        }
        out.debug.functions.insert(
            p.addr,
            DebugFunction {
                name,
                linkage: None,
                prototype: proto,
            },
        );
    }
    for (addr, name, ty) in &globals {
        if out.debug.globals.contains_key(addr) || out.procs.contains_key(addr) {
            continue;
        }
        let ty_ref = conv.type_ref(ty.0, 0);
        let size = conv.size_of(ty.0, 0).unwrap_or(0);
        out.data.insert(*addr, (name.clone(), size));
        out.debug.globals.insert(
            *addr,
            DebugGlobal {
                name: name.replace(' ', "_"),
                ty: ty_ref,
            },
        );
    }
    for (addr, name, function) in publics {
        if out.procs.contains_key(&addr) {
            continue;
        }
        if function {
            let names = out.code_names.entry(addr).or_default();
            if !names.contains(&name) {
                names.push(name);
            }
        } else {
            out.data.entry(addr).or_insert((name, 0));
        }
    }

    let mut typedefs = 0;
    for (name, index) in udts {
        if typedefs >= MAX_TYPEDEFS {
            break;
        }
        if let Some(def) = conv.typedef(&name, index) {
            out.debug.types.push(def);
            typedefs += 1;
        }
    }
    let (types, display) = conv.finish();
    // typedefs refer to types, so the definitions come first
    let mut all = types;
    all.append(&mut out.debug.types);
    out.debug.types = all;
    out.debug.display = display;
    Ok(out)
}

struct ProcRecord {
    addr: u64,
    len: u32,
    name: String,
    type_index: TypeIndex,
    params: Vec<Option<String>>,
}

fn clip(name: &str) -> String {
    name.chars().take(MAX_NAME).collect()
}

fn function_name(name: &str) -> String {
    name.replace(' ', "_")
}

#[allow(clippy::type_complexity)]
fn scan(
    mut symbols: SymbolIter<'_>,
    budget: &mut usize,
    va: &dyn Fn(pdb2::PdbInternalSectionOffset) -> Option<u64>,
    procs: &mut Vec<ProcRecord>,
    globals: &mut Vec<(u64, String, TypeIndex)>,
    udts: &mut Vec<(String, TypeIndex)>,
    publics: &mut Vec<(u64, String, bool)>,
) {
    // the procedure whose scope is open and the index of its last symbol
    let mut open: Option<(usize, u32)> = None;
    while *budget > 0 {
        let Ok(Some(symbol)) = symbols.next() else {
            break;
        };
        *budget -= 1;
        if let Some((_, end)) = open
            && symbol.index().0 > end
        {
            open = None;
        }
        let Ok(data) = symbol.parse() else { continue };
        match data {
            SymbolData::Procedure(p) => {
                let Some(addr) = va(p.offset) else { continue };
                procs.push(ProcRecord {
                    addr,
                    len: p.len,
                    name: clip(&p.name.to_string()),
                    type_index: p.type_index,
                    params: Vec::new(),
                });
                open = Some((procs.len() - 1, p.end.0));
            }
            SymbolData::Local(l) if l.flags.isparam => {
                if let Some((i, _)) = open
                    && procs[i].params.len() < MAX_PARAMS
                {
                    procs[i].params.push(Some(clip(&l.name.to_string())));
                }
            }
            SymbolData::Data(d) => {
                if let Some(addr) = va(d.offset) {
                    globals.push((addr, clip(&d.name.to_string()), d.type_index));
                }
            }
            SymbolData::Public(p) => {
                if let Some(addr) = va(p.offset) {
                    publics.push((addr, clip(&p.name.to_string()), p.code || p.function));
                }
            }
            SymbolData::UserDefinedType(u) if udts.len() < MAX_TYPEDEFS => {
                udts.push((clip(&u.name.to_string()), u.type_index));
            }
            _ => {}
        }
    }
}

/// A C identifier from a PDB name.
fn c_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Whether a type name stands for no name (`<unnamed-tag>`, `__unnamed`).
fn anonymous(name: &str) -> bool {
    name.is_empty() || name.starts_with('<') || name.contains("::<") || name == "__unnamed"
}

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

fn void() -> TypeRef {
    prim(PrimitiveClass::Void, 0, false)
}

enum Kind {
    Struct,
    Union,
    Enum,
}

struct Conv<'t> {
    finder: ItemFinder<'t, TypeIndex>,
    /// Definitions by (unique) name, to resolve forward references.
    full: HashMap<String, u32>,
    /// The type name given to a definition.
    names: HashMap<u32, String>,
    taken: HashSet<String>,
    /// Names for anonymous types, from user-defined type symbols.
    anon: HashMap<u32, String>,
    memo: HashMap<u32, TypeRef>,
    sizes: HashMap<u32, u64>,
    aligns: HashMap<String, u32>,
    types: Vec<TypeDef>,
    declared: BTreeSet<String>,
    display: BTreeMap<String, String>,
    ptr: u32,
    anon_count: u32,
    /// Type records parsed so far, a bound on the work one file can ask for.
    work: usize,
}

impl<'t> Conv<'t> {
    fn new(finder: ItemFinder<'t, TypeIndex>, indices: &[TypeIndex], ptr: u32) -> Self {
        let mut c = Conv {
            finder,
            full: HashMap::new(),
            names: HashMap::new(),
            taken: HashSet::new(),
            anon: HashMap::new(),
            memo: HashMap::new(),
            sizes: HashMap::new(),
            aligns: HashMap::new(),
            types: Vec::new(),
            declared: BTreeSet::new(),
            display: BTreeMap::new(),
            ptr,
            anon_count: 0,
            work: 0,
        };
        for index in indices {
            let Some(data) = c.parse(index.0) else {
                continue;
            };
            let (name, unique, forward) = match &data {
                TypeData::Class(k) => (
                    k.name.to_string().into_owned(),
                    k.unique_name.map(|u| u.to_string().into_owned()),
                    k.properties.forward_reference(),
                ),
                TypeData::Union(u) => (
                    u.name.to_string().into_owned(),
                    u.unique_name.map(|n| n.to_string().into_owned()),
                    u.properties.forward_reference(),
                ),
                TypeData::Enumeration(e) => (
                    e.name.to_string().into_owned(),
                    e.unique_name.map(|n| n.to_string().into_owned()),
                    e.properties.forward_reference(),
                ),
                _ => continue,
            };
            if forward || name.is_empty() {
                continue;
            }
            c.full.entry(name).or_insert(index.0);
            if let Some(u) = unique {
                c.full.entry(u).or_insert(index.0);
            }
        }
        c
    }

    fn parse(&mut self, index: u32) -> Option<TypeData<'t>> {
        self.work += 1;
        if self.work > MAX_TYPES * 8 {
            return None;
        }
        self.finder.find(TypeIndex(index)).ok()?.parse().ok()
    }

    /// The definition `index` stands for: itself, or for a forward reference the one that has
    /// its name.
    fn resolve(&mut self, index: u32) -> u32 {
        let Some(data) = self.parse(index) else {
            return index;
        };
        let (name, unique, forward) = match &data {
            TypeData::Class(k) => (k.name, k.unique_name, k.properties.forward_reference()),
            TypeData::Union(u) => (u.name, u.unique_name, u.properties.forward_reference()),
            TypeData::Enumeration(e) => (e.name, e.unique_name, e.properties.forward_reference()),
            _ => return index,
        };
        if !forward {
            return index;
        }
        unique
            .and_then(|u| self.full.get(u.to_string().as_ref()).copied())
            .or_else(|| self.full.get(name.to_string().as_ref()).copied())
            .unwrap_or(index)
    }

    /// Names the anonymous type at `index` after a user-defined type symbol.
    fn name_anonymous(&mut self, index: TypeIndex, name: &str) {
        let at = self.resolve(index.0);
        let own = match self.parse(at) {
            Some(TypeData::Class(k)) => k.name.to_string().into_owned(),
            Some(TypeData::Union(u)) => u.name.to_string().into_owned(),
            Some(TypeData::Enumeration(e)) => e.name.to_string().into_owned(),
            _ => return,
        };
        if anonymous(&own) {
            self.anon.entry(at).or_insert_with(|| name.to_string());
        }
    }

    /// A type name for the definition at `at`, unique among the definitions.
    fn reserve(&mut self, at: u32, raw: &str) -> String {
        let raw = match (anonymous(raw), self.anon.get(&at)) {
            (true, Some(named)) => named.clone(),
            (true, None) => {
                self.anon_count += 1;
                format!("anon_{}", self.anon_count)
            }
            (false, _) => raw.to_string(),
        };
        let base = c_name(&clip(&raw));
        let mut name = base.clone();
        let mut n = 0;
        while !self.taken.insert(name.clone()) {
            n += 1;
            name = format!("{base}_conflict{n}");
        }
        if name != raw {
            self.display.insert(name.clone(), raw);
        }
        self.names.insert(at, name.clone());
        name
    }

    fn prim_ref(kind: PrimitiveKind, ptr: u32) -> TypeRef {
        use PrimitiveKind as K;
        let int = |size: u32, signed: bool| prim(PrimitiveClass::Int, size, signed);
        match kind {
            K::NoType => prim(PrimitiveClass::Undefined, 1, false),
            K::Void => void(),
            K::Char | K::RChar => prim(PrimitiveClass::Char, 1, true),
            K::UChar | K::Char8 => prim(PrimitiveClass::Char, 1, false),
            K::WChar | K::RChar16 => prim(PrimitiveClass::Char, 2, false),
            K::RChar32 => prim(PrimitiveClass::Char, 4, false),
            K::I8 => int(1, true),
            K::U8 => int(1, false),
            K::Short | K::I16 => int(2, true),
            K::UShort | K::U16 => int(2, false),
            K::Long | K::I32 | K::HRESULT => int(4, true),
            K::ULong | K::U32 => int(4, false),
            K::Quad | K::I64 => int(8, true),
            K::UQuad | K::U64 => int(8, false),
            K::Octa | K::I128 => int(16, true),
            K::UOcta | K::U128 => int(16, false),
            K::F16 => prim(PrimitiveClass::Float, 2, true),
            K::F32 | K::F32PP => prim(PrimitiveClass::Float, 4, true),
            K::F48 => prim(PrimitiveClass::Float, 6, true),
            K::F64 => prim(PrimitiveClass::Float, 8, true),
            K::F80 => prim(PrimitiveClass::Float, 10, true),
            K::F128 => prim(PrimitiveClass::Float, 16, true),
            K::Complex32 => prim(PrimitiveClass::Undefined, 8, false),
            K::Complex64 => prim(PrimitiveClass::Undefined, 16, false),
            K::Complex80 => prim(PrimitiveClass::Undefined, 20, false),
            K::Complex128 => prim(PrimitiveClass::Undefined, 32, false),
            K::Bool8 => prim(PrimitiveClass::Bool, 1, false),
            K::Bool16 => prim(PrimitiveClass::Bool, 2, false),
            K::Bool32 => prim(PrimitiveClass::Bool, 4, false),
            K::Bool64 => prim(PrimitiveClass::Bool, 8, false),
            #[allow(unreachable_patterns)]
            _ => prim(PrimitiveClass::Undefined, ptr.min(8), false),
        }
    }

    fn primitive(&mut self, index: u32) -> Option<TypeRef> {
        let TypeData::Primitive(p) = self.parse(index)? else {
            return None;
        };
        let base = Self::prim_ref(p.kind, self.ptr);
        Some(match p.indirection {
            None => base,
            Some(i) => {
                use pdb2::Indirection as I;
                let size = match i {
                    I::Near16 => 2,
                    I::Far16 | I::Huge16 | I::Near32 => 4,
                    I::Far32 => 6,
                    I::Near64 => 8,
                    I::Near128 => 16,
                };
                TypeRef::Pointer {
                    target: Box::new(base),
                    size,
                }
            }
        })
    }

    /// The reference for the type at `index`; `void` for what cannot be read.
    fn type_ref(&mut self, index: u32, depth: usize) -> TypeRef {
        if let Some(r) = self.memo.get(&index) {
            return r.clone();
        }
        if index < 0x1000 {
            let r = self.primitive(index).unwrap_or_else(void);
            self.memo.insert(index, r.clone());
            return r;
        }
        if depth > MAX_DEPTH {
            return void();
        }
        let Some(data) = self.parse(index) else {
            return void();
        };
        let r = match data {
            TypeData::Class(_) | TypeData::Union(_) | TypeData::Enumeration(_) => {
                self.composite_ref(index)
            }
            TypeData::Pointer(p) => {
                let size = if p.attributes.pointer_to_member() {
                    self.ptr
                } else {
                    match u32::from(p.attributes.size()) {
                        0 => self.ptr,
                        s => s,
                    }
                };
                if p.attributes.pointer_to_member() {
                    TypeRef::Pointer {
                        target: Box::new(void()),
                        size,
                    }
                } else {
                    TypeRef::Pointer {
                        target: Box::new(self.type_ref(p.underlying_type.0, depth + 1)),
                        size,
                    }
                }
            }
            TypeData::Modifier(m) => self.type_ref(m.underlying_type.0, depth + 1),
            TypeData::Alias(a) => self.type_ref(a.underlying_type.0, depth + 1),
            TypeData::Bitfield(b) => self.type_ref(b.underlying_type.0, depth + 1),
            TypeData::Array(a) => {
                let element = self.type_ref(a.element_type.0, depth + 1);
                let total = a.dimensions.first().copied().map_or(0, u64::from);
                let each = self.size_of(a.element_type.0, depth + 1).unwrap_or(0);
                let count = total.checked_div(each).unwrap_or(0);
                if count > MAX_ARRAY {
                    void()
                } else {
                    TypeRef::Array {
                        element: Box::new(element),
                        count,
                    }
                }
            }
            TypeData::Procedure(_) | TypeData::MemberFunction(_) => {
                TypeRef::Function(Box::new(self.prototype_at(index, &[], depth + 1)))
            }
            _ => void(),
        };
        self.memo.insert(index, r.clone());
        r
    }

    /// A named reference to the struct, union or enum at `index`, defining it on first use.
    fn composite_ref(&mut self, index: u32) -> TypeRef {
        let at = self.resolve(index);
        if let Some(name) = self.names.get(&at) {
            return TypeRef::Named { name: name.clone() };
        }
        let Some(data) = self.parse(at) else {
            return void();
        };
        let (raw, kind) = match &data {
            TypeData::Class(k) => (k.name.to_string().into_owned(), Kind::Struct),
            TypeData::Union(u) => (u.name.to_string().into_owned(), Kind::Union),
            TypeData::Enumeration(e) => (e.name.to_string().into_owned(), Kind::Enum),
            _ => return void(),
        };
        let name = self.reserve(at, &raw);
        let r = TypeRef::Named { name: name.clone() };
        // a recursive use finds the name already
        self.memo.insert(index, r.clone());
        self.memo.insert(at, r.clone());
        let forward = match &data {
            TypeData::Class(k) => k.properties.forward_reference(),
            TypeData::Union(u) => u.properties.forward_reference(),
            TypeData::Enumeration(e) => e.properties.forward_reference(),
            _ => false,
        };
        if forward {
            // no definition anywhere: an opaque struct
            self.declared.insert(name);
            return r;
        }
        match (kind, data) {
            (Kind::Struct, TypeData::Class(k)) => {
                let (fields, align) = self.fields(k.fields, &name);
                self.finish_composite(at, &name, k.size, fields, align, false);
            }
            (Kind::Union, TypeData::Union(u)) => {
                let (fields, align) = self.fields(Some(u.fields), &name);
                self.finish_composite(at, &name, u.size, fields, align, true);
            }
            (Kind::Enum, TypeData::Enumeration(e)) => {
                let size = self
                    .size_of(e.underlying_type.0, 0)
                    .unwrap_or(4)
                    .clamp(1, 8) as u32;
                let variants = self.enumerators(e.fields);
                self.sizes.insert(at, u64::from(size));
                self.types.push(TypeDef::Enum(EnumDef {
                    name,
                    size,
                    variants,
                }));
            }
            _ => {}
        }
        r
    }

    fn finish_composite(
        &mut self,
        at: u32,
        name: &str,
        size: u64,
        fields: Vec<Field>,
        align: u32,
        union: bool,
    ) {
        self.sizes.insert(at, size);
        self.aligns.insert(name.to_string(), align);
        let c = Composite {
            name: name.to_string(),
            size,
            align,
            fields,
        };
        self.types.push(if union {
            TypeDef::Union(c)
        } else {
            TypeDef::Struct(c)
        });
    }

    /// The fields of the field list at `list`, following continuations, and their alignment.
    fn fields(&mut self, list: Option<TypeIndex>, owner: &str) -> (Vec<Field>, u32) {
        let mut out = Vec::new();
        let mut align = 1;
        let mut next = list;
        let mut hops = 0;
        while let Some(index) = next.take() {
            hops += 1;
            if hops > MAX_CONTINUATIONS {
                break;
            }
            let Some(TypeData::FieldList(fl)) = self.parse(index.0) else {
                break;
            };
            for f in fl.fields {
                if out.len() >= MAX_FIELDS {
                    break;
                }
                let (name, offset, ty, bitfield) = match f {
                    TypeData::Member(m) => {
                        let bitfield = match self.parse(m.field_type.0) {
                            Some(TypeData::Bitfield(b)) => Some(Bitfield {
                                bit_offset: u32::from(b.position),
                                bit_size: u32::from(b.length),
                            }),
                            _ => None,
                        };
                        (
                            c_name(&clip(&m.name.to_string())),
                            m.offset,
                            self.type_ref(m.field_type.0, 1),
                            bitfield,
                        )
                    }
                    TypeData::BaseClass(b) => {
                        let ty = self.type_ref(b.base_class.0, 1);
                        let base = match &ty {
                            TypeRef::Named { name } => name.clone(),
                            _ => continue,
                        };
                        (format!("super_{base}"), u64::from(b.offset), ty, None)
                    }
                    _ => continue,
                };
                if name == owner {
                    continue;
                }
                align = align.max(self.align_of(&ty));
                out.push(Field {
                    name,
                    offset,
                    ty,
                    bitfield,
                });
            }
            next = fl.continuation;
        }
        (out, align)
    }

    fn align_of(&self, ty: &TypeRef) -> u32 {
        match ty {
            TypeRef::Primitive(p) => p.size.clamp(1, 8).next_power_of_two().min(8),
            TypeRef::Pointer { size, .. } => (*size).clamp(1, 8),
            TypeRef::Array { element, .. } => self.align_of(element),
            TypeRef::Named { name } => self.aligns.get(name).copied().unwrap_or(1),
            TypeRef::Function(_) => 1,
        }
    }

    fn enumerators(&mut self, list: TypeIndex) -> Vec<EnumVariant> {
        let mut out = Vec::new();
        let mut next = Some(list);
        let mut hops = 0;
        while let Some(index) = next.take() {
            hops += 1;
            if hops > MAX_CONTINUATIONS {
                break;
            }
            let Some(TypeData::FieldList(fl)) = self.parse(index.0) else {
                break;
            };
            for f in fl.fields {
                if out.len() >= MAX_FIELDS {
                    break;
                }
                if let TypeData::Enumerate(e) = f {
                    let value = match e.value {
                        Variant::U8(v) => i64::from(v),
                        Variant::U16(v) => i64::from(v),
                        Variant::U32(v) => i64::from(v),
                        Variant::U64(v) => v as i64,
                        Variant::I8(v) => i64::from(v),
                        Variant::I16(v) => i64::from(v),
                        Variant::I32(v) => i64::from(v),
                        Variant::I64(v) => v,
                    };
                    out.push(EnumVariant {
                        name: c_name(&clip(&e.name.to_string())),
                        value,
                    });
                }
            }
            next = fl.continuation;
        }
        out
    }

    /// The size in bytes of the type at `index`, when it has one.
    fn size_of(&mut self, index: u32, depth: usize) -> Option<u64> {
        if depth > MAX_DEPTH {
            return None;
        }
        if index < 0x1000 {
            return match self.primitive(index)? {
                TypeRef::Primitive(p) => Some(u64::from(p.size)),
                TypeRef::Pointer { size, .. } => Some(u64::from(size)),
                _ => None,
            };
        }
        if let Some(s) = self.sizes.get(&index) {
            return Some(*s);
        }
        match self.parse(index)? {
            TypeData::Class(k) => {
                if k.properties.forward_reference() {
                    let at = self.resolve(index);
                    if at != index {
                        return self.size_of(at, depth + 1);
                    }
                }
                Some(k.size)
            }
            TypeData::Union(u) => {
                if u.properties.forward_reference() {
                    let at = self.resolve(index);
                    if at != index {
                        return self.size_of(at, depth + 1);
                    }
                }
                Some(u.size)
            }
            TypeData::Enumeration(e) => self.size_of(e.underlying_type.0, depth + 1),
            TypeData::Pointer(p) => Some(match u32::from(p.attributes.size()) {
                0 => u64::from(self.ptr),
                s => u64::from(s),
            }),
            TypeData::Modifier(m) => self.size_of(m.underlying_type.0, depth + 1),
            TypeData::Alias(a) => self.size_of(a.underlying_type.0, depth + 1),
            TypeData::Bitfield(b) => self.size_of(b.underlying_type.0, depth + 1),
            TypeData::Array(a) => a.dimensions.first().copied().map(u64::from),
            _ => None,
        }
    }

    /// The calling convention keyword of the procedure type at `index` for 32-bit code, when it
    /// is not the default `__cdecl`.
    fn convention(&mut self, index: TypeIndex) -> Option<&'static str> {
        let attrs = match self.parse(index.0)? {
            TypeData::Procedure(p) => p.attributes,
            TypeData::MemberFunction(m) => m.attributes,
            _ => return None,
        };
        convention_name(attrs.calling_convention())
    }

    fn prototype(&mut self, index: TypeIndex, names: &[Option<String>]) -> FunctionPrototype {
        self.prototype_at(index.0, names, 0)
    }

    fn prototype_at(
        &mut self,
        index: u32,
        names: &[Option<String>],
        depth: usize,
    ) -> FunctionPrototype {
        let mut proto = FunctionPrototype {
            name: None,
            return_type: Box::new(void()),
            params: Vec::new(),
            calling_convention: String::new(),
            varargs: false,
            noreturn: false,
        };
        let (ret, attrs, args, this) = match self.parse(index) {
            Some(TypeData::Procedure(p)) => (p.return_type, p.attributes, p.argument_list, None),
            Some(TypeData::MemberFunction(m)) => (
                Some(m.return_type),
                m.attributes,
                m.argument_list,
                m.this_pointer_type,
            ),
            _ => return proto,
        };
        if let Some(r) = ret {
            proto.return_type = Box::new(self.type_ref(r.0, depth + 1));
        }
        if self.ptr == 4
            && let Some(c) = convention_name(attrs.calling_convention())
        {
            proto.calling_convention = c.to_string();
        }
        let mut args_list = Vec::new();
        if let Some(TypeData::ArgumentList(a)) = self.parse(args.0) {
            args_list = a.arguments;
        }
        if let Some(last) = args_list.last()
            && last.0 == 0
        {
            proto.varargs = true;
            args_list.pop();
        }
        args_list.truncate(MAX_PARAMS);
        let mut tys = Vec::new();
        if let Some(t) = this {
            tys.push(self.type_ref(t.0, depth + 1));
        }
        for a in args_list {
            tys.push(self.type_ref(a.0, depth + 1));
        }
        // the symbols name the parameters in order, `this` first
        let mut named = names.iter();
        for ty in tys {
            let name = named.next().cloned().flatten().map(|n| c_name(&n));
            proto.params.push(Param {
                name,
                ty,
                storage: None,
            });
        }
        proto
    }

    /// A typedef for the user-defined type symbol `name`, unless the type is called that.
    fn typedef(&mut self, name: &str, index: TypeIndex) -> Option<TypeDef> {
        let at = self.resolve(index.0);
        if self.anon.get(&at).is_some_and(|n| n == name) {
            return None;
        }
        let own = match self.parse(at) {
            Some(TypeData::Class(k)) => Some(k.name.to_string().into_owned()),
            Some(TypeData::Union(u)) => Some(u.name.to_string().into_owned()),
            Some(TypeData::Enumeration(e)) => Some(e.name.to_string().into_owned()),
            _ => None,
        };
        if own.as_deref() == Some(name) {
            return None;
        }
        let ident = c_name(name);
        if self.taken.contains(&ident) || crate::typestore::is_core(&ident) {
            return None;
        }
        let target = self.type_ref(index.0, 0);
        // a typedef of a type that came out as nothing adds no information
        if matches!(&target, TypeRef::Primitive(p) if p.class == PrimitiveClass::Void) {
            return None;
        }
        self.taken.insert(ident.clone());
        Some(TypeDef::Typedef(TypedefDef {
            name: ident,
            target,
        }))
    }

    fn finish(mut self) -> (Vec<TypeDef>, BTreeMap<String, String>) {
        for name in std::mem::take(&mut self.declared) {
            self.types.push(TypeDef::Struct(Composite {
                name,
                size: 1,
                align: 1,
                fields: Vec::new(),
            }));
        }
        (self.types, self.display)
    }
}

fn convention_name(cc: u8) -> Option<&'static str> {
    match cc {
        0x04 | 0x05 => Some("__fastcall"),
        0x07 | 0x08 => Some("__stdcall"),
        0x0b => Some("__thiscall"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_input_gives_an_empty_result_and_no_panic() {
        assert!(parse(b"", 0x1_4000_0000, 8).procs.is_empty());
        assert!(
            parse(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", 0, 8)
                .procs
                .is_empty()
        );
        let junk: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
        assert!(parse(&junk, 0, 4).debug.types.is_empty());
        assert!(identity(&junk).is_none());
    }

    #[test]
    fn names_become_c_identifiers() {
        assert_eq!(c_name("std::vector<int>"), "std__vector_int_");
        assert_eq!(c_name("<unnamed-tag>"), "_unnamed_tag_");
        assert_eq!(c_name("9lives"), "_9lives");
        assert!(anonymous("<unnamed-tag>"));
        assert!(!anonymous("shape"));
    }
}
