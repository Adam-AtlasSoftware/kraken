//! DWARF import (`.debug_info` through `gimli`): named types and function prototypes, the way
//! Ghidra's DWARF analyzer uses them.
//!
//! - Structs, classes, unions, enums and typedefs become type definitions in the neutral model
//!   (base classes as `super_<Base>` fields, as Ghidra names them). C++ names that are not C
//!   identifiers (`vector<double>`) are spelled with underscores, because the decompiler's C
//!   grammar reads them; a second, different type of the same name gets `_conflict<n>`.
//!   Incomplete declarations without a definition anywhere become opaque one-byte structs.
//! - Every defined subprogram (with an address) gives the function's name (`DW_AT_name`, spaces
//!   as underscores, so `operator new` is `operator_new`), its linkage name and its prototype:
//!   parameter names and types, `this` included, references as pointers, varargs, noreturn, and a
//!   class returned in memory as Ghidra shows it (`string * f(string * __return_storage_ptr__)`).
//!
//! Addresses are the file's (not rebased); [`Debug::functions`] is keyed by them.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use gimli::{
    AttributeValue, DebuggingInformationEntry, DwTag, EndianSlice, LittleEndian, Unit, UnitOffset,
    constants,
};
use kraken_proto::{
    Composite, EnumDef, EnumVariant, Field, FunctionPrototype, Param, Primitive, PrimitiveClass,
    TypeDef, TypeRef, TypedefDef,
};
use object::read::{Object, ObjectSection};

type R<'a> = EndianSlice<'a, LittleEndian>;

/// Upper bound on DIEs read, so a hostile file cannot take unbounded time.
const MAX_DIES: usize = 2_000_000;
/// Upper bound on type nesting followed.
const MAX_DEPTH: usize = 64;

/// What the DWARF of a file says.
#[derive(Debug, Clone, Default)]
pub struct Debug {
    /// Named types, each after the types it holds by value.
    pub types: Vec<TypeDef>,
    /// Functions by entry address (as in the file).
    pub functions: BTreeMap<u64, DebugFunction>,
    /// File-level variables with a fixed address, by address (as in the file).
    pub globals: BTreeMap<u64, DebugGlobal>,
    /// Type names as Ghidra shows them (`vector<double,_std::allocator<double>_>`,
    /// `__unique_ptr_t.conflict1`), by the identifier the type store uses, where they differ.
    pub display: BTreeMap<String, String>,
}

/// One function with debug information.
#[derive(Debug, Clone, PartialEq)]
pub struct DebugFunction {
    /// Its name as Ghidra shows it (`DW_AT_name`, spaces as underscores).
    pub name: String,
    /// `DW_AT_linkage_name` (the mangled name), if any.
    pub linkage: Option<String>,
    /// The prototype.
    pub prototype: FunctionPrototype,
}

/// One global variable with debug information.
#[derive(Debug, Clone, PartialEq)]
pub struct DebugGlobal {
    /// Its name (`DW_AT_name`, spaces as underscores).
    pub name: String,
    /// Its type.
    pub ty: TypeRef,
}

/// One DIE with the attributes the importer reads.
#[derive(Debug, Default, Clone)]
struct Die {
    tag: u16,
    parent: Option<usize>,
    children: Vec<usize>,
    name: Option<String>,
    linkage: Option<String>,
    byte_size: Option<u64>,
    encoding: Option<u8>,
    ty: Option<usize>,
    low_pc: Option<u64>,
    /// The address of a `DW_OP_addr` location.
    location: Option<u64>,
    first_range: Option<u64>,
    member_location: Option<u64>,
    bit_size: bool,
    count: Option<u64>,
    upper_bound: Option<i64>,
    const_value: Option<i64>,
    specification: Option<usize>,
    origin: Option<usize>,
    artificial: bool,
    declaration: bool,
    noreturn: bool,
    by_reference: bool,
}

fn uleb(bytes: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for (i, b) in bytes.iter().enumerate().take(10) {
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Most bytes a compressed debug section may expand to; larger ones are skipped.
const MAX_SECTION_BYTES: u64 = 512 << 20;

/// The contents of a debug section, decompressed (zlib, zstd) when it is compressed.
fn section_bytes<'a>(s: &object::Section<'a, '_>) -> Option<Cow<'a, [u8]>> {
    if let Ok(c) = s.compressed_data()
        && c.format != object::CompressionFormat::None
        && c.uncompressed_size > MAX_SECTION_BYTES
    {
        return None;
    }
    s.uncompressed_data().ok()
}

/// Parses the DWARF of `file`; empty when it has none or it does not parse.
pub fn parse(file: &object::File<'_>) -> Debug {
    if file.section_by_name(".debug_info").is_none() {
        return Debug::default();
    }
    let mut importer = Importer::default();
    let mut total = 0;
    import(&mut importer, &mut total, |name| {
        file.section_by_name(name)
            .and_then(|s| section_bytes(&s))
            .unwrap_or(Cow::Borrowed(&[]))
    });
    importer.finish()
}

/// Parses the DWARF of several objects into one [`Debug`]: one map of section bytes (relocated,
/// by section name) per object, as the object loader prepares them.
pub fn parse_sets(sets: &[BTreeMap<String, Vec<u8>>]) -> Debug {
    let mut importer = Importer::default();
    let mut total = 0;
    for set in sets {
        let more = import(&mut importer, &mut total, |name| {
            set.get(name)
                .map(|v| Cow::Borrowed(v.as_slice()))
                .unwrap_or(Cow::Borrowed(&[]))
        });
        if !more {
            break;
        }
    }
    importer.finish()
}

/// Feeds the units of one set of sections to `importer`; false once [`MAX_DIES`] is reached.
fn import<'a>(
    importer: &mut Importer,
    total: &mut usize,
    section: impl Fn(&str) -> Cow<'a, [u8]>,
) -> bool {
    let load =
        |id: gimli::SectionId| -> Result<Cow<'a, [u8]>, gimli::Error> { Ok(section(id.name())) };
    let Ok(sections) = gimli::DwarfSections::load(load) else {
        return true;
    };
    let dwarf = sections.borrow(|s| EndianSlice::new(s, LittleEndian));
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let Some(dies) = read_unit(&dwarf, &unit, total) else {
            return false;
        };
        importer.unit(&dies);
    }
    true
}

/// The DIEs of one unit, or `None` past [`MAX_DIES`].
fn read_unit(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &Unit<R<'_>>,
    total: &mut usize,
) -> Option<Vec<Die>> {
    let mut dies: Vec<Die> = Vec::new();
    let mut by_offset: HashMap<usize, usize> = HashMap::new();
    // unit offsets of references, resolved to indices at the end
    let mut refs: Vec<(usize, u8, usize)> = Vec::new();
    let mut stack: Vec<(isize, usize)> = Vec::new();
    let mut cursor = unit.entries();
    while let Ok(Some(entry)) = cursor.next_dfs() {
        *total += 1;
        if *total > MAX_DIES {
            return None;
        }
        let depth = entry.depth();
        while stack.last().is_some_and(|(d, _)| *d >= depth) {
            stack.pop();
        }
        let idx = dies.len();
        let parent = stack.last().map(|(_, i)| *i);
        let mut die = read_die(dwarf, unit, entry, idx, &mut refs);
        die.parent = parent;
        if let Some(p) = parent {
            dies[p].children.push(idx);
        }
        by_offset.insert(entry.offset().0, idx);
        if entry.has_children() {
            stack.push((depth, idx));
        }
        dies.push(die);
    }
    for (idx, which, off) in refs {
        let Some(target) = by_offset.get(&off).copied() else {
            continue;
        };
        let d = &mut dies[idx];
        match which {
            0 => d.ty = Some(target),
            1 => d.specification = Some(target),
            _ => d.origin = Some(target),
        }
    }
    Some(dies)
}

fn read_die(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &Unit<R<'_>>,
    entry: &DebuggingInformationEntry<R<'_>>,
    idx: usize,
    refs: &mut Vec<(usize, u8, usize)>,
) -> Die {
    let mut d = Die {
        tag: entry.tag().0,
        ..Die::default()
    };
    let string = |v: AttributeValue<R<'_>>| {
        dwarf
            .attr_string(unit, v)
            .ok()
            .map(|s| s.to_string_lossy().into_owned())
    };
    for attr in entry.attrs() {
        let v = attr.value();
        match attr.name() {
            constants::DW_AT_name => d.name = string(v),
            constants::DW_AT_linkage_name | constants::DW_AT_MIPS_linkage_name => {
                d.linkage = string(v)
            }
            constants::DW_AT_byte_size => d.byte_size = v.udata_value(),
            constants::DW_AT_bit_size | constants::DW_AT_data_bit_offset => d.bit_size = true,
            constants::DW_AT_encoding => {
                if let AttributeValue::Encoding(e) = v {
                    d.encoding = Some(e.0);
                }
            }
            constants::DW_AT_type
            | constants::DW_AT_specification
            | constants::DW_AT_abstract_origin => {
                let which = match attr.name() {
                    constants::DW_AT_type => 0,
                    constants::DW_AT_specification => 1,
                    _ => 2,
                };
                if let AttributeValue::UnitRef(UnitOffset(o)) = v {
                    refs.push((idx, which, o));
                }
            }
            constants::DW_AT_low_pc => d.low_pc = dwarf.attr_address(unit, v).ok().flatten(),
            constants::DW_AT_location => {
                if let Some(e) = v.exprloc_value() {
                    let b = e.0.slice();
                    if b.first() == Some(&0x03) && b.len() == 9 {
                        d.location = b[1..].try_into().ok().map(u64::from_le_bytes);
                    } else if b.first() == Some(&0x03) && b.len() == 5 {
                        d.location = b[1..]
                            .try_into()
                            .ok()
                            .map(|x| u64::from(u32::from_le_bytes(x)));
                    }
                }
            }
            constants::DW_AT_ranges => {
                if let Ok(Some(off)) = dwarf.attr_ranges_offset(unit, v)
                    && let Ok(mut ranges) = dwarf.ranges(unit, off)
                    && let Ok(Some(r)) = ranges.next()
                {
                    d.first_range = Some(r.begin);
                }
            }
            constants::DW_AT_data_member_location => {
                d.member_location = v.udata_value().or_else(|| {
                    // DW_OP_plus_uconst <n>
                    let e = v.exprloc_value()?;
                    let b = e.0.slice();
                    (b.first() == Some(&0x23)).then(|| uleb(&b[1..])).flatten()
                });
            }
            constants::DW_AT_count => d.count = v.udata_value(),
            constants::DW_AT_upper_bound => d.upper_bound = v.sdata_value(),
            constants::DW_AT_const_value => d.const_value = v.sdata_value(),
            constants::DW_AT_artificial => d.artificial = matches!(v, AttributeValue::Flag(true)),
            constants::DW_AT_declaration => d.declaration = matches!(v, AttributeValue::Flag(true)),
            constants::DW_AT_noreturn => d.noreturn = matches!(v, AttributeValue::Flag(true)),
            constants::DW_AT_calling_convention => {
                d.by_reference = matches!(
                    v,
                    AttributeValue::CallingConvention(constants::DW_CC_pass_by_reference)
                );
            }
            _ => {}
        }
    }
    d
}

/// A C identifier for a DWARF type name: other characters become underscores.
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

/// Ghidra's spelling of a DWARF function name: spaces become underscores.
fn function_name(name: &str) -> String {
    name.replace(' ', "_")
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

/// The scope-qualified name of the DIE at `i` (`std::vector<double>::pointer`).
fn qualified(dies: &[Die], i: usize) -> String {
    let mut parts = Vec::new();
    let mut at = Some(i);
    for _ in 0..32 {
        let Some(j) = at else { break };
        let d = &dies[j];
        if d.tag == constants::DW_TAG_compile_unit.0 {
            break;
        }
        parts.push(d.name.as_deref().unwrap_or("?"));
        at = d.parent;
    }
    parts.reverse();
    parts.join("::")
}

/// What tells two DWARF types of one name apart: tag, scope, size, member count and, for a
/// typedef, what it names.
fn die_key(dies: &[Die], i: usize) -> String {
    let d = &dies[i];
    let members = d
        .children
        .iter()
        .filter(|c| {
            matches!(
                DwTag(dies[**c].tag),
                constants::DW_TAG_member
                    | constants::DW_TAG_inheritance
                    | constants::DW_TAG_enumerator
            )
        })
        .count();
    let target =
        d.ty.map(|t| format!("{}:{}", dies[t].tag, qualified(dies, t)))
            .unwrap_or_default();
    format!(
        "{}:{}:{}:{members}:{target}",
        d.tag,
        qualified(dies, i),
        d.byte_size.unwrap_or(0)
    )
}

/// Whether the type at `at` is a class without data (an empty base, laid out in no bytes).
fn is_empty_class(dies: &[Die], at: Option<usize>, depth: usize) -> bool {
    let Some(i) = at else { return false };
    if depth > MAX_DEPTH {
        return false;
    }
    let d = &dies[i];
    match DwTag(d.tag) {
        constants::DW_TAG_typedef
        | constants::DW_TAG_const_type
        | constants::DW_TAG_volatile_type => is_empty_class(dies, d.ty, depth + 1),
        constants::DW_TAG_structure_type | constants::DW_TAG_class_type => {
            d.byte_size.is_some_and(|s| s <= 1)
                && d.children.iter().all(|c| {
                    let m = &dies[*c];
                    match DwTag(m.tag) {
                        constants::DW_TAG_member => m.member_location.is_none(),
                        constants::DW_TAG_inheritance => is_empty_class(dies, m.ty, depth + 1),
                        _ => true,
                    }
                })
        }
        _ => false,
    }
}

/// A name for a new type, or the one an equal type already has.
enum Slot {
    New(String),
    Have(String),
}

#[derive(Default)]
struct Importer {
    types: Vec<TypeDef>,
    /// Name -> key ([`die_key`]) of the type that has it.
    names: HashMap<String, String>,
    /// Struct names seen only as declarations.
    declared: BTreeSet<String>,
    functions: BTreeMap<u64, DebugFunction>,
    globals: BTreeMap<u64, DebugGlobal>,
    display: BTreeMap<String, String>,
    /// Base name -> the scope of the first type that had it.
    scopes: HashMap<String, String>,
    anon: usize,
}

/// One unit's conversion state.
struct UnitImport<'a> {
    dies: &'a [Die],
    memo: HashMap<usize, TypeRef>,
}

impl Importer {
    fn unit(&mut self, dies: &[Die]) {
        let mut u = UnitImport {
            dies,
            memo: HashMap::new(),
        };
        for (i, d) in dies.iter().enumerate() {
            match DwTag(d.tag) {
                constants::DW_TAG_structure_type
                | constants::DW_TAG_class_type
                | constants::DW_TAG_union_type
                | constants::DW_TAG_enumeration_type
                | constants::DW_TAG_typedef
                    if d.name.is_some() =>
                {
                    self.type_ref(&mut u, Some(i), 0);
                }
                constants::DW_TAG_subprogram => self.function(&mut u, i),
                constants::DW_TAG_variable => self.global(&mut u, i),
                _ => {}
            }
        }
    }

    fn finish(mut self) -> Debug {
        for name in std::mem::take(&mut self.declared) {
            if !self.names.contains_key(&name) {
                self.types.push(TypeDef::Struct(Composite {
                    name,
                    size: 1,
                    align: 1,
                    fields: Vec::new(),
                }));
            }
        }
        Debug {
            types: self.types,
            functions: self.functions,
            globals: self.globals,
            display: self.display,
        }
    }

    /// The name for the type at `i` (base name `base`): the base name, or `<base>_conflict<n>`
    /// when a different type has it, or the name of an equal type imported before.
    fn reserve(&mut self, dies: &[Die], i: usize, base: String) -> Slot {
        let key = die_key(dies, i);
        let mut name = base.clone();
        let mut n = 0;
        loop {
            match self.names.get(&name) {
                None => break,
                Some(have) if *have == key => return Slot::Have(name),
                Some(_) => {
                    n += 1;
                    name = format!("{base}_conflict{n}");
                }
            }
        }
        self.names.insert(name.clone(), key);
        let scope = qualified(dies, i);
        let same_scope = n > 0 && self.scopes.get(&base) == Some(&scope);
        self.scopes.entry(base).or_insert(scope);
        if let Some(raw) = &dies[i].name {
            // Ghidra keeps types of one name apart by their namespace and marks only a second
            // definition in the same one
            let mut shown = function_name(raw);
            if same_scope {
                shown = format!("{shown}.conflict{n}");
            }
            if shown != name {
                self.display.insert(name.clone(), shown);
            }
        }
        Slot::New(name)
    }

    fn type_name(&mut self, d: &Die, kind: &str) -> String {
        match &d.name {
            Some(n) => c_name(n),
            None => {
                self.anon += 1;
                format!("anon_{kind}_{}", self.anon)
            }
        }
    }

    /// The type a `DW_AT_type` reference names; `void` for none.
    fn type_ref(&mut self, u: &mut UnitImport<'_>, at: Option<usize>, depth: usize) -> TypeRef {
        let Some(i) = at else {
            return void();
        };
        if depth > MAX_DEPTH {
            return prim(PrimitiveClass::Undefined, 1, false);
        }
        if let Some(t) = u.memo.get(&i) {
            return t.clone();
        }
        let dies = u.dies;
        let d = &dies[i];
        let t = match DwTag(d.tag) {
            constants::DW_TAG_base_type => {
                let size = d.byte_size.unwrap_or(0) as u32;
                let enc = d.encoding.unwrap_or(0);
                let class = match constants::DwAte(enc) {
                    constants::DW_ATE_boolean => PrimitiveClass::Bool,
                    constants::DW_ATE_float => PrimitiveClass::Float,
                    constants::DW_ATE_signed_char
                    | constants::DW_ATE_unsigned_char
                    | constants::DW_ATE_UTF
                        if size <= 4 =>
                    {
                        PrimitiveClass::Char
                    }
                    constants::DW_ATE_signed | constants::DW_ATE_unsigned => PrimitiveClass::Int,
                    _ => PrimitiveClass::Undefined,
                };
                // plain `char` is Ghidra's `char` whatever its signedness (unsigned on ARM,
                // AArch64 and RISC-V), so strings read as strings there too
                let plain_char = constants::DwAte(enc) == constants::DW_ATE_unsigned_char
                    && d.name.as_deref() == Some("char");
                let signed = plain_char
                    || matches!(
                        constants::DwAte(enc),
                        constants::DW_ATE_signed
                            | constants::DW_ATE_signed_char
                            | constants::DW_ATE_float
                    );
                // `long double` is 16 bytes in memory, 10 of them used
                let size = if class == PrimitiveClass::Float && size == 16 {
                    10
                } else {
                    size
                };
                prim(class, size, signed)
            }
            constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_rvalue_reference_type => {
                // the target is converted after the memo holds the pointer's slot, so cycles
                // through pointers end
                u.memo.insert(
                    i,
                    TypeRef::Pointer {
                        target: Box::new(void()),
                        size: d.byte_size.unwrap_or(8) as u32,
                    },
                );
                let target = self.type_ref(u, d.ty, depth + 1);
                TypeRef::Pointer {
                    target: Box::new(target),
                    size: d.byte_size.unwrap_or(8) as u32,
                }
            }
            constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type => self.type_ref(u, d.ty, depth + 1),
            constants::DW_TAG_typedef => {
                let base = self.type_name(d, "typedef");
                match self.reserve(dies, i, base) {
                    Slot::Have(name) => TypeRef::Named { name },
                    Slot::New(name) => {
                        u.memo.insert(i, TypeRef::Named { name: name.clone() });
                        let target = self.type_ref(u, d.ty, depth + 1);
                        if target == (TypeRef::Named { name: name.clone() }) {
                            // a typedef of itself would never resolve
                            return void();
                        }
                        self.types.push(TypeDef::Typedef(TypedefDef {
                            name: name.clone(),
                            target,
                        }));
                        TypeRef::Named { name }
                    }
                }
            }
            constants::DW_TAG_structure_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_union_type => {
                let union = d.tag == constants::DW_TAG_union_type.0;
                let base = self.type_name(d, if union { "union" } else { "struct" });
                if d.declaration || d.byte_size.is_none() {
                    self.declared.insert(base.clone());
                    TypeRef::Named { name: base }
                } else {
                    let name = match self.reserve(dies, i, base) {
                        Slot::Have(name) => {
                            u.memo.insert(i, TypeRef::Named { name: name.clone() });
                            return TypeRef::Named { name };
                        }
                        Slot::New(name) => name,
                    };
                    u.memo.insert(i, TypeRef::Named { name: name.clone() });
                    let mut fields = Vec::new();
                    for &c in &d.children {
                        let m = &dies[c];
                        let tag = DwTag(m.tag);
                        if (tag != constants::DW_TAG_member && tag != constants::DW_TAG_inheritance)
                            || m.bit_size
                            || m.declaration
                            || (tag == constants::DW_TAG_inheritance
                                && is_empty_class(dies, m.ty, 0))
                        {
                            continue;
                        }
                        let offset = match (m.member_location, union) {
                            (Some(o), _) => o,
                            (None, true) => 0,
                            (None, false) => continue,
                        };
                        let ty = self.type_ref(u, m.ty, depth + 1);
                        let fname = if tag == constants::DW_TAG_inheritance {
                            let base = match &ty {
                                TypeRef::Named { name } => name.clone(),
                                _ => "base".into(),
                            };
                            format!("super_{base}")
                        } else {
                            match &m.name {
                                Some(n) => c_name(n),
                                None => format!("field_{offset:#x}"),
                            }
                        };
                        fields.push(Field {
                            name: fname,
                            offset,
                            ty,
                            bitfield: None,
                        });
                    }
                    let c = Composite {
                        name: name.clone(),
                        size: d.byte_size.unwrap_or(0),
                        align: 1,
                        fields,
                    };
                    self.types.push(if union {
                        TypeDef::Union(c)
                    } else {
                        TypeDef::Struct(c)
                    });
                    TypeRef::Named { name }
                }
            }
            constants::DW_TAG_enumeration_type => {
                let base = self.type_name(d, "enum");
                let name = match self.reserve(dies, i, base) {
                    Slot::Have(name) => {
                        u.memo.insert(i, TypeRef::Named { name: name.clone() });
                        return TypeRef::Named { name };
                    }
                    Slot::New(name) => name,
                };
                let variants = d
                    .children
                    .iter()
                    .map(|c| &u.dies[*c])
                    .filter(|m| m.tag == constants::DW_TAG_enumerator.0)
                    .filter_map(|m| {
                        Some(EnumVariant {
                            name: c_name(m.name.as_deref()?),
                            value: m.const_value.unwrap_or(0),
                        })
                    })
                    .collect();
                self.types.push(TypeDef::Enum(EnumDef {
                    name: name.clone(),
                    size: d.byte_size.unwrap_or(4) as u32,
                    variants,
                }));
                TypeRef::Named { name }
            }
            constants::DW_TAG_array_type => {
                let element = self.type_ref(u, d.ty, depth + 1);
                let dims: Vec<u64> = d
                    .children
                    .iter()
                    .map(|c| &u.dies[*c])
                    .filter(|m| m.tag == constants::DW_TAG_subrange_type.0)
                    .map(|m| {
                        m.count
                            .or_else(|| m.upper_bound.map(|b| (b + 1).max(0) as u64))
                            .unwrap_or(0)
                    })
                    .collect();
                let mut t = element;
                for n in dims.iter().rev() {
                    t = TypeRef::Array {
                        element: Box::new(t),
                        count: (*n).max(1),
                    };
                }
                if dims.is_empty() {
                    t = TypeRef::Array {
                        element: Box::new(t),
                        count: 1,
                    };
                }
                t
            }
            constants::DW_TAG_subroutine_type => {
                TypeRef::Function(Box::new(self.prototype(u, i, i, depth + 1)))
            }
            constants::DW_TAG_ptr_to_member_type => prim(
                PrimitiveClass::Undefined,
                d.byte_size.unwrap_or(8) as u32,
                false,
            ),
            _ => void(),
        };
        u.memo.insert(i, t.clone());
        t
    }

    /// The prototype of a subprogram or subroutine type: the return type from `decl` (or what
    /// it refers to) and the parameters from `def`'s children (else `decl`'s).
    fn prototype(
        &mut self,
        u: &mut UnitImport<'_>,
        def: usize,
        decl: usize,
        depth: usize,
    ) -> FunctionPrototype {
        let links = chain(u.dies, def);
        let ret_die = links.iter().copied().find(|c| u.dies[*c].ty.is_some());
        let mut return_type = match ret_die {
            Some(c) => self.type_ref(u, u.dies[c].ty, depth),
            None => void(),
        };
        let noreturn = links.iter().any(|c| u.dies[*c].noreturn);
        let mut params = Vec::new();
        let mut varargs = false;
        let mut source = def;
        let has_params = |i: usize| {
            u.dies[i].children.iter().any(|c| {
                matches!(
                    DwTag(u.dies[*c].tag),
                    constants::DW_TAG_formal_parameter | constants::DW_TAG_unspecified_parameters
                )
            })
        };
        // an out-of-line instance lists the parameters it uses; its abstract origin has them
        // all (a destructor's `__in_chrg`), and Ghidra shows those
        if let Some(origin) = u.dies[def].origin.filter(|o| has_params(*o)) {
            source = origin;
        } else if !has_params(def) {
            source = links
                .iter()
                .copied()
                .find(|c| has_params(*c))
                .unwrap_or(decl);
        }
        for &c in &u.dies[source].children.clone() {
            let p = &u.dies[c];
            match DwTag(p.tag) {
                constants::DW_TAG_formal_parameter => {
                    let pchain = chain(u.dies, c);
                    let name = pchain.iter().find_map(|x| u.dies[*x].name.clone());
                    let ty_die = pchain.iter().copied().find(|x| u.dies[*x].ty.is_some());
                    let ty = match ty_die {
                        Some(x) => self.type_ref(u, u.dies[x].ty, depth),
                        None => prim(PrimitiveClass::Undefined, 8, false),
                    };
                    params.push(Param {
                        name: name.map(|n: String| c_name(&n)),
                        ty,
                        storage: None,
                    });
                }
                constants::DW_TAG_unspecified_parameters => varargs = true,
                _ => {}
            }
        }
        // a class returned in memory: the caller passes the storage, as Ghidra shows it
        if self.returned_in_memory(u, ret_die.and_then(|c| u.dies[c].ty), 0) {
            let ptr = TypeRef::Pointer {
                target: Box::new(return_type.clone()),
                size: 8,
            };
            params.insert(
                0,
                Param {
                    name: Some("__return_storage_ptr__".into()),
                    ty: ptr.clone(),
                    storage: None,
                },
            );
            return_type = ptr;
        }
        FunctionPrototype {
            name: None,
            return_type: Box::new(return_type),
            params,
            calling_convention: String::new(),
            varargs,
            noreturn,
        }
    }

    /// Whether a value of the type at `at` is returned through memory: a class passed by
    /// reference (non-trivial copy or destruction), or a composite larger than 16 bytes.
    fn returned_in_memory(&self, u: &UnitImport<'_>, at: Option<usize>, depth: usize) -> bool {
        let Some(i) = at else { return false };
        if depth > MAX_DEPTH {
            return false;
        }
        let d = &u.dies[i];
        match DwTag(d.tag) {
            constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type => self.returned_in_memory(u, d.ty, depth + 1),
            constants::DW_TAG_structure_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_union_type => d.by_reference || d.byte_size.is_some_and(|s| s > 16),
            _ => false,
        }
    }

    fn global(&mut self, u: &mut UnitImport<'_>, i: usize) {
        let d = &u.dies[i];
        let at_top = d.parent.is_some_and(|p| {
            matches!(
                DwTag(u.dies[p].tag),
                constants::DW_TAG_compile_unit | constants::DW_TAG_namespace
            )
        });
        let Some(addr) = d.location.filter(|a| *a != 0) else {
            return;
        };
        if !at_top {
            return;
        }
        let chain = chain(u.dies, i);
        let Some(name) = chain.iter().find_map(|c| u.dies[*c].name.clone()) else {
            return;
        };
        let ty_die = chain.iter().find_map(|c| u.dies[*c].ty);
        let ty = self.type_ref(u, ty_die, 0);
        self.globals.entry(addr).or_insert(DebugGlobal {
            name: function_name(&name),
            ty,
        });
    }

    fn function(&mut self, u: &mut UnitImport<'_>, i: usize) {
        let dies = u.dies;
        let d = &dies[i];
        let Some(entry) = d.low_pc.filter(|a| *a != 0).or(d.first_range) else {
            return;
        };
        let chain = chain(u.dies, i);
        let Some(name) = chain.iter().find_map(|c| u.dies[*c].name.clone()) else {
            return;
        };
        let linkage = chain.iter().find_map(|c| u.dies[*c].linkage.clone());
        let decl = chain.last().copied().unwrap_or(i);
        let prototype = self.prototype(u, i, decl, 0);
        self.functions.entry(entry).or_insert(DebugFunction {
            name: function_name(&name),
            linkage,
            prototype,
        });
    }
}

/// `i` followed by the DIEs it refers to through `DW_AT_specification` and
/// `DW_AT_abstract_origin` (the declaration and the abstract instance).
fn chain(dies: &[Die], i: usize) -> Vec<usize> {
    let mut out = vec![i];
    let mut at = i;
    for _ in 0..8 {
        let d = &dies[at];
        match d.specification.or(d.origin) {
            Some(n) if !out.contains(&n) => {
                out.push(n);
                at = n;
            }
            _ => break,
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

    fn debug_of(name: &str) -> Debug {
        let data = corpus(name);
        let file = object::File::parse(&*data).expect("parse");
        parse(&file)
    }

    #[test]
    fn c_types_and_prototypes_come_from_dwarf() {
        let d = debug_of("pie_list-O0");
        let record = d
            .types
            .iter()
            .find_map(|t| match t {
                TypeDef::Struct(c) if c.name == "record" => Some(c),
                _ => None,
            })
            .expect("struct record");
        assert_eq!(record.size, 40);
        let names: Vec<&str> = record.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["id", "name", "pos", "weight"]);
        assert!(
            d.types
                .iter()
                .any(|t| matches!(t, TypeDef::Typedef(td) if td.name == "cmp_fn"))
        );
        let cmp = d
            .functions
            .get(&0x124e)
            .expect("cmp_id at its file address");
        assert_eq!(cmp.name, "cmp_id");
        let p = &cmp.prototype;
        assert_eq!(p.params.len(), 2);
        assert_eq!(p.params[0].name.as_deref(), Some("a"));
        assert_eq!(
            p.params[0].ty,
            TypeRef::Pointer {
                target: Box::new(TypeRef::Named {
                    name: "record".into()
                }),
                size: 8
            }
        );
        let main = d
            .functions
            .values()
            .find(|f| f.name == "main")
            .expect("main");
        assert!(main.prototype.params.is_empty());
    }

    #[test]
    fn cpp_names_this_and_return_storage() {
        let d = debug_of("cpp_shapes-O0");
        let by_name = |n: &str| {
            d.functions
                .values()
                .filter(|f| f.name == n)
                .collect::<Vec<_>>()
        };
        assert!(!by_name("operator_new").is_empty());
        let area = by_name("area");
        assert!(
            area.iter().any(
                |f| f.prototype.params.first().and_then(|p| p.name.as_deref()) == Some("this")
            ),
            "{area:?}"
        );
        let describe = by_name("describe");
        assert!(describe.iter().all(|f| {
            f.prototype.params.first().and_then(|p| p.name.as_deref())
                == Some("__return_storage_ptr__")
        }));
        assert!(
            d.types
                .iter()
                .any(|t| matches!(t, TypeDef::Struct(c) if c.name == "Rect"
                    && c.fields.first().is_some_and(|f| f.name == "super_Shape")))
        );
    }

    #[test]
    fn stripped_binaries_have_none() {
        let d = debug_of("pie_list-O0-stripped");
        assert!(d.types.is_empty() && d.functions.is_empty());
    }

    #[test]
    fn names_become_identifiers() {
        assert_eq!(c_name("vector<double>"), "vector_double_");
        assert_eq!(c_name("_vptr.Shape"), "_vptr_Shape");
        assert_eq!(function_name("operator new"), "operator_new");
    }
}
