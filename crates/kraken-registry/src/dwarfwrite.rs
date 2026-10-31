//! Writes what KRAKEN knows about a program as a separate ELF debug file: DWARF (`gimli::write`)
//! with a subprogram for every named function, the types, and the globals, plus the program's
//! build-id note so debuggers pick the file up. The container is written by hand: section
//! headers only (no segments), the program's allocated sections as `NOBITS` like
//! `objcopy --only-keep-debug`, then the debug sections.

use std::collections::HashMap;

use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, Expression, Sections, StringId, UnitEntryId,
};
use gimli::{Encoding, Format, RunTimeEndian, constants};
use kraken_proto::cdecl::{CContext, parse_declarations};
use kraken_proto::{Composite, FunctionPrototype, Primitive, PrimitiveClass, TypeDef, TypeRef};

/// Most DIEs the writer creates, so a huge type store cannot grow the file without bound.
const MAX_ENTRIES: usize = 1_500_000;
/// Deepest type nesting followed.
const MAX_DEPTH: usize = 48;

/// A section of the program that the debug file lists (without contents).
#[derive(Debug, Clone)]
pub struct AllocSection {
    /// Section name.
    pub name: String,
    /// `sh_flags`.
    pub flags: u64,
    /// Virtual address in the file (not rebased).
    pub addr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Alignment.
    pub align: u64,
}

/// The program the file describes.
#[derive(Debug, Clone)]
pub struct Target {
    /// File name of the program, the compile unit's name.
    pub name: String,
    /// Little-endian (false: big-endian).
    pub little: bool,
    /// 64-bit ELF (false: 32-bit).
    pub is64: bool,
    /// `e_type` of the program.
    pub e_type: u16,
    /// `e_machine` of the program.
    pub e_machine: u16,
    /// `EI_OSABI` of the program.
    pub osabi: u8,
    /// `e_flags` of the program.
    pub e_flags: u32,
    /// The allocated sections of the program.
    pub sections: Vec<AllocSection>,
    /// The program's GNU build-id.
    pub build_id: Option<Vec<u8>>,
}

/// A function to describe.
#[derive(Debug, Clone)]
pub struct FuncIn {
    /// Entry address in the file's address space.
    pub addr: u64,
    /// Size of the body in bytes, when known.
    pub size: Option<u64>,
    /// Name.
    pub name: String,
    /// Mangled name, when `name` is a demangled one.
    pub linkage: Option<String>,
    /// Rendered signature, such as `int add(int a, int b)`.
    pub signature: Option<String>,
}

/// A global variable to describe.
#[derive(Debug, Clone)]
pub struct GlobalIn {
    /// Address in the file's address space.
    pub addr: u64,
    /// Name.
    pub name: String,
    /// Type, when known.
    pub ty: Option<TypeRef>,
}

/// What a build wrote.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Subprograms written.
    pub functions: u32,
    /// Of those, the ones whose signature was understood.
    pub prototypes: u32,
    /// Variables written.
    pub globals: u32,
    /// Named types written.
    pub types: u32,
    /// Things left out and why.
    pub warnings: Vec<String>,
}

type Res<T> = Result<T, String>;

struct Builder<'a> {
    dw: DwarfUnit,
    root: UnitEntryId,
    defs: HashMap<&'a str, &'a TypeDef>,
    named: HashMap<String, Option<UnitEntryId>>,
    memo: HashMap<TypeRef, Option<UnitEntryId>>,
    entries: usize,
    types: u32,
    byte_fallback: Option<UnitEntryId>,
}

fn dw_err(e: gimli::write::Error) -> String {
    format!("DWARF writer: {e}")
}

impl<'a> Builder<'a> {
    fn str_attr(&mut self, s: &str) -> AttributeValue {
        let id: StringId = self.dw.strings.add(s.as_bytes().to_vec());
        AttributeValue::StringRef(id)
    }

    fn add(&mut self, parent: UnitEntryId, tag: constants::DwTag) -> Res<UnitEntryId> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return Err(
                "too many debug entries; the program has more than the writer takes".into(),
            );
        }
        Ok(self.dw.unit.add(parent, tag))
    }

    fn set(&mut self, id: UnitEntryId, at: constants::DwAt, v: AttributeValue) {
        self.dw.unit.get_mut(id).set(at, v);
    }

    fn name_of(&mut self, id: UnitEntryId, name: &str) {
        let v = self.str_attr(name);
        self.set(id, constants::DW_AT_name, v);
    }

    fn base(&mut self, name: &str, enc: constants::DwAte, size: u32) -> Res<UnitEntryId> {
        let id = self.add(self.root, constants::DW_TAG_base_type)?;
        self.name_of(id, name);
        self.set(
            id,
            constants::DW_AT_byte_size,
            AttributeValue::Udata(size.into()),
        );
        self.set(id, constants::DW_AT_encoding, AttributeValue::Encoding(enc));
        Ok(id)
    }

    fn primitive(&mut self, p: &Primitive) -> Res<Option<UnitEntryId>> {
        let n = p.size;
        let (name, enc) = match p.class {
            PrimitiveClass::Void => return Ok(None),
            PrimitiveClass::Bool => ("_Bool".to_string(), constants::DW_ATE_boolean),
            PrimitiveClass::Char if p.signed => ("char".into(), constants::DW_ATE_signed_char),
            PrimitiveClass::Char => ("unsigned char".into(), constants::DW_ATE_unsigned_char),
            PrimitiveClass::Float => (
                match n {
                    4 => "float".to_string(),
                    8 => "double".into(),
                    10 => "long double".into(),
                    _ => format!("float{}", n * 8),
                },
                constants::DW_ATE_float,
            ),
            PrimitiveClass::Int => {
                let name = match (n, p.signed) {
                    (1, true) => "int8_t".to_string(),
                    (1, false) => "uint8_t".into(),
                    (2, true) => "short".into(),
                    (2, false) => "unsigned short".into(),
                    (4, true) => "int".into(),
                    (4, false) => "unsigned int".into(),
                    (8, true) => "long".into(),
                    (8, false) => "unsigned long".into(),
                    (16, true) => "__int128".into(),
                    (16, false) => "unsigned __int128".into(),
                    (_, true) => format!("int{}_t", n * 8),
                    (_, false) => format!("uint{}_t", n * 8),
                };
                let enc = if p.signed {
                    constants::DW_ATE_signed
                } else {
                    constants::DW_ATE_unsigned
                };
                (name, enc)
            }
            PrimitiveClass::Undefined => (format!("undefined{n}"), constants::DW_ATE_unsigned),
        };
        // `long double` occupies 16 bytes in memory, 10 of them used
        let size = if p.class == PrimitiveClass::Float && n == 10 {
            16
        } else {
            n
        };
        Ok(Some(self.base(&name, enc, size)?))
    }

    fn byte(&mut self) -> Res<UnitEntryId> {
        if let Some(id) = self.byte_fallback {
            return Ok(id);
        }
        let id = self.base("unsigned char", constants::DW_ATE_unsigned_char, 1)?;
        self.byte_fallback = Some(id);
        Ok(id)
    }

    fn type_ref(&mut self, t: &TypeRef, depth: usize) -> Res<Option<UnitEntryId>> {
        if depth > MAX_DEPTH {
            return Ok(Some(self.byte()?));
        }
        if let TypeRef::Named { name } = t {
            return self.named_type(name, depth);
        }
        if let Some(id) = self.memo.get(t) {
            return Ok(*id);
        }
        let id = match t {
            TypeRef::Named { .. } => None,
            TypeRef::Primitive(p) => self.primitive(p)?,
            TypeRef::Pointer { target, size } => {
                let id = self.add(self.root, constants::DW_TAG_pointer_type)?;
                self.set(
                    id,
                    constants::DW_AT_byte_size,
                    AttributeValue::Udata((*size).into()),
                );
                if let Some(to) = self.type_ref(target, depth + 1)? {
                    self.set(id, constants::DW_AT_type, AttributeValue::UnitRef(to));
                }
                Some(id)
            }
            TypeRef::Array { element, count } => {
                let id = self.add(self.root, constants::DW_TAG_array_type)?;
                let el = match self.type_ref(element, depth + 1)? {
                    Some(e) => e,
                    None => self.byte()?,
                };
                self.set(id, constants::DW_AT_type, AttributeValue::UnitRef(el));
                let sub = self.add(id, constants::DW_TAG_subrange_type)?;
                if *count > 0 {
                    self.set(
                        sub,
                        constants::DW_AT_upper_bound,
                        AttributeValue::Udata(count - 1),
                    );
                }
                Some(id)
            }
            TypeRef::Function(p) => Some(self.subroutine(p, depth + 1)?),
        };
        self.memo.insert(t.clone(), id);
        Ok(id)
    }

    fn subroutine(&mut self, p: &FunctionPrototype, depth: usize) -> Res<UnitEntryId> {
        let id = self.add(self.root, constants::DW_TAG_subroutine_type)?;
        self.set(id, constants::DW_AT_prototyped, AttributeValue::Flag(true));
        if let Some(r) = self.type_ref(&p.return_type, depth)? {
            self.set(id, constants::DW_AT_type, AttributeValue::UnitRef(r));
        }
        self.params(id, p, depth, false)?;
        Ok(id)
    }

    fn params(
        &mut self,
        parent: UnitEntryId,
        p: &FunctionPrototype,
        depth: usize,
        names: bool,
    ) -> Res<()> {
        for a in &p.params {
            let c = self.add(parent, constants::DW_TAG_formal_parameter)?;
            if names && let Some(n) = &a.name {
                self.name_of(c, n);
            }
            let ty = match self.type_ref(&a.ty, depth)? {
                Some(t) => t,
                None => self.byte()?,
            };
            self.set(c, constants::DW_AT_type, AttributeValue::UnitRef(ty));
        }
        if p.varargs {
            self.add(parent, constants::DW_TAG_unspecified_parameters)?;
        }
        Ok(())
    }

    fn named_type(&mut self, name: &str, depth: usize) -> Res<Option<UnitEntryId>> {
        if let Some(id) = self.named.get(name) {
            return Ok(*id);
        }
        let Some(def) = self.defs.get(name).copied() else {
            // referred to, never defined: a declaration debuggers show as incomplete
            let id = self.add(self.root, constants::DW_TAG_structure_type)?;
            self.name_of(id, name);
            self.set(id, constants::DW_AT_declaration, AttributeValue::Flag(true));
            self.named.insert(name.to_string(), Some(id));
            return Ok(Some(id));
        };
        let id = match def {
            TypeDef::Struct(c) => {
                Some(self.composite(c, constants::DW_TAG_structure_type, depth)?)
            }
            TypeDef::Union(c) => Some(self.composite(c, constants::DW_TAG_union_type, depth)?),
            TypeDef::Enum(e) => {
                let id = self.add(self.root, constants::DW_TAG_enumeration_type)?;
                self.named.insert(name.to_string(), Some(id));
                self.name_of(id, &e.name);
                self.set(
                    id,
                    constants::DW_AT_byte_size,
                    AttributeValue::Udata(e.size.into()),
                );
                for v in &e.variants {
                    let c = self.add(id, constants::DW_TAG_enumerator)?;
                    self.name_of(c, &v.name);
                    self.set(
                        c,
                        constants::DW_AT_const_value,
                        AttributeValue::Sdata(v.value),
                    );
                }
                self.types += 1;
                Some(id)
            }
            TypeDef::Typedef(t) => {
                let id = self.add(self.root, constants::DW_TAG_typedef)?;
                self.named.insert(name.to_string(), Some(id));
                self.name_of(id, &t.name);
                if let Some(to) = self.type_ref(&t.target, depth + 1)? {
                    self.set(id, constants::DW_AT_type, AttributeValue::UnitRef(to));
                }
                self.types += 1;
                Some(id)
            }
            TypeDef::Function(p) => {
                let id = self.subroutine(p, depth + 1)?;
                self.named.insert(name.to_string(), Some(id));
                Some(id)
            }
        };
        self.named.insert(name.to_string(), id);
        Ok(id)
    }

    fn composite(
        &mut self,
        c: &Composite,
        tag: constants::DwTag,
        depth: usize,
    ) -> Res<UnitEntryId> {
        let id = self.add(self.root, tag)?;
        self.named.insert(c.name.clone(), Some(id));
        self.name_of(id, &c.name);
        self.set(
            id,
            constants::DW_AT_byte_size,
            AttributeValue::Udata(c.size),
        );
        for f in &c.fields {
            let m = self.add(id, constants::DW_TAG_member)?;
            self.name_of(m, &f.name);
            let ty = match self.type_ref(&f.ty, depth + 1)? {
                Some(t) => t,
                None => self.byte()?,
            };
            self.set(m, constants::DW_AT_type, AttributeValue::UnitRef(ty));
            match f.bitfield {
                Some(b) => {
                    self.set(
                        m,
                        constants::DW_AT_bit_size,
                        AttributeValue::Udata(b.bit_size.into()),
                    );
                    self.set(
                        m,
                        constants::DW_AT_data_bit_offset,
                        AttributeValue::Udata(f.offset * 8 + u64::from(b.bit_offset)),
                    );
                }
                None => self.set(
                    m,
                    constants::DW_AT_data_member_location,
                    AttributeValue::Udata(f.offset),
                ),
            }
        }
        self.types += 1;
        Ok(id)
    }
}

/// The prototype a rendered signature spells (`int add(int a, int b)`), read with the type
/// parser against `defs`; `None` when it does not parse (a type the store does not know).
pub fn parse_signature(
    sig: &str,
    pointer_size: u32,
    long_size: u32,
    lookup: &dyn Fn(&str) -> Option<TypeDef>,
) -> Option<FunctionPrototype> {
    let mut s = sig.trim();
    let mut noreturn = false;
    let mut cc = String::new();
    loop {
        if let Some(r) = s.strip_prefix("noreturn ") {
            noreturn = true;
            s = r.trim_start();
        } else if let Some(r) = ["__stdcall ", "__fastcall ", "__cdecl ", "__thiscall "]
            .iter()
            .find_map(|p| s.strip_prefix(p).map(|r| (p.trim(), r)))
        {
            cc = r.0.to_string();
            s = r.1.trim_start();
        } else {
            break;
        }
    }
    let open = s.find('(')?;
    let head = s[..open].trim_end();
    let cut = head.rfind(|c: char| c.is_whitespace() || c == '*')? + 1;
    let text = format!("{}kraken_fn__{};", &head[..cut], &s[open..]);
    let cx = CContext {
        pointer_size,
        long_size,
        lookup,
    };
    let defs = parse_declarations(&text, &cx).ok()?;
    defs.into_iter().find_map(|d| match d {
        TypeDef::Function(mut p) if p.name.as_deref() == Some("kraken_fn__") => {
            p.noreturn = noreturn;
            p.calling_convention = cc.clone();
            Some(p)
        }
        _ => None,
    })
}

fn put(out: &mut Vec<u8>, little: bool, bytes: u64, width: usize) {
    let b = if little {
        bytes.to_le_bytes().to_vec()
    } else {
        bytes.to_be_bytes()[8 - width..].to_vec()
    };
    out.extend_from_slice(&b[..width]);
}

struct Part {
    name: String,
    kind: u32,
    flags: u64,
    addr: u64,
    align: u64,
    size: u64,
    data: Vec<u8>,
}

/// The ELF file: header, section contents, section header table.
fn container(t: &Target, parts: &[Part]) -> Vec<u8> {
    let ptr = if t.is64 { 8 } else { 4 };
    let ehsize: usize = if t.is64 { 64 } else { 52 };
    let shentsize: usize = if t.is64 { 64 } else { 40 };
    let mut names = vec![0u8];
    let mut name_off = vec![0u32];
    for p in parts {
        name_off.push(names.len() as u32);
        names.extend_from_slice(p.name.as_bytes());
        names.push(0);
    }
    let shstr_name = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");

    let mut out = vec![0u8; ehsize];
    let mut offsets = Vec::new();
    for p in parts {
        while !out.len().is_multiple_of(p.align.max(1) as usize) {
            out.push(0);
        }
        offsets.push(out.len() as u64);
        out.extend_from_slice(&p.data);
    }
    let shstr_off = out.len() as u64;
    out.extend_from_slice(&names);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    let shoff = out.len() as u64;
    let le = t.little;
    let shdr = |out: &mut Vec<u8>, n: u32, ty: u32, fl: u64, ad: u64, of: u64, sz: u64, al: u64| {
        put(out, le, n.into(), 4);
        put(out, le, ty.into(), 4);
        put(out, le, fl, ptr);
        put(out, le, ad, ptr);
        put(out, le, of, ptr);
        put(out, le, sz, ptr);
        put(out, le, 0, 4);
        put(out, le, 0, 4);
        put(out, le, al, ptr);
        put(out, le, 0, ptr);
    };
    shdr(&mut out, 0, 0, 0, 0, 0, 0, 0);
    for (i, p) in parts.iter().enumerate() {
        shdr(
            &mut out,
            name_off[i + 1],
            p.kind,
            p.flags,
            p.addr,
            offsets[i],
            p.size,
            p.align,
        );
    }
    shdr(
        &mut out,
        shstr_name,
        3,
        0,
        0,
        shstr_off,
        names.len() as u64,
        1,
    );

    let mut h = Vec::with_capacity(ehsize);
    h.extend_from_slice(&[0x7f, b'E', b'L', b'F', if t.is64 { 2 } else { 1 }]);
    h.push(if le { 1 } else { 2 });
    h.push(1);
    h.push(t.osabi);
    h.resize(16, 0);
    put(&mut h, le, t.e_type.into(), 2);
    put(&mut h, le, t.e_machine.into(), 2);
    put(&mut h, le, 1, 4);
    put(&mut h, le, 0, ptr);
    put(&mut h, le, 0, ptr);
    put(&mut h, le, shoff, ptr);
    put(&mut h, le, t.e_flags.into(), 4);
    put(&mut h, le, ehsize as u64, 2);
    put(&mut h, le, 0, 2);
    put(&mut h, le, 0, 2);
    put(&mut h, le, shentsize as u64, 2);
    put(&mut h, le, (parts.len() + 2) as u64, 2);
    put(&mut h, le, (parts.len() + 1) as u64, 2);
    out[..ehsize].copy_from_slice(&h);
    out
}

fn build_id_note(id: &[u8], little: bool) -> Vec<u8> {
    let mut n = Vec::new();
    put(&mut n, little, 4, 4);
    put(&mut n, little, id.len() as u64, 4);
    put(&mut n, little, 3, 4);
    n.extend_from_slice(b"GNU\0");
    n.extend_from_slice(id);
    while !n.len().is_multiple_of(4) {
        n.push(0);
    }
    n
}

/// Builds the debug file.
pub fn build(
    target: &Target,
    producer: &str,
    funcs: &[FuncIn],
    globals: &[GlobalIn],
    types: &[TypeDef],
    long_size: u32,
) -> Res<(Vec<u8>, Stats)> {
    let ptr: u32 = if target.is64 { 8 } else { 4 };
    let encoding = Encoding {
        address_size: ptr as u8,
        format: Format::Dwarf32,
        version: 4,
    };
    let dw = DwarfUnit::new(encoding);
    let root = dw.unit.root();
    let mut b = Builder {
        dw,
        root,
        defs: types
            .iter()
            .filter_map(|d| d.name().map(|n| (n, d)))
            .collect(),
        named: HashMap::new(),
        memo: HashMap::new(),
        entries: 0,
        types: 0,
        byte_fallback: None,
    };
    let mut stats = Stats::default();

    let v = b.str_attr(&target.name);
    b.set(root, constants::DW_AT_name, v);
    let v = b.str_attr(producer);
    b.set(root, constants::DW_AT_producer, v);
    b.set(
        root,
        constants::DW_AT_language,
        AttributeValue::Language(constants::DW_LANG_C99),
    );
    let lo = funcs.iter().map(|f| f.addr).min();
    let hi = funcs
        .iter()
        .map(|f| f.addr.saturating_add(f.size.unwrap_or(1).max(1)))
        .max();
    if let (Some(lo), Some(hi)) = (lo, hi) {
        b.set(
            root,
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(lo)),
        );
        b.set(
            root,
            constants::DW_AT_high_pc,
            AttributeValue::Udata(hi - lo),
        );
    }

    // every type of the store, so the file is useful for types alone too
    for d in types {
        if let (
            Some(n),
            TypeDef::Struct(_) | TypeDef::Union(_) | TypeDef::Enum(_) | TypeDef::Typedef(_),
        ) = (d.name(), d)
        {
            b.named_type(n, 0)?;
        }
    }

    let index: HashMap<&str, &TypeDef> = types
        .iter()
        .filter_map(|d| d.name().map(|n| (n, d)))
        .collect();
    let lookup = |n: &str| index.get(n).map(|d| (*d).clone());
    for f in funcs {
        let id = b.add(root, constants::DW_TAG_subprogram)?;
        b.name_of(id, &f.name);
        if let Some(l) = &f.linkage {
            let v = b.str_attr(l);
            b.set(id, constants::DW_AT_linkage_name, v);
        }
        b.set(id, constants::DW_AT_external, AttributeValue::Flag(true));
        b.set(
            id,
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(f.addr)),
        );
        b.set(
            id,
            constants::DW_AT_high_pc,
            AttributeValue::Udata(f.size.unwrap_or(1).max(1)),
        );
        let proto = f
            .signature
            .as_deref()
            .and_then(|s| parse_signature(s, ptr, long_size, &lookup));
        if let Some(p) = proto {
            b.set(id, constants::DW_AT_prototyped, AttributeValue::Flag(true));
            if p.noreturn {
                b.set(id, constants::DW_AT_noreturn, AttributeValue::Flag(true));
            }
            if let Some(r) = b.type_ref(&p.return_type, 0)? {
                b.set(id, constants::DW_AT_type, AttributeValue::UnitRef(r));
            }
            b.params(id, &p, 0, true)?;
            stats.prototypes += 1;
        }
        stats.functions += 1;
    }

    for g in globals {
        let id = b.add(root, constants::DW_TAG_variable)?;
        b.name_of(id, &g.name);
        let ty = match &g.ty {
            Some(t) => b.type_ref(t, 0)?,
            None => None,
        };
        let ty = match ty {
            Some(t) => t,
            None => b.byte()?,
        };
        b.set(id, constants::DW_AT_type, AttributeValue::UnitRef(ty));
        b.set(id, constants::DW_AT_external, AttributeValue::Flag(true));
        let mut e = Expression::new();
        e.op_addr(Address::Constant(g.addr));
        b.set(id, constants::DW_AT_location, AttributeValue::Exprloc(e));
        stats.globals += 1;
    }
    stats.types = b.types;

    let endian = if target.little {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut sections = Sections::new(EndianVec::new(endian));
    b.dw.write(&mut sections).map_err(dw_err)?;

    let mut parts = Vec::new();
    if let Some(id) = &target.build_id {
        let data = build_id_note(id, target.little);
        parts.push(Part {
            name: ".note.gnu.build-id".into(),
            kind: 7,
            flags: 2,
            addr: 0,
            align: 4,
            size: data.len() as u64,
            data,
        });
    }
    for s in &target.sections {
        parts.push(Part {
            name: s.name.clone(),
            kind: 8,
            flags: s.flags,
            addr: s.addr,
            align: s.align,
            size: s.size,
            data: Vec::new(),
        });
    }
    sections.for_each(|id, w| -> Result<(), String> {
        let data = w.slice().to_vec();
        if !data.is_empty() {
            parts.push(Part {
                name: id.name().to_string(),
                kind: 1,
                flags: 0,
                addr: 0,
                align: 1,
                size: data.len() as u64,
                data,
            });
        }
        Ok(())
    })?;
    Ok((container(target, &parts), stats))
}
