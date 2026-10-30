//! A small C declaration parser: struct, union, enum and typedef declarations (and function
//! prototypes) into the neutral type model, with natural layout.
//!
//! It covers what people type to describe a data structure: scalar types, pointers, arrays,
//! nested named types, function-pointer typedefs. Preprocessor lines, bitfields, anonymous
//! members and initializers are refused with a message that says where.

use std::collections::BTreeMap;

use crate::types::{
    Composite, EnumDef, EnumVariant, Field, FunctionPrototype, Param, Primitive, PrimitiveClass,
    TypeDef, TypeRef, TypedefDef,
};

/// Deepest nesting a declared type may have, counted in JSON levels (a pointer or array adds
/// one, a function pointer adds three around its parameters). Deeper types could not be read
/// back from the edit log, whose JSON reader stops at 128 levels.
pub const MAX_TYPE_NESTING: u32 = 32;

/// Largest size in bytes a declared type may have.
pub const MAX_TYPE_SIZE: u64 = 1 << 32;

/// How many declarators (function-pointer parameter lists) may be nested in one another.
const MAX_DECLARATOR_DEPTH: u32 = 16;

/// The nesting of `t` in the units of [`MAX_TYPE_NESTING`].
pub fn type_nesting(t: &TypeRef) -> u32 {
    match t {
        TypeRef::Named { .. } | TypeRef::Primitive(_) => 1,
        TypeRef::Pointer { target, .. } => 1 + type_nesting(target),
        TypeRef::Array { element, .. } => 1 + type_nesting(element),
        TypeRef::Function(p) => prototype_nesting(p),
    }
}

fn prototype_nesting(p: &FunctionPrototype) -> u32 {
    let params = p
        .params
        .iter()
        .map(|q| 2 + type_nesting(&q.ty))
        .max()
        .unwrap_or(0);
    1 + type_nesting(&p.return_type).max(params)
}

/// Checks that `def` stays within [`MAX_TYPE_NESTING`] and [`MAX_TYPE_SIZE`], for definitions
/// that did not come through the parser.
pub fn check_limits(def: &TypeDef) -> Result<(), String> {
    let deep = |t: &TypeRef| type_nesting(t) > MAX_TYPE_NESTING;
    let too_deep = match def {
        TypeDef::Struct(c) | TypeDef::Union(c) => {
            if c.size > MAX_TYPE_SIZE {
                return Err(format!("the type is larger than {MAX_TYPE_SIZE} bytes"));
            }
            c.fields.iter().any(|f| deep(&f.ty))
        }
        TypeDef::Enum(_) => false,
        TypeDef::Typedef(t) => deep(&t.target),
        TypeDef::Function(p) => prototype_nesting(p) > MAX_TYPE_NESTING,
    };
    if too_deep {
        return Err(format!(
            "the type is nested too deeply (more than {MAX_TYPE_NESTING} levels of pointers, arrays and function pointers)"
        ));
    }
    Ok(())
}

/// Places a member of size `s` and alignment `a` after `size` bytes: its offset and the new
/// size, or `None` past [`MAX_TYPE_SIZE`].
fn place(size: u64, s: u64, a: u32) -> Option<(u64, u64)> {
    let o = size.checked_next_multiple_of(u64::from(a.max(1)))?;
    let end = o.checked_add(s)?;
    (end <= MAX_TYPE_SIZE).then_some((o, end))
}

/// What the parser needs to know about the program.
pub struct CContext<'a> {
    /// Pointer size in bytes.
    pub pointer_size: u32,
    /// Size of `long` in bytes (8 on LP64, 4 on LLP64 and ILP32).
    pub long_size: u32,
    /// Existing definitions, for sizes of types the text refers to but does not declare.
    pub lookup: &'a dyn Fn(&str) -> Option<TypeDef>,
}

/// A parse error with its position.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}, column {column}: {message}")]
pub struct CParseError {
    /// What is wrong.
    pub message: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(i64),
    Punct(char),
    Ellipsis,
}

struct Lexed {
    tok: Tok,
    line: usize,
    column: usize,
}

fn lex(text: &str) -> Result<Vec<Lexed>, CParseError> {
    let chars: Vec<char> = text.chars().collect();
    let (mut i, mut line, mut col) = (0usize, 1usize, 1usize);
    let mut out = Vec::new();
    let err = |m: &str, line, column| CParseError {
        message: m.into(),
        line,
        column,
    };
    while i < chars.len() {
        let c = chars[i];
        let (l0, c0) = (line, col);
        let mut adv = |n: usize, i: &mut usize| {
            for _ in 0..n {
                if chars[*i] == '\n' {
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                *i += 1;
            }
        };
        if c.is_whitespace() {
            adv(1, &mut i);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                adv(1, &mut i);
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            adv(2, &mut i);
            loop {
                if i + 1 >= chars.len() {
                    return Err(err("unterminated comment", l0, c0));
                }
                if chars[i] == '*' && chars[i + 1] == '/' {
                    adv(2, &mut i);
                    break;
                }
                adv(1, &mut i);
            }
        } else if c == '#' {
            return Err(err("preprocessor lines are not supported", l0, c0));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                adv(1, &mut i);
            }
            out.push(Lexed {
                tok: Tok::Ident(chars[start..i].iter().collect()),
                line: l0,
                column: c0,
            });
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                adv(1, &mut i);
            }
            let s: String = chars[start..i].iter().collect();
            let t = s.trim_end_matches(['u', 'U', 'l', 'L']);
            let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i64::from_str_radix(h, 16)
            } else if t.len() > 1 && t.starts_with('0') {
                i64::from_str_radix(&t[1..], 8)
            } else {
                t.parse()
            };
            let v = v.map_err(|_| err(&format!("bad number {s:?}"), l0, c0))?;
            out.push(Lexed {
                tok: Tok::Num(v),
                line: l0,
                column: c0,
            });
        } else if c == '.' && chars.get(i + 1) == Some(&'.') && chars.get(i + 2) == Some(&'.') {
            adv(3, &mut i);
            out.push(Lexed {
                tok: Tok::Ellipsis,
                line: l0,
                column: c0,
            });
        } else if "{}()[];,*=-:".contains(c) {
            adv(1, &mut i);
            out.push(Lexed {
                tok: Tok::Punct(c),
                line: l0,
                column: c0,
            });
        } else {
            return Err(err(&format!("unexpected character {c:?}"), l0, c0));
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<Lexed>,
    at: usize,
    cx: &'a CContext<'a>,
    defs: BTreeMap<String, TypeDef>,
    order: Vec<String>,
    /// Parsing the type of a `typedef`, whose name may name an anonymous body.
    in_typedef: bool,
    /// An anonymous body took the typedef's name already.
    typedef_done: bool,
    depth: u32,
    decl_depth: u32,
}

type PResult<T> = Result<T, CParseError>;

const QUALIFIERS: &[&str] = &[
    "const", "volatile", "restrict", "static", "extern", "inline",
];

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

impl<'a> Parser<'a> {
    fn pos(&self) -> (usize, usize) {
        self.toks
            .get(self.at)
            .or(self.toks.last())
            .map_or((1, 1), |t| (t.line, t.column))
    }

    fn fail<T>(&self, message: impl Into<String>) -> PResult<T> {
        let (line, column) = self.pos();
        Err(CParseError {
            message: message.into(),
            line,
            column,
        })
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|t| &t.tok)
    }

    fn peek_ident(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Ident(s)) => Some(s),
            _ => None,
        }
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, c: char) -> PResult<()> {
        if self.eat(c) {
            Ok(())
        } else {
            self.fail(format!("expected `{c}`"))
        }
    }

    fn ident(&mut self, what: &str) -> PResult<String> {
        match self.peek() {
            Some(Tok::Ident(s)) => {
                let s = s.clone();
                self.at += 1;
                Ok(s)
            }
            _ => self.fail(format!("expected {what}")),
        }
    }

    fn skip_qualifiers(&mut self) {
        while self.peek_ident().is_some_and(|s| QUALIFIERS.contains(&s)) {
            self.at += 1;
        }
    }

    fn int_value(&mut self) -> PResult<i64> {
        let neg = self.eat('-');
        match self.peek() {
            Some(Tok::Num(n)) => {
                let n = *n;
                self.at += 1;
                Ok(if neg { -n } else { n })
            }
            _ => self.fail("expected a number"),
        }
    }

    fn lookup(&self, name: &str) -> Option<TypeDef> {
        self.defs
            .get(name)
            .cloned()
            .or_else(|| (self.cx.lookup)(name))
    }

    fn size_align(&self, t: &TypeRef) -> PResult<(u64, u32)> {
        self.size_align_depth(t, 0)
    }

    fn size_align_depth(&self, t: &TypeRef, depth: u32) -> PResult<(u64, u32)> {
        match t {
            TypeRef::Primitive(p) => Ok((u64::from(p.size), p.size.max(1))),
            TypeRef::Pointer { size, .. } => Ok((u64::from(*size), *size)),
            TypeRef::Array { element, count } => {
                let (s, a) = self.size_align_depth(element, depth + 1)?;
                match s.checked_mul(*count) {
                    Some(n) if n <= MAX_TYPE_SIZE => Ok((n, a)),
                    _ => self.fail(format!("an array is larger than {MAX_TYPE_SIZE} bytes")),
                }
            }
            TypeRef::Function(_) => self.fail("a function cannot be a member by value"),
            TypeRef::Named { name } => match self.lookup(name) {
                Some(TypeDef::Struct(c) | TypeDef::Union(c)) => Ok((c.size, c.align.max(1))),
                Some(TypeDef::Enum(e)) => Ok((u64::from(e.size), e.size.max(1))),
                Some(TypeDef::Typedef(t)) if depth < 32 => {
                    self.size_align_depth(&t.target, depth + 1)
                }
                Some(_) => self.fail(format!("`{name}` has no size")),
                None => self.fail(format!(
                    "`{name}` is not defined; declare it first or use a pointer to it"
                )),
            },
        }
    }

    /// The base type of a declaration: `unsigned long`, `struct node`, a typedef name, or an
    /// inline definition.
    fn base_type(&mut self) -> PResult<TypeRef> {
        self.skip_qualifiers();
        let first = match self.peek_ident() {
            Some(s) => s.to_string(),
            None => return self.fail("expected a type"),
        };
        if matches!(first.as_str(), "struct" | "union") {
            self.at += 1;
            return self.composite(first == "union");
        }
        if first == "enum" {
            self.at += 1;
            return self.enumeration();
        }
        let mut words: Vec<String> = Vec::new();
        loop {
            self.skip_qualifiers();
            match self.peek_ident() {
                Some(w)
                    if matches!(
                        w,
                        "unsigned"
                            | "signed"
                            | "short"
                            | "long"
                            | "int"
                            | "char"
                            | "void"
                            | "float"
                            | "double"
                            | "_Bool"
                    ) =>
                {
                    words.push(w.to_string());
                    self.at += 1;
                }
                _ => break,
            }
        }
        if words.is_empty() {
            let name = self.ident("a type")?;
            return Ok(self.named_scalar(&name));
        }
        self.scalar(&words)
    }

    fn named_scalar(&self, name: &str) -> TypeRef {
        let ps = self.cx.pointer_size;
        let int = |s, sg| prim(PrimitiveClass::Int, s, sg);
        match name {
            "int8_t" => int(1, true),
            "uint8_t" => int(1, false),
            "int16_t" => int(2, true),
            "uint16_t" => int(2, false),
            "int32_t" => int(4, true),
            "uint32_t" => int(4, false),
            "int64_t" => int(8, true),
            "uint64_t" => int(8, false),
            "size_t" | "uintptr_t" => int(ps, false),
            "ssize_t" | "intptr_t" | "ptrdiff_t" => int(ps, true),
            "bool" => prim(PrimitiveClass::Bool, 1, false),
            _ => TypeRef::Named { name: name.into() },
        }
    }

    fn scalar(&self, words: &[String]) -> PResult<TypeRef> {
        let has = |w: &str| words.iter().any(|x| x == w);
        let longs = words.iter().filter(|w| *w == "long").count();
        let unsigned = has("unsigned");
        Ok(if has("void") {
            prim(PrimitiveClass::Void, 0, false)
        } else if has("_Bool") {
            prim(PrimitiveClass::Bool, 1, false)
        } else if has("float") {
            prim(PrimitiveClass::Float, 4, true)
        } else if has("double") {
            prim(PrimitiveClass::Float, if longs > 0 { 16 } else { 8 }, true)
        } else if has("char") {
            prim(PrimitiveClass::Char, 1, !unsigned)
        } else if has("short") {
            prim(PrimitiveClass::Int, 2, !unsigned)
        } else if longs >= 2 {
            prim(PrimitiveClass::Int, 8, !unsigned)
        } else if longs == 1 {
            prim(PrimitiveClass::Int, self.cx.long_size, !unsigned)
        } else {
            prim(PrimitiveClass::Int, 4, !unsigned)
        })
    }

    fn register(&mut self, def: TypeDef) -> PResult<()> {
        let name = def.name().unwrap_or_default().to_string();
        if self.defs.contains_key(&name) {
            return self.fail(format!("`{name}` is declared twice"));
        }
        self.order.push(name.clone());
        self.defs.insert(name, def);
        Ok(())
    }

    /// After `struct` or `union`: a tag, a body, or both. A body registers the type.
    fn composite(&mut self, union: bool) -> PResult<TypeRef> {
        let tag = match self.peek_ident() {
            Some(_) => Some(self.ident("a name")?),
            None => None,
        };
        if self.peek() != Some(&Tok::Punct('{')) {
            return match tag {
                Some(name) => Ok(TypeRef::Named { name }),
                None => self.fail("expected a name or a body"),
            };
        }
        self.at += 1;
        if self.depth >= 16 || self.depth + self.decl_depth >= 2 * MAX_DECLARATOR_DEPTH {
            return self.fail("declarations are nested too deeply");
        }
        self.depth += 1;
        let outer_typedef = std::mem::replace(&mut self.in_typedef, false);
        let mut fields: Vec<Field> = Vec::new();
        let (mut size, mut align) = (0u64, 1u32);
        while !self.eat('}') {
            if self.peek().is_none() {
                return self.fail("expected `}`");
            }
            let base = self.base_type()?;
            loop {
                let (ty, name) = self.declarator(base.clone())?;
                let Some(name) = name else {
                    return self.fail("anonymous members are not supported");
                };
                if self.peek() == Some(&Tok::Punct(':')) {
                    return self.fail("bitfields are not supported");
                }
                if fields.iter().any(|f| f.name == name) {
                    return self.fail(format!("duplicate member `{name}`"));
                }
                let (s, a) = self.size_align(&ty)?;
                align = align.max(a);
                let offset = if union {
                    size = size.max(s);
                    0
                } else {
                    let Some((o, end)) = place(size, s, a) else {
                        return self.fail(format!("the type is larger than {MAX_TYPE_SIZE} bytes"));
                    };
                    size = end;
                    o
                };
                fields.push(Field {
                    name,
                    offset,
                    ty,
                    bitfield: None,
                });
                if !self.eat(',') {
                    break;
                }
            }
            self.expect(';')?;
        }
        self.depth -= 1;
        self.in_typedef = outer_typedef;
        let Some((_, size)) = place(size, 0, align) else {
            return self.fail(format!("the type is larger than {MAX_TYPE_SIZE} bytes"));
        };
        let Some(name) = tag else {
            // an anonymous body is named by the typedef that follows
            return self.anonymous_body(
                union,
                Composite {
                    name: String::new(),
                    size,
                    align,
                    fields,
                },
            );
        };
        let c = Composite {
            name: name.clone(),
            size,
            align,
            fields,
        };
        self.register(if union {
            TypeDef::Union(c)
        } else {
            TypeDef::Struct(c)
        })?;
        Ok(TypeRef::Named { name })
    }

    fn anonymous_body(&mut self, union: bool, c: Composite) -> PResult<TypeRef> {
        // `typedef struct { ... } name;` names the body; anything else is refused
        let name = match self.peek_ident() {
            Some(n) if self.in_typedef => n.to_string(),
            _ => return self.fail("a struct or union needs a name here"),
        };
        let c = Composite {
            name: name.clone(),
            ..c
        };
        self.at += 1;
        self.typedef_done = true;
        self.register(if union {
            TypeDef::Union(c)
        } else {
            TypeDef::Struct(c)
        })?;
        Ok(TypeRef::Named { name })
    }

    fn enumeration(&mut self) -> PResult<TypeRef> {
        let tag = match self.peek_ident() {
            Some(_) => Some(self.ident("a name")?),
            None => None,
        };
        if self.peek() != Some(&Tok::Punct('{')) {
            return match tag {
                Some(name) => Ok(TypeRef::Named { name }),
                None => self.fail("expected a name or a body"),
            };
        }
        self.at += 1;
        let mut variants: Vec<EnumVariant> = Vec::new();
        let mut next = 0i64;
        while !self.eat('}') {
            let name = self.ident("an enumerator")?;
            if self.eat('=') {
                next = self.int_value()?;
            }
            if variants.iter().any(|v| v.name == name) {
                return self.fail(format!("duplicate enumerator `{name}`"));
            }
            variants.push(EnumVariant { name, value: next });
            next = next.wrapping_add(1);
            if !self.eat(',') && self.peek() != Some(&Tok::Punct('}')) {
                return self.fail("expected `,` or `}`");
            }
        }
        let name = match tag {
            Some(n) => n,
            None => match self.peek_ident() {
                Some(n) if self.in_typedef => {
                    let n = n.to_string();
                    self.at += 1;
                    self.typedef_done = true;
                    n
                }
                _ => return self.fail("an enum needs a name here"),
            },
        };
        self.register(TypeDef::Enum(EnumDef {
            name: name.clone(),
            size: 4,
            variants,
        }))?;
        Ok(TypeRef::Named { name })
    }

    /// Pointers, name, array suffixes and function-pointer declarators.
    fn declarator(&mut self, base: TypeRef) -> PResult<(TypeRef, Option<String>)> {
        if self.decl_depth >= MAX_DECLARATOR_DEPTH {
            return self.fail("declarations are nested too deeply");
        }
        self.decl_depth += 1;
        let out = self.declarator_inner(base);
        self.decl_depth -= 1;
        let (ty, name) = out?;
        if type_nesting(&ty) > MAX_TYPE_NESTING {
            return self.fail(format!(
                "the type is nested too deeply (more than {MAX_TYPE_NESTING} levels of pointers, arrays and function pointers)"
            ));
        }
        Ok((ty, name))
    }

    fn declarator_inner(&mut self, base: TypeRef) -> PResult<(TypeRef, Option<String>)> {
        let mut ty = base;
        while self.eat('*') {
            if type_nesting(&ty) > MAX_TYPE_NESTING {
                return self.fail("too many levels of pointers");
            }
            self.skip_qualifiers();
            ty = TypeRef::Pointer {
                target: Box::new(ty),
                size: self.cx.pointer_size,
            };
        }
        // `(*name)(params)`: a function pointer
        if self.peek() == Some(&Tok::Punct('('))
            && self.toks.get(self.at + 1).map(|t| &t.tok) == Some(&Tok::Punct('*'))
        {
            self.at += 2;
            let mut stars = 1u32;
            while self.eat('*') {
                stars += 1;
                if stars > MAX_TYPE_NESTING {
                    return self.fail("too many levels of pointers");
                }
            }
            let name = match self.peek_ident() {
                Some(_) => Some(self.ident("a name")?),
                None => None,
            };
            self.expect(')')?;
            self.expect('(')?;
            let params = self.params()?;
            let mut out = TypeRef::Function(Box::new(FunctionPrototype {
                name: None,
                return_type: Box::new(ty),
                params: params.0,
                calling_convention: String::new(),
                varargs: params.1,
                noreturn: false,
            }));
            for _ in 0..stars {
                out = TypeRef::Pointer {
                    target: Box::new(out),
                    size: self.cx.pointer_size,
                };
            }
            return Ok((out, name));
        }
        let name = match self.peek_ident() {
            Some(_) => Some(self.ident("a name")?),
            None => None,
        };
        let mut dims = Vec::new();
        while self.eat('[') {
            let n = self.int_value()?;
            if n < 0 {
                return self.fail("an array cannot have a negative size");
            }
            self.expect(']')?;
            if dims.len() as u32 >= MAX_TYPE_NESTING {
                return self.fail("too many array dimensions");
            }
            dims.push(n as u64);
        }
        for n in dims.into_iter().rev() {
            ty = TypeRef::Array {
                element: Box::new(ty),
                count: n,
            };
        }
        Ok((ty, name))
    }

    /// Parameters after `(`, through the closing `)`.
    fn params(&mut self) -> PResult<(Vec<Param>, bool)> {
        let mut out = Vec::new();
        let mut varargs = false;
        if self.eat(')') {
            return Ok((out, false));
        }
        loop {
            if self.peek() == Some(&Tok::Ellipsis) {
                self.at += 1;
                varargs = true;
            } else {
                let base = self.base_type()?;
                let (ty, name) = self.declarator(base)?;
                let void = matches!(&ty, TypeRef::Primitive(p) if p.class == PrimitiveClass::Void);
                if !(void && name.is_none() && out.is_empty()) {
                    out.push(Param {
                        name,
                        ty,
                        storage: None,
                    });
                }
            }
            if self.eat(',') {
                continue;
            }
            self.expect(')')?;
            return Ok((out, varargs));
        }
    }

    fn declaration(&mut self) -> PResult<()> {
        if self.eat(';') {
            return Ok(());
        }
        let typedef = self.peek_ident() == Some("typedef");
        if typedef {
            self.at += 1;
        }
        self.in_typedef = typedef;
        self.typedef_done = false;
        let base = self.base_type()?;
        if self.typedef_done {
            self.in_typedef = false;
            return self.expect(';');
        }
        self.in_typedef = false;
        if self.eat(';') {
            // `struct x { ... };`, `enum e { ... };` or a forward declaration
            return Ok(());
        }
        loop {
            let (ty, name) = self.declarator(base.clone())?;
            let Some(name) = name else {
                return self.fail("expected a name");
            };
            if typedef {
                // `typedef struct node node;` only forward-declares
                let same = matches!(&ty, TypeRef::Named { name: n } if *n == name);
                if !same {
                    self.register(TypeDef::Typedef(TypedefDef { name, target: ty }))?;
                }
            } else if self.peek() == Some(&Tok::Punct('(')) {
                self.at += 1;
                let (params, varargs) = self.params()?;
                self.register(TypeDef::Function(FunctionPrototype {
                    name: Some(name),
                    return_type: Box::new(ty),
                    params,
                    calling_convention: String::new(),
                    varargs,
                    noreturn: false,
                }))?;
            } else {
                return self.fail("only type declarations are supported: struct, union, enum, typedef or a function prototype");
            }
            if !self.eat(',') {
                break;
            }
        }
        self.expect(';')
    }
}

/// Parses `text`, returning the definitions it declares in order.
pub fn parse_declarations(text: &str, cx: &CContext<'_>) -> Result<Vec<TypeDef>, CParseError> {
    let toks = lex(text)?;
    let mut p = Parser {
        toks,
        at: 0,
        cx,
        defs: BTreeMap::new(),
        order: Vec::new(),
        in_typedef: false,
        typedef_done: false,
        depth: 0,
        decl_depth: 0,
    };
    while p.at < p.toks.len() {
        p.declaration()?;
    }
    if p.order.is_empty() {
        return p.fail("no declaration found");
    }
    let Parser {
        mut defs, order, ..
    } = p;
    Ok(order.iter().filter_map(|n| defs.remove(n)).collect())
}

fn bare_parser<'a>(cx: &'a CContext<'a>) -> Parser<'a> {
    Parser {
        toks: Vec::new(),
        at: 0,
        cx,
        defs: BTreeMap::new(),
        order: Vec::new(),
        in_typedef: false,
        typedef_done: false,
        depth: 0,
        decl_depth: 0,
    }
}

/// Parses one type such as `unsigned char *` or `struct node *[4]` (no name, no body).
pub fn parse_type(text: &str, cx: &CContext<'_>) -> Result<TypeRef, CParseError> {
    let shifted = |e: CParseError| CParseError {
        column: e.column.saturating_sub("typedef ".len()).max(1),
        ..e
    };
    let mut defs =
        parse_declarations(&format!("typedef {text} kraken_t__;"), cx).map_err(shifted)?;
    match (defs.pop(), defs.is_empty()) {
        (Some(TypeDef::Typedef(t)), true) => Ok(t.target),
        _ => Err(CParseError {
            message: "give just a type, such as `unsigned int *`".into(),
            line: 1,
            column: 1,
        }),
    }
}

/// Lays the fields of `c` out again in order with natural alignment (after a field's type
/// changed).
pub fn relayout(c: &mut Composite, union: bool, cx: &CContext<'_>) -> Result<(), CParseError> {
    let too_large = || CParseError {
        message: format!("the type is larger than {MAX_TYPE_SIZE} bytes"),
        line: 1,
        column: 1,
    };
    let p = bare_parser(cx);
    let (mut size, mut align) = (0u64, 1u32);
    for f in &mut c.fields {
        if f.bitfield.is_some() {
            return Err(CParseError {
                message: "a struct with bitfields cannot be laid out again".into(),
                line: 1,
                column: 1,
            });
        }
        let (s, a) = p.size_align(&f.ty)?;
        align = align.max(a);
        if union {
            f.offset = 0;
            size = size.max(s);
        } else {
            let (o, end) = place(size, s, a).ok_or_else(too_large)?;
            f.offset = o;
            size = end;
        }
    }
    c.align = align;
    c.size = place(size, 0, align).ok_or_else(too_large)?.1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Vec<TypeDef>, CParseError> {
        let none = |_: &str| None;
        parse_declarations(
            text,
            &CContext {
                pointer_size: 8,
                long_size: 8,
                lookup: &none,
            },
        )
    }

    #[test]
    fn struct_layout_and_nesting() {
        let defs = parse(
            "struct node { int id; char tag; struct node *next; unsigned char buf[3]; };\n\
             typedef struct { struct node n; double d; } wrap_t;",
        )
        .unwrap();
        let TypeDef::Struct(n) = &defs[0] else {
            panic!()
        };
        assert_eq!(
            n.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
            [0, 4, 8, 16]
        );
        assert_eq!((n.size, n.align), (24, 8));
        let TypeDef::Struct(w) = &defs[1] else {
            panic!()
        };
        assert_eq!(w.name, "wrap_t");
        assert_eq!(w.fields[1].offset, 24);
        assert_eq!(w.size, 32);
    }

    #[test]
    fn enums_unions_typedefs_prototypes() {
        let defs = parse(
            "enum mode { A, B = 5, C, D = -1 };\n\
             union u { int i; short s[5]; };\n\
             typedef int (*handler_t)(void *ctx, int code, ...);\n\
             typedef unsigned long ulong_t;\n\
             int run(const char *name, handler_t h);",
        )
        .unwrap();
        let TypeDef::Enum(e) = &defs[0] else { panic!() };
        assert_eq!(
            e.variants.iter().map(|v| v.value).collect::<Vec<_>>(),
            [0, 5, 6, -1]
        );
        let TypeDef::Union(u) = &defs[1] else {
            panic!()
        };
        assert_eq!(u.size, 12);
        let TypeDef::Typedef(t) = &defs[2] else {
            panic!()
        };
        assert!(
            matches!(&t.target, TypeRef::Pointer { target, .. } if matches!(**target, TypeRef::Function(_)))
        );
        assert!(matches!(&defs[4], TypeDef::Function(f) if f.params.len() == 2));
    }

    #[test]
    fn errors_say_where() {
        let e = parse("struct a {\n  int x;\n  nosuch y;\n};").unwrap_err();
        assert_eq!(e.line, 3);
        assert!(e.message.contains("nosuch"), "{e}");
        assert!(parse("struct a { int x }").is_err());
        assert!(parse("#include <x.h>").is_err());
        assert!(parse("struct a { int x; }; struct a { int y; };").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn deep_function_pointers_fail_cleanly() {
        // thousands of nested parameter lists used to overflow the stack
        let n = 2500;
        let text = format!(
            "struct t {{ void (*f)({}void{}); }};",
            "void(*)(".repeat(n),
            ")".repeat(n)
        );
        let e = parse(&text).unwrap_err();
        assert!(e.message.contains("nested too deeply"), "{e}");
        // a run on a small stack, as on a worker thread
        let h = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || parse(&text).is_err())
            .unwrap();
        assert!(h.join().unwrap());
        assert!(parse("typedef void (*h)(void (*)(int (*)(char *)));").is_ok());
    }

    #[test]
    fn pointer_nesting_is_capped_and_what_parses_reads_back() {
        let e = parse(&format!("struct s {{ char {}p; }};", "*".repeat(200))).unwrap_err();
        assert!(e.message.contains("pointers"), "{e}");
        let e = parse(&format!("typedef int (*{}f)(void);", "*".repeat(200))).unwrap_err();
        assert!(e.message.contains("pointers"), "{e}");
        let e = parse(&format!("struct s {{ char a{}; }};", "[1]".repeat(200))).unwrap_err();
        assert!(e.message.contains("dimensions"), "{e}");
        // the deepest accepted type survives a JSON round trip
        let ok = parse(&format!("struct s {{ char {}p; }};", "*".repeat(30))).unwrap();
        let json = serde_json::to_string(&ok).unwrap();
        let back: Vec<TypeDef> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ok);
        assert!(check_limits(&ok[0]).is_ok());
        let mut deep = TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size: 1,
            signed: true,
        });
        for _ in 0..40 {
            deep = TypeRef::Pointer {
                target: Box::new(deep),
                size: 8,
            };
        }
        let def = TypeDef::Typedef(TypedefDef {
            name: "d".into(),
            target: deep,
        });
        assert!(check_limits(&def).is_err());
    }

    #[test]
    fn sizes_do_not_overflow() {
        let e = parse("struct u { char a[4611686018427387904][4]; };").unwrap_err();
        assert!(e.message.contains("larger"), "{e}");
        let e = parse("struct u { char a[4294967296]; char b; };").unwrap_err();
        assert!(e.message.contains("larger"), "{e}");
        let e = parse("struct u { char a[9223372036854775807]; long b; };").unwrap_err();
        assert!(e.message.contains("larger"), "{e}");
        assert!(parse("struct u { char a[65536]; };").is_ok());
    }
}
