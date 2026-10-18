//! The neutral type model as C declarations in the decompiler's own type names (`int`, `uint`,
//! `ulong`, `undefined8`, `code`), which its C grammar (`parse_C`, `parse_protopieces`) reads.
//! Also a small parser for the prototype table in [`crate::libc`].

use kraken_proto::{
    Composite, EnumDef, Field, FunctionPrototype, Param, Primitive, PrimitiveClass, TypeDef,
    TypeRef, TypedefDef,
};

/// The decompiler's name for a primitive, or `None` when it has no single core type (odd sizes).
pub fn primitive_name(p: &Primitive) -> Option<&'static str> {
    Some(match (p.class, p.size, p.signed) {
        (PrimitiveClass::Void, _, _) => "void",
        (PrimitiveClass::Bool, _, _) => "bool",
        (PrimitiveClass::Char, 1, true) => "char",
        (PrimitiveClass::Char, 1, false) => "byte",
        (PrimitiveClass::Char, 2, _) => "wchar16",
        (PrimitiveClass::Char, 4, _) => "wchar32",
        (PrimitiveClass::Int, 1, true) => "sbyte",
        (PrimitiveClass::Int, 1, false) => "byte",
        (PrimitiveClass::Int, 2, true) => "short",
        (PrimitiveClass::Int, 2, false) => "ushort",
        (PrimitiveClass::Int, 4, true) => "int",
        (PrimitiveClass::Int, 4, false) => "uint",
        (PrimitiveClass::Int, 8, true) => "long",
        (PrimitiveClass::Int, 8, false) => "ulong",
        (PrimitiveClass::Float, 4, _) => "float",
        (PrimitiveClass::Float, 8, _) => "double",
        (PrimitiveClass::Float, 10, _) => "float10",
        (PrimitiveClass::Float, 16, _) => "float16",
        (PrimitiveClass::Undefined, 1, _) => "undefined",
        (PrimitiveClass::Undefined, 2, _) => "undefined2",
        (PrimitiveClass::Undefined, 4, _) => "undefined4",
        (PrimitiveClass::Undefined, 8, _) => "undefined8",
        _ => return None,
    })
}

/// Which named types the decompiler already knows.
pub type Known<'a> = &'a dyn Fn(&str) -> bool;

/// A declaration of `name` (possibly empty) with type `ty`, such as `char *name` or
/// `int name[4]`. Function pointers become `code *` (the decompiler's opaque code type), and a
/// pointer to a named type the decompiler does not know yet becomes `void *`, so recursive and
/// forward references still parse.
pub fn declarator(ty: &TypeRef, name: &str, known: Known<'_>) -> String {
    let sep = |base: &str| {
        if name.is_empty() {
            base.to_string()
        } else if base.ends_with('*') {
            format!("{base}{name}")
        } else {
            format!("{base} {name}")
        }
    };
    match ty {
        TypeRef::Named { name: n } => sep(n),
        TypeRef::Primitive(p) => match primitive_name(p) {
            Some(n) => sep(n),
            // odd sizes become byte arrays
            None => format!("undefined {name}[{}]", p.size.max(1)),
        },
        TypeRef::Pointer { target, .. } => sep(&star(base_of(target, known))),
        TypeRef::Array { element, count } => {
            format!("{}[{}]", declarator(element, name, known), (*count).max(1))
        }
        TypeRef::Function(_) => sep("code *"),
    }
}

/// `base` followed by one more star: `char *` for `char`, `char **` for `char *`.
fn star(base: String) -> String {
    if base.ends_with('*') {
        base + "*"
    } else {
        base + " *"
    }
}

/// The type of a pointer target as a type name followed by its own stars.
fn base_of(ty: &TypeRef, known: Known<'_>) -> String {
    match ty {
        TypeRef::Pointer { target, .. } => star(base_of(target, known)),
        // pointers to arrays and functions decay to pointers to their element / code
        TypeRef::Array { element, .. } => base_of(element, known),
        TypeRef::Function(_) => "code".into(),
        TypeRef::Named { name } if !known(name) => "void".into(),
        other => declarator(other, "", known),
    }
}

/// A C prototype `ret name(T a,U b,...)` for `parse_protopieces`.
pub fn prototype(p: &FunctionPrototype, name: &str, known: Known<'_>) -> String {
    prototype_with(p, name, known, ",")
}

/// A prototype as a listed signature, in the decompiler's spelling:
/// `int cmp_id(record *a, record *b)`.
pub fn signature(p: &FunctionPrototype, name: &str, known: Known<'_>) -> String {
    prototype_with(p, name, known, ", ")
}

fn prototype_with(p: &FunctionPrototype, name: &str, known: Known<'_>, sep: &str) -> String {
    let mut params: Vec<String> = p
        .params
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let n = a
                .name
                .clone()
                .filter(|n| is_ident(n))
                .unwrap_or_else(|| format!("param_{}", i + 1));
            declarator(&a.ty, &n, known)
        })
        .collect();
    if p.varargs {
        params.push("...".into());
    }
    let args = if params.is_empty() {
        "void".to_string()
    } else {
        params.join(sep)
    };
    format!("{}({args})", declarator(&p.return_type, name, known))
}

/// A declaration for `parse_C`, or `None` for prototypes (applied to functions instead).
pub fn declaration(def: &TypeDef, known: Known<'_>) -> Option<String> {
    match def {
        TypeDef::Struct(c) => Some(composite("struct", c, known)),
        TypeDef::Union(c) => Some(composite("union", c, known)),
        TypeDef::Enum(e) => Some(enumeration(e)),
        TypeDef::Typedef(t) => Some(format!(
            "typedef {};",
            declarator(&t.target, &t.name, known)
        )),
        TypeDef::Function(_) => None,
    }
}

fn composite(keyword: &str, c: &Composite, known: Known<'_>) -> String {
    let mut body = String::new();
    let mut at = 0u64;
    let mut pad = 0;
    let mut fields: Vec<&Field> = c.fields.iter().collect();
    if keyword == "struct" {
        fields.sort_by_key(|f| f.offset);
    }
    for f in fields {
        if keyword == "struct" && f.offset > at {
            body.push_str(&format!("undefined _pad{pad}[{}];", f.offset - at));
            pad += 1;
        }
        body.push_str(&declarator(&f.ty, &f.name, known));
        body.push(';');
        at = at.max(f.offset + size_hint(&f.ty));
    }
    if keyword == "struct" && c.size > at {
        body.push_str(&format!("undefined _pad{pad}[{}];", c.size - at));
    }
    if body.is_empty() {
        body.push_str("undefined _opaque;");
    }
    format!("{keyword} {} {{{body}}};", c.name)
}

/// Size in bytes as far as it can be known without the store (named types count as 0 so the
/// next field's offset decides the padding).
fn size_hint(ty: &TypeRef) -> u64 {
    match ty {
        TypeRef::Primitive(p) => u64::from(p.size),
        TypeRef::Pointer { size, .. } => u64::from(*size),
        TypeRef::Array { element, count } => size_hint(element) * count,
        TypeRef::Function(_) | TypeRef::Named { .. } => 0,
    }
}

fn enumeration(e: &EnumDef) -> String {
    if e.variants.is_empty() {
        // the grammar wants at least one enumerator; an integer of the size stands in
        let int = match e.size {
            1 => "byte",
            2 => "ushort",
            8 => "ulong",
            _ => "uint",
        };
        return format!("typedef {int} {};", e.name);
    }
    let body: Vec<String> = e
        .variants
        .iter()
        .map(|v| format!("{}={}", v.name, v.value))
        .collect();
    format!("enum {} {{{}}};", e.name, body.join(","))
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// Whether `s` is a valid C identifier (type and function names the grammar accepts).
pub fn valid_name(s: &str) -> bool {
    is_ident(s)
}

// ---- the prototype table syntax -------------------------------------------------------------

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

/// A type name of the table syntax: C spellings, the decompiler's names, or a named typedef.
fn base_type(word: &str) -> TypeRef {
    use PrimitiveClass::*;
    match word {
        "void" => prim(Void, 0, false),
        "bool" | "_Bool" => prim(Bool, 1, false),
        "char" => prim(Char, 1, true),
        "uchar" | "byte" => prim(Int, 1, false),
        "short" => prim(Int, 2, true),
        "ushort" => prim(Int, 2, false),
        "int" => prim(Int, 4, true),
        "uint" => prim(Int, 4, false),
        "long" => prim(Int, 8, true),
        "ulong" => prim(Int, 8, false),
        "float" => prim(Float, 4, true),
        "double" => prim(Float, 8, true),
        other => TypeRef::Named {
            name: other.to_string(),
        },
    }
}

/// Parses `[noreturn] T name(T a, U *b, ...)` (one level of syntax: base type, `const` ignored,
/// stars, optional parameter names, `...`). Errors name the offending text.
pub fn parse_prototype(src: &str) -> Result<(String, FunctionPrototype), String> {
    let mut s = src.trim();
    let noreturn = match s.strip_prefix("noreturn ") {
        Some(rest) => {
            s = rest.trim_start();
            true
        }
        None => false,
    };
    let open = s.find('(').ok_or_else(|| format!("no `(` in {src:?}"))?;
    let close = s.rfind(')').ok_or_else(|| format!("no `)` in {src:?}"))?;
    let (ret, name) = split_decl(&s[..open]).ok_or_else(|| format!("bad head in {src:?}"))?;
    let name = name.ok_or_else(|| format!("no function name in {src:?}"))?;
    let mut params = Vec::new();
    let mut varargs = false;
    let inner = s[open + 1..close].trim();
    if !inner.is_empty() && inner != "void" {
        for p in inner.split(',') {
            let p = p.trim();
            if p == "..." {
                varargs = true;
                continue;
            }
            let (ty, pname) = split_decl(p).ok_or_else(|| format!("bad parameter {p:?}"))?;
            params.push(Param {
                name: pname,
                ty,
                storage: None,
            });
        }
    }
    Ok((
        name.clone(),
        FunctionPrototype {
            name: Some(name),
            return_type: Box::new(ret),
            params,
            calling_convention: String::new(),
            varargs,
            noreturn,
        },
    ))
}

/// Splits `const char *name` into its type and optional name.
fn split_decl(s: &str) -> Option<(TypeRef, Option<String>)> {
    let spaced = s.replace('*', " * ");
    let words: Vec<&str> = spaced
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "restrict" | "volatile" | "struct"))
        .collect();
    let mut words = words.as_slice();
    let mut base: Vec<&str> = Vec::new();
    // `unsigned` / `signed` / `long long` spellings
    while let Some((w, rest)) = words.split_first() {
        if matches!(*w, "unsigned" | "signed" | "long" | "short") {
            base.push(w);
            words = rest;
        } else {
            break;
        }
    }
    if let Some((w, rest)) = words.split_first()
        && (base.is_empty() || matches!(*w, "int" | "char" | "double"))
    {
        base.push(w);
        words = rest;
    }
    if base.is_empty() {
        return None;
    }
    let rest = words;
    let ty = match base.join(" ").as_str() {
        "unsigned" | "unsigned int" => base_type("uint"),
        "signed" | "signed int" => base_type("int"),
        "unsigned char" => base_type("uchar"),
        "signed char" => prim(PrimitiveClass::Int, 1, true),
        "unsigned short" | "unsigned short int" => base_type("ushort"),
        "short int" => base_type("short"),
        "long int" | "long long" | "long long int" => base_type("long"),
        "unsigned long" | "unsigned long int" | "unsigned long long" => base_type("ulong"),
        other => base_type(other),
    };
    let mut ty = ty;
    let mut name = None;
    for w in rest {
        match *w {
            "*" => {
                ty = TypeRef::Pointer {
                    target: Box::new(ty),
                    size: 8,
                }
            }
            n if is_ident(n) && name.is_none() => name = Some(n.to_string()),
            _ => return None,
        }
    }
    Some((ty, name))
}

/// Typedefs and opaque structs the prototype table refers to (LP64 Linux).
pub fn base_definitions() -> Vec<TypeDef> {
    let td = |name: &str, target: TypeRef| {
        TypeDef::Typedef(TypedefDef {
            name: name.into(),
            target,
        })
    };
    let opaque = |name: &str, size: u64| {
        TypeDef::Struct(Composite {
            name: name.into(),
            size,
            align: 8,
            fields: Vec::new(),
        })
    };
    use PrimitiveClass::*;
    vec![
        td("size_t", prim(Int, 8, false)),
        td("ssize_t", prim(Int, 8, true)),
        td("off_t", prim(Int, 8, true)),
        td("time_t", prim(Int, 8, true)),
        td("pid_t", prim(Int, 4, true)),
        td("uid_t", prim(Int, 4, false)),
        td("gid_t", prim(Int, 4, false)),
        td("mode_t", prim(Int, 4, false)),
        td("socklen_t", prim(Int, 4, false)),
        td("wchar_t", prim(Int, 4, true)),
        td("intptr_t", prim(Int, 8, true)),
        td("uintptr_t", prim(Int, 8, false)),
        td(
            "va_list",
            TypeRef::Pointer {
                target: Box::new(prim(Void, 0, false)),
                size: 8,
            },
        ),
        opaque("FILE", 216),
        opaque("DIR", 8),
        opaque("pthread_mutex_t", 40),
        opaque("jmp_buf", 200),
        opaque("tm", 56),
        opaque("stat", 144),
        opaque("sockaddr", 16),
        opaque("timespec", 16),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(_: &str) -> bool {
        true
    }

    #[test]
    fn table_syntax_parses() {
        let (n, p) = parse_prototype("int printf(const char *format, ...)").expect("printf");
        assert_eq!(n, "printf");
        assert!(p.varargs && !p.noreturn);
        assert_eq!(
            prototype(&p, "printf", &all),
            "int printf(char *format,...)"
        );
        let (_, p) = parse_prototype("noreturn void exit(int status)").expect("exit");
        assert!(p.noreturn);
        assert_eq!(prototype(&p, "exit", &all), "void exit(int status)");
        let (_, p) = parse_prototype("size_t strlen(const char *s)").expect("strlen");
        assert_eq!(prototype(&p, "strlen", &all), "size_t strlen(char *s)");
        let (_, p) = parse_prototype("unsigned long strtoul(const char *s, char **end, int base)")
            .expect("strtoul");
        assert_eq!(
            prototype(&p, "strtoul", &all),
            "ulong strtoul(char *s,char **end,int base)"
        );
        let (_, p) = parse_prototype("int rand(void)").expect("rand");
        assert_eq!(prototype(&p, "rand", &all), "int rand(void)");
        assert!(parse_prototype("int (").is_err());
    }

    #[test]
    fn declarations_use_core_names() {
        let def = TypeDef::Struct(Composite {
            name: "rec".into(),
            size: 16,
            align: 8,
            fields: vec![
                Field {
                    name: "id".into(),
                    offset: 0,
                    ty: prim(PrimitiveClass::Int, 4, true),
                    bitfield: None,
                },
                Field {
                    name: "next".into(),
                    offset: 8,
                    ty: TypeRef::Pointer {
                        target: Box::new(TypeRef::Named { name: "rec".into() }),
                        size: 8,
                    },
                    bitfield: None,
                },
            ],
        });
        assert_eq!(
            declaration(&def, &all).as_deref(),
            Some("struct rec {int id;undefined _pad0[4];rec *next;};")
        );
        // the struct is not known while it is being declared
        let known = |n: &str| n != "rec";
        assert_eq!(
            declaration(&def, &known).as_deref(),
            Some("struct rec {int id;undefined _pad0[4];void *next;};")
        );
        let arr = TypeRef::Array {
            element: Box::new(prim(PrimitiveClass::Char, 1, true)),
            count: 8,
        };
        assert_eq!(declarator(&arr, "buf", &all), "char buf[8]");
        let fp = TypeRef::Function(Box::new(parse_prototype("int f(int)").expect("f").1));
        assert_eq!(declarator(&fp, "cb", &all), "code *cb");
    }
}
