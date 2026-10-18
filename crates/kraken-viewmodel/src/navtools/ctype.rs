//! A small C declaration reader for the Retype and Edit signature dialogs: it turns text such as
//! `int parse(char *buf, size_t len)` or `uint8_t[16]` into the neutral type model `set_type`
//! takes. It knows the C basic types, fixed-width integers and the names Ghidra prints
//! (`undefined8`, `uint`, `qword`, ...); any other name is a reference to a named type.

use kraken_proto::{FunctionPrototype, Param, Primitive, PrimitiveClass, TypeRef};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Star,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Ellipsis,
    Number(u64),
}

fn tokenize(text: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '*' => {
                out.push(Tok::Star);
                i += 1;
            }
            '&' => return Err("References (&) are not C; use a pointer (*) instead.".into()),
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            ';' => i += 1,
            '.' => {
                if chars.get(i..i + 3) == Some(&['.', '.', '.']) {
                    out.push(Tok::Ellipsis);
                    i += 3;
                } else {
                    return Err(
                        "A lone dot is not valid here; write ... for variable arguments.".into(),
                    );
                }
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                    i += 1;
                }
                let s: String = chars[start..i].iter().collect();
                let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16),
                    None => s.parse(),
                }
                .map_err(|_| format!("`{s}` is not a number."))?;
                out.push(Tok::Number(n));
            }
            c if c.is_alphabetic() || c == '_' || c == '$' => {
                let start = i;
                while i < chars.len() {
                    let ch = chars[i];
                    if ch.is_alphanumeric() || ch == '_' || ch == '$' {
                        i += 1;
                    } else if ch == ':' && chars.get(i + 1) == Some(&':') {
                        i += 2;
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            other => return Err(format!("`{other}` is not allowed in a type.")),
        }
    }
    Ok(out)
}

const QUALIFIERS: &[&str] = &["const", "volatile", "restrict", "__restrict", "register"];
const CONVENTIONS: &[&str] = &[
    "__cdecl",
    "__stdcall",
    "__fastcall",
    "__thiscall",
    "__vectorcall",
    "__pascal",
];
const NORETURN: &[&str] = &["noreturn", "_Noreturn", "__noreturn"];
const MODIFIERS: &[&str] = &["signed", "unsigned", "short", "long"];
const BASES: &[&str] = &["void", "char", "int", "float", "double", "bool", "_Bool"];

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

/// The primitive a single name stands for, given the pointer size.
fn named_primitive(name: &str, ptr: u32) -> Option<TypeRef> {
    use PrimitiveClass::*;
    Some(match name {
        "void" => prim(Void, 0, false),
        "bool" | "_Bool" => prim(Bool, 1, false),
        "char" => prim(Char, 1, true),
        "uchar" => prim(Char, 1, false),
        "wchar_t" | "wchar32" => prim(Char, 4, false),
        "wchar16" | "char16_t" => prim(Char, 2, false),
        "byte" => prim(Int, 1, false),
        "short" => prim(Int, 2, true),
        "ushort" | "word" => prim(Int, 2, false),
        "int" => prim(Int, 4, true),
        "uint" | "dword" => prim(Int, 4, false),
        "long" => prim(Int, ptr, true),
        "ulong" => prim(Int, ptr, false),
        "longlong" => prim(Int, 8, true),
        "ulonglong" | "qword" => prim(Int, 8, false),
        "float" => prim(Float, 4, true),
        "double" => prim(Float, 8, true),
        "int8_t" => prim(Int, 1, true),
        "uint8_t" => prim(Int, 1, false),
        "int16_t" => prim(Int, 2, true),
        "uint16_t" => prim(Int, 2, false),
        "int32_t" => prim(Int, 4, true),
        "uint32_t" => prim(Int, 4, false),
        "int64_t" => prim(Int, 8, true),
        "uint64_t" => prim(Int, 8, false),
        "size_t" | "uintptr_t" => prim(Int, ptr, false),
        "ssize_t" | "intptr_t" | "ptrdiff_t" => prim(Int, ptr, true),
        "undefined" => prim(Undefined, 1, false),
        n if n.starts_with("undefined") => {
            let size: u32 = n["undefined".len()..].parse().ok()?;
            prim(Undefined, size, false)
        }
        _ => return None,
    })
}

/// A base type written as words, such as `unsigned long long` or `struct node`.
fn base_type(words: &[String], ptr: u32) -> Result<TypeRef, String> {
    use PrimitiveClass::*;
    if let [tag, name] = words
        && matches!(tag.as_str(), "struct" | "union" | "enum" | "class")
    {
        return Ok(TypeRef::Named { name: name.clone() });
    }
    if let [w] = words {
        if let Some(p) = named_primitive(w, ptr) {
            return Ok(p);
        }
        if !MODIFIERS.contains(&w.as_str()) {
            return Ok(TypeRef::Named { name: w.clone() });
        }
    }
    let all_c = words
        .iter()
        .all(|w| MODIFIERS.contains(&w.as_str()) || BASES.contains(&w.as_str()));
    if !all_c {
        return Err(format!(
            "`{}` is not a type KRAKEN understands.",
            words.join(" ")
        ));
    }
    let count = |w: &str| words.iter().filter(|x| x.as_str() == w).count();
    let unsigned = count("unsigned") > 0;
    if unsigned && count("signed") > 0 {
        return Err("A type cannot be both signed and unsigned.".into());
    }
    let base: Vec<&str> = words
        .iter()
        .map(String::as_str)
        .filter(|w| BASES.contains(w))
        .collect();
    if base.len() > 1 {
        return Err(format!("`{}` names two types at once.", words.join(" ")));
    }
    let longs = count("long");
    let shorts = count("short");
    Ok(match (base.first().copied(), shorts, longs) {
        (Some("void"), 0, 0) if !unsigned => prim(Void, 0, false),
        (Some("bool" | "_Bool"), 0, 0) => prim(Bool, 1, false),
        (Some("char"), 0, 0) => prim(Char, 1, !unsigned),
        (Some("float"), 0, 0) => prim(Float, 4, true),
        (Some("double"), 0, 0) => prim(Float, 8, true),
        (Some("double"), 0, 1) => prim(Float, 10, true),
        (None | Some("int"), 1, 0) => prim(Int, 2, !unsigned),
        (None | Some("int"), 0, 0) => prim(Int, 4, !unsigned),
        (None | Some("int"), 0, 1) => prim(Int, ptr, !unsigned),
        (None | Some("int"), 0, 2) => prim(Int, 8, !unsigned),
        _ => {
            return Err(format!("`{}` is not a valid C type.", words.join(" ")));
        }
    })
}

/// A declaration split into its parts: base words, stars, array sizes and an optional name.
struct Decl {
    ty: TypeRef,
    name: Option<String>,
}

/// Reads `type-words [*...] [name] [[N]...]` from `toks`.
fn declaration(toks: &[Tok], ptr: u32, want_name: bool) -> Result<Decl, String> {
    let mut words: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(Tok::Ident(w)) = toks.get(i) {
        if !QUALIFIERS.contains(&w.as_str()) {
            words.push(w.clone());
        }
        i += 1;
    }
    let mut stars = 0;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Star => stars += 1,
            Tok::Ident(w) if QUALIFIERS.contains(&w.as_str()) => {}
            _ => break,
        }
        i += 1;
    }
    let mut name = None;
    if let Some(Tok::Ident(w)) = toks.get(i) {
        name = Some(w.clone());
        i += 1;
    } else if want_name && stars == 0 && words.len() >= 2 {
        // `config_t cfg`, but not `unsigned int` or `struct node`.
        let last = words.last().map(String::as_str).unwrap_or("");
        let tagged =
            words.len() == 2 && matches!(words[0].as_str(), "struct" | "union" | "enum" | "class");
        let keyword = MODIFIERS.contains(&last) || BASES.contains(&last);
        if !tagged && !keyword {
            name = words.pop();
        }
    }
    let mut dims = Vec::new();
    while let Some(Tok::LBracket) = toks.get(i) {
        match (toks.get(i + 1), toks.get(i + 2)) {
            (Some(Tok::Number(n)), Some(Tok::RBracket)) if *n > 0 => {
                dims.push(*n);
                i += 3;
            }
            // `char *argv[]`: a parameter, where the outer array is a pointer anyway.
            (Some(Tok::RBracket), _) if want_name && dims.is_empty() => {
                dims.push(1);
                i += 2;
            }
            _ => return Err("An array size must be a positive number, such as [16].".into()),
        }
    }
    if let Some(t) = toks.get(i) {
        return Err(match t {
            Tok::LParen => {
                "Function pointers cannot be typed here yet. Use a typedef name instead.".into()
            }
            _ => "There is something extra at the end of the type.".into(),
        });
    }
    if words.is_empty() {
        return Err("Write a type first, such as int or char *.".into());
    }
    let mut ty = base_type(&words, ptr)?;
    for _ in 0..stars {
        ty = TypeRef::Pointer {
            target: Box::new(ty),
            size: ptr,
        };
    }
    for n in dims.into_iter().rev() {
        ty = TypeRef::Array {
            element: Box::new(ty),
            count: n,
        };
    }
    Ok(Decl { ty, name })
}

/// Parses a data type such as `char *`, `unsigned int[4]` or `config_t`. `ptr` is the pointer
/// size in bytes.
pub fn parse_type(text: &str, ptr: u32) -> Result<TypeRef, String> {
    let toks = tokenize(text)?;
    if toks.is_empty() {
        return Err("Type a type, such as int, char * or a struct name.".into());
    }
    let d = declaration(&toks, ptr, false)?;
    if let Some(n) = d.name {
        return Err(format!(
            "Only the type is needed here; leave out the name `{n}`."
        ));
    }
    Ok(d.ty)
}

/// A parsed prototype and the function name written in it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPrototype {
    /// The prototype, without a name: names change through rename.
    pub prototype: FunctionPrototype,
    /// The name written before the parameter list.
    pub name: Option<String>,
}

/// Parses a C prototype such as `int __stdcall parse(char *buf, size_t len, ...)`.
pub fn parse_prototype(text: &str, ptr: u32) -> Result<ParsedPrototype, String> {
    let mut toks = tokenize(text)?;
    let mut convention = String::new();
    let mut noreturn = false;
    toks.retain(|t| match t {
        Tok::Ident(w) if CONVENTIONS.contains(&w.as_str()) => {
            convention = w.clone();
            false
        }
        Tok::Ident(w) if NORETURN.contains(&w.as_str()) => {
            noreturn = true;
            false
        }
        _ => true,
    });
    let open = toks
        .iter()
        .position(|t| *t == Tok::LParen)
        .ok_or("A signature needs a parameter list in parentheses, such as int f(int x).")?;
    if toks.last() != Some(&Tok::RParen) {
        return Err("The signature must end with the closing parenthesis.".into());
    }
    let head = &toks[..open];
    let body = &toks[open + 1..toks.len() - 1];
    let ret = declaration(head, ptr, true)?;
    let name = ret.name.clone();
    if name.is_none() {
        return Err("Write the function name before the parentheses.".into());
    }
    let mut params = Vec::new();
    let mut varargs = false;
    let parts: Vec<&[Tok]> = if body.is_empty() {
        Vec::new()
    } else {
        body.split(|t| *t == Tok::Comma).collect()
    };
    let n = parts.len();
    for (i, part) in parts.into_iter().enumerate() {
        if part == [Tok::Ellipsis] {
            if i + 1 != n {
                return Err("... must be the last parameter.".into());
            }
            varargs = true;
            continue;
        }
        if part.is_empty() {
            return Err(format!("Parameter {} is empty.", i + 1));
        }
        if n == 1 && part == [Tok::Ident("void".into())] {
            continue;
        }
        if part.contains(&Tok::LParen) || part.contains(&Tok::RParen) {
            return Err(
                "Function pointer parameters cannot be typed here yet. Use a typedef name instead."
                    .into(),
            );
        }
        let d = declaration(part, ptr, true).map_err(|e| format!("Parameter {}: {e}", i + 1))?;
        // An array parameter is a pointer in C.
        let ty = match d.ty {
            TypeRef::Array { element, .. } => TypeRef::Pointer {
                target: element,
                size: ptr,
            },
            t => t,
        };
        if matches!(&ty, TypeRef::Primitive(p) if p.class == PrimitiveClass::Void) {
            return Err(format!("Parameter {} cannot be void.", i + 1));
        }
        params.push(Param {
            name: d.name,
            ty,
            storage: None,
        });
    }
    Ok(ParsedPrototype {
        prototype: FunctionPrototype {
            name: None,
            return_type: Box::new(ret.ty),
            params,
            calling_convention: convention,
            varargs,
            noreturn,
        },
        name,
    })
}

/// Pointer size for an architecture string such as `x86:LE:64:default`.
pub fn pointer_size(arch: &str) -> u32 {
    if arch.split(':').any(|p| p == "32") || arch.contains("i386") || arch.contains("x86_32") {
        4
    } else if arch.split(':').any(|p| p == "16") {
        2
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(size: u32, signed: bool) -> TypeRef {
        prim(PrimitiveClass::Int, size, signed)
    }

    #[test]
    fn data_types() {
        assert_eq!(parse_type("int", 8).unwrap(), int(4, true));
        assert_eq!(parse_type("unsigned long long", 8).unwrap(), int(8, false));
        assert_eq!(parse_type("long", 4).unwrap(), int(4, true));
        assert_eq!(
            parse_type("const char *", 8).unwrap(),
            TypeRef::Pointer {
                target: Box::new(prim(PrimitiveClass::Char, 1, true)),
                size: 8
            }
        );
        assert_eq!(
            parse_type("uint8_t[16]", 8).unwrap(),
            TypeRef::Array {
                element: Box::new(int(1, false)),
                count: 16
            }
        );
        assert_eq!(
            parse_type("struct node *", 4).unwrap(),
            TypeRef::Pointer {
                target: Box::new(TypeRef::Named {
                    name: "node".into()
                }),
                size: 4
            }
        );
        assert_eq!(
            parse_type("undefined8", 8).unwrap(),
            prim(PrimitiveClass::Undefined, 8, false)
        );
        assert_eq!(
            parse_type("config_t", 8).unwrap(),
            TypeRef::Named {
                name: "config_t".into()
            }
        );
        for bad in [
            "",
            "int x",
            "signed unsigned",
            "int (*)(int)",
            "char [0]",
            "int @",
            "short double",
        ] {
            assert!(parse_type(bad, 8).is_err(), "{bad}");
        }
    }

    #[test]
    fn prototypes() {
        let p = parse_prototype("int __stdcall parse(char *buf, size_t len, ...);", 8).unwrap();
        assert_eq!(p.name.as_deref(), Some("parse"));
        let proto = p.prototype;
        assert_eq!(*proto.return_type, int(4, true));
        assert_eq!(proto.calling_convention, "__stdcall");
        assert!(proto.varargs);
        assert_eq!(proto.params.len(), 2);
        assert_eq!(proto.params[0].name.as_deref(), Some("buf"));
        assert_eq!(proto.params[1].name.as_deref(), Some("len"));
        assert_eq!(proto.params[1].ty, int(8, false));

        let p = parse_prototype("void f(void)", 8).unwrap();
        assert!(p.prototype.params.is_empty());
        let p = parse_prototype(
            "undefined8 FUN_00401000(undefined8 param_1, int param_2)",
            8,
        )
        .unwrap();
        assert_eq!(p.prototype.params[0].name.as_deref(), Some("param_1"));
        let p = parse_prototype("void __noreturn die(config_t cfg, unsigned int)", 8).unwrap();
        assert!(p.prototype.noreturn);
        assert_eq!(p.prototype.params[0].name.as_deref(), Some("cfg"));
        assert_eq!(p.prototype.params[1].name, None);
        let p = parse_prototype("int main(int argc, char *argv[])", 8).unwrap();
        assert!(matches!(p.prototype.params[1].ty, TypeRef::Pointer { .. }));

        for bad in [
            "int f",
            "int (int x)",
            "int f(..., int x)",
            "int f(void x)",
            "int f(int (*cb)(int))",
            "int f(int,)",
        ] {
            assert!(parse_prototype(bad, 8).is_err(), "{bad}");
        }
    }

    #[test]
    fn pointer_sizes() {
        assert_eq!(pointer_size("x86:LE:64:default"), 8);
        assert_eq!(pointer_size("x86:LE:32:default"), 4);
        assert_eq!(pointer_size("AARCH64:LE:64:v8A"), 8);
    }
}
