//! The layouts of the structs a function uses, from the engine's type information, for the
//! translation prompt: field offsets the decompile only implies, stated outright.
//!
//! A model that guesses a layout from the decompile gets it wrong often enough (invented padding,
//! fields out of order) to fail a whole program. The engine knows the layouts from the debug
//! information or from the person's own types, so they are given as offset tables. Type and field
//! names come from the program: only plain identifiers are used, so nothing in them can read as
//! an instruction.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use kraken_engine::{CancellationToken, SharedEngine};
use kraken_proto::{Composite, Primitive, PrimitiveClass, TypeDef, TypeRef};

/// Most types described for one function.
pub const MAX_TYPES: usize = 8;
/// Most fields listed per type.
pub const MAX_FIELDS: usize = 40;
/// Longest name kept.
const MAX_NAME: usize = 64;

/// C words that are never the name of a struct.
const NOT_TYPES: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "const",
    "volatile",
    "struct",
    "union",
    "enum",
    "return",
    "sizeof",
    "bool",
    "byte",
    "uint",
    "ulong",
    "ushort",
    "uchar",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "size_t",
    "ssize_t",
    "longlong",
    "ulonglong",
    "code",
    "string",
    "wchar_t",
];

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// Names written in a type position in `text`: before a `*`, after `struct`/`union`, and as the
/// type of a declaration in a parameter list or a local.
pub fn type_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |w: &str| {
        if identifier(w) && !NOT_TYPES.contains(&w) && !out.iter().any(|o| o == w) {
            out.push(w.to_string());
        }
    };
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '*'))
        .filter(|w| !w.is_empty())
        .collect();
    for (i, w) in words.iter().enumerate() {
        let bare = w.trim_end_matches('*');
        if *w == "struct" || *w == "union" {
            if let Some(n) = words.get(i + 1) {
                push(n.trim_end_matches('*'));
            }
        } else if (w.ends_with('*') && !bare.is_empty())
            || words.get(i + 1).is_some_and(|n| n.starts_with('*'))
        {
            push(bare);
        }
    }
    out
}

fn prim(p: &Primitive) -> String {
    match p.class {
        PrimitiveClass::Void => "void".into(),
        PrimitiveClass::Bool => "bool".into(),
        PrimitiveClass::Float => match p.size {
            4 => "float".into(),
            8 => "double".into(),
            n => format!("float{}", n * 8),
        },
        PrimitiveClass::Char => if p.signed { "char" } else { "unsigned char" }.into(),
        PrimitiveClass::Int => format!("{}int{}", if p.signed { "" } else { "u" }, p.size * 8),
        PrimitiveClass::Undefined => format!("{} unknown bytes", p.size),
    }
}

/// `t` as C, with the struct names it mentions added to `named`.
fn type_text(t: &TypeRef, named: &mut Vec<String>) -> String {
    match t {
        TypeRef::Named { name } => {
            if identifier(name) {
                if !named.contains(name) {
                    named.push(name.clone());
                }
                name.clone()
            } else {
                "a type".into()
            }
        }
        TypeRef::Primitive(p) => prim(p),
        TypeRef::Pointer { target, size } => {
            format!("{} * ({size}-byte pointer)", type_text(target, named))
        }
        TypeRef::Array { element, count } => format!("{}[{count}]", type_text(element, named)),
        TypeRef::Function(_) => "function pointer".into(),
    }
}

fn composite(kind: &str, c: &Composite, named: &mut Vec<String>) -> String {
    let mut s = format!(
        "{kind} {} ({:#x} bytes, aligned to {}):\n",
        c.name, c.size, c.align
    );
    for f in c.fields.iter().take(MAX_FIELDS) {
        let name = if identifier(&f.name) {
            f.name.as_str()
        } else {
            "field"
        };
        let _ = writeln!(s, "  +{:#06x} {} {name}", f.offset, type_text(&f.ty, named));
    }
    if c.fields.len() > MAX_FIELDS {
        let _ = writeln!(s, "  ... {} more fields", c.fields.len() - MAX_FIELDS);
    }
    s
}

/// The layouts of the structs and unions `texts` (the signature, the decompile) name, and of
/// those their fields name, as the engine knows them. Empty when it knows none.
pub async fn describe(engine: &SharedEngine, texts: &[&str], cancel: &CancellationToken) -> String {
    let Some(store) = engine.type_store() else {
        return String::new();
    };
    let mut queue: Vec<String> = texts.iter().flat_map(|t| type_names(t)).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = String::new();
    let mut described = 0;
    while let Some(name) = (!queue.is_empty()).then(|| queue.remove(0)) {
        if described >= MAX_TYPES || !seen.insert(name.clone()) {
            continue;
        }
        let mut named = Vec::new();
        let text = match store.get_type(&name, cancel).await {
            Ok(TypeDef::Struct(c)) => composite("struct", &c, &mut named),
            Ok(TypeDef::Union(c)) => composite("union", &c, &mut named),
            Ok(TypeDef::Typedef(t)) => {
                let target = type_text(&t.target, &mut named);
                format!("typedef {} = {target}\n", name)
            }
            _ => continue,
        };
        described += 1;
        out.push_str(&text);
        queue.extend(named);
    }
    if out.is_empty() {
        return out;
    }
    format!(
        "Layouts from the program's type information (exact offsets; give a #[repr(C)] struct \
         exactly these fields at these offsets, with explicit padding where there are gaps):\n{out}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_are_found_in_type_positions() {
        let sig = "void print_rec(record * r, void * ctx)";
        let body =
            "node *n;\n  struct list l;\n  n = (node *)calloc(1,0x30);\n  int x = cfg.length;";
        assert_eq!(type_names(sig), vec!["record".to_string()]);
        assert_eq!(
            type_names(body),
            vec!["node".to_string(), "list".to_string()]
        );
        // C keywords and Ghidra's undefinedN never count.
        assert!(type_names("undefined8 * p; char *s; void *q").is_empty());
    }
}
