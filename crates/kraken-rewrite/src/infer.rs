//! A guess at a function's System V ABI from the C-like signature KRAKEN shows
//! (`int cmp_id(record * a, record * b)`), and generic test inputs for it.
//!
//! The guess is deliberately narrow: integers up to 64 bits in registers and pointers to
//! caller-owned buffers, at most six parameters, an integer or void result. Anything else
//! (floating point, structs by value, varargs, function pointers, pointer results) is refused with
//! a reason, so a function outside what the oracle can check never gets a verdict that means
//! nothing. Buffer sizes are unknown here, so the generic inputs fill a fixed-size buffer with
//! random bytes; a curated input generator (see `targets`) tests structs far better.

use crate::abi::{Param, Ret, Signature};
use crate::difftest::{Generator, InputSpec, IntGen, ParamGen};

/// Why a signature cannot be checked yet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unsupported(pub String);

fn un(s: impl Into<String>) -> Unsupported {
    Unsupported(s.into())
}

/// Bytes in each generated buffer argument (random content), before zero padding.
pub const BUFFER_BYTES: usize = 64;

/// The Rust identifier used for a function: its name when that is a plain identifier that is not
/// a Rust keyword, else `fn_<address>`.
pub fn rust_name(name: &str, address: u64) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do",
        "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
        "gen", "main",
    ];
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !KEYWORDS.contains(&name);
    if plain {
        name.to_string()
    } else {
        format!("fn_{address:x}")
    }
}

/// `(bits, signed)` for a C integer type spelled `ty`, or `None` for an unknown type.
fn int_type(ty: &str) -> Option<(u8, bool)> {
    let t = ty
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile" | "register" | "struct" | "enum"))
        .collect::<Vec<_>>()
        .join(" ");
    Some(match t.as_str() {
        "char" | "signed char" | "int8_t" | "sbyte" | "schar" => (8, true),
        "uchar" | "unsigned char" | "uint8_t" | "byte" | "undefined1" | "bool" | "_Bool" => {
            (8, false)
        }
        "short" | "int16_t" | "short int" | "signed short" => (16, true),
        "ushort" | "unsigned short" | "uint16_t" | "undefined2" | "word" | "wchar_t" => (16, false),
        "int" | "int32_t" | "signed int" | "signed" => (32, true),
        "uint" | "unsigned int" | "unsigned" | "uint32_t" | "undefined4" | "dword" => (32, false),
        "long" | "longlong" | "long long" | "int64_t" | "ssize_t" | "intptr_t" | "ptrdiff_t"
        | "off_t" | "long int" => (64, true),
        "ulong" | "ulonglong" | "unsigned long" | "unsigned long long" | "uint64_t" | "size_t"
        | "uintptr_t" | "undefined8" | "qword" => (64, false),
        _ => return None,
    })
}

fn split_params(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in list.chars() {
        match c {
            '(' | '[' | '<' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() || !out.is_empty() {
        out.push(cur);
    }
    out.into_iter().map(|s| s.trim().to_string()).collect()
}

/// The type of a parameter declaration (`record * a` gives `record *`): everything but the
/// trailing parameter name.
fn param_type(decl: &str) -> String {
    let d = decl.trim();
    if d.contains('(') {
        return d.to_string(); // function pointer syntax
    }
    let name_start = d
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1);
    let (head, name) = d.split_at(name_start);
    let head = head.trim();
    // A lone word is a type without a name (`int`, `void`).
    if head.is_empty() || name.is_empty() || int_type(d).is_some() {
        d.to_string()
    } else {
        head.to_string()
    }
}

fn is_pointer(ty: &str) -> bool {
    ty.contains('*') || ty.contains('[')
}

fn classify_param(decl: &str) -> Result<Param, Unsupported> {
    let ty = param_type(decl);
    if ty.contains('(') {
        return Err(un(format!("function-pointer parameter `{decl}`")));
    }
    if is_pointer(&ty) {
        return Ok(Param::Buf);
    }
    if ty.contains("float") || ty.contains("double") {
        return Err(un(format!("floating-point parameter `{decl}`")));
    }
    match int_type(&ty) {
        Some((bits, signed)) => Ok(Param::Int { bits, signed }),
        None => Err(un(format!(
            "parameter `{decl}` has a type that is not a plain integer or pointer \
             (structure by value, function-pointer typedef, ...)"
        ))),
    }
}

fn classify_ret(ty: &str) -> Result<Ret, Unsupported> {
    let ty = ty.trim();
    if ty == "void" {
        return Ok(Ret::Void);
    }
    if is_pointer(ty) {
        return Err(un(
            "pointer result (addresses are not comparable between the original and the Rust build)",
        ));
    }
    if ty.contains("float") || ty.contains("double") {
        return Err(un("floating-point result"));
    }
    match int_type(ty) {
        Some((bits, signed)) => Ok(Ret::Int { bits, signed }),
        None => Err(un(format!("result type `{ty}` is not a plain integer"))),
    }
}

/// Reads `signature` (as `list_functions` renders it) into a [`Signature`] named `name`.
pub fn infer_signature(signature: &str, name: &str) -> Result<Signature, Unsupported> {
    let sig = signature.trim();
    let open = sig
        .find('(')
        .ok_or_else(|| un("the signature has no parameter list"))?;
    let close = sig
        .rfind(')')
        .filter(|c| *c > open)
        .ok_or_else(|| un("the signature has no closing parenthesis"))?;
    let head = sig[..open].trim_end();
    let ret_ty = head
        .strip_suffix(|c: char| c.is_ascii_alphanumeric() || c == '_')
        .map(|_| {
            let start = head
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            head[..start].trim()
        })
        .unwrap_or("");
    if ret_ty.is_empty() {
        return Err(un("the signature has no result type"));
    }
    let ret = classify_ret(ret_ty)?;
    let inner = sig[open + 1..close].trim();
    let decls = if inner.is_empty() || inner == "void" {
        Vec::new()
    } else {
        split_params(inner)
    };
    if decls.iter().any(|d| d.contains("...")) {
        return Err(un("variadic function"));
    }
    if decls.len() > 6 {
        return Err(un(
            "more than six parameters (stack arguments are not modelled)",
        ));
    }
    let params = decls
        .iter()
        .map(|d| classify_param(d))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Signature {
        name: name.to_string(),
        params,
        ret,
    })
}

/// Generic inputs for `sig`: edge and random values for integers, random bytes (with zero padding
/// after them) for buffers.
pub fn generic_inputs(sig: &Signature) -> InputSpec {
    let gens = sig
        .params
        .iter()
        .map(|p| match p {
            Param::Int { bits, signed } => ParamGen::Int(IntGen::full(*bits, *signed)),
            Param::Buf => ParamGen::Bytes {
                min_len: 8,
                max_len: BUFFER_BYTES,
                alphabet: None,
                terminator: false,
                pad: BUFFER_BYTES,
            },
        })
        .collect();
    InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(gens),
    }
}

/// Layout notes for the prompt that follow from the inference (trusted operator text).
pub fn generic_notes(sig: &Signature) -> String {
    if sig.params.iter().any(|p| matches!(p, Param::Buf)) {
        format!(
            "Pointer parameters are caller-owned buffers whose layout is not known; the checks \
             pass buffers of {BUFFER_BYTES} bytes of arbitrary content followed by zero bytes. \
             Read and write only what the decompile reads and writes."
        )
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(s: &str) -> Result<Signature, Unsupported> {
        infer_signature(s, "f")
    }

    #[test]
    fn integers_and_pointers_map_to_registers_and_buffers() {
        let s = sig("int cmp_id(record * a, record * b)").expect("sig");
        assert_eq!(s.params, vec![Param::Buf, Param::Buf]);
        assert_eq!(
            s.ret,
            Ret::Int {
                bits: 32,
                signed: true
            }
        );
        let s = sig("void vm_fail(char * msg, uint pc)").expect("sig");
        assert_eq!(
            s.params,
            vec![
                Param::Buf,
                Param::Int {
                    bits: 32,
                    signed: false
                }
            ]
        );
        assert_eq!(s.ret, Ret::Void);
        let s = sig("int vm_run(vm * vm, uint8_t * code, uint len)").expect("sig");
        assert_eq!(s.params.len(), 3);
        let s = sig("int main(void)").expect("sig");
        assert!(s.params.is_empty());
        let s = sig("long f(size_t n, short s, uchar c)").expect("sig");
        assert_eq!(
            s.params,
            vec![
                Param::Int {
                    bits: 64,
                    signed: false
                },
                Param::Int {
                    bits: 16,
                    signed: true
                },
                Param::Int {
                    bits: 8,
                    signed: false
                }
            ]
        );
    }

    #[test]
    fn what_the_oracle_cannot_check_is_refused_with_a_reason() {
        for (text, needle) in [
            (
                "node * node_new(int id, char * name, int x, int y, double w)",
                "pointer result",
            ),
            ("int f(double w)", "floating-point"),
            ("void list_sort(list * l, cmp_fn cmp)", "cmp_fn"),
            ("int printf(char * __format, ...)", "variadic"),
            (
                "int f(int a, int b, int c, int d, int e, int g, int h)",
                "six",
            ),
            ("undefined FUN_00101020()", "result type"),
            ("int f(vec3 v)", "vec3"),
        ] {
            let e = sig(text).expect_err(text);
            assert!(e.0.contains(needle), "{text}: {e}");
        }
    }

    #[test]
    fn names_that_are_not_plain_identifiers_are_replaced() {
        assert_eq!(rust_name("cmp_id", 0x1000), "cmp_id");
        assert_eq!(rust_name("operator<<", 0x1000), "fn_1000");
        assert_eq!(rust_name("fn", 0x20), "fn_20");
        assert_eq!(rust_name("", 0x20), "fn_20");
        assert_eq!(rust_name("9lives", 0x20), "fn_20");
    }

    #[test]
    fn generic_inputs_match_the_signature() {
        let s = sig("int f(char * a, uint n)").expect("sig");
        let spec = generic_inputs(&s);
        let cases = spec.cases(1, 5);
        assert!(!cases.is_empty());
        assert!(cases.iter().all(|c| c.len() == 2));
        assert!(generic_notes(&s).contains("caller-owned"));
        assert!(generic_notes(&sig("int f(int a)").expect("sig")).is_empty());
    }
}
