//! A guess at a function's System V ABI from the C-like signature KRAKEN shows
//! (`int cmp_id(record * a, record * b)`), and generic test inputs for it.
//!
//! The guess is deliberately narrow: integers up to 64 bits, `double`, pointers to caller-owned
//! buffers and function pointers in registers (six integer-class and eight floating-point
//! parameters at most), and an integer, `double` or void result. Anything else (single-precision
//! floating point, structs by value, varargs, pointer results) is refused with a reason, so a
//! function outside what the oracle can check never gets a verdict that means nothing. Buffer
//! sizes are unknown here, so the generic inputs mix raw random bytes with small pointer graphs; a
//! curated input generator (see `targets`) tests structs far better.

use crate::abi::{Param, Ret, Signature};
use crate::difftest::{Generator, InputSpec, IntGen, ParamGen, TextGen};

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

/// True for a type that is a function pointer: C syntax (`int (*)(int)`), Ghidra's `code *` and
/// `_func_...` types, and typedef names that say so (`cmp_fn`, `visit_func`, `done_cb`).
fn is_function_pointer(ty: &str) -> bool {
    if ty.contains('(') {
        return true;
    }
    let word = ty
        .split_whitespace()
        .rev()
        .find(|w| *w != "*" && !w.chars().all(|c| c == '*'))
        .unwrap_or("")
        .trim_end_matches('*');
    word == "code"
        || word.starts_with("_func_")
        || [
            "_fn",
            "_func",
            "_cb",
            "_callback",
            "_proc",
            "_handler",
            "_funcptr",
        ]
        .iter()
        .any(|s| word.ends_with(s))
}

fn classify_param(decl: &str) -> Result<Param, Unsupported> {
    let ty = param_type(decl);
    if is_function_pointer(&ty) {
        return Ok(Param::FnPtr);
    }
    if is_pointer(&ty) {
        return Ok(Param::Buf);
    }
    if ty.contains("float") {
        return Err(un(format!(
            "single-precision floating-point parameter `{decl}`"
        )));
    }
    if ty.split_whitespace().last() == Some("double") {
        return Ok(Param::Double);
    }
    if ty.contains("double") {
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

fn classify_ret(ty: &str, allow_ptr: bool) -> Result<Ret, Unsupported> {
    let ty = ty.trim();
    if ty == "void" {
        return Ok(Ret::Void);
    }
    // A stripped binary's decompiler leaves a function whose result it cannot type as
    // `undefined`; a program rewrite reads that as no result, and the program-level test finds
    // out if the callers disagree.
    if ty == "undefined" && allow_ptr {
        return Ok(Ret::Void);
    }
    if is_pointer(ty) && allow_ptr {
        return Ok(Ret::Ptr);
    }
    if is_pointer(ty) {
        return Err(un(
            "pointer result (addresses are not comparable between the original and the Rust build)",
        ));
    }
    if ty == "double" {
        return Ok(Ret::Double);
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
    infer_with(signature, name, false)
}

/// [`infer_signature`] for a program rewrite: a pointer result becomes [`Ret::Ptr`] and the
/// second value says why the function cannot be compared against the original at function level
/// (it can still be translated and compiled, and the program-level test covers it).
pub fn infer_signature_for_program(
    signature: &str,
    name: &str,
) -> Result<(Signature, Option<String>), Unsupported> {
    let sig = infer_with(signature, name, true)?;
    let note = (sig.ret == Ret::Ptr).then(|| {
        "pointer result: addresses are not comparable between the original and the Rust build"
            .to_string()
    });
    Ok((sig, note))
}

fn infer_with(signature: &str, name: &str, allow_ptr: bool) -> Result<Signature, Unsupported> {
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
    let ret = classify_ret(ret_ty, allow_ptr)?;
    let inner = sig[open + 1..close].trim();
    let decls = if inner.is_empty() || inner == "void" {
        Vec::new()
    } else {
        split_params(inner)
    };
    if decls.iter().any(|d| d.contains("...")) {
        return Err(un("variadic function"));
    }
    let params = decls
        .iter()
        .map(|d| classify_param(d))
        .collect::<Result<Vec<_>, _>>()?;
    let sig = Signature {
        name: name.to_string(),
        params,
        ret,
    };
    if !sig.fits_registers() {
        return Err(un(
            "more than six integer or eight floating-point parameters (stack arguments are not \
             modelled)",
        ));
    }
    Ok(sig)
}

/// Generic inputs for `sig`: edge and random values for integers, random bytes (with zero padding
/// after them) for buffers.
pub fn generic_inputs(sig: &Signature) -> InputSpec {
    let gens = sig
        .params
        .iter()
        .map(|p| match p {
            Param::Int { bits, signed } => ParamGen::Int(IntGen::full(*bits, *signed)),
            // Half the cases are raw bytes, which is what string and memory functions want; the
            // other half are small pointer graphs (a struct whose words are null, numbers, text
            // pointers or pointers to a second struct), which is what parsers and list code want.
            Param::Buf => ParamGen::OneOf(vec![
                ParamGen::Bytes {
                    min_len: 8,
                    max_len: BUFFER_BYTES,
                    alphabet: None,
                    terminator: false,
                    pad: BUFFER_BYTES,
                },
                ParamGen::Mixed(TextGen::generic()),
            ]),
            Param::Double => ParamGen::Double,
            Param::FnPtr => ParamGen::FnPtr,
        })
        .collect();
    InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(gens),
    }
}

/// Layout notes for the prompt that follow from the inference (trusted operator text).
pub fn generic_notes(sig: &Signature) -> String {
    let mut notes = Vec::new();
    if sig.params.iter().any(|p| matches!(p, Param::Buf)) {
        notes.push(format!(
            "Pointer parameters are caller-owned buffers whose layout is not known; the checks \
             pass either {BUFFER_BYTES} bytes of arbitrary content followed by zero bytes, or a \
             32-byte struct whose 8-byte words are null, small numbers, pointers to text or \
             pointers to a second such struct. Read and write only what the decompile reads and \
             writes."
        ));
    }
    if sig.params.iter().any(|p| matches!(p, Param::FnPtr)) {
        notes.push(
            "A function-pointer parameter is called by the checks with the host's callbacks, \
             which take up to two pointer-sized arguments and return the difference of the first \
             32-bit integers the two pointers point to (or 0). Call it exactly as the decompile \
             does and write the parameter as `Option<unsafe extern \"C\" fn(...)>` or a plain \
             `unsafe extern \"C\" fn(...)` of the shape the decompile calls."
                .to_string(),
        );
    }
    notes.join("\n")
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
            ("int f(float w)", "single-precision"),
            ("float f(int w)", "floating-point"),
            (
                "int f(int a, double b, double c, double d, double e, double g, double h, double i, double j, double k)",
                "eight",
            ),
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
    fn doubles_and_function_pointers_map_to_their_own_register_classes() {
        let s = sig("double scale(double x, int n)").expect("sig");
        assert_eq!(
            s.params,
            vec![
                Param::Double,
                Param::Int {
                    bits: 32,
                    signed: true
                }
            ]
        );
        assert_eq!(s.ret, Ret::Double);
        assert!(s.rust_prototype().contains("a0: f64"));
        assert!(s.rust_prototype().ends_with("-> f64"));
        for text in [
            "void list_sort(list * l, cmp_fn cmp)",
            "void list_each(list * l, visit_fn fn, void * ctx)",
            "void on_done(code * param_1, int x)",
            "void h(int (*)(int) cb)",
            "void h(_func_int_record_ptr_record_ptr * f)",
        ] {
            let s = sig(text).expect(text);
            assert!(s.params.contains(&Param::FnPtr), "{text}: {s:?}");
        }
        let s = sig("void list_each(list * l, visit_fn fn, void * ctx)").expect("sig");
        assert_eq!(s.params, vec![Param::Buf, Param::FnPtr, Param::Buf]);
        // Eight doubles fit; the integer class is counted on its own.
        sig("double f(double a, double b, double c, double d, double e, double g, double h, double i)")
            .expect("eight doubles");
        // A pointer to a double is a buffer, not a double.
        assert_eq!(
            sig("void f(double * p)").expect("sig").params,
            vec![Param::Buf]
        );
    }

    #[test]
    fn a_program_rewrite_accepts_pointer_and_untyped_results_but_only_compiles_the_first() {
        let (s, note) =
            infer_signature_for_program("char * op_name(uint op)", "op_name").expect("sig");
        assert_eq!(s.ret, Ret::Ptr);
        assert!(note.expect("note").contains("pointer result"));
        assert!(s.rust_prototype().ends_with("-> *const u8"));
        let (s, note) = infer_signature_for_program("undefined FUN_00101149(long * param_1)", "f")
            .expect("sig");
        assert_eq!((s.ret, note), (Ret::Void, None));
        // Everything else stays as strict as for a single function.
        for text in [
            "int f(float w)",
            "int f(vec3 v)",
            "int printf(char * f, ...)",
        ] {
            assert!(infer_signature_for_program(text, "f").is_err(), "{text}");
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
