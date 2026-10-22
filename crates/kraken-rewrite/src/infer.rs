//! A guess at a function's System V ABI from the C-like signature KRAKEN shows
//! (`int cmp_id(record * a, record * b)`), and generic test inputs for it.
//!
//! The guess is deliberately narrow: integers up to 64 bits, `double`, pointers to caller-owned
//! buffers and function pointers in registers (six integer-class and eight floating-point
//! parameters at most), and an integer, `double`, pointer or void result (a pointer result is
//! compared by what it points at). Anything else (single-precision
//! floating point, structs by value, varargs) is refused with a reason, so a
//! function outside what the oracle can check never gets a verdict that means nothing. Buffer
//! sizes are unknown here, so the generic inputs mix raw random bytes with small pointer graphs; a
//! curated input generator (see `targets`) tests structs far better.

use std::collections::BTreeMap;

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

/// The class of a C++ method from its signature: `Button` for `undefined begin(Button * this)`.
fn this_class(signature: Option<&str>) -> Option<String> {
    let sig = signature?;
    let at = sig.find(" * this")?;
    let head = &sig[..at];
    let start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1);
    let class = &head[start..];
    (!class.is_empty() && class.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| class.to_string())
}

/// `Class::name` for a C++ method (from the `this` parameter of its signature), else `name`.
pub fn qualified_name(name: &str, signature: Option<&str>) -> String {
    match this_class(signature) {
        Some(class) if !name.contains("::") => format!("{class}::{name}"),
        _ => name.to_string(),
    }
}

/// `name` as a Rust identifier: template arguments dropped, `~X` as `drop_X`, every other
/// character that is not a letter, digit or `_` as `_`.
fn identifier(name: &str) -> String {
    let base = name.split('<').next().unwrap_or(name);
    let base = match base.strip_prefix('~') {
        Some(rest) => format!("drop_{rest}"),
        None => base.to_string(),
    };
    let mut out = String::new();
    for c in base.chars() {
        let c = if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '_'
        };
        if !(c == '_' && out.ends_with("__")) {
            out.push(c);
        }
    }
    let out = out.trim_end_matches('_').to_string();
    out.chars().take(48).collect()
}

/// Rust names for the functions of a whole program: `(address, name, signature)` in, a unique
/// identifier per address out. A C++ method is prefixed with its class (`Button_begin`); a name
/// that is not an identifier is made one (`operator()` gives `operator`, a template its base
/// name); a name that is still not unique, not usable or a keyword gets its address
/// (`begin_107d90`).
pub fn program_names(functions: &[(u64, String, Option<String>)]) -> BTreeMap<u64, String> {
    let base: Vec<(u64, String)> = functions
        .iter()
        .map(|(a, name, sig)| {
            let id = identifier(name);
            let id = match this_class(sig.as_deref()) {
                Some(class) if !id.is_empty() => format!("{class}_{id}"),
                _ => id,
            };
            (*a, id)
        })
        .collect();
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, id) in &base {
        *count.entry(id.as_str()).or_default() += 1;
    }
    base.iter()
        .map(|(a, id)| {
            let unique = count.get(id.as_str()) == Some(&1);
            let name = if unique {
                rust_name(id, *a)
            } else if id.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                format!("{id}_{a:x}")
            } else {
                format!("fn_{a:x}")
            };
            (*a, name)
        })
        .collect()
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
    if d.contains("(*") {
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
    ty.contains('*') || ty.contains('[') || ty.trim_end().ends_with('&')
}

/// True for a type that is a function pointer: C syntax (`int (*)(int)`), Ghidra's `code *` and
/// `_func_...` types, and typedef names that say so (`cmp_fn`, `visit_func`, `done_cb`).
fn is_function_pointer(ty: &str) -> bool {
    if ty.contains("(*") {
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

/// The last word of a type without qualifiers (`const float` gives `float`).
fn base_word(ty: &str) -> &str {
    ty.split_whitespace()
        .rfind(|w| !matches!(*w, "const" | "volatile" | "register"))
        .unwrap_or("")
}

/// How strictly unknown types are read: a single function refuses them, a program rewrite reads
/// them as a 64-bit register value (a small struct, a C++ class Ghidra could not size) and lets
/// the program-level test judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Function,
    Program,
}

fn classify_param(decl: &str, mode: Mode, notes: &mut Vec<String>) -> Result<Param, Unsupported> {
    let ty = param_type(decl);
    if is_function_pointer(&ty) {
        return Ok(Param::FnPtr);
    }
    if is_pointer(&ty) {
        return Ok(Param::Buf);
    }
    match base_word(&ty) {
        "float" if !ty.contains("long") => return Ok(Param::Float),
        "double" if !ty.contains("long") => return Ok(Param::Double),
        _ => {}
    }
    if ty.contains("float") || ty.contains("double") {
        return Err(un(format!("floating-point parameter `{decl}`")));
    }
    match int_type(&ty) {
        Some((bits, signed)) => Ok(Param::Int { bits, signed }),
        None if mode == Mode::Program => {
            notes.push(format!(
                "parameter `{decl}` has a type the signature does not size; it is passed as a \
                 64-bit integer register"
            ));
            Ok(Param::Int {
                bits: 64,
                signed: false,
            })
        }
        None => Err(un(format!(
            "parameter `{decl}` has a type that is not a plain integer or pointer \
             (structure by value, function-pointer typedef, ...)"
        ))),
    }
}

fn classify_ret(ty: &str, mode: Mode, notes: &mut Vec<String>) -> Result<Ret, Unsupported> {
    let ty = ty.trim();
    if ty == "void" {
        return Ok(Ret::Void);
    }
    let program = mode == Mode::Program;
    // A stripped binary's decompiler leaves a function whose result it cannot type as
    // `undefined`; a program rewrite reads that as no result, and the program-level test finds
    // out if the callers disagree.
    if ty == "undefined" && program {
        return Ok(Ret::Void);
    }
    // A pointer result is compared by what it points at (`ptrdesc`).
    if is_pointer(ty) {
        return Ok(Ret::Ptr);
    }
    match base_word(ty) {
        "double" if !ty.contains("long") => return Ok(Ret::Double),
        "float" if !ty.contains("long") => return Ok(Ret::Float),
        _ => {}
    }
    if ty.contains("float") || ty.contains("double") {
        return Err(un("floating-point result"));
    }
    match int_type(ty) {
        Some((bits, signed)) => Ok(Ret::Int { bits, signed }),
        None if program => {
            notes.push(format!(
                "the result type `{ty}` is not sized by the signature; it is returned as a 64-bit \
                 integer register (RAX)"
            ));
            Ok(Ret::Int {
                bits: 64,
                signed: false,
            })
        }
        None => Err(un(format!("result type `{ty}` is not a plain integer"))),
    }
}

/// Reads `signature` (as `list_functions` renders it) into a [`Signature`] named `name`.
pub fn infer_signature(signature: &str, name: &str) -> Result<Signature, Unsupported> {
    infer_with(signature, name, None, Mode::Function, &mut Vec::new())
}

/// What [`infer_signature_for_program`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSignature {
    /// The ABI.
    pub signature: Signature,
    /// Why the function cannot be compared against the original at function level (it can still
    /// be translated and compiled, and the program-level test covers it).
    pub compile_only: Option<String>,
    /// What was guessed about types the signature does not size.
    pub guesses: Vec<String>,
}

/// [`infer_signature`] for a program rewrite: a pointer result becomes [`Ret::Ptr`], types the
/// signature does not size are read as 64-bit registers, and `display` (the function's name as
/// the engine shows it, which can be a C++ name such as `~_Vector_base`, `operator()` or a
/// template instantiation) is how the name is found in the signature.
pub fn infer_signature_for_program(
    signature: &str,
    name: &str,
    display: &str,
) -> Result<ProgramSignature, Unsupported> {
    let mut guesses = Vec::new();
    let sig = infer_with(signature, name, Some(display), Mode::Program, &mut guesses)?;
    Ok(ProgramSignature {
        signature: sig,
        compile_only: None,
        guesses,
    })
}

/// Where the parameter list of `sig` opens: the first `(` after the function's name when the name
/// is known (C++ names hold parentheses: `operator()`, `{lambda(int)#1}`), else the first `(`.
fn open_paren(sig: &str, display: Option<&str>) -> Option<usize> {
    if let Some(d) = display.filter(|d| !d.is_empty())
        && let Some(i) = sig.find(&format!("{d}("))
    {
        return Some(i + d.len());
    }
    sig.find('(')
}

/// The `)` that closes the parameter list opened at `open`.
fn close_paren(sig: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in sig[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The result type in `head` (everything before the parameter list): `head` without the name.
fn result_type<'a>(head: &'a str, display: Option<&str>) -> &'a str {
    if let Some(d) = display.filter(|d| !d.is_empty())
        && let Some(rest) = head.strip_suffix(d)
    {
        return rest.trim();
    }
    head.strip_suffix(|c: char| c.is_ascii_alphanumeric() || c == '_')
        .map(|_| {
            let start = head
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            head[..start].trim()
        })
        .unwrap_or("")
}

fn infer_with(
    signature: &str,
    name: &str,
    display: Option<&str>,
    mode: Mode,
    notes: &mut Vec<String>,
) -> Result<Signature, Unsupported> {
    let sig = signature.trim();
    let open = open_paren(sig, display).ok_or_else(|| un("the signature has no parameter list"))?;
    let close = close_paren(sig, open)
        .or_else(|| sig.rfind(')').filter(|c| *c > open))
        .ok_or_else(|| un("the signature has no closing parenthesis"))?;
    let ret_ty = result_type(sig[..open].trim_end(), display);
    if ret_ty.is_empty() {
        return Err(un("the signature has no result type"));
    }
    let ret = classify_ret(ret_ty, mode, notes)?;
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
        .map(|d| classify_param(d, mode, notes))
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
            Param::Float => ParamGen::Float,
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
            ("long double f(int w)", "floating-point"),
            ("int f(long double w)", "floating-point"),
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
    fn pointer_and_untyped_results_are_accepted_and_pointers_are_checked() {
        let r = infer_signature_for_program("char * op_name(uint op)", "op_name", "op_name")
            .expect("sig");
        assert_eq!((r.signature.ret, r.compile_only), (Ret::Ptr, None));
        assert_eq!(
            sig("node * node_new(int id, char * name, int x, int y, double w)")
                .expect("a function-level signature too")
                .ret,
            Ret::Ptr
        );
        assert!(r.signature.rust_prototype().ends_with("-> *const u8"));
        let r = infer_signature_for_program(
            "undefined FUN_00101149(long * param_1)",
            "f",
            "FUN_00101149",
        )
        .expect("sig");
        assert_eq!((r.signature.ret, r.compile_only), (Ret::Void, None));
        // A structure by value or a class Ghidra could not size is a 64-bit register, and the
        // guess is said.
        let r = infer_signature_for_program("int f(vec3 v)", "f", "f").expect("sig");
        assert_eq!(
            r.signature.params,
            vec![Param::Int {
                bits: 64,
                signed: false
            }]
        );
        assert!(r.guesses[0].contains("vec3 v"), "{:?}", r.guesses);
        let r = infer_signature_for_program("Button tap(Button * this)", "Button_tap", "tap")
            .expect("sig");
        assert_eq!(
            r.signature.ret,
            Ret::Int {
                bits: 64,
                signed: false
            }
        );
        assert!(infer_signature_for_program("int printf(char * f, ...)", "f", "printf").is_err());
    }

    #[test]
    fn floats_map_to_sse_registers_in_single_precision() {
        let s = sig("float midiToHz(int param_1)").expect("sig");
        assert_eq!(s.ret, Ret::Float);
        assert!(s.rust_prototype().ends_with("-> f32"));
        let s = sig("int parsePart(float param_1, byte * param_2, char param_4)").expect("sig");
        assert_eq!(s.params[0], Param::Float);
        assert!(s.rust_prototype().contains("a0: f32"));
        let s = sig("void f(const float x, double y)").expect("sig");
        assert_eq!(s.params, vec![Param::Float, Param::Double]);
    }

    #[test]
    fn cpp_names_are_found_in_their_signatures() {
        let r = infer_signature_for_program(
            "void __insertion_sort<__gnu_cxx::__normal_iterator<unsigned_short*,std::vector<unsigned_short,std::allocator<unsigned_short>>>,std::less<void>>(ushort * param_1, ushort * param_2)",
            "insertion_sort",
            "__insertion_sort<__gnu_cxx::__normal_iterator<unsigned_short*,std::vector<unsigned_short,std::allocator<unsigned_short>>>,std::less<void>>",
        )
        .expect("template");
        assert_eq!(r.signature.ret, Ret::Void);
        assert_eq!(r.signature.params, vec![Param::Buf, Param::Buf]);
        let r = infer_signature_for_program(
            "undefined ~_Vector_base(_Vector_base<short,std::allocator<short>> * this)",
            "drop__Vector_base",
            "~_Vector_base",
        )
        .expect("destructor");
        assert_eq!(r.signature.ret, Ret::Void);
        assert_eq!(r.signature.params, vec![Param::Buf]);
        let r = infer_signature_for_program(
            "undefined operator()({lambda(unsigned_short)#1} * this, undefined2 param_1)",
            "operator_103770",
            "operator()",
        )
        .expect("lambda");
        assert_eq!(
            r.signature.params,
            vec![
                Param::Buf,
                Param::Int {
                    bits: 16,
                    signed: false
                }
            ]
        );
    }

    #[test]
    fn program_names_are_unique_identifiers() {
        let names = program_names(&[
            (
                0x10,
                "begin".into(),
                Some("undefined begin(Button * this, int x)".into()),
            ),
            (
                0x20,
                "begin".into(),
                Some("undefined begin(Button * this)".into()),
            ),
            (
                0x30,
                "begin".into(),
                Some("undefined8 begin(FlashStore * this)".into()),
            ),
            (0x40, "operator()".into(), None),
            (0x50, "operator()".into(), None),
            (0x60, "~_Vector_base".into(), None),
            (0x70, "main".into(), None),
            (0x80, "cmp_id".into(), None),
            (0x90, "__insertion_sort<a,b>".into(), None),
        ]);
        assert_eq!(names[&0x10], "Button_begin_10");
        assert_eq!(names[&0x20], "Button_begin_20");
        assert_eq!(names[&0x30], "FlashStore_begin");
        assert_eq!(names[&0x40], "operator_40");
        assert_eq!(names[&0x60], "drop__Vector_base");
        assert_eq!(names[&0x70], "fn_70", "main keeps the address form");
        assert_eq!(names[&0x80], "cmp_id");
        assert_eq!(names[&0x90], "__insertion_sort");
        assert_eq!(
            qualified_name("begin", Some("undefined begin(Button * this)")),
            "Button::begin"
        );
        assert_eq!(qualified_name("main", Some("int main(void)")), "main");
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
