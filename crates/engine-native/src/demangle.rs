//! C++ demangling, and the names Ghidra derives from it: the Itanium ABI (GCC, Clang, mingw-w64)
//! with `cpp_demangle`, and Microsoft's decoration (`?area@Rect@@QEBANXZ`, MSVC) with
//! `msvc-demangler` (MIT, a port of LLVM's demangler).
//!
//! Ghidra names a function after the last component of its demangled name (`capacity` for
//! `std::__cxx11::basic_string<...>::capacity() const`), with spaces turned into underscores
//! (`_M_construct<char_const*>`), except after `operator`, where it uses a dot
//! (`operator.new`). Special symbols get fixed names: `vtable`, `typeinfo`, `typeinfo-name`.
//! Rust symbols (legacy `_ZN...17h<hash>E` and v0 `_R...`) go through `rustc-demangle`; the name is
//! the last path component without generic arguments and without the hash
//! (`core::ptr::drop_in_place<alloc::string::String>` -> `drop_in_place`).
//! The mangled name stays available next to it (labels, `mangled` in summaries and symbols).

use cpp_demangle::{DemangleOptions, Symbol};
use rustc_demangle::try_demangle;

/// A demangled symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demangled {
    /// The whole demangled name with parameters (`Rect::area() const`).
    pub full: String,
    /// The name Ghidra gives the symbol (`area`).
    pub name: String,
}

/// `name` without an ELF symbol version (`_Znwm@GLIBCXX_3.4` -> `_Znwm`). A Microsoft name
/// (`?f@@YAXXZ`) has `@` in it and no version.
pub fn unversioned(name: &str) -> &str {
    if is_msvc(name) {
        return name;
    }
    name.split('@').next().unwrap_or(name)
}

/// Whether `name` looks like a Microsoft-decorated C++ name.
pub fn is_msvc(name: &str) -> bool {
    name.starts_with('?')
}

/// Whether `name` is a Rust symbol: v0 (`_R`) or legacy (`_ZN`, ending in the 17h hash).
pub fn is_rust(name: &str) -> bool {
    let n = unversioned(name);
    (n.starts_with("_R") || n.starts_with("_ZN")) && try_demangle(n).is_ok()
}

/// Whether `name` looks like a mangled name (Itanium C++, Microsoft or Rust).
pub fn is_mangled(name: &str) -> bool {
    is_msvc(name) || unversioned(name).starts_with("_Z") || is_rust(name)
}

/// Demangles a Rust symbol: the path with generics, without the hash, and the short name.
fn demangle_rust(raw: &str) -> Option<Demangled> {
    let d = try_demangle(raw).ok()?;
    let full = format!("{d:#}");
    let last = last_component(&full);
    let short = if last.starts_with(['<', '{']) {
        last
    } else {
        last.split('<').next().unwrap_or(last)
    };
    if short.is_empty() {
        return None;
    }
    Some(Demangled {
        name: sanitize(short),
        full,
    })
}

/// Demangles a Microsoft-decorated name: the whole name, and Ghidra's name for it.
fn demangle_msvc(raw: &str) -> Option<Demangled> {
    use msvc_demangler::DemangleFlags;
    let full = msvc_demangler::demangle(raw, DemangleFlags::llvm()).ok()?;
    let short = msvc_demangler::demangle(raw, DemangleFlags::NAME_ONLY).ok()?;
    // `Rect::`scalar deleting destructor'` and the like keep their quotes out
    let short = short.replace(['`', '\''], "");
    let name = ghidra_name(&short)?;
    Some(Demangled { full, name })
}

/// Demangles a C++ name; `None` for anything else or what does not parse.
pub fn demangle(raw: &str) -> Option<Demangled> {
    if is_msvc(raw) {
        return demangle_msvc(raw);
    }
    let raw = unversioned(raw);
    if is_rust(raw) {
        return demangle_rust(raw);
    }
    if !is_mangled(raw) {
        return None;
    }
    let sym = Symbol::new(raw).ok()?;
    let full = sym.demangle().ok()?;
    let short = sym
        .demangle_with_options(&DemangleOptions::new().no_params().no_return_type())
        .ok()?;
    let name = special_name(raw).or_else(|| ghidra_name(&short))?;
    Some(Demangled { full, name })
}

/// The name shown for a symbol: Ghidra's name for a mangled one, else the symbol as it is.
pub fn display_name(raw: &str) -> String {
    match demangle(raw) {
        Some(d) => d.name,
        None => raw.to_string(),
    }
}

/// The mangled form of `raw` when it is one (without its version), for keeping next to the
/// demangled name.
pub fn mangled(raw: &str) -> Option<String> {
    demangle(raw).map(|_| unversioned(raw).to_string())
}

/// The fixed name of a special symbol (`_ZTV5Shape`, `vtable for Shape` -> `vtable`).
fn special_name(raw: &str) -> Option<String> {
    [
        ("_ZTV", "vtable"),
        ("_ZTC", "construction-vtable"),
        ("_ZTS", "typeinfo-name"),
        ("_ZTI", "typeinfo"),
        ("_ZTT", "VTT"),
        ("_ZGV", "guard_variable"),
    ]
    .into_iter()
    .find(|(prefix, _)| raw.starts_with(prefix))
    .map(|(_, name)| name.to_string())
}

/// Ghidra's symbol name for a demangled name printed without parameters and return type.
fn ghidra_name(short: &str) -> Option<String> {
    // member function qualifiers follow even without parameters
    let mut short = short.trim_end();
    loop {
        let before = short;
        for q in [" const", " volatile", " &&", " &", " noexcept"] {
            short = short.strip_suffix(q).unwrap_or(short);
        }
        if short == before {
            break;
        }
    }
    // a thunk is named after its target
    let mut s = short;
    for prefix in [
        "non-virtual thunk to ",
        "virtual thunk to ",
        "covariant return thunk to ",
        "transaction clone for ",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
        }
    }
    // Ghidra spells the standard string classes by their typedef names, and names their
    // constructors and destructors after them
    let mut abbreviated = s.to_string();
    for (long, short) in STRING_TYPEDEFS {
        abbreviated = abbreviated.replace(long, short);
    }
    let s = abbreviated.as_str();
    let base = last_component(s);
    let mut base = strip_abi_tags(base);
    for (_, short) in STRING_TYPEDEFS {
        let class = short.trim_start_matches("std::");
        if s.ends_with(&format!("{short}::basic_string")) {
            base = class.to_string();
        } else if s.ends_with(&format!("{short}::~basic_string")) {
            base = format!("~{class}");
        }
    }
    if base.is_empty() {
        return None;
    }
    Some(sanitize(&base))
}

/// The standard string classes and the typedef names Ghidra shows for them.
const STRING_TYPEDEFS: &[(&str, &str)] = &[
    (
        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >",
        "std::string",
    ),
    (
        "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
        "std::string",
    ),
    (
        "std::__cxx11::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
        "std::wstring",
    ),
];

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// The length of the operator token at the start of `s` (which follows `operator`).
fn operator_len(s: &str) -> usize {
    if let Some(rest) = s.strip_prefix(' ') {
        // `operator new`, `operator delete[]`, or a conversion `operator unsigned long`
        for word in ["new[]", "delete[]", "new", "delete"] {
            if rest.starts_with(word) {
                return 1 + word.len();
            }
        }
        return s.len();
    }
    for pair in ["()", "[]"] {
        if s.starts_with(pair) {
            return 2;
        }
    }
    s.chars()
        .take_while(|c| "+-*/%^&|~!=<>,".contains(*c))
        .map(char::len_utf8)
        .sum()
}

/// The last `::` component at nesting depth 0 (template arguments, parentheses, brackets and
/// braces nest), skipping a leading return type.
fn last_component(s: &str) -> &str {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if depth == 0
            && s[i..].starts_with("operator")
            && (i == 0 || !is_ident(b[i - 1] as char))
            && !s[i + 8..].starts_with(|c: char| is_ident(c))
        {
            i += 8 + operator_len(&s[i + 8..]);
            // `operator<< <T>`: the space before template arguments does not separate
            if s[i..].starts_with(" <") {
                i += 1;
            }
            continue;
        }
        match c {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth -= 1,
            ':' if depth == 0 && b.get(i + 1) == Some(&b':') => {
                start = i + 2;
                i += 2;
                continue;
            }
            ' ' if depth == 0 => start = i + 1,
            _ => {}
        }
        i += 1;
    }
    &s[start..]
}

/// `name` without `[abi:cxx11]` tags.
fn strip_abi_tags(name: &str) -> String {
    let mut out = name.to_string();
    while let Some(i) = out.find("[abi:") {
        match out[i..].find(']') {
            Some(j) => out.replace_range(i..i + j + 1, ""),
            None => break,
        }
    }
    out
}

/// Spaces become underscores, except the one after `operator`, which becomes a dot.
fn sanitize(name: &str) -> String {
    match name.strip_prefix("operator ") {
        Some(rest) => format!("operator.{}", rest.replace(' ', "_")),
        None => name.replace(' ', "_"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> String {
        demangle(raw).map(|d| d.name).unwrap_or_default()
    }

    #[test]
    fn rust_symbols_are_demangled_legacy_and_v0() {
        let legacy = "_ZN4core3ptr42drop_in_place$LT$alloc..string..String$GT$17h0123456789abcdefE";
        assert!(is_rust(legacy) && is_mangled(legacy));
        let d = demangle(legacy).unwrap();
        assert_eq!(d.full, "core::ptr::drop_in_place<alloc::string::String>");
        assert_eq!(d.name, "drop_in_place");
        assert_eq!(mangled(legacy).as_deref(), Some(legacy));

        let v0 = "_RNvCs1234_7mycrate4main";
        assert!(is_rust(v0));
        let d = demangle(v0).unwrap();
        assert_eq!(d.full, "mycrate::main");
        assert_eq!(d.name, "main");

        let closure = "_ZN4demo4main28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE";
        assert_eq!(name(closure), "{{closure}}");
        let imp = "_ZN60_$LT$alloc..string..String$u20$as$u20$core..fmt..Display$GT$3fmt17h0123456789abcdefE";
        assert_eq!(name(imp), "fmt");
        // C++ names and plain C names are not Rust
        assert!(!is_rust("_ZN4RectC2Edd"));
        assert!(!is_rust("_Rtl_thing"));
        assert!(!is_rust("main"));
        assert_eq!(name("_ZN4RectC2Edd"), "Rect");
    }

    #[test]
    fn functions_are_named_after_their_last_component() {
        assert_eq!(
            name("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv"),
            "capacity"
        );
        assert_eq!(name("_ZN4RectC2Edd"), "Rect");
        assert_eq!(name("_ZN5ShapeD0Ev"), "~Shape");
        assert_eq!(name("_ZNK4Rect4areaEv"), "area");
        assert_eq!(name("_ZNK5Shape8describeB5cxx11Ev"), "describe");
        assert_eq!(name("_ZNSt7__cxx119to_stringEi"), "to_string");
    }

    #[test]
    fn microsoft_names_are_demangled_too() {
        let d = demangle("?area@Rect@@QEBANXZ").expect("msvc name");
        assert_eq!(d.name, "area");
        assert!(d.full.contains("Rect::area"), "{}", d.full);
        assert_eq!(name("??0Rect@@QEAA@NN@Z"), "Rect");
        assert_eq!(name("??1Shape@@UEAA@XZ"), "~Shape");
        assert_eq!(
            name(
                "?describe@Shape@@UEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ"
            ),
            "describe"
        );
        assert!(is_mangled("?f@@YAXXZ"));
        assert_eq!(unversioned("?f@@YAXXZ"), "?f@@YAXXZ");
        assert_eq!(mangled("?f@@YAXXZ").as_deref(), Some("?f@@YAXXZ"));
        // C names and stdcall decorations are not C++
        assert_eq!(display_name("_on_tls@12"), "_on_tls@12");
        assert!(demangle("?not a name").is_none());
    }

    #[test]
    fn templates_keep_their_arguments_with_underscores() {
        assert_eq!(
            name("_ZNSt8__detail14__to_chars_lenIjEEjT_i"),
            "__to_chars_len<unsigned_int>"
        );
        assert_eq!(
            name(
                "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag"
            ),
            "_M_construct<char_const*>"
        );
    }

    #[test]
    fn operators_use_a_dot_after_operator() {
        assert_eq!(name("_Znwm"), "operator.new");
        assert_eq!(name("_ZdlPvm"), "operator.delete");
        assert_eq!(name("_Znam"), "operator.new[]");
        assert_eq!(
            name("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLERKS4_"),
            "operator+="
        );
        assert_eq!(
            name("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc"),
            "operator="
        );
        assert_eq!(
            name("_ZZNSt7__cxx119to_stringEiENKUlPcmE_clES0_m"),
            "operator()"
        );
        assert_eq!(
            name("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc"),
            "operator<<_<std::char_traits<char>_>"
        );
    }

    #[test]
    fn string_classes_go_by_their_typedef_names() {
        assert_eq!(
            name("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS4_"),
            "string"
        );
        assert_eq!(
            name("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev"),
            "~string"
        );
    }

    #[test]
    fn special_symbols_have_fixed_names() {
        assert_eq!(name("_ZTV5Shape"), "vtable");
        assert_eq!(name("_ZTI6Circle"), "typeinfo");
        assert_eq!(name("_ZTS6Square"), "typeinfo-name");
    }

    #[test]
    fn plain_names_and_versions() {
        assert_eq!(demangle("printf"), None);
        assert_eq!(display_name("printf"), "printf");
        assert_eq!(display_name("_Znwm@GLIBCXX_3.4"), "operator.new");
        assert_eq!(mangled("_Znwm@GLIBCXX_3.4").as_deref(), Some("_Znwm"));
        assert_eq!(mangled("main"), None);
        assert_eq!(
            demangle("_ZN4RectC2Edd").map(|d| d.full).as_deref(),
            Some("Rect::Rect(double, double)")
        );
        assert_eq!(demangle("_Zgarbage"), None);
    }
}
