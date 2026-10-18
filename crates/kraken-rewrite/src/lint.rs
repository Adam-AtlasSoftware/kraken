//! The allowlist lint for model-written Rust (finding H1).
//!
//! A translation is parsed with `syn` and must stay inside a small, computing-only subset:
//!
//! * items: functions, types, constants, statics, traits, impls, inline modules and `use`; no
//!   `extern` blocks or crates, no `mod x;` (a file module), no `macro_rules!`;
//! * attributes: `repr`, `derive` of std traits, `inline`, `no_mangle`, lint levels and a few
//!   markers; no `link*`, `path`, `export_name`, `cfg`, crate-level attributes;
//! * macros: formatting and assertion macros only; their arguments are parsed and checked like
//!   any other code, so `println!("{}", include_str!(..))` is refused as well;
//! * paths: nothing from `std::fs`, `std::net`, `std::env`, `std::os`, `std::thread`,
//!   `std::process` (except `exit` and `abort`), `std::arch` or `std::intrinsics`; the crate roots
//!   `std`/`core`/`alloc` cannot be imported or aliased as a whole, so a module cannot be reached
//!   by renaming.
//!
//! This is defence in depth: the compile step and the runner are confined by [`crate::sandbox`]
//! whatever the lint says.

use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Expr, Token};

/// Largest translation accepted, in bytes.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// Std modules a translation may not name (below `std`, `core` or `alloc`).
const DENIED_MODULES: &[&str] = &[
    "fs",
    "net",
    "process",
    "env",
    "os",
    "thread",
    "arch",
    "intrinsics",
    "sys",
    "sys_common",
    "rt",
];
/// Under `std::process`, only these leave the process alone.
const PROCESS_OK: &[&str] = &["exit", "abort"];
/// Crates that must never be the root of a path.
const DENIED_ROOTS: &[&str] = &["libc", "proc_macro", "test"];
const STD_ROOTS: &[&str] = &["std", "core", "alloc"];

const MACROS: &[&str] = &[
    "print",
    "println",
    "eprint",
    "eprintln",
    "write",
    "writeln",
    "format",
    "format_args",
    "panic",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "unreachable",
    "unimplemented",
    "todo",
    "vec",
    "matches",
];

const ATTRIBUTES: &[&str] = &[
    "repr",
    "derive",
    "inline",
    "cold",
    "no_mangle",
    "must_use",
    "doc",
    "allow",
    "warn",
    "deny",
    "forbid",
    "deprecated",
    "non_exhaustive",
    "track_caller",
];

const DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "PartialEq",
    "Eq",
    "PartialOrd",
    "Ord",
    "Hash",
];

/// Returns why `code` may not be built, if it may not.
pub fn lint_translation(code: &str) -> Option<String> {
    if code.len() > MAX_SOURCE_BYTES {
        return Some(format!(
            "the translation is {} bytes; the limit is {MAX_SOURCE_BYTES}",
            code.len()
        ));
    }
    let file = match syn::parse_file(code) {
        Ok(f) => f,
        Err(e) => return Some(format!("does not compile: not valid Rust: {e}")),
    };
    let mut lint = Lint { error: None };
    lint.visit_file(&file);
    lint.error
}

struct Lint {
    error: Option<String>,
}

fn ident(i: &syn::Ident) -> String {
    let s = i.to_string();
    s.strip_prefix("r#").unwrap_or(&s).to_string()
}

impl Lint {
    fn deny(&mut self, what: impl std::fmt::Display, why: &str) {
        if self.error.is_none() {
            self.error = Some(format!("`{what}` is not allowed in a translation: {why}"));
        }
    }

    /// Checks a full path given as segments.
    fn check_segments(&mut self, segs: &[String]) {
        let Some(first) = segs.first() else { return };
        if DENIED_ROOTS.contains(&first.as_str()) && segs.len() > 1 {
            self.deny(
                segs.join("::"),
                "that crate is not available to a translation",
            );
            return;
        }
        if !STD_ROOTS.contains(&first.as_str()) {
            return;
        }
        for (i, s) in segs.iter().enumerate().skip(1) {
            if !DENIED_MODULES.contains(&s.as_str()) {
                continue;
            }
            let exit =
                s == "process" && segs.len() == i + 2 && PROCESS_OK.contains(&segs[i + 1].as_str());
            if !exit {
                self.deny(
                    segs.join("::"),
                    "file system, network, process, environment, thread and OS APIs are off \
                     limits (only std::process::exit and abort are allowed)",
                );
                return;
            }
        }
    }

    fn check_use(&mut self, t: &syn::UseTree, prefix: &mut Vec<String>) {
        match t {
            syn::UseTree::Path(p) => {
                prefix.push(ident(&p.ident));
                self.check_use(&p.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let name = ident(&n.ident);
                self.check_use_leaf(prefix, (name != "self").then_some(name));
            }
            syn::UseTree::Rename(r) => {
                let name = ident(&r.ident);
                self.check_use_leaf(prefix, (name != "self").then_some(name));
            }
            syn::UseTree::Glob(_) => self.check_use_leaf(prefix, Some("*".into())),
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.check_use(item, prefix);
                }
            }
        }
    }

    fn check_use_leaf(&mut self, prefix: &[String], leaf: Option<String>) {
        let mut segs = prefix.to_vec();
        let is_glob = leaf.as_deref() == Some("*");
        if let Some(l) = leaf
            && !is_glob
        {
            segs.push(l);
        }
        // `use std;`, `use std as s;`, `use std::*;`, `use std::{self as s};` would hand out the
        // whole crate under a name the checks cannot follow.
        if segs.len() == 1 && STD_ROOTS.contains(&segs[0].as_str()) {
            self.deny(
                format!("use {}", segs[0]),
                "importing a whole standard crate would hide the modules that are off limits",
            );
            return;
        }
        if is_glob && segs.len() == 1 {
            return;
        }
        self.check_segments(&segs);
    }

    fn check_macro_args(&mut self, name: &str, m: &syn::Macro) {
        let parsed: syn::Result<Vec<Expr>> = match name {
            "vec" => m.parse_body_with(|input: syn::parse::ParseStream| {
                if input.is_empty() {
                    return Ok(Vec::new());
                }
                let first: Expr = input.parse()?;
                if input.peek(Token![;]) {
                    let _: Token![;] = input.parse()?;
                    let n: Expr = input.parse()?;
                    return Ok(vec![first, n]);
                }
                let mut all = vec![first];
                while !input.is_empty() {
                    let _: Token![,] = input.parse()?;
                    if input.is_empty() {
                        break;
                    }
                    all.push(input.parse()?);
                }
                Ok(all)
            }),
            "matches" => {
                let r = m.parse_body_with(|input: syn::parse::ParseStream| {
                    let e: Expr = input.parse()?;
                    let _: Token![,] = input.parse()?;
                    let pat = syn::Pat::parse_multi_with_leading_vert(input)?;
                    let guard = if input.peek(Token![if]) {
                        let _: Token![if] = input.parse()?;
                        Some(input.parse::<Expr>()?)
                    } else {
                        None
                    };
                    let _: Option<Token![,]> = input.parse()?;
                    Ok((e, pat, guard))
                });
                match r {
                    Ok((e, pat, guard)) => {
                        self.visit_pat(&pat);
                        Ok(std::iter::once(e).chain(guard).collect())
                    }
                    Err(e) => Err(e),
                }
            }
            _ => m
                .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                .map(|p| p.into_iter().collect()),
        };
        match parsed {
            Ok(exprs) => {
                for e in &exprs {
                    self.visit_expr(e);
                }
            }
            Err(e) => self.deny(
                format!("{name}!"),
                &format!("the arguments are not plain expressions: {e}"),
            ),
        }
    }
}

impl<'ast> Visit<'ast> for Lint {
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        let segs: Vec<String> = a.path().segments.iter().map(|s| ident(&s.ident)).collect();
        let name = segs.join("::");
        // `#[unsafe(no_mangle)]`
        if name == "unsafe" {
            let ok = matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string() == "no_mangle");
            if !ok {
                self.deny("#[unsafe(..)]", "only `unsafe(no_mangle)` is allowed");
            }
            return;
        }
        if segs.len() != 1 || !ATTRIBUTES.contains(&name.as_str()) {
            self.deny(
                format!("#[{name}]"),
                "this attribute is not on the allowlist (repr, derive, inline, no_mangle, doc, \
                 lint levels and a few markers)",
            );
            return;
        }
        if name == "derive"
            && let syn::Meta::List(l) = &a.meta
        {
            match l.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated) {
                Ok(paths) => {
                    for p in paths {
                        let last = p
                            .segments
                            .last()
                            .map(|s| ident(&s.ident))
                            .unwrap_or_default();
                        if !DERIVES.contains(&last.as_str()) {
                            self.deny(format!("derive({last})"), "only std traits may be derived");
                        }
                    }
                }
                Err(_) => self.deny("#[derive]", "unreadable derive list"),
            }
        }
        visit::visit_attribute(self, a);
    }

    fn visit_item(&mut self, i: &'ast syn::Item) {
        if let syn::Item::Verbatim(_) = i {
            self.deny("item", "syntax the lint cannot read");
            return;
        }
        visit::visit_item(self, i);
    }

    fn visit_item_foreign_mod(&mut self, _: &'ast syn::ItemForeignMod) {
        self.deny(
            "extern { .. }",
            "foreign declarations let code call any libc function",
        );
    }

    fn visit_item_extern_crate(&mut self, i: &'ast syn::ItemExternCrate) {
        self.deny(format!("extern crate {}", i.ident), "external crates");
    }

    fn visit_item_macro(&mut self, _: &'ast syn::ItemMacro) {
        self.deny("macro item", "defining or invoking macros at item level");
    }

    fn visit_impl_item_macro(&mut self, _: &'ast syn::ImplItemMacro) {
        self.deny("macro item", "macros in impl blocks");
    }

    fn visit_trait_item_macro(&mut self, _: &'ast syn::TraitItemMacro) {
        self.deny("macro item", "macros in trait definitions");
    }

    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        if i.content.is_none() {
            self.deny(
                format!("mod {};", i.ident),
                "a module declaration loads another file",
            );
            return;
        }
        visit::visit_item_mod(self, i);
    }

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        self.check_use(&i.tree, &mut Vec::new());
        // The use tree holds only identifiers; nothing below needs visiting.
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        let segs: Vec<String> = p.segments.iter().map(|s| ident(&s.ident)).collect();
        self.check_segments(&segs);
        visit::visit_path(self, p);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let segs: Vec<String> = m.path.segments.iter().map(|s| ident(&s.ident)).collect();
        let name = segs.last().cloned().unwrap_or_default();
        let rooted_ok =
            segs.len() == 1 || (segs.len() == 2 && STD_ROOTS.contains(&segs[0].as_str()));
        // `addr_of!(place)` and `addr_of_mut!(place)` only take an address.
        let addr_of = matches!(name.as_str(), "addr_of" | "addr_of_mut")
            && (segs.len() == 1
                || (segs.len() == 3 && STD_ROOTS.contains(&segs[0].as_str()) && segs[1] == "ptr"));
        if addr_of {
            self.check_macro_args(&name, m);
            return;
        }
        if !rooted_ok || !MACROS.contains(&name.as_str()) {
            self.deny(
                format!("{}!", segs.join("::")),
                "only formatting, assertion, vec and matches macros are allowed",
            );
            return;
        }
        self.check_macro_args(&name, m);
    }

    fn visit_expr(&mut self, e: &'ast Expr) {
        if let Expr::Verbatim(_) = e {
            self.deny("expression", "syntax the lint cannot read");
            return;
        }
        visit::visit_expr(self, e);
    }

    fn visit_type(&mut self, t: &'ast syn::Type) {
        if let syn::Type::Verbatim(_) = t {
            self.deny("type", "syntax the lint cannot read");
            return;
        }
        visit::visit_type(self, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        #[repr(C)]
        #[derive(Clone, Copy, Debug)]
        pub struct P { pub x: i32 }
        fn helper(p: &P) -> i32 { p.x.wrapping_add(1) }
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn f(a: *const P) -> i32 {
            let v = vec![1u8, 2, 3];
            if matches!(v.len(), 1 | 3) { eprint!("n={}\n", v.len()); }
            if v.is_empty() { std::process::exit(42); }
            unsafe { helper(&*a) }
        }
    "#;

    fn refused(code: &str) -> String {
        lint_translation(code).unwrap_or_else(|| panic!("accepted:\n{code}"))
    }

    #[test]
    fn ordinary_translations_pass() {
        assert_eq!(lint_translation(GOOD), None);
        for r in [
            include_str!("../references/cmp_id.rs"),
            include_str!("../references/cmp_dist.rs"),
            include_str!("../references/evaluate.rs"),
            include_str!("../references/vm_run.rs"),
        ] {
            assert_eq!(lint_translation(r), None);
        }
    }

    #[test]
    fn include_macros_are_refused_whatever_the_spacing() {
        for code in [
            r#"fn f() -> &'static str { include_str !("/etc/passwd") }"#,
            r#"fn f() -> &'static [u8] { include_bytes ! ("/etc/passwd") }"#,
            r#"fn f() { include!("/etc/passwd"); }"#,
            r#"fn f() { std::include_str!("x"); }"#,
            r#"fn f() { println!("{}", include_str!("/etc/passwd")); }"#,
            r#"fn f() { let _ = format!("{}", concat!("a", include_str!("x"))); }"#,
            r#"fn f() { let _ = matches!(1, 1 if include_str!("x").is_empty()); }"#,
            r#"fn f() { compile_error!(concat!("LEAK:", include_str !("sec.txt"))); }"#,
            r#"fn f() -> &'static str { env!("HOME") }"#,
            r#"fn f() { std::arch::asm!("nop"); }"#,
            r#"macro_rules! m { () => {} } fn f() { m!(); }"#,
        ] {
            refused(code);
        }
    }

    #[test]
    fn io_and_process_apis_are_refused_however_they_are_spelled() {
        for code in [
            "use std::{fs, process::Command}; fn f() {}",
            "use std::fs; fn f() { let _ = fs::read(\"x\"); }",
            "fn f() { let _ = std::fs::read(\"x\"); }",
            "fn f() { let _ = ::std::fs::read(\"x\"); }",
            "fn f() { let _ = std :: net :: UdpSocket :: bind(\"0:0\"); }",
            "fn f() { let _ = core::arch::x86_64::_rdtsc(); }",
            "use std::os::unix::net::UnixStream; fn f() {}",
            "use std::*; fn f() {}",
            "use std as s; fn f() { let _ = s::fs::read(\"x\"); }",
            "use std::{self as s}; fn f() {}",
            "use std::process; fn f() { process::Command::new(\"x\"); }",
            "fn f() { let _ = std::process::Command::new(\"id\"); }",
            "fn f() { std::thread::spawn(|| {}); }",
            "fn f() { let _ = std::env::var(\"HOME\"); }",
            "fn f() { let _ = r#std::r#fs::read(\"x\"); }",
            "mod m { pub use std::fs::File; } fn f() {}",
            "fn f() { let _ = <std::fs::File as Sized>::clone; }",
            "fn f(_: std::fs::File) {}",
            "extern crate libc; fn f() {}",
            "fn f() { let _ = libc::getpid(); }",
        ] {
            refused(code);
        }
    }

    #[test]
    fn extern_blocks_and_link_attributes_are_refused() {
        for code in [
            r#"extern "C" { fn socket(d: i32, t: i32, p: i32) -> i32; } fn f() {}"#,
            r#"unsafe extern "C" { fn sendto(); } fn f() {}"#,
            r#"#[link(name = "c")] unsafe extern "C" { } fn f() {}"#,
            r#"#[ link(name = "c")] fn f() {}"#,
            r#"#[link_name = "x"] fn f() {}"#,
            r#"#[export_name = "x"] fn f() {}"#,
            r#"#[link_section = ".x"] static X: u8 = 0; fn f() {}"#,
            r#"#[path = "/etc/shadow"] mod x; fn f() {}"#,
            r#"mod x; fn f() {}"#,
            r#"#![no_std] fn f() {}"#,
            r#"#![feature(x)] fn f() {}"#,
            r#"#[cfg_attr(all(), link(name = "c"))] fn f() {}"#,
            r#"#[derive(serde::Serialize)] struct S; fn f() {}"#,
            r#"#[unsafe(export_name = "x")] fn f() {}"#,
        ] {
            refused(code);
        }
    }

    #[test]
    fn unparsable_and_oversized_code_is_refused() {
        assert!(refused("fn f( {").contains("does not compile"));
        let big = format!(
            "fn f() {{}}\n{}",
            "// pad\n".repeat(MAX_SOURCE_BYTES / 7 + 1)
        );
        assert!(refused(&big).contains("limit"));
    }

    #[test]
    fn locals_named_like_modules_are_fine() {
        assert_eq!(
            lint_translation("fn f(env: u8, fs: u8) -> u8 { let os = env; os.wrapping_add(fs) }"),
            None
        );
    }
}
