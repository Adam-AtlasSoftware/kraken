//! Reusing accepted translations of callees.
//!
//! When a program callee already has an accepted unit that was made from the callee's current
//! decompile, a new translation calls that unit's Rust function instead of translating the
//! callee again. For the differential test the accepted code is compiled together with the new
//! code (each callee in a private module, so helper names cannot clash); for the export it is a
//! `use` of the callee's module. The record keeps which version was called ([`ReusedUnit`]), so
//! an export can check that the same function is still accepted.

use std::collections::BTreeSet;

use kraken_registry::commands::UnitStatus;

use crate::error::RewriteError;
use crate::fetch::FunctionContext;
use crate::store::RewriteStore;
use crate::unit::{CalleeRef, ReusedUnit, RewriteUnit};

/// An accepted callee that a translation calls as Rust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedCallee {
    /// The callee's name in the decompile.
    pub name: String,
    /// Entry address as KRAKEN reports it.
    pub address: u64,
    /// SHA-256 of the callee's decompile when the accepted unit was made.
    pub decompile_hash: String,
    /// The accepted unit.
    pub reused: ReusedUnit,
    /// `pub unsafe extern "C" fn ...` declaration of the Rust function.
    pub prototype: String,
    /// The accepted unit's Rust code.
    pub code: String,
    /// Accepted callees that code calls in turn: (address, Rust function).
    pub requires: Vec<(u64, String)>,
}

impl ReusedCallee {
    /// The Rust function the translation calls.
    pub fn symbol(&self) -> &str {
        &self.reused.symbol
    }

    /// The record entry for a unit that calls it.
    pub fn callee_ref(&self) -> CalleeRef {
        CalleeRef {
            name: self.name.clone(),
            address: format!("{:#x}", self.address),
            decompile_hash: self.decompile_hash.clone(),
            reused: Some(self.reused.clone()),
        }
    }

    fn module(&self) -> String {
        module_name(self.address)
    }
}

fn module_name(address: u64) -> String {
    format!("__kr_callee_{address:x}")
}

fn parse_addr(a: &str) -> u64 {
    u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0)
}

/// What [`resolve`] decided for the callees of a function.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// Callees called as accepted Rust.
    pub direct: Vec<ReusedCallee>,
    /// `direct` plus what their code needs in turn, dependencies first.
    pub all: Vec<ReusedCallee>,
    /// Callees that still have to be translated together with the function.
    pub remaining: Vec<FunctionContext>,
}

/// Looks up `callees` in the store: those whose accepted unit was made from the callee's current
/// decompile (and whose own reused callees are still accepted) are reused; the others stay in
/// `remaining`. `own_address` is never reused (a recursive call stays part of the unit).
pub fn resolve(
    store: &RewriteStore,
    program_sha256: &str,
    own_address: u64,
    callees: &[FunctionContext],
) -> Result<Resolved, RewriteError> {
    let mut out = Resolved::default();
    let mut seen = BTreeSet::new();
    for c in callees {
        if c.address == own_address {
            out.remaining.push(c.clone());
            continue;
        }
        let mut chain = Vec::new();
        match reusable(store, program_sha256, c, &mut chain, 0)? {
            Some(top) => {
                for r in chain {
                    if seen.insert(r.address) {
                        out.all.push(r);
                    }
                }
                if seen.insert(top.address) {
                    out.all.push(top.clone());
                }
                out.direct.push(top);
            }
            None => out.remaining.push(c.clone()),
        }
    }
    Ok(out)
}

const MAX_DEPTH: usize = 8;

/// The reusable form of `c`; its dependencies are pushed to `chain` (dependencies first).
fn reusable(
    store: &RewriteStore,
    sha: &str,
    c: &FunctionContext,
    chain: &mut Vec<ReusedCallee>,
    depth: usize,
) -> Result<Option<ReusedCallee>, RewriteError> {
    let address = format!("{:#x}", c.address);
    let Some(unit) = store.accepted(sha, &address)? else {
        return Ok(None);
    };
    if unit.status != UnitStatus::Accepted || unit.source_decompile_hash != c.decompile_hash {
        return Ok(None);
    }
    from_unit(store, sha, &unit, c, chain, depth)
}

fn from_unit(
    store: &RewriteStore,
    sha: &str,
    unit: &RewriteUnit,
    c: &FunctionContext,
    chain: &mut Vec<ReusedCallee>,
    depth: usize,
) -> Result<Option<ReusedCallee>, RewriteError> {
    if depth > MAX_DEPTH {
        return Ok(None);
    }
    let mut requires = Vec::new();
    for dep in unit.callees.iter().filter(|d| d.reused.is_some()) {
        let a = parse_addr(&dep.address);
        let Some(dep_unit) = store.accepted(sha, &dep.address)? else {
            return Ok(None);
        };
        if dep_unit.source_decompile_hash != dep.decompile_hash {
            return Ok(None);
        }
        let ctx = FunctionContext {
            name: dep.name.clone(),
            address: a,
            signature: None,
            decompile: String::new(),
            decompile_hash: dep.decompile_hash.clone(),
            program_sha256: sha.to_string(),
            image_base: c.image_base,
        };
        let mut sub = Vec::new();
        let Some(r) = from_unit(store, sha, &dep_unit, &ctx, &mut sub, depth + 1)? else {
            return Ok(None);
        };
        chain.extend(sub);
        requires.push((a, r.symbol().to_string()));
        chain.push(r);
    }
    Ok(Some(ReusedCallee {
        name: c.name.clone(),
        address: c.address,
        decompile_hash: c.decompile_hash.clone(),
        reused: ReusedUnit {
            unit: unit.id.clone(),
            version: unit.version,
            symbol: unit.signature.name.clone(),
        },
        prototype: unit.rust_prototype.clone(),
        code: unit.rust_code.clone(),
        requires,
    }))
}

/// The source that goes in front of the new translation when it is compiled: every reused
/// callee in its own module, then `use` lines for the ones the translation calls directly.
pub fn prelude(all: &[ReusedCallee], direct: &[ReusedCallee]) -> String {
    let mut s = String::new();
    for r in all {
        s.push_str(&format!("mod {} {{\n", r.module()));
        for (addr, sym) in &r.requires {
            s.push_str(&format!("use super::{}::{sym};\n", module_name(*addr)));
        }
        s.push_str(&r.code);
        s.push_str("\n}\n");
    }
    for r in direct {
        s.push_str(&format!("use {}::{};\n", r.module(), r.symbol()));
    }
    s
}

/// An accepted unit as the export knows it: module name, version, exported symbol.
pub type ExportedUnit = (String, u32, String);

/// The `use` lines that give an exported unit module access to the callees it reuses.
/// `exported` looks an accepted unit up by entry address. The export refuses a unit whose
/// reused callee is no longer accepted, or is accepted at another version than the one the
/// unit was tested against: its verdict says nothing about the new callee.
pub fn export_uses(
    unit: &RewriteUnit,
    exported: &dyn Fn(u64) -> Option<ExportedUnit>,
) -> Result<String, RewriteError> {
    let mut s = String::new();
    for c in unit.callees.iter().filter(|c| c.reused.is_some()) {
        let Some(r) = &c.reused else { continue };
        let fail = |why: String| {
            RewriteError::Store(format!(
                "unit {} ({}) calls the accepted Rust of `{}` at {}, but {why}; translate {} again \
                 so it is tested against the callee as it is now",
                unit.id, unit.anchor.name, c.name, c.address, unit.anchor.name
            ))
        };
        match exported(parse_addr(&c.address)) {
            None => return Err(fail("that callee is not among the accepted units".into())),
            Some((_, version, symbol)) if version != r.version || symbol != r.symbol => {
                return Err(fail(format!(
                    "the accepted version of that callee is now {version} ({symbol}), not {} ({})",
                    r.version, r.symbol
                )));
            }
            Some((module, _, symbol)) => {
                s.push_str(&format!("use super::{module}::{symbol};\n"));
            }
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::lint_translation;

    fn reused(addr: u64, sym: &str, requires: Vec<(u64, String)>) -> ReusedCallee {
        ReusedCallee {
            name: format!("f{addr:x}"),
            address: addr,
            decompile_hash: "h".into(),
            reused: ReusedUnit {
                unit: "ru-1".into(),
                version: 1,
                symbol: sym.into(),
            },
            prototype: format!("pub unsafe extern \"C\" fn {sym}(a: i32) -> i32"),
            code: format!(
                "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {sym}(a: i32) -> i32 {{ a.wrapping_add(1) }}"
            ),
            requires,
        }
    }

    #[test]
    fn prelude_wraps_each_callee_and_imports_direct_ones() {
        let inner = reused(0x10, "inner", vec![]);
        let outer = reused(0x20, "outer", vec![(0x10, "inner".into())]);
        let p = prelude(&[inner.clone(), outer.clone()], &[outer]);
        assert!(p.contains("mod __kr_callee_10 {"));
        assert!(p.contains("mod __kr_callee_20 {\nuse super::__kr_callee_10::inner;\n"));
        assert!(p.trim_end().ends_with("use __kr_callee_20::outer;"));
        assert!(!p.contains("use __kr_callee_10::inner;\n\n"));
    }

    #[test]
    fn composed_source_passes_the_lint() {
        let inner = reused(0x10, "inner", vec![]);
        let p = prelude(std::slice::from_ref(&inner), std::slice::from_ref(&inner));
        let code = format!(
            "{p}\n#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn top(a: i32) -> i32 {{ unsafe {{ inner(a) }} }}"
        );
        assert_eq!(lint_translation(&code), None);
    }
}
