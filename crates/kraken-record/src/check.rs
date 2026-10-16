//! Structural comparison of two recordings of the same binary.

use std::collections::BTreeMap;
use std::fmt;

use engine_fake::{FixtureFile, FixtureFunction};
use kraken_proto::{FlowKind, Locator, TokenKind, XrefKind};

/// One structural difference between a committed fixture and a fresh recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// Program facts (arch, format, base, sha256, size) differ.
    Program {
        /// Committed value.
        committed: String,
        /// Fresh value.
        fresh: String,
    },
    /// A function is in the fresh recording only.
    FunctionAdded(String),
    /// A function is in the committed fixture only.
    FunctionRemoved(String),
    /// A function's name differs.
    Name {
        /// Entry.
        at: String,
        /// Committed name.
        committed: String,
        /// Fresh name.
        fresh: String,
    },
    /// A function's signature differs.
    Signature {
        /// Entry and name.
        at: String,
        /// Committed signature.
        committed: String,
        /// Fresh signature.
        fresh: String,
    },
    /// A function's size differs.
    Size {
        /// Entry and name.
        at: String,
        /// Committed size.
        committed: Option<u64>,
        /// Fresh size.
        fresh: Option<u64>,
    },
    /// The sequence of token kinds in the decompilation differs.
    TokenKinds {
        /// Entry and name.
        at: String,
        /// Per-kind counts, committed.
        committed: String,
        /// Per-kind counts, fresh.
        fresh: String,
    },
    /// A function's listing, control-flow graph or references differ.
    FunctionData {
        /// Entry and name.
        at: String,
        /// `listing`, `cfg` or `xrefs`.
        what: &'static str,
        /// Counts and the first difference.
        detail: String,
    },
    /// Memory map, strings or symbols differ.
    ProgramData {
        /// `memory`, `strings`, `imports` or `exports`.
        what: &'static str,
        /// Counts and the first difference.
        detail: String,
    },
    /// A type is in the fresh recording only.
    TypeAdded(String),
    /// A type is in the committed fixture only.
    TypeRemoved(String),
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Drift::Program { committed, fresh } => {
                write!(f, "program: {committed} -> {fresh}")
            }
            Drift::FunctionAdded(a) => write!(f, "function added: {a}"),
            Drift::FunctionRemoved(a) => write!(f, "function removed: {a}"),
            Drift::Name {
                at,
                committed,
                fresh,
            } => write!(f, "{at}: name {committed:?} -> {fresh:?}"),
            Drift::Signature {
                at,
                committed,
                fresh,
            } => write!(f, "{at}: signature {committed:?} -> {fresh:?}"),
            Drift::Size {
                at,
                committed,
                fresh,
            } => write!(f, "{at}: size {committed:?} -> {fresh:?}"),
            Drift::TokenKinds {
                at,
                committed,
                fresh,
            } => write!(f, "{at}: token kinds {committed} -> {fresh}"),
            Drift::FunctionData { at, what, detail } => write!(f, "{at}: {what}: {detail}"),
            Drift::ProgramData { what, detail } => write!(f, "{what}: {detail}"),
            Drift::TypeAdded(n) => write!(f, "type added: {n}"),
            Drift::TypeRemoved(n) => write!(f, "type removed: {n}"),
        }
    }
}

fn key(l: &Locator) -> (String, u64) {
    match l {
        Locator::Native { space, offset } => (space.clone(), offset.0),
        _ => (String::new(), 0),
    }
}

fn addr(l: &Locator) -> String {
    let (space, off) = key(l);
    format!("{space}:{off:#x}")
}

fn kind_histogram(f: &FixtureFunction) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for t in &f.decompile.tokens {
        let k = serde_json::to_value(t.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        *counts.entry(k).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn kinds(f: &FixtureFunction) -> Vec<TokenKind> {
    f.decompile.tokens.iter().map(|t| t.kind).collect()
}

fn type_names(fx: &FixtureFile) -> Vec<String> {
    let mut v: Vec<String> = fx
        .types
        .iter()
        .filter_map(|t| kraken_engine::type_def_name(t).map(str::to_string))
        .collect();
    v.sort();
    v
}

fn index(fx: &FixtureFile) -> BTreeMap<(String, u64), &FixtureFunction> {
    fx.functions
        .iter()
        .map(|f| (key(&f.summary.locator), f))
        .collect()
}

/// Counts and the first difference of two recorded lists, or `None` when they are equal. An
/// absent list differs from a present one.
fn list_diff<T: PartialEq + fmt::Debug>(
    committed: Option<&[T]>,
    fresh: Option<&[T]>,
) -> Option<String> {
    match (committed, fresh) {
        (None, None) => None,
        (Some(a), Some(b)) if a == b => None,
        (Some(a), Some(b)) => {
            let at = a
                .iter()
                .zip(b)
                .position(|(x, y)| x != y)
                .unwrap_or(a.len().min(b.len()));
            let show = |l: &[T]| l.get(at).map_or("(none)".to_string(), |x| format!("{x:?}"));
            Some(format!(
                "{} -> {} items, first difference at index {at}: {} -> {}",
                a.len(),
                b.len(),
                show(a),
                show(b)
            ))
        }
        (Some(a), None) => Some(format!("{} items -> not recorded", a.len())),
        (None, Some(b)) => Some(format!("not recorded -> {} items", b.len())),
    }
}

/// The parts of a listing row that identify the code: address, bytes, mnemonic and flow.
fn listing_key(f: &FixtureFunction) -> Option<Vec<(u64, String, String, FlowKind)>> {
    f.disassembly.as_ref().map(|rows| {
        rows.iter()
            .map(|r| (r.address.0, r.bytes.clone(), r.mnemonic.clone(), r.flow))
            .collect()
    })
}

fn xref_key(f: &FixtureFunction) -> Option<Vec<(u64, u64, XrefKind)>> {
    f.xrefs
        .as_ref()
        .map(|x| x.iter().map(|x| (x.from.0, x.to.0, x.kind)).collect())
}

fn cfg_key(f: &FixtureFunction) -> Option<Vec<String>> {
    f.cfg.as_ref().map(|c| {
        let blocks = c
            .blocks
            .iter()
            .map(|b| format!("block {}..{} x{}", b.start, b.end, b.instructions));
        let edges = c
            .edges
            .iter()
            .map(|e| format!("edge {} -> {} {:?}", e.from, e.to, e.kind));
        blocks.chain(edges).collect()
    })
}

/// Compares the function set, names, signatures, sizes, decompile token kinds, type names, and
/// the recorded listing (address, bytes, mnemonic, flow), control-flow graph, references, memory
/// map, strings, imports and exports. Decompile text, token symbols, labels, operand text, hashes
/// and the Ghidra version header are deliberately ignored.
pub fn compare(committed: &FixtureFile, fresh: &FixtureFile) -> Vec<Drift> {
    let mut out = Vec::new();
    let (a, b) = (&committed.program, &fresh.program);
    if a != b {
        out.push(Drift::Program {
            committed: format!("{a:?}"),
            fresh: format!("{b:?}"),
        });
    }
    let (old, new) = (index(committed), index(fresh));
    for (k, f) in &old {
        let at = format!("{} {}", addr(&f.summary.locator), f.summary.name);
        let Some(g) = new.get(k) else {
            out.push(Drift::FunctionRemoved(at));
            continue;
        };
        if f.summary.name != g.summary.name {
            out.push(Drift::Name {
                at: addr(&f.summary.locator),
                committed: f.summary.name.clone(),
                fresh: g.summary.name.clone(),
            });
        }
        if f.summary.signature != g.summary.signature {
            out.push(Drift::Signature {
                at: at.clone(),
                committed: f.summary.signature.clone().unwrap_or_default(),
                fresh: g.summary.signature.clone().unwrap_or_default(),
            });
        }
        if f.summary.size != g.summary.size {
            out.push(Drift::Size {
                at: at.clone(),
                committed: f.summary.size,
                fresh: g.summary.size,
            });
        }
        if kinds(f) != kinds(g) {
            out.push(Drift::TokenKinds {
                at: at.clone(),
                committed: kind_histogram(f),
                fresh: kind_histogram(g),
            });
        }
        let data = [
            (
                "listing",
                list_diff(listing_key(f).as_deref(), listing_key(g).as_deref()),
            ),
            (
                "cfg",
                list_diff(cfg_key(f).as_deref(), cfg_key(g).as_deref()),
            ),
            (
                "xrefs",
                list_diff(xref_key(f).as_deref(), xref_key(g).as_deref()),
            ),
        ];
        for (what, detail) in data {
            if let Some(detail) = detail {
                out.push(Drift::FunctionData {
                    at: at.clone(),
                    what,
                    detail,
                });
            }
        }
    }
    for (k, g) in &new {
        if !old.contains_key(k) {
            out.push(Drift::FunctionAdded(format!(
                "{} {}",
                addr(&g.summary.locator),
                g.summary.name
            )));
        }
    }
    let program = [
        (
            "memory",
            list_diff(committed.memory.as_deref(), fresh.memory.as_deref()),
        ),
        (
            "strings",
            list_diff(committed.strings.as_deref(), fresh.strings.as_deref()),
        ),
        (
            "imports",
            list_diff(committed.imports.as_deref(), fresh.imports.as_deref()),
        ),
        (
            "exports",
            list_diff(committed.exports.as_deref(), fresh.exports.as_deref()),
        ),
    ];
    for (what, detail) in program {
        if let Some(detail) = detail {
            out.push(Drift::ProgramData { what, detail });
        }
    }
    let (ta, tb) = (type_names(committed), type_names(fresh));
    for n in ta.iter().filter(|n| !tb.contains(n)) {
        out.push(Drift::TypeRemoved(n.clone()));
    }
    for n in tb.iter().filter(|n| !ta.contains(n)) {
        out.push(Drift::TypeAdded(n.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = include_str!("../../engine-fake/fixtures/tiny.json");

    fn tiny() -> FixtureFile {
        FixtureFile::from_json(TINY).expect("tiny fixture")
    }

    #[test]
    fn identical_fixtures_do_not_drift() {
        assert!(compare(&tiny(), &tiny()).is_empty());
    }

    #[test]
    fn decompile_text_and_version_are_ignored() {
        let a = tiny();
        let mut b = tiny();
        b.ghidra_version = "99".into();
        b.functions[0].decompile.warnings.push("noise".into());
        assert!(compare(&a, &b).is_empty());
    }

    #[test]
    fn listing_and_program_data_drift_is_reported() {
        use kraken_proto::{DisasmRow, Hex64, MemoryBlock, MemoryKind};
        let row = |addr: u64, mnemonic: &str| DisasmRow {
            address: Hex64(addr),
            bytes: "90".into(),
            mnemonic: mnemonic.into(),
            operands: vec![],
            comment: None,
            labels: vec![],
            flow: FlowKind::Fallthrough,
        };
        let mut a = tiny();
        a.functions[0].disassembly = Some(vec![row(0x401000, "nop"), row(0x401001, "ret")]);
        a.memory = Some(vec![MemoryBlock {
            name: ".text".into(),
            space: "ram".into(),
            start: Hex64(0x401000),
            end: Hex64(0x402000),
            perms: "r-x".into(),
            initialized: true,
            kind: MemoryKind::Default,
        }]);
        assert!(compare(&a, &a.clone()).is_empty());
        let mut b = a.clone();
        b.functions[0].disassembly = Some(vec![row(0x401000, "nop"), row(0x401001, "hlt")]);
        b.memory.as_mut().expect("memory")[0].perms = "rwx".into();
        let drift = compare(&a, &b);
        assert!(drift.iter().any(|d| matches!(
            d,
            Drift::FunctionData { what: "listing", detail, .. } if detail.contains("index 1")
        )));
        assert!(
            drift
                .iter()
                .any(|d| matches!(d, Drift::ProgramData { what: "memory", .. }))
        );
        // present versus absent is a difference too
        b.functions[0].disassembly = None;
        assert!(compare(&a, &b).iter().any(|d| matches!(
            d,
            Drift::FunctionData { what: "listing", detail, .. } if detail.contains("not recorded")
        )));
    }

    #[test]
    fn structural_changes_are_reported() {
        let a = tiny();
        let mut b = tiny();
        b.functions[0].summary.name = "renamed".into();
        b.functions[1].summary.signature = Some("void x(void)".into());
        let removed = b.functions.pop().expect("a function");
        b.functions[0].decompile.tokens.pop();
        let drift = compare(&a, &b);
        assert!(drift.iter().any(|d| matches!(d, Drift::Name { .. })));
        assert!(drift.iter().any(|d| matches!(d, Drift::Signature { .. })));
        assert!(drift.iter().any(|d| matches!(d, Drift::TokenKinds { .. })));
        assert!(
            drift.iter().any(
                |d| matches!(d, Drift::FunctionRemoved(n) if n.contains(&removed.summary.name))
            )
        );
        let rev = compare(&b, &a);
        assert!(rev.iter().any(|d| matches!(d, Drift::FunctionAdded(_))));
    }
}
