//! Structural comparison of two recordings of the same binary.

use std::collections::BTreeMap;
use std::fmt;

use engine_fake::{FixtureFile, FixtureFunction};
use kraken_proto::{Locator, TokenKind};

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

/// Compares the function set, names, signatures, sizes, decompile token kinds and type names.
/// Decompile text, token symbols, hashes and the Ghidra version header are deliberately ignored.
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
                at,
                committed: kind_histogram(f),
                fresh: kind_histogram(g),
            });
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
