//! The offline glossary behind learn-mode tooltips (decision 20).
//!
//! Entries live in `data/glossary.toml`, compiled in. Look terms up exactly with
//! [`Glossary::get`] / [`Glossary::mnemonic`], or by typing with [`Glossary::lookup`], which
//! also forgives prefixes, substrings and small typos.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const BUILTIN: &str = include_str!("../data/glossary.toml");

/// What an entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlossaryKind {
    /// A reverse-engineering term.
    Concept,
    /// An instruction mnemonic of one architecture.
    Mnemonic,
}

/// Instruction set of a mnemonic entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// x86-64 (Intel/AMD 64-bit).
    X86_64,
    /// AArch64 (64-bit Arm).
    Aarch64,
}

impl Arch {
    /// Guesses the architecture from a Ghidra-style language id or a plain name
    /// (`x86:LE:64:default`, `AARCH64:LE:64:v8A`, `arm64`, `amd64`, ...).
    pub fn from_name(name: &str) -> Option<Arch> {
        let n = name.to_ascii_lowercase();
        if n.contains("aarch64") || n.contains("arm64") {
            Some(Arch::Aarch64)
        } else if n.contains("x86") || n.contains("amd64") || n.contains("x64") {
            Some(Arch::X86_64)
        } else {
            None
        }
    }
}

/// One glossary entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlossaryEntry {
    /// The term as displayed.
    pub term: String,
    /// Concept or mnemonic.
    pub kind: GlossaryKind,
    /// Instruction set, for mnemonics.
    #[serde(default)]
    pub arch: Option<Arch>,
    /// Other spellings and related words that find this entry.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One plain sentence.
    pub short: String,
    /// Optional longer explanation.
    #[serde(default)]
    pub note: Option<String>,
}

/// How a query matched an entry, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// The query is the entry's term.
    Exact,
    /// The query is one of the entry's aliases.
    Alias,
    /// The query is the start of the term or an alias.
    Prefix,
    /// The query appears inside the term or an alias.
    Substring,
    /// The query is within a couple of typos of the term or an alias.
    Fuzzy,
}

/// A lookup result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlossaryMatch {
    /// The entry.
    pub entry: GlossaryEntry,
    /// How it matched.
    pub how: MatchKind,
    /// Lower is better; ties break alphabetically by term.
    pub distance: u32,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    entry: Vec<GlossaryEntry>,
}

/// A set of entries with lookup.
#[derive(Debug, Clone)]
pub struct Glossary {
    entries: Vec<GlossaryEntry>,
    /// normalised term or alias -> indexes of entries
    index: BTreeMap<String, Vec<usize>>,
}

/// Lowercases and treats spaces, hyphens and underscores alike.
fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_sep = true;
    for c in s.trim().chars().flat_map(char::to_lowercase) {
        if c.is_whitespace() || c == '-' || c == '_' {
            if !last_sep {
                out.push(' ');
            }
            last_sep = true;
        } else {
            out.push(c);
            last_sep = false;
        }
    }
    out.trim_end().to_string()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

impl Glossary {
    /// The built-in glossary.
    pub fn builtin() -> &'static Glossary {
        static G: OnceLock<Glossary> = OnceLock::new();
        G.get_or_init(|| match Glossary::parse(BUILTIN) {
            Ok(g) => g,
            // The data file is compiled in and covered by tests; an empty glossary is the
            // harmless fallback.
            Err(_) => Glossary::from_entries(Vec::new()),
        })
    }

    /// Parses glossary TOML (`[[entry]]` tables).
    pub fn parse(text: &str) -> Result<Glossary, String> {
        let f: File = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(Glossary::from_entries(f.entry))
    }

    fn from_entries(entries: Vec<GlossaryEntry>) -> Glossary {
        let mut index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            index.entry(norm(&e.term)).or_default().push(i);
            for a in &e.aliases {
                let list = index.entry(norm(a)).or_default();
                if !list.contains(&i) {
                    list.push(i);
                }
            }
        }
        Glossary { entries, index }
    }

    /// Every entry.
    pub fn entries(&self) -> &[GlossaryEntry] {
        &self.entries
    }

    /// The concept entry for `term` (exact term or alias, case-insensitive). Mnemonics are not
    /// returned here; see [`mnemonic`](Self::mnemonic).
    pub fn get(&self, term: &str) -> Option<&GlossaryEntry> {
        self.index
            .get(&norm(term))?
            .iter()
            .map(|&i| &self.entries[i])
            .find(|e| e.kind == GlossaryKind::Concept)
    }

    /// The mnemonic entry for `mnemonic` on `arch` (`jne`, `b.eq`, `rep movsb`, ...).
    pub fn mnemonic(&self, arch: Arch, mnemonic: &str) -> Option<&GlossaryEntry> {
        let find = |m: &str| {
            self.index.get(&norm(m)).and_then(|v| {
                v.iter()
                    .map(|&i| &self.entries[i])
                    .find(|e| e.kind == GlossaryKind::Mnemonic && e.arch == Some(arch))
            })
        };
        let m = mnemonic.trim();
        find(m).or_else(|| {
            // `rep movsb`, `lock add`: the first word is the prefix; `movsb` -> `movs`.
            let first = m.split_whitespace().next()?;
            find(first).or_else(|| {
                let stem = first.trim_end_matches(['b', 'w', 'd', 'q']);
                (stem != first && !stem.is_empty())
                    .then(|| find(stem))
                    .flatten()
            })
        })
    }

    /// Finds entries for what a person typed: exact, alias, prefix, substring and fuzzy
    /// matches, best first. `limit` caps the number returned.
    pub fn lookup(&self, query: &str, limit: usize) -> Vec<GlossaryMatch> {
        let q = norm(query);
        if q.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut best: BTreeMap<usize, (MatchKind, u32)> = BTreeMap::new();
        let mut offer = |i: usize, how: MatchKind, d: u32| {
            let slot = best.entry(i).or_insert((how, d));
            if (how, d) < *slot {
                *slot = (how, d);
            }
        };
        let max_typos = match q.chars().count() {
            0..=3 => 0,
            4..=7 => 1,
            _ => 2,
        };
        for (i, e) in self.entries.iter().enumerate() {
            let term = norm(&e.term);
            if term == q {
                offer(i, MatchKind::Exact, 0);
            }
            let names = std::iter::once(term.clone()).chain(e.aliases.iter().map(|a| norm(a)));
            for n in names {
                if n == q {
                    if n != term {
                        offer(i, MatchKind::Alias, 0);
                    }
                } else if n.starts_with(&q) {
                    offer(i, MatchKind::Prefix, (n.len() - q.len()) as u32);
                } else if n.contains(&q) {
                    offer(i, MatchKind::Substring, (n.len() - q.len()) as u32);
                } else if max_typos > 0 {
                    let d = edit_distance(&n, &q);
                    if d <= max_typos {
                        offer(i, MatchKind::Fuzzy, d as u32);
                    }
                }
            }
        }
        let mut out: Vec<GlossaryMatch> = best
            .into_iter()
            .map(|(i, (how, distance))| GlossaryMatch {
                entry: self.entries[i].clone(),
                how,
                distance,
            })
            .collect();
        out.sort_by(|a, b| {
            (a.how, a.distance, &a.entry.term, a.entry.arch).cmp(&(
                b.how,
                b.distance,
                &b.entry.term,
                b.entry.arch,
            ))
        });
        out.truncate(limit);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_builtin_file_parses_and_is_big_enough() {
        let g = Glossary::parse(BUILTIN).expect("glossary.toml parses");
        let concepts = g
            .entries()
            .iter()
            .filter(|e| e.kind == GlossaryKind::Concept)
            .count();
        let x86 = g
            .entries()
            .iter()
            .filter(|e| e.arch == Some(Arch::X86_64))
            .count();
        let arm = g
            .entries()
            .iter()
            .filter(|e| e.arch == Some(Arch::Aarch64))
            .count();
        assert!(concepts >= 80, "{concepts} concepts");
        assert!(x86 >= 30, "{x86} x86-64 mnemonics");
        assert!(arm >= 30, "{arm} AArch64 mnemonics");
        assert_eq!(Glossary::builtin().entries().len(), g.entries().len());
    }

    #[test]
    fn entries_are_well_formed_and_unique() {
        let g = Glossary::builtin();
        let mut seen = BTreeSet::new();
        for e in g.entries() {
            assert!(
                seen.insert((
                    norm(&e.term),
                    e.kind == GlossaryKind::Mnemonic,
                    e.arch.map(|a| a as u8)
                )),
                "duplicate entry {}",
                e.term
            );
            assert!(
                e.short.trim().ends_with('.'),
                "{}: short ends in a period",
                e.term
            );
            assert!(
                e.short.len() >= 20 && e.short.len() <= 260,
                "{}: short length",
                e.term
            );
            assert!(!e.short.contains('\n'), "{}: short is one line", e.term);
            if let Some(n) = &e.note {
                assert!(!n.trim().is_empty(), "{}: note", e.term);
            }
            match e.kind {
                GlossaryKind::Mnemonic => assert!(e.arch.is_some(), "{}: arch", e.term),
                GlossaryKind::Concept => assert!(e.arch.is_none(), "{}: arch", e.term),
            }
        }
    }

    #[test]
    fn exact_alias_and_separators() {
        let g = Glossary::builtin();
        assert_eq!(
            g.get("Stack Frame").map(|e| e.term.as_str()),
            Some("stack frame")
        );
        assert_eq!(
            g.get("stack_frame").map(|e| e.term.as_str()),
            Some("stack frame")
        );
        assert_eq!(
            g.get("xref").map(|e| e.term.as_str()),
            Some("cross-reference")
        );
        assert_eq!(
            g.get("RIP").map(|e| e.term.as_str()),
            Some("program counter")
        );
        assert!(g.get("no such thing").is_none());
        // Mnemonics are not concepts.
        assert!(g.get("lea").is_none());
    }

    #[test]
    fn mnemonics_are_per_architecture() {
        let g = Glossary::builtin();
        let x = g.mnemonic(Arch::X86_64, "mov").expect("x86 mov");
        let a = g.mnemonic(Arch::Aarch64, "MOV").expect("arm mov");
        assert_ne!(x.short, a.short);
        assert_eq!(
            g.mnemonic(Arch::X86_64, "jne").map(|e| e.term.as_str()),
            Some("jcc")
        );
        assert_eq!(
            g.mnemonic(Arch::Aarch64, "b.eq").map(|e| e.term.as_str()),
            Some("b.cond")
        );
        assert_eq!(
            g.mnemonic(Arch::X86_64, "rep movsb")
                .map(|e| e.term.as_str()),
            Some("rep")
        );
        assert!(g.mnemonic(Arch::X86_64, "adrp").is_none());
        assert!(g.mnemonic(Arch::Aarch64, "adrp").is_some());
        assert!(g.mnemonic(Arch::Aarch64, "lea").is_none());
    }

    #[test]
    fn arch_names_from_language_ids() {
        assert_eq!(Arch::from_name("x86:LE:64:default"), Some(Arch::X86_64));
        assert_eq!(Arch::from_name("AARCH64:LE:64:v8A"), Some(Arch::Aarch64));
        assert_eq!(Arch::from_name("arm64"), Some(Arch::Aarch64));
        assert_eq!(Arch::from_name("riscv"), None);
    }

    #[test]
    fn fuzzy_lookup_ranks_exact_first_and_forgives_typos() {
        let g = Glossary::builtin();
        let r = g.lookup("stack", 5);
        assert_eq!(r[0].entry.term, "stack");
        assert_eq!(r[0].how, MatchKind::Exact);
        assert!(r.len() > 1, "prefix matches follow");
        let typo = g.lookup("decompilr", 3);
        assert_eq!(typo[0].entry.term, "decompiler");
        assert_eq!(typo[0].how, MatchKind::Fuzzy);
        let typo = g.lookup("dissasembler", 3);
        assert_eq!(typo[0].entry.term, "disassembler");
        assert_eq!(typo[0].how, MatchKind::Fuzzy);
        let sub = g.lookup("pointer", 10);
        assert!(sub.iter().any(|m| m.entry.term == "null pointer"));
        assert!(g.lookup("", 5).is_empty());
        assert!(g.lookup("zzzzqqqq", 5).is_empty());
    }
}
