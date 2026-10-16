//! Fixture file format and perturbation.

use std::path::PathBuf;

use kraken_engine::ProgramInfo;
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations};
use kraken_proto::{
    Cfg, Completeness, DecompileResult, DisasmRow, ErrorCode, FunctionRef, FunctionSummary, Hex64,
    Locator, MemoryBlock, ProtoError, StringEntry, SymbolEntry, Token, TokenKind, TypeDef, Xref,
};
use serde::{Deserialize, Serialize};

/// A whole fixture: what a recorded engine session knew about one program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureFile {
    /// Version of the Ghidra build the fixture was recorded with (free-form).
    pub ghidra_version: String,
    /// What the loader reports for the program.
    pub program: ProgramInfo,
    /// Functions, in any order; the engine sorts them by (space, offset).
    pub functions: Vec<FixtureFunction>,
    /// Named types known to the program.
    #[serde(default)]
    pub types: Vec<TypeDef>,
    /// Memory blocks; absent means four synthetic blocks derived from the functions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Vec<MemoryBlock>>,
    /// Strings in memory; absent means string literals found in the decompiled text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<StringEntry>>,
    /// Imported symbols; absent means call targets that are not functions of the fixture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<SymbolEntry>>,
    /// Exported symbols; absent means the lowest function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports: Option<Vec<SymbolEntry>>,
    /// How the fixture was recorded, when a recorder wrote it (absent in hand-written fixtures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording: Option<Recording>,
}

/// Provenance and caps of a recorded fixture (written by `kraken-record`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recording {
    /// Recorder name and version.
    pub recorder: String,
    /// Maximum number of functions recorded.
    pub function_cap: usize,
    /// Functions the engine listed.
    pub functions_listed: usize,
    /// Functions in this file.
    pub functions_recorded: usize,
    /// Listed functions skipped because they could not be decompiled (externals, failures).
    pub functions_skipped: usize,
    /// Maximum number of types recorded.
    pub type_cap: usize,
    /// Types the engine listed.
    pub types_listed: usize,
    /// Types in this file.
    pub types_recorded: usize,
    /// Maximum number of strings recorded (strings referenced by recorded functions come first).
    #[serde(default)]
    pub string_cap: usize,
    /// Strings of at least four characters the engine listed.
    #[serde(default)]
    pub strings_listed: usize,
    /// Strings in this file.
    #[serde(default)]
    pub strings_recorded: usize,
}

/// One function: its listing entry and its decompilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureFunction {
    /// Listing entry; `summary.locator` is the key.
    pub summary: FunctionSummary,
    /// Decompiler output; `decompile.function` must equal `summary.locator`.
    pub decompile: DecompileResult,
    /// Instructions of the body in address order; absent means a synthetic listing of four-byte
    /// instructions with calls at the decompiled call targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<DisasmRow>>,
    /// Control-flow graph; absent means one block spanning the listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cfg: Option<Cfg>,
    /// References originating in the body (and any to the entry the recorder kept); absent means
    /// references derived from the call and jump rows of the listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<Vec<Xref>>,
}

impl FixtureFunction {
    /// A function with only a summary and a decompilation.
    pub fn new(summary: FunctionSummary, decompile: DecompileResult) -> Self {
        FixtureFunction {
            summary,
            decompile,
            disassembly: None,
            cfg: None,
            xrefs: None,
        }
    }
}

impl FixtureFile {
    /// Parses a fixture from JSON text.
    pub fn from_json(s: &str) -> Result<Self, ProtoError> {
        serde_json::from_str(s).map_err(|e| {
            ProtoError::new(ErrorCode::InvalidArgument, format!("bad fixture json: {e}"))
        })
    }

    /// Reads a fixture from a JSON file.
    pub fn from_path(path: &std::path::Path) -> Result<Self, ProtoError> {
        let s = std::fs::read_to_string(path).map_err(|e| {
            ProtoError::new(ErrorCode::NotFound, format!("{}: {e}", path.display()))
        })?;
        Self::from_json(&s)
    }

    /// Pretty-printed JSON with a trailing newline.
    pub fn to_json(&self) -> Result<String, ProtoError> {
        let mut s = serde_json::to_string_pretty(self)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        s.push('\n');
        Ok(s)
    }

    /// What the contract suite should expect from an engine built from this fixture. The scratch
    /// address lies past the end of every function.
    pub fn expectations(&self, binary_path: impl Into<PathBuf>) -> FixtureExpectations {
        let mut functions: Vec<(String, u64, ExpectedFunction)> = self
            .functions
            .iter()
            .map(|f| {
                let (space, off) = key_of(&f.summary.locator);
                (
                    space,
                    off,
                    ExpectedFunction {
                        locator: f.summary.locator.clone(),
                        name: f.summary.name.clone(),
                    },
                )
            })
            .collect();
        functions.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        let end = self
            .functions
            .iter()
            .map(|f| key_of(&f.summary.locator).1 + f.summary.size.unwrap_or(1))
            .max()
            .unwrap_or(self.program.base.0);
        FixtureExpectations {
            binary_path: binary_path.into(),
            program: self.program.clone(),
            functions: functions.into_iter().map(|t| t.2).collect(),
            rename_to: "kraken_renamed_fn".into(),
            scratch: Locator::ram((end + 0x1000) & !0xfff),
        }
    }
}

pub(crate) fn key_of(l: &Locator) -> (String, u64) {
    match l {
        Locator::Native { space, offset } => (space.clone(), offset.0),
        _ => (String::new(), 0),
    }
}

/// Deterministic perturbation of a fixture (decision 49), to test anchors and replay.
///
/// Steps, with addresses given in the fixture's original `ram` coordinates:
/// 1. `split`: the function with that entry and a size of at least 2 is cut in half. The first half
///    keeps the name, hash and decompilation (plus a warning); the second half starts at
///    `entry + size / 2`, is named `<name>_part2`, has hash `<hash>:part2` and a stub decompilation.
/// 2. `merge`: `(a, b)` removes function `b` and extends `a` to the end of `b`.
/// 3. `base_shift`: every `ram` address (program base, locators, token targets) moves by this amount.
///
/// Unknown entries are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Perturb {
    /// Signed shift applied to every `ram` address after splits and merges.
    #[serde(default)]
    pub base_shift: i64,
    /// Entries of functions to split in two.
    #[serde(default)]
    pub split: Vec<Hex64>,
    /// `(keep, absorb)` pairs: `absorb` is merged into `keep`.
    #[serde(default)]
    pub merge: Vec<(Hex64, Hex64)>,
}

impl Perturb {
    /// Returns the perturbed copy of `fixture`.
    pub fn apply(&self, fixture: &FixtureFile) -> FixtureFile {
        let mut out = fixture.clone();
        for at in &self.split {
            split(&mut out, at.0);
        }
        for (keep, absorb) in &self.merge {
            merge(&mut out, keep.0, absorb.0);
        }
        if self.base_shift != 0 {
            shift(&mut out, self.base_shift);
        }
        out
    }
}

fn find(fx: &FixtureFile, entry: u64) -> Option<usize> {
    fx.functions
        .iter()
        .position(|f| key_of(&f.summary.locator) == ("ram".to_string(), entry))
}

fn split(fx: &mut FixtureFile, entry: u64) {
    let Some(i) = find(fx, entry) else { return };
    let size = match fx.functions[i].summary.size {
        Some(s) if s >= 2 => s,
        _ => return,
    };
    let half = size / 2;
    let first = &mut fx.functions[i];
    first.summary.size = Some(half);
    first
        .decompile
        .warnings
        .push("function was split by perturbation".into());
    let name = format!("{}_part2", first.summary.name);
    let hash = first.summary.fn_hash.as_ref().map(|h| format!("{h}:part2"));
    let cut = entry + half;
    let locator = Locator::ram(cut);
    let mut second = FixtureFunction::new(
        FunctionSummary {
            locator: locator.clone(),
            name: name.clone(),
            size: Some(size - half),
            signature: Some(format!("void {name}(void)")),
            fn_hash: hash,
            completeness: Completeness::Complete,
        },
        stub_decompile(&locator, &name),
    );
    // Recorded listing data follows the cut; graphs and derived references are recomputed.
    if let Some(rows) = first.disassembly.take() {
        let (head, tail): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| r.address.0 < cut);
        first.disassembly = Some(head);
        second.disassembly = (!tail.is_empty()).then_some(tail);
    }
    first.cfg = None;
    if let Some(x) = first.xrefs.as_mut() {
        x.retain(|x| x.from.0 < cut);
    }
    fx.functions.push(second);
}

fn merge(fx: &mut FixtureFile, keep: u64, absorb: u64) {
    let (Some(a), Some(b)) = (find(fx, keep), find(fx, absorb)) else {
        return;
    };
    if a == b {
        return;
    }
    let absorbed = fx.functions.remove(b);
    let a = if b < a { a - 1 } else { a };
    let keep_fn = &mut fx.functions[a];
    if let (Some(sa), Some(sb)) = (keep_fn.summary.size, absorbed.summary.size) {
        let end = (absorb + sb).max(keep + sa);
        keep_fn.summary.size = Some(end - keep);
    }
    keep_fn
        .decompile
        .warnings
        .push("function was merged by perturbation".into());
    keep_fn.disassembly = match (keep_fn.disassembly.take(), absorbed.disassembly) {
        (Some(mut a), Some(b)) => {
            a.extend(b);
            a.sort_by_key(|r| r.address);
            Some(a)
        }
        _ => None,
    };
    keep_fn.cfg = None;
    keep_fn.xrefs = None;
}

fn shift(fx: &mut FixtureFile, delta: i64) {
    fn loc(l: &mut Locator, delta: i64) {
        if let Locator::Native { space, offset } = l
            && space == "ram"
        {
            offset.0 = offset.0.wrapping_add_signed(delta);
        }
    }
    let hex = |h: &mut Hex64| h.0 = h.0.wrapping_add_signed(delta);
    let func_ref = |r: &mut Option<FunctionRef>| {
        if let Some(r) = r {
            r.address.0 = r.address.0.wrapping_add_signed(delta);
        }
    };
    fx.program.base.0 = fx.program.base.0.wrapping_add_signed(delta);
    for f in &mut fx.functions {
        loc(&mut f.summary.locator, delta);
        loc(&mut f.decompile.function, delta);
        for t in &mut f.decompile.tokens {
            if let Some(l) = t.target.as_mut() {
                loc(l, delta);
            }
        }
        for row in f.disassembly.iter_mut().flatten() {
            hex(&mut row.address);
            for op in &mut row.operands {
                if let Some(l) = op.target.as_mut() {
                    loc(l, delta);
                }
            }
        }
        if let Some(c) = f.cfg.as_mut() {
            hex(&mut c.function);
            for b in &mut c.blocks {
                hex(&mut b.start);
                hex(&mut b.end);
            }
            for e in &mut c.edges {
                hex(&mut e.from);
                hex(&mut e.to);
            }
        }
        for x in f.xrefs.iter_mut().flatten() {
            hex(&mut x.from);
            hex(&mut x.to);
            func_ref(&mut x.from_function);
            func_ref(&mut x.to_function);
        }
    }
    for b in fx.memory.iter_mut().flatten() {
        if b.space == "ram" {
            hex(&mut b.start);
            hex(&mut b.end);
        }
    }
    for s in fx.strings.iter_mut().flatten() {
        hex(&mut s.address);
    }
    for s in fx.imports.iter_mut().chain(fx.exports.iter_mut()).flatten() {
        if let Some(a) = s.address.as_mut() {
            hex(a);
        }
    }
}

/// A minimal decompilation `void <name>(void) { return; }` with type and function tokens.
pub(crate) fn stub_decompile(locator: &Locator, name: &str) -> DecompileResult {
    let text = format!("void {name}(void)\n{{\n  return;\n}}\n");
    let tokens = vec![
        Token {
            start: 0,
            end: 4,
            kind: TokenKind::Type,
            target: None,
            symbol: Some("void".into()),
            varnode: None,
        },
        Token {
            start: 5,
            end: 5 + name.len() as u32,
            kind: TokenKind::Function,
            target: Some(locator.clone()),
            symbol: Some(name.to_string()),
            varnode: None,
        },
    ];
    DecompileResult {
        function: locator.clone(),
        language: kraken_proto::LANGUAGE_C.into(),
        text,
        tokens,
        warnings: Vec::new(),
        completeness: Completeness::Complete,
    }
}
