//! Fixture file format and perturbation.

use std::path::PathBuf;

use kraken_engine::ProgramInfo;
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations};
use kraken_proto::{
    Completeness, DecompileResult, ErrorCode, FunctionSummary, Hex64, Locator, ProtoError, Token,
    TokenKind, TypeDef,
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
}

/// One function: its listing entry and its decompilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureFunction {
    /// Listing entry; `summary.locator` is the key.
    pub summary: FunctionSummary,
    /// Decompiler output; `decompile.function` must equal `summary.locator`.
    pub decompile: DecompileResult,
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
    let locator = Locator::ram(entry + half);
    let second = FixtureFunction {
        summary: FunctionSummary {
            locator: locator.clone(),
            name: name.clone(),
            size: Some(size - half),
            signature: Some(format!("void {name}(void)")),
            fn_hash: hash,
            completeness: Completeness::Complete,
        },
        decompile: stub_decompile(&locator, &name),
    };
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
}

fn shift(fx: &mut FixtureFile, delta: i64) {
    fn loc(l: &mut Locator, delta: i64) {
        if let Locator::Native { space, offset } = l
            && space == "ram"
        {
            offset.0 = offset.0.wrapping_add_signed(delta);
        }
    }
    fx.program.base.0 = fx.program.base.0.wrapping_add_signed(delta);
    for f in &mut fx.functions {
        loc(&mut f.summary.locator, delta);
        loc(&mut f.decompile.function, delta);
        for t in &mut f.decompile.tokens {
            if let Some(l) = t.target.as_mut() {
                loc(l, delta);
            }
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
