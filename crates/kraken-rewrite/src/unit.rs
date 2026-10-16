//! The rewrite-unit record (decision 46): one versioned artifact per translated function, linked
//! to a function anchor and carrying the source hash, the Rust code, the ABI, the oracle that
//! checked it, the test cases and the verdict.
//!
//! For the spike units live in a JSON file under the project directory
//! (`<project>/rewrite/units.json`); the DB migration comes with the pipeline proper.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::abi::Signature;
use crate::difftest::{CaseRecord, Counterexample, DiffReport, Verdict};
use crate::error::RewriteError;

/// Version of the record layout.
pub const UNIT_SCHEMA: u32 = 1;
/// Most stored test cases per unit (counterexamples are kept on top of these).
pub const MAX_STORED_CASES: usize = 256;

/// SHA-256 as lowercase hex.
pub fn sha256_hex(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What the unit is attached to: a function of a specific program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAnchor {
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// Address space (`ram`).
    pub space: String,
    /// Entry address as KRAKEN reports it (`0x...`, includes the image base).
    pub address: String,
    /// The function's name when the record was made (informational; the address is the key).
    pub name: String,
}

/// A callee whose decompile the translation was made from as well.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalleeRef {
    /// Name when the record was made.
    pub name: String,
    /// Entry address.
    pub address: String,
    /// SHA-256 of its decompile text.
    pub decompile_hash: String,
}

/// Where the Rust code came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// `reference` (hand-written, checked in) or `model`.
    pub author: String,
    /// Provider id, for a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model name, for a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Task kind that produced it.
    pub task: String,
    /// SHA-256 of the prompt (system and user message).
    pub prompt_hash: String,
}

/// What checked the translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleInfo {
    /// Oracle kind, for example `icicle-emu/x86-64-sleigh`.
    pub kind: String,
    /// Emulator pin.
    pub emulator: String,
    /// Binary file name the original ran from.
    pub binary: String,
    /// The function's ELF virtual address in that binary.
    pub elf_vaddr: u64,
}

/// Counts from the differential run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    /// Seed of the random cases.
    pub seed: u64,
    /// Cases run on both sides.
    pub cases_run: usize,
    /// Cases that agreed.
    pub passed: usize,
    /// Cases the oracle could not evaluate.
    pub skipped: usize,
    /// How the translation was confined.
    pub sandbox: String,
}

/// One versioned rewrite unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteUnit {
    /// Record layout version ([`UNIT_SCHEMA`]).
    pub schema: u32,
    /// Stable id of this exact (anchor, source, code).
    pub id: String,
    /// 1, 2, ... per anchor address.
    pub version: u32,
    /// The function this is for.
    pub anchor: FunctionAnchor,
    /// SHA-256 of the decompile text the translation was made from.
    pub source_decompile_hash: String,
    /// Callees translated together with the function.
    #[serde(default)]
    pub callees: Vec<CalleeRef>,
    /// The Rust code.
    pub rust_code: String,
    /// SHA-256 of the Rust code.
    pub rust_code_hash: String,
    /// The ABI the code is checked at.
    pub signature: Signature,
    /// The Rust declaration that signature maps to.
    pub rust_prototype: String,
    /// Who wrote it.
    pub provenance: Provenance,
    /// What checked it.
    pub oracle: OracleInfo,
    /// The cases and the oracle's expected results.
    pub test_cases: Vec<CaseRecord>,
    /// Counts.
    pub summary: RunSummary,
    /// Disagreements found, if any.
    pub counterexamples: Vec<Counterexample>,
    /// The verdict.
    pub verdict: Verdict,
}

/// What a unit is made from, besides the code and the run.
#[derive(Debug, Clone)]
pub struct UnitSource {
    /// The function.
    pub anchor: FunctionAnchor,
    /// SHA-256 of its decompile text.
    pub source_decompile_hash: String,
    /// Callees translated with it.
    pub callees: Vec<CalleeRef>,
    /// The ABI.
    pub signature: Signature,
    /// Who wrote the code.
    pub provenance: Provenance,
    /// What checked it.
    pub oracle: OracleInfo,
}

impl RewriteUnit {
    /// Builds a record (version 0 until stored) from a differential run.
    pub fn from_run(source: UnitSource, rust_code: String, report: DiffReport) -> Self {
        let UnitSource {
            anchor,
            source_decompile_hash,
            callees,
            signature,
            provenance,
            oracle,
        } = source;
        let rust_code_hash = sha256_hex(&rust_code);
        let id = format!(
            "ru-{}",
            &sha256_hex(&format!(
                "{}|{}|{}|{}",
                anchor.program_sha256, anchor.address, source_decompile_hash, rust_code_hash
            ))[..16]
        );
        let summary = RunSummary {
            seed: report.seed,
            cases_run: report.cases_run,
            passed: report.passed,
            skipped: report.skipped,
            sandbox: report.sandbox.clone(),
        };
        // Keep an even spread of cases rather than only the first ones.
        let total = report.cases.len();
        let step = total.div_ceil(MAX_STORED_CASES).max(1);
        let test_cases: Vec<CaseRecord> = report.cases.into_iter().step_by(step).collect();
        let rust_prototype = signature.rust_prototype();
        RewriteUnit {
            schema: UNIT_SCHEMA,
            id,
            version: 0,
            anchor,
            source_decompile_hash,
            callees,
            rust_code,
            rust_code_hash,
            signature,
            rust_prototype,
            provenance,
            oracle,
            test_cases,
            summary,
            counterexamples: report.counterexamples,
            verdict: report.verdict,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    schema: u32,
    units: Vec<RewriteUnit>,
}

/// A JSON file of units.
#[derive(Debug, Clone)]
pub struct UnitStore {
    path: PathBuf,
}

impl UnitStore {
    /// The store of a project directory: `<project>/rewrite/units.json`.
    pub fn in_project(project_dir: &Path) -> Self {
        UnitStore {
            path: project_dir.join("rewrite").join("units.json"),
        }
    }

    /// A store at an explicit file.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        UnitStore { path: path.into() }
    }

    /// The file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<StoreFile, RewriteError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                let f: StoreFile = serde_json::from_str(&text)
                    .map_err(|e| RewriteError::Store(format!("{}: {e}", self.path.display())))?;
                if f.schema != UNIT_SCHEMA {
                    return Err(RewriteError::Store(format!(
                        "unit store schema {} is not supported (expected {UNIT_SCHEMA})",
                        f.schema
                    )));
                }
                Ok(f)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreFile {
                schema: UNIT_SCHEMA,
                units: Vec::new(),
            }),
            Err(e) => Err(RewriteError::Store(format!("{}: {e}", self.path.display()))),
        }
    }

    /// Every unit, oldest first.
    pub fn list(&self) -> Result<Vec<RewriteUnit>, RewriteError> {
        Ok(self.read()?.units)
    }

    /// The newest unit for the function at `address`.
    pub fn latest(&self, address: &str) -> Result<Option<RewriteUnit>, RewriteError> {
        Ok(self
            .read()?
            .units
            .into_iter()
            .filter(|u| u.anchor.address == address)
            .max_by_key(|u| u.version))
    }

    /// Appends a unit as the next version for its anchor and returns it. Older versions stay.
    pub fn put(&self, mut unit: RewriteUnit) -> Result<RewriteUnit, RewriteError> {
        let mut file = self.read()?;
        unit.version = file
            .units
            .iter()
            .filter(|u| u.anchor.address == unit.anchor.address)
            .map(|u| u.version)
            .max()
            .unwrap_or(0)
            + 1;
        file.units.push(unit.clone());
        let text =
            serde_json::to_string_pretty(&file).map_err(|e| RewriteError::Store(e.to_string()))?;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| RewriteError::Store("store path has no parent".into()))?;
        std::fs::create_dir_all(dir).map_err(|e| RewriteError::Store(e.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| RewriteError::Store(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| RewriteError::Store(e.to_string()))?;
        Ok(unit)
    }
}
