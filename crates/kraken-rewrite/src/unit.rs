//! The rewrite-unit record (decision 46): one versioned artifact per translated function, linked
//! to a function anchor and carrying the source hash, the Rust code, the ABI, the oracle that
//! checked it, the test cases and the verdict.
//!
//! Units are persisted by [`crate::store::RewriteStore`] in `<project>/rewrite.sqlite`.

use kraken_registry::commands::{RewriteMode, UnitStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::abi::Signature;
use crate::difftest::{CaseRecord, Counterexample, DiffReport, Verdict};

/// Version of the record layout.
pub const UNIT_SCHEMA: u32 = 2;
/// Most stored test cases per unit (counterexamples are kept on top of these).
pub const MAX_STORED_CASES: usize = 256;

/// SHA-256 as lowercase hex.
pub fn sha256_hex(text: &str) -> String {
    sha256_bytes_hex(text.as_bytes())
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_bytes_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
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
    /// Set when the callee was not translated again but called as the Rust of an accepted unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused: Option<ReusedUnit>,
}

/// The accepted unit a callee was called as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReusedUnit {
    /// Id of the accepted version.
    pub unit: String,
    /// Its version number.
    pub version: u32,
    /// The Rust function it defines.
    pub symbol: String,
}

/// Where a version stands in a repair run: the first attempt has `attempt` 1 and no
/// `repair_of`; each later attempt answers the failure of the one before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairLink {
    /// Attempt number within the run, from 1.
    pub attempt: u32,
    /// Version number of the failed attempt this one answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_of: Option<u32>,
    /// What was fed back: `compile`, `rejected`, `counterexample` or `reply`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
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
    /// How the translation was made.
    #[serde(default)]
    pub mode: RewriteMode,
    /// Lifecycle status of this version.
    #[serde(default = "default_status")]
    pub status: UnitStatus,
    /// The stored spec a `spec` mode translation was made from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_id: Option<u64>,
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
    /// Repair-run bookkeeping; `None` for a version made outside a run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairLink>,
}

fn default_status() -> UnitStatus {
    UnitStatus::Translated
}

/// The status a verdict leads to: only a pass is `verified`; an inconclusive run leaves the unit
/// `translated`; a refused, uncompilable or disagreeing translation is `failed`.
pub fn status_for(verdict: &Verdict) -> UnitStatus {
    match verdict {
        Verdict::Pass => UnitStatus::Verified,
        Verdict::Fail | Verdict::Rejected { .. } => UnitStatus::Failed,
        Verdict::Inconclusive { .. } => UnitStatus::Translated,
    }
}

/// What a unit is made from, besides the code and the run.
#[derive(Debug, Clone)]
pub struct UnitSource {
    /// How the translation was made.
    pub mode: RewriteMode,
    /// The spec used, for `spec` mode.
    pub spec_id: Option<u64>,
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
            mode,
            spec_id,
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
            mode,
            status: status_for(&report.verdict),
            spec_id,
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
            repair: None,
        }
    }
}
