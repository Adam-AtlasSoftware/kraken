//! Typed views of the registry's JSON outputs. Lenient on purpose: unknown fields are ignored so
//! a newer daemon does not break an older GUI.

use std::collections::BTreeMap;

use kraken_proto::{CommentKind, Completeness, Hex64, Page, Untrusted};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FunctionWire {
    pub address: Hex64,
    pub name: Untrusted<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub signature: Option<Untrusted<String>>,
    #[serde(default = "complete")]
    pub completeness: Completeness,
}

fn complete() -> Completeness {
    Completeness::Complete
}

pub(crate) type FunctionPage = Page<FunctionWire>;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CommentWire {
    pub kind: CommentKind,
    pub text: Untrusted<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DetailWire {
    #[serde(flatten)]
    pub function: FunctionWire,
    #[serde(default)]
    pub calling_convention: Option<String>,
    #[serde(default)]
    pub comments: Vec<CommentWire>,
    #[serde(default)]
    pub versions: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReferenceWire {
    pub name: Untrusted<String>,
    pub address: Hex64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DecompileWire {
    #[serde(default)]
    pub language: String,
    pub text: Untrusted<String>,
    #[serde(default)]
    pub truncated: bool,
    /// Server-made token spans (UTF-8 byte offsets into `text`); absent on older daemons.
    #[serde(default)]
    pub tokens: Vec<crate::views::TokenWire>,
    #[serde(default)]
    pub references: Vec<ReferenceWire>,
    #[serde(default)]
    pub warnings: Vec<Untrusted<String>>,
    #[serde(default = "complete")]
    pub completeness: Completeness,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AuthorWire {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HistoryWire {
    pub id: u64,
    pub op: String,
    #[serde(default)]
    pub address: Option<Hex64>,
    pub description: Untrusted<String>,
    pub author: AuthorWire,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub status: Value,
    #[serde(default)]
    pub sync: Value,
    #[serde(default)]
    pub undoes_entry_id: Option<u64>,
    #[serde(default)]
    pub undone_by: Option<u64>,
    #[serde(default)]
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProposalWire {
    pub id: u64,
    #[serde(default)]
    pub run_id: Option<String>,
    pub author: AuthorWire,
    pub op: String,
    #[serde(default)]
    pub address: Option<Hex64>,
    pub description: Untrusted<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MutationWire {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UndoWire {
    pub status: String,
    #[serde(default)]
    pub undone_entry_ids: Vec<u64>,
    #[serde(default)]
    pub failed: Vec<Value>,
    #[serde(default)]
    pub tainted: Vec<Hex64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AnalyzeWire {
    pub job_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProgramWire {
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AnalysisWire {
    pub phase: String,
    #[serde(default)]
    pub function_count: Option<u64>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProjectWire {
    #[serde(default)]
    pub project_dir: String,
    #[serde(default)]
    pub binary_path: String,
    pub program: ProgramWire,
    #[serde(default)]
    pub engine_build: String,
    #[serde(default)]
    pub epoch_stale: bool,
    pub analysis: AnalysisWire,
    #[serde(default)]
    pub pending_entries: u64,
    #[serde(default)]
    pub log_entries: u64,
    #[serde(default)]
    pub open_proposals: u64,
}
