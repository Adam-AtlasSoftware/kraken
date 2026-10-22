//! Registry-specific output types. Every binary- or engine-derived string is sanitised and
//! wrapped in [`Untrusted`].

use std::collections::BTreeMap;

use kraken_engine::ProgramInfo;
use kraken_model::{Author, AuthorKind, LogEntryView, ProposalView};
use kraken_proto::{
    CommentKind, Completeness, FunctionSummary, Hex64, Locator, LogOp, LogStatus, Provenance,
    SyncState, Untrusted, sanitize,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validate::untrusted;
use crate::views_data::TokenView;

/// Splits a locator into its address space and offset. A managed locator's metadata token is its
/// offset (in the default space); the module is [`locator_module`].
pub(crate) fn locator_parts(l: &Locator) -> (String, Hex64) {
    match l {
        Locator::Native { space, offset } => (space.clone(), *offset),
        Locator::Managed { token, .. } => {
            (kraken_proto::DEFAULT_SPACE.into(), Hex64(u64::from(*token)))
        }
        _ => (String::new(), Hex64(0)),
    }
}

/// The module (MVID) of a managed locator.
pub(crate) fn locator_module(l: &Locator) -> Option<String> {
    match l {
        Locator::Managed { module, .. } => Some(sanitize(module)),
        _ => None,
    }
}

fn space_if_not_ram(space: String) -> Option<String> {
    (space != kraken_proto::DEFAULT_SPACE).then(|| sanitize(&space))
}

/// Marks a completeness as partial while analysis is running.
pub(crate) fn adjust_completeness(c: Completeness, analysis_running: bool) -> Completeness {
    match c {
        Completeness::Complete if analysis_running => Completeness::Partial {
            reason: "analysis is still running".into(),
        },
        other => other,
    }
}

/// One function in a listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionView {
    /// Entry address; for a managed method, its metadata token.
    pub address: Hex64,
    /// Address space when it is not `ram`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    /// Module id (MVID) of a managed method. Send it back as `module` with the token in
    /// `address`. Absent for native code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
    /// Body size in bytes, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Rendered signature, if known (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Untrusted<String>>,
    /// How much analysis backs this entry.
    pub completeness: Completeness,
    /// The mangled symbol name when `name` is demangled (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mangled: Option<Untrusted<String>>,
}

impl FunctionView {
    pub(crate) fn from_summary(f: &FunctionSummary, analysis_running: bool) -> Self {
        let (space, address) = locator_parts(&f.locator);
        FunctionView {
            address,
            space: space_if_not_ram(space),
            module: locator_module(&f.locator),
            name: untrusted(&f.name),
            size: f.size,
            signature: f.signature.as_deref().map(untrusted),
            completeness: adjust_completeness(f.completeness.clone(), analysis_running),
            mangled: f.mangled.as_deref().map(untrusted),
        }
    }
}

/// A comment read back from the project log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CommentView {
    /// Which comment slot.
    pub kind: CommentKind,
    /// The text (may originate from binary content via an agent).
    pub text: Untrusted<String>,
}

/// One function with its annotations and entity versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionDetail {
    /// The listing fields.
    #[serde(flatten)]
    pub function: FunctionView,
    /// Calling convention set through KRAKEN, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
    /// Comments set through KRAKEN at this address.
    pub comments: Vec<CommentView>,
    /// Current version of each entity key at this address that has ever been written; pass these
    /// back as `expect_versions` on writes. Keys not listed have version 0.
    pub versions: BTreeMap<String, u64>,
}

/// One cross-reference found in decompiler output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceView {
    /// Symbol text at the reference (binary-derived).
    pub name: Untrusted<String>,
    /// Target address; for managed code, the metadata token.
    pub address: Hex64,
    /// Module id (MVID) of a managed target. Absent for native code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

/// Decompiler output, size-capped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecompileView {
    /// Function entry; for a managed method, its metadata token.
    pub address: Hex64,
    /// Module id (MVID) of a managed method. Absent for native code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Language tag such as `c` (`csharp` for managed code).
    pub language: String,
    /// Decompiled source (binary-derived), cut at 64 KiB.
    pub text: Untrusted<String>,
    /// True when `text` was cut.
    pub truncated: bool,
    /// Token spans into `text`: UTF-8 byte offsets, valid for exactly the returned text.
    pub tokens: Vec<TokenView>,
    /// Distinct call and data targets found in the output, capped.
    pub references: Vec<ReferenceView>,
    /// Decompiler warnings (binary-derived).
    pub warnings: Vec<Untrusted<String>>,
    /// How much analysis backs this result.
    pub completeness: Completeness,
}

/// Who made an edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorView {
    /// `user` or `agent`.
    pub kind: String,
    /// User name or agent id.
    pub id: String,
}

impl From<&Author> for AuthorView {
    fn from(a: &Author) -> Self {
        AuthorView {
            kind: match a.kind {
                AuthorKind::User => "user",
                AuthorKind::Agent => "agent",
            }
            .into(),
            id: sanitize(&a.id),
        }
    }
}

/// What a mutation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MutationStatus {
    /// Logged and pushed to the engine.
    Applied,
    /// Logged but waiting for analysis to finish before it is pushed.
    Queued,
    /// Not applied; waiting for a user to accept it.
    Proposed,
}

/// Result of every edit command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MutationOutput {
    /// `applied`, `queued` or `proposed`.
    pub status: MutationStatus,
    /// Log entry id (applied and queued).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<u64>,
    /// Proposal id (proposed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<u64>,
    /// Entity key the edit wrote.
    pub key: String,
    /// New version of the written key (applied and queued).
    pub versions: BTreeMap<String, u64>,
    /// For proposals, why the edit was not auto-applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn op_kind(op: &LogOp) -> &'static str {
    match op {
        LogOp::Rename { .. } => "rename",
        LogOp::SetType { .. } => "set_type",
        LogOp::SetComment { .. } => "set_comment",
        LogOp::CreateFunction { .. } => "create_function",
        LogOp::DeleteFunction { .. } => "delete_function",
        LogOp::SetFunctionBounds { .. } => "set_function_bounds",
        LogOp::SetCodeData { .. } => "set_code_data",
        LogOp::SetCallingConvention { .. } => "set_calling_convention",
        LogOp::SetPatch { .. } => "set_patch",
    }
}

fn op_address(op: &LogOp) -> Option<Hex64> {
    let anchor = kraken_model::op_anchor(op);
    match anchor.native() {
        Ok((_, offset, _, _)) => Some(offset),
        Err(_) => anchor
            .managed_parts()
            .map(|(_, token)| Hex64(u64::from(token))),
    }
}

fn describe_op(op: &LogOp) -> String {
    let addr = op_address(op).map(|a| a.to_hex()).unwrap_or_default();
    let detail = match op {
        LogOp::Rename {
            old_name, new_name, ..
        } => format!("{} -> {new_name}", old_name.as_deref().unwrap_or("?")),
        LogOp::SetType { new, .. } => serde_json::to_string(new).unwrap_or_default(),
        LogOp::SetComment {
            comment_kind, new, ..
        } => format!(
            "{comment_kind:?}: {}",
            new.as_deref().unwrap_or("<cleared>")
        ),
        LogOp::CreateFunction { name, .. } => name.clone().unwrap_or_default(),
        LogOp::DeleteFunction { .. } => String::new(),
        LogOp::SetFunctionBounds { new, .. } => format!("{}..{}", new.start, new.end),
        LogOp::SetCodeData { new, .. } => format!("{new:?}"),
        LogOp::SetCallingConvention { new, .. } => new.clone(),
        LogOp::SetPatch {
            original, old, new, ..
        } => match new {
            Some(b) => {
                let mut d = format!("{original} -> {}", b.replacement);
                if !b.note.is_empty() {
                    d.push_str(&format!(": {}", b.note));
                }
                d
            }
            None => format!(
                "removed (was {})",
                old.as_ref().map_or("?", |b| b.replacement.as_str())
            ),
        },
    };
    let text = format!("{} {addr} {detail}", op_kind(op));
    let (cut, _) = crate::validate::truncate_utf8(text, 400);
    cut.trim().to_string()
}

/// One log entry as shown by `history`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryEntryView {
    /// Entry id.
    pub id: u64,
    /// Operation name such as `rename`.
    pub op: String,
    /// Address the operation applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// One-line rendering of the operation (may contain binary-derived text).
    pub description: Untrusted<String>,
    /// Who made the edit.
    pub author: AuthorView,
    /// Run the edit belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Where the content came from.
    pub provenance: Provenance,
    /// Applied, rejected or orphaned.
    pub status: LogStatus,
    /// Whether the engine has the edit.
    pub sync: SyncState,
    /// For a compensating entry, the entry it reverses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undoes_entry_id: Option<u64>,
    /// The entry that reversed this one, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_by: Option<u64>,
    /// Creation time, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

impl From<&LogEntryView> for HistoryEntryView {
    fn from(e: &LogEntryView) -> Self {
        HistoryEntryView {
            id: e.id.0,
            op: op_kind(&e.op.op).into(),
            address: op_address(&e.op.op),
            description: untrusted(&describe_op(&e.op.op)),
            author: (&e.author).into(),
            run_id: e.run_id.as_ref().map(|r| sanitize(&r.0)),
            provenance: e.provenance,
            status: e.status.clone(),
            sync: e.sync.clone(),
            undoes_entry_id: e.undoes_entry_id.map(|i| i.0),
            undone_by: e.undone_by.map(|i| i.0),
            ts_ms: e.ts_ms,
        }
    }
}

/// An open or resolved proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposalOut {
    /// Proposal id.
    pub id: u64,
    /// Run that produced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Who proposed it.
    pub author: AuthorView,
    /// Operation name such as `rename`.
    pub op: String,
    /// Address the operation applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// One-line rendering of the operation (may contain binary-derived text).
    pub description: Untrusted<String>,
    /// Why it was not auto-applied.
    pub reason: String,
    /// `open`, `accepted` or `rejected`.
    pub status: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

impl From<&ProposalView> for ProposalOut {
    fn from(p: &ProposalView) -> Self {
        ProposalOut {
            id: p.id.0,
            run_id: p.run_id.as_ref().map(|r| sanitize(&r.0)),
            author: (&p.author).into(),
            op: op_kind(&p.op.op).into(),
            address: op_address(&p.op.op),
            description: untrusted(&describe_op(&p.op.op)),
            reason: p.reason.clone(),
            status: p.status.as_str().into(),
            ts_ms: p.ts_ms,
        }
    }
}

/// Facts about the loaded program (engine-derived strings are sanitised).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramView {
    /// Architecture / language id.
    pub arch: String,
    /// Container format.
    pub format: String,
    /// Image base.
    pub base: Hex64,
    /// SHA-256 as reported by the engine.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// What the file is, in plain words (`Linux static library with 2 objects`); absent when
    /// the engine does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The members of a static or import library, in file order (at most
    /// [`ProgramView::MAX_MEMBERS`]); all of a static library's members are loaded together.
    /// Names come from the file, so they are untrusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Untrusted<String>>,
    /// How many members the library has; absent for other files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
}

impl ProgramView {
    /// How many member names the view lists.
    pub const MAX_MEMBERS: usize = 200;
}

impl From<&ProgramInfo> for ProgramView {
    fn from(p: &ProgramInfo) -> Self {
        ProgramView {
            arch: sanitize(&p.arch),
            format: sanitize(&p.format),
            base: p.base,
            sha256: sanitize(&p.sha256),
            size: p.size,
            description: p.description.as_deref().map(sanitize),
            members: p
                .members
                .iter()
                .take(Self::MAX_MEMBERS)
                .map(|m| Untrusted::sanitized(m))
                .collect(),
            member_count: (!p.members.is_empty()).then_some(p.members.len() as u64),
        }
    }
}
