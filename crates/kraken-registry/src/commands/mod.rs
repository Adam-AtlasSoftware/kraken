//! The 0.1a commands and the `rewrite_*` commands.

use kraken_proto::{Hex64, Locator, PageRequest};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::command::Registry;

mod data;
mod edit;
mod history;
mod jobs;
mod project;
mod query;
mod rebuild;
mod rewrite;
mod undo_entry;

pub use data::{
    CallGraphArgs, Callees, Callers, CfgArgs, CfgCommand, CfgOut, Disassemble, DisassembleArgs,
    Exports, Imports, MemoryMap, MemoryMapOut, ReadBytes, ReadBytesArgs, ReadBytesOut, Strings,
    StringsArgs, SymbolsArgs, Xrefs, XrefsArgs,
};
pub use edit::{
    CreateFunction, CreateFunctionArgs, DeleteFunction, DeleteFunctionArgs, ProposalAccept,
    ProposalIdArgs, ProposalReject, RenameSymbol, RenameSymbolArgs, SetCallingConvention,
    SetCallingConventionArgs, SetComment, SetCommentArgs, SetFunctionBounds, SetFunctionBoundsArgs,
    SetType, SetTypeArgs, Undo, UndoOut, UndoRun, UndoRunArgs,
};
pub use history::{History, HistoryArgs, ProposalFilter, ProposalsList, ProposalsListArgs};
pub use jobs::{
    Analyze, AnalyzeOut, AnalyzeResult, JobAwait, JobAwaitArgs, JobCancel, JobIdArgs, JobStatus,
    JobView,
};
pub use project::{
    AnalysisView, ProjectCreate, ProjectCreateArgs, ProjectInfo, ProjectInfoOut, ProjectOpen,
    ProjectOpenArgs, project_gate,
};
pub use query::{
    Decompile, DecompileArgs, GetFunction, GetFunctionArgs, ListFunctions, ListFunctionsArgs,
};
pub use rebuild::{DriftEntry, DriftKind, Rebuild, RebuildReport, ReplayFailure};
pub use rewrite::{
    CounterexampleView, ExportCoverage, ExportRequest, PlanEntry, PlanFlag, PlanScope,
    RewriteAccept, RewriteAcceptArgs, RewriteAcceptOut, RewriteBackend, RewriteExport,
    RewriteExportArgs, RewriteExportResult, RewriteFunction, RewriteFunctionArgs,
    RewriteFunctionResult, RewriteMode, RewritePlan, RewritePlanArgs, RewritePlanOut, RewriteSpec,
    RewriteSpecArgs, RewriteSpecResult, RewriteStatus, RewriteStatusArgs, RewriteStatusOut,
    RewriteUnit, RewriteUnitArgs, RewriteUnitOut, StatusCounts, UnitRow, UnitSpecView, UnitStatus,
    UnitVersionView, is_inside,
};
pub use undo_entry::{
    DependentView, TaintedClear, TaintedClearArgs, TaintedClearOut, TaintedFunction, TaintedList,
    TaintedListOut, UndoEntry, UndoEntryArgs, UndoPreview, UndoPreviewArgs, UndoPreviewCommand,
};

/// Arguments of a command that takes none.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

/// A started job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct JobStarted {
    /// Id to pass to `job_status`, `job_await` and `job_cancel`.
    pub job_id: String,
}

pub(crate) fn locator(address: Hex64) -> Locator {
    Locator::ram(address.0)
}

/// Builds an engine/model page request clamped to `cap`.
pub(crate) fn page_request(cursor: Option<String>, limit: Option<u32>, cap: u32) -> PageRequest {
    let req = PageRequest { cursor, limit };
    PageRequest {
        limit: Some(req.effective_limit().min(cap.max(1))),
        cursor: req.cursor,
    }
}

/// Registers every command.
pub fn register_all(r: &mut Registry) {
    r.register(ProjectCreate);
    r.register(ProjectOpen);
    r.register(ProjectInfo);
    r.register(Analyze);
    r.register(JobStatus);
    r.register(JobAwait);
    r.register(JobCancel);
    r.register(ListFunctions);
    r.register(GetFunction);
    r.register(Decompile);
    r.register(MemoryMap);
    r.register(ReadBytes);
    r.register(Disassemble);
    r.register(Xrefs);
    r.register(Callers);
    r.register(Callees);
    r.register(CfgCommand);
    r.register(Strings);
    r.register(Imports);
    r.register(Exports);
    r.register(RenameSymbol);
    r.register(SetComment);
    r.register(SetType);
    r.register(SetCallingConvention);
    r.register(CreateFunction);
    r.register(DeleteFunction);
    r.register(SetFunctionBounds);
    r.register(Undo);
    r.register(UndoRun);
    r.register(UndoEntry);
    r.register(UndoPreviewCommand);
    r.register(TaintedList);
    r.register(TaintedClear);
    r.register(History);
    r.register(ProposalsList);
    r.register(ProposalAccept);
    r.register(ProposalReject);
    r.register(Rebuild);
    r.register(RewritePlan);
    r.register(RewriteStatus);
    r.register(RewriteUnit);
    r.register(RewriteFunction);
    r.register(RewriteAccept);
    r.register(RewriteSpec);
    r.register(RewriteExport);
}
