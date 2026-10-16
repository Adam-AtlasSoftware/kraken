//! The 0.1a commands.

use kraken_proto::{Hex64, Locator, PageRequest};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::command::Registry;

mod edit;
mod history;
mod jobs;
mod project;
mod query;
mod rebuild;

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
    ProjectOpenArgs,
};
pub use query::{
    Decompile, DecompileArgs, GetFunction, GetFunctionArgs, ListFunctions, ListFunctionsArgs,
};
pub use rebuild::{DriftEntry, DriftKind, Rebuild, RebuildReport, ReplayFailure};

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

/// Registers every 0.1a command.
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
    r.register(RenameSymbol);
    r.register(SetComment);
    r.register(SetType);
    r.register(SetCallingConvention);
    r.register(CreateFunction);
    r.register(DeleteFunction);
    r.register(SetFunctionBounds);
    r.register(Undo);
    r.register(UndoRun);
    r.register(History);
    r.register(ProposalsList);
    r.register(ProposalAccept);
    r.register(ProposalReject);
    r.register(Rebuild);
}
