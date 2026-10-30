//! The 0.1a commands and the `rewrite_*` commands.

use kraken_proto::{ErrorCode, Hex64, Locator, PageRequest, ProtoError};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::command::Registry;

mod ai;
mod assist;
mod bookmarks;
mod bulk;
mod config;
mod data;
#[cfg(unix)]
mod debug;
mod debuginfo;
mod debuginfo_fetch;
mod edit;
mod emulate;
#[cfg(unix)]
mod emulate_call;
mod emulate_call_types;
mod firmware;
mod gui_navigate;
mod help;
mod history;
mod infer;
mod integrations;
mod jobs;
mod local_model;
mod patch;
mod patch_check;
mod patch_formats;
mod patch_group;
mod patch_intent;
mod patch_source;
mod patch_write;
mod patched_view;
mod probe;
mod project;
mod query;
mod rawguess;
mod rebuild;
mod rewrite;
mod rewrite_build;
mod rewrite_control;
mod rewrite_hint;
mod rewrite_preload;
mod rewrite_program;
mod search;
mod setup;
mod symbols;
mod symbols_parse;
mod typedit;
mod types;
mod ui;
mod undo_entry;

pub use ai::{
    AiJobs, AiJobsOut, AiUsage, AiUsageArgs, AiUsageGroupView, AiUsageOut, AiUsageScope,
    ESTIMATE_NOTE,
};
pub use assist::{
    AssistAutoName, AssistAutoNameArgs, AssistExplain, AssistExplainArgs, AssistJobs,
    AssistOverview, AssistRequest, DEFAULT_AUTO_NAME, MAX_AUTO_NAME,
};
pub use bookmarks::{
    BOOKMARK_PAGE_CAP, BookmarkAdd, BookmarkAddArgs, BookmarkList, BookmarkListArgs,
    BookmarkRemove, BookmarkRemoveArgs, BookmarkRemoveOut, BookmarkView, MAX_BOOKMARK_NOTE,
};
pub use bulk::{
    ApplyEdits, ApplyEditsArgs, ApplyEditsOut, BulkEdit, BulkItemResult, BulkOp, BulkOutcome,
    MAX_BULK_EDITS,
};
pub use config::{
    ConfigEntry, ConfigGet, ConfigGetArgs, ConfigGetOut, ConfigSet, ConfigSetArgs, ConfigStore,
};
pub use data::{
    CallGraphArgs, Callees, Callers, CfgArgs, CfgCommand, CfgOut, Disassemble, DisassembleArgs,
    Exports, Imports, MemoryMap, MemoryMapOut, ReadBytes, ReadBytesArgs, ReadBytesOut, Strings,
    StringsArgs, SymbolsArgs, Xrefs, XrefsArgs,
};
#[cfg(unix)]
pub use debug::{
    DebugBreakArgs, DebugBreakList, DebugBreakOut, DebugBreakRemove, DebugBreakSet, DebugContinue,
    DebugDisasm, DebugDisasmArgs, DebugDisasmOut, DebugGdbServe, DebugGdbServeArgs,
    DebugGdbServeOut, DebugInsn, DebugMemOut, DebugMemRead, DebugMemReadArgs, DebugRegister,
    DebugRegs, DebugRegsOut, DebugReverseContinue, DebugReverseStep, DebugReverseStepArgs,
    DebugRunArgs, DebugRunTo, DebugRunToArgs, DebugSessionArgs, DebugSessions, DebugSessionsOut,
    DebugStart, DebugStartArgs, DebugStartOut, DebugStateCommand, DebugStateOut, DebugStep,
    DebugStepArgs, DebugStepOut, DebugStepOver, DebugStop, DebugStopOut, DebugStopSession,
    DebugStopSessionOut, DebugTable, DebugWatch, DebugWatchArgs, DebugWatchHit, DebugWatchOut,
    DebugWatchRemove, DebugWatchSet,
};
pub use debuginfo::{
    CandidateSource, DebugCandidate, DebugInfoAttach, DebugInfoAttachArgs, DebugInfoDetach,
    DebugInfoFind, DebugInfoFindArgs, DebugInfoProbe, DebugInfoProbeArgs, DebugInfoProbeOut,
    DebugInfoServers, DebugInfoServersArgs, DebugServer, DebugServersOut, DebugStatus, Verdict,
    engine_accepts, pdb_identity, probe as probe_debug_info, resolve_for_attach,
};
pub use debuginfo_fetch::{
    DebugFindOut, FindAttempt, find as find_debug_file,
    normalize_server as normalize_symbol_server, offline_env as symbols_offline_env,
    servers_with_env as symbol_servers_with_env, wanted_of as debug_wanted,
};
pub use edit::{
    CreateFunction, CreateFunctionArgs, DeleteFunction, DeleteFunctionArgs, ProposalAccept,
    ProposalIdArgs, ProposalReject, RenameSymbol, RenameSymbolArgs, SetCallingConvention,
    SetCallingConventionArgs, SetComment, SetCommentArgs, SetFunctionBounds, SetFunctionBoundsArgs,
    SetLocal, SetLocalArgs, SetType, SetTypeArgs, Undo, UndoOut, UndoRun, UndoRunArgs,
};
pub use emulate::{
    DEFAULT_MAX_STEPS, DEFAULT_TIMEOUT_SECONDS, EmulateCompare, EmulateCompareArgs,
    EmulateCompareOut, EmulateDifference, EmulateExit, EmulateExitKind, EmulateFile, EmulateInput,
    EmulateRun, EmulateRunArgs, EmulateRunOut, MAX_MAX_STEPS, MAX_TIMEOUT_SECONDS,
};
#[cfg(unix)]
pub use emulate_call::EmulateCall;
pub use emulate_call_types::{
    CallArgIn, CallBufferOut, CallValue, EmulateCallArgs, EmulateCallOut, IntText,
};
pub use firmware::{
    FirmwareIdentify, FirmwareIdentifyArgs, FirmwareIdentifyOut, identify_firmware,
};
pub use gui_navigate::{GuiNavigate, GuiNavigateArgs, GuiNavigateOut, GuiTabName};
pub use help::{
    DEFAULT_HELP_HITS, HelpSection, KrakenHelp, KrakenHelpArgs, KrakenHelpOut, MAX_HELP_HITS,
};
pub use history::{History, HistoryArgs, ProposalFilter, ProposalsList, ProposalsListArgs};
pub use infer::{
    LocalModelArgs, LocalModelDevices, LocalModelDevicesOut, LocalModelHold, LocalModelList,
    LocalModelListOut, LocalModelRelease, LocalModelReleaseOut, LocalModelStart,
    LocalModelStartArgs, LocalModelStatus, LocalModelStatusOut, LocalModelStop, LocalModelStopOut,
    NoArgs as LocalModelNoArgs, ServedModelView, ServingBackend,
};
pub use integrations::{
    EmulatorRun, EmulatorRunArgs, EmulatorRunOut, InstallProgress, IntegrationInstall,
    IntegrationInstallArgs, IntegrationRemove, IntegrationRemoveArgs, IntegrationRemoveOut,
    IntegrationSource, IntegrationStatus, IntegrationUsePath, IntegrationUsePathArgs,
    IntegrationView, IntegrationsBackend, IntegrationsList, IntegrationsListOut, LaunchSpec,
    RunTarget, command_line, expand_arg,
};
pub use jobs::{
    Analyze, AnalyzeOut, AnalyzeResult, JobAwait, JobAwaitArgs, JobCancel, JobIdArgs, JobStatus,
    JobView,
};
pub use local_model::{
    DownloadView, GpuView, LocalFeature, LocalModelBackend, LocalModelRecommend,
    LocalModelRecommendArgs, LocalModelRecommendOut, LocalModelSetup, LocalModelSetupArgs,
    LocalModelSetupOut, LocalSetupPlan, MissingView, ModelView, SetupProgress, StrataCandidateView,
    StrataPlan, StrataView, recommend_view, recommendation_now, strata_downloads, strata_now,
    strata_view,
};
pub use patch::{
    AppliedPatchView, Assemble, AssembleArgs, AssembleOut, MAX_ASSEMBLY_LINE, MAX_ASSEMBLY_LINES,
    MAX_PATCH_BYTES, MAX_PATCH_NOTE, PATCH_PAGE_CAP, PatchEditOut, PatchExport, PatchExportArgs,
    PatchExportOut, PatchList, PatchListArgs, PatchRemove, PatchRemoveArgs, PatchSet, PatchSetArgs,
    PatchView,
};
pub use patch_check::{
    LintFinding, PatchLint, PatchLintArgs, PatchLintOut, PatchVerdictView, PatchVerify,
    PatchVerifyArgs, PatchVerifyOut,
};
pub use patch_formats::{
    ImportedPatch, MAX_IMPORT_PATCHES, PatchExportDiff, PatchExportDiffArgs, PatchExportDiffOut,
    PatchFileFormat, PatchImport, PatchImportArgs, PatchImportOut,
};
pub use patch_group::{
    MAX_ASSIGN, MAX_GROUP_DESCRIPTION, MAX_GROUP_NAME, PatchGroupAssign, PatchGroupAssignArgs,
    PatchGroupChangeOut, PatchGroupEnable, PatchGroupEnableArgs, PatchGroupList,
    PatchGroupListArgs, PatchGroupListOut, PatchGroupRemove, PatchGroupRemoveArgs,
    PatchGroupRemoveOut, PatchGroupSet, PatchGroupSetArgs, PatchGroupView,
};
pub use patch_intent::{
    BranchChange, PatchBranch, PatchBranchArgs, PatchConstant, PatchConstantArgs, PatchFill,
    PatchFillArgs, PatchIntentOut, PatchNop, PatchNopArgs, PatchReturn, PatchReturnArgs,
};
pub use patch_source::{
    DEFAULT_SOURCE_PATCH_ATTEMPTS, MAX_SOURCE_BYTES, MAX_SOURCE_PATCH_ATTEMPTS, PatchFromSource,
    PatchFromSourceArgs, PatchFromSourceResult, PlannedPatch, SourcePatchBackend, SourcePatchCheck,
    SourcePatchVerdict, source_patch_result,
};
pub use patch_write::{
    MAX_STRING_BYTES, PatchAsm, PatchAsmArgs, PatchString, PatchStringArgs, PatchStringEncoding,
    PatchStringOut, StringPlan, detect_encoding, encode_string, plan_string,
};
pub use patched_view::{DecompilePatched, DecompilePatchedArgs};
pub use probe::{BinaryFormat, BinaryProbe, BinaryProbeArgs, BinaryProbeOut, probe_binary};
pub use project::{
    AnalysisView, ProjectClose, ProjectCloseOut, ProjectCreate, ProjectCreateArgs, ProjectInfo,
    ProjectInfoOut, ProjectOpen, ProjectOpenArgs, project_gate,
};
pub use query::{
    Decompile, DecompileArgs, GetFunction, GetFunctionArgs, ListFunctions, ListFunctionsArgs,
};
pub use rawguess::RawSuggestion;
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
pub use rewrite_build::{
    BUILD_LOG_CAP, BUILD_SUMMARY, BuildStepResult, EXPORT_GENERATOR, MAX_RUN_ARGS,
    PROGRAM_GENERATOR, RewriteBuild, RewriteBuildArgs, RewriteBuildResult, crate_kind,
    manifest_kind,
};
pub use rewrite_control::{
    CacheAction, CoverageView, Prereq, PrereqLevel, RewriteAddCase, RewriteAddCaseArgs,
    RewriteCache, RewriteCacheArgs, RewriteCacheOut, RewriteCheck, RewriteCheckArgs,
    RewriteCheckOut, RewriteReject, RewriteRejectArgs, RewriteSpecEdit, RewriteSpecEditArgs,
    RewriteUnaccept, RewriteUnacceptCmd, RewriteVerify, RewriteVerifyArgs, RewriteVerifyResult,
    UnitChangeOut,
};
pub use rewrite_hint::{
    RewriteHintGet, RewriteHintGetArgs, RewriteHintSet, RewriteHintSetArgs, RewriteHints,
    RewriteHintsOut, TypeHint, VarRename,
};
pub use rewrite_preload::{
    PreloadCalls, PreloadCheck, PreloadHook, PreloadSkip, RewritePreloadBuild,
    RewritePreloadBuildArgs, RewritePreloadBuildResult,
};
pub use rewrite_program::{
    DEFAULT_PROGRAM_DIR, DEFAULT_REPAIR_ROUNDS, MAX_GENERATED_CASES, MAX_REPAIR_ROUNDS,
    MAX_USER_CASES, ProgramCaseResult, ProgramCaseSpec, ProgramFunctionRow, ProgramRepairView,
    ProgramRunSummary, ProgramRunView, ProgramVerdictView, RUN_ORIGINAL_SUMMARY, RewriteProgram,
    RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatus, RewriteProgramStatusArgs,
    RewriteProgramStatusOut,
};
pub use search::{
    DEFAULT_SEARCH_HITS, MAX_SCAN_BYTES, MAX_SCAN_FUNCTIONS, MAX_SEARCH_HITS, Search, SearchArgs,
    SearchHit, SearchKind, parse_pattern,
};
pub use setup::{
    GlobalJobOut, IntegrationInstallStart, SetupArgs, SetupBackend, SetupDotnet, SetupGhidra,
    SetupItem, SetupNative, SetupState, SetupStatus, SetupStatusOut, SetupTask,
};
pub use symbols::{
    ConflictPolicy, DEFAULT_PREVIEW, ExportFormat, MAX_EXPORT_TEXT_BYTES, MAX_IMPORT_EDITS,
    MAX_PREVIEW, MAX_SYMBOL_FILE_BYTES, PlanAction, PlanStatus, PlannedSymbolEdit, SymbolsExport,
    SymbolsExportArgs, SymbolsExportOut, SymbolsImport, SymbolsImportArgs, SymbolsImportOut,
};
pub use symbols_parse::SymbolFormat;
pub use typedit::{
    TypeDefine, TypeDefineArgs, TypeDefineOut, TypeDelete, TypeDeleteArgs, TypeEditField,
    TypeEditFieldArgs,
};
pub use types::{
    TYPES_PAGE_CAP, TypeGet, TypeGetArgs, TypeSummaryView, TypeView, TypesList, TypesListArgs,
};
pub use ui::{
    DENIED_UI_ACTIONS, MAX_HIGHLIGHT_NOTE, UiAction, UiActionArgs, UiActionOut, UiHighlight,
    UiHighlightArgs, UiHighlightOut, UiState, UiStateArgs, UiStateOut,
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

/// The locator named by `address` and, for managed code, the module it belongs to. A module is a
/// lowercase hyphenated GUID and the address must be a 32-bit metadata token.
pub(crate) fn locator_in(address: Hex64, module: Option<&str>) -> Result<Locator, ProtoError> {
    let Some(module) = module else {
        return Ok(locator(address));
    };
    let guid = module.len() == 36
        && module.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        });
    if !guid {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "module must be a lowercase hyphenated GUID (the `module` of a managed function)",
        ));
    }
    let token = u32::try_from(address.0).map_err(|_| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            "a managed address is a 32-bit metadata token",
        )
    })?;
    Ok(Locator::managed(module, token))
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
    r.register(SetLocal);
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
    r.register(RewriteReject);
    r.register(RewriteUnacceptCmd);
    r.register(RewriteAddCase);
    r.register(RewriteCheck);
    r.register(RewriteCache);
    r.register(RewriteVerify);
    r.register(RewriteSpecEdit);
    r.register(RewriteSpec);
    r.register(RewriteExport);
    r.register(RewriteProgram);
    r.register(RewriteProgramStatus);
    // Card IN-06: the assistant and the config as commands.
    r.register(AssistExplain);
    r.register(AssistOverview);
    r.register(AssistAutoName);
    r.register(ConfigGet);
    r.register(ConfigSet);
    // Card SHELL: the open/import workflow.
    r.register(BinaryProbe);
    r.register(FirmwareIdentify);
    r.register(DebugInfoProbe);
    r.register(DebugInfoAttach);
    r.register(DebugInfoDetach);
    r.register(DebugInfoFind);
    r.register(DebugInfoServers);
    r.register(ProjectClose);
    // Card REWRITE
    r.register(RewriteBuild);
    r.register(RewriteHintGet);
    r.register(RewriteHintSet);
    r.register(RewritePreloadBuild);
    // Card AI
    r.register(ApplyEdits);
    r.register(SymbolsImport);
    r.register(SymbolsExport);
    r.register(GuiNavigate);
    // Card ASSIST: the assistant drives the GUI, knows KRAKEN and sets up local models.
    r.register(UiAction);
    r.register(UiState);
    r.register(UiHighlight);
    r.register(KrakenHelp);
    // Card INTEGRATIONS: emulators and tools downloaded from upstream on the user's machine.
    r.register(IntegrationsList);
    r.register(IntegrationInstall);
    r.register(IntegrationInstallStart);
    r.register(SetupStatus);
    r.register(SetupGhidra);
    r.register(SetupNative);
    r.register(SetupDotnet);
    r.register(IntegrationUsePath);
    r.register(IntegrationRemove);
    r.register(EmulatorRun);
    r.register(LocalModelRecommend);
    r.register(LocalModelSetup);
    // Card LOCAL-SERVING: the models KRAKEN runs on this computer.
    r.register(LocalModelList);
    r.register(LocalModelDevices);
    r.register(LocalModelStatus);
    r.register(LocalModelStart);
    r.register(LocalModelHold);
    r.register(LocalModelRelease);
    r.register(LocalModelStop);
    // Card NAV: search and bookmarks.
    r.register(Search);
    // Card DI-03: types as C.
    r.register(TypesList);
    r.register(TypeGet);
    // Card DI-07: types are edits.
    r.register(TypeDefine);
    r.register(TypeEditField);
    r.register(TypeDelete);
    r.register(BookmarkAdd);
    r.register(BookmarkRemove);
    r.register(BookmarkList);
    r.register(PatchSet);
    r.register(Assemble);
    r.register(PatchFromSource);
    r.register(DecompilePatched);
    r.register(PatchRemove);
    r.register(PatchNop);
    r.register(PatchBranch);
    r.register(PatchReturn);
    r.register(PatchFill);
    r.register(PatchConstant);
    r.register(PatchAsm);
    r.register(PatchString);
    r.register(PatchGroupSet);
    r.register(PatchGroupList);
    r.register(PatchGroupRemove);
    r.register(PatchGroupAssign);
    r.register(PatchGroupEnable);
    r.register(PatchList);
    r.register(PatchExport);
    r.register(PatchLint);
    r.register(PatchVerify);
    r.register(PatchExportDiff);
    r.register(PatchImport);
    // Card COST: what AI work costs and what runs.
    r.register(AiUsage);
    r.register(AiJobs);
    // Card EMULATE: run the analysed program in the emulator.
    r.register(EmulateRun);
    r.register(EmulateCompare);
    // Card EM-05: step the program in the emulator.
    #[cfg(unix)]
    {
        r.register(EmulateCall);
        r.register(DebugStart);
        r.register(DebugStep);
        r.register(DebugStepOver);
        r.register(DebugStepOut);
        r.register(DebugContinue);
        r.register(DebugRunTo);
        r.register(DebugBreakSet);
        r.register(DebugBreakRemove);
        r.register(DebugBreakList);
        r.register(DebugWatchSet);
        r.register(DebugWatchRemove);
        r.register(DebugReverseStep);
        r.register(DebugReverseContinue);
        r.register(DebugRegs);
        r.register(DebugMemRead);
        r.register(DebugDisasm);
        r.register(DebugStateCommand);
        r.register(DebugSessions);
        r.register(DebugStopSession);
        r.register(DebugGdbServe);
    }
}

/// Debug sessions need the Unix sandbox; elsewhere the table is empty and there are no commands.
#[cfg(not(unix))]
#[derive(Clone, Default, Debug)]
pub struct DebugTable;

#[cfg(not(unix))]
impl DebugTable {
    /// Nothing to end.
    pub fn clear(&self) {}
}
