//! The Rewrite tab (ADR 0013): the plan in bottom-up order with a status chip per function,
//! running `rewrite_function` as a job with progress, one function's decompiled C next to the
//! generated Rust with its test results and version history, accepting a verified version, the
//! cited spec, and the export of accepted functions.
//!
//! State lives on [`RewriteState`] (`vm.rewrite`); the window only draws it and calls the
//! `rewrite_*` methods of [`ViewModel`](crate::ViewModel) in `flow.rs`.
//!
//! Two things the six registry commands do not hand out are read through an optional
//! `rewrite_unit` query: the stored Rust code with the version history, and a stored spec. When
//! the daemon has no such command the panel still shows everything the job results carry and
//! says what is missing ([`UnitDetail::stored_note`]).

use std::collections::HashMap;

use kraken_proto::{Completeness, DecompileResult, Locator, Token};

use crate::backend::{JobProgress, JobState};

pub use kraken_registry::commands::{RewriteMode, UnitStatus};
pub use spec::{Inline, SpecBlock, citations, parse_spec};

mod build;
mod bulk;
mod flow;
mod highlight;
mod program;
mod spec;
#[cfg(test)]
mod tests;
mod wire;
mod wizard;

#[cfg(feature = "demo")]
pub mod demo;
#[cfg(all(test, feature = "demo"))]
mod demo_tests;

pub use build::{BuildOutcome, BuildState, BuildStepItem};
pub use highlight::highlight_rust;
pub use program::{
    DEFAULT_REPAIR_ROUNDS, DiffKind, DiffLine, MAX_REPAIR_ROUNDS, ProgramCaseItem,
    ProgramFunctionItem, ProgramInput, ProgramRepairItem, ProgramRunDetail, ProgramRunItem,
    ProgramState, ProgramVerdictItem, RunSide, line_diff, split_args, verdict_line,
};
pub use wizard::{Check, CheckLevel, WizardScope, WizardState, WizardStep, wizard_scope_explain};

/// Rows loaded into the plan view at most (the daemon pages 200 at a time).
pub(crate) const MAX_ROWS: usize = 5000;
/// Finished jobs kept in the job list.
pub(crate) const JOBS_KEPT: usize = 12;

/// Why a function needs more than a plain translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// Calls a library function the test has no stand-in for.
    NeedsStubs,
    /// Reads or writes global data.
    UsesGlobals,
    /// Makes system calls directly.
    UsesSyscalls,
    /// Part of a recursive group.
    Recursive,
    /// Its signature is something the test cannot call.
    UnsupportedAbi,
    /// A flag this build does not know; shown as it came.
    Other(String),
}

impl Flag {
    pub(crate) fn from_wire(s: &str) -> Flag {
        match s {
            "needs_stubs" => Flag::NeedsStubs,
            "uses_globals" => Flag::UsesGlobals,
            "uses_syscalls" => Flag::UsesSyscalls,
            "recursive" => Flag::Recursive,
            "unsupported_abi" => Flag::UnsupportedAbi,
            other => Flag::Other(other.replace('_', " ")),
        }
    }

    /// Short chip text.
    pub fn label(&self) -> String {
        match self {
            Flag::NeedsStubs => "needs stubs".into(),
            Flag::UsesGlobals => "uses globals".into(),
            Flag::UsesSyscalls => "system calls".into(),
            Flag::Recursive => "recursive".into(),
            Flag::UnsupportedAbi => "unsupported signature".into(),
            Flag::Other(s) => s.clone(),
        }
    }

    /// One plain sentence for the tooltip.
    pub fn explain(&self) -> String {
        match self {
            Flag::NeedsStubs => "Calls a library function (such as malloc) that the test cannot imitate yet. The check would come out inconclusive until a stand-in exists.".into(),
            Flag::UsesGlobals => "Reads or writes global data. The test does not control globals, so a pass says less about this function.".into(),
            Flag::UsesSyscalls => "Asks the operating system for something directly. The test cannot run that.".into(),
            Flag::Recursive => "Calls itself, or is part of a group of functions that call each other. The group is translated together.".into(),
            Flag::UnsupportedAbi => "Its signature uses something the test cannot call yet: floating point, structures passed by value, variable arguments or function pointers.".into(),
            Flag::Other(s) => format!("The plan marked this function \"{s}\"."),
        }
    }
}

/// Status chip text of a unit.
pub fn status_label(s: UnitStatus) -> &'static str {
    s.as_str()
}

/// One sentence saying what a status means.
pub fn status_explain(s: UnitStatus) -> &'static str {
    match s {
        UnitStatus::Planned => "In the plan. Nothing has been translated yet.",
        UnitStatus::Translated => {
            "Rust exists, but the test could not decide whether it matches the original."
        }
        UnitStatus::Verified => {
            "The Rust version agreed with the original on every test case that ran. Accept it to include it in the export."
        }
        UnitStatus::Failed => {
            "The Rust version differed from the original, or did not compile. A counterexample shows where."
        }
        UnitStatus::Accepted => "You accepted this version. It goes into the export.",
    }
}

/// One function in the plan view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitItem {
    /// Id of the newest version (`ru-...`); empty when nothing was translated.
    pub unit: String,
    /// Position in the rewrite order, from 0 (callees first).
    pub order: Option<u32>,
    /// Entry address.
    pub address: u64,
    /// Function name.
    pub name: String,
    /// Where the unit stands.
    pub status: UnitStatus,
    /// Newest version (0 when nothing was translated).
    pub version: u32,
    /// The accepted version, if any.
    pub accepted_version: Option<u32>,
    /// Mode of the newest version.
    pub mode: Option<String>,
    /// `pass`, `fail`, `rejected` or `inconclusive`.
    pub verdict: Option<String>,
    /// Cases that ran on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Counterexamples stored with the verdict.
    pub counterexamples: u32,
    /// Provider that wrote the newest version.
    pub provider: Option<String>,
    /// Model that wrote the newest version.
    pub model: Option<String>,
    /// Why it needs care.
    pub flags: Vec<Flag>,
}

/// Units per status over the whole program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// In the plan only.
    pub planned: u32,
    /// Translated, not decided.
    pub translated: u32,
    /// Verified, not accepted.
    pub verified: u32,
    /// Failed.
    pub failed: u32,
    /// Accepted.
    pub accepted: u32,
}

impl Counts {
    /// All units.
    pub fn total(&self) -> u32 {
        self.planned + self.translated + self.verified + self.failed + self.accepted
    }

    /// Units of one status.
    pub fn of(&self, s: UnitStatus) -> u32 {
        match s {
            UnitStatus::Planned => self.planned,
            UnitStatus::Translated => self.translated,
            UnitStatus::Verified => self.verified,
            UnitStatus::Failed => self.failed,
            UnitStatus::Accepted => self.accepted,
        }
    }
}

/// What a new plan covered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanSummary {
    /// Functions the engine lists.
    pub functions_total: u64,
    /// Functions in the plan.
    pub functions_planned: u64,
    /// Import thunks left out.
    pub skipped_imports: u64,
    /// Compiler and loader glue left out.
    pub skipped_runtime: u64,
    /// Groups (a recursive group counts once).
    pub groups: u32,
    /// The plan was cut short by the function limit.
    pub truncated: bool,
}

/// What the plan says about one function beyond its status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionPlan {
    /// Functions of the program it calls, leaves first.
    pub callees: Vec<(u64, String)>,
    /// Library functions it calls directly.
    pub imports: Vec<String>,
    /// Library functions (direct or through callees) the test cannot imitate.
    pub needs_stubs: Vec<String>,
    /// Functions in its recursive group (1 when it is not recursive).
    pub group_size: u32,
}

/// Source text with its colours, in the shape the code widget draws.
#[derive(Debug, Clone, PartialEq)]
pub struct CodePane(pub DecompileResult);

impl CodePane {
    pub(crate) fn new(language: &str, text: String, tokens: Vec<Token>) -> CodePane {
        CodePane(DecompileResult {
            function: Locator::ram(0),
            language: language.into(),
            text,
            tokens,
            warnings: Vec::new(),
            completeness: Completeness::Complete,
        })
    }

    /// The source text.
    pub fn text(&self) -> &str {
        &self.0.text
    }
}

/// A case where the Rust version and the original disagreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counterexample {
    /// The arguments the case called both with.
    pub args: Vec<String>,
    /// What differed, one line each ("result: original 0x80, Rust 0xffffff80").
    pub differences: Vec<String>,
}

/// One version of a function's Rust translation.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionItem {
    /// Unit id (`ru-...`), the handle for accepting it; empty when unknown.
    pub unit: String,
    /// Version number.
    pub version: u32,
    /// Mode it was made in.
    pub mode: RewriteMode,
    /// Status.
    pub status: UnitStatus,
    /// `pass`, `fail`, `rejected` or `inconclusive`.
    pub verdict: String,
    /// Why, for `rejected` and `inconclusive`.
    pub verdict_detail: Option<String>,
    /// Cases that ran on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Cases the oracle could not evaluate.
    pub skipped: u32,
    /// The smallest disagreement.
    pub counterexample: Option<Counterexample>,
    /// The Rust declaration the code was checked at.
    pub prototype: String,
    /// The code, when the daemon hands it out.
    pub rust: Option<CodePane>,
    /// How the generated code was confined.
    pub sandbox: String,
    /// Provider that wrote it.
    pub provider: String,
    /// Model that wrote it.
    pub model: String,
    /// What the model said it assumed.
    pub assumptions: Vec<String>,
    /// What the model said it could not translate.
    pub unsupported: Vec<String>,
}

impl VersionItem {
    /// One line such as "200 of 200 cases agreed" or "agreed on 150, 4 skipped".
    pub fn cases_line(&self) -> String {
        if self.cases_run == 0 {
            return "No test case ran.".into();
        }
        let mut s = format!(
            "{} of {} cases agreed with the original",
            self.passed, self.cases_run
        );
        if self.skipped > 0 {
            s.push_str(&format!(", {} could not be evaluated", self.skipped));
        }
        s.push('.');
        s
    }
}

/// Everything shown about the selected function.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UnitDetail {
    /// Entry address.
    pub address: u64,
    /// Function name.
    pub name: String,
    /// The decompiled C.
    pub c: Option<CodePane>,
    /// What the plan says about it.
    pub plan: Option<FunctionPlan>,
    /// Versions the daemon stored (`rewrite_unit`), oldest first.
    pub stored: Vec<VersionItem>,
    /// Versions this window made, from job results, oldest first.
    pub session: Vec<VersionItem>,
    /// Why the stored versions or their code are not shown, when that is the case.
    pub stored_note: Option<String>,
    /// The version being looked at (version number); the newest when `None`.
    pub shown: Option<u32>,
    /// A plain-language reason the last action on this function failed.
    pub error: Option<String>,
    /// Things are loading.
    pub loading: bool,
}

impl UnitDetail {
    /// The versions to list, oldest first: the stored ones, plus any this window made that the
    /// daemon has not listed.
    pub fn versions(&self) -> Vec<&VersionItem> {
        let mut out: Vec<&VersionItem> = self.stored.iter().collect();
        for v in &self.session {
            if !out.iter().any(|s| s.version == v.version) {
                out.push(v);
            }
        }
        out.sort_by_key(|v| v.version);
        out
    }

    /// The version on show: the picked one, else the newest.
    pub fn current(&self) -> Option<&VersionItem> {
        let all = self.versions();
        match self.shown {
            Some(n) => all.iter().copied().find(|v| v.version == n),
            None => None,
        }
        .or_else(|| all.last().copied())
    }
}

/// What a job started from the tab is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobKind {
    /// `rewrite_function`.
    Function {
        /// The function.
        address: u64,
        /// How it is rewritten.
        mode: RewriteMode,
    },
    /// `rewrite_spec`; `None` is the whole program.
    Spec {
        /// The function.
        address: Option<u64>,
    },
    /// `rewrite_export`.
    Export,
    /// `rewrite_program`.
    Program,
    /// `rewrite_build`.
    Build,
}

/// A job started from the tab.
#[derive(Debug, Clone, PartialEq)]
pub struct RewriteJob {
    /// Local number (the daemon's job id is not known until it replies).
    pub seq: u64,
    /// The daemon's job id.
    pub job_id: Option<String>,
    /// What it does.
    pub kind: JobKind,
    /// "Rewriting checksum".
    pub label: String,
    /// Where it stands.
    pub state: JobState,
    /// Latest progress report.
    pub progress: Option<JobProgress>,
    /// Plain-language reason it failed.
    pub error: Option<String>,
    /// One-line outcome of a finished job.
    pub outcome: Option<String>,
}

impl RewriteJob {
    /// The job is still going (including while the daemon has not answered yet).
    pub fn running(&self) -> bool {
        self.state == JobState::Running
    }

    /// 0.0 to 1.0, when the progress report says how far.
    pub fn fraction(&self) -> Option<f32> {
        let p = self.progress.as_ref()?;
        (p.total > 0).then(|| (p.done as f32 / p.total as f32).clamp(0.0, 1.0))
    }
}

/// A spec as the Spec view draws it.
#[derive(Debug, Clone, PartialEq)]
pub struct SpecDoc {
    /// Stored spec id.
    pub id: u64,
    /// The Markdown as written.
    pub markdown: String,
    /// Parsed blocks.
    pub blocks: Vec<SpecBlock>,
    /// Functions it was written from.
    pub functions: u32,
    /// Cited facts.
    pub facts: u32,
    /// Provider that wrote it.
    pub provider: String,
    /// Model that wrote it.
    pub model: String,
}

impl SpecDoc {
    fn new(w: wire::SpecWire) -> SpecDoc {
        let markdown = w.markdown.0;
        SpecDoc {
            id: w.spec,
            blocks: parse_spec(&markdown),
            markdown,
            functions: w.functions,
            facts: w.facts,
            provider: w.provider,
            model: w.model,
        }
    }

    /// Addresses the spec cites.
    pub fn cited(&self) -> Vec<u64> {
        citations(&self.blocks)
    }
}

/// Where the export would write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirCheck {
    /// Inside the project folder.
    Inside,
    /// Somewhere else on the computer.
    Outside,
    /// Not usable; the reason.
    Invalid(String),
}

/// Checks an export target the way the command will: relative paths are inside the project, `..`
/// is refused, an absolute path is inside when it starts with the project folder.
pub fn check_export_dir(project_dir: Option<&str>, input: &str) -> DirCheck {
    use std::path::{Component, Path};
    let t = input.trim();
    if t.is_empty() {
        return DirCheck::Invalid("Type a folder name first.".into());
    }
    if t.contains('\0') {
        return DirCheck::Invalid("That is not a folder path.".into());
    }
    let p = Path::new(t);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return DirCheck::Invalid(
            "A folder path cannot contain \"..\". Type the full path instead.".into(),
        );
    }
    if !p.is_absolute() {
        return DirCheck::Inside;
    }
    if p.parent().is_none() {
        return DirCheck::Invalid("Pick a folder, not the root of a disk.".into());
    }
    match project_dir {
        Some(dir) if p.starts_with(dir) => DirCheck::Inside,
        _ => DirCheck::Outside,
    }
}

/// What a finished export wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    /// The folder written.
    pub dir: String,
    /// Crates in the workspace.
    pub crates: Vec<String>,
    /// Exported `extern "C"` symbols.
    pub symbols: Vec<String>,
    /// The workspace was built in the sandbox and its symbols match.
    pub built: bool,
    /// How the build was confined.
    pub sandbox: String,
    /// Accepted units exported.
    pub accepted: u32,
    /// Functions in the plan.
    pub planned: u32,
    /// Functions the engine lists.
    pub functions_total: u64,
}

/// The export dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportState {
    /// The dialog is open.
    pub open: bool,
    /// Target folder as typed.
    pub dir: String,
    /// Crate name prefix, empty for the default.
    pub name: String,
    /// Build the workspace in the sandbox before reporting success.
    pub build: bool,
    /// The target is outside the project and the person has not agreed yet.
    pub ask_outside: bool,
    /// The person agreed to the outside folder in `dir`.
    pub(crate) agreed_outside: bool,
    /// Plain-language reason the export could not start or failed.
    pub error: Option<String>,
    /// Result of the last export.
    pub result: Option<ExportSummary>,
}

impl Default for ExportState {
    fn default() -> Self {
        ExportState {
            open: false,
            dir: "rewrite-export".into(),
            name: String::new(),
            build: true,
            ask_outside: false,
            agreed_outside: false,
            error: None,
            result: None,
        }
    }
}

/// Whether the tab can run generated code here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Availability {
    /// Nothing is known to be wrong.
    #[default]
    Unknown,
    /// This computer cannot confine generated code, so nothing is translated or built.
    NoConfinement(String),
    /// The daemon has no rewrite pipeline attached.
    NotAttached(String),
}

/// What to tell the person when `os` cannot confine generated code, `None` when it can.
pub fn platform_note(os: &str) -> Option<String> {
    if os == "linux" {
        return None;
    }
    Some(format!(
        "KRAKEN runs the Rust it generates only inside a sandbox, and the sandbox it has today is Linux's. On this computer ({os}) nothing is translated, tested or built, so the buttons that would do that are off. You can still read the plan and the specs. Use a Linux machine for the rewrite."
    ))
}

/// All state of the Rewrite tab.
pub struct RewriteState {
    /// The plan status has been requested at least once.
    pub loaded: bool,
    /// A plan or status request is running.
    pub loading: bool,
    /// Why loading failed.
    pub error: Option<String>,
    /// A plan is stored for the program.
    pub plan_present: bool,
    /// Units per status over the whole program.
    pub counts: Counts,
    /// The plan, in rewrite order.
    pub rows: Vec<UnitItem>,
    /// More rows exist than were loaded.
    pub truncated_list: bool,
    /// What the last new plan covered.
    pub plan_summary: Option<PlanSummary>,
    /// Whether code can run here.
    pub availability: Availability,
    /// The function whose detail is open.
    pub selected: Option<u64>,
    /// Detail of the functions looked at, by address.
    pub details: HashMap<u64, UnitDetail>,
    /// Jobs started from the tab, oldest first.
    pub jobs: Vec<RewriteJob>,
    /// Specs written for single functions.
    pub specs: HashMap<u64, SpecDoc>,
    /// The program-level spec.
    pub program_spec: Option<SpecDoc>,
    /// The export dialog.
    pub export: ExportState,
    /// The Program view.
    pub program: ProgramState,
    /// The build and test of an exported crate.
    pub build: BuildState,
    /// The step-by-step rewrite window.
    pub wizard: WizardState,
    /// Bulk actions of the plan list: the functions still waiting to be translated.
    pub bulk: bulk::BulkState,
    /// The window should show the Program section of the Rewrite tab.
    pub show_program_request: bool,
    pub(crate) generation: u64,
    pub(crate) next_seq: u64,
    pub(crate) stash: Vec<(String, crate::backend::JobInfo)>,
    /// `Some(false)` once the daemon said it has no `rewrite_unit` query.
    pub(crate) unit_query: Option<bool>,
}

impl Default for RewriteState {
    fn default() -> Self {
        RewriteState {
            loaded: false,
            loading: false,
            error: None,
            plan_present: false,
            counts: Counts::default(),
            rows: Vec::new(),
            truncated_list: false,
            plan_summary: None,
            availability: platform_note(std::env::consts::OS)
                .map(Availability::NoConfinement)
                .unwrap_or_default(),
            selected: None,
            details: HashMap::new(),
            jobs: Vec::new(),
            specs: HashMap::new(),
            program_spec: None,
            export: ExportState::default(),
            program: ProgramState::default(),
            build: BuildState::default(),
            wizard: WizardState::default(),
            bulk: bulk::BulkState::default(),
            show_program_request: false,
            generation: 0,
            next_seq: 1,
            stash: Vec::new(),
            unit_query: None,
        }
    }
}

impl RewriteState {
    /// A blank state for another project; answers still on their way to the old one are dropped.
    pub(crate) fn reset(&self) -> RewriteState {
        RewriteState {
            generation: self.generation + 1,
            next_seq: self.next_seq,
            ..RewriteState::default()
        }
    }

    /// Code can be translated and built here as far as anyone knows.
    pub fn can_run(&self) -> bool {
        self.availability == Availability::Unknown
    }

    /// Why the run buttons are off, when they are.
    pub fn blocked_note(&self) -> Option<&str> {
        match &self.availability {
            Availability::Unknown => None,
            Availability::NoConfinement(s) | Availability::NotAttached(s) => Some(s),
        }
    }

    /// The row of `address`.
    pub fn row(&self, address: u64) -> Option<&UnitItem> {
        self.rows.iter().find(|r| r.address == address)
    }

    /// The job of function `address` that is still running.
    pub fn running_for(&self, address: u64) -> Option<&RewriteJob> {
        self.jobs.iter().rev().find(|j| {
            j.running() && matches!(&j.kind, JobKind::Function { address: a, .. } if *a == address)
        })
    }

    /// Any job is running.
    pub fn busy(&self) -> bool {
        self.jobs.iter().any(RewriteJob::running)
    }

    /// The build job is running.
    pub fn building(&self) -> bool {
        self.jobs
            .iter()
            .any(|j| j.running() && j.kind == JobKind::Build)
    }

    /// The export job is running.
    pub fn exporting(&self) -> bool {
        self.jobs
            .iter()
            .any(|j| j.running() && j.kind == JobKind::Export)
    }

    /// Detail of the selected function.
    pub fn selected_detail(&self) -> Option<&UnitDetail> {
        self.selected.and_then(|a| self.details.get(&a))
    }

    /// The spec for a function, or the program's for `None`.
    pub fn spec_for(&self, address: Option<u64>) -> Option<&SpecDoc> {
        match address {
            Some(a) => self.specs.get(&a),
            None => self.program_spec.as_ref(),
        }
    }

    /// The unit id that "Accept" would send for `address`: the newest version, when it is
    /// verified, not yet accepted and its id is known.
    pub fn acceptable_unit(&self, address: u64) -> Option<String> {
        let d = self.details.get(&address)?;
        let v = d.versions().into_iter().next_back()?;
        (v.status == UnitStatus::Verified && !v.unit.is_empty()).then(|| v.unit.clone())
    }

    /// "Accepted 3 of 12 planned functions (3 of 15 in the program)."
    pub fn coverage_line(&self) -> String {
        let planned = u64::from(self.counts.total());
        let planned = if planned == 0 {
            self.plan_summary
                .as_ref()
                .map_or(0, |p| p.functions_planned)
        } else {
            planned
        };
        let mut s = format!(
            "Accepted {} of {} planned function{}",
            self.counts.accepted,
            planned,
            if planned == 1 { "" } else { "s" }
        );
        if let Some(p) = self.plan_summary.as_ref().filter(|p| p.functions_total > 0) {
            s.push_str(&format!(
                " ({} of {} in the program)",
                self.counts.accepted, p.functions_total
            ));
        }
        s.push('.');
        s
    }
}
