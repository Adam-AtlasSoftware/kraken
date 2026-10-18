//! The Program view of the Rewrite tab (ADR 0013, task R3): the stored runs of `rewrite_program`,
//! the function table of one run with the status of each translation, where the generated crate
//! is, the cases the original and the rewritten program were both run on with a diff of their
//! standard output, standard error and exit status, and the program-level repair rounds.
//!
//! Everything shown comes from `rewrite_program_status`; the Run button starts the
//! `rewrite_program` job, whose approval question (it runs the original binary natively, in the
//! sandbox) is asked by the same dialog every dangerous command uses.

use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    ProgramCaseResult, ProgramRepairView, ProgramRunView, RewriteProgramResult,
    RewriteProgramStatusOut,
};
use serde_json::json;

use super::{JobKind, UnitStatus};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, parse};

/// Program-level repair rounds the Run button asks for unless the person changes it.
pub const DEFAULT_REPAIR_ROUNDS: u32 = kraken_registry::commands::DEFAULT_REPAIR_ROUNDS;
/// Most rounds a run may ask for.
pub const MAX_REPAIR_ROUNDS: u32 = kraken_registry::commands::MAX_REPAIR_ROUNDS;

/// One function of a program rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFunctionItem {
    /// Position in the plan (callees first).
    pub order: u32,
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Status of the translation the crate uses.
    pub status: UnitStatus,
    /// Function-level verdict: `pass`, `fail`, `rejected`, `inconclusive` or `none`.
    pub verdict: String,
    /// `differential`, `unchecked`, `compile_only`, `stored`, `skipped` or `none`.
    pub check: String,
    /// Why the function-level test could not compare, if it could not.
    pub check_note: Option<String>,
    /// Translation attempts.
    pub attempts: u32,
    /// Translated callees this one calls.
    pub reused: Vec<String>,
    /// Part of the generated crate.
    pub included: bool,
}

impl ProgramFunctionItem {
    /// One plain phrase for the Check column.
    pub fn check_label(&self) -> &'static str {
        match self.check.as_str() {
            "differential" => "compared with the original",
            "compile_only" => "compiled only",
            "unchecked" => "not checked on its own",
            "stored" => "accepted earlier",
            "skipped" => "not part of the program",
            _ => "not translated",
        }
    }

    /// The function is part of the program but nothing compared it with the original.
    pub fn unverified(&self) -> bool {
        self.included
            && !(self.check == "differential" && self.verdict == "pass")
            && self.check != "stored"
    }
}

/// What one program did on one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSide {
    /// `exit 0`, `signal 11`, `timeout`.
    pub exit: String,
    /// Standard output (cut at 4 KiB).
    pub stdout: String,
    /// Bytes written to standard output.
    pub stdout_bytes: u64,
    /// Standard error (cut at 4 KiB).
    pub stderr: String,
    /// Bytes written to standard error.
    pub stderr_bytes: u64,
}

impl RunSide {
    fn new(r: ProgramRunView) -> RunSide {
        RunSide {
            exit: r.exit,
            stdout: r.stdout.0,
            stdout_bytes: r.stdout_bytes,
            stderr: r.stderr.0,
            stderr_bytes: r.stderr_bytes,
        }
    }
}

/// One program-level case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramCaseItem {
    /// Label.
    pub name: String,
    /// `baseline`, `corpus`, `generated` or `user`.
    pub origin: String,
    /// Arguments after `argv[0]`.
    pub argv: Vec<String>,
    /// Bytes of standard input.
    pub stdin_bytes: u64,
    /// Exit status, stdout and stderr all agreed.
    pub agree: bool,
    /// The original binary.
    pub original: RunSide,
    /// The rewritten program.
    pub rewritten: RunSide,
    /// What differs.
    pub differences: Vec<String>,
}

impl ProgramCaseItem {
    fn new(c: ProgramCaseResult) -> ProgramCaseItem {
        ProgramCaseItem {
            name: c.name,
            origin: c.origin,
            argv: c.argv.into_iter().map(|a| a.0).collect(),
            stdin_bytes: c.stdin_bytes,
            agree: c.agree,
            original: RunSide::new(c.original),
            rewritten: RunSide::new(c.rewritten),
            differences: c.differences.into_iter().map(|d| d.0).collect(),
        }
    }

    /// The command line the case stands for: `prog a b < 12 bytes`.
    pub fn command_line(&self) -> String {
        let mut s = String::from("prog");
        for a in &self.argv {
            s.push(' ');
            if a.is_empty() || a.contains(' ') {
                s.push_str(&format!("{a:?}"));
            } else {
                s.push_str(a);
            }
        }
        if self.stdin_bytes > 0 {
            s.push_str(&format!("  < {} bytes of input", self.stdin_bytes));
        }
        s
    }
}

/// One function a repair round asked the provider to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRepairItem {
    /// Round, from 1.
    pub round: u32,
    /// Function name.
    pub name: String,
    /// Entry address.
    pub address: u64,
    /// The case whose difference was fed back.
    pub case: String,
    /// What the rewritten program was doing where the first difference appeared.
    pub at: String,
    /// Translated functions on its call stack there, innermost first.
    pub stack: Vec<String>,
    /// Why this function was suspected.
    pub why: String,
    /// `replaced`, `kept` or `no_reply`.
    pub outcome: String,
    /// Version before and after.
    pub versions: (u32, u32),
    /// Program verdict after the round.
    pub verdict_after: String,
}

impl ProgramRepairItem {
    fn new(r: ProgramRepairView) -> ProgramRepairItem {
        ProgramRepairItem {
            round: r.round,
            name: r.name.0,
            address: r.address.0,
            case: r.case,
            at: r.at,
            stack: r.stack,
            why: r.why.0,
            outcome: r.outcome,
            versions: (r.version_before, r.version_after),
            verdict_after: r.verdict_after,
        }
    }

    /// One plain sentence for the outcome.
    pub fn outcome_text(&self) -> &'static str {
        match self.outcome.as_str() {
            "replaced" => "A new translation passed its own checks and replaced the old one.",
            "kept" => "The new translation failed its own checks, so the old one stays.",
            _ => "The provider's reply could not be used.",
        }
    }
}

/// The program-level verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramVerdictItem {
    /// `pass`, `fail`, `incomplete`, `inconclusive` or `not_run`.
    pub verdict: String,
    /// Why, for everything but `pass` and `fail`.
    pub detail: Option<String>,
    /// Cases run on both programs.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Cases that differed.
    pub failed: u32,
    /// The cases loaded (the differing ones first).
    pub cases: Vec<ProgramCaseItem>,
    /// How the programs were confined.
    pub sandbox: String,
}

/// A stored run in the run list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRunItem {
    /// Run number.
    pub run: u64,
    /// When it finished (seconds since the Unix epoch).
    pub created: u64,
    /// Entry point.
    pub entry: u64,
    /// Program verdict.
    pub verdict: String,
    /// Cases run.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Where the crate was written.
    pub crate_dir: String,
}

/// One run in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRunDetail {
    /// Run number.
    pub run: u64,
    /// Entry point.
    pub entry: u64,
    /// Its name.
    pub entry_name: String,
    /// Functions in the plan.
    pub functions_planned: u32,
    /// Functions the entry point does not reach.
    pub skipped: u32,
    /// Functions translated in this run.
    pub translated: u32,
    /// Functions taken from accepted units of earlier runs.
    pub reused_from_store: u32,
    /// Functions without a usable translation.
    pub failed: u32,
    /// Functions in the crate.
    pub included: u32,
    /// The function table, in plan order.
    pub functions: Vec<ProgramFunctionItem>,
    /// Where the crate is (empty when none was written).
    pub crate_dir: String,
    /// The crate was built in the sandbox.
    pub built: bool,
    /// SHA-256 of the generated sources.
    pub crate_sha256: String,
    /// Provider that wrote the translations.
    pub provider: String,
    /// Its model.
    pub model: String,
    /// When the run finished.
    pub created: u64,
    /// The program verdict.
    pub verdict: ProgramVerdictItem,
    /// The repair rounds.
    pub repairs: Vec<ProgramRepairItem>,
}

impl ProgramRunDetail {
    fn new(r: RewriteProgramResult) -> ProgramRunDetail {
        ProgramRunDetail {
            run: r.run,
            entry: r.entry.0,
            entry_name: r.entry_name.0,
            functions_planned: r.functions_planned,
            skipped: r.skipped,
            translated: r.translated,
            reused_from_store: r.reused_from_store,
            failed: r.failed,
            included: r.included,
            functions: r
                .functions
                .into_iter()
                .map(|f| ProgramFunctionItem {
                    order: f.order,
                    address: f.address.0,
                    name: f.name.0,
                    status: f.status,
                    verdict: f.verdict,
                    check: f.check,
                    check_note: f.check_note.map(|n| n.0),
                    attempts: f.attempts,
                    reused: f.reused_callees,
                    included: f.included,
                })
                .collect(),
            crate_dir: r.crate_dir,
            built: r.built,
            crate_sha256: r.crate_sha256,
            provider: r.provider,
            model: r.model,
            created: r.created,
            verdict: ProgramVerdictItem {
                verdict: r.verdict.verdict,
                detail: r.verdict.detail.map(|d| d.0),
                cases_run: r.verdict.cases_run,
                passed: r.verdict.passed,
                failed: r.verdict.failed,
                cases: r
                    .verdict
                    .cases
                    .into_iter()
                    .map(ProgramCaseItem::new)
                    .collect(),
                sandbox: r.verdict.sandbox,
            },
            repairs: r.repairs.into_iter().map(ProgramRepairItem::new).collect(),
        }
    }

    /// Functions in the crate that no test compared with the original on its own.
    pub fn unverified(&self) -> usize {
        self.functions.iter().filter(|f| f.unverified()).count()
    }
}

/// One test case the person typed: how the program is started and what it is fed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramInput {
    /// Label in the report.
    pub name: String,
    /// Arguments after the program name, as typed (quotes group words).
    pub args: String,
    /// Text written to standard input.
    pub stdin: String,
}

impl ProgramInput {
    /// Nothing typed in any field.
    pub fn is_blank(&self) -> bool {
        self.name.trim().is_empty() && self.args.trim().is_empty() && self.stdin.is_empty()
    }
}

/// Splits typed arguments into words: spaces separate, single or double quotes group, a
/// backslash escapes the next character outside single quotes.
pub fn split_args(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') | (None, '\\') => match chars.next() {
                Some(n) => {
                    cur.push(n);
                    has = true;
                }
                None => return Err("The arguments end with a backslash.".into()),
            },
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => {
                cur.push(c);
                has = true;
            }
        }
    }
    if quote.is_some() {
        return Err("A quote in the arguments is not closed.".into());
    }
    if has {
        out.push(cur);
    }
    Ok(out)
}

/// State of the Program view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramState {
    /// The runs were requested at least once.
    pub loaded: bool,
    /// A request is running.
    pub loading: bool,
    /// Why loading failed.
    pub error: Option<String>,
    /// Stored runs of this binary, newest first.
    pub runs: Vec<ProgramRunItem>,
    /// The run on show.
    pub detail: Option<ProgramRunDetail>,
    /// List the cases that agreed too (they are not loaded otherwise).
    pub all_cases: bool,
    /// The case on show (index into the loaded cases).
    pub selected_case: Option<usize>,
    /// The function on show in the table.
    pub selected_function: Option<u64>,
    /// Repair rounds the Run button asks for.
    pub repair_rounds: u32,
    /// The last Run was refused by the person; the sentence to show.
    pub declined: Option<String>,
    /// Test cases the person added; they run on both programs.
    pub inputs: Vec<ProgramInput>,
    /// Folder for the generated crate; empty for the default inside the project.
    pub output_dir: String,
    /// Test every function against the original too (not only the whole program).
    pub verify_functions: bool,
    pub(crate) generation: u64,
}

impl Default for ProgramState {
    fn default() -> Self {
        ProgramState {
            loaded: false,
            loading: false,
            error: None,
            runs: Vec::new(),
            detail: None,
            all_cases: false,
            selected_case: None,
            selected_function: None,
            repair_rounds: DEFAULT_REPAIR_ROUNDS,
            declined: None,
            inputs: Vec::new(),
            output_dir: String::new(),
            verify_functions: true,
            generation: 0,
        }
    }
}

impl ProgramState {
    /// The case on show.
    pub fn case(&self) -> Option<&ProgramCaseItem> {
        let d = self.detail.as_ref()?;
        d.verdict.cases.get(self.selected_case?)
    }

    /// The function on show.
    pub fn function(&self) -> Option<&ProgramFunctionItem> {
        let a = self.selected_function?;
        self.detail
            .as_ref()?
            .functions
            .iter()
            .find(|f| f.address == a)
    }
}

// ---------------------------------------------------------------- text diff

/// How a line of a diff relates to the two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// On both sides.
    Same,
    /// Only the original has it.
    Original,
    /// Only the rewritten program has it.
    Rewritten,
}

/// One line of a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// Where the line is.
    pub kind: DiffKind,
    /// The text, without its newline.
    pub text: String,
}

/// Most lines per side the diff works on (the longest common subsequence is quadratic).
const MAX_DIFF_LINES: usize = 400;

/// A line diff of `original` against `rewritten`: lines on both sides, then runs of lines on one
/// side only (the original's first). Text past [`MAX_DIFF_LINES`] lines is left out.
pub fn line_diff(original: &str, rewritten: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = original.split('\n').take(MAX_DIFF_LINES).collect();
    let b: Vec<&str> = rewritten.split('\n').take(MAX_DIFF_LINES).collect();
    // lcs[i][j]: length of the longest common subsequence of a[i..] and b[j..].
    let mut lcs = vec![vec![0u16; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out: Vec<DiffLine> = Vec::new();
    let (mut i, mut j) = (0, 0);
    let (mut gone, mut came): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    let flush = |out: &mut Vec<DiffLine>, gone: &mut Vec<&str>, came: &mut Vec<&str>| {
        out.extend(gone.drain(..).map(|t| DiffLine {
            kind: DiffKind::Original,
            text: t.to_string(),
        }));
        out.extend(came.drain(..).map(|t| DiffLine {
            kind: DiffKind::Rewritten,
            text: t.to_string(),
        }));
    };
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            flush(&mut out, &mut gone, &mut came);
            out.push(DiffLine {
                kind: DiffKind::Same,
                text: a[i].to_string(),
            });
            i += 1;
            j += 1;
        } else if j < b.len() && (i == a.len() || lcs[i][j + 1] >= lcs[i + 1][j]) {
            came.push(b[j]);
            j += 1;
        } else {
            gone.push(a[i]);
            i += 1;
        }
    }
    flush(&mut out, &mut gone, &mut came);
    // A trailing empty line is the final newline, not a difference worth a row.
    while out
        .last()
        .is_some_and(|l| l.text.is_empty() && l.kind == DiffKind::Same)
    {
        out.pop();
    }
    out
}

impl ProgramCaseItem {
    /// The diff of standard output.
    pub fn stdout_diff(&self) -> Vec<DiffLine> {
        line_diff(&self.original.stdout, &self.rewritten.stdout)
    }

    /// The diff of standard error.
    pub fn stderr_diff(&self) -> Vec<DiffLine> {
        line_diff(&self.original.stderr, &self.rewritten.stderr)
    }

    /// The exit statuses agree.
    pub fn exit_agrees(&self) -> bool {
        self.original.exit == self.rewritten.exit
    }
}

// ---------------------------------------------------------------- flow

/// "pass on 9 cases", "fail: 2 of 9 cases differ", ...
pub fn verdict_line(v: &ProgramVerdictItem) -> String {
    match v.verdict.as_str() {
        "pass" => format!(
            "The rewritten program did the same as the original on all {} cases.",
            v.cases_run
        ),
        "fail" => format!(
            "The rewritten program differs from the original on {} of {} cases.",
            v.failed, v.cases_run
        ),
        "incomplete" => format!(
            "No runnable rewrite exists. {}",
            v.detail.as_deref().unwrap_or("")
        )
        .trim_end()
        .to_string(),
        "inconclusive" => format!(
            "The cases could not tell. {}",
            v.detail.as_deref().unwrap_or("")
        )
        .trim_end()
        .to_string(),
        _ => "The program was not run.".to_string(),
    }
}

impl ViewModel {
    /// Loads the stored runs once, when the Program view is first shown.
    pub fn rewrite_program_ensure_loaded(&mut self) {
        if !self.rewrite.program.loaded && !self.rewrite.program.loading {
            self.rewrite_program_refresh(None);
        }
    }

    /// Reads the stored runs and shows run `run`, else the newest.
    pub fn rewrite_program_refresh(&mut self, run: Option<u64>) {
        let st = &mut self.rewrite.program;
        st.generation += 1;
        st.loading = true;
        st.error = None;
        let generation = st.generation;
        let mut args = json!({ "all_cases": st.all_cases });
        if let Some(r) = run {
            args["run"] = json!(r);
        }
        self.call("rewrite_program_status", args, move |vm, res| {
            if vm.rewrite.program.generation != generation {
                return;
            }
            let st = &mut vm.rewrite.program;
            st.loading = false;
            st.loaded = true;
            match res.and_then(parse::<RewriteProgramStatusOut>) {
                Ok(out) => {
                    st.runs = out
                        .runs
                        .into_iter()
                        .map(|r| ProgramRunItem {
                            run: r.run,
                            created: r.created,
                            entry: r.entry.0,
                            verdict: r.verdict,
                            cases_run: r.cases_run,
                            passed: r.passed,
                            crate_dir: r.crate_dir,
                        })
                        .collect();
                    st.detail = out.run.map(ProgramRunDetail::new);
                    st.selected_function = None;
                    st.selected_case = st.detail.as_ref().and_then(|d| {
                        d.verdict.cases.iter().position(|c| !c.agree).or(
                            if d.verdict.cases.is_empty() {
                                None
                            } else {
                                Some(0)
                            },
                        )
                    });
                }
                Err(e) => vm.rewrite_program_load_failed(&e),
            }
        });
    }

    fn rewrite_program_load_failed(&mut self, e: &ProtoError) {
        if e.code == ErrorCode::Unsupported {
            if self.rewrite.availability == super::Availability::Unknown {
                self.rewrite.availability = super::Availability::NotAttached(plain_error(e));
            }
        } else if e.code != ErrorCode::NotFound {
            self.rewrite.program.error = Some(plain_error(e));
        }
    }

    /// Shows another stored run.
    pub fn rewrite_program_show_run(&mut self, run: u64) {
        self.rewrite_program_refresh(Some(run));
    }

    /// Lists the cases that agreed as well (or only the ones that differed).
    pub fn rewrite_program_set_all_cases(&mut self, all: bool) {
        if self.rewrite.program.all_cases == all {
            return;
        }
        self.rewrite.program.all_cases = all;
        let run = self.rewrite.program.detail.as_ref().map(|d| d.run);
        self.rewrite_program_refresh(run);
    }

    /// Shows case `index` of the loaded cases.
    pub fn rewrite_program_select_case(&mut self, index: usize) {
        let st = &mut self.rewrite.program;
        if st
            .detail
            .as_ref()
            .is_some_and(|d| index < d.verdict.cases.len())
        {
            st.selected_case = Some(index);
        }
    }

    /// Shows one function of the table.
    pub fn rewrite_program_select_function(&mut self, address: Option<u64>) {
        self.rewrite.program.selected_function = address;
    }

    /// How many repair rounds the Run button asks for.
    pub fn rewrite_program_set_rounds(&mut self, rounds: u32) {
        self.rewrite.program.repair_rounds = rounds.min(MAX_REPAIR_ROUNDS);
    }

    /// Why the typed test cases cannot be used, if so.
    pub fn rewrite_program_inputs_problem(&self) -> Option<String> {
        let cases: Vec<&ProgramInput> = self
            .rewrite
            .program
            .inputs
            .iter()
            .filter(|i| !i.is_blank())
            .collect();
        if cases.len() > kraken_registry::commands::MAX_USER_CASES {
            return Some(format!(
                "At most {} test cases can be added.",
                kraken_registry::commands::MAX_USER_CASES
            ));
        }
        for (n, c) in cases.iter().enumerate() {
            if c.name.trim().is_empty() {
                return Some(format!("Test case {} needs a name.", n + 1));
            }
            if let Err(e) = split_args(&c.args) {
                return Some(format!("Test case \"{}\": {e}", c.name.trim()));
            }
            if c.args.contains('\0') || c.stdin.contains('\0') {
                return Some(format!(
                    "Test case \"{}\" contains a character that cannot be passed to a program.",
                    c.name.trim()
                ));
            }
        }
        None
    }

    /// The `inputs` array of `rewrite_program` built from the typed cases.
    fn rewrite_program_inputs_json(&self) -> Vec<serde_json::Value> {
        self.rewrite
            .program
            .inputs
            .iter()
            .filter(|i| !i.is_blank())
            .map(|i| {
                let mut j = json!({
                    "name": i.name.trim(),
                    "argv": split_args(&i.args).unwrap_or_default(),
                });
                if !i.stdin.is_empty() {
                    j["stdin"] = json!(i.stdin);
                }
                j
            })
            .collect()
    }

    /// Where the typed output folder is, relative to the project.
    pub fn rewrite_program_dir_check(&self) -> Option<super::DirCheck> {
        let dir = self.rewrite.program.output_dir.trim();
        if dir.is_empty() {
            return None;
        }
        let project = self.project.as_ref().map(|p| p.project_dir.as_str());
        Some(super::check_export_dir(project, dir))
    }

    /// A program rewrite is going.
    pub fn rewrite_program_running(&self) -> bool {
        self.rewrite
            .jobs
            .iter()
            .any(|j| j.running() && j.kind == JobKind::Program)
    }

    /// Rewrites the whole program and compares it with the original; a job. The daemon asks the
    /// person first (the original program runs natively, in the sandbox) through the approval
    /// dialog, and the job does not start when the answer is no.
    pub fn rewrite_program_run(&mut self) {
        if !self.rewrite.can_run() || self.rewrite_program_running() {
            return;
        }
        if let Some(why) = self.rewrite_program_inputs_problem() {
            self.rewrite.program.error = Some(why);
            return;
        }
        if let Some(super::DirCheck::Invalid(why)) = self.rewrite_program_dir_check() {
            self.rewrite.program.error = Some(why);
            return;
        }
        self.rewrite.program.declined = None;
        self.rewrite.program.error = None;
        let st = &self.rewrite.program;
        let mut args = json!({
            "scope": "all",
            "repair_rounds": st.repair_rounds,
            "verify_functions": st.verify_functions,
        });
        let inputs = self.rewrite_program_inputs_json();
        if !inputs.is_empty() {
            args["inputs"] = json!(inputs);
        }
        let dir = st.output_dir.trim();
        if !dir.is_empty() {
            args["dir"] = json!(dir);
        }
        self.rewrite_start_job(
            JobKind::Program,
            "Rewriting the whole program".into(),
            "rewrite_program",
            args,
        );
    }

    /// The person said no to the approval question.
    pub(crate) fn rewrite_program_declined(&mut self) {
        self.rewrite.program.declined = Some(
            "Not run. Rewriting the whole program runs the original program on test inputs (inside a sandbox with no network), and you did not allow that."
                .into(),
        );
    }

    pub(crate) fn rewrite_program_done(
        &mut self,
        result: serde_json::Value,
    ) -> Result<String, String> {
        let r = parse::<RewriteProgramResult>(result).map_err(|e| plain_error(&e))?;
        let repaired = r.repairs.iter().filter(|x| x.outcome == "replaced").count();
        let mut text = format!(
            "Run {}: {} of {} functions are in the crate. {}",
            r.run,
            r.included,
            r.functions_planned,
            match r.verdict.verdict.as_str() {
                "pass" => format!(
                    "The program matches the original on {} cases.",
                    r.verdict.cases_run
                ),
                "fail" => format!(
                    "The program differs from the original on {} of {} cases.",
                    r.verdict.failed, r.verdict.cases_run
                ),
                other => format!("Program verdict: {other}."),
            }
        );
        if repaired > 0 {
            text.push_str(&format!(
                " {repaired} function{} translated again after the first run.",
                if repaired == 1 { " was" } else { "s were" }
            ));
        }
        let level = match r.verdict.verdict.as_str() {
            "pass" => ToastLevel::Success,
            "fail" => ToastLevel::Warning,
            _ => ToastLevel::Info,
        };
        let run = r.run;
        self.toast(level, text.clone());
        self.rewrite_program_refresh(Some(run));
        Ok(text)
    }
}
