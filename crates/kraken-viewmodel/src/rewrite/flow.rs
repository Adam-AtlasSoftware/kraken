//! The Rewrite tab's actions: loading the plan, selecting a function, running the jobs and
//! reading their results.

use std::collections::HashMap;

use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};

use super::wire::{
    AcceptWire, CounterexampleWire, DecompileTextWire, ExportWire, PlanWire, RowWire, SpecWire,
    StartedWire, StatusWire, UnitWire, VersionWire,
};
use super::{
    Availability, CodePane, Counterexample, Counts, DirCheck, ExportSummary, Flag, FunctionPlan,
    JOBS_KEPT, JobKind, MAX_ROWS, PlanSummary, RewriteJob, RewriteMode, SpecDoc, UnitDetail,
    UnitItem, UnitStatus, VersionItem, check_export_dir, highlight_rust,
};
use crate::backend::{JobInfo, JobState};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

fn item(w: RowWire) -> UnitItem {
    UnitItem {
        unit: w.unit,
        order: w.order,
        address: w.address.0,
        name: w.name.0,
        status: UnitStatus::parse(&w.status).unwrap_or(UnitStatus::Planned),
        version: w.version,
        accepted_version: w.accepted_version,
        mode: w.mode,
        verdict: w.verdict,
        cases_run: w.cases_run,
        passed: w.passed,
        counterexamples: w.counterexamples,
        provider: w.provider,
        model: w.model,
        flags: w.flags.iter().map(|f| Flag::from_wire(f)).collect(),
    }
}

fn counterexample(w: CounterexampleWire) -> Counterexample {
    Counterexample {
        args: w.args,
        differences: w.differences.into_iter().map(|d| d.0).collect(),
    }
}

pub(super) fn version(w: VersionWire) -> VersionItem {
    VersionItem {
        unit: w.unit,
        version: w.version,
        mode: if w.mode.as_deref() == Some("spec") {
            RewriteMode::Spec
        } else {
            RewriteMode::Incremental
        },
        status: if w.accepted {
            UnitStatus::Accepted
        } else {
            UnitStatus::parse(&w.status).unwrap_or(UnitStatus::Translated)
        },
        verdict: w.verdict,
        verdict_detail: w.verdict_detail.map(|d| d.0),
        cases_run: w.cases_run,
        passed: w.passed,
        skipped: w.skipped,
        counterexample: w.counterexample.map(counterexample),
        prototype: w.rust_prototype,
        rust: w.rust_code.map(|c| {
            let tokens = highlight_rust(&c.0);
            CodePane::new("rust", c.0, tokens)
        }),
        sandbox: w.sandbox,
        provider: w.provider,
        model: w.model,
        assumptions: w.assumptions.into_iter().map(|a| a.0).collect(),
        unsupported: w.unsupported.into_iter().map(|a| a.0).collect(),
        coverage: w.coverage.map(|c| super::CoverageItem {
            blocks: c.blocks,
            hit: c.hit,
            missed: c.missed.into_iter().map(|a| a.0).collect(),
            cases: c.cases,
        }),
        user_cases: w.user_cases,
    }
}

impl ViewModel {
    // ---------------------------------------------------------------- the plan

    /// Loads the plan once, when the tab is first shown.
    pub fn rewrite_ensure_loaded(&mut self) {
        if !self.rewrite.loaded && !self.rewrite.loading {
            self.rewrite_refresh();
        }
    }

    /// Reloads the status of every function.
    pub fn rewrite_refresh(&mut self) {
        self.rewrite.generation += 1;
        self.rewrite.loading = true;
        self.rewrite.error = None;
        let generation = self.rewrite.generation;
        self.rewrite_fetch_status(None, generation, Vec::new());
    }

    fn rewrite_fetch_status(
        &mut self,
        cursor: Option<String>,
        generation: u64,
        rows: Vec<UnitItem>,
    ) {
        let mut args = json!({ "limit": 200 });
        if let Some(c) = cursor {
            args["cursor"] = json!(c);
        }
        self.call("rewrite_status", args, move |vm, res| {
            if vm.rewrite.generation != generation {
                return;
            }
            match res.and_then(parse::<StatusWire>) {
                Ok(w) => {
                    let StatusWire {
                        plan_present,
                        counts,
                        units,
                        next_cursor,
                    } = w;
                    let mut rows = rows;
                    rows.extend(units.into_iter().map(item));
                    match next_cursor {
                        Some(c) if rows.len() < MAX_ROWS => {
                            vm.rewrite_fetch_status(Some(c), generation, rows);
                        }
                        more => {
                            let st = &mut vm.rewrite;
                            st.truncated_list = more.is_some();
                            st.plan_present = plan_present;
                            st.counts = Counts {
                                planned: counts.planned,
                                translated: counts.translated,
                                verified: counts.verified,
                                failed: counts.failed,
                                accepted: counts.accepted,
                            };
                            st.rows = rows;
                            st.loading = false;
                            st.loaded = true;
                        }
                    }
                }
                Err(e) => vm.rewrite_load_failed(&e),
            }
        });
    }

    fn rewrite_load_failed(&mut self, e: &ProtoError) {
        let st = &mut self.rewrite;
        st.loading = false;
        st.loaded = true;
        if e.code == ErrorCode::Unsupported {
            if st.availability == Availability::Unknown {
                st.availability = Availability::NotAttached(plain_error(e));
            }
        } else {
            st.error = Some(plain_error(e));
        }
    }

    /// Plans the whole program (or plans it again) and reloads the list.
    pub fn rewrite_make_plan(&mut self) {
        if self.rewrite.loading {
            return;
        }
        self.rewrite.loading = true;
        self.rewrite.error = None;
        self.call(
            "rewrite_plan",
            json!({ "scope": "all", "limit": 1 }),
            |vm, res| match res.and_then(parse::<PlanWire>) {
                Ok(p) => {
                    vm.rewrite.plan_summary = Some(PlanSummary {
                        functions_total: p.functions_total,
                        functions_planned: p.functions_planned,
                        skipped_imports: p.skipped_imports,
                        skipped_runtime: p.skipped_runtime,
                        groups: p.groups,
                        truncated: p.truncated,
                    });
                    vm.rewrite.loading = false;
                    vm.rewrite_refresh();
                }
                Err(e) => vm.rewrite_load_failed(&e),
            },
        );
    }

    // ---------------------------------------------------------------- one function

    pub(super) fn rewrite_name(&self, address: u64) -> String {
        self.rewrite
            .row(address)
            .map(|r| r.name.clone())
            .or_else(|| {
                self.functions
                    .items
                    .iter()
                    .find(|f| f.address == address)
                    .map(|f| f.name.clone())
            })
            .unwrap_or_else(|| hex(address))
    }

    /// Opens the detail of the function at `address`.
    pub fn rewrite_select(&mut self, address: u64) {
        self.rewrite.selected = Some(address);
        let name = self.rewrite_name(address);
        let d = self
            .rewrite
            .details
            .entry(address)
            .or_insert_with(|| UnitDetail {
                address,
                name,
                ..UnitDetail::default()
            });
        d.loading = true;
        d.error = None;
        let need_c = d.c.is_none();
        if need_c {
            self.rewrite_load_c(address);
        }
        self.rewrite_load_plan(address);
        self.rewrite_load_unit(address);
    }

    /// Closes the detail.
    pub fn rewrite_deselect(&mut self) {
        self.rewrite.selected = None;
    }

    /// Shows version `number` of the selected function instead of the newest.
    pub fn rewrite_show_version(&mut self, address: u64, number: u32) {
        if let Some(d) = self.rewrite.details.get_mut(&address) {
            d.shown = Some(number);
        }
    }

    fn rewrite_load_c(&mut self, address: u64) {
        self.call(
            "decompile",
            json!({ "address": hex(address) }),
            move |vm, res| {
                if let Ok(w) = res.and_then(parse::<DecompileTextWire>)
                    && let Some(d) = vm.rewrite.details.get_mut(&address)
                {
                    let tokens = crate::tokenize(&w.text.0, &HashMap::new());
                    d.c = Some(CodePane::new("c", w.text.0, tokens));
                }
            },
        );
    }

    fn rewrite_load_plan(&mut self, address: u64) {
        self.call(
            "rewrite_plan",
            json!({ "scope": "function", "address": hex(address) }),
            move |vm, res| {
                let Ok(p) = res.and_then(parse::<PlanWire>) else {
                    return;
                };
                let names: HashMap<u64, String> = p
                    .entries
                    .iter()
                    .filter_map(|e| e.name.as_ref().map(|n| (e.address.0, n.0.clone())))
                    .collect();
                let Some(own) = p.entries.iter().find(|e| e.address.0 == address) else {
                    return;
                };
                let plan = FunctionPlan {
                    callees: own
                        .callees
                        .iter()
                        .map(|c| {
                            let name = names.get(&c.0).cloned().unwrap_or_else(|| hex(c.0));
                            (c.0, name)
                        })
                        .collect(),
                    imports: own.imports.iter().map(|i| i.0.clone()).collect(),
                    needs_stubs: own.needs_stubs.iter().map(|i| i.0.clone()).collect(),
                    group_size: own.group_size.max(1),
                };
                if let Some(d) = vm.rewrite.details.get_mut(&address) {
                    d.plan = Some(plan);
                }
            },
        );
    }

    const NO_UNIT_QUERY: &'static str = "The generated Rust and the earlier versions of this function are kept in the project, but the running daemon cannot send them to this window yet. Results from rewrites started in this window are shown below.";

    pub(super) fn rewrite_load_unit(&mut self, address: u64) {
        let offered = {
            let cmds = self.backend().commands();
            cmds.is_empty() || cmds.iter().any(|c| c.name == "rewrite_unit")
        };
        if !offered || self.rewrite.unit_query == Some(false) {
            self.rewrite.unit_query = Some(false);
            if let Some(d) = self.rewrite.details.get_mut(&address) {
                d.loading = false;
                d.stored_note = Some(Self::NO_UNIT_QUERY.into());
            }
            return;
        }
        self.call(
            "rewrite_unit",
            json!({ "address": hex(address) }),
            move |vm, res| {
                let missing = matches!(&res, Err(e)
                    if e.code == ErrorCode::Unsupported
                        || (e.code == ErrorCode::NotFound && e.message.contains("unknown command")));
                if missing {
                    vm.rewrite.unit_query = Some(false);
                }
                let parsed = res.and_then(parse::<UnitWire>);
                let Some(d) = vm.rewrite.details.get_mut(&address) else {
                    return;
                };
                d.loading = false;
                match parsed {
                    Ok(u) => {
                        d.stored = u.versions.into_iter().map(version).collect();
                        d.stored_note = None;
                        if let Some(s) = u.spec {
                            vm.rewrite.specs.insert(address, SpecDoc::new(s));
                        }
                    }
                    Err(_) if missing => d.stored_note = Some(Self::NO_UNIT_QUERY.into()),
                    Err(e) => d.stored_note = Some(plain_error(&e)),
                }
            },
        );
    }

    // ---------------------------------------------------------------- jobs

    pub(super) fn rewrite_start_job(
        &mut self,
        kind: JobKind,
        label: String,
        command: &'static str,
        args: Value,
    ) {
        let seq = self.rewrite.next_seq;
        self.rewrite.next_seq += 1;
        let jobs = &mut self.rewrite.jobs;
        jobs.push(RewriteJob {
            seq,
            job_id: None,
            kind,
            label,
            state: JobState::Running,
            progress: None,
            error: None,
            outcome: None,
        });
        while jobs.len() > JOBS_KEPT {
            match jobs.iter().position(|j| !j.running()) {
                Some(i) => jobs.remove(i),
                None => break,
            };
        }
        self.call(command, args, move |vm, res| {
            match res.and_then(parse::<StartedWire>) {
                Ok(s) => vm.rewrite_job_started(seq, s.job_id),
                Err(e) => vm.rewrite_job_not_started(seq, &e),
            }
        });
    }

    fn rewrite_job_started(&mut self, seq: u64, job_id: String) {
        let Some(idx) = self.rewrite.jobs.iter().position(|j| j.seq == seq) else {
            return;
        };
        self.rewrite.jobs[idx].job_id = Some(job_id.clone());
        // The daemon may have reported on the job before its reply reached us.
        if let Some(p) = self.rewrite.stash.iter().position(|(id, _)| *id == job_id) {
            let (_, info) = self.rewrite.stash.remove(p);
            self.rewrite_apply_job(idx, info);
        }
    }

    fn rewrite_job_not_started(&mut self, seq: u64, e: &ProtoError) {
        let Some(idx) = self.rewrite.jobs.iter().position(|j| j.seq == seq) else {
            return;
        };
        let denied = e
            .details
            .as_ref()
            .and_then(|d| d.get("approval"))
            .and_then(Value::as_str)
            == Some("denied");
        let kind = self.rewrite.jobs[idx].kind.clone();
        if denied && matches!(kind, JobKind::Program | JobKind::Build) {
            // The person said no to running generated code: not an error, nothing to report.
            let job = &mut self.rewrite.jobs[idx];
            job.state = JobState::Cancelled;
            job.outcome = Some("Not run: not allowed.".into());
            if kind == JobKind::Program {
                self.rewrite_program_declined();
            } else {
                self.rewrite_build_declined();
            }
            return;
        }
        self.rewrite_job_failed(idx, e);
        self.rewrite_bulk_advance();
    }

    /// A job event from the backend; ignores everything but the `rewrite_*` jobs started here.
    pub(crate) fn rewrite_on_job(&mut self, info: &JobInfo) {
        if !info.command.starts_with("rewrite_") {
            return;
        }
        match self
            .rewrite
            .jobs
            .iter()
            .position(|j| j.job_id.as_deref() == Some(info.job_id.as_str()))
        {
            Some(idx) => self.rewrite_apply_job(idx, info.clone()),
            None => {
                let st = &mut self.rewrite;
                st.stash.retain(|(id, _)| *id != info.job_id);
                st.stash.push((info.job_id.clone(), info.clone()));
                if st.stash.len() > 16 {
                    st.stash.remove(0);
                }
            }
        }
    }

    fn rewrite_apply_job(&mut self, idx: usize, info: JobInfo) {
        let job = &mut self.rewrite.jobs[idx];
        if !job.running() {
            return;
        }
        job.state = info.status;
        if info.progress.is_some() {
            job.progress = info.progress.clone();
        }
        match info.status {
            JobState::Running => {}
            JobState::Succeeded => self.rewrite_job_succeeded(idx, info.result),
            JobState::Failed => {
                let e = info.error.unwrap_or_else(|| {
                    ProtoError::new(ErrorCode::Internal, "the job failed without a reason")
                });
                self.rewrite_job_failed(idx, &e);
            }
            JobState::Cancelled => {
                job.outcome = Some("Cancelled.".into());
            }
        }
        self.rewrite_bulk_advance();
    }

    fn rewrite_job_failed(&mut self, idx: usize, e: &ProtoError) {
        let why = plain_error(e);
        let job = &mut self.rewrite.jobs[idx];
        job.state = JobState::Failed;
        job.error = Some(why.clone());
        let kind = job.kind.clone();
        let label = job.label.clone();
        let cannot_confine = e.code == ErrorCode::Unsupported;
        match kind {
            JobKind::Function { address, .. } => {
                if cannot_confine {
                    self.rewrite.availability = Availability::NoConfinement(why.clone());
                } else {
                    let name = self.rewrite_name(address);
                    let d = self
                        .rewrite
                        .details
                        .entry(address)
                        .or_insert_with(|| UnitDetail {
                            address,
                            name,
                            ..UnitDetail::default()
                        });
                    d.error = Some(why.clone());
                }
            }
            JobKind::Export => {
                if cannot_confine && self.rewrite.export.build {
                    self.rewrite.availability = Availability::NoConfinement(why.clone());
                    self.rewrite.export.build = false;
                }
                self.rewrite.export.error = Some(why.clone());
            }
            JobKind::Spec { .. } => {}
            JobKind::Verify { address } => {
                let name = self.rewrite_name(address);
                let d = self
                    .rewrite
                    .details
                    .entry(address)
                    .or_insert_with(|| UnitDetail {
                        address,
                        name,
                        ..UnitDetail::default()
                    });
                d.error = Some(why.clone());
            }
            JobKind::Program => {
                if cannot_confine {
                    self.rewrite.availability = Availability::NoConfinement(why.clone());
                }
                self.rewrite.program.error = Some(why.clone());
            }
            JobKind::Build => {
                if cannot_confine {
                    self.rewrite.availability = Availability::NoConfinement(why.clone());
                }
                self.rewrite.build.error = Some(why.clone());
            }
        }
        if !cannot_confine {
            self.toast(ToastLevel::Error, format!("{label} failed. {why}"));
        }
    }

    fn rewrite_job_succeeded(&mut self, idx: usize, result: Option<Value>) {
        let kind = self.rewrite.jobs[idx].kind.clone();
        let result = result.unwrap_or(Value::Null);
        let outcome = match kind {
            JobKind::Function { address, .. } => self.rewrite_function_done(address, result),
            JobKind::Spec { address } => self.rewrite_spec_done(address, result),
            JobKind::Export => self.rewrite_export_done(result),
            JobKind::Program => self.rewrite_program_done(result),
            JobKind::Build => self.rewrite_build_done(result),
            JobKind::Verify { address } => self.rewrite_verify_done(address, result),
        };
        match outcome {
            Ok(text) => self.rewrite.jobs[idx].outcome = Some(text),
            Err(e) => {
                self.rewrite.jobs[idx].state = JobState::Failed;
                self.rewrite.jobs[idx].error = Some(e);
            }
        }
    }

    fn rewrite_function_done(&mut self, address: u64, result: Value) -> Result<String, String> {
        let w = parse::<VersionWire>(result).map_err(|e| plain_error(&e))?;
        let v = version(w);
        let name = self.rewrite_name(address);
        let text = match (v.status, v.verdict.as_str()) {
            (UnitStatus::Verified, _) => format!(
                "{name}: verified. {} Review it, then accept it.",
                v.cases_line()
            ),
            (UnitStatus::Failed, "fail") => format!(
                "{name}: the Rust version differs from the original. See the counterexample."
            ),
            (UnitStatus::Failed, _) => format!(
                "{name}: the generated Rust was refused or did not compile. {}",
                v.verdict_detail.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
            _ => format!(
                "{name}: translated, but the test could not decide. {}",
                v.cases_line()
            ),
        };
        let level = match v.status {
            UnitStatus::Verified | UnitStatus::Accepted => ToastLevel::Success,
            UnitStatus::Failed => ToastLevel::Warning,
            _ => ToastLevel::Info,
        };
        let d = self
            .rewrite
            .details
            .entry(address)
            .or_insert_with(|| UnitDetail {
                address,
                name: name.clone(),
                ..UnitDetail::default()
            });
        d.session.retain(|s| s.version != v.version);
        d.session.push(v);
        d.shown = None;
        d.error = None;
        self.toast(level, text.clone());
        self.rewrite_refresh();
        if self.rewrite.selected == Some(address) {
            self.rewrite_load_unit(address);
        }
        Ok(text)
    }

    fn rewrite_spec_done(&mut self, address: Option<u64>, result: Value) -> Result<String, String> {
        let w = parse::<SpecWire>(result).map_err(|e| plain_error(&e))?;
        let doc = SpecDoc::new(w);
        let text = format!(
            "Spec written from {} function{} with {} cited fact{}.",
            doc.functions,
            if doc.functions == 1 { "" } else { "s" },
            doc.facts,
            if doc.facts == 1 { "" } else { "s" }
        );
        match address {
            Some(a) => {
                self.rewrite.specs.insert(a, doc);
            }
            None => self.rewrite.program_spec = Some(doc),
        }
        self.toast(ToastLevel::Success, text.clone());
        Ok(text)
    }

    fn rewrite_export_done(&mut self, result: Value) -> Result<String, String> {
        let w = parse::<ExportWire>(result).map_err(|e| plain_error(&e))?;
        let s = ExportSummary {
            dir: w.dir,
            crates: w.crates,
            symbols: w.symbols,
            built: w.built,
            sandbox: w.sandbox,
            accepted: w.coverage.accepted,
            planned: w.coverage.planned,
            functions_total: w.coverage.functions_total,
        };
        let text = format!(
            "Exported {} function{} to {}{}.",
            s.symbols.len(),
            if s.symbols.len() == 1 { "" } else { "s" },
            s.dir,
            if s.built { " and built it" } else { "" }
        );
        self.rewrite.export.result = Some(s);
        self.rewrite.export.error = None;
        self.toast(ToastLevel::Success, text.clone());
        Ok(text)
    }

    // ---------------------------------------------------------------- rewriting

    /// Translates the function at `address` and verifies it; a job.
    pub fn rewrite_run(&mut self, address: u64, mode: RewriteMode) {
        if !self.rewrite.can_run() || self.rewrite.running_for(address).is_some() {
            return;
        }
        if !self.ai_gate(crate::ai::AiAction::RewriteFunction { address, mode }) {
            return;
        }
        let name = self.rewrite_name(address);
        let label = match mode {
            RewriteMode::Incremental => format!("Rewriting {name}"),
            RewriteMode::Spec => format!("Rewriting {name} from its spec"),
        };
        if let Some(d) = self.rewrite.details.get_mut(&address) {
            d.error = None;
        }
        let mut args = json!({ "address": hex(address), "mode": mode.as_str() });
        self.ai_rewrite_args(&mut args);
        self.rewrite_start_job(
            JobKind::Function { address, mode },
            label,
            "rewrite_function",
            args,
        );
    }

    /// Runs the function again in the mode of its newest version.
    pub fn rewrite_retry(&mut self, address: u64) {
        if !self.ai_gate(crate::ai::AiAction::RetryFunction(address)) {
            return;
        }
        let mode = self
            .rewrite
            .details
            .get(&address)
            .and_then(|d| d.versions().last().map(|v| v.mode))
            .or_else(|| {
                self.rewrite
                    .row(address)
                    .and_then(|r| r.mode.as_deref())
                    .map(|m| {
                        if m == "spec" {
                            RewriteMode::Spec
                        } else {
                            RewriteMode::Incremental
                        }
                    })
            })
            .unwrap_or_default();
        let was = std::mem::replace(&mut self.ai.bypass, true);
        self.rewrite_run(address, mode);
        self.ai.bypass = was;
    }

    /// "Rewrite this function" for the function in the decompiler. Returns its address.
    pub fn rewrite_run_current(&mut self) -> Option<u64> {
        let addr = self.current.as_ref()?.address;
        self.rewrite_select(addr);
        self.rewrite_run(addr, RewriteMode::Incremental);
        Some(addr)
    }

    /// Accepts the newest verified version of the function at `address` (people only).
    pub fn rewrite_accept(&mut self, address: u64) {
        let Some(unit) = self.rewrite.acceptable_unit(address) else {
            return;
        };
        self.call(
            "rewrite_accept",
            json!({ "unit": unit }),
            move |vm, res| match res.and_then(parse::<AcceptWire>) {
                Ok(w) => {
                    let name = vm.rewrite_name(address);
                    let mut text = format!("Accepted {name}. It will be part of the export.");
                    if let Some(old) = w.replaced_version {
                        text.push_str(&format!(" It replaces version {old}."));
                    }
                    vm.toast(ToastLevel::Success, text);
                    vm.rewrite_refresh();
                    vm.rewrite_load_unit(address);
                }
                Err(e) => {
                    let why = plain_error(&e);
                    if let Some(d) = vm.rewrite.details.get_mut(&address) {
                        d.error = Some(why);
                    }
                    vm.toast_error(&e);
                }
            },
        );
    }

    // ---------------------------------------------------------------- specs

    /// Has the model write the spec of one function, or of the program for `None`; a job.
    pub fn rewrite_write_spec(&mut self, address: Option<u64>) {
        let (label, args) = match address {
            Some(a) => (
                format!("Writing the spec of {}", self.rewrite_name(a)),
                json!({ "scope": "function", "address": hex(a) }),
            ),
            None => (
                "Writing the spec of the program".to_string(),
                json!({ "scope": "all" }),
            ),
        };
        let running = self
            .rewrite
            .jobs
            .iter()
            .any(|j| j.running() && j.kind == JobKind::Spec { address });
        if running {
            return;
        }
        if !self.ai_gate(crate::ai::AiAction::WriteSpec(address)) {
            return;
        }
        let mut args = args;
        self.ai_rewrite_args(&mut args);
        self.rewrite_start_job(JobKind::Spec { address }, label, "rewrite_spec", args);
    }

    // ---------------------------------------------------------------- export

    /// Opens the export dialog.
    pub fn rewrite_export_open(&mut self) {
        let blocked = !self.rewrite.can_run();
        let e = &mut self.rewrite.export;
        e.open = true;
        e.error = None;
        e.ask_outside = false;
        e.agreed_outside = false;
        if blocked {
            e.build = false;
        }
    }

    /// Closes the export dialog.
    pub fn rewrite_export_close(&mut self) {
        self.rewrite.export.open = false;
        self.rewrite.export.ask_outside = false;
    }

    /// The person typed a different target folder.
    pub fn rewrite_export_set_dir(&mut self, dir: String) {
        let e = &mut self.rewrite.export;
        if e.dir != dir {
            e.dir = dir;
            e.ask_outside = false;
            e.agreed_outside = false;
            e.error = None;
        }
    }

    /// Where the typed folder is, relative to the project.
    pub fn rewrite_export_check(&self) -> DirCheck {
        let project = self.project.as_ref().map(|p| p.project_dir.as_str());
        check_export_dir(project, &self.rewrite.export.dir)
    }

    /// Starts the export. A folder outside the project first asks the person
    /// ([`ExportState::ask_outside`]); [`rewrite_export_agree_outside`](Self::rewrite_export_agree_outside)
    /// carries on after a yes.
    pub fn rewrite_export_start(&mut self) {
        if self.rewrite.exporting() {
            return;
        }
        match self.rewrite_export_check() {
            DirCheck::Invalid(why) => {
                self.rewrite.export.error = Some(why);
                return;
            }
            DirCheck::Outside if !self.rewrite.export.agreed_outside => {
                self.rewrite.export.ask_outside = true;
                self.rewrite.export.error = None;
                return;
            }
            _ => {}
        }
        let build = self.rewrite.export.build && self.rewrite.can_run();
        let e = &mut self.rewrite.export;
        e.ask_outside = false;
        e.error = None;
        e.result = None;
        let mut args = json!({ "dir": e.dir.trim(), "build": build });
        if !e.name.trim().is_empty() {
            args["name"] = json!(e.name.trim());
        }
        self.rewrite_start_job(
            JobKind::Export,
            "Exporting the accepted functions".into(),
            "rewrite_export",
            args,
        );
    }

    /// The person agreed to write outside the project folder.
    pub fn rewrite_export_agree_outside(&mut self) {
        self.rewrite.export.agreed_outside = true;
        self.rewrite_export_start();
    }
}
