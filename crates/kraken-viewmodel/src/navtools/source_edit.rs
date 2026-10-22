//! The Edit tab (experimental): edit a function's decompiled C, have the assistant's model plan
//! the byte patch that does the same (`patch_from_source`), look at the check, then stage the
//! patches (`patch_set`) and run them from the Patches tab.

use kraken_proto::Hex64;
use kraken_registry::commands::{PatchFromSourceResult, SourcePatchVerdict, source_patch_result};
use serde_json::{Value, json};

use super::NavTab;
use super::patches::spaced_hex;
use crate::errors::plain_error;
use crate::state::{Load, ToastLevel};
use crate::vm::{ViewModel, hex};

/// How long one `job_await` waits before the window looks again.
const AWAIT_MS: u64 = 1500;

/// Where the edit stands.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceEditPhase {
    /// Being edited.
    Editing,
    /// The model is planning and checking (job id, once known).
    Planning(Option<String>),
    /// A plan came back.
    Planned(Box<PatchFromSourceResult>),
    /// The plan's patches are being staged.
    Staging(Box<PatchFromSourceResult>),
    /// The plan's patches are staged.
    Staged(Box<PatchFromSourceResult>),
    /// Planning failed (plain language).
    Failed(String),
}

/// The function being edited.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceEdit {
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// The decompile as it was when the edit began.
    pub original: String,
    /// The text being edited.
    pub text: String,
    /// Where it stands.
    pub phase: SourceEditPhase,
}

impl SourceEdit {
    /// True when the text differs from the decompile.
    pub fn changed(&self) -> bool {
        self.text.trim() != self.original.trim()
    }

    /// The lines that differ, as `(line number, before, after)` (1-based; a side is empty when
    /// the line is added or removed). A plain line-by-line comparison: enough for small edits.
    pub fn changed_lines(&self) -> Vec<(usize, String, String)> {
        let a: Vec<&str> = self.original.lines().collect();
        let b: Vec<&str> = self.text.lines().collect();
        (0..a.len().max(b.len()))
            .filter_map(|i| {
                let (x, y) = (
                    a.get(i).copied().unwrap_or(""),
                    b.get(i).copied().unwrap_or(""),
                );
                (x.trim_end() != y.trim_end()).then(|| (i + 1, x.to_string(), y.to_string()))
            })
            .collect()
    }

    /// The plan, when there is one.
    pub fn plan(&self) -> Option<&PatchFromSourceResult> {
        match &self.phase {
            SourceEditPhase::Planned(p)
            | SourceEditPhase::Staging(p)
            | SourceEditPhase::Staged(p) => Some(p),
            _ => None,
        }
    }

    /// True while the model works.
    pub fn busy(&self) -> bool {
        matches!(
            self.phase,
            SourceEditPhase::Planning(_) | SourceEditPhase::Staging(_)
        )
    }
}

/// A verdict in words, and whether it is good news.
pub fn verdict_text(v: SourcePatchVerdict) -> (&'static str, bool) {
    match v {
        SourcePatchVerdict::Matches => {
            ("Verified: the patched code decompiles to your edit.", true)
        }
        SourcePatchVerdict::Partial => (
            "Partly verified: some of your edit shows after patching.",
            false,
        ),
        SourcePatchVerdict::Mismatch => (
            "Not verified: the patched code does not match your edit.",
            false,
        ),
        SourcePatchVerdict::Unverified => (
            "Not checked: the patched code could not be decompiled again. Check it yourself.",
            false,
        ),
    }
}

impl ViewModel {
    /// Opens the Edit tab on the function in the decompiler, starting from its decompile.
    pub fn begin_source_edit(&mut self) {
        let Some(cur) = self.current.as_ref() else {
            self.toast(ToastLevel::Info, "Open a function first, then patch it.");
            return;
        };
        let Load::Ready(d) = &cur.decompiled else {
            self.toast(
                ToastLevel::Info,
                "Wait for the decompiler to finish, then patch the function.",
            );
            return;
        };
        let text = d.result.text.clone();
        let (address, name) = (cur.address, cur.name.clone());
        let same = self
            .tools
            .source_edit
            .as_ref()
            .is_some_and(|e| e.address == address);
        if !same {
            self.tools.source_edit = Some(SourceEdit {
                address,
                name,
                original: text.clone(),
                text,
                phase: SourceEditPhase::Editing,
            });
        }
        self.ensure_patches();
        self.tools.request_tab(NavTab::Edit);
    }

    /// Updates the text being edited (ignored while the model works).
    pub fn set_source_edit_text(&mut self, text: impl Into<String>) {
        if let Some(e) = self.tools.source_edit.as_mut().filter(|e| !e.busy()) {
            e.text = text.into();
            if !matches!(e.phase, SourceEditPhase::Editing) {
                e.phase = SourceEditPhase::Editing;
            }
        }
    }

    /// Puts the decompile back.
    pub fn reset_source_edit(&mut self) {
        if let Some(e) = self.tools.source_edit.as_mut().filter(|e| !e.busy()) {
            e.text = e.original.clone();
            e.phase = SourceEditPhase::Editing;
        }
    }

    /// Closes the edit.
    pub fn discard_source_edit(&mut self) {
        if let Some(SourceEditPhase::Planning(Some(job))) =
            self.tools.source_edit.as_ref().map(|e| e.phase.clone())
        {
            self.call("job_cancel", json!({"job_id": job}), |_, _| {});
        }
        self.tools.source_edit = None;
    }

    /// Asks the model for the patch (after the AI cost question, when one is due).
    pub fn plan_source_edit(&mut self) {
        let Some(e) = self.tools.source_edit.as_ref() else {
            return;
        };
        if e.busy() {
            return;
        }
        if !e.changed() {
            self.toast(
                ToastLevel::Info,
                "Change the code first: the patch is planned from your edit.",
            );
            return;
        }
        if self.ai_gate(crate::ai::AiAction::PatchFromSource(e.address)) {
            self.plan_source_edit_now();
        }
    }

    pub(crate) fn plan_source_edit_now(&mut self) {
        let Some(e) = self.tools.source_edit.as_mut() else {
            return;
        };
        e.phase = SourceEditPhase::Planning(None);
        let (address, source) = (e.address, e.text.clone());
        self.call(
            "patch_from_source",
            json!({"address": hex(address), "source": source}),
            move |vm, res| match res {
                Ok(v) => match v.get("job_id").and_then(Value::as_str) {
                    Some(job) => {
                        let job = job.to_string();
                        if let Some(e) = vm.source_edit_at(address) {
                            e.phase = SourceEditPhase::Planning(Some(job.clone()));
                        }
                        vm.await_source_patch(address, job);
                    }
                    None => vm.source_edit_failed(address, "The planner did not start a job."),
                },
                Err(e) => vm.source_edit_failed(address, &plain_error(&e)),
            },
        );
    }

    fn source_edit_at(&mut self, address: u64) -> Option<&mut SourceEdit> {
        self.tools
            .source_edit
            .as_mut()
            .filter(|e| e.address == address)
    }

    fn source_edit_failed(&mut self, address: u64, why: &str) {
        if let Some(e) = self.source_edit_at(address) {
            e.phase = SourceEditPhase::Failed(why.to_string());
        }
    }

    /// Waits for the planning job a little at a time, so the window stays live and Discard
    /// can stop it.
    fn await_source_patch(&mut self, address: u64, job: String) {
        let still = self.tools.source_edit.as_ref().is_some_and(|e| {
            e.address == address && e.phase == SourceEditPhase::Planning(Some(job.clone()))
        });
        if !still {
            return;
        }
        let args = json!({"job_id": job.clone(), "timeout_ms": AWAIT_MS});
        self.call("job_await", args, move |vm, res| {
            let v = match res {
                Ok(v) => v,
                Err(e) => return vm.source_edit_failed(address, &plain_error(&e)),
            };
            match v.get("status").and_then(Value::as_str) {
                Some("succeeded") => match source_patch_result(&v["result"]) {
                    Ok(plan) => {
                        if let Some(e) = vm.source_edit_at(address) {
                            e.phase = SourceEditPhase::Planned(Box::new(plan));
                        }
                    }
                    Err(e) => vm.source_edit_failed(address, &plain_error(&e)),
                },
                Some("failed") | Some("cancelled") => {
                    let why = v
                        .pointer("/error/message")
                        .and_then(Value::as_str)
                        .unwrap_or("The planner stopped.");
                    vm.source_edit_failed(address, &kraken_proto::sanitize(why));
                }
                _ => vm.await_source_patch(address, job),
            }
        });
    }

    /// Stages every patch of the plan (`patch_set`, one after the other).
    pub fn stage_source_edit(&mut self) {
        let Some(e) = self.tools.source_edit.as_mut() else {
            return;
        };
        let SourceEditPhase::Planned(plan) = &e.phase else {
            return;
        };
        if plan.patches.is_empty() {
            return;
        }
        let plan = plan.clone();
        e.phase = SourceEditPhase::Staging(plan.clone());
        let (address, name) = (e.address, e.name.clone());
        self.stage_next(address, name, plan, 0, Vec::new());
    }

    fn stage_next(
        &mut self,
        address: u64,
        name: String,
        plan: Box<PatchFromSourceResult>,
        index: usize,
        errors: Vec<String>,
    ) {
        let Some(p) = plan.patches.get(index).cloned() else {
            let total = plan.patches.len();
            if let Some(e) = self.source_edit_at(address) {
                e.phase = if errors.is_empty() {
                    SourceEditPhase::Staged(plan)
                } else {
                    SourceEditPhase::Planned(plan)
                };
            }
            self.refresh_patches();
            if errors.is_empty() {
                self.toast(
                    ToastLevel::Success,
                    format!(
                        "Staged {total} patch{}. Run them from the Patches tab; nothing on disk \
                         changes until you export.",
                        if total == 1 { "" } else { "es" }
                    ),
                );
            } else {
                self.toast(
                    ToastLevel::Error,
                    format!("Not every patch could be staged: {}", errors.join(" ")),
                );
            }
            return;
        };
        let note = format!(
            "From an edit of {name}: {}",
            p.explanation.0.chars().take(300).collect::<String>()
        );
        let args = json!({
            "address": Hex64(p.address.0),
            "bytes": spaced_hex(&decode(&p.replacement)),
            "note": note,
        });
        self.call("patch_set", args, move |vm, res| {
            let mut errors = errors;
            if let Err(e) = res {
                errors.push(plain_error(&e));
            }
            vm.stage_next(address, name, plan, index + 1, errors);
        });
    }

    /// After staging: the Patches tab, with the original and the patched program run side by
    /// side.
    pub fn verify_source_edit(&mut self) {
        self.show_patches();
        self.run_patched_compare();
    }
}

fn decode(hex: &str) -> Vec<u8> {
    super::patches::parse_hex(hex).unwrap_or_default()
}
