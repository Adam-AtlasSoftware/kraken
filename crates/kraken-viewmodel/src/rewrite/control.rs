//! Human control over rewrite units in the Rewrite tab: reject, unaccept, replay the cases, add
//! a case, edit a spec; and the prerequisite rows of the Check step.

use serde_json::{Value, json};

use super::flow::version;
use super::wire::{CheckWire, VersionWire};
use super::{CheckLevel, JobKind, PrereqItem, UnitDetail, UnitStatus, VersionItem};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

impl super::RewriteState {
    /// The version that "Reject" would act on: the newest one, when it is neither failed nor
    /// accepted and its id is known.
    pub fn rejectable_unit(&self, address: u64) -> Option<&VersionItem> {
        let d = self.details.get(&address)?;
        let v = d.versions().into_iter().next_back()?;
        (!v.unit.is_empty() && matches!(v.status, UnitStatus::Verified | UnitStatus::Translated))
            .then_some(v)
    }

    /// The accepted version of the function, if one is listed.
    pub fn accepted_version(&self, address: u64) -> Option<&VersionItem> {
        let d = self.details.get(&address)?;
        d.versions()
            .into_iter()
            .find(|v| v.status == UnitStatus::Accepted && !v.unit.is_empty())
    }

    /// The version a replay or a new case would use: the one on show, when its id is known.
    pub fn replayable_unit(&self, address: u64) -> Option<&VersionItem> {
        let v = self.details.get(&address)?.current()?;
        (!v.unit.is_empty() && v.status != UnitStatus::Planned).then_some(v)
    }

    /// A replay or a case is running for the function.
    pub fn verifying(&self, address: u64) -> bool {
        self.jobs.iter().any(|j| {
            j.running() && matches!(&j.kind, JobKind::Verify { address: a } if *a == address)
        })
    }
}

impl ViewModel {
    // ---------------------------------------------------------------- prerequisites

    /// Asks the daemon what the host and the program provide for the rewrite.
    pub fn rewrite_check_refresh(&mut self) {
        if self.rewrite.prereqs_loading {
            return;
        }
        self.rewrite.prereqs_loading = true;
        self.call("rewrite_check", json!({}), |vm, res| {
            vm.rewrite.prereqs_loading = false;
            match res.and_then(parse::<CheckWire>) {
                Ok(w) => {
                    vm.rewrite.prereqs = Some(
                        w.checks
                            .into_iter()
                            .map(|c| PrereqItem {
                                id: c.id,
                                title: c.title,
                                level: match c.level.as_str() {
                                    "ok" => CheckLevel::Ok,
                                    "warn" => CheckLevel::Warn,
                                    _ => CheckLevel::Blocked,
                                },
                                detail: c.detail,
                                fix: c.fix,
                            })
                            .collect(),
                    );
                }
                // An older daemon has no such query: the other rows still tell what they can.
                Err(_) => vm.rewrite.prereqs = Some(Vec::new()),
            }
        });
    }

    // ---------------------------------------------------------------- unit decisions

    fn rewrite_after_change(&mut self, address: u64, text: String, level: ToastLevel) {
        self.toast(level, text);
        self.rewrite_refresh();
        self.rewrite_load_unit(address);
    }

    fn rewrite_control_failed(&mut self, address: u64, e: &kraken_proto::ProtoError) {
        let why = plain_error(e);
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
        d.error = Some(why);
        self.toast_error(e);
    }

    /// Rejects the newest version of the function (people only): it is never exported.
    pub fn rewrite_reject(&mut self, address: u64) {
        let Some(unit) = self
            .rewrite
            .rejectable_unit(address)
            .map(|v| v.unit.clone())
        else {
            return;
        };
        self.call(
            "rewrite_reject",
            json!({ "unit": unit, "reason": "rejected in the Rewrite tab" }),
            move |vm, res| match res {
                Ok(_) => {
                    let name = vm.rewrite_name(address);
                    vm.rewrite_after_change(
                        address,
                        format!("Rejected the latest version of {name}. It will not be exported."),
                        ToastLevel::Info,
                    );
                }
                Err(e) => vm.rewrite_control_failed(address, &e),
            },
        );
    }

    /// Takes the acceptance of the function back (people only).
    pub fn rewrite_unaccept(&mut self, address: u64) {
        let Some(unit) = self
            .rewrite
            .accepted_version(address)
            .map(|v| v.unit.clone())
        else {
            return;
        };
        self.call(
            "rewrite_unaccept",
            json!({ "unit": unit }),
            move |vm, res| match res {
                Ok(_) => {
                    let name = vm.rewrite_name(address);
                    vm.rewrite_after_change(
                        address,
                        format!("{name} is no longer accepted. It is out of the next export."),
                        ToastLevel::Info,
                    );
                }
                Err(e) => vm.rewrite_control_failed(address, &e),
            },
        );
    }

    // ---------------------------------------------------------------- replay and cases

    /// Replays every case of the version on show and measures what they reach; a job.
    pub fn rewrite_verify(&mut self, address: u64) {
        if !self.rewrite.can_run() || self.rewrite.verifying(address) {
            return;
        }
        let Some(unit) = self
            .rewrite
            .replayable_unit(address)
            .map(|v| v.unit.clone())
        else {
            return;
        };
        let name = self.rewrite_name(address);
        if let Some(d) = self.rewrite.details.get_mut(&address) {
            d.error = None;
        }
        self.rewrite_start_job(
            JobKind::Verify { address },
            format!("Replaying the cases of {name}"),
            "rewrite_verify",
            json!({ "unit": unit }),
        );
    }

    /// Adds a case you typed (JSON values for the parameters, separated by commas) and replays
    /// all cases; a job. The error is why the text was not understood.
    pub fn rewrite_add_case(&mut self, address: u64, text: &str) -> Result<(), String> {
        if !self.rewrite.can_run() || self.rewrite.verifying(address) {
            return Err("A replay is already running, or the sandbox is off.".into());
        }
        let Some(unit) = self
            .rewrite
            .replayable_unit(address)
            .map(|v| v.unit.clone())
        else {
            return Err("This version has no known id yet. Reload the function first.".into());
        };
        let values: Value = serde_json::from_str(&format!("[{}]", text.trim())).map_err(|e| {
            format!("The values are not JSON: {e}. Write them like: 5, {{\"text\": \"abc\"}}")
        })?;
        let name = self.rewrite_name(address);
        if let Some(d) = self.rewrite.details.get_mut(&address) {
            d.error = None;
        }
        self.rewrite_start_job(
            JobKind::Verify { address },
            format!("Adding a case to {name}"),
            "rewrite_add_case",
            json!({ "unit": unit, "args": values }),
        );
        Ok(())
    }

    pub(super) fn rewrite_verify_done(
        &mut self,
        address: u64,
        result: Value,
    ) -> Result<String, String> {
        let w = parse::<VersionWire>(result).map_err(|e| plain_error(&e))?;
        let v = version(w);
        let name = self.rewrite_name(address);
        let cov = v
            .coverage
            .as_ref()
            .map(|c| format!(" The cases reach {}.", c.line()))
            .unwrap_or_default();
        let (text, level) = match v.verdict.as_str() {
            "pass" => (
                format!("{name}: all {} cases agree.{cov}", v.cases_run),
                ToastLevel::Success,
            ),
            "fail" => (
                format!(
                    "{name}: the Rust version differs from the original on a case. It is now marked failed.{cov}"
                ),
                ToastLevel::Warning,
            ),
            _ => (
                format!(
                    "{name}: could not decide. {}",
                    v.verdict_detail.as_deref().unwrap_or("")
                )
                .trim_end()
                .to_string(),
                ToastLevel::Info,
            ),
        };
        self.rewrite_after_change(address, text.clone(), level);
        Ok(text)
    }

    // ---------------------------------------------------------------- specs

    /// Stores `markdown` as the function's spec.
    pub fn rewrite_edit_spec(&mut self, address: u64, markdown: String) {
        self.call(
            "rewrite_spec_edit",
            json!({ "address": hex(address), "markdown": markdown }),
            move |vm, res| match res {
                Ok(v) => match parse::<super::wire::SpecWire>(v) {
                    Ok(w) => {
                        vm.rewrite.specs.insert(address, super::SpecDoc::new(w));
                        vm.toast(ToastLevel::Success, "Saved your edit of the spec.");
                    }
                    Err(e) => vm.toast_error(&e),
                },
                Err(e) => vm.toast_error(&e),
            },
        );
    }
}
