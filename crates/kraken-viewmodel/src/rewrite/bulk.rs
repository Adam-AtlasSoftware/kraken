//! Bulk actions of the plan list: translate every planned function, retry every failed one,
//! accept every verified one.
//!
//! Translating runs one function at a time, in plan order, so callees are done before the
//! functions that call them and the model is never asked for twenty things at once.

use std::collections::VecDeque;

use serde_json::json;

use super::{JobKind, RewriteMode, UnitStatus};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::ViewModel;

/// An accept-all in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AcceptBatch {
    /// Functions being accepted.
    pub total: u32,
    /// Answers received.
    pub done: u32,
    /// Answers that were errors.
    pub failed: u32,
}

/// What the bulk actions are doing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkState {
    /// Functions still waiting to be translated, next first.
    pub queue: VecDeque<(u64, RewriteMode)>,
    /// Functions the current bulk translate started with.
    pub total: u32,
    /// What the current bulk translate is called.
    pub label: String,
    /// The accept-all in flight.
    pub accepting: Option<AcceptBatch>,
}

impl BulkState {
    /// Functions are waiting to be translated.
    pub fn active(&self) -> bool {
        !self.queue.is_empty()
    }
}

impl ViewModel {
    /// Functions in the plan that nothing has translated yet.
    pub fn rewrite_planned_count(&self) -> usize {
        self.rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Planned)
            .count()
    }

    /// Functions whose newest version failed.
    pub fn rewrite_failed_count(&self) -> usize {
        self.rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Failed)
            .count()
    }

    /// Functions whose newest version is verified and waits for an answer.
    pub fn rewrite_verified_count(&self) -> usize {
        self.rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Verified && !r.unit.is_empty())
            .count()
    }

    /// Why "Translate all planned" is off, when it is.
    pub fn rewrite_bulk_translate_blocker(&self) -> Option<String> {
        if let Some(n) = self.rewrite.blocked_note() {
            return Some(n.to_string());
        }
        if self.rewrite.bulk.active() {
            return Some("A bulk run is already going.".into());
        }
        if self.rewrite_planned_count() == 0 {
            return Some("Every function in the plan has already been translated.".into());
        }
        None
    }

    /// Why "Retry all failed" is off, when it is.
    pub fn rewrite_bulk_retry_blocker(&self) -> Option<String> {
        if let Some(n) = self.rewrite.blocked_note() {
            return Some(n.to_string());
        }
        if self.rewrite.bulk.active() {
            return Some("A bulk run is already going.".into());
        }
        if self.rewrite_failed_count() == 0 {
            return Some("No function has failed.".into());
        }
        None
    }

    /// Why "Accept all verified" is off, when it is.
    pub fn rewrite_bulk_accept_blocker(&self) -> Option<String> {
        if self.rewrite.bulk.accepting.is_some() {
            return Some("Accepting is already going.".into());
        }
        if self.rewrite_verified_count() == 0 {
            return Some("No function is verified and waiting to be accepted.".into());
        }
        None
    }

    /// Translates every planned function, one after the other, in plan order.
    pub fn rewrite_bulk_translate_planned(&mut self, mode: RewriteMode) {
        if self.rewrite_bulk_translate_blocker().is_some() {
            return;
        }
        let queue: VecDeque<(u64, RewriteMode)> = self
            .rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Planned)
            .map(|r| (r.address, mode))
            .collect();
        self.rewrite_bulk_start(queue, "Translating every planned function");
    }

    /// Runs every failed function again, each in the mode of its newest version.
    pub fn rewrite_bulk_retry_failed(&mut self) {
        if self.rewrite_bulk_retry_blocker().is_some() {
            return;
        }
        let queue: VecDeque<(u64, RewriteMode)> = self
            .rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Failed)
            .map(|r| {
                let mode = if r.mode.as_deref() == Some("spec") {
                    RewriteMode::Spec
                } else {
                    RewriteMode::Incremental
                };
                (r.address, mode)
            })
            .collect();
        self.rewrite_bulk_start(queue, "Retrying every failed function");
    }

    fn rewrite_bulk_start(&mut self, queue: VecDeque<(u64, RewriteMode)>, label: &str) {
        let b = &mut self.rewrite.bulk;
        b.total = u32::try_from(queue.len()).unwrap_or(u32::MAX);
        b.queue = queue;
        b.label = label.into();
        self.rewrite_bulk_advance();
    }

    /// Starts the next waiting function when none is running. Called whenever a job ends.
    pub(crate) fn rewrite_bulk_advance(&mut self) {
        if self.rewrite.bulk.queue.is_empty() {
            return;
        }
        if !self.rewrite.can_run() {
            self.rewrite.bulk.queue.clear();
            return;
        }
        let function_running = self
            .rewrite
            .jobs
            .iter()
            .any(|j| j.running() && matches!(j.kind, JobKind::Function { .. }));
        if function_running {
            return;
        }
        if let Some((address, mode)) = self.rewrite.bulk.queue.pop_front() {
            self.rewrite_run(address, mode);
            if self.rewrite.running_for(address).is_none() {
                // Nothing started (it was already running, or code cannot run); try the next.
                self.rewrite_bulk_advance();
            }
        }
    }

    /// Functions the current bulk translate has finished.
    pub fn rewrite_bulk_done(&self) -> u32 {
        let running = self
            .rewrite
            .jobs
            .iter()
            .filter(|j| j.running() && matches!(j.kind, JobKind::Function { .. }))
            .count();
        let left = self.rewrite.bulk.queue.len() + running;
        self.rewrite
            .bulk
            .total
            .saturating_sub(u32::try_from(left).unwrap_or(u32::MAX))
    }

    /// Stops the bulk run after the function that is running now, and asks that one to stop too.
    pub fn rewrite_bulk_cancel(&mut self) {
        self.rewrite.bulk.queue.clear();
        let ids: Vec<String> = self
            .rewrite
            .jobs
            .iter()
            .filter(|j| j.running() && matches!(j.kind, JobKind::Function { .. }))
            .filter_map(|j| j.job_id.clone())
            .collect();
        for id in ids {
            self.call("job_cancel", json!({ "job_id": id }), |_, _| {});
        }
    }

    /// Accepts the newest version of every verified function. A person's step: it is only
    /// reachable from buttons.
    pub fn rewrite_bulk_accept_verified(&mut self) {
        if self.rewrite_bulk_accept_blocker().is_some() {
            return;
        }
        let units: Vec<String> = self
            .rewrite
            .rows
            .iter()
            .filter(|r| r.status == UnitStatus::Verified && !r.unit.is_empty())
            .map(|r| r.unit.clone())
            .collect();
        self.rewrite.bulk.accepting = Some(AcceptBatch {
            total: u32::try_from(units.len()).unwrap_or(u32::MAX),
            ..AcceptBatch::default()
        });
        for unit in units {
            self.call("rewrite_accept", json!({ "unit": unit }), |vm, res| {
                let first_error = res.err().map(|e| plain_error(&e));
                vm.rewrite_accept_answered(first_error);
            });
        }
    }

    fn rewrite_accept_answered(&mut self, error: Option<String>) {
        let Some(b) = self.rewrite.bulk.accepting.as_mut() else {
            return;
        };
        b.done += 1;
        if error.is_some() {
            b.failed += 1;
        }
        if b.done < b.total {
            return;
        }
        let batch = *b;
        self.rewrite.bulk.accepting = None;
        let ok = batch.total - batch.failed;
        let (level, text) = if batch.failed == 0 {
            (
                ToastLevel::Success,
                format!(
                    "Accepted {ok} function{}. They will be part of the export.",
                    if ok == 1 { "" } else { "s" }
                ),
            )
        } else {
            (
                ToastLevel::Warning,
                format!(
                    "Accepted {ok} of {} functions. {} could not be accepted; open them to see why.",
                    batch.total, batch.failed
                ),
            )
        };
        self.toast(level, text);
        self.rewrite_refresh();
        if let Some(a) = self.rewrite.selected {
            self.rewrite_select(a);
        }
    }
}
