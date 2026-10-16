//! The auto-name review table: the assistant only suggests; the person applies, so every applied
//! name is their own edit and `undo` reverses it.

use kraken_assist::{Confidence, EvidenceKind, TaskOutput, TaskResult};
use kraken_proto::{Hex64, ProtoError, sanitize};
use serde_json::{Value, json};

use super::{AutoNameReview, AutoNameState, ReviewRow, RowStatus};
use crate::backend::Backend;
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, validate_name};
use crate::wire::DetailWire;

/// Which suggestions to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyWhich {
    /// The ticked rows.
    Selected,
    /// Every row that can still be applied.
    All,
}

/// What a kind of evidence means, in words.
pub fn evidence_text(kind: EvidenceKind, detail: &str) -> String {
    let lead = match kind {
        EvidenceKind::String => "Uses the text",
        EvidenceKind::Import => "Calls the library function",
        EvidenceKind::Caller => "Called by",
        EvidenceKind::Callee => "Calls",
        EvidenceKind::Decompile => "From reading the code",
        EvidenceKind::Other => "Note",
    };
    let detail = sanitize(detail);
    if detail.trim().is_empty() {
        lead.to_string()
    } else {
        format!("{lead}: {}", detail.trim())
    }
}

/// The plain label of a confidence level.
pub fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::Low => "weak evidence",
        Confidence::Medium => "fair evidence",
        Confidence::High => "strong evidence",
    }
}

pub(crate) fn build_review(vm: &ViewModel, result: &TaskResult) -> AutoNameReview {
    let Some(TaskOutput::AutoName(report)) = &result.output else {
        return AutoNameReview::default();
    };
    let mut rows: Vec<ReviewRow> = Vec::new();
    for s in &report.suggestions {
        let Some(address) = s.address.trim().parse::<Hex64>().ok().map(|h| h.0) else {
            continue;
        };
        if rows.iter().any(|r| r.address == address) {
            continue;
        }
        let new_name = s
            .new_name
            .as_deref()
            .map(|n| sanitize(n.trim()))
            .filter(|n| !n.is_empty());
        let comment = s
            .comment
            .as_deref()
            .map(|c| sanitize(c.trim()))
            .filter(|c| !c.is_empty());
        if new_name.is_none() && comment.is_none() {
            continue;
        }
        // The name shown comes from the project, not from what the model remembers.
        let old_name = vm
            .functions
            .find(address)
            .map(|f| f.name.clone())
            .or_else(|| s.current_name.as_deref().map(sanitize))
            .unwrap_or_else(|| format!("{address:#x}"));
        rows.push(ReviewRow {
            address,
            old_name,
            new_name,
            comment,
            evidence: s
                .evidence
                .iter()
                .map(|e| evidence_text(e.kind, &e.detail))
                .collect(),
            confidence: s.confidence,
            basis: sanitize(&s.confidence_basis),
            selected: s.confidence != Confidence::Low,
            status: RowStatus::Pending,
        });
    }
    AutoNameReview {
        rows,
        note: sanitize(&report.note),
        busy: false,
        undoable: 0,
        message: None,
    }
}

fn name_key(addr: u64) -> String {
    format!("native:ram:{addr:#x}:name")
}

fn comment_key(addr: u64) -> String {
    format!("native:ram:{addr:#x}:comment:plate")
}

/// Applies one row as the person; returns how many log entries it created.
async fn apply_row(backend: &dyn Backend, row: &ReviewRow) -> Result<usize, String> {
    let hex = format!("{:#x}", row.address);
    let detail = backend
        .call("get_function", json!({ "address": hex }))
        .await
        .map_err(|e| plain_error(&e))?;
    let d: DetailWire = serde_json::from_value(detail)
        .map_err(|e| format!("Unexpected reply from the engine: {e}"))?;
    if d.function.name.0 != row.old_name {
        return Err(format!(
            "It is now called {}, so the suggestion was skipped.",
            d.function.name.0
        ));
    }
    let mut entries = 0usize;
    if let Some(name) = &row.new_name {
        let name = validate_name(name, &row.old_name)?;
        let v = d.versions.get(&name_key(row.address)).copied().unwrap_or(0);
        backend
            .call(
                "rename_symbol",
                json!({
                    "address": hex,
                    "new_name": name,
                    "expect_versions": { name_key(row.address): v },
                }),
            )
            .await
            .map_err(|e| plain_error(&e))?;
        entries += 1;
    }
    if let Some(text) = &row.comment {
        let v = d
            .versions
            .get(&comment_key(row.address))
            .copied()
            .unwrap_or(0);
        backend
            .call(
                "set_comment",
                json!({
                    "address": hex,
                    "kind": "plate",
                    "text": text,
                    "expect_versions": { comment_key(row.address): v },
                }),
            )
            .await
            .map_err(|e| plain_error(&e))?;
        entries += 1;
    }
    Ok(entries)
}

impl ViewModel {
    fn review_mut(&mut self) -> Option<&mut AutoNameReview> {
        match &mut self.assist.autoname {
            AutoNameState::Review(r) => Some(r),
            _ => None,
        }
    }

    /// Ticks or unticks row `index`.
    pub fn autoname_select(&mut self, index: usize, on: bool) {
        if let Some(row) = self.review_mut().and_then(|r| r.rows.get_mut(index)) {
            row.selected = on;
        }
    }

    /// Ticks or unticks every row.
    pub fn autoname_select_all(&mut self, on: bool) {
        if let Some(r) = self.review_mut() {
            r.rows.iter_mut().for_each(|row| row.selected = on);
        }
    }

    /// Closes the review without applying anything more.
    pub fn autoname_close(&mut self) {
        if self.review_mut().is_some_and(|r| !r.busy) {
            self.assist.autoname = AutoNameState::Idle;
        }
    }

    /// Applies suggestions as the person's own edits, one function at a time.
    pub fn autoname_apply(&mut self, which: ApplyWhich) {
        let Some(review) = self.review_mut() else {
            return;
        };
        if review.busy {
            return;
        }
        let todo: Vec<(usize, ReviewRow)> = review
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                !matches!(r.status, RowStatus::Applied) && (which == ApplyWhich::All || r.selected)
            })
            .map(|(i, r)| (i, r.clone()))
            .collect();
        if todo.is_empty() {
            review.message = Some("Tick at least one suggestion first.".to_string());
            return;
        }
        review.busy = true;
        review.message = None;
        let backend = self.backend().clone();
        let poster = self.poster();
        poster.runtime().clone().spawn(async move {
            for (index, row) in todo {
                let res = apply_row(backend.as_ref(), &row).await;
                poster.post(move |vm| vm.autoname_row_done(index, res));
            }
            poster.post(|vm| vm.autoname_apply_done());
        });
    }

    fn autoname_row_done(&mut self, index: usize, res: Result<usize, String>) {
        let Some(review) = self.review_mut() else {
            return;
        };
        let Some(row) = review.rows.get_mut(index) else {
            return;
        };
        match res {
            Ok(n) => {
                row.status = RowStatus::Applied;
                review.undoable += n;
            }
            Err(e) => row.status = RowStatus::Failed(e),
        }
    }

    fn autoname_apply_done(&mut self) {
        let Some(review) = self.review_mut() else {
            return;
        };
        review.busy = false;
        let applied = review
            .rows
            .iter()
            .filter(|r| r.status == RowStatus::Applied)
            .count();
        let failed = review
            .rows
            .iter()
            .filter(|r| matches!(r.status, RowStatus::Failed(_)))
            .count();
        review.message = Some(match (applied, failed) {
            (a, 0) => {
                format!("Applied {a} suggestion(s). They are your edits; Undo reverses them.")
            }
            (a, f) => {
                format!("Applied {a} suggestion(s); {f} could not be applied (see the rows).")
            }
        });
        self.refresh_after_edit();
    }

    /// Reverses the edits the last Apply made (the person's newest edits).
    pub fn autoname_undo(&mut self) {
        let Some(review) = self.review_mut() else {
            return;
        };
        if review.busy || review.undoable == 0 {
            return;
        }
        review.busy = true;
        let count = review.undoable;
        let backend = self.backend().clone();
        let poster = self.poster();
        poster.runtime().clone().spawn(async move {
            let mut undone = 0usize;
            let mut error: Option<ProtoError> = None;
            for _ in 0..count {
                match backend.call("undo", json!({})).await {
                    Ok(v) => undone += undone_count(&v),
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
            poster.post(move |vm| vm.autoname_undo_done(undone, error));
        });
    }

    fn autoname_undo_done(&mut self, undone: usize, error: Option<ProtoError>) {
        if let Some(e) = &error {
            self.toast(ToastLevel::Error, plain_error(e));
        }
        let Some(review) = self.review_mut() else {
            return;
        };
        review.busy = false;
        review.undoable = review.undoable.saturating_sub(undone);
        if review.undoable == 0 {
            for row in &mut review.rows {
                if row.status == RowStatus::Applied {
                    row.status = RowStatus::Undone;
                }
            }
        }
        review.message = Some(if undone == 0 {
            "Nothing was undone.".to_string()
        } else {
            format!("Undid {undone} change(s).")
        });
        self.refresh_after_edit();
    }
}

fn undone_count(v: &Value) -> usize {
    v.get("undone_entry_ids")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}
