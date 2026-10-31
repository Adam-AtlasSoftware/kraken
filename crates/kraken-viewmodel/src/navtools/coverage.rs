//! Coverage overlay: the basic blocks a traced run executed, shaded in the Listing and the Graph.

use kraken_proto::Page;
use kraken_proto::trace::CoverageBlock;
use serde::Deserialize;
use serde_json::json;

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, parse};

/// Pages of blocks read at most (5000 blocks each).
const MAX_PAGES: usize = 10;

/// One stored run, as `coverage_list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CoverageRunItem {
    /// Id other commands take.
    pub id: u64,
    /// Label of the run.
    pub label: String,
    /// How it ended.
    pub exit: String,
    /// Instructions executed.
    pub instructions: u64,
    /// Blocks the engine knows.
    pub blocks_total: u64,
    /// Blocks that ran.
    pub blocks_hit: u64,
}

#[derive(Debug, Deserialize)]
struct RunList {
    runs: Vec<CoverageRunItem>,
}

/// State of the coverage overlay.
#[derive(Debug, Clone, Default)]
pub struct CoveragePanel {
    /// The overlay is drawn (Emulate > Show coverage).
    pub show: bool,
    /// Stored runs.
    pub runs: Vec<CoverageRunItem>,
    /// Executed blocks as `(start, end, hits)`, sorted by start.
    ranges: Vec<(u64, u64, u64)>,
    /// A trace or a reload is running.
    pub busy: bool,
    /// The blocks were read at least once.
    pub loaded: bool,
    /// Why the last trace or load failed.
    pub error: Option<String>,
    /// Bumped on every change of the ranges, so caches can tell.
    pub revision: u64,
    record_if_empty: bool,
    generation: u64,
}

impl CoveragePanel {
    /// Replaces the executed blocks.
    pub fn set_blocks(&mut self, blocks: &[CoverageBlock]) {
        let mut r: Vec<(u64, u64, u64)> = blocks
            .iter()
            .map(|b| {
                (
                    b.start.0,
                    b.start.0.saturating_add(u64::from(b.size.max(1))),
                    b.hits,
                )
            })
            .collect();
        r.sort_unstable();
        self.ranges = r;
        self.revision += 1;
    }

    /// True when any block has been recorded.
    pub fn has_data(&self) -> bool {
        !self.ranges.is_empty()
    }

    /// How often the block holding `addr` ran, when it ran.
    pub fn hits_at(&self, addr: u64) -> Option<u64> {
        let i = self.ranges.partition_point(|r| r.0 <= addr);
        let (_, end, hits) = *self.ranges.get(i.checked_sub(1)?)?;
        (addr < end).then_some(hits)
    }

    /// Hits of the executed blocks that overlap `[start, end)`: how often control entered that
    /// range, `None` when none ran.
    pub fn hits_in(&self, start: u64, end: u64) -> Option<u64> {
        let from = self.ranges.partition_point(|r| r.1 <= start);
        let mut total = None;
        for r in &self.ranges[from..] {
            if r.0 >= end {
                break;
            }
            total = Some(total.unwrap_or(0) + r.2);
        }
        total
    }

    /// The overlay should be drawn: switched on and there is something to draw.
    pub fn active(&self) -> bool {
        self.show && self.has_data()
    }
}

impl ViewModel {
    /// Switches the overlay on or off, reading the stored coverage the first time.
    pub fn set_coverage_shown(&mut self, on: bool) {
        self.tools.coverage.show = on;
        if on && !self.tools.coverage.loaded && !self.tools.coverage.busy {
            self.refresh_coverage();
        }
    }

    /// The toolbar switch: off when on; on when coverage is stored; otherwise records a run
    /// (after looking for stored coverage the first time).
    pub fn toggle_coverage_or_record(&mut self) {
        let c = &mut self.tools.coverage;
        if c.show {
            c.show = false;
        } else if c.has_data() {
            c.show = true;
        } else if c.loaded {
            self.record_coverage();
        } else {
            c.show = true;
            c.record_if_empty = true;
            if !c.busy {
                self.refresh_coverage();
            }
        }
    }

    /// Reads the stored runs and their executed blocks.
    pub fn refresh_coverage(&mut self) {
        let c = &mut self.tools.coverage;
        c.generation += 1;
        c.busy = true;
        c.error = None;
        let generation = c.generation;
        self.call("coverage_list", json!({}), move |vm, res| {
            if vm.tools.coverage.generation != generation {
                return;
            }
            match res.and_then(parse::<RunList>) {
                Ok(l) => {
                    vm.tools.coverage.runs = l.runs;
                    vm.fetch_coverage_blocks(generation, Vec::new(), None, 0);
                }
                Err(e) => {
                    let c = &mut vm.tools.coverage;
                    c.busy = false;
                    c.error = Some(plain_error(&e));
                }
            }
        });
    }

    fn fetch_coverage_blocks(
        &mut self,
        generation: u64,
        mut so_far: Vec<CoverageBlock>,
        cursor: Option<String>,
        page: usize,
    ) {
        let mut args = json!({"limit": 5000});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        self.call("coverage_blocks", args, move |vm, res| {
            if vm.tools.coverage.generation != generation {
                return;
            }
            match res.and_then(parse::<Page<CoverageBlock>>) {
                Ok(p) => {
                    so_far.extend(p.items);
                    match p.next_cursor {
                        Some(c) if page + 1 < MAX_PAGES => {
                            vm.fetch_coverage_blocks(generation, so_far, Some(c), page + 1);
                        }
                        _ => {
                            let c = &mut vm.tools.coverage;
                            c.set_blocks(&so_far);
                            c.busy = false;
                            c.loaded = true;
                            if std::mem::take(&mut c.record_if_empty) && !c.has_data() {
                                vm.record_coverage();
                            }
                        }
                    }
                }
                Err(e) => {
                    let c = &mut vm.tools.coverage;
                    c.busy = false;
                    c.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Runs the program in the emulator with default input, records which blocks run and
    /// switches the overlay on.
    pub fn record_coverage(&mut self) {
        if self.tools.coverage.busy {
            self.toast(ToastLevel::Info, "Coverage is already being recorded.");
            return;
        }
        let c = &mut self.tools.coverage;
        c.busy = true;
        c.error = None;
        self.toast(
            ToastLevel::Info,
            "Running the program to record coverage...",
        );
        self.call("debug_trace", json!({}), |vm, res| {
            let id = res
                .as_ref()
                .ok()
                .and_then(|v| v.get("job_id"))
                .and_then(|j| j.as_str())
                .map(str::to_string);
            let Some(id) = id else {
                let m = match res {
                    Err(e) => plain_error(&e),
                    Ok(_) => "the run did not start".to_string(),
                };
                vm.coverage_failed(m);
                return;
            };
            vm.call(
                "job_await",
                json!({"job_id": id, "timeout_ms": 130_000}),
                |vm, res| {
                    vm.tools.coverage.busy = false;
                    let failed = match res {
                        Ok(v) if v["status"] == "succeeded" => None,
                        Ok(v) => Some(
                            v["error"]["message"]
                                .as_str()
                                .unwrap_or("the run did not finish")
                                .to_string(),
                        ),
                        Err(e) => Some(plain_error(&e)),
                    };
                    match failed {
                        None => {
                            vm.tools.coverage.show = true;
                            vm.refresh_coverage();
                            vm.toast(ToastLevel::Info, "Coverage recorded.");
                        }
                        Some(m) => vm.coverage_failed(m),
                    }
                },
            );
        });
    }

    fn coverage_failed(&mut self, message: String) {
        let c = &mut self.tools.coverage;
        c.busy = false;
        c.error = Some(message.clone());
        self.toast(ToastLevel::Error, format!("Coverage failed: {message}"));
    }

    /// Removes the stored coverage.
    pub fn clear_coverage(&mut self) {
        self.tools.coverage.generation += 1;
        self.call("coverage_clear", json!({}), |vm, res| match res {
            Ok(_) => {
                let c = &mut vm.tools.coverage;
                c.runs.clear();
                c.set_blocks(&[]);
                c.loaded = true;
                c.busy = false;
                vm.toast(ToastLevel::Info, "Coverage cleared.");
            }
            Err(e) => vm.toast(ToastLevel::Error, plain_error(&e)),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::Hex64;

    fn block(start: u64, size: u32, hits: u64) -> CoverageBlock {
        CoverageBlock {
            start: Hex64(start),
            size,
            hits,
        }
    }

    #[test]
    fn lookups_find_the_block_holding_an_address() {
        let mut c = CoveragePanel::default();
        c.set_blocks(&[block(0x30, 4, 1), block(0x10, 8, 3)]);
        assert_eq!(c.hits_at(0x10), Some(3));
        assert_eq!(c.hits_at(0x17), Some(3));
        assert_eq!(c.hits_at(0x18), None);
        assert_eq!(c.hits_at(0x0f), None);
        assert_eq!(c.hits_at(0x33), Some(1));
        assert_eq!(c.hits_in(0x00, 0x20), Some(3));
        assert_eq!(c.hits_in(0x00, 0x40), Some(4));
        assert_eq!(c.hits_in(0x18, 0x30), None);
        assert!(!c.active());
        c.show = true;
        assert!(c.active());
    }
}
