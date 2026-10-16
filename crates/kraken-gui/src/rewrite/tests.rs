//! Headless frames of the Rewrite tab over the demo project's scripted pipeline.

use std::sync::Arc;
use std::time::Duration;

use egui::{Context, RawInput, Rect, Shape, pos2};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::demo::{demo_fixture, demo_project_with};
use kraken_viewmodel::rewrite::{Availability, DirCheck, RewriteMode, platform_note};

use super::detail::split_difference;
use super::{DetailView, RewriteUi, export_dialog, panel};
use crate::fonts;
use crate::workspace::Tab;

const WAIT: Duration = Duration::from_secs(20);
const CHECKSUM: u64 = 0x401240;

struct Rig {
    ctx: Context,
    vm: ViewModel,
    ui: RewriteUi,
    front: Option<Tab>,
    _rt: Arc<tokio::runtime::Runtime>,
}

impl Rig {
    fn new() -> Rig {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        fonts::install(&ctx);
        let demo = {
            let _g = rt.enter();
            demo_project_with(demo_fixture(), Duration::ZERO).expect("demo")
        };
        let mut vm = ViewModel::new(demo.backend.clone(), rt.handle().clone());
        vm.create_project(
            demo.binary.to_string_lossy(),
            demo.project_dir.to_string_lossy(),
        );
        assert!(vm.block_until_idle(WAIT));
        // The script runs on any computer.
        vm.rewrite.availability = Availability::Unknown;
        Rig {
            ctx,
            vm,
            ui: RewriteUi::default(),
            front: None,
            _rt: rt,
        }
    }

    /// Draws one frame and returns every piece of text it painted.
    fn frame(&mut self) -> Vec<String> {
        self.vm.poll();
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1400.0, 800.0))),
            ..Default::default()
        };
        let (vm, ui, front) = (&mut self.vm, &mut self.ui, &mut self.front);
        let mut out = self.ctx.run_ui(input, |root| {
            panel(root, vm, ui, front);
            export_dialog(root.ctx(), vm);
        });
        out.textures_delta.clear();
        let mut texts = Vec::new();
        for s in &out.shapes {
            collect(&s.shape, &mut texts);
        }
        texts
    }

    fn settle(&mut self, cond: impl Fn(&ViewModel) -> bool) -> Vec<String> {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let t = self.frame();
            if cond(&self.vm) {
                return self.frame();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out; last frame: {t:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn collect(s: &Shape, out: &mut Vec<String>) {
    match s {
        Shape::Text(t) => out.push(t.galley.text().to_string()),
        Shape::Vec(v) => v.iter().for_each(|s| collect(s, out)),
        _ => {}
    }
}

fn has(texts: &[String], needle: &str) -> bool {
    texts.iter().any(|t| t.contains(needle))
}

#[test]
fn the_plan_lists_functions_callees_first_with_status_chips_and_flags() {
    let mut r = Rig::new();
    let t = r.settle(|vm| vm.rewrite.loaded && !vm.rewrite.rows.is_empty());
    assert!(has(&t, "13 functions - callees first"), "{t:?}");
    for s in ["FUN_00401440", "checksum", "log_error", "main"] {
        assert!(has(&t, s), "{s} is listed");
    }
    for chip in [
        "accepted",
        "failed",
        "verified",
        "translated",
        "planned",
        "needs stubs",
    ] {
        assert!(has(&t, chip), "chip {chip}");
    }
    assert!(has(&t, "Accepted 1 of 13 planned functions"));
    assert!(has(&t, "Export..."));
    assert!(has(&t, "Pick a function"));
    // Filtering by a status narrows the list.
    r.ui.filter = Some(kraken_viewmodel::rewrite::UnitStatus::Failed);
    let t = r.frame();
    assert!(has(&t, "1 failed - callees first"), "{t:?}");
    assert!(!has(&t, "FUN_00401300"));
}

#[test]
fn a_failed_function_shows_c_and_rust_side_by_side_with_the_counterexample() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded);
    r.vm.rewrite_select(CHECKSUM);
    let t = r.settle(|vm| {
        vm.rewrite
            .selected_detail()
            .is_some_and(|d| d.c.is_some() && !d.loading && d.versions().len() == 2)
    });
    assert!(has(&t, "Decompiled C"), "{t:?}");
    assert!(has(&t, "Generated Rust  (version 2)"));
    assert!(has(&t, "Different from the original"));
    assert!(has(&t, "Smallest case where they disagree"));
    assert!(has(&t, "buf[8]=41 07"));
    assert!(has(&t, "original 0x41"));
    assert!(has(&t, "Rust 0x88e"));
    assert!(has(&t, "v1 failed") && has(&t, "v2 failed"));
    assert!(has(&t, "Retry") && has(&t, "Accept"));
    // The code itself is drawn (one galley per visible line).
    assert!(has(&t, "from_raw_parts"));
    assert!(has(&t, "uint32_t checksum"));

    // Looking at version 1 swaps the result card and the code.
    r.vm.rewrite_show_version(CHECKSUM, 1);
    let t = r.frame();
    assert!(has(&t, "Generated Rust  (version 1)"), "{t:?}");
    assert!(has(&t, "Rust 0xffffff80"));
    assert!(has(&t, "as i8"));
}

#[test]
fn retry_then_accept_runs_the_job_with_progress_and_marks_it_accepted() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded);
    r.vm.rewrite_select(CHECKSUM);
    r.settle(|vm| vm.rewrite.selected_detail().is_some_and(|d| !d.loading));
    r.vm.rewrite_retry(CHECKSUM);
    let t = r.settle(|vm| vm.rewrite.running_for(CHECKSUM).is_some());
    assert!(has(&t, "Rewriting checksum"), "{t:?}");
    let t = r.settle(|vm| vm.rewrite.acceptable_unit(CHECKSUM).is_some());
    assert!(has(&t, "Version 3: Passed"), "{t:?}");
    r.vm.rewrite_accept(CHECKSUM);
    let t = r.settle(|vm| vm.rewrite.counts.accepted == 2);
    assert!(has(&t, "2 accepted"), "{t:?}");
}

#[test]
fn the_spec_view_renders_headings_and_clickable_citations() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded);
    r.vm.rewrite_select(CHECKSUM);
    r.vm.rewrite_write_spec(Some(CHECKSUM));
    r.settle(|vm| vm.rewrite.spec_for(Some(CHECKSUM)).is_some());
    r.ui.view = DetailView::Spec;
    let t = r.frame();
    assert!(has(&t, "Purpose"), "{t:?}");
    assert!(has(&t, "Open questions"));
    assert!(has(&t, "@0x4011a0"), "citations are drawn as links");
    assert!(has(&t, "Write it again"));
    // The program spec is a separate document that has not been written.
    r.ui.program_spec = true;
    let t = r.frame();
    assert!(has(&t, "No spec of the whole program yet"), "{t:?}");
}

#[test]
fn a_computer_that_cannot_confine_code_gets_an_explanation_instead_of_buttons() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded);
    r.vm.rewrite.availability =
        Availability::NoConfinement(platform_note("macos").expect("macos cannot confine"));
    r.vm.rewrite_select(CHECKSUM);
    let t = r.settle(|vm| vm.rewrite.selected_detail().is_some_and(|d| !d.loading));
    assert!(has(&t, "Rewriting is off on this computer"), "{t:?}");
    assert!(has(&t, "only inside a sandbox"));
    assert!(has(&t, "Translating and testing are off here."));
    assert!(!has(&t, "Retry") && !has(&t, "Rewrite this function"));
    // A click on the (absent) button cannot start anything either.
    r.vm.rewrite_run(CHECKSUM, RewriteMode::Incremental);
    assert!(r.vm.rewrite.jobs.is_empty());
}

#[test]
fn the_export_dialog_warns_about_folders_outside_the_project() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded);
    r.vm.rewrite_export_open();
    r.frame();
    let t = r.frame();
    assert!(has(&t, "Export the rewrite"), "{t:?}");
    assert!(has(&t, "Inside your project"));
    assert!(has(&t, "Accepted 1 of 13"));

    r.vm.rewrite_export_set_dir("/tmp/elsewhere".into());
    assert_eq!(r.vm.rewrite_export_check(), DirCheck::Outside);
    r.frame();
    let t = r.frame();
    assert!(has(&t, "outside your project"), "{t:?}");
    r.vm.rewrite_export_start();
    r.frame();
    let t = r.frame();
    assert!(has(&t, "Write outside the project?"), "{t:?}");
    assert!(
        r.vm.rewrite.jobs.is_empty(),
        "nothing starts before the yes"
    );

    r.vm.rewrite_export_set_dir("../up".into());
    r.frame();
    let t = r.frame();
    assert!(has(&t, "cannot contain"), "{t:?}");
}

#[test]
fn a_difference_line_splits_into_what_original_and_rust() {
    assert_eq!(
        split_difference("result: original 0x80, Rust 0xffffff80"),
        Some(("result", "0x80", "0xffffff80"))
    );
    assert_eq!(
        split_difference("stdout: original \"a\", Rust \"b\""),
        Some(("stdout", "\"a\"", "\"b\""))
    );
    assert_eq!(split_difference("the Rust version panicked"), None);
}
