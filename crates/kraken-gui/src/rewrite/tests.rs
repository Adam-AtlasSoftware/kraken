//! Headless frames of the Rewrite tab over the demo project's scripted pipeline.

use std::sync::Arc;
use std::time::Duration;

use egui::{Context, RawInput, Rect, Shape, pos2};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::demo::{demo_fixture, demo_project_with};
use kraken_viewmodel::rewrite::{Availability, DirCheck, RewriteMode, platform_note};

use super::detail::split_difference;
use super::{DetailView, RewriteUi, Section, export_dialog, panel, wizard_window};
use crate::fonts;
use crate::workspace::Tab;

const WAIT: Duration = Duration::from_secs(20);
const CHECKSUM: u64 = 0x401240;

struct Rig {
    ctx: Context,
    vm: ViewModel,
    ui: RewriteUi,
    demo: Arc<kraken_viewmodel::InProcessBackend>,
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
            demo: demo.backend.clone(),
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
            wizard_window(root.ctx(), vm, front);
        });
        out.textures_delta.clear();
        let mut texts = Vec::new();
        for s in &out.shapes {
            collect(&s.shape, &mut texts);
        }
        texts
    }

    /// Two frames: a window that has just opened is only drawn on the second.
    fn frame2(&mut self) -> Vec<String> {
        self.frame();
        self.frame()
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
                "timed out; jobs: {:?}; last frame: {t:?}",
                self.vm.rewrite.jobs
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
    assert!(
        !t.iter()
            .any(|x| x == "Retry" || x == "Rewrite this function")
    );
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

    // Absolute on every platform (`/tmp/elsewhere` is relative on Windows).
    let elsewhere = if cfg!(windows) {
        "C:\\elsewhere"
    } else {
        "/tmp/elsewhere"
    };
    r.vm.rewrite_export_set_dir(elsewhere.into());
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

// ---------------------------------------------------------------- the Program view

fn program_rig() -> (Rig, kraken_viewmodel::ApprovalBroker) {
    let mut r = Rig::new();
    let broker = kraken_viewmodel::ApprovalBroker::new();
    // The window installs its broker on the backend; the headless rig does the same.
    r.demo.set_approver(Arc::new(broker.clone()));
    r.ui.section = Section::Program;
    (r, broker)
}

#[test]
fn the_program_view_shows_the_function_table_the_crate_and_the_diff_of_a_failing_case() {
    let (mut r, _b) = program_rig();
    let t = r.settle(|vm| vm.rewrite.program.detail.is_some());
    assert!(has(&t, "Rewrite the whole program"), "{t:?}");
    // The verdict and what it means.
    assert!(has(&t, "Run 1"));
    assert!(has(&t, "fail"));
    assert!(has(
        &t,
        "The rewritten program differs from the original on 2 of 3 cases."
    ));
    // The crate: a path to copy or open.
    assert!(has(&t, "/work/demo/rewrite-program"), "{t:?}");
    assert!(has(&t, "Copy path") && has(&t, "Open folder"));
    assert!(has(&t, "built"));
    // The function table: names, statuses, how each was checked.
    for name in ["FUN_00401440", "checksum", "process_packet"] {
        assert!(has(&t, name), "{name}");
    }
    assert!(has(&t, "compared with the original") && has(&t, "compiled only"));
    assert!(has(&t, "verified") && has(&t, "translated"));
    assert!(
        has(&t, "never compared with the original on their own"),
        "{t:?}"
    );
    // Cases: the differing ones, and the first is open with a diff of each stream.
    assert!(has(&t, "differing only"));
    assert!(has(&t, "baseline") && has(&t, "-v"));
    assert!(has(&t, "Exit status") && has(&t, "Standard output") && has(&t, "Standard error"));
    assert!(has(&t, "- status: 2 handled"), "{t:?}");
    assert!(has(&t, "+ status:  2 handled"));
    assert!(has(&t, "only the original, + only the rewritten program"));
}

#[test]
fn a_function_of_the_table_opens_its_notes_and_the_agreeing_cases_can_be_listed() {
    let (mut r, _b) = program_rig();
    r.settle(|vm| vm.rewrite.program.detail.is_some());
    r.vm.rewrite_program_select_function(Some(0x4011a0));
    let t = r.frame();
    assert!(
        has(
            &t,
            "calls fprintf, which the function-level test does not model"
        ),
        "{t:?}"
    );
    assert!(has(&t, "Calls the translations of"));
    r.vm.rewrite_program_set_all_cases(true);
    let t = r.settle(|vm| {
        vm.rewrite
            .program
            .detail
            .as_ref()
            .is_some_and(|d| d.verdict.cases.len() == 3)
    });
    assert!(has(&t, "generated-1") && has(&t, "all cases"), "{t:?}");
    r.vm.rewrite_program_select_case(2);
    let t = r.frame();
    assert!(has(&t, "same"), "{t:?}");
    assert!(has(&t, "prog \"x y\""));
}

#[test]
fn the_run_button_asks_first_and_the_new_run_shows_the_repair_that_fixed_it() {
    let (mut r, broker) = program_rig();
    r.settle(|vm| vm.rewrite.program.detail.is_some());
    r.vm.rewrite_program_run();
    // The dialog's question, as the window's approval dialog would show it.
    let (id, prompt) = loop {
        r.frame();
        if let Some(q) = broker.current() {
            break q;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(prompt.command, "rewrite_program");
    assert!(prompt.summary.contains("run the original program natively"));
    // While the question is open the job has not produced anything.
    assert_eq!(r.vm.rewrite.program.runs.len(), 1);
    broker.respond(id, true);
    let t = r.settle(|vm| vm.rewrite.program.runs.len() == 2 && !vm.rewrite_program_running());
    assert!(has(&t, "Run 2"), "{t:?}");
    assert!(has(
        &t,
        "The rewritten program did the same as the original on all 3 cases."
    ));
    // The repair round: which function, where the output went wrong, the call stack.
    assert!(
        has(&t, "1 repair round: 1 function translated again"),
        "{t:?}"
    );
    r.ui.program.repairs_open = true;
    let t = r.frame();
    assert!(has(&t, "process_packet"), "{t:?}");
    assert!(has(&t, "replaced"));
    assert!(
        has(
            &t,
            "writing byte 29 of its standard output, inside process_packet <- main"
        ),
        "{t:?}"
    );
    assert!(has(&t, "then pass"));
}

#[test]
fn a_run_that_is_not_allowed_says_so_and_changes_nothing() {
    let (mut r, broker) = program_rig();
    r.settle(|vm| vm.rewrite.program.detail.is_some());
    r.vm.rewrite_program_run();
    let (id, _) = loop {
        r.frame();
        if let Some(q) = broker.current() {
            break q;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    broker.respond(id, false);
    let t = r.settle(|vm| vm.rewrite.program.declined.is_some());
    assert!(has(&t, "Not run."), "{t:?}");
    assert!(has(&t, "you did not allow that"));
    assert_eq!(r.vm.rewrite.program.runs.len(), 1);
}

#[test]
fn a_computer_that_cannot_confine_code_turns_the_run_button_off_in_this_view_too() {
    let (mut r, _b) = program_rig();
    r.settle(|vm| vm.rewrite.program.detail.is_some());
    r.vm.rewrite.availability =
        Availability::NoConfinement(platform_note("macos").expect("macos cannot confine"));
    let t = r.frame();
    assert!(has(&t, "Rewriting is off on this computer"), "{t:?}");
    r.vm.rewrite_program_run();
    assert!(r.vm.rewrite.jobs.is_empty());
    // Reading the stored runs still works.
    assert!(has(&t, "Run 1"));
}

// ---------------------------------------------------------------- bulk actions

#[test]
fn the_header_offers_the_bulk_actions_with_counts_and_asks_before_accepting() {
    let mut r = Rig::new();
    let t = r.settle(|vm| vm.rewrite.loaded && !vm.rewrite.rows.is_empty());
    assert!(has(&t, "All at once"), "{t:?}");
    assert!(has(&t, "Translate all planned (9)"), "{t:?}");
    assert!(has(&t, "Retry all failed (1)"));
    assert!(has(&t, "Accept all verified (1)"));
    assert!(has(&t, "Guided rewrite..."));
    // Nothing is accepted before the question is answered.
    assert!(!has(&t, "Accept the verified functions?"));
    r.ui.confirm_accept = true;
    let t = r.frame2();
    assert!(has(&t, "Accept the verified functions?"), "{t:?}");
    assert!(has(&t, "1 function will be accepted."));
    assert!(has(&t, "helper"));
    assert!(has(&t, "evidence, not proof"));
    assert_eq!(r.vm.rewrite.counts.accepted, 1);
    r.vm.rewrite_bulk_accept_verified();
    r.settle(|vm| vm.rewrite.counts.accepted == 2);
    let t = r.frame2();
    assert!(has(&t, "Accept all verified (0)"), "{t:?}");
}

#[test]
fn translate_all_shows_how_far_it_is_and_can_be_stopped() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded && !vm.rewrite.rows.is_empty());
    r.vm.rewrite_bulk_translate_planned(RewriteMode::Incremental);
    let t = r.frame2();
    assert!(
        has(&t, "Translating every planned function: 0 of 9 done"),
        "{t:?}"
    );
    assert!(has(&t, "Stop after this one"));
    // While it runs the button is off.
    assert!(r.vm.rewrite_bulk_translate_blocker().is_some());
    r.vm.rewrite_bulk_cancel();
    r.settle(|vm| !vm.rewrite.busy());
    assert!(!r.vm.rewrite.bulk.active());
    let t = r.frame2();
    assert!(!has(&t, "Stop after this one"), "{t:?}");
}

// ---------------------------------------------------------------- export dialog

#[test]
fn the_export_dialog_has_a_browse_button_and_after_success_open_and_copy_buttons() {
    let mut r = Rig::new();
    r.settle(|vm| vm.rewrite.loaded && !vm.rewrite.rows.is_empty());
    r.vm.rewrite_export_open();
    let t = r.frame2();
    assert!(has(&t, "Browse..."), "{t:?}");
    assert!(!has(&t, "Open folder"));
    r.vm.rewrite_export_start();
    r.settle(|vm| vm.rewrite.export.result.is_some());
    let t = r.frame2();
    for b in ["Open folder", "Open in editor", "Copy path"] {
        assert!(has(&t, b), "{b} in {t:?}");
    }
}

// ---------------------------------------------------------------- the program inputs editor

fn editor_frame(r: &mut Rig) -> Vec<String> {
    let input = RawInput {
        screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1000.0, 600.0))),
        ..Default::default()
    };
    let vm = &mut r.vm;
    let mut out = r.ctx.run_ui(input, |root| {
        super::program::inputs_editor(root, vm, false);
    });
    out.textures_delta.clear();
    let mut texts = Vec::new();
    for s in &out.shapes {
        collect(&s.shape, &mut texts);
    }
    texts
}

#[test]
fn test_cases_can_be_added_edited_and_removed_and_a_bad_row_says_what_is_wrong() {
    let mut r = Rig::new();
    let t = editor_frame(&mut r);
    assert!(has(&t, "Add a test case"), "{t:?}");
    assert!(!has(&t, "Standard input"), "no header without rows");
    r.vm.rewrite.program.inputs.push(Default::default());
    r.vm.rewrite.program.inputs[0].args = "-v".into();
    let t = editor_frame(&mut r);
    for h in ["Name", "Arguments", "Standard input", "Remove"] {
        assert!(has(&t, h), "{h} in {t:?}");
    }
    assert!(has(&t, "Test case 1 needs a name."), "{t:?}");
    r.vm.rewrite.program.inputs[0].name = "verbose".into();
    let t = editor_frame(&mut r);
    assert!(!has(&t, "needs a name"), "{t:?}");
    assert!(has(&t, "verbose"));
    // The summary on the folded options says how many there are.
    r.ui.section = Section::Program;
    let t = r.frame2();
    assert!(has(&t, "Options: 1 test case, default folder"), "{t:?}");
    r.vm.rewrite.program.verify_functions = false;
    r.vm.rewrite.program.output_dir = "out".into();
    let t = r.frame2();
    assert!(
        has(
            &t,
            "Options: 1 test case, own folder, functions not checked one by one"
        ),
        "{t:?}"
    );
}

// ---------------------------------------------------------------- the wizard

fn wizard_rig() -> (Rig, kraken_viewmodel::ApprovalBroker) {
    let mut r = Rig::new();
    let broker = kraken_viewmodel::ApprovalBroker::new();
    r.demo.set_approver(Arc::new(broker.clone()));
    r.settle(|vm| vm.rewrite.loaded && !vm.rewrite.rows.is_empty());
    (r, broker)
}

fn answer(r: &mut Rig, broker: &kraken_viewmodel::ApprovalBroker, command: &str) {
    let (id, prompt) = loop {
        r.frame2();
        if let Some(q) = broker.current() {
            break q;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(prompt.command, command);
    broker.respond(id, true);
}

fn step(r: &Rig) -> kraken_viewmodel::rewrite::WizardStep {
    r.vm.rewrite.wizard.step
}

#[test]
fn the_wizard_walks_one_function_from_scope_to_an_opened_project() {
    use kraken_viewmodel::rewrite::WizardStep as S;
    let (mut r, broker) = wizard_rig();
    assert!(!has(&r.frame2(), "Step 1 of 9"), "closed until asked for");
    r.vm.perform(kraken_viewmodel::AppAction::RewriteWizard);
    let t = r.frame2();
    assert!(has(&t, "Rewrite in Rust"), "{t:?}");
    assert!(has(&t, "Step 1 of 9: Scope"));
    assert!(has(
        &t,
        "Choose how much of the program to rewrite in Rust."
    ));
    for s in [
        "Scope", "Mode", "Check", "Run", "Review", "Accept", "Export", "Build", "Open",
    ] {
        assert!(has(&t, s), "stepper shows {s}");
    }
    for sc in ["This function", "The plan", "The whole program"] {
        assert!(has(&t, sc), "{sc}");
    }

    // The function scope needs a function; the reason is on screen.
    r.vm.rewrite_wizard_set_scope(kraken_viewmodel::rewrite::WizardScope::Function);
    r.vm.rewrite.wizard.function = None;
    let t = r.frame2();
    assert!(has(&t, "Choose a function."), "{t:?}");
    r.vm.rewrite_wizard_next();
    assert_eq!(step(&r), S::Scope);
    r.vm.rewrite_wizard_set_function(CHECKSUM);
    r.frame2();
    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Mode);
    assert!(has(&t, "Translate the code"), "{t:?}");
    assert!(has(&t, "Write a spec, then reimplement"));

    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Check);
    for c in ["Assistant", "Sandbox", "Analysis", "Size of the job"] {
        assert!(has(&t, c), "{c} in {t:?}");
    }
    assert!(has(&t, "1 function, up to 3 requests"), "{t:?}");

    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Run);
    assert!(has(&t, "Press Start to run the rewrite."), "{t:?}");
    r.vm.rewrite_wizard_start();
    let t = r.frame2();
    assert!(has(&t, "The rewrite is running."), "{t:?}");
    r.settle(|vm| vm.rewrite.wizard.step == S::Review);
    let t = r.frame2();
    assert!(has(&t, "Step 5 of 9: Review"), "{t:?}");
    assert!(has(&t, "checksum") && has(&t, "verified"));

    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Accept);
    assert!(has(&t, "Accept this function"), "{t:?}");
    assert!(has(&t, "only you can accept it"));
    let accepted = r.vm.rewrite.counts.accepted;
    r.vm.rewrite_wizard_accept();
    r.settle(|vm| vm.rewrite.counts.accepted == accepted + 1);

    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Export);
    assert!(has(&t, "Browse..."), "{t:?}");
    assert!(has(&t, "Export"));
    r.vm.rewrite_wizard_export();
    r.settle(|vm| vm.rewrite.export.result.is_some());
    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Build);
    assert!(has(&t, "Build and test"), "{t:?}");
    assert!(has(&t, "Run the tests"));
    // Nothing to go on with until the build has run.
    assert!(r.vm.rewrite_wizard_blocker().is_some());
    r.vm.rewrite_wizard_build();
    answer(&mut r, &broker, "rewrite_build");
    r.settle(|vm| vm.rewrite.build.result.is_some());
    let t = r.frame2();
    assert!(has(&t, "passed"), "{t:?}");
    assert!(has(&t, "Build") && has(&t, "Test"));
    // A log that passed is folded; one that failed opens by itself.
    assert!(has(&t, "Log") && !has(&t, "cargo build --release"), "{t:?}");

    r.vm.rewrite_wizard_next();
    let t = r.frame2();
    assert_eq!(step(&r), S::Open);
    for b in ["Open folder", "Open in editor", "Copy path", "Done"] {
        assert!(has(&t, b), "{b} in {t:?}");
    }
    assert!(has(&t, "It built and its tests passed in the sandbox."));
    let dir = r.vm.rewrite_wizard_crate_dir().expect("dir");
    assert!(dir.ends_with("rewrite-export"), "{dir}");
    assert!(std::path::Path::new(&dir).join("manifest.json").is_file());
}

#[test]
fn the_check_step_blocks_on_a_missing_sandbox_and_says_why_on_screen() {
    use kraken_viewmodel::rewrite::WizardStep as S;
    let (mut r, _b) = wizard_rig();
    r.vm.rewrite_wizard_open();
    r.vm.rewrite_wizard_set_function(CHECKSUM);
    r.vm.rewrite.availability =
        Availability::NoConfinement(platform_note("macos").expect("macos cannot confine"));
    r.vm.rewrite.wizard.step = S::Check;
    let t = r.frame2();
    assert!(has(&t, "Stop"), "{t:?}");
    assert!(
        has(
            &t,
            "Sandbox: KRAKEN runs the Rust it generates only inside a sandbox"
        ),
        "{t:?}"
    );
    r.vm.rewrite_wizard_next();
    assert_eq!(step(&r), S::Check);
    // Starting is off too.
    r.vm.rewrite.wizard.step = S::Run;
    r.vm.rewrite_wizard_start();
    assert!(r.vm.rewrite.jobs.is_empty());
}

#[test]
fn the_whole_program_path_takes_typed_cases_skips_export_and_builds_the_crate_it_wrote() {
    use kraken_viewmodel::rewrite::{WizardScope, WizardStep as S};
    let (mut r, broker) = wizard_rig();
    r.vm.rewrite_wizard_open();
    r.vm.rewrite_wizard_set_scope(WizardScope::Program);
    r.vm.rewrite
        .program
        .inputs
        .push(kraken_viewmodel::rewrite::ProgramInput {
            name: "verbose".into(),
            args: "-v".into(),
            stdin: String::new(),
        });
    r.vm.rewrite.wizard.step = S::Mode;
    let t = r.frame2();
    assert!(has(&t, "Not available for the whole program yet."), "{t:?}");
    r.vm.rewrite.wizard.step = S::Run;
    let t = r.frame2();
    assert!(has(&t, "Options: 1 test case, default folder"), "{t:?}");
    assert!(has(&t, "Starting asks you first"));
    r.vm.rewrite_wizard_start();
    answer(&mut r, &broker, "rewrite_program");
    r.settle(|vm| vm.rewrite.wizard.step == S::Review);
    let t = r.frame2();
    assert!(has(&t, "Open the whole-program view"), "{t:?}");
    r.vm.rewrite_wizard_next();
    assert_eq!(step(&r), S::Accept);
    let t = r.frame2();
    assert!(has(&t, "this step is optional"), "{t:?}");
    r.vm.rewrite_wizard_next();
    assert_eq!(step(&r), S::Build, "the export step is passed over");
    let t = r.frame2();
    assert!(has(&t, "Run the program afterwards"), "{t:?}");
    r.vm.rewrite.build.run = true;
    r.vm.rewrite.build.run_args = "-v".into();
    r.vm.rewrite_wizard_build();
    answer(&mut r, &broker, "rewrite_build");
    r.settle(|vm| vm.rewrite.build.result.is_some());
    let out = r.vm.rewrite.build.result.clone().expect("result");
    assert_eq!(out.kind, "program");
    assert_eq!(out.steps.last().map(|s| s.step.as_str()), Some("run"));
    // Back over the skipped step.
    r.vm.rewrite_wizard_back();
    assert_eq!(step(&r), S::Accept);
    // The review links into the program view.
    r.vm.rewrite.wizard.step = S::Review;
    r.frame2();
    r.vm.rewrite.show_program_request = true;
    r.frame2();
    assert_eq!(r.ui.section, Section::Program);
}

#[test]
fn the_wizard_closes_without_losing_the_results_and_the_palette_action_opens_it() {
    let (mut r, _b) = wizard_rig();
    assert_eq!(
        kraken_viewmodel::AppAction::RewriteWizard.label(),
        "Rewrite in Rust..."
    );
    assert!(kraken_viewmodel::AppAction::ALL.contains(&kraken_viewmodel::AppAction::RewriteWizard));
    r.vm.perform(kraken_viewmodel::AppAction::RewriteWizard);
    assert!(r.vm.rewrite.wizard.open);
    r.vm.rewrite_wizard_close();
    assert!(!has(&r.frame2(), "Step 1 of 9"));
    assert_eq!(r.vm.rewrite.counts.accepted, 1);
}
