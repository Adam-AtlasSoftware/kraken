//! The Emulate menu, the Run dialog and the Emulation tab over the demo project.

use egui_kittest::kittest::Queryable;
use kraken_viewmodel::navtools::{Difference, EmulateMode, EmulationResult, FileDetail, RunDetail};
use kraken_viewmodel::{AnalysisPhase, AppAction, Connection};

use super::shell::{Kit, kit, kit_with};
use crate::workspace::Tab;

fn ready(k: &mut Kit) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        k.h.run_steps(1);
        if k.h.state_mut().view_model_mut().is_some_and(|vm| {
            vm.connection == Connection::Open
                && vm.analysis.phase == AnalysisPhase::Complete
                && !vm.busy()
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the demo did not load"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    k.h.run_steps(8);
}

fn run(stdout: &str, exit: &str, clean: bool) -> RunDetail {
    RunDetail {
        exit: exit.into(),
        clean,
        stdout: stdout.into(),
        stderr: String::new(),
        steps: 143_990,
        notes: vec!["architecture x86_64".into()],
        files: vec![FileDetail {
            name: "out.txt".into(),
            size: 9,
            preview: "mode=fast".into(),
            binary: false,
        }],
        truncated: false,
    }
}

/// A comparison as `emulate_compare` reports it for a patch that upper-cases `hash=`.
fn comparison() -> EmulationResult {
    EmulationResult::Compare {
        given: "arguments -v and 6 bytes of input".into(),
        a: Box::new(run(
            "joined: static linking\ncount of i: 6\nhash=6490\n",
            "exit code 0",
            true,
        )),
        b: Box::new(run(
            "joined: static linking\ncount of i: 6\nHASH=6490\n",
            "exit code 0",
            true,
        )),
        same: false,
        differences: vec![Difference {
            field: "stdout".into(),
            summary: "line 3: \"hash=6490\" vs \"HASH=6490\"".into(),
        }],
        first_divergence: "stdout: line 3: \"hash=6490\" vs \"HASH=6490\"".into(),
    }
}

#[test]
fn the_emulate_menu_opens_the_run_dialog_and_a_comparison_without_patches_says_so() {
    let mut k = kit(true);
    ready(&mut k);
    k.h.get_by_label("Emulate").click();
    k.h.run_steps(3);
    assert!(k.h.query_by_label("Run program...").is_some());
    assert!(k.h.query_by_label("Run patched program...").is_some());
    assert!(k.h.query_by_label("About running programs").is_some());
    k.h.get_by_label("Compare original vs patched...").click();
    k.h.run_steps(4);
    {
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        let d = vm
            .tools
            .emulate_dialog
            .as_mut()
            .expect("the Run dialog is open");
        assert_eq!(d.mode, EmulateMode::Compare);
        d.argv = "-v 'two words'".into();
        d.stdin = "hello\n".into();
    }
    k.h.run_steps(3);
    k.h.get_by_label("Run both and compare").click();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        k.h.run_steps(2);
        let error = k.h.state_mut().view_model_mut().and_then(|vm| {
            vm.tools
                .emulate_dialog
                .as_ref()
                .and_then(|d| d.error.clone())
        });
        if let Some(e) = error {
            assert!(e.contains("patch"), "the reason is shown: {e}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no answer");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        k.h.query_all_by_label_contains("no byte patches")
            .next()
            .is_some(),
        "the dialog shows the reason"
    );
    k.h.get_by_label("Cancel").click();
    k.h.run_steps(3);
    assert!(
        k.h.state_mut()
            .view_model_mut()
            .is_some_and(|vm| vm.tools.emulate_dialog.is_none())
    );
}

#[test]
fn the_emulation_tab_shows_a_comparison_side_by_side() {
    let mut k = kit(true);
    ready(&mut k);
    {
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        vm.tools.emulation.result = Some(comparison());
    }
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ShowEmulation, &ctx);
    k.h.run_steps(6);
    assert!(k.h.state_mut().dock().find_tab(&Tab::Emulation).is_some());
    assert!(
        k.h.query_by_label("The patched program behaved differently.")
            .is_some()
    );
    assert!(
        k.h.query_by_label_contains("First difference: stdout: line 3")
            .is_some()
    );
    assert!(
        k.h.query_by_label("hash=6490").is_some(),
        "the original's line"
    );
    assert!(
        k.h.query_by_label("HASH=6490").is_some(),
        "the patched line"
    );
    assert!(k.h.query_by_label("differs").is_some());
}

#[test]
#[ignore = "writes a PNG file and needs a GPU; run by hand (KRAKEN_SHOT_DIR=<dir>)"]
fn screenshot_the_emulation_tab() {
    let mut k = kit_with(true, true);
    ready(&mut k);
    {
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        vm.tools.emulation.result = Some(comparison());
    }
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ShowEmulation, &ctx);
    k.h.state_mut().hide_notices();
    k.h.run_steps(8);
    let img = k.h.render().expect("render");
    let dir = std::env::var_os("KRAKEN_SHOT_DIR")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let path = dir.join("emulation.png");
    img.save(&path).expect("save png");
    println!("saved {}", path.display());
}
