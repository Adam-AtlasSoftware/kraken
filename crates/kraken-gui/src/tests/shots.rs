//! Documentation screenshots of the help window and the tour, drawn on the GPU without a window.
//! Run by hand from the repository root: `KRAKEN_SHOT_DIR=$PWD/docs/images cargo test -p kraken-gui shots -- --ignored`.

use std::path::PathBuf;

use kraken_viewmodel::{AnalysisPhase, AppAction, Connection, Load};

use super::shell::{Kit, kit_with};

fn out_dir() -> PathBuf {
    std::env::var_os("KRAKEN_SHOT_DIR").map_or_else(std::env::temp_dir, PathBuf::from)
}

fn save(k: &mut Kit, name: &str) {
    k.h.state_mut().hide_notices();
    k.h.run_steps(6);
    let img = k.h.render().expect("render");
    let path = out_dir().join(name);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("create dir");
    }
    img.save(&path).expect("save png");
    println!("saved {}", path.display());
}

fn ready_demo(k: &mut Kit) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut selected = false;
    loop {
        k.h.run_steps(1);
        let state = k.h.state_mut();
        if let Some(vm) = state.view_model_mut()
            && vm.connection == Connection::Open
            && vm.analysis.phase == AnalysisPhase::Complete
            && !vm.busy()
        {
            if !selected {
                let main = vm
                    .functions
                    .items
                    .iter()
                    .find(|f| f.name == "main")
                    .map(|f| f.address);
                if let Some(a) = main {
                    vm.select_function(a);
                    selected = true;
                }
            } else if vm
                .current
                .as_ref()
                .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)))
            {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the demo did not load"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    k.h.run_steps(10);
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_welcome_screen() {
    let mut k = kit_with(false, true);
    k.h.run_steps(4);
    save(&mut k, "tutorial/welcome.png");
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_welcome_screen_with_the_tour() {
    let mut k = kit_with(false, true);
    k.h.run_steps(4);
    k.h.state_mut().start_tour_at(1);
    save(&mut k, "welcome-tour.png");
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_help_window() {
    let mut k = kit_with(true, true);
    ready_demo(&mut k);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ShowHelp, &ctx);
    save(&mut k, "help.png");
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_a_tour_step() {
    let mut k = kit_with(true, true);
    ready_demo(&mut k);
    k.h.state_mut().start_tour_at(3);
    save(&mut k, "tour.png");
}
