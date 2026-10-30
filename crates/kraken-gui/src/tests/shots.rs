//! Documentation screenshots of the help window and the tour, drawn on the GPU without a window.
//! Run by hand from the repository root: `KRAKEN_SHOT_DIR=$PWD/docs/images cargo test -p kraken-gui shots -- --ignored`.

use std::path::PathBuf;

use egui_kittest::kittest::Queryable;

use kraken_viewmodel::{AnalysisPhase, AppAction, Connection, Load};

use super::shell::{Kit, kit_from, kit_with};

fn out_dir() -> PathBuf {
    std::env::var_os("KRAKEN_SHOT_DIR").map_or_else(std::env::temp_dir, PathBuf::from)
}

pub(super) fn save(k: &mut Kit, name: &str) {
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

pub(super) fn ready_demo(k: &mut Kit) {
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

/// A real project, drawn without a window (the windowed `--screenshot` needs a compositor that
/// draws, which an idle or locked session does not). `KRAKEN_SHOT_PROJECT=<dir>` opens it in
/// this process, `KRAKEN_SHOT_FUNCTION=<name>` selects a function, `KRAKEN_SHOT_TAB=<title>`
/// brings a tab forward, `KRAKEN_SHOT_ACTION=wizard` opens the rewrite wizard,
/// `KRAKEN_SHOT_MENU=<menu>` opens a menu of the menu bar, and `KRAKEN_SHOT_NAME=<file.png>` names
/// the picture in `KRAKEN_SHOT_DIR`.
#[test]
#[ignore = "writes PNG files and needs a GPU and a project; run by hand"]
fn screenshot_a_project_from_the_environment() {
    let Some(project) = std::env::var_os("KRAKEN_SHOT_PROJECT").map(PathBuf::from) else {
        eprintln!("skipped: set KRAKEN_SHOT_PROJECT");
        return;
    };
    let mut opts = super::options(false);
    opts.no_daemon = true;
    opts.open_project = Some(project);
    let mut k = kit_from(crate::services::Services::from_env(true), &opts, true);
    let function = std::env::var("KRAKEN_SHOT_FUNCTION").ok();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut selected = function.is_none();
    loop {
        k.h.run_steps(1);
        let state = k.h.state_mut();
        if let Some(vm) = state.view_model_mut()
            && vm.connection == Connection::Open
            && !vm.functions.items.is_empty()
            && !vm.busy()
        {
            if !selected {
                let pick = vm
                    .functions
                    .items
                    .iter()
                    .find(|f| Some(&f.name) == function.as_ref())
                    .map(|f| f.address);
                if let Some(a) = pick {
                    vm.select_function(a);
                }
                selected = true;
            } else if function.is_none()
                || vm
                    .current
                    .as_ref()
                    .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)))
            {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            let vm = k.h.state().view_model();
            panic!(
                "the project did not open: connection {:?}, {} functions, busy {:?}, current {:?}",
                vm.map(|v| v.connection.clone()),
                vm.map_or(0, |v| v.functions.items.len()),
                vm.map(|v| v.busy()),
                vm.and_then(|v| v.current.as_ref()).map(|c| (
                    c.name.clone(),
                    format!("{:?}", c.decompiled)
                        .chars()
                        .take(200)
                        .collect::<String>()
                )),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    k.h.run_steps(10);
    if let Ok(title) = std::env::var("KRAKEN_SHOT_TAB")
        && let Some(tab) = crate::menu::VIEW_TABS
            .into_iter()
            .find(|t| t.title() == title)
    {
        k.h.state_mut().bring_to_front(tab);
    }
    if let Ok(menu) = std::env::var("KRAKEN_SHOT_MENU") {
        k.h.get_by_label(&menu).click();
    }
    if std::env::var("KRAKEN_SHOT_ACTION").is_ok_and(|a| a == "patch-wizard") {
        patch_wizard_to_preview(&mut k);
    }
    if std::env::var("KRAKEN_SHOT_ACTION").is_ok_and(|a| a == "wizard") {
        let ctx = k.h.ctx.clone();
        k.h.state_mut().dispatch(AppAction::RewriteWizard, &ctx);
    }
    for _ in 0..200 {
        k.h.run_steps(1);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let name = std::env::var("KRAKEN_SHOT_NAME").unwrap_or_else(|_| "project.png".into());
    save(&mut k, &name);
}

/// Main's first instruction selected in the Listing.
pub(super) fn select_first_instruction(k: &mut Kit) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        k.h.run_steps(1);
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        vm.ensure_listing();
        if vm.views.listing.loaded && !vm.views.listing.rows.is_empty() {
            vm.select_listing_row(0);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no listing");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_patch_dialog_and_the_patches_tab() {
    let mut k = kit_with(true, true);
    ready_demo(&mut k);
    select_first_instruction(&mut k);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::PatchHere, &ctx);
    k.h.run_steps(2);
    let vm = k.h.state_mut().view_model_mut().expect("vm");
    let len = vm
        .tools
        .patch_dialog
        .as_ref()
        .and_then(|d| d.original.as_ref())
        .map_or(1, Vec::len);
    let _ = len;
    vm.set_patch_asm("xor eax, eax");
    vm.assemble_patch();
    vm.set_patch_note("return 0 instead");
    k.h.run_steps(4);
    save(&mut k, "patch-dialog.png");

    let vm = k.h.state_mut().view_model_mut().expect("vm");
    vm.pad_patch_with_nops();
    vm.submit_patch();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        k.h.run_steps(1);
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        if vm.tools.patch_dialog.is_none() && !vm.tools.patches.items.is_empty() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "not staged");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    k.h.state_mut().dispatch(AppAction::ShowPatches, &ctx);
    save(&mut k, "patches.png");
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_edit_tab_with_a_plan() {
    let mut k = kit_with(true, true);
    ready_demo(&mut k);
    let ctx = k.h.ctx.clone();
    let vm = k.h.state_mut().view_model_mut().expect("vm");
    vm.begin_source_edit();
    let text = vm
        .tools
        .source_edit
        .as_ref()
        .map(|e| e.text.replacen("return 2;", "return 0;  // keep going", 1))
        .expect("edit");
    vm.set_source_edit_text(text);
    vm.plan_source_edit();
    let _ = ctx;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        k.h.run_steps(1);
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        if vm.ai.confirm.is_some() {
            vm.ai_confirm_yes();
        }
        if vm
            .tools
            .source_edit
            .as_ref()
            .is_some_and(|e| e.plan().is_some())
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no plan");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    save(&mut k, "edit-tab.png");
}

#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_the_patch_wizard_preview() {
    use kraken_viewmodel::navtools::{Draft, WizardIntent};
    let mut k = kit_with(true, true);
    ready_demo(&mut k);
    select_first_instruction(&mut k);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ChangeWhatItDoes, &ctx);
    k.h.run_steps(3);
    k.h.get_by_label("Next").click();
    k.h.run_steps(3);
    let vm = k.h.state_mut().view_model_mut().expect("vm");
    let w = vm.tools.patch_wizard.as_mut().expect("wizard");
    w.intent = Some(WizardIntent::ReturnValue);
    w.value = "1".into();
    k.h.run_steps(3);
    save(&mut k, "patch-wizard-what.png");
    k.h.get_by_label("Next").click();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        k.h.run_steps(1);
        let vm = k.h.state().view_model().expect("vm");
        if vm
            .tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| matches!(w.draft, Draft::Staged(_)) && w.lint.is_some())
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no preview");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    save(&mut k, "patch-wizard-preview.png");
}

/// `KRAKEN_SHOT_ACTION=patch-wizard`: the Change what this code does wizard on its preview step,
/// at `KRAKEN_SHOT_ADDRESS` with `KRAKEN_SHOT_INTENT` (`always`, `never`, `return`).
fn patch_wizard_to_preview(k: &mut Kit) {
    use kraken_viewmodel::navtools::{CText, Draft, WizardIntent};
    let address = std::env::var("KRAKEN_SHOT_ADDRESS")
        .ok()
        .and_then(|a| kraken_viewmodel::navtools::parse_number(&a))
        .map(|a| a as u64);
    let intent = match std::env::var("KRAKEN_SHOT_INTENT").as_deref() {
        Ok("always") => WizardIntent::AlwaysTake,
        Ok("return") => WizardIntent::ReturnValue,
        _ => WizardIntent::NeverTake,
    };
    k.h.state_mut()
        .view_model_mut()
        .expect("vm")
        .begin_patch_wizard(address);
    k.h.run_steps(5);
    k.h.get_by_label("Next").click();
    k.h.run_steps(8);
    let w =
        k.h.state_mut()
            .view_model_mut()
            .and_then(|vm| vm.tools.patch_wizard.as_mut())
            .expect("wizard");
    w.intent = Some(intent);
    k.h.run_steps(5);
    k.h.state_mut().hide_notices();
    k.h.run_steps(6);
    k.h.get_by_label("Next").click();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        k.h.run_steps(1);
        let done =
            k.h.state()
                .view_model()
                .and_then(|vm| vm.tools.patch_wizard.as_ref())
                .is_some_and(|w| {
                    matches!(w.draft, Draft::Staged(_))
                        && w.lint.is_some()
                        && !matches!(w.c_before, CText::Loading)
                        && !matches!(w.c_after, CText::Loading)
                });
        if done {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no preview");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    k.h.run_steps(10);
}
