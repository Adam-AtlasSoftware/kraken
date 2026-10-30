//! "Change what this code does...": the wizard driven through its window on the demo project,
//! from the Patch menu action to Save, then checked against `patch_list`.

use std::time::{Duration, Instant};

use egui_kittest::kittest::{NodeT, Queryable};
use kraken_viewmodel::AppAction;
use kraken_viewmodel::navtools::{CText, Draft, PatchStep, WizardIntent};
use kraken_viewmodel::wizard::WizardFlow;

use super::shell::{Kit, kit};
use super::shots::{ready_demo, select_first_instruction};

fn until(k: &mut Kit, what: &str, cond: impl Fn(&Kit) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        k.h.run_steps(2);
        if cond(k) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wizard_is(k: &Kit, f: impl Fn(&kraken_viewmodel::navtools::PatchWizard) -> bool) -> bool {
    k.h.state()
        .view_model()
        .and_then(|vm| vm.tools.patch_wizard.as_ref())
        .is_some_and(f)
}

/// The preview has everything it asks for, so the window has stopped changing size.
fn settled(k: &Kit) -> bool {
    wizard_is(k, |w| {
        matches!(w.draft, Draft::Staged(_))
            && w.lint.is_some()
            && !matches!(w.c_before, CText::Loading)
            && !matches!(w.c_after, CText::Loading)
    })
}

fn step(k: &Kit) -> PatchStep {
    k.h.state()
        .view_model()
        .and_then(|vm| vm.tools.patch_wizard.as_ref())
        .expect("the wizard is open")
        .current()
}

fn press(k: &mut Kit, label: &str) {
    // A notice drawn over the footer would take the click.
    k.h.state_mut().hide_notices();
    k.h.run_steps(6);
    k.h.get_by_label(label).click();
    // The window re-centres over a few frames when the next step is taller.
    k.h.run_steps(8);
}

fn open(k: &mut Kit) {
    ready_demo(k);
    k.h.state_mut().hide_notices();
    select_first_instruction(k);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ChangeWhatItDoes, &ctx);
    k.h.run_steps(3);
    assert_eq!(step(k), PatchStep::Pick);
    until(k, "the pick", |k| wizard_is(k, |w| w.pick.is_some()));
}

fn patch_count(k: &Kit) -> usize {
    k.h.state()
        .view_model()
        .map_or(0, |vm| vm.tools.patches.items.len())
}

#[test]
fn the_wizard_goes_from_the_menu_to_a_saved_patch_set() {
    let mut k = kit(true);
    open(&mut k);

    // Where: the selected instruction is filled in; nothing is staged.
    press(&mut k, "Next");
    assert_eq!(step(&k), PatchStep::Intent);
    assert_eq!(patch_count(&k), 0);

    // What: Next waits for a choice; clicking a card makes it.
    assert!(
        k.h.get_by_label("Next").accesskit_node().is_disabled(),
        "Next waits for an intent"
    );
    k.h.get_by_label_contains("Return a value").click();
    k.h.run_steps(3);
    assert!(
        wizard_is(&k, |w| w.intent == Some(WizardIntent::ReturnValue)),
        "{:?}",
        k.h.state()
            .view_model()
            .and_then(|vm| vm.tools.patch_wizard.as_ref())
    );
    press(&mut k, "Next");
    assert_eq!(step(&k), PatchStep::Preview);

    // Preview: the draft is staged so the checks and the patched C can be asked for.
    until(&mut k, "the preview", settled);
    assert!(
        k.h.query_all_by_label_contains("Patch checks")
            .next()
            .is_some()
    );
    press(&mut k, "Next");
    assert_eq!(
        step(&k),
        PatchStep::Test,
        "{:?}",
        k.h.state()
            .view_model()
            .and_then(|vm| vm.tools.patch_wizard.as_ref())
            .and_then(|w| w.blocker())
    );
    press(&mut k, "Next");
    assert_eq!(step(&k), PatchStep::Save);

    // Save: a named set; the patch ends up in it.
    k.h.state_mut()
        .view_model_mut()
        .and_then(|vm| vm.tools.patch_wizard.as_mut())
        .expect("wizard")
        .set_name = "return one".into();
    k.h.run_steps(2);
    press(&mut k, "Save");
    until(&mut k, "the set to be saved", |k| {
        k.h.state().view_model().is_some_and(|vm| {
            vm.tools.patch_wizard.is_none()
                && vm.tools.patches.items.len() == 1
                && vm.tools.patches.items[0].group == "return one"
        })
    });
}

#[test]
fn cancelling_after_the_preview_removes_the_draft() {
    let mut k = kit(true);
    open(&mut k);
    press(&mut k, "Next");
    k.h.get_by_label_contains("Return a value").click();
    k.h.run_steps(4);
    press(&mut k, "Next");
    until(&mut k, "the preview", settled);
    assert_eq!(patch_count(&k), 1);
    press(&mut k, "Cancel");
    until(&mut k, "the draft to go", |k| {
        patch_count(k) == 0 && !wizard_is(k, |_| true)
    });
}
