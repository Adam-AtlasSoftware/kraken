//! Byte patching in the window: the Patch menu flow over the demo project.

use egui::{Key, Modifiers};
use kraken_viewmodel::AppAction;
use kraken_viewmodel::navtools::spaced_hex;

use super::Harness;
use crate::workspace::Tab;

#[test]
fn patch_here_stages_from_the_listing_and_show_patches_opens_the_tab() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.dispatch(AppAction::GoToMain, &ctx);
    h.run_until("the listing of main", |a| {
        a.view_model().is_some_and(|vm| {
            vm.current.as_ref().is_some_and(|c| c.name == "main")
                && vm.views.listing.loaded
                && !vm.views.listing.rows.is_empty()
        })
    });
    let vm = h.app.view_model_mut().expect("vm");
    vm.select_listing_row(0);
    let row = vm.views.listing.selected_row().cloned().expect("row");

    h.app.dispatch(AppAction::PatchHere, &ctx);
    h.step();
    let vm = h.app.view_model_mut().expect("vm");
    let d = vm
        .tools
        .patch_dialog
        .clone()
        .expect("the patch dialog opens");
    assert_eq!(d.address, row.address);
    let nops = vec![0x90; row.bytes.len()];
    vm.set_patch_input(spaced_hex(&nops));
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the patch to be staged and listed", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools.patch_dialog.is_none()
                && vm
                    .tools
                    .patches
                    .items
                    .iter()
                    .any(|p| p.address == row.address)
        })
    });

    assert!(
        h.app.dock().find_tab(&Tab::Patches).is_none(),
        "not in the default layout"
    );
    h.app.dispatch(AppAction::ShowPatches, &ctx);
    h.step();
    h.step();
    assert!(
        h.app.dock().find_tab(&Tab::Patches).is_some(),
        "opened on demand"
    );

    h.app.dispatch(AppAction::ExportPatched, &ctx);
    h.step();
    assert!(
        h.app
            .view_model()
            .is_some_and(|vm| vm.tools.export_dialog.is_some())
    );
    h.key(Key::Escape, Modifiers::NONE);
    h.step();
    assert!(
        h.app
            .view_model()
            .is_some_and(|vm| vm.tools.export_dialog.is_none())
    );
}

#[test]
fn enter_assembles_the_typed_instruction_then_stages_it() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.dispatch(AppAction::GoToMain, &ctx);
    h.run_until("the listing of main", |a| {
        a.view_model()
            .is_some_and(|vm| vm.views.listing.loaded && !vm.views.listing.rows.is_empty())
    });
    let vm = h.app.view_model_mut().expect("vm");
    vm.select_listing_row(0);
    let at = vm.views.listing.selected_row().expect("row").address;
    h.app.dispatch(AppAction::PatchHere, &ctx);
    h.step();
    h.step();
    assert!(
        h.ctx
            .memory(|m| m.has_focus(egui::Id::new("kraken_patch_asm"))),
        "the instruction field has the focus"
    );
    h.app
        .view_model_mut()
        .expect("vm")
        .set_patch_asm("xor eax, eax");
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the instruction to be assembled", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools
                .patch_dialog
                .as_ref()
                .is_some_and(|d| d.input == "31 c0")
        })
    });
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the assembled bytes to be staged", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools.patch_dialog.is_none()
                && vm
                    .tools
                    .patches
                    .items
                    .iter()
                    .any(|p| p.address == at && p.replacement == [0x31, 0xc0])
        })
    });
}
