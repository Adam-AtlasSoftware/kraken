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

#[test]
fn the_context_menu_patch_items_preview_then_apply_a_nop() {
    use crate::panels::context::{self, NavChoice, Target, TargetKind};
    use kraken_viewmodel::navtools::IntentKind;

    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.dispatch(AppAction::GoToMain, &ctx);
    h.run_until("the listing of main", |a| {
        a.view_model()
            .is_some_and(|vm| vm.views.listing.loaded && !vm.views.listing.rows.is_empty())
    });
    let vm = h.app.view_model_mut().expect("vm");
    vm.select_listing_row(0);
    let row = vm.views.listing.selected_row().cloned().expect("row");

    let target = Target {
        kind: TargetKind::Code,
        address: Some(row.address),
        name: None,
        function: None,
    };
    let items = context::items(vm, &target);
    let patch: Vec<_> = items.iter().filter(|i| i.group == Some("Patch")).collect();
    assert_eq!(patch.len(), 6, "NOP, three branch edits, return, fill");
    assert!(
        patch
            .iter()
            .all(|i| i.disabled.is_none() || i.choice == NavChoice::PatchReturn)
    );
    let data = Target {
        kind: TargetKind::Data,
        ..target.clone()
    };
    let off = context::items(vm, &data)
        .into_iter()
        .find(|i| i.choice == NavChoice::PatchNop)
        .expect("item");
    assert!(off.disabled.is_some(), "NOP is for instructions");

    context::run(&ctx, vm, &target, NavChoice::PatchNop);
    h.run_until("the preview", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools
                .intent_dialog
                .as_ref()
                .is_some_and(|d| d.preview.is_some())
        })
    });
    let d = h
        .app
        .view_model()
        .expect("vm")
        .tools
        .intent_dialog
        .clone()
        .expect("dialog");
    assert_eq!(d.kind, IntentKind::Nop);
    let pv = d.preview.expect("preview");
    assert_eq!(pv.original.len(), row.bytes.len() * 2);
    assert_eq!(pv.replacement.len(), pv.original.len());
    assert!(pv.replacement.starts_with("0f1f") || pv.replacement.starts_with("90"));
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the NOP to be staged", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools.intent_dialog.is_none()
                && vm
                    .tools
                    .patches
                    .items
                    .iter()
                    .any(|p| p.address == row.address)
        })
    });

    // A branch edit on a plain instruction is refused with a reason, and nothing is staged.
    let vm = h.app.view_model_mut().expect("vm");
    let next = vm.views.listing.rows.get(1).expect("row 1").address;
    vm.begin_intent(IntentKind::BranchInvert, next);
    h.run_until("the refusal", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools
                .intent_dialog
                .as_ref()
                .is_some_and(|d| d.error.is_some())
        })
    });
    let err = h
        .app
        .view_model()
        .expect("vm")
        .tools
        .intent_dialog
        .as_ref()
        .and_then(|d| d.error.clone())
        .expect("error");
    assert!(err.to_lowercase().contains("conditional"), "{err}");
    h.key(Key::Escape, Modifiers::NONE);
    h.step();
    assert!(
        h.app
            .view_model()
            .expect("vm")
            .tools
            .intent_dialog
            .is_none()
    );
}

#[test]
fn the_patched_toggle_shows_the_patch_in_the_listing_and_offers_a_patched_decompile() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.dispatch(AppAction::GoToMain, &ctx);
    h.run_until("the listing of main", |a| {
        a.view_model()
            .is_some_and(|vm| vm.views.listing.loaded && !vm.views.listing.rows.is_empty())
    });
    let vm = h.app.view_model_mut().expect("vm");
    vm.select_listing_row(0);
    let row = vm.views.listing.selected_row().cloned().expect("row");
    assert!(row.patch.is_none());

    h.app.dispatch(AppAction::PatchHere, &ctx);
    h.step();
    let vm = h.app.view_model_mut().expect("vm");
    vm.set_patch_input(spaced_hex(&vec![0x90; row.bytes.len()]));
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the patch to be listed", |a| {
        a.view_model()
            .is_some_and(|vm| vm.has_patches() && vm.tools.patch_dialog.is_none())
    });

    // Original side: the listing is the file on disk.
    h.run_until("the listing reloaded", |a| {
        a.view_model()
            .is_some_and(|vm| vm.views.listing.loaded && !vm.views.listing.loading)
    });
    let vm = h.app.view_model_mut().expect("vm");
    assert!(vm.views.listing.rows.iter().all(|r| r.patch.is_none()));

    vm.set_patched_view(true);
    h.run_until("the patched listing", |a| {
        a.view_model().is_some_and(|vm| {
            vm.views.listing.rows.iter().any(|r| r.patch.is_some()) && !vm.views.listing.loading
        })
    });
    let vm = h.app.view_model().expect("vm");
    let first = &vm.views.listing.rows[0];
    assert_eq!(first.mnemonic, "nop", "{first:?}");
    assert!(first.patch.is_some());
    // The four NOPs together cover the instruction that was on disk.
    let originals: Vec<u8> = vm
        .views
        .listing
        .rows
        .iter()
        .filter_map(|r| r.patch.as_ref())
        .flat_map(|p| p.original_bytes.clone())
        .collect();
    assert_eq!(originals, row.bytes);

    // The Decompiler offers the patched decompile; asking settles into a result or a reason.
    h.step();
    h.step();
    h.app
        .view_model_mut()
        .expect("vm")
        .decompile_patched_current();
    h.run_until("the patched decompile to settle", |a| {
        a.view_model().is_some_and(|vm| {
            !matches!(
                vm.views.patched_decompile.state,
                kraken_viewmodel::Load::Idle | kraken_viewmodel::Load::Loading
            )
        })
    });
    h.step();

    // Back to Original.
    h.app.view_model_mut().expect("vm").set_patched_view(false);
    h.run_until("the original listing", |a| {
        a.view_model().is_some_and(|vm| {
            !vm.views.listing.loading && vm.views.listing.rows.iter().all(|r| r.patch.is_none())
        })
    });
    let vm = h.app.view_model().expect("vm");
    assert_ne!(vm.views.listing.rows[0].mnemonic, "nop");
}
