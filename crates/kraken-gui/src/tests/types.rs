//! Types are edits in the Types tab: the New type dialog, inline field editing, Apply to address
//! and Delete, drawn over the demo project.

use egui::{Key, Modifiers};

use super::Harness;
use crate::workspace::Tab;

fn types(h: &mut Harness) -> &mut kraken_viewmodel::navtools::TypesPanel {
    &mut h.app.view_model_mut().expect("vm").tools.types
}

#[test]
fn a_type_is_defined_edited_applied_and_deleted_in_the_tab() {
    let mut h = Harness::ready_demo();
    h.app.show_tab(Tab::Types);
    h.run_until("the types list", |a| {
        a.view_model().is_some_and(|vm| vm.tools.types.loaded)
    });

    // the dialog opens and a parse error stays in it
    h.app.view_model_mut().expect("vm").open_type_define();
    h.step();
    types(&mut h).define.as_mut().expect("dialog").text = "struct bad {\n  nosuch x;\n};".into();
    h.step();
    h.key(Key::Enter, Modifiers::COMMAND);
    h.run_until("the parse error", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools
                .types
                .define
                .as_ref()
                .is_some_and(|d| d.error.as_deref().is_some_and(|e| e.contains("line 2")))
        })
    });

    // a good declaration defines the type and selects it, with its fields to edit
    types(&mut h).define.as_mut().expect("dialog").text =
        "struct pkt { unsigned short len; char tag; };".into();
    h.step();
    h.key(Key::Enter, Modifiers::COMMAND);
    h.run_until("the new type to be shown", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools.types.define.is_none()
                && vm
                    .tools
                    .types
                    .decl
                    .as_ref()
                    .is_some_and(|d| d.name == "pkt" && d.fields.len() == 2)
        })
    });

    // inline edit goes through the same command
    h.app.view_model_mut().expect("vm").edit_type_field(
        "pkt",
        "len",
        Some("length".into()),
        Some("int".into()),
    );
    h.run_until("the renamed field", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools
                .types
                .decl
                .as_ref()
                .is_some_and(|d| d.fields[0].name == "length" && d.fields[1].offset == 4)
        })
    });

    // the Apply dialog checks the address before it asks
    h.app.view_model_mut().expect("vm").open_type_apply("pkt");
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.step();
    assert!(
        types(&mut h)
            .apply
            .as_ref()
            .is_some_and(|d| d.error.is_some()),
        "an empty address is refused in the dialog"
    );
    h.key(Key::Escape, Modifiers::NONE);
    h.step();
    assert!(types(&mut h).apply.is_none());

    h.app.view_model_mut().expect("vm").delete_type("pkt");
    h.run_until("the type to be gone", |a| {
        a.view_model().is_some_and(|vm| {
            vm.tools.types.items.iter().all(|t| t.name != "pkt") && vm.tools.types.decl.is_none()
        })
    });
}
