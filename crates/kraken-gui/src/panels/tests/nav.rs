//! Headless tests of the navigation and editing tools: Go to, Search, the right-click menu,
//! Ctrl+Z and the palette's generated forms.

use egui::{Event, Key, Modifiers};

use super::{Harness, ctrl, is_front};
use crate::panels::context::{self, NavChoice, Target, TargetKind, items};
use crate::workspace::Tab;

impl Harness {
    fn click(&mut self, pos: egui::Pos2) {
        self.step_with(vec![Event::PointerMoved(pos)]);
        for pressed in [true, false] {
            self.step_with(vec![Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            }]);
        }
    }

    fn click_remembered(&mut self, key: (&str, impl std::hash::Hash + std::fmt::Debug + Copy)) {
        let rect = crate::panels::remembered_rect(&self.ctx, key)
            .unwrap_or_else(|| panic!("{key:?} was not drawn"));
        self.click(rect.center());
    }

    fn type_text(&mut self, text: &str) {
        self.step_with(vec![Event::Text(text.into())]);
    }

    fn addr_of(&self, name: &str) -> u64 {
        self.app
            .view_model()
            .unwrap()
            .functions
            .items
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no function {name}"))
            .address
    }

    fn current(&self) -> Option<u64> {
        self.app
            .view_model()
            .unwrap()
            .current
            .as_ref()
            .map(|c| c.address)
    }
}

#[test]
fn g_opens_go_to_and_enter_jumps_to_the_typed_name() {
    let mut h = Harness::demo();
    let main = h.select("main");
    let helper = h.addr_of("helper");
    h.press(Key::G);
    h.step();
    assert!(
        h.app.view_model().unwrap().tools.goto.is_some(),
        "G opens Go to"
    );
    h.type_text("helper");
    h.settle();
    h.press(Key::Enter);
    h.settle();
    assert!(
        h.app.view_model().unwrap().tools.goto.is_none(),
        "Enter closes the dialog"
    );
    assert_eq!(h.current(), Some(helper));
    // The jump is in the history.
    h.press_with(Key::ArrowLeft, Modifiers::ALT);
    h.settle();
    assert_eq!(h.current(), Some(main));

    // Escape closes it without moving.
    h.press(Key::G);
    h.step();
    h.press(Key::Escape);
    h.step();
    assert!(h.app.view_model().unwrap().tools.goto.is_none());
    assert_eq!(h.current(), Some(main));
}

#[test]
fn tool_keys_do_nothing_while_a_text_field_has_the_focus() {
    let mut h = Harness::demo();
    h.select("main");
    h.app.pending_nav().focus_filter = true;
    h.step();
    h.step();
    for key in [Key::G, Key::Y, Key::P] {
        h.press(key);
    }
    h.press_with(Key::D, ctrl());
    h.settle();
    let vm = h.app.view_model().unwrap();
    assert!(vm.tools.goto.is_none());
    assert!(vm.tools.type_dialog.is_none());
    assert!(vm.tools.function_dialog.is_none());
    assert!(vm.tools.bookmark_dialog.is_none());
}

#[test]
fn y_and_ctrl_d_open_their_dialogs_for_the_function_being_read() {
    let mut h = Harness::demo();
    let main = h.select("main");
    h.press(Key::Y);
    h.step();
    let vm = h.app.view_model().unwrap();
    assert_eq!(vm.tools.type_dialog.as_ref().map(|d| d.address), Some(main));
    h.press(Key::Escape);
    h.step();
    h.press_with(Key::D, ctrl());
    h.step();
    let vm = h.app.view_model().unwrap();
    assert_eq!(
        vm.tools.bookmark_dialog.as_ref().map(|d| d.address),
        Some(main)
    );
}

#[test]
fn the_types_tab_lists_types_and_shows_the_picked_declaration() {
    let mut h = Harness::demo();
    h.app.bring_to_front(Tab::Types);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::Types));
    let vm = h.app.view_model().unwrap();
    assert!(vm.tools.types.loaded);
    let i = vm
        .tools
        .types
        .items
        .iter()
        .position(|t| t.name == "point")
        .expect("the demo has a struct named point");
    // the list is a virtual list: rows are not individually addressable, so pick through the
    // view-model as a click would, and check the tab draws it
    h.app.view_model_mut().unwrap().select_type("point");
    h.settle();
    let vm = h.app.view_model().unwrap();
    assert!(vm.tools.types.items.len() > i);
    let c = &vm.tools.types.decl.as_ref().expect("declaration").c;
    assert!(c.contains("struct point"), "{c}");
}

#[test]
fn ctrl_shift_f_searches_and_clicking_a_result_navigates() {
    let mut h = Harness::demo();
    h.select("main");
    h.press_with(
        Key::F,
        Modifiers {
            shift: true,
            ..ctrl()
        },
    );
    h.settle();
    assert!(
        is_front(h.app.dock(), Tab::Search),
        "Ctrl+Shift+F shows Search"
    );
    h.type_text("process");
    h.step();
    h.press(Key::Enter);
    h.settle();
    let vm = h.app.view_model().unwrap();
    assert!(vm.tools.search.searched, "Enter in the box runs the search");
    let i = vm
        .tools
        .search
        .hits
        .iter()
        .position(|x| x.text == "process_packet")
        .expect("found process_packet");
    let target = vm.tools.search.hits[i].address;
    h.click_remembered(("search_row", i));
    h.settle();
    assert_eq!(h.current(), Some(target));
    assert!(is_front(h.app.dock(), Tab::Decompiler));
}

fn open_menu_on(h: &mut Harness, target: Target) {
    h.app.pending_nav().assist.menu = Some(crate::assist::MenuState {
        pos: egui::pos2(300.0, 160.0),
        token: target.name.clone(),
        line: None,
        line_kind: kraken_viewmodel::assist::SelectionKind::Decompile,
        function: target.function,
        target: Some(target),
    });
    h.step();
    h.step();
}

#[test]
fn the_right_click_menu_lists_every_item_and_dispatches_them() {
    let mut h = Harness::demo();
    let main = h.select("main");
    let helper = h.addr_of("helper");
    let fun = Target {
        kind: TargetKind::Function,
        address: Some(helper),
        name: Some("helper".into()),
        function: Some(main),
        varnode: None,
    };
    let all = items(h.app.view_model().unwrap(), &fun);
    for want in [
        "Rename",
        "Retype",
        "Edit function signature...",
        "Comment",
        "Show references",
        "Go to definition",
        "Copy address",
        "Copy name",
        "Add bookmark",
        "Delete function...",
        "Rewrite this function in Rust",
    ] {
        assert!(all.iter().any(|i| i.label == want), "{want} missing");
    }
    assert!(all.iter().all(|i| !i.hover.is_empty()));
    let shortcut = |label: &str| all.iter().find(|i| i.label == label).unwrap().shortcut;
    assert_eq!(shortcut("Rename"), Some("N"));
    assert_eq!(shortcut("Retype"), Some("Y"));
    assert_eq!(shortcut("Comment"), Some(";"));
    assert_eq!(shortcut("Show references"), Some("X"));
    assert_eq!(shortcut("Add bookmark"), Some("Ctrl+D"));

    // A variable: rename and retype are there, disabled, and say why.
    let var = Target {
        kind: TargetKind::Variable,
        address: None,
        name: Some("argc".into()),
        function: Some(main),
        varnode: None,
    };
    let vi = items(h.app.view_model().unwrap(), &var);
    let retype = vi.iter().find(|i| i.label == "Retype").unwrap();
    assert!(
        retype
            .disabled
            .as_deref()
            .unwrap_or("")
            .contains("no stored place")
    );
    // Where the variable lives is what makes it editable.
    let placed = Target {
        varnode: Some("stack:0xfffffffffffffff0:8".into()),
        ..var.clone()
    };
    let pi = items(h.app.view_model().unwrap(), &placed);
    for label in ["Rename", "Retype"] {
        let i = pi.iter().find(|i| i.label == label).unwrap();
        assert!(i.disabled.is_none(), "{label}: {:?}", i.disabled);
    }
    context::run(
        &egui::Context::default(),
        h.app.view_model_mut().unwrap(),
        &placed,
        NavChoice::Retype,
    );
    let d = h
        .app
        .view_model()
        .unwrap()
        .tools
        .local_dialog
        .clone()
        .expect("dialog");
    assert_eq!(
        (d.storage.as_str(), d.old_name.as_str(), d.focus_type),
        ("stack:0xfffffffffffffff0", "argc", true)
    );
    h.step();
    h.step();
    h.app.view_model_mut().unwrap().cancel_local();
    let create = vi
        .iter()
        .find(|i| i.label == "Create function here")
        .unwrap();
    assert!(create.disabled.is_some());

    // Clicking items does what they say.
    open_menu_on(&mut h, fun.clone());
    h.click_remembered(("menu", "Rename"));
    h.step();
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .rename
            .as_ref()
            .map(|r| r.address),
        Some(helper)
    );
    assert!(h.app.pending_nav().assist.menu.is_none(), "the menu closes");
    h.app.view_model_mut().unwrap().cancel_rename();
    h.step();

    open_menu_on(&mut h, fun.clone());
    h.click_remembered(("menu", "Go to definition"));
    h.settle();
    assert_eq!(h.current(), Some(helper));

    open_menu_on(&mut h, fun.clone());
    h.click_remembered(("menu", "Add bookmark"));
    h.step();
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .tools
            .bookmark_dialog
            .as_ref()
            .map(|d| d.address),
        Some(helper)
    );
    h.settle();
    h.click_remembered(("dialog", "Save"));
    h.settle();
    assert!(h.app.view_model().unwrap().bookmark_at(helper).is_some());

    open_menu_on(&mut h, fun.clone());
    h.click_remembered(("menu", "Edit function signature..."));
    h.step();
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .tools
            .type_dialog
            .as_ref()
            .map(|d| d.address),
        Some(helper)
    );
    h.press(Key::Escape);
    h.step();

    open_menu_on(&mut h, fun);
    h.click_remembered(("menu", "Delete function..."));
    h.step();
    assert!(h.app.view_model().unwrap().tools.function_dialog.is_some());
    h.settle();
    h.click_remembered(("dialog", "Delete"));
    h.settle();
    assert!(h.app.view_model().unwrap().functions.find(helper).is_none());
}

#[test]
fn ctrl_z_undoes_the_last_change_with_a_link_to_history() {
    let mut h = Harness::demo();
    let helper = h.addr_of("helper");
    let vm = h.app.view_model_mut().unwrap();
    vm.begin_rename(helper, Some("helper"));
    vm.set_rename_input("reply");
    vm.submit_rename();
    h.settle();
    h.press_with(Key::Z, ctrl());
    h.settle();
    let vm = h.app.view_model().unwrap();
    let t = vm
        .toasts
        .iter()
        .find(|t| t.text.starts_with("Undid"))
        .expect("an undo toast");
    assert!(t.text.contains("reply"), "{}", t.text);
    assert_eq!(t.action, Some(kraken_viewmodel::ToastAction::OpenHistory));
    let id = t.id;
    h.app.view_model_mut().unwrap().run_toast_action(id);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::History));
}

#[test]
fn the_palette_opens_a_form_for_any_command_and_runs_it() {
    let mut h = Harness::demo();
    let main = h.select("main");
    h.press_with(Key::K, ctrl());
    h.step();
    h.type_text("read_bytes");
    h.step();
    h.press(Key::Enter);
    h.settle();
    let vm = h.app.view_model().unwrap();
    let form = vm.tools.form.as_ref().expect("a form for read_bytes");
    assert_eq!(form.command, "read_bytes");
    let len = form.fields.iter().position(|f| f.name == "length").unwrap();
    let addr = form.fields.iter().find(|f| f.name == "address").unwrap();
    assert_eq!(addr.value, format!("{main:#x}"), "the address is prefilled");
    h.app.view_model_mut().unwrap().set_form_value(len, "16");
    h.settle();
    h.click_remembered(("dialog", "Run"));
    h.settle();
    let vm = h.app.view_model().unwrap();
    assert!(vm.tools.form.is_none());
    let r = vm.tools.result.as_ref().expect("a result window");
    assert!(!r.failed, "{}", r.text);
    assert!(r.text.contains("\"length\": 16"));
}
