//! The tools over the demo project: the real registry on the fake engine, in process.

use std::time::Duration;

use tokio::runtime::Runtime;

use super::*;
use crate::demo::{demo_fixture, demo_project_with};
use crate::{AnalysisPhase, Connection, ToastAction, ToastLevel, ViewModel};

const WAIT: Duration = Duration::from_secs(20);

struct Rig {
    vm: ViewModel,
    _rt: Runtime,
}

fn rig() -> Rig {
    rig_with(demo_fixture())
}

fn rig_with(fixture: engine_fake::FixtureFile) -> Rig {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(fixture, Duration::ZERO).expect("demo");
    let mut vm = ViewModel::new(d.backend, rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until(WAIT, |v| v.connection == Connection::Open));
    vm.start_analysis();
    assert!(
        vm.block_until(WAIT, |v| v.analysis.phase == AnalysisPhase::Complete
            && !v.functions.items.is_empty()
            && !v.busy())
    );
    Rig { vm, _rt: rt }
}

fn addr_of(vm: &ViewModel, name: &str) -> u64 {
    vm.functions
        .items
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no {name}"))
        .address
}

fn idle(vm: &mut ViewModel) {
    assert!(vm.block_until_idle(WAIT));
}

#[test]
fn addresses_parse_but_bare_words_are_names() {
    assert_eq!(parse_address("0x401000"), Some(0x401000));
    assert_eq!(parse_address("401000"), Some(0x401000));
    assert_eq!(parse_address("401000h"), Some(0x401000));
    assert_eq!(parse_address("add"), None);
    assert_eq!(parse_address("0xadd"), Some(0xadd));
    assert_eq!(parse_address("main"), None);
    assert_eq!(parse_address("0x"), None);
}

#[test]
fn go_to_takes_names_addresses_and_main_and_records_history() {
    let mut r = rig();
    let main = addr_of(&r.vm, "main");
    let helper = addr_of(&r.vm, "helper");

    r.vm.open_goto();
    idle(&mut r.vm);
    r.vm.set_goto_input("helpe");
    idle(&mut r.vm);
    let d = r.vm.tools.goto.as_ref().expect("dialog");
    assert_eq!(d.suggestions[0].name, "helper");
    r.vm.submit_goto();
    idle(&mut r.vm);
    assert!(r.vm.tools.goto.is_none());
    assert_eq!(r.vm.current.as_ref().map(|c| c.address), Some(helper));

    r.vm.open_goto();
    r.vm.set_goto_input("main");
    r.vm.submit_goto();
    idle(&mut r.vm);
    assert_eq!(r.vm.current.as_ref().map(|c| c.address), Some(main));

    r.vm.open_goto();
    r.vm.set_goto_input(format!("{helper:#x}"));
    r.vm.submit_goto();
    idle(&mut r.vm);
    assert_eq!(r.vm.current.as_ref().map(|c| c.address), Some(helper));
    r.vm.go_back();
    idle(&mut r.vm);
    assert_eq!(r.vm.current.as_ref().map(|c| c.address), Some(main));

    r.vm.open_goto();
    r.vm.set_goto_input("no_such_thing_anywhere");
    idle(&mut r.vm);
    r.vm.submit_goto();
    idle(&mut r.vm);
    let d = r.vm.tools.goto.as_ref().expect("still open");
    assert!(
        d.error
            .as_deref()
            .unwrap_or("")
            .contains("Nothing is called")
    );
}

#[test]
fn search_finds_names_and_instructions_and_opens_hits() {
    let mut r = rig();
    r.vm.open_search();
    assert_eq!(r.vm.tools.take_tab(), Some(NavTab::Search));
    r.vm.tools.search.query = "process".into();
    r.vm.run_search();
    idle(&mut r.vm);
    let s = &r.vm.tools.search;
    assert!(s.searched && s.error.is_none(), "{:?}", s.error);
    let i = s
        .hits
        .iter()
        .position(|h| h.text == "process_packet")
        .expect("process_packet found");
    let target = s.hits[i].address;
    r.vm.open_search_hit(i);
    idle(&mut r.vm);
    assert_eq!(r.vm.current.as_ref().map(|c| c.address), Some(target));

    r.vm.tools.search.query = "call".into();
    r.vm.set_search_kind(SearchKind::Instructions);
    idle(&mut r.vm);
    let s = &r.vm.tools.search;
    assert!(!s.hits.is_empty());
    assert!(
        s.hits
            .iter()
            .all(|h| h.kind == "instruction" && h.function.is_some())
    );

    r.vm.tools.search.query = "   ".into();
    r.vm.run_search();
    assert!(r.vm.tools.search.error.is_some());
}

#[test]
fn bookmarks_are_added_listed_and_removed() {
    let mut r = rig();
    let main = addr_of(&r.vm, "main");
    r.vm.select_function(main);
    idle(&mut r.vm);
    r.vm.begin_bookmark_here();
    r.vm.set_bookmark_input("start reading here");
    r.vm.submit_bookmark();
    idle(&mut r.vm);
    assert!(r.vm.tools.bookmark_dialog.is_none());
    let b = r.vm.bookmark_at(main).expect("listed");
    assert_eq!(b.note, "start reading here");
    assert_eq!(b.who, "you");

    r.vm.begin_bookmark(main);
    assert!(
        r.vm.tools
            .bookmark_dialog
            .as_ref()
            .is_some_and(|d| d.existing)
    );
    r.vm.cancel_bookmark();
    r.vm.remove_bookmark(main);
    idle(&mut r.vm);
    assert!(r.vm.bookmark_at(main).is_none());
}

#[test]
fn types_are_listed_filtered_and_shown_as_c() {
    let mut r = rig();
    r.vm.ensure_types();
    idle(&mut r.vm);
    let names: Vec<&str> =
        r.vm.tools
            .types
            .items
            .iter()
            .map(|t| t.name.as_str())
            .collect();
    assert_eq!(names, ["color", "point", "pt_t"]);

    r.vm.set_types_kind("struct");
    idle(&mut r.vm);
    assert_eq!(r.vm.tools.types.items.len(), 1);
    r.vm.set_types_kind("");
    r.vm.set_types_filter("PT");
    idle(&mut r.vm);
    assert_eq!(r.vm.tools.types.items[0].name, "pt_t");
    r.vm.set_types_filter("");
    idle(&mut r.vm);

    r.vm.select_type("point");
    idle(&mut r.vm);
    let decl = r.vm.tools.types.decl.as_ref().expect("declaration");
    assert!(decl.c.starts_with("struct point {"), "{}", decl.c);
    r.vm.select_type("nope");
    idle(&mut r.vm);
    assert!(r.vm.tools.types.decl.is_none() && r.vm.tools.types.decl_error.is_some());
}

#[test]
fn types_are_defined_edited_and_deleted_from_the_tab() {
    let mut r = rig();
    r.vm.ensure_types();
    idle(&mut r.vm);

    // a parse error stays in the dialog and names the line
    r.vm.open_type_define();
    r.vm.tools.types.define.as_mut().expect("dialog").text =
        "struct packet {\n  int len;\n  nosuch x;\n};".into();
    r.vm.submit_type_define();
    idle(&mut r.vm);
    let d = r.vm.tools.types.define.as_ref().expect("still open");
    assert!(
        !d.busy && d.error.as_deref().is_some_and(|e| e.contains("line 3")),
        "{d:?}"
    );

    r.vm.tools.types.define.as_mut().expect("dialog").text =
        "struct packet { unsigned short len; char tag; };".into();
    r.vm.submit_type_define();
    idle(&mut r.vm);
    idle(&mut r.vm);
    assert!(r.vm.tools.types.define.is_none());
    assert!(r.vm.tools.types.items.iter().any(|t| t.name == "packet"));
    let decl = r.vm.tools.types.decl.as_ref().expect("selected");
    assert_eq!(decl.name, "packet");
    assert_eq!(decl.fields.len(), 2);
    assert_eq!(decl.fields[0].ty, "uint16_t");

    r.vm.edit_type_field("packet", "len", Some("length".into()), Some("int".into()));
    idle(&mut r.vm);
    idle(&mut r.vm);
    let decl = r.vm.tools.types.decl.as_ref().expect("declaration");
    assert_eq!(decl.fields[0].name, "length");
    assert_eq!(decl.fields[1].offset, 4);

    r.vm.edit_type_field("packet", "nope", Some("x".into()), None);
    idle(&mut r.vm);
    assert!(r.vm.tools.types.edit_error.is_some());

    r.vm.open_type_apply("packet");
    r.vm.tools.types.apply.as_mut().expect("dialog").address = "not an address".into();
    r.vm.submit_type_apply();
    assert!(
        r.vm.tools
            .types
            .apply
            .as_ref()
            .is_some_and(|d| d.error.is_some())
    );
    r.vm.close_type_apply();

    r.vm.delete_type("packet");
    idle(&mut r.vm);
    idle(&mut r.vm);
    assert!(r.vm.tools.types.items.iter().all(|t| t.name != "packet"));
    assert!(r.vm.tools.types.decl.is_none());
}

#[test]
fn signature_dialog_parses_inline_and_saves_through_set_type() {
    let mut r = rig();
    let helper = addr_of(&r.vm, "helper");
    r.vm.select_function(helper);
    idle(&mut r.vm);
    r.vm.begin_retype(helper);
    let d = r.vm.tools.type_dialog.as_ref().expect("dialog");
    assert_eq!(d.mode, TypeMode::Signature);
    assert!(d.input.contains("helper"), "{}", d.input);

    r.vm.set_type_input("int helper(int (*cb)(int))");
    let before = r.vm.pending_calls();
    r.vm.submit_type();
    assert_eq!(r.vm.pending_calls(), before, "a parse error sends nothing");
    assert!(r.vm.tools.type_dialog.as_ref().unwrap().error.is_some());

    r.vm.set_type_input("int other_name(int count, char *name)");
    let (_, note) =
        r.vm.tools
            .type_dialog
            .as_ref()
            .unwrap()
            .check()
            .expect("parses");
    assert!(note.is_some_and(|n| n.contains("Rename")));
    r.vm.set_type_input("int helper(int count, char *name)");
    r.vm.submit_type();
    idle(&mut r.vm);
    assert!(
        r.vm.tools.type_dialog.is_none(),
        "{:?}",
        r.vm.tools.type_dialog
    );
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.contains("Signature change"))
    );

    // Data: the type dialog for an address that is not a function.
    r.vm.begin_retype(0x10);
    let d = r.vm.tools.type_dialog.as_ref().expect("data dialog");
    assert_eq!(d.mode, TypeMode::Data);
    r.vm.set_type_input("char *p");
    assert!(r.vm.tools.type_dialog.as_ref().unwrap().check().is_err());
}

#[test]
fn variable_dialog_checks_the_input_and_saves_through_set_local() {
    let mut r = rig();
    let helper = addr_of(&r.vm, "helper");
    r.vm.select_function(helper);
    idle(&mut r.vm);

    r.vm.begin_local(helper, "nonsense", "x", false);
    assert!(r.vm.tools.local_dialog.is_none(), "no storage, no dialog");
    r.vm.begin_local(helper, "stack:0xfffffffffffffff0:8", "lStack_10", false);
    let d = r.vm.tools.local_dialog.as_ref().expect("dialog");
    assert_eq!(d.storage, "stack:0xfffffffffffffff0");
    assert!(d.check().is_err(), "nothing changed yet");

    let before = r.vm.pending_calls();
    r.vm.set_local_input("lStack_10", "not a type!");
    r.vm.submit_local();
    assert_eq!(r.vm.pending_calls(), before, "a parse error sends nothing");
    assert!(r.vm.tools.local_dialog.as_ref().unwrap().error.is_some());

    r.vm.set_local_input("total", "unsigned long");
    let args =
        r.vm.tools
            .local_dialog
            .as_ref()
            .unwrap()
            .check()
            .expect("ok");
    assert_eq!(args["name"], "total");
    assert_eq!(args["storage"], "stack:0xfffffffffffffff0");
    assert_eq!(args["data_type"]["kind"], "primitive");
    r.vm.set_local_input("has space", "");
    assert!(r.vm.tools.local_dialog.as_ref().unwrap().check().is_err());
    r.vm.set_local_input("total", "");
    r.vm.submit_local();
    idle(&mut r.vm);
    assert!(
        r.vm.tools.local_dialog.is_none(),
        "{:?}",
        r.vm.tools.local_dialog
    );
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.contains("Variable saved"))
    );
}

#[test]
fn functions_are_created_and_deleted_after_a_confirmation() {
    let mut r = rig();
    let helper = addr_of(&r.vm, "helper");
    r.vm.begin_create_function(helper);
    assert!(
        r.vm.tools.function_dialog.is_none(),
        "one exists there already"
    );

    r.vm.begin_delete_function(helper);
    let d = r.vm.tools.function_dialog.as_ref().expect("confirm");
    assert_eq!(d.kind, FunctionDialogKind::Delete);
    assert_eq!(d.name, "helper");
    r.vm.submit_function_dialog();
    idle(&mut r.vm);
    assert!(r.vm.tools.function_dialog.is_none());
    assert!(r.vm.functions.find(helper).is_none());

    r.vm.begin_create_function(helper);
    r.vm.set_function_name_input("bad name");
    r.vm.submit_function_dialog();
    assert!(r.vm.tools.function_dialog.as_ref().unwrap().error.is_some());
    r.vm.set_function_name_input("helper_again");
    r.vm.submit_function_dialog();
    idle(&mut r.vm);
    assert!(r.vm.tools.function_dialog.is_none());
    assert_eq!(
        r.vm.functions.find(helper).map(|f| f.name.as_str()),
        Some("helper_again")
    );
}

#[test]
fn undo_says_what_it_undid_and_links_to_the_history() {
    let mut r = rig();
    let helper = addr_of(&r.vm, "helper");
    r.vm.begin_rename(helper, Some("helper"));
    r.vm.set_rename_input("send_reply");
    r.vm.submit_rename();
    idle(&mut r.vm);
    assert!(!r.vm.history.entries.is_empty());
    r.vm.perform(crate::AppAction::UndoLast);
    idle(&mut r.vm);
    let t =
        r.vm.toasts
            .iter()
            .rev()
            .find(|t| t.text.starts_with("Undid"))
            .expect("undo toast")
            .clone();
    assert_eq!(t.level, ToastLevel::Success);
    assert!(t.text.contains("send_reply"), "{}", t.text);
    assert_eq!(t.action, Some(ToastAction::OpenHistory));
    r.vm.run_toast_action(t.id);
    assert_eq!(r.vm.tools.take_tab(), Some(NavTab::History));
}

#[test]
fn generated_forms_prefill_addresses_and_show_results() {
    let mut r = rig();
    let main = addr_of(&r.vm, "main");
    r.vm.select_function(main);
    idle(&mut r.vm);
    r.vm.open_command_form("read_bytes");
    let f = r.vm.tools.form.as_ref().expect("form");
    let addr = f.fields.iter().position(|x| x.name == "address").unwrap();
    let len = f.fields.iter().position(|x| x.name == "length").unwrap();
    assert_eq!(f.fields[addr].kind, FieldKind::Address);
    assert_eq!(f.fields[addr].value, format!("{main:#x}"));
    assert_eq!(f.fields[len].kind, FieldKind::Integer);
    assert!(f.fields[len].required);

    r.vm.submit_command_form();
    assert!(
        r.vm.tools.form.as_ref().unwrap().error.is_some(),
        "length is required"
    );
    r.vm.set_form_value(len, "8");
    r.vm.submit_command_form();
    idle(&mut r.vm);
    assert!(r.vm.tools.form.is_none());
    let res = r.vm.tools.result.as_ref().expect("result");
    assert!(!res.failed);
    assert!(res.text.contains("\"length\": 8"), "{}", res.text);
    let lines = result_lines(&res.text);
    assert!(
        lines
            .iter()
            .flatten()
            .any(|s| matches!(s, ResultSegment::Address(_, a) if *a == main))
    );

    // An enum and an optional field.
    r.vm.open_command_form("xrefs");
    let f = r.vm.tools.form.as_ref().unwrap();
    let dir = f.fields.iter().find(|x| x.name == "direction").unwrap();
    assert!(matches!(&dir.kind, FieldKind::Enum(o) if o.iter().any(|(v, _)| v == "to")));
    let kind = f.fields.iter().find(|x| x.name == "kind").unwrap();
    assert!(!kind.required);
    assert!(f.fields.iter().all(|x| x.name != "expect_versions"));
    r.vm.cancel_command_form();

    // A command with no arguments runs at once.
    r.vm.open_command_form("project_info");
    idle(&mut r.vm);
    assert!(r.vm.tools.form.is_none());
    assert!(
        r.vm.tools
            .result
            .as_ref()
            .unwrap()
            .text
            .contains("demo-server")
    );
}

#[test]
fn result_lines_link_addresses_only_at_word_starts() {
    let lines = result_lines("  \"a\": \"0x401000\", \"b\": \"ab0x12\"\nplain");
    assert_eq!(lines.len(), 2);
    let addrs: Vec<u64> = lines[0]
        .iter()
        .filter_map(|s| match s {
            ResultSegment::Address(_, a) => Some(*a),
            _ => None,
        })
        .collect();
    assert_eq!(addrs, vec![0x401000]);
    assert_eq!(lines[1], vec![ResultSegment::Text("plain".into())]);
    let joined: String = lines[0]
        .iter()
        .map(|s| match s {
            ResultSegment::Text(t) | ResultSegment::Address(t, _) => t.as_str(),
        })
        .collect();
    assert_eq!(joined, "  \"a\": \"0x401000\", \"b\": \"ab0x12\"");
}

// ---------------------------------------------------------------- patches

#[test]
fn hex_input_parses_like_the_registry() {
    assert_eq!(parse_hex("b8 07 00 00 00").unwrap(), vec![0xb8, 7, 0, 0, 0]);
    assert_eq!(parse_hex("0xEB10").unwrap(), vec![0xeb, 0x10]);
    assert!(parse_hex("").is_err());
    assert!(parse_hex("abc").unwrap_err().contains("two hex digits"));
    assert!(parse_hex("zz").unwrap_err().contains("not a hex digit"));
    assert_eq!(spaced_hex(&[0xb8, 7]), "b8 07");
}

#[test]
fn a_short_replacement_is_flagged_and_can_be_padded_with_nops() {
    let mut d = PatchDialog {
        address: 0x40113a,
        by_offset: false,
        offset_text: String::new(),
        original: Some(vec![0xb8, 3, 0, 0, 0]),
        origin: PatchOrigin::Instruction("mov eax, 0x3".into()),
        input: "31 c0".into(),
        note: String::new(),
        existing: false,
        error: None,
        submitting: false,
        x86: true,
        asm: String::new(),
        asm_state: AsmState::Idle,
        asm_note: None,
        group: String::new(),
    };
    assert!(d.length_note().expect("note").contains("first 2 of the 5"));
    d.pad_with_nops();
    assert_eq!(d.input, "31 c0 90 90 90");
    assert_eq!(d.length_note(), None);
    d.input = "b8 07 00 00 00 90".into();
    assert!(
        d.length_note()
            .expect("note")
            .contains("overwrite what follows")
    );
    // No nop padding on other processors.
    d.input = "00".into();
    d.x86 = false;
    d.pad_with_nops();
    assert_eq!(d.input, "00");
}

/// An approver that always says yes and counts the questions.
#[derive(Default)]
struct Yes(std::sync::Mutex<Vec<String>>);

#[async_trait::async_trait]
impl crate::backend::Approver for Yes {
    async fn approve(&self, prompt: crate::backend::ApprovalPrompt) -> bool {
        self.0.lock().expect("lock").push(prompt.command);
        true
    }
}

#[test]
fn an_instruction_patch_is_staged_listed_edited_removed_and_exported_after_a_question() {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::ZERO).expect("demo");
    let yes = std::sync::Arc::new(Yes::default());
    d.backend.set_approver(yes.clone());
    let mut vm = ViewModel::new(d.backend.clone(), rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until(WAIT, |v| v.connection == Connection::Open));
    vm.start_analysis();
    assert!(
        vm.block_until(WAIT, |v| v.analysis.phase == AnalysisPhase::Complete
            && !v.functions.items.is_empty()
            && !v.busy())
    );

    // Nothing selected: a hint, no dialog.
    vm.begin_patch_instruction();
    assert!(vm.tools.patch_dialog.is_none());

    let main = addr_of(&vm, "main");
    vm.goto(main);
    idle(&mut vm);
    vm.ensure_listing();
    assert!(vm.block_until(WAIT, |v| v.views.listing.loaded && !v.busy()));
    vm.select_listing_row(0);
    let row = vm.views.listing.selected_row().cloned().expect("a row");
    vm.begin_patch_instruction();
    idle(&mut vm);
    let dialog = vm.tools.patch_dialog.clone().expect("dialog");
    assert_eq!(dialog.address, row.address);
    assert_eq!(dialog.original.as_deref(), Some(row.bytes.as_slice()));
    assert_eq!(
        dialog.input,
        spaced_hex(&row.bytes),
        "starts from the bytes there"
    );
    assert!(matches!(dialog.origin, PatchOrigin::Instruction(_)));

    // Typing an instruction fills the hex with its shortest encoding; others can be picked.
    vm.set_patch_asm("xor eax, eax");
    vm.assemble_patch();
    idle(&mut vm);
    let d = vm.tools.patch_dialog.clone().expect("dialog");
    assert_eq!(d.input, "31 c0");
    assert!(
        matches!(&d.asm_state, AsmState::Done(e) if e.len() == 2),
        "{d:?}"
    );
    vm.pick_patch_encoding(1);
    assert_eq!(vm.tools.patch_dialog.as_ref().unwrap().input, "33 c0");
    vm.set_patch_asm("frobnicate");
    vm.assemble_patch();
    idle(&mut vm);
    let d = vm.tools.patch_dialog.clone().expect("dialog");
    assert!(
        matches!(&d.asm_state, AsmState::Failed(m) if m.contains("frobnicate")),
        "{d:?}"
    );
    assert_eq!(d.input, "33 c0", "a failed line leaves the hex alone");

    vm.set_patch_input("zz");
    vm.submit_patch();
    assert!(vm.tools.patch_dialog.as_ref().unwrap().error.is_some());
    let new = vec![0x90; row.bytes.len()];
    vm.set_patch_input(spaced_hex(&new));
    vm.set_patch_note("skip it");
    vm.submit_patch();
    idle(&mut vm);
    assert!(vm.tools.patch_dialog.is_none(), "staged and closed");
    assert!(vm.block_until(WAIT, |v| v.tools.patches.loaded && !v.busy()));
    let p = vm.tools.patches.items.first().cloned().expect("listed");
    assert_eq!(
        (p.address, &p.original, &p.replacement),
        (row.address, &row.bytes, &new)
    );
    assert_eq!((p.note.as_str(), p.who.as_str()), ("skip it", "you"));
    assert!(vm.tools.patches.covering(row.address).is_some());
    assert!(yes.0.lock().unwrap().is_empty(), "staging asks nothing");

    // Opening the dialog again at the address edits that patch.
    vm.begin_patch_instruction();
    let again = vm.tools.patch_dialog.clone().expect("dialog");
    assert!(again.existing);
    assert_eq!(again.input, spaced_hex(&new));
    vm.cancel_patch();

    // Export is the dangerous step: it asks, then really tries (the demo binary is no ELF).
    vm.begin_patch_export();
    let e = vm.tools.export_dialog.clone().expect("export dialog");
    assert!(e.output_path.ends_with(".patched"), "{e:?}");
    vm.submit_patch_export();
    idle(&mut vm);
    assert_eq!(yes.0.lock().unwrap().as_slice(), ["patch_export"]);
    let err = vm
        .tools
        .export_dialog
        .as_ref()
        .and_then(|d| d.error.clone())
        .expect("the placeholder binary cannot be patched");
    assert!(!err.contains("approval"), "{err}");

    vm.remove_patch(row.address);
    idle(&mut vm);
    assert!(vm.block_until(WAIT, |v| !v.tools.patches.loading && !v.busy()));
    assert!(vm.tools.patches.items.is_empty());
}

// ---------------------------------------------------------------- edit tab

#[test]
fn an_edit_of_the_decompile_is_planned_staged_and_listed() {
    let mut r = rig();
    // Nothing open: a hint, no edit.
    r.vm.begin_source_edit();
    assert!(r.vm.tools.source_edit.is_none());

    let main = addr_of(&r.vm, "main");
    r.vm.select_function(main);
    assert!(r.vm.block_until(WAIT, |v| {
        v.current
            .as_ref()
            .is_some_and(|c| matches!(c.decompiled, crate::Load::Ready(_)))
    }));
    r.vm.begin_source_edit();
    assert_eq!(r.vm.tools.take_tab(), Some(NavTab::Edit));
    let e = r.vm.tools.source_edit.clone().expect("edit");
    assert_eq!((e.address, e.name.as_str()), (main, "main"));
    assert!(!e.changed());

    // Unchanged code is not sent.
    r.vm.plan_source_edit();
    assert_eq!(
        r.vm.tools.source_edit.as_ref().unwrap().phase,
        SourceEditPhase::Editing
    );

    let edited = e.text.replacen("return", "return 7; //", 1);
    r.vm.set_source_edit_text(edited.clone());
    let e = r.vm.tools.source_edit.clone().unwrap();
    assert!(e.changed());
    assert!(!e.changed_lines().is_empty());
    r.vm.ai.bypass = true;
    r.vm.plan_source_edit();
    assert!(r.vm.tools.source_edit.as_ref().unwrap().busy());
    assert!(r.vm.block_until(WAIT, |v| {
        matches!(
            v.tools.source_edit.as_ref().map(|e| &e.phase),
            Some(SourceEditPhase::Planned(_) | SourceEditPhase::Failed(_))
        )
    }));
    let plan =
        r.vm.tools
            .source_edit
            .as_ref()
            .and_then(|e| e.plan().cloned())
            .unwrap_or_else(|| panic!("{:?}", r.vm.tools.source_edit));
    assert_eq!(plan.patches.len(), 1);
    assert!(
        verdict_text(plan.check.verdict).1,
        "the demo planner says it matches"
    );

    r.vm.stage_source_edit();
    assert!(r.vm.block_until(WAIT, |v| {
        matches!(
            v.tools.source_edit.as_ref().map(|e| &e.phase),
            Some(SourceEditPhase::Staged(_))
        ) && v.tools.patches.loaded
            && !v.tools.patches.loading
            && !v.busy()
    }));
    let staged = &r.vm.tools.patches.items;
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].address, plan.patches[0].address.0);
    assert!(
        staged[0].note.starts_with("From an edit of main"),
        "{:?}",
        staged[0]
    );

    // Editing again goes back to editing; discarding closes it.
    r.vm.set_source_edit_text(edited + "\n");
    assert_eq!(
        r.vm.tools.source_edit.as_ref().unwrap().phase,
        SourceEditPhase::Editing
    );
    r.vm.discard_source_edit();
    assert!(r.vm.tools.source_edit.is_none());
}

#[test]
fn import_symbols_previews_then_applies_as_one_run() {
    let mut r = rig();
    let main = addr_of(&r.vm, "main");
    let dir = std::env::temp_dir().join(format!("kraken-sym-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("names.csv");
    std::fs::write(&file, format!("address,name\n{main:#x},imported_entry\n")).expect("write");
    r.vm.begin_import_symbols();
    r.vm.edit_symbols_dialog(|d| d.path = file.to_string_lossy().into_owned());
    r.vm.preview_import_symbols();
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .symbols_dialog
            .as_ref()
            .is_some_and(|d| d.preview.is_some() && !d.busy)
    }));
    let pv =
        r.vm.tools
            .symbols_dialog
            .as_ref()
            .and_then(|d| d.preview.clone())
            .expect("preview");
    assert_eq!(pv.conflicts, 1, "main already has a name: {pv:?}");
    r.vm.edit_symbols_dialog(|d| d.conflicts = 1);
    r.vm.submit_import_symbols();
    assert!(r.vm.block_until(WAIT, |v| v.tools.symbols_dialog.is_none() && !v.busy()));
    assert!(r.vm.block_until(WAIT, |v| {
        v.functions.items.iter().any(|f| f.name == "imported_entry")
    }));
    std::fs::remove_dir_all(&dir).ok();
}

/// The demo with `main` holding x86 code that has a conditional branch.
fn x86_main_rig() -> (Rig, u64) {
    use kraken_proto::{DisasmRow, FlowKind, Hex64, Locator};
    let mut fx = demo_fixture();
    fx.program.arch = "x86:LE:64:default".into();
    let f = fx
        .functions
        .iter_mut()
        .find(|f| f.summary.name == "main")
        .expect("main");
    let Locator::Native { offset, .. } = f.summary.locator.clone() else {
        panic!("native main");
    };
    let row = |at: u64, bytes: &str, m: &str, flow| DisasmRow {
        address: Hex64(at),
        bytes: bytes.into(),
        mnemonic: m.into(),
        operands: Vec::new(),
        comment: None,
        labels: Vec::new(),
        flow,
    };
    let a = offset.0;
    f.disassembly = Some(vec![
        row(a, "83f805", "cmp", FlowKind::Fallthrough),
        row(a + 3, "7510", "jne", FlowKind::ConditionalJump),
        row(a + 5, "b801000000", "mov", FlowKind::Fallthrough),
        row(a + 10, "c3", "ret", FlowKind::Return),
    ]);
    (rig_with(fx), a + 3)
}

fn wizard(vm: &ViewModel) -> &PatchWizard {
    vm.tools.patch_wizard.as_ref().expect("the wizard is open")
}

#[test]
fn the_patch_wizard_walks_a_branch_change_to_a_saved_set() {
    use crate::wizard::{WizardFlow, WizardNav};
    let (mut r, jne) = x86_main_rig();
    r.vm.begin_patch_wizard(Some(jne));
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| w.pick.is_some())
    }));
    assert_eq!(wizard(&r.vm).current(), PatchStep::Pick);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);

    // No choice, no way on; and nothing has been written.
    assert!(matches!(r.vm.patch_wizard_next(), WizardNav::Blocked(_)));
    assert!(r.vm.tools.patches.items.is_empty());
    r.vm.tools.patch_wizard.as_mut().expect("wizard").intent = Some(WizardIntent::AlwaysTake);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert_eq!(wizard(&r.vm).current(), PatchStep::Preview);

    // The preview: the branch becomes a jump, the C is asked for before and after, the checks run.
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools.patch_wizard.as_ref().is_some_and(|w| {
            matches!(w.draft, Draft::Staged(_))
                && matches!(w.c_before, CText::Ready(_))
                && matches!(w.c_after, CText::Ready(_) | CText::Failed(_))
                && w.lint.is_some()
        })
    }));
    let w = wizard(&r.vm);
    let pv = w.preview.as_ref().expect("preview");
    assert!(pv.old_disassembly[0].contains("jne"), "{pv:?}");
    assert_eq!(pv.replacement, "eb10", "{pv:?}");
    assert!(
        pv.new_disassembly
            .iter()
            .any(|l| l.to_lowercase().contains("jmp")),
        "{pv:?}"
    );
    assert!(r.vm.block_until(WAIT, |v| v.tools.patches.items.len() == 1));

    // Back before the preview takes the draft out again.
    r.vm.patch_wizard_back();
    assert!(r.vm.block_until(WAIT, |v| v.tools.patches.items.is_empty() && !v.busy()));
    assert!(wizard(&r.vm).preview.is_none());

    // Forward again, through the test step, to Save.
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| matches!(w.draft, Draft::Staged(_)))
    }));
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert_eq!(wizard(&r.vm).current(), PatchStep::Save);
    assert!(wizard(&r.vm).set_name.contains("Always take this branch"));
    r.vm.tools.patch_wizard.as_mut().expect("wizard").set_name = "skip the check".into();
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Finish);
    assert!(r.vm.block_until(WAIT, |v| v.tools.patch_wizard.is_none() && !v.busy()));
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools.patches.items.len() == 1 && v.tools.patches.items[0].group == "skip the check"
    }));
    assert_eq!(r.vm.tools.patches.items[0].address, jne);
}

#[test]
fn cancelling_the_patch_wizard_leaves_no_patch_behind() {
    use crate::wizard::WizardNav;
    let (mut r, jne) = x86_main_rig();
    r.vm.begin_patch_wizard(Some(jne));
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| w.pick.is_some())
    }));
    r.vm.tools.patch_wizard.as_mut().expect("wizard").intent = Some(WizardIntent::NeverTake);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert!(r.vm.block_until(WAIT, |v| v.tools.patches.items.len() == 1));
    r.vm.cancel_patch_wizard();
    assert!(r.vm.tools.patch_wizard.is_none());
    assert!(r.vm.block_until(WAIT, |v| v.tools.patches.items.is_empty() && !v.busy()));
}

/// Walks a fresh wizard on `jne` to the preview with Never take this branch staged.
fn stage_never_take(r: &mut Rig, jne: u64) {
    use crate::wizard::WizardNav;
    r.vm.begin_patch_wizard(Some(jne));
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| w.pick.is_some())
    }));
    r.vm.tools.patch_wizard.as_mut().expect("wizard").intent = Some(WizardIntent::NeverTake);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| matches!(w.draft, Draft::Staged(_)))
            && !v.busy()
    }));
}

#[test]
fn opening_the_patch_wizard_again_takes_the_old_draft_out() {
    use crate::wizard::WizardFlow;
    let (mut r, jne) = x86_main_rig();
    stage_never_take(&mut r, jne);
    r.vm.begin_patch_wizard(Some(jne));
    assert_eq!(wizard(&r.vm).draft, Draft::None);
    assert_eq!(wizard(&r.vm).current(), PatchStep::Pick);
    r.vm.refresh_patches();
    assert!(r.vm.block_until(WAIT, |v| !v.busy() && v.tools.patches.items.is_empty()));
    // the new wizard stages and cancels on its own, unaffected by the old one's replies
    r.vm.cancel_patch_wizard();
    stage_never_take(&mut r, jne);
    r.vm.cancel_patch_wizard();
    r.vm.refresh_patches();
    assert!(r.vm.block_until(WAIT, |v| !v.busy() && v.tools.patches.items.is_empty()));
}

#[test]
fn a_draft_over_a_patch_the_wizard_did_not_know_of_puts_it_back_on_cancel() {
    use crate::wizard::WizardNav;
    let (mut r, jne) = x86_main_rig();
    r.vm.begin_patch_wizard(Some(jne));
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| w.pick.is_some())
            && !v.busy()
    }));
    r.vm.tools.patch_wizard.as_mut().expect("wizard").intent = Some(WizardIntent::NeverTake);
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    // a patch the wizard's list has not seen yet (set elsewhere, or past the first page)
    r.vm.call(
        "patch_set",
        serde_json::json!({"address": format!("{jne:#x}"), "bytes": "7511", "note": "mine"}),
        |_, res| {
            res.expect("patch_set");
        },
    );
    assert!(r.vm.block_until(WAIT, |v| !v.busy()));
    assert_eq!(r.vm.patch_wizard_next(), WizardNav::Moved);
    assert!(r.vm.block_until(WAIT, |v| {
        v.tools
            .patch_wizard
            .as_ref()
            .is_some_and(|w| matches!(w.draft, Draft::Staged(_)))
            && !v.busy()
    }));
    r.vm.cancel_patch_wizard();
    r.vm.refresh_patches();
    assert!(r.vm.block_until(WAIT, |v| !v.busy() && v.tools.patches.loaded));
    let items = &r.vm.tools.patches.items;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].address, jne);
    assert_eq!(items[0].replacement, vec![0x75, 0x11]);
}

#[test]
fn a_patch_by_file_offset_is_staged_listed_apart_from_addresses_and_removed() {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::ZERO).expect("demo");
    let mut vm = ViewModel::new(d.backend.clone(), rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until(WAIT, |v| v.connection == Connection::Open));
    let size = std::fs::metadata(&d.binary).expect("binary").len();
    assert!(size > 8, "the demo binary has bytes to patch");

    vm.begin_patch_file_offset();
    let dlg = vm.tools.patch_dialog.clone().expect("dialog");
    assert!(dlg.by_offset && !dlg.existing);
    assert!(dlg.check().is_err(), "no offset typed yet");
    vm.set_patch_offset_text("not a number");
    vm.set_patch_input("aa bb");
    vm.submit_patch();
    assert!(vm.tools.patch_dialog.as_ref().unwrap().error.is_some());

    vm.set_patch_offset_text("0x2");
    vm.set_patch_input("aa bb");
    vm.set_patch_note("header byte");
    vm.submit_patch();
    idle(&mut vm);
    assert!(vm.tools.patch_dialog.is_none(), "staged and closed");
    assert!(vm.block_until(WAIT, |v| v.tools.patches.loaded && !v.busy()));
    let p = vm.tools.patches.items.first().cloned().expect("listed");
    assert!(p.by_offset);
    assert_eq!((p.address, p.replacement.clone()), (2, vec![0xaa, 0xbb]));
    assert_eq!(p.original.len(), 2, "read from the file");
    assert!(
        vm.tools.patches.covering(2).is_none(),
        "an offset is not an address"
    );

    vm.remove_patch_at(2, true);
    idle(&mut vm);
    assert!(vm.block_until(WAIT, |v| !v.tools.patches.loading && !v.busy()));
    assert!(vm.tools.patches.items.is_empty());
}
