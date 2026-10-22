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
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::ZERO).expect("demo");
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
        original: Some(vec![0xb8, 3, 0, 0, 0]),
        origin: PatchOrigin::Instruction("mov eax, 0x3".into()),
        input: "31 c0".into(),
        note: String::new(),
        existing: false,
        error: None,
        submitting: false,
        x86: true,
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
