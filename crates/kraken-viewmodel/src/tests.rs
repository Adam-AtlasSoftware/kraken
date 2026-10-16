//! View-model tests: a scripted backend for exact flows, the in-process backend over the tiny
//! fixture for end-to-end behaviour.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kraken_proto::{CommentKind, ErrorCode, ProtoError, TokenKind};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use crate::testing::FakeBackend;
use crate::*;

const WAIT: Duration = Duration::from_secs(10);

fn rt() -> Runtime {
    Runtime::new().expect("runtime")
}

fn u(s: &str) -> Value {
    json!({"untrusted": true, "value": s})
}

fn fn_view(addr: u64, name: &str) -> Value {
    json!({
        "address": format!("{addr:#x}"),
        "name": u(name),
        "size": 32,
        "signature": u(&format!("void {name}(void)")),
        "completeness": {"kind": "complete"},
    })
}

fn page(items: Vec<Value>, next: Option<&str>) -> Value {
    let mut p = json!({ "items": items });
    if let Some(n) = next {
        p["next_cursor"] = json!(n);
    }
    p
}

fn project_json(phase: &str) -> Value {
    json!({
        "project_dir": "/tmp/p",
        "binary_path": "/bin/demo-server",
        "binary_sha256": "00",
        "program": {"arch": "x86:LE:64", "format": "elf", "base": "0x400000", "sha256": "00", "size": 4096},
        "engine_build": "fake",
        "capabilities": [],
        "epoch": {},
        "epoch_stale": false,
        "stale_fields": [],
        "analysis": {"phase": phase, "function_count": 2},
        "pending_entries": 0,
        "log_entries": 1,
        "open_proposals": 0,
    })
}

fn detail_json(addr: u64, name: &str, version: u64) -> Value {
    let mut v = fn_view(addr, name);
    v["comments"] = json!([]);
    v["versions"] = json!({ format!("native:ram:{addr:#x}:name"): version });
    v
}

fn decompile_json(addr: u64, text: &str, refs: &[(&str, u64)]) -> Value {
    json!({
        "address": format!("{addr:#x}"),
        "language": "c",
        "text": u(text),
        "truncated": false,
        "references": refs.iter().map(|(n, a)| json!({"name": u(n), "address": format!("{a:#x}")})).collect::<Vec<_>>(),
        "warnings": [],
        "completeness": {"kind": "complete"},
    })
}

fn applied() -> Value {
    json!({"status": "applied", "entry_id": 1, "key": "k", "versions": {}})
}

/// Backend with the replies every flow needs.
fn base_backend() -> FakeBackend {
    FakeBackend::new()
        .reply("project_open", project_json("complete"))
        .reply("project_create", project_json("not_started"))
        .reply("project_info", project_json("complete"))
        .reply(
            "list_functions",
            page(
                vec![fn_view(0x401000, "main"), fn_view(0x401040, "helper")],
                None,
            ),
        )
        .reply("history", page(vec![], None))
        .reply("proposals_list", page(vec![], None))
        .on("get_function", |a| {
            let addr = a["address"].as_str().unwrap_or("0x0");
            let n = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0);
            let name = if n == 0x401000 { "main" } else { "helper" };
            Ok(detail_json(n, name, 3))
        })
        .on("decompile", |a| {
            let addr = a["address"].as_str().unwrap_or("0x0");
            let n = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0);
            if n == 0x401000 {
                Ok(decompile_json(
                    n,
                    "int main(void)\n{\n  helper();\n  return 0;\n}\n",
                    &[("main", 0x401000), ("helper", 0x401040)],
                ))
            } else {
                Ok(decompile_json(n, "void helper(void)\n{\n}\n", &[]))
            }
        })
}

struct Rig {
    _rt: Runtime,
    vm: ViewModel,
    backend: Arc<FakeBackend>,
}

fn rig(backend: FakeBackend) -> Rig {
    let rt = rt();
    let backend = Arc::new(backend);
    let vm = ViewModel::new(backend.clone(), rt.handle().clone());
    Rig {
        _rt: rt,
        vm,
        backend,
    }
}

fn opened(backend: FakeBackend) -> Rig {
    let mut r = rig(backend);
    r.vm.open_project("/tmp/p");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.connection, Connection::Open);
    r
}

fn last_toast(vm: &ViewModel) -> (ToastLevel, String) {
    let t = vm.toasts.last().expect("a toast");
    (t.level, t.text.clone())
}

// ------------------------------------------------------------------ project

#[test]
fn opening_a_project_loads_every_panel() {
    let r = opened(base_backend());
    let p = r.vm.project.as_ref().expect("project");
    assert_eq!(p.name, "demo-server");
    assert_eq!(p.arch, "x86:LE:64");
    assert_eq!(r.vm.functions.items.len(), 2);
    assert_eq!(r.vm.functions.items[0].name, "main");
    assert_eq!(r.vm.analysis.phase, AnalysisPhase::Complete);
    assert_eq!(r.vm.status_text(), "Ready: 2 functions");
    for c in ["history", "proposals_list", "list_functions"] {
        assert_eq!(r.backend.calls_to(c).len(), 1, "{c}");
    }
    assert_eq!(
        r.backend.calls_to("project_open")[0],
        json!({"project_dir": "/tmp/p"})
    );
}

#[test]
fn create_project_sends_binary_and_dir() {
    let mut r = rig(base_backend());
    r.vm.create_project("/bin/ls", "/tmp/newproj");
    assert!(matches!(r.vm.connection, Connection::Opening(_)));
    assert_eq!(r.vm.status_text(), "Loading ls...");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.connection, Connection::Open);
    assert_eq!(
        r.backend.calls_to("project_create")[0],
        json!({"binary": "/bin/ls", "project_dir": "/tmp/newproj"})
    );
    assert_eq!(
        r.vm.status_text(),
        "Not analyzed yet. Run Analyze to find functions"
    );
}

#[test]
fn open_failure_is_shown_plainly() {
    let mut r = rig(base_backend().fail("project_open", ErrorCode::NotFound, "no project at /x"));
    r.vm.open_project("/x");
    assert!(r.vm.block_until_idle(WAIT));
    match &r.vm.connection {
        Connection::Failed(m) => assert!(m.contains("no project at /x"), "{m}"),
        other => panic!("{other:?}"),
    }
    let (level, text) = last_toast(&r.vm);
    assert_eq!(level, ToastLevel::Error);
    assert!(text.contains("no project at /x"));
    assert!(r.vm.status_text().starts_with("Could not open the project"));
}

#[test]
fn poll_without_work_reports_no_change() {
    let mut r = rig(base_backend());
    assert!(!r.vm.poll());
    assert_eq!(r.vm.pending_calls(), 0);
    assert!(!r.vm.busy());
}

// ------------------------------------------------------------------ function list

fn paged_backend(total: usize, page_size: usize, calls: Arc<Mutex<Vec<Value>>>) -> FakeBackend {
    base_backend().on("list_functions", move |a| {
        calls.lock().unwrap().push(a.clone());
        let start: usize = a
            .get("cursor")
            .and_then(Value::as_str)
            .map_or(0, |c| c.parse().unwrap());
        let filter = a.get("name_filter").and_then(Value::as_str);
        let end = (start + page_size).min(total);
        let items: Vec<Value> = (start..end)
            .map(|i| fn_view(0x400000 + i as u64 * 0x10, &format!("fn_{i}")))
            .filter(|v| {
                filter.is_none_or(|f| v["name"]["value"].as_str().unwrap_or("").contains(f))
            })
            .collect();
        Ok(page(
            items,
            (end < total).then(|| end.to_string()).as_deref(),
        ))
    })
}

#[test]
fn function_list_pages_in_as_the_user_scrolls() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut r = opened(paged_backend(450, 200, calls.clone()));
    assert_eq!(r.vm.functions.items.len(), 200);
    assert!(r.vm.functions.has_more());

    r.vm.ensure_loaded(50);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        r.vm.functions.items.len(),
        200,
        "far from the end: no fetch"
    );

    r.vm.ensure_loaded(190);
    r.vm.ensure_loaded(190);
    assert!(r.vm.functions.loading);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.functions.items.len(), 400);

    r.vm.ensure_loaded(399);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.functions.items.len(), 450);
    assert!(!r.vm.functions.has_more());
    r.vm.ensure_loaded(449);
    assert_eq!(r.vm.pending_calls(), 0, "nothing left to load");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3, "double ensure_loaded sends one request");
    assert_eq!(calls[1]["cursor"], json!("200"));
    assert_eq!(calls[0]["limit"], json!(FUNCTION_PAGE));
}

#[test]
fn filter_resets_the_list_and_skips_empty_pages() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut r = opened(paged_backend(450, 200, calls.clone()));
    // Only fn_300..fn_309 and fn_30 contain "fn_30"; the first page has just fn_30 and
    // fn_300..: pages 0..200 contain fn_30 only, 200..400 contain fn_300-309.
    r.vm.set_filter("fn_44");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.functions.items.len(), 1, "page one only has fn_44");
    // The window asks for more every frame while the list is shorter than the screen.
    while r.vm.functions.has_more() {
        r.vm.ensure_loaded(r.vm.functions.items.len());
        assert!(r.vm.block_until_idle(WAIT));
    }
    let names: Vec<_> =
        r.vm.functions
            .items
            .iter()
            .map(|f| f.name.clone())
            .collect();
    assert!(names.contains(&"fn_44".to_string()));
    assert!(names.contains(&"fn_449".to_string()), "{names:?}");
    assert!(!r.vm.functions.has_more());
    let last = calls.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last["name_filter"], json!("fn_44"));

    // Same filter again is a no-op; clearing reloads everything.
    let n = calls.lock().unwrap().len();
    r.vm.set_filter("fn_44");
    assert_eq!(calls.lock().unwrap().len(), n);
    r.vm.set_filter("");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.functions.items.len(), 200);
}

#[test]
fn a_filtered_page_that_comes_back_empty_keeps_paging() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut r = opened(paged_backend(450, 200, calls.clone()));
    r.vm.set_filter("fn_449");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.functions.items.len(), 1);
    assert_eq!(r.vm.functions.items[0].name, "fn_449");
    assert_eq!(
        calls.lock().unwrap().len(),
        4,
        "initial + three filtered pages"
    );
}

#[test]
fn list_failure_is_kept_on_the_panel() {
    let backend = base_backend().fail("list_functions", ErrorCode::Internal, "boom");
    let r = opened(backend);
    let e = r.vm.functions.error.clone().expect("error");
    assert!(e.contains("boom"), "{e}");
    assert!(r.vm.functions.items.is_empty());
    assert!(!r.vm.functions.loading);
}

// ------------------------------------------------------------------ navigation + decompile

#[test]
fn selecting_a_function_decompiles_it_with_clickable_calls() {
    let mut r = opened(base_backend());
    r.vm.select_function(0x401000);
    assert_eq!(r.vm.selected, Some(0x401000));
    let cur = r.vm.current.as_ref().unwrap();
    assert_eq!(cur.name, "main");
    assert_eq!(cur.decompiled, Load::Loading);
    assert!(r.vm.block_until_idle(WAIT));

    let cur = r.vm.current.as_ref().unwrap();
    let d = cur.decompiled.ready().expect("decompiled");
    assert!(d.result.text.contains("helper();"));
    assert!(d.partial_reason.is_none());
    let helper = d
        .result
        .tokens
        .iter()
        .find(|t| t.symbol.as_deref() == Some("helper"))
        .expect("helper token");
    assert_eq!(helper.kind, TokenKind::Function);
    assert_eq!(helper.target, Some(kraken_proto::Locator::ram(0x401040)));
    assert_eq!(
        cur.detail.as_ref().unwrap().versions["native:ram:0x401000:name"],
        3
    );
    d.result.validate_tokens().expect("valid");
}

#[test]
fn back_and_forward_walk_the_history() {
    let mut r = opened(base_backend());
    r.vm.select_function(0x401000);
    r.vm.navigate_to(0x401040);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401040);
    assert!(r.vm.nav.can_back() && !r.vm.nav.can_forward());

    r.vm.go_back();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401000);
    assert_eq!(r.vm.selected, Some(0x401000));
    assert!(r.vm.nav.can_forward());
    r.vm.go_forward();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401040);
    r.vm.go_forward();
    assert_eq!(r.vm.current.as_ref().unwrap().address, 0x401040);
    assert!(r.vm.block_until_idle(WAIT));
}

#[test]
fn a_slow_earlier_decompile_cannot_overwrite_a_newer_one() {
    let gate = Arc::new(AtomicUsize::new(0));
    let g = gate.clone();
    let backend = base_backend().on("decompile", move |a| {
        let addr = a["address"].as_str().unwrap().to_string();
        if addr == "0x401000" {
            g.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            Ok(decompile_json(0x401000, "int main(void)\n{\n}\n", &[]))
        } else {
            Ok(decompile_json(0x401040, "void helper(void)\n{\n}\n", &[]))
        }
    });
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    std::thread::sleep(Duration::from_millis(20));
    r.vm.select_function(0x401040);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(gate.load(Ordering::SeqCst), 1);
    let cur = r.vm.current.as_ref().unwrap();
    assert_eq!(cur.address, 0x401040);
    assert!(
        cur.decompiled
            .ready()
            .unwrap()
            .result
            .text
            .starts_with("void helper")
    );
}

#[test]
fn decompile_failure_is_shown_in_the_panel() {
    let backend = base_backend().fail("decompile", ErrorCode::Unsupported, "no decompiler");
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    match &r.vm.current.as_ref().unwrap().decompiled {
        Load::Failed(m) => assert!(m.contains("no decompiler"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn partial_results_are_flagged() {
    let backend = base_backend().on("decompile", |_| {
        let mut v = decompile_json(0x401000, "int main(void)\n{\n}\n", &[]);
        v["completeness"] = json!({"kind": "partial", "reason": "analysis is still running"});
        Ok(v)
    });
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    let d =
        r.vm.current
            .as_ref()
            .unwrap()
            .decompiled
            .ready()
            .unwrap()
            .clone();
    assert_eq!(
        d.partial_reason.as_deref(),
        Some("analysis is still running")
    );
}

// ------------------------------------------------------------------ rename

#[test]
fn rename_validates_locally_without_calling_the_backend() {
    let mut r = opened(base_backend());
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_rename_current();
    {
        let d = r.vm.rename.as_ref().unwrap();
        assert_eq!(d.input, "main");
        assert_eq!(d.validate(), Err("That is already the name.".into()));
    }
    for (input, needle) in [
        ("", "Type a name"),
        ("two words", "spaces"),
        ("tab\tname", "spaces"),
        (&"x".repeat(201), "200"),
        ("main", "already"),
    ] {
        r.vm.set_rename_input(input);
        r.vm.submit_rename();
        let d = r.vm.rename.as_ref().unwrap();
        let e = d.error.as_deref().expect("validation error");
        assert!(e.contains(needle), "{input:?}: {e}");
        assert!(!d.submitting);
    }
    assert!(r.backend.calls_to("rename_symbol").is_empty());
    assert_eq!(validate_name("  entry  ", "main"), Ok("entry".into()));
}

#[test]
fn rename_sends_expected_versions_and_refreshes_everything() {
    let renamed = Arc::new(AtomicUsize::new(0));
    let flag = renamed.clone();
    let backend = base_backend().on("rename_symbol", move |_| {
        flag.store(1, Ordering::SeqCst);
        Ok(applied())
    });
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    let before = r.backend.calls_to("list_functions").len();
    let dec_before = r.backend.calls_to("decompile").len();

    r.vm.begin_rename_current();
    r.vm.set_rename_input("entry_point");
    r.vm.submit_rename();
    assert!(r.vm.rename.as_ref().unwrap().submitting);
    assert!(r.vm.block_until_idle(WAIT));

    assert_eq!(renamed.load(Ordering::SeqCst), 1);
    assert!(r.vm.rename.is_none(), "dialog closes on success");
    assert_eq!(
        r.backend.calls_to("rename_symbol")[0],
        json!({"address": "0x401000", "new_name": "entry_point", "expect_versions": {"native:ram:0x401000:name": 3}})
    );
    let (level, text) = last_toast_matching(&r.vm, "Renamed");
    assert_eq!(level, ToastLevel::Success);
    assert!(text.contains("entry_point"));
    assert_eq!(r.backend.calls_to("list_functions").len(), before + 1);
    assert_eq!(r.backend.calls_to("decompile").len(), dec_before + 1);
    assert_eq!(r.backend.calls_to("history").len(), 2);
}

fn last_toast_matching(vm: &ViewModel, needle: &str) -> (ToastLevel, String) {
    vm.toasts
        .iter()
        .rev()
        .find(|t| t.text.contains(needle))
        .map(|t| (t.level, t.text.clone()))
        .unwrap_or_else(|| panic!("no toast containing {needle:?}: {:?}", vm.toasts))
}

#[test]
fn rename_conflict_refreshes_and_explains() {
    let version = Arc::new(AtomicUsize::new(3));
    let v = version.clone();
    let backend = base_backend()
        .on("get_function", move |_| {
            Ok(detail_json(
                0x401000,
                "renamed_elsewhere",
                v.load(Ordering::SeqCst) as u64,
            ))
        })
        .on("rename_symbol", |_| {
            Err(ProtoError::new(
                ErrorCode::ConflictStaleRead,
                "sym:0x401000 changed",
            ))
        });
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_rename_current();
    r.vm.set_rename_input("mine");
    version.store(4, Ordering::SeqCst); // somebody else edited meanwhile
    r.vm.submit_rename();
    assert!(r.vm.block_until_idle(WAIT));

    let d = r.vm.rename.as_ref().expect("dialog stays open");
    assert!(!d.submitting);
    assert!(d.error.is_none());
    assert!(d.notice.as_deref().unwrap().contains("reloaded"));
    assert_eq!(
        d.old_name, "renamed_elsewhere",
        "dialog shows the fresh name"
    );
    assert_eq!(d.input, "mine", "typed text is kept");
    // A second try now carries the refreshed version.
    r.vm.submit_rename();
    assert!(r.vm.block_until_idle(WAIT));
    let calls = r.backend.calls_to("rename_symbol");
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0]["expect_versions"]["native:ram:0x401000:name"],
        json!(3)
    );
    assert_eq!(
        calls[1]["expect_versions"]["native:ram:0x401000:name"],
        json!(4)
    );
    let cur = r.vm.current.as_ref().unwrap();
    assert_eq!(cur.name, "renamed_elsewhere", "the view was refreshed too");
}

#[test]
fn rename_server_errors_appear_in_the_dialog() {
    let backend = base_backend().fail(
        "rename_symbol",
        ErrorCode::InvalidArgument,
        "name `x` is reserved",
    );
    let mut r = opened(backend);
    r.vm.begin_rename(0x401040, Some("helper"));
    r.vm.set_rename_input("x");
    r.vm.submit_rename();
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.rename.as_ref().unwrap();
    assert_eq!(d.error.as_deref(), Some("name `x` is reserved"));
    assert!(!d.submitting);
    r.vm.cancel_rename();
    assert!(r.vm.rename.is_none());
}

#[test]
fn rename_of_a_call_target_fetches_its_own_versions() {
    let backend = base_backend().reply("rename_symbol", applied());
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_rename(0x401040, Some("helper"));
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.set_rename_input("helper2");
    r.vm.submit_rename();
    assert!(r.vm.block_until_idle(WAIT));
    let args = &r.backend.calls_to("rename_symbol")[0];
    assert_eq!(args["address"], json!("0x401040"));
    assert!(
        args["expect_versions"]
            .get("native:ram:0x401040:name")
            .is_some()
    );
}

#[test]
fn queued_and_proposed_renames_say_so() {
    for (status, needle) in [("queued", "analysis finishes"), ("proposed", "proposal")] {
        let backend = base_backend().reply(
            "rename_symbol",
            json!({"status": status, "key": "k", "versions": {}, "reason": "needs review"}),
        );
        let mut r = opened(backend);
        r.vm.begin_rename(0x401040, Some("helper"));
        r.vm.set_rename_input("other");
        r.vm.submit_rename();
        assert!(r.vm.block_until_idle(WAIT));
        let (level, text) = last_toast(&r.vm);
        assert_eq!(level, ToastLevel::Info);
        assert!(text.contains(needle), "{text}");
    }
}

#[test]
fn rename_without_a_function_explains_what_to_do() {
    let mut r = opened(base_backend());
    r.vm.begin_rename_current();
    assert!(r.vm.rename.is_none());
    assert!(last_toast(&r.vm).1.contains("Pick a function"));
}

// ------------------------------------------------------------------ comments

#[test]
fn comments_prefill_save_and_clear() {
    let backend = base_backend()
        .on("get_function", |_| {
            let mut d = detail_json(0x401000, "main", 3);
            d["comments"] = json!([{"kind": "plate", "text": u("entry point")}]);
            Ok(d)
        })
        .reply("set_comment", applied());
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_comment_current();
    assert_eq!(r.vm.comment.as_ref().unwrap().input, "entry point");
    r.vm.set_comment_kind(CommentKind::Eol);
    assert_eq!(r.vm.comment.as_ref().unwrap().input, "");
    r.vm.set_comment_kind(CommentKind::Plate);
    r.vm.set_comment_input("the real entry");
    r.vm.submit_comment();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.comment.is_none());
    assert_eq!(
        r.backend.calls_to("set_comment")[0],
        json!({"address": "0x401000", "kind": "plate", "text": "the real entry",
               "expect_versions": {"native:ram:0x401000:comment:plate": 0}})
    );
    assert_eq!(last_toast_matching(&r.vm, "Comment").1, "Comment saved.");

    r.vm.begin_comment_current();
    r.vm.set_comment_input("");
    r.vm.submit_comment();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(last_toast_matching(&r.vm, "Comment").1, "Comment cleared.");
}

#[test]
fn comment_errors_stay_in_the_dialog() {
    let backend = base_backend().fail("set_comment", ErrorCode::ConflictStaleRead, "changed");
    let mut r = opened(backend);
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_comment_current();
    r.vm.set_comment_input("hi");
    r.vm.submit_comment();
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.comment.as_ref().unwrap();
    assert!(d.error.as_deref().unwrap().contains("refreshed"));
    assert!(!d.submitting);

    r.vm.set_comment_input("y".repeat(5000));
    r.vm.submit_comment();
    assert!(
        r.vm.comment
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("4096")
    );
    r.vm.cancel_comment();
    assert!(r.vm.comment.is_none());
}

// ------------------------------------------------------------------ history, undo, proposals

fn history_entry(id: u64, op: &str, author: (&str, &str), undone_by: Option<u64>) -> Value {
    let mut v = json!({
        "id": id, "op": op, "address": "0x401000",
        "description": u(&format!("{op} 0x401000 main -> entry")),
        "author": {"kind": author.0, "id": author.1},
        "provenance": "user",
        "status": {"kind": "applied"},
        "sync": {"kind": "pushed"},
        "ts_ms": 1_700_000_000_000i64,
    });
    if let Some(u) = undone_by {
        v["undone_by"] = json!(u);
    }
    v
}

#[test]
fn history_rows_are_mapped_for_display() {
    let backend = base_backend().reply(
        "history",
        page(
            vec![
                history_entry(3, "rename", ("agent", "scout"), None),
                history_entry(2, "set_comment", ("user", "gui-user"), Some(4)),
                {
                    let mut e = history_entry(4, "rename", ("user", "gui-user"), None);
                    e["undoes_entry_id"] = json!(2);
                    e["run_id"] = json!("run-7");
                    e
                },
            ],
            Some("older"),
        ),
    );
    let r = opened(backend);
    let h = &r.vm.history;
    assert_eq!(h.entries.len(), 3);
    assert!(h.entries[0].by_agent);
    assert_eq!(h.entries[0].who, "scout");
    assert_eq!(h.entries[1].who, "you");
    assert!(h.entries[1].undone);
    assert!(h.entries[2].is_undo);
    assert_eq!(h.entries[2].run_id.as_deref(), Some("run-7"));
    assert_eq!(h.entries[0].status, "applied");
    assert_eq!(h.entries[0].sync, "pushed");
    assert_eq!(h.entries[0].address, Some(0x401000));
    assert_eq!(h.next_cursor.as_deref(), Some("older"));
}

#[test]
fn history_loads_older_pages() {
    let backend = base_backend().on("history", |a| {
        if a.get("cursor").is_some() {
            Ok(page(
                vec![history_entry(1, "rename", ("user", "me"), None)],
                None,
            ))
        } else {
            Ok(page(
                vec![history_entry(2, "rename", ("user", "me"), None)],
                Some("c1"),
            ))
        }
    });
    let mut r = opened(backend);
    r.vm.load_more_history();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.history.entries.len(), 2);
    assert!(r.vm.history.next_cursor.is_none());
    r.vm.load_more_history();
    assert_eq!(r.vm.pending_calls(), 0);
}

#[test]
fn undo_last_reports_and_refreshes() {
    let backend = base_backend().reply(
        "undo",
        json!({"status": "applied", "entry_ids": [5], "undone_entry_ids": [4], "failed": []}),
    );
    let mut r = opened(backend);
    let before = r.backend.calls_to("history").len();
    r.vm.undo_last();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        last_toast_matching(&r.vm, "Undid").1,
        "Undid your last change."
    );
    assert_eq!(r.backend.calls_to("history").len(), before + 1);
    assert_eq!(r.backend.calls_to("undo")[0], json!({}));
}

#[test]
fn undo_with_nothing_to_undo_and_errors() {
    let backend = base_backend().reply(
        "undo",
        json!({"status": "applied", "entry_ids": [], "undone_entry_ids": [], "failed": []}),
    );
    let mut r = opened(backend);
    r.vm.undo_last();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(last_toast(&r.vm).1.contains("nothing to undo"));

    let backend = base_backend().fail("undo_run", ErrorCode::NotFound, "no such run");
    let mut r = opened(backend);
    r.vm.undo_run("run-9");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        r.backend.calls_to("undo_run")[0],
        json!({"run_id": "run-9"})
    );
    let (level, text) = last_toast(&r.vm);
    assert_eq!(level, ToastLevel::Error);
    assert!(text.contains("no such run"));
}

#[test]
fn undo_run_summarises_and_warns_about_engine_refusals() {
    let backend = base_backend().reply(
        "undo_run",
        json!({"status": "applied", "entry_ids": [7, 8], "undone_entry_ids": [3, 2],
               "failed": [{"entry_id": 8, "code": "engine_rejected", "message": "x"}]}),
    );
    let mut r = opened(backend);
    r.vm.undo_run("run-1");
    assert!(r.vm.block_until_idle(WAIT));
    assert!(
        last_toast_matching(&r.vm, "Undid 2")
            .1
            .contains("run run-1")
    );
    assert_eq!(last_toast(&r.vm).0, ToastLevel::Warning);
}

fn proposal(id: u64) -> Value {
    json!({
        "id": id, "run_id": "run-3", "author": {"kind": "agent", "id": "scout"},
        "op": "rename", "address": "0x401040",
        "description": u("rename 0x401040 helper -> parse_header"),
        "reason": "overwrites a name you set", "status": "open", "ts_ms": 1,
    })
}

#[test]
fn proposals_list_accept_and_reject() {
    let backend = base_backend()
        .reply("proposals_list", page(vec![proposal(1), proposal(2)], None))
        .reply("proposal_accept", json!({"id": 1, "status": "accepted"}))
        .reply("proposal_reject", json!({"id": 2, "status": "rejected"}));
    let mut r = opened(backend);
    assert_eq!(r.vm.proposals.items.len(), 2);
    let p = &r.vm.proposals.items[0];
    assert_eq!(p.who, "scout");
    assert_eq!(p.address, Some(0x401040));
    assert!(p.reason.contains("overwrites"));

    r.vm.accept_proposal(1);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.backend.calls_to("proposal_accept")[0], json!({"id": 1}));
    assert!(last_toast_matching(&r.vm, "accepted").0 == ToastLevel::Success);
    assert!(
        r.backend.calls_to("list_functions").len() >= 2,
        "accept refreshes names"
    );

    r.vm.reject_proposal(2);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.backend.calls_to("proposal_reject")[0], json!({"id": 2}));
    assert!(
        last_toast_matching(&r.vm, "rejected")
            .1
            .contains("Proposal")
    );
}

#[test]
fn proposal_failures_are_shown() {
    let backend = base_backend()
        .reply("proposals_list", page(vec![proposal(1)], None))
        .fail(
            "proposal_accept",
            ErrorCode::ConflictStaleRead,
            "name changed since",
        );
    let mut r = opened(backend);
    r.vm.accept_proposal(1);
    assert!(r.vm.block_until_idle(WAIT));
    let (level, text) = last_toast(&r.vm);
    assert_eq!(level, ToastLevel::Error);
    assert!(text.contains("name changed since"));
}

// ------------------------------------------------------------------ analysis

fn job(status: &str, done: u64, total: u64, phase: &str) -> JobInfo {
    serde_json::from_value(json!({
        "job_id": "job-1", "command": "analyze", "status": status,
        "progress": {"phase": phase, "done": done, "total": total, "message": ""},
        "result": if status == "succeeded" { json!({"function_count": 12}) } else { Value::Null },
    }))
    .unwrap()
}

fn analysis_backend() -> FakeBackend {
    base_backend()
        .on("project_info", |_| {
            let mut p = project_json("complete");
            p["analysis"]["function_count"] = json!(12);
            Ok(p)
        })
        .reply(
            "analyze",
            json!({"job_id": "job-1", "already_running": false}),
        )
        .on("job_status", |_| {
            Ok(serde_json::to_value(job("running", 1, 3, "load")).unwrap())
        })
}

#[test]
fn analysis_progress_flows_from_events_to_the_status_bar() {
    let mut r = opened(analysis_backend());
    r.vm.start_analysis();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.analysis.running());
    assert_eq!(r.vm.status_text(), "Analyzing: load (1 of 3)");

    r.backend
        .emit(BackendEvent::Job(job("running", 2, 3, "core")));
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.analysis
            .progress
            .as_ref()
            .is_some_and(|p| p.phase == "core")
    }));
    assert_eq!(r.vm.status_text(), "Analyzing: core (2 of 3)");
    assert!((r.vm.analysis.fraction().unwrap() - 2.0 / 3.0).abs() < 1e-6);

    let lists = r.backend.calls_to("list_functions").len();
    r.backend
        .emit(BackendEvent::Job(job("succeeded", 3, 3, "expensive")));
    assert!(r.vm.block_until(WAIT, |vm| vm.analysis.phase == AnalysisPhase::Complete));
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.analysis.function_count, Some(12));
    assert_eq!(r.vm.status_text(), "Ready: 12 functions");
    assert!(
        last_toast_matching(&r.vm, "Analysis finished")
            .1
            .contains("12")
    );
    assert!(
        r.backend.calls_to("list_functions").len() > lists,
        "list reloads"
    );

    // A repeated terminal event does not toast twice.
    let n = r.vm.toasts.len();
    r.backend
        .emit(BackendEvent::Job(job("succeeded", 3, 3, "expensive")));
    std::thread::sleep(Duration::from_millis(50));
    r.vm.poll();
    assert_eq!(r.vm.toasts.len(), n);
}

#[test]
fn analysis_failure_and_cancel_are_reported() {
    let backend = analysis_backend()
        .reply("project_info", project_json("cancelled"))
        .reply(
            "job_cancel",
            serde_json::to_value(job("cancelled", 1, 3, "load")).unwrap(),
        );
    let mut r = opened(backend);
    r.vm.start_analysis();
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.start_analysis();
    assert!(last_toast(&r.vm).1.contains("already running"));

    r.vm.cancel_analysis();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.vm.analysis.phase, AnalysisPhase::Cancelled);
    assert_eq!(
        r.backend.calls_to("job_cancel")[0],
        json!({"job_id": "job-1"})
    );
    assert!(last_toast_matching(&r.vm, "cancelled").0 == ToastLevel::Warning);
    assert!(r.vm.status_text().contains("cancelled"));

    let mut failed = job("failed", 1, 3, "core");
    failed.error = Some(ProtoError::new(ErrorCode::Internal, "engine crashed"));
    r.backend.emit(BackendEvent::Job(failed));
    assert!(r.vm.block_until(WAIT, |vm| vm.analysis.phase == AnalysisPhase::Failed));
    assert!(
        r.vm.analysis
            .error
            .as_deref()
            .unwrap()
            .contains("engine crashed")
    );
    assert_eq!(last_toast(&r.vm).0, ToastLevel::Error);
    assert_eq!(r.vm.status_text(), "Analysis failed");
}

#[test]
fn cancel_without_a_running_job_is_a_gentle_no_op() {
    let mut r = opened(base_backend());
    r.vm.cancel_analysis();
    assert!(last_toast(&r.vm).1.contains("No analysis is running"));
    assert!(r.backend.calls_to("job_cancel").is_empty());
}

#[test]
fn opening_a_project_that_is_mid_analysis_picks_up_its_job() {
    let backend = analysis_backend().reply("project_open", {
        let mut p = project_json("running");
        p["analysis"]["job_id"] = json!("job-1");
        p
    });
    let mut r = opened(backend);
    assert!(r.vm.block_until(WAIT, |vm| vm.analysis.progress.is_some()));
    assert!(r.vm.analysis.running());
    assert_eq!(
        r.backend.calls_to("job_status")[0],
        json!({"job_id": "job-1"})
    );
}

#[test]
fn start_analysis_failure_toasts() {
    let backend = base_backend().fail("analyze", ErrorCode::Unsupported, "engine cannot analyze");
    let mut r = opened(backend);
    r.vm.start_analysis();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(last_toast(&r.vm).0, ToastLevel::Error);
    assert!(!r.vm.analysis.running());
}

#[test]
fn backend_events_for_other_jobs_and_disconnects() {
    let mut r = opened(base_backend());
    let mut other = job("running", 1, 2, "x");
    other.command = "rebuild".into();
    r.backend.emit(BackendEvent::Job(other));
    r.backend
        .emit(BackendEvent::Disconnected("socket closed".into()));
    assert!(r.vm.block_until(WAIT, |vm| !vm.toasts.is_empty()));
    assert!(!r.vm.analysis.running());
    assert!(last_toast(&r.vm).1.contains("socket closed"));
    let n = r.backend.calls_to("project_info").len();
    r.backend.emit(BackendEvent::ProjectChanged);
    assert!(r.vm.block_until(WAIT, |_| r.backend.calls_to("project_info").len() > n));
    assert!(r.vm.block_until_idle(WAIT));
}

fn change(author: &str, by_agent: bool, ids: &[u64]) -> ChangeInfo {
    ChangeInfo {
        command: "rename_symbol".into(),
        by_agent,
        author: author.into(),
        run_id: Some("run-1".into()),
        entry_ids: ids.to_vec(),
        key: None,
    }
}

fn history_row(id: u64, op: &str, description: &str, run: Option<&str>) -> Value {
    json!({
        "id": id, "op": op, "address": "0x401000", "description": u(description),
        "author": {"kind": "agent", "id": "claude"}, "run_id": run,
        "status": "applied", "sync": "pushed", "ts_ms": 1,
    })
}

#[test]
fn an_agent_edit_refreshes_everything_and_toasts_with_an_undo() {
    let backend = base_backend()
        .reply(
            "history",
            page(
                vec![history_row(
                    4,
                    "rename",
                    "rename 0x401000 main -> entry",
                    Some("run-1"),
                )],
                None,
            ),
        )
        .reply(
            "undo_run",
            json!({"status": "applied", "undone_entry_ids": [4], "failed": []}),
        );
    let mut r = opened(backend);
    let before = r.backend.calls_to("list_functions").len();
    r.backend
        .emit(BackendEvent::EntryApplied(change("claude", true, &[4])));
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.toasts
            .iter()
            .any(|t| t.text.contains("Agent renamed main"))
    }));
    let backend = r.backend.clone();
    assert!(r.vm.block_until(WAIT, |_| backend.calls_to("list_functions").len() > before));
    let toast = r.vm.toasts.last().cloned().expect("toast");
    assert!(toast.text.contains("main \u{2192} entry"), "{}", toast.text);
    assert!(toast.text.contains("claude"));
    assert_eq!(
        toast.action,
        Some(ToastAction::UndoRun {
            run_id: "run-1".into()
        })
    );

    // The same entry is announced only once.
    r.backend
        .emit(BackendEvent::EntryApplied(change("claude", true, &[4])));
    assert!(r.vm.block_until_idle(WAIT));
    std::thread::sleep(Duration::from_millis(50));
    r.vm.poll();
    assert_eq!(r.vm.toasts.iter().filter(|t| t.action.is_some()).count(), 1);

    // The toast's button undoes the run.
    let backend = r.backend.clone();
    r.vm.run_toast_action(toast.id);
    assert!(r.vm.block_until(WAIT, |_| !backend.calls_to("undo_run").is_empty()));
    assert_eq!(
        r.backend.calls_to("undo_run")[0],
        json!({"run_id": "run-1"})
    );
    assert!(r.vm.toasts.iter().all(|t| t.id != toast.id));
}

#[test]
fn a_persons_edit_elsewhere_refreshes_quietly() {
    let mut r = opened(base_backend());
    let n = r.backend.calls_to("list_functions").len();
    r.backend
        .emit(BackendEvent::EntryApplied(change("adam", false, &[9])));
    let backend = r.backend.clone();
    assert!(r.vm.block_until(WAIT, |_| backend.calls_to("list_functions").len() > n));
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.toasts.is_empty());
    assert!(r.backend.calls_to("history").len() >= 2);
}

#[test]
fn a_new_proposal_reloads_the_tab_and_says_so() {
    let mut r = opened(base_backend());
    let n = r.backend.calls_to("proposals_list").len();
    r.backend
        .emit(BackendEvent::ProposalCreated(change("claude", true, &[])));
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.toasts
            .iter()
            .any(|t| t.text.contains("Agent claude proposed"))
    }));
    let backend = r.backend.clone();
    assert!(r.vm.block_until(WAIT, |_| backend.calls_to("proposals_list").len() > n));
}

#[test]
fn sidecar_and_connection_events_are_explained_and_refresh_on_return() {
    let mut r = opened(base_backend());
    r.backend.emit(BackendEvent::SidecarExited {
        restart_failed: false,
    });
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.toasts
            .iter()
            .any(|t| t.level == ToastLevel::Warning && t.text.contains("Restarting"))
    }));

    let backend = r.backend.clone();
    let n = backend.calls_to("list_functions").len();
    r.backend.emit(BackendEvent::SidecarRestarted {
        replayed: 2,
        rejected: 1,
    });
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.toasts
            .iter()
            .any(|t| t.text.contains("2 saved edit(s)") && t.text.contains("refused 1"))
    }));
    assert!(r.vm.block_until(WAIT, |_| backend.calls_to("list_functions").len() > n));

    r.backend.emit(BackendEvent::Disconnected("gone".into()));
    assert!(r.vm.block_until(WAIT, |vm| matches!(vm.link, LinkState::Disconnected(_))));
    // A second drop notice does not stack another error toast.
    let errors = |vm: &ViewModel| {
        vm.toasts
            .iter()
            .filter(|t| t.level == ToastLevel::Error)
            .count()
    };
    r.backend
        .emit(BackendEvent::Disconnected("still gone".into()));
    assert!(r.vm.block_until(WAIT, |vm| vm.link
        == LinkState::Disconnected("still gone".into())));
    assert_eq!(errors(&r.vm), 1);

    let n = backend.calls_to("list_functions").len();
    r.backend.emit(BackendEvent::Reconnected);
    assert!(r.vm.block_until(WAIT, |vm| vm.link == LinkState::Connected));
    assert!(r.vm.block_until(WAIT, |_| backend.calls_to("list_functions").len() > n));
    assert!(r.vm.block_until_idle(WAIT));
}

// ------------------------------------------------------------------ palette, actions, toasts

fn command_list() -> Vec<CommandInfo> {
    let c = |name: &str, perm| CommandInfo {
        name: name.into(),
        summary: format!("{name} summary"),
        kind: CommandKind::Query,
        permission: perm,
    };
    vec![
        c("analyze", Permission::Mutating),
        c("decompile", Permission::Safe),
        c("rename_symbol", Permission::Mutating),
    ]
}

#[test]
fn palette_filters_and_runs_actions_keyboard_first() {
    let mut r = opened(base_backend().with_commands(command_list()));
    r.vm.open_palette();
    assert!(r.vm.palette.open);
    r.vm.palette.set_query("theme");
    assert_eq!(
        r.vm.palette.selected_item().unwrap().target,
        PaletteTarget::Action(AppAction::ToggleTheme)
    );
    assert_eq!(r.vm.activate_palette(), Some(UiRequest::ToggleTheme));
    assert!(!r.vm.palette.open, "choosing closes the palette");

    r.vm.open_palette();
    r.vm.palette.set_query("back");
    assert_eq!(r.vm.activate_palette(), None);

    r.vm.open_palette();
    r.vm.palette.set_query("rename");
    let first = r.vm.palette.selected_item().unwrap();
    assert_eq!(
        first.target,
        PaletteTarget::Action(AppAction::RenameCurrent)
    );
    r.vm.palette.move_selection(1);
    assert_eq!(
        r.vm.palette.selected_item().unwrap().target,
        PaletteTarget::Command("rename_symbol".into())
    );
    assert_eq!(r.vm.activate_palette(), None);
    assert!(last_toast(&r.vm).1.contains("rename_symbol"));
}

#[test]
fn palette_with_no_match_does_nothing() {
    let mut r = opened(base_backend());
    r.vm.open_palette();
    r.vm.palette.set_query("qqqqzzzz");
    assert_eq!(r.vm.activate_palette(), None);
    assert!(
        r.vm.palette.open,
        "stays open so the person can keep typing"
    );
}

#[test]
fn actions_that_need_a_project_say_so() {
    let mut r = rig(base_backend());
    assert_eq!(r.vm.perform(AppAction::Analyze), None);
    assert!(last_toast(&r.vm).1.contains("Open a project first"));
    assert!(r.backend.calls().is_empty());
    assert_eq!(r.vm.perform(AppAction::OpenDemo), Some(UiRequest::OpenDemo));
    assert_eq!(
        r.vm.perform(AppAction::ToggleTheme),
        Some(UiRequest::ToggleTheme)
    );
    assert_eq!(
        r.vm.perform(AppAction::OpenProject),
        Some(UiRequest::OpenProject)
    );
    assert_eq!(
        r.vm.perform(AppAction::NewProject),
        Some(UiRequest::NewProject)
    );
    assert_eq!(r.vm.status_text(), "No project open");
}

#[test]
fn window_level_actions_come_back_as_requests() {
    let mut r = opened(base_backend());
    for (a, u) in [
        (
            AppAction::FocusFunctionFilter,
            UiRequest::FocusFunctionFilter,
        ),
        (AppAction::ShowHistory, UiRequest::ShowHistory),
        (AppAction::ShowProposals, UiRequest::ShowProposals),
    ] {
        assert_eq!(r.vm.perform(a), Some(u));
    }
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.perform(AppAction::RenameCurrent);
    assert!(r.vm.rename.is_some());
    r.vm.perform(AppAction::CommentCurrent);
    assert!(r.vm.comment.is_some());
    r.vm.perform(AppAction::RefreshAll);
    assert!(r.vm.block_until_idle(WAIT));
}

#[test]
fn toasts_expire_and_can_be_dismissed() {
    let mut r = rig(base_backend());
    r.vm.toast(ToastLevel::Info, "a");
    r.vm.toast(ToastLevel::Error, "b");
    let id = r.vm.toasts[0].id;
    let t0 = Instant::now();
    assert!(!r.vm.expire_toasts(t0));
    assert!(r.vm.expire_toasts(t0 + Duration::from_secs(5)));
    assert_eq!(r.vm.toasts.len(), 1, "errors live longer");
    assert_eq!(r.vm.toasts[0].text, "b");
    r.vm.dismiss_toast(id);
    assert_eq!(r.vm.toasts.len(), 1);
    let id = r.vm.toasts[0].id;
    r.vm.dismiss_toast(id);
    assert!(r.vm.toasts.is_empty());
    for i in 0..10 {
        r.vm.toast(ToastLevel::Info, format!("t{i}"));
    }
    assert_eq!(r.vm.toasts.len(), 6, "the stack is capped");
    assert_eq!(r.vm.toasts.last().unwrap().text, "t9");
}

#[test]
fn opening_another_project_clears_old_state() {
    let mut r = opened(base_backend());
    r.vm.select_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.begin_rename_current();
    r.vm.open_project("/tmp/other");
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.current.is_none());
    assert!(r.vm.rename.is_none());
    assert!(!r.vm.nav.can_back());
    assert_eq!(r.vm.selected, None);
}

#[test]
fn malformed_replies_become_errors_not_panics() {
    let backend = base_backend().reply("list_functions", json!({"items": "nope"}));
    let r = opened(backend);
    assert!(
        r.vm.functions
            .error
            .as_deref()
            .unwrap()
            .contains("unexpected reply")
    );
}

#[test]
fn commands_come_from_the_backend() {
    let r = rig(base_backend().with_commands(command_list()));
    assert_eq!(r.vm.commands().len(), 3);
}

// ------------------------------------------------------------------ in-process backend, tiny fixture

mod inprocess {
    use super::*;
    use crate::demo::{DemoProject, demo_project_with};
    use engine_fake::FixtureFile;

    const TINY: &str = include_str!("../../engine-fake/fixtures/tiny.json");

    struct Live {
        _rt: Runtime,
        vm: ViewModel,
        demo: Arc<crate::InProcessBackend>,
    }

    fn live(delay: Duration) -> Live {
        let rt = rt();
        let fixture = FixtureFile::from_json(TINY).unwrap();
        let DemoProject {
            backend,
            binary,
            project_dir,
        } = {
            let _g = rt.enter();
            demo_project_with(fixture, delay).unwrap()
        };
        let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
        vm.create_project(binary.to_string_lossy(), project_dir.to_string_lossy());
        assert!(vm.block_until_idle(WAIT));
        assert_eq!(vm.connection, Connection::Open, "{:?}", vm.toasts);
        Live {
            _rt: rt,
            vm,
            demo: backend,
        }
    }

    fn names(vm: &ViewModel) -> Vec<String> {
        vm.functions.items.iter().map(|f| f.name.clone()).collect()
    }

    #[test]
    fn registry_commands_are_listed_for_the_palette() {
        let l = live(Duration::ZERO);
        let cmds = l.vm.commands();
        assert!(cmds.len() >= 20);
        let rename = cmds.iter().find(|c| c.name == "rename_symbol").unwrap();
        assert_eq!(rename.kind, CommandKind::Mutation);
        assert_eq!(rename.permission, Permission::Mutating);
        let decompile = cmds.iter().find(|c| c.name == "decompile").unwrap();
        assert_eq!(decompile.permission, Permission::Safe);
    }

    #[test]
    fn opens_lists_and_decompiles_the_tiny_fixture() {
        let mut l = live(Duration::ZERO);
        assert_eq!(names(&l.vm), ["main", "helper", "cleanup"]);
        assert_eq!(l.vm.project.as_ref().unwrap().name, "demo-server");
        assert_eq!(l.vm.project.as_ref().unwrap().arch, "x86:LE:64:default");
        assert!(
            l.vm.functions.items[0]
                .signature
                .as_deref()
                .unwrap()
                .contains("main")
        );

        l.vm.select_function(0x401000);
        assert!(l.vm.block_until_idle(WAIT));
        let cur = l.vm.current.as_ref().unwrap();
        let d = cur.decompiled.ready().expect("decompiled");
        assert!(d.result.text.starts_with("int main(int argc"));
        let helper = d
            .result
            .tokens
            .iter()
            .find(|t| t.symbol.as_deref() == Some("helper"))
            .expect("helper token");
        let target = match &helper.target {
            Some(kraken_proto::Locator::Native { offset, .. }) => offset.0,
            other => panic!("{other:?}"),
        };
        // Following the call navigates to helper.
        l.vm.navigate_to(target);
        assert!(l.vm.block_until_idle(WAIT));
        let cur = l.vm.current.as_ref().unwrap();
        assert_eq!(cur.name, "helper");
        assert!(
            cur.decompiled
                .ready()
                .unwrap()
                .result
                .text
                .contains("cleanup")
        );
        l.vm.go_back();
        assert!(l.vm.block_until_idle(WAIT));
        assert_eq!(l.vm.current.as_ref().unwrap().name, "main");
    }

    #[test]
    fn rename_then_undo_round_trips_through_the_real_pipeline() {
        let mut l = live(Duration::ZERO);
        l.vm.select_function(0x401040);
        assert!(l.vm.block_until_idle(WAIT));

        l.vm.begin_rename_current();
        l.vm.set_rename_input("process_item");
        l.vm.submit_rename();
        assert!(l.vm.block_until_idle(WAIT));
        assert!(l.vm.rename.is_none(), "{:?}", l.vm.rename);
        assert_eq!(names(&l.vm), ["main", "process_item", "cleanup"]);
        let cur = l.vm.current.as_ref().unwrap();
        assert_eq!(cur.name, "process_item");
        assert!(
            cur.decompiled
                .ready()
                .unwrap()
                .result
                .text
                .contains("process_item")
        );
        assert_eq!(l.vm.project.as_ref().unwrap().log_entries, 1);

        let h = &l.vm.history.entries;
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].op, "rename");
        assert_eq!(h[0].who, "you");
        assert!(!h[0].by_agent && !h[0].undone);
        assert!(h[0].description.contains("process_item"));

        l.vm.undo_last();
        assert!(l.vm.block_until_idle(WAIT));
        assert_eq!(names(&l.vm), ["main", "helper", "cleanup"]);
        assert!(l.vm.history.entries.iter().any(|e| e.undone));
        assert!(l.vm.history.entries.iter().any(|e| e.is_undo));
        assert_eq!(last_toast_matching(&l.vm, "Undid").0, ToastLevel::Success);
    }

    #[test]
    fn a_real_stale_read_conflict_is_explained_and_recoverable() {
        let mut l = live(Duration::ZERO);
        l.vm.select_function(0x401040);
        assert!(l.vm.block_until_idle(WAIT));
        l.vm.begin_rename_current();
        l.vm.set_rename_input("mine");

        // Someone else renames the same function after the dialog captured its versions.
        let backend = l.demo.clone();
        l._rt
            .block_on(async move {
                use crate::Backend;
                backend
                    .call(
                        "rename_symbol",
                        json!({"address": "0x401040", "new_name": "theirs"}),
                    )
                    .await
            })
            .expect("other rename");

        l.vm.submit_rename();
        assert!(l.vm.block_until_idle(WAIT));
        let d = l.vm.rename.as_ref().expect("dialog stays open");
        assert!(
            d.notice.as_deref().unwrap_or("").contains("reloaded"),
            "{d:?}"
        );
        assert!(d.error.is_none());
        assert_eq!(d.old_name, "theirs");
        assert_eq!(names(&l.vm)[1], "theirs");

        l.vm.submit_rename();
        assert!(l.vm.block_until_idle(WAIT));
        assert!(l.vm.rename.is_none(), "{:?}", l.vm.rename);
        assert_eq!(names(&l.vm)[1], "mine");
    }

    #[test]
    fn invalid_names_from_the_server_are_shown() {
        let mut l = live(Duration::ZERO);
        l.vm.begin_rename(0x401040, Some("helper"));
        l.vm.set_rename_input("bad\u{7}name");
        l.vm.submit_rename();
        assert_eq!(
            l.vm.rename.as_ref().unwrap().error.as_deref(),
            Some("A name cannot contain control characters.")
        );
        assert!(l.vm.block_until_idle(WAIT));
    }

    #[test]
    fn comments_round_trip() {
        let mut l = live(Duration::ZERO);
        l.vm.select_function(0x401000);
        assert!(l.vm.block_until_idle(WAIT));
        l.vm.begin_comment_current();
        l.vm.set_comment_input("program entry");
        l.vm.submit_comment();
        assert!(l.vm.block_until_idle(WAIT));
        assert!(l.vm.comment.is_none(), "{:?}", l.vm.comment);
        let d = l.vm.current.as_ref().unwrap().detail.as_ref().unwrap();
        assert_eq!(d.comments.len(), 1);
        assert_eq!(d.comments[0].text, "program entry");
        assert!(l.vm.history.entries.iter().any(|e| e.op == "set_comment"));
    }

    #[test]
    fn analysis_runs_with_progress_and_finishes() {
        let mut l = live(Duration::from_millis(15));
        assert_eq!(
            l.vm.status_text(),
            "Not analyzed yet. Run Analyze to find functions"
        );
        l.vm.start_analysis();
        assert!(l.vm.block_until(WAIT, |vm| vm.analysis.progress.is_some()));
        assert!(l.vm.status_text().starts_with("Analyzing: "));
        assert!(l.vm.block_until(WAIT, |vm| vm.analysis.phase == AnalysisPhase::Complete));
        assert!(l.vm.block_until_idle(WAIT));
        assert_eq!(l.vm.analysis.function_count, Some(3));
        assert_eq!(l.vm.status_text(), "Ready: 3 functions");
        assert!(
            l.vm.toasts
                .iter()
                .any(|t| t.text.contains("Analysis finished"))
        );
    }

    #[test]
    fn edits_during_analysis_are_queued_and_say_so() {
        let mut l = live(Duration::from_millis(30));
        l.vm.start_analysis();
        assert!(l.vm.block_until(WAIT, |vm| vm.analysis.running()));
        l.vm.begin_rename(0x401040, Some("helper"));
        l.vm.set_rename_input("queued_name");
        l.vm.submit_rename();
        assert!(l.vm.block_until(WAIT, |vm| vm.rename.is_none()));
        assert!(
            l.vm.toasts
                .iter()
                .any(|t| t.text.contains("when analysis finishes"))
        );
        assert!(l.vm.block_until(WAIT, |vm| vm.analysis.phase == AnalysisPhase::Complete));
        assert!(l.vm.block_until_idle(WAIT));
        assert!(
            names(&l.vm).contains(&"queued_name".to_string()),
            "{:?}",
            names(&l.vm)
        );
    }

    #[test]
    fn opening_a_missing_project_directory_fails_plainly() {
        let rt = rt();
        let demo = {
            let _g = rt.enter();
            crate::demo::demo_project().unwrap()
        };
        let mut vm = ViewModel::new(demo.backend.clone(), rt.handle().clone());
        vm.open_project("/definitely/not/a/project");
        assert!(vm.block_until_idle(WAIT));
        assert!(matches!(vm.connection, Connection::Failed(_)));
        assert_eq!(last_toast(&vm).0, ToastLevel::Error);
    }

    #[test]
    fn proposals_are_empty_for_a_fresh_project_and_refreshable() {
        let mut l = live(Duration::ZERO);
        assert!(l.vm.proposals.items.is_empty());
        assert!(l.vm.proposals.error.is_none());
        l.vm.refresh_proposals();
        assert!(l.vm.block_until_idle(WAIT));
        assert!(l.vm.proposals.error.is_none());
    }

    #[test]
    fn demo_project_lists_the_richer_function_set() {
        let rt = rt();
        let demo = {
            let _g = rt.enter();
            demo_project_with(crate::demo::demo_fixture(), Duration::ZERO).unwrap()
        };
        let mut vm = ViewModel::new(demo.backend.clone(), rt.handle().clone());
        vm.create_project(
            demo.binary.to_string_lossy(),
            demo.project_dir.to_string_lossy(),
        );
        assert!(vm.block_until_idle(WAIT));
        assert!(vm.functions.items.len() >= 10);
        let main = vm
            .functions
            .items
            .iter()
            .find(|f| f.name == "main")
            .unwrap()
            .address;
        vm.select_function(main);
        assert!(vm.block_until_idle(WAIT));
        let d = vm
            .current
            .as_ref()
            .unwrap()
            .decompiled
            .ready()
            .unwrap()
            .clone();
        let callee = d
            .result
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Function && t.target.is_some())
            .count();
        assert!(callee >= 4, "main calls several known functions");
    }
}
