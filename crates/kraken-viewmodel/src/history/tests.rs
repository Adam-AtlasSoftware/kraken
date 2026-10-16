//! Tests of the undo preview / cascade flow, run grouping and stale markers against a scripted
//! backend.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use super::*;
use crate::testing::FakeBackend;
use crate::{Connection, ToastLevel, ViewModel};

const WAIT: Duration = Duration::from_secs(10);

fn u(s: &str) -> Value {
    json!({"untrusted": true, "value": s})
}

fn entry(id: u64, op: &str, addr: u64, who: (&str, &str), run: Option<&str>) -> Value {
    let mut v = json!({
        "id": id, "op": op, "address": format!("{addr:#x}"),
        "description": u(&format!("{op} {addr:#x} x")),
        "author": {"kind": who.0, "id": who.1},
        "provenance": "user",
        "status": {"kind": "applied"},
        "sync": {"kind": "pushed"},
        "ts_ms": 1_700_000_000_000i64,
    });
    if let Some(r) = run {
        v["run_id"] = json!(r);
    }
    v
}

fn dependent(id: u64, keys: &[&str]) -> Value {
    json!({"entry": entry(id, "rename", 0x401040, ("agent", "bot"), Some("run-7")), "keys": keys})
}

fn project_json() -> Value {
    json!({
        "project_dir": "/tmp/p", "binary_path": "/bin/demo", "binary_sha256": "00",
        "program": {"arch": "x86:LE:64", "format": "elf", "base": "0x400000", "sha256": "00", "size": 4096},
        "engine_build": "fake", "capabilities": [], "epoch": {}, "epoch_stale": false,
        "stale_fields": [], "analysis": {"phase": "complete", "function_count": 1},
        "pending_entries": 0, "log_entries": 3, "open_proposals": 0,
    })
}

fn fn_view(addr: u64, name: &str) -> Value {
    json!({"address": format!("{addr:#x}"), "name": u(name), "size": 32,
           "signature": u("void f(void)"), "completeness": {"kind": "complete"}})
}

fn backend(history: Vec<Value>) -> FakeBackend {
    FakeBackend::new()
        .reply("project_open", project_json())
        .reply("project_info", project_json())
        .reply(
            "list_functions",
            json!({"items": [fn_view(0x401000, "main")]}),
        )
        .reply("history", json!({"items": history}))
        .reply("proposals_list", json!({"items": []}))
        .on("get_function", |a| {
            let mut v = fn_view(0x401000, "main");
            v["comments"] = json!([]);
            v["versions"] = json!({});
            let _ = a;
            Ok(v)
        })
        .on("decompile", |a| {
            Ok(json!({"address": a["address"], "language": "c",
                "text": u("void main(void)\n{\n}\n"), "truncated": false,
                "references": [], "warnings": [], "completeness": {"kind": "complete"}}))
        })
}

struct Rig {
    _rt: Runtime,
    vm: ViewModel,
    backend: Arc<FakeBackend>,
}

fn opened(b: FakeBackend) -> Rig {
    let rt = Runtime::new().expect("runtime");
    let backend = Arc::new(b);
    let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
    vm.open_project("/tmp/p");
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    Rig {
        _rt: rt,
        vm,
        backend,
    }
}

fn type_history() -> Vec<Value> {
    vec![
        entry(3, "rename", 0x401040, ("agent", "bot"), Some("run-7")),
        entry(2, "rename", 0x401080, ("agent", "bot"), Some("run-7")),
        entry(1, "set_type", 0x401000, ("user", "adam"), None),
    ]
}

fn undo_ok(undone: &[u64], tainted: &[&str]) -> Value {
    json!({"status": "applied", "entry_ids": [], "undone_entry_ids": undone,
           "failed": [], "tainted": tainted})
}

#[test]
fn the_dialog_names_the_dependents_and_undo_all_cascades() {
    let b = backend(type_history())
        .reply(
            "undo_preview",
            json!({"entry": entry(1, "set_type", 0x401000, ("user", "adam"), None),
                   "dependents": [dependent(2, &["native:ram:0x401000:type"]),
                                  dependent(3, &["native:ram:0x401040:name"])],
                   "undo_order": [3, 2, 1], "stale_functions": ["0x401000", "0x401040"]}),
        )
        .reply("undo_entry", undo_ok(&[3, 2, 1], &["0x401000", "0x401040"]));
    let mut r = opened(b);
    r.vm.request_undo_entry(1);
    assert!(r.vm.undo.dialog.as_ref().is_some_and(|d| d.loading));
    assert!(r.vm.block_until_idle(WAIT));

    let d = r.vm.undo.dialog.clone().expect("dialog");
    assert!(d.visible());
    assert_eq!(d.target, UndoTarget::Entry(1));
    assert_eq!(d.dependents.len(), 2);
    assert_eq!(d.dependents[0].id, 2);
    assert_eq!(d.dependents[0].who, "bot");
    assert!(d.dependents[0].by_agent);
    assert_eq!(d.dependents[0].op, "rename");
    assert_eq!(d.dependents[0].keys, vec!["native:ram:0x401000:type"]);
    assert_eq!(d.confirm_label(), "Undo all");
    let text = d.summary();
    assert!(
        text.starts_with(
            "Undoing this also undoes 2 later edits that depended on it: rename 0x401040 x (bot)"
        ),
        "{text}"
    );
    assert!(d.stale_note().expect("note").contains("0x401000"));
    // nothing is undone before the person confirms
    assert!(r.backend.calls_to("undo_entry").is_empty());
    assert_eq!(
        r.backend.calls_to("undo_preview")[0],
        json!({"entry_id": 1})
    );

    let history_calls = r.backend.calls_to("history").len();
    r.vm.confirm_undo();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        r.backend.calls_to("undo_entry"),
        vec![json!({"entry_id": 1, "cascade": true})]
    );
    assert!(r.vm.undo.dialog.is_none());
    assert_eq!(r.backend.calls_to("history").len(), history_calls + 1);
    let t = r.vm.toasts.last().expect("toast");
    assert_eq!(t.level, ToastLevel::Success);
    assert!(t.text.starts_with("Undid 3 changes"), "{}", t.text);
    // the type-edit undo marks both functions stale; the shown function was just re-read
    assert!(r.vm.is_stale(0x401040));
}

#[test]
fn cancel_leaves_everything_alone() {
    let b = backend(type_history()).reply(
        "undo_preview",
        json!({"entry": entry(1, "set_type", 0x401000, ("user", "adam"), None),
               "dependents": [dependent(2, &["k"])], "undo_order": [2, 1], "stale_functions": []}),
    );
    let mut r = opened(b);
    r.vm.request_undo_entry(1);
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.undo.dialog.as_ref().is_some_and(UndoDialog::visible));
    r.vm.cancel_undo();
    assert!(r.vm.undo.dialog.is_none());
    assert!(r.backend.calls_to("undo_entry").is_empty());
    assert!(r.vm.undo.stale.is_empty());
}

#[test]
fn an_edit_nothing_depends_on_is_undone_without_a_dialog() {
    let b = backend(type_history())
        .reply(
            "undo_preview",
            json!({"entry": entry(2, "rename", 0x401080, ("agent", "bot"), None),
                   "dependents": [], "undo_order": [2], "stale_functions": []}),
        )
        .reply("undo_entry", undo_ok(&[2], &[]));
    let mut r = opened(b);
    r.vm.request_undo_entry(2);
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        r.backend.calls_to("undo_entry"),
        vec![json!({"entry_id": 2, "cascade": false})]
    );
    assert!(r.vm.undo.dialog.is_none());
    assert_eq!(
        r.vm.toasts.last().map(|t| t.text.as_str()),
        Some("Undid that change.")
    );
}

#[test]
fn dependents_that_appear_after_the_preview_reopen_the_dialog() {
    let calls = Arc::new(Mutex::new(0u32));
    let c = calls.clone();
    let b = backend(type_history())
        .on("undo_preview", move |_| {
            let mut n = c.lock().expect("lock");
            *n += 1;
            let deps = if *n == 1 {
                json!([])
            } else {
                json!([dependent(9, &["k"])])
            };
            // the first preview has nothing to review but a stale note, so the dialog shows
            Ok(
                json!({"entry": entry(1, "set_type", 0x401000, ("user", "adam"), None),
                      "dependents": deps, "undo_order": [1], "stale_functions": ["0x401000"]}),
            )
        })
        .on("undo_entry", |_| {
            Err(
                ProtoError::new(ErrorCode::InvalidArgument, "has dependents").with_details(
                    json!({"reason": "has_dependents", "entry_id": 1, "dependents": []}),
                ),
            )
        });
    let mut r = opened(b);
    r.vm.request_undo_entry(1);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.confirm_undo();
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.undo.dialog.clone().expect("dialog stays");
    assert!(!d.running);
    assert!(d.error.is_some());
    assert_eq!(d.dependents.len(), 1);
    assert_eq!(d.dependents[0].id, 9);
    assert!(d.visible());
}

#[test]
fn other_errors_close_the_dialog_with_a_toast() {
    let b = backend(type_history()).fail("undo_preview", ErrorCode::NotFound, "no log entry 99");
    let mut r = opened(b);
    r.vm.request_undo_entry(99);
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.undo.dialog.is_none());
    let t = r.vm.toasts.last().expect("toast");
    assert_eq!(t.level, ToastLevel::Error);
}

#[test]
fn history_rows_of_one_agent_run_are_grouped() {
    let r = opened(backend(vec![
        entry(6, "rename", 0x1, ("user", "adam"), None),
        entry(5, "rename", 0x2, ("agent", "bot"), Some("run-7")),
        entry(4, "rename", 0x3, ("agent", "bot"), Some("run-7")),
        entry(3, "rename", 0x4, ("agent", "bot"), Some("run-8")),
        entry(2, "rename", 0x5, ("user", "adam"), Some("run-8")),
        {
            let mut e = entry(1, "rename", 0x6, ("agent", "bot"), Some("run-8"));
            e["undone_by"] = json!(7);
            e
        },
    ]));
    let g = group_history(&r.vm.history.entries);
    let shape: Vec<_> = g
        .iter()
        .map(|g| (g.run_id.as_deref(), g.first, g.len, g.live))
        .collect();
    assert_eq!(
        shape,
        vec![
            (None, 0, 1, 1),
            (Some("run-7"), 1, 2, 2),
            (Some("run-8"), 3, 1, 1),
            (None, 4, 1, 1),
            (Some("run-8"), 5, 1, 0),
        ]
    );
}

#[test]
fn undoing_a_run_with_no_outside_dependents_uses_undo_run() {
    let b = backend(type_history())
        .on("undo_preview", |a| {
            // entry 3 has entry 2 (same run) depending on it; neither has outside dependents
            let id = a["entry_id"].as_u64().unwrap_or(0);
            let deps = if id == 2 {
                json!([dependent(3, &["k"])])
            } else {
                json!([])
            };
            Ok(
                json!({"entry": entry(id, "rename", 0x401040, ("agent", "bot"), Some("run-7")),
                      "dependents": deps, "undo_order": [id], "stale_functions": []}),
            )
        })
        .reply("undo_run", undo_ok(&[3, 2], &[]));
    let mut r = opened(b);
    r.vm.request_undo_run("run-7");
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(r.backend.calls_to("undo_preview").len(), 2);
    assert_eq!(
        r.backend.calls_to("undo_run"),
        vec![json!({"run_id": "run-7"})]
    );
    assert!(r.backend.calls_to("undo_entry").is_empty());
    assert!(r.vm.undo.dialog.is_none());
}

#[test]
fn undoing_a_run_with_outside_dependents_asks_and_then_undoes_newest_first() {
    let b = backend(type_history())
        .on("undo_preview", |a| {
            let id = a["entry_id"].as_u64().unwrap_or(0);
            // a later edit by the user (id 8) depends on run entry 2
            let deps = if id == 2 {
                json!([{"entry": entry(8, "rename", 0x401080, ("user", "adam"), None),
                        "keys": ["native:ram:0x401080:name"]}])
            } else {
                json!([])
            };
            Ok(
                json!({"entry": entry(id, "rename", 0x401080, ("agent", "bot"), Some("run-7")),
                      "dependents": deps, "undo_order": [id], "stale_functions": []}),
            )
        })
        .reply("undo_entry", undo_ok(&[1], &[]));
    let mut r = opened(b);
    r.vm.request_undo_run("run-7");
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.undo.dialog.clone().expect("dialog");
    assert!(d.visible());
    assert_eq!(d.target, UndoTarget::Run("run-7".into()));
    assert_eq!(d.dependents.len(), 1);
    assert_eq!(d.dependents[0].id, 8);
    assert!(
        d.summary()
            .starts_with("Undoing this run also undoes 1 later edit that depended on it"),
        "{}",
        d.summary()
    );
    assert!(r.backend.calls_to("undo_run").is_empty());

    r.vm.confirm_undo();
    assert!(r.vm.block_until_idle(WAIT));
    assert_eq!(
        r.backend.calls_to("undo_entry"),
        vec![
            json!({"entry_id": 3, "cascade": true}),
            json!({"entry_id": 2, "cascade": true}),
        ]
    );
    assert!(r.vm.undo.dialog.is_none());
}

#[test]
fn a_function_stays_marked_stale_until_it_is_decompiled_again() {
    let cleared = Arc::new(Mutex::new(Vec::<Value>::new()));
    let c = cleared.clone();
    let b = backend(vec![])
        .reply(
            "tainted_list",
            json!({"items": [{"address": "0x401000", "keys": ["k"], "entry_id": 4,
                              "reason": "r", "ts_ms": 0},
                             {"address": "0x401040", "keys": ["k"], "entry_id": 4,
                              "reason": "r", "ts_ms": 0}]}),
        )
        .on("tainted_clear", move |a| {
            c.lock().expect("lock").push(a.clone());
            Ok(json!({"cleared": 1}))
        });
    let mut r = opened(b);
    assert!(r.vm.is_stale(0x401000));
    assert!(r.vm.is_stale(0x401040));

    // viewing the function re-reads it, which clears its marker
    r.vm.show_function(0x401000);
    assert!(r.vm.block_until_idle(WAIT));
    assert!(!r.vm.is_stale(0x401000));
    assert!(r.vm.is_stale(0x401040));
    assert_eq!(
        *cleared.lock().expect("lock"),
        vec![json!({"address": "0x401000"})]
    );

    // a list that was requested before the clear cannot bring the marker back
    r.vm.refresh_tainted();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.is_stale(0x401040));
}

#[test]
fn a_backend_without_tainted_commands_just_has_no_markers() {
    let r = opened(backend(vec![]));
    assert!(r.vm.undo.stale.is_empty());
}
