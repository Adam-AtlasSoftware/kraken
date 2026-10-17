//! Tests of the Rewrite tab against a backend with scripted `rewrite_*` replies.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use super::*;
use crate::backend::{BackendEvent, JobInfo, JobProgress, JobState};
use crate::testing::FakeBackend;
use crate::{Connection, ToastLevel, ViewModel};

const WAIT: Duration = Duration::from_secs(10);

fn u(s: &str) -> Value {
    json!({"untrusted": true, "value": s})
}

fn project_json() -> Value {
    json!({
        "project_dir": "/work/proj", "binary_path": "/bin/demo", "binary_sha256": "00",
        "program": {"arch": "x86:LE:64", "format": "elf", "base": "0x400000", "sha256": "00", "size": 4096},
        "engine_build": "fake", "capabilities": [], "epoch": {}, "epoch_stale": false,
        "stale_fields": [], "analysis": {"phase": "complete", "function_count": 3},
        "pending_entries": 0, "log_entries": 0, "open_proposals": 0,
    })
}

fn row(order: u32, addr: u64, name: &str, status: &str, version: u32, flags: &[&str]) -> Value {
    json!({"order": order, "address": format!("{addr:#x}"), "name": u(name), "status": status,
           "version": version, "cases_run": 200, "passed": 200, "counterexamples": 0,
           "flags": flags})
}

fn status_page(units: Vec<Value>, next: Option<&str>) -> Value {
    json!({"program_sha256": "00", "plan_present": true,
           "counts": {"planned": 1, "translated": 0, "verified": 1, "failed": 1, "accepted": 1},
           "units": units, "next_cursor": next})
}

fn version_result(unit: &str, version: u32, status: &str, verdict: &str) -> Value {
    json!({"unit": unit, "address": "0x401240", "name": u("checksum"), "version": version,
           "mode": "incremental", "status": status, "verdict": verdict, "cases_run": 200,
           "passed": if verdict == "pass" { 200 } else { 37 }, "skipped": 0,
           "rust_prototype": "pub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32",
           "sandbox": "landlock", "provider": "demo", "model": "scripted",
           "assumptions": [u("len counts bytes")], "unsupported": []})
}

fn failing_result() -> Value {
    let mut v = version_result("ru-1", 1, "failed", "fail");
    v["counterexample"] = json!({
        "args": ["buf[8]=80 00 00 00 00 00 00 00", "len=1"],
        "differences": [u("result: original 0x80, Rust 0xffffff80")],
    });
    v
}

fn job(id: &str, command: &str, status: JobState) -> JobInfo {
    JobInfo {
        job_id: id.into(),
        command: command.into(),
        status,
        progress: None,
        result: None,
        error: None,
    }
}

fn done(id: &str, command: &str, result: Value) -> BackendEvent {
    BackendEvent::Job(JobInfo {
        result: Some(result),
        ..job(id, command, JobState::Succeeded)
    })
}

fn base() -> FakeBackend {
    FakeBackend::new()
        .reply("project_open", project_json())
        .reply("project_info", project_json())
        .reply("list_functions", json!({"items": []}))
        .reply("history", json!({"items": []}))
        .reply("proposals_list", json!({"items": []}))
        .reply(
            "rewrite_status",
            status_page(
                vec![
                    row(0, 0x401440, "xor_len", "accepted", 1, &[]),
                    row(1, 0x401240, "checksum", "failed", 1, &["uses_globals"]),
                    row(
                        2,
                        0x4012a0,
                        "log_error",
                        "planned",
                        0,
                        &["needs_stubs", "future_flag"],
                    ),
                ],
                None,
            ),
        )
        .reply(
            "decompile",
            json!({"address": "0x401240", "language": "c",
                   "text": u("uint32_t checksum(uint8_t *buf, size_t len)\n{\n  return 0;\n}\n"),
                   "truncated": false, "references": [], "warnings": [],
                   "completeness": {"kind": "complete"}}),
        )
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
    vm.open_project("/work/proj");
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    // Whatever the test machine is, the tests are about a host that can confine code.
    vm.rewrite.availability = Availability::Unknown;
    Rig {
        _rt: rt,
        vm,
        backend,
    }
}

impl Rig {
    fn idle(&mut self) {
        assert!(self.vm.block_until_idle(WAIT));
    }

    fn until(&mut self, what: &str, cond: impl Fn(&ViewModel) -> bool) {
        assert!(
            self.vm.block_until(WAIT, cond),
            "timed out waiting for {what}"
        );
    }
}

#[test]
fn the_plan_loads_in_order_with_counts_flags_and_pages() {
    let b = base().on("rewrite_status", {
        let calls = Mutex::new(0);
        move |args| {
            let mut n = calls.lock().expect("lock");
            *n += 1;
            Ok(if *n == 1 {
                assert!(args.get("cursor").is_none());
                status_page(
                    vec![row(0, 0x401440, "xor_len", "accepted", 1, &[])],
                    Some("c2"),
                )
            } else {
                assert_eq!(args["cursor"], "c2");
                status_page(
                    vec![
                        row(1, 0x401240, "checksum", "failed", 2, &["uses_globals"]),
                        row(
                            2,
                            0x4012a0,
                            "log_error",
                            "planned",
                            0,
                            &["needs_stubs", "future_flag"],
                        ),
                    ],
                    None,
                )
            })
        }
    });
    let mut r = opened(b);
    r.vm.rewrite_ensure_loaded();
    assert!(r.vm.rewrite.loading);
    r.idle();
    let st = &r.vm.rewrite;
    assert!(st.loaded && !st.loading && st.plan_present && st.error.is_none());
    let names: Vec<&str> = st.rows.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["xor_len", "checksum", "log_error"]);
    assert_eq!(st.rows[0].status, UnitStatus::Accepted);
    assert_eq!(st.rows[1].status, UnitStatus::Failed);
    assert_eq!(st.rows[1].version, 2);
    assert_eq!(
        st.rows[2].flags,
        [Flag::NeedsStubs, Flag::Other("future flag".into())]
    );
    assert_eq!(st.counts.total(), 4);
    assert_eq!(st.counts.of(UnitStatus::Verified), 1);
    assert!(Flag::NeedsStubs.explain().contains("malloc"));
    // Loaded once; asking again does not call again.
    r.vm.rewrite_ensure_loaded();
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_status").len(), 2);
}

#[test]
fn making_a_plan_stores_the_summary_and_reloads_the_rows() {
    let b = base().reply(
        "rewrite_plan",
        json!({"scope": "all", "program_sha256": "00", "functions_total": 21,
               "functions_planned": 3, "skipped_imports": 6, "skipped_runtime": 2,
               "groups": 3, "truncated": false, "entries": []}),
    );
    let mut r = opened(b);
    r.vm.rewrite_make_plan();
    r.idle();
    let plan = r.backend.calls_to("rewrite_plan");
    assert_eq!(plan[0]["scope"], "all");
    let s = r.vm.rewrite.plan_summary.clone().expect("summary");
    assert_eq!(
        (s.functions_total, s.skipped_imports, s.skipped_runtime),
        (21, 6, 2)
    );
    assert_eq!(r.vm.rewrite.rows.len(), 3);
    assert_eq!(
        r.vm.rewrite.coverage_line(),
        "Accepted 1 of 4 planned functions (1 of 21 in the program)."
    );
}

#[test]
fn a_rewrite_job_shows_progress_then_the_verified_result() {
    let b = base()
        .reply("rewrite_function", json!({"job_id": "job-7"}))
        .reply("rewrite_unit", json!({"versions": []}));
    let mut r = opened(b);
    r.vm.rewrite_refresh();
    r.idle();
    r.vm.rewrite_select(0x401240);
    r.idle();
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    // Asking twice while it runs does not start a second job.
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    assert_eq!(r.vm.rewrite.jobs.len(), 1);
    assert!(r.vm.rewrite.running_for(0x401240).is_some());
    r.idle();
    let call = &r.backend.calls_to("rewrite_function")[0];
    assert_eq!(call["address"], "0x401240");
    assert_eq!(call["mode"], "incremental");
    assert_eq!(r.vm.rewrite.jobs[0].job_id.as_deref(), Some("job-7"));

    r.backend.emit(BackendEvent::Job(JobInfo {
        progress: Some(JobProgress {
            phase: "Testing".into(),
            done: 3,
            total: 4,
            message: "Running both versions".into(),
        }),
        ..job("job-7", "rewrite_function", JobState::Running)
    }));
    r.until("progress", |vm| vm.rewrite.jobs[0].progress.is_some());
    assert_eq!(r.vm.rewrite.jobs[0].fraction(), Some(0.75));
    // Another command's job is none of the tab's business.
    r.backend.emit(BackendEvent::Job(job(
        "job-8",
        "analyze",
        JobState::Running,
    )));

    let before = r.backend.calls_to("rewrite_status").len();
    r.backend.emit(done(
        "job-7",
        "rewrite_function",
        version_result("ru-2", 2, "verified", "pass"),
    ));
    r.until("the job to finish", |vm| !vm.rewrite.jobs[0].running());
    r.idle();
    let j = &r.vm.rewrite.jobs[0];
    assert_eq!(j.state, JobState::Succeeded);
    assert!(j.outcome.as_deref().is_some_and(|o| o.contains("verified")));
    assert!(
        r.backend.calls_to("rewrite_status").len() > before,
        "the list is refreshed"
    );
    let d = r.vm.rewrite.details.get(&0x401240).expect("detail");
    let v = d.current().expect("version");
    assert_eq!((v.version, v.status), (2, UnitStatus::Verified));
    assert_eq!(v.assumptions, ["len counts bytes"]);
    assert!(v.cases_line().starts_with("200 of 200 cases agreed"));
    assert!(r.vm.toasts.iter().any(|t| t.level == ToastLevel::Success));
    assert_eq!(
        r.vm.rewrite.acceptable_unit(0x401240).as_deref(),
        Some("ru-2")
    );
}

#[test]
fn a_job_event_that_beats_the_reply_is_not_lost() {
    let b = base().on("rewrite_function", |_| Ok(json!({"job_id": "job-3"})));
    let mut r = opened(b);
    // The daemon reports the job before the reply is applied.
    r.backend.emit(done(
        "job-3",
        "rewrite_function",
        version_result("ru-1", 1, "verified", "pass"),
    ));
    std::thread::sleep(Duration::from_millis(50));
    r.vm.poll();
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.until("the stashed result", |vm| {
        vm.rewrite.jobs.first().is_some_and(|j| !j.running())
    });
    assert_eq!(r.vm.rewrite.jobs[0].state, JobState::Succeeded);
}

#[test]
fn a_failed_unit_shows_the_c_the_rust_the_counterexample_and_its_history() {
    let rust_v1 = "#[no_mangle]\npub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32 {\n    0\n}\n";
    let mut v1 = failing_result();
    v1["rust_code"] = u(rust_v1);
    let mut v2 = version_result("ru-2", 2, "translated", "inconclusive");
    v2["rust_code"] = u("pub fn checksum() {}");
    v2["verdict_detail"] = u("most cases ended in a library call");
    let b = base()
        .reply("rewrite_unit", json!({"versions": [v1, v2]}))
        .reply(
            "rewrite_plan",
            json!({"scope": "function", "program_sha256": "00", "functions_total": 3,
                   "functions_planned": 2, "skipped_imports": 0, "skipped_runtime": 0, "groups": 2,
                   "truncated": false, "entries": [
                       {"order": 0, "address": "0x4012a0", "name": u("log_error"), "group": 0,
                        "group_size": 1, "callees": [], "imports": [u("fprintf")],
                        "needs_stubs": [u("fprintf")], "flags": ["needs_stubs"], "status": "planned"},
                       {"order": 1, "address": "0x401240", "name": u("checksum"), "group": 1,
                        "group_size": 1, "callees": ["0x4012a0"], "imports": [],
                        "needs_stubs": [], "flags": [], "status": "failed"}]}),
        );
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    assert_eq!(r.vm.rewrite.selected, Some(0x401240));
    r.idle();
    let d = r.vm.rewrite.selected_detail().expect("detail");
    assert!(!d.loading && d.stored_note.is_none());
    assert!(
        d.c.as_ref()
            .expect("c")
            .text()
            .contains("uint32_t checksum")
    );
    let plan = d.plan.as_ref().expect("plan");
    assert_eq!(plan.callees, [(0x4012a0, "log_error".to_string())]);
    let versions = d.versions();
    assert_eq!(versions.len(), 2);
    // Newest first in what is shown, oldest first in the list.
    let shown = d.current().expect("shown");
    assert_eq!(shown.version, 2);
    assert_eq!(
        shown.verdict_detail.as_deref(),
        Some("most cases ended in a library call")
    );
    // Looking at the older failing version.
    r.vm.rewrite_show_version(0x401240, 1);
    let d = r.vm.rewrite.selected_detail().expect("detail");
    let v = d.current().expect("v1");
    assert_eq!(v.status, UnitStatus::Failed);
    let cx = v.counterexample.as_ref().expect("counterexample");
    assert_eq!(cx.args[1], "len=1");
    assert_eq!(cx.differences, ["result: original 0x80, Rust 0xffffff80"]);
    let rust = v.rust.as_ref().expect("rust code");
    assert_eq!(rust.text(), rust_v1);
    assert!(
        rust.0
            .tokens
            .iter()
            .any(|t| t.kind == kraken_proto::TokenKind::Keyword)
    );
    assert_eq!(rust.0.language, "rust");
    // A failed version cannot be accepted, and Retry runs in the same mode.
    assert!(r.vm.rewrite.acceptable_unit(0x401240).is_none());
}

#[test]
fn without_a_unit_query_the_panel_says_what_is_missing_and_keeps_job_results() {
    let b = base()
        .fail(
            "rewrite_unit",
            ErrorCode::NotFound,
            "unknown command `rewrite_unit`",
        )
        .reply("rewrite_function", json!({"job_id": "job-1"}));
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    r.idle();
    let d = r.vm.rewrite.selected_detail().expect("detail");
    assert!(
        d.stored_note
            .as_deref()
            .is_some_and(|n| n.contains("cannot send them"))
    );
    assert!(d.versions().is_empty());
    // Not asked again for the next function.
    r.vm.rewrite_select(0x4012a0);
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_unit").len(), 1);

    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.idle();
    r.backend
        .emit(done("job-1", "rewrite_function", failing_result()));
    r.until("result", |vm| !vm.rewrite.jobs[0].running());
    let d = r.vm.rewrite.details.get(&0x401240).expect("detail");
    let v = d.current().expect("version from the job result");
    assert_eq!(v.status, UnitStatus::Failed);
    assert!(v.counterexample.is_some());
    assert!(v.rust.is_none());
    assert!(r.vm.toasts.iter().any(|t| t.level == ToastLevel::Warning));
}

#[test]
fn accepting_sends_the_unit_of_the_verified_version() {
    let b = base()
        .reply("rewrite_function", json!({"job_id": "job-4"}))
        .reply("rewrite_unit", json!({"versions": []}))
        .reply(
            "rewrite_accept",
            json!({"status": "accepted", "unit": "ru-9", "address": "0x401240", "version": 1,
                   "replaced_version": 0}),
        );
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    r.idle();
    // Nothing to accept before a verified version exists.
    r.vm.rewrite_accept(0x401240);
    r.idle();
    assert!(r.backend.calls_to("rewrite_accept").is_empty());

    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.idle();
    r.backend.emit(done(
        "job-4",
        "rewrite_function",
        version_result("ru-9", 1, "verified", "pass"),
    ));
    r.until("verified", |vm| {
        vm.rewrite.acceptable_unit(0x401240).is_some()
    });
    r.vm.rewrite_accept(0x401240);
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_accept")[0],
        json!({"unit": "ru-9"})
    );
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.starts_with("Accepted") && t.level == ToastLevel::Success)
    );
}

#[test]
fn a_refused_accept_is_explained_on_the_function() {
    let b = base()
        .reply("rewrite_function", json!({"job_id": "job-4"}))
        .reply("rewrite_unit", json!({"versions": []}))
        .fail(
            "rewrite_accept",
            ErrorCode::InvalidArgument,
            "unit `ru-9` is failed",
        );
    let mut r = opened(b);
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.idle();
    r.backend.emit(done(
        "job-4",
        "rewrite_function",
        version_result("ru-9", 1, "verified", "pass"),
    ));
    r.until("verified", |vm| {
        vm.rewrite.acceptable_unit(0x401240).is_some()
    });
    r.vm.rewrite_accept(0x401240);
    r.idle();
    let d = r.vm.rewrite.details.get(&0x401240).expect("detail");
    assert_eq!(d.error.as_deref(), Some("unit `ru-9` is failed"));
}

const SPEC: &str = "# checksum\n\n## Purpose\nRolling hash [@0x401240].\n\n## Inputs\n- `buf` read by [@0x401240] and [@0x4011a0]\n";

#[test]
fn a_spec_job_renders_clickable_citations() {
    let b = base().reply("rewrite_spec", json!({"job_id": "job-5"}));
    let mut r = opened(b);
    r.vm.rewrite_write_spec(Some(0x401240));
    r.vm.rewrite_write_spec(Some(0x401240));
    assert_eq!(r.vm.rewrite.jobs.len(), 1);
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_spec")[0],
        json!({"scope": "function", "address": "0x401240"})
    );
    r.backend.emit(done(
        "job-5",
        "rewrite_spec",
        json!({"spec": 3, "scope": "function", "address": "0x401240", "functions": 1, "facts": 2,
               "citations": ["0x401240", "0x4011a0"], "markdown": u(SPEC),
               "provider": "demo", "model": "scripted"}),
    ));
    r.until("spec", |vm| vm.rewrite.spec_for(Some(0x401240)).is_some());
    let doc = r.vm.rewrite.spec_for(Some(0x401240)).expect("spec");
    assert_eq!(doc.id, 3);
    assert_eq!(doc.cited(), vec![0x401240, 0x4011a0]);
    assert!(matches!(
        &doc.blocks[0],
        SpecBlock::Heading { level: 1, .. }
    ));
    assert!(r.vm.rewrite.spec_for(None).is_none());

    r.vm.rewrite_write_spec(None);
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_spec")[1],
        json!({"scope": "all"})
    );
}

#[test]
fn export_goes_into_the_project_by_default_and_asks_before_leaving_it() {
    let b = base().on("rewrite_export", |_| Ok(json!({"job_id": "job-6"})));
    let mut r = opened(b);
    r.vm.rewrite_export_open();
    assert!(r.vm.rewrite.export.open);
    assert_eq!(r.vm.rewrite.export.dir, "rewrite-export");
    assert_eq!(r.vm.rewrite_export_check(), DirCheck::Inside);

    // Outside the project: nothing is sent until the person agrees.
    r.vm.rewrite_export_set_dir("/home/me/elsewhere".into());
    assert_eq!(r.vm.rewrite_export_check(), DirCheck::Outside);
    r.vm.rewrite_export_start();
    r.idle();
    assert!(r.vm.rewrite.export.ask_outside);
    assert!(r.backend.calls_to("rewrite_export").is_empty());
    // Typing another folder withdraws the question.
    r.vm.rewrite_export_set_dir("/work/proj/out".into());
    assert!(!r.vm.rewrite.export.ask_outside);
    assert_eq!(r.vm.rewrite_export_check(), DirCheck::Inside);
    r.vm.rewrite_export_set_dir("/home/me/elsewhere".into());
    r.vm.rewrite_export_start();
    r.vm.rewrite_export_agree_outside();
    r.idle();
    let call = &r.backend.calls_to("rewrite_export")[0];
    assert_eq!(call["dir"], "/home/me/elsewhere");
    assert_eq!(call["build"], true);
    assert!(!r.vm.rewrite.export.ask_outside);

    r.backend.emit(done(
        "job-6",
        "rewrite_export",
        json!({"dir": "/home/me/elsewhere", "crates": ["demo", "demo_shim"],
               "symbols": ["checksum", "xor_len"], "built": true, "sandbox": "landlock",
               "coverage": {"accepted": 2, "planned": 3, "functions_total": 21}, "readme": {"untrusted": true, "value": "README.md"}}),
    ));
    r.until("export", |vm| vm.rewrite.export.result.is_some());
    let s = r.vm.rewrite.export.result.clone().expect("summary");
    assert_eq!(
        (s.symbols.len(), s.accepted, s.planned, s.functions_total),
        (2, 2, 3, 21)
    );
    assert!(s.built);
    assert!(
        r.vm.rewrite.jobs[0]
            .outcome
            .as_deref()
            .is_some_and(|o| o.contains("Exported 2"))
    );
}

#[test]
fn export_refuses_unusable_folders_and_a_relative_one_needs_no_question() {
    assert!(matches!(
        check_export_dir(Some("/p"), ""),
        DirCheck::Invalid(_)
    ));
    assert!(matches!(
        check_export_dir(Some("/p"), "../x"),
        DirCheck::Invalid(_)
    ));
    assert!(matches!(
        check_export_dir(Some("/p"), "a/../../x"),
        DirCheck::Invalid(_)
    ));
    assert_eq!(check_export_dir(Some("/p"), "out"), DirCheck::Inside);
    assert_eq!(check_export_dir(Some("/p"), "/p/out"), DirCheck::Inside);
    assert_eq!(check_export_dir(Some("/p"), "/q/out"), DirCheck::Outside);
    assert_eq!(check_export_dir(None, "/q/out"), DirCheck::Outside);

    let mut r = opened(base().reply("rewrite_export", json!({"job_id": "job-6"})));
    r.vm.rewrite_export_set_dir("../escape".into());
    r.vm.rewrite_export_start();
    assert!(
        r.vm.rewrite
            .export
            .error
            .as_deref()
            .is_some_and(|e| e.contains(".."))
    );
    r.idle();
    assert!(r.backend.calls_to("rewrite_export").is_empty());
    r.vm.rewrite_export_set_dir("out".into());
    r.vm.rewrite_export_start();
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_export")[0]["dir"], "out");
}

#[test]
fn a_host_that_cannot_confine_code_explains_instead_of_failing_buttons() {
    assert!(platform_note("linux").is_none());
    for os in ["macos", "windows"] {
        let note = platform_note(os).expect("note");
        assert!(note.contains(os) && note.contains("sandbox"));
    }

    // The daemon refuses at the start of the job.
    let b = base().fail(
        "rewrite_function",
        ErrorCode::Unsupported,
        "this host cannot confine generated code",
    );
    let mut r = opened(b);
    assert!(r.vm.rewrite.can_run());
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.idle();
    assert!(!r.vm.rewrite.can_run());
    let note = r.vm.rewrite.blocked_note().expect("note");
    assert!(note.contains("cannot confine"));
    // The refused job is not left running, and no toast piles on top of the explanation.
    assert!(!r.vm.rewrite.jobs[0].running());
    assert!(r.vm.toasts.is_empty());
    // Further attempts do nothing at all.
    r.vm.rewrite_run(0x401240, RewriteMode::Incremental);
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_function").len(), 1);
    // The export dialog turns the build off.
    r.vm.rewrite_export_open();
    assert!(!r.vm.rewrite.export.build);
}

#[test]
fn a_daemon_without_the_pipeline_is_reported_once_for_the_whole_tab() {
    let b = base().fail(
        "rewrite_status",
        ErrorCode::Unsupported,
        "the rewrite pipeline is not attached",
    );
    let mut r = opened(b);
    r.vm.rewrite_ensure_loaded();
    r.idle();
    assert!(matches!(
        r.vm.rewrite.availability,
        Availability::NotAttached(_)
    ));
    assert!(r.vm.rewrite.loaded && r.vm.rewrite.error.is_none());
    assert!(
        r.vm.rewrite
            .blocked_note()
            .is_some_and(|n| n.contains("not attached"))
    );
}

#[test]
fn another_failure_is_a_message_and_a_failed_job_says_why() {
    let b = base()
        .fail("rewrite_status", ErrorCode::Internal, "disk is full")
        .reply("rewrite_function", json!({"job_id": "job-2"}));
    let mut r = opened(b);
    r.vm.rewrite_ensure_loaded();
    r.idle();
    assert!(
        r.vm.rewrite
            .error
            .as_deref()
            .is_some_and(|e| e.contains("disk is full"))
    );

    r.vm.rewrite_run(0x401240, RewriteMode::Spec);
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_function")[0]["mode"], "spec");
    r.backend.emit(BackendEvent::Job(JobInfo {
        error: Some(ProtoError::new(
            ErrorCode::InvalidArgument,
            "floating point parameters are not supported yet",
        )),
        ..job("job-2", "rewrite_function", JobState::Failed)
    }));
    r.until("failure", |vm| !vm.rewrite.jobs[0].running());
    let d = r.vm.rewrite.details.get(&0x401240).expect("detail");
    assert_eq!(
        d.error.as_deref(),
        Some("floating point parameters are not supported yet")
    );
    assert!(
        r.vm.rewrite.can_run(),
        "a refused signature is not a missing sandbox"
    );
    // Retry runs again in the mode of the row.
    r.vm.rewrite_retry(0x401240);
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_function").len(), 2);
}

#[test]
fn a_new_project_clears_the_tab() {
    let mut r = opened(base());
    r.vm.rewrite_refresh();
    r.idle();
    assert!(!r.vm.rewrite.rows.is_empty());
    r.vm.open_project("/work/other");
    r.idle();
    assert!(r.vm.rewrite.rows.is_empty() && !r.vm.rewrite.loaded);
}

// ---------------------------------------------------------------- the Program view

fn side(exit: &str, out: &str, err: &str) -> Value {
    json!({"exit": exit, "stdout": u(out), "stdout_bytes": out.len(),
           "stderr": u(err), "stderr_bytes": err.len()})
}

fn case_json(name: &str, agree: bool) -> Value {
    json!({"name": name, "origin": "baseline", "argv": [u("-v"), u("a b")], "stdin_bytes": 12,
           "agree": agree,
           "original": side("exit 0", "one\ntwo\nthree\n", ""),
           "rewritten": if agree { side("exit 0", "one\ntwo\nthree\n", "") }
                        else { side("exit 3", "one\n2\nthree\n", "oops\n") },
           "differences": if agree { json!([]) } else {
               json!([u("exit status: original exit 0, rewritten exit 3"),
                      u("stdout: first difference at byte 4")]) }})
}

fn program_run_json(run: u64, fail: bool) -> Value {
    let f = |order: u32, addr: u64, name: &str, check: &str, verdict: &str, included: bool| {
        json!({"order": order, "address": format!("{addr:#x}"), "name": u(name),
               "unit": format!("ru-{order}"), "version": 1,
               "status": if verdict == "pass" { "verified" } else { "translated" },
               "verdict": verdict, "check": check, "attempts": 1,
               "reused_callees": if order == 1 { json!(["xor_len"]) } else { json!([]) },
               "included": included,
               "check_note": if verdict == "pass" { Value::Null } else { u("pointer result") }})
    };
    json!({
        "run": run, "program_sha256": "00", "entry": "0x401500", "entry_name": u("main"),
        "functions_planned": 3, "skipped": 0, "translated": 3, "reused_from_store": 0,
        "failed": 0, "included": 3,
        "functions": [
            f(0, 0x401440, "xor_len", "differential", "pass", true),
            f(1, 0x401240, "checksum", "compile_only", "inconclusive", true),
            f(2, 0x401500, "main", "differential", "pass", true),
        ],
        "crate_dir": "/work/proj/rewrite-program", "built": true, "crate_sha256": "ab12",
        "provider": "demo", "model": "scripted", "created": 1_760_000_000u64,
        "verdict": {
            "verdict": if fail { "fail" } else { "pass" }, "cases_run": 3,
            "passed": if fail { 2 } else { 3 }, "failed": if fail { 1 } else { 0 },
            "cases": if fail { vec![case_json("baseline", false)] } else { vec![] },
            "sandbox": "landlock-v6+netns",
        },
        "repairs": if fail { json!([]) } else { json!([{
            "round": 1, "address": "0x401240", "name": u("checksum"), "case": "baseline",
            "at": "writing byte 4 of its standard output", "stack": ["checksum", "main"],
            "why": u("it was running when the first differing output was produced"),
            "outcome": "replaced", "version_before": 1, "version_after": 2,
            "verdict_after": "pass"}]) },
    })
}

fn status_out(runs: &[(u64, &str)], shown: Option<Value>) -> Value {
    json!({"program_sha256": "00", "present": !runs.is_empty(),
           "runs": runs.iter().map(|(n, v)| json!({
               "run": n, "created": 1_760_000_000u64, "entry": "0x401500", "verdict": v,
               "cases_run": 3, "passed": 2, "crate_dir": "/work/proj/rewrite-program"}))
               .collect::<Vec<_>>(),
           "run": shown})
}

#[test]
fn the_program_view_lists_runs_the_function_table_and_the_failing_case() {
    let b = base().on("rewrite_program_status", |args| {
        assert_eq!(args["all_cases"], false);
        Ok(status_out(
            &[(2, "fail"), (1, "pass")],
            Some(program_run_json(2, true)),
        ))
    });
    let mut r = opened(b);
    r.vm.rewrite_program_ensure_loaded();
    assert!(r.vm.rewrite.program.loading);
    r.idle();
    let p = &r.vm.rewrite.program;
    assert!(p.loaded && !p.loading && p.error.is_none());
    assert_eq!(p.runs.len(), 2);
    assert_eq!(p.runs[0].run, 2);
    let d = p.detail.as_ref().expect("detail");
    assert_eq!(d.entry_name, "main");
    assert_eq!(d.crate_dir, "/work/proj/rewrite-program");
    assert!(d.built);
    let names: Vec<&str> = d.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["xor_len", "checksum", "main"]);
    assert_eq!(d.functions[1].check_label(), "compiled only");
    assert_eq!(d.functions[1].reused, ["xor_len"]);
    assert_eq!(d.functions[2].check_label(), "compared with the original");
    assert!(d.functions[1].unverified() && !d.functions[0].unverified());
    assert_eq!(d.unverified(), 1);
    // The failing case is on show at once.
    assert_eq!(p.selected_case, Some(0));
    let c = p.case().expect("case");
    assert!(!c.agree);
    assert_eq!(c.command_line(), "prog -v \"a b\"  < 12 bytes of input");
    assert!(!c.exit_agrees());
    assert_eq!(c.rewritten.exit, "exit 3");
    assert_eq!(
        verdict_line(&d.verdict),
        "The rewritten program differs from the original on 1 of 3 cases."
    );
    // Run again with the same list, once: ensure_loaded does not call twice.
    r.vm.rewrite_program_ensure_loaded();
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_program_status").len(), 1);
}

#[test]
fn another_run_and_the_agreeing_cases_are_asked_for_by_number_and_flag() {
    let b = base().on("rewrite_program_status", |args| {
        let run = args.get("run").and_then(Value::as_u64).unwrap_or(2);
        Ok(status_out(
            &[(2, "pass"), (1, "fail")],
            Some(program_run_json(run, run == 1)),
        ))
    });
    let mut r = opened(b);
    r.vm.rewrite_program_refresh(None);
    r.idle();
    assert_eq!(r.vm.rewrite.program.detail.as_ref().map(|d| d.run), Some(2));
    // A passing run has no differing case and shows its repair round.
    let d = r.vm.rewrite.program.detail.clone().expect("detail");
    assert!(d.verdict.cases.is_empty());
    assert_eq!(r.vm.rewrite.program.selected_case, None);
    let rep = &d.repairs[0];
    assert_eq!(rep.name, "checksum");
    assert_eq!(rep.stack, ["checksum", "main"]);
    assert_eq!(rep.versions, (1, 2));
    assert_eq!(rep.verdict_after, "pass");
    assert!(rep.outcome_text().contains("replaced the old one"));
    r.vm.rewrite_program_show_run(1);
    r.idle();
    assert_eq!(r.vm.rewrite.program.detail.as_ref().map(|d| d.run), Some(1));
    assert_eq!(
        r.vm.rewrite
            .program
            .detail
            .as_ref()
            .map(|d| d.verdict.failed),
        Some(1)
    );
    r.vm.rewrite_program_set_all_cases(true);
    r.idle();
    let calls = r.backend.calls_to("rewrite_program_status");
    assert_eq!(calls.last().expect("call")["all_cases"], true);
    assert_eq!(
        calls.last().expect("call")["run"],
        1,
        "the same run is read again"
    );
}

#[test]
fn the_run_button_starts_a_job_with_the_repair_rounds_and_reads_the_result() {
    let b = base()
        .reply("rewrite_program", json!({"job_id": "job-p"}))
        .on("rewrite_program_status", |args| {
            let run = args.get("run").and_then(Value::as_u64).unwrap_or(1);
            Ok(status_out(
                &[(run, "pass")],
                Some(program_run_json(run, false)),
            ))
        });
    let mut r = opened(b);
    r.vm.rewrite_program_set_rounds(9);
    assert_eq!(r.vm.rewrite.program.repair_rounds, MAX_REPAIR_ROUNDS);
    r.vm.rewrite_program_set_rounds(1);
    r.vm.rewrite_program_run();
    // A second click while it runs does nothing.
    r.vm.rewrite_program_run();
    assert!(r.vm.rewrite_program_running());
    r.idle();
    let started = r.backend.calls_to("rewrite_program");
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["scope"], "all");
    assert_eq!(started[0]["repair_rounds"], 1);
    assert_eq!(r.vm.rewrite.jobs[0].kind, JobKind::Program);
    r.backend
        .emit(done("job-p", "rewrite_program", program_run_json(3, false)));
    r.until("the result", |vm| !vm.rewrite_program_running());
    r.idle();
    let outcome = r.vm.rewrite.jobs[0].outcome.clone().expect("outcome");
    assert!(
        outcome.starts_with("Run 3: 3 of 3 functions are in the crate."),
        "{outcome}"
    );
    assert!(
        outcome.contains("matches the original on 3 cases"),
        "{outcome}"
    );
    assert!(
        outcome.contains("1 function was translated again"),
        "{outcome}"
    );
    // The new run was read back.
    let calls = r.backend.calls_to("rewrite_program_status");
    assert_eq!(calls.last().expect("call")["run"], 3);
    assert_eq!(r.vm.rewrite.program.detail.as_ref().map(|d| d.run), Some(3));
}

#[test]
fn a_run_the_person_does_not_allow_is_not_an_error() {
    let b = base().on("rewrite_program", |_| {
        Err(ProtoError::new(
            ErrorCode::Unsupported,
            "approval denied: `rewrite_program` was not approved",
        )
        .with_details(json!({"approval": "denied"})))
    });
    let mut r = opened(b);
    r.vm.rewrite_program_run();
    r.idle();
    let st = &r.vm.rewrite;
    assert!(!r.vm.rewrite_program_running());
    assert_eq!(st.jobs[0].state, JobState::Cancelled);
    assert!(
        st.program
            .declined
            .as_deref()
            .is_some_and(|d| d.starts_with("Not run."))
    );
    assert!(st.program.error.is_none());
    assert!(st.can_run(), "a refusal does not switch the tab off");
    assert!(
        !r.vm.toasts.iter().any(|t| t.level == ToastLevel::Error),
        "{:?}",
        r.vm.toasts
    );
    // Asking again clears the note.
    r.vm.rewrite_program_run();
    assert!(r.vm.rewrite.program.declined.is_none());
}

#[test]
fn a_failed_run_says_why_and_a_missing_pipeline_is_reported_once() {
    let b = base()
        .reply("rewrite_program", json!({"job_id": "job-f"}))
        .fail(
            "rewrite_program_status",
            ErrorCode::Unsupported,
            "no pipeline here",
        );
    let mut r = opened(b);
    r.vm.rewrite.availability = Availability::Unknown;
    r.vm.rewrite_program_refresh(None);
    r.idle();
    assert!(matches!(
        r.vm.rewrite.availability,
        Availability::NotAttached(_)
    ));
    r.vm.rewrite.availability = Availability::Unknown;
    r.vm.rewrite_program_run();
    r.idle();
    r.backend.emit(BackendEvent::Job(JobInfo {
        error: Some(ProtoError::new(
            ErrorCode::InvalidArgument,
            "the binary changed",
        )),
        ..job("job-f", "rewrite_program", JobState::Failed)
    }));
    r.until("the failure", |vm| !vm.rewrite_program_running());
    assert!(r.vm.rewrite.program.error.is_some());
    assert_eq!(r.vm.rewrite.jobs[0].state, JobState::Failed);
}

#[test]
fn the_line_diff_pairs_equal_lines_and_groups_the_rest() {
    let d = line_diff("a\nb\nc\n", "a\nB\nc\n");
    let shape: Vec<(DiffKind, &str)> = d.iter().map(|l| (l.kind, l.text.as_str())).collect();
    assert_eq!(
        shape,
        [
            (DiffKind::Same, "a"),
            (DiffKind::Original, "b"),
            (DiffKind::Rewritten, "B"),
            (DiffKind::Same, "c"),
        ]
    );
    assert!(
        line_diff("same\n", "same\n")
            .iter()
            .all(|l| l.kind == DiffKind::Same)
    );
    // Missing and extra lines at either end.
    let d = line_diff("x\ny\n", "y\nz\n");
    let shape: Vec<(DiffKind, &str)> = d.iter().map(|l| (l.kind, l.text.as_str())).collect();
    assert_eq!(
        shape,
        [
            (DiffKind::Original, "x"),
            (DiffKind::Same, "y"),
            (DiffKind::Rewritten, "z"),
        ]
    );
    assert!(line_diff("", "").is_empty());
    // A long text is cut, not slow.
    let long: String = (0..2000).map(|i| format!("{i}\n")).collect();
    assert!(line_diff(&long, &long).len() <= 400);
}
