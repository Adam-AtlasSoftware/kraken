//! Tests of the unit controls (reject, unaccept, replay, add a case) and of the Check rows that
//! come from `rewrite_check`.

use super::tests::{base, done, opened, version_result};
use super::*;
use crate::ToastLevel;
use serde_json::json;

fn unit_reply(units: &[(&str, u32, &str)]) -> serde_json::Value {
    let versions: Vec<_> = units
        .iter()
        .map(|(unit, version, status)| {
            let mut v = version_result(unit, *version, status, "pass");
            v["accepted"] = json!(*status == "accepted");
            v["rust_code"] =
                json!({"untrusted": true, "value": "pub unsafe extern \"C\" fn checksum() {}"});
            v
        })
        .collect();
    json!({"address": "0x401240", "versions": versions})
}

#[test]
fn reject_and_unaccept_send_the_unit_that_is_listed() {
    let b = base()
        .reply(
            "rewrite_unit",
            unit_reply(&[("ru-1", 1, "accepted"), ("ru-2", 2, "verified")]),
        )
        .reply(
            "rewrite_reject",
            json!({"status": "failed", "unit": "ru-2", "address": "0x401240", "version": 2}),
        )
        .reply(
            "rewrite_unaccept",
            json!({"status": "verified", "unit": "ru-1", "address": "0x401240", "version": 1}),
        );
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    r.idle();
    assert_eq!(
        r.vm.rewrite
            .rejectable_unit(0x401240)
            .map(|v| v.unit.as_str()),
        Some("ru-2"),
        "the newest version can be rejected"
    );
    assert_eq!(
        r.vm.rewrite
            .accepted_version(0x401240)
            .map(|v| v.unit.as_str()),
        Some("ru-1")
    );
    r.vm.rewrite_reject(0x401240);
    r.idle();
    assert_eq!(r.backend.calls_to("rewrite_reject")[0]["unit"], "ru-2");
    r.vm.rewrite_unaccept(0x401240);
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_unaccept")[0],
        json!({"unit": "ru-1"})
    );
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.contains("no longer accepted"))
    );
    // The unit list is read again after a change.
    assert!(r.backend.calls_to("rewrite_unit").len() >= 3);
}

#[test]
fn nothing_is_sent_for_a_function_without_a_listed_unit() {
    let b = base().reply("rewrite_unit", json!({"versions": []}));
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    r.idle();
    r.vm.rewrite_reject(0x401240);
    r.vm.rewrite_unaccept(0x401240);
    r.vm.rewrite_verify(0x401240);
    assert!(r.vm.rewrite_add_case(0x401240, "1").is_err());
    r.idle();
    for c in [
        "rewrite_reject",
        "rewrite_unaccept",
        "rewrite_verify",
        "rewrite_add_case",
    ] {
        assert!(r.backend.calls_to(c).is_empty(), "{c}");
    }
}

#[test]
fn a_replay_shows_its_coverage_and_a_typed_case_is_sent_as_json() {
    let b = base()
        .reply("rewrite_unit", unit_reply(&[("ru-2", 2, "verified")]))
        .reply("rewrite_verify", json!({"job_id": "job-v"}))
        .reply("rewrite_add_case", json!({"job_id": "job-c"}));
    let mut r = opened(b);
    r.vm.rewrite_select(0x401240);
    r.idle();
    r.vm.rewrite_verify(0x401240);
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_verify")[0],
        json!({"unit": "ru-2"})
    );
    assert!(r.vm.rewrite.verifying(0x401240));
    let mut result = version_result("ru-2", 2, "verified", "pass");
    result["coverage"] = json!({"blocks": 5, "hit": 4, "missed": ["0x401260"], "cases": 200});
    result["user_cases"] = json!(0);
    r.backend.emit(done("job-v", "rewrite_verify", result));
    r.until("replay done", |vm| !vm.rewrite.verifying(0x401240));
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.contains("4 of 5 blocks") && t.level == ToastLevel::Success),
        "{:?}",
        r.vm.toasts
            .iter()
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
    );

    let bad = r.vm.rewrite_add_case(0x401240, "{not json");
    assert!(bad.is_err_and(|e| e.contains("not JSON")));
    r.vm.rewrite_add_case(0x401240, "5, {\"text\": \"abc\"}")
        .expect("case");
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_add_case")[0],
        json!({"unit": "ru-2", "args": [5, {"text": "abc"}]})
    );
}

#[test]
fn coverage_in_a_stored_version_is_read_back() {
    let mut reply = unit_reply(&[("ru-2", 2, "verified")]);
    reply["versions"][0]["coverage"] = json!({"blocks": 3, "hit": 3, "missed": [], "cases": 40});
    reply["versions"][0]["user_cases"] = json!(2);
    let mut r = opened(base().reply("rewrite_unit", reply));
    r.vm.rewrite_select(0x401240);
    r.idle();
    let v = r.vm.rewrite.details[&0x401240]
        .current()
        .expect("version")
        .clone();
    let c = v.coverage.expect("coverage");
    assert!(c.complete());
    assert_eq!(c.line(), "3 of 3 blocks");
    assert_eq!(v.user_cases, 2);
}

#[test]
fn the_check_step_lists_the_requirements_the_daemon_found() {
    let b = base().reply(
        "rewrite_check",
        json!({"ready": false, "checks": [
            {"id": "sandbox", "title": "Sandbox", "level": "ok", "detail": "confined"},
            {"id": "toolchain", "title": "Rust toolchain", "level": "blocked",
             "detail": "rustc could not be run.", "fix": "Install Rust with rustup."},
            {"id": "specs", "title": "Spec files", "level": "warn",
             "detail": "No SLEIGH files.", "fix": "Run `kraken setup --native`."},
            {"id": "program", "title": "Program", "level": "ok", "detail": "x86-64 ELF"},
        ]}),
    );
    let mut r = opened(b);
    r.vm.rewrite_wizard_open();
    r.idle();
    let checks = r.vm.rewrite_wizard_checks();
    let find = |t: &str| checks.iter().find(|c| c.title == t).expect(t);
    let tool = find("Rust toolchain");
    assert_eq!(tool.level, CheckLevel::Blocked);
    assert!(tool.detail.contains("rustup"));
    assert_eq!(tool.fix.as_deref(), Some("Install Rust with rustup."));
    assert_eq!(find("Spec files").level, CheckLevel::Warn);
    assert_eq!(find("Program").level, CheckLevel::Ok);
    assert_eq!(find("Program").fix, None);
    assert!(
        checks.iter().filter(|c| c.title == "Sandbox").count() == 1,
        "the sandbox row is not listed twice"
    );
}

#[test]
fn a_daemon_without_rewrite_check_leaves_the_other_rows() {
    let mut r = opened(base());
    r.vm.rewrite_wizard_open();
    r.idle();
    let checks = r.vm.rewrite_wizard_checks();
    assert!(checks.iter().any(|c| c.title == "Assistant"));
    assert!(checks.iter().all(|c| c.title != "Spec files"));
}

#[test]
fn harvesting_sends_the_input_and_reports_what_was_recorded_and_held_out() {
    let b = base().reply("rewrite_harvest", json!({"job_id": "job-h"}));
    let mut r = opened(b);
    r.vm.rewrite_harvest(0x401240, "-v  in.txt", "hello\n");
    r.idle();
    assert_eq!(
        r.backend.calls_to("rewrite_harvest")[0],
        json!({"address": "0x401240", "argv": ["-v", "in.txt"], "stdin": "hello\n"})
    );
    assert!(r.vm.rewrite.harvesting(0x401240));
    r.backend.emit(done(
        "job-h",
        "rewrite_harvest",
        json!({"hits": 9, "total_train": 6, "total_held_out": 3}),
    ));
    r.until("harvest done", |vm| !vm.rewrite.harvesting(0x401240));
    assert!(
        r.vm.toasts
            .iter()
            .any(|t| t.text.contains("6 recorded inputs") && t.text.contains("3 held out")),
        "{:?}",
        r.vm.toasts
            .iter()
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
    );
}
