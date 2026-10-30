//! The Run dialog over a scripted backend: what it sends to `emulate_run` and `emulate_compare`
//! and what the Emulation tab gets back.

use super::*;
use crate::navtools::{EmulateMode, EmulationResult};

fn run_out(stdout: &str, code: i64) -> Value {
    json!({
        "exit": {"kind": "code", "value": code},
        "stdout": u(stdout),
        "stderr": u(""),
        "steps": 1200,
        "truncated": false,
        "notes": ["architecture x86_64"],
        "files": [{
            "name": "out.txt", "size": 4, "preview": u("done"), "binary": false, "truncated": false
        }],
    })
}

#[test]
fn a_run_sends_what_the_dialog_holds_and_fills_the_emulation_tab() {
    let mut r = opened(base_backend().on("emulate_run", |a| {
        assert_eq!(a["argv"], json!(["-v"]));
        assert_eq!(a["stdin"], "hi\n");
        assert_eq!(a["env"], json!({"MODE": "fast"}));
        assert_eq!(a["inputs"], json!([{"name": "in.txt", "text": "x"}]));
        assert_eq!(a["patched"], false);
        assert_eq!(a["return_files"], true);
        Ok(run_out("hello\n", 0))
    }));
    r.vm.begin_emulate(EmulateMode::Run);
    let d = r.vm.tools.emulate_dialog.as_mut().expect("dialog");
    d.argv = "-v".into();
    d.stdin = "hi\n".into();
    d.env = "MODE=fast".into();
    d.inputs.push(crate::navtools::InputRow {
        name: "in.txt".into(),
        text: "x".into(),
        binary: None,
    });
    r.vm.submit_emulate();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.tools.emulate_dialog.is_none(), "closed on success");
    let Some(EmulationResult::Run { patched, run, .. }) = r.vm.tools.emulation.result.clone()
    else {
        panic!("a run result");
    };
    assert!(!patched);
    assert_eq!((run.exit.as_str(), run.clean), ("exit code 0", true));
    assert_eq!(run.stdout, "hello\n");
    assert_eq!(run.files[0].name, "out.txt");
    assert_eq!(
        r.vm.tools.take_tab(),
        Some(crate::navtools::NavTab::Emulation)
    );
}

#[test]
fn a_comparison_keeps_both_runs_and_the_first_divergence() {
    let mut r = opened(base_backend().on("emulate_compare", |a| {
        assert_eq!(a["stdin"], "go\n");
        Ok(json!({
            "a": run_out("hash=1\n", 0),
            "b": run_out("HASH=1\n", 3),
            "same": false,
            "differences": [
                {"field": "stdout", "summary": u("line 1: \"hash=1\" vs \"HASH=1\"")},
                {"field": "exit", "summary": u("exit code 0 vs exit code 3")},
            ],
            "first_divergence": u("stdout: line 1: \"hash=1\" vs \"HASH=1\""),
        }))
    }));
    r.vm.begin_emulate(EmulateMode::Compare);
    r.vm.tools.emulate_dialog.as_mut().expect("dialog").stdin = "go\n".into();
    r.vm.submit_emulate();
    assert!(r.vm.block_until_idle(WAIT));
    let Some(EmulationResult::Compare {
        a,
        b,
        same,
        differences,
        first_divergence,
        ..
    }) = r.vm.tools.emulation.result.clone()
    else {
        panic!("a comparison");
    };
    assert!(!same);
    assert_eq!(
        (a.stdout.as_str(), b.stdout.as_str()),
        ("hash=1\n", "HASH=1\n")
    );
    assert_eq!(b.exit, "exit code 3");
    assert_eq!(differences.len(), 2);
    assert!(first_divergence.starts_with("stdout: line 1"));
}

#[test]
fn a_failed_run_stays_in_the_dialog_with_the_reason() {
    let mut r = opened(base_backend().fail(
        "emulate_run",
        kraken_proto::ErrorCode::Unsupported,
        "the emulator's child program `kraken-emu-run` was not found",
    ));
    r.vm.begin_emulate(EmulateMode::RunPatched);
    r.vm.submit_emulate();
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.tools.emulate_dialog.as_ref().expect("still open");
    assert!(!d.running);
    assert!(
        d.error
            .as_deref()
            .is_some_and(|e| e.contains("kraken-emu-run")),
        "{d:?}"
    );
    assert!(r.vm.tools.emulation.result.is_none());
}

#[test]
fn calling_a_function_sends_its_signature_filled_arguments_and_shows_the_value() {
    let mut r = opened(base_backend().on("emulate_call", |a| {
        assert_eq!(a["address"], "0x401040");
        assert_eq!(a["args"], json!([{"string": "level"}]));
        assert_eq!(a["returns"], "void");
        assert_eq!(a["libc"], true);
        Ok(json!({
            "address": "0x401040", "name": u("helper"), "ended": "returned", "detail": null,
            "value": {"kind": "i32", "hex": "0x7", "signed": 7, "unsigned": 7, "float": null},
            "buffers": [{
                "arg": 0, "address": "0x6000", "size": 6, "hex": u("6c6576656c00"),
                "text": u("LEVEL"), "changed": true
            }],
            "stdout": u(""), "stderr": u(""), "steps": 321, "notes": ["architecture x86_64"],
        }))
    }));
    r.vm.begin_call(0x401040);
    let d = r.vm.tools.call_dialog.as_mut().expect("dialog");
    assert_eq!(d.name, "helper");
    d.params.clear();
    d.params.push(crate::navtools::CallParam {
        label: "const char *s".into(),
        kind: crate::navtools::ParamKind::Text,
        value: "level".into(),
    });
    d.returns = "void".into();
    d.libc = true;
    r.vm.submit_call();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.tools.call_dialog.is_none(), "closed on success");
    let Some(EmulationResult::Call(c)) = r.vm.tools.emulation.result.clone() else {
        panic!("a call result");
    };
    assert_eq!(c.value.as_deref(), Some("7 (0x7)"));
    assert!(c.clean);
    assert_eq!(
        (c.buffers[0].text.as_str(), c.buffers[0].changed),
        ("LEVEL", true)
    );
    assert_eq!(
        r.vm.tools.take_tab(),
        Some(crate::navtools::NavTab::Emulation)
    );
}

#[test]
fn a_call_that_fails_stays_in_the_dialog_with_the_reason() {
    let mut r = opened(base_backend().fail(
        "emulate_call",
        kraken_proto::ErrorCode::NotFound,
        "the program has no main symbol: give startup_address",
    ));
    r.vm.begin_call(0x401040);
    r.vm.submit_call();
    assert!(r.vm.block_until_idle(WAIT));
    let d = r.vm.tools.call_dialog.as_ref().expect("still open");
    assert!(!d.running);
    assert!(
        d.error
            .as_deref()
            .is_some_and(|e| e.contains("startup_address")),
        "{d:?}"
    );
}

#[test]
fn verifying_sends_the_inputs_to_patch_verify_and_reloads_the_patches_with_the_verdict() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let verified = std::sync::Arc::new(AtomicBool::new(false));
    let (seen, listed) = (verified.clone(), verified.clone());
    let mut r = opened(
        base_backend()
            .on("patch_verify", move |a| {
                assert_eq!(a["argv"], json!(["-v"]));
                assert_eq!(a["stdin"], "1 + 2\n");
                assert_eq!(a["env"], json!({"MODE": "fast"}));
                seen.store(true, Ordering::SeqCst);
                Ok(json!({
                    "a": run_out("= 7\n", 0),
                    "b": run_out("= 5\n", 0),
                    "same": false,
                    "differences": [{"field": "stdout", "summary": u("line 1: \"= 7\" vs \"= 5\"")}],
                    "first_divergence": u("stdout: line 1: \"= 7\" vs \"= 5\""),
                    "verdict": {
                        "set_hash": "0123456789abcdef", "same": false,
                        "summary": u("stdout: line 1: \"= 7\" vs \"= 5\""), "ts_ms": 1,
                    },
                }))
            })
            .on("patch_list", move |_| {
                let mut p = json!({
                    "address": "0x401446", "original": "4801d0", "replacement": "4829d0",
                    "length": 3, "note": u(""), "author_kind": "user", "author_id": "adam",
                    "ts_ms": 1, "group": u(""), "enabled": true,
                });
                if listed.load(Ordering::SeqCst) {
                    p["verdict"] = json!({
                        "set_hash": "0123456789abcdef", "same": false,
                        "summary": u("stdout: line 1"), "ts_ms": 1,
                    });
                }
                Ok(json!({"items": [p], "next_cursor": null, "total": 1}))
            }),
    );
    r.vm.refresh_patches();
    assert!(r.vm.block_until_idle(WAIT));
    assert!(r.vm.tools.patches.items[0].verdict.is_none());

    r.vm.begin_emulate(EmulateMode::Verify);
    let d = r.vm.tools.emulate_dialog.as_mut().expect("dialog");
    d.argv = "-v".into();
    d.stdin = "1 + 2\n".into();
    d.env = "MODE=fast".into();
    r.vm.submit_emulate();
    assert!(r.vm.block_until_idle(WAIT));

    let Some(EmulationResult::Compare { same, a, b, .. }) = r.vm.tools.emulation.result.clone()
    else {
        panic!("the comparison");
    };
    assert!(!same);
    assert_eq!((a.stdout.as_str(), b.stdout.as_str()), ("= 7\n", "= 5\n"));
    let v = r.vm.tools.patches.items[0]
        .verdict
        .clone()
        .expect("the verdict shows after the reload");
    assert!(!v.same);
    assert!(v.summary.starts_with("stdout: line 1"));
}

#[test]
fn checking_patches_keeps_the_findings_until_the_patches_change() {
    let mut r = opened(base_backend().on("patch_lint", |_| {
        Ok(json!({
            "patches_checked": 2,
            "findings": [{
                "kind": "relocation", "severity": "warning", "address": "0x403010",
                "message": "the patch at 0x403010 overlaps a base relocation",
            }],
        }))
    }));
    r.vm.check_patches();
    assert!(r.vm.block_until_idle(WAIT));
    let l = r.vm.tools.patches.lint.clone().expect("a report");
    assert_eq!(l.checked, 2);
    assert_eq!(l.findings[0].address, Some(0x403010));
    assert_eq!(l.findings[0].severity, "warning");
    r.vm.refresh_patches();
    assert!(r.vm.tools.patches.lint.is_none(), "stale after a reload");
}
