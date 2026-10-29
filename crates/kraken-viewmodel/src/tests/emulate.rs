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
