//! The repair loop, callee reuse and staleness, offline: a `ReplayProvider` plays the model, a
//! fake verifier plays the sandboxed differential test, and units go through a real
//! `rewrite.sqlite` (in memory). Nothing here needs Ghidra or the sandbox.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use kraken_agent::{
    Cassette, CassetteEntry, ChatProvider, Fingerprint, FinishReason, ReplayProvider, StreamEvent,
};
use kraken_registry::commands::{RewriteMode, UnitStatus};
use kraken_rewrite::RewriteError;
use kraken_rewrite::abi::{Arg, Observation, Signature, Termination};
use kraken_rewrite::difftest::{Counterexample, DiffReport, Verdict};
use kraken_rewrite::fetch::FunctionContext;
use kraken_rewrite::infer::infer_signature;
use kraken_rewrite::repair::{self, Attempt, Feedback, RepairRound, feedback_for};
use kraken_rewrite::reuse;
use kraken_rewrite::store::{RewriteStore, stale_reason};
use kraken_rewrite::task::{Budget, RewriteTask};
use kraken_rewrite::unit::{
    CalleeRef, OracleInfo, Provenance, ReusedUnit, RewriteUnit, UnitSource, sha256_hex,
};
use tokio_util::sync::CancellationToken;

const SHA: &str = "feedface";

fn sig(name: &str) -> Signature {
    infer_signature("int f(int a)", name).expect("signature")
}

fn function(name: &str, address: u64, decompile: &str) -> FunctionContext {
    FunctionContext {
        name: name.into(),
        address,
        signature: Some("int f(int a)".into()),
        decompile: decompile.into(),
        decompile_hash: sha256_hex(decompile),
        program_sha256: SHA.into(),
        image_base: 0,
    }
}

fn task_for(f: &FunctionContext) -> RewriteTask {
    RewriteTask {
        function: f.clone(),
        callees: Vec::new(),
        signature: sig(&f.name),
        layout_notes: String::new(),
        spec: None,
        reused: Vec::new(),
        repairs: Vec::new(),
        budget: Budget::default(),
    }
}

fn code(name: &str, body: &str) -> String {
    format!("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {name}(a: i32) -> i32 {{ {body} }}")
}

fn reply(rust: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta {
            text: RewriteTask::reply_text(rust, &[]),
        },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

fn report(verdict: Verdict, counterexamples: Vec<Counterexample>) -> DiffReport {
    DiffReport {
        verdict,
        seed: 1,
        cases_run: 10,
        passed: 10,
        skipped: 0,
        counterexamples,
        cases: Vec::new(),
        sandbox: "test".into(),
    }
}

fn counterexample() -> Counterexample {
    let obs = |ret| Observation {
        termination: Termination::Returned,
        ret: Some(ret),
        buffers: Vec::new(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        callbacks: Vec::new(),
        global_writes: Vec::new(),
        instructions: 0,
    };
    Counterexample {
        args: vec![Arg::Int { value: u64::MAX }],
        original: obs(0),
        translation: obs(1),
        differences: vec!["return value: original Some(0), translation Some(1)".into()],
    }
}

/// A unit as the verifier would build it for `attempt` of `f`.
fn unit_of(
    f: &FunctionContext,
    attempt: &Attempt,
    callees: Vec<CalleeRef>,
    verdict: Verdict,
    cx: Vec<Counterexample>,
) -> RewriteUnit {
    let mut unit = RewriteUnit::from_run(
        UnitSource {
            mode: RewriteMode::Incremental,
            spec_id: None,
            anchor: f.anchor(),
            source_decompile_hash: f.decompile_hash.clone(),
            callees,
            signature: sig(&f.name),
            provenance: attempt.provenance.clone(),
            oracle: OracleInfo {
                kind: "test".into(),
                emulator: "test".into(),
                binary: "t".into(),
                elf_vaddr: f.address,
            },
        },
        attempt.output.rust_code.clone(),
        report(verdict, cx),
    );
    unit.repair = Some(attempt.link.clone());
    unit
}

fn accepted_unit(store: &RewriteStore, f: &FunctionContext, body: &str) -> RewriteUnit {
    let attempt = Attempt {
        output: kraken_rewrite::task::RewriteOutput {
            rust_code: code(&f.name, body),
            assumptions: vec![],
            unsupported: vec![],
        },
        provenance: Provenance {
            author: "model".into(),
            provider: Some("replay".into()),
            model: Some("cassette".into()),
            task: "rewrite_function".into(),
            prompt_hash: "p".into(),
        },
        link: kraken_rewrite::unit::RepairLink {
            attempt: 1,
            repair_of: None,
            feedback: None,
        },
    };
    let u = store
        .put_unit(unit_of(f, &attempt, vec![], Verdict::Pass, vec![]))
        .expect("put");
    store.accept(&u.id, "tester").expect("accept");
    store.get(&u.id).expect("get").expect("unit")
}

#[tokio::test]
async fn a_compile_error_is_fed_back_and_the_second_attempt_is_a_new_version() {
    let f = function("twice", 0x401000, "int twice(int a) { return a * 2; }");
    let task = task_for(&f);
    let bad = code("twice", "a.wrapping_mul(2) +");
    let good = code("twice", "a.wrapping_mul(2)");
    let error = "does not compile: error[E0308]: expected `i32`, found `()` --> translation.rs:2";

    // The cassette holds the exact second prompt the loop must build.
    let mut second = task.clone();
    second.repairs.push(RepairRound {
        previous_code: bad.clone(),
        feedback: Feedback {
            kind: "compile",
            text: error.into(),
        },
    });
    let cassette = Cassette {
        entries: vec![
            CassetteEntry {
                fingerprint: Fingerprint::of(&task.request()),
                events: reply(&bad),
            },
            CassetteEntry {
                fingerprint: Fingerprint::of(&second.request()),
                events: reply(&good),
            },
        ],
        ..Cassette::default()
    };
    let provider = ReplayProvider::new(cassette);
    let store = Arc::new(RewriteStore::open_in_memory().expect("store"));

    let run = repair::run(
        &task,
        &provider,
        CancellationToken::new(),
        3,
        |attempt: Attempt| {
            let (store, f) = (store.clone(), f.clone());
            async move {
                let verdict = if attempt.link.attempt == 1 {
                    Verdict::Rejected {
                        reason: error.into(),
                    }
                } else {
                    Verdict::Pass
                };
                store.put_unit(unit_of(&f, &attempt, vec![], verdict, vec![]))
            }
        },
    )
    .await
    .expect("run");

    assert_eq!(run.attempts.len(), 2);
    let (u1, u2) = (&run.attempts[0].0, &run.attempts[1].0);
    assert_eq!((u1.version, u1.status), (1, UnitStatus::Failed));
    assert_eq!((u2.version, u2.status), (2, UnitStatus::Verified));
    assert_eq!(u1.provenance.task, "rewrite_function");
    assert_eq!(u2.provenance.task, "rewrite_function/repair");
    assert_ne!(u1.provenance.prompt_hash, u2.provenance.prompt_hash);

    // Both attempts are stored, with the link between them.
    let stored = store.versions(SHA, "0x401000").expect("versions");
    assert_eq!(stored.len(), 2);
    let link = stored[1].repair.as_ref().expect("repair link");
    assert_eq!(
        (link.attempt, link.repair_of, link.feedback.as_deref()),
        (2, Some(1), Some("compile"))
    );
    assert_eq!(stored[0].repair.as_ref().map(|r| r.attempt), Some(1));
    assert_eq!(stored[0].repair.as_ref().and_then(|r| r.repair_of), None);
}

#[tokio::test]
async fn the_repair_prompt_carries_code_and_evidence_in_untrusted_blocks() {
    let f = function("twice", 0x401000, "int twice(int a) { return a * 2; }");
    let mut task = task_for(&f);
    let bad = code("twice", "a");
    let unit = {
        let attempt = Attempt {
            output: kraken_rewrite::task::RewriteOutput {
                rust_code: bad.clone(),
                assumptions: vec![],
                unsupported: vec![],
            },
            provenance: Provenance {
                author: "model".into(),
                provider: None,
                model: None,
                task: "t".into(),
                prompt_hash: "p".into(),
            },
            link: kraken_rewrite::unit::RepairLink {
                attempt: 1,
                repair_of: None,
                feedback: None,
            },
        };
        unit_of(&f, &attempt, vec![], Verdict::Fail, vec![counterexample()])
    };
    let fb = feedback_for(&unit).expect("a failed unit gives feedback");
    assert_eq!(fb.kind, "counterexample");
    assert!(fb.text.contains("-1 (0xffffffffffffffff)"), "{}", fb.text);
    assert!(fb.text.contains("return value"), "{}", fb.text);
    task.repairs.push(RepairRound {
        previous_code: bad,
        feedback: fb,
    });
    let user = match &task.request().messages[0] {
        kraken_agent::Message::User { content } => content.clone(),
        other => panic!("{other:?}"),
    };
    assert!(user.contains("<previous-code untrusted=\"true\">"));
    assert!(user.contains("<feedback untrusted=\"true\" kind=\"counterexample\">"));
    assert!(user.contains("it behaves differently from the original"));
    assert!(user.contains("complete corrected Rust source"));
}

#[tokio::test]
async fn only_failures_are_repaired_and_the_loop_is_bounded() {
    let f = function("twice", 0x401000, "int twice(int a) { return a * 2; }");
    let task = task_for(&f);

    // A run that never passes stops at the bound.
    let provider = ReplayProvider::scripted(vec![reply(&code("twice", "a"))]);
    let calls = Arc::new(AtomicU32::new(0));
    let c2 = calls.clone();
    let run = repair::run(
        &task,
        &provider,
        CancellationToken::new(),
        3,
        |attempt: Attempt| {
            c2.fetch_add(1, Ordering::SeqCst);
            let f = f.clone();
            async move {
                Ok(unit_of(
                    &f,
                    &attempt,
                    vec![],
                    Verdict::Fail,
                    vec![counterexample()],
                ))
            }
        },
    )
    .await
    .expect("run");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(run.attempts.len(), 3);
    assert_eq!(run.last().0.status, UnitStatus::Failed);
    let chain: Vec<Option<u32>> = run
        .attempts
        .iter()
        .map(|(u, _)| u.repair.as_ref().and_then(|r| r.repair_of))
        .collect();
    assert_eq!(chain, vec![None, Some(0), Some(0)]);

    // max_attempts 1 turns the loop off.
    let calls = Arc::new(AtomicU32::new(0));
    let c2 = calls.clone();
    let run = repair::run(
        &task,
        &provider,
        CancellationToken::new(),
        1,
        |attempt: Attempt| {
            c2.fetch_add(1, Ordering::SeqCst);
            let f = f.clone();
            async move { Ok(unit_of(&f, &attempt, vec![], Verdict::Fail, vec![])) }
        },
    )
    .await
    .expect("run");
    assert_eq!((calls.load(Ordering::SeqCst), run.attempts.len()), (1, 1));

    // An inconclusive run is not something the model can fix.
    let calls = Arc::new(AtomicU32::new(0));
    let c2 = calls.clone();
    repair::run(
        &task,
        &provider,
        CancellationToken::new(),
        3,
        |attempt: Attempt| {
            c2.fetch_add(1, Ordering::SeqCst);
            let f = f.clone();
            async move {
                Ok(unit_of(
                    &f,
                    &attempt,
                    vec![],
                    Verdict::Inconclusive {
                        reason: "mostly skipped".into(),
                    },
                    vec![],
                ))
            }
        },
    )
    .await
    .expect("run");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unusable_reply_is_an_error_first_and_an_attempt_later() {
    let f = function("twice", 0x401000, "int twice(int a) { return a * 2; }");
    let task = task_for(&f);
    let garbage = vec![
        StreamEvent::TextDelta {
            text: "I cannot do that".into(),
        },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ];

    let provider = ReplayProvider::scripted(vec![garbage.clone()]);
    let err = repair::run(&task, &provider, CancellationToken::new(), 3, |_a| async {
        Err(RewriteError::Cancelled)
    })
    .await
    .expect_err("first reply unusable");
    assert!(matches!(err, RewriteError::Output(_)), "{err}");

    // Second reply unusable: the model is told and answers again.
    let provider = ReplayProvider::scripted(vec![
        reply(&code("twice", "a")),
        garbage,
        reply(&code("twice", "a.wrapping_mul(2)")),
    ]);
    let run = repair::run(
        &task,
        &provider,
        CancellationToken::new(),
        4,
        |attempt: Attempt| {
            let f = f.clone();
            async move {
                let (v, cx) = if attempt.output.rust_code.contains("wrapping_mul") {
                    (Verdict::Pass, vec![])
                } else {
                    (Verdict::Fail, vec![counterexample()])
                };
                Ok(unit_of(&f, &attempt, vec![], v, cx))
            }
        },
    )
    .await
    .expect("run");
    assert_eq!(run.attempts.len(), 2);
    assert_eq!(run.last().0.status, UnitStatus::Verified);
    assert_eq!(run.last().0.repair.as_ref().map(|r| r.attempt), Some(3));
    assert_eq!(
        run.last()
            .0
            .repair
            .as_ref()
            .and_then(|r| r.feedback.clone()),
        Some("reply".to_string())
    );
}

#[tokio::test]
async fn a_cancelled_run_stops_before_asking_again() {
    let f = function("twice", 0x401000, "int twice(int a) { return a * 2; }");
    let task = task_for(&f);
    let provider = ReplayProvider::scripted(vec![reply(&code("twice", "a"))]);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = repair::run(&task, &provider, cancel, 3, |_a| async {
        Err(RewriteError::Cancelled)
    })
    .await
    .expect_err("cancelled");
    assert!(matches!(err, RewriteError::Cancelled));
}

// ----- reuse -----

#[test]
fn accepted_callees_are_reused_only_while_current() {
    let store = RewriteStore::open_in_memory().expect("store");
    let helper = function("helper", 0x401100, "int helper(int a) { return a + 1; }");
    let other = function("other", 0x401200, "int other(int a) { return a - 1; }");
    let top = function("top", 0x401300, "int top(int a) { return helper(a); }");
    accepted_unit(&store, &helper, "a.wrapping_add(1)");

    let r = reuse::resolve(&store, SHA, top.address, &[helper.clone(), other.clone()])
        .expect("resolve");
    assert_eq!(r.direct.len(), 1);
    assert_eq!(r.direct[0].symbol(), "helper");
    assert_eq!(
        r.remaining
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        ["other"]
    );

    // The callee's decompile changed: its accepted unit is out of date, translate it again.
    let changed = function("helper", 0x401100, "int helper(int a) { return a + 2; }");
    let r = reuse::resolve(&store, SHA, top.address, &[changed]).expect("resolve");
    assert!(r.direct.is_empty());
    assert_eq!(r.remaining.len(), 1);

    // A function never reuses itself.
    let r = reuse::resolve(&store, SHA, helper.address, std::slice::from_ref(&helper))
        .expect("resolve");
    assert!(r.direct.is_empty());
}

#[test]
fn the_prompt_lists_reused_callees_and_refuses_a_redefinition() {
    let store = RewriteStore::open_in_memory().expect("store");
    let helper = function("helper", 0x401100, "int helper(int a) { return a + 1; }");
    let top = function("top", 0x401300, "int top(int a) { return helper(a); }");
    accepted_unit(&store, &helper, "a.wrapping_add(1)");
    let r =
        reuse::resolve(&store, SHA, top.address, std::slice::from_ref(&helper)).expect("resolve");

    let mut task = task_for(&top);
    task.callees = r.remaining.clone();
    task.reused = r.direct.clone();
    let user = match &task.request().messages[0] {
        kraken_agent::Message::User { content } => content.clone(),
        other => panic!("{other:?}"),
    };
    assert!(user.contains("Already translated callees"));
    assert!(r.direct[0].prototype.contains("fn helper("));
    assert!(user.contains(&r.direct[0].prototype), "{user}");
    assert!(
        !user.contains("<callee "),
        "a reused callee is not translated again"
    );

    let ok = code("top", "unsafe { helper(a) }");
    assert!(task.parse(&RewriteTask::reply_text(&ok, &[])).is_ok());
    let redefines = format!("{ok}\n{}", code("helper", "0"));
    let err = task
        .parse(&RewriteTask::reply_text(&redefines, &[]))
        .expect_err("redefinition");
    assert!(err.to_string().contains("already translated"), "{err}");
}

#[test]
fn a_reuse_chain_brings_its_dependencies_first_and_the_export_checks_versions() {
    let store = RewriteStore::open_in_memory().expect("store");
    let inner = function("inner", 0x401100, "int inner(int a) { return a + 1; }");
    let mid = function("mid", 0x401200, "int mid(int a) { return inner(a); }");
    let top = function("top", 0x401300, "int top(int a) { return mid(a); }");
    accepted_unit(&store, &inner, "a.wrapping_add(1)");

    // mid was translated against the accepted inner.
    let inner_ru = reuse::resolve(&store, SHA, mid.address, std::slice::from_ref(&inner))
        .expect("resolve")
        .direct;
    let attempt = Attempt {
        output: kraken_rewrite::task::RewriteOutput {
            rust_code: code("mid", "unsafe { inner(a) }"),
            assumptions: vec![],
            unsupported: vec![],
        },
        provenance: Provenance {
            author: "model".into(),
            provider: None,
            model: None,
            task: "t".into(),
            prompt_hash: "p".into(),
        },
        link: kraken_rewrite::unit::RepairLink {
            attempt: 1,
            repair_of: None,
            feedback: None,
        },
    };
    let mid_unit = store
        .put_unit(unit_of(
            &mid,
            &attempt,
            inner_ru.iter().map(|r| r.callee_ref()).collect(),
            Verdict::Pass,
            vec![],
        ))
        .expect("put");
    store.accept(&mid_unit.id, "tester").expect("accept");

    let r = reuse::resolve(&store, SHA, top.address, std::slice::from_ref(&mid)).expect("resolve");
    assert_eq!(r.direct.len(), 1);
    assert_eq!(
        r.all.iter().map(|c| c.symbol()).collect::<Vec<_>>(),
        ["inner", "mid"],
        "dependencies come first"
    );
    let pre = reuse::prelude(&r.all, &r.direct);
    assert!(
        pre.find("mod __kr_callee_401100").unwrap() < pre.find("mod __kr_callee_401200").unwrap()
    );
    assert!(pre.contains("use super::__kr_callee_401100::inner;"));
    assert!(pre.contains("use __kr_callee_401200::mid;"));

    // If inner's accepted unit goes away, mid can no longer be reused.
    let store2 = RewriteStore::open_in_memory().expect("store");
    let unit = store.get(&mid_unit.id).expect("get").expect("mid");
    store2.put_unit(unit).expect("put");
    let again =
        reuse::resolve(&store2, SHA, top.address, std::slice::from_ref(&mid)).expect("resolve");
    assert!(again.direct.is_empty());

    // The export checks that the reused callee is accepted at the version it was tested with.
    let reused = store.get(&mid_unit.id).expect("get").expect("mid");
    let exported = |v: u32| {
        move |a: u64| (a == 0x401100).then(|| ("u_inner".to_string(), v, "inner".to_string()))
    };
    let uses = reuse::export_uses(&reused, &exported(1)).expect("same version");
    assert_eq!(uses, "use super::u_inner::inner;\n");
    let err = reuse::export_uses(&reused, &exported(2)).expect_err("other version");
    assert!(err.to_string().contains("translate mid again"), "{err}");
    let err = reuse::export_uses(&reused, &|_| None).expect_err("callee missing");
    assert!(err.to_string().contains("not among the accepted"), "{err}");
}

#[test]
fn reuse_survives_the_store_round_trip() {
    let store = RewriteStore::open_in_memory().expect("store");
    let inner = function("inner", 0x401100, "int inner(int a) { return a + 1; }");
    let u = accepted_unit(&store, &inner, "a");
    let callee = CalleeRef {
        name: "inner".into(),
        address: "0x401100".into(),
        decompile_hash: inner.decompile_hash.clone(),
        reused: Some(ReusedUnit {
            unit: u.id.clone(),
            version: u.version,
            symbol: "inner".into(),
        }),
    };
    let json = serde_json::to_string(&callee).expect("json");
    assert_eq!(
        serde_json::from_str::<CalleeRef>(&json).expect("back"),
        callee
    );
    // Records written before reuse existed have no `reused` key.
    let old = r#"{"name":"x","address":"0x1","decompile_hash":"h"}"#;
    assert!(
        serde_json::from_str::<CalleeRef>(old)
            .expect("old")
            .reused
            .is_none()
    );
}

// ----- staleness -----

#[test]
fn a_version_goes_stale_when_its_decompile_or_a_callee_changes() {
    let store = RewriteStore::open_in_memory().expect("store");
    let helper = function("helper", 0x401100, "int helper(int a) { return a + 1; }");
    let top = function("top", 0x401300, "int top(int a) { return helper(a); }");
    let attempt = Attempt {
        output: kraken_rewrite::task::RewriteOutput {
            rust_code: code("top", "a"),
            assumptions: vec![],
            unsupported: vec![],
        },
        provenance: Provenance {
            author: "model".into(),
            provider: None,
            model: None,
            task: "t".into(),
            prompt_hash: "p".into(),
        },
        link: kraken_rewrite::unit::RepairLink {
            attempt: 1,
            repair_of: None,
            feedback: None,
        },
    };
    let callee = CalleeRef {
        name: "helper".into(),
        address: "0x401100".into(),
        decompile_hash: helper.decompile_hash.clone(),
        reused: None,
    };
    let u = store
        .put_unit(unit_of(&top, &attempt, vec![callee], Verdict::Pass, vec![]))
        .expect("put");
    store.accept(&u.id, "tester").expect("accept");

    // Storing a unit records the hashes it was made from; nothing is stale.
    assert!(store.stale_reasons(SHA).expect("stale").is_empty());
    assert_eq!(store.summaries(SHA).expect("summaries")[0].stale, None);

    // The callee's decompile changes.
    store
        .observe(
            SHA,
            &[(
                "0x401100".into(),
                sha256_hex("int helper(int a) { return a + 3; }"),
            )],
        )
        .expect("observe");
    let stale = store.stale_reasons(SHA).expect("stale");
    assert!(stale["0x401300"].contains("callee `helper`"), "{stale:?}");
    assert!(store.summaries(SHA).expect("summaries")[0].stale.is_some());

    // The function's own decompile changes too.
    store
        .observe(
            SHA,
            &[(
                "0x401300".into(),
                sha256_hex("int top(int a) { return 0; }"),
            )],
        )
        .expect("observe");
    assert!(
        store.stale_reasons(SHA).expect("stale")["0x401300"].contains("the function's decompile")
    );

    // Translating again from the new decompile makes the new version current, and the
    // translation is no longer stale.
    let new_top = function("top", 0x401300, "int top(int a) { return 0; }");
    let new_helper = function("helper", 0x401100, "int helper(int a) { return a + 3; }");
    let callee = CalleeRef {
        name: "helper".into(),
        address: "0x401100".into(),
        decompile_hash: new_helper.decompile_hash.clone(),
        reused: None,
    };
    store
        .put_unit(unit_of(
            &new_top,
            &attempt,
            vec![callee],
            Verdict::Pass,
            vec![],
        ))
        .expect("put");
    // The accepted version is still the old one, so the function stays stale until the new
    // version is accepted: acceptance is the user's call.
    assert!(!store.stale_reasons(SHA).expect("stale").is_empty());
    let newest = store
        .latest(SHA, "0x401300")
        .expect("latest")
        .expect("unit");
    store.accept(&newest.id, "tester").expect("accept");
    assert!(store.stale_reasons(SHA).expect("stale").is_empty());
}

#[test]
fn stale_reason_ignores_functions_that_were_never_observed() {
    let callees = vec![CalleeRef {
        name: "c".into(),
        address: "0x20".into(),
        decompile_hash: "old".into(),
        reused: None,
    }];
    let mut seen = std::collections::BTreeMap::new();
    assert_eq!(stale_reason("0x10", "h", &callees, &seen), None);
    seen.insert("0x10".to_string(), "h".to_string());
    assert_eq!(stale_reason("0x10", "h", &callees, &seen), None);
    seen.insert("0x20".to_string(), "new".to_string());
    assert!(stale_reason("0x10", "h", &callees, &seen).is_some());
}

#[test]
fn the_provider_is_an_ordinary_chat_provider() {
    // Guards the trait-object use in the service: `run` takes `&dyn ChatProvider`.
    let p: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![reply("x")]));
    assert_eq!(p.info().id, "replay");
}
