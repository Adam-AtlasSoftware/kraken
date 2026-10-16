//! The loop end to end, offline: registry decompile (FakeEngine on a corpus fixture) -> task with
//! a cassette -> differential test under emulation -> versioned unit in a JSON store.

mod common;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use common::{config, corpus_bin};
use engine_fake::{FakeEngine, FixtureFile};
use kraken_agent::{
    AgentError, Cassette, CassetteEntry, ChatProvider, ChatRequest, Fingerprint, FinishReason,
    ReplayProvider, StreamEvent,
};
use kraken_engine::SharedEngine;
use kraken_host::backend::LocalBackend;
use kraken_proto::ProtoError;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::difftest::{DiffOptions, Verdict};
use kraken_rewrite::fetch::fetch_function;
use kraken_rewrite::oracle::FunctionOracle;
use kraken_rewrite::pipeline::{RewriteJob, job_for_target, rewrite_and_verify, verify};
use kraken_rewrite::targets::{Target, target, targets};
use kraken_rewrite::task::{RewriteTask, SpecScope, SpecTask};
use kraken_rewrite::unit::{Provenance, UnitStore};
use tokio_util::sync::CancellationToken;

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    backend: Arc<LocalBackend>,
}

/// A project over `binary` whose engine replays `corpus/fixtures/<binary>.json`.
async fn rig(binary: &str) -> Rig {
    let fx_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{binary}.json"));
    let fixture = FixtureFile::from_path(&fx_path).expect("fixture");
    let tmp = tempfile::Builder::new()
        .prefix("kraken-rewrite-test-")
        .tempdir()
        .expect("tempdir");
    let session = Arc::new(Session::new(Arc::new(FakeFactory { fixture })));
    session
        .create_project(&tmp.path().join("p"), &corpus_bin(binary))
        .await
        .expect("project");
    let registry = Arc::new(Registry::standard());
    let backend = Arc::new(LocalBackend::new(registry, session, None));
    Rig { _tmp: tmp, backend }
}

fn user() -> CallContext {
    CallContext::user("tester", Surface::Test)
}

fn reply_events(text: String) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta { text },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

fn entry(req: &ChatRequest, text: String) -> CassetteEntry {
    CassetteEntry {
        fingerprint: Fingerprint::of(req),
        events: reply_events(text),
    }
}

async fn job(t: &Target) -> (Rig, RewriteJob) {
    let r = rig(t.binary).await;
    let j = job_for_target(&*r.backend, &user(), t).await.expect("job");
    (r, j)
}

fn cassette_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("cassettes/rewrite-reference.json")
}

/// The cassette answering every target's rewrite request with its reference translation.
async fn build_cassette() -> Cassette {
    let mut c = Cassette::default();
    for t in targets() {
        let (_r, j) = job(&t).await;
        let req = j.task().request();
        c.entries
            .push(entry(&req, RewriteTask::reply_text(t.reference, &[])));
    }
    c
}

#[tokio::test]
async fn the_checked_in_cassette_matches_the_current_prompts() {
    let fresh = build_cassette().await;
    let path = cassette_path();
    if std::env::var_os("KRAKEN_UPDATE_CASSETTES").is_some() {
        fresh.save(&path).expect("save cassette");
    }
    let stored = Cassette::load(&path).unwrap_or_else(|e| {
        panic!("{e}; regenerate with KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite")
    });
    assert_eq!(
        stored, fresh,
        "the prompts or reference translations changed; regenerate the cassette with \
         KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test pipeline"
    );
}

#[tokio::test]
async fn registry_decompile_feeds_the_task_prompt() {
    let t = target("vm_run").expect("target");
    let (_r, j) = job(&t).await;
    assert_eq!(j.function.name, "vm_run");
    assert_eq!(j.function.image_base, 0x100000);
    assert_eq!(j.function.elf_vaddr(), 0x1255);
    assert!(
        j.function.decompile.contains("switch(uVar1)"),
        "{}",
        j.function.decompile
    );
    assert_eq!(j.callees.len(), 3);
    assert_eq!(j.function.program_sha256.len(), 64);

    let req = j.task().request();
    assert!(req.tools.is_empty());
    // Binary-derived text only ever sits inside untrusted blocks of the user message.
    assert!(!req.system.contains("vm_run"));
    assert!(!req.system.contains("switch(uVar1)"));
    let kraken_agent::Message::User { content } = &req.messages[0] else {
        panic!("user message expected");
    };
    assert!(content.contains("<decompile untrusted=\"true\">"));
    assert!(content.contains("<callee untrusted=\"true\" name=\"vm_fail\""));
    assert!(
        content.contains(
            "pub unsafe extern \"C\" fn vm_run(a0: *mut u8, a1: *mut u8, a2: u32) -> i32"
        )
    );
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn cassette_backed_rewrite_of_every_target_verifies_and_is_stored() {
    let provider = ReplayProvider::from_path(&cassette_path()).expect("cassette");
    for t in targets() {
        let (r, j) = job(&t).await;
        let mut oracle = FunctionOracle::load(&corpus_bin(t.binary), &config()).expect("oracle");
        let dir = r._tmp.path().join("p");
        let store = UnitStore::in_project(&dir);
        let opts = DiffOptions {
            random_cases: 60,
            ..DiffOptions::default()
        };
        let unit = rewrite_and_verify(
            &j,
            &provider,
            &mut oracle,
            &opts,
            Some(&store),
            CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", t.id));
        assert_eq!(
            unit.verdict,
            Verdict::Pass,
            "{}: {:?}",
            t.id,
            unit.counterexamples.first()
        );
        assert_eq!(unit.version, 1);
        assert_eq!(unit.summary.cases_run, unit.summary.passed);
        assert_eq!(unit.provenance.provider.as_deref(), Some("replay"));
        assert_eq!(unit.anchor.address, format!("{:#x}", j.function.address));
        assert_eq!(unit.source_decompile_hash, j.function.decompile_hash);
        assert_eq!(unit.callees.len(), t.callees.len());
        assert_eq!(unit.oracle.elf_vaddr, j.function.elf_vaddr());
        assert!(!unit.test_cases.is_empty());
        assert!(
            unit.rust_code
                .contains(&format!("extern \"C\" fn {}(", t.function))
        );

        // Persisted as JSON under the project dir and read back identically.
        assert!(dir.join("rewrite/units.json").is_file());
        let back = store
            .latest(&unit.anchor.address)
            .expect("read")
            .expect("unit");
        assert_eq!(back, unit);
    }
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn a_wrong_translation_is_stored_as_a_failed_version_with_its_counterexample() {
    let t = target("cmp_id").expect("target");
    let (r, j) = job(&t).await;
    let mut oracle = FunctionOracle::load(&corpus_bin(t.binary), &config()).expect("oracle");
    let store = UnitStore::in_project(&r._tmp.path().join("p"));
    let opts = DiffOptions {
        random_cases: 30,
        ..DiffOptions::default()
    };
    let prov = |author: &str| Provenance {
        author: author.into(),
        provider: None,
        model: None,
        task: "rewrite_function".into(),
        prompt_hash: String::new(),
    };
    let wrong = t.reference.replace(
        "(*a).id.wrapping_sub((*b).id)",
        "(*a).id.cmp(&(*b).id) as i32",
    );
    let bad = store
        .put(verify(&j, &wrong, prov("model"), &mut oracle, &opts).expect("verify"))
        .expect("put");
    assert_eq!(bad.verdict, Verdict::Fail);
    assert_eq!(bad.version, 1);
    assert!(!bad.counterexamples.is_empty());

    let good = store
        .put(verify(&j, t.reference, prov("reference"), &mut oracle, &opts).expect("verify"))
        .expect("put");
    assert_eq!(good.verdict, Verdict::Pass);
    assert_eq!(good.version, 2, "a new version for the same anchor");
    assert_ne!(good.id, bad.id);
    let all = store.list().expect("list");
    assert_eq!(all.len(), 2, "older versions are kept");
    assert_eq!(
        store
            .latest(&good.anchor.address)
            .expect("latest")
            .expect("unit")
            .id,
        good.id
    );
}

#[tokio::test]
async fn a_changed_prompt_misses_the_cassette_instead_of_returning_a_stale_answer() {
    let t = target("cmp_id").expect("target");
    let (_r, mut j) = job(&t).await;
    j.layout_notes.push_str("\nan extra note");
    let provider = ReplayProvider::from_path(&cassette_path()).expect("cassette");
    let err = j
        .task()
        .run(&provider, CancellationToken::new())
        .await
        .expect_err("miss");
    assert!(
        matches!(
            err,
            kraken_rewrite::RewriteError::Provider(AgentError::CassetteMiss(_))
        ),
        "{err}"
    );
}

struct Canned(String);

#[async_trait]
impl ChatProvider for Canned {
    fn info(&self) -> kraken_agent::ProviderInfo {
        kraken_agent::ProviderInfo {
            id: "canned".into(),
            model: "canned".into(),
            supports_tools: false,
            context_window: None,
        }
    }
    async fn complete(
        &self,
        _req: ChatRequest,
        _cancel: CancellationToken,
    ) -> Result<kraken_agent::ChatStream, AgentError> {
        let events: Vec<Result<StreamEvent, AgentError>> =
            reply_events(self.0.clone()).into_iter().map(Ok).collect();
        Ok(Box::pin(futures_util::stream::iter(events)))
    }
}

#[tokio::test]
async fn malformed_model_output_is_an_error_not_a_unit() {
    let t = target("cmp_id").expect("target");
    let (_r, j) = job(&t).await;
    let task = j.task();
    for bad in [
        "here is some prose and no code".to_string(),
        "<kraken-rust>\nfn something_else() {}\n</kraken-rust>".to_string(),
        RewriteTask::reply_text(t.reference, &[])
            .replace("{\"assumptions\": [], \"unsupported\": []}", "{nope}"),
    ] {
        let err = task
            .run(&Canned(bad.clone()), CancellationToken::new())
            .await
            .expect_err("bad output");
        assert!(
            matches!(err, kraken_rewrite::RewriteError::Output(_)),
            "{bad}: {err}"
        );
    }
    // A fenced block inside the tags is accepted.
    let fenced = format!(
        "<kraken-rust>\n```rust\n{}\n```\n</kraken-rust>",
        t.reference.trim()
    );
    let (out, _) = task
        .run(&Canned(fenced), CancellationToken::new())
        .await
        .expect("fenced");
    assert!(out.rust_code.starts_with("// Reference translation"));
}

// ----- behavioural specs -----

fn spec_cassette_provider(task: &SpecTask, md: &str) -> ReplayProvider {
    let c = Cassette {
        entries: vec![entry(&task.request(), md.to_string())],
        ..Cassette::default()
    };
    ReplayProvider::new(c)
}

async fn spec_task(binary: &str, scope: SpecScope, names: &[&str]) -> (Rig, SpecTask) {
    let r = rig(binary).await;
    let mut functions = Vec::new();
    for n in names {
        functions.push(
            fetch_function(&*r.backend, &user(), n)
                .await
                .expect("function"),
        );
    }
    (
        r,
        SpecTask {
            scope,
            functions,
            budget: Default::default(),
        },
    )
}

#[tokio::test]
async fn function_spec_with_citations_is_accepted_and_every_citation_is_checked() {
    let md = include_str!("../references/spec_vm_run.md");
    let (_r, task) = spec_task(
        "switch_vm-O0",
        SpecScope::Function,
        &["vm_run", "push", "pop", "vm_fail"],
    )
    .await;
    let provider = spec_cassette_provider(&task, md);
    let (spec, _) = task
        .run(&provider, CancellationToken::new())
        .await
        .expect("spec");
    assert_eq!(spec.scope, SpecScope::Function);
    assert!(spec.facts >= 12, "{}", spec.facts);
    assert_eq!(spec.citations, vec![0x101159, 0x101194, 0x1011f3, 0x101255]);
    assert!(spec.markdown.starts_with("# Behavioural spec: vm_run"));

    // The request carries the schema in the system prompt and the code only as untrusted data.
    let req = task.request();
    assert!(req.system.contains("## Side effects"));
    assert!(req.system.contains("[@0x401136]"));
    assert!(!req.system.contains("vm_run"));
}

#[tokio::test]
async fn program_spec_covers_the_functions_given() {
    let md = include_str!("../references/spec_calc.md");
    let names = [
        "evaluate",
        "parse_expr",
        "parse_term",
        "parse_atom",
        "parse_number",
        "skip_ws",
    ];
    let (_r, task) = spec_task("stripped_calc-O0", SpecScope::Program, &names).await;
    let provider = spec_cassette_provider(&task, md);
    let (spec, _) = task
        .run(&provider, CancellationToken::new())
        .await
        .expect("spec");
    assert_eq!(spec.scope, SpecScope::Program);
    assert_eq!(spec.citations.len(), 6, "{:x?}", spec.citations);
}

#[tokio::test]
async fn specs_with_uncited_facts_hallucinated_addresses_or_missing_sections_are_rejected() {
    let md = include_str!("../references/spec_vm_run.md");
    let (_r, task) = spec_task(
        "switch_vm-O0",
        SpecScope::Function,
        &["vm_run", "push", "pop", "vm_fail"],
    )
    .await;

    let uncited = md.replace(" [@0x101255]\n- `code`", "\n- `code`");
    let e = task.parse(&uncited).expect_err("uncited");
    assert!(e.to_string().contains("uncited fact in `## Inputs`"), "{e}");

    let invented = md.replace("[@0x101159]", "[@0xdeadbeef]");
    let e = task.parse(&invented).expect_err("invented");
    assert!(e.to_string().contains("0xdeadbeef"), "{e}");

    let missing = md.replace("## Invariants", "## Notes");
    let e = task.parse(&missing).expect_err("headings");
    assert!(
        e.to_string().contains("unexpected heading `## Notes`"),
        "{e}"
    );

    let truncated = md
        .split("## Invariants")
        .next()
        .expect("prefix")
        .to_string();
    let e = task.parse(&truncated).expect_err("short");
    assert!(
        e.to_string().contains("missing section `## Invariants`"),
        "{e}"
    );
}
