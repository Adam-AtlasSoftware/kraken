//! `patch_from_source` end to end, offline: FakeEngine on a corpus fixture over the real corpus
//! binary, the `RewriteService` planner attached through `with_rewrite`, and a scripted model.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_agent::{ChatProvider, FinishReason, ReplayProvider, StreamEvent};
use kraken_assist::{ApiBackend, AssistBackend};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    PatchFromSourceResult, RewriteBackend, SourcePatchVerdict, source_patch_result,
};
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::service::{BackendSource, RewriteConfig, RewriteService};
use serde_json::{Value, json};

use common::corpus_bin;

const BINARY: &str = "pie_list-O0";

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

/// The model, set once the test knows what to answer.
#[derive(Default)]
struct Slot(Mutex<Option<Arc<dyn ChatProvider>>>);

impl BackendSource for Slot {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        self.0
            .lock()
            .expect("slot")
            .clone()
            .map(|p| Arc::new(ApiBackend::new(p)) as Arc<dyn AssistBackend>)
            .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "no provider set in the test"))
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    session: Session,
    registry: Registry,
    slot: Arc<Slot>,
}

async fn rig() -> Rig {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{BINARY}.json"));
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::tempdir().expect("tempdir");
    let slot = Arc::new(Slot::default());
    let service: Arc<dyn RewriteBackend> =
        Arc::new(RewriteService::new(slot.clone(), RewriteConfig::default()));
    let session = Session::new(Arc::new(FakeFactory { fixture })).with_rewrite(service);
    session
        .create_project(&tmp.path().join("p"), &corpus_bin(BINARY))
        .await
        .expect("project");
    Rig {
        _tmp: tmp,
        session,
        registry: Registry::standard(),
        slot,
    }
}

fn ctx() -> CallContext {
    CallContext::user("tester", Surface::Test)
}

impl Rig {
    async fn call(&self, name: &str, args: Value) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, &ctx(), args)
            .await
    }

    /// `main`'s entry and its first instruction with more than one byte.
    async fn target(&self) -> (u64, u64, String) {
        let fns = self
            .call(
                "list_functions",
                json!({"name_filter": "main", "limit": 50}),
            )
            .await
            .expect("functions");
        let main = fns["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|f| f["name"] == "main" || f["name"]["value"] == "main")
            .expect("main");
        let entry = u64::from_str_radix(
            main["address"]
                .as_str()
                .expect("addr")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");
        let d = self
            .call("disassemble", json!({"function": format!("{entry:#x}")}))
            .await
            .expect("disassembly");
        let insn = d["items"]
            .as_array()
            .expect("rows")
            .iter()
            .find(|r| r["bytes"].as_str().is_some_and(|b| b.len() >= 4))
            .expect("a multi-byte instruction");
        let at = u64::from_str_radix(
            insn["address"]
                .as_str()
                .expect("a")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");
        (
            entry,
            at,
            insn["bytes"].as_str().expect("bytes").to_string(),
        )
    }

    async fn run(
        &self,
        entry: u64,
        answers: Vec<String>,
    ) -> Result<PatchFromSourceResult, ProtoError> {
        let script = answers
            .into_iter()
            .map(|t| {
                vec![
                    StreamEvent::TextDelta { text: t },
                    StreamEvent::Finish {
                        reason: FinishReason::Stop,
                    },
                ]
            })
            .collect();
        *self.slot.0.lock().expect("slot") = Some(Arc::new(ReplayProvider::scripted(script)));
        let started = self
            .call(
                "patch_from_source",
                json!({"address": format!("{entry:#x}"), "source": "int main(void) { return 7; }"}),
            )
            .await?;
        let job = started["job_id"].as_str().expect("job").to_string();
        let done = self
            .call("job_await", json!({"job_id": job, "timeout_ms": 60000}))
            .await
            .expect("await");
        match done["status"].as_str() {
            Some("succeeded") => source_patch_result(&done["result"]),
            _ => Err(ProtoError::new(
                ErrorCode::Internal,
                format!("job did not succeed: {done}"),
            )),
        }
    }
}

/// The same bytes with the first byte flipped.
fn flipped(hex: &str) -> String {
    let first = u8::from_str_radix(&hex[..2], 16).expect("hex") ^ 0x01;
    format!("{first:02x}{}", &hex[2..])
}

fn plan(at: u64, bytes: &str) -> String {
    format!(
        "Here is the plan:\n```json\n{{\"patches\": [{{\"address\": \"{at:#x}\", \"bytes\": \
         \"{bytes}\", \"explanation\": \"change it\"}}], \"summary\": \"return 7\"}}\n```"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plan_that_checks_out_comes_back_with_the_patched_decompile() {
    let r = rig().await;
    let (entry, at, bytes) = r.target().await;
    let new = flipped(&bytes);
    let out = r
        .run(
            entry,
            vec![
                plan(at, &new),
                "{\"verdict\": \"matches\", \"reason\": \"returns 7 now\"}".into(),
            ],
        )
        .await
        .expect("result");
    assert_eq!(out.function.0, entry);
    assert_eq!(out.patches.len(), 1, "{out:?}");
    let p = &out.patches[0];
    assert_eq!((p.address.0, p.original.as_str()), (at, bytes.as_str()));
    assert_eq!(p.replacement, new);
    assert_eq!(out.summary.0, "return 7");
    assert_eq!(out.attempts, 1);
    assert_eq!(out.check.verdict, SourcePatchVerdict::Matches, "{out:?}");
    assert!(
        out.check
            .patched_decompile
            .as_ref()
            .is_some_and(|d| !d.0.is_empty()),
        "the patched copy was decompiled: {out:?}"
    );
    // Nothing was staged.
    let staged = r.call("patch_list", json!({})).await.expect("list");
    assert_eq!(staged["items"].as_array().map(Vec::len), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_check_is_planned_again_and_bad_patches_are_dropped() {
    let r = rig().await;
    let (entry, at, bytes) = r.target().await;
    let new = flipped(&bytes);
    let out = r
        .run(
            entry,
            vec![
                // Round 1: outside the function and the same bytes: nothing usable.
                format!(
                    "{{\"patches\": [{{\"address\": \"0x10\", \"bytes\": \"90\"}}, \
                     {{\"address\": \"{at:#x}\", \"bytes\": \"{bytes}\"}}], \"summary\": \"x\"}}"
                ),
                // Round 2: a real patch, but the check disagrees.
                plan(at, &new),
                "{\"verdict\": \"mismatch\", \"reason\": \"still returns 3\"}".into(),
            ],
        )
        .await
        .expect("result");
    assert_eq!(out.attempts, 2, "{out:?}");
    assert_eq!(out.check.verdict, SourcePatchVerdict::Mismatch);
    assert_eq!(out.check.reason.0, "still returns 3");
    assert_eq!(out.patches.len(), 1);
    assert!(
        out.warnings.iter().any(|w| w.contains("not all inside"))
            && out.warnings.iter().any(|w| w.contains("changes nothing")),
        "{:?}",
        out.warnings
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_arguments_are_refused_before_a_job_starts() {
    let r = rig().await;
    let (entry, ..) = r.target().await;
    let e = r
        .call(
            "patch_from_source",
            json!({"address": format!("{entry:#x}"), "source": "  "}),
        )
        .await
        .expect_err("empty source");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = r
        .call(
            "patch_from_source",
            json!({"address": format!("{entry:#x}"), "source": "x", "max_attempts": 9}),
        )
        .await
        .expect_err("too many attempts");
    assert!(e.message.contains("max_attempts"), "{e:?}");
}

#[tokio::test]
async fn without_the_pipeline_the_command_is_unsupported() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{BINARY}.json"));
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = Session::new(Arc::new(FakeFactory { fixture }));
    session
        .create_project(&tmp.path().join("p"), &corpus_bin(BINARY))
        .await
        .expect("project");
    let e = Registry::standard()
        .call_json(
            "patch_from_source",
            &session,
            &ctx(),
            json!({"address": "0x1000", "source": "x"}),
        )
        .await
        .expect_err("unsupported");
    assert_eq!(e.code, ErrorCode::Unsupported);
}
