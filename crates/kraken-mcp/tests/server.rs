//! kraken-mcp over an in-process rmcp client and FakeEngine.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::SharedEngine;
use kraken_mcp::{KrakenMcp, McpOptions, serve_transport};
use kraken_proto::{Locator, ProtoError};
use kraken_registry::{
    CallContext, Command, CommandKind, CommandSpec, EngineFactory, Permission, Registry, Session,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ElicitResult,
    ElicitationAction, Implementation, NumberOrString, ProgressNotificationParam, ProgressToken,
};
use rmcp::model::{ElicitRequestParams, RequestParamsMeta};
use rmcp::service::{NotificationContext, RequestContext, RunningService};
use rmcp::{ClientHandler, ErrorData as McpError, RoleClient, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

struct Factory {
    delay: Duration,
}

fn fixture() -> FixtureFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
    let mut fx = FixtureFile::from_path(&path).expect("tiny fixture");
    for f in &mut fx.functions {
        if let Locator::Native { offset, .. } = &f.summary.locator {
            f.summary.name = format!("FUN_{:08x}", offset.0);
        }
    }
    fx
}

#[async_trait]
impl EngineFactory for Factory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(
            FakeEngine::new(fixture()).with_stage_delay(self.delay),
        ))
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PatchArgs {
    /// Bytes to write.
    bytes: String,
}

#[derive(Serialize, JsonSchema)]
struct PatchOut {
    /// What was written.
    written: String,
}

struct PatchBytes;

#[async_trait]
impl Command for PatchBytes {
    type Args = PatchArgs;
    type Output = PatchOut;
    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_bytes",
            "Write bytes into the binary",
            CommandKind::Mutation,
            Permission::Dangerous,
        )
    }
    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        a: PatchArgs,
    ) -> Result<PatchOut, ProtoError> {
        Ok(PatchOut { written: a.bytes })
    }
}

#[derive(Clone)]
struct TestClient {
    name: &'static str,
    /// `Some(answer)`: declares elicitation and answers with `answer`.
    elicit: Option<bool>,
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
}

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        let caps = if self.elicit.is_some() {
            ClientCapabilities::builder().enable_elicitation().build()
        } else {
            ClientCapabilities::default()
        };
        ClientConfig::new(caps, Implementation::new(self.name, "1.0"))
    }

    async fn create_elicitation(
        &self,
        _request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        Ok(match self.elicit {
            Some(true) => {
                ElicitResult::new(ElicitationAction::Accept).with_content(json!({"approve": true}))
            }
            Some(false) => {
                ElicitResult::new(ElicitationAction::Accept).with_content(json!({"approve": false}))
            }
            None => ElicitResult::new(ElicitationAction::Decline),
        })
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(params);
    }
}

struct Rig {
    client: RunningService<RoleClient, TestClient>,
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
    dir: tempfile::TempDir,
    binary: String,
}

async fn rig(name: &'static str, elicit: Option<bool>, delay: Duration, project: bool) -> Rig {
    rig_with(name, elicit, delay, project, false).await
}

/// `project`: a person opened a project before the agent connected (as `kraken mcp --project`
/// does). `bound`: the server is bound to it.
async fn rig_with(
    name: &'static str,
    elicit: Option<bool>,
    delay: Duration,
    project: bool,
    bound: bool,
) -> Rig {
    let dir = tempfile::Builder::new()
        .prefix("kraken-mcp-test-")
        .tempdir()
        .expect("tempdir");
    let binary = dir.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake").expect("binary");
    let mut registry = Registry::standard();
    registry.register(PatchBytes);
    let session = Arc::new(Session::new(Arc::new(Factory { delay })));
    let server = KrakenMcp::new(
        Arc::new(registry),
        session.clone(),
        McpOptions {
            agent_id: None,
            run_id: Some("run-test-1".into()),
            bound_project: bound,
        },
    );
    let (c, s) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_transport(server, s).await;
    });
    let progress = Arc::new(Mutex::new(Vec::new()));
    let client = TestClient {
        name,
        elicit,
        progress: progress.clone(),
    }
    .serve(c)
    .await
    .expect("client connects");
    let rig = Rig {
        client,
        progress,
        binary: binary.to_string_lossy().into_owned(),
        dir,
    };
    if project {
        session
            .create_project(&rig.dir.path().join("p"), &binary)
            .await
            .expect("the person opens the project");
    }
    rig
}

impl Rig {
    async fn call(&self, tool: &str, args: Value) -> CallToolResult {
        self.call_with(CallToolRequestParams::new(tool.to_string()), args)
            .await
    }

    async fn call_with(&self, params: CallToolRequestParams, args: Value) -> CallToolResult {
        let obj = args.as_object().cloned().unwrap_or_default();
        self.client
            .call_tool(params.with_arguments(obj))
            .await
            .unwrap_or_else(|e| panic!("protocol error: {e}"))
    }

    async fn ok(&self, tool: &str, args: Value) -> Value {
        let r = self.call(tool, args).await;
        assert_ne!(r.is_error, Some(true), "{tool}: {r:?}");
        r.structured_content.expect("structured content")
    }
}

fn error_json(r: &CallToolResult) -> Value {
    assert_eq!(r.is_error, Some(true), "{r:?}");
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text");
    serde_json::from_str(&text).expect("ProtoError JSON")
}

#[tokio::test]
async fn tools_mirror_the_registry() {
    let rig = rig("t", None, Duration::ZERO, false).await;
    let tools = rig.client.list_all_tools().await.expect("tools");
    let mut expected: Vec<String> = Registry::standard()
        .iter()
        .map(|e| e.spec().name.clone())
        .collect();
    expected.push("patch_bytes".into());
    expected.sort();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, expected);
    let by = |n: &str| tools.iter().find(|t| t.name == n).expect("tool");
    let list = by("list_functions");
    assert_eq!(
        list.annotations.as_ref().and_then(|a| a.read_only_hint),
        Some(true)
    );
    assert!(list.output_schema.is_some());
    assert!(
        list.description
            .as_deref()
            .is_some_and(|d| d.starts_with("List functions") && d.contains("untrusted"))
    );
    let props = &by("rename_symbol").input_schema["properties"];
    assert!(props["new_name"].is_object() && props["address"].is_object());
    let patch = by("patch_bytes");
    assert_eq!(
        patch.annotations.as_ref().and_then(|a| a.destructive_hint),
        Some(true)
    );
    assert_eq!(
        patch.annotations.as_ref().and_then(|a| a.read_only_hint),
        Some(false)
    );
}

#[tokio::test]
async fn an_agent_cannot_open_a_project_unless_the_person_approves() {
    let args = |rig: &Rig| json!({"binary": rig.binary, "project_dir": rig.dir.path().join("p")});
    // A client that cannot ask the person: denied.
    let silent = rig("t", None, Duration::ZERO, false).await;
    let denied = silent.call("project_create", args(&silent)).await;
    assert_eq!(error_json(&denied)["details"]["approval"], "denied");
    assert!(!silent.dir.path().join("p").exists());
    // The person says no.
    let declining = rig("t", Some(false), Duration::ZERO, false).await;
    let denied = declining.call("project_create", args(&declining)).await;
    assert_eq!(error_json(&denied)["details"]["approval"], "denied");
    assert!(!declining.dir.path().join("p").exists());
    // The person says yes.
    let approving = rig("t", Some(true), Duration::ZERO, false).await;
    let created = approving.call("project_create", args(&approving)).await;
    assert_ne!(created.is_error, Some(true), "{created:?}");
    // Opening an existing project is asked the same way.
    let p = approving.dir.path().join("p");
    let silent = rig("t", None, Duration::ZERO, false).await;
    let denied = silent.call("project_open", json!({"project_dir": p})).await;
    assert_eq!(error_json(&denied)["details"]["approval"], "denied");
}

#[tokio::test]
async fn a_bound_server_neither_lists_nor_runs_the_project_tools() {
    let rig = rig_with("t", None, Duration::ZERO, true, true).await;
    let tools = rig.client.list_all_tools().await.expect("tools");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        !names
            .iter()
            .any(|n| n == "project_create" || n == "project_open")
    );
    assert!(names.iter().any(|n| n == "project_info"), "{names:?}");
    for tool in ["project_create", "project_open"] {
        let r = rig
            .call(
                tool,
                json!({"binary": rig.binary, "project_dir": rig.dir.path().join("other")}),
            )
            .await;
        let e = error_json(&r);
        assert_eq!(e["code"], "unsupported", "{e}");
        assert!(e["message"].as_str().unwrap().contains("bound"), "{e}");
    }
    assert!(!rig.dir.path().join("other").exists());
    // The bound project keeps working.
    let list = rig.ok("list_functions", json!({})).await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(3));
}

#[tokio::test]
async fn without_a_project_only_project_tools_can_work() {
    let rig = rig("t", Some(true), Duration::ZERO, false).await;
    let err = error_json(&rig.call("list_functions", json!({})).await);
    assert_eq!(err["code"], "not_found");
    let created = rig
        .call(
            "project_create",
            json!({"binary": rig.binary, "project_dir": rig.dir.path().join("p")}),
        )
        .await;
    assert_ne!(created.is_error, Some(true), "{created:?}");
    let list = rig.ok("list_functions", json!({})).await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(3));
    let unknown = error_json(&rig.call("no_such_tool", json!({})).await);
    assert_eq!(unknown["code"], "not_found");
    let bad = error_json(&rig.call("list_functions", json!({"bogus": 1})).await);
    assert_eq!(bad["code"], "invalid_argument");
}

#[tokio::test]
async fn edits_are_logged_as_the_client_agent_with_one_run_id() {
    let rig = rig("claude-test", None, Duration::ZERO, true).await;
    let r = rig
        .ok(
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "entry"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let again = rig
        .ok(
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "entry2"}),
        )
        .await;
    assert_eq!(again["status"], "proposed");
    assert!(again["proposal"].is_object(), "proposal field: {again}");
    assert_eq!(again["proposal"]["id"], again["proposal_id"]);
    let hist = rig.ok("history", json!({})).await;
    let items = hist["items"].as_array().expect("items");
    assert!(!items.is_empty());
    for e in items {
        assert_eq!(e["author"]["kind"], "agent");
        assert_eq!(e["author"]["id"], "claude-test");
        assert_eq!(e["run_id"], "run-test-1");
    }
}

#[tokio::test]
async fn job_await_streams_progress_when_a_token_is_given() {
    let rig = rig("t", None, Duration::from_millis(120), true).await;
    let started = rig.ok("analyze", json!({})).await;
    let mut params = CallToolRequestParams::new("job_await");
    params.set_progress_token(ProgressToken(NumberOrString::Number(7)));
    let r = rig
        .call_with(
            params,
            json!({"job_id": started["job_id"], "timeout_ms": 20000}),
        )
        .await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let done = r.structured_content.expect("structured");
    assert_eq!(done["status"], "succeeded");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = rig
        .progress
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(!seen.is_empty(), "no progress notifications arrived");
    assert!(
        seen.iter()
            .all(|p| p.progress_token == seen[0].progress_token)
    );
    assert!(seen.windows(2).all(|w| w[1].progress > w[0].progress));
    assert!(
        seen.iter()
            .any(|p| p.message.as_deref().is_some_and(|m| !m.is_empty()))
    );
}

#[tokio::test]
async fn dangerous_tools_use_elicitation_when_the_client_can() {
    let approving = rig("t", Some(true), Duration::ZERO, true).await;
    let ok = approving.ok("patch_bytes", json!({"bytes": "90"})).await;
    assert_eq!(ok["written"], "90");

    let declining = rig("t", Some(false), Duration::ZERO, true).await;
    let r = declining.call("patch_bytes", json!({"bytes": "90"})).await;
    let e = error_json(&r);
    assert_eq!(e["code"], "unsupported");
    assert_eq!(e["details"]["approval"], "denied");
}

#[tokio::test]
async fn dangerous_tools_are_denied_with_an_explanation_without_elicitation() {
    let rig = rig("t", None, Duration::ZERO, true).await;
    let e = error_json(&rig.call("patch_bytes", json!({"bytes": "90"})).await);
    assert_eq!(e["details"]["approval"], "denied");
    assert!(
        e["message"]
            .as_str()
            .is_some_and(|m| m.contains("elicitation")),
        "{e}"
    );
}
