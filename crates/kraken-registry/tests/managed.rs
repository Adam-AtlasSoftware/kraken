//! Engine kinds: a project records which engine opened it and reopens with that engine, and the
//! function commands carry managed (.NET) locators as a module plus a metadata token.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{code, user};
use engine_fake::{FakeEngine, FixtureFile, FixtureFunction};
use kraken_engine::{Cap, SharedEngine};
use kraken_proto::{
    Completeness, DecompileResult, ErrorCode, FunctionSummary, Locator, ProtoError, Token,
    TokenKind,
};
use kraken_registry::{EngineFactory, EngineKind, Registry, Session};
use serde_json::{Value, json};

const MVID: &str = "61a35c05-1940-4673-81a7-f2157a66b75c";
const MAIN: u32 = 0x0600_0001;
const GREET: u32 = 0x0600_0002;

fn method(token: u32, name: &str, text: &str, tokens: Vec<Token>) -> FixtureFunction {
    let locator = Locator::managed(MVID, token);
    FixtureFunction::new(
        FunctionSummary {
            locator: locator.clone(),
            name: name.into(),
            size: None,
            signature: Some(format!("void {name}()")),
            fn_hash: None,
            completeness: Completeness::Complete,
            mangled: None,
        },
        DecompileResult {
            function: locator,
            language: "csharp".into(),
            text: text.into(),
            tokens,
            warnings: vec![],
            completeness: Completeness::Complete,
        },
    )
}

/// What a .NET engine would answer: managed locators, C#, no analyzer and no mutator.
fn managed_fixture() -> FixtureFile {
    let mut fx = common::tiny();
    fx.program.arch = "cil".into();
    fx.program.format = "dotnet".into();
    let call = Token {
        start: 24,
        end: 29,
        kind: TokenKind::Function,
        target: Some(Locator::managed(MVID, GREET)),
        symbol: Some("Greet".into()),
        varnode: None,
    };
    fx.functions = vec![
        method(
            MAIN,
            "Main",
            "static void Main()\n{\n    Greet();\n}\n",
            vec![call],
        ),
        method(GREET, "Greet", "static void Greet()\n{\n}\n", vec![]),
    ];
    fx
}

/// Picks the engine from the file's first bytes (`MZ` is managed here) and records what it made.
struct KindFactory {
    made: Mutex<Vec<EngineKind>>,
}

#[async_trait]
impl EngineFactory for KindFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        self.create_kind(EngineKind::Ghidra, engine_dir).await
    }

    fn detect_kind(&self, binary: &Path) -> Result<EngineKind, ProtoError> {
        let head = std::fs::read(binary).unwrap_or_default();
        Ok(if head.starts_with(b"MZ") {
            EngineKind::Dotnet
        } else {
            EngineKind::Ghidra
        })
    }

    async fn create_kind(
        &self,
        kind: EngineKind,
        _engine_dir: &Path,
    ) -> Result<SharedEngine, ProtoError> {
        self.made.lock().unwrap().push(kind);
        Ok(Arc::new(match kind {
            EngineKind::Ghidra | EngineKind::Native => FakeEngine::new(common::tiny()),
            EngineKind::Dotnet => [
                Cap::Analyzer,
                Cap::Memory,
                Cap::Disassembler,
                Cap::Xrefs,
                Cap::Cfg,
                Cap::Strings,
                Cap::Symbols,
            ]
            .into_iter()
            .fold(FakeEngine::new(managed_fixture()), FakeEngine::without),
        }))
    }
}

struct Rig {
    tmp: tempfile::TempDir,
    factory: Arc<KindFactory>,
    session: Session,
    registry: Registry,
}

impl Rig {
    fn new() -> Rig {
        let factory = Arc::new(KindFactory {
            made: Mutex::new(vec![]),
        });
        Rig {
            tmp: tempfile::tempdir().unwrap(),
            session: Session::new(factory.clone()),
            factory,
            registry: Registry::standard(),
        }
    }

    async fn call(&self, name: &str, args: Value) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, &user(), args)
            .await
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let p = self.tmp.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn dir(&self, name: &str) -> String {
        self.tmp.path().join(name).to_string_lossy().into_owned()
    }

    fn meta(&self, project: &str) -> Value {
        let text =
            std::fs::read_to_string(self.tmp.path().join(project).join("meta.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn made(&self) -> Vec<EngineKind> {
        self.factory.made.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn the_engine_kind_is_recorded_and_used_again_on_reopen() {
    let r = Rig::new();
    let dll = r.write("app.dll", b"MZ managed");
    let elf = r.write("prog", b"\x7fELF native");

    let dotnet_dir = r.dir("net");
    r.call(
        "project_create",
        json!({"binary": dll, "project_dir": dotnet_dir}),
    )
    .await
    .unwrap();
    let native_dir = r.dir("nat");
    r.call(
        "project_create",
        json!({"binary": elf, "project_dir": native_dir}),
    )
    .await
    .unwrap();
    assert_eq!(r.meta("net")["engine_kind"], "dotnet");
    assert_eq!(r.meta("nat")["engine_kind"], "ghidra");
    assert_eq!(r.made(), vec![EngineKind::Dotnet, EngineKind::Ghidra]);

    // Reopening asks for the recorded kind, whatever the file looks like now.
    r.call("project_open", json!({"project_dir": dotnet_dir}))
        .await
        .unwrap();
    r.call("project_open", json!({"project_dir": native_dir}))
        .await
        .unwrap();
    assert_eq!(
        r.made()[2..],
        [EngineKind::Dotnet, EngineKind::Ghidra],
        "{:?}",
        r.made()
    );
}

#[tokio::test]
async fn a_project_written_before_engine_kinds_reopens_with_ghidra() {
    let r = Rig::new();
    let elf = r.write("prog", b"\x7fELF native");
    let dir = r.dir("old");
    r.call("project_create", json!({"binary": elf, "project_dir": dir}))
        .await
        .unwrap();
    let path = r.tmp.path().join("old/meta.json");
    let mut meta: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    meta.as_object_mut().unwrap().remove("engine_kind");
    std::fs::write(&path, meta.to_string()).unwrap();

    r.call("project_open", json!({"project_dir": dir}))
        .await
        .unwrap();
    assert_eq!(r.made(), vec![EngineKind::Ghidra, EngineKind::Ghidra]);
}

#[tokio::test]
async fn managed_functions_travel_as_a_module_and_a_token() {
    let r = Rig::new();
    let dll = r.write("app.dll", b"MZ managed");
    r.call(
        "project_create",
        json!({"binary": dll, "project_dir": r.dir("net")}),
    )
    .await
    .unwrap();

    let list = r.call("list_functions", json!({})).await.unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{list}");
    assert_eq!(items[0]["address"], "0x6000001");
    assert_eq!(items[0]["module"], MVID);
    assert!(items[0].get("space").is_none(), "{}", items[0]);

    let d = r
        .call("decompile", json!({"address": "0x6000001", "module": MVID}))
        .await
        .unwrap();
    assert_eq!(d["language"], "csharp");
    assert_eq!(d["module"], MVID);
    assert_eq!(d["address"], "0x6000001");
    let tok = &d["tokens"][0];
    assert_eq!(tok["target"], "0x6000002");
    assert_eq!(tok["target_module"], MVID);
    assert_eq!(d["references"][0]["address"], "0x6000002");
    assert_eq!(d["references"][0]["module"], MVID);

    let f = r
        .call(
            "get_function",
            json!({"address": "0x6000002", "module": MVID}),
        )
        .await
        .unwrap();
    assert_eq!(f["name"]["value"], "Greet");
    assert_eq!(f["module"], MVID);

    // Without the module the address means native code, which this engine does not have.
    let e = r
        .call("decompile", json!({"address": "0x6000001"}))
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::NotFound, "{e}");
}

#[tokio::test]
async fn bad_modules_and_tokens_are_refused() {
    let r = Rig::new();
    let dll = r.write("app.dll", b"MZ managed");
    r.call(
        "project_create",
        json!({"binary": dll, "project_dir": r.dir("net")}),
    )
    .await
    .unwrap();
    for (address, module) in [
        ("0x6000001", "not-a-guid"),
        ("0x6000001", "61A35C05-1940-4673-81A7-F2157A66B75C"),
        ("0x6000001", ""),
        ("0x1_0000_0001", MVID),
    ] {
        let e = r
            .call("decompile", json!({"address": address, "module": module}))
            .await
            .unwrap_err();
        assert_eq!(
            code(&e),
            ErrorCode::InvalidArgument,
            "{address} {module}: {e}"
        );
    }
}

#[tokio::test]
async fn commands_the_dotnet_engine_lacks_answer_unsupported() {
    let r = Rig::new();
    let dll = r.write("app.dll", b"MZ managed");
    r.call(
        "project_create",
        json!({"binary": dll, "project_dir": r.dir("net")}),
    )
    .await
    .unwrap();
    for (cmd, args) in [
        ("analyze", json!({})),
        ("xrefs", json!({"address": "0x6000001", "direction": "to"})),
        ("disassemble", json!({"address": "0x6000001"})),
        ("strings", json!({})),
        (
            "set_type",
            json!({"address": "0x6000001", "type_name": "int"}),
        ),
        ("create_function", json!({"address": "0x6000010"})),
    ] {
        let e = r.call(cmd, args).await.unwrap_err();
        assert!(
            matches!(code(&e), ErrorCode::Unsupported),
            "{cmd} should be unsupported, got {e}"
        );
    }
}

async fn net_project(r: &Rig) -> String {
    let dll = r.write("app.dll", b"MZ managed");
    let dir = r.dir("net");
    r.call("project_create", json!({"binary": dll, "project_dir": dir}))
        .await
        .unwrap();
    dir
}

#[tokio::test]
async fn managed_methods_can_be_renamed_commented_and_undone() {
    let r = Rig::new();
    net_project(&r).await;

    let out = r
        .call(
            "rename_symbol",
            json!({"address": "0x6000002", "module": MVID, "new_name": "SayHello"}),
        )
        .await
        .unwrap();
    assert_eq!(out["status"], "applied", "{out}");
    assert_eq!(out["key"], format!("managed:{MVID}:0x6000002:name"));

    let f = r
        .call(
            "get_function",
            json!({"address": "0x6000002", "module": MVID}),
        )
        .await
        .unwrap();
    assert_eq!(f["name"]["value"], "SayHello");
    assert_eq!(f["versions"][format!("managed:{MVID}:0x6000002:name")], 1);
    let d = r
        .call("decompile", json!({"address": "0x6000002", "module": MVID}))
        .await
        .unwrap();
    assert!(d["text"]["value"].as_str().unwrap().contains("SayHello"));

    // A second rename sees the first name as the old one; a stale expectation is refused.
    let e = r
        .call(
            "rename_symbol",
            json!({"address": "0x6000002", "module": MVID, "new_name": "Hi",
                   "expect_versions": {format!("managed:{MVID}:0x6000002:name"): 0}}),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::ConflictStaleRead, "{e}");

    r.call(
        "set_comment",
        json!({"address": "0x6000002", "module": MVID, "kind": "plate", "text": "greets"}),
    )
    .await
    .unwrap();
    let f = r
        .call(
            "get_function",
            json!({"address": "0x6000002", "module": MVID}),
        )
        .await
        .unwrap();
    assert_eq!(f["comments"][0]["kind"], "plate");
    assert_eq!(f["comments"][0]["text"]["value"], "greets");

    let h = r.call("history", json!({})).await.unwrap();
    let entries = h["items"].as_array().unwrap();
    // The stale rename stays in the log as rejected.
    assert_eq!(entries.len(), 3, "{h}");
    assert_eq!(entries[0]["address"], "0x6000002", "{h}");

    r.call("undo", json!({})).await.unwrap();
    r.call("undo", json!({})).await.unwrap();
    let f = r
        .call(
            "get_function",
            json!({"address": "0x6000002", "module": MVID}),
        )
        .await
        .unwrap();
    assert_eq!(f["name"]["value"], "Greet");
    assert!(f["comments"].as_array().is_none_or(Vec::is_empty), "{f}");
}

#[tokio::test]
async fn managed_edits_need_a_module_and_a_supported_operation() {
    let r = Rig::new();
    net_project(&r).await;

    // A native-style address in a .NET project is explained, not logged.
    let e = r
        .call(
            "rename_symbol",
            json!({"address": "0x6000001", "new_name": "Entry"}),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::Unsupported, "{e}");
    assert!(e.message.contains("module"), "{e}");

    let e = r
        .call(
            "set_calling_convention",
            json!({"address": "0x6000001", "convention": "stdcall"}),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::Unsupported, "{e}");

    let e = r
        .call(
            "rename_symbol",
            json!({"address": "0x6000001", "module": "not-a-guid", "new_name": "Entry"}),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::InvalidArgument, "{e}");

    let h = r.call("history", json!({})).await.unwrap();
    assert!(
        h["items"].as_array().unwrap().is_empty(),
        "nothing is logged: {h}"
    );
}

#[tokio::test]
async fn managed_annotations_come_back_when_the_project_is_reopened() {
    let r = Rig::new();
    let dir = net_project(&r).await;
    r.call(
        "rename_symbol",
        json!({"address": "0x6000002", "module": MVID, "new_name": "SayHello"}),
    )
    .await
    .unwrap();

    // The factory builds a fresh engine that knows nothing; the log gives the rename back.
    r.call("project_open", json!({"project_dir": dir}))
        .await
        .unwrap();
    let f = r
        .call(
            "get_function",
            json!({"address": "0x6000002", "module": MVID}),
        )
        .await
        .unwrap();
    assert_eq!(f["name"]["value"], "SayHello");
}

#[tokio::test]
async fn the_engine_choice_is_recorded_and_reported_by_project_info() {
    let r = Rig::new();
    let elf = r.write("prog", b"\x7fELF native");

    let dir = r.dir("auto");
    let created = r
        .call(
            "project_create",
            json!({"binary": elf, "project_dir": dir, "engine": "auto"}),
        )
        .await
        .unwrap();
    assert_eq!(created["engine"]["kind"], "ghidra");
    assert_eq!(created["engine"]["choice"], "auto");
    assert!(created["engine"]["reason"].as_str().is_some(), "{created}");
    assert_eq!(r.meta("auto")["engine_choice"], "auto");
    let info = r.call("project_info", json!({})).await.unwrap();
    assert_eq!(info["engine"], created["engine"]);

    // This factory has no native engine: the request is refused and leaves no project behind.
    let e = r
        .call(
            "project_create",
            json!({"binary": elf, "project_dir": r.dir("nat"), "engine": "native"}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, kraken_proto::ErrorCode::Unsupported);
    assert!(!r.tmp.path().join("nat/meta.json").exists());

    // Reopening reports the recorded choice; an old project has none.
    let path = r.tmp.path().join("auto/meta.json");
    let mut meta: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let m = meta.as_object_mut().unwrap();
    m.remove("engine_choice");
    m.remove("engine_reason");
    std::fs::write(&path, meta.to_string()).unwrap();
    let reopened = r
        .call("project_open", json!({"project_dir": dir}))
        .await
        .unwrap();
    assert_eq!(reopened["engine"], json!({"kind": "ghidra"}));
}
