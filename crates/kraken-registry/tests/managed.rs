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
            EngineKind::Ghidra => FakeEngine::new(common::tiny()),
            EngineKind::Dotnet => [
                Cap::Analyzer,
                Cap::Mutator,
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
            "rename_symbol",
            json!({"address": "0x6000001", "new_name": "Entry"}),
        ),
    ] {
        let e = r.call(cmd, args).await.unwrap_err();
        assert!(
            matches!(code(&e), ErrorCode::Unsupported),
            "{cmd} should be unsupported, got {e}"
        );
    }
}
