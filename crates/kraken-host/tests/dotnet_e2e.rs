//! A .NET assembly through the real stack: `HostEngineFactory` picks the .NET engine for the
//! corpus assembly, the project records it, the commands carry managed locators and a reopened
//! project uses the .NET engine again. Needs the pinned SDK in `~/.cache/kraken-dev/dotnet` (or
//! `KRAKEN_DOTNET_ROOT`) and `cargo xtask dotnet-ext`:
//!
//! `cargo test -p kraken-host --features real-dotnet --test dotnet_e2e`
#![cfg(all(feature = "real-dotnet", unix))]

use std::path::Path;
use std::sync::Arc;

use kraken_host::{HostEngineFactory, KrakenConfig, ManagedFactory};
use kraken_proto::ErrorCode;
use kraken_registry::{CallContext, Registry, Session, Surface};
use serde_json::{Value, json};

fn corpus() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dotnet/bin/kraken-corpus.dll")
        .to_string_lossy()
        .into_owned()
}

async fn call(registry: &Registry, session: &Session, name: &str, args: Value) -> Value {
    let ctx = CallContext::user("adam", Surface::Test);
    match registry.call_json(name, session, &ctx, args).await {
        Ok(v) => v,
        Err(e) => panic!("{name} failed: {e} {:?}", e.details),
    }
}

#[tokio::test]
async fn a_dotnet_assembly_is_created_decompiled_and_reopened_with_the_dotnet_engine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("proj");
    let factory = Arc::new(HostEngineFactory::new(KrakenConfig::default()));
    let registry = Registry::standard();
    let session = Session::new(factory.clone());

    call(
        &registry,
        &session,
        "project_create",
        json!({"binary": corpus(), "project_dir": project}),
    )
    .await;
    let meta: Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["engine_kind"], "dotnet");

    let info = call(&registry, &session, "project_info", json!({})).await;
    assert_eq!(info["program"]["format"], "dotnet");

    let list = call(&registry, &session, "list_functions", json!({"limit": 50})).await;
    let items = list["items"].as_array().expect("items");
    assert!(!items.is_empty(), "{list}");
    let first = &items[0];
    let module = first["module"].as_str().expect("a module").to_string();
    assert!(
        first["address"].as_str().unwrap().starts_with("0x6"),
        "{first}"
    );

    // Find a method whose C# calls another corpus method and follow the call.
    let mut followed = false;
    for f in items {
        let d = call(
            &registry,
            &session,
            "decompile",
            json!({"address": f["address"], "module": module}),
        )
        .await;
        assert_eq!(d["language"], "csharp");
        assert!(d["text"]["value"].as_str().unwrap().len() > 5, "{d}");
        if let Some(t) = d["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["target_module"] == json!(module))
        {
            let next = call(
                &registry,
                &session,
                "decompile",
                json!({"address": t["target"], "module": module}),
            )
            .await;
            assert_eq!(next["module"], json!(module));
            followed = true;
            break;
        }
    }
    assert!(followed, "no corpus method calls another one");

    // What the .NET engine lacks answers `unsupported`.
    let ctx = CallContext::user("adam", Surface::Test);
    for (cmd, args) in [
        ("analyze", json!({})),
        (
            "rename_symbol",
            json!({"address": first["address"], "new_name": "Renamed"}),
        ),
    ] {
        let e = registry
            .call_json(cmd, &session, &ctx, args)
            .await
            .expect_err(cmd);
        assert_eq!(e.code, ErrorCode::Unsupported, "{cmd}: {e}");
    }

    let diag = factory.diagnostics();
    assert_eq!(diag.len(), 1);
    assert_eq!(diag[0].value["engine"], "dotnet");
    assert_eq!(diag[0].value["state"], "running");

    // A new session (a restarted daemon) reopens with the recorded engine.
    factory.shutdown().await;
    let again = Session::new(factory.clone());
    call(
        &registry,
        &again,
        "project_open",
        json!({"project_dir": project}),
    )
    .await;
    let list = call(&registry, &again, "list_functions", json!({"limit": 5})).await;
    assert_eq!(list["items"][0]["module"], json!(module));
    factory.shutdown().await;
    assert!(factory.diagnostics().is_empty());
}
