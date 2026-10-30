//! `config_get` and `config_set` through the registry: who may call them and what they write.

use std::sync::Arc;

use kraken_host::KrakenConfig;
use kraken_host::config_keys::HostConfigStore;
use kraken_host::factory::HostEngineFactory;
use kraken_registry::{CallContext, Registry, Session, Surface};
use serde_json::json;

fn session(path: &std::path::Path) -> Session {
    Session::new(Arc::new(HostEngineFactory::new(KrakenConfig::default())))
        .with_config_store(Arc::new(HostConfigStore::at(path.to_path_buf())))
}

#[tokio::test]
async fn a_person_sets_a_key_and_an_agent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    let s = session(&path);
    let r = Registry::standard();
    let person = CallContext::user("tester", Surface::Test);

    let out = r
        .call_json(
            "config_set",
            &s,
            &person,
            json!({"key": "daemon.idle_secs", "value": 45}),
        )
        .await
        .expect("set");
    assert_eq!(out["value"], 45);
    assert!(
        std::fs::read_to_string(&path)
            .expect("file")
            .contains("idle_secs = 45")
    );

    let got = r
        .call_json("config_get", &s, &person, json!({"key": "danger_mode"}))
        .await
        .expect("get");
    assert_eq!(got["entries"][0]["person_only"], true);
    assert!(got["entries"][0].get("value").is_none());

    let agent = CallContext::agent("a1", "run-1", Surface::Mcp);
    let err = r
        .call_json(
            "config_set",
            &s,
            &agent,
            json!({"key": "danger_mode", "value": "yolo"}),
        )
        .await
        .expect_err("agent refused");
    assert!(
        err.message.contains("reserved for people"),
        "{}",
        err.message
    );
    // An agent may read.
    r.call_json("config_get", &s, &agent, json!({}))
        .await
        .expect("agent get");

    let err = r
        .call_json(
            "config_set",
            &s,
            &person,
            json!({"key": "provider", "value": {}}),
        )
        .await
        .expect_err("secret");
    assert!(err.message.contains("credentials"), "{}", err.message);
}
