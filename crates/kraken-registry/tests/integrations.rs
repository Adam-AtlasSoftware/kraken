//! The integrations commands over a scripted catalogue: approval rules, the licence gate, and
//! `emulator_run` handing a file to a real (tiny) program.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{Setup, agent, tiny, user};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    IntegrationRemoveOut, IntegrationSource, IntegrationStatus, IntegrationView,
    IntegrationsBackend, LaunchSpec,
};
use kraken_registry::{AutoApprove, CallContext};
use serde_json::json;

#[derive(Debug, Default)]
struct Fake {
    installed: Mutex<Vec<String>>,
}

fn view(id: &str, key: bool, status: IntegrationStatus) -> IntegrationView {
    IntegrationView {
        id: id.into(),
        name: id.to_uppercase(),
        kind: "emulator".into(),
        summary: "test".into(),
        homepage: String::new(),
        platforms: vec!["Test".into()],
        formats: Vec::new(),
        status,
        source: None,
        version: None,
        pinned_version: Some("1".into()),
        path: None,
        download_bytes: 10,
        disk_bytes: 0,
        license: "MIT".into(),
        notice: "read me".into(),
        contains_key_material: key,
        user_supplied: false,
        debuggable: true,
        argv: vec!["{exe}".into()],
        progress: None,
    }
}

#[async_trait]
impl IntegrationsBackend for Fake {
    fn list(&self) -> Result<Vec<IntegrationView>, ProtoError> {
        let done = self.installed.lock().unwrap().clone();
        Ok(["plain", "keyed"]
            .iter()
            .map(|id| {
                let mut v = view(
                    id,
                    *id == "keyed",
                    if done.iter().any(|d| d == id) {
                        IntegrationStatus::Ready
                    } else {
                        IntegrationStatus::NotInstalled
                    },
                );
                if v.status == IntegrationStatus::Ready {
                    v.source = Some(IntegrationSource::Downloaded);
                }
                v
            })
            .collect())
    }

    async fn install(&self, id: &str, _accept: bool) -> Result<IntegrationView, ProtoError> {
        self.installed.lock().unwrap().push(id.to_string());
        Ok(view(id, false, IntegrationStatus::Ready))
    }

    fn use_path(&self, id: &str, _path: &Path) -> Result<IntegrationView, ProtoError> {
        Ok(view(id, false, IntegrationStatus::Ready))
    }

    fn remove(&self, id: &str) -> Result<IntegrationRemoveOut, ProtoError> {
        self.installed.lock().unwrap().retain(|d| d != id);
        Ok(IntegrationRemoveOut {
            id: id.into(),
            freed_bytes: 1,
            note: "gone".into(),
        })
    }

    fn launch_spec(&self, id: &str) -> Result<LaunchSpec, ProtoError> {
        if !self.installed.lock().unwrap().iter().any(|d| d == id) {
            return Err(ProtoError::new(ErrorCode::NotFound, "not installed"));
        }
        Ok(LaunchSpec {
            id: id.into(),
            name: id.into(),
            exe: PathBuf::from("/bin/echo"),
            argv: vec!["{exe}".into(), "ran".into(), "{binary}".into()],
            gdb_argv: Some(vec!["{exe}".into(), "debug".into(), "{port}".into()]),
            gdb_port: Some(4321),
            gui: false,
            env: Vec::new(),
        })
    }
}

fn approved(ctx: CallContext) -> CallContext {
    ctx.with_approval(Arc::new(AutoApprove))
}

#[tokio::test]
async fn install_needs_the_licence_and_asks_agents() {
    let env = Setup::new(tiny())
        .integrations(Arc::new(Fake::default()))
        .start()
        .await;
    let list = env.ok(&user(), "integrations_list", json!({})).await;
    assert_eq!(list["integrations"].as_array().unwrap().len(), 2);

    let e = env
        .err(&user(), "integration_install", json!({"id": "plain"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("accept_licence"), "{e}");

    let e = env
        .err(
            &user(),
            "integration_install",
            json!({"id": "nope", "accept_licence": true}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    // An agent with no way to ask is refused; with a person saying yes it goes through.
    let args = json!({"id": "plain", "accept_licence": true});
    let e = env
        .err(&agent("r"), "integration_install", args.clone())
        .await;
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    env.ok(&approved(agent("r")), "integration_install", args.clone())
        .await;

    // A person installs without a prompt.
    let out = env
        .ok(
            &user(),
            "integration_install",
            json!({"id": "keyed", "accept_licence": true}),
        )
        .await;
    assert_eq!(out["status"], "ready");
}

#[tokio::test]
async fn key_material_is_never_installed_for_an_agent() {
    let env = Setup::new(tiny())
        .integrations(Arc::new(Fake::default()))
        .start()
        .await;
    let e = env
        .err(
            &approved(agent("r")),
            "integration_install",
            json!({"id": "keyed", "accept_licence": true}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("key material"), "{e}");
}

#[tokio::test]
async fn use_path_wants_an_absolute_path_and_remove_is_dangerous() {
    let env = Setup::new(tiny())
        .integrations(Arc::new(Fake::default()))
        .start()
        .await;
    let e = env
        .err(
            &user(),
            "integration_use_path",
            json!({"id": "plain", "path": "relative/emu"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    env.ok(
        &user(),
        "integration_use_path",
        json!({"id": "plain", "path": "/bin/echo"}),
    )
    .await;
    // `remove` and `emulator_run` always go through the approver; the default refuses.
    let e = env
        .err(&user(), "integration_remove", json!({"id": "plain"}))
        .await;
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied");
    let out = env
        .ok(
            &approved(user()),
            "integration_remove",
            json!({"id": "plain"}),
        )
        .await;
    assert_eq!(out["note"], "gone");
}

#[tokio::test]
async fn emulator_run_hands_the_file_to_the_emulator() {
    let backend = Arc::new(Fake::default());
    let env = Setup::new(tiny())
        .integrations(backend.clone())
        .start()
        .await;
    let ctx = approved(user());
    let run = |args| env.call(&ctx, "emulator_run", args);

    // Not installed yet.
    assert_eq!(
        run(json!({"id": "plain"})).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    env.ok(
        &user(),
        "integration_install",
        json!({"id": "plain", "accept_licence": true}),
    )
    .await;

    let out = run(json!({"id": "plain"})).await.unwrap();
    assert_eq!(out["exited"], true);
    assert_eq!(out["exit_code"], 0);
    let text = out["output"]["value"].as_str().unwrap();
    assert!(
        text.contains(&format!("ran {}", env.binary.display())),
        "{out}"
    );
    assert_eq!(out["command"][1], "ran");

    // No patches yet: says so and runs the original.
    let out = run(json!({"id": "plain", "target": "patched"}))
        .await
        .unwrap();
    assert!(
        out["notes"][0]
            .as_str()
            .unwrap()
            .contains("no byte patches"),
        "{out}"
    );

    // Any file, and the debug flags with the manifest's port.
    let file = env.tmp.path().join("export.bin");
    std::fs::write(&file, b"x").unwrap();
    let out = run(json!({
        "id": "plain", "target": "file", "file": file.to_str().unwrap(), "debug": true,
        "args": ["--extra"]
    }))
    .await
    .unwrap();
    assert_eq!(out["gdb"], "127.0.0.1:4321");
    assert_eq!(
        out["command"],
        json!(["/bin/echo", "debug", "4321", "--extra"])
    );

    // Bad requests.
    assert!(run(json!({"id": "plain", "target": "file"})).await.is_err());
    assert!(
        run(json!({"id": "plain", "target": "file", "file": "rel"}))
            .await
            .is_err()
    );
    // An agent is asked first.
    let e = env
        .err(&agent("r"), "emulator_run", json!({"id": "plain"}))
        .await;
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied");
}
