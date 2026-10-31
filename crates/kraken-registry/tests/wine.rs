//! `wine_run`, and the Wine runtime of `emulate_compare` and `patch_verify`, on the PE corpus
//! programs. The real runs need Wine on the PATH and a sandbox (Landlock); they are skipped
//! where either is missing.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use common::{Setup, agent, tiny, user};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    IntegrationRemoveOut, IntegrationView, IntegrationsBackend, LaunchSpec,
};
use kraken_registry::{AutoApprove, CallContext};
use serde_json::{Value, json};

/// A catalogue whose `wine` entry is the Wine on the PATH.
#[derive(Debug)]
struct WineOnPath(PathBuf);

#[async_trait]
impl IntegrationsBackend for WineOnPath {
    fn list(&self) -> Result<Vec<IntegrationView>, ProtoError> {
        Ok(Vec::new())
    }
    async fn install(&self, _: &str, _: bool) -> Result<IntegrationView, ProtoError> {
        Err(ProtoError::new(ErrorCode::Unsupported, "no"))
    }
    fn use_path(&self, _: &str, _: &Path) -> Result<IntegrationView, ProtoError> {
        Err(ProtoError::new(ErrorCode::Unsupported, "no"))
    }
    fn remove(&self, _: &str) -> Result<IntegrationRemoveOut, ProtoError> {
        Err(ProtoError::new(ErrorCode::Unsupported, "no"))
    }
    fn launch_spec(&self, id: &str) -> Result<LaunchSpec, ProtoError> {
        if id != "wine" {
            return Err(ProtoError::new(ErrorCode::NotFound, "only wine"));
        }
        Ok(LaunchSpec {
            id: id.into(),
            name: "Wine".into(),
            exe: self.0.clone(),
            argv: vec!["{exe}".into(), "{binary}".into()],
            gdb_argv: None,
            gdb_port: None,
            gui: true,
            env: Vec::new(),
        })
    }
}

fn wine_on_path() -> Option<PathBuf> {
    if !kraken_confine::enforced() {
        return None;
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("wine"))
        .find(|p| p.is_file())
}

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/pe/bin")
        .join(name)
}

fn approved(ctx: CallContext) -> CallContext {
    ctx.with_approval(Arc::new(AutoApprove))
}

/// A session whose project binary is a copy of `exe`, with `win_dll.dll` beside it.
async fn project_of(wine: PathBuf, exe: &str) -> common::Env {
    let env = Setup::new(tiny())
        .integrations(Arc::new(WineOnPath(wine)))
        .start()
        .await;
    std::fs::copy(corpus(exe), &env.binary).expect("copy the program");
    let dir = env.binary.parent().expect("dir");
    std::fs::copy(corpus("win_dll-x64-O0.dll"), dir.join("win_dll.dll")).expect("copy the dll");
    env
}

/// A text field with Windows line ends turned into `\n`.
fn text(v: &Value) -> String {
    v["value"]
        .as_str()
        .unwrap_or_default()
        .replace("\r\n", "\n")
}

#[tokio::test]
async fn wine_run_asks_first_and_checks_its_arguments() {
    let env = Setup::new(tiny())
        .integrations(Arc::new(WineOnPath(PathBuf::from("/usr/bin/wine"))))
        .start()
        .await;
    let e = env.err(&agent("r"), "wine_run", json!({})).await;
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    let ctx = approved(user());
    let e = env
        .err(&ctx, "wine_run", json!({"timeout_seconds": 0}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env.err(&ctx, "wine_run", json!({"target": "file"})).await;
    assert!(e.message.contains("needs `file`"), "{e}");
    let e = env
        .err(
            &ctx,
            "wine_run",
            json!({"target": "file", "file": "rel.exe"}),
        )
        .await;
    assert!(e.message.contains("absolute"), "{e}");
}

#[tokio::test]
async fn a_pe_console_program_runs_under_wine() {
    let Some(wine) = wine_on_path() else {
        eprintln!("skipped: no wine on the PATH or no sandbox");
        return;
    };
    let env = project_of(wine, "win_tls-x64-O0.exe").await;
    let out = env
        .ok(
            &approved(user()),
            "wine_run",
            json!({"timeout_seconds": 120}),
        )
        .await;
    assert_eq!(out["exit"]["kind"], "code", "{out}");
    assert_eq!(out["exit"]["value"], 0, "{out}");
    let stdout = text(&out["stdout"]);
    assert_eq!(
        stdout,
        "1 ant one\n2 bat two\n5 eel five\n7 cow seven\n9 yak many\nfirst by name: ant\n\
         KRAKEN PE CORPUS ff8a927a\napply_all=55 secret=37 version=win_dll 1.0\n\
         counter=9 tls=1 probe=1\n"
    );
    let notes = out["notes"].to_string();
    assert!(notes.contains("confined (landlock"), "{notes}");
}

#[tokio::test]
async fn switch_vm_runs_and_a_patched_copy_is_compared() {
    let Some(wine) = wine_on_path() else {
        eprintln!("skipped: no wine on the PATH or no sandbox");
        return;
    };
    let env = project_of(wine, "switch_vm-x64-O0.exe").await;
    let ctx = approved(user());
    let expected = "out: 5\nout: 4\nout: 3\nout: 2\nout: 1\nresult=0 steps=28 first=push\n";
    let out = env
        .ok(&ctx, "wine_run", json!({"timeout_seconds": 120}))
        .await;
    assert_eq!(text(&out["stdout"]), expected, "{out}");

    // Patch the "result=" format string by file offset, then compare original and patched.
    let bytes = std::fs::read(&env.binary).expect("read");
    let at = bytes
        .windows(7)
        .position(|w| w == b"result=")
        .expect("format string");
    env.ok(
        &user(),
        "patch_set",
        json!({"offset": format!("{at:#x}"), "bytes": "52"}),
    )
    .await;
    let cmp = env
        .ok(
            &ctx,
            "emulate_compare",
            json!({"runtime": "wine", "timeout_seconds": 120}),
        )
        .await;
    assert_eq!(cmp["same"], false, "{cmp}");
    assert_eq!(cmp["differences"][0]["field"], "stdout", "{cmp}");
    let summary = text(&cmp["differences"][0]["summary"]);
    assert!(
        summary.contains("result=0") && summary.contains("Result=0"),
        "{summary}"
    );
    assert!(text(&cmp["b"]["stdout"]).contains("Result=0 steps=28"));
    assert_eq!(text(&cmp["a"]["stdout"]), expected);

    // The same through patch_verify: it records a verdict.
    let v = env
        .ok(
            &ctx,
            "patch_verify",
            json!({"runtime": "wine", "timeout_seconds": 120}),
        )
        .await;
    assert_eq!(v["same"], false, "{v}");
    assert_eq!(v["verdict"]["same"], false, "{v}");

    // A patched wine_run prints the patched text.
    let p = env
        .ok(
            &ctx,
            "wine_run",
            json!({"target": "patched", "timeout_seconds": 120}),
        )
        .await;
    assert!(text(&p["stdout"]).contains("Result=0"), "{p}");
}
