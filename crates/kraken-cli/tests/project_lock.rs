//! A project open in this process is refused to a second `kraken` process running without the
//! daemon, with a message that says what to do.

mod common;

use std::sync::Arc;

use common::*;
use kraken_registry::Session;

#[tokio::test]
async fn a_second_process_without_the_daemon_is_told_the_project_is_in_use() {
    let work = workdir();
    let dir = work.tmp.path().join("p");
    let session = Session::create(&dir, &work.binary, Arc::new(StatefulFactory))
        .await
        .expect("create");
    let runtime = work.tmp.path().join("runtime");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kraken"))
        .args(["--json", "project-info", "--project"])
        .arg(&dir)
        .env("KRAKEN_NO_DAEMON", "1")
        .env("KRAKEN_RUNTIME_DIR", &runtime)
        .env("XDG_CONFIG_HOME", work.tmp.path().join("config"))
        .env("XDG_DATA_HOME", work.tmp.path().join("data"))
        .output()
        .expect("run kraken");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{stdout}{stderr}");
    let text = format!("{stdout}{stderr}");
    assert!(
        text.contains(&format!(
            "open in another KRAKEN process (pid {})",
            std::process::id()
        )),
        "{text}"
    );
    assert!(text.contains("use the daemon"), "{text}");
    drop(session);
}
