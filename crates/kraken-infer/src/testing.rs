//! Helpers for tests of crates that host backends (the daemon, the CLI, the GUI): find the
//! `kraken-fake-server` binary and describe it as an engine manifest. Not part of the API.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const NAME: &str = "kraken-fake-server";

fn find(dir: &Path) -> Option<PathBuf> {
    let file = format!("{NAME}{}", std::env::consts::EXE_SUFFIX);
    [Some(dir), dir.parent()]
        .into_iter()
        .flatten()
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// Path of the fake inference server next to the running test executable, building it with
/// `cargo build -p kraken-infer` when only another package was tested.
///
/// # Panics
/// When the binary cannot be found or built; this is for tests.
pub fn fake_server_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(locate_or_build).clone()
}

#[allow(clippy::expect_used)]
fn locate_or_build() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let dir = exe.parent().expect("test executable directory");
    if let Some(p) = find(dir) {
        return p;
    }
    let release = dir
        .ancestors()
        .any(|a| a.file_name().is_some_and(|n| n == "release"));
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "-p", "kraken-infer", "--bin", NAME]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().expect("run cargo build");
    assert!(status.success(), "cargo build -p kraken-infer failed");
    find(dir).expect("kraken-fake-server was built")
}

/// An engine manifest (TOML) that runs the fake server. Settings: `model` (a file path),
/// `ready_after` (seconds until `/health` answers), `ctx`, `flash` and `mode`.
pub fn fake_manifest(id: &str, server: &Path) -> String {
    format!(
        r#"
id = "{id}"
name = "Fake engine"
license = "MIT"
command = ['{server}', '--port', '{{port}}', '--ready-after', '{{ready_after}}']
health_path = "/health"
ready_timeout_secs = 30
grace_secs = 1

[capabilities]
os = ["linux", "macos", "windows"]
arch = ["x86_64", "aarch64"]
gpu_apis = ["cpu"]
min_ram_mb = 16
supports_moe_offload = true

[settings_schema]
type = "object"
required = ["model"]

[settings_schema.properties.model]
type = "string"
title = "Model file"
x-kraken-widget = "file-path"

[settings_schema.properties.ready_after]
type = "number"
title = "Seconds until ready"
minimum = 0
default = 0

[settings_schema.properties.ctx]
type = "integer"
title = "Context size"
minimum = 1
default = 4096

[settings_schema.properties.flash]
type = "boolean"
title = "Flash attention"
default = true

[settings_schema.properties.mode]
type = "string"
title = "Mode"
enum = ["fast", "small"]
default = "fast"
"#,
        server = server.display()
    )
}
