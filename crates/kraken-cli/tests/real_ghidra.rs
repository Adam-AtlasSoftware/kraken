//! Smoke test of the built `kraken` binary against a real Ghidra. `#[ignore]`d:
//!
//! ```text
//! source plans/dev-env.sh && cargo xtask ghidra-ext && \
//!   cargo test -p kraken-cli --test real_ghidra -- --ignored --nocapture
//! ```
//!
//! The Ghidra install comes from `KRAKEN_GHIDRA_HOME` / `KRAKEN_JAVA_HOME` (or the pinned copies
//! in `~/.cache/kraken-dev`) and the extension jar from `cargo xtask ghidra-ext`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn first_child(parent: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

struct Kraken {
    project: PathBuf,
    config: PathBuf,
    ghidra_home: Option<PathBuf>,
    java_home: Option<PathBuf>,
}

impl Kraken {
    /// Runs `kraken --json [--project P] args...` and returns (exit code, stdout, stderr).
    fn run(&self, with_project: bool, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kraken"));
        cmd.env("KRAKEN_CONFIG", &self.config);
        cmd.env_remove("KRAKEN_PROJECT");
        if let Some(g) = &self.ghidra_home {
            cmd.env("KRAKEN_GHIDRA_HOME", g);
        }
        if let Some(j) = &self.java_home {
            cmd.env("KRAKEN_JAVA_HOME", j);
        }
        cmd.arg("--json");
        if with_project {
            cmd.arg("--project").arg(&self.project);
        }
        let out = cmd.args(args).output().expect("run kraken");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn ok(&self, with_project: bool, args: &[&str]) -> Value {
        let (code, stdout, stderr) = self.run(with_project, args);
        assert_eq!(
            code, 0,
            "kraken {args:?} failed\nstdout: {stdout}\nstderr: {stderr}"
        );
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("kraken {args:?}: stdout is not JSON ({e}): {stdout}"))
    }
}

fn names(list: &Value) -> Vec<(String, String)> {
    list["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|f| {
            (
                f["address"].as_str().expect("address").to_string(),
                f["name"]["value"].as_str().expect("name").to_string(),
            )
        })
        .collect()
}

#[test]
#[ignore = "needs Ghidra: source plans/dev-env.sh && cargo xtask ghidra-ext"]
fn project_create_analyze_list_decompile_rename_undo() {
    let cache = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kraken-dev"));
    let ghidra_home = std::env::var_os("KRAKEN_GHIDRA_HOME")
        .map(PathBuf::from)
        .or_else(|| cache.as_ref().and_then(|c| first_child(&c.join("ghidra"))));
    let java_home = std::env::var_os("KRAKEN_JAVA_HOME")
        .or_else(|| std::env::var_os("JAVA_HOME"))
        .map(PathBuf::from)
        .or_else(|| cache.as_ref().and_then(|c| first_child(&c.join("jdk"))));

    // Ghidra rejects project paths with a dot-prefixed element, so no default `.tmpXXXX` dirs.
    let tmp = tempfile::Builder::new()
        .prefix("kraken-smoke-")
        .tempdir()
        .expect("tempdir");
    let k = Kraken {
        project: tmp.path().join("proj"),
        config: tmp.path().join("no-config.toml"),
        ghidra_home,
        java_home,
    };
    let binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/pie_list-O0");
    assert!(
        binary.is_file(),
        "missing corpus binary {}",
        binary.display()
    );

    let created = k.ok(
        false,
        &[
            "project-create",
            "--binary",
            binary.to_str().expect("utf-8 path"),
            "--project-dir",
            k.project.to_str().expect("utf-8 path"),
        ],
    );
    assert_eq!(created["program"]["format"], "elf");
    assert!(
        created["capabilities"]
            .as_array()
            .is_some_and(|c| c.len() >= 6)
    );

    let (code, stdout, stderr) = k.run(true, &["analyze"]);
    assert_eq!(
        code, 0,
        "analyze failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    let job: Value = serde_json::from_str(stdout.trim()).expect("job JSON");
    assert_eq!(job["status"], "succeeded", "{job}");
    assert!(
        job["result"]["function_count"].as_u64().unwrap_or(0) > 10,
        "{job}"
    );
    assert!(
        stderr.contains('['),
        "analyze prints progress on stderr: {stderr}"
    );

    let list = k.ok(true, &["list-functions", "--limit", "200"]);
    let funcs = names(&list);
    assert!(funcs.len() > 10, "{funcs:?}");
    let (main_addr, _) = funcs
        .iter()
        .find(|(_, n)| n == "main")
        .unwrap_or_else(|| panic!("no main in {funcs:?}"))
        .clone();

    let dec = k.ok(true, &["decompile", "--address", &main_addr]);
    let text = dec["text"]["value"].as_str().expect("decompile text");
    assert!(text.contains("main"), "{text}");

    // Rename a FUN_ function (else any function but main), then undo.
    let (addr, original) = funcs
        .iter()
        .find(|(_, n)| n.starts_with("FUN_"))
        .or_else(|| {
            funcs
                .iter()
                .find(|(_, n)| n != "main" && !n.starts_with('_'))
        })
        .cloned()
        .expect("a function to rename");
    let renamed = k.ok(
        true,
        &[
            "rename-symbol",
            "--address",
            &addr,
            "--new-name",
            "smoke_renamed",
        ],
    );
    assert_eq!(renamed["status"], "applied", "{renamed}");
    let after = names(&k.ok(true, &["list-functions", "--name-filter", "smoke_renamed"]));
    assert_eq!(after, vec![(addr.clone(), "smoke_renamed".to_string())]);

    let undone = k.ok(true, &["undo"]);
    assert_eq!(undone["status"], "applied", "{undone}");
    let restored = names(&k.ok(true, &["list-functions", "--limit", "200"]));
    assert!(
        restored.contains(&(addr.clone(), original.clone())),
        "{addr} should be named {original} again: {restored:?}"
    );
    assert!(!restored.iter().any(|(_, n)| n == "smoke_renamed"));
}
