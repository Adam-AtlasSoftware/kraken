//! The per-project engine choice on the built `kraken` binary: the `--engine` flag, the engine
//! recorded in `meta.json` and reported by `project_info`, and a real native project created,
//! listed, decompiled, renamed and reopened through the CLI.
//!
//! The real test needs the native library in this build and the compiled `.sla` files
//! (`cargo xtask native-src && cargo xtask native-sla`, then a rebuild); without them it
//! prints a note and passes.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

struct Kraken {
    runtime: tempfile::TempDir,
    config: PathBuf,
}

impl Kraken {
    fn new() -> Kraken {
        let runtime = tempfile::Builder::new()
            .prefix("kr")
            .tempdir_in("/tmp")
            .expect("runtime dir");
        // An empty config: the user's own settings must not leak in.
        let config = runtime.path().join("config.toml");
        std::fs::write(&config, "").expect("config");
        Kraken { runtime, config }
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_kraken"))
            .env("KRAKEN_CONFIG", &self.config)
            .env("KRAKEN_RUNTIME_DIR", self.runtime.path())
            .env("KRAKEN_NO_DAEMON", "1")
            .env_remove("KRAKEN_PROJECT")
            .env_remove("KRAKEN_ENGINE")
            .arg("--json")
            .args(args)
            .output()
            .expect("run kraken");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, stdout, stderr) = self.run(args);
        assert_eq!(
            code, 0,
            "kraken {args:?}\nstdout: {stdout}\nstderr: {stderr}"
        );
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("kraken {args:?}: not JSON ({e}): {stdout}"))
    }
}

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/bin")
        .join(name)
}

#[test]
fn the_engine_flag_is_a_choice_of_three() {
    let k = Kraken::new();
    let (code, out, _) = {
        let out = Command::new(env!("CARGO_BIN_EXE_kraken"))
            .env("KRAKEN_CONFIG", &k.config)
            .args(["project-create", "--help"])
            .output()
            .expect("run kraken");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::new(),
        )
    };
    assert_eq!(code, 0);
    assert!(out.contains("--engine <VALUE>"), "{out}");
    assert!(
        out.contains("[possible values: ghidra, native, auto]"),
        "{out}"
    );

    let (code, _, err) = k.run(&[
        "project-create",
        "--binary",
        "/bin/sh",
        "--project-dir",
        k.runtime.path().join("p").to_str().unwrap(),
        "--engine",
        "turbo",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("turbo"), "{err}");
}

#[test]
fn an_explicit_native_request_that_cannot_be_met_says_how_to_get_out() {
    let k = Kraken::new();
    let text = k.runtime.path().join("notes.txt");
    std::fs::write(&text, "not a program").unwrap();
    let dir = k.runtime.path().join("p");
    let (code, stdout, stderr) = k.run(&[
        "project-create",
        "--binary",
        text.to_str().unwrap(),
        "--project-dir",
        dir.to_str().unwrap(),
        "--engine",
        "native",
    ]);
    assert_ne!(code, 0, "{stdout}");
    let text = format!("{stdout}{stderr}");
    assert!(text.contains("native engine was requested"), "{text}");
    assert!(text.contains("--engine ghidra"), "{text}");
    assert!(!dir.join("meta.json").exists(), "no half-made project");
}

#[test]
fn setup_native_conflicts_with_dotnet() {
    let k = Kraken::new();
    let (code, _, err) = k.run(&["setup", "--native", "--dotnet"]);
    assert_ne!(code, 0);
    assert!(err.contains("cannot be used with"), "{err}");
}

fn native_ready() -> bool {
    match kraken_host::native::NativeProbe::detect(None).problem() {
        None => true,
        Some(why) => {
            eprintln!("skipping the real native test: {why}");
            false
        }
    }
}

#[test]
fn a_native_project_is_created_listed_decompiled_and_reopened_through_the_cli() {
    if !native_ready() {
        return;
    }
    let k = Kraken::new();
    let dir = k.runtime.path().join("proj");
    let bin = corpus("pie_list-O0");
    let info = k.ok(&[
        "project-create",
        "--binary",
        bin.to_str().unwrap(),
        "--project-dir",
        dir.to_str().unwrap(),
        "--engine",
        "auto",
    ]);
    assert_eq!(info["engine"]["kind"], "native", "{info}");
    assert_eq!(info["engine"]["choice"], "auto");
    assert!(
        info["engine"]["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("auto picked native")),
        "{info}"
    );
    assert!(
        info["engine_build"]
            .as_str()
            .unwrap()
            .starts_with("kraken-native/"),
        "{info}"
    );

    let meta: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["engine_kind"], "native");
    assert_eq!(meta["engine_choice"], "auto");

    let p = dir.to_str().unwrap();
    let list = k.ok(&["--project", p, "list-functions", "--name-filter", "cmp_id"]);
    let f = &list["items"][0];
    assert_eq!(f["name"]["value"], "cmp_id", "{list}");
    let addr = f["address"].as_str().expect("address").to_string();
    let dec = k.ok(&["--project", p, "decompile", "--address", &addr]);
    let text = dec["text"]["value"].as_str().expect("decompile text");
    assert!(text.contains("cmp_id") && text.contains("return"), "{text}");

    // A new process reopens the project with the recorded engine, whatever the default is.
    let again = k.ok(&["--project", p, "project-info"]);
    assert_eq!(again["engine"]["kind"], "native");
    assert_eq!(again["engine"]["choice"], "auto");
    let list = k.ok(&["--project", p, "list-functions", "--name-filter", "cmp_id"]);
    assert_eq!(list["items"][0]["name"]["value"], "cmp_id");

    // Edits go through the native mutator (in its worker) and survive into a new process, which
    // replays the engine directory's native-state.json.
    let renamed = k.ok(&[
        "--project",
        p,
        "rename-symbol",
        "--address",
        &addr,
        "--new-name",
        "compare_ids",
    ]);
    assert_eq!(renamed["status"], "applied", "{renamed}");
    let list = k.ok(&[
        "--project",
        p,
        "list-functions",
        "--name-filter",
        "compare_ids",
    ]);
    assert_eq!(list["items"][0]["name"]["value"], "compare_ids", "{list}");
    let dec = k.ok(&["--project", p, "decompile", "--address", &addr]);
    let text = dec["text"]["value"].as_str().expect("decompile text");
    assert!(text.contains("compare_ids("), "{text}");
    let states = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|d| d.path().join("native-state.json").is_file())
        .count();
    assert_eq!(states, 1, "the engine directory holds native-state.json");
}
