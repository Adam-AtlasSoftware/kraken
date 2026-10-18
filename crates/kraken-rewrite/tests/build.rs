//! `rewrite_build`: only crates KRAKEN wrote are built, and the build, test and run steps run in
//! the sandbox.

use std::path::Path;

use kraken_rewrite::build::build_and_test;
use kraken_rewrite::sandbox::{self, Confinement};

fn crate_dir(root: &Path, marker: (&str, &str), test_body: &str) -> std::path::PathBuf {
    let dir = root.join("c");
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(
        dir.join("src/main.rs"),
        format!(
            "fn add(a: i32, b: i32) -> i32 {{ a + b }}\n\
             fn main() {{ println!(\"sum {{}}\", add(2, std::env::args().count() as i32)); }}\n\
             #[cfg(test)]\nmod t {{ use super::*; #[test] fn adds() {{ {test_body} }} }}\n"
        ),
    )
    .expect("main");
    std::fs::write(dir.join(marker.0), marker.1).expect("marker");
    dir
}

fn root(name: &str) -> std::path::PathBuf {
    let r = std::env::temp_dir().join(format!("kr-build-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(&r).expect("root");
    r
}

#[test]
fn a_folder_kraken_did_not_write_is_refused() {
    let r = root("refuse");
    let dir = crate_dir(&r, ("notes.txt", "hello"), "assert_eq!(add(1, 1), 2);");
    let err =
        build_and_test(&dir, true, None, &Confinement::default(), &|_| {}).expect_err("no marker");
    assert!(
        err.to_string().contains("not a crate KRAKEN exported"),
        "{err}"
    );
    let dir2 = crate_dir(
        &root("refuse2"),
        ("manifest.json", r#"{"generator":"something-else"}"#),
        "assert_eq!(add(1, 1), 2);",
    );
    assert!(build_and_test(&dir2, true, None, &Confinement::default(), &|_| {}).is_err());
    let _ = std::fs::remove_dir_all(r);
}

#[test]
fn an_export_cannot_be_run() {
    let r = root("lib");
    let dir = crate_dir(
        &r,
        ("manifest.json", r#"{"generator":"kraken-rewrite"}"#),
        "assert_eq!(add(1, 1), 2);",
    );
    let args = vec!["x".to_string()];
    let err = build_and_test(&dir, true, Some(&args), &Confinement::default(), &|_| {})
        .expect_err("export has no binary to run");
    assert!(err.to_string().contains("program crate"), "{err}");
    let _ = std::fs::remove_dir_all(r);
}

#[test]
fn a_program_crate_builds_tests_and_runs_in_the_sandbox() {
    if !sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code");
        return;
    }
    let r = root("ok");
    let dir = crate_dir(
        &r,
        (
            "kraken-program.json",
            r#"{"generator":"kraken-rewrite/program"}"#,
        ),
        "assert_eq!(add(1, 1), 2);",
    );
    let seen = std::sync::Mutex::new(Vec::new());
    let args = vec!["one".to_string()];
    let report = build_and_test(&dir, true, Some(&args), &Confinement::default(), &|s| {
        seen.lock().expect("lock").push(s.to_string());
    })
    .expect("build");
    assert!(report.passed(), "{report:?}");
    assert_eq!(report.kind, "program");
    let names: Vec<_> = report.steps.iter().map(|s| s.step.as_str()).collect();
    assert_eq!(names, ["build", "test", "run"]);
    assert_eq!(*seen.lock().expect("lock"), ["build", "test", "run"]);
    // argv[0] and "one": two arguments, so the program prints 2 + 2.
    assert!(
        report.steps[2].log_tail.0.contains("sum 4"),
        "{:?}",
        report.steps[2]
    );
    assert!(report.sandbox.starts_with("landlock"), "{}", report.sandbox);
    // Nothing was written next to the exported files.
    assert!(!dir.join("target").exists());
    let _ = std::fs::remove_dir_all(r);
}

#[test]
fn a_failing_test_ends_the_build_with_its_log() {
    if !sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code");
        return;
    }
    let r = root("fail");
    let dir = crate_dir(
        &r,
        (
            "kraken-program.json",
            r#"{"generator":"kraken-rewrite/program"}"#,
        ),
        "assert_eq!(add(1, 1), 3);",
    );
    let args = vec![];
    let report = build_and_test(&dir, true, Some(&args), &Confinement::default(), &|_| {})
        .expect("the build itself runs");
    assert!(!report.passed());
    let names: Vec<_> = report.steps.iter().map(|s| s.step.as_str()).collect();
    assert_eq!(
        names,
        ["build", "test"],
        "the run step must not follow a failed test"
    );
    assert_eq!(report.steps[1].exit, "exit 101");
    assert!(
        report.steps[1].log_tail.0.contains("adds"),
        "{:?}",
        report.steps[1]
    );
    let _ = std::fs::remove_dir_all(r);
}

#[test]
fn a_build_error_is_reported_not_raised() {
    if !sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code");
        return;
    }
    let r = root("err");
    let dir = crate_dir(
        &r,
        ("manifest.json", r#"{"generator":"kraken-rewrite"}"#),
        "assert_eq!(add(1, 1), 2);",
    );
    std::fs::write(
        dir.join("src/main.rs"),
        "fn main() { let x: i32 = \"no\"; }\n",
    )
    .expect("break");
    let report = build_and_test(&dir, true, None, &Confinement::default(), &|_| {}).expect("runs");
    assert!(!report.passed());
    assert_eq!(report.steps.len(), 1);
    assert!(
        report.steps[0].log_tail.0.contains("mismatched types"),
        "{:?}",
        report.steps[0]
    );
    let _ = std::fs::remove_dir_all(r);
}
