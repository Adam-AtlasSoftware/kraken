//! `kraken rewrite-*` in-process (no daemon): plan and status as tables, a cassette-backed
//! rewrite of one function, accepting it, and exporting it. Needs a Ghidra install for the SLEIGH
//! specs of the emulator, like the kraken-rewrite tests.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{FakeFactory, kraken};
use engine_fake::FixtureFile;
use kraken_agent::ReplayProvider;
use kraken_cli::{CliAuthor, CliEnv, DaemonMode};
use kraken_host::KrakenConfig;
use kraken_registry::Registry;
use kraken_rewrite::oracle::OracleConfig;
use kraken_rewrite::service::{FixedProvider, RewriteConfig, RewriteService};

fn corpus(sub: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(sub)
        .join(file)
}

/// A Ghidra install for the SLEIGH specs: the environment, else the dev cache.
fn ghidra_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("KRAKEN_GHIDRA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    let home = std::env::var_os("HOME")?;
    std::fs::read_dir(Path::new(&home).join(".cache/kraken-dev/ghidra"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.join("Ghidra/Processors/x86/data/languages/x86.ldefs")
                .is_file()
        })
}

fn env(binary: &str, cassette: Option<&str>) -> CliEnv {
    let fixture =
        FixtureFile::from_path(&corpus("fixtures", &format!("{binary}.json"))).expect("fixture");
    let provider = match cassette {
        Some(c) => ReplayProvider::from_path(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kraken-rewrite/cassettes")
                .join(c),
        )
        .expect("cassette"),
        None => ReplayProvider::scripted(vec![]),
    };
    let service = RewriteService::new(
        Arc::new(FixedProvider(Arc::new(provider))),
        RewriteConfig {
            oracle: OracleConfig {
                ghidra_home: ghidra_home(),
                ..OracleConfig::default()
            },
            ..RewriteConfig::default()
        },
    );
    CliEnv {
        registry: Arc::new(Registry::standard()),
        factory: Arc::new(FakeFactory { fixture }),
        config: KrakenConfig::default(),
        author: CliAuthor::User("tester".into()),
        vars: Box::new(|_| None),
        interactive: false,
        session: None,
        daemon: DaemonMode::Direct,
        rewrite: Some(service.into_backend()),
    }
}

async fn create(env: &CliEnv, binary: &str, dir: &Path) {
    let bin = corpus("bin", binary);
    let run = kraken(
        env,
        &[
            "--json",
            "project-create",
            "--binary",
            bin.to_str().expect("utf8"),
            "--project-dir",
            dir.to_str().expect("utf8"),
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
}

#[tokio::test]
async fn plan_and_status_print_tables() {
    let env = env("switch_vm-O0", None);
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("p");
    create(&env, "switch_vm-O0", &dir).await;
    let project = dir.to_str().expect("utf8");

    let plan = kraken(&env, &["--project", project, "rewrite-plan"]).await;
    assert_eq!(plan.code, 0, "{}", plan.stderr);
    let lines: Vec<&str> = plan.stdout.lines().collect();
    assert_eq!(
        lines[0],
        "6 of 18 functions planned in 6 groups (4 import thunks and 8 runtime functions left out)"
    );
    assert!(lines[1].starts_with("ORDER  ADDRESS"), "{}", lines[1]);
    let names: Vec<&str> = lines[2..8]
        .iter()
        .map(|l| l.split_whitespace().nth(2).expect("name column"))
        .collect();
    assert_eq!(
        names,
        ["vm_fail", "push", "pop", "vm_run", "op_name", "main"]
    );
    assert!(lines[2].contains("planned"), "{}", lines[2]);

    let status = kraken(&env, &["--project", project, "rewrite-status"]).await;
    assert_eq!(status.code, 0, "{}", status.stderr);
    assert!(
        status
            .stdout
            .starts_with("6 planned, 0 translated, 0 verified, 0 failed, 0 accepted (6 functions)"),
        "{}",
        status.stdout
    );
    assert!(status.stdout.contains("vm_fail"));

    // The same through --json, and a page of the plan with a cursor.
    let json = kraken(
        &env,
        &[
            "--json",
            "--project",
            project,
            "rewrite-plan",
            "--limit",
            "2",
        ],
    )
    .await;
    let v = json.json();
    assert_eq!(v["entries"].as_array().map(Vec::len), Some(2));
    assert_eq!(v["next_cursor"], "2");
    let page = kraken(
        &env,
        &[
            "--project",
            project,
            "rewrite-plan",
            "--limit",
            "2",
            "--cursor",
            "2",
        ],
    )
    .await;
    assert!(page.stdout.contains("more: --cursor 4"), "{}", page.stdout);

    // Before any plan the status says what to do.
    let fresh = tempfile::tempdir().expect("tempdir");
    let dir2 = fresh.path().join("p");
    create(&env, "switch_vm-O0", &dir2).await;
    let st = kraken(
        &env,
        &["--project", dir2.to_str().expect("utf8"), "rewrite-status"],
    )
    .await;
    assert!(
        st.stdout.contains("no plan stored, run rewrite-plan"),
        "{}",
        st.stdout
    );
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn rewrite_accept_and_export_from_the_command_line() {
    let env = env("pie_list-O0", Some("service-pie.json"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("p");
    create(&env, "pie_list-O0", &dir).await;
    let project = dir.to_str().expect("utf8");

    let run = kraken(
        &env,
        &[
            "--project",
            project,
            "rewrite-function",
            "--address",
            "0x10124e",
            "--cases",
            "30",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.contains("cmp_id 0x10124e") && run.stdout.contains(": pass --"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("status: verified"));
    assert!(
        run.stdout
            .contains("accept it with: kraken rewrite-accept --unit ru-")
    );
    let unit = run
        .stdout
        .lines()
        .find_map(|l| l.split("rewrite-accept --unit ").nth(1))
        .expect("unit id")
        .trim()
        .to_string();

    let st = kraken(&env, &["--project", project, "rewrite-status"]).await;
    assert!(
        st.stdout.contains("0 planned, 0 translated, 1 verified"),
        "{}",
        st.stdout
    );

    let acc = kraken(
        &env,
        &["--project", project, "rewrite-accept", "--unit", &unit],
    )
    .await;
    assert_eq!(acc.code, 0, "{}", acc.stderr);
    assert!(acc.stdout.contains("status: accepted"), "{}", acc.stdout);
    let st = kraken(&env, &["--project", project, "rewrite-status"]).await;
    assert!(st.stdout.contains("1 accepted"), "{}", st.stdout);

    let exp = kraken(
        &env,
        &[
            "--json",
            "--project",
            project,
            "rewrite-export",
            "--dir",
            "export",
        ],
    )
    .await;
    assert_eq!(exp.code, 0, "{}", exp.stderr);
    let v = exp.json();
    assert_eq!(v["result"]["built"], true, "{v}");
    // The function, and the entry point that tells exported code where the program's data is.
    assert_eq!(
        v["result"]["symbols"],
        serde_json::json!(["cmp_id", "kraken_attach_image"])
    );
    assert!(dir.join("export/README.md").is_file());

    // A function the oracle cannot check is explained, not attempted.
    let bad = kraken(
        &env,
        &[
            "--project",
            project,
            "rewrite-function",
            "--address",
            "0x101189",
        ],
    )
    .await;
    assert_ne!(bad.code, 0);
    assert!(
        bad.stderr.contains("cannot check `node_new` yet"),
        "{}",
        bad.stderr
    );
}
