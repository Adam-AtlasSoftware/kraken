//! CLI behaviour on FakeEngine: flags, human output, exit codes, project handling.

mod common;

use async_trait::async_trait;
use common::*;
use kraken_cli::{CliAuthor, build_args, build_cli};
use kraken_host::KrakenConfig;
use kraken_proto::ProtoError;
use kraken_registry::{
    CallContext, Command, CommandKind, CommandSpec, Permission, Registry, Session,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

fn path_str(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn project_create_then_separate_invocations() {
    let work = workdir();
    let dir = work.tmp.path().join("proj");
    let env = fresh_env(KrakenConfig::default(), vec![]);

    let create = kraken(
        &env,
        &[
            "--json",
            "project-create",
            "--binary",
            &path_str(&work.binary),
            "--project-dir",
            &path_str(&dir),
        ],
    )
    .await;
    assert_eq!(create.code, 0, "{}", create.stderr);
    assert_eq!(create.json()["program"]["format"], "elf");

    // A new invocation opens the project from --project.
    let list = kraken(
        &env,
        &[
            "--json",
            "--project",
            &path_str(&dir),
            "list-functions",
            "--limit",
            "2",
        ],
    )
    .await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    let v = list.json();
    assert_eq!(v["items"].as_array().map(Vec::len), Some(2));
    assert!(v["next_cursor"].is_string());

    // KRAKEN_PROJECT works the same, and --project may follow the subcommand.
    let env_var = fresh_env(
        KrakenConfig::default(),
        vec![("KRAKEN_PROJECT", path_str(&dir))],
    );
    let info = kraken(&env_var, &["--json", "project-info"]).await;
    assert_eq!(info.code, 0, "{}", info.stderr);
    let info2 = kraken(
        &env,
        &["project-info", "--json", "--project", &path_str(&dir)],
    )
    .await;
    assert_eq!(info.json(), info2.json());

    // An edit made by one invocation is in the log seen by the next.
    let rename = kraken(
        &env,
        &[
            "--json",
            "--project",
            &path_str(&dir),
            "rename-symbol",
            "--address",
            "0x401000",
            "--new-name",
            "entry",
        ],
    )
    .await;
    assert_eq!(rename.code, 0, "{}", rename.stderr);
    assert_eq!(rename.json()["status"], "applied");
    let hist = kraken(&env, &["--json", "--project", &path_str(&dir), "history"]).await;
    assert_eq!(hist.json()["items"][0]["author"]["id"], "tester");
}

#[tokio::test]
async fn project_create_defaults_to_the_projects_root() {
    let work = workdir();
    let root = work.tmp.path().join("projects");
    let env = fresh_env(
        KrakenConfig {
            projects_root: Some(root.clone()),
            ..Default::default()
        },
        vec![],
    );
    let r = kraken(
        &env,
        &[
            "--json",
            "project-create",
            "--binary",
            &path_str(&work.binary),
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(root.join("prog_bin").join("meta.json").is_file());
    assert_eq!(
        r.json()["project_dir"].as_str(),
        Some(path_str(&root.join("prog_bin")).as_str())
    );
}

#[tokio::test]
async fn human_output_is_readable() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    let create = kraken(
        &r.env,
        &[
            "project-create",
            "--binary",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    assert_eq!(create.code, 0, "{}", create.stderr);
    assert!(create.stdout.contains("engine_build:"), "{}", create.stdout);

    let list = kraken(&r.env, &["--project", &dir, "list-functions"]).await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert!(lines[0].starts_with("ADDRESS"), "{lines:?}");
    assert!(lines[0].contains("NAME"));
    assert!(lines[1].starts_with("0x401000"));
    assert!(lines[1].contains("FUN_00401000"));
    assert!(list.stdout.contains("3 total"), "{}", list.stdout);

    let dec = kraken(
        &r.env,
        &["--project", &dir, "decompile", "--address", "0x401000"],
    )
    .await;
    assert_eq!(dec.code, 0, "{}", dec.stderr);
    assert!(dec.stdout.starts_with("int main("), "{}", dec.stdout);
    assert!(!dec.stdout.contains("untrusted"));
}

#[tokio::test]
async fn analyze_waits_and_reports_progress_on_stderr() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    kraken(
        &r.env,
        &[
            "project-create",
            "--binary",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    let a = kraken(&r.env, &["--json", "--project", &dir, "analyze"]).await;
    assert_eq!(a.code, 0, "{}", a.stderr);
    let v = a.json();
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["result"]["function_count"], 3);
    assert!(
        a.stderr.contains("[core]")
            || a.stderr.contains("[expensive]")
            || a.stderr.contains("[load]"),
        "progress on stderr: {:?}",
        a.stderr
    );
}

#[tokio::test]
async fn exit_codes() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    kraken(
        &r.env,
        &[
            "project-create",
            "--binary",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    let p = ["--json", "--project", dir.as_str()];
    let run = |extra: &[&str]| {
        let args: Vec<String> = p
            .iter()
            .chain(extra.iter())
            .map(|s| s.to_string())
            .collect();
        let env = &r.env;
        async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            kraken(env, &refs).await
        }
    };

    // 2: missing required argument, bad value, unknown flag, bad JSON.
    assert_eq!(
        run(&["rename-symbol", "--address", "0x401000"]).await.code,
        2
    );
    assert_eq!(run(&["list-functions", "--limit", "many"]).await.code, 2);
    assert_eq!(run(&["list-functions", "--nope"]).await.code, 2);
    assert_eq!(run(&["list-functions", "--args-json", "["]).await.code, 2);
    assert_eq!(run(&["proposals-list", "--status", "bogus"]).await.code, 2);
    assert_eq!(kraken(&r.env, &["no-such-command"]).await.code, 2);
    assert_eq!(kraken(&r.env, &[]).await.code, 2);
    // 3: not found.
    let nf = run(&["job-status", "--job-id", "job-404"]).await;
    assert_eq!(nf.code, 3, "{}", nf.stderr);
    assert_eq!(nf.json()["code"], "not_found");
    // 4: stale read.
    let stale = run(&[
        "rename-symbol",
        "--address",
        "0x401000",
        "--new-name",
        "a",
        "--expect-versions",
        "{\"name@ram:0x401000\": 7}",
    ])
    .await;
    assert_eq!(stale.code, 4, "{} {}", stale.stdout, stale.stderr);
    assert_eq!(stale.json()["code"], "conflict_stale_read");
    // 0 and the help paths.
    assert_eq!(run(&["list-functions"]).await.code, 0);
    assert_eq!(kraken(&r.env, &["--help"]).await.code, 0);
    assert_eq!(kraken(&r.env, &["list-functions", "--help"]).await.code, 0);
    assert_eq!(kraken(&r.env, &["--version"]).await.code, 0);
    // No project at all.
    let env = fresh_env(KrakenConfig::default(), vec![]);
    let none = kraken(&env, &["--json", "list-functions"]).await;
    assert_eq!(none.code, 2);
    assert!(
        none.json()["message"]
            .as_str()
            .unwrap_or("")
            .contains("--project")
    );
    // A missing project directory is not_found.
    let gone = kraken(
        &env,
        &["--json", "--project", "/nonexistent/proj", "list-functions"],
    )
    .await;
    assert_eq!(gone.code, 3, "{}", gone.stderr);
}

#[tokio::test]
async fn commands_json_describes_every_command() {
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let out = kraken(&r.env, &["commands", "--json"]).await;
    assert_eq!(out.code, 0);
    let v = out.json();
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), Registry::standard().len());
    for c in arr {
        let name = c["name"].as_str().expect("name");
        assert_eq!(c["args_schema"]["type"], "object", "{name}");
        assert!(c["output_schema"].is_object(), "{name}");
        assert_eq!(c["cli"]["subcommand"], name.replace('_', "-"));
        assert!(c["cli"]["flags"].is_array());
        assert!(c["summary"].as_str().is_some_and(|s| !s.is_empty()));
    }
    let human = kraken(&r.env, &["commands"]).await;
    assert!(human.stdout.starts_with("COMMAND"));
    assert!(human.stdout.contains("rename-symbol"));
}

#[test]
fn flags_and_args_json_build_the_same_arguments() {
    let registry = Registry::standard();
    let cli = build_cli(&registry);
    let entry = registry.get("set_comment").expect("set_comment");
    let by_flags = cli
        .clone()
        .try_get_matches_from([
            "kraken",
            "set-comment",
            "--address",
            "0x401000",
            "--kind",
            "eol",
            "--text",
            "hi",
            "--expect-versions",
            "{\"k\": 2}",
        ])
        .expect("flags parse");
    let by_json = cli
        .try_get_matches_from([
            "kraken", "set-comment", "--args-json",
            "{\"address\":\"0x401000\",\"kind\":\"eol\",\"text\":\"hi\",\"expect_versions\":{\"k\":2}}",
        ])
        .expect("json parses");
    let a = build_args(entry, by_flags.subcommand().expect("sub").1).expect("args");
    let b = build_args(entry, by_json.subcommand().expect("sub").1).expect("args");
    assert_eq!(a, b);
    assert_eq!(a["expect_versions"], json!({"k": 2}));
}

#[test]
fn every_command_exposes_a_flag_per_argument() {
    let registry = Registry::standard();
    let cli = build_cli(&registry);
    for entry in registry.iter() {
        let sub = cli
            .find_subcommand(entry.spec().name.replace('_', "-"))
            .unwrap_or_else(|| panic!("subcommand for {}", entry.spec().name));
        let props = entry.args_schema()["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for p in props.keys() {
            let flag = p.replace('_', "-");
            assert!(
                sub.get_arguments()
                    .any(|a| a.get_long() == Some(flag.as_str())),
                "{} lacks --{flag}",
                entry.spec().name
            );
        }
    }
}

// A dangerous command to exercise approval.

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PatchArgs {
    /// Bytes to write.
    bytes: String,
}

#[derive(Serialize, JsonSchema)]
struct PatchOut {
    /// What was written.
    written: String,
}

struct PatchBytes;

#[async_trait]
impl Command for PatchBytes {
    type Args = PatchArgs;
    type Output = PatchOut;
    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_bytes",
            "Write bytes into the binary",
            CommandKind::Mutation,
            Permission::Dangerous,
        )
    }
    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        a: PatchArgs,
    ) -> Result<PatchOut, ProtoError> {
        Ok(PatchOut { written: a.bytes })
    }
}

#[tokio::test]
async fn dangerous_commands_are_denied_without_a_prompt_and_run_with_yes() {
    let work = workdir();
    let mut r = rig(CliAuthor::User("tester".into()), vec![]);
    let mut registry = Registry::standard();
    registry.register(PatchBytes);
    r.env.registry = std::sync::Arc::new(registry);
    let dir = path_str(&work.tmp.path().join("p"));
    kraken(
        &r.env,
        &[
            "project-create",
            "--binary",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    let denied = kraken(
        &r.env,
        &["--json", "--project", &dir, "patch-bytes", "--bytes", "90"],
    )
    .await;
    assert_eq!(denied.code, 4, "{}", denied.stderr);
    assert_eq!(denied.json()["details"]["approval"], "denied");
    let ok = kraken(
        &r.env,
        &[
            "--json",
            "--yes",
            "--project",
            &dir,
            "patch-bytes",
            "--bytes",
            "90",
        ],
    )
    .await;
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    assert_eq!(ok.json(), json!({"written": "90"}));
}
