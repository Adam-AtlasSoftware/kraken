//! `kraken explain | overview | auto-name` with `kind = "terminal_agent"` in the `[provider]`
//! table, against the fake ACP agent (`kraken agents __fake-agent`). No network, no real agents,
//! no daemon.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};

use common::*;
use kraken_cli::{CliAuthor, CliEnv};

struct World {
    tmp: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        World {
            tmp: tempfile::Builder::new()
                .prefix("kraken-cli-termagent-")
                .tempdir()
                .expect("tempdir"),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        let p = self.tmp.path().join(name);
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    /// Configures the fake agent as a custom agent and selects it as the assistant.
    fn select(&self, provider_table: &str) -> Vec<(&'static str, String)> {
        let cfg_dir = self.dir("config").join("kraken");
        std::fs::create_dir_all(&cfg_dir).expect("mkdir");
        std::fs::write(
            cfg_dir.join("agents.toml"),
            format!(
                "[[agent]]\nid = \"fake\"\nname = \"Fake agent\"\ncommand = \"{}\"\nargs = [\"agents\", \"__fake-agent\"]\n",
                env!("CARGO_BIN_EXE_kraken")
            ),
        )
        .expect("agents.toml");
        let config = cfg_dir.join("config.toml");
        std::fs::write(&config, provider_table).expect("config.toml");
        let s = |p: &Path| p.to_string_lossy().into_owned();
        vec![
            ("PATH", s(&self.dir("empty"))),
            ("XDG_DATA_HOME", s(&self.dir("data"))),
            ("XDG_CONFIG_HOME", s(&self.dir("config"))),
            ("HOME", s(&self.dir("home"))),
            ("KRAKEN_CONFIG", s(&config)),
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_RUNTIME_DIR", s(&self.dir("runtime"))),
            ("KRAKEN_EXE", env!("CARGO_BIN_EXE_kraken").into()),
        ]
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

async fn project(env: &CliEnv, w: &Workdir) -> String {
    let dir = path_str(&w.tmp.path().join("p"));
    let c = kraken(
        env,
        &[
            "project-create",
            "--binary",
            &path_str(&w.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    assert_eq!(c.code, 0, "{}", c.stderr);
    dir
}

const FAKE: &str = "[provider]\nkind = \"terminal_agent\"\nagent = \"fake\"\n";

#[tokio::test]
async fn explain_runs_on_the_selected_terminal_agent() {
    let world = World::new();
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), world.select(FAKE));
    let dir = project(&r.env, &work).await;

    let run = kraken(&r.env, &["--yes", "--project", &dir, "explain", "0x401000"]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    // The same rendering as with a model API: streamed prose, then the structured sections.
    assert!(
        run.stdout.contains("starting function"),
        "stdout: {}",
        run.stdout
    );
    assert!(run.stdout.contains("What it does:"), "{}", run.stdout);
    assert!(run.stdout.contains("program_main"), "{}", run.stdout);
    assert!(!run.stdout.contains("kraken-result"), "{}", run.stdout);
    // KRAKEN tool calls show by command name on stderr, as they do for a model API.
    assert!(
        run.stderr.contains("terminal agent: Fake agent"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("> get_function"), "{}", run.stderr);
    assert!(run.stderr.contains("> decompile"), "{}", run.stderr);
    // The one-time notice about agents running outside KRAKEN's safety net.
    assert!(
        run.stderr.contains(kraken_acp::WARNING_TITLE),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("undo-run"), "{}", run.stderr);

    // The notice is shown once.
    let again = kraken(&r.env, &["--yes", "--project", &dir, "explain", "0x401000"]).await;
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert!(!again.stderr.contains(kraken_acp::WARNING_TITLE));
}

#[tokio::test]
async fn json_output_has_the_same_shape_for_a_terminal_agent() {
    let world = World::new();
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), world.select(FAKE));
    let dir = project(&r.env, &work).await;

    let run = kraken(&r.env, &["--yes", "--json", "--project", &dir, "overview"]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["task"], "overview");
    assert_eq!(v["backend"], "terminal_agent");
    assert_eq!(v["provider"]["id"], "fake");
    assert_eq!(v["stop"], "completed");
    assert_eq!(v["output"]["type"], "overview");
    assert_eq!(
        v["output"]["what_it_is"], "A small command-line program.",
        "{v}"
    );
    let calls: Vec<&str> = v["tool_calls"]
        .as_array()
        .expect("tool calls")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert_eq!(calls, ["project_info", "list_functions"]);
}

#[tokio::test]
async fn auto_name_reports_what_the_agents_edits_did() {
    let world = World::new();
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), world.select(FAKE));
    let dir = project(&r.env, &work).await;

    let run = kraken(
        &r.env,
        &["--yes", "--project", &dir, "auto-name", "--limit", "2"],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("program_main"), "{}", run.stdout);
    assert!(run.stdout.contains("rename: applied"), "{}", run.stdout);
    assert!(run.stdout.contains("proposed"), "{}", run.stdout);
    assert!(
        run.stderr.contains("became a proposal"),
        "the proposal is announced: {}",
        run.stderr
    );
    assert!(run.stderr.contains("proposals-list"), "{}", run.stderr);
}

#[tokio::test]
async fn an_agent_that_is_not_set_up_is_explained() {
    let world = World::new();
    let work = workdir();
    // `claude` needs Node and its adapter, neither of which exists in this empty world.
    let r = rig(
        CliAuthor::User("tester".into()),
        world.select("[provider]\nkind = \"terminal_agent\"\nagent = \"claude\"\n"),
    );
    let dir = project(&r.env, &work).await;
    let run = kraken(&r.env, &["--yes", "--project", &dir, "explain", "0x401000"]).await;
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("kraken agents setup claude") || run.stderr.contains("Node.js"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty());
}

#[tokio::test]
async fn an_unknown_agent_lists_the_known_ones() {
    let world = World::new();
    let work = workdir();
    let r = rig(
        CliAuthor::User("tester".into()),
        world.select("[provider]\nkind = \"terminal_agent\"\nagent = \"nope\"\n"),
    );
    let dir = project(&r.env, &work).await;
    let run = kraken(&r.env, &["--yes", "--project", &dir, "overview"]).await;
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("no agent called `nope`"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("claude"), "{}", run.stderr);
}
