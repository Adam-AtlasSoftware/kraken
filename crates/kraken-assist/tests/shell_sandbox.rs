//! The shell tool in its sandbox. Skipped where the host cannot confine (Landlock ABI 4 and
//! network isolation).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_agent::{Decision, ToolCtx, ToolError, ToolHost, ToolSpec};
use kraken_assist::shell::sandbox::{ShellOutcome, run};
use kraken_assist::{SHELL_TOOL, ShellHost, ShellSession};
use kraken_host::ShellConfig;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// The process limit is counted per user, so a test that exhausts it would starve the others.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

macro_rules! need_sandbox {
    () => {
        if !kraken_confine::enforced() {
            eprintln!("skipped: this host cannot confine");
            return;
        }
        let _guard = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    };
}

struct Nothing;

#[async_trait]
impl ToolHost for Nothing {
    fn tools(&self) -> Vec<ToolSpec> {
        Vec::new()
    }

    async fn call(&self, name: &str, _: Value, _: &ToolCtx) -> Result<Value, ToolError> {
        Err(ToolError::NotFound(name.into()))
    }
}

fn sh(session: &ShellSession, command: &str) -> ShellOutcome {
    sh_with(session, command, &[], 10)
}

fn sh_with(session: &ShellSession, command: &str, ro: &[PathBuf], secs: u64) -> ShellOutcome {
    let scratch = session.scratch().unwrap();
    run(command, &scratch, ro, Duration::from_secs(secs)).unwrap()
}

/// A `python3 -` command with the lines as its script.
fn heredoc(lines: &[&str]) -> String {
    format!("python3 - <<'EOF'\n{}\nEOF", lines.join("\n"))
}

fn ctx() -> ToolCtx {
    ToolCtx {
        run_id: "r".into(),
        call_id: "c".into(),
        cancel: CancellationToken::new(),
    }
}

fn host(project: Option<PathBuf>) -> ShellHost {
    ShellHost::new(
        Arc::new(Nothing),
        Arc::new(ShellSession::new()),
        ShellConfig::default(),
        project,
        None,
    )
}

#[test]
fn arithmetic_and_python_work() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(&s, "echo '2^64-1' | bc");
    assert_eq!(o.exit, Some(0), "{o:?}");
    assert_eq!(o.output.trim(), "18446744073709551615");
    let o = sh(&s, "python3 -c 'print(2**64)'");
    assert_eq!(o.output.trim(), "18446744073709551616", "{o:?}");
    let o = sh(&s, "python3 -c 'print(0x9e3779b9*3 % 2**32)'");
    assert_eq!(
        o.output.trim(),
        ((0x9e37_79b9u64 * 3) % (1 << 32)).to_string()
    );
}

#[test]
fn a_pipeline_of_four_commands_runs() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(&s, "seq 1 100 | sort -n | uniq | wc -l | tr -d ' '");
    assert_eq!(o.exit, Some(0), "{o:?}");
    assert_eq!(o.output.trim(), "100");
}

#[test]
fn the_environment_is_nearly_empty() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(&s, "env | sort");
    assert!(o.output.contains("LANG=C"), "{o:?}");
    assert!(!o.output.contains("HOME="), "{o:?}");
    assert!(!o.output.contains("KRAKEN"), "{o:?}");
}

#[test]
fn the_network_is_cut_off() {
    need_sandbox!();
    let s = ShellSession::new();
    let code = heredoc(&[
        "import socket",
        "try:",
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "    s.settimeout(3)",
        "    s.connect(('127.0.0.1', 9))",
        "    print('connected')",
        "except OSError as e:",
        "    print('blocked', type(e).__name__)",
        "try:",
        "    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        "    u.sendto(b'x', ('8.8.8.8', 53))",
        "    print('sent')",
        "except OSError:",
        "    print('blocked-udp')",
    ]);
    let o = sh(&s, &code);
    assert!(o.output.contains("blocked"), "{o:?}");
    assert!(
        !o.output.contains("connected") && !o.output.contains("sent"),
        "{o:?}"
    );
}

#[test]
fn writes_go_to_the_scratch_directory_only_and_it_is_kept() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(&s, "echo kept > note.txt && cat note.txt");
    assert_eq!(o.output.trim(), "kept", "{o:?}");
    let o = sh(&s, "cat note.txt");
    assert_eq!(o.output.trim(), "kept", "second call, same session: {o:?}");
    let outside = std::env::temp_dir().join(format!("kr-shell-outside-{}", std::process::id()));
    let o = sh(&s, &format!("echo x > {}", outside.display()));
    assert_ne!(o.exit, Some(0), "{o:?}");
    assert!(!outside.exists());
    let o = sh(&s, "echo x > /usr/kr-shell-test");
    assert_ne!(o.exit, Some(0), "{o:?}");
}

#[test]
fn nothing_written_into_the_scratch_directory_can_be_executed() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(
        &s,
        "printf '#!/bin/sh\\necho ran\\n' > p.sh; chmod +x p.sh; ./p.sh; echo \"exit $?\"",
    );
    assert!(!o.output.contains("ran"), "{o:?}");
    assert!(!o.output.contains("exit 0"), "{o:?}");
    let o = sh(&s, "cp /usr/bin/true ./t; ./t; echo \"exit $?\"");
    assert!(!o.output.contains("exit 0"), "{o:?}");
}

#[test]
fn the_analysed_program_is_readable_but_not_runnable_or_writable() {
    need_sandbox!();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("prog");
    std::fs::write(&bin, "#!/bin/sh\necho ran\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let s = ShellSession::new();
    let ro = [bin.clone()];
    let o = sh_with(
        &s,
        &format!("head -c 9 {} | xxd -p", bin.display()),
        &ro,
        10,
    );
    assert_eq!(o.output.trim(), "23212f62696e2f7368", "{o:?}");
    let o = sh_with(&s, &format!("{}; echo \"exit $?\"", bin.display()), &ro, 10);
    assert!(!o.output.contains("ran"), "{o:?}");
    let o = sh_with(&s, &format!("echo x >> {}", bin.display()), &ro, 10);
    assert_ne!(o.exit, Some(0), "{o:?}");
    assert_eq!(
        std::fs::read_to_string(&bin).unwrap(),
        "#!/bin/sh\necho ran\n"
    );
    // Other files next to it stay hidden.
    std::fs::write(dir.path().join("secret"), "s").unwrap();
    let o = sh_with(&s, &format!("cat {}/secret", dir.path().display()), &ro, 10);
    assert_ne!(o.exit, Some(0), "{o:?}");
}

#[test]
fn the_home_directory_and_kraken_config_are_not_readable() {
    need_sandbox!();
    let s = ShellSession::new();
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let o = sh(&s, &format!("ls {}", home.display()));
    assert_ne!(o.exit, Some(0), "{o:?}");
    let o = sh(&s, &format!("ls {}/.config/kraken", home.display()));
    assert_ne!(o.exit, Some(0), "{o:?}");
    let o = sh(&s, &format!("cat {}/.ssh/id_rsa", home.display()));
    assert_ne!(o.exit, Some(0), "{o:?}");
    let o = sh(&s, "cat /etc/passwd");
    assert_ne!(o.exit, Some(0), "{o:?}");
}

#[test]
fn a_command_over_its_time_is_killed_with_all_children() {
    need_sandbox!();
    let s = ShellSession::new();
    let started = Instant::now();
    let o = sh_with(
        &s,
        "sleep 31337 & echo $! > pid; sleep 31338 | cat; echo done",
        &[],
        1,
    );
    assert!(o.timed_out, "{o:?}");
    assert_eq!(o.exit, None);
    assert!(started.elapsed() < Duration::from_secs(6));
    let pid = std::fs::read_to_string(s.scratch().unwrap().join("pid"))
        .unwrap()
        .trim()
        .to_string();
    let gone = (0..40).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    });
    assert!(gone, "background child {pid} survived");
    let ps = std::process::Command::new("pgrep")
        .args(["-f", "sleep 3133"])
        .output();
    if let Ok(ps) = ps {
        assert!(
            ps.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&ps.stdout)
        );
    }
}

#[test]
fn a_fork_bomb_is_stopped() {
    need_sandbox!();
    let s = ShellSession::new();
    let code = heredoc(&[
        "import os, time",
        "kids = 0",
        "try:",
        "    for _ in range(2000):",
        "        if os.fork() == 0:",
        "            time.sleep(5)",
        "            os._exit(0)",
        "        kids += 1",
        "except OSError:",
        "    pass",
        "print('kids', kids)",
    ]);
    let o = sh_with(&s, &code, &[], 20);
    let kids: u64 = o
        .output
        .split_whitespace()
        .last()
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{o:?}"));
    assert!(kids < 1000, "{kids} children were started");
}

#[test]
fn long_output_is_cut_with_a_note() {
    need_sandbox!();
    let s = ShellSession::new();
    let o = sh(&s, "seq 1 5000");
    assert!(o.output.contains("[output cut at 4000 characters"), "{o:?}");
    assert!(o.output.chars().count() < 4200);
    let o = sh(&s, "yes | head -c 200000");
    assert!(o.output.contains("output cut"), "{o:?}");
}

#[test]
fn the_tool_through_the_host() {
    need_sandbox!();
    let project = tempfile::tempdir().unwrap();
    let h = host(Some(project.path().to_path_buf()));
    let tools = h.tools();
    let spec = tools.iter().find(|t| t.name == SHELL_TOOL).unwrap();
    assert_eq!(spec.permission, kraken_agent::Permission::Dangerous);

    let a = json!({"command": "echo '2^64-1' | bc"});
    assert_eq!(h.decide(SHELL_TOOL, &a), Decision::Allow);
    let r = tokio_test_block(h.call(SHELL_TOOL, a, &ctx())).unwrap();
    assert_eq!(r["exit"], 0);
    assert_eq!(r["timed_out"], false);
    assert_eq!(r["output"]["untrusted"], true);
    assert_eq!(
        r["output"]["value"].as_str().unwrap().trim(),
        "18446744073709551615"
    );

    let ask = json!({"command": "ls"});
    assert_eq!(h.decide(SHELL_TOOL, &ask), Decision::Ask);
    let deny = json!({"command": "./a.out"});
    assert!(matches!(h.decide(SHELL_TOOL, &deny), Decision::Deny(r) if r.contains("emulate_run")));
    // Even approved, a refused command does not run.
    let err = tokio_test_block(h.call(SHELL_TOOL, deny, &ctx())).unwrap_err();
    assert!(err.to_string().contains("emulate_run"), "{err}");
    let err =
        tokio_test_block(h.call(SHELL_TOOL, json!({"command": "sudo id"}), &ctx())).unwrap_err();
    assert!(err.to_string().contains("sudo"), "{err}");
    assert!(matches!(
        h.decide(SHELL_TOOL, &json!({})),
        Decision::Deny(_)
    ));
    // Other tools go to the inner host.
    assert_eq!(h.decide("other", &json!({})), Decision::Allow);
}

#[test]
fn a_project_allow_entry_takes_effect_at_once() {
    need_sandbox!();
    let project = tempfile::tempdir().unwrap();
    let h = host(Some(project.path().to_path_buf()));
    let a = json!({"command": "cat /dev/null"});
    assert_eq!(h.decide(SHELL_TOOL, &a), Decision::Ask);
    kraken_assist::add_project_allow(project.path(), "cat").unwrap();
    assert_eq!(h.decide(SHELL_TOOL, &a), Decision::Allow);
}

fn tokio_test_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}
