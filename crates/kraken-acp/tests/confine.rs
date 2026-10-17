//! Security finding H4: an agent launched the way KRAKEN launches agents cannot read the user
//! token (or reach the original runtime directory through `/proc`), while the MCP child it
//! starts still connects to the daemon socket with the agent credential.
//!
//! The "agent" is this very test binary re-run with `CONFINE_CHILD` set.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kraken_acp::confine::{AGENT_VISIBLE, Confinement, HiddenDir, probe};
use kraken_acp::process::{SpawnSpec, spawn};

const USER_TOKEN: &str = "USER-SECRET-TOKEN";
const AGENT_TOKEN: &str = "agent-class-token";

/// Runs inside the sandbox when the parent test re-executes this binary.
#[test]
fn confined_child() {
    let Some(dir) = std::env::var_os("CONFINE_CHILD").map(PathBuf::from) else {
        return;
    };
    let parent_pid = std::env::var("CONFINE_PARENT_PID").unwrap_or_default();
    let user = std::fs::read_to_string(dir.join("daemon.token"));
    eprintln!(
        "user-token: {}",
        match user {
            Ok(t) if t.contains(USER_TOKEN) => "LEAKED",
            _ => "hidden",
        }
    );
    // The way around a mount: the daemon's root through /proc.
    let via_proc = std::fs::read_to_string(format!(
        "/proc/{parent_pid}/root{}/daemon.token",
        dir.display()
    ));
    eprintln!(
        "proc-root: {}",
        if via_proc.is_ok() { "LEAKED" } else { "hidden" }
    );
    // What the MCP server does: agent credential, daemon socket.
    let token = std::fs::read_to_string(dir.join("agent.token")).expect("agent token readable");
    let mut s = UnixStream::connect(dir.join("daemon.sock")).expect("socket reachable");
    writeln!(s, "hello {}", token.trim()).unwrap();
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap();
    eprintln!("mcp: {}", line.trim());
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let cap_eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .unwrap_or("?")
        .trim()
        .to_string();
    eprintln!("cap-eff: {cap_eff}");
    eprintln!("other-files: {}", std::fs::read_dir(&dir).unwrap().count());
}

#[tokio::test]
async fn confined_agent_cannot_read_the_user_token_but_mcp_still_connects() {
    if let Err(why) = probe() {
        eprintln!("skipped: namespaces are unavailable here ({why})");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("kraken-confine")
        .tempdir()
        .unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("daemon.token"), USER_TOKEN).unwrap();
    std::fs::write(dir.join("agent.token"), AGENT_TOKEN).unwrap();
    std::fs::write(dir.join("unrelated.txt"), "x").unwrap();
    let listener = UnixListener::bind(dir.join("daemon.sock")).unwrap();
    let server = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).unwrap();
        let mut s = s;
        let reply = match line.trim().strip_prefix("hello ") {
            Some(AGENT_TOKEN) => "welcome agent",
            _ => "refused",
        };
        writeln!(s, "{reply}").unwrap();
    });

    let spec = SpawnSpec {
        program: std::env::current_exe().unwrap(),
        args: [
            "--exact",
            "confined_child",
            "--nocapture",
            "--test-threads=1",
        ]
        .map(OsString::from)
        .to_vec(),
        env: vec![
            (
                OsString::from("CONFINE_CHILD"),
                dir.clone().into_os_string(),
            ),
            (
                OsString::from("CONFINE_PARENT_PID"),
                OsString::from(std::process::id().to_string()),
            ),
        ],
        cwd: Path::new("/").to_path_buf(),
        confine: Some(Confinement {
            hide: vec![HiddenDir {
                dir: dir.clone(),
                keep: AGENT_VISIBLE.iter().map(OsString::from).collect(),
            }],
        }),
    };
    let mut s = spawn(spec, None).await.expect("spawn confined");
    let info = s
        .process
        .wait_exit(Duration::from_secs(60))
        .await
        .expect("exit");
    let log = s.stderr.text();
    assert_eq!(info.code, Some(0), "child failed:\n{log}");
    assert!(log.contains("user-token: hidden"), "{log}");
    assert!(log.contains("proc-root: hidden"), "{log}");
    assert!(log.contains("mcp: welcome agent"), "{log}");
    assert!(log.contains("cap-eff: 0000000000000000"), "{log}");
    // Only the socket and the agent token (daemon.json does not exist here).
    assert!(log.contains("other-files: 2"), "{log}");
    server.join().unwrap();
    // The real directory is untouched from the outside.
    assert_eq!(
        std::fs::read_to_string(dir.join("daemon.token")).unwrap(),
        USER_TOKEN
    );
}

#[tokio::test]
async fn an_unconfined_child_can_read_the_user_token() {
    // The control: without the sandbox the same read succeeds, so the test above proves something.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("daemon.token"), USER_TOKEN).unwrap();
    let spec = SpawnSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec![
            OsString::from("-c"),
            OsString::from(format!("cat {}/daemon.token >&2", dir.display())),
        ],
        env: vec![],
        cwd: PathBuf::from("/"),
        confine: None,
    };
    let mut s = spawn(spec, None).await.unwrap();
    s.process.wait_exit(Duration::from_secs(10)).await.unwrap();
    assert!(s.stderr.text().contains(USER_TOKEN));
}

#[tokio::test]
async fn terminating_a_confined_agent_ends_everything_in_it() {
    if probe().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    let spec = SpawnSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec![
            OsString::from("-c"),
            OsString::from("sleep 300 & echo started >&2; wait"),
        ],
        env: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
        cwd: PathBuf::from("/"),
        confine: Some(Confinement {
            hide: vec![HiddenDir { dir, keep: vec![] }],
        }),
    };
    let mut s = spawn(spec, None).await.unwrap();
    for _ in 0..200 {
        if s.stderr.text().contains("started") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let info = s.process.terminate(Duration::from_secs(2)).await.unwrap();
    assert!(info.code.is_some() || info.signal.is_some());
}
