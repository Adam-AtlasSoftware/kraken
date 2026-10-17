//! The agent child process.
//!
//! The child is started from a dedicated OS thread that stays alive until the child is gone: on
//! Linux `PR_SET_PDEATHSIG` fires when the *thread* that forked the child exits, so that thread
//! must outlive the child. The same thread polls for exit and performs the SIGTERM then SIGKILL
//! escalation, so dropping an [`AgentProcess`] never leaves an agent behind. On Unix the agent
//! runs in its own process group and the whole group is signalled, so the shells and MCP servers
//! the agent started go with it. (Windows job objects follow with the Windows tier-1 work.)

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot};

/// Lines of the agent's stderr kept for error messages.
const STDERR_TAIL_LINES: usize = 40;

/// What to start.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// Program.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<OsString>,
    /// The complete environment (nothing else is inherited).
    pub env: Vec<(OsString, OsString)>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Runs the program in the Linux sandbox of [`crate::confine`] when set. Starting fails
    /// when the sandbox cannot be created; callers check [`crate::confine::probe`] first.
    pub confine: Option<crate::confine::Confinement>,
}

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    /// Exit code, when it exited normally.
    pub code: Option<i32>,
    /// Terminating signal, on Unix.
    pub signal: Option<i32>,
}

enum Cmd {
    Stop(Duration),
    Kill,
}

/// The last lines the agent wrote to stderr.
#[derive(Debug, Clone, Default)]
pub struct StderrTail(Arc<Mutex<VecDeque<String>>>);

impl StderrTail {
    fn push(&self, line: String) {
        let mut q = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() == STDERR_TAIL_LINES {
            q.pop_front();
        }
        q.push_back(line);
    }

    /// The kept lines, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// The kept lines joined with newlines.
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
}

/// A running agent. Dropping it kills the process (group).
#[derive(Debug)]
pub struct AgentProcess {
    pid: u32,
    cmd: std_mpsc::Sender<Cmd>,
    exit: Option<oneshot::Receiver<ExitInfo>>,
    exited: Option<ExitInfo>,
}

/// A started agent with its pipes.
pub struct Spawned {
    /// The process handle.
    pub process: AgentProcess,
    /// Writes to the agent's stdin.
    pub stdin: ChildStdin,
    /// Reads the agent's stdout.
    pub stdout: ChildStdout,
    /// The agent's recent stderr.
    pub stderr: StderrTail,
}

/// Spawn failure.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// The OS refused to start the program.
    #[error("cannot start {program}: {source}")]
    Start {
        /// Program.
        program: String,
        /// OS error.
        #[source]
        source: std::io::Error,
    },
    /// The spawner thread vanished.
    #[error("the process spawner thread died")]
    SpawnerDied,
}

struct Piped {
    pid: u32,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

/// Starts the agent. `stderr_lines` receives every stderr line as it is written.
pub async fn spawn(
    spec: SpawnSpec,
    stderr_lines: Option<mpsc::UnboundedSender<String>>,
) -> Result<Spawned, SpawnError> {
    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<Piped, std::io::Error>>();
    let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
    let (exit_tx, exit_rx) = oneshot::channel::<ExitInfo>();
    let tail = StderrTail::default();
    let thread_tail = tail.clone();
    let program = spec.program.display().to_string();

    thread::Builder::new()
        .name("kraken-acp-spawner".into())
        .spawn(move || {
            spawner_main(spec, cmd_rx, ready_tx, exit_tx, thread_tail, stderr_lines);
        })
        .map_err(|source| SpawnError::Start {
            program: program.clone(),
            source,
        })?;

    let piped = tokio::task::spawn_blocking(move || ready_rx.recv())
        .await
        .map_err(|_| SpawnError::SpawnerDied)?
        .map_err(|_| SpawnError::SpawnerDied)?
        .map_err(|source| SpawnError::Start { program, source })?;
    let stdin = ChildStdin::from_std(piped.stdin).map_err(|source| SpawnError::Start {
        program: "stdin".into(),
        source,
    })?;
    let stdout = ChildStdout::from_std(piped.stdout).map_err(|source| SpawnError::Start {
        program: "stdout".into(),
        source,
    })?;
    Ok(Spawned {
        process: AgentProcess {
            pid: piped.pid,
            cmd: cmd_tx,
            exit: Some(exit_rx),
            exited: None,
        },
        stdin,
        stdout,
        stderr: tail,
    })
}

fn spawner_main(
    spec: SpawnSpec,
    cmd_rx: std_mpsc::Receiver<Cmd>,
    ready_tx: std_mpsc::Sender<Result<Piped, std::io::Error>>,
    exit_tx: oneshot::Sender<ExitInfo>,
    tail: StderrTail,
    stderr_lines: Option<mpsc::UnboundedSender<String>>,
) {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&spec.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure only performs async-signal-safe syscalls (prctl, getppid, _exit)
        // between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // The parent may have died between fork and prctl.
                if libc::getppid() == 1 {
                    libc::_exit(1);
                }
                Ok(())
            });
        }
    }
    // After the parent-death hook above: this hook forks, and the agent's parent is then not
    // the spawner.
    if let Some(c) = &spec.confine
        && let Err(e) = crate::confine::install(&mut command, c)
    {
        let _ = ready_tx.send(Err(e));
        return;
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let pid = child.id();
    // Windows: the job object is the process group and the parent-death hook (no-op elsewhere).
    kraken_procguard::watch_parent_death(pid, true);
    let guard = kraken_procguard::ProcessGuard::new().ok();
    if let Some(g) = &guard {
        let _ = g.assign_pid(pid);
    }
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = ready_tx.send(Err(std::io::Error::other("the agent's pipes are missing")));
        return;
    };
    let _ = ready_tx.send(Ok(Piped { pid, stdin, stdout }));
    let reader = thread::Builder::new()
        .name("kraken-acp-stderr".into())
        .spawn(move || read_stderr(stderr, &tail, stderr_lines.as_ref()))
        .ok();

    let mut term_deadline: Option<Instant> = None;
    let status = loop {
        match cmd_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(Cmd::Stop(grace)) => {
                if term_deadline.is_none() {
                    signal_group(pid, &mut child, false);
                    term_deadline = Some(Instant::now() + grace);
                }
            }
            Ok(Cmd::Kill) => signal_group(pid, &mut child, true),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            // The owner is gone: never leave an agent behind.
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                signal_group(pid, &mut child, true);
                let _ = child.wait();
                return;
            }
        }
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if term_deadline.is_some_and(|d| Instant::now() >= d) {
            signal_group(pid, &mut child, true);
            term_deadline = None;
        }
    };
    // Whatever the agent left running in its group goes too.
    #[cfg(unix)]
    kill_group(pid);
    if let Some(g) = &guard {
        g.terminate();
    }
    if let Some(r) = reader {
        let _ = r.join();
    }
    let info = status.map_or(
        ExitInfo {
            code: None,
            signal: None,
        },
        |st| ExitInfo {
            code: st.code(),
            signal: exit_signal(&st),
        },
    );
    let _ = exit_tx.send(info);
}

fn read_stderr(
    stderr: impl Read,
    tail: &StderrTail,
    lines: Option<&mpsc::UnboundedSender<String>>,
) {
    for line in BufReader::new(stderr).lines() {
        let Ok(line) = line else { break };
        if let Some(tx) = lines {
            let _ = tx.send(line.clone());
        }
        tail.push(line);
    }
}

#[cfg(unix)]
fn signal_group(pid: u32, child: &mut std::process::Child, kill: bool) {
    let sig = if kill { libc::SIGKILL } else { libc::SIGTERM };
    // SAFETY: plain signal delivery to the process group the child leads.
    let rc = unsafe { libc::kill(-(pid as libc::pid_t), sig) };
    if rc != 0 {
        // The group may not exist yet or any more; fall back to the child itself.
        if kill {
            let _ = child.kill();
        } else {
            // SAFETY: as above, for the single pid.
            unsafe {
                libc::kill(pid as libc::pid_t, sig);
            }
        }
    }
}

#[cfg(not(unix))]
fn signal_group(_pid: u32, child: &mut std::process::Child, _kill: bool) {
    let _ = child.kill();
}

#[cfg(unix)]
fn kill_group(pid: u32) {
    // SAFETY: plain signal delivery; the group id is the (reaped) child's pid.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(unix)]
fn exit_signal(st: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    st.signal()
}

#[cfg(not(unix))]
fn exit_signal(_st: &std::process::ExitStatus) -> Option<i32> {
    None
}

impl AgentProcess {
    /// The process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Asks the process (group) to stop: SIGTERM now, SIGKILL after `grace`. Returns how it
    /// ended, waiting at most `grace` plus a short margin.
    pub async fn terminate(&mut self, grace: Duration) -> Option<ExitInfo> {
        if self.exited.is_none() {
            let _ = self.cmd.send(Cmd::Stop(grace));
            self.wait_exit(grace + Duration::from_secs(3)).await
        } else {
            self.exited
        }
    }

    /// Kills immediately.
    pub fn kill(&self) {
        let _ = self.cmd.send(Cmd::Kill);
    }

    /// Waits up to `timeout` for the process to end.
    pub async fn wait_exit(&mut self, timeout: Duration) -> Option<ExitInfo> {
        if let Some(e) = self.exited {
            return Some(e);
        }
        let rx = self.exit.as_mut()?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(info)) => {
                self.exited = Some(info);
                self.exit = None;
                Some(info)
            }
            _ => None,
        }
    }

    /// True when the process is known to have ended.
    pub fn has_exited(&mut self) -> bool {
        if self.exited.is_some() {
            return true;
        }
        if let Some(rx) = self.exit.as_mut()
            && let Ok(info) = rx.try_recv()
        {
            self.exited = Some(info);
            self.exit = None;
            return true;
        }
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> SpawnSpec {
        SpawnSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec![OsString::from("-c"), OsString::from(script)],
            env: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
            cwd: std::env::temp_dir(),
            confine: None,
        }
    }

    #[tokio::test]
    async fn exit_codes_and_stderr_are_reported() {
        let mut s = spawn(sh("echo oops >&2; exit 3"), None)
            .await
            .expect("spawn");
        let info = s
            .process
            .wait_exit(Duration::from_secs(10))
            .await
            .expect("exit");
        assert_eq!(info.code, Some(3));
        assert_eq!(s.stderr.text(), "oops");
    }

    #[tokio::test]
    async fn the_environment_is_exactly_what_was_given() {
        let mut spec = sh("echo \"[$SECRET][$KEEP]\" >&2");
        spec.env
            .push((OsString::from("KEEP"), OsString::from("yes")));
        let mut s = spawn(spec, None).await.expect("spawn");
        s.process
            .wait_exit(Duration::from_secs(10))
            .await
            .expect("exit");
        assert_eq!(s.stderr.text(), "[][yes]");
    }

    #[tokio::test]
    async fn terminate_kills_the_process_and_its_children() {
        let marker = tempfile::tempdir().expect("tempdir");
        let pidfile = marker.path().join("child.pid");
        let script = format!("sleep 300 & echo $! > {}; wait", pidfile.display());
        let mut s = spawn(sh(&script), None).await.expect("spawn");
        let mut child_pid = None;
        for _ in 0..200 {
            if let Ok(t) = std::fs::read_to_string(&pidfile)
                && let Ok(p) = t.trim().parse::<i32>()
            {
                child_pid = Some(p);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let child_pid = child_pid.expect("grandchild started");
        let info = s
            .process
            .terminate(Duration::from_secs(2))
            .await
            .expect("ended");
        assert!(info.signal.is_some() || info.code.is_some());
        tokio::time::sleep(Duration::from_millis(200)).await;
        // SAFETY: signal 0 only checks that the pid exists.
        let alive = unsafe { libc::kill(child_pid, 0) } == 0;
        assert!(!alive, "the grandchild was killed with the group");
    }

    #[tokio::test]
    async fn dropping_the_handle_kills_the_agent() {
        let marker = tempfile::tempdir().expect("tempdir");
        let pidfile = marker.path().join("pid");
        let script = format!("echo $$ > {}; exec sleep 300", pidfile.display());
        let s = spawn(sh(&script), None).await.expect("spawn");
        let pid = s.process.pid() as i32;
        drop(s);
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: signal 0 only checks that the pid exists.
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(gone, "agent still running after drop");
    }

    #[tokio::test]
    async fn a_missing_program_is_a_clear_error() {
        let mut spec = sh("true");
        spec.program = PathBuf::from("/nonexistent/kraken-agent");
        let err = spawn(spec, None).await.map(|_| ()).expect_err("must fail");
        assert!(err.to_string().contains("cannot start"), "{err}");
    }
}
