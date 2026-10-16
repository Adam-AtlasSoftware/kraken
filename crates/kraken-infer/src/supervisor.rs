//! `ManagedProcess`: spawns an engine as a child process and keeps it healthy.
//!
//! Each incarnation is owned by a dedicated OS thread. On Linux `PR_SET_PDEATHSIG` fires when the
//! *thread* that forked the child exits, so that thread must outlive the child; it also does the
//! polling for exit, SIGTERM and the SIGKILL escalation. The async side only exchanges messages.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::error::{InferError, Result};
use crate::logring::{LogLine, LogRing, LogStream};
use crate::port::LOOPBACK;

/// Environment variables inherited by supervised engines; everything else (API keys included)
/// is dropped. Engine-specific values go in [`ProcessSpec::env`].
pub const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "LD_LIBRARY_PATH",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "CUDA_VISIBLE_DEVICES",
    "HIP_VISIBLE_DEVICES",
    "ROCR_VISIBLE_DEVICES",
    "VK_ICD_FILENAMES",
    "VK_DRIVER_FILES",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
];

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Consecutive crashes tolerated before the process is declared failed.
    pub max_restarts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// Running at least this long resets the crash counter and backoff.
    pub stable_after: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(10),
            stable_after: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// HTTP GET path on 127.0.0.1, e.g. `/health` (llama-server) or `/v1/models`.
    pub path: String,
    pub interval: Duration,
    pub request_timeout: Duration,
    /// An incarnation that is not healthy by then is killed and counted as a crash.
    pub ready_timeout: Duration,
}

impl HealthCheck {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            interval: Duration::from_millis(250),
            request_timeout: Duration::from_secs(2),
            ready_timeout: Duration::from_secs(600),
        }
    }
}

#[derive(Clone)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Explicit extra environment, applied after the allowlist.
    pub env: Vec<(String, String)>,
    pub env_allowlist: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub port: u16,
    pub health: HealthCheck,
    pub restart: RestartPolicy,
    /// SIGTERM to SIGKILL grace period.
    pub grace: Duration,
    pub log_capacity: usize,
    /// Maps a log line to a loading fraction in 0..=1.
    pub progress_parser: Option<fn(&str) -> Option<f32>>,
}

impl ProcessSpec {
    pub fn new(program: impl Into<PathBuf>, port: u16, health_path: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            env_allowlist: DEFAULT_ENV_ALLOWLIST
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            cwd: None,
            port,
            health: HealthCheck::new(health_path),
            restart: RestartPolicy::default(),
            grace: Duration::from_secs(5),
            log_capacity: 2000,
            progress_parser: None,
        }
    }
}

/// Builds the child environment from `inherited`, keeping only allowlisted names, then `extra`.
pub fn filter_env<I>(
    inherited: I,
    allowlist: &[String],
    extra: &[(String, String)],
) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut out: Vec<(OsString, OsString)> = inherited
        .into_iter()
        .filter(|(k, _)| {
            k.to_str()
                .is_some_and(|k| allowlist.iter().any(|a| a.eq_ignore_ascii_case(k)))
        })
        .collect();
    for (k, v) in extra {
        out.retain(|(ek, _)| ek != k.as_str());
        out.push((k.into(), v.into()));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Process spawned, not yet healthy.
    Starting,
    /// Log output indicates model loading progress.
    Loading,
    Ready,
    /// Crashed; waiting out the backoff before the next spawn.
    Restarting,
    /// Crashed more often than the restart policy allows, or failed to spawn.
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadProgress {
    pub phase: Phase,
    pub fraction: Option<f32>,
    pub message: String,
    /// Restarts performed so far (total over the lifetime of this supervisor).
    pub restarts: u32,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl std::fmt::Display for ExitInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.code, self.signal) {
            (Some(c), _) => write!(f, "exit code {c}"),
            (None, Some(s)) => write!(f, "signal {s}"),
            _ => write!(f, "unknown exit"),
        }
    }
}

enum Cmd {
    Stop(Duration),
    Kill,
}

struct Incarnation {
    pid: u32,
    cmd: std_mpsc::Sender<Cmd>,
    exit: oneshot::Receiver<ExitInfo>,
}

fn spawn_incarnation(spec: &ProcessSpec, ring: &LogRing) -> Result<Incarnation> {
    let (ready_tx, ready_rx) = std_mpsc::channel::<std::io::Result<u32>>();
    let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
    let (exit_tx, exit_rx) = oneshot::channel::<ExitInfo>();
    let spec = spec.clone();
    let ring = ring.clone();

    thread::Builder::new()
        .name("kraken-infer-spawner".into())
        .spawn(move || {
            let mut command = Command::new(&spec.program);
            command
                .args(&spec.args)
                .env_clear()
                .envs(filter_env(
                    std::env::vars_os(),
                    &spec.env_allowlist,
                    &spec.env,
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(cwd) = &spec.cwd {
                command.current_dir(cwd);
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                // SAFETY: the closure only performs async-signal-safe syscalls (prctl, getppid,
                // _exit) between fork and exec.
                unsafe {
                    command.pre_exec(|| {
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0
                        {
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
            let mut child = match command.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let pid = child.id();
            let _ = ready_tx.send(Ok(pid));

            if let Some(out) = child.stdout.take() {
                spawn_reader(out, LogStream::Stdout, ring.clone());
            }
            if let Some(err) = child.stderr.take() {
                spawn_reader(err, LogStream::Stderr, ring.clone());
            }

            let mut term_deadline: Option<Instant> = None;
            let status = loop {
                match cmd_rx.recv_timeout(Duration::from_millis(20)) {
                    Ok(Cmd::Stop(grace)) => {
                        if term_deadline.is_none() {
                            send_term(&mut child);
                            term_deadline = Some(Instant::now() + grace);
                        }
                    }
                    Ok(Cmd::Kill) => {
                        let _ = child.kill();
                    }
                    Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                    // Owner dropped: never leave an orphan behind.
                    Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = child.kill();
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
                    let _ = child.kill();
                    term_deadline = None;
                }
            };
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
        })
        .map_err(InferError::Spawn)?;

    let pid = ready_rx
        .recv()
        .map_err(|_| InferError::Spawn(std::io::Error::other("spawner thread died")))?
        .map_err(InferError::Spawn)?;
    Ok(Incarnation {
        pid,
        cmd: cmd_tx,
        exit: exit_rx,
    })
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

#[cfg(unix)]
fn send_term(child: &mut std::process::Child) {
    // SAFETY: kill(2) on a pid of our own un-reaped child.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
fn send_term(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn spawn_reader<R: Read + Send + 'static>(r: R, stream: LogStream, ring: LogRing) {
    thread::spawn(move || {
        let mut reader = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&buf);
                    ring.push(stream, text.trim_end_matches(['\n', '\r']));
                }
            }
        }
    });
}

/// Returns the HTTP status of `GET http://127.0.0.1:port/path`, or `None` if unreachable.
pub async fn http_status(port: u16, path: &str, timeout: Duration) -> Option<u16> {
    let fut = async {
        let mut s = TcpStream::connect((LOOPBACK, port)).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {LOOPBACK}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 64];
        let mut n = 0;
        while n < 12 {
            let r = s.read(&mut buf[n..]).await.ok()?;
            if r == 0 {
                break;
            }
            n += r;
        }
        let head = std::str::from_utf8(&buf[..n]).ok()?;
        head.split(' ').nth(1)?.parse::<u16>().ok()
    };
    tokio::time::timeout(timeout, fut).await.ok().flatten()
}

type SharedProgress = Arc<watch::Sender<LoadProgress>>;

fn update(tx: &SharedProgress, f: impl FnOnce(&mut LoadProgress)) {
    tx.send_modify(f);
}

/// A supervised child process. Dropping it kills the child.
pub struct ManagedProcess {
    port: u16,
    health: HealthCheck,
    ring: LogRing,
    progress: SharedProgress,
    stop_tx: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ManagedProcess {
    /// Spawns the process (failing here if it cannot be spawned at all) and starts supervising it
    /// on the current tokio runtime.
    pub fn start(spec: ProcessSpec) -> Result<Self> {
        let initial = LoadProgress {
            phase: Phase::Starting,
            fraction: None,
            message: "starting".into(),
            restarts: 0,
            pid: None,
        };
        let (ptx, _) = watch::channel(initial);
        let progress: SharedProgress = Arc::new(ptx);

        let hook = spec.progress_parser.map(|parser| {
            let p = Arc::clone(&progress);
            Arc::new(move |line: &LogLine| {
                if let Some(frac) = parser(&line.text) {
                    update(&p, |s| {
                        if matches!(s.phase, Phase::Starting | Phase::Loading) {
                            s.phase = Phase::Loading;
                            s.fraction = Some(frac.clamp(0.0, 1.0));
                            s.message.clone_from(&line.text);
                        }
                    });
                }
            }) as Arc<dyn Fn(&LogLine) + Send + Sync>
        });
        let ring = LogRing::with_hook(spec.log_capacity, hook);

        ring.push(
            LogStream::System,
            format!(
                "spawning {} {}",
                spec.program.display(),
                spec.args.join(" ")
            ),
        );
        let first = spawn_incarnation(&spec, &ring)?;
        update(&progress, |s| s.pid = Some(first.pid));

        let (stop_tx, stop_rx) = watch::channel(false);
        let port = spec.port;
        let health = spec.health.clone();
        let task = tokio::spawn(supervise(
            spec,
            ring.clone(),
            Arc::clone(&progress),
            stop_rx,
            first,
        ));
        Ok(Self {
            port,
            health,
            ring,
            progress,
            stop_tx,
            task: Mutex::new(Some(task)),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn ring(&self) -> &LogRing {
        &self.ring
    }

    pub fn logs(&self) -> Vec<LogLine> {
        self.ring.snapshot()
    }

    pub fn status(&self) -> LoadProgress {
        self.progress.borrow().clone()
    }

    /// Stream of phase / loading-progress updates.
    pub fn subscribe(&self) -> watch::Receiver<LoadProgress> {
        self.progress.subscribe()
    }

    /// Probes the health endpoint right now.
    pub async fn health(&self) -> bool {
        matches!(
            http_status(self.port, &self.health.path, self.health.request_timeout).await,
            Some(200..=299)
        )
    }

    /// Waits until the process is healthy; fails if it ends up failed/stopped or on timeout.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let mut rx = self.subscribe();
        let wait = async {
            loop {
                let (phase, msg) = {
                    let s = rx.borrow_and_update();
                    (s.phase, s.message.clone())
                };
                match phase {
                    Phase::Ready => return Ok(()),
                    Phase::Failed | Phase::Stopped => {
                        return Err(InferError::NotReady(format!("{phase:?}: {msg}")));
                    }
                    _ => {}
                }
                if rx.changed().await.is_err() {
                    return Err(InferError::NotReady("supervisor ended".into()));
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| InferError::NotReady("timed out waiting for health".into()))?
    }

    /// Stops the child (SIGTERM, then SIGKILL after the grace period) and ends supervision.
    pub async fn stop(&self) {
        let _ = self.stop_tx.send(true);
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(t) = task {
            let _ = t.await;
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
    }
}

async fn supervise(
    spec: ProcessSpec,
    ring: LogRing,
    progress: SharedProgress,
    mut stop_rx: watch::Receiver<bool>,
    first: Incarnation,
) {
    let policy = spec.restart.clone();
    let mut crashes = 0u32;
    let mut total_restarts = 0u32;
    let mut backoff = policy.initial_backoff;
    let mut next = Some(first);

    loop {
        let inc = match next.take() {
            Some(i) => i,
            None => match spawn_incarnation(&spec, &ring) {
                Ok(i) => i,
                Err(e) => {
                    ring.push(LogStream::System, format!("spawn failed: {e}"));
                    match backoff_or_fail(
                        &mut crashes,
                        &mut backoff,
                        &policy,
                        &progress,
                        &mut stop_rx,
                        total_restarts,
                        &e.to_string(),
                    )
                    .await
                    {
                        Flow::Retry => {
                            total_restarts += 1;
                            continue;
                        }
                        Flow::Done => return,
                    }
                }
            },
        };
        let pid = inc.pid;
        let Incarnation { cmd, mut exit, .. } = inc;
        update(&progress, |s| {
            s.phase = Phase::Starting;
            s.fraction = None;
            s.message = "starting".into();
            s.pid = Some(pid);
            s.restarts = total_restarts;
        });

        let started = Instant::now();
        let mut ready = false;
        let mut killed_for_timeout = false;

        let exit_info = loop {
            let tick = async {
                if ready {
                    std::future::pending::<()>().await;
                } else {
                    tokio::time::sleep(spec.health.interval).await;
                }
            };
            tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    let _ = cmd.send(Cmd::Stop(spec.grace));
                    let info = (&mut exit).await.ok();
                    ring.push(LogStream::System, format!("stopped: {}", fmt_exit(info)));
                    update(&progress, |s| {
                        s.phase = Phase::Stopped;
                        s.message = "stopped".into();
                        s.pid = None;
                    });
                    return;
                }
                info = &mut exit => break info.ok(),
                () = tick => {
                    if http_status(spec.port, &spec.health.path, spec.health.request_timeout)
                        .await
                        .is_some_and(|c| (200..300).contains(&c))
                    {
                        ready = true;
                        update(&progress, |s| {
                            s.phase = Phase::Ready;
                            s.fraction = Some(1.0);
                            s.message = "ready".into();
                        });
                    } else if !killed_for_timeout && started.elapsed() > spec.health.ready_timeout {
                        killed_for_timeout = true;
                        ring.push(LogStream::System, "not healthy before ready_timeout; killing");
                        let _ = cmd.send(Cmd::Kill);
                    }
                }
            }
        };

        let reason = format!("process ended: {}", fmt_exit(exit_info));
        ring.push(LogStream::System, reason.clone());
        if started.elapsed() >= policy.stable_after {
            crashes = 0;
            backoff = policy.initial_backoff;
        }
        match backoff_or_fail(
            &mut crashes,
            &mut backoff,
            &policy,
            &progress,
            &mut stop_rx,
            total_restarts,
            &reason,
        )
        .await
        {
            Flow::Retry => total_restarts += 1,
            Flow::Done => return,
        }
    }
}

fn fmt_exit(info: Option<ExitInfo>) -> String {
    info.map_or_else(|| "unknown".to_string(), |i| i.to_string())
}

enum Flow {
    Retry,
    Done,
}

/// Decides between giving up (Failed), being told to stop, and sleeping the backoff.
async fn backoff_or_fail(
    crashes: &mut u32,
    backoff: &mut Duration,
    policy: &RestartPolicy,
    progress: &SharedProgress,
    stop_rx: &mut watch::Receiver<bool>,
    total_restarts: u32,
    reason: &str,
) -> Flow {
    if *crashes >= policy.max_restarts {
        update(progress, |s| {
            s.phase = Phase::Failed;
            s.message = format!("giving up after {total_restarts} restarts: {reason}");
            s.pid = None;
        });
        return Flow::Done;
    }
    *crashes += 1;
    update(progress, |s| {
        s.phase = Phase::Restarting;
        s.message = format!("restarting in {:?}: {reason}", *backoff);
        s.pid = None;
    });
    let wait = *backoff;
    *backoff = (*backoff * 2).min(policy.max_backoff);
    tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            update(progress, |s| {
                s.phase = Phase::Stopped;
                s.message = "stopped".into();
            });
            Flow::Done
        }
        () = tokio::time::sleep(wait) => Flow::Retry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn env_allowlist_drops_secrets_and_applies_extras() {
        let inherited = vec![
            (os("PATH"), os("/bin")),
            (os("ANTHROPIC_API_KEY"), os("sk-secret")),
            (os("OPENAI_API_KEY"), os("sk-other")),
            (os("HOME"), os("/home/u")),
        ];
        let allow: Vec<String> = DEFAULT_ENV_ALLOWLIST
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let extra = vec![("PATH".to_string(), "/custom".to_string())];
        let out = filter_env(inherited, &allow, &extra);
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert!(names.contains(&"HOME"));
        assert!(!names.contains(&"ANTHROPIC_API_KEY"));
        assert!(!names.contains(&"OPENAI_API_KEY"));
        let path = out.iter().find(|(k, _)| k == "PATH").unwrap();
        assert_eq!(path.1, os("/custom"));
    }
}
