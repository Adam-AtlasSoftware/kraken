//! Spike S2: spawn the KRAKEN Ghidra sidecar under confinement and analyse /bin/ls.
//!
//! Confinement: scrubbed env, PR_SET_PDEATHSIG from a dedicated spawner thread, Landlock
//! filesystem rules, and no network (Landlock ABI v4 TCP rules and/or an unshared net namespace).

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use serde_json::{Value, json};

const ABI_TARGET: ABI = ABI::V6;
const WATCHDOG: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NetMode {
    /// Landlock ABI v4 TCP bind/connect denial (plus ABI v6 abstract-socket and signal scoping).
    Landlock,
    /// unshare(CLONE_NEWUSER | CLONE_NEWNET): empty network namespace.
    Unshare,
    Both,
    None,
}

struct Options {
    net: NetMode,
    confine: bool,
    jdk: PathBuf,
    ghidra: PathBuf,
    ext_jar_dir: PathBuf,
    binary: PathBuf,
    /// Paths to omit from the built-in allow list (used to find the minimal set).
    skip: Vec<String>,
    /// Extra read-only paths (for experiments).
    extra_ro: Vec<PathBuf>,
}

fn main() -> Result<()> {
    if std::env::var_os("KRAKEN_PROBE_CHILD").is_some() {
        return probe_child();
    }
    let mut args = std::env::args().skip(1);
    let mut opts = Options {
        net: NetMode::Landlock,
        confine: true,
        jdk: first_child(&cache_dir()?.join("jdk"))?,
        ghidra: first_child(&cache_dir()?.join("ghidra"))?,
        ext_jar_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../java/kraken-ghidra/build/libs"),
        binary: PathBuf::from("/bin/ls"),
        skip: Vec::new(),
        extra_ro: Vec::new(),
    };
    let mut probe = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "net-probe" => probe = true,
            "--no-confine" => opts.confine = false,
            "--net" => {
                opts.net = match args.next().context("--net needs a value")?.as_str() {
                    "landlock" => NetMode::Landlock,
                    "unshare" => NetMode::Unshare,
                    "both" => NetMode::Both,
                    "none" => NetMode::None,
                    other => bail!("unknown --net mode {other}"),
                }
            }
            "--binary" => opts.binary = args.next().context("--binary needs a value")?.into(),
            "--ro" => opts
                .extra_ro
                .push(args.next().context("--ro needs a value")?.into()),
            "--skip" => opts.skip.push(args.next().context("--skip needs a value")?),
            other => bail!("unknown argument {other}"),
        }
    }
    opts.ext_jar_dir = fs::canonicalize(&opts.ext_jar_dir).with_context(|| {
        format!(
            "extension jar dir {} (run `cargo xtask ghidra-ext`)",
            opts.ext_jar_dir.display()
        )
    })?;

    if probe {
        return net_probe(&opts);
    }
    run(&opts)
}

fn cache_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".cache/kraken-dev"))
}

fn first_child(parent: &Path) -> Result<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(parent)
        .with_context(|| format!("reading {}", parent.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter()
        .next()
        .with_context(|| format!("nothing in {}", parent.display()))
}

fn jars_under(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            jars_under(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "jar") {
            out.push(path);
        }
    }
    Ok(())
}

/// Same jar set as Ghidra's buildExtension.gradle puts on the compile classpath.
fn classpath(opts: &Options) -> Result<String> {
    let mut jars = Vec::new();
    for sub in ["Framework", "Features", "Debug", "Processors"] {
        let dir = opts.ghidra.join("Ghidra").join(sub);
        if dir.is_dir() {
            jars_under(&dir, &mut jars)?;
        }
    }
    jars_under(&opts.ext_jar_dir, &mut jars)?;
    jars.sort();
    Ok(jars
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":"))
}

/// Read-only paths. Entries are (path, why); anything in `--skip` is dropped.
fn ro_paths(opts: &Options, binary_in_work: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![
        opts.jdk.clone(),
        opts.ghidra.clone(),
        opts.ext_jar_dir.clone(),
        binary_in_work.to_path_buf(),
        // Without /dev/random the JVM falls back to a slow seed generator (+8s on load).
        "/dev/random".into(),
        "/dev/urandom".into(),
        "/usr/lib".into(),
        "/lib".into(),
    ];
    v.retain(|p| !opts.skip.iter().any(|s| p.as_os_str() == s.as_str()));
    v.extend(opts.extra_ro.iter().cloned());
    v
}

/// Read-write paths other than the temp dirs.
fn rw_extra(opts: &Options) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    v.retain(|p| !opts.skip.iter().any(|s| p.as_os_str() == s.as_str()));
    v
}

fn build_ruleset(opts: &Options, ro: &[PathBuf], rw: &[PathBuf]) -> Result<RulesetCreated> {
    let mut rs = Ruleset::default().handle_access(AccessFs::from_all(ABI_TARGET))?;
    if matches!(opts.net, NetMode::Landlock | NetMode::Both) {
        // Handling TCP bind/connect with no allow rules denies all TCP.
        rs = rs.handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)?;
        rs = rs.scope(Scope::AbstractUnixSocket)?;
        rs = rs.scope(Scope::Signal)?;
    }
    let mut created = rs.create()?;
    for p in ro {
        match PathFd::new(p) {
            Ok(fd) => {
                created =
                    created.add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))?;
            }
            Err(e) => eprintln!("[spike] skipping missing RO path {}: {e}", p.display()),
        }
    }
    for p in rw {
        match PathFd::new(p) {
            Ok(fd) => {
                created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(ABI_TARGET)))?;
            }
            Err(e) => eprintln!("[spike] skipping missing RW path {}: {e}", p.display()),
        }
    }
    // Hard-fail instead of silently degrading if the kernel lacks the requested features.
    Ok(created.set_compatibility(CompatLevel::HardRequirement))
}

/// Runs in the forked child, before exec. Only raw syscalls here: unshare, prctl, landlock.
fn child_setup(net: NetMode, ruleset: &mut Option<RulesetCreated>) -> std::io::Result<()> {
    // SAFETY: plain syscalls on the current (single-threaded, post-fork) process.
    unsafe {
        if libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            return Err(std::io::Error::other(format!(
                "pdeathsig: {}",
                std::io::Error::last_os_error()
            )));
        }
        // The parent may have died between fork and prctl.
        if libc::getppid() == 1 {
            libc::_exit(1);
        }
        if matches!(net, NetMode::Unshare | NetMode::Both)
            && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0
        {
            return Err(std::io::Error::other(format!(
                "unshare: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    if let Some(rs) = ruleset.take() {
        let status = rs.restrict_self().map_err(std::io::Error::other)?;
        // PartiallyEnforced is expected: file rules drop directory-only access bits.
        if status.ruleset == RulesetStatus::NotEnforced {
            return Err(std::io::Error::other("landlock not enforced"));
        }
    }
    Ok(())
}

struct Sandbox {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Dropping this lets the spawner thread exit; it must outlive the child (PDEATHSIG is per-thread).
    _spawner_release: mpsc::Sender<()>,
}

fn spawn_confined(
    opts: &Options,
    cmd_builder: impl FnOnce() -> Result<Command> + Send + 'static,
    ruleset: Option<RulesetCreated>,
) -> Result<Sandbox> {
    let net = opts.net;
    let (tx, rx) = mpsc::channel::<Result<Child>>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::Builder::new()
        .name("spawner".into())
        .spawn(move || {
            let spawned = (|| {
                let mut cmd = cmd_builder()?;
                let mut slot = ruleset;
                // SAFETY: child_setup only performs syscalls (see above); the one allocation risk is
                // inside landlock's restrict_self, accepted for the spike.
                unsafe {
                    cmd.pre_exec(move || child_setup(net, &mut slot));
                }
                cmd.spawn().context("spawn failed")
            })();
            let ok = spawned.is_ok();
            let _ = tx.send(spawned);
            if ok {
                // Keep this thread alive until the owner is done with the child.
                let _ = release_rx.recv();
            }
        })?;
    let mut child = rx.recv().context("spawner thread died")??;
    let stdin = child.stdin.take().context("no stdin")?;
    let stdout = BufReader::new(child.stdout.take().context("no stdout")?);
    Ok(Sandbox {
        child,
        stdin,
        stdout,
        _spawner_release: release_tx,
    })
}

fn write_frame(w: &mut impl Write, v: &Value) -> Result<()> {
    let body = serde_json::to_vec(v)?;
    w.write_all(&u32::try_from(body.len())?.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .context("reading frame length (sidecar died?)")?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    r.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

fn call(sb: &mut Sandbox, id: u64, method: &str, params: Value) -> Result<Value> {
    write_frame(
        &mut sb.stdin,
        &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )?;
    let resp = read_frame(&mut sb.stdout)?;
    if resp["id"] != json!(id) {
        bail!("unexpected response {resp}");
    }
    if let Some(err) = resp.get("error") {
        bail!("rpc error: {err}");
    }
    Ok(resp["result"].clone())
}

fn run(opts: &Options) -> Result<()> {
    let t_total = Instant::now();
    let tmp = std::env::temp_dir().join(format!("kraken-s2-{}", std::process::id()));
    let home = tmp.join("home");
    let project = tmp.join("project");
    let work = tmp.join("work");
    for d in [&home, &project, &work, &home.join("tmp")] {
        fs::create_dir_all(d)?;
    }
    let binary = work.join(opts.binary.file_name().context("binary has no file name")?);
    fs::copy(&opts.binary, &binary)
        .with_context(|| format!("copying {}", opts.binary.display()))?;

    let ruleset = if opts.confine {
        let ro = ro_paths(opts, &binary);
        let mut rw = vec![home.clone(), project.clone()];
        rw.extend(rw_extra(opts));
        Some(build_ruleset(opts, &ro, &rw)?)
    } else {
        None
    };

    let cp = classpath(opts)?;
    let java = opts.jdk.join("bin/java");
    let jdk = opts.jdk.clone();
    let ghidra = opts.ghidra.clone();
    let (home2, project2) = (home.clone(), project.clone());
    let builder = move || -> Result<Command> {
        let mut cmd = Command::new(java);
        cmd.env_clear()
            .env("PATH", jdk.join("bin"))
            .env("HOME", &home2)
            .env("JAVA_HOME", &jdk)
            .env("LANG", "C.UTF-8")
            .args(["-Xmx2g", "-XX:+UseSerialGC", "-Djava.awt.headless=true"])
            .arg(format!("-Duser.home={}", home2.display()))
            .arg(format!("-Djava.io.tmpdir={}", home2.join("tmp").display()))
            .arg(format!("-Dghidra.install.dir={}", ghidra.display()))
            .arg("-cp")
            .arg(cp)
            .arg("kraken.ghidra.KrakenSidecar")
            .arg(&project2)
            .current_dir(&home2)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(cmd)
    };

    let t_spawn = Instant::now();
    let mut sb = spawn_confined(opts, builder, ruleset)?;
    let stderr = sb.child.stderr.take().context("no stderr")?;
    let log = thread::spawn(move || {
        for line in BufReader::new(stderr)
            .lines()
            .map_while(std::result::Result::ok)
        {
            eprintln!("[sidecar +{:.2}s] {line}", t_spawn.elapsed().as_secs_f64());
        }
    });
    let pid = sb.child.id();
    thread::spawn(move || {
        thread::sleep(WATCHDOG);
        // SAFETY: signalling a pid we spawned; harmless if it already exited.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    });

    let ready = read_frame(&mut sb.stdout).context("waiting for ready notification")?;
    let startup = t_spawn.elapsed();
    println!("ready: {ready}");

    let t = Instant::now();
    let pong = call(&mut sb, 1, "ping", json!({}))?;
    let ping = t.elapsed();
    println!("ping -> {pong} ({ping:?})");

    let t = Instant::now();
    let res = call(&mut sb, 2, "open_binary", json!({"path": binary}))?;
    let open = t.elapsed();

    let count = res["function_count"]
        .as_i64()
        .context("no function_count")?;
    println!("open_binary({}) -> {res}", binary.display());
    println!("function_count = {count}");
    println!("confinement: confine={} net={:?}", opts.confine, opts.net);
    println!(
        "timings: startup(spawn->ready)={:.2}s ping={:.1}ms open_binary(total)={:.2}s (load={}ms analyze={}ms) wall={:.2}s",
        startup.as_secs_f64(),
        ping.as_secs_f64() * 1000.0,
        open.as_secs_f64(),
        res["load_ms"],
        res["analyze_ms"],
        t_total.elapsed().as_secs_f64()
    );

    drop(sb.stdin);
    let status = sb.child.wait()?;
    let _ = log.join();
    println!("sidecar exit: {status}");
    if std::env::var_os("KRAKEN_KEEP_TMP").is_none() {
        let _ = fs::remove_dir_all(&tmp);
    }
    Ok(())
}

fn probe_child() -> Result<()> {
    let target = std::env::var("KRAKEN_PROBE_ADDR")?;
    let describe = |r: std::io::Result<()>| {
        r.map(|()| "OK".to_string())
            .unwrap_or_else(|e| format!("denied ({e})"))
    };
    println!(
        "connect: {}",
        describe(std::net::TcpStream::connect(&target).map(drop))
    );
    println!(
        "bind: {}",
        describe(std::net::TcpListener::bind("127.0.0.1:0").map(drop))
    );
    Ok(())
}

/// Re-executes this binary under the same confinement code and checks that TCP is refused.
fn net_probe(opts: &Options) -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let exe = std::env::current_exe()?;
    let ruleset = if opts.confine {
        let ro: Vec<PathBuf> = vec!["/usr".into(), "/lib".into(), "/proc".into(), exe.clone()];
        Some(build_ruleset(opts, &ro, &[])?)
    } else {
        None
    };
    let mut sb = spawn_confined(
        opts,
        move || {
            let mut c = Command::new(exe);
            c.env_clear()
                .env("KRAKEN_PROBE_CHILD", "1")
                .env("KRAKEN_PROBE_ADDR", addr.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            Ok(c)
        },
        ruleset,
    )?;
    let mut out = String::new();
    sb.stdout.read_to_string(&mut out)?;
    let status = sb.child.wait()?;
    println!(
        "net={:?} confine={}: {}exit {status}",
        opts.net,
        opts.confine,
        out.replace('\n', "; ")
    );
    Ok(())
}
