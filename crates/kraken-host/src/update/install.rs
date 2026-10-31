//! How KRAKEN was installed (ADR 0015, "Knowing the install") and what computer it runs on.
//!
//! [`detect`] goes through the ADR's order: AppImage, install receipt, package owner, cargo,
//! source checkout, Windows, a release archive unpacked by hand, else unknown. Every input comes
//! through [`Probe`], so tests use temporary directories, a fake environment and canned package
//! manager answers.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kraken_registry::commands::{InstallView, SystemView};
use serde::Deserialize;

/// `release` for builds of the release workflow, `source` otherwise.
pub const BUILD_CHANNEL: &str = env!("KRAKEN_BUILD_CHANNEL");
/// The target triple this build was compiled for.
pub const BUILD_TARGET: &str = env!("KRAKEN_BUILD_TARGET");
/// The running version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The AUR package.
pub const AUR_PACKAGE: &str = "kraken-workbench-bin";
/// The releases page, for installs KRAKEN cannot tell apart.
pub const RELEASES_URL: &str = "https://github.com/Adam-AtlasSoftware/kraken/releases";

/// How KRAKEN was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallKind {
    /// An AppImage; self-update replaces the file.
    AppImage {
        /// The `.AppImage` file (`$APPIMAGE`).
        path: PathBuf,
    },
    /// `install.sh` (its receipt names the prefix).
    Script {
        /// The prefix holding `bin/` and `share/kraken/`.
        prefix: PathBuf,
    },
    /// A release archive unpacked by hand into a directory the user owns.
    Archive {
        /// The directory holding `bin/`.
        prefix: PathBuf,
    },
    /// The Windows zip.
    Portable {
        /// The directory holding `bin\`.
        prefix: PathBuf,
    },
    /// The per-user Windows installer (its receipt).
    WindowsInstaller {
        /// The install directory.
        prefix: PathBuf,
    },
    /// The AUR package.
    Aur {
        /// Package name.
        package: String,
        /// `yay` or `paru`, whichever is installed.
        helper: String,
    },
    /// A distribution package.
    Package {
        /// `pacman`, `dpkg` or `rpm`.
        manager: String,
        /// Package name.
        package: String,
    },
    /// `cargo install`.
    Cargo {
        /// `$CARGO_HOME/bin`.
        bin: PathBuf,
    },
    /// A clone built with cargo.
    Source {
        /// The checkout.
        checkout: PathBuf,
    },
    /// The Python module (`pip install kraken-workbench`).
    Python,
    /// None of the above.
    Unknown,
}

impl InstallKind {
    /// Stable id: `appimage`, `script`, ...
    pub fn id(&self) -> &'static str {
        match self {
            InstallKind::AppImage { .. } => "appimage",
            InstallKind::Script { .. } => "script",
            InstallKind::Archive { .. } => "archive",
            InstallKind::Portable { .. } => "portable",
            InstallKind::WindowsInstaller { .. } => "windows_installer",
            InstallKind::Aur { .. } => "aur",
            InstallKind::Package { .. } => "package",
            InstallKind::Cargo { .. } => "cargo",
            InstallKind::Source { .. } => "source",
            InstallKind::Python => "python",
            InstallKind::Unknown => "unknown",
        }
    }

    /// True for the kinds KRAKEN updates itself (when the files are the user's).
    pub fn self_updating(&self) -> bool {
        matches!(
            self,
            InstallKind::AppImage { .. }
                | InstallKind::Script { .. }
                | InstallKind::Archive { .. }
                | InstallKind::Portable { .. }
                | InstallKind::WindowsInstaller { .. }
        )
    }

    /// The prefix holding `bin/` and `share/kraken/` for the kinds that have one.
    pub fn prefix(&self) -> Option<&Path> {
        match self {
            InstallKind::Script { prefix }
            | InstallKind::Archive { prefix }
            | InstallKind::Portable { prefix }
            | InstallKind::WindowsInstaller { prefix } => Some(prefix),
            _ => None,
        }
    }

    /// In plain words, with `~` for the home directory.
    pub fn label(&self, home: Option<&Path>) -> String {
        let p = |p: &Path| tilde(p, home);
        match self {
            InstallKind::AppImage { path } => format!("AppImage at {}", p(path)),
            InstallKind::Script { prefix } => format!("install script into {}", p(prefix)),
            InstallKind::Archive { prefix } => format!("release archive in {}", p(prefix)),
            InstallKind::Portable { prefix } => format!("Windows zip in {}", p(prefix)),
            InstallKind::WindowsInstaller { prefix } => {
                format!("Windows installer in {}", p(prefix))
            }
            InstallKind::Aur { package, .. } => format!("AUR package {package}"),
            InstallKind::Package { manager, package } => {
                format!("{} package {package}", manager_name(manager))
            }
            InstallKind::Cargo { bin } => format!("cargo install in {}", p(bin)),
            InstallKind::Source { checkout } => format!("source checkout at {}", p(checkout)),
            InstallKind::Python => "Python package kraken-workbench".into(),
            InstallKind::Unknown => "unknown (see the releases page)".into(),
        }
    }

    /// The command the person runs to update a package-managed install; `latest` fills in the
    /// version where the command needs one.
    pub fn command(&self, latest: Option<&str>) -> Option<String> {
        match self {
            InstallKind::Aur { package, helper } => Some(format!("{helper} -Syu {package}")),
            InstallKind::Package { manager, package } => Some(match manager.as_str() {
                "pacman" => "sudo pacman -Syu".to_string(),
                "dpkg" => format!("sudo apt update && sudo apt install --only-upgrade {package}"),
                _ => format!("sudo dnf upgrade {package}"),
            }),
            InstallKind::Cargo { .. } => Some(format!(
                "cargo install --locked --git https://github.com/Adam-AtlasSoftware/kraken --tag v{} kraken-cli krakend kraken-gui",
                latest.unwrap_or("X.Y.Z")
            )),
            InstallKind::Source { checkout } => Some(format!(
                "git -C {} pull --ff-only && cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native",
                checkout.display()
            )),
            InstallKind::Python => Some("pip install -U kraken-workbench".into()),
            _ => None,
        }
    }
}

fn manager_name(m: &str) -> &str {
    match m {
        "pacman" => "pacman",
        "dpkg" => "Debian",
        _ => "RPM",
    }
}

/// `path` with the home directory written as `~`.
pub fn tilde(path: &Path, home: Option<&Path>) -> String {
    if let Some(h) = home
        && let Ok(rest) = path.strip_prefix(h)
    {
        if rest.as_os_str().is_empty() {
            return "~".into();
        }
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

/// Everything detection looks at, so tests can fake it.
pub trait Probe {
    /// An environment variable (empty counts as unset).
    fn var(&self, key: &str) -> Option<OsString>;
    /// Runs `program` with `args`, no shell, with a timeout; its stdout when it succeeded.
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
    /// True when `path` is a regular file (not a link) the current user owns, in a directory
    /// the user can write.
    fn owned_and_writable(&self, path: &Path) -> bool;
}

/// The real computer.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemProbe;

impl Probe for SystemProbe {
    fn var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key).filter(|v| !v.is_empty())
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        run_with_timeout(program, args, Duration::from_secs(3))
    }

    fn owned_and_writable(&self, path: &Path) -> bool {
        super::apply::check_replaceable(path, false).is_ok()
            && path.parent().is_some_and(dir_writable)
    }
}

/// True when the current user may create files in `dir`.
pub fn dir_writable(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(dir).is_ok_and(|m| !m.permissions().readonly())
    }
}

/// Runs a program without a shell and gives up after `timeout`; stdout when it exited with 0.
pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_path_with_timeout(Path::new(program), args, &[], timeout)
}

/// [`run_with_timeout`] for a path, with extra environment variables.
pub fn run_path_with_timeout(
    program: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::Read::take(&mut stdout, 1 << 20), &mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let out = reader.join().ok()?;
    status
        .success()
        .then(|| String::from_utf8_lossy(&out).into_owned())
}

#[derive(Deserialize)]
struct Receipt {
    method: String,
}

fn read_receipt(prefix: &Path) -> Option<String> {
    let text = std::fs::read_to_string(prefix.join("share/kraken/install.json")).ok()?;
    if text.len() > 64 * 1024 {
        return None;
    }
    serde_json::from_str::<Receipt>(&text)
        .ok()
        .map(|r| r.method)
}

/// `<prefix>` when `exe` is `<prefix>/bin/<name>`.
fn bin_prefix(exe: &Path) -> Option<PathBuf> {
    let bin = exe.parent()?;
    (bin.file_name()? == "bin").then(|| bin.parent().map(Path::to_path_buf))?
}

fn under_system_dir(exe: &Path) -> bool {
    exe.starts_with("/usr") || exe.starts_with("/opt")
}

fn package_owner(exe: &Path, probe: &dyn Probe) -> Option<InstallKind> {
    let path = exe.to_str()?;
    if let Some(out) = probe.run("pacman", &["-Qqo", path]) {
        let package = out.lines().next()?.trim().to_string();
        if package.is_empty() {
            return None;
        }
        let foreign = probe
            .run("pacman", &["-Qqm"])
            .is_some_and(|l| l.lines().any(|p| p.trim() == package));
        if foreign {
            let helper = ["yay", "paru"]
                .into_iter()
                .find(|h| probe.run(h, &["--version"]).is_some())
                .unwrap_or("yay");
            return Some(InstallKind::Aur {
                package,
                helper: helper.into(),
            });
        }
        return Some(InstallKind::Package {
            manager: "pacman".into(),
            package,
        });
    }
    if let Some(out) = probe.run("dpkg", &["-S", path]) {
        // `kraken-workbench: /usr/bin/kraken`
        let package = out.lines().next()?.split(':').next()?.trim().to_string();
        if !package.is_empty() {
            return Some(InstallKind::Package {
                manager: "dpkg".into(),
                package,
            });
        }
    }
    if let Some(out) = probe.run("rpm", &["-qf", "--queryformat", "%{NAME}", path]) {
        let package = out.trim().to_string();
        if !package.is_empty() && !package.contains(' ') {
            return Some(InstallKind::Package {
                manager: "rpm".into(),
                package,
            });
        }
    }
    None
}

fn cargo_install(exe: &Path, probe: &dyn Probe) -> Option<InstallKind> {
    let home = probe
        .var("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| probe.var("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
    let bin = home.join("bin");
    if exe.parent()? != bin {
        return None;
    }
    let listed = std::fs::read_to_string(home.join(".crates2.json"))
        .is_ok_and(|t| t.contains("\"kraken-cli "));
    listed.then_some(InstallKind::Cargo { bin })
}

fn source_checkout(exe: &Path) -> Option<InstallKind> {
    let profile = exe.parent()?;
    if !matches!(profile.file_name()?.to_str()?, "release" | "debug") {
        return None;
    }
    let mut target = profile.parent()?;
    if target.file_name()? != "target" {
        // target/<triple>/release
        target = target.parent()?;
        if target.file_name()? != "target" {
            return None;
        }
    }
    let dir = target.parent()?;
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let ours =
        manifest.contains("[workspace]") && dir.join("crates/kraken-cli/Cargo.toml").is_file();
    ours.then(|| InstallKind::Source {
        checkout: dir.to_path_buf(),
    })
}

/// Works out how the program at `exe` was installed, for a build of `channel`.
pub fn detect(exe: &Path, channel: &str, probe: &dyn Probe) -> InstallKind {
    // 2. AppImage: the program runs from the mounted image.
    if let (Some(image), Some(appdir)) = (probe.var("APPIMAGE"), probe.var("APPDIR"))
        && exe.starts_with(PathBuf::from(&appdir))
    {
        return InstallKind::AppImage {
            path: PathBuf::from(image),
        };
    }
    let prefix = bin_prefix(exe);
    // 3. Install receipt (a hint: self-update still checks the files).
    if let Some(prefix) = &prefix {
        match read_receipt(prefix).as_deref() {
            Some("script") => {
                return InstallKind::Script {
                    prefix: prefix.clone(),
                };
            }
            Some("windows_installer") => {
                return InstallKind::WindowsInstaller {
                    prefix: prefix.clone(),
                };
            }
            _ => {}
        }
    }
    // 4. Package owner.
    if cfg!(unix)
        && under_system_dir(exe)
        && let Some(kind) = package_owner(exe, probe)
    {
        return kind;
    }
    // 5. cargo install.
    if let Some(kind) = cargo_install(exe, probe) {
        return kind;
    }
    // 6. Source checkout.
    if channel == "source"
        && let Some(kind) = source_checkout(exe)
    {
        return kind;
    }
    // 7. Windows zip; elsewhere a release archive unpacked by hand.
    if let Some(prefix) = prefix
        && channel == "release"
        && !under_system_dir(exe)
        && probe.owned_and_writable(exe)
    {
        return if cfg!(windows) {
            InstallKind::Portable { prefix }
        } else {
            InstallKind::Archive { prefix }
        };
    }
    InstallKind::Unknown
}

/// The install of the running program, as the registry reports it.
pub fn view(
    kind: &InstallKind,
    exe: &Path,
    latest: Option<&str>,
    probe: &dyn Probe,
) -> InstallView {
    let home = probe.var("HOME").map(PathBuf::from);
    let blocked = if !kind.self_updating() {
        None
    } else if is_root() {
        Some("KRAKEN does not update itself when it runs as root".to_string())
    } else {
        let target = match kind {
            InstallKind::AppImage { path } => path.clone(),
            _ => exe.to_path_buf(),
        };
        (!probe.owned_and_writable(&target)).then(|| {
            format!(
                "{} is not a file you own in a folder you can write",
                tilde(&target, home.as_deref())
            )
        })
    };
    InstallView {
        kind: kind.id().into(),
        label: kind.label(home.as_deref()),
        can_self_update: kind.self_updating() && blocked.is_none(),
        self_update_blocked: blocked,
        command: kind.command(latest),
        program: exe.display().to_string(),
    }
}

/// True when the process runs as root (euid 0).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// `NAME VERSION` from the text of `/etc/os-release`.
pub fn os_release_name(text: &str) -> Option<String> {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            fields.insert(k.trim(), v.trim().trim_matches('"').trim_matches('\''));
        }
    }
    if let Some(p) = fields.get("PRETTY_NAME").filter(|p| !p.is_empty()) {
        return Some((*p).to_string());
    }
    let name = fields.get("NAME")?;
    Some(match fields.get("VERSION_ID") {
        Some(v) => format!("{name} {v}"),
        None => (*name).to_string(),
    })
}

/// The C library the build links.
pub fn libc_name() -> &'static str {
    if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "glibc"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unknown"
    }
}

/// The session: desktop and display server, SSH or a terminal.
pub fn session_name(probe: &dyn Probe) -> String {
    let s = |k: &str| probe.var(k).map(|v| v.to_string_lossy().into_owned());
    if cfg!(windows) {
        return "Windows desktop".into();
    }
    let display = if s("WAYLAND_DISPLAY").is_some() {
        Some("Wayland")
    } else if s("DISPLAY").is_some() {
        Some("X11")
    } else {
        None
    };
    match (s("XDG_CURRENT_DESKTOP"), display) {
        (Some(d), Some(x)) => format!("{d} desktop ({x})"),
        (None, Some(x)) => format!("desktop ({x})"),
        _ if s("SSH_CONNECTION").is_some() => "SSH terminal".into(),
        _ => "terminal (no display)".into(),
    }
}

/// This computer.
pub fn system(probe: &dyn Probe) -> SystemView {
    let os = if cfg!(target_os = "linux") {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|t| os_release_name(&t))
            .map(|n| format!("{n} (Linux)"))
            .unwrap_or_else(|| "Linux".into())
    } else if cfg!(windows) {
        probe
            .run("cmd", &["/C", "ver"])
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "Windows".into())
    } else if cfg!(target_os = "macos") {
        probe
            .run("sw_vers", &["-productVersion"])
            .map(|v| format!("macOS {}", v.trim()))
            .unwrap_or_else(|| "macOS".into())
    } else {
        std::env::consts::OS.into()
    };
    SystemView {
        os,
        arch: std::env::consts::ARCH.into(),
        libc: libc_name().into(),
        session: session_name(probe),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        env: HashMap<String, String>,
        out: HashMap<String, String>,
        owned: bool,
    }

    impl Probe for Fake {
        fn var(&self, key: &str) -> Option<OsString> {
            self.env.get(key).map(OsString::from)
        }
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            self.out
                .get(&format!("{program} {}", args.join(" ")))
                .cloned()
        }
        fn owned_and_writable(&self, _path: &Path) -> bool {
            self.owned
        }
    }

    fn touch(p: &Path, text: &str) {
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(p, text).expect("write");
    }

    #[test]
    fn an_appimage_is_found_by_its_mount_point() {
        let mut f = Fake::default();
        f.env
            .insert("APPIMAGE".into(), "/home/a/Apps/KRAKEN.AppImage".into());
        f.env.insert("APPDIR".into(), "/tmp/.mount_KRAKENx".into());
        f.env.insert("HOME".into(), "/home/a".into());
        let k = detect(
            Path::new("/tmp/.mount_KRAKENx/usr/bin/kraken"),
            "release",
            &f,
        );
        assert_eq!(
            k,
            InstallKind::AppImage {
                path: "/home/a/Apps/KRAKEN.AppImage".into()
            }
        );
        assert_eq!(
            k.label(Some(Path::new("/home/a"))),
            "AppImage at ~/Apps/KRAKEN.AppImage"
        );
        assert!(k.self_updating() && k.command(None).is_none());
        // APPIMAGE alone (a program outside the mount) is not an AppImage.
        let k = detect(Path::new("/opt/x/bin/kraken"), "release", &f);
        assert_ne!(k.id(), "appimage");
    }

    #[test]
    fn the_install_receipt_names_a_script_install() {
        let d = tempfile::tempdir().expect("tmp");
        touch(
            &d.path().join("share/kraken/install.json"),
            r#"{"method": "script", "version": "0.3.0", "prefix": "/x"}"#,
        );
        let exe = d.path().join("bin/kraken");
        touch(&exe, "");
        let k = detect(&exe, "release", &Fake::default());
        assert_eq!(
            k,
            InstallKind::Script {
                prefix: d.path().to_path_buf()
            }
        );
        assert_eq!(k.prefix(), Some(d.path()));
    }

    #[test]
    fn an_aur_package_is_told_from_a_repository_one() {
        let mut f = Fake::default();
        f.out.insert(
            "pacman -Qqo /usr/bin/kraken".into(),
            "kraken-workbench-bin\n".into(),
        );
        f.out.insert(
            "pacman -Qqm".into(),
            "paru-bin\nkraken-workbench-bin\n".into(),
        );
        f.out.insert("paru --version".into(), "paru v2".into());
        let k = detect(Path::new("/usr/bin/kraken"), "release", &f);
        assert_eq!(
            k,
            InstallKind::Aur {
                package: AUR_PACKAGE.into(),
                helper: "paru".into()
            }
        );
        assert_eq!(
            k.command(None).as_deref(),
            Some("paru -Syu kraken-workbench-bin")
        );
        assert!(!k.self_updating());
        f.out.remove("pacman -Qqm");
        let k = detect(Path::new("/usr/bin/kraken"), "release", &f);
        assert_eq!(k.id(), "package");
        assert_eq!(k.command(None).as_deref(), Some("sudo pacman -Syu"));
    }

    #[test]
    fn dpkg_and_rpm_owners_are_found() {
        let mut f = Fake::default();
        f.out.insert(
            "dpkg -S /usr/bin/kraken".into(),
            "kraken-workbench: /usr/bin/kraken\n".into(),
        );
        let k = detect(Path::new("/usr/bin/kraken"), "release", &f);
        assert_eq!(
            k,
            InstallKind::Package {
                manager: "dpkg".into(),
                package: "kraken-workbench".into()
            }
        );
        assert!(k.command(None).is_some_and(|c| c.contains("apt")));
        let mut f = Fake::default();
        f.out.insert(
            "rpm -qf --queryformat %{NAME} /opt/kraken/bin/kraken".into(),
            "kraken-workbench".into(),
        );
        let k = detect(Path::new("/opt/kraken/bin/kraken"), "release", &f);
        assert_eq!(k.label(None), "RPM package kraken-workbench");
    }

    #[test]
    fn cargo_install_needs_the_crates_list() {
        let d = tempfile::tempdir().expect("tmp");
        let mut f = Fake::default();
        f.env
            .insert("CARGO_HOME".into(), d.path().display().to_string());
        let exe = d.path().join("bin/kraken");
        touch(&exe, "");
        assert_eq!(detect(&exe, "source", &f), InstallKind::Unknown);
        touch(
            &d.path().join(".crates2.json"),
            r#"{"installs":{"kraken-cli 0.3.0 (git+https://github.com/Adam-AtlasSoftware/kraken)":{}}}"#,
        );
        let k = detect(&exe, "source", &f);
        assert_eq!(k.id(), "cargo");
        assert!(
            k.command(Some("0.4.0"))
                .is_some_and(|c| c.contains("--tag v0.4.0"))
        );
    }

    #[test]
    fn a_source_checkout_is_found_from_its_target_dir() {
        let d = tempfile::tempdir().expect("tmp");
        touch(
            &d.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        touch(&d.path().join("crates/kraken-cli/Cargo.toml"), "");
        let exe = d.path().join("target/release/kraken");
        touch(&exe, "");
        let k = detect(&exe, "source", &Fake::default());
        assert_eq!(
            k,
            InstallKind::Source {
                checkout: d.path().to_path_buf()
            }
        );
        assert!(
            k.command(None)
                .is_some_and(|c| c.contains("pull --ff-only"))
        );
        // A release build in a target dir is not a source checkout.
        assert_eq!(
            detect(&exe, "release", &Fake::default()),
            InstallKind::Unknown
        );
        let exe = d
            .path()
            .join("target/x86_64-unknown-linux-musl/debug/kraken");
        touch(&exe, "");
        assert_eq!(detect(&exe, "source", &Fake::default()).id(), "source");
    }

    #[test]
    fn a_hand_unpacked_release_archive_updates_itself_only_when_owned() {
        let d = tempfile::tempdir().expect("tmp");
        let exe = d.path().join("kraken-0.3.0/bin/kraken");
        touch(&exe, "");
        let mut f = Fake {
            owned: true,
            ..Default::default()
        };
        let k = detect(&exe, "release", &f);
        assert_eq!(k.id(), if cfg!(windows) { "portable" } else { "archive" });
        f.owned = false;
        assert_eq!(detect(&exe, "release", &f), InstallKind::Unknown);
        assert_eq!(detect(&exe, "source", &f), InstallKind::Unknown);
    }

    #[test]
    fn the_view_reports_why_self_update_is_blocked() {
        let k = InstallKind::Script {
            prefix: "/home/a/.local".into(),
        };
        let mut f = Fake::default();
        f.env.insert("HOME".into(), "/home/a".into());
        let v = view(&k, Path::new("/home/a/.local/bin/kraken"), None, &f);
        assert_eq!(v.kind, "script");
        assert_eq!(v.label, "install script into ~/.local");
        if !is_root() {
            assert!(!v.can_self_update);
            assert!(
                v.self_update_blocked
                    .as_deref()
                    .is_some_and(|b| b.contains("~/.local/bin/kraken"))
            );
            f.owned = true;
            let v = view(&k, Path::new("/home/a/.local/bin/kraken"), None, &f);
            assert!(v.can_self_update && v.self_update_blocked.is_none());
        }
        let v = view(&InstallKind::Unknown, Path::new("/x"), None, &f);
        assert!(!v.can_self_update && v.self_update_blocked.is_none());
    }

    #[test]
    fn system_names_come_from_os_release_and_the_session() {
        assert_eq!(
            os_release_name("NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\n").as_deref(),
            Some("Arch Linux")
        );
        assert_eq!(
            os_release_name("NAME=Debian\nVERSION_ID=\"13\"\n").as_deref(),
            Some("Debian 13")
        );
        assert_eq!(os_release_name("FOO=1"), None);
        if !cfg!(windows) {
            let mut f = Fake::default();
            assert_eq!(session_name(&f), "terminal (no display)");
            f.env.insert("SSH_CONNECTION".into(), "1 2 3 4".into());
            assert_eq!(session_name(&f), "SSH terminal");
            f.env.insert("WAYLAND_DISPLAY".into(), "wayland-0".into());
            f.env.insert("XDG_CURRENT_DESKTOP".into(), "KDE".into());
            assert_eq!(session_name(&f), "KDE desktop (Wayland)");
        }
        assert!(!libc_name().is_empty());
        assert!(BUILD_CHANNEL == "source" || BUILD_CHANNEL == "release");
        assert!(!BUILD_TARGET.is_empty());
    }
}
