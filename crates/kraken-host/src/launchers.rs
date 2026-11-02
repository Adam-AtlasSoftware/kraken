//! Makes what KRAKEN installed easy to start from the system: a command on `PATH` and an entry in
//! the application list. Everything is per user and nothing needs an administrator.
//!
//! On Linux a command is a small script in `~/.local/bin` and an entry a `.desktop` file; on
//! Windows a `.cmd` file in KRAKEN's own folder, which goes on the user's `Path`, and a Start Menu
//! shortcut. A command is a wrapper rather than a link because a program can need its environment,
//! as Ghidra needs KRAKEN's JDK.
//!
//! Nothing of the person's is shadowed or overwritten: a name another program uses becomes
//! `kraken-<id>`, and only files with KRAKEN's mark are replaced or removed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::provision::Layout;

/// Stands in every file written here; only such files are replaced or removed.
const MARK: &str = "Installed by KRAKEN";

/// Stands in a shell profile KRAKEN added its `PATH` line to.
const PROFILE_MARK: &str = "# Added by KRAKEN: the commands of what it installs";

/// Where commands and entries go.
#[derive(Debug, Clone)]
pub struct Places {
    /// The folder of the commands.
    pub bin: PathBuf,
    /// The folder of the application entries.
    pub apps: PathBuf,
    /// The `PATH` to look at.
    pub path_env: OsString,
    /// Login scripts of the shells in use, for a `bin` not on `PATH` (Linux).
    pub profiles: Vec<PathBuf>,
    /// Windows, whatever the host is, so the formats can be tested anywhere.
    pub windows: bool,
}

/// One program to make reachable.
#[derive(Debug, Clone)]
pub struct Launcher {
    /// Stable id: letters, digits and `-`.
    pub id: String,
    /// The name in the application list.
    pub name: String,
    /// One line for the application list.
    pub summary: String,
    /// The command people type, when free.
    pub command: String,
    /// The program.
    pub exe: PathBuf,
    /// Environment of the program.
    pub env: Vec<(String, String)>,
    /// Folders to put before `PATH` for the program.
    pub path_dirs: Vec<PathBuf>,
    /// An entry in the application list as well as a command.
    pub app: bool,
    /// Icon file.
    pub icon: Option<PathBuf>,
    /// `Categories` of the desktop entry, such as `Game;Emulator;`.
    pub categories: String,
}

/// What [`publish`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The command to type.
    pub command: String,
    /// One line for people.
    pub note: String,
}

impl Places {
    /// The person's own folders; `None` where KRAKEN has none (macOS) or `HOME` is not set.
    pub fn system() -> Option<Places> {
        Self::from_env_with(std::env::consts::OS, &|k| std::env::var_os(k))
    }

    /// [`system`](Self::system) with an injectable system and environment.
    pub fn from_env_with(os: &str, env: &dyn Fn(&str) -> Option<OsString>) -> Option<Places> {
        let dir = |k: &str| {
            env(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let path_env = env("PATH").unwrap_or_default();
        match os {
            "linux" => {
                let home = dir("HOME")?;
                let apps = dir("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
                let config = dir("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
                let mut profiles = vec![home.join(".profile")];
                for shell in [".bash_profile", ".zprofile"] {
                    let file = home.join(shell);
                    let zsh = shell == ".zprofile"
                        && env("SHELL").is_some_and(|s| s.to_string_lossy().ends_with("zsh"));
                    if zsh || file.exists() {
                        profiles.push(file);
                    }
                }
                let fish = config.join("fish");
                if fish.is_dir() {
                    profiles.push(fish.join("conf.d/kraken.fish"));
                }
                Some(Places {
                    bin: dir("XDG_BIN_HOME").unwrap_or_else(|| home.join(".local/bin")),
                    apps: apps.join("applications"),
                    path_env,
                    profiles,
                    windows: false,
                })
            }
            "windows" => Some(Places {
                bin: dir("LOCALAPPDATA")?.join("KRAKEN").join("bin"),
                apps: dir("APPDATA")?.join("Microsoft/Windows/Start Menu/Programs/KRAKEN"),
                path_env,
                profiles: Vec::new(),
                windows: true,
            }),
            _ => None,
        }
    }

    fn command_file(&self, command: &str) -> PathBuf {
        if self.windows {
            self.bin.join(format!("{command}.cmd"))
        } else {
            self.bin.join(command)
        }
    }

    fn entry_file(&self, l: &Launcher) -> PathBuf {
        if self.windows {
            self.apps.join(format!("{}.lnk", file_safe(&l.name)))
        } else {
            self.apps.join(format!("kraken-{}.desktop", l.id))
        }
    }

    fn bin_on_path(&self) -> bool {
        std::env::split_paths(&self.path_env).any(|p| p == self.bin)
    }

    /// True when another folder of `PATH` holds a program called `command`.
    fn taken(&self, command: &str) -> bool {
        let names: Vec<String> = if self.windows {
            ["exe", "cmd", "bat", "com"]
                .iter()
                .map(|e| format!("{command}.{e}"))
                .collect()
        } else {
            vec![command.to_string()]
        };
        std::env::split_paths(&self.path_env)
            .filter(|p| *p != self.bin && !p.as_os_str().is_empty())
            .any(|p| names.iter().any(|n| p.join(n).is_file()))
    }

    /// The first free name: the wanted one, else `kraken-<id>`.
    fn free_command(&self, l: &Launcher) -> Option<String> {
        [l.command.clone(), format!("kraken-{}", l.id)]
            .into_iter()
            .find(|c| {
                let file = self.command_file(c);
                valid_name(c) && (!file.exists() || ours(&file)) && !self.taken(c)
            })
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['-', '.'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

fn valid_env_key(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A name for one file of the Start Menu.
fn file_safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !r#"<>:"/\|?*"#.contains(*c))
        .collect::<String>()
        .trim_matches([' ', '.'])
        .to_string()
}

fn ours(file: &Path) -> bool {
    std::fs::read(file).is_ok_and(|b| {
        b.windows(MARK.len())
            .take(4096)
            .any(|w| w == MARK.as_bytes())
    })
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The script behind a command on Linux.
fn sh_wrapper(l: &Launcher) -> Result<String, String> {
    let mut t = format!("#!/bin/sh\n# {MARK}: {}\n", l.id);
    for (k, v) in &l.env {
        if !valid_env_key(k) {
            return Err(format!("the variable name `{k}` cannot be used"));
        }
        t.push_str(&format!("export {k}={}\n", sh_quote(v)));
    }
    for d in &l.path_dirs {
        t.push_str(&format!(
            "export PATH={}:\"$PATH\"\n",
            sh_quote(&d.to_string_lossy())
        ));
    }
    t.push_str(&format!(
        "exec {} \"$@\"\n",
        sh_quote(&l.exe.to_string_lossy())
    ));
    Ok(t)
}

fn cmd_value(s: &str) -> Result<String, String> {
    if s.contains(['"', '\n', '\r']) {
        return Err(format!("`{s}` cannot be written in a command file"));
    }
    Ok(s.replace('%', "%%"))
}

/// The command file on Windows.
fn cmd_wrapper(l: &Launcher) -> Result<String, String> {
    let mut t = format!("@echo off\r\nrem {MARK}: {}\r\n", l.id);
    for (k, v) in &l.env {
        if !valid_env_key(k) {
            return Err(format!("the variable name `{k}` cannot be used"));
        }
        t.push_str(&format!("set \"{k}={}\"\r\n", cmd_value(v)?));
    }
    for d in &l.path_dirs {
        t.push_str(&format!(
            "set \"PATH={};%PATH%\"\r\n",
            cmd_value(&d.to_string_lossy())?
        ));
    }
    t.push_str(&format!(
        "\"{}\" %*\r\n",
        cmd_value(&l.exe.to_string_lossy())?
    ));
    Ok(t)
}

/// One line of a desktop entry's value.
fn desktop_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace('\\', r"\\")
}

/// A program path as the `Exec` key wants it: quoted, then escaped once more as a string value.
fn desktop_exec(p: &Path) -> String {
    let mut q = String::from("\"");
    for c in p.to_string_lossy().chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q.replace('\\', r"\\").replace('%', "%%")
}

fn desktop_entry(l: &Launcher, command_file: &Path) -> String {
    let icon = l.icon.as_ref().map_or_else(
        || "application-x-executable".to_string(),
        |p| desktop_text(&p.to_string_lossy()),
    );
    format!(
        "[Desktop Entry]\n# {MARK}: {id}\nType=Application\nName={name}\nComment={summary}\nExec={exec}\nIcon={icon}\nTerminal=false\nCategories={categories}\n",
        id = l.id,
        name = desktop_text(&l.name),
        summary = desktop_text(&l.summary),
        exec = desktop_exec(command_file),
        categories = desktop_text(&l.categories),
    )
}

fn write_file(file: &Path, text: &str, executable: bool) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("cannot write {}: {e}", file.display());
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let tmp = file.with_extension("kraken-new");
    std::fs::write(&tmp, text).map_err(fail)?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(fail)?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    std::fs::rename(&tmp, file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

/// Adds the `PATH` line for `bin` to `profile` unless it is there. The line itself checks `PATH`,
/// so a login that has the folder already is not changed.
fn add_to_profile(profile: &Path, bin: &Path) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("cannot change {}: {e}", profile.display());
    let old = match std::fs::read_to_string(profile) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(fail(e)),
    };
    if old.contains(PROFILE_MARK) {
        return Ok(());
    }
    let quoted = sh_quote(&bin.to_string_lossy());
    let line = if profile.extension().is_some_and(|e| e == "fish") {
        format!("fish_add_path -g {quoted}")
    } else {
        format!("case \":$PATH:\" in *:{quoted}:*) ;; *) export PATH={quoted}:\"$PATH\" ;; esac")
    };
    let sep = if old.is_empty() || old.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let text = format!("{old}{sep}{PROFILE_MARK}\n{line}\n");
    if let Some(dir) = profile.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    std::fs::write(profile, text).map_err(fail)
}

/// Runs a PowerShell script with its values in the environment, so none needs quoting.
fn powershell(script: &str, env: &[(&str, &Path)]) -> Result<(), String> {
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("cannot start PowerShell: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// PowerShell's own call also tells running programs that the variable changed.
const ADD_USER_PATH: &str = r"$p = [Environment]::GetEnvironmentVariable('Path', 'User')
$dirs = @($p -split ';' | Where-Object { $_ })
if ($dirs -notcontains $env:KRAKEN_DIR) {
  [Environment]::SetEnvironmentVariable('Path', (($dirs + $env:KRAKEN_DIR) -join ';'), 'User')
}";

const MAKE_SHORTCUT: &str = r"$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:KRAKEN_LINK)
$s.TargetPath = $env:KRAKEN_TARGET
if ($env:KRAKEN_ICON) { $s.IconLocation = $env:KRAKEN_ICON }
$s.WindowStyle = 7
$s.Save()";

fn publish_files(places: &Places, l: &Launcher, command: &str) -> Result<(), String> {
    let file = places.command_file(command);
    let text = if places.windows {
        cmd_wrapper(l)?
    } else {
        sh_wrapper(l)?
    };
    write_file(&file, &text, true)?;
    if !l.app {
        return Ok(());
    }
    let entry = places.entry_file(l);
    if places.windows {
        std::fs::create_dir_all(&places.apps).map_err(|e| e.to_string())?;
        let target = if l.env.is_empty() && l.path_dirs.is_empty() {
            l.exe.as_path()
        } else {
            file.as_path()
        };
        let none = PathBuf::new();
        let icon = l.icon.as_ref().unwrap_or(&none);
        powershell(
            MAKE_SHORTCUT,
            &[
                ("KRAKEN_LINK", &entry),
                ("KRAKEN_TARGET", target),
                ("KRAKEN_ICON", icon),
            ],
        )
    } else if entry.exists() && !ours(&entry) {
        Err(format!("{} is not KRAKEN's", entry.display()))
    } else {
        write_file(&entry, &desktop_entry(l, &file), false)
    }
}

fn put_bin_on_path(places: &Places) -> Result<bool, String> {
    if places.bin_on_path() {
        return Ok(false);
    }
    if places.windows {
        powershell(ADD_USER_PATH, &[("KRAKEN_DIR", &places.bin)])?;
    } else {
        for p in &places.profiles {
            add_to_profile(p, &places.bin)?;
        }
    }
    Ok(true)
}

/// Makes `l` reachable. Failing here leaves the install working, so callers keep the message.
pub fn publish(places: &Places, l: &Launcher) -> Result<Published, String> {
    let command = places
        .free_command(l)
        .ok_or_else(|| format!("no free command name for {}", l.name))?;
    publish_files(places, l, &command)?;
    let new_path = put_bin_on_path(places)?;
    let mut note = format!("Run it with `{command}`");
    if l.app {
        note.push_str(if places.windows {
            ", or from the Start Menu"
        } else {
            ", or from your application list"
        });
    }
    note.push('.');
    if new_path {
        note.push_str(" Open a new terminal for the command to work.");
    }
    Ok(Published { command, note })
}

/// Removes what [`publish`] wrote for `l` under `command`; files without the mark stay.
pub fn withdraw(places: &Places, l: &Launcher, command: &str) {
    let file = places.command_file(command);
    if ours(&file) {
        let _ = std::fs::remove_file(file);
    }
    let entry = places.entry_file(l);
    // A shortcut is binary, but KRAKEN's folder of the Start Menu holds only KRAKEN's.
    if places.windows || ours(&entry) {
        let _ = std::fs::remove_file(entry);
    }
}

/// The launcher of the Ghidra in `layout`, when both Ghidra and its JDK are there.
pub fn ghidra_launcher(layout: &Layout, windows: bool) -> Option<Launcher> {
    let p = layout.provisioned();
    let (home, java) = (p.ghidra_home?, p.java_home?);
    let exe = home.join(if windows {
        "ghidraRun.bat"
    } else {
        "ghidraRun"
    });
    let icon = home.join(if windows {
        "support/ghidra.ico"
    } else {
        "docs/images/GHIDRA_1.png"
    });
    Some(Launcher {
        id: "ghidra".into(),
        name: "Ghidra".into(),
        summary: "Software reverse engineering framework".into(),
        command: "ghidra".into(),
        exe,
        env: vec![("JAVA_HOME".into(), java.to_string_lossy().into_owned())],
        path_dirs: vec![java.join("bin")],
        app: true,
        icon: icon.is_file().then_some(icon),
        categories: "Development;Debugger;".into(),
    })
}

/// Makes the Ghidra in `layout` reachable; the outcome is a line for people.
pub fn publish_ghidra(layout: &Layout) -> Option<String> {
    let places = Places::system()?;
    let l = ghidra_launcher(layout, places.windows)?;
    Some(publish(&places, &l).map_or_else(
        |e| format!("Ghidra was not added to the system: {e}"),
        |p| p.note,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn places(dir: &Path, windows: bool) -> Places {
        Places {
            bin: dir.join("bin"),
            apps: dir.join("apps"),
            path_env: OsString::new(),
            profiles: vec![dir.join(".profile")],
            windows,
        }
    }

    fn launcher(exe: &Path) -> Launcher {
        Launcher {
            id: "toy".into(),
            name: "Toy".into(),
            summary: "A toy".into(),
            command: "toy".into(),
            exe: exe.to_path_buf(),
            env: vec![("TOY_MODE".into(), "it's on".into())],
            path_dirs: vec![],
            app: true,
            icon: None,
            categories: "Game;Emulator;".into(),
        }
    }

    #[test]
    fn places_follow_the_system_and_its_variables() {
        let env = |k: &str| match k {
            "HOME" => Some("/home/a".into()),
            "LOCALAPPDATA" => Some("/l".into()),
            "APPDATA" => Some("/r".into()),
            _ => None,
        };
        let l = Places::from_env_with("linux", &env).unwrap();
        assert_eq!(l.bin, Path::new("/home/a/.local/bin"));
        assert_eq!(l.apps, Path::new("/home/a/.local/share/applications"));
        let w = Places::from_env_with("windows", &env).unwrap();
        assert_eq!(w.bin, Path::new("/l/KRAKEN/bin"));
        assert!(w.windows);
        assert!(Places::from_env_with("macos", &env).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_published_command_runs_the_program_with_its_environment_and_arguments() {
        let d = tempfile::tempdir().unwrap();
        let prog = d.path().join("the prog");
        write_file(&prog, "#!/bin/sh\necho \"$TOY_MODE|$*\"\n", true).unwrap();
        let p = places(d.path(), false);
        let out = publish(&p, &launcher(&prog)).unwrap();
        assert_eq!(out.command, "toy");
        assert!(out.note.contains("application list"), "{}", out.note);
        assert!(out.note.contains("new terminal"), "{}", out.note);
        let run = std::process::Command::new(p.bin.join("toy"))
            .args(["a b", "c"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&run.stdout), "it's on|a b c\n");
    }

    #[test]
    fn the_desktop_entry_runs_the_command_with_awkward_paths_escaped() {
        let d = tempfile::tempdir().unwrap();
        let p = places(d.path(), false);
        publish(&p, &launcher(Path::new("/x"))).unwrap();
        let t = std::fs::read_to_string(p.apps.join("kraken-toy.desktop")).unwrap();
        assert!(t.starts_with("[Desktop Entry]\n"), "{t}");
        assert!(t.contains("Terminal=false\n"), "{t}");
        assert!(t.contains("Categories=Game;Emulator;\n"), "{t}");
        assert_eq!(
            desktop_exec(Path::new("/a b/100%/$x")),
            r#""/a b/100%%/\\$x""#
        );
    }

    #[test]
    fn a_name_in_use_elsewhere_or_not_ours_gets_a_kraken_name() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = d.path().join("usr");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("toy"), "system copy").unwrap();
        let mut p = places(d.path(), false);
        p.path_env = elsewhere.into_os_string();
        let out = publish(&p, &launcher(Path::new("/x"))).unwrap();
        assert_eq!(out.command, "kraken-toy");
        assert!(!p.bin.join("toy").exists());

        let d = tempfile::tempdir().unwrap();
        let p = places(d.path(), false);
        std::fs::create_dir_all(&p.bin).unwrap();
        std::fs::write(p.bin.join("toy"), "mine").unwrap();
        let out = publish(&p, &launcher(Path::new("/x"))).unwrap();
        assert_eq!(out.command, "kraken-toy");
        assert_eq!(std::fs::read_to_string(p.bin.join("toy")).unwrap(), "mine");
    }

    #[test]
    fn publishing_again_replaces_kraken_s_own_files() {
        let d = tempfile::tempdir().unwrap();
        let p = places(d.path(), false);
        publish(&p, &launcher(Path::new("/old"))).unwrap();
        let out = publish(&p, &launcher(Path::new("/new"))).unwrap();
        assert_eq!(out.command, "toy");
        let t = std::fs::read_to_string(p.bin.join("toy")).unwrap();
        assert!(t.contains("/new") && !t.contains("/old"), "{t}");
    }

    #[test]
    fn withdrawing_removes_kraken_s_files_and_leaves_the_person_s() {
        let d = tempfile::tempdir().unwrap();
        let p = places(d.path(), false);
        let l = launcher(Path::new("/x"));
        publish(&p, &l).unwrap();
        withdraw(&p, &l, "toy");
        assert!(!p.bin.join("toy").exists());
        assert!(!p.apps.join("kraken-toy.desktop").exists());
        write_file(&p.bin.join("toy"), "mine", false).unwrap();
        write_file(&p.apps.join("kraken-toy.desktop"), "mine", false).unwrap();
        withdraw(&p, &l, "toy");
        assert!(p.bin.join("toy").exists());
        assert!(p.apps.join("kraken-toy.desktop").exists());
    }

    #[test]
    fn the_profile_gets_one_marked_line_and_keeps_its_text() {
        let d = tempfile::tempdir().unwrap();
        let p = places(d.path(), false);
        std::fs::write(&p.profiles[0], "export A=1").unwrap();
        publish(&p, &launcher(Path::new("/x"))).unwrap();
        publish(&p, &launcher(Path::new("/x"))).unwrap();
        let t = std::fs::read_to_string(&p.profiles[0]).unwrap();
        assert!(t.starts_with("export A=1\n"), "{t}");
        assert_eq!(t.matches(PROFILE_MARK).count(), 1, "{t}");

        let mut on = places(d.path(), false);
        on.path_env = on.bin.clone().into_os_string();
        on.profiles = vec![d.path().join("other")];
        publish(&on, &launcher(Path::new("/x"))).unwrap();
        assert!(!d.path().join("other").exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_profile_line_adds_the_folder_once_when_a_shell_reads_it() {
        let d = tempfile::tempdir().unwrap();
        let profile = d.path().join(".profile");
        add_to_profile(&profile, Path::new("/k b/bin")).unwrap();
        let script = format!(". '{0}'; . '{0}'; printf %s \"$PATH\"", profile.display());
        let out = std::process::Command::new("sh")
            .env("PATH", "/usr/bin:/bin")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "/k b/bin:/usr/bin:/bin"
        );
    }

    #[test]
    fn windows_command_files_quote_and_refuse_what_cmd_cannot_hold() {
        let mut l = launcher(Path::new(r"C:\Program Files\toy.exe"));
        l.env = vec![("A".into(), "50%".into())];
        l.path_dirs = vec![PathBuf::from(r"C:\jdk\bin")];
        let t = cmd_wrapper(&l).unwrap();
        assert!(t.contains("set \"A=50%%\"\r\n"), "{t}");
        assert!(t.contains("set \"PATH=C:\\jdk\\bin;%PATH%\"\r\n"), "{t}");
        assert!(t.ends_with("\"C:\\Program Files\\toy.exe\" %*\r\n"), "{t}");
        assert!(t.contains(MARK));
        l.exe = PathBuf::from("bad\"name");
        assert!(cmd_wrapper(&l).is_err());
    }

    #[test]
    fn bad_names_are_refused() {
        assert!(!valid_name("../x") && !valid_name("-x") && !valid_name(""));
        assert!(valid_name("mgba-qt") && valid_name("qemu-x86_64"));
        let mut l = launcher(Path::new("/x"));
        l.env = vec![("A=B;".into(), "x".into())];
        assert!(sh_wrapper(&l).is_err());
        assert_eq!(file_safe(r"A/B: c?"), "AB c");
    }
}
