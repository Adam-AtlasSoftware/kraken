//! When the shell tool runs a command without asking, asks, or refuses.
//!
//! The sandbox is the security boundary (no network, read-only project, nothing executable
//! outside the system directories); this policy only decides when the person is asked. Three
//! outcomes: [`Verdict::Allow`] for a pipeline of known harmless programs, [`Verdict::Deny`]
//! for what is never run from here, and [`Verdict::Ask`] for the rest.
//!
//! Sources, in order: the built-in tables, the global `[assistant_shell]` table, the project's
//! `assistant-shell.toml`. A `deny` entry always wins. An `allow` entry adds to the built-in
//! allow set but can neither lift a built-in refusal nor make complex syntax (`;`, `>`, `$(`,
//! ...) run without asking; such entries are ignored with a warning. An `ask` entry makes a
//! program ask even when the built-in set allows it.

use std::path::Path;

use kraken_host::ShellConfig;

use super::tokenize::{Parsed, parse};

/// Name of the per-project file, in the project directory.
pub const PROJECT_FILE: &str = "assistant-shell.toml";

/// Programs that run without asking, when their arguments pass the rules in [`builtin_allows`].
pub const ALLOW: &[&str] = &[
    "bc",
    "dc",
    "expr",
    "printf",
    "echo",
    "seq",
    "date",
    "true",
    "false",
    "test",
    "wc",
    "head",
    "tail",
    "sort",
    "uniq",
    "cut",
    "tr",
    "paste",
    "fold",
    "rev",
    "tac",
    "nl",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "diff",
    "cmp",
    "comm",
    "xxd",
    "od",
    "hexdump",
    "base64",
    "basenc",
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "cksum",
    "b2sum",
    "strings",
    "file",
    "readelf",
    "objdump",
    "nm",
    "c++filt",
    "size",
    "python3",
];

/// Programs that are never run from the shell tool, whatever the settings say.
pub const NEVER: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "ssh",
    "scp",
    "sftp",
    "curl",
    "wget",
    "nc",
    "ncat",
    "telnet",
    "ftp",
    "pip",
    "pip3",
    "npm",
    "npx",
    "cargo",
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "mount",
    "umount",
    "kill",
    "pkill",
    "killall",
    "reboot",
    "shutdown",
    "poweroff",
    "systemctl",
    "service",
    "docker",
    "podman",
    "nsenter",
    "chroot",
];

/// Programs that run another program given as an argument; their arguments are checked against
/// [`NEVER`] too.
const WRAPPERS: &[&str] = &[
    "env", "xargs", "nohup", "time", "timeout", "nice", "exec", "command", "builtin", "stdbuf",
    "setsid", "watch", "busybox", "ionice", "chrt", "taskset", "strace", "ltrace", "flock",
];

/// Directories whose programs count as system programs when named by path.
const SYSTEM_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

const RUN_WITH_EMULATOR: &str = "The analysed program is run with emulate_run, not the shell.";

/// What to do with a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run it.
    Allow,
    /// Ask the person; the text says why.
    Ask(String),
    /// Refuse; the text says why.
    Deny(String),
}

/// The merged rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    allow: Vec<Vec<String>>,
    ask: Vec<Vec<String>>,
    deny: Vec<Vec<String>>,
    /// Entries that were ignored, and unreadable files, in plain words.
    pub warnings: Vec<String>,
}

fn words(entry: &str) -> Vec<String> {
    entry.split_whitespace().map(str::to_string).collect()
}

/// `argv[0]` for lookup: a system program given by path counts as its name.
fn program_name(arg0: &str) -> Result<&str, ()> {
    if !arg0.contains('/') {
        return Ok(arg0);
    }
    let (dir, name) = arg0.rsplit_once('/').ok_or(())?;
    if SYSTEM_DIRS.contains(&dir) && !name.is_empty() && name != ".." && name != "." {
        Ok(name)
    } else {
        Err(())
    }
}

fn starts_with(argv: &[String], prefix: &[String]) -> bool {
    !prefix.is_empty() && argv.len() >= prefix.len() && argv.iter().zip(prefix).all(|(a, p)| a == p)
}

/// Normalised argv: a system path replaced by the program's name.
fn normalised(argv: &[String]) -> Vec<String> {
    let mut v = argv.to_vec();
    if let Some(Ok(name)) = argv.first().map(|a| program_name(a)) {
        v[0] = name.to_string();
    }
    v
}

impl Policy {
    /// The built-in rules only.
    pub fn builtin() -> Self {
        Policy::default()
    }

    /// The built-in rules, then `global`, then `<project_dir>/assistant-shell.toml`.
    pub fn load(global: &ShellConfig, project_dir: Option<&Path>) -> Self {
        let mut p = Policy::builtin();
        p.merge(global, "config.toml");
        if let Some(dir) = project_dir {
            let path = dir.join(PROJECT_FILE);
            match std::fs::read_to_string(&path) {
                Ok(text) => match toml::from_str::<ShellConfig>(&text) {
                    Ok(cfg) => p.merge(&cfg, PROJECT_FILE),
                    Err(e) => p.warnings.push(format!(
                        "{} is not valid and was ignored: {}",
                        path.display(),
                        e.message()
                    )),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => p
                    .warnings
                    .push(format!("{} could not be read: {e}", path.display())),
            }
        }
        p
    }

    /// Adds the entries of `cfg`; `source` names the file in warnings.
    pub fn merge(&mut self, cfg: &ShellConfig, source: &str) {
        for e in &cfg.deny {
            match words(e) {
                w if w.is_empty() => self.warn_empty(source, "deny"),
                w => self.deny.push(w),
            }
        }
        for e in &cfg.ask {
            match words(e) {
                w if w.is_empty() => self.warn_empty(source, "ask"),
                w => self.ask.push(w),
            }
        }
        for e in &cfg.allow {
            let w = words(e);
            if w.is_empty() {
                self.warn_empty(source, "allow");
            } else if let Some(why) = allow_refusal(&w) {
                self.warnings
                    .push(format!("{source}: allow entry `{e}` ignored: {why}"));
            } else {
                self.allow.push(w);
            }
        }
    }

    fn warn_empty(&mut self, source: &str, key: &str) {
        self.warnings
            .push(format!("{source}: an empty `{key}` entry was ignored"));
    }

    /// The decision for a command line.
    pub fn classify(&self, command: &str) -> Verdict {
        let parsed = parse(command);
        if parsed.segments.is_empty() {
            return Verdict::Ask("The command is empty or could not be read.".into());
        }
        if let Some(v) = self.refusal(&parsed) {
            return Verdict::Deny(v);
        }
        for seg in &parsed.segments {
            let argv = normalised(seg);
            if self.ask.iter().any(|p| starts_with(&argv, p)) {
                return Verdict::Ask(format!(
                    "`{}` is set to ask in the shell settings.",
                    argv[0]
                ));
            }
        }
        if let Some(why) = &parsed.complex {
            return Verdict::Ask(format!(
                "The command uses {why}; only plain pipelines run without asking."
            ));
        }
        for seg in &parsed.segments {
            if let Some(why) = self.segment_needs_asking(seg, command) {
                return Verdict::Ask(why);
            }
        }
        Verdict::Allow
    }

    /// The first program of `command` that keeps it from running without asking and could be
    /// allowed for the project: `None` when the command is refused, when the line is complex
    /// (an allow entry would not help) or when it would run anyway.
    pub fn program_to_allow(&self, command: &str) -> Option<String> {
        let parsed = parse(command);
        if parsed.complex.is_some() || parsed.segments.is_empty() || self.refusal(&parsed).is_some()
        {
            return None;
        }
        parsed.segments.iter().find_map(|seg| {
            let argv = normalised(seg);
            let name = argv.first()?.clone();
            allow_refusal(std::slice::from_ref(&name))
                .is_none()
                .then_some(())?;
            let ask_listed = self.ask.iter().any(|p| starts_with(&argv, p));
            (ask_listed || self.segment_needs_asking(seg, command).is_some()).then_some(name)
        })
    }

    /// The reason a line is refused, if it is.
    fn refusal(&self, parsed: &Parsed) -> Option<String> {
        for seg in &parsed.segments {
            let argv = normalised(seg);
            let raw0 = seg.first().map(String::as_str).unwrap_or_default();
            if program_name(raw0).is_err() {
                return Some(RUN_WITH_EMULATOR.into());
            }
            if self.deny.iter().any(|p| starts_with(&argv, p)) {
                return Some(format!(
                    "`{}` is refused by the shell settings.",
                    argv.join(" ")
                ));
            }
            let wrapped = WRAPPERS.contains(&argv[0].as_str());
            let checked: &[String] = if wrapped { &argv } else { &argv[..1] };
            for w in checked {
                let name = program_name(w).unwrap_or(w.as_str());
                if NEVER.contains(&name) {
                    return Some(format!("`{name}` is never run from the assistant's shell."));
                }
            }
        }
        None
    }

    /// Why one simple command does not run without asking (`None`: it does).
    fn segment_needs_asking(&self, seg: &[String], whole: &str) -> Option<String> {
        let argv = normalised(seg);
        if self.allow.iter().any(|p| starts_with(&argv, p)) {
            return None;
        }
        let name = argv[0].as_str();
        if !ALLOW.contains(&name) {
            return Some(format!(
                "`{name}` is not on the list of programs that run without asking."
            ));
        }
        builtin_allows(&argv, whole)
    }
}

/// Why an `allow` entry cannot be honoured (`None`: it can).
fn allow_refusal(entry: &[String]) -> Option<String> {
    let first = &entry[0];
    if first.contains('=') {
        return Some("it sets a variable".into());
    }
    let name = program_name(first).unwrap_or(first.as_str());
    if program_name(first).is_err() {
        return Some(RUN_WITH_EMULATOR.into());
    }
    if NEVER.contains(&name) {
        return Some(format!("`{name}` is never run from the assistant's shell"));
    }
    if WRAPPERS.contains(&name) {
        return Some(format!("`{name}` runs other programs"));
    }
    let joined = entry.join(" ");
    let parsed = parse(&joined);
    if let Some(why) = parsed.complex {
        return Some(format!("it uses {why}"));
    }
    if parsed.segments.len() != 1 {
        return Some("it is not a single command".into());
    }
    None
}

fn is_flag_with(arg: &str, short: &[char], long: &[&str]) -> bool {
    if let Some(rest) = arg.strip_prefix("--") {
        let name = rest.split('=').next().unwrap_or(rest);
        return !name.is_empty() && long.iter().any(|l| l.starts_with(name));
    }
    match arg.strip_prefix('-') {
        Some(cluster) if !cluster.is_empty() => cluster.chars().any(|c| short.contains(&c)),
        _ => false,
    }
}

fn positionals(args: &[String]) -> usize {
    let mut n = 0;
    let mut options_done = false;
    for a in args {
        if !options_done && a == "--" {
            options_done = true;
        } else if options_done || !a.starts_with('-') || a == "-" {
            n += 1;
        }
    }
    n
}

/// The argument rules of the built-in allow set: `None` when `argv` may run without asking,
/// else the reason it asks.
fn builtin_allows(argv: &[String], whole: &str) -> Option<String> {
    let name = argv[0].as_str();
    let args = &argv[1..];
    let ask = |why: &str| Some(format!("`{name}` {why}."));
    match name {
        "sort" => {
            if args
                .iter()
                .any(|a| is_flag_with(a, &['o'], &["output", "compress-program"]))
            {
                return ask("with that option can write files or run programs");
            }
        }
        "grep" | "egrep" | "fgrep" => {
            if args.iter().any(|a| is_flag_with(a, &[], &["pre"])) {
                return ask("with --pre runs another program");
            }
        }
        "uniq" => {
            if positionals(args) > 1 {
                return ask("with an output file writes it");
            }
        }
        "xxd" => {
            if positionals(args) > 1 {
                return ask("with an output file writes it");
            }
        }
        "file" => {
            if args.iter().any(|a| is_flag_with(a, &['C'], &["compile"])) {
                return ask("with that option writes files");
            }
        }
        "dc" => {
            if whole.contains('!') {
                return ask("with `!` can run a shell command");
            }
        }
        "sed" => return sed_asks(args),
        "python3" => {
            let ok = match args {
                [c, _code, ..] if c == "-c" => true,
                [dash, ..] if dash == "-" => true,
                _ => false,
            };
            if !ok {
                return ask("runs without asking only as `python3 -c CODE` or `python3 -`");
            }
        }
        _ => {}
    }
    None
}

/// `sed` runs without asking when the script has only `s`, `y`, `p`, `P`, `d`, `D`, `q`, `n`
/// and `N` commands (no `e`/`w`/`r` flags or commands) and no option that edits in place or
/// reads a script file.
fn sed_asks(args: &[String]) -> Option<String> {
    let ask = |why: &str| Some(format!("`sed` {why}."));
    let mut scripts: Vec<&str> = Vec::new();
    let mut i = 0;
    let mut have_e = false;
    let mut first_positional: Option<usize> = None;
    let mut options_done = false;
    while i < args.len() {
        let a = args[i].as_str();
        if options_done || !a.starts_with('-') || a == "-" {
            first_positional.get_or_insert(i);
            if !have_e && scripts.is_empty() {
                scripts.push(a);
            }
            options_done = true;
            i += 1;
            continue;
        }
        if a == "--" {
            options_done = true;
        } else if a == "-e" {
            have_e = true;
            match args.get(i + 1) {
                Some(s) => scripts.push(s),
                None => return ask("has no script"),
            }
            i += 1;
        } else if let Some(long) = a.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            let fine = ["quiet", "silent", "regexp-extended", "null-data", "posix"];
            if name.len() < 3 || !fine.iter().any(|f| f.starts_with(name)) {
                return ask("with that option can write files or run programs");
            }
        } else {
            let cluster = &a[1..];
            if let Some(script) = cluster.strip_prefix('e') {
                have_e = true;
                if script.is_empty() {
                    return ask("has no script");
                }
                scripts.push(script);
            } else if !cluster.chars().all(|c| matches!(c, 'n' | 'E' | 'r' | 'z')) {
                return ask("with that option can write files or run programs");
            }
        }
        i += 1;
    }
    if scripts.is_empty() {
        return ask("has no script");
    }
    if scripts.iter().all(|s| simple_sed_script(s)) {
        None
    } else {
        ask("script is not a plain s///, y///, p, d, q, n or N script")
    }
}

/// True when `script` is a `;`/newline separated list of simple commands.
fn simple_sed_script(script: &str) -> bool {
    let c: Vec<char> = script.chars().collect();
    let mut i = 0;
    let mut any = false;
    loop {
        while i < c.len() && (c[i].is_whitespace() || c[i] == ';') {
            i += 1;
        }
        if i >= c.len() {
            return any;
        }
        // Address: line number, `$`, `/re/`, `first~step`, ranges, then an optional `!`.
        loop {
            if i < c.len() && (c[i].is_ascii_digit() || c[i] == '$' || c[i] == '~') {
                while i < c.len() && (c[i].is_ascii_digit() || c[i] == '$' || c[i] == '~') {
                    i += 1;
                }
            } else if i < c.len() && c[i] == '/' {
                match delimited(&c, i + 1, '/') {
                    Some(end) => i = end,
                    None => return false,
                }
                while i < c.len() && matches!(c[i], 'I' | 'M') {
                    i += 1;
                }
            } else {
                break;
            }
            if i < c.len() && c[i] == ',' {
                i += 1;
            } else {
                break;
            }
        }
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        if i < c.len() && c[i] == '!' {
            i += 1;
            while i < c.len() && c[i].is_whitespace() {
                i += 1;
            }
        }
        let Some(&cmd) = c.get(i) else { return false };
        i += 1;
        match cmd {
            's' | 'y' => {
                let Some(&d) = c.get(i) else { return false };
                if d == '\\' || d == '\n' || d.is_alphanumeric() {
                    return false;
                }
                let Some(mid) = delimited(&c, i + 1, d) else {
                    return false;
                };
                let Some(end) = delimited(&c, mid, d) else {
                    return false;
                };
                i = end;
                if cmd == 's' {
                    while i < c.len() && !matches!(c[i], ';' | '\n' | ' ' | '\t') {
                        if !matches!(c[i], 'g' | 'p' | 'i' | 'I' | 'm' | 'M' | '0'..='9') {
                            return false;
                        }
                        i += 1;
                    }
                }
            }
            'p' | 'P' | 'd' | 'D' | 'n' | 'N' => {}
            'q' => {
                while i < c.len() && c[i].is_ascii_digit() {
                    i += 1;
                }
            }
            _ => return false,
        }
        while i < c.len() && matches!(c[i], ' ' | '\t') {
            i += 1;
        }
        if i < c.len() && !matches!(c[i], ';' | '\n') {
            return false;
        }
        any = true;
    }
}

/// Index just after the next unescaped `delim` at or after `from`.
fn delimited(c: &[char], from: usize, delim: char) -> Option<usize> {
    let mut i = from;
    while i < c.len() {
        if c[i] == '\\' {
            i += 2;
            continue;
        }
        if c[i] == delim {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

// ----- the project file -----

/// Why the project file could not be changed.
#[derive(Debug, thiserror::Error)]
pub enum PolicyFileError {
    /// The entry cannot be allowed.
    #[error("{0}")]
    Refused(String),
    /// The existing file is not valid TOML of the expected shape.
    #[error("{path} is not valid: {message}")]
    Invalid { path: String, message: String },
    /// Reading or writing failed.
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

const HEADER: &str = "# Shell commands the assistant may run in this project without asking.\n\
# Each entry is a command prefix, for example \"objdump\" or \"git log\".\n\
# Keys: allow, ask, deny. A deny entry always wins. The sandbox still applies.\n";

/// Adds `prefix` to `allow` in `<project_dir>/assistant-shell.toml`, creating the file with a
/// short header when it is missing and keeping everything else in it. Returns `false` when the
/// entry was already there. The file is replaced atomically.
pub fn add_project_allow(project_dir: &Path, prefix: &str) -> Result<bool, PolicyFileError> {
    let entry = words(prefix).join(" ");
    if entry.is_empty() {
        return Err(PolicyFileError::Refused("The entry is empty.".into()));
    }
    if let Some(why) = allow_refusal(&words(&entry)) {
        return Err(PolicyFileError::Refused(format!(
            "`{entry}` cannot be allowed: {why}."
        )));
    }
    let path = project_dir.join(PROJECT_FILE);
    let io = |source| PolicyFileError::Io {
        path: path.display().to_string(),
        source,
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => format!("{HEADER}\nallow = []\n"),
        Err(e) => return Err(io(e)),
    };
    let invalid = |message: String| PolicyFileError::Invalid {
        path: path.display().to_string(),
        message,
    };
    let cfg: ShellConfig = toml::from_str(&text).map_err(|e| invalid(e.message().to_string()))?;
    if cfg.allow.iter().any(|a| words(a).join(" ") == entry) {
        return Ok(false);
    }
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| invalid(e.message().to_string()))?;
    let item = doc
        .entry("allow")
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let arr = item
        .as_array_mut()
        .ok_or_else(|| invalid("`allow` is not a list".into()))?;
    arr.push(entry.as_str());
    let out = doc.to_string();
    let tmp = project_dir.join(format!(".{PROJECT_FILE}.tmp"));
    std::fs::write(&tmp, out).map_err(io)?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(e));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Policy {
        Policy::builtin()
    }

    fn allow(cmd: &str) {
        assert_eq!(p().classify(cmd), Verdict::Allow, "{cmd}");
    }

    fn ask(cmd: &str) {
        assert!(
            matches!(p().classify(cmd), Verdict::Ask(_)),
            "{cmd}: {:?}",
            p().classify(cmd)
        );
    }

    fn deny(cmd: &str) {
        assert!(
            matches!(p().classify(cmd), Verdict::Deny(_)),
            "{cmd}: {:?}",
            p().classify(cmd)
        );
    }

    #[test]
    fn the_examples_run_without_asking() {
        allow("echo '2^64-1' | bc");
        allow("python3 -c 'print(0x9e3779b9*3 % 2**32)'");
        allow("printf '%x\\n' 255");
        allow("echo aGk= | base64 -d");
        allow("echo hi | sha256sum");
        allow("seq 1 10 | sort -n | uniq -c | head -3");
        allow("echo hi | xxd");
        allow("objdump -d /bin/true | grep call | wc -l");
        allow("/usr/bin/echo hi");
        allow("echo hi | python3 -");
        allow("python3 -c 'import sys; print(sys.argv)' a b");
    }

    #[test]
    fn programs_that_are_never_run_are_refused() {
        for c in [
            "sudo id",
            "curl http://x",
            "wget x",
            "ssh host",
            "echo 1 | nc -l",
            "cargo build",
            "pip install x",
            "docker run x",
            "kill 1",
            "systemctl stop x",
            "echo a; sudo id",
            "echo $(curl x)",
            "echo `wget x`",
            "echo \"$(ssh x)\"",
            "(curl x)",
            "env curl x",
            "xargs -n1 curl",
            "timeout 5 nc x 1",
            "/usr/bin/curl x",
            "nice -n 5 sudo id",
        ] {
            deny(c);
        }
    }

    #[test]
    fn a_program_given_by_a_path_is_the_analysed_program() {
        for c in [
            "./a.out",
            "./a.out | wc",
            "/home/me/proj/a.out",
            "/tmp/x/prog",
            "/usr/bin/../../home/x/p",
            "../prog",
            "/usr/bin/foo/bar",
            "echo 1; ./prog",
        ] {
            match p().classify(c) {
                Verdict::Deny(r) => assert_eq!(r, RUN_WITH_EMULATOR, "{c}"),
                other => panic!("{c}: {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_programs_and_complex_syntax_ask() {
        for c in [
            "ls",
            "cat /etc/passwd",
            "awk 'BEGIN{system(\"id\")}'",
            "find . -exec id ;",
            "echo a; echo b",
            "echo a > f",
            "echo $HOME",
            "echo a && echo b",
            "echo `id`",
            "echo $(id)",
            "(echo a)",
            "FOO=1 echo a",
            "env echo hi",
            "",
            "   ",
            "echo 'open",
            "xargs echo",
        ] {
            ask(c);
        }
    }

    #[test]
    fn argument_rules() {
        ask("sort -o out");
        ask("sort -no out");
        ask("sort --output=out");
        ask("sort --out=out");
        ask("sort --compress-program=sh");
        allow("sort -n -r");
        allow("sort -t, -k2");
        ask("grep --pre=sh x");
        allow("grep -i foo");
        allow("egrep -c 'a|b'");
        ask("uniq in out");
        allow("uniq -c in");
        ask("xxd -r in out");
        allow("xxd -r in");
        ask("file -C");
        allow("file a.bin");
        ask("echo '!ls' | dc");
        allow("echo '2 3 + p' | dc");
        ask("python3 script.py");
        ask("python3 -m http.server");
        ask("python3 -i");
        ask("python3 -E -c 'print(1)'");
        ask("python3");
        ask("python3 -c");
        allow("python3 -");
    }

    #[test]
    fn sed_is_checked_conservatively() {
        allow("sed 's/a/b/' f");
        allow("sed -n '2p' f");
        allow("sed -e 's/a/b/g;s/c/d/' f");
        allow("sed 's|a|b|2' f");
        allow("sed '1,3d'");
        allow("sed -E 's/(a)/\\1\\1/'");
        allow("sed '/x/!d'");
        allow("sed 'y/abc/xyz/'");
        allow("sed 5q");
        allow("echo a | sed 's/a/b/'");
        ask("sed -i 's/a/b/' f");
        ask("sed --in-place s/a/b/ f");
        ask("sed -ni p f");
        ask("sed 's/a/b/w out' f");
        ask("sed 's/a/b/e' f");
        ask("sed 'w out' f");
        ask("sed '1r other' f");
        ask("sed 'e id'");
        ask("sed -f script f");
        ask("sed -s p f");
        allow("sed '$!N;s/\\n/ /'");
        ask("sed '{p}'");
        ask("sed");
    }

    #[test]
    fn config_entries_follow_the_merge_rules() {
        let cfg = ShellConfig {
            allow: vec![
                "git log".into(),
                "ls".into(),
                "curl".into(),
                "sudo id".into(),
                "./prog".into(),
                "echo a; b".into(),
                "env".into(),
                "".into(),
            ],
            ask: vec!["objdump".into()],
            deny: vec!["rm".into(), "git push".into(), "base64".into()],
        };
        let mut pol = Policy::builtin();
        pol.merge(&cfg, "config.toml");
        assert_eq!(pol.classify("git log --oneline"), Verdict::Allow);
        assert!(matches!(pol.classify("git status"), Verdict::Ask(_)));
        assert_eq!(pol.classify("ls | wc -l"), Verdict::Allow);
        assert!(matches!(pol.classify("objdump -d x"), Verdict::Ask(_)));
        assert!(matches!(pol.classify("rm x"), Verdict::Deny(_)));
        assert!(matches!(pol.classify("git push"), Verdict::Deny(_)));
        assert!(matches!(pol.classify("echo a | base64"), Verdict::Deny(_)));
        assert!(matches!(pol.classify("curl x"), Verdict::Deny(_)));
        assert!(matches!(pol.classify("./prog"), Verdict::Deny(_)));
        // Allow entries do not lift the complex syntax rule.
        assert!(matches!(pol.classify("ls; ls"), Verdict::Ask(_)));
        assert!(matches!(pol.classify("ls > f"), Verdict::Ask(_)));
        assert_eq!(pol.warnings.len(), 6, "{:?}", pol.warnings);
        // A deny entry wins over an allow entry for the same program.
        let both = ShellConfig {
            allow: vec!["ls".into()],
            deny: vec!["ls".into()],
            ..ShellConfig::default()
        };
        let mut pol = Policy::builtin();
        pol.merge(&both, "x");
        assert!(matches!(pol.classify("ls"), Verdict::Deny(_)));
        // An ask entry beats an allow entry.
        let both = ShellConfig {
            allow: vec!["ls".into()],
            ask: vec!["ls".into()],
            ..ShellConfig::default()
        };
        let mut pol = Policy::builtin();
        pol.merge(&both, "x");
        assert!(matches!(pol.classify("ls"), Verdict::Ask(_)));
    }

    #[test]
    fn an_allow_entry_with_arguments_is_a_prefix() {
        let mut pol = Policy::builtin();
        pol.merge(
            &ShellConfig {
                allow: vec!["git log".into()],
                ..ShellConfig::default()
            },
            "x",
        );
        assert_eq!(pol.classify("git log -3"), Verdict::Allow);
        assert!(matches!(pol.classify("git commit"), Verdict::Ask(_)));
        assert!(matches!(pol.classify("git"), Verdict::Ask(_)));
    }

    #[test]
    fn load_reads_the_project_file_and_survives_a_broken_one() {
        let dir = tempfile::tempdir().unwrap();
        let global = ShellConfig {
            allow: vec!["ls".into()],
            ..ShellConfig::default()
        };
        let pol = Policy::load(&global, Some(dir.path()));
        assert!(pol.warnings.is_empty());
        assert_eq!(pol.classify("ls"), Verdict::Allow);
        std::fs::write(
            dir.path().join(PROJECT_FILE),
            "allow = [\"cat\"]\ndeny = [\"ls\"]\n",
        )
        .unwrap();
        let pol = Policy::load(&global, Some(dir.path()));
        assert_eq!(pol.classify("cat x"), Verdict::Allow);
        assert!(matches!(pol.classify("ls"), Verdict::Deny(_)));
        std::fs::write(dir.path().join(PROJECT_FILE), "allow = [").unwrap();
        let pol = Policy::load(&global, Some(dir.path()));
        assert_eq!(pol.warnings.len(), 1);
        assert_eq!(pol.classify("ls"), Verdict::Allow);
        std::fs::write(dir.path().join(PROJECT_FILE), "bogus = 1\n").unwrap();
        assert_eq!(Policy::load(&global, Some(dir.path())).warnings.len(), 1);
    }

    #[test]
    fn program_to_allow_names_the_blocking_program() {
        let pol = p();
        assert_eq!(pol.program_to_allow("ls | wc -l").as_deref(), Some("ls"));
        assert_eq!(pol.program_to_allow("echo a | cat").as_deref(), Some("cat"));
        assert_eq!(
            pol.program_to_allow("python3 x.py").as_deref(),
            Some("python3")
        );
        assert_eq!(pol.program_to_allow("ls; ls"), None);
        assert_eq!(pol.program_to_allow("sudo ls"), None);
        assert_eq!(pol.program_to_allow("./x"), None);
        assert_eq!(pol.program_to_allow("echo a | bc"), None);
    }

    #[test]
    fn add_project_allow_creates_keeps_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(PROJECT_FILE);
        assert!(add_project_allow(dir.path(), "objdump").unwrap());
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.starts_with("# Shell commands"), "{text}");
        assert!(
            text.contains("allow = [\"objdump\"]") && text.contains("Keys:"),
            "{text}"
        );
        assert!(!add_project_allow(dir.path(), "objdump").unwrap());
        assert!(add_project_allow(dir.path(), "git  log").unwrap());
        let cfg: ShellConfig = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(cfg.allow, ["objdump", "git log"]);
        assert!(!dir.path().join(format!(".{PROJECT_FILE}.tmp")).exists());

        std::fs::write(
            &file,
            "# mine\ndeny = [\"rm\"]  # never\n\nask = [\"cat\"]\n",
        )
        .unwrap();
        assert!(add_project_allow(dir.path(), "nm").unwrap());
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.contains("# mine") && text.contains("# never"),
            "{text}"
        );
        let cfg: ShellConfig = toml::from_str(&text).unwrap();
        assert_eq!(
            (cfg.allow, cfg.deny, cfg.ask),
            (
                vec!["nm".to_string()],
                vec!["rm".to_string()],
                vec!["cat".to_string()]
            )
        );
    }

    #[test]
    fn add_project_allow_refuses_what_cannot_be_allowed() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["curl", "sudo", "./a.out", "", "ls; id", "env", "a | b"] {
            assert!(
                matches!(
                    add_project_allow(dir.path(), bad),
                    Err(PolicyFileError::Refused(_))
                ),
                "{bad}"
            );
        }
        assert!(!dir.path().join(PROJECT_FILE).exists());
        std::fs::write(dir.path().join(PROJECT_FILE), "allow = [").unwrap();
        assert!(matches!(
            add_project_allow(dir.path(), "nm"),
            Err(PolicyFileError::Invalid { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(PROJECT_FILE)).unwrap(),
            "allow = ["
        );
    }

    #[test]
    fn the_tables_do_not_overlap() {
        for a in ALLOW {
            assert!(!NEVER.contains(a), "{a}");
        }
    }
}
