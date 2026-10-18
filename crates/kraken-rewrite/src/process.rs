//! The program-level oracle (oracle kind `process`, ADR 0013): run the original program and the
//! rewritten one on the same inputs, each inside the sandbox with no network, and compare exit
//! status, standard output and standard error.
//!
//! Inputs ([`ProgramCase`]) are an argument vector and standard input. They come from four
//! places: the baseline run (no arguments, empty input), string literals of the program's source
//! when the source is at hand (the corpus programs ship theirs in `corpus/src`), seeded
//! generation, and cases the caller gives. A program that never reads its arguments or its input
//! still gets the cases: the rewrite has to ignore them just as the original does.
//!
//! Both programs are started the same way: a fresh private directory that holds a copy of the
//! executable and is the only writable place, the environment cleared, `argv[0]` set to `prog`.

use std::path::Path;
use std::time::Duration;

use kraken_registry::commands::ProgramCaseSpec;

use crate::difftest::Rng;
use crate::error::RewriteError;
use crate::sandbox::{
    Confinement, ConfinementReport, ReadScope, confine, run_captured_with_input, scratch_dir,
};

/// Wall-clock limit for one run of one program.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on the output kept per stream.
pub const OUTPUT_CAP: usize = 1 << 20;
/// Most cases one verification runs.
pub const MAX_CASES: usize = 300;
/// Most bytes of output shown in a view.
pub const VIEW_BYTES: usize = 4096;

/// Where a case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseOrigin {
    /// No arguments, empty input.
    Baseline,
    /// Derived from the program's source.
    Corpus,
    /// Seeded generation.
    Generated,
    /// Given by the caller.
    User,
}

impl CaseOrigin {
    /// The name in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            CaseOrigin::Baseline => "baseline",
            CaseOrigin::Corpus => "corpus",
            CaseOrigin::Generated => "generated",
            CaseOrigin::User => "user",
        }
    }
}

/// How a program is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramCase {
    /// Label.
    pub name: String,
    /// Where it came from.
    pub origin: CaseOrigin,
    /// Arguments after `argv[0]`.
    pub argv: Vec<String>,
    /// Standard input.
    pub stdin: Vec<u8>,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// `exit(code)` or return from `main`.
    Code(i32),
    /// Killed by a signal.
    Signal(i32),
    /// The wall-clock limit killed it.
    Timeout,
}

impl Exit {
    /// The text in reports.
    pub fn describe(self) -> String {
        match self {
            Exit::Code(c) => format!("exit {c}"),
            Exit::Signal(s) => format!("signal {s}"),
            Exit::Timeout => "timeout".to_string(),
        }
    }
}

/// What one run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// How it ended.
    pub exit: Exit,
    /// Standard output (capped at [`OUTPUT_CAP`]).
    pub stdout: Vec<u8>,
    /// Standard error (capped).
    pub stderr: Vec<u8>,
    /// The files the program left in its working directory, by name.
    pub files: Vec<WrittenFile>,
}

/// Most files of a run that are compared.
pub const MAX_FILES: usize = 64;
/// Block size of [`WrittenFile::blocks`].
const FILE_BLOCK: usize = 4096;

/// A file a run wrote, summarised so that two runs can be compared without keeping the contents:
/// the size, a hash of the whole and of every 4 KiB block, and the first bytes for context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    /// Path relative to the working directory.
    pub name: String,
    /// Length in bytes.
    pub size: u64,
    /// SHA-256 of the contents.
    pub sha256: String,
    /// The first 8 bytes of the SHA-256 of each block.
    pub blocks: Vec<u64>,
    /// The first bytes.
    pub head: Vec<u8>,
}

impl WrittenFile {
    pub(crate) fn of(name: String, data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let blocks = data
            .chunks(FILE_BLOCK)
            .map(|c| {
                let d = Sha256::digest(c);
                u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
            })
            .collect();
        WrittenFile {
            name,
            size: data.len() as u64,
            sha256: crate::unit::sha256_bytes_hex(data),
            blocks,
            head: data[..data.len().min(64)].to_vec(),
        }
    }
}

/// The regular files under `dir` (without `skip`), sorted by name, at most [`MAX_FILES`].
fn written_files(dir: &Path, skip: &str) -> Vec<WrittenFile> {
    let mut out = Vec::new();
    let mut todo = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, prefix)) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            let Ok(ty) = e.file_type() else { continue };
            if ty.is_dir() && prefix.matches('/').count() < 4 {
                todo.push((e.path(), format!("{name}/")));
            } else if ty.is_file()
                && name != skip
                && out.len() < MAX_FILES
                && let Ok(data) = std::fs::read(e.path())
            {
                out.push(WrittenFile::of(name, &data));
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Runs `exe` on `case` inside the sandbox. The executable is copied into a fresh private
/// directory first: that directory is the program's working directory and its only writable
/// place, and it is gone afterwards.
pub fn run_case(
    exe: &Path,
    case: &ProgramCase,
    confinement: &Confinement,
) -> Result<(Outcome, ConfinementReport), RewriteError> {
    run_case_with_env(exe, case, confinement, &[])
}

/// [`run_case`] with extra environment variables (the environment is otherwise empty).
pub fn run_case_with_env(
    exe: &Path,
    case: &ProgramCase,
    confinement: &Confinement,
    env: &[(&str, String)],
) -> Result<(Outcome, ConfinementReport), RewriteError> {
    let dir = scratch_dir("kraken-prog-")?;
    let copy = dir.path().join("prog");
    std::fs::copy(exe, &copy)
        .map_err(|e| RewriteError::Native(format!("copy {}: {e}", exe.display())))?;
    let mut cmd = std::process::Command::new(&copy);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0("prog");
    }
    cmd.args(&case.argv);
    let report = confine(
        &mut cmd,
        dir.path(),
        ReadScope::SystemLibraries,
        confinement,
    )?;
    cmd.envs(env.iter().map(|(k, v)| (*k, v.as_str())));
    // Another thread's fork can briefly hold the freshly written copy open for writing, which
    // makes exec fail with ETXTBSY; it lets go as soon as that child has exec'd.
    let mut tries = 0;
    let out = loop {
        match run_captured_with_input(
            &mut cmd,
            Some(case.stdin.clone()),
            RUN_TIMEOUT,
            OUTPUT_CAP,
            Duration::from_millis(2),
        ) {
            Err(e) if e.raw_os_error() == Some(26) && tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                return Err(RewriteError::Native(format!(
                    "cannot start the program: {e}"
                )));
            }
            Ok(out) => break out,
        }
    };
    let exit = match out.status {
        None => Exit::Timeout,
        Some(status) => match status.code() {
            Some(c) => Exit::Code(c),
            None => Exit::Signal(signal_of(&status)),
        },
    };
    Ok((
        Outcome {
            exit,
            stdout: out.stdout,
            stderr: out.stderr,
            files: written_files(dir.path(), "prog"),
        },
        report,
    ))
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}

#[cfg(not(unix))]
fn signal_of(_: &std::process::ExitStatus) -> i32 {
    0
}

fn excerpt(bytes: &[u8], at: usize) -> String {
    let from = at.saturating_sub(16);
    let to = (at + 48).min(bytes.len());
    let text: String = String::from_utf8_lossy(&bytes[from..to])
        .chars()
        .flat_map(char::escape_default)
        .collect();
    format!(
        "{}{text}{}",
        if from > 0 { "..." } else { "" },
        if to < bytes.len() { "..." } else { "" }
    )
}

fn stream_difference(name: &str, a: &[u8], b: &[u8]) -> Option<String> {
    if a == b {
        return None;
    }
    let at = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    Some(format!(
        "{name}: {} bytes vs {} bytes, first difference at byte {at}: original `{}`, rewritten `{}`",
        a.len(),
        b.len(),
        excerpt(a, at),
        excerpt(b, at)
    ))
}

/// What differs between the original's run and the rewrite's (empty when nothing).
pub fn compare(original: &Outcome, rewritten: &Outcome) -> Vec<String> {
    let mut d = Vec::new();
    if original.exit != rewritten.exit {
        d.push(format!(
            "exit status: original {}, rewritten {}",
            original.exit.describe(),
            rewritten.exit.describe()
        ));
    }
    d.extend(stream_difference(
        "stdout",
        &original.stdout,
        &rewritten.stdout,
    ));
    d.extend(stream_difference(
        "stderr",
        &original.stderr,
        &rewritten.stderr,
    ));
    d.extend(file_differences(&original.files, &rewritten.files));
    d
}

/// What differs between the files two runs wrote.
fn file_differences(a: &[WrittenFile], b: &[WrittenFile]) -> Vec<String> {
    let mut d = Vec::new();
    for f in a {
        match b.iter().find(|g| g.name == f.name) {
            None => d.push(format!(
                "file {}: the original wrote it ({} bytes), the rewrite did not",
                f.name, f.size
            )),
            Some(g) if g.sha256 != f.sha256 => {
                let block = f
                    .blocks
                    .iter()
                    .zip(&g.blocks)
                    .position(|(x, y)| x != y)
                    .unwrap_or(f.blocks.len().min(g.blocks.len()));
                let at = f
                    .head
                    .iter()
                    .zip(&g.head)
                    .position(|(x, y)| x != y)
                    .filter(|_| block == 0)
                    .map(|i| format!("byte {i}"))
                    .unwrap_or_else(|| {
                        format!(
                            "bytes {} to {}",
                            block * FILE_BLOCK,
                            (block + 1) * FILE_BLOCK - 1
                        )
                    });
                d.push(format!(
                    "file {}: {} bytes vs {} bytes, first difference in {at}",
                    f.name, f.size, g.size
                ));
            }
            Some(_) => {}
        }
    }
    for g in b {
        if !a.iter().any(|f| f.name == g.name) {
            d.push(format!(
                "file {}: the rewrite wrote it ({} bytes), the original did not",
                g.name, g.size
            ));
        }
    }
    d
}

// ----- source-derived and generated cases -----

/// The source file a corpus binary was built from: `<root>/bin/<name>-O0[-stripped]` has its
/// source in `<root>/src/<name>.c` or `.cpp`. Returns the file name and the text.
pub fn corpus_source(binary: &Path) -> Option<(String, String)> {
    let file = binary.file_name()?.to_str()?;
    let stem = file.split("-O").next().filter(|s| !s.is_empty())?;
    let src_dir = binary.parent()?.parent()?.join("src");
    for ext in ["c", "cpp"] {
        let name = format!("{stem}.{ext}");
        if let Ok(text) = std::fs::read_to_string(src_dir.join(&name)) {
            return Some((name, text));
        }
    }
    None
}

/// Printable string literals of C source worth feeding to a program: no format strings, no
/// include paths, short, at most `max` distinct ones in source order.
pub fn string_literals(source: &str, max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in source.lines() {
        let t = line.trim_start();
        if t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                // A character literal: skip it whole so `'"'` does not open a string.
                while let Some(x) = chars.next() {
                    if x == '\\' {
                        chars.next();
                    } else if x == '\'' {
                        break;
                    }
                }
                continue;
            }
            if c != '"' {
                continue;
            }
            let mut lit = String::new();
            let mut closed = false;
            while let Some(x) = chars.next() {
                match x {
                    '\\' => match chars.next() {
                        Some('n') => lit.push('\n'),
                        Some('t') => lit.push('\t'),
                        Some('\\') => lit.push('\\'),
                        Some('"') => lit.push('"'),
                        _ => lit.push('\u{0}'),
                    },
                    '"' => {
                        closed = true;
                        break;
                    }
                    other => lit.push(other),
                }
            }
            let usable = closed
                && !lit.is_empty()
                && lit.chars().count() <= 48
                && !lit.contains('%')
                && lit.chars().all(|c| c == '\t' || (' '..='~').contains(&c));
            if usable && !out.contains(&lit) {
                out.push(lit);
                if out.len() >= max {
                    return out;
                }
            }
        }
    }
    out
}

fn mentions(source: &str, words: &[&str]) -> bool {
    words.iter().any(|w| source.contains(w))
}

/// What case derivation starts from.
#[derive(Debug, Clone, Default)]
pub struct CaseSeed<'a> {
    /// The program's source text, when known.
    pub source: Option<&'a str>,
    /// Seed of the generated cases.
    pub seed: u64,
    /// How many generated cases.
    pub generated: usize,
    /// Cases the caller gave.
    pub user: &'a [ProgramCaseSpec],
}

fn case(name: &str, origin: CaseOrigin, argv: &[&str], stdin: &[u8]) -> ProgramCase {
    ProgramCase {
        name: name.to_string(),
        origin,
        argv: argv.iter().map(|s| (*s).to_string()).collect(),
        stdin: stdin.to_vec(),
    }
}

/// The cases to run, in order, without duplicates.
pub fn derive_cases(seed: &CaseSeed<'_>) -> Vec<ProgramCase> {
    let mut cases = vec![case("baseline", CaseOrigin::Baseline, &[], b"")];
    if let Some(src) = seed.source {
        let literals = string_literals(src, 8);
        let uses_argv = mentions(src, &["argv", "argc"]);
        let uses_stdin = mentions(
            src,
            &[
                "stdin", "getchar", "fgets", "scanf", "getline", "fread(", "read(0",
            ],
        );
        // A program that never looks at its arguments or input must ignore them in the rewrite
        // too; one that does gets a case per literal and the awkward shapes.
        let tag = |what: &str, used: bool| {
            if used {
                what.to_string()
            } else {
                format!("{what}-ignored")
            }
        };
        for (i, lit) in literals.iter().enumerate() {
            cases.push(case(
                &format!("{}-{i}", tag("argv-literal", uses_argv)),
                CaseOrigin::Corpus,
                &[lit.as_str()],
                b"",
            ));
        }
        if literals.len() > 1 {
            let all: Vec<&str> = literals.iter().map(String::as_str).collect();
            cases.push(case(
                &tag("argv-all-literals", uses_argv),
                CaseOrigin::Corpus,
                &all,
                b"",
            ));
        }
        cases.push(case(
            &tag("argv-flag", uses_argv),
            CaseOrigin::Corpus,
            &["--help"],
            b"",
        ));
        if uses_argv {
            cases.push(case("argv-empty-arg", CaseOrigin::Corpus, &[""], b""));
            let long = "a".repeat(4096);
            cases.push(case("argv-long", CaseOrigin::Corpus, &[long.as_str()], b""));
        }
        let joined = literals.join("\n");
        cases.push(ProgramCase {
            name: tag("stdin-literals", uses_stdin),
            origin: CaseOrigin::Corpus,
            argv: Vec::new(),
            stdin: format!("{joined}\n").into_bytes(),
        });
        for (i, lit) in literals.iter().enumerate().take(4) {
            cases.push(ProgramCase {
                name: format!("{}-{i}", tag("stdin-line", uses_stdin)),
                origin: CaseOrigin::Corpus,
                argv: Vec::new(),
                stdin: lit.clone().into_bytes(),
            });
        }
        if uses_stdin {
            cases.push(case(
                "stdin-binary",
                CaseOrigin::Corpus,
                &[],
                &[0, 255, 10, 0],
            ));
            cases.push(ProgramCase {
                name: "stdin-large".into(),
                origin: CaseOrigin::Corpus,
                argv: Vec::new(),
                stdin: b"0123456789abcdef\n".repeat(4096),
            });
        }
    }
    let mut rng = Rng::new(seed.seed ^ 0x5052_4f47_5241_4d00);
    for i in 0..seed.generated {
        cases.push(generated_case(&mut rng, i));
    }
    for u in seed.user {
        cases.push(ProgramCase {
            name: u.name.clone(),
            origin: CaseOrigin::User,
            argv: u.argv.clone(),
            stdin: u.stdin.clone().unwrap_or_default().into_bytes(),
        });
    }
    let mut seen: Vec<(Vec<String>, Vec<u8>)> = Vec::new();
    cases.retain(|c| {
        let key = (c.argv.clone(), c.stdin.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
    cases.truncate(MAX_CASES);
    cases
}

fn random_text(rng: &mut Rng, max: u64) -> String {
    const ALPHABET: &[u8] = b"abcXYZ019 +-*/%().,:_=<>!?\t";
    let n = rng.below(max + 1);
    (0..n)
        .map(|_| ALPHABET[rng.below(ALPHABET.len() as u64) as usize] as char)
        .collect()
}

fn generated_case(rng: &mut Rng, i: usize) -> ProgramCase {
    let argc = rng.below(4);
    let argv: Vec<String> = (0..argc)
        .map(|_| {
            if rng.chance(1, 8) {
                String::new()
            } else {
                random_text(rng, 24)
            }
        })
        .filter(|a| !a.contains('\0'))
        .collect();
    let stdin = match rng.below(8) {
        0 | 1 => Vec::new(),
        2..=4 => format!("{}\n", random_text(rng, 40)).into_bytes(),
        5 | 6 => (0..rng.below(300)).map(|_| rng.next_u64() as u8).collect(),
        _ => (0..70_000u32).map(|n| b'a' + (n % 26) as u8).collect(),
    };
    ProgramCase {
        name: format!("gen-{i}"),
        origin: CaseOrigin::Generated,
        argv,
        stdin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_skip_format_strings_includes_and_characters() {
        let src = r#"
#include <stdio.h>
/* "not a literal"? it is: block comments are not parsed */
static const char *const cases[] = { "1 + 2", "(3)", "x" };
int f(void) { printf("%d\n", 1); return 'a' == '"'; }
const char *g(void) { return "tab\there"; }
"#;
        let l = string_literals(src, 10);
        assert!(l.contains(&"1 + 2".to_string()), "{l:?}");
        assert!(l.contains(&"(3)".to_string()));
        assert!(l.contains(&"tab\there".to_string()));
        assert!(!l.iter().any(|s| s.contains('%') || s.contains("stdio")));
        assert_eq!(string_literals(src, 2).len(), 2);
    }

    #[test]
    fn a_program_that_ignores_its_input_still_gets_cases() {
        let src = "int main(void) { puts(\"hi\"); return 0; }";
        let cases = derive_cases(&CaseSeed {
            source: Some(src),
            seed: 1,
            generated: 3,
            user: &[],
        });
        assert_eq!(cases[0].name, "baseline");
        assert!(cases.iter().any(|c| c.name.ends_with("-ignored")));
        assert_eq!(
            cases
                .iter()
                .filter(|c| c.origin == CaseOrigin::Generated)
                .count(),
            3
        );
    }

    #[test]
    fn a_program_that_reads_argv_and_stdin_gets_shaped_cases() {
        let src =
            "int main(int argc, char **argv) { char b[8]; fgets(b, 8, stdin); return \"go\"[0]; }";
        let cases = derive_cases(&CaseSeed {
            source: Some(src),
            seed: 1,
            generated: 0,
            user: &[],
        });
        let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"argv-empty-arg"), "{names:?}");
        assert!(names.contains(&"stdin-binary"));
        assert!(names.contains(&"stdin-large"));
        assert!(!names.iter().any(|n| n.ends_with("-ignored")), "{names:?}");
    }

    #[test]
    fn generation_is_deterministic_and_user_cases_come_last() {
        let user = [ProgramCaseSpec {
            name: "mine".into(),
            argv: vec!["x".into()],
            stdin: Some("y".into()),
        }];
        let seed = CaseSeed {
            source: None,
            seed: 7,
            generated: 5,
            user: &user,
        };
        let a = derive_cases(&seed);
        assert_eq!(a, derive_cases(&seed));
        assert_eq!(a.last().map(|c| c.name.as_str()), Some("mine"));
        assert_eq!(a.last().map(|c| c.origin), Some(CaseOrigin::User));
        let b = derive_cases(&CaseSeed { seed: 8, ..seed });
        assert_ne!(a, b);
    }

    #[test]
    fn the_files_a_run_leaves_are_compared_by_content() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("prog"), b"exe").expect("prog");
        std::fs::write(dir.path().join("mix.wav"), vec![1u8; 9000]).expect("wav");
        std::fs::create_dir(dir.path().join("out")).expect("sub");
        std::fs::write(dir.path().join("out/log.txt"), b"ok").expect("log");
        let files = written_files(dir.path(), "prog");
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["mix.wav", "out/log.txt"]);
        let mut changed = vec![1u8; 9000];
        changed[5000] = 2;
        let other = vec![
            WrittenFile::of("mix.wav".into(), &changed),
            WrittenFile::of("extra.bin".into(), b"x"),
        ];
        let d = file_differences(&files, &other);
        assert_eq!(d.len(), 3, "{d:?}");
        assert!(
            d[0].contains("mix.wav") && d[0].contains("bytes 4096 to 8191"),
            "{d:?}"
        );
        assert!(
            d[1].contains("out/log.txt") && d[1].contains("did not"),
            "{d:?}"
        );
        assert!(
            d[2].contains("extra.bin") && d[2].contains("the rewrite wrote it"),
            "{d:?}"
        );
        assert!(file_differences(&files, &files).is_empty());
    }

    #[test]
    fn differences_name_the_stream_and_the_first_byte() {
        let ok = Outcome {
            exit: Exit::Code(0),
            stdout: b"abc\n".to_vec(),
            stderr: Vec::new(),
            files: Vec::new(),
        };
        assert!(compare(&ok, &ok.clone()).is_empty());
        let bad = Outcome {
            exit: Exit::Signal(11),
            stdout: b"abd\n".to_vec(),
            stderr: b"oops".to_vec(),
            files: Vec::new(),
        };
        let d = compare(&ok, &bad);
        assert_eq!(d.len(), 3, "{d:?}");
        assert!(d[0].contains("exit 0") && d[0].contains("signal 11"));
        assert!(d[1].starts_with("stdout:") && d[1].contains("byte 2"));
        assert!(d[2].starts_with("stderr:"));
    }

    #[test]
    fn corpus_source_is_found_next_to_the_binary_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let (name, text) =
            corpus_source(&root.join("bin/stripped_calc-O0-stripped")).expect("source");
        assert_eq!(name, "stripped_calc.c");
        assert!(text.contains("parse_expr"));
        assert!(corpus_source(&root.join("bin/nonexistent-O0")).is_none());
    }
}
