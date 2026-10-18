#![cfg(unix)]
//! Expected outputs of the corpus programs (`corpus/expected/<program>.json`): for every C
//! program of the cross-architecture sets, the standard cases of the program oracle
//! ([`derive_cases`] from the program's source, no generated cases) with the exit status, stdout
//! and stderr of the x86-64 build. Emulator tests of the arm32, aarch64, riscv64 and riscv32
//! builds compare against these.
//!
//! The test checks that the stored cases are still the ones [`derive_cases`] gives and, on x86-64
//! Linux, that the x86-64 builds (`-O0` and `-O2`) still produce the stored results.
//! `KRAKEN_CORPUS_BLESS=1` rewrites the files from the `-O0` build.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kraken_rewrite::process::{CaseSeed, ProgramCase, derive_cases};
use serde_json::{Value, json};

/// The programs built for every cross-architecture set.
const PROGRAMS: &[&str] = &["pie_list", "static_strops", "stripped_calc", "switch_vm"];
/// The fields of a stored case that hold the result of the run.
const RESULT_KEYS: &[&str] = &[
    "exit",
    "signal",
    "stdout",
    "stderr",
    "stdout_hex",
    "stderr_hex",
];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn cases(program: &str) -> Vec<ProgramCase> {
    let src = std::fs::read_to_string(corpus().join(format!("src/{program}.c"))).expect("source");
    derive_cases(&CaseSeed {
        source: Some(&src),
        seed: 0,
        generated: 0,
        user: &[],
    })
}

fn bytes_field(name: &str, data: &[u8]) -> (String, Value) {
    match std::str::from_utf8(data) {
        Ok(s) => (name.to_string(), json!(s)),
        Err(_) => {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            (format!("{name}_hex"), json!(hex))
        }
    }
}

/// Runs `exe` on `case` the way the program oracle starts a program: `argv[0]` is `prog`, the
/// environment is empty, the working directory is a fresh private one.
fn run(exe: &Path, case: &ProgramCase) -> Value {
    use std::io::Write;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(exe)
        .arg0("prog")
        .args(&case.argv)
        .env_clear()
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    // A program that does not read its input may exit before taking all of it.
    let _ = stdin.write_all(&case.stdin);
    drop(stdin);
    let out = child.wait_with_output().expect("wait");
    let mut v = serde_json::Map::new();
    match out.status.code() {
        Some(c) => v.insert("exit".into(), json!(c)),
        None => v.insert("signal".into(), json!(out.status.signal())),
    };
    let (k, s) = bytes_field("stdout", &out.stdout);
    v.insert(k, s);
    let (k, s) = bytes_field("stderr", &out.stderr);
    v.insert(k, s);
    Value::Object(v)
}

fn case_input(case: &ProgramCase) -> Value {
    let mut v = serde_json::Map::new();
    v.insert("name".into(), json!(case.name));
    v.insert("origin".into(), json!(case.origin.as_str()));
    v.insert("argv".into(), json!(case.argv));
    let (k, s) = bytes_field("stdin", &case.stdin);
    v.insert(k, s);
    Value::Object(v)
}

fn sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).expect("read binary");
    Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn document(program: &str) -> Value {
    let reference = format!("bin/{program}-O0");
    let exe = corpus().join(&reference);
    let cases: Vec<Value> = cases(program)
        .iter()
        .map(|c| {
            let mut v = case_input(c);
            let result = run(&exe, c);
            let (Value::Object(m), Value::Object(r)) = (&mut v, result) else {
                unreachable!("objects")
            };
            m.extend(r);
            v
        })
        .collect();
    json!({
        "program": program,
        "source_file": format!("src/{program}.c"),
        "reference": reference,
        "reference_sha256": sha256(&exe),
        "cases": cases,
    })
}

fn expected_path(program: &str) -> PathBuf {
    corpus().join(format!("expected/{program}.json"))
}

fn stored(program: &str) -> Value {
    let text = std::fs::read_to_string(expected_path(program))
        .unwrap_or_else(|e| panic!("{program}: {e}; bless with KRAKEN_CORPUS_BLESS=1"));
    serde_json::from_str(&text).expect("expected json")
}

#[test]
fn stored_cases_are_the_derived_cases() {
    if std::env::var_os("KRAKEN_CORPUS_BLESS").is_some() {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            panic!("blessing runs the x86-64 corpus builds: needs x86-64 Linux");
        }
        std::fs::create_dir_all(corpus().join("expected")).expect("mkdir");
        for p in PROGRAMS {
            let text = serde_json::to_string_pretty(&document(p)).expect("json") + "\n";
            std::fs::write(expected_path(p), text).expect("write");
        }
    }
    for p in PROGRAMS {
        let doc = stored(p);
        let got: Vec<Value> = doc["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|c| {
                let mut c = c.clone();
                let m = c.as_object_mut().expect("case");
                for k in RESULT_KEYS {
                    m.remove(*k);
                }
                c
            })
            .collect();
        let want: Vec<Value> = cases(p).iter().map(case_input).collect();
        assert_eq!(got, want, "{p}: the derived cases changed; bless again");
        assert_eq!(
            doc["reference_sha256"].as_str(),
            Some(sha256(&corpus().join(format!("bin/{p}-O0"))).as_str()),
            "{p}: the reference binary changed"
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn x86_64_builds_produce_the_stored_results() {
    if std::env::var_os("KRAKEN_CORPUS_BLESS").is_some() {
        return; // the other test is rewriting the files from these runs
    }
    for p in PROGRAMS {
        let doc = stored(p);
        let stored_cases = doc["cases"].as_array().expect("cases");
        for opt in ["O0", "O2"] {
            let exe = corpus().join(format!("bin/{p}-{opt}"));
            for (case, want) in cases(p).iter().zip(stored_cases) {
                let got = run(&exe, case);
                for k in RESULT_KEYS {
                    assert_eq!(
                        got.get(k),
                        want.get(k),
                        "{p}-{opt} case {}: {k} differs",
                        case.name
                    );
                }
            }
        }
    }
}
