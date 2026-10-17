//! Regression tests for the checks in `scripts/install.sh` (security review M9) and the curl
//! flags of both install scripts (L8). Unix only; needs `bash` and `tar`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_file(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Runs `body` in bash after sourcing install.sh's functions; returns (success, stderr).
fn run(dir: &Path, body: &str) -> (bool, String) {
    let script = repo_file("scripts/install.sh");
    let out = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "set -euo pipefail; KRAKEN_INSTALL_SOURCE_ONLY=1 source '{}'; {body}",
            script.display()
        ))
        .current_dir(dir)
        .env_remove("KRAKEN_REQUIRE_SIGNATURE")
        .output()
        .expect("bash");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn make_tar(dir: &Path, name: &str, script: &str) {
    let st = Command::new("bash")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(st.success(), "building {name}");
}

#[test]
fn archives_with_links_or_unsafe_names_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    make_tar(
        d,
        "good",
        "mkdir -p p/bin && echo x > p/bin/kraken && tar -czf good.tgz p",
    );
    make_tar(
        d,
        "sym",
        "mkdir -p q && ln -s /etc/passwd q/evil && tar -czf sym.tgz q",
    );
    make_tar(
        d,
        "hard",
        "mkdir -p r && echo x > r/a && ln r/a r/b && tar -czf hard.tgz r",
    );
    make_tar(
        d,
        "dots",
        // GNU tar renames with --transform, BSD tar (macOS) with -s.
        "mkdir -p s && echo x > s/a && if tar --version 2>/dev/null | grep -q GNU; then \
         tar -czf dots.tgz --transform 's|^s/a|s/../a|' s; else tar -czf dots.tgz -s '|^s/a|s/../a|' s; fi",
    );
    assert!(run(d, "check_archive_entries good.tgz").0);
    let (ok, err) = run(d, "check_archive_entries sym.tgz");
    assert!(!ok && err.contains("links"), "{err}");
    let (ok, err) = run(d, "check_archive_entries hard.tgz");
    assert!(!ok && err.contains("links"), "{err}");
    let (ok, err) = run(d, "check_archive_entries dots.tgz");
    assert!(!ok && err.contains("unsafe paths"), "{err}");
}

#[test]
fn signature_check_is_mandatory_once_a_key_is_embedded() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    std::fs::write(d.join("SHA256SUMS"), "x\n").unwrap();
    std::fs::write(d.join("SHA256SUMS.minisig"), "sig\n").unwrap();
    // No key yet: skipped with a notice, unless a signature is required.
    let (ok, err) = run(d, "verify_signature SHA256SUMS '' '' 0");
    assert!(ok && err.contains("no release signing key"), "{err}");
    assert!(!run(d, "verify_signature SHA256SUMS '' '' 1").0);
    // Key embedded but the release has no signature file.
    let (ok, err) = run(d, "verify_signature SHA256SUMS '' KEY 0");
    assert!(!ok && err.contains("no SHA256SUMS.minisig"), "{err}");
    // A stub minisign that rejects, then one that accepts.
    std::fs::create_dir(d.join("bin")).unwrap();
    let stub = |code: i32| {
        let p = d.join("bin/minisign");
        std::fs::write(&p, format!("#!/bin/sh\nexit {code}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(1);
    let call = "PATH=\"$PWD/bin:$PATH\" verify_signature SHA256SUMS SHA256SUMS.minisig KEY 0";
    let (ok, err) = run(d, call);
    assert!(!ok && err.contains("signature check failed"), "{err}");
    stub(0);
    assert!(run(d, call).0);
}

#[test]
fn install_scripts_restrict_curl_to_https() {
    for rel in ["scripts/install.sh", "dotnet/install-sdk.sh"] {
        let text = std::fs::read_to_string(repo_file(rel)).unwrap();
        let mut seen = 0;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with('#') || !t.contains("curl ") && !t.starts_with("curl") {
                continue;
            }
            if t.contains("command -v") || t.starts_with("need ") {
                continue;
            }
            seen += 1;
            assert!(
                line.contains("--proto '=https'"),
                "{rel}:{}: curl without --proto '=https'",
                i + 1
            );
        }
        assert!(seen > 0, "{rel}: no curl invocation found");
    }
}
