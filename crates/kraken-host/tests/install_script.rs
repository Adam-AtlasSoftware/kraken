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

#[test]
fn the_embedded_key_is_the_one_the_updater_trusts() {
    let text = std::fs::read_to_string(repo_file("scripts/install.sh")).unwrap();
    let line = format!(
        "KRAKEN_MINISIGN_PUBKEY=\"{}\"",
        kraken_host::update::verify::RELEASE_PUBLIC_KEY
    );
    assert!(
        text.contains(&line),
        "install.sh must embed the release key"
    );
    // The install always requires a signature now.
    assert!(text.contains("\"$KRAKEN_MINISIGN_PUBKEY\" 1\n"));
}

#[test]
fn a_signature_for_another_release_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    std::fs::write(
        d.join("sig"),
        "untrusted comment: x\nAAAA\ntrusted comment: kraken v0.4.0 SHA256SUMS\nBBBB\n",
    )
    .unwrap();
    assert!(run(d, "check_trusted_comment sig v0.4.0").0);
    let (ok, err) = run(d, "check_trusted_comment sig v0.5.0");
    assert!(!ok && err.contains("not for v0.5.0"), "{err}");
}

#[test]
fn the_receipt_names_the_script_install() {
    let t = tempfile::tempdir().unwrap();
    let prefix = t.path().join("we\"ird prefix");
    let (ok, err) = run(
        t.path(),
        &format!("write_receipt '{}' 0.4.0", prefix.display()),
    );
    assert!(ok, "{err}");
    let text = std::fs::read_to_string(prefix.join("share/kraken/install.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["method"], "script");
    assert_eq!(v["version"], "0.4.0");
    assert_eq!(v["prefix"], prefix.display().to_string());
    // The updater reads it as a script install.
    let exe = prefix.join("bin/kraken");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, "").unwrap();
    let kind = kraken_host::update::install::detect(
        &exe,
        "release",
        &kraken_host::update::install::SystemProbe,
    );
    assert_eq!(kind.id(), "script");
}

// A throwaway test key and a prehashed signature of "abc  kraken-0.4.0-x.tar.gz\n" made with it
// (rsign), with the trusted comment the release workflow writes. Not the release key.
const TEST_PUBKEY: &str = "RWQAS8IwejLSSdYnOjMLzWIIlo7D4mZpWCGhI8FfQM2T0BAdtAanBEdU";
const TEST_SIG: &str = "untrusted comment: signature from rsign secret key
RUQAS8IwejLSSSs9SJx33YS7LxTb/KccbBR4S0D0kv8ubDC/lccmXFR1PxFJ+0LMx3UgkXYRlqJUuECUErqMgtT9SqtIbqA7zQM=
trusted comment: kraken v0.4.0 SHA256SUMS
o2aqTOjCcoDWQJ4P2Qa+fqR5dDH5xai0YhnSUsPCs8eYp8rHPYAVdTrIrUzY+9W/biJRv1gQDCucu3VN+abRCw==
";

#[test]
fn openssl_verifies_minisign_signatures_without_minisign() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    if !run(d, "openssl_can_verify").0 {
        eprintln!("skipped: no OpenSSL 3 with BLAKE2b");
        return;
    }
    std::fs::write(d.join("SUMS"), "abc  kraken-0.4.0-x.tar.gz\n").unwrap();
    std::fs::write(d.join("SUMS.minisig"), TEST_SIG).unwrap();
    let call = |file: &str, sig: &str, key: &str| {
        run(d, &format!("verify_with_openssl {file} {sig} {key}")).0
    };
    assert!(call("SUMS", "SUMS.minisig", TEST_PUBKEY));
    // A changed list, a changed trusted comment and another key are all refused.
    std::fs::write(d.join("OTHER"), "abd  kraken-0.4.0-x.tar.gz\n").unwrap();
    assert!(!call("OTHER", "SUMS.minisig", TEST_PUBKEY));
    std::fs::write(d.join("bad.minisig"), TEST_SIG.replace("v0.4.0", "v0.5.0")).unwrap();
    assert!(!call("SUMS", "bad.minisig", TEST_PUBKEY));
    assert!(!call(
        "SUMS",
        "SUMS.minisig",
        "RWQcuc9uv/vL6fNGCFoY+ea132bmfUHhfczZGY/UgdNbC08hjU6DYmln"
    ));
}

#[test]
fn only_the_pinned_unsigned_releases_skip_the_signature() {
    let t = tempfile::tempdir().unwrap();
    for tag in ["v0.1.0", "v0.2.0", "v0.3.0"] {
        let (ok, _) = run(t.path(), &format!("unsigned_release_sums {tag}"));
        assert!(ok, "{tag} should be pinned");
    }
    for tag in ["v0.3.1", "v0.4.0", "v0.3.0-rc1", "v1.0.0"] {
        assert!(!run(t.path(), &format!("unsigned_release_sums {tag}")).0, "{tag}");
    }
}
