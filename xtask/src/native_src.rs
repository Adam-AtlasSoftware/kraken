//! `cargo xtask native-src`: fetches the pinned Ghidra source tarball, checks its SHA-256 and
//! extracts only the decompiler C++ sources (plus the bundled zlib, Ghidra's LICENSE and NOTICE
//! and the zlib license) for `engine-native-sys`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{Result, cache_dir};

/// Ghidra release tag the native engine builds from.
pub const TAG: &str = "Ghidra_12.1.4_build";
/// GitHub's source archive for [`TAG`].
pub const URL: &str =
    "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_12.1.4_build.tar.gz";
/// SHA-256 of the archive at [`URL`], recorded 2026-10-16.
pub const SHA256: &str = "2a858300c350f05ae2e729dff86b4f584d0b9a6b398879c55025574e67696cec";

/// Top-level directory of the archive.
pub const PREFIX: &str = "ghidra-Ghidra_12.1.4_build";
const DECOMPILE: &str = "Ghidra/Features/Decompiler/src/decompile";

/// Where the sources are extracted: `~/.cache/kraken-dev/ghidra-src/<TAG>`.
pub fn source_root() -> Result<PathBuf> {
    Ok(cache_dir()
        .ok_or("HOME is not set")?
        .join("ghidra-src")
        .join(TAG))
}

pub fn native_src() -> Result<()> {
    let root = cache_dir().ok_or("HOME is not set")?.join("ghidra-src");
    let archive = fetch_archive()?;
    let dest = root.join(TAG);
    let staging = root.join(format!("{TAG}.staging"));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(staging.join("decompile"))
        .map_err(|e| format!("cannot create {}: {e}", staging.display()))?;
    for sub in ["cpp", "zlib"] {
        extract(
            &archive,
            &staging.join("decompile"),
            &format!("{PREFIX}/{DECOMPILE}/{sub}"),
            6,
        )?;
    }
    for member in ["LICENSE", "NOTICE", "licenses/zlib_License.txt"] {
        extract(&archive, &staging, &format!("{PREFIX}/{member}"), 1)?;
    }
    fs::write(
        staging.join("SOURCE.txt"),
        format!(
            "Extracted by `cargo xtask native-src` from\n{URL}\nsha256 {SHA256}\nmembers: \
             {DECOMPILE}/cpp, {DECOMPILE}/zlib, LICENSE, NOTICE (Apache-2.0; zlib under its own \
             license, licenses/zlib_License.txt)\n"
        ),
    )
    .map_err(|e| format!("cannot write SOURCE.txt: {e}"))?;
    if !staging.join("decompile/cpp/sleigh.cc").is_file() {
        return Err("the archive did not contain the decompiler sources".into());
    }
    let _ = fs::remove_dir_all(&dest);
    fs::rename(&staging, &dest).map_err(|e| format!("cannot move into place: {e}"))?;
    println!(
        "native-src: sources in {} (KRAKEN_GHIDRA_SRC={})",
        dest.display(),
        dest.join("decompile").display()
    );
    Ok(())
}

/// The pinned archive in `~/.cache/kraken-dev/ghidra-src/dl`, downloaded first if it is missing
/// or does not match [`SHA256`].
pub fn fetch_archive() -> Result<PathBuf> {
    let archive = archive_path()?;
    let dl = archive.parent().ok_or("bad archive path")?.to_path_buf();
    fs::create_dir_all(&dl).map_err(|e| format!("cannot create {}: {e}", dl.display()))?;

    if !archive.is_file() || sha256_file(&archive)? != SHA256 {
        let part = dl.join(format!("{TAG}.tar.gz.part"));
        println!("native-src: downloading {URL}");
        let status = Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
            ])
            .arg("--output")
            .arg(&part)
            .arg(URL)
            .status()
            .map_err(|e| format!("cannot run curl: {e}"))?;
        if !status.success() {
            return Err(format!("download failed: {status}"));
        }
        let got = sha256_file(&part)?;
        if got != SHA256 {
            let _ = fs::remove_file(&part);
            return Err(format!(
                "SHA-256 mismatch for {URL}: expected {SHA256}, got {got} (GitHub may have \
                 regenerated the archive; verify the new one before updating the pin in \
                 xtask/src/native_src.rs)"
            ));
        }
        fs::rename(&part, &archive).map_err(|e| format!("cannot move archive: {e}"))?;
    }
    println!("native-src: {} sha256 {SHA256} ok", archive.display());
    Ok(archive)
}

/// Where the pinned archive is kept: `~/.cache/kraken-dev/ghidra-src/dl/<TAG>.tar.gz`.
pub fn archive_path() -> Result<PathBuf> {
    Ok(cache_dir()
        .ok_or("HOME is not set")?
        .join("ghidra-src/dl")
        .join(format!("{TAG}.tar.gz")))
}

pub fn extract(archive: &Path, into: &Path, member: &str, strip: u32) -> Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .arg(format!("--strip-components={strip}"))
        .arg("--no-same-owner")
        .arg(member)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("tar failed extracting {member}: {status}"))
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
