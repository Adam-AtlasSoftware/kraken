//! ARM, AArch64 and RISC-V through `llvm-mc`, run in a confined child (Landlock read-only view,
//! no network, scrubbed environment, a deadline). Not found on `PATH`: a plain error that says
//! what to install.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use kraken_confine::{Confinement, ReadScope, confine, run_captured_with_input, scratch_dir};
use kraken_proto::{ErrorCode, ProtoError};

const DEADLINE: Duration = Duration::from_secs(5);

/// The `llvm-mc` on `PATH` (`llvm-mc`, else the newest `llvm-mc-<n>`).
pub fn find() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let mut versioned: Vec<(u32, PathBuf)> = Vec::new();
    for dir in std::env::split_paths(&path) {
        let plain = dir.join("llvm-mc");
        if plain.is_file() {
            return Some(plain);
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if let Some(v) = n
                .strip_prefix("llvm-mc-")
                .and_then(|v| v.parse::<u32>().ok())
            {
                versioned.push((v, e.path()));
            }
        }
    }
    versioned.into_iter().max().map(|(_, p)| p)
}

/// The processor name `llvm-mc` takes and the NOP of the language, or `None` for a language
/// this backend does not cover.
pub struct Target {
    pub triple: &'static str,
    pub attrs: &'static str,
    pub nop: &'static [u8],
}

pub fn target(language: &str, thumb: bool) -> Option<Target> {
    Some(if language.starts_with("AARCH64:") {
        Target {
            triple: "aarch64-linux-gnu",
            attrs: "",
            nop: &[0x1f, 0x20, 0x03, 0xd5],
        }
    } else if language.starts_with("ARM:") && thumb {
        Target {
            triple: "thumbv8-linux-gnueabihf",
            attrs: "",
            nop: &[0x00, 0xbf],
        }
    } else if language.starts_with("ARM:") {
        Target {
            triple: "armv8-linux-gnueabihf",
            attrs: "",
            nop: &[0x00, 0xf0, 0x20, 0xe3],
        }
    } else if language.starts_with("RISCV:LE:64") {
        Target {
            triple: "riscv64-linux-gnu",
            attrs: "+m,+a,+f,+d,+c",
            nop: &[0x13, 0x00, 0x00, 0x00],
        }
    } else if language.starts_with("RISCV:LE:32") {
        Target {
            triple: "riscv32-linux-gnu",
            attrs: "+m,+a,+f,+d,+c",
            nop: &[0x13, 0x00, 0x00, 0x00],
        }
    } else {
        return None;
    })
}

fn unsupported(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, m)
}

/// The encoding of each instruction of `text` (`;` or newlines between them), in order.
pub fn assemble(exe: &PathBuf, t: &Target, text: &str) -> Result<Vec<Vec<u8>>, ProtoError> {
    let dir = scratch_dir("kraken-asm")
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
    let mut cmd = Command::new(exe);
    cmd.arg(format!("--triple={}", t.triple))
        .arg("--show-encoding");
    if !t.attrs.is_empty() {
        cmd.arg(format!("--mattr={}", t.attrs));
    }
    confine(
        &mut cmd,
        dir.path(),
        ReadScope::Toolchain,
        &Confinement::default(),
    )
    .map_err(|e| unsupported(format!("llvm-mc cannot run confined here: {e}")))?;
    let src = text.replace(';', "\n") + "\n";
    let out = run_captured_with_input(
        &mut cmd,
        Some(src.into_bytes()),
        DEADLINE,
        1 << 20,
        Duration::from_millis(10),
    )
    .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot run llvm-mc: {e}")))?;
    let Some(status) = out.status else {
        return Err(ProtoError::new(ErrorCode::Timeout, "llvm-mc timed out"));
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !status.success() {
        let why = stderr
            .lines()
            .find(|l| l.contains("error:"))
            .map(|l| l.split("error:").nth(1).unwrap_or(l).trim().to_string())
            .unwrap_or_else(|| stderr.trim().to_string());
        return Err(ProtoError::new(ErrorCode::InvalidArgument, why));
    }
    let mut encodings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(rest) = line.split("encoding: [").nth(1) else {
            continue;
        };
        let inner = rest.split(']').next().unwrap_or("");
        let bytes = inner
            .split(',')
            .map(|b| u8::from_str_radix(b.trim().trim_start_matches("0x"), 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "the instruction has an operand that is not known until link time (a symbol or a label); give a number",
                )
            })?;
        encodings.push(bytes);
    }
    if encodings.is_empty() {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "nothing assembled",
        ));
    }
    Ok(encodings)
}

/// The error when no `llvm-mc` is installed.
pub fn missing(language: &str) -> ProtoError {
    unsupported(format!(
        "assembling {language} needs llvm-mc; install LLVM (package `llvm`, for example `apt install llvm` or `pacman -S llvm`) so that `llvm-mc` is on PATH"
    ))
}
