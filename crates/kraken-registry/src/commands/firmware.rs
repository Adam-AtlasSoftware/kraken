//! `firmware_identify`: what is inside a firmware or ROM image, before a project exists.

use std::io::Read;
use std::path::Path;

use async_trait::async_trait;
use kraken_formats::scan::{self, ENTROPY_BLOCK};
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{Session, blocking};
use crate::trust;

/// Most bytes read from the image; a larger file is scanned over its first part only.
pub const MAX_SCAN_BYTES: u64 = 64 << 20;
/// Longest entropy map returned: blocks are merged (averaged) beyond this many.
const MAX_MAP_CHARS: usize = 4096;

/// Arguments of `firmware_identify`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareIdentifyArgs {
    /// Path of the firmware or ROM image.
    pub path: String,
}

/// A structure found inside the image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareSignature {
    /// File offset of the structure's first byte.
    pub offset: Hex64,
    /// `gzip`, `xz`, `lzma`, `bzip2`, `zstd`, `squashfs`, `cramfs`, `uimage`, `fit`, `dtb`,
    /// `elf`, `pe`, `ihex` or `uefi_fv`.
    pub kind: String,
    /// The structure in plain words.
    pub name: String,
    /// What its header says; empty when nothing more.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// The structure's own length when its header says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// A run of the image with one entropy character.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareRegion {
    pub offset: Hex64,
    pub length: u64,
    /// `padding`, `code_or_data` or `compressed_or_encrypted`.
    pub kind: String,
}

/// What `firmware_identify` found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareIdentifyOut {
    /// The absolute path that was read. Chosen by whoever supplied the file, so untrusted.
    pub path: Untrusted<String>,
    /// File size in bytes.
    pub size: u64,
    /// Bytes scanned (the first part of a file over 64 MiB).
    pub scanned: u64,
    /// True when `scanned` is less than `size`, or more signatures were found than are listed.
    pub truncated: bool,
    /// Embedded structures, in offset order.
    pub signatures: Vec<FirmwareSignature>,
    /// Entropy runs: padding, code or data, compressed or encrypted.
    pub regions: Vec<FirmwareRegion>,
    /// One character per block: the Shannon entropy in bits per byte, rounded down (`0` to
    /// `8`). Compressed and encrypted data reads 7 or 8, code 4 to 6, padding 0.
    pub entropy: String,
    /// Bytes each `entropy` character stands for (4096 unless the image is over 16 MiB).
    pub entropy_block: u64,
    /// One sentence: what the image looks like.
    pub summary: String,
}

fn summarise(signatures: &[FirmwareSignature], regions: &[FirmwareRegion], size: u64) -> String {
    let mut kinds: Vec<(&str, usize)> = Vec::new();
    for s in signatures {
        match kinds.iter_mut().find(|(k, _)| *k == s.name) {
            Some((_, n)) => *n += 1,
            None => kinds.push((&s.name, 1)),
        }
    }
    let packed: u64 = regions
        .iter()
        .filter(|r| r.kind == "compressed_or_encrypted")
        .map(|r| r.length)
        .sum();
    let pct = (packed * 100).checked_div(size).unwrap_or(0);
    let found = if kinds.is_empty() {
        "no known container signatures".to_string()
    } else {
        kinds
            .iter()
            .map(|(k, n)| {
                if *n > 1 {
                    format!("{k} x{n}")
                } else {
                    (*k).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("{found}; {pct}% of the image is compressed or encrypted")
}

/// Scans the file at `path`; no decompression, at most [`MAX_SCAN_BYTES`] read.
pub fn identify_firmware(path: &Path) -> Result<FirmwareIdentifyOut, ProtoError> {
    let io = |e: std::io::Error| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("{}: {e}", path.display()),
        )
    };
    // before opening: opening a FIFO for reading blocks until a writer comes, for ever
    trust::ensure_regular_file(path)?;
    let file = std::fs::File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("{} is not a file", path.display()),
        ));
    }
    let size = meta.len();
    let mut data = Vec::new();
    file.take(MAX_SCAN_BYTES)
        .read_to_end(&mut data)
        .map_err(io)?;
    let found = scan::scan(&data);

    let signatures: Vec<FirmwareSignature> = found
        .signatures
        .iter()
        .map(|s| FirmwareSignature {
            offset: Hex64(s.offset),
            kind: s.kind.to_string(),
            name: s.name.to_string(),
            detail: s.detail.clone(),
            size: s.size,
        })
        .collect();
    let regions: Vec<FirmwareRegion> = found
        .regions
        .iter()
        .map(|r| FirmwareRegion {
            offset: Hex64(r.offset),
            length: r.length,
            kind: r.kind.to_string(),
        })
        .collect();

    let merge = found.entropy.len().div_ceil(MAX_MAP_CHARS).max(1);
    let entropy: String = found
        .entropy
        .chunks(merge)
        .map(|c| {
            let avg = c.iter().map(|&v| usize::from(v)).sum::<usize>() / c.len();
            char::from(b'0' + (avg / 10).min(8) as u8)
        })
        .collect();
    let summary = summarise(&signatures, &regions, data.len() as u64);
    Ok(FirmwareIdentifyOut {
        path: Untrusted(path.to_string_lossy().into_owned()),
        size,
        scanned: data.len() as u64,
        truncated: (data.len() as u64) < size || found.truncated,
        signatures,
        regions,
        entropy,
        entropy_block: (ENTROPY_BLOCK * merge) as u64,
        summary,
    })
}

/// The command.
pub struct FirmwareIdentify;

#[async_trait]
impl Command for FirmwareIdentify {
    type Args = FirmwareIdentifyArgs;
    type Output = FirmwareIdentifyOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "firmware_identify",
            "Find the structures inside a firmware or ROM image and map where it is compressed",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Scans a flash dump, ROM or firmware update file for embedded structures (gzip, xz, \
             LZMA, bzip2, zstd, SquashFS, cramfs, U-Boot uImage, FIT and device-tree blobs, ELF, \
             PE, Intel HEX, UEFI firmware volumes) and reports each with its file offset and the \
             length its header gives, plus an entropy map in 4 KiB blocks that shows padding, \
             code and compressed or encrypted regions. Nothing is decompressed or run. Needs no \
             open project. Agents may not scan files in hidden folders of the home directory.\n\
             Example: firmware_identify {\"path\": \"/home/me/dumps/router.bin\"}",
        )
        .details(
            "Header checks only, so a hit is a candidate (a magic number plus the plausibility \
             checks the format allows); at most 1000 signatures are listed and the first 64 MiB \
             of the file are read (`truncated` says when either limit applied). `entropy` has \
             one character per block, the entropy in bits per byte rounded down; for images over \
             16 MiB blocks are averaged and `entropy_block` gives the bytes per character. To \
             open an image as code, use `binary_probe` for suggestions and `project_create` with \
             `loader: raw`.",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        ctx: &CallContext,
        args: FirmwareIdentifyArgs,
    ) -> Result<FirmwareIdentifyOut, ProtoError> {
        let path = if ctx.needs_user_approval() {
            trust::check_agent_path("path", Path::new(&args.path))?
        } else {
            Path::new(&args.path).to_path_buf()
        };
        blocking(move || identify_firmware(&path)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dense_image_maps_to_high_digits_and_a_padded_one_to_zero() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("img.bin");
        let mut d = vec![0xffu8; 4096];
        d.extend((0..8192u64).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8));
        std::fs::write(&p, d).expect("write");
        let out = identify_firmware(&p).expect("scan");
        assert_eq!(out.entropy.len(), 3);
        assert!(out.entropy.starts_with('0'), "{}", out.entropy);
        assert_eq!(out.size, 12288);
        assert!(!out.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_is_refused_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("fifo");
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).expect("path");
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(identify_firmware(&p).map(|_| ()));
        });
        let e = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("identify_firmware blocked on the pipe")
            .expect_err("a pipe is not an image");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }
}
