//! `patch_export_diff` and `patch_import`: patches as files other tools understand.
//!
//! `patch_export_diff` writes the patches that are switched on as an IPS, IPS32, BPS, `.1337`,
//! DIF or JSON file of file-offset changes against the original binary, through the same address
//! to file-offset mapping `patch_export` uses. `patch_import` reads an IPS, IPS32, BPS or JSON
//! file made for the project's binary and stages its changes as patches: a person's become
//! ordinary `SetPatch` entries under one run, an agent's become proposals. The readers are in
//! [`crate::patchformats`] and are bounded: they parse files from strangers.

use std::fs;
use std::path::PathBuf;

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_model::{AuthorKind, Patch, RunId};
use kraken_proto::{ErrorCode, Hex64, ProtoError, hex_bytes, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchfile::{OffsetMap, apply_project_patches, pe_checksum_field};
use crate::patchformats::{self as formats, Files, Format, FormatError, Record, WriteRecord};
use crate::session::{Session, blocking};
use crate::views::MutationStatus;

use super::patch::{MAX_PATCH_BYTES, MAX_PATCH_NOTE, set_patch_vetted};

/// Most patches one import stages; a bigger file is refused so the log stays reviewable.
pub const MAX_IMPORT_PATCHES: usize = 500;

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn format_error(e: FormatError) -> ProtoError {
    let code = match e {
        FormatError::Limit(_) => ErrorCode::InvalidArgument,
        FormatError::Unrepresentable(_) => ErrorCode::Unsupported,
        FormatError::Malformed(_) | FormatError::WrongSource(_) => ErrorCode::InvalidArgument,
    };
    ProtoError::new(code, e.to_string())
}

/// A patch file format, as named in arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PatchFileFormat {
    /// IPS: 3-byte offsets (files up to 16 MiB).
    Ips,
    /// IPS32: 4-byte offsets.
    Ips32,
    /// BPS: a delta with checksums; importing refuses a file it was not made for.
    Bps,
    /// `.1337`: text lines `offset:old->new` (export only).
    #[serde(rename = "1337")]
    X1337,
    /// DIF: IDA's text difference file (export only).
    Dif,
    /// KRAKEN's JSON with offsets, addresses and notes.
    Json,
}

impl From<PatchFileFormat> for Format {
    fn from(f: PatchFileFormat) -> Format {
        match f {
            PatchFileFormat::Ips => Format::Ips,
            PatchFileFormat::Ips32 => Format::Ips32,
            PatchFileFormat::Bps => Format::Bps,
            PatchFileFormat::X1337 => Format::X1337,
            PatchFileFormat::Dif => Format::Dif,
            PatchFileFormat::Json => Format::Json,
        }
    }
}

impl From<Format> for PatchFileFormat {
    fn from(f: Format) -> PatchFileFormat {
        match f {
            Format::Ips => PatchFileFormat::Ips,
            Format::Ips32 => PatchFileFormat::Ips32,
            Format::Bps => PatchFileFormat::Bps,
            Format::X1337 => PatchFileFormat::X1337,
            Format::Dif => PatchFileFormat::Dif,
            Format::Json => PatchFileFormat::Json,
        }
    }
}

fn resolve_path(project: &crate::session::Project, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        project.dir().join(p)
    }
}

// ---- patch_export_diff ------------------------------------------------------------------

/// Arguments of `patch_export_diff`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchExportDiffArgs {
    /// Where to write the patch file. A relative path is resolved against the project directory.
    pub output_path: String,
    /// The format. Absent takes it from the file extension of `output_path` (`.ips`, `.ips32`,
    /// `.bps`, `.1337`, `.dif`, `.json`).
    #[serde(default)]
    pub format: Option<PatchFileFormat>,
    /// Overwrite an existing file at `output_path` (default false).
    #[serde(default)]
    pub overwrite: bool,
    /// Export only the patches of this patch set. Absent exports every patch that is on.
    #[serde(default)]
    pub group: Option<String>,
}

/// Result of `patch_export_diff`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchExportDiffOut {
    /// Absolute path of the file written.
    pub output_path: String,
    /// The format written.
    pub format: PatchFileFormat,
    /// Number of patches in the file.
    pub patches: u32,
    /// Size of the file in bytes.
    pub bytes_written: u64,
    /// SHA-256 of the file, lower-case hex.
    pub sha256: String,
}

/// Writes the patches as a patch file.
pub struct PatchExportDiff;

#[async_trait]
impl Command for PatchExportDiff {
    type Args = PatchExportDiffArgs;
    type Output = PatchExportDiffOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_export_diff",
            "Write the byte patches as an IPS, BPS, JSON or other patch file against the original binary",
            CommandKind::Query,
            Permission::Dangerous,
        )
        .doc(
            "Writes the byte patches that are switched on (all of them, or one patch set) as a \
             patch file other tools can apply to the original binary: `ips`, `ips32`, `bps`, \
             `1337`, `dif` or `json`. Each patch's address is mapped to a file offset the same way \
             `patch_export` does it and the recorded original bytes are checked first. Unlike \
             `patch_export` the result holds only the changes, not the program, so it can be \
             shared. `ips` reaches 16 MiB (use `ips32`, `bps` or `json` for bigger files); `bps` \
             carries the checksum of the original so a wrong file is refused; `json` keeps \
             addresses and notes and can be read back with `patch_import`. Always asks for \
             approval.\n\
             Example: patch_export_diff {\"output_path\": \"fix.ips\"}",
        )
        .details(
            "The format comes from `format`, or from the extension of `output_path`. `1337` and \
             `dif` list one line per changed byte and cannot be imported. With no patches on, \
             the command is refused. A relative `output_path` is taken relative to the project \
             directory.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: PatchExportDiffArgs,
    ) -> Result<PatchExportDiffOut, ProtoError> {
        if args.output_path.trim().is_empty() {
            return Err(invalid("output_path is empty"));
        }
        let format: Format = match args.format {
            Some(f) => f.into(),
            None => std::path::Path::new(&args.output_path)
                .extension()
                .and_then(|e| e.to_str())
                .and_then(Format::from_name)
                .ok_or_else(|| {
                    invalid(
                        "give `format` (ips, ips32, bps, 1337, dif or json) or an output_path \
                         that ends in one of them",
                    )
                })?,
        };
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let out = resolve_path(&project, &args.output_path);
        let group = args.group.clone();
        let patches = project
            .with_store(move |st| {
                if let Some(g) = &group
                    && !st.patch_groups()?.iter().any(|(n, _)| n == g)
                {
                    return Err(invalid(format!("there is no patch set named {g:?}")));
                }
                st.active_patches(group.as_deref())
            })
            .await?;
        let overwrite = args.overwrite;
        let base = project.program().base.0;
        blocking(move || export_diff(&binary, &out, &patches, format, overwrite, base)).await
    }
}

fn export_diff(
    binary: &std::path::Path,
    out: &std::path::Path,
    patches: &[Patch],
    format: Format,
    overwrite: bool,
    engine_base: u64,
) -> Result<PatchExportDiffOut, ProtoError> {
    if patches.is_empty() {
        return Err(invalid(
            "there are no patches switched on to export; stage one with patch_set first",
        ));
    }
    if out.exists() && !overwrite {
        return Err(invalid(format!(
            "{} already exists; pass overwrite to replace it",
            out.display()
        )));
    }
    let (patched, applied) = apply_project_patches(binary, patches, engine_base)?;
    let original = fs::read(binary).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read the project's binary {}: {e}", binary.display()),
        )
    })?;
    let mut records: Vec<WriteRecord> = applied
        .iter()
        .map(|a| {
            let off = a.file_offset as usize;
            let note = patches
                .iter()
                .find(|p| p.address == a.address)
                .map(|p| p.note.clone())
                .unwrap_or_default();
            WriteRecord {
                address: a.address,
                offset: a.file_offset,
                original: original[off..off + a.len].to_vec(),
                replacement: patched[off..off + a.len].to_vec(),
                note,
            }
        })
        .collect();
    // The export recomputes a PE file's checksum; the patch file carries the new value too, or
    // applying it gives a file that fails its own target checksum (BPS) or a stale one.
    if let Some(field) = pe_checksum_field(&original)
        && original[field.clone()] != patched[field.clone()]
        && !records.iter().any(|r| {
            (r.offset as usize) < field.end && r.offset as usize + r.original.len() > field.start
        })
    {
        records.push(WriteRecord {
            address: engine_base.saturating_add(field.start as u64),
            offset: field.start as u64,
            original: original[field.clone()].to_vec(),
            replacement: patched[field].to_vec(),
            note: "PE checksum, recomputed".into(),
        });
    }
    records.sort_by_key(|r| r.offset);
    let name = binary
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let data = formats::write(
        format,
        &Files {
            original: &original,
            patched: &patched,
            name: &name,
        },
        &records,
    )
    .map_err(format_error)?;
    fs::write(out, &data).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("cannot write {}: {e}", out.display()),
        )
    })?;
    Ok(PatchExportDiffOut {
        output_path: out.display().to_string(),
        format: format.into(),
        patches: records.len() as u32,
        bytes_written: data.len() as u64,
        sha256: sha256_hex(&data),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_bytes(&Sha256::digest(bytes))
}

// ---- patch_import -----------------------------------------------------------------------

/// Arguments of `patch_import`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchImportArgs {
    /// The patch file to read. A relative path is resolved against the project directory.
    pub path: String,
    /// The format. Absent is recognised from the file's first bytes.
    #[serde(default)]
    pub format: Option<PatchFileFormat>,
    /// The patch set to put the patches in (see `patch_group_set`).
    #[serde(default)]
    pub group: Option<String>,
    /// Only report what would be staged; record nothing (default false).
    #[serde(default)]
    pub preview: bool,
}

/// One patch an import stages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImportedPatch {
    /// Where it goes.
    pub address: Hex64,
    /// Number of bytes.
    pub length: u32,
    /// The file offset it came from.
    pub file_offset: Hex64,
    /// `applied`, `proposed` (an agent's, waiting for the person), or `preview`.
    pub status: String,
    /// The proposal, when proposed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<u64>,
}

/// Result of `patch_import`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchImportOut {
    /// The format read.
    pub format: PatchFileFormat,
    /// The patches staged (or that would be, with `preview`).
    pub patches: Vec<ImportedPatch>,
    /// How many were applied at once.
    pub applied: u32,
    /// How many wait as proposals.
    pub proposed: u32,
    /// The run the entries belong to; `undo_run` takes the whole import back. Absent for a
    /// preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

/// Stages the changes of a patch file as byte patches.
pub struct PatchImport;

#[async_trait]
impl Command for PatchImport {
    type Args = PatchImportArgs;
    type Output = PatchImportOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_import",
            "Stage the changes of an IPS, BPS or JSON patch file as byte patches",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Reads an IPS, IPS32, BPS or KRAKEN JSON patch file made for the project's binary and \
             stages each run of changed bytes as a byte patch (like `patch_set`). A person's \
             patches apply at once under one run, so `undo_run` takes the whole import back; an \
             agent's become proposals for the person to accept. The file is checked first and \
             nothing is staged if anything is wrong: a BPS or JSON file made for another file \
             (size, CRC-32 or SHA-256 differ), a record outside the file, a patch that grows the \
             file, an overlap with a patch already staged, or more than 500 patches. `preview` \
             lists what would be staged.\n\
             Example: patch_import {\"path\": \"fix.ips\", \"preview\": true}",
        )
        .details(
            "Patch files come from other people, so the readers are bounded: at most 16 MiB, \
             100,000 records, 64 MiB of expanded run-length data, and every offset is checked \
             against the original file. Formats are recognised by their first bytes unless \
             `format` is given. `1337` and `dif` files cannot be read. Nothing on disk changes; \
             `patch_export` writes the patched program.",
        )
        .needs(&[Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchImportArgs,
    ) -> Result<PatchImportOut, ProtoError> {
        if args.path.trim().is_empty() {
            return Err(invalid("path is empty"));
        }
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let file = resolve_path(&project, &args.path);
        let base = project.program().base.0;
        let wanted: Option<Format> = args.format.map(Into::into);
        let pieces = blocking(move || plan_import(&binary, &file, wanted, base)).await?;
        let format = pieces.format;

        if let Some(g) = &args.group {
            let g = g.clone();
            let known = project.with_store(move |st| st.patch_groups()).await?;
            if !g.is_empty() && !known.iter().any(|(n, _)| *n == g) {
                return Err(invalid(format!(
                    "there is no patch set named {g:?}; create it with patch_group_set"
                )));
            }
        }
        // Nothing is staged unless every piece fits among the patches already there.
        let existing = project.with_store(|st| st.all_patches()).await?;
        for p in &pieces.patches {
            let end = p.address + p.bytes.len() as u64;
            if let Some(o) = existing.iter().find(|o| {
                o.address != p.address
                    && o.address < end
                    && o.address.saturating_add(o.replacement.len() as u64) > p.address
            }) {
                return Err(invalid(format!(
                    "the file's change at {:#x}..{end:#x} overlaps the patch at {:#x}; remove \
                     that patch (patch_remove) or import a file that avoids it",
                    p.address, o.address
                )));
            }
        }

        let mut out = PatchImportOut {
            format: format.into(),
            patches: Vec::with_capacity(pieces.patches.len()),
            applied: 0,
            proposed: 0,
            run_id: None,
        };
        if args.preview {
            out.patches = pieces
                .patches
                .iter()
                .map(|p| ImportedPatch {
                    address: Hex64(p.address),
                    length: p.bytes.len() as u32,
                    file_offset: Hex64(p.offset),
                    status: "preview".into(),
                    proposal_id: None,
                })
                .collect();
            return Ok(out);
        }

        let mut ctx = ctx.clone();
        if ctx.run_id.is_none() && ctx.author.kind == AuthorKind::User {
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis());
            ctx.run_id = Some(RunId(format!("import-{ms}")));
        }
        out.run_id = crate::mutate::effective_run(&ctx).map(|r| r.0);
        let note = sanitize(&format!(
            "imported from {} ({})",
            pieces.file_name,
            format.name()
        ));
        let note: String = note.chars().take(MAX_PATCH_NOTE).collect();
        let vet = "a patch file from outside the project; the person decides whether to take it";
        for (i, p) in pieces.patches.iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
            }
            let edit = set_patch_vetted(
                s,
                &ctx,
                Hex64(p.address),
                p.bytes.clone(),
                note.clone(),
                args.group.clone(),
                Some(vet),
            )
            .await
            .map_err(|mut e| {
                e.message = format!(
                    "{} (after {i} of {} patches; undo_run {:?} takes back the ones staged)",
                    e.message,
                    pieces.patches.len(),
                    out.run_id
                );
                e
            })?;
            let proposed = edit.edit.status == MutationStatus::Proposed;
            if proposed {
                out.proposed += 1;
            } else {
                out.applied += 1;
            }
            out.patches.push(ImportedPatch {
                address: Hex64(p.address),
                length: p.bytes.len() as u32,
                file_offset: Hex64(p.offset),
                status: if proposed { "proposed" } else { "applied" }.into(),
                proposal_id: edit.edit.proposal_id,
            });
        }
        Ok(out)
    }
}

struct Piece {
    address: u64,
    offset: u64,
    bytes: Vec<u8>,
}

struct Plan {
    format: Format,
    file_name: String,
    patches: Vec<Piece>,
}

/// Reads and checks the patch file against the project's binary and cuts its changes into
/// patch-sized pieces at their addresses.
fn plan_import(
    binary: &std::path::Path,
    file: &std::path::Path,
    wanted: Option<Format>,
    engine_base: u64,
) -> Result<Plan, ProtoError> {
    let meta = fs::metadata(file).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", file.display()),
        )
    })?;
    if !meta.is_file() {
        return Err(invalid(format!("{} is not a file", file.display())));
    }
    if meta.len() > formats::MAX_PATCH_FILE as u64 {
        return Err(invalid(format!(
            "{} is {} bytes; at most {} are read",
            file.display(),
            meta.len(),
            formats::MAX_PATCH_FILE
        )));
    }
    let data = fs::read(file).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", file.display()),
        )
    })?;
    let image = fs::read(binary).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read the project's binary {}: {e}", binary.display()),
        )
    })?;
    let format = match wanted.or_else(|| formats::detect(&data)) {
        Some(f) => f,
        None => {
            return Err(invalid(
                "this is not an IPS, IPS32, BPS or KRAKEN JSON patch file (no recognised header)",
            ));
        }
    };
    let records = formats::read(format, &data, &image).map_err(format_error)?;
    let runs = formats::normalize(&image, &records).map_err(format_error)?;
    let runs = without_pe_checksum(&image, runs);
    let map = OffsetMap::new(&image, engine_base)
        .map_err(|e| ProtoError::new(ErrorCode::Unsupported, e.to_string()))?;
    let mut patches = Vec::new();
    for r in runs {
        split_run(&map, &r, &mut patches)?;
        if patches.len() > MAX_IMPORT_PATCHES {
            return Err(invalid(format!(
                "the file holds more than {MAX_IMPORT_PATCHES} separate changes; import is \
                 limited so the history stays reviewable"
            )));
        }
    }
    if patches.is_empty() {
        return Err(invalid(
            "the patch file changes nothing in this binary (every byte already matches)",
        ));
    }
    Ok(Plan {
        format,
        file_name: file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        patches,
    })
}

/// Maps a run of changed bytes to addresses, cutting it at segment ends and patch size.
/// `runs` without the bytes of a PE file's `CheckSum` field: an export recomputes it and writes
/// it into the patch file, and it is not loaded memory, so there is nothing to stage for it.
fn without_pe_checksum(image: &[u8], runs: Vec<Record>) -> Vec<Record> {
    let Some(field) = pe_checksum_field(image) else {
        return runs;
    };
    let (lo, hi) = (field.start as u64, field.end as u64);
    let mut out = Vec::with_capacity(runs.len());
    for r in runs {
        let end = r.offset + r.bytes.len() as u64;
        if end <= lo || r.offset >= hi {
            out.push(r);
            continue;
        }
        let piece = |from: u64, to: u64| Record {
            offset: from,
            bytes: r.bytes[(from - r.offset) as usize..(to - r.offset) as usize].to_vec(),
            original: r
                .original
                .as_ref()
                .map(|o| o[(from - r.offset) as usize..(to - r.offset) as usize].to_vec()),
        };
        if r.offset < lo {
            out.push(piece(r.offset, lo));
        }
        if end > hi {
            out.push(piece(hi, end));
        }
    }
    out
}

fn split_run(map: &OffsetMap, r: &Record, out: &mut Vec<Piece>) -> Result<(), ProtoError> {
    let mut done = 0usize;
    while done < r.bytes.len() {
        let offset = r.offset + done as u64;
        let left = (r.bytes.len() - done).min(MAX_PATCH_BYTES) as u64;
        let (address, len) = map.address(offset, left).ok_or_else(|| {
            invalid(format!(
                "the file changes offset {offset:#x}, which is not loaded into memory (a header \
                 or padding), so there is no address to patch"
            ))
        })?;
        let len = len as usize;
        out.push(Piece {
            address,
            offset,
            bytes: r.bytes[done..done + len].to_vec(),
        });
        done += len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patchformats::normalize;

    const DLL_BASE: u64 = 0x2ca150000;

    #[test]
    fn a_patched_pe_file_exports_with_its_new_checksum_and_imports_without_it() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/pe/bin/win_dll-x64-O0.dll");
        let dir = tempfile::tempdir().expect("tmp");
        let binary = dir.path().join("win_dll-x64-O0.dll");
        fs::copy(&src, &binary).expect("copy");
        let image = fs::read(&binary).expect("read");
        let off = 0x400usize;
        let patch = Patch {
            address: DLL_BASE + 0x1000,
            original: image[off..off + 1].to_vec(),
            replacement: vec![image[off] ^ 0xff],
            note: String::new(),
            group: String::new(),
            disabled: false,
            author: kraken_model::Author::user("t"),
            ts_ms: 0,
        };
        let (patched, _) =
            apply_project_patches(&binary, std::slice::from_ref(&patch), DLL_BASE).expect("apply");
        let field = pe_checksum_field(&image).expect("pe");
        assert_ne!(image[field.clone()], patched[field], "the checksum changes");

        for (format, name) in [
            (Format::Bps, "p.bps"),
            (Format::Ips, "p.ips"),
            (Format::Json, "p.json"),
        ] {
            let out = dir.path().join(name);
            let r = export_diff(
                &binary,
                &out,
                std::slice::from_ref(&patch),
                format,
                false,
                DLL_BASE,
            )
            .expect("export");
            assert_eq!(r.patches, 2, "{format:?}: the byte and the checksum");
            // Reading a BPS file checks its target CRC, so this fails on a stale checksum.
            let data = fs::read(&out).expect("written");
            let records = formats::read(format, &data, &image).expect("read back");
            let runs = normalize(&image, &records).expect("normalize");
            let mut applied = image.clone();
            for run in &runs {
                let o = run.offset as usize;
                applied[o..o + run.bytes.len()].copy_from_slice(&run.bytes);
            }
            assert!(applied == patched, "{format:?} gives the exported file");

            // Importing stages the byte only: the checksum is not loaded memory.
            let plan = plan_import(&binary, &out, None, DLL_BASE).expect("import");
            assert_eq!(plan.patches.len(), 1, "{format:?}");
            assert_eq!(plan.patches[0].address, DLL_BASE + 0x1000);
        }
    }
}
