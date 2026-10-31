//! `debuginfo_export`: write what the project learned (names, prototypes, types, globals) as an
//! ELF debug file with DWARF that a debugger, or another KRAKEN project, can read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use async_trait::async_trait;
use base64::Engine as _;
use kraken_engine::Cap;
use kraken_model::{AuthorKind, StateValue};
use kraken_proto::{ErrorCode, Locator, PageRequest, ProtoError, TypeDef, TypeRef};
use object::read::{Object, ObjectSection, ObjectSegment};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::dwarfwrite::{self, AllocSection, FuncIn, GlobalIn, Target};
use crate::session::Session;
use crate::views::locator_parts;

use super::debuginfo::crc32;
use super::symbols_parse;

/// Largest program the export reads.
const MAX_PROGRAM_BYTES: u64 = 1 << 30;
/// Largest debug file returned inline.
pub const MAX_INLINE_BYTES: usize = 8 * 1024 * 1024;
const PAGE: u32 = 500;
const MAX_PAGES: usize = 400;

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn internal(e: impl ToString) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, e.to_string())
}

fn is_default_name(n: &str) -> bool {
    ["FUN_", "sub_", "thunk_FUN_", "LAB_", "DAT_", "PTR_"]
        .iter()
        .any(|p| n.starts_with(p))
}

/// Arguments of `debuginfo_export`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugInfoExportArgs {
    /// Write the debug file here (people only; relative paths are taken against the project
    /// directory). Without it the bytes come back base64-encoded, up to 8 MiB.
    #[serde(default)]
    pub path: Option<String>,
    /// Replace an existing file at `path` (default false).
    #[serde(default)]
    pub overwrite: bool,
    /// Also describe functions that still have default names (`FUN_...`).
    #[serde(default)]
    pub include_default: bool,
    /// Subtracted from every address instead of the program's own load base (a PIE is loaded
    /// at 0x100000 by the native engine; the file's addresses start at 0).
    #[serde(default)]
    pub base_offset: Option<i64>,
}

/// Result of `debuginfo_export`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DebugInfoExportOut {
    /// Size of the debug file in bytes.
    pub size: u64,
    /// Functions described.
    pub functions: u32,
    /// Of those, the ones with a prototype (parameters and return type).
    pub prototypes: u32,
    /// Global variables described.
    pub globals: u32,
    /// Named types described.
    pub types: u32,
    /// The GNU build-id the file carries (the program's); absent when the program has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// CRC-32 of the file, the value `.gnu_debuglink` of a stripped program needs.
    pub debuglink_crc: u32,
    /// Command that adds the debug link to a stripped copy of the program.
    pub debuglink_hint: String,
    /// Absolute path written, when `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The file, base64-encoded, when no `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
    /// Things left out and why.
    pub warnings: Vec<String>,
}

/// Writes the project's knowledge as a DWARF debug file.
pub struct DebugInfoExport;

struct Gathered {
    funcs: Vec<FuncIn>,
    globals: Vec<GlobalIn>,
    types: Vec<TypeDef>,
}

async fn gather(
    s: &Session,
    ctx: &CallContext,
    bias: u64,
    include_default: bool,
    warnings: &mut Vec<String>,
) -> Result<Gathered, ProtoError> {
    let project = s.project()?;
    let engine = project.engine();
    let cancelled = || ProtoError::new(ErrorCode::Cancelled, "call cancelled");
    let mut funcs = Vec::new();
    let mut entries = BTreeSet::new();
    let mut below = 0u32;
    if let Some(lister) = engine.function_lister() {
        let mut cursor = None;
        loop {
            if ctx.cancel.is_cancelled() {
                return Err(cancelled());
            }
            let page = lister
                .list_functions(
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(1000),
                    },
                    &ctx.cancel,
                )
                .await?;
            for f in page.items {
                let Locator::Native { space, .. } = &f.locator else {
                    continue;
                };
                if space != "ram" {
                    continue;
                }
                let at = locator_parts(&f.locator).1.0;
                entries.insert(at);
                if !include_default && is_default_name(&f.name) {
                    continue;
                }
                let Some(addr) = at.checked_sub(bias) else {
                    below += 1;
                    continue;
                };
                funcs.push(FuncIn {
                    addr,
                    size: f.size,
                    name: f.name,
                    linkage: f.mangled,
                    signature: f.signature,
                });
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    }
    if below > 0 {
        warnings.push(format!(
            "{below} functions lie below the load base and were left out"
        ));
    }
    funcs.sort_by_key(|f| f.addr);
    funcs.dedup_by_key(|f| f.addr);

    let mut types = Vec::new();
    if let Some(store) = engine.type_store() {
        let mut cursor = None;
        for _ in 0..MAX_PAGES {
            if ctx.cancel.is_cancelled() {
                return Err(cancelled());
            }
            let page = store
                .list_types(
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(PAGE),
                    },
                    &ctx.cancel,
                )
                .await?;
            types.extend(page.items);
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    }

    let state = project.with_store(|st| st.current_state()).await?;
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    let mut tys: BTreeMap<u64, TypeRef> = BTreeMap::new();
    for (key, value) in &state {
        let Some(rest) = key.strip_prefix("native:ram:") else {
            continue;
        };
        let Some((addr, aspect)) = rest.split_once(':') else {
            continue;
        };
        let Some(addr) = symbols_parse::parse_address(addr) else {
            continue;
        };
        match (aspect, value) {
            ("name", StateValue::Name { name }) => {
                names.insert(addr, name.clone());
            }
            ("type", StateValue::Type { ty }) => {
                tys.insert(addr, ty.clone());
            }
            _ => {}
        }
    }
    let mut globals = Vec::new();
    for (at, name) in names {
        if entries.contains(&at) || is_default_name(&name) {
            continue;
        }
        let Some(addr) = at.checked_sub(bias) else {
            continue;
        };
        globals.push(GlobalIn {
            addr,
            name,
            ty: tys.get(&at).cloned(),
        });
    }
    Ok(Gathered {
        funcs,
        globals,
        types,
    })
}

/// The load base the native engine gives an ELF whose lowest segment starts at 0.
fn elf_bias(file: &object::File<'_>) -> u64 {
    let low = file.segments().map(|s| s.address()).min().unwrap_or(0);
    if low != 0 {
        0
    } else if file.is_64() {
        0x10_0000
    } else {
        0x1_0000
    }
}

fn target_of(data: &[u8], file: &object::File<'_>, name: String) -> Result<Target, ProtoError> {
    if file.format() != object::BinaryFormat::Elf {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            "debug information is exported for ELF programs; a PE program takes a PDB, which KRAKEN reads but does not write",
        ));
    }
    let little = file.is_little_endian();
    let is64 = file.is_64();
    let u16at = |o: usize| {
        let b: [u8; 2] = data.get(o..o + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let flags_at = if is64 { 48 } else { 36 };
    let e_flags = data
        .get(flags_at..flags_at + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, |b| {
            if little {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        });
    let sections = file
        .sections()
        .filter_map(|s| {
            let object::SectionFlags::Elf { sh_flags, .. } = s.flags() else {
                return None;
            };
            let sh_flags = sh_flags.0;
            if sh_flags & 2 == 0 || s.kind() == object::SectionKind::Note {
                return None;
            }
            Some(AllocSection {
                name: s.name().ok()?.to_string(),
                flags: sh_flags,
                addr: s.address(),
                size: s.size(),
                align: s.align().max(1),
            })
        })
        .collect();
    Ok(Target {
        name,
        little,
        is64,
        e_type: u16at(16).unwrap_or(2),
        e_machine: u16at(18).unwrap_or(0),
        osabi: data.get(7).copied().unwrap_or(0),
        e_flags,
        sections,
        build_id: file.build_id().ok().flatten().map(<[u8]>::to_vec),
    })
}

#[async_trait]
impl Command for DebugInfoExport {
    type Args = DebugInfoExportArgs;
    type Output = DebugInfoExportOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debuginfo_export",
            "Export names, prototypes, types and globals as an ELF debug file with DWARF",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Writes a separate debug file for an ELF program: a DWARF subprogram for every named \
             function with its parameters and return type, the struct, union, enum and typedef \
             definitions, and the globals you named, plus the program's build-id so gdb and \
             lldb find it beside a stripped copy. `debuginfo_attach` reads it back in another \
             project. Without `path` the file comes back base64-encoded (up to 8 MiB); only a \
             person can write a file with `path`.\n\
             Example: debuginfo_export {\"path\": \"prog.debug\", \"overwrite\": true}",
        )
        .details(
            "Names and signatures come from the engine's function list (your renames and \
             prototypes included), types from the type store, globals from the names and types \
             you set on data addresses. Functions with default names (`FUN_...`) are left out \
             unless `include_default` is set. Addresses are the program file's own, so a PIE's \
             load base is subtracted. A signature whose types the store does not know is \
             written as a name and address without parameters. `debuglink_crc` and \
             `debuglink_hint` tell how to point a stripped copy at the file with \
             `objcopy --add-gnu-debuglink`; KRAKEN never changes the program.",
        )
        .needs(&[Cap::FunctionLister])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: DebugInfoExportArgs,
    ) -> Result<DebugInfoExportOut, ProtoError> {
        let project = s.project()?;
        if args.path.is_some() && ctx.author.kind == AuthorKind::Agent {
            return Err(ProtoError::new(
                ErrorCode::RejectedHumanPriority,
                "an agent reads the exported bytes; writing a file is for people",
            ));
        }
        let binary = PathBuf::from(project.meta().binary_path);
        let name = binary.file_name().map_or_else(
            || "program".to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let read = tokio::task::spawn_blocking(move || {
            let len = std::fs::metadata(&binary)
                .map_err(|e| invalid(format!("cannot read {}: {e}", binary.display())))?
                .len();
            if len > MAX_PROGRAM_BYTES {
                return Err(invalid("the program is too large to describe"));
            }
            std::fs::read(&binary)
                .map_err(|e| invalid(format!("cannot read {}: {e}", binary.display())))
        })
        .await
        .map_err(internal)??;
        let (target, bias) = {
            let file = object::File::parse(&*read)
                .map_err(|e| invalid(format!("not a program KRAKEN can read: {e}")))?;
            (target_of(&read, &file, name)?, elf_bias(&file))
        };
        let bias = match args.base_offset {
            Some(o) => u64::try_from(o).map_err(|_| invalid("base_offset must not be negative"))?,
            None => bias,
        };
        let mut warnings = Vec::new();
        let got = gather(s, ctx, bias, args.include_default, &mut warnings).await?;
        let long = if target.is64 { 8 } else { 4 };
        let producer = format!("KRAKEN {}", env!("CARGO_PKG_VERSION"));
        let build_id = target.build_id.clone();
        let (bytes, stats) = tokio::task::spawn_blocking(move || {
            dwarfwrite::build(
                &target,
                &producer,
                &got.funcs,
                &got.globals,
                &got.types,
                long,
            )
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        warnings.extend(stats.warnings);
        let crc = crc32(&bytes);
        let file_name = args
            .path
            .as_deref()
            .and_then(|p| std::path::Path::new(p).file_name())
            .map_or_else(
                || "<debug file>".to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
        let mut out = DebugInfoExportOut {
            size: bytes.len() as u64,
            functions: stats.functions,
            prototypes: stats.prototypes,
            globals: stats.globals,
            types: stats.types,
            build_id: build_id.map(|b| b.iter().map(|x| format!("{x:02x}")).collect()),
            debuglink_crc: crc,
            debuglink_hint: format!(
                "objcopy --add-gnu-debuglink={file_name} <stripped program>  (CRC-32 {crc:#010x})"
            ),
            path: None,
            data_base64: None,
            warnings,
        };
        match args.path {
            Some(p) => {
                let path = PathBuf::from(&p);
                let path = if path.is_absolute() {
                    path
                } else {
                    project.dir().join(path)
                };
                let overwrite = args.overwrite;
                let shown = path.display().to_string();
                tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let mut o = std::fs::OpenOptions::new();
                    o.write(true);
                    if overwrite {
                        o.create(true).truncate(true);
                    } else {
                        o.create_new(true);
                    }
                    let mut f = o
                        .open(&path)
                        .map_err(|e| invalid(format!("cannot write {}: {e}", path.display())))?;
                    f.write_all(&bytes)
                        .map_err(|e| invalid(format!("cannot write {}: {e}", path.display())))
                })
                .await
                .map_err(internal)??;
                out.path = Some(shown);
            }
            None => {
                if bytes.len() > MAX_INLINE_BYTES {
                    return Err(invalid(
                        "the debug file is over 8 MiB; give `path` to write it to a file",
                    ));
                }
                out.data_base64 = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
            }
        }
        Ok(out)
    }
}
