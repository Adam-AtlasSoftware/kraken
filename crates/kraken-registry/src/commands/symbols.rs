//! `symbols_import` and `symbols_export`: bring names, labels and comments in from link maps,
//! CSV, splat and IDA scripts as one undoable run, and write them back out.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_model::{AuthorKind, NewProposal, RunId, StateValue};
use kraken_proto::{
    CommentKind, ErrorCode, Hex64, Locator, LogOp, PageRequest, ProtoError, VersionedLogOp,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::mutate::anchor_for;
use crate::session::{Project, Session};
use crate::validate::{clean_comment, validate_name};
use crate::views::locator_parts;

use super::bulk::{ApplyEdits, ApplyEditsArgs, BulkEdit, BulkOp, BulkOutcome, MAX_BULK_EDITS};
use super::symbols_parse::{self, SymbolFormat};

/// Largest symbol file `symbols_import` reads.
pub const MAX_SYMBOL_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Planned edits one import takes.
pub const MAX_IMPORT_EDITS: usize = 100_000;
/// Default and largest number of planned edits returned in the preview.
pub const DEFAULT_PREVIEW: u32 = 500;
/// Largest preview a caller may ask for.
pub const MAX_PREVIEW: u32 = 10_000;
/// Largest text `symbols_export` returns inline.
pub const MAX_EXPORT_TEXT_BYTES: usize = 8 * 1024 * 1024;

static IMPORT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// What to do with a name that differs from the one the function already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Keep the existing name (default).
    #[default]
    Skip,
    /// Replace it. An agent's replacement still becomes a proposal.
    Overwrite,
    /// File each replacement as a proposal for a person to accept.
    Propose,
}

/// How a planned edit relates to the program as it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// Nothing but a default name (or no function) at the address.
    New,
    /// The function already has this name.
    Unchanged,
    /// The function has a different name.
    Conflict,
    /// The name or comment is not acceptable; see `reason`.
    Invalid,
    /// An earlier record of the file already names this address.
    Duplicate,
}

/// What the import does with a planned edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    /// Apply it.
    Apply,
    /// File it as a proposal.
    Propose,
    /// Leave it out.
    Skip,
}

/// Arguments of `symbols_import`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolsImportArgs {
    /// Symbol file to read (people only; an agent sends `text`). Relative paths are taken
    /// against the project directory.
    #[serde(default)]
    pub path: Option<String>,
    /// The file's text, instead of `path`.
    #[serde(default)]
    pub text: Option<String>,
    /// `auto` (default), `gnu_map`, `msvc_map`, `csv`, `splat` or `idc`.
    #[serde(default = "auto_format")]
    pub format: SymbolFormat,
    /// Plan only: list the edits and conflicts, change nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// What to do when a function already has another name: `skip` (default), `overwrite` or
    /// `propose`.
    #[serde(default)]
    pub conflicts: ConflictPolicy,
    /// Added to every address of the file (negative values subtract), to match the load base
    /// of the program.
    #[serde(default)]
    pub base_offset: Option<i64>,
    /// How many planned edits to return (default 500, at most 10000); conflicts come first.
    #[serde(default)]
    pub preview_limit: Option<u32>,
}

fn auto_format() -> SymbolFormat {
    SymbolFormat::Auto
}

/// One edit the import plans (and, after a real run, its outcome).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlannedSymbolEdit {
    /// `rename` or `comment`.
    pub op: String,
    /// Address after rebasing.
    pub address: Hex64,
    /// New name (`rename`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Comment text (`comment`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Comment slot (`comment`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CommentKind>,
    /// How it relates to the program now.
    pub status: PlanStatus,
    /// The name the function has now, for a conflict or unchanged name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing: Option<String>,
    /// What the import does with it.
    pub action: PlanAction,
    /// Line of the file.
    pub line: u32,
    /// After a real run: `applied`, `queued`, `proposed` or `rejected`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<BulkOutcome>,
    /// Why it is invalid or was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of `symbols_import`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolsImportOut {
    /// The format that was read (the detected one for `auto`).
    pub format: SymbolFormat,
    /// Whether nothing was changed.
    pub dry_run: bool,
    /// Run id of the edits; `undo_run` with it reverts the import. Absent for a dry run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Records read from the file.
    pub records: u32,
    /// Planned edits at a new address or over a default name.
    pub new: u32,
    /// Names the program already has.
    pub unchanged: u32,
    /// Names that differ from the program's.
    pub conflicts: u32,
    /// Edits refused by validation.
    pub invalid: u32,
    /// Records whose address an earlier record already names.
    pub duplicates: u32,
    /// Edits applied or queued.
    pub applied: u32,
    /// Edits filed as proposals.
    pub proposed: u32,
    /// Edits the engine or the checks refused.
    pub rejected: u32,
    /// Lines that did not parse.
    pub ignored_lines: u32,
    /// Notes about the file (limits hit, lines skipped).
    pub warnings: Vec<String>,
    /// The planned edits, conflicts and problems first, cut to `preview_limit`.
    pub edits: Vec<PlannedSymbolEdit>,
    /// Planned edits left out of `edits`.
    pub edits_omitted: u32,
}

/// Imports symbols.
pub struct SymbolsImport;

fn is_default_name(n: &str) -> bool {
    ["FUN_", "sub_", "thunk_FUN_", "LAB_", "DAT_"]
        .iter()
        .any(|p| n.starts_with(p))
}

fn rebase(addr: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        addr.checked_add(offset.unsigned_abs())
    } else {
        addr.checked_sub(offset.unsigned_abs())
    }
}

/// Entry address to name of every function the engine lists.
async fn function_names(
    project: &Project,
    ctx: &CallContext,
) -> Result<HashMap<u64, String>, ProtoError> {
    let mut out = HashMap::new();
    let engine = project.engine();
    let Some(lister) = engine.function_lister() else {
        return Ok(out);
    };
    let mut cursor = None;
    loop {
        if ctx.cancel.is_cancelled() {
            return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
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
            if let Locator::Native { .. } = f.locator {
                out.insert(locator_parts(&f.locator).1.0, f.name);
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
}

async fn read_input(
    s: &Session,
    ctx: &CallContext,
    args: &SymbolsImportArgs,
) -> Result<String, ProtoError> {
    match (&args.path, &args.text) {
        (Some(_), Some(_)) => Err(invalid("give `path` or `text`, not both")),
        (None, None) => Err(invalid("give `path` or `text`")),
        (None, Some(t)) => {
            if t.len() as u64 > MAX_SYMBOL_FILE_BYTES {
                return Err(invalid("`text` is over the 32 MiB limit"));
            }
            Ok(t.clone())
        }
        (Some(p), None) => {
            if ctx.author.kind == AuthorKind::Agent {
                return Err(ProtoError::new(
                    ErrorCode::RejectedHumanPriority,
                    "an agent sends the file's contents as `text`; reading a path is for people",
                ));
            }
            let project = s.project()?;
            let path = PathBuf::from(p);
            let path = if path.is_absolute() {
                path
            } else {
                project.dir().join(path)
            };
            tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let f = std::fs::File::open(&path)
                    .map_err(|e| invalid(format!("cannot open {}: {e}", path.display())))?;
                let mut buf = Vec::new();
                f.take(MAX_SYMBOL_FILE_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
                if buf.len() as u64 > MAX_SYMBOL_FILE_BYTES {
                    return Err(invalid("the file is over the 32 MiB limit"));
                }
                Ok(String::from_utf8_lossy(&buf).into_owned())
            })
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?
        }
    }
}

struct Plan {
    items: Vec<PlannedSymbolEdit>,
    format: SymbolFormat,
    records: u32,
    ignored: u32,
    warnings: Vec<String>,
}

fn plan_edits(
    text: &str,
    args: &SymbolsImportArgs,
    kind: AuthorKind,
    existing: &HashMap<u64, String>,
) -> Result<Plan, ProtoError> {
    let (format, parsed) = symbols_parse::parse(text, args.format);
    let offset = args.base_offset.unwrap_or(0);
    let mut warnings = parsed.warnings;
    let mut items = Vec::new();
    let mut named: HashMap<u64, String> = HashMap::new();
    let mut bad_address = 0usize;
    for rec in &parsed.records {
        let Some(address) = rebase(rec.address, offset) else {
            bad_address += 1;
            continue;
        };
        let line = u32::try_from(rec.line).unwrap_or(u32::MAX);
        if let Some(name) = &rec.name {
            let mut item = PlannedSymbolEdit {
                op: "rename".into(),
                address: Hex64(address),
                name: Some(name.clone()),
                text: None,
                kind: None,
                status: PlanStatus::New,
                existing: None,
                action: PlanAction::Apply,
                line,
                outcome: None,
                reason: None,
            };
            match validate_name("name", name, kind) {
                Err(e) => {
                    item.status = PlanStatus::Invalid;
                    item.action = PlanAction::Skip;
                    item.reason = Some(e.message);
                }
                Ok(_) => match named.get(&address) {
                    Some(first) => {
                        item.status = PlanStatus::Duplicate;
                        item.action = PlanAction::Skip;
                        item.reason = Some(format!("{first} already names this address"));
                    }
                    None => {
                        named.insert(address, name.clone());
                        match existing.get(&address) {
                            Some(cur) if cur == name => {
                                item.status = PlanStatus::Unchanged;
                                item.action = PlanAction::Skip;
                                item.existing = Some(cur.clone());
                            }
                            Some(cur) if !is_default_name(cur) => {
                                item.status = PlanStatus::Conflict;
                                item.existing = Some(cur.clone());
                                item.action = match args.conflicts {
                                    ConflictPolicy::Skip => PlanAction::Skip,
                                    ConflictPolicy::Overwrite => PlanAction::Apply,
                                    ConflictPolicy::Propose => PlanAction::Propose,
                                };
                            }
                            _ => {}
                        }
                    }
                },
            }
            items.push(item);
        }
        if let Some((ck, ctext)) = &rec.comment {
            let mut item = PlannedSymbolEdit {
                op: "comment".into(),
                address: Hex64(address),
                name: None,
                text: Some(ctext.clone()),
                kind: Some(*ck),
                status: PlanStatus::New,
                existing: None,
                action: PlanAction::Apply,
                line,
                outcome: None,
                reason: None,
            };
            if let Err(e) = clean_comment(ctext) {
                item.status = PlanStatus::Invalid;
                item.action = PlanAction::Skip;
                item.reason = Some(e.message);
            }
            items.push(item);
        }
        if items.len() > MAX_IMPORT_EDITS {
            return Err(invalid(format!(
                "the file plans more than {MAX_IMPORT_EDITS} edits; split it"
            )));
        }
    }
    if bad_address > 0 {
        warnings.push(format!(
            "{bad_address} records fell outside the address range after `base_offset` and were left out"
        ));
    }
    Ok(Plan {
        items,
        format,
        records: u32::try_from(parsed.records.len()).unwrap_or(u32::MAX),
        ignored: u32::try_from(parsed.ignored).unwrap_or(u32::MAX),
        warnings,
    })
}

async fn file_proposal(
    s: &Session,
    ctx: &CallContext,
    run_id: &RunId,
    item: &PlannedSymbolEdit,
) -> Result<(u64, String), ProtoError> {
    let project = s.project()?;
    let name = item.name.clone().unwrap_or_default();
    let r = anchor_for(&project, ctx, item.address).await?;
    let old_name = r
        .function
        .as_ref()
        .filter(|f| locator_parts(&f.locator).1 == item.address)
        .map(|f| f.name.clone());
    let op = LogOp::Rename {
        anchor: r.anchor,
        old_name,
        new_name: name,
    };
    let reason = format!(
        "symbols_import: the program names this {:?}",
        item.existing.clone().unwrap_or_default()
    );
    let author = ctx.author.clone();
    let run = run_id.clone();
    let why = reason.clone();
    let id = project
        .with_store(move |st| {
            st.add_proposal(NewProposal {
                run_id: Some(run),
                author,
                op: VersionedLogOp::new(op),
                reason: why,
            })
        })
        .await?;
    Ok((id.0, reason))
}

#[async_trait]
impl Command for SymbolsImport {
    type Args = SymbolsImportArgs;
    type Output = SymbolsImportOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "symbols_import",
            "Import names and comments from a link map, CSV, splat or IDA script",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Reads function and label names and comments from a GNU ld or MSVC `.map`, a CSV \
             (`address,name[,size,comment]`), a splat `symbol_addrs.txt` or an IDA script \
             (`set_name`, `MakeName`, `set_cmt`, `MakeComm`, `set_func_cmt`), and applies them \
             as one run: `undo_run` with the returned `run_id` reverts all of it. Use \
             `dry_run` first to see the new names and conflicts. A function that already has \
             another name is a conflict: `conflicts` is `skip` (default), `overwrite` or \
             `propose`; an agent's replacements always become proposals. `base_offset` shifts \
             addresses to the program's load base. A person gives `path`, an agent `text`.\n\
             Example: symbols_import {\"path\": \"build/app.map\", \"dry_run\": true, \"base_offset\": 0}",
        )
        .details(
            "Formats: `gnu_map` reads the `0xADDRESS name` lines under `Linker script and \
             memory map`; `msvc_map` reads `Publics by Value` using the `Rva+Base` column; \
             `csv` takes `0x` or bare hex addresses, an optional header line and quoted fields, \
             and its fourth column becomes a plate comment; `splat` reads `name = 0xADDR; // \
             size:0x10`; `idc` reads the calls above (`set_cmt` and `MakeComm` are end-of-line \
             comments, `set_func_cmt` a plate, a nonzero last argument makes either \
             repeatable). Lines over 4096 bytes are skipped and a file may plan at most \
             100000 edits. A name over a default name (`FUN_...`, `sub_...`) is new, not a \
             conflict. Existing comments are overwritten without a conflict check. `edits` \
             lists conflicts and problems first and is cut to `preview_limit`; counts cover \
             everything.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SymbolsImportArgs,
    ) -> Result<SymbolsImportOut, ProtoError> {
        let project = s.project()?;
        let text = read_input(s, ctx, &args).await?;
        let existing = function_names(&project, ctx).await?;
        let mut plan = plan_edits(&text, &args, ctx.author.kind, &existing)?;
        drop(text);

        let mut out = SymbolsImportOut {
            format: plan.format,
            dry_run: args.dry_run,
            run_id: None,
            records: plan.records,
            new: 0,
            unchanged: 0,
            conflicts: 0,
            invalid: 0,
            duplicates: 0,
            applied: 0,
            proposed: 0,
            rejected: 0,
            ignored_lines: plan.ignored,
            warnings: std::mem::take(&mut plan.warnings),
            edits: Vec::new(),
            edits_omitted: 0,
        };
        for it in &plan.items {
            match it.status {
                PlanStatus::New => out.new += 1,
                PlanStatus::Unchanged => out.unchanged += 1,
                PlanStatus::Conflict => out.conflicts += 1,
                PlanStatus::Invalid => out.invalid += 1,
                PlanStatus::Duplicate => out.duplicates += 1,
            }
        }

        if !args.dry_run {
            let run = ctx.run_id.clone().unwrap_or_else(|| {
                let n = IMPORT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis());
                RunId(format!("symbols-import-{ms}-{n}"))
            });
            let mut run_ctx = ctx.clone();
            run_ctx.run_id = Some(run.clone());
            let mut batch: Vec<usize> = Vec::new();
            let flush = |batch: &mut Vec<usize>| std::mem::take(batch);
            for i in 0..plan.items.len() {
                match plan.items[i].action {
                    PlanAction::Skip => {}
                    PlanAction::Apply => batch.push(i),
                    PlanAction::Propose => {
                        match file_proposal(s, &run_ctx, &run, &plan.items[i]).await {
                            Ok((_, reason)) => {
                                out.proposed += 1;
                                plan.items[i].outcome = Some(BulkOutcome::Proposed);
                                plan.items[i].reason = Some(reason);
                            }
                            Err(e) => {
                                out.rejected += 1;
                                plan.items[i].outcome = Some(BulkOutcome::Rejected);
                                plan.items[i].reason = Some(e.message);
                            }
                        }
                    }
                }
                if batch.len() == MAX_BULK_EDITS {
                    let ids = flush(&mut batch);
                    apply_batch(s, &run_ctx, &mut plan.items, &ids, &mut out).await?;
                }
            }
            if !batch.is_empty() {
                apply_batch(s, &run_ctx, &mut plan.items, &batch, &mut out).await?;
            }
            if out.applied + out.proposed > 0 {
                out.run_id = Some(run.0);
            }
        }

        let limit = args
            .preview_limit
            .unwrap_or(DEFAULT_PREVIEW)
            .min(MAX_PREVIEW) as usize;
        let rank = |it: &PlannedSymbolEdit| match it.status {
            PlanStatus::Conflict => 0,
            PlanStatus::Invalid => 1,
            PlanStatus::New => 2,
            _ => 3,
        };
        plan.items.sort_by_key(rank);
        out.edits_omitted =
            u32::try_from(plan.items.len().saturating_sub(limit)).unwrap_or(u32::MAX);
        plan.items.truncate(limit);
        out.edits = plan.items;
        Ok(out)
    }
}

async fn apply_batch(
    s: &Session,
    ctx: &CallContext,
    items: &mut [PlannedSymbolEdit],
    ids: &[usize],
    out: &mut SymbolsImportOut,
) -> Result<(), ProtoError> {
    let edits: Vec<BulkEdit> = ids
        .iter()
        .map(|&i| {
            let it = &items[i];
            BulkEdit {
                op: if it.op == "rename" {
                    BulkOp::Rename
                } else {
                    BulkOp::Comment
                },
                address: it.address,
                name: it.name.clone(),
                text: it.text.clone(),
                kind: it.kind,
                type_name: None,
                module: None,
            }
        })
        .collect();
    let res = ApplyEdits.run(s, ctx, ApplyEditsArgs { edits }).await?;
    for (r, &i) in res.results.iter().zip(ids) {
        items[i].outcome = Some(r.outcome);
        if r.reason.is_some() {
            items[i].reason = r.reason.clone();
        }
    }
    out.applied += res.applied;
    out.proposed += res.proposed;
    out.rejected += res.rejected;
    Ok(())
}

/// Output format of `symbols_export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// `address,name,size,comment` with a header line (default).
    #[default]
    Csv,
    /// GNU ld style `0xADDRESS name` lines that `symbols_import` reads back as `gnu_map`.
    Map,
}

/// Arguments of `symbols_export`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolsExportArgs {
    /// `csv` (default) or `map`.
    #[serde(default)]
    pub format: ExportFormat,
    /// Write the text to this file (relative paths are taken against the project directory)
    /// instead of returning it.
    #[serde(default)]
    pub path: Option<String>,
    /// Replace an existing file at `path` (default false).
    #[serde(default)]
    pub overwrite: bool,
    /// Also list functions that still have default names (`FUN_...`).
    #[serde(default)]
    pub include_default: bool,
    /// Subtracted from every address, the inverse of `base_offset` on import.
    #[serde(default)]
    pub base_offset: Option<i64>,
}

/// Result of `symbols_export`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolsExportOut {
    /// The format written.
    pub format: ExportFormat,
    /// Symbols written.
    pub count: u32,
    /// Absolute path of the file written, when `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The text, when no `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Exports symbols.
pub struct SymbolsExport;

fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\"").replace(['\n', '\r'], " "))
    } else {
        s.to_string()
    }
}

#[derive(Default)]
struct Sym {
    name: Option<String>,
    size: Option<u64>,
    comment: Option<(u8, String)>,
}

#[async_trait]
impl Command for SymbolsExport {
    type Args = SymbolsExportArgs;
    type Output = SymbolsExportOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "symbols_export",
            "Export names and comments as CSV or a .map-like text",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Writes every named function and label, with its size and comment, as CSV \
             (`address,name,size,comment`) or GNU-map style lines, so another tool or another \
             project can read them (`symbols_import` reads both back). Without `path` the text \
             is returned (up to 8 MiB); only a person can write a file with `path`.\n\
             Example: symbols_export {\"format\": \"csv\", \"path\": \"names.csv\", \"overwrite\": true}",
        )
        .details(
            "Names come from the engine's function list and the project's rename edits; \
             comments from the edit log (plate first, then end-of-line, pre, post, repeatable; \
             one per address). The map format carries no comments or sizes.",
        )
        .needs(&[Cap::FunctionLister])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SymbolsExportArgs,
    ) -> Result<SymbolsExportOut, ProtoError> {
        let project = s.project()?;
        if args.path.is_some() && ctx.author.kind == AuthorKind::Agent {
            return Err(ProtoError::new(
                ErrorCode::RejectedHumanPriority,
                "an agent reads the exported text; writing a file is for people",
            ));
        }
        let offset = args.base_offset.unwrap_or(0);
        let mut syms: std::collections::BTreeMap<u64, Sym> = std::collections::BTreeMap::new();

        let engine = project.engine();
        if let Some(lister) = engine.function_lister() {
            let mut cursor = None;
            loop {
                if ctx.cancel.is_cancelled() {
                    return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
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
                    if !matches!(f.locator, Locator::Native { .. }) {
                        continue;
                    }
                    if !args.include_default && is_default_name(&f.name) {
                        continue;
                    }
                    let e = syms.entry(locator_parts(&f.locator).1.0).or_default();
                    e.name = Some(f.name);
                    e.size = f.size;
                }
                match page.next_cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
        }
        let state = project.with_store(|st| st.current_state()).await?;
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
                    syms.entry(addr).or_default().name = Some(name.clone());
                }
                (a, StateValue::Comment { text }) if a.starts_with("comment:") => {
                    let rank = match &a["comment:".len()..] {
                        "plate" => 0,
                        "eol" => 1,
                        "pre" => 2,
                        "post" => 3,
                        _ => 4,
                    };
                    let e = syms.entry(addr).or_default();
                    if e.comment.as_ref().is_none_or(|(r, _)| rank < *r) {
                        e.comment = Some((rank, text.clone()));
                    }
                }
                _ => {}
            }
        }

        let mut text = String::new();
        let mut count = 0u32;
        match args.format {
            ExportFormat::Csv => text.push_str("address,name,size,comment\n"),
            ExportFormat::Map => text.push_str("Linker script and memory map\n\n"),
        }
        for (addr, sym) in &syms {
            let Some(addr) = rebase(*addr, offset.checked_neg().unwrap_or(0)) else {
                continue;
            };
            match args.format {
                ExportFormat::Csv => {
                    if sym.name.is_none() && sym.comment.is_none() {
                        continue;
                    }
                    let _ = writeln!(
                        text,
                        "{:#x},{},{},{}",
                        addr,
                        csv_quote(sym.name.as_deref().unwrap_or("")),
                        sym.size.map(|n| format!("{n:#x}")).unwrap_or_default(),
                        csv_quote(sym.comment.as_ref().map_or("", |c| c.1.as_str())),
                    );
                }
                ExportFormat::Map => {
                    let Some(name) = &sym.name else { continue };
                    let _ = writeln!(text, "                {addr:#018x}                {name}");
                }
            }
            count += 1;
        }

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
                    f.write_all(text.as_bytes())
                        .map_err(|e| invalid(format!("cannot write {}: {e}", path.display())))
                })
                .await
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))??;
                Ok(SymbolsExportOut {
                    format: args.format,
                    count,
                    path: Some(shown),
                    text: None,
                })
            }
            None => {
                if text.len() > MAX_EXPORT_TEXT_BYTES {
                    return Err(invalid(
                        "the export is over 8 MiB; give `path` to write it to a file",
                    ));
                }
                Ok(SymbolsExportOut {
                    format: args.format,
                    count,
                    path: None,
                    text: Some(text),
                })
            }
        }
    }
}
