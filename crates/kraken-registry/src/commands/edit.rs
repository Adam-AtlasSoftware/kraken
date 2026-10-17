//! Edit commands: rename, comment, type, calling convention, function structure, undo and
//! proposal decisions. All of them go through the mutation pipeline.

use std::collections::BTreeMap;

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_model::{AuthorKind, EntryId, ProposalId, ProposalStatus, RunId, StateValue, op_key};
use kraken_proto::{
    AddressRange, CommentKind, ErrorCode, FunctionPrototype, Hex64, LogOp, ProtoError, TypeRef,
    VersionedLogOp, sanitize,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::mutate::{
    self, Resolved, anchor_for, engine_rejected, managed_anchor_for, submit, submit_as,
};
use crate::session::{Project, Session};
use crate::validate::{clean_comment, validate_name};
use crate::views::{MutationOutput, MutationStatus, ProposalOut, locator_parts};

use super::NoArgs;
use super::rebuild::DriftEntry;
use super::undo_entry::refresh_after_undo;

const MAX_TYPE_DEPTH: usize = 16;
const MAX_PARAMS: usize = 64;

const EXPECT_DOC: &str = "Entity versions the edit is based on, as returned by `get_function`; \
    absent means the current version. A stale version is rejected with `conflict_stale_read`.";

async fn state_value(project: &Project, key: String) -> Result<Option<StateValue>, ProtoError> {
    project
        .with_store(move |st| Ok(st.current_state()?.get(&key).cloned()))
        .await
}

/// The function whose entry is exactly `address`, if the engine found one.
fn function_at(r: &Resolved, address: Hex64) -> Option<&kraken_proto::FunctionSummary> {
    r.function
        .as_ref()
        .filter(|f| locator_parts(&f.locator).1 == address)
}

fn function_range(f: &kraken_proto::FunctionSummary) -> Option<AddressRange> {
    let (space, start) = locator_parts(&f.locator);
    f.size.map(|n| AddressRange {
        space,
        start,
        end: Hex64(start.0.saturating_add(n)),
    })
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Arguments of `rename_symbol`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameSymbolArgs {
    /// Address of the function (or label), as `0x...`.
    pub address: Hex64,
    /// The new name. Agents: `[A-Za-z_][A-Za-z0-9_:.$@<>~]*`, at most 200 characters. In a .NET
    /// assembly the name must be a plain C# identifier.
    pub new_name: String,
    /// Module id (MVID) of a .NET entity; `address` is then its metadata token (method, type,
    /// field or parameter). Leave out for native code.
    #[serde(default)]
    pub module: Option<String>,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Renames a function or label.
pub struct RenameSymbol;

#[async_trait]
impl Command for RenameSymbol {
    type Args = RenameSymbolArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rename_symbol",
            "Rename a function or label",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Agents auto-apply renames only on symbols that still have a default name \
             (`FUN_...`); anything else becomes a proposal. Result `status`: `applied`, \
             `queued` (analysis running) or `proposed`.",
        )
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RenameSymbolArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let name = validate_name("new_name", &args.new_name, ctx.author.kind)?;
        let r = match args.module.as_deref() {
            Some(m) => managed_anchor_for(&project, ctx, args.address, m).await?,
            None => anchor_for(&project, ctx, args.address).await?,
        };
        let old_name = function_at(&r, args.address).map(|f| f.name.clone());
        let op = LogOp::Rename {
            anchor: r.anchor,
            old_name,
            new_name: name,
        };
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// Arguments of `set_comment`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCommentArgs {
    /// Address the comment attaches to, as `0x...`.
    pub address: Hex64,
    /// Comment slot: `plate`, `pre`, `eol`, `post` or `repeatable`.
    pub kind: CommentKind,
    /// Comment text, at most 4096 characters; empty clears the comment.
    pub text: String,
    /// Module id (MVID) of a .NET method; `address` is then its metadata token. Leave out for
    /// native code.
    #[serde(default)]
    pub module: Option<String>,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Sets or clears a comment.
pub struct SetComment;

#[async_trait]
impl Command for SetComment {
    type Args = SetCommentArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "set_comment",
            "Set or clear a comment at an address",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Agents auto-apply only new comments; replacing or clearing one becomes a proposal. \
             Control and escape characters are stripped from the text.",
        )
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SetCommentArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let clean = clean_comment(&args.text)?;
        let r = match args.module.as_deref() {
            Some(m) => managed_anchor_for(&project, ctx, args.address, m).await?,
            None => anchor_for(&project, ctx, args.address).await?,
        };
        let mut op = LogOp::SetComment {
            anchor: r.anchor,
            comment_kind: args.kind,
            old: None,
            new: (!clean.is_empty()).then_some(clean),
        };
        if let Some(StateValue::Comment { text }) = state_value(&project, op_key(&op)?).await?
            && let LogOp::SetComment { old, .. } = &mut op
        {
            *old = Some(text);
        }
        submit(s, ctx, op, args.expect_versions).await
    }
}

fn check_type_ref(t: &TypeRef, who: AuthorKind, depth: usize) -> Result<(), ProtoError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(invalid("type is nested too deeply"));
    }
    match t {
        TypeRef::Named { name } => validate_name("type name", name, who).map(|_| ()),
        TypeRef::Primitive(_) => Ok(()),
        TypeRef::Pointer { target, .. } => check_type_ref(target, who, depth + 1),
        TypeRef::Array { element, .. } => check_type_ref(element, who, depth + 1),
        TypeRef::Function(p) => check_prototype(p, who, depth + 1),
    }
}

fn check_prototype(p: &FunctionPrototype, who: AuthorKind, depth: usize) -> Result<(), ProtoError> {
    if p.params.len() > MAX_PARAMS {
        return Err(invalid(format!("more than {MAX_PARAMS} parameters")));
    }
    if let Some(n) = &p.name {
        validate_name("prototype name", n, who)?;
    }
    if !p.calling_convention.is_empty() {
        validate_name("calling convention", &p.calling_convention, who)?;
    }
    check_type_ref(&p.return_type, who, depth + 1)?;
    for param in &p.params {
        if let Some(n) = &param.name {
            validate_name("parameter name", n, who)?;
        }
        if let Some(st) = &param.storage
            && sanitize(st) != *st
        {
            return Err(invalid("parameter storage contains control characters"));
        }
        check_type_ref(&param.ty, who, depth + 1)?;
    }
    Ok(())
}

/// Arguments of `set_type`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetTypeArgs {
    /// Address of the function or data item, as `0x...`.
    pub address: Hex64,
    /// A function prototype in the neutral type model (give this or `type_name`).
    #[serde(default)]
    pub prototype: Option<FunctionPrototype>,
    /// The name of an existing type (give this or `prototype`).
    #[serde(default)]
    pub type_name: Option<String>,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Sets the type of a function or data item.
pub struct SetType;

#[async_trait]
impl Command for SetType {
    type Args = SetTypeArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "set_type",
            "Set the prototype of a function or the type of a data item",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Give exactly one of `prototype` (a neutral function prototype: return_type, params, \
             calling_convention, varargs, noreturn) or `type_name`. Agents auto-apply only on \
             items that have no type recorded yet.",
        )
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SetTypeArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let who = ctx.author.kind;
        let new = match (args.prototype, args.type_name) {
            (Some(p), None) => {
                check_prototype(&p, who, 0)?;
                TypeRef::Function(Box::new(p))
            }
            (None, Some(name)) => {
                validate_name("type_name", &name, ctx.author.kind)?;
                TypeRef::Named { name }
            }
            _ => return Err(invalid("give exactly one of `prototype` and `type_name`")),
        };
        let r = anchor_for(&project, ctx, args.address).await?;
        let mut op = LogOp::SetType {
            anchor: r.anchor,
            old: None,
            new,
        };
        if let Some(StateValue::Type { ty }) = state_value(&project, op_key(&op)?).await?
            && let LogOp::SetType { old, .. } = &mut op
        {
            *old = Some(ty);
        }
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// Arguments of `set_calling_convention`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCallingConventionArgs {
    /// Address of the function, as `0x...`.
    pub address: Hex64,
    /// Calling convention name such as `__cdecl` or `__stdcall`.
    pub convention: String,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Sets a function's calling convention.
pub struct SetCallingConvention;

#[async_trait]
impl Command for SetCallingConvention {
    type Args = SetCallingConventionArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "set_calling_convention",
            "Set a function's calling convention",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SetCallingConventionArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let convention = validate_name("convention", &args.convention, ctx.author.kind)?;
        let r = anchor_for(&project, ctx, args.address).await?;
        if function_at(&r, args.address).is_none() {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function at {}", args.address),
            ));
        }
        let mut op = LogOp::SetCallingConvention {
            anchor: r.anchor,
            old: None,
            new: convention,
        };
        if let Some(StateValue::CallingConvention { name }) =
            state_value(&project, op_key(&op)?).await?
            && let LogOp::SetCallingConvention { old, .. } = &mut op
        {
            *old = Some(name);
        }
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// Arguments of `create_function`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateFunctionArgs {
    /// Entry address of the new function, as `0x...`.
    pub address: Hex64,
    /// Name for the function; the engine picks a default when absent.
    #[serde(default)]
    pub name: Option<String>,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Creates a function.
pub struct CreateFunction;

#[async_trait]
impl Command for CreateFunction {
    type Args = CreateFunctionArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "create_function",
            "Create a function at an address",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc("Structural edit: agents' creations always become proposals for a user to accept.")
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: CreateFunctionArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let name = args
            .name
            .as_deref()
            .map(|n| validate_name("name", n, ctx.author.kind))
            .transpose()?;
        let r = anchor_for(&project, ctx, args.address).await?;
        if let Some(f) = &r.function {
            return Err(invalid(format!(
                "a function already contains {} (entry {})",
                args.address,
                locator_parts(&f.locator).1
            )));
        }
        let op = LogOp::CreateFunction {
            anchor: r.anchor,
            name,
            body: None,
        };
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// Arguments of `delete_function`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteFunctionArgs {
    /// Entry address of the function, as `0x...`.
    pub address: Hex64,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Deletes a function.
pub struct DeleteFunction;

#[async_trait]
impl Command for DeleteFunction {
    type Args = DeleteFunctionArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "delete_function",
            "Delete a function (its code stays)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc("Structural edit: agents' deletions always become proposals for a user to accept.")
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: DeleteFunctionArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let r = anchor_for(&project, ctx, args.address).await?;
        let Some(f) = function_at(&r, args.address) else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function starts at {}", args.address),
            ));
        };
        let op = LogOp::DeleteFunction {
            old_body: function_range(f),
            anchor: r.anchor,
        };
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// Arguments of `set_function_bounds`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetFunctionBoundsArgs {
    /// Entry address of the function, as `0x...`.
    pub address: Hex64,
    /// First address of the new body, as `0x...`.
    pub start: Hex64,
    /// One past the last address of the new body, as `0x...`.
    pub end: Hex64,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Changes a function's address range.
pub struct SetFunctionBounds;

#[async_trait]
impl Command for SetFunctionBounds {
    type Args = SetFunctionBoundsArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "set_function_bounds",
            "Change a function's address range",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc("Structural edit: agents' changes always become proposals for a user to accept.")
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SetFunctionBoundsArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        if args.start.0 >= args.end.0 {
            return Err(invalid("`start` must be below `end`"));
        }
        let r = anchor_for(&project, ctx, args.address).await?;
        let Some(f) = function_at(&r, args.address) else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function starts at {}", args.address),
            ));
        };
        let op = LogOp::SetFunctionBounds {
            old: function_range(f),
            new: AddressRange {
                space: kraken_proto::DEFAULT_SPACE.into(),
                start: args.start,
                end: args.end,
            },
            anchor: r.anchor,
        };
        submit(s, ctx, op, args.expect_versions).await
    }
}

/// One edit the engine refused while pushing an undo.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UndoFailure {
    /// The compensating log entry.
    pub entry_id: u64,
    /// The engine's error code.
    pub code: String,
    /// The engine's reason.
    pub message: String,
}

/// Result of `undo` and `undo_run`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UndoOut {
    /// `applied` or `queued` (analysis running).
    pub status: MutationStatus,
    /// Compensating log entries, in creation order.
    pub entry_ids: Vec<u64>,
    /// Original entries that were reversed, in the same order.
    pub undone_entry_ids: Vec<u64>,
    /// Compensations the engine refused; the model still records them as undone.
    pub failed: Vec<UndoFailure>,
    /// Functions whose derived data is now stale (a type or signature edit was undone); they
    /// were re-decompiled and stay listed by `tainted_list` until `tainted_clear`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tainted: Vec<Hex64>,
    /// Where the engine disagrees with the log for those functions after the undo.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift: Vec<DriftEntry>,
}

pub(crate) async fn finish_undo(
    ctx: &CallContext,
    project: &Project,
    ids: Vec<EntryId>,
) -> Result<UndoOut, ProtoError> {
    let originals = {
        let ids = ids.clone();
        project
            .with_store(move |st| {
                ids.iter()
                    .map(|i| Ok(st.get_entry(*i)?.undoes_entry_id.map(|o| o.0).unwrap_or(0)))
                    .collect::<Result<Vec<_>, ProtoError>>()
            })
            .await?
    };
    let settled = mutate::settle(project, ctx, &ids).await?;
    let (tainted, drift) = if settled.status == MutationStatus::Applied {
        refresh_after_undo(ctx, project, &ids).await
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(UndoOut {
        status: settled.status,
        entry_ids: ids.iter().map(|i| i.0).collect(),
        undone_entry_ids: originals,
        failed: settled
            .failed
            .iter()
            .map(|(id, e)| {
                let e = engine_rejected(*id, e);
                UndoFailure {
                    entry_id: id.0,
                    code: e
                        .details
                        .as_ref()
                        .and_then(|d| d["engine_code"].as_str())
                        .unwrap_or("engine_rejected")
                        .to_string(),
                    message: e.message,
                }
            })
            .collect(),
        tainted,
        drift,
    })
}

/// Undoes the caller's last edit.
pub struct Undo;

#[async_trait]
impl Command for Undo {
    type Args = NoArgs;
    type Output = UndoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "undo",
            "Undo the caller's most recent edit",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Appends a compensating log entry and pushes it to the engine. Each author undoes \
             only their own edits; run it again to step further back. Derived data (decompiler \
             output) is re-read on demand and may be stale until then.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<UndoOut, ProtoError> {
        let project = s.project()?;
        let _write = project.write_lock.lock().await;
        let author = ctx.author.clone();
        let id = project.with_store(move |st| st.undo_last(&author)).await?;
        finish_undo(ctx, &project, vec![id]).await
    }
}

/// Arguments of `undo_run`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoRunArgs {
    /// The run whose edits to reverse, newest first.
    pub run_id: String,
}

/// Undoes every edit of a run.
pub struct UndoRun;

#[async_trait]
impl Command for UndoRun {
    type Args = UndoRunArgs;
    type Output = UndoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "undo_run",
            "Undo every edit of an agent run, newest first",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Reverses all applied, not yet undone edits that carry the run id in reverse order, \
             as compensating entries authored by the caller. Open proposals of the run are left \
             alone.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: UndoRunArgs,
    ) -> Result<UndoOut, ProtoError> {
        let project = s.project()?;
        let _write = project.write_lock.lock().await;
        let author = ctx.author.clone();
        let run = RunId(args.run_id);
        let ids = project
            .with_store(move |st| st.undo_run(&run, &author))
            .await?;
        finish_undo(ctx, &project, ids).await
    }
}

/// Arguments naming a proposal.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalIdArgs {
    /// Proposal id from `proposals_list`.
    pub id: u64,
}

fn require_user(ctx: &CallContext, what: &str) -> Result<(), ProtoError> {
    if ctx.author.kind == AuthorKind::User {
        Ok(())
    } else {
        Err(ProtoError::new(
            ErrorCode::RejectedHumanPriority,
            format!("{what} is reserved for users; agents cannot decide on proposals"),
        ))
    }
}

/// Accepts a proposal and applies it.
pub struct ProposalAccept;

#[async_trait]
impl Command for ProposalAccept {
    type Args = ProposalIdArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "proposal_accept",
            "Accept an agent proposal and apply it as the caller (users only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Applies the proposed edit as a user edit under the proposal's run id, then marks the \
             proposal accepted. If the engine refuses it the proposal stays open.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ProposalIdArgs,
    ) -> Result<MutationOutput, ProtoError> {
        require_user(ctx, "accepting a proposal")?;
        let project = s.project()?;
        let id = ProposalId(args.id);
        let proposal = project.with_store(move |st| st.get_proposal(id)).await?;
        if proposal.status != ProposalStatus::Open {
            return Err(invalid(format!(
                "proposal {} is already {}",
                args.id,
                proposal.status.as_str()
            )));
        }
        let VersionedLogOp { op, .. } = proposal.op;
        let out = submit_as(s, ctx, op, None, proposal.run_id).await?;
        project.with_store(move |st| st.accept_proposal(id)).await?;
        Ok(out)
    }
}

/// Rejects a proposal.
pub struct ProposalReject;

#[async_trait]
impl Command for ProposalReject {
    type Args = ProposalIdArgs;
    type Output = ProposalOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "proposal_reject",
            "Reject an agent proposal (users only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ProposalIdArgs,
    ) -> Result<Self::Output, ProtoError> {
        require_user(ctx, "rejecting a proposal")?;
        let project = s.project()?;
        let id = ProposalId(args.id);
        let p = project.with_store(move |st| st.reject_proposal(id)).await?;
        Ok((&p).into())
    }
}

trait SpecExt {
    fn doc_expect(self) -> Self;
}

impl SpecExt for CommandSpec {
    /// Appends the shared `expect_versions` note to the long doc.
    fn doc_expect(mut self) -> Self {
        if !self.doc.is_empty() {
            self.doc.push_str("\n\n");
        }
        self.doc.push_str(EXPECT_DOC);
        self
    }
}
