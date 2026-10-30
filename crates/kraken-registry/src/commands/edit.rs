//! Edit commands: rename, comment, type, calling convention, function structure, undo and
//! proposal decisions. All of them go through the mutation pipeline.

use std::collections::BTreeMap;

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_model::{AuthorKind, EntryId, ProposalId, ProposalStatus, RunId, StateValue, op_key};
use kraken_proto::{
    AddressRange, CommentKind, ErrorCode, FunctionPrototype, Hex64, LocalSpec, LogOp, ProtoError,
    TypeRef, VersionedLogOp, sanitize,
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
            "Gives a function or label a meaningful name. An agent's rename applies at once only \
             on a default name (`FUN_...`); renaming anything else becomes a proposal for a \
             person. `status` is `applied`, `queued` (analysis running) or `proposed`. Name \
             what the code does, e.g. `parse_header`.\n\
             Example: rename_symbol {\"address\": \"0x401136\", \"new_name\": \"parse_header\"}",
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
            "Adds a comment that shows in the listing and decompile. An agent's new comment \
             applies at once; replacing or clearing one becomes a proposal. Use `plate` for a \
             function header, `eol` for one line. Empty `text` clears it.\n\
             Example: set_comment {\"address\": \"0x401136\", \"kind\": \"plate\", \"text\": \"Parses the config file\"}",
        )
        .details("Control and escape characters are stripped from the text.")
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
    /// A data type in the neutral type model, such as a pointer or an array (give exactly one of
    /// `prototype`, `type_name` and `data_type`).
    #[serde(default)]
    pub data_type: Option<TypeRef>,
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
            "Fixes what the decompiler shows for a function's signature or a data item. Give \
             exactly one of `prototype`, `type_name` or `data_type`. An agent applies it at once only where \
             no type is recorded yet; otherwise it becomes a proposal.\n\
             Example: set_type {\"address\": \"0x404040\", \"type_name\": \"config_t\"}",
        )
        .details(
            "A prototype is the neutral function model: `return_type`, `params` (each with \
             `name` and `type`), `calling_convention`, `varargs`, `noreturn`; types are tagged \
             with `kind` (`primitive`, `named`, `pointer`, `array`, `function`).",
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
        let new = match (args.prototype, args.type_name, args.data_type) {
            (Some(p), None, None) => {
                check_prototype(&p, who, 0)?;
                TypeRef::Function(Box::new(p))
            }
            (None, Some(name), None) => {
                validate_name("type_name", &name, ctx.author.kind)?;
                TypeRef::Named { name }
            }
            (None, None, Some(t)) => {
                check_type_ref(&t, who, 0)?;
                t
            }
            _ => {
                return Err(invalid(
                    "give exactly one of `prototype`, `type_name` and `data_type`",
                ));
            }
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
        .doc(
            "Changes how the decompiler reads arguments and the return value, when a signature \
             looks wrong (a register argument missing, for instance). Re-run `decompile` to see \
             the effect.\n\
             Example: set_calling_convention {\"address\": \"0x401136\", \"convention\": \"__stdcall\"}",
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

/// Arguments of `set_local`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetLocalArgs {
    /// Entry address of the function that holds the variable, as `0x...`.
    pub address: Hex64,
    /// Where the variable lives: the `varnode` of its tokens in `decompile` without the size,
    /// such as `stack:0xffffffffffffffec` or `register:0x38`.
    pub storage: String,
    /// The new name; leave out to keep the name the variable has now.
    #[serde(default)]
    pub name: Option<String>,
    /// The name of an existing type (give at most one of `type_name` and `data_type`).
    #[serde(default)]
    pub type_name: Option<String>,
    /// A data type in the neutral type model (give at most one of `type_name` and `data_type`).
    #[serde(default)]
    pub data_type: Option<TypeRef>,
    /// Remove the override, so the decompiler names and types the variable again.
    #[serde(default)]
    pub clear: bool,
    /// Entity versions the edit is based on; see `get_function`.
    #[serde(default)]
    pub expect_versions: Option<BTreeMap<String, u64>>,
}

/// Renames or retypes a local variable or parameter of a function.
pub struct SetLocal;

#[async_trait]
impl Command for SetLocal {
    type Args = SetLocalArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "set_local",
            "Rename or retype a local variable or parameter in decompiled C",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Gives a variable of a decompiled function a name and/or a type; every later \
             `decompile` shows it. Take `storage` from the `varnode` of a variable token (drop \
             the `:size`). An agent applies it at once only on a variable nobody has named or \
             typed; changing or clearing an override becomes a proposal. Native engine only.\n\
             Example: set_local {\"address\": \"0x401136\", \"storage\": \"stack:0xfffffffffffffff0\", \"name\": \"total\"}",
        )
        .details(
            "Give `name`, a type (`type_name` or `data_type`), or both; what you leave out stays \
             as the last override (or the decompiler's choice) had it. `clear: true` removes the \
             override. A type of another size than the variable's can overlap its neighbours; \
             the decompile then warns that it was not applied. The Ghidra engine rejects the \
             edit as unsupported.",
        )
        .doc_expect()
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SetLocalArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let who = ctx.author.kind;
        let Some((space, offset)) = kraken_proto::parse_storage(&args.storage) else {
            return Err(invalid(format!(
                "{:?} is not a storage such as stack:0xfffffffffffffff0 or register:0x38",
                args.storage
            )));
        };
        if matches!(space.as_str(), "const" | "ram") {
            return Err(invalid(
                "a variable lives in a register, the stack or a temporary",
            ));
        }
        let storage = kraken_proto::storage_key(&space, offset);
        let name = match args.name.as_deref() {
            Some(n) => Some(validate_name("name", n, who)?),
            None => None,
        };
        let ty = match (args.type_name, args.data_type) {
            (Some(n), None) => {
                validate_name("type_name", &n, who)?;
                Some(TypeRef::Named { name: n })
            }
            (None, Some(t)) => {
                check_type_ref(&t, who, 0)?;
                Some(t)
            }
            (None, None) => None,
            _ => return Err(invalid("give at most one of `type_name` and `data_type`")),
        };
        if args.clear && (name.is_some() || ty.is_some()) {
            return Err(invalid("`clear` cannot come with a name or a type"));
        }
        if !args.clear && name.is_none() && ty.is_none() {
            return Err(invalid(
                "give a `name`, a `type_name` or `data_type`, or `clear`",
            ));
        }
        let r = anchor_for(&project, ctx, args.address).await?;
        if function_at(&r, args.address).is_none() {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function at {}", args.address),
            ));
        }
        let mut op = LogOp::SetLocal {
            anchor: r.anchor,
            storage,
            old: None,
            new: None,
        };
        let current = match state_value(&project, op_key(&op)?).await? {
            Some(StateValue::Local { name, ty }) => Some(LocalSpec { name, ty }),
            _ => None,
        };
        let new = (!args.clear).then(|| LocalSpec {
            name: name.or_else(|| current.as_ref().and_then(|c| c.name.clone())),
            ty: ty.or_else(|| current.as_ref().and_then(|c| c.ty.clone())),
        });
        if let LogOp::SetLocal { old, new: slot, .. } = &mut op {
            *old = current;
            *slot = new;
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
        .doc(
            "Marks code the analysis missed as a function. A structural edit: an agent's \
             version always becomes a proposal for a person to accept.\n\
             Example: create_function {\"address\": \"0x401800\", \"name\": \"handler\"}",
        )
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
        .doc(
            "Removes a wrongly detected function; the code stays. A structural edit: an agent's \
             version always becomes a proposal for a person to accept.\n\
             Example: delete_function {\"address\": \"0x401800\"}",
        )
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
        .doc(
            "Corrects where a function starts or ends when the analysis cut it wrong. A \
             structural edit: an agent's version always becomes a proposal for a person to \
             accept.\n\
             Example: set_function_bounds {\"address\": \"0x401136\", \"start\": \"0x401136\", \"end\": \"0x401180\"}",
        )
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
            "Reverses your own latest edit; call again to step further back. You cannot undo \
             someone else's edit this way. To undo one specific edit or a whole run, use \
             `undo_entry` or `undo_run`.\n\
             Example: undo {}",
        )
        .details(
            "Appends a compensating log entry and pushes it to the engine. Derived data \
             (decompiler output) is re-read on demand and may be stale until then.",
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
            "Reverses everything one agent run changed (find the `run_id` in `history`), newest \
             edit first. Open proposals of the run are left alone.\n\
             Example: undo_run {\"run_id\": \"run-7f3a\"}",
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
            "People only. Applies a proposal from `proposals_list` as the person's own edit. If \
             the engine refuses it, the proposal stays open.\n\
             Example: proposal_accept {\"id\": 3}",
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
        .doc(
            "People only. Declines a proposal from `proposals_list`; nothing is applied.\n\
             Example: proposal_reject {\"id\": 3}",
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
    /// Appends the shared `expect_versions` note to the reference text.
    fn doc_expect(mut self) -> Self {
        if !self.details.is_empty() {
            self.details.push_str("\n\n");
        }
        self.details.push_str(EXPECT_DOC);
        self
    }
}
