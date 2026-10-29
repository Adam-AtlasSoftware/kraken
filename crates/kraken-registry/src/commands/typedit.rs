//! `type_define`, `type_edit_field` and `type_delete`: types are edits. Each change is one
//! `DefineType` entry in the edit log (the whole definition before and after), so it can be
//! undone, is replayed when the project is reopened and reaches the engine like any other edit.

use std::cell::RefCell;
use std::collections::BTreeMap;

use async_trait::async_trait;
use kraken_engine::{Cap, TypeStore, unsupported};
use kraken_model::StateValue;
use kraken_proto::cdecl::{CContext, CParseError, parse_declarations, parse_type, relayout};
use kraken_proto::{ErrorCode, LogOp, ProtoError, TypeDef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::mutate::submit;
use crate::session::{Project, Session};
use crate::validate::validate_name;
use crate::views::MutationOutput;

/// Longest C text `type_define` takes.
const MAX_DECL_BYTES: usize = 64 * 1024;
/// Most definitions one `type_define` call creates.
const MAX_DEFS: usize = 64;
/// Most fields a struct or union defined here may have.
const MAX_FIELDS: usize = 1024;

fn invalid(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, m)
}

fn parse_error(e: CParseError) -> ProtoError {
    invalid(e.to_string()).with_details(json!({ "line": e.line, "column": e.column }))
}

/// Pointer and `long` sizes from the architecture id and container format.
fn sizes(project: &Project) -> (u32, u32) {
    let info = project.program();
    let ptr = if info.arch.contains(":64:") || info.arch.to_ascii_uppercase().starts_with("AARCH64")
    {
        8
    } else {
        4
    };
    let long = if ptr == 4 || info.format == "pe" {
        4
    } else {
        8
    };
    (ptr, long)
}

/// Runs `f` with a lookup into the engine's types, fetching the types it turns out to need.
async fn with_lookup<T>(
    store: &dyn TypeStore,
    ctx: &CallContext,
    sizes: (u32, u32),
    f: impl Fn(&CContext<'_>) -> Result<T, CParseError>,
) -> Result<T, ProtoError> {
    let mut cache: BTreeMap<String, Option<TypeDef>> = BTreeMap::new();
    for _ in 0..MAX_DEFS {
        // the closures live in this block so that none is held across an await
        let (result, missed) = {
            let missed: RefCell<Option<String>> = RefCell::default();
            let lookup = |n: &str| {
                let hit = cache.get(n).cloned();
                if hit.is_none() {
                    *missed.borrow_mut() = Some(n.to_string());
                }
                hit.flatten()
            };
            let cx = CContext {
                pointer_size: sizes.0,
                long_size: sizes.1,
                lookup: &lookup,
            };
            let r = f(&cx);
            (r, missed.into_inner())
        };
        match result {
            Ok(v) => return Ok(v),
            Err(e) => {
                let Some(name) = missed.filter(|n| !cache.contains_key(n)) else {
                    return Err(parse_error(e));
                };
                let found = match store.get_type(&name, &ctx.cancel).await {
                    Ok(d) => Some(d),
                    Err(err) if err.code == ErrorCode::NotFound => None,
                    Err(err) => return Err(err),
                };
                cache.insert(name, found);
            }
        }
    }
    Err(invalid("the declaration refers to too many other types"))
}

/// What the project has under `name` now: the log's definition, else the engine's.
async fn current(
    project: &Project,
    store: &dyn TypeStore,
    ctx: &CallContext,
    name: &str,
) -> Result<Option<TypeDef>, ProtoError> {
    let key = format!("type:{name}");
    if let Some(StateValue::TypeDef { def }) = project
        .with_store(move |st| Ok(st.current_state()?.get(&key).cloned()))
        .await?
    {
        return Ok(Some(def));
    }
    match store.get_type(name, &ctx.cancel).await {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.code == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn check_names(def: &TypeDef, who: kraken_model::AuthorKind) -> Result<(), ProtoError> {
    if let Some(n) = def.name() {
        validate_name("type name", n, who)?;
    }
    if let TypeDef::Struct(c) | TypeDef::Union(c) = def {
        if c.fields.len() > MAX_FIELDS {
            return Err(invalid(format!("more than {MAX_FIELDS} fields")));
        }
        for f in &c.fields {
            validate_name("field name", &f.name, who)?;
        }
    }
    Ok(())
}

async fn submit_define(
    s: &Session,
    ctx: &CallContext,
    store: &dyn TypeStore,
    name: String,
    new: Option<TypeDef>,
) -> Result<MutationOutput, ProtoError> {
    let project = s.project()?;
    let old = current(&project, store, ctx, &name).await?;
    let op = LogOp::DefineType { name, old, new };
    submit(s, ctx, op, None).await
}

/// Arguments of `type_define`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeDefineArgs {
    /// C declarations: `struct`, `union`, `enum`, `typedef` (function-pointer typedefs too) and
    /// function prototypes, without preprocessor lines or bitfields.
    pub c_declaration: String,
}

/// What `type_define` created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TypeDefineOut {
    /// Names of the declared types, in declaration order.
    pub types: Vec<String>,
    /// One edit per type, in the same order.
    pub edits: Vec<MutationOutput>,
}

/// Defines types from C declarations.
pub struct TypeDefine;

#[async_trait]
impl Command for TypeDefine {
    type Args = TypeDefineArgs;
    type Output = TypeDefineOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "type_define",
            "Define structs, unions, enums and typedefs from C declarations",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Parses the C text, lays structs out naturally for the program's architecture and \
             records one undoable edit per type. Then `set_type` with `type_name` applies a type \
             to an address. A new name applies at once, even for an agent; replacing an existing \
             type becomes a proposal for an agent. A parse error names the line and column.\n\
             Example: type_define {\"c_declaration\": \"struct packet { unsigned short len; char tag; int *data; };\"}",
        )
        .details(
            "Supported: scalar types (`unsigned long`, `uint32_t`, `size_t`, ...), pointers, \
             arrays, `struct`/`union`/`enum` bodies, `typedef`, function-pointer typedefs and \
             function prototypes. A struct that holds another type by value needs that type \
             defined first (in the same text or earlier). The decompiler reads a type once: a \
             redefined type shows its new layout in listings and `type_get`, while the \
             decompiler of a running native engine keeps the old one until the project is \
             reopened.",
        )
        .needs(&[Cap::TypeStore, Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: TypeDefineArgs,
    ) -> Result<TypeDefineOut, ProtoError> {
        if args.c_declaration.len() > MAX_DECL_BYTES {
            return Err(invalid(format!(
                "the declaration is over {MAX_DECL_BYTES} bytes"
            )));
        }
        let project = s.project()?;
        let engine = project.engine();
        let store = engine
            .type_store()
            .ok_or_else(|| unsupported("type_store"))?;
        let sz = sizes(&project);
        let text = args.c_declaration;
        let defs = with_lookup(store, ctx, sz, |cx| parse_declarations(&text, cx)).await?;
        if defs.len() > MAX_DEFS {
            return Err(invalid(format!("more than {MAX_DEFS} declarations")));
        }
        for d in &defs {
            check_names(d, ctx.author.kind)?;
        }
        let mut out = TypeDefineOut {
            types: Vec::new(),
            edits: Vec::new(),
        };
        for def in defs {
            let name = def.name().unwrap_or_default().to_string();
            let edit = submit_define(s, ctx, store, name.clone(), Some(def)).await?;
            out.types.push(name);
            out.edits.push(edit);
        }
        Ok(out)
    }
}

/// Arguments of `type_edit_field`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeEditFieldArgs {
    /// The struct or union.
    pub type_name: String,
    /// The field to change.
    pub field: String,
    /// New field name.
    #[serde(default)]
    pub new_name: Option<String>,
    /// New field type as C text, such as `unsigned int *` or `char[16]`; the struct is laid out
    /// again.
    #[serde(default)]
    pub new_type: Option<String>,
}

/// Renames a field or changes its type.
pub struct TypeEditField;

#[async_trait]
impl Command for TypeEditField {
    type Args = TypeEditFieldArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "type_edit_field",
            "Rename a field of a struct or union, or change its type",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Changes one field and records the whole new definition as an undoable edit. A new \
             type lays the fields out again with natural alignment, which moves later fields. \
             An agent's change becomes a proposal.\n\
             Example: type_edit_field {\"type_name\": \"packet\", \"field\": \"len\", \"new_name\": \"length\", \"new_type\": \"unsigned int\"}",
        )
        .needs(&[Cap::TypeStore, Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: TypeEditFieldArgs,
    ) -> Result<MutationOutput, ProtoError> {
        if args.new_name.is_none() && args.new_type.is_none() {
            return Err(invalid("give `new_name`, `new_type` or both"));
        }
        let project = s.project()?;
        let engine = project.engine();
        let store = engine
            .type_store()
            .ok_or_else(|| unsupported("type_store"))?;
        let mut def = current(&project, store, ctx, &args.type_name)
            .await?
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::NotFound,
                    format!("no type named {}", args.type_name),
                )
            })?;
        let union = matches!(def, TypeDef::Union(_));
        let (TypeDef::Struct(c) | TypeDef::Union(c)) = &mut def else {
            return Err(invalid("only structs and unions have fields"));
        };
        let at = c
            .fields
            .iter()
            .position(|f| f.name == args.field)
            .ok_or_else(|| {
                ProtoError::new(ErrorCode::NotFound, format!("no field {}", args.field))
            })?;
        if let Some(n) = &args.new_name {
            validate_name("field name", n, ctx.author.kind)?;
            if *n != args.field && c.fields.iter().any(|f| f.name == *n) {
                return Err(invalid(format!("the type already has a field {n}")));
            }
            c.fields[at].name = n.clone();
        }
        if let Some(text) = &args.new_type {
            let sz = sizes(&project);
            let ty = with_lookup(store, ctx, sz, |cx| parse_type(text, cx)).await?;
            c.fields[at].ty = ty;
            let before = c.clone();
            *c = with_lookup(store, ctx, sz, |cx| {
                let mut laid = before.clone();
                relayout(&mut laid, union, cx).map(|()| laid)
            })
            .await?;
        }
        submit_define(s, ctx, store, args.type_name, Some(def)).await
    }
}

/// Arguments of `type_delete`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeDeleteArgs {
    /// The type to remove.
    pub name: String,
}

/// Deletes a type.
pub struct TypeDelete;

#[async_trait]
impl Command for TypeDelete {
    type Args = TypeDeleteArgs;
    type Output = MutationOutput;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "type_delete",
            "Delete a type",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Removes the type from the program and records an undoable edit that brings it \
             back. Items already given the type keep it by name. An agent's deletion becomes a \
             proposal.\n\
             Example: type_delete {\"name\": \"packet\"}",
        )
        .needs(&[Cap::TypeStore, Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: TypeDeleteArgs,
    ) -> Result<MutationOutput, ProtoError> {
        let project = s.project()?;
        let engine = project.engine();
        let store = engine
            .type_store()
            .ok_or_else(|| unsupported("type_store"))?;
        let name = validate_name("type name", &args.name, ctx.author.kind)?;
        if current(&project, store, ctx, &name).await?.is_none() {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no type named {name}"),
            ));
        }
        submit_define(s, ctx, store, name, None).await
    }
}
