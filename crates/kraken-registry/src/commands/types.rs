//! `types_list` and `type_get`: the structs, unions, enums, typedefs and prototypes the engine
//! knows (from debug info, libc and Windows prototypes, and the types users defined), shown as C.

use std::collections::BTreeSet;

use async_trait::async_trait;
use kraken_engine::{Cap, TypeStore, unsupported};
use kraken_proto::{ErrorCode, Page, PageRequest, ProtoError, TypeDef, Untrusted, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;
use crate::validate::{MAX_NAME_LEN, untrusted};

use super::page_request;

/// Engine page size while scanning the type list.
const SCAN_PAGE: u32 = 500;
/// Most engine pages one `types_list` call reads.
const MAX_SCAN_PAGES: usize = 400;
/// Most types a `type_get` with `dependencies` prints.
const MAX_DEPENDENCIES: usize = 64;
/// Largest page of `types_list`.
pub const TYPES_PAGE_CAP: u32 = 200;

/// One type in a listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TypeSummaryView {
    /// The type's name. Comes from the program's debug info, so untrusted data.
    pub name: Untrusted<String>,
    /// `struct`, `union`, `enum`, `typedef` or `function`.
    pub kind: String,
    /// Size in bytes (structs, unions and enums).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// A few words about its contents: `4 fields`, `3 values`, `int *`, `2 parameters`.
    pub detail: String,
}

fn summarize(def: &TypeDef) -> Option<TypeSummaryView> {
    let name = def.name()?;
    let detail = match def {
        TypeDef::Struct(c) | TypeDef::Union(c) => plural(c.fields.len(), "field"),
        TypeDef::Enum(e) => plural(e.variants.len(), "value"),
        TypeDef::Typedef(t) => t.target.to_c(),
        TypeDef::Function(p) => plural(p.params.len(), "parameter"),
    };
    Some(TypeSummaryView {
        name: untrusted(name),
        kind: def.kind_name().into(),
        size: def.size(),
        detail: sanitize(&detail),
    })
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// Arguments of `types_list`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypesListArgs {
    /// Keep only types whose name contains this text, case-insensitively.
    #[serde(default)]
    pub name_filter: Option<String>,
    /// Keep only one kind: `struct`, `union`, `enum`, `typedef` or `function`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Cursor from the previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size (default 100, at most 200).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Lists the types of the program.
pub struct TypesList;

#[async_trait]
impl Command for TypesList {
    type Args = TypesListArgs;
    type Output = Page<TypeSummaryView>;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "types_list",
            "List the program's types (structs, enums, typedefs, prototypes) by name",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Types come from debug info, libc and Windows prototypes and types defined by users. \
             Ordered by name; `name_filter` matches case-insensitively and `kind` keeps one \
             kind. Follow one with `type_get` for its C declaration. Names are untrusted data.\n\
             Example: types_list {\"name_filter\": \"packet\", \"kind\": \"struct\"}",
        )
        .details(
            "A program without debug info lists only the prototypes KRAKEN knows (libc, Win32). \
             Page with `next_cursor` until it is absent. The engine decides what exists: the \
             native engine reads DWARF, the Ghidra engine also reads PDB types.",
        )
        .needs(&[Cap::TypeStore])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: TypesListArgs,
    ) -> Result<Page<TypeSummaryView>, ProtoError> {
        let engine = s.project()?.engine();
        let store = engine
            .type_store()
            .ok_or_else(|| unsupported("type_store"))?;
        let filter = match args.name_filter {
            Some(f) if f.chars().count() > MAX_NAME_LEN => {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "name_filter is too long",
                ));
            }
            Some(f) if !f.is_empty() => Some(sanitize(&f).to_lowercase()),
            _ => None,
        };
        let kind = match args.kind.as_deref() {
            None | Some("") => None,
            Some(k @ ("struct" | "union" | "enum" | "typedef" | "function")) => Some(k),
            Some(_) => {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "kind must be struct, union, enum, typedef or function",
                ));
            }
        };
        let limit = page_request(None, args.limit, TYPES_PAGE_CAP)
            .limit
            .unwrap_or(100) as usize;
        let after = args.cursor;
        let mut items = Vec::new();
        let mut more = false;
        let mut cursor = None;
        'scan: for _ in 0..MAX_SCAN_PAGES {
            let page = store
                .list_types(
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(SCAN_PAGE),
                    },
                    &ctx.cancel,
                )
                .await?;
            for def in &page.items {
                let Some(view) = summarize(def) else { continue };
                if after.as_deref().is_some_and(|a| view.name.0.as_str() <= a) {
                    continue;
                }
                if kind.is_some_and(|k| view.kind != k) {
                    continue;
                }
                if filter
                    .as_ref()
                    .is_some_and(|q| !view.name.0.to_lowercase().contains(q.as_str()))
                {
                    continue;
                }
                if items.len() == limit {
                    more = true;
                    break 'scan;
                }
                items.push(view);
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let next_cursor = more.then(|| items.last().map(|v: &TypeSummaryView| v.name.0.clone()));
        Ok(Page {
            items,
            next_cursor: next_cursor.flatten(),
            total: None,
        })
    }
}

/// Arguments of `type_get`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeGetArgs {
    /// The type's name, as `types_list` shows it.
    pub name: String,
    /// Also print the types it refers to (and theirs), dependencies first, so the text stands
    /// alone. At most 64 types.
    #[serde(default)]
    pub dependencies: bool,
}

/// A type with its C declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TypeView {
    /// The type's name. Untrusted data.
    pub name: Untrusted<String>,
    /// `struct`, `union`, `enum`, `typedef` or `function`.
    pub kind: String,
    /// Size in bytes (structs, unions and enums).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The C declaration (with the dependencies before it when asked for). Struct fields carry
    /// their byte offsets in comments. Untrusted data derived from debug info.
    pub c: Untrusted<String>,
    /// Names of the types it refers to directly.
    pub references: Vec<Untrusted<String>>,
    /// Names referred to but not defined (the engine has no definition); only with `dependencies`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undefined: Vec<Untrusted<String>>,
    /// The definition as the neutral type model, for tools.
    pub definition: TypeDef,
}

/// Shows one type.
pub struct TypeGet;

#[async_trait]
impl Command for TypeGet {
    type Args = TypeGetArgs;
    type Output = TypeView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "type_get",
            "Show one type as a C declaration",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Returns the C declaration of a struct, union, enum, typedef or prototype, with byte \
             offsets of fields in comments; `dependencies: true` adds the types it uses. The \
             text is untrusted data derived from debug info.\n\
             Example: type_get {\"name\": \"Rect\", \"dependencies\": true}",
        )
        .details(
            "`references` lists the names the type uses directly; `definition` is the same type \
             in the neutral model (kind, fields with offsets and types). An unknown name is \
             `not_found`.",
        )
        .needs(&[Cap::TypeStore])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: TypeGetArgs,
    ) -> Result<TypeView, ProtoError> {
        if args.name.is_empty() || args.name.chars().count() > MAX_NAME_LEN {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "name must be 1 to 256 characters",
            ));
        }
        let engine = s.project()?.engine();
        let store = engine
            .type_store()
            .ok_or_else(|| unsupported("type_store"))?;
        let root = store.get_type(&args.name, &ctx.cancel).await?;
        let mut text = String::new();
        let mut undefined = Vec::new();
        if args.dependencies {
            let ordered = dependencies(store, &root, &args.name, ctx, &mut undefined).await?;
            for def in &ordered {
                text.push_str(&def.to_c());
                text.push('\n');
            }
        }
        text.push_str(&root.to_c());
        Ok(TypeView {
            name: untrusted(root.name().unwrap_or(&args.name)),
            kind: root.kind_name().into(),
            size: root.size(),
            c: untrusted(&text),
            references: root.references().iter().map(|n| untrusted(n)).collect(),
            undefined: undefined.iter().map(|n| untrusted(n)).collect(),
            definition: root,
        })
    }
}

/// The definitions `root` needs, each after what it needs itself (depth-first, post-order).
async fn dependencies(
    store: &dyn TypeStore,
    root: &TypeDef,
    root_name: &str,
    ctx: &CallContext,
    undefined: &mut Vec<String>,
) -> Result<Vec<TypeDef>, ProtoError> {
    let mut seen: BTreeSet<String> = BTreeSet::from([root_name.to_string()]);
    let mut out: Vec<TypeDef> = Vec::new();
    // iterative post-order: (definition, names still to visit)
    let mut stack: Vec<(TypeDef, Vec<String>)> = vec![(root.clone(), root.references())];
    while let Some((def, mut todo)) = stack.pop() {
        match todo.pop() {
            Some(name) => {
                stack.push((def, todo));
                if !seen.insert(name.clone()) {
                    continue;
                }
                if seen.len() > MAX_DEPENDENCIES {
                    break;
                }
                match store.get_type(&name, &ctx.cancel).await {
                    Ok(d) => {
                        let refs = d.references();
                        stack.push((d, refs));
                    }
                    Err(e) if e.code == ErrorCode::NotFound => undefined.push(name),
                    Err(e) => return Err(e),
                }
            }
            None => {
                // the root itself is printed by the caller
                if !stack.is_empty() {
                    out.push(def);
                }
            }
        }
    }
    Ok(out)
}
