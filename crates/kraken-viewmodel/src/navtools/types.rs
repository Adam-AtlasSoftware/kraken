//! The Types tab: the program's structs, enums, typedefs and prototypes, with the C declaration of
//! the one picked.

use kraken_proto::{Page, TypeDef, Untrusted};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::errors::plain_error;
use crate::vm::{ViewModel, parse};

use super::parse_address;

/// Rows asked for at a time.
const PAGE: u32 = 200;

/// One type in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeItem {
    /// The type's name.
    pub name: String,
    /// `struct`, `union`, `enum`, `typedef` or `function`.
    pub kind: String,
    /// Size in bytes, where the kind has one.
    pub size: Option<u64>,
    /// A few words about its contents.
    pub detail: String,
}

/// The declaration shown on the right of the list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TypeDecl {
    /// Name of the type.
    pub name: String,
    /// Its C declaration (with the types it uses before it when asked for).
    pub c: String,
    /// Names it refers to that the engine has no definition for.
    pub undefined: Vec<String>,
    /// `struct`, `union`, `enum`, `typedef` or `function`.
    pub kind: String,
    /// Fields of a struct or union, for inline editing.
    pub fields: Vec<FieldRow>,
}

/// One field of the picked struct or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRow {
    /// Field name.
    pub name: String,
    /// Field type as C text.
    pub ty: String,
    /// Byte offset.
    pub offset: u64,
}

/// The "New type" dialog.
#[derive(Debug, Clone, Default)]
pub struct DefineDialog {
    /// The C declarations being typed.
    pub text: String,
    /// Why the last attempt failed (a parse error names the line).
    pub error: Option<String>,
    /// The call is running.
    pub busy: bool,
}

/// The "Apply to address" dialog.
#[derive(Debug, Clone, Default)]
pub struct ApplyDialog {
    /// The type being applied.
    pub type_name: String,
    /// The address as typed.
    pub address: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// The call is running.
    pub busy: bool,
}

/// State of the Types tab.
#[derive(Debug, Clone, Default)]
pub struct TypesPanel {
    /// Types loaded so far, by name.
    pub items: Vec<TypeItem>,
    /// The name filter.
    pub filter: String,
    /// The kind filter (`struct`, `enum`, ...); empty for all.
    pub kind: String,
    /// Whether the declaration includes the types it uses.
    pub dependencies: bool,
    /// Where the next page starts.
    pub next_cursor: Option<String>,
    /// A list call is running.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// The type picked in the list.
    pub selected: Option<String>,
    /// Its declaration, when it arrived.
    pub decl: Option<TypeDecl>,
    /// A declaration call is running.
    pub decl_loading: bool,
    /// Why the declaration could not be shown.
    pub decl_error: Option<String>,
    /// The New type dialog, when open.
    pub define: Option<DefineDialog>,
    /// The Apply to address dialog, when open.
    pub apply: Option<ApplyDialog>,
    /// Why the last field edit or deletion failed.
    pub edit_error: Option<String>,
    /// What the last change did, in a few words.
    pub notice: Option<String>,
    generation: u64,
    decl_generation: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct TypeWire {
    name: Untrusted<String>,
    kind: String,
    #[serde(default)]
    size: Option<u64>,
    detail: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TypeDeclWire {
    name: Untrusted<String>,
    c: Untrusted<String>,
    #[serde(default)]
    undefined: Vec<Untrusted<String>>,
    kind: String,
    definition: TypeDef,
}

#[derive(Debug, Clone, Deserialize)]
struct DefineWire {
    types: Vec<String>,
}

impl TypesPanel {
    /// True when more rows can be loaded.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

impl ViewModel {
    /// Loads the first page of types once.
    pub fn ensure_types(&mut self) {
        let t = &self.tools.types;
        if !t.loaded && !t.loading && t.error.is_none() {
            self.fetch_types(true);
        }
    }

    /// Sets the name filter and reloads.
    pub fn set_types_filter(&mut self, filter: impl Into<String>) {
        let filter = filter.into();
        if filter == self.tools.types.filter {
            return;
        }
        self.tools.types.filter = filter;
        self.fetch_types(true);
    }

    /// Sets the kind filter (`struct`, `union`, `enum`, `typedef`, `function`, or empty) and reloads.
    pub fn set_types_kind(&mut self, kind: impl Into<String>) {
        let kind = kind.into();
        if kind == self.tools.types.kind {
            return;
        }
        self.tools.types.kind = kind;
        self.fetch_types(true);
    }

    /// Reloads the list from the first page.
    pub fn refresh_types(&mut self) {
        self.fetch_types(true);
    }

    /// Loads the next page when the rows on screen get near the end.
    pub fn types_scrolled(&mut self, visible_end: usize) {
        let t = &self.tools.types;
        if t.has_more() && !t.loading && visible_end + 30 >= t.items.len() {
            self.fetch_types(false);
        }
    }

    fn fetch_types(&mut self, reset: bool) {
        let t = &mut self.tools.types;
        let mut args = json!({ "limit": PAGE });
        if !t.filter.is_empty() {
            args["name_filter"] = Value::String(t.filter.clone());
        }
        if !t.kind.is_empty() {
            args["kind"] = Value::String(t.kind.clone());
        }
        if reset {
            t.generation += 1;
            t.next_cursor = None;
        } else if t.loading || t.next_cursor.is_none() {
            return;
        } else if let Some(c) = &t.next_cursor {
            args["cursor"] = Value::String(c.clone());
        }
        t.loading = true;
        t.error = None;
        let generation = t.generation;
        self.call("types_list", args, move |vm, res| {
            let t = &mut vm.tools.types;
            if t.generation != generation {
                return;
            }
            t.loading = false;
            match res.and_then(parse::<Page<TypeWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(|w| TypeItem {
                        name: w.name.0,
                        kind: w.kind,
                        size: w.size,
                        detail: w.detail,
                    });
                    if reset {
                        t.items = rows.collect();
                    } else {
                        t.items.extend(rows);
                    }
                    t.loaded = true;
                    t.next_cursor = page.next_cursor;
                }
                Err(e) => {
                    t.loaded = true;
                    t.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Retries after a failed load.
    pub fn retry_types(&mut self) {
        self.tools.types.error = None;
        self.fetch_types(true);
    }

    /// Picks a type and fetches its declaration.
    pub fn select_type(&mut self, name: &str) {
        self.tools.types.selected = Some(name.to_string());
        self.fetch_type_decl();
    }

    /// Shows or hides the types the picked one uses, and refetches.
    pub fn set_types_dependencies(&mut self, on: bool) {
        if self.tools.types.dependencies != on {
            self.tools.types.dependencies = on;
            self.fetch_type_decl();
        }
    }

    fn fetch_type_decl(&mut self) {
        let t = &mut self.tools.types;
        let Some(name) = t.selected.clone() else {
            return;
        };
        t.decl_generation += 1;
        t.decl_loading = true;
        t.decl_error = None;
        let generation = t.decl_generation;
        let args = json!({ "name": name, "dependencies": t.dependencies });
        self.call("type_get", args, move |vm, res| {
            let t = &mut vm.tools.types;
            if t.decl_generation != generation {
                return;
            }
            t.decl_loading = false;
            match res.and_then(parse::<TypeDeclWire>) {
                Ok(w) => {
                    t.decl = Some(TypeDecl {
                        name: w.name.0,
                        c: w.c.0,
                        undefined: w.undefined.into_iter().map(|u| u.0).collect(),
                        kind: w.kind,
                        fields: match &w.definition {
                            TypeDef::Struct(c) | TypeDef::Union(c) => c
                                .fields
                                .iter()
                                .map(|f| FieldRow {
                                    name: f.name.clone(),
                                    ty: f.ty.to_c(),
                                    offset: f.offset,
                                })
                                .collect(),
                            _ => Vec::new(),
                        },
                    });
                }
                Err(e) => {
                    t.decl = None;
                    t.decl_error = Some(plain_error(&e));
                }
            }
        });
    }
}

impl ViewModel {
    /// Opens the New type dialog with a starting template.
    pub fn open_type_define(&mut self) {
        self.tools.types.define = Some(DefineDialog {
            text: "struct name {\n    int field;\n};\n".into(),
            ..DefineDialog::default()
        });
    }

    /// Closes the New type dialog.
    pub fn close_type_define(&mut self) {
        self.tools.types.define = None;
    }

    /// Sends the dialog's C text to `type_define`. A parse error stays in the dialog.
    pub fn submit_type_define(&mut self) {
        let Some(d) = self.tools.types.define.as_mut() else {
            return;
        };
        if d.busy {
            return;
        }
        d.busy = true;
        d.error = None;
        let args = json!({ "c_declaration": d.text });
        self.call("type_define", args, |vm, res| {
            match res.and_then(parse::<DefineWire>) {
                Ok(out) => {
                    vm.tools.types.define = None;
                    vm.tools.types.notice = Some(match out.types.as_slice() {
                        [one] => format!("Defined {one}."),
                        many => format!("Defined {} types.", many.len()),
                    });
                    vm.refresh_types();
                    if let Some(first) = out.types.first() {
                        vm.select_type(first);
                    }
                }
                Err(e) => {
                    if let Some(d) = vm.tools.types.define.as_mut() {
                        d.busy = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }

    /// Renames a field or changes its type (C text); the struct is laid out again.
    pub fn edit_type_field(
        &mut self,
        type_name: &str,
        field: &str,
        new_name: Option<String>,
        new_type: Option<String>,
    ) {
        let mut args = json!({ "type_name": type_name, "field": field });
        if let Some(n) = new_name {
            args["new_name"] = Value::String(n);
        }
        if let Some(t) = new_type {
            args["new_type"] = Value::String(t);
        }
        self.tools.types.edit_error = None;
        let name = type_name.to_string();
        self.call("type_edit_field", args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.types.notice = Some(format!("Changed {name}."));
                vm.refresh_types();
                vm.select_type(&name);
            }
            Err(e) => vm.tools.types.edit_error = Some(plain_error(&e)),
        });
    }

    /// Deletes a type.
    pub fn delete_type(&mut self, name: &str) {
        self.tools.types.edit_error = None;
        let name = name.to_string();
        self.call(
            "type_delete",
            json!({ "name": name }),
            move |vm, res| match res {
                Ok(_) => {
                    vm.tools.types.notice = Some(format!("Deleted {name}."));
                    let t = &mut vm.tools.types;
                    if t.selected.as_deref() == Some(name.as_str()) {
                        t.selected = None;
                        t.decl = None;
                    }
                    vm.refresh_types();
                }
                Err(e) => vm.tools.types.edit_error = Some(plain_error(&e)),
            },
        );
    }

    /// Opens the Apply to address dialog for a type.
    pub fn open_type_apply(&mut self, name: &str) {
        self.tools.types.apply = Some(ApplyDialog {
            type_name: name.to_string(),
            ..ApplyDialog::default()
        });
    }

    /// Closes the Apply to address dialog.
    pub fn close_type_apply(&mut self) {
        self.tools.types.apply = None;
    }

    /// Gives the address in the dialog the type, through `set_type`.
    pub fn submit_type_apply(&mut self) {
        let Some(d) = self.tools.types.apply.as_mut() else {
            return;
        };
        if d.busy {
            return;
        }
        let Some(at) = parse_address(&d.address) else {
            d.error = Some("Type an address such as 0x404040.".into());
            return;
        };
        d.busy = true;
        d.error = None;
        let args = json!({ "address": format!("{at:#x}"), "type_name": d.type_name });
        self.call("set_type", args, |vm, res| match res {
            Ok(_) => {
                if let Some(d) = vm.tools.types.apply.take() {
                    vm.tools.types.notice =
                        Some(format!("{} applied at {}.", d.type_name, d.address.trim()));
                }
            }
            Err(e) => {
                if let Some(d) = vm.tools.types.apply.as_mut() {
                    d.busy = false;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }
}
