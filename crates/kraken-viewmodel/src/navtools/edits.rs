//! The Retype / Edit signature dialog and the Create / Delete function dialog.

use serde_json::{Value, json};

use super::ctype::{parse_prototype, parse_type, pointer_size};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse, validate_name};
use crate::wire::MutationWire;

/// What the type dialog edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeMode {
    /// The type of a data item at an address.
    Data,
    /// A function's prototype.
    Signature,
}

/// The Retype / Edit signature dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDialog {
    /// The function entry or data address.
    pub address: u64,
    /// What is edited.
    pub mode: TypeMode,
    /// The C text typed so far.
    pub input: String,
    /// The text the dialog opened with.
    pub original: String,
    /// Name of the function or `0x...` of the data item.
    pub target: String,
    /// Pointer size of the program, for `*`.
    pub pointer_size: u32,
    /// Why saving failed (from the engine).
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
}

impl TypeDialog {
    /// Reads the typed text. `Ok` holds the `set_type` arguments and a note to show (a name
    /// written in a signature is not applied: names change through rename).
    pub fn check(&self) -> Result<(Value, Option<String>), String> {
        match self.mode {
            TypeMode::Data => {
                let t = parse_type(&self.input, self.pointer_size)?;
                Ok((json!({"address": hex(self.address), "data_type": t}), None))
            }
            TypeMode::Signature => {
                let p = parse_prototype(&self.input, self.pointer_size)?;
                let note = p.name.filter(|n| *n != self.target).map(|n| {
                    format!("The name {n} is not applied here. Use Rename (N) to change it.")
                });
                Ok((
                    json!({"address": hex(self.address), "prototype": p.prototype}),
                    note,
                ))
            }
        }
    }
}

/// The Rename / retype variable dialog: a local variable or parameter of a decompiled function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDialog {
    /// Entry of the function that holds the variable.
    pub function: u64,
    /// Where the variable lives, as `space:0xoffset` (the token's varnode without its size).
    pub storage: String,
    /// The name the variable has in the decompiled text.
    pub old_name: String,
    /// The new name as typed; empty keeps the name.
    pub name: String,
    /// The new type as typed in C; empty keeps the type.
    pub ty: String,
    /// Pointer size of the program, for `*`.
    pub pointer_size: u32,
    /// True when the dialog opened to retype: the type field gets the focus.
    pub focus_type: bool,
    /// Why saving failed (from the engine).
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
}

impl LocalDialog {
    /// Reads the typed name and type. `Ok` holds the `set_local` arguments.
    pub fn check(&self) -> Result<Value, String> {
        let name = self.name.trim();
        let mut args = json!({"address": hex(self.function), "storage": self.storage});
        let mut something = false;
        if !name.is_empty() && name != self.old_name {
            args["name"] = json!(validate_name(name, &self.old_name)?);
            something = true;
        }
        if !self.ty.trim().is_empty() {
            args["data_type"] = json!(parse_type(&self.ty, self.pointer_size)?);
            something = true;
        }
        if !something {
            return Err("Type a new name, a type, or both.".into());
        }
        Ok(args)
    }
}

/// Whether the function dialog creates or deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionDialogKind {
    /// Mark code as a new function.
    Create,
    /// Remove a function (its code stays).
    Delete,
}

/// The Create / Delete function dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDialog {
    /// Create or delete.
    pub kind: FunctionDialogKind,
    /// The entry address.
    pub address: u64,
    /// Name for a new function (empty: the engine picks one), or the name being deleted.
    pub name: String,
    /// Why saving failed.
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
}

impl ViewModel {
    /// Pointer size of the open program.
    pub fn pointer_size(&self) -> u32 {
        self.project.as_ref().map_or(8, |p| pointer_size(&p.arch))
    }

    /// Why types cannot be edited right now, if they cannot.
    pub fn type_edit_blocked(&self) -> Option<&'static str> {
        if self.module.is_some() {
            return Some("Types in a .NET assembly cannot be edited yet.");
        }
        None
    }

    /// Why functions cannot be created or deleted right now, if they cannot.
    pub fn function_edit_blocked(&self) -> Option<&'static str> {
        if self.module.is_some() {
            return Some(
                "Functions in a .NET assembly are fixed; they cannot be created or deleted.",
            );
        }
        None
    }

    fn is_function_entry(&self, addr: u64) -> bool {
        self.functions.find(addr).is_some()
            || self.current.as_ref().is_some_and(|c| c.address == addr)
    }

    /// Opens the type dialog for `addr`: a function's signature at a function entry, the data
    /// type anywhere else.
    pub fn begin_retype(&mut self, addr: u64) {
        if let Some(why) = self.type_edit_blocked() {
            self.toast(ToastLevel::Info, why);
            return;
        }
        if self.is_function_entry(addr) {
            self.begin_edit_signature(addr);
            return;
        }
        if let crate::views::nav::Place::Inside(entry) = self.place_of(addr) {
            let name = self
                .functions
                .find(entry)
                .map_or_else(|| hex(entry), |f| f.name.clone());
            self.toast(
                ToastLevel::Info,
                format!(
                    "{} is an instruction inside {name}. Only data and functions take a type; right-click and choose Edit function signature to change {name}.",
                    hex(addr)
                ),
            );
            return;
        }
        self.tools.type_dialog = Some(TypeDialog {
            address: addr,
            mode: TypeMode::Data,
            input: String::new(),
            original: String::new(),
            target: hex(addr),
            pointer_size: self.pointer_size(),
            error: None,
            submitting: false,
        });
    }

    /// Opens the type dialog for the address at the cursor.
    pub fn begin_retype_here(&mut self) {
        match self.cursor_address() {
            Some(a) => self.begin_retype(a),
            None => self.toast(ToastLevel::Info, "Pick a function or an address first."),
        }
    }

    /// Opens the signature editor for the function at `addr`, prefilled with its prototype.
    pub fn begin_edit_signature(&mut self, addr: u64) {
        if let Some(why) = self.type_edit_blocked() {
            self.toast(ToastLevel::Info, why);
            return;
        }
        let detail = self
            .current
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .filter(|d| d.address == addr);
        let item = self.functions.find(addr);
        let name = detail
            .map(|d| d.name.clone())
            .or_else(|| item.map(|f| f.name.clone()))
            .unwrap_or_else(|| hex(addr));
        let sig = detail
            .and_then(|d| d.signature.clone())
            .or_else(|| item.and_then(|f| f.signature.clone()))
            .unwrap_or_else(|| format!("void {name}(void)"));
        self.tools.type_dialog = Some(TypeDialog {
            address: addr,
            mode: TypeMode::Signature,
            input: sig.clone(),
            original: sig,
            target: name,
            pointer_size: self.pointer_size(),
            error: None,
            submitting: false,
        });
    }

    /// Opens the signature editor for the function being read.
    pub fn begin_edit_signature_current(&mut self) {
        match self.current.as_ref().map(|c| c.address) {
            Some(a) => self.begin_edit_signature(a),
            None => self.toast(
                ToastLevel::Info,
                "Pick a function first, then edit its signature.",
            ),
        }
    }

    /// Updates the text of the type dialog.
    pub fn set_type_input(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.type_dialog.as_mut() {
            d.input = text.into();
            d.error = None;
        }
    }

    /// Closes the type dialog.
    pub fn cancel_type(&mut self) {
        self.tools.type_dialog = None;
    }

    /// Sends the type through `set_type`. Parse errors stay in the dialog.
    pub fn submit_type(&mut self) {
        let Some(d) = self.tools.type_dialog.as_mut().filter(|d| !d.submitting) else {
            return;
        };
        let args = match d.check() {
            Ok((a, _)) => a,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.submitting = true;
        let what = match d.mode {
            TypeMode::Data => "Type change",
            TypeMode::Signature => "Signature change",
        };
        self.call("set_type", args, move |vm, res| {
            match res.and_then(parse::<MutationWire>) {
                Ok(m) => {
                    vm.tools.type_dialog = None;
                    vm.toast_mutation(&m, &format!("{what} saved."), what);
                    vm.refresh_after_edit();
                }
                Err(e) => {
                    if let Some(d) = vm.tools.type_dialog.as_mut() {
                        d.submitting = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------- local variables

    /// Why local variables cannot be renamed or retyped right now, if they cannot.
    pub fn local_edit_blocked(&self) -> Option<&'static str> {
        if self.module.is_some() {
            return Some("Variables in a .NET assembly cannot be renamed here yet.");
        }
        None
    }

    /// Opens the dialog for the variable `name` stored at `varnode` (as in a decompiler token,
    /// with or without the `:size`) of the function at `function`.
    pub fn begin_local(&mut self, function: u64, varnode: &str, name: &str, focus_type: bool) {
        if let Some(why) = self.local_edit_blocked() {
            self.toast(ToastLevel::Info, why);
            return;
        }
        let Some((space, offset)) = kraken_proto::parse_storage(varnode) else {
            self.toast(
                ToastLevel::Info,
                "This variable has no place KRAKEN can name it by. Try another use of it.",
            );
            return;
        };
        self.tools.local_dialog = Some(LocalDialog {
            function,
            storage: kraken_proto::storage_key(&space, offset),
            old_name: name.to_string(),
            name: name.to_string(),
            ty: String::new(),
            pointer_size: self.pointer_size(),
            focus_type,
            error: None,
            submitting: false,
        });
    }

    /// Updates the text fields of the variable dialog.
    pub fn set_local_input(&mut self, name: impl Into<String>, ty: impl Into<String>) {
        if let Some(d) = self.tools.local_dialog.as_mut() {
            d.name = name.into();
            d.ty = ty.into();
            d.error = None;
        }
    }

    /// Closes the variable dialog.
    pub fn cancel_local(&mut self) {
        self.tools.local_dialog = None;
    }

    /// Sends the name and type through `set_local`. Parse errors stay in the dialog.
    pub fn submit_local(&mut self) {
        let Some(d) = self.tools.local_dialog.as_mut().filter(|d| !d.submitting) else {
            return;
        };
        let args = match d.check() {
            Ok(a) => a,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.submitting = true;
        self.call("set_local", args, move |vm, res| {
            match res.and_then(parse::<MutationWire>) {
                Ok(m) => {
                    vm.tools.local_dialog = None;
                    vm.toast_mutation(&m, "Variable saved.", "Variable change");
                    vm.refresh_after_edit();
                }
                Err(e) => {
                    if let Some(d) = vm.tools.local_dialog.as_mut() {
                        d.submitting = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------- functions

    /// Opens the dialog that creates a function at `addr`.
    pub fn begin_create_function(&mut self, addr: u64) {
        if let Some(why) = self.function_edit_blocked() {
            self.toast(ToastLevel::Info, why);
            return;
        }
        if self.functions.find(addr).is_some() {
            self.toast(
                ToastLevel::Info,
                format!("There is already a function at {}.", hex(addr)),
            );
            return;
        }
        self.tools.function_dialog = Some(FunctionDialog {
            kind: FunctionDialogKind::Create,
            address: addr,
            name: String::new(),
            error: None,
            submitting: false,
        });
    }

    /// Opens the create dialog for the address at the cursor.
    pub fn begin_create_function_here(&mut self) {
        match self.views.cursor {
            Some(a) => self.begin_create_function(a),
            None => self.toast(
                ToastLevel::Info,
                "Click an instruction in the listing first, then create a function there.",
            ),
        }
    }

    /// Asks whether to delete the function at `addr`.
    pub fn begin_delete_function(&mut self, addr: u64) {
        if let Some(why) = self.function_edit_blocked() {
            self.toast(ToastLevel::Info, why);
            return;
        }
        let name = self
            .functions
            .find(addr)
            .map(|f| f.name.clone())
            .or_else(|| {
                self.current
                    .as_ref()
                    .filter(|c| c.address == addr)
                    .map(|c| c.name.clone())
            })
            .unwrap_or_else(|| hex(addr));
        self.tools.function_dialog = Some(FunctionDialog {
            kind: FunctionDialogKind::Delete,
            address: addr,
            name,
            error: None,
            submitting: false,
        });
    }

    /// Asks whether to delete the function being read.
    pub fn begin_delete_current(&mut self) {
        match self.current.as_ref().map(|c| c.address) {
            Some(a) => self.begin_delete_function(a),
            None => self.toast(ToastLevel::Info, "Pick a function first."),
        }
    }

    /// Updates the name typed in the create dialog.
    pub fn set_function_name_input(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.function_dialog.as_mut() {
            d.name = text.into();
            d.error = None;
        }
    }

    /// Closes the function dialog.
    pub fn cancel_function_dialog(&mut self) {
        self.tools.function_dialog = None;
    }

    /// Creates or deletes the function.
    pub fn submit_function_dialog(&mut self) {
        let Some(d) = self
            .tools
            .function_dialog
            .as_mut()
            .filter(|d| !d.submitting)
        else {
            return;
        };
        let addr = d.address;
        let (command, args, done, what) = match d.kind {
            FunctionDialogKind::Create => {
                let mut args = json!({"address": hex(addr)});
                if !d.name.trim().is_empty() {
                    match validate_name(&d.name, "") {
                        Ok(n) => args["name"] = json!(n),
                        Err(e) => {
                            d.error = Some(e);
                            return;
                        }
                    }
                }
                (
                    "create_function",
                    args,
                    format!("Created a function at {}.", hex(addr)),
                    "Creating the function",
                )
            }
            FunctionDialogKind::Delete => (
                "delete_function",
                json!({"address": hex(addr)}),
                format!("Deleted the function {}. Its code stays.", d.name),
                "Deleting the function",
            ),
        };
        let kind = d.kind;
        d.submitting = true;
        self.call(command, args, move |vm, res| {
            match res.and_then(parse::<MutationWire>) {
                Ok(m) => {
                    vm.tools.function_dialog = None;
                    vm.toast_mutation(&m, &done, what);
                    let applied = m.status == "applied";
                    if kind == FunctionDialogKind::Delete
                        && applied
                        && vm.current.as_ref().is_some_and(|c| c.address == addr)
                    {
                        vm.current = None;
                        vm.selected = None;
                    }
                    vm.refresh_after_edit();
                    if kind == FunctionDialogKind::Create && applied {
                        vm.navigate_to(addr);
                    }
                }
                Err(e) => {
                    if let Some(d) = vm.tools.function_dialog.as_mut() {
                        d.submitting = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }
}

impl ViewModel {
    /// Opens the comment dialog for the address at the cursor: above the function at its
    /// entry, at the end of the line anywhere else.
    pub fn begin_comment_here(&mut self) {
        match self.cursor_address() {
            Some(a) => {
                let kind = if self.is_function_entry(a) {
                    kraken_proto::CommentKind::Plate
                } else {
                    kraken_proto::CommentKind::Eol
                };
                self.begin_comment(a, kind);
            }
            None => self.toast(ToastLevel::Info, "Pick a function or an address first."),
        }
    }
}
