//! Byte patching: the Patches tab, the dialog that stages a patch (`patch_set`) from the
//! Listing or the Hex view, and the export dialog (`patch_export`).
//!
//! Staging a patch changes nothing on disk; it is a reversible overlay entry. Export writes a
//! patched copy of the binary and goes through the backend's approval question like every
//! dangerous command.

use kraken_proto::{Hex64, Page, Untrusted};
use serde::Deserialize;
use serde_json::json;

use super::NavTab;
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// Longest patch, in bytes (matches the registry).
pub const MAX_PATCH_BYTES: usize = 4096;
/// Longest note, in characters (matches the registry).
pub const MAX_PATCH_NOTE: usize = 1000;

/// One staged patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchItem {
    /// The patched address.
    pub address: u64,
    /// The bytes that were there.
    pub original: Vec<u8>,
    /// The bytes written in their place.
    pub replacement: Vec<u8>,
    /// The note, possibly empty.
    pub note: String,
    /// True when an agent set it.
    pub by_agent: bool,
    /// "you" or the agent id.
    pub who: String,
    /// The patch set it is in; empty for none.
    pub group: String,
    /// False when it is switched off: not exported or emulated.
    pub enabled: bool,
}

/// A patch set as the Patches tab lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchGroupItem {
    /// Its name.
    pub name: String,
    /// What it does; may be empty.
    pub description: String,
    /// Patches in it.
    pub patches: u32,
    /// Of those, how many are on.
    pub enabled_patches: u32,
}

impl PatchGroupItem {
    /// `on`, `off` or `mixed`.
    pub fn state(&self) -> &'static str {
        if self.enabled_patches == self.patches {
            "on"
        } else if self.enabled_patches == 0 {
            "off"
        } else {
            "mixed"
        }
    }
}

/// The dialog that creates a patch set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupDialog {
    /// The name typed.
    pub name: String,
    /// The description typed.
    pub description: String,
    /// Why creating failed.
    pub error: Option<String>,
}

impl PatchItem {
    /// The addresses it covers.
    pub fn range(&self) -> std::ops::Range<u64> {
        self.address..self.address + self.replacement.len() as u64
    }
}

/// The last patched binary written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDone {
    /// Where it was written.
    pub output_path: String,
    /// How many patches went in.
    pub applied: usize,
    /// Size of the file.
    pub bytes_written: u64,
    /// SHA-256 of the file, lower-case hex.
    pub sha256: String,
}

/// State of the Patches tab.
#[derive(Debug, Clone, Default)]
pub struct PatchesPanel {
    /// Patches loaded so far, by address.
    pub items: Vec<PatchItem>,
    /// Where the next page starts.
    pub next_cursor: Option<String>,
    /// A call is running.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// The last export of this session.
    pub last_export: Option<ExportDone>,
    /// The patch sets, by name.
    pub groups: Vec<PatchGroupItem>,
    /// The new-set dialog, when open.
    pub group_dialog: Option<GroupDialog>,
    generation: u64,
}

impl PatchesPanel {
    /// The patch covering `addr`, when loaded.
    pub fn covering(&self, addr: u64) -> Option<&PatchItem> {
        self.items.iter().find(|p| p.range().contains(&addr))
    }
}

/// Where the patch dialog was opened from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOrigin {
    /// An instruction of the Listing: its text, e.g. `mov eax, 0x3`.
    Instruction(String),
    /// A selection of the Hex view.
    Bytes,
}

/// The dialog that stages a byte patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchDialog {
    /// Address to patch.
    pub address: u64,
    /// The bytes there now, when known (the instruction's, or the cached ones).
    pub original: Option<Vec<u8>>,
    /// Where it was opened from.
    pub origin: PatchOrigin,
    /// The replacement hex typed so far.
    pub input: String,
    /// The note typed so far.
    pub note: String,
    /// A patch already starts here (saving replaces it).
    pub existing: bool,
    /// Why saving failed.
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
    /// The program is x86 (one-byte `nop` is 0x90).
    pub x86: bool,
    /// The instruction typed to be assembled into `input`.
    pub asm: String,
    /// Where assembling the instruction stands.
    pub asm_state: AsmState,
    /// What the assembler did beyond the typed text (NOP padding, instructions replaced).
    pub asm_note: Option<String>,
    /// The patch set the patch goes in; empty for none.
    pub group: String,
}

/// Assembling the typed instruction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AsmState {
    /// Nothing asked.
    #[default]
    Idle,
    /// The engine is assembling.
    Busy,
    /// The encodings, shortest first; the first one is in the hex field.
    Done(Vec<Vec<u8>>),
    /// Why it did not assemble (plain language).
    Failed(String),
}

impl PatchDialog {
    /// The replacement bytes, or why the input is not usable.
    pub fn parsed(&self) -> Result<Vec<u8>, String> {
        parse_hex(&self.input)
    }

    /// Whether Stage may be pressed.
    pub fn check(&self) -> Result<(), String> {
        self.parsed()?;
        if self.note.chars().count() > MAX_PATCH_NOTE {
            return Err(format!(
                "A note can be at most {MAX_PATCH_NOTE} characters."
            ));
        }
        Ok(())
    }

    /// A plain-language warning when the replacement is not the length of the original.
    pub fn length_note(&self) -> Option<String> {
        let (Ok(new), Some(old)) = (self.parsed(), self.original.as_ref()) else {
            return None;
        };
        let what = match self.origin {
            PatchOrigin::Instruction(_) => "instruction",
            PatchOrigin::Bytes => "selection",
        };
        match new.len().cmp(&old.len()) {
            std::cmp::Ordering::Equal => None,
            std::cmp::Ordering::Less => Some(format!(
                "{} bytes replace the first {} of the {} {what} bytes; the rest stay as they are \
                 and may no longer make sense as code.",
                new.len(),
                new.len(),
                old.len()
            )),
            std::cmp::Ordering::Greater => Some(format!(
                "{} bytes are longer than the {} {what} bytes: they overwrite what follows.",
                new.len(),
                old.len()
            )),
        }
    }

    /// Pads the replacement with one-byte `nop`s (x86) to the original's length.
    pub fn pad_with_nops(&mut self) {
        let (Ok(mut new), Some(old)) = (self.parsed(), self.original.as_ref()) else {
            return;
        };
        if !self.x86 || new.len() >= old.len() {
            return;
        }
        new.resize(old.len(), 0x90);
        self.input = spaced_hex(&new);
    }
}

/// The dialog that writes a patched copy of the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDialog {
    /// Where to write it; relative paths are taken from the project directory.
    pub output_path: String,
    /// Replace an existing file.
    pub overwrite: bool,
    /// Export only this patch set; `None` exports every patch that is on.
    pub group: Option<String>,
    /// Why writing failed.
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
    /// What was written, once it was: the dialog then shows the result.
    pub done: Option<ExportDone>,
}

#[derive(Debug, Clone, Deserialize)]
struct PatchWire {
    address: Hex64,
    original: String,
    replacement: String,
    note: Untrusted<String>,
    author_kind: String,
    author_id: String,
    #[serde(default)]
    group: Untrusted<String>,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct GroupWire {
    name: Untrusted<String>,
    description: Untrusted<String>,
    patches: u32,
    enabled_patches: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupListWire {
    groups: Vec<GroupWire>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExportWire {
    output_path: String,
    applied: Vec<serde_json::Value>,
    bytes_written: u64,
    #[serde(default)]
    sha256: String,
}

/// Parses hex like the registry does: spaces ignored, an optional `0x`.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if cleaned.is_empty() {
        return Err("Type the new bytes as hex, for example 90 90 or eb 10.".into());
    }
    if let Some(c) = cleaned.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("`{c}` is not a hex digit."));
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("Each byte needs two hex digits.".into());
    }
    let bytes: Vec<u8> = (0..cleaned.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect();
    if bytes.len() > MAX_PATCH_BYTES {
        return Err(format!("A patch covers at most {MAX_PATCH_BYTES} bytes."));
    }
    Ok(bytes)
}

/// `b8 07 00 00 00`.
pub fn spaced_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn unhex(s: &str) -> Vec<u8> {
    parse_hex(s).unwrap_or_default()
}

impl ViewModel {
    /// Loads the patches once.
    pub fn ensure_patches(&mut self) {
        let p = &self.tools.patches;
        if !p.loaded && !p.loading && p.error.is_none() {
            self.refresh_patches();
        }
    }

    /// Reloads the patches from the first page, and the patch sets.
    pub fn refresh_patches(&mut self) {
        self.tools.patches.generation += 1;
        self.tools.patches.next_cursor = None;
        self.patches_changed();
        self.fetch_patches(true);
        self.fetch_patch_groups();
    }

    fn fetch_patch_groups(&mut self) {
        self.call("patch_group_list", json!({}), |vm, res| {
            if let Ok(list) = res.and_then(parse::<GroupListWire>) {
                vm.tools.patches.groups = list
                    .groups
                    .into_iter()
                    .map(|g| PatchGroupItem {
                        name: g.name.0,
                        description: g.description.0,
                        patches: g.patches,
                        enabled_patches: g.enabled_patches,
                    })
                    .collect();
            }
        });
    }

    /// Opens the dialog that creates a patch set.
    pub fn begin_patch_group(&mut self) {
        self.tools.patches.group_dialog = Some(GroupDialog::default());
    }

    /// Closes the new-set dialog.
    pub fn cancel_patch_group(&mut self) {
        self.tools.patches.group_dialog = None;
    }

    /// Updates the new set's name and description.
    pub fn set_patch_group_text(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) {
        if let Some(d) = self.tools.patches.group_dialog.as_mut() {
            d.name = name.into();
            d.description = description.into();
            d.error = None;
        }
    }

    /// Creates the set typed in the dialog (`patch_group_set`).
    pub fn submit_patch_group(&mut self) {
        let Some(d) = self.tools.patches.group_dialog.clone() else {
            return;
        };
        let name = d.name.trim().to_string();
        if name.is_empty() {
            if let Some(d) = self.tools.patches.group_dialog.as_mut() {
                d.error = Some("Give the set a name.".into());
            }
            return;
        }
        let args = json!({"name": name, "description": d.description.trim()});
        self.call("patch_group_set", args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.patches.group_dialog = None;
                vm.toast(
                    ToastLevel::Success,
                    format!("Created the patch set {name}."),
                );
                vm.fetch_patch_groups();
            }
            Err(e) => {
                if let Some(d) = vm.tools.patches.group_dialog.as_mut() {
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Switches every patch of a set on or off (`patch_group_enable`).
    pub fn set_patch_group_enabled(&mut self, name: &str, enabled: bool) {
        let n = name.to_string();
        self.call(
            "patch_group_enable",
            json!({"name": name, "enabled": enabled}),
            move |vm, res| match res {
                Ok(_) => {
                    vm.toast(
                        ToastLevel::Info,
                        format!(
                            "Switched the patch set {n} {}.",
                            if enabled { "on" } else { "off" }
                        ),
                    );
                    vm.refresh_patches();
                    vm.refresh_history();
                }
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    /// Moves the patch at `address` into the set `group` (`""` for none).
    pub fn assign_patch_group(&mut self, address: u64, group: &str) {
        self.call(
            "patch_group_assign",
            json!({"group": group, "addresses": [hex(address)]}),
            |vm, res| match res {
                Ok(_) => {
                    vm.refresh_patches();
                    vm.refresh_history();
                }
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    /// Deletes an empty patch set (`patch_group_remove`).
    pub fn remove_patch_group(&mut self, name: &str) {
        self.call(
            "patch_group_remove",
            json!({"name": name}),
            |vm, res| match res {
                Ok(_) => vm.fetch_patch_groups(),
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    /// Loads the next page of patches.
    pub fn more_patches(&mut self) {
        let p = &self.tools.patches;
        if !p.loading && p.next_cursor.is_some() {
            self.fetch_patches(false);
        }
    }

    fn fetch_patches(&mut self, reset: bool) {
        let p = &mut self.tools.patches;
        p.loading = true;
        p.error = None;
        let generation = p.generation;
        let mut args = json!({"limit": 200});
        if !reset && let Some(c) = &p.next_cursor {
            args["cursor"] = json!(c);
        }
        self.call("patch_list", args, move |vm, res| {
            let p = &mut vm.tools.patches;
            if p.generation != generation {
                return;
            }
            p.loading = false;
            match res.and_then(parse::<Page<PatchWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(|w| PatchItem {
                        address: w.address.0,
                        original: unhex(&w.original),
                        replacement: unhex(&w.replacement),
                        note: w.note.0,
                        by_agent: w.author_kind != "user",
                        who: if w.author_kind == "user" {
                            "you".into()
                        } else {
                            w.author_id
                        },
                        group: w.group.0,
                        enabled: w.enabled,
                    });
                    if reset {
                        p.items = rows.collect();
                    } else {
                        p.items.extend(rows);
                    }
                    p.loaded = true;
                    p.next_cursor = page.next_cursor;
                }
                Err(e) => p.error = Some(plain_error(&e)),
            }
        });
    }

    fn is_x86(&self) -> bool {
        self.project
            .as_ref()
            .is_some_and(|p| p.arch.to_ascii_lowercase().starts_with("x86"))
    }

    /// Opens the patch dialog at `address` over `original` (the bytes there now, when known).
    /// A patch that starts there is loaded for editing.
    pub fn begin_patch(&mut self, address: u64, original: Option<Vec<u8>>, origin: PatchOrigin) {
        let existing = self
            .tools
            .patches
            .items
            .iter()
            .find(|p| p.address == address)
            .cloned();
        let (original, input, note) = match &existing {
            Some(p) => (
                Some(p.original.clone()),
                spaced_hex(&p.replacement),
                p.note.clone(),
            ),
            None => (
                original.clone(),
                original.as_deref().map(spaced_hex).unwrap_or_default(),
                String::new(),
            ),
        };
        self.tools.patch_dialog = Some(PatchDialog {
            address,
            original,
            origin,
            input,
            note,
            existing: existing.is_some(),
            error: None,
            submitting: false,
            x86: self.is_x86(),
            asm: String::new(),
            asm_state: AsmState::Idle,
            asm_note: None,
            group: existing
                .as_ref()
                .map(|p| p.group.clone())
                .unwrap_or_default(),
        });
    }

    /// Opens the patch dialog on the selected instruction of the Listing.
    pub fn begin_patch_instruction(&mut self) {
        let Some(row) = self.views.listing.selected_row().cloned() else {
            self.toast(
                ToastLevel::Info,
                "Click an instruction in the Listing first, then patch it.",
            );
            return;
        };
        let ops: String = row.operands.iter().map(|o| o.text.as_str()).collect();
        let text = format!("{} {ops}", row.mnemonic).trim().to_string();
        self.ensure_patches();
        self.begin_patch(row.address, Some(row.bytes), PatchOrigin::Instruction(text));
    }

    /// Opens the patch dialog on the selection of the Hex view.
    pub fn begin_patch_bytes(&mut self) {
        let Some(sel) = self.views.hex.selection.clone() else {
            self.toast(
                ToastLevel::Info,
                "Select bytes in the Hex view first, then patch them.",
            );
            return;
        };
        let len = (sel.end - sel.start).min(MAX_PATCH_BYTES as u64);
        let original: Option<Vec<u8>> = (sel.start..sel.start + len)
            .map(|a| self.views.bytes.byte(a))
            .collect();
        self.ensure_patches();
        self.begin_patch(sel.start, original, PatchOrigin::Bytes);
    }

    /// Updates the replacement being typed.
    pub fn set_patch_input(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.input = text.into();
            d.error = None;
        }
    }

    /// Updates the note being typed.
    pub fn set_patch_note(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.note = text.into();
            d.error = None;
        }
    }

    /// Chooses the patch set for the patch being staged (`""` for none).
    pub fn set_patch_dialog_group(&mut self, group: impl Into<String>) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.group = group.into();
        }
    }

    /// Updates the instruction being typed.
    pub fn set_patch_asm(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.asm = text.into();
            if !matches!(d.asm_state, AsmState::Busy) {
                d.asm_state = AsmState::Idle;
                d.asm_note = None;
            }
        }
    }

    /// Assembles the typed instruction at the dialog's address and puts the shortest encoding
    /// in the hex field.
    pub fn assemble_patch(&mut self) {
        let Some(d) = self.tools.patch_dialog.as_mut() else {
            return;
        };
        let text = d.asm.trim().to_string();
        if text.is_empty() || matches!(d.asm_state, AsmState::Busy) {
            return;
        }
        d.asm_state = AsmState::Busy;
        d.asm_note = None;
        let address = d.address;
        self.call(
            "assemble",
            json!({"address": hex(address), "text": text}),
            move |vm, res| {
                let Some(d) = vm
                    .tools
                    .patch_dialog
                    .as_mut()
                    .filter(|d| d.address == address)
                else {
                    return;
                };
                match res {
                    Ok(v) => {
                        let enc: Vec<Vec<u8>> = v["encodings"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|h| h.as_str()).map(unhex).collect())
                            .unwrap_or_default();
                        d.asm_note = asm_note(&v);
                        let padded = v["padded"].as_str().map(unhex);
                        match padded.as_ref().or(enc.first()) {
                            Some(first) => {
                                d.input = spaced_hex(first);
                                d.error = None;
                                d.asm_state = AsmState::Done(enc);
                            }
                            None => d.asm_state = AsmState::Failed("No encoding came back.".into()),
                        }
                    }
                    Err(e)
                        if e.code == kraken_proto::ErrorCode::Unsupported
                            && e.message.contains("llvm-mc") =>
                    {
                        d.asm_state = AsmState::Failed(plain_error(&e));
                    }
                    Err(e) if e.code == kraken_proto::ErrorCode::Unsupported => {
                        d.asm_state = AsmState::Failed(
                            "This engine cannot assemble instructions; open the project with the \
                             Ghidra engine, or type the bytes as hex."
                                .into(),
                        );
                    }
                    Err(e) => d.asm_state = AsmState::Failed(plain_error(&e)),
                }
            },
        );
    }

    /// Uses another encoding of the assembled instruction.
    pub fn pick_patch_encoding(&mut self, index: usize) {
        if let Some(d) = self.tools.patch_dialog.as_mut()
            && let AsmState::Done(enc) = &d.asm_state
            && let Some(b) = enc.get(index)
        {
            d.input = spaced_hex(b);
            d.error = None;
        }
    }

    /// Fills the rest of the instruction with `nop`s (x86).
    pub fn pad_patch_with_nops(&mut self) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.pad_with_nops();
        }
    }

    /// Closes the patch dialog without staging.
    pub fn cancel_patch(&mut self) {
        self.tools.patch_dialog = None;
    }

    /// Stages the patch (`patch_set`).
    pub fn submit_patch(&mut self) {
        let Some(d) = self.tools.patch_dialog.as_mut().filter(|d| !d.submitting) else {
            return;
        };
        let bytes = match d.check().and_then(|()| d.parsed()) {
            Ok(b) => b,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.submitting = true;
        let addr = d.address;
        let args = json!({
            "address": hex(addr),
            "bytes": spaced_hex(&bytes),
            "note": d.note.trim(),
            "group": d.group,
        });
        self.call("patch_set", args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.patch_dialog = None;
                vm.toast(
                    ToastLevel::Success,
                    format!(
                        "Staged a {}-byte patch at {}. Nothing on disk changes until you export.",
                        bytes.len(),
                        hex(addr)
                    ),
                );
                vm.refresh_patches();
                vm.refresh_history();
                vm.refresh_project();
            }
            Err(e) => {
                if let Some(d) = vm.tools.patch_dialog.as_mut() {
                    d.submitting = false;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Removes the patch at `addr` (`patch_remove`).
    pub fn remove_patch(&mut self, addr: u64) {
        self.call(
            "patch_remove",
            json!({"address": hex(addr)}),
            move |vm, res| match res {
                Ok(_) => {
                    vm.toast(
                        ToastLevel::Info,
                        format!("Removed the patch at {}.", hex(addr)),
                    );
                    vm.refresh_patches();
                    vm.refresh_history();
                    vm.refresh_project();
                }
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    /// Opens the export dialog for every patch that is on.
    pub fn begin_patch_export(&mut self) {
        self.begin_patch_export_group(None);
    }

    /// Opens the export dialog for one patch set (or all patches that are on, with `None`),
    /// suggesting `<binary>.patched` next to the project.
    pub fn begin_patch_export_group(&mut self, group: Option<String>) {
        let name = self
            .project
            .as_ref()
            .map(|p| p.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "program".into());
        let output_path = match &group {
            Some(g) => format!("{name}.{}.patched", file_stem(g)),
            None => format!("{name}.patched"),
        };
        self.tools.export_dialog = Some(ExportDialog {
            output_path,
            group,
            overwrite: false,
            error: None,
            submitting: false,
            done: None,
        });
    }

    /// Updates the export path being typed.
    pub fn set_export_path(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.export_dialog.as_mut() {
            d.output_path = text.into();
            d.error = None;
        }
    }

    /// Sets whether an existing file may be replaced.
    pub fn set_export_overwrite(&mut self, on: bool) {
        if let Some(d) = self.tools.export_dialog.as_mut() {
            d.overwrite = on;
            d.error = None;
        }
    }

    /// Closes the export dialog.
    pub fn cancel_patch_export(&mut self) {
        self.tools.export_dialog = None;
    }

    /// Writes the patched binary (`patch_export`; the backend asks for approval first).
    pub fn submit_patch_export(&mut self) {
        let Some(d) = self.tools.export_dialog.as_mut().filter(|d| !d.submitting) else {
            return;
        };
        let path = d.output_path.trim().to_string();
        if path.is_empty() {
            d.error = Some("Choose where to write the patched binary.".into());
            return;
        }
        d.submitting = true;
        let mut args = json!({"output_path": path, "overwrite": d.overwrite});
        if let Some(g) = &d.group {
            args["group"] = json!(g);
        }
        self.call("patch_export", args, move |vm, res| {
            match res.and_then(parse::<ExportWire>) {
                Ok(out) => {
                    let done = ExportDone {
                        output_path: out.output_path,
                        applied: out.applied.len(),
                        bytes_written: out.bytes_written,
                        sha256: out.sha256,
                    };
                    if let Some(d) = vm.tools.export_dialog.as_mut() {
                        d.submitting = false;
                        d.done = Some(done.clone());
                    }
                    vm.tools.patches.last_export = Some(done);
                }
                Err(e) => {
                    if let Some(d) = vm.tools.export_dialog.as_mut() {
                        d.submitting = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }

    /// Shows the Patches tab.
    pub fn show_patches(&mut self) {
        self.ensure_patches();
        self.tools.request_tab(NavTab::Patches);
    }
}

/// A set name as part of a file name.
fn file_stem(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    s.trim_matches('_').to_string()
}

/// The sentence about NOP padding and replaced instructions in an `assemble` result.
fn asm_note(v: &serde_json::Value) -> Option<String> {
    let pad = v["pad"].as_u64().unwrap_or(0);
    let over = v["overwritten"].as_u64().unwrap_or(0);
    if pad == 0 && over == 0 {
        return None;
    }
    let mut note = format!(
        "Padded with {pad} byte{} of nop up to the next instruction.",
        if pad == 1 { "" } else { "s" }
    );
    if over > 0 {
        note.push_str(&format!(
            " Replaces {over} following instruction{}.",
            if over == 1 { "" } else { "s" }
        ));
    }
    Some(note)
}
