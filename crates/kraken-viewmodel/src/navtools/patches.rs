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
}

/// One emulated run, as the Patches tab shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSide {
    /// How it ended, in words ("exit code 0", "signal 11").
    pub exit: String,
    /// Standard output (program data).
    pub stdout: String,
    /// Standard error (program data).
    pub stderr: String,
    /// The emulator's notes.
    pub notes: Vec<String>,
}

/// The original and the patched program run side by side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCompare {
    /// The program as it is on disk.
    pub original: Result<RunSide, String>,
    /// With every patch applied.
    pub patched: Result<RunSide, String>,
}

impl RunCompare {
    /// True when both ran and behaved the same (exit and output).
    pub fn same(&self) -> bool {
        match (&self.original, &self.patched) {
            (Ok(a), Ok(b)) => a.exit == b.exit && a.stdout == b.stdout && a.stderr == b.stderr,
            _ => false,
        }
    }
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
    /// The emulator is running the program.
    pub running: bool,
    /// The last original-versus-patched run.
    pub run: Option<RunCompare>,
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
    /// Why writing failed.
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PatchWire {
    address: Hex64,
    original: String,
    replacement: String,
    note: Untrusted<String>,
    author_kind: String,
    author_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ExitWire {
    kind: String,
    value: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct RunWire {
    exit: ExitWire,
    stdout: Untrusted<String>,
    stderr: Untrusted<String>,
    notes: Vec<String>,
}

impl From<RunWire> for RunSide {
    fn from(w: RunWire) -> Self {
        let exit = match (w.exit.kind.as_str(), w.exit.value) {
            ("code", Some(v)) => format!("exit code {v}"),
            ("signal", Some(v)) => format!("signal {v}"),
            ("timeout", _) => "ran out of time".into(),
            ("step_limit", _) => "ran out of instructions".into(),
            ("unsupported", _) => "needs something the emulator lacks".into(),
            (k, _) => k.replace('_', " "),
        };
        RunSide {
            exit,
            stdout: w.stdout.0,
            stderr: w.stderr.0,
            notes: w.notes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ExportWire {
    output_path: String,
    applied: Vec<serde_json::Value>,
    bytes_written: u64,
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

    /// Reloads the patches from the first page.
    pub fn refresh_patches(&mut self) {
        self.tools.patches.generation += 1;
        self.tools.patches.next_cursor = None;
        self.fetch_patches(true);
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

    /// Updates the instruction being typed.
    pub fn set_patch_asm(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.patch_dialog.as_mut() {
            d.asm = text.into();
            if !matches!(d.asm_state, AsmState::Busy) {
                d.asm_state = AsmState::Idle;
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
                        match enc.first() {
                            Some(first) => {
                                d.input = spaced_hex(first);
                                d.error = None;
                                d.asm_state = AsmState::Done(enc);
                            }
                            None => d.asm_state = AsmState::Failed("No encoding came back.".into()),
                        }
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

    /// Opens the export dialog, suggesting `<binary>.patched` next to the project.
    pub fn begin_patch_export(&mut self) {
        let name = self
            .project
            .as_ref()
            .map(|p| p.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "program".into());
        self.tools.export_dialog = Some(ExportDialog {
            output_path: format!("{name}.patched"),
            overwrite: false,
            error: None,
            submitting: false,
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
        let args = json!({"output_path": path, "overwrite": d.overwrite});
        self.call("patch_export", args, move |vm, res| {
            match res.and_then(parse::<ExportWire>) {
                Ok(out) => {
                    vm.tools.export_dialog = None;
                    vm.toast(
                        ToastLevel::Success,
                        format!(
                            "Wrote {} with {} patch{}.",
                            out.output_path,
                            out.applied.len(),
                            if out.applied.len() == 1 { "" } else { "es" }
                        ),
                    );
                    vm.tools.patches.last_export = Some(ExportDone {
                        output_path: out.output_path,
                        applied: out.applied.len(),
                        bytes_written: out.bytes_written,
                    });
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

    /// Runs the program in the emulator as it is and with the patches, to compare them.
    pub fn run_patched_compare(&mut self) {
        if self.tools.patches.running {
            return;
        }
        self.tools.patches.running = true;
        self.tools.patches.run = None;
        self.call("emulate_run", json!({"patched": false}), |vm, original| {
            let original = original
                .and_then(parse::<RunWire>)
                .map(RunSide::from)
                .map_err(|e| plain_error(&e));
            vm.call(
                "emulate_run",
                json!({"patched": true}),
                move |vm, patched| {
                    let patched = patched
                        .and_then(parse::<RunWire>)
                        .map(RunSide::from)
                        .map_err(|e| plain_error(&e));
                    vm.tools.patches.running = false;
                    vm.tools.patches.run = Some(RunCompare { original, patched });
                },
            );
        });
    }

    /// Shows the Patches tab.
    pub fn show_patches(&mut self) {
        self.ensure_patches();
        self.tools.request_tab(NavTab::Patches);
    }
}
