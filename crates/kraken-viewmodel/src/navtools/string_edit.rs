//! "Edit string...": rewrites a string of the program in place (`patch_string`).
//!
//! The dialog asks the command for the string that is there now (a preview with empty text), so
//! the room the new text has is the engine's answer, then counts the bytes of what is typed as
//! it is typed. Same length or shorter fits, with NUL padding; longer is refused with the number
//! of bytes to cut. Nothing on disk changes until the patches are exported.

use kraken_registry::commands::{PatchStringEncoding, encode_string};
use serde::Deserialize;
use serde_json::json;

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// The dialog that edits a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringDialog {
    /// The string's address.
    pub address: u64,
    /// The encoding asked for (`Auto` looks at the bytes).
    pub encoding: PatchStringEncoding,
    /// The encoding the program's string was found in, once known.
    pub found: Option<PatchStringEncoding>,
    /// The string now, once read.
    pub old_text: Option<String>,
    /// The room the new text has, in bytes (the old text's, terminator not counted).
    pub capacity: Option<usize>,
    /// The new text typed.
    pub input: String,
    /// The note typed.
    pub note: String,
    /// The patch set it goes in; empty for none.
    pub group: String,
    /// Why the string could not be read or saved.
    pub error: Option<String>,
    /// The string is being read.
    pub probing: bool,
    /// The save is running.
    pub submitting: bool,
    generation: u64,
}

impl StringDialog {
    /// The encoding the counter uses.
    pub fn effective(&self) -> PatchStringEncoding {
        match self.encoding {
            PatchStringEncoding::Auto => self.found.unwrap_or(PatchStringEncoding::Utf8),
            e => e,
        }
    }

    /// Bytes the typed text takes in the encoding, or why it cannot be stored.
    pub fn needed(&self) -> Result<usize, String> {
        encode_string(&self.input, self.effective())
            .map(|b| b.len())
            .map_err(|e| e.message)
    }

    /// Whether Save may be pressed, or the plain reason it may not.
    pub fn check(&self) -> Result<(), String> {
        if self.probing {
            return Err("Reading the string...".into());
        }
        let Some(capacity) = self.capacity else {
            return Err(self
                .error
                .clone()
                .unwrap_or_else(|| "The string could not be read.".into()));
        };
        let needed = self.needed()?;
        if needed > capacity {
            return Err(format!(
                "{} byte{} too long: the string here holds {capacity} byte{}. Shorten the text; \
                 nothing after the string can move.",
                needed - capacity,
                if needed - capacity == 1 { "" } else { "s" },
                if capacity == 1 { "" } else { "s" },
            ));
        }
        if self.old_text.as_deref() == Some(self.input.as_str()) {
            return Err("That is what the string says already.".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ProbeWire {
    encoding: String,
    old_text: kraken_proto::Untrusted<String>,
    capacity: u32,
}

fn encoding_arg(e: PatchStringEncoding) -> &'static str {
    match e {
        PatchStringEncoding::Auto => "auto",
        PatchStringEncoding::Ascii => "ascii",
        PatchStringEncoding::Utf8 => "utf8",
        PatchStringEncoding::Utf16le => "utf16le",
    }
}

fn found_encoding(name: &str) -> PatchStringEncoding {
    match name {
        "ascii" => PatchStringEncoding::Ascii,
        "utf16le" => PatchStringEncoding::Utf16le,
        _ => PatchStringEncoding::Utf8,
    }
}

impl ViewModel {
    /// Opens the dialog on the string at `address` and reads what is there.
    pub fn begin_string_edit(&mut self, address: u64) {
        self.ensure_patches();
        self.tools.string_dialog = Some(StringDialog {
            address,
            encoding: PatchStringEncoding::Auto,
            found: None,
            old_text: None,
            capacity: None,
            input: String::new(),
            note: String::new(),
            group: String::new(),
            error: None,
            probing: true,
            submitting: false,
            generation: 0,
        });
        self.probe_string(true);
    }

    fn probe_string(&mut self, fill: bool) {
        let Some(d) = self.tools.string_dialog.as_mut() else {
            return;
        };
        d.generation += 1;
        d.probing = true;
        d.error = None;
        let (address, generation) = (d.address, d.generation);
        let args = json!({
            "address": hex(address),
            "text": "",
            "encoding": encoding_arg(d.encoding),
            "preview": true,
        });
        self.call("patch_string", args, move |vm, res| {
            let Some(d) = vm
                .tools
                .string_dialog
                .as_mut()
                .filter(|d| d.generation == generation)
            else {
                return;
            };
            d.probing = false;
            match res.and_then(parse::<ProbeWire>) {
                Ok(p) => {
                    d.found = Some(found_encoding(&p.encoding));
                    d.capacity = Some(p.capacity as usize);
                    if fill {
                        d.input = p.old_text.0.clone();
                    }
                    d.old_text = Some(p.old_text.0);
                }
                Err(e) => {
                    d.capacity = None;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Updates the new text.
    pub fn set_string_input(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.string_dialog.as_mut() {
            d.input = text.into();
            d.error = None;
        }
    }

    /// Updates the note.
    pub fn set_string_note(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.string_dialog.as_mut() {
            d.note = text.into();
        }
    }

    /// Chooses the patch set for the edit (`""` for none).
    pub fn set_string_group(&mut self, group: impl Into<String>) {
        if let Some(d) = self.tools.string_dialog.as_mut() {
            d.group = group.into();
        }
    }

    /// Chooses the encoding and reads the string again under it.
    pub fn set_string_encoding(&mut self, encoding: PatchStringEncoding) {
        let Some(d) = self.tools.string_dialog.as_mut() else {
            return;
        };
        if d.encoding == encoding {
            return;
        }
        d.encoding = encoding;
        self.probe_string(false);
    }

    /// Closes the dialog without saving.
    pub fn cancel_string_edit(&mut self) {
        self.tools.string_dialog = None;
    }

    /// Saves the new text (`patch_string`).
    pub fn submit_string_edit(&mut self) {
        let Some(d) = self.tools.string_dialog.as_mut().filter(|d| !d.submitting) else {
            return;
        };
        if let Err(e) = d.check() {
            d.error = Some(e);
            return;
        }
        d.submitting = true;
        let (address, used) = (d.address, d.needed().unwrap_or(0));
        let args = json!({
            "address": hex(address),
            "text": d.input,
            "encoding": encoding_arg(d.encoding),
            "note": d.note.trim(),
            "group": d.group,
        });
        self.call("patch_string", args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.string_dialog = None;
                vm.toast(
                    ToastLevel::Success,
                    format!(
                        "Staged a {used}-byte string at {}. Nothing on disk changes until you \
                         export.",
                        hex(address)
                    ),
                );
                vm.refresh_patches();
                vm.refresh_history();
                vm.refresh_project();
            }
            Err(e) => {
                if let Some(d) = vm.tools.string_dialog.as_mut() {
                    d.submitting = false;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }
}
