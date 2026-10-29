//! One-click patches: the right-click Patch items (NOP this, Invert / Always / Never take branch,
//! Make function return..., Fill...). Each opens a dialog that asks the backend for a preview
//! (`preview: true` on the `patch_*` command) showing the old and new bytes and the new
//! disassembly, and applies the same command when the person agrees. Applying records an
//! ordinary patch, so it is undoable from the History.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex};

/// Which intent a dialog is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentKind {
    /// `patch_nop`.
    Nop,
    /// `patch_branch` with `invert`.
    BranchInvert,
    /// `patch_branch` with `always`.
    BranchAlways,
    /// `patch_branch` with `never`.
    BranchNever,
    /// `patch_return`.
    Return,
    /// `patch_fill`.
    Fill,
}

impl IntentKind {
    /// The dialog title.
    pub fn title(self) -> &'static str {
        match self {
            IntentKind::Nop => "NOP this",
            IntentKind::BranchInvert => "Invert branch",
            IntentKind::BranchAlways => "Always take branch",
            IntentKind::BranchNever => "Never take branch",
            IntentKind::Return => "Make function return",
            IntentKind::Fill => "Fill bytes",
        }
    }

    /// One line on what it does.
    pub fn blurb(self) -> &'static str {
        match self {
            IntentKind::Nop => "Replaces the instruction with NOPs of this processor.",
            IntentKind::BranchInvert => "Takes the branch exactly when it was not taken.",
            IntentKind::BranchAlways => {
                "Turns the conditional branch into a jump to the same place."
            }
            IntentKind::BranchNever => "Removes the branch: execution always falls through.",
            IntentKind::Return => "Makes the function return a number as soon as it is called.",
            IntentKind::Fill => "Overwrites a range of bytes with a repeated pattern.",
        }
    }

    /// Whether the dialog asks for a value before previewing.
    pub fn takes_input(self) -> bool {
        matches!(self, IntentKind::Return | IntentKind::Fill)
    }
}

/// What the backend says it would write.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IntentPreview {
    /// Bytes covered.
    pub length: u32,
    /// The bytes now, hex.
    pub original: String,
    /// The bytes after, hex.
    pub replacement: String,
    /// The instructions replaced.
    #[serde(default)]
    pub old_disassembly: Vec<String>,
    /// The new bytes decoded; empty when the decoder is not available.
    #[serde(default)]
    pub new_disassembly: Vec<String>,
    /// Things to know.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The one-click patch dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentDialog {
    /// Which intent.
    pub kind: IntentKind,
    /// The address it acts on (the function entry for Return).
    pub address: u64,
    /// The return value (Return) or the length in bytes (Fill) as typed.
    pub value: String,
    /// The fill pattern as typed (Fill).
    pub pattern: String,
    /// A preview call is running.
    pub loading: bool,
    /// The preview, once it came back.
    pub preview: Option<IntentPreview>,
    /// Why the preview or the apply failed, in plain words.
    pub error: Option<String>,
    /// The apply call is running.
    pub applying: bool,
    seq: u64,
}

impl IntentDialog {
    /// The command and arguments for this dialog; `preview` asks only for the preview.
    /// `Err` when the typed input is not usable.
    pub fn request(&self, preview: bool) -> Result<(&'static str, Value), String> {
        let addr = hex(self.address);
        Ok(match self.kind {
            IntentKind::Nop => ("patch_nop", json!({"address": addr, "preview": preview})),
            IntentKind::BranchInvert | IntentKind::BranchAlways | IntentKind::BranchNever => {
                let mode = match self.kind {
                    IntentKind::BranchInvert => "invert",
                    IntentKind::BranchAlways => "always",
                    _ => "never",
                };
                (
                    "patch_branch",
                    json!({"address": addr, "mode": mode, "preview": preview}),
                )
            }
            IntentKind::Return => {
                let text = self.value.trim();
                let value = if text.is_empty() {
                    0
                } else {
                    parse_number(text)
                        .ok_or("The return value is a number such as 0, 1, -1 or 0x10.")?
                };
                (
                    "patch_return",
                    json!({"address": addr, "value": value, "preview": preview}),
                )
            }
            IntentKind::Fill => {
                let length = parse_number(self.value.trim())
                    .filter(|n| (1..=4096).contains(n))
                    .ok_or("The length is a number of bytes from 1 to 4096.")?;
                let pattern = self.pattern.trim();
                (
                    "patch_fill",
                    json!({
                        "address": addr,
                        "length": length,
                        "pattern": if pattern.is_empty() { "00" } else { pattern },
                        "preview": preview
                    }),
                )
            }
        })
    }
}

/// Reads a decimal or `0x` number, with an optional minus sign.
pub fn parse_number(text: &str) -> Option<i64> {
    let (neg, t) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok()?,
        None => t.parse::<i64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

impl ViewModel {
    /// Opens the one-click patch dialog for `kind` at `address`. NOP and the branch edits ask
    /// for their preview at once; Return and Fill wait for the value.
    pub fn begin_intent(&mut self, kind: IntentKind, address: u64) {
        self.ensure_patches();
        let seq = self.tools.next_seq();
        self.tools.intent_dialog = Some(IntentDialog {
            kind,
            address,
            value: match kind {
                IntentKind::Return => "0".into(),
                IntentKind::Fill => "1".into(),
                _ => String::new(),
            },
            pattern: if kind == IntentKind::Fill {
                "90".into()
            } else {
                String::new()
            },
            loading: false,
            preview: None,
            error: None,
            applying: false,
            seq,
        });
        self.preview_intent();
    }

    /// Updates the typed value and clears the stale preview.
    pub fn set_intent_value(&mut self, value: impl Into<String>) {
        if let Some(d) = self.tools.intent_dialog.as_mut() {
            d.value = value.into();
            d.preview = None;
            d.error = None;
        }
    }

    /// Updates the typed fill pattern and clears the stale preview.
    pub fn set_intent_pattern(&mut self, pattern: impl Into<String>) {
        if let Some(d) = self.tools.intent_dialog.as_mut() {
            d.pattern = pattern.into();
            d.preview = None;
            d.error = None;
        }
    }

    /// Asks the backend what the patch would write.
    pub fn preview_intent(&mut self) {
        let seq = self.tools.next_seq();
        let Some(d) = self.tools.intent_dialog.as_mut() else {
            return;
        };
        let (cmd, args) = match d.request(true) {
            Ok(r) => r,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.loading = true;
        d.error = None;
        d.seq = seq;
        self.call(cmd, args, move |vm, res| {
            let Some(d) = vm.tools.intent_dialog.as_mut().filter(|d| d.seq == seq) else {
                return;
            };
            d.loading = false;
            match res {
                Ok(v) => match serde_json::from_value::<IntentPreview>(v) {
                    Ok(p) => d.preview = Some(p),
                    Err(e) => d.error = Some(format!("The answer was not understood: {e}")),
                },
                Err(e) => d.error = Some(plain_error(&e)),
            }
        });
    }

    /// Records the patch.
    pub fn apply_intent(&mut self) {
        let Some(d) = self
            .tools
            .intent_dialog
            .as_mut()
            .filter(|d| !d.applying && d.preview.is_some())
        else {
            return;
        };
        let (cmd, args) = match d.request(false) {
            Ok(r) => r,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.applying = true;
        let (title, address) = (d.kind.title(), d.address);
        self.call(cmd, args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.intent_dialog = None;
                vm.toast(
                    ToastLevel::Success,
                    format!(
                        "{title} at {}: staged. Undo it from the History; nothing on disk changes \
                         until you export.",
                        hex(address)
                    ),
                );
                vm.refresh_patches();
                vm.refresh_history();
                vm.refresh_project();
            }
            Err(e) => {
                if let Some(d) = vm.tools.intent_dialog.as_mut() {
                    d.applying = false;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Closes the dialog.
    pub fn cancel_intent(&mut self) {
        self.tools.intent_dialog = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_read_in_decimal_and_hex() {
        assert_eq!(parse_number("12"), Some(12));
        assert_eq!(parse_number("-1"), Some(-1));
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("- 0x10"), Some(-16));
        assert_eq!(parse_number("x"), None);
    }

    fn dialog(kind: IntentKind, value: &str) -> IntentDialog {
        IntentDialog {
            kind,
            address: 0x401000,
            value: value.into(),
            pattern: "cc".into(),
            loading: false,
            preview: None,
            error: None,
            applying: false,
            seq: 0,
        }
    }

    #[test]
    fn requests_name_the_command_and_its_arguments() {
        let (c, a) = dialog(IntentKind::BranchInvert, "").request(true).unwrap();
        assert_eq!(c, "patch_branch");
        assert_eq!(
            a,
            json!({"address": "0x401000", "mode": "invert", "preview": true})
        );
        let (c, a) = dialog(IntentKind::Return, "-1").request(false).unwrap();
        assert_eq!(c, "patch_return");
        assert_eq!(a["value"], -1);
        let (c, a) = dialog(IntentKind::Fill, "16").request(false).unwrap();
        assert_eq!(
            (c, &a["length"], &a["pattern"]),
            ("patch_fill", &json!(16), &json!("cc"))
        );
        assert!(dialog(IntentKind::Fill, "0").request(true).is_err());
        assert!(dialog(IntentKind::Return, "abc").request(true).is_err());
    }
}
