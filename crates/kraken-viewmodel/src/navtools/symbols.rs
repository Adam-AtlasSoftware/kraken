//! File > Import symbols...: pick a map, CSV, splat or IDA script, preview what it would name
//! and where it clashes (`symbols_import` with `dry_run`), then apply it as one undoable run.

use serde::Deserialize;
use serde_json::json;

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, parse};

/// Formats the dialog offers, as the command names them, with the label shown.
pub const SYMBOL_FORMATS: [(&str, &str); 6] = [
    ("auto", "Detect"),
    ("gnu_map", "GNU ld map"),
    ("msvc_map", "MSVC map"),
    ("csv", "CSV"),
    ("splat", "splat symbol_addrs"),
    ("idc", "IDA script (IDC)"),
];

/// What to do with a name that clashes, as the command names it, with the label shown.
pub const SYMBOL_CONFLICTS: [(&str, &str); 3] = [
    ("skip", "Keep the existing name"),
    ("overwrite", "Replace it"),
    ("propose", "File a proposal"),
];

/// One row of the preview table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SymbolRow {
    /// `rename` or `comment`.
    pub op: String,
    /// Address after the offset, as `0x...`.
    pub address: String,
    /// New name for a rename.
    #[serde(default)]
    pub name: Option<String>,
    /// Comment text.
    #[serde(default)]
    pub text: Option<String>,
    /// `new`, `unchanged`, `conflict`, `invalid` or `duplicate`.
    pub status: String,
    /// The name the program has now.
    #[serde(default)]
    pub existing: Option<String>,
    /// `apply`, `propose` or `skip`.
    pub action: String,
    /// Why it is invalid or was refused.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What a dry run or an import reported.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SymbolsReport {
    /// The format that was read.
    pub format: String,
    /// Run id of a real import.
    #[serde(default)]
    pub run_id: Option<String>,
    /// Records in the file.
    pub records: u32,
    /// New names and comments.
    pub new: u32,
    /// Names already in place.
    pub unchanged: u32,
    /// Names that clash.
    pub conflicts: u32,
    /// Refused entries.
    pub invalid: u32,
    /// Repeated addresses.
    pub duplicates: u32,
    /// Applied edits.
    pub applied: u32,
    /// Filed proposals.
    pub proposed: u32,
    /// Refused edits.
    pub rejected: u32,
    /// Lines that did not parse.
    pub ignored_lines: u32,
    /// Notes about the file.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The table: conflicts first.
    #[serde(default)]
    pub edits: Vec<SymbolRow>,
    /// Rows left out of the table.
    #[serde(default)]
    pub edits_omitted: u32,
}

/// The Import symbols dialog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolsDialog {
    /// File to read.
    pub path: String,
    /// Index into [`SYMBOL_FORMATS`].
    pub format: usize,
    /// Index into [`SYMBOL_CONFLICTS`].
    pub conflicts: usize,
    /// Offset typed by the person: `0x100000`, `-0x1000` or decimal.
    pub offset: String,
    /// Why the last call failed.
    pub error: Option<String>,
    /// A call is running.
    pub busy: bool,
    /// The preview of the current settings.
    pub preview: Option<SymbolsReport>,
}

/// Reads `0x100000`, `-0x1000`, `4096` as an offset; empty is zero.
pub fn parse_offset(text: &str) -> Option<i64> {
    let t = text.trim();
    if t.is_empty() {
        return Some(0);
    }
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r.trim_start()),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok()?,
        None => t.parse::<i64>().ok()?,
    };
    if neg { v.checked_neg() } else { Some(v) }
}

impl ViewModel {
    /// Opens the Import symbols dialog.
    pub fn begin_import_symbols(&mut self) {
        if self.project.is_none() {
            return;
        }
        self.tools.symbols_dialog = Some(SymbolsDialog::default());
    }

    /// Closes the dialog.
    pub fn cancel_import_symbols(&mut self) {
        self.tools.symbols_dialog = None;
    }

    /// Edits the dialog's fields; any change drops the preview.
    pub fn edit_symbols_dialog(&mut self, f: impl FnOnce(&mut SymbolsDialog)) {
        if let Some(d) = self.tools.symbols_dialog.as_mut() {
            let before = d.clone();
            f(d);
            if *d != before {
                d.preview = None;
                d.error = None;
            }
        }
    }

    fn symbols_args(&self, dry_run: bool) -> Result<serde_json::Value, String> {
        let d = self
            .tools
            .symbols_dialog
            .as_ref()
            .ok_or("The dialog is closed.")?;
        if d.path.trim().is_empty() {
            return Err("Choose the symbol file.".into());
        }
        let offset =
            parse_offset(&d.offset).ok_or("The offset is a number such as 0x100000 or -0x1000.")?;
        Ok(json!({
            "path": d.path.trim(),
            "format": SYMBOL_FORMATS[d.format.min(SYMBOL_FORMATS.len() - 1)].0,
            "conflicts": SYMBOL_CONFLICTS[d.conflicts.min(SYMBOL_CONFLICTS.len() - 1)].0,
            "base_offset": offset,
            "dry_run": dry_run,
            "preview_limit": 500,
        }))
    }

    /// Reads the file and lists what the import would do, changing nothing.
    pub fn preview_import_symbols(&mut self) {
        let args = match self.symbols_args(true) {
            Ok(a) => a,
            Err(e) => {
                if let Some(d) = self.tools.symbols_dialog.as_mut() {
                    d.error = Some(e);
                }
                return;
            }
        };
        let Some(d) = self.tools.symbols_dialog.as_mut().filter(|d| !d.busy) else {
            return;
        };
        d.busy = true;
        d.error = None;
        self.call("symbols_import", args, move |vm, res| {
            let Some(d) = vm.tools.symbols_dialog.as_mut() else {
                return;
            };
            d.busy = false;
            match res.and_then(parse::<SymbolsReport>) {
                Ok(r) => d.preview = Some(r),
                Err(e) => d.error = Some(plain_error(&e)),
            }
        });
    }

    /// Applies the import as one run and closes the dialog.
    pub fn submit_import_symbols(&mut self) {
        let args = match self.symbols_args(false) {
            Ok(a) => a,
            Err(e) => {
                if let Some(d) = self.tools.symbols_dialog.as_mut() {
                    d.error = Some(e);
                }
                return;
            }
        };
        let Some(d) = self.tools.symbols_dialog.as_mut().filter(|d| !d.busy) else {
            return;
        };
        d.busy = true;
        d.error = None;
        self.call("symbols_import", args, move |vm, res| {
            match res.and_then(parse::<SymbolsReport>) {
                Ok(r) => {
                    vm.tools.symbols_dialog = None;
                    let mut text = format!("Imported {} edits", r.applied);
                    if r.proposed > 0 {
                        text.push_str(&format!(", filed {} proposals", r.proposed));
                    }
                    if r.rejected > 0 {
                        text.push_str(&format!(", {} refused", r.rejected));
                    }
                    text.push_str(". History can undo them all in one step");
                    if let Some(id) = &r.run_id {
                        text.push_str(&format!(" (run {id})"));
                    }
                    text.push('.');
                    vm.toast(ToastLevel::Info, text);
                    vm.refresh_functions();
                    vm.refresh_history();
                    vm.refresh_project();
                }
                Err(e) => {
                    if let Some(d) = vm.tools.symbols_dialog.as_mut() {
                        d.busy = false;
                        d.error = Some(plain_error(&e));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::parse_offset;

    #[test]
    fn offsets_read_hex_signed_and_empty() {
        assert_eq!(parse_offset(""), Some(0));
        assert_eq!(parse_offset("0x100000"), Some(0x10_0000));
        assert_eq!(parse_offset(" -0x1000 "), Some(-0x1000));
        assert_eq!(parse_offset("4096"), Some(4096));
        assert_eq!(parse_offset("zz"), None);
    }
}
