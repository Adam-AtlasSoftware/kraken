//! Choosing a folder with the system dialog, and showing a finished project's folder: the text
//! box with a Browse button, and the Open folder / Open in editor / Copy path buttons.

use std::sync::Mutex;

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::rewrite::DirCheck;

use crate::style::{self, pal};

/// What a chosen folder is for. Each purpose has one text box that takes the answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// The folder of the library export.
    Export,
    /// The folder of the whole-program crate.
    Program,
    /// Only for the test of the hand-over.
    #[cfg(test)]
    Probe,
}

static PICKS: Mutex<Vec<(Purpose, String)>> = Mutex::new(Vec::new());

/// Records a chosen folder; the text box of `purpose` takes it on its next frame.
pub fn deliver(purpose: Purpose, path: String) {
    if let Ok(mut p) = PICKS.lock() {
        p.retain(|(q, _)| *q != purpose);
        p.push((purpose, path));
    }
}

fn take(purpose: Purpose) -> Option<String> {
    let mut p = PICKS.lock().ok()?;
    let i = p.iter().position(|(q, _)| *q == purpose)?;
    Some(p.remove(i).1)
}

fn open_dialog(vm: &ViewModel, ctx: &egui::Context, purpose: Purpose, title: &'static str) {
    let ctx = ctx.clone();
    let start = vm.project.as_ref().map(|p| p.project_dir.clone());
    vm.runtime_handle().spawn(async move {
        let mut d = rfd::AsyncFileDialog::new().set_title(title);
        if let Some(s) = start.filter(|s| std::path::Path::new(s).is_dir()) {
            d = d.set_directory(s);
        }
        if let Some(h) = d.pick_folder().await {
            deliver(purpose, h.path().to_string_lossy().into_owned());
            ctx.request_repaint();
        }
    });
}

/// What a folder text box says about itself.
pub struct FolderField<'a> {
    /// Widget id, unique per place.
    pub id: &'a str,
    /// Grey text when empty.
    pub hint: &'a str,
    /// What the folder is for.
    pub purpose: Purpose,
    /// Title of the system dialog.
    pub title: &'static str,
    /// Hover text of the text box.
    pub tip: &'a str,
}

/// A folder text box with a Browse button and a note on where the folder is. `check` is the
/// view-model's reading of the text. Returns true when the text changed.
pub fn folder_field(
    ui: &mut Ui,
    vm: &ViewModel,
    text: &mut String,
    check: Option<&DirCheck>,
    enabled: bool,
    f: &FolderField<'_>,
) -> bool {
    let before = text.clone();
    if let Some(p) = take(f.purpose) {
        *text = p;
    }
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.add_enabled_ui(enabled, |ui| {
        ui.horizontal(|ui| {
            let w = (ui.available_width() - 84.0).max(120.0);
            ui.add(
                egui::TextEdit::singleline(text)
                    .id_salt(f.id)
                    .hint_text(f.hint)
                    .desired_width(w),
            )
            .on_hover_text(f.tip);
            if ui
                .button("Browse...")
                .on_hover_text("Choose the folder in a file dialog.")
                .clicked()
            {
                open_dialog(vm, ui.ctx(), f.purpose, f.title);
            }
        });
    });
    match (check, vm.project.as_ref()) {
        (Some(DirCheck::Inside), Some(proj)) => {
            ui.label(
                RichText::new(format!("Inside your project ({}).", proj.project_dir))
                    .size(11.5)
                    .color(p.text_dim),
            );
        }
        (Some(DirCheck::Outside), _) => {
            ui.label(
                RichText::new(
                    "This folder is outside your project. KRAKEN will ask before writing there.",
                )
                .size(12.0)
                .color(s.warning),
            );
        }
        (Some(DirCheck::Invalid(why)), _) => {
            ui.label(RichText::new(why).size(12.0).color(s.danger));
        }
        _ => {}
    }
    *text != before
}

/// A `file://` address for `path`, with the characters a URL cannot hold escaped.
pub fn file_url(path: &str) -> String {
    let mut out = String::from("file://");
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The file an editor should open for the project in `dir`: the program's `main.rs`, else the
/// workspace's `Cargo.toml`.
pub fn editor_file(dir: &str) -> String {
    let main = std::path::Path::new(dir).join("src").join("main.rs");
    if main.is_file() {
        main.to_string_lossy().into_owned()
    } else {
        std::path::Path::new(dir)
            .join("Cargo.toml")
            .to_string_lossy()
            .into_owned()
    }
}

/// Open folder, Open in editor and Copy path for the finished project in `dir`.
pub fn open_buttons(ui: &mut Ui, dir: &str) {
    ui.horizontal_wrapped(|ui| {
        if ui
            .button("Open folder")
            .on_hover_text("Show the folder in your file manager. Read the code before you trust it: the assistant wrote it.")
            .clicked()
        {
            ui.ctx()
                .open_url(egui::OpenUrl::new_tab(file_url(dir)));
        }
        if ui
            .button("Open in editor")
            .on_hover_text("Open the project's main file with the program your computer uses for Rust files or Cargo.toml.")
            .clicked()
        {
            ui.ctx()
                .open_url(egui::OpenUrl::new_tab(file_url(&editor_file(dir))));
        }
        if ui
            .button("Copy path")
            .on_hover_text("Copy the folder's path, for a terminal or another program.")
            .clicked()
        {
            ui.ctx().copy_text(dir.to_string());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_escape_spaces_and_non_ascii() {
        assert_eq!(file_url("/home/a b/ü"), "file:///home/a%20b/%C3%BC");
        assert_eq!(file_url("/tmp/x-1_2.rs"), "file:///tmp/x-1_2.rs");
    }

    #[test]
    fn a_delivered_folder_is_taken_once_by_its_purpose() {
        deliver(Purpose::Probe, "/a".into());
        deliver(Purpose::Probe, "/b".into());
        assert_eq!(take(Purpose::Probe).as_deref(), Some("/b"));
        assert_eq!(take(Purpose::Probe), None);
    }
}
