//! The import dialog: one flow for every way a program comes in (File > Open program, a file
//! dropped on the window, the welcome screen and a path on the command line). It probes the
//! file first (`binary_probe`), says what it found in plain words, and lets the person name the
//! project, pick where it goes and which engine opens it.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};

use egui::{Align, Layout, RichText, Ui};
use kraken_host::KrakenConfig;
use kraken_registry::commands::{BinaryFormat, BinaryProbeOut};
use kraken_registry::{EngineChoice, EngineKind};
use tokio::runtime::Handle;

use crate::style::{self, medium, pal};
use crate::welcome::{Choice, default_project_dir, engine_help, engine_label, project_dir_problem};

/// What a file dialog returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Picked {
    /// A program to import.
    Binary(String),
    /// An existing project folder to open.
    Project(String),
    /// A folder to save a new project in.
    Location(String),
}

/// File dialogs run off the UI thread; their answers arrive here.
pub struct Picker {
    tx: Sender<Picked>,
    rx: Receiver<Picked>,
}

impl Default for Picker {
    fn default() -> Self {
        let (tx, rx) = channel();
        Picker { tx, rx }
    }
}

/// The picker's filters. A portal filter cannot say "no extension", and most Linux programs
/// have none, so "Programs" also lists every file.
const PROGRAM_EXTENSIONS: [&str; 7] = ["", "exe", "dll", "so", "elf", "bin", "o"];

impl Picker {
    fn spawn(
        &self,
        rt: &Handle,
        ctx: &egui::Context,
        dialog: rfd::AsyncFileDialog,
        folder: bool,
        wrap: fn(String) -> Picked,
    ) {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        rt.spawn(async move {
            let picked = if folder {
                dialog.pick_folder().await
            } else {
                dialog.pick_file().await
            };
            if let Some(h) = picked {
                let _ = tx.send(wrap(h.path().to_string_lossy().into_owned()));
                ctx.request_repaint();
            }
        });
    }

    /// Asks for a program to import.
    pub fn binary(&self, rt: &Handle, ctx: &egui::Context) {
        let d = rfd::AsyncFileDialog::new()
            .set_title("Choose a program to import")
            .add_filter("Programs", &PROGRAM_EXTENSIONS)
            .add_filter("All files", &["*"]);
        self.spawn(rt, ctx, d, false, Picked::Binary);
    }

    /// Asks for an existing project folder.
    pub fn project(&self, rt: &Handle, ctx: &egui::Context, start: Option<PathBuf>) {
        let mut d = rfd::AsyncFileDialog::new().set_title("Open a KRAKEN project folder");
        if let Some(s) = start.filter(|s| s.is_dir()) {
            d = d.set_directory(s);
        }
        self.spawn(rt, ctx, d, true, Picked::Project);
    }

    /// Asks where a new project should be saved.
    pub fn location(&self, rt: &Handle, ctx: &egui::Context, start: Option<PathBuf>) {
        let mut d = rfd::AsyncFileDialog::new().set_title("Where should the project be saved?");
        if let Some(s) = start {
            // The dialog cannot open a folder that does not exist yet.
            let s = if s.is_dir() {
                s
            } else {
                s.parent().map(Path::to_path_buf).unwrap_or(s)
            };
            d = d.set_directory(s);
        }
        self.spawn(rt, ctx, d, true, Picked::Location);
    }

    /// Answers that arrived since the last call.
    pub fn drain(&self) -> Vec<Picked> {
        self.rx.try_iter().collect()
    }

    /// Feeds an answer as if a dialog had returned it (tests).
    #[cfg(test)]
    pub fn inject(&self, p: Picked) {
        let _ = self.tx.send(p);
    }
}

/// True when `dir` holds a KRAKEN project.
pub fn is_project_dir(dir: &Path) -> bool {
    dir.is_dir() && dir.join("meta.json").is_file()
}

/// Where the probe stands.
pub enum ProbeState {
    /// The file is being read.
    Probing(Receiver<Result<BinaryProbeOut, String>>),
    /// What the probe found.
    Ready(Box<BinaryProbeOut>),
    /// The file could not be read.
    Failed(String),
}

/// What the dialog asks the app to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportAction {
    /// Create the project.
    Import(Choice),
    /// Close the dialog.
    Cancel,
}

pub struct ImportDialog {
    /// The program being imported.
    pub binary: String,
    pub probe: ProbeState,
    /// Folder name of the project.
    pub name: String,
    /// The folder the project folder goes in.
    pub location: String,
    /// The engine to ask for.
    pub engine: EngineChoice,
    /// Start the analysis as soon as the project is open.
    pub analyze: bool,
    /// Whether the engine was set from the probe's recommendation yet.
    engine_set: bool,
    picker: Picker,
}

/// `12.3 KB`, `4.0 MB`: a size in plain words.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut v = bytes as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// One sentence: what the file is.
pub fn describe(p: &BinaryProbeOut) -> String {
    if p.format == BinaryFormat::Unknown {
        return format!(
            "KRAKEN does not recognise this file ({}).",
            human_size(p.size)
        );
    }
    let kind = match p.kind.as_str() {
        "executable" => "program",
        "shared_library" => "library",
        "object" => "object file (not linked yet)",
        "core" => "core dump",
        _ => "file",
    };
    let article = if p.format == BinaryFormat::Elf {
        "An"
    } else {
        "A"
    };
    let mut s = format!("{article} {} {kind}", p.format.label());
    if let Some(arch) = &p.arch {
        s.push_str(&format!(" for {arch}"));
    }
    let mut extra = Vec::new();
    if let Some(b) = p.bits {
        extra.push(format!("{b}-bit"));
    }
    if let Some(e) = &p.endian {
        extra.push(format!("{e}-endian"));
    }
    if !extra.is_empty() {
        s.push_str(&format!(" ({})", extra.join(", ")));
    }
    s.push_str(&format!(", {}.", human_size(p.size)));
    s
}

/// The facts below the summary, as (label, value, explanation) rows.
pub fn fact_rows(p: &BinaryProbeOut) -> Vec<(&'static str, String, &'static str)> {
    let mut rows = Vec::new();
    if let Some(stripped) = p.stripped {
        rows.push(if stripped {
            (
                "Function names",
                "Removed (stripped)".to_string(),
                "The program was shipped without its symbol table. Functions get placeholder names such as FUN_00401000 until you or the assistant name them.",
            )
        } else {
            (
                "Function names",
                "Present".to_string(),
                "The program still has its symbol table, so most functions keep their real names.",
            )
        });
    }
    if let Some(debug) = p.debug_info {
        rows.push(if debug {
            (
                "Debug information",
                "Present".to_string(),
                "Extra data the compiler left in: KRAKEN uses it for names, types and parameters.",
            )
        } else {
            (
                "Debug information",
                "None".to_string(),
                "No debug data. Types and parameter names are guessed by the decompiler.",
            )
        });
    }
    if let Some(e) = p.entry_point {
        rows.push((
            "Starts at",
            format!("{:#x}", e.0),
            "The address where the operating system starts running the program.",
        ));
    }
    rows.push((
        "SHA-256",
        p.sha256.chars().take(16).collect::<String>() + "...",
        "A fingerprint of the file. The project records it and warns you if the file changes.",
    ));
    rows
}

/// The engine choice's reason without the developer prefix `auto picked ...:`.
pub fn plain_reason(reason: &str) -> String {
    if let Some(rest) = reason.strip_prefix("auto picked Ghidra: ") {
        return format!("the native engine cannot be used here: {rest}");
    }
    reason
        .strip_prefix("auto picked native: ")
        .unwrap_or(reason)
        .to_string()
}

fn kind_label(k: EngineKind) -> &'static str {
    match k {
        EngineKind::Ghidra => "Ghidra",
        EngineKind::Native => "Native",
        EngineKind::Dotnet => ".NET",
    }
}

impl ImportDialog {
    /// Opens the dialog for `binary` and starts probing it on `rt`.
    pub fn start(cfg: &KrakenConfig, binary: &str, rt: &Handle, ctx: &egui::Context) -> Self {
        let (tx, rx) = channel();
        let (cfg2, path, ctx) = (cfg.clone(), PathBuf::from(binary), ctx.clone());
        rt.spawn_blocking(move || {
            let r = kraken_host::native::probe_binary(&cfg2, &path).map_err(|e| e.message);
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        Self::new(cfg, binary, ProbeState::Probing(rx))
    }

    /// The dialog over a finished probe.
    #[cfg(test)]
    pub fn with_probe(cfg: &KrakenConfig, binary: &str, probe: BinaryProbeOut) -> Self {
        let mut d = Self::new(cfg, binary, ProbeState::Ready(Box::new(probe)));
        d.apply_recommendation();
        d
    }

    fn new(cfg: &KrakenConfig, binary: &str, probe: ProbeState) -> Self {
        let dir = PathBuf::from(default_project_dir(cfg, binary));
        let name = dir
            .file_name()
            .map_or_else(|| "project".into(), |n| n.to_string_lossy().into_owned());
        let location = dir
            .parent()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned());
        ImportDialog {
            binary: binary.to_string(),
            probe,
            name,
            location,
            engine: cfg.engine.unwrap_or_default(),
            analyze: true,
            engine_set: false,
            picker: Picker::default(),
        }
    }

    /// Takes a finished probe and folder choices that arrived.
    pub fn poll(&mut self) {
        if let ProbeState::Probing(rx) = &self.probe {
            match rx.try_recv() {
                Ok(Ok(p)) => self.probe = ProbeState::Ready(Box::new(p)),
                Ok(Err(e)) => self.probe = ProbeState::Failed(e),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.probe = ProbeState::Failed("the file could not be read".into());
                }
            }
        }
        self.apply_recommendation();
        for p in self.picker.drain() {
            if let Picked::Location(dir) = p {
                self.location = dir;
            }
        }
    }

    fn apply_recommendation(&mut self) {
        if self.engine_set {
            return;
        }
        if let ProbeState::Ready(p) = &self.probe {
            self.engine_set = true;
            self.engine = match p.recommended_engine {
                Some(EngineKind::Native) => EngineChoice::Native,
                Some(EngineKind::Ghidra) => EngineChoice::Ghidra,
                Some(EngineKind::Dotnet) => EngineChoice::Auto,
                None => self.engine,
            };
        }
    }

    /// The probe result, once ready.
    pub fn probed(&self) -> Option<&BinaryProbeOut> {
        match &self.probe {
            ProbeState::Ready(p) => Some(p),
            _ => None,
        }
    }

    /// Where the project will be made.
    pub fn project_dir(&self) -> String {
        Path::new(self.location.trim())
            .join(self.name.trim())
            .to_string_lossy()
            .into_owned()
    }

    /// Why Import cannot be pressed yet, if so.
    pub fn blocker(&self) -> Option<String> {
        match &self.probe {
            ProbeState::Probing(_) => {
                return Some("Wait until KRAKEN has looked at the file.".into());
            }
            ProbeState::Failed(e) => return Some(format!("The file could not be read: {e}")),
            ProbeState::Ready(p) if !p.supported => {
                return Some(
                    p.problem
                        .clone()
                        .unwrap_or_else(|| "KRAKEN cannot open this file.".into()),
                );
            }
            ProbeState::Ready(_) => {}
        }
        let name = self.name.trim();
        if name.is_empty() {
            return Some("Give the project a name.".into());
        }
        if name.contains(['/', '\\']) {
            return Some("The name cannot contain slashes.".into());
        }
        if self.location.trim().is_empty() {
            return Some("Choose where to save the project.".into());
        }
        project_dir_problem(&self.project_dir())
    }

    /// The choice Import makes, when it can be pressed.
    pub fn choice(&self) -> Option<Choice> {
        if self.blocker().is_some() {
            return None;
        }
        Some(Choice::NewProject {
            binary: self.binary.clone(),
            project_dir: self.project_dir(),
            engine: self.engine,
            analyze: self.analyze,
        })
    }

    fn engine_row(&mut self, ui: &mut Ui, p: &BinaryProbeOut) {
        let pal = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("Engine", 13.0).color(pal.text_strong));
        if p.format == BinaryFormat::Dotnet {
            ui.label(
                RichText::new("The .NET engine, chosen automatically for .NET assemblies.")
                    .color(pal.text),
            )
            .on_hover_text(
                "Managed code always goes to the .NET engine (ILSpy). It shows C# instead of C.",
            );
        } else {
            ui.horizontal(|ui| {
                for (choice, kind) in [
                    (EngineChoice::Ghidra, EngineKind::Ghidra),
                    (EngineChoice::Native, EngineKind::Native),
                ] {
                    let status = p.engines.iter().find(|e| e.kind == kind);
                    let usable = status.is_none_or(|e| e.usable);
                    let mut label = engine_label(choice).to_string();
                    if p.recommended_engine == Some(kind) {
                        label.push_str(" (recommended)");
                    }
                    let r = ui.radio_value(&mut self.engine, choice, label);
                    let tip = if usable {
                        engine_help(choice).to_string()
                    } else {
                        format!(
                            "{} Not ready on this computer: {}",
                            engine_help(choice),
                            status.and_then(|e| e.problem.clone()).unwrap_or_default()
                        )
                    };
                    r.on_hover_text(tip);
                }
            });
        }
        if let Some(k) = p.recommended_engine {
            ui.label(
                RichText::new(format!(
                    "Why {}: {}",
                    kind_label(k),
                    plain_reason(&p.recommended_reason)
                ))
                .size(12.0)
                .color(pal.text_dim),
            );
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("On this computer:")
                    .size(11.5)
                    .color(pal.text_dim),
            );
            for e in &p.engines {
                let (text, color) = if e.usable {
                    (format!("{} ready", kind_label(e.kind)), s.success)
                } else {
                    (format!("{} not ready", kind_label(e.kind)), s.warning)
                };
                let r = ui.label(RichText::new(text).size(11.5).color(color));
                match &e.problem {
                    Some(why) => r.on_hover_text(why),
                    None => r.on_hover_text("Installed and ready to use."),
                };
            }
        });
        let chosen = match self.engine {
            EngineChoice::Ghidra => Some(EngineKind::Ghidra),
            EngineChoice::Native => Some(EngineKind::Native),
            EngineChoice::Auto => None,
        };
        if p.format != BinaryFormat::Dotnet
            && let Some(e) =
                chosen.and_then(|k| p.engines.iter().find(|e| e.kind == k && !e.usable))
        {
            ui.label(
                RichText::new(format!(
                    "{} is not ready here, so the import will probably fail. {}",
                    kind_label(e.kind),
                    e.problem.clone().unwrap_or_default()
                ))
                .size(12.0)
                .color(s.warning),
            );
        }
    }

    /// Draws the dialog. Escape and Cancel close it.
    pub fn show(&mut self, ctx: &egui::Context, rt: &Handle) -> Option<ImportAction> {
        self.poll();
        let mut action = None;
        let modal = egui::Modal::new(egui::Id::new("kraken_import")).show(ctx, |ui| {
            ui.set_width(560.0_f32.min(ctx.content_rect().width() - 48.0));
            let p = pal(ui);
            let s = style::status(style::dark(ui));
            ui.label(medium("Import a program", 18.0).color(p.text_strong));
            ui.add(
                egui::Label::new(RichText::new(&self.binary).monospace().size(12.0).color(p.text_dim))
                    .truncate(),
            )
            .on_hover_text(&self.binary);
            ui.add_space(8.0);
            let probed = match &self.probe {
                ProbeState::Probing(_) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Looking at the file...");
                    });
                    None
                }
                ProbeState::Failed(e) => {
                    ui.label(
                        RichText::new(format!("The file could not be read: {e}"))
                            .color(s.danger),
                    );
                    None
                }
                ProbeState::Ready(pr) => Some(pr.as_ref().clone()),
            };
            if let Some(pr) = &probed {
                ui.label(RichText::new(describe(pr)).size(14.0).color(p.text));
                if pr.supported {
                    egui::Grid::new("kraken_import_facts")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for (label, value, why) in fact_rows(pr) {
                                ui.label(RichText::new(label).color(p.text_dim))
                                    .on_hover_text(why);
                                let v = ui.label(RichText::new(value).color(p.text));
                                if label == "SHA-256" {
                                    v.on_hover_text(format!("{why}\n{}", pr.sha256));
                                } else {
                                    v.on_hover_text(why);
                                }
                                ui.end_row();
                            }
                        });
                } else if let Some(problem) = &pr.problem {
                    ui.add_space(4.0);
                    ui.label(RichText::new(problem).color(s.warning));
                }
            }
            if probed.as_ref().is_some_and(|p| p.supported) {
                ui.add_space(10.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Project name").color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name)
                            .desired_width(ui.available_width()),
                    )
                    .on_hover_text("The name of the project folder. It does not change the program.");
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Save in").color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.location)
                            .desired_width(ui.available_width() - 90.0),
                    )
                    .on_hover_text("The folder the project folder is created in.");
                    if ui
                        .button("Browse...")
                        .on_hover_text("Choose the folder the project is saved in")
                        .clicked()
                    {
                        let start = Some(PathBuf::from(self.location.trim()));
                        self.picker.location(rt, ctx, start);
                    }
                });
                ui.label(
                    RichText::new(format!("The project will be saved in {}", self.project_dir()))
                        .size(11.5)
                        .color(p.text_dim),
                );
                ui.add_space(6.0);
                if let Some(pr) = &probed {
                    self.engine_row(ui, pr);
                }
                ui.add_space(6.0);
                ui.checkbox(&mut self.analyze, "Analyze after import")
                    .on_hover_text(
                        "Find and name the functions as soon as the project opens. You can also start it later with Analyze.",
                    );
            }
            ui.add_space(10.0);
            let blocker = self.blocker();
            if let Some(b) = &blocker
                && !matches!(self.probe, ProbeState::Probing(_))
                && probed.as_ref().is_some_and(|p| p.supported)
            {
                ui.label(RichText::new(b).size(12.0).color(s.warning));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let import = ui
                    .add_enabled_ui(blocker.is_none(), |ui| {
                        style::primary_button(ui, "Import")
                            .on_hover_text("Create the project and open it")
                            .on_disabled_hover_text(blocker.clone().unwrap_or_default())
                    })
                    .inner;
                if import.clicked()
                    && let Some(c) = self.choice()
                {
                    action = Some(ImportAction::Import(c));
                }
                if ui
                    .button("Cancel")
                    .on_hover_text("Close this dialog without importing anything")
                    .clicked()
                {
                    action = Some(ImportAction::Cancel);
                }
            });
        });
        if action.is_none() && modal.should_close() {
            action = Some(ImportAction::Cancel);
        }
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(rel: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(rel)
            .to_string_lossy()
            .into_owned()
    }

    fn cfg_in(root: &Path) -> KrakenConfig {
        KrakenConfig {
            projects_root: Some(root.to_path_buf()),
            ..Default::default()
        }
    }

    fn probed(cfg: &KrakenConfig, rel: &str) -> ImportDialog {
        let bin = corpus(rel);
        let out = kraken_host::native::probe_binary(cfg, Path::new(&bin)).unwrap();
        ImportDialog::with_probe(cfg, &bin, out)
    }

    #[test]
    fn sizes_read_as_words() {
        assert_eq!(human_size(10), "10 bytes");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(5 << 20), "5.0 MB");
    }

    #[test]
    fn an_elf_program_is_described_and_can_be_imported() {
        let tmp = crate::testutil::tempdir();
        let cfg = cfg_in(tmp.path());
        let d = probed(&cfg, "bin/pie_list-O0");
        let p = d.probed().unwrap();
        let text = describe(p);
        assert!(text.starts_with("An ELF program for x86-64"), "{text}");
        assert!(plain_reason("auto picked Ghidra: no specs").starts_with("the native engine"));
        assert!(text.contains("64-bit"), "{text}");
        assert!(
            fact_rows(p)
                .iter()
                .any(|r| r.0 == "Function names" && r.1 == "Present")
        );
        assert_eq!(d.name, "pie_list-O0");
        assert_eq!(Path::new(&d.project_dir()), tmp.path().join("pie_list-O0"));
        assert!(d.blocker().is_none(), "{:?}", d.blocker());
        match d.choice() {
            Some(Choice::NewProject { analyze, .. }) => assert!(analyze),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_files_and_bad_names_block_the_import() {
        let tmp = crate::testutil::tempdir();
        let cfg = cfg_in(&tmp.path().join("projects"));
        let txt = tmp.path().join("notes.txt");
        std::fs::write(&txt, b"text").unwrap();
        let out = kraken_host::native::probe_binary(&cfg, &txt).unwrap();
        let d = ImportDialog::with_probe(&cfg, &txt.to_string_lossy(), out);
        assert!(d.blocker().unwrap().contains("does not recognise"));
        assert!(d.choice().is_none());

        let mut d = probed(&cfg, "bin/pie_list-O0");
        d.name = "a/b".into();
        assert!(d.blocker().unwrap().contains("slashes"));
        d.name = String::new();
        assert!(d.blocker().unwrap().contains("name"));
    }

    #[test]
    fn dotnet_assemblies_go_to_the_dotnet_engine_automatically() {
        let tmp = crate::testutil::tempdir();
        let d = probed(&cfg_in(tmp.path()), "dotnet/bin/kraken-corpus.dll");
        assert_eq!(d.probed().unwrap().format, BinaryFormat::Dotnet);
        assert_eq!(d.engine, EngineChoice::Auto);
    }

    #[test]
    fn a_chosen_location_arrives_through_the_picker() {
        let tmp = crate::testutil::tempdir();
        let mut d = probed(&cfg_in(tmp.path()), "bin/pie_list-O0");
        d.picker.inject(Picked::Location("/elsewhere".into()));
        d.poll();
        assert_eq!(d.location, "/elsewhere");
        assert_eq!(
            Path::new(&d.project_dir()),
            Path::new("/elsewhere/pie_list-O0")
        );
    }
}
