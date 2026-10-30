//! File > Import program...: the Import wizard. Seven steps (the loader options only for a raw
//! file, the debug-information step only for ELF and PE programs): pick the file, what it is, the
//! engine, loader options, debug information, analysis options, summary. It reuses the quick
//! import dialog's probe and pieces (`ImportDialog`) and adds the debug-information step, which
//! asks `debuginfo_probe` what the program refers to and checks every debug file it can find or
//! the person points at.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use egui::{RichText, Ui};
use kraken_host::KrakenConfig;
use kraken_proto::DwarfState;
use kraken_registry::EngineChoice;
use kraken_registry::commands::{
    BinaryFormat, ConfigStore, DebugCandidate, DebugFindOut, DebugInfoProbeOut, DebugStatus,
    Verdict, debug_wanted, find_debug_file, normalize_symbol_server, symbol_servers_with_env,
    symbols_offline_env,
};
use kraken_viewmodel::RawLoad;
use kraken_viewmodel::wizard::WizardFlow;
use tokio::runtime::Handle;

use crate::import::{ImportDialog, Picked, Picker, describe, fact_rows, members_note};
use crate::style::{self, medium, pal};
use crate::welcome::{Choice, engine_label};

/// The steps of the wizard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImportStep {
    /// Choose the file.
    File,
    /// What the file is.
    Kind,
    /// Which engine opens it.
    Engine,
    /// Raw files: processor, base address, entry.
    Loader,
    /// What debug information the program refers to, and the files that match.
    DebugInfo,
    /// Project name, folder and analysis.
    Analysis,
    /// What will be done.
    Summary,
}

/// Where the debug-information check stands.
enum DebugProbe {
    /// Not started (no program yet, or the step does not apply).
    Idle,
    /// Being read; the path asked about (a file or folder the person chose) rides along.
    Running(Receiver<(Option<String>, Result<DebugInfoProbeOut, String>)>),
}

/// The "Search symbol servers" part of the debug-information step.
struct SymbolSearch {
    /// The person ticked the consent box.
    consent: bool,
    /// The servers, as typed (space separated); filled in the first time the step is shown.
    servers: Option<String>,
    /// A search in flight.
    running: Option<Receiver<Result<DebugFindOut, String>>>,
    /// What the last search found out.
    last: Option<DebugFindOut>,
    /// Why the last search could not run.
    error: Option<String>,
}

/// The debug-information step's state.
pub struct DebugState {
    search: SymbolSearch,
    probe: DebugProbe,
    /// The last good answer.
    out: Option<Box<DebugInfoProbeOut>>,
    /// The file or folder the person chose last.
    chosen: Option<String>,
    /// What went wrong with the last choice (a folder with no debug file in it).
    error: Option<String>,
    /// Attach the best matching file when the project is created.
    use_file: bool,
    /// The engine was changed to Native for the debug file.
    switched: bool,
}

impl DebugState {
    fn new() -> Self {
        DebugState {
            search: SymbolSearch {
                consent: false,
                servers: None,
                running: None,
                last: None,
                error: None,
            },
            probe: DebugProbe::Idle,
            out: None,
            chosen: None,
            error: None,
            use_file: true,
            switched: false,
        }
    }

    /// The answer, once there is one.
    pub fn answer(&self) -> Option<&DebugInfoProbeOut> {
        self.out.as_deref()
    }

    fn running(&self) -> bool {
        matches!(self.probe, DebugProbe::Running(_))
    }
}

/// The wizard.
pub struct ImportWizard {
    step: ImportStep,
    /// The path as typed on the first step.
    pub path: String,
    /// The quick dialog's state for the file: probe, engine, raw options, name, folder.
    pub dialog: Option<ImportDialog>,
    started_for: String,
    picker: Picker,
    cfg: KrakenConfig,
    rt: Handle,
    ctx: egui::Context,
    /// The debug-information step.
    pub debug: DebugState,
    /// Where `config.toml` is, to record the consent to search symbol servers.
    pub config_path: Option<PathBuf>,
}

#[cfg(test)]
impl ImportWizard {
    /// The picker, to feed it a file dialog's answer.
    pub fn picker(&self) -> &Picker {
        &self.picker
    }
}

impl ImportWizard {
    /// A wizard on its first step; with `path` already known it opens on step 2.
    pub fn open(
        cfg: &KrakenConfig,
        path: Option<String>,
        rt: &Handle,
        ctx: &egui::Context,
    ) -> Self {
        let mut w = ImportWizard {
            step: ImportStep::File,
            path: path.clone().unwrap_or_default(),
            dialog: None,
            started_for: String::new(),
            picker: Picker::default(),
            cfg: cfg.clone(),
            rt: rt.clone(),
            ctx: ctx.clone(),
            debug: DebugState::new(),
            config_path: KrakenConfig::default_path(),
        };
        if path.is_some() {
            w.start_file();
            w.step = ImportStep::Kind;
        }
        w
    }

    /// Fills in the symbol search the way a person would, before pressing its button.
    #[cfg(test)]
    pub fn set_search(&mut self, servers: &str, consent: bool) {
        self.debug.search.servers = Some(servers.to_string());
        self.debug.search.consent = consent;
    }

    /// The current step.
    #[cfg(test)]
    pub fn step(&self) -> ImportStep {
        self.step
    }

    fn start_file(&mut self) {
        let path = self.path.trim().to_string();
        if path == self.started_for && self.dialog.is_some() {
            return;
        }
        self.started_for = path.clone();
        self.debug = DebugState::new();
        self.dialog = Some(ImportDialog::start(&self.cfg, &path, &self.rt, &self.ctx));
    }

    /// Whether the file is an Intel HEX or S-record firmware image.
    fn records(&self) -> bool {
        self.dialog.as_ref().is_some_and(|d| {
            d.probed()
                .is_some_and(|p| matches!(p.format, BinaryFormat::IntelHex | BinaryFormat::Srec))
        })
    }

    /// Whether the debug-information step applies to this file.
    fn debug_applies(&self) -> bool {
        self.dialog.as_ref().is_some_and(|d| {
            !d.raw_active()
                && d.probed()
                    .is_some_and(|p| matches!(p.format, BinaryFormat::Elf | BinaryFormat::Pe))
        })
    }

    fn start_debug(&mut self, extra: Option<String>) {
        let (tx, rx) = channel();
        let (path, ctx) = (PathBuf::from(self.started_for.clone()), self.ctx.clone());
        let ask = extra.clone();
        self.rt.spawn_blocking(move || {
            let r =
                kraken_registry::commands::probe_debug_info(&path, ask.as_deref().map(Path::new))
                    .map_err(|e| e.message);
            let _ = tx.send((ask, r));
            ctx.request_repaint();
        });
        self.debug.probe = DebugProbe::Running(rx);
    }

    /// Records the consent and the servers in `config.toml`, then asks them for the program's
    /// debug file; the answer arrives through [`poll`](Self::poll).
    fn start_search(&mut self, refs: kraken_proto::DebugRefs) {
        let text = self.debug.search.servers.clone().unwrap_or_default();
        let mut servers = Vec::new();
        for u in text.split_whitespace() {
            match normalize_symbol_server(u) {
                Ok(u) => servers.push(u),
                Err(e) => {
                    self.debug.search.error = Some(e);
                    return;
                }
            }
        }
        if servers.is_empty() {
            self.debug.search.error = Some("Enter at least one server address.".into());
            return;
        }
        let Some(path) = self.config_path.clone() else {
            self.debug.search.error =
                Some("Cannot tell where config.toml is, so the consent cannot be recorded.".into());
            return;
        };
        let (tx, rx) = channel();
        let ctx = self.ctx.clone();
        self.debug.search.error = None;
        self.debug.search.last = None;
        self.rt.spawn(async move {
            let store = kraken_host::config_keys::HostConfigStore::at(path);
            let recorded = store
                .set("debuginfo.servers", serde_json::json!(servers))
                .and_then(|_| store.set("debuginfo.consent", serde_json::json!(true)))
                .map_err(|e| format!("cannot record your consent: {}", e.message));
            let r = match recorded {
                Ok(_) => find_debug_file(&refs, &servers).await,
                Err(e) => Err(e),
            };
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.debug.search.running = Some(rx);
    }

    /// Takes finished probes and folder picks; call every frame.
    pub fn poll(&mut self) {
        if let Some(rx) = &self.debug.search.running {
            match rx.try_recv() {
                Ok(r) => {
                    self.debug.search.running = None;
                    match r {
                        Ok(out) => {
                            let found = out.found;
                            self.debug.search.last = Some(out);
                            if found {
                                self.start_debug(None);
                            }
                        }
                        Err(e) => self.debug.search.error = Some(e),
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.debug.search.running = None,
            }
        }
        if let Some(d) = self.dialog.as_mut() {
            d.poll();
        }
        if let DebugProbe::Running(rx) = &self.debug.probe {
            match rx.try_recv() {
                Ok((ask, Ok(out))) => {
                    self.debug.use_file = out.best.is_some();
                    self.debug.out = Some(Box::new(out));
                    self.debug.chosen = ask;
                    self.debug.error = None;
                    self.debug.probe = DebugProbe::Idle;
                }
                Ok((_, Err(e))) => {
                    self.debug.error = Some(e);
                    self.debug.probe = DebugProbe::Idle;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.debug.probe = DebugProbe::Idle,
            }
        }
        for p in self.picker.drain() {
            match p {
                Picked::Binary(b) => self.path = b,
                Picked::Location(dir) => {
                    if let Some(d) = self.dialog.as_mut() {
                        d.location = dir;
                    }
                }
                Picked::DebugFile(f) | Picked::DebugFolder(f) => self.start_debug(Some(f)),
                Picked::Project(_) => {}
            }
        }
    }

    /// The debug file the project will get, when the person left "use it" on: separate DWARF
    /// only (a PDB is read by Ghidra from beside the program).
    pub fn debug_file(&self) -> Option<String> {
        let out = self.debug.out.as_deref()?;
        if !self.debug_applies() || !self.debug.use_file || out.refs.pdb.is_some() {
            return None;
        }
        out.best.as_ref().map(|b| b.0.clone())
    }

    /// The project the wizard would create, when everything is in order.
    pub fn choice(&self) -> Option<Choice> {
        let Some(Choice::NewProject {
            binary,
            project_dir,
            engine,
            analyze,
            raw,
            ..
        }) = self.dialog.as_ref()?.choice()
        else {
            return None;
        };
        let raw = if self.records() {
            let d = self.dialog.as_ref()?;
            Some(RawLoad {
                language: d.raw_load.language.clone(),
                records: true,
                ..RawLoad::default()
            })
        } else {
            raw
        };
        Some(Choice::NewProject {
            binary,
            project_dir,
            engine,
            analyze,
            raw,
            debug_file: self.debug_file(),
        })
    }
}

fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:=+@%".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

impl WizardFlow for ImportWizard {
    type Step = ImportStep;
    const ID: &'static str = "import";

    fn steps(&self) -> Vec<ImportStep> {
        let mut v = vec![ImportStep::File, ImportStep::Kind, ImportStep::Engine];
        if self.dialog.as_ref().is_some_and(ImportDialog::raw_active) || self.records() {
            v.push(ImportStep::Loader);
        }
        if self.debug_applies() {
            v.push(ImportStep::DebugInfo);
        }
        v.push(ImportStep::Analysis);
        v.push(ImportStep::Summary);
        v
    }

    fn current(&self) -> ImportStep {
        self.step
    }

    fn set_current(&mut self, step: ImportStep) {
        self.step = step;
    }

    fn title(&self, step: ImportStep) -> &'static str {
        match step {
            ImportStep::File => "File",
            ImportStep::Kind => "What it is",
            ImportStep::Engine => "Engine",
            ImportStep::Loader => "Loading",
            ImportStep::DebugInfo => "Debug information",
            ImportStep::Analysis => "Project",
            ImportStep::Summary => "Create",
        }
    }

    fn explain(&self, step: ImportStep) -> &'static str {
        match step {
            ImportStep::File => {
                "Choose the program, library or firmware file to import. It is only read, never changed."
            }
            ImportStep::Kind => {
                "KRAKEN looks at the file and says what it is and what it can do with it."
            }
            ImportStep::Engine => {
                "The engine does the analysis. The recommended one is already chosen."
            }
            ImportStep::Loader => {
                "A file with no header does not say how it is laid out: tell KRAKEN the processor and where the code lives."
            }
            ImportStep::DebugInfo => {
                "Debug information gives functions their real names and types. It may be inside the program, in a separate file, or missing."
            }
            ImportStep::Analysis => {
                "Name the project, choose where it is saved, and say whether to analyze at once."
            }
            ImportStep::Summary => "Check the choices. Create makes the project and opens it.",
        }
    }

    fn blocker(&self) -> Option<String> {
        match self.step {
            ImportStep::File => {
                let p = self.path.trim();
                if p.is_empty() {
                    Some("Choose a file to import.".into())
                } else if !Path::new(p).is_file() {
                    Some("That path is not a file. Check it or use Browse.".into())
                } else {
                    None
                }
            }
            ImportStep::Kind => self.dialog.as_ref().and_then(ImportDialog::probe_blocker),
            ImportStep::Engine => self.dialog.as_ref().and_then(ImportDialog::probe_blocker),
            ImportStep::Loader if self.records() => self
                .dialog
                .as_ref()
                .filter(|d| d.raw_load.language.trim().is_empty())
                .map(|_| "Choose the processor the firmware was built for.".to_string()),
            ImportStep::Loader => self.dialog.as_ref().and_then(ImportDialog::raw_problem),
            ImportStep::DebugInfo => {
                let d = self.dialog.as_ref()?;
                (self.debug_file().is_some() && d.engine == EngineChoice::Ghidra).then(|| {
                    "A separate DWARF file works with the native engine. Go back and choose Native or Automatic, or untick \"Use this file\".".to_string()
                })
            }
            ImportStep::Analysis | ImportStep::Summary => {
                self.dialog.as_ref().and_then(ImportDialog::blocker)
            }
        }
    }

    fn leave(&mut self, step: ImportStep) {
        match step {
            ImportStep::File => self.start_file(),
            ImportStep::Kind | ImportStep::Engine | ImportStep::Loader => {
                if self.records()
                    && let Some(d) = self.dialog.as_mut()
                    && d.raw_load.language.trim().is_empty()
                    && let Some(first) = d.probed().and_then(|p| p.raw_options.first().cloned())
                {
                    d.use_suggestion(&first);
                }
                if self.debug_applies() && !self.debug.running() && self.debug.out.is_none() {
                    self.start_debug(None);
                }
            }
            _ => {}
        }
    }

    fn finish_label(&self) -> &'static str {
        "Create project"
    }

    fn commands(&self) -> Vec<String> {
        let Some(Choice::NewProject {
            binary,
            project_dir,
            engine,
            analyze,
            raw,
            ..
        }) = self.choice()
        else {
            return Vec::new();
        };
        let mut c = format!(
            "kraken project-create --binary {} --project-dir {} --engine {}",
            quote(&binary),
            quote(&project_dir),
            engine.as_str()
        );
        if let Some(r) = raw {
            if !r.records {
                c.push_str(" --loader raw");
            }
            c.push_str(&format!(" --language {}", quote(r.language.trim())));
            for (flag, v) in [
                ("base", &r.base),
                ("offset", &r.offset),
                ("length", &r.length),
                ("entry", &r.entry),
            ] {
                if !v.trim().is_empty() {
                    c.push_str(&format!(" --{flag} {}", quote(v.trim())));
                }
            }
        }
        if let Some(f) = self.debug_file() {
            c.push_str(&format!(" --debug-file {}", quote(&f)));
        }
        let mut out = vec![c];
        if analyze {
            out.push("kraken analyze".into());
        }
        out
    }
}

/// Draws the current step.
pub fn body(ui: &mut Ui, w: &mut ImportWizard) {
    w.poll();
    match w.step {
        ImportStep::File => file_step(ui, w),
        ImportStep::Kind => kind_step(ui, w),
        ImportStep::Engine => engine_step(ui, w),
        ImportStep::Loader => loader_step(ui, w),
        ImportStep::DebugInfo => debug_step(ui, w),
        ImportStep::Analysis => analysis_step(ui, w),
        ImportStep::Summary => summary_step(ui, w),
    }
}

fn file_step(ui: &mut Ui, w: &mut ImportWizard) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new("File").color(p.text_dim));
        ui.add(
            egui::TextEdit::singleline(&mut w.path)
                .hint_text("/path/to/program")
                .desired_width(ui.available_width() - 90.0),
        )
        .on_hover_text(
            "The path of the program, library or firmware file. You can type it or use Browse.",
        );
        if ui
            .button("Browse...")
            .on_hover_text("Choose the file in a file dialog")
            .clicked()
        {
            w.picker.binary(&w.rt, &w.ctx);
        }
    });
}

fn probing(ui: &mut Ui, w: &ImportWizard) -> bool {
    let s = style::status(style::dark(ui));
    let Some(d) = w.dialog.as_ref() else {
        ui.label("Choose a file first.");
        return false;
    };
    match &d.probe {
        crate::import::ProbeState::Probing(_) => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Looking at the file...");
            });
            false
        }
        crate::import::ProbeState::Failed(e) => {
            ui.label(RichText::new(format!("The file could not be read: {e}")).color(s.danger));
            false
        }
        crate::import::ProbeState::Ready(_) => true,
    }
}

fn kind_step(ui: &mut Ui, w: &mut ImportWizard) {
    if !probing(ui, w) {
        return;
    }
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(pr) = w.dialog.as_ref().and_then(|d| d.probed()).cloned() else {
        return;
    };
    ui.label(RichText::new(describe(&pr)).size(14.0).color(p.text));
    if let Some(pl) = &pr.platform {
        ui.add_space(4.0);
        egui::Grid::new("kraken_wizard_platform")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Format").color(p.text_dim))
                    .on_hover_text("The file format KRAKEN recognised.");
                ui.label(RichText::new(&pl.format_name).color(p.text));
                ui.end_row();
                ui.label(RichText::new("Platform").color(p.text_dim))
                    .on_hover_text("The system the program was made to run on.");
                ui.label(RichText::new(&pl.name).color(p.text));
                ui.end_row();
                if !pl.detail.is_empty() {
                    ui.label(RichText::new("Details").color(p.text_dim))
                        .on_hover_text("What the file's header says.");
                    ui.label(RichText::new(&pl.detail).color(p.text));
                    ui.end_row();
                }
                ui.label(RichText::new("Confidence").color(p.text_dim))
                    .on_hover_text("How sure the detector is: a magic number or checksum is high; structure checks alone are medium.");
                ui.label(RichText::new(&pl.confidence).color(p.text));
                ui.end_row();
            });
        ui.add_space(4.0);
        ui.label(medium("What KRAKEN can do with it", 13.0).color(p.text_strong));
        for c in &pl.capabilities {
            ui.label(
                RichText::new(format!("\u{2022} {c}"))
                    .size(12.5)
                    .color(p.text),
            );
        }
        if pl.emulators.is_empty() {
            ui.label(
                RichText::new("\u{2022} No catalogue emulator runs this file; the built-in emulator can run Linux programs.")
                    .size(12.5)
                    .color(p.text_dim),
            );
        }
    }
    ui.add_space(6.0);
    if pr.supported {
        egui::Grid::new("kraken_wizard_facts")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                for (label, value, why) in fact_rows(&pr) {
                    ui.label(RichText::new(label).color(p.text_dim))
                        .on_hover_text(why);
                    ui.label(RichText::new(value).color(p.text))
                        .on_hover_text(why);
                    ui.end_row();
                }
            });
        if let Some(note) = members_note(&pr) {
            ui.add_space(4.0);
            ui.label(RichText::new(note).size(12.0).color(p.text_dim));
        }
    } else if let Some(problem) = &pr.problem {
        ui.label(RichText::new(problem).color(s.warning));
    }
}

fn engine_step(ui: &mut Ui, w: &mut ImportWizard) {
    if !probing(ui, w) {
        return;
    }
    let Some(d) = w.dialog.as_mut() else { return };
    let Some(pr) = d.probed().cloned() else {
        return;
    };
    d.engine_row(ui, &pr);
}

fn loader_step(ui: &mut Ui, w: &mut ImportWizard) {
    let records = w.records();
    let Some(d) = w.dialog.as_mut() else { return };
    let Some(pr) = d.probed().cloned() else {
        return;
    };
    if !records {
        d.raw_section(ui, &pr);
        return;
    }
    let p = pal(ui);
    ui.label(
        RichText::new(
            "The records give the addresses and the start address, so only the processor is missing. KRAKEN suggests one from the code it found.",
        )
        .size(12.5)
        .color(p.text),
    );
    ui.add_space(4.0);
    for s in pr.raw_options.clone() {
        let name = crate::import::RAW_PROCESSORS
            .iter()
            .find(|(_, n)| *n == s.language)
            .map_or(s.language.as_str(), |(l, _)| *l);
        if ui
            .selectable_label(
                d.raw_load.language == s.language,
                format!("{name} ({} confidence)", s.confidence),
            )
            .on_hover_text(format!("{} Click to use it.", s.why))
            .clicked()
        {
            d.raw_load.language = s.language.clone();
        }
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("Processor").color(p.text_dim));
        egui::ComboBox::from_id_salt("kraken_wizard_records_processor")
            .selected_text(
                crate::import::RAW_PROCESSORS
                    .iter()
                    .find(|(_, n)| n.eq_ignore_ascii_case(d.raw_load.language.trim()))
                    .map_or("Choose...", |(l, _)| *l),
            )
            .width(260.0)
            .show_ui(ui, |ui| {
                for (label, name) in crate::import::RAW_PROCESSORS {
                    ui.selectable_value(&mut d.raw_load.language, name.to_string(), label)
                        .on_hover_text(format!("Open the firmware as {label} code."));
                }
            })
            .response
            .on_hover_text("The processor the firmware was built for.");
    });
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Match => "Matches",
        Verdict::Unverified => "Cannot be checked",
        Verdict::Mismatch => "Does not match",
        Verdict::NotDebugInfo => "Not usable",
    }
}

fn candidate_row(ui: &mut Ui, c: &DebugCandidate) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let color = match c.verdict {
        Verdict::Match => s.success,
        Verdict::Unverified => s.warning,
        Verdict::Mismatch | Verdict::NotDebugInfo => s.danger,
    };
    egui::Frame::new()
        .fill(p.surface)
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(medium(verdict_text(c.verdict), 12.5).color(color));
                ui.label(
                    RichText::new(format!("({})", c.source.label()))
                        .size(12.0)
                        .color(p.text_dim),
                );
            });
            ui.add(
                egui::Label::new(
                    RichText::new(&c.path.0)
                        .monospace()
                        .size(11.5)
                        .color(p.text),
                )
                .truncate(),
            )
            .on_hover_text(&c.path.0);
            ui.label(
                RichText::new(&c.detail.0)
                    .size(12.0)
                    .color(match c.verdict {
                        Verdict::Match => p.text_dim,
                        _ => color,
                    }),
            );
        });
}

fn refs_grid(ui: &mut Ui, out: &DebugInfoProbeOut) {
    let p = pal(ui);
    let r = &out.refs;
    let mut rows: Vec<(&str, String, &str)> = Vec::new();
    if let Some(pdb) = &r.pdb {
        rows.push((
            "PDB",
            format!("{} (GUID {}, age {})", pdb.name.0, pdb.guid, pdb.age),
            "The program was linked against this PDB: the GUID and age identify the exact build.",
        ));
    }
    if let Some(id) = &r.build_id {
        rows.push((
            "Build-id",
            id.clone(),
            "A fingerprint the linker put in the program. A debug file with the same build-id belongs to it.",
        ));
    }
    if let Some(l) = &r.debuglink {
        rows.push((
            "Debug link",
            format!("{} (CRC-32 {:#010x})", l.name.0, l.crc),
            "The program names a separate debug file and the checksum of its contents.",
        ));
    }
    rows.push((
        "DWARF inside",
        match r.dwarf {
            Some(DwarfState::Embedded) => "Yes",
            Some(DwarfState::Compressed) => "Yes (compressed)",
            Some(DwarfState::Split) => "Points at another file",
            None => "No",
        }
        .to_string(),
        "DWARF is the debug format of ELF programs.",
    ));
    egui::Grid::new("kraken_wizard_debug_refs")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for (label, value, why) in rows {
                ui.label(RichText::new(label).color(p.text_dim))
                    .on_hover_text(why);
                ui.add(egui::Label::new(RichText::new(value).color(p.text)).wrap())
                    .on_hover_text(why);
                ui.end_row();
            }
        });
}

fn debug_step(ui: &mut Ui, w: &mut ImportWizard) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    if w.debug.out.is_none() && !w.debug.running() {
        w.start_debug(None);
    }
    if w.debug.running() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Looking for debug information...");
        });
    }
    if let Some(e) = &w.debug.error {
        ui.label(RichText::new(e).size(12.5).color(s.warning));
        ui.add_space(4.0);
    }
    let Some(out) = w.debug.out.clone() else {
        return;
    };
    let status_color = match out.status {
        DebugStatus::Embedded | DebugStatus::Found => s.success,
        DebugStatus::Missing => s.warning,
        DebugStatus::None => p.text_dim,
    };
    ui.label(RichText::new(&out.summary).size(13.0).color(status_color));
    ui.add_space(6.0);
    refs_grid(ui, &out);
    if out.refs.pdb.is_some() && out.status != DebugStatus::Embedded {
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "A PDB is read by the Ghidra engine when it sits next to the program as <name>.pdb. Put the matching PDB there; the native engine does not read PDB files yet.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
    }
    if !out.candidates.is_empty() {
        ui.add_space(8.0);
        ui.label(medium("Files that were checked", 13.0).color(p.text_strong));
        for c in &out.candidates {
            candidate_row(ui, c);
            ui.add_space(3.0);
        }
    }
    if let Some(best) = &out.best
        && out.refs.pdb.is_none()
    {
        // A separate DWARF file is read by the native engine only: switch to it when it is
        // installed, and say so.
        if w.debug.use_file
            && let Some(d) = w.dialog.as_mut()
            && d.engine == EngineChoice::Ghidra
            && d.probed().is_some_and(|p| {
                p.engines
                    .iter()
                    .any(|e| e.kind == kraken_registry::EngineKind::Native && e.usable)
            })
        {
            d.engine = EngineChoice::Native;
            w.debug.switched = true;
        }
        let engine_ghidra = w
            .dialog
            .as_ref()
            .is_some_and(|d| d.engine == EngineChoice::Ghidra);
        if w.debug.switched && w.debug.use_file {
            ui.label(
                RichText::new(
                    "The engine was switched to Native, which reads separate DWARF. You can change it on the Engine step.",
                )
                .size(12.0)
                .color(p.text_dim),
            );
        }
        ui.add_space(4.0);
        ui.checkbox(
            &mut w.debug.use_file,
            format!("Use this file ({})", file_name(&best.0)),
        )
        .on_hover_text(
            "The project reads names and types from this file. You can detach it later with debuginfo_detach.",
        );
        if engine_ghidra && w.debug.use_file {
            ui.label(
                RichText::new(format!(
                    "The {} engine is chosen; it does not read separate DWARF.",
                    engine_label(EngineChoice::Ghidra)
                ))
                .size(12.0)
                .color(s.warning),
            );
        }
    }
    symbol_search(ui, w, &out);
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        let start = w
            .started_for
            .rsplit_once('/')
            .map(|(d, _)| PathBuf::from(d));
        if ui
            .button("Choose debug file...")
            .on_hover_text("Point KRAKEN at a .debug or .pdb file. It is checked against the program before it is used.")
            .clicked()
        {
            w.picker.debug_file(&w.rt, &w.ctx, start.clone());
        }
        if ui
            .button("Choose folder...")
            .on_hover_text("Point KRAKEN at a folder that holds the debug file; the file it needs is looked for by name and build-id.")
            .clicked()
        {
            w.picker.debug_folder(&w.rt, &w.ctx, start);
        }
    });
    if !out.searched.is_empty() {
        egui::CollapsingHeader::new(format!("Places that were searched ({})", out.searched.len()))
            .id_salt("kraken_wizard_searched")
            .show(ui, |ui| {
                for pth in &out.searched {
                    ui.label(RichText::new(&pth.0).monospace().size(11.5).color(p.text_dim));
                }
            })
            .header_response
            .on_hover_text("Beside the program, in its .debug folder, under /usr/lib/debug and in the debuginfod cache.");
    }
}

/// "Search symbol servers": offered when the program names debug information that is not on
/// this computer. Nothing is sent until the person ticks the consent box and presses the button.
fn symbol_search(ui: &mut Ui, w: &mut ImportWizard, out: &DebugInfoProbeOut) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    if out.best.is_some()
        || out.status == DebugStatus::Embedded
        || debug_wanted(&out.refs).is_none()
    {
        return;
    }
    let offline = w.cfg.debuginfo.offline || symbols_offline_env();
    if w.debug.search.servers.is_none() {
        let mut list = symbol_servers_with_env(&w.cfg.debuginfo.servers);
        if list.is_empty() {
            list.push(
                if out.refs.pdb.is_some() {
                    "https://msdl.microsoft.com/download/symbols"
                } else {
                    "https://debuginfod.elfutils.org"
                }
                .to_string(),
            );
        }
        w.debug.search.servers = Some(list.join(" "));
        w.debug.search.consent = w.cfg.debuginfo.consent;
    }
    ui.add_space(8.0);
    ui.label(medium("Symbol servers", 13.0).color(p.text_strong));
    let (ids, what) = match &out.refs.pdb {
        Some(pdb) => (
            format!(
                "{}, GUID {} and age {}",
                file_name(&pdb.name.0),
                pdb.guid,
                pdb.age
            ),
            "the PDB's name, GUID and age",
        ),
        None => (
            out.refs.build_id.clone().unwrap_or_default(),
            "the program's build-id",
        ),
    };
    if offline {
        ui.label(
            RichText::new(
                "Offline mode is on (debuginfo.offline or KRAKEN_OFFLINE): no server is asked.",
            )
            .size(12.0)
            .color(s.warning),
        );
        return;
    }
    ui.label(
        RichText::new(format!(
            "Ask a server for the matching debug file. Only {what} ({ids}) is sent; whatever comes back is checked against the program before it is used."
        ))
        .size(12.0)
        .color(p.text_dim),
    );
    let busy = w.debug.search.running.is_some();
    let mut text = w.debug.search.servers.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Servers").color(p.text_dim));
        ui.add(egui::TextEdit::singleline(&mut text).desired_width(ui.available_width()))
            .on_hover_text(
                "debuginfod servers (ELF, by build-id) or Microsoft-style symbol servers (PDB), separated by spaces. Only http:// and https:// addresses are accepted.",
            );
    });
    w.debug.search.servers = Some(text.clone());
    ui.checkbox(
        &mut w.debug.search.consent,
        "I agree to send this to these servers",
    )
    .on_hover_text(
        "Asking a server tells its operator which program you are looking at. Your agreement is saved in config.toml ([debuginfo] consent) and you can withdraw it with `kraken debuginfo-servers --consent false`.",
    );
    let ready = w.debug.search.consent && !busy && !text.trim().is_empty();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(ready, egui::Button::new("Search symbol servers"))
            .on_hover_text("Ask the servers above for this program's debug file. Nothing is sent before you tick the box.")
            .clicked()
        {
            w.start_search(out.refs.clone());
        }
        if busy {
            ui.spinner();
            ui.label("Asking the servers...");
        }
    });
    if let Some(e) = &w.debug.search.error {
        ui.label(RichText::new(e).size(12.0).color(s.warning));
    }
    if let Some(last) = &w.debug.search.last {
        let color = if last.found { s.success } else { s.warning };
        ui.label(RichText::new(&last.summary).size(12.5).color(color));
        if last.found
            && out.refs.pdb.is_some()
            && let Some(f) = &last.file
        {
            ui.label(
                RichText::new(format!(
                    "The PDB is at {}. The Ghidra engine reads a PDB that sits next to the program as <name>.pdb: copy it there.",
                    f.0
                ))
                .size(12.0)
                .color(p.text_dim),
            );
        }
        for a in &last.attempts {
            ui.label(
                RichText::new(format!("{}: {}", a.url.0, a.outcome.0))
                    .monospace()
                    .size(11.0)
                    .color(p.text_dim),
            );
        }
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn analysis_step(ui: &mut Ui, w: &mut ImportWizard) {
    let p = pal(ui);
    let rt = w.rt.clone();
    let ctx = w.ctx.clone();
    let Some(d) = w.dialog.as_mut() else { return };
    ui.horizontal(|ui| {
        ui.label(RichText::new("Project name").color(p.text_dim));
        ui.add(egui::TextEdit::singleline(&mut d.name).desired_width(ui.available_width()))
            .on_hover_text("The name of the project folder. It does not change the program.");
    });
    let mut browse = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Save in").color(p.text_dim));
        ui.add(
            egui::TextEdit::singleline(&mut d.location).desired_width(ui.available_width() - 90.0),
        )
        .on_hover_text("The folder the project folder is created in.");
        browse = ui
            .button("Browse...")
            .on_hover_text("Choose the folder the project is saved in")
            .clicked();
    });
    if browse {
        w.picker
            .location(&rt, &ctx, Some(PathBuf::from(d.location.trim())));
    }
    ui.label(
        RichText::new(format!("The project will be saved in {}", d.project_dir()))
            .size(11.5)
            .color(p.text_dim),
    );
    ui.add_space(6.0);
    ui.checkbox(&mut d.analyze, "Analyze after import")
        .on_hover_text(
            "Find and name the functions as soon as the project opens. You can also start it later with Analyze.",
        );
}

fn summary_step(ui: &mut Ui, w: &mut ImportWizard) {
    let p = pal(ui);
    let debug = w.debug_file();
    let Some(d) = w.dialog.as_ref() else { return };
    let Some(pr) = d.probed() else { return };
    let mut rows: Vec<(&str, String)> = vec![
        ("Program", d.binary.clone()),
        ("What it is", describe(pr)),
        ("Engine", engine_label(d.engine).to_string()),
    ];
    if d.raw_active() {
        let r = &d.raw_load;
        rows.push((
            "Loaded as",
            format!(
                "raw image, processor {}, base {}{}",
                r.language,
                if r.base.is_empty() { "0" } else { &r.base },
                if r.entry.is_empty() {
                    String::new()
                } else {
                    format!(", entry {}", r.entry)
                }
            ),
        ));
    }
    if w.debug_applies() {
        rows.push((
            "Debug information",
            match (&debug, w.debug.answer()) {
                (Some(f), _) => format!("separate file {f}"),
                (None, Some(o)) => match o.status {
                    DebugStatus::Embedded => "inside the program".into(),
                    DebugStatus::Found => "a matching PDB or file was found, not attached".into(),
                    DebugStatus::Missing => "named by the program but not found".into(),
                    DebugStatus::None => "none".into(),
                },
                (None, None) => "not checked".into(),
            },
        ));
    }
    rows.push(("Project folder", d.project_dir()));
    rows.push((
        "Analysis",
        if d.analyze {
            "starts as soon as the project opens".into()
        } else {
            "later, with Analyze".into()
        },
    ));
    egui::Grid::new("kraken_wizard_summary")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for (label, value) in rows {
                ui.label(RichText::new(label).color(p.text_dim))
                    .on_hover_text("A choice you made in this wizard.");
                ui.add(egui::Label::new(RichText::new(value).color(p.text)).wrap())
                    .on_hover_text("Go back to a step to change it.");
                ui.end_row();
            }
        });
}
