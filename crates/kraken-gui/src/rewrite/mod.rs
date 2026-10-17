//! The Rewrite tab (ADR 0013): the plan with a status chip per function, the selected function's
//! C next to the generated Rust with its test results, the spec, and the export dialog.

use egui::{Color32, Id, Rect, RichText, Sense, Shape, Ui, vec2};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::rewrite::{
    Availability, Flag, RewriteJob, RewriteMode, UnitItem, UnitStatus,
};
use kraken_viewmodel::{ViewModel, rewrite::status_explain};

use crate::style::{self, chip, empty_state, medium, pal, primary_button};
use crate::workspace::Tab;

mod detail;
mod export;
mod program;
mod spec_view;
#[cfg(test)]
mod tests;

pub use export::dialog as export_dialog;
pub use program::ProgramUi;

/// The function the `--scene rewrite` screenshot opens: `checksum`, which the demo script has
/// failed twice.
pub const SCENE_FUNCTION: u64 = 0x401240;

/// The layout of the Rewrite screenshot: the plan and detail get the whole window.
pub fn scene_dock() -> egui_dock::DockState<Tab> {
    use egui_dock::NodeIndex;
    let mut dock = egui_dock::DockState::new(vec![Tab::Rewrite, Tab::Decompiler, Tab::History]);
    let surface = dock.main_surface_mut();
    let [_main, _left] = surface.split_left(NodeIndex::root(), 0.13, vec![Tab::Functions]);
    dock
}

/// Which half of the detail pane is shown.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum DetailView {
    /// The C and the Rust side by side, with the test results.
    #[default]
    Code,
    /// The spec.
    Spec,
}

/// The two halves of the tab.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Section {
    /// The plan and one function at a time.
    #[default]
    Functions,
    /// The whole program: the function table, the crate and the program-level cases.
    Program,
}

/// GUI-only state of the tab.
#[derive(Default)]
pub struct RewriteUi {
    /// Functions or the whole program.
    pub section: Section,
    /// The Program view.
    pub program: ProgramUi,
    /// Only this status is listed.
    pub filter: Option<UnitStatus>,
    /// Code or spec.
    pub view: DetailView,
    /// Spec of the whole program instead of the selected function.
    pub program_spec: bool,
}

/// What the person asked for in one frame; applied after the drawing borrow ends.
#[derive(Default)]
pub(crate) struct Acts {
    pub select: Option<u64>,
    pub run: Option<(u64, RewriteMode)>,
    pub retry: Option<u64>,
    pub accept: Option<u64>,
    pub spec: Option<Option<u64>>,
    pub show_version: Option<(u64, u32)>,
    pub goto: Option<u64>,
    pub plan: bool,
    pub refresh: bool,
    pub export: bool,
}

/// The colour of a status chip.
pub(crate) fn status_color(s: UnitStatus, dark: bool, p: &Palette) -> Color32 {
    let st = style::status(dark);
    match s {
        UnitStatus::Planned => p.text_dim,
        UnitStatus::Translated => st.warning,
        UnitStatus::Verified => st.info,
        UnitStatus::Failed => st.danger,
        UnitStatus::Accepted => st.success,
    }
}

/// A chip that can be clicked; `active` draws it filled.
pub(crate) fn chip_button(ui: &mut Ui, text: &str, color: Color32, active: bool) -> egui::Response {
    let r = chip(ui, text, color);
    let r = ui.interact(r.rect, ui.id().with(("chip", text)), Sense::click());
    if active {
        ui.painter().rect_stroke(
            r.rect,
            9.0,
            egui::Stroke::new(1.5, color),
            egui::StrokeKind::Outside,
        );
    }
    r.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The Rewrite tab.
pub fn panel(ui: &mut Ui, vm: &mut ViewModel, st: &mut RewriteUi, front: &mut Option<Tab>) {
    vm.rewrite_ensure_loaded();
    section_switch(ui, vm, st);
    if st.section == Section::Program {
        if let Some(note) = vm.rewrite.blocked_note() {
            blocked_banner(
                ui,
                note,
                matches!(vm.rewrite.availability, Availability::NoConfinement(_)),
            );
        }
        jobs_strip(ui, vm);
        program::panel(ui, vm, &mut st.program, front);
        return;
    }
    let mut acts = Acts::default();
    header(ui, vm, st, &mut acts);
    if let Some(note) = vm.rewrite.blocked_note() {
        blocked_banner(
            ui,
            note,
            matches!(vm.rewrite.availability, Availability::NoConfinement(_)),
        );
    }
    jobs_strip(ui, vm);
    if vm.rewrite.rows.is_empty() {
        empty(ui, vm, &mut acts);
    } else {
        let width = (ui.available_width() * 0.3).clamp(240.0, 360.0);
        egui::Panel::left(Id::new("kraken_rewrite_plan"))
            .resizable(true)
            .default_size(width)
            .size_range(220.0..=560.0)
            .frame(egui::Frame::new())
            .show(ui, |ui| plan_list(ui, vm, st, &mut acts));
        detail::show(ui, vm, st, &mut acts);
    }
    apply(vm, st, acts, front);
}

/// "Functions | Program" at the top of the tab.
fn section_switch(ui: &mut Ui, vm: &ViewModel, st: &mut RewriteUi) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        for (s, label, tip) in [
            (
                Section::Functions,
                "Functions",
                "The plan, one function at a time: its C, the Rust KRAKEN wrote and how they compared.",
            ),
            (
                Section::Program,
                "Whole program",
                "Rewrite the entire program as one crate and compare it with the original binary.",
            ),
        ] {
            if ui
                .selectable_label(st.section == s, label)
                .on_hover_text(tip)
                .clicked()
            {
                st.section = s;
            }
        }
        if let Some(d) = vm.rewrite.program.detail.as_ref().filter(|_| st.section == Section::Functions)
        {
            ui.label(
                RichText::new(format!("Last whole-program run: {}", d.verdict.verdict))
                    .size(11.5)
                    .color(p.text_dim),
            );
        }
    });
}

fn apply(vm: &mut ViewModel, st: &mut RewriteUi, acts: Acts, front: &mut Option<Tab>) {
    if acts.plan {
        vm.rewrite_make_plan();
    }
    if acts.refresh {
        vm.rewrite_refresh();
    }
    if let Some(a) = acts.select {
        vm.rewrite_select(a);
        st.program_spec = false;
    }
    if let Some((a, mode)) = acts.run {
        vm.rewrite_run(a, mode);
    }
    if let Some(a) = acts.retry {
        vm.rewrite_retry(a);
    }
    if let Some(a) = acts.accept {
        vm.rewrite_accept(a);
    }
    if let Some(target) = acts.spec {
        vm.rewrite_write_spec(target);
    }
    if let Some((a, n)) = acts.show_version {
        vm.rewrite_show_version(a, n);
    }
    if let Some(a) = acts.goto {
        vm.navigate_to(a);
        *front = Some(Tab::Decompiler);
    }
    if acts.export {
        vm.rewrite_export_open();
    }
}

fn header(ui: &mut Ui, vm: &ViewModel, st: &mut RewriteUi, acts: &mut Acts) {
    let p = pal(ui);
    let dark = style::dark(ui);
    let r = &vm.rewrite;
    ui.horizontal_wrapped(|ui| {
        if r.rows.is_empty() {
            ui.label(medium("Rewrite in Rust", 14.0).color(p.text_strong));
        } else {
            for s in [
                UnitStatus::Planned,
                UnitStatus::Translated,
                UnitStatus::Verified,
                UnitStatus::Failed,
                UnitStatus::Accepted,
            ] {
                let n = r.counts.of(s);
                let on = st.filter == Some(s);
                let resp = chip_button(
                    ui,
                    &format!("{n} {}", s.as_str()),
                    status_color(s, dark, &p),
                    on,
                )
                .on_hover_text(format!(
                    "{} Click to {} the list.",
                    status_explain(s),
                    if on { "show all of" } else { "narrow" }
                ));
                if resp.clicked() {
                    st.filter = if on { None } else { Some(s) };
                }
            }
            ui.label(RichText::new(r.coverage_line()).size(12.0).color(p.text_dim));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let can_export = r.counts.accepted > 0 && !r.exporting();
            if ui
                .add_enabled(can_export, egui::Button::new("Export..."))
                .on_hover_text(if r.counts.accepted == 0 {
                    "Accept at least one verified function first. Only accepted functions are exported."
                } else {
                    "Write the accepted functions as a Rust project with a shim that can stand in for the originals."
                })
                .clicked()
            {
                acts.export = true;
            }
            if ui
                .add_enabled(!r.loading, egui::Button::new("Refresh"))
                .on_hover_text("Read the status of every function again.")
                .clicked()
            {
                acts.refresh = true;
            }
            if !r.rows.is_empty()
                && ui
                    .add_enabled(!r.loading, egui::Button::new("Plan again"))
                    .on_hover_text(
                        "Work out the rewrite order again. Functions that are already translated keep their results.",
                    )
                    .clicked()
            {
                acts.plan = true;
            }
            if r.loading {
                ui.spinner();
            }
        });
    });
    if r.truncated_list {
        ui.label(
            RichText::new("Only the first part of a very long plan is listed.")
                .size(11.5)
                .color(p.text_dim),
        );
    }
    ui.separator();
}

fn blocked_banner(ui: &mut Ui, note: &str, sandbox: bool) {
    let s = style::status(style::dark(ui));
    egui::Frame::new()
        .fill(s.warning.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, s.warning.gamma_multiply(0.5)))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                medium(
                    if sandbox {
                        "Rewriting is off on this computer"
                    } else {
                        "The rewrite pipeline is not connected"
                    },
                    13.0,
                )
                .color(s.warning),
            );
            ui.label(RichText::new(note).size(12.0));
        });
    ui.add_space(4.0);
}

fn jobs_strip(ui: &mut Ui, vm: &ViewModel) {
    let running: Vec<&RewriteJob> = vm.rewrite.jobs.iter().filter(|j| j.running()).collect();
    if running.is_empty() {
        return;
    }
    let p = pal(ui);
    for j in running {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(medium(&j.label, 12.5).color(p.text_strong));
            if let Some(pr) = &j.progress {
                ui.label(
                    RichText::new(format!(
                        "{}  ({} of {})",
                        pr.phase,
                        pr.done.min(pr.total) + 1,
                        pr.total.max(1)
                    ))
                    .size(12.0)
                    .color(p.text_dim),
                );
            }
            let bar = egui::ProgressBar::new(j.fraction().unwrap_or(0.0))
                .desired_width(160.0)
                .desired_height(8.0);
            ui.add(bar);
            if let Some(pr) = &j.progress {
                ui.label(RichText::new(&pr.message).size(11.5).color(p.text_dim));
            }
        });
    }
    ui.add_space(2.0);
}

fn empty(ui: &mut Ui, vm: &ViewModel, acts: &mut Acts) {
    let r = &vm.rewrite;
    if r.loading || !r.loaded {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Reading the rewrite plan...");
        });
        return;
    }
    if let Some(e) = &r.error {
        let s = style::status(style::dark(ui));
        ui.label(RichText::new(e).color(s.danger));
        if ui.button("Try again").clicked() {
            acts.refresh = true;
        }
        return;
    }
    if r.blocked_note().is_some() && matches!(r.availability, Availability::NotAttached(_)) {
        return;
    }
    empty_state(
        ui,
        "No rewrite plan yet",
        "KRAKEN lists your program's functions with the ones that call nothing else first, so each can be rewritten in Rust and checked against the original before the next one builds on it.",
        Some("Analyze the program first if the Functions list is empty."),
    );
    ui.vertical_centered(|ui| {
        ui.add_space(6.0);
        if primary_button(ui, "Plan the rewrite").clicked() {
            acts.plan = true;
        }
    });
}

fn plan_list(ui: &mut Ui, vm: &ViewModel, st: &RewriteUi, acts: &mut Acts) {
    let p = pal(ui);
    let dark = style::dark(ui);
    let rows: Vec<&UnitItem> = vm
        .rewrite
        .rows
        .iter()
        .filter(|r| st.filter.is_none_or(|f| r.status == f))
        .collect();
    ui.label(
        RichText::new(match st.filter {
            Some(f) => format!("{} {} - callees first", rows.len(), f.as_str()),
            None => format!("{} functions - callees first", rows.len()),
        })
        .size(11.5)
        .color(p.text_dim),
    );
    if rows.is_empty() {
        ui.label(RichText::new("No function has this status.").color(p.text_dim));
        return;
    }
    let row_h = 26.0;
    egui::ScrollArea::vertical()
        .id_salt("kraken_rewrite_plan_scroll")
        .auto_shrink([false, false])
        .show_rows(ui, row_h, rows.len(), |ui, range| {
            for i in range {
                let r = rows[i];
                let selected = vm.rewrite.selected == Some(r.address);
                let (rect, _) =
                    ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::hover());
                let resp = ui.interact(rect, Id::new(("rw_row", r.address)), Sense::click());
                if selected || resp.hovered() {
                    let fill = if selected { p.selection } else { p.row_hover };
                    ui.painter().add(Shape::rect_filled(rect, 4.0, fill));
                }
                let mut inner = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(Rect::from_min_max(rect.min + vec2(6.0, 0.0), rect.max))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                row_contents(&mut inner, vm, r, &p, dark);
                if resp.clicked() {
                    acts.select = Some(r.address);
                }
            }
        });
}

fn row_contents(ui: &mut Ui, vm: &ViewModel, r: &UnitItem, p: &Palette, dark: bool) {
    ui.spacing_mut().item_spacing.x = 6.0;
    ui.label(
        RichText::new(r.order.map_or("-".into(), |o| format!("{:>3}", o + 1)))
            .monospace()
            .size(11.5)
            .color(p.text_dim),
    );
    chip(ui, r.status.as_str(), status_color(r.status, dark, p))
        .on_hover_text(status_explain(r.status));
    let color = if vm.rewrite.selected == Some(r.address) {
        p.text_strong
    } else {
        p.text
    };
    ui.label(RichText::new(&r.name).monospace().size(12.5).color(color));
    if vm.rewrite.running_for(r.address).is_some() {
        ui.spinner();
    }
    if r.version > 0 {
        ui.label(
            RichText::new(format!("v{}", r.version))
                .size(11.0)
                .color(p.text_dim),
        );
    }
    let s = style::status(dark);
    for f in &r.flags {
        let c = match f {
            Flag::Recursive => p.text_dim,
            _ => s.warning,
        };
        chip(ui, &f.label(), c).on_hover_text(f.explain());
    }
}
