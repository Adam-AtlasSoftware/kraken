//! The detail pane: one function's status, actions, plan notes, test results and code.

use std::hash::{Hash, Hasher};

use egui::{Frame, Margin, RichText, Ui};
use kraken_gui_widgets::{Palette, TokenText};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::rewrite::{
    CodePane, Counterexample, RewriteMode, UnitDetail, UnitStatus, VersionItem,
};

use super::{Acts, DetailView, RewriteUi, chip_button, spec_view, status_color};
use crate::style::{self, chip, empty_state, medium, pal, primary_button};

pub(super) fn show(ui: &mut Ui, vm: &ViewModel, st: &mut RewriteUi, acts: &mut Acts) {
    let p = pal(ui);
    let Some(addr) = vm.rewrite.selected else {
        empty_state(
            ui,
            "Pick a function",
            "Choose one from the plan on the left to see its C, the Rust KRAKEN wrote for it and how the two compared.",
            Some("Start at the top of the list: those functions call nothing else."),
        );
        return;
    };
    let row = vm.rewrite.row(addr);
    let name = row.map_or_else(|| format!("{addr:#x}"), |r| r.name.clone());
    let empty = UnitDetail {
        address: addr,
        name: name.clone(),
        ..UnitDetail::default()
    };
    let d = vm.rewrite.details.get(&addr).unwrap_or(&empty);
    let status = row.map_or(UnitStatus::Planned, |r| r.status);

    egui::ScrollArea::vertical()
        .id_salt("kraken_rewrite_detail_top")
        .max_height((ui.available_height() * 0.5).max(150.0))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            title(ui, vm, &name, addr, status, acts);
            actions(ui, vm, d, addr, status, acts);
            plan_notes(ui, vm, d, &p);
            if let Some(e) = &d.error {
                let s = style::status(style::dark(ui));
                ui.label(RichText::new(e).color(s.danger));
            }
            versions(ui, d, acts, &p);
            if let Some(v) = d.current() {
                results(ui, v, &p);
            }
        });
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        for (view, label) in [(DetailView::Code, "Code"), (DetailView::Spec, "Spec")] {
            if ui.selectable_label(st.view == view, label).clicked() {
                st.view = view;
            }
        }
    });
    ui.separator();
    match st.view {
        DetailView::Code => code_view(ui, d, &p),
        DetailView::Spec => spec_view::show(ui, vm, st, addr, acts),
    }
}

fn title(ui: &mut Ui, vm: &ViewModel, name: &str, addr: u64, status: UnitStatus, acts: &mut Acts) {
    let p = pal(ui);
    let dark = style::dark(ui);
    ui.horizontal(|ui| {
        ui.label(medium(name, 15.0).color(p.text_strong));
        if ui
            .link(
                RichText::new(format!("{addr:#x}"))
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            )
            .on_hover_text("Show this function in the Decompiler")
            .clicked()
        {
            acts.goto = Some(addr);
        }
        chip(ui, status.as_str(), status_color(status, dark, &p))
            .on_hover_text(kraken_viewmodel::rewrite::status_explain(status));
        if let Some(r) = vm.rewrite.row(addr)
            && let Some(a) = r.accepted_version
            && status != UnitStatus::Accepted
        {
            chip(
                ui,
                &format!("v{a} accepted"),
                status_color(UnitStatus::Accepted, dark, &p),
            )
            .on_hover_text(
                "An earlier version is accepted and stays in the export until you accept another.",
            );
        }
    });
}

fn actions(
    ui: &mut Ui,
    vm: &ViewModel,
    d: &UnitDetail,
    addr: u64,
    status: UnitStatus,
    acts: &mut Acts,
) {
    let p = pal(ui);
    let running = vm.rewrite.running_for(addr).is_some();
    let can_run = vm.rewrite.can_run() && !running;
    let has_versions = !d.versions().is_empty() || status != UnitStatus::Planned;
    ui.horizontal_wrapped(|ui| {
        if vm.rewrite.can_run() {
            let (label, tip) = if has_versions {
                ("Retry", "Ask for a new translation and test it. The earlier versions stay in the history.")
            } else {
                (
                    "Rewrite this function",
                    "Translate it to Rust, then run the original and the Rust on the same inputs. The decompiled code is sent to your configured AI provider.",
                )
            };
            ui.add_enabled_ui(can_run, |ui| {
                let clicked = if has_versions {
                    ui.button(label).on_hover_text(tip).clicked()
                } else {
                    primary_button(ui, label).on_hover_text(tip).clicked()
                };
                if clicked {
                    if has_versions {
                        acts.retry = Some(addr);
                    } else {
                        acts.run = Some((addr, RewriteMode::Incremental));
                    }
                }
                if ui
                    .button("Rewrite from the spec")
                    .on_hover_text("Write a cited spec of what the function does (if there is none), then have the Rust written from the spec alone, without the decompiled code.")
                    .clicked()
                {
                    acts.run = Some((addr, RewriteMode::Spec));
                }
            });
        } else if let Some(note) = vm.rewrite.blocked_note() {
            ui.label(
                RichText::new("Translating and testing are off here.")
                    .color(p.text_dim)
                    .size(12.0),
            )
            .on_hover_text(note);
        }
        let unit = vm.rewrite.acceptable_unit(addr);
        let tip = match (&unit, status) {
            (Some(_), _) => "Include this verified version in the export. Only you can do this; agents cannot.",
            (None, UnitStatus::Verified) => "KRAKEN does not know this version's id yet. Retry the rewrite, or use a daemon that lists stored versions.",
            _ => "Only a verified version can be accepted.",
        };
        if ui
            .add_enabled(unit.is_some(), egui::Button::new("Accept"))
            .on_hover_text(tip)
            .clicked()
        {
            acts.accept = Some(addr);
        }
        if running {
            ui.spinner();
        }
    });
}

fn plan_notes(ui: &mut Ui, vm: &ViewModel, d: &UnitDetail, p: &Palette) {
    let flags = vm
        .rewrite
        .row(d.address)
        .map(|r| r.flags.clone())
        .unwrap_or_default();
    let s = style::status(style::dark(ui));
    for f in &flags {
        ui.horizontal_wrapped(|ui| {
            chip(ui, &f.label(), s.warning);
            ui.label(RichText::new(f.explain()).size(12.0).color(p.text));
        });
    }
    if let Some(plan) = &d.plan {
        let mut parts = Vec::new();
        if !plan.callees.is_empty() {
            let names: Vec<String> = plan.callees.iter().map(|(_, n)| n.clone()).collect();
            parts.push(format!("Calls {} (rewritten first).", names.join(", ")));
        }
        if !plan.imports.is_empty() {
            parts.push(format!("Library calls: {}.", plan.imports.join(", ")));
        }
        if !plan.needs_stubs.is_empty() {
            parts.push(format!(
                "No stand-in yet for {}, so those calls end a test case early.",
                plan.needs_stubs.join(", ")
            ));
        }
        if plan.group_size > 1 {
            parts.push(format!(
                "Translated together with {} other functions.",
                plan.group_size - 1
            ));
        }
        if !parts.is_empty() {
            ui.label(RichText::new(parts.join(" ")).size(12.0).color(p.text_dim));
        }
    }
}

fn versions(ui: &mut Ui, d: &UnitDetail, acts: &mut Acts, p: &Palette) {
    let all = d.versions();
    if all.is_empty() {
        if let Some(n) = &d.stored_note {
            ui.label(RichText::new(n).size(12.0).color(p.text_dim));
        } else if d.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Looking for earlier versions...").color(p.text_dim));
            });
        } else {
            ui.label(RichText::new("Nothing has been translated yet.").color(p.text_dim));
        }
        return;
    }
    let dark = style::dark(ui);
    let shown = d.current().map(|v| v.version);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("History").size(12.0).color(p.text_dim));
        for v in &all {
            let label = format!("v{} {}", v.version, v.status.as_str());
            if chip_button(
                ui,
                &label,
                status_color(v.status, dark, p),
                shown == Some(v.version),
            )
            .on_hover_text(format!(
                "Written by {} ({}). Click to look at it.",
                v.model, v.provider
            ))
            .clicked()
            {
                acts.show_version = Some((d.address, v.version));
            }
        }
    });
    if let Some(n) = d
        .stored_note
        .as_ref()
        .filter(|_| all.iter().all(|v| v.rust.is_none()))
    {
        ui.label(RichText::new(n).size(11.5).color(p.text_dim));
    }
}

/// Splits "result: original 0x80, Rust 0xffffff80" into what, original and Rust.
pub(super) fn split_difference(s: &str) -> Option<(&str, &str, &str)> {
    let (what, rest) = s.split_once(": original ")?;
    let (orig, rust) = rest.split_once(", Rust ")?;
    Some((what, orig, rust))
}

fn results(ui: &mut Ui, v: &VersionItem, p: &Palette) {
    let s = style::status(style::dark(ui));
    let (color, head) = match v.verdict.as_str() {
        "pass" => (s.success, "Passed"),
        "fail" => (s.danger, "Different from the original"),
        "rejected" => (s.danger, "Refused"),
        _ => (s.warning, "Inconclusive"),
    };
    Frame::new()
        .fill(color.gamma_multiply(0.08))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(medium(format!("Version {}: {head}", v.version), 13.0).color(color));
                ui.label(RichText::new(v.cases_line()).size(12.0).color(p.text));
            });
            if let Some(d) = &v.verdict_detail {
                ui.label(RichText::new(d).size(12.0).color(p.text_dim));
            }
            if let Some(cx) = &v.counterexample {
                counterexample(ui, cx, p);
            }
            if !v.prototype.is_empty() {
                ui.label(
                    RichText::new(&v.prototype)
                        .monospace()
                        .size(11.5)
                        .color(p.text_dim),
                );
            }
            if !v.assumptions.is_empty() {
                ui.label(
                    RichText::new(format!("The model assumed: {}", v.assumptions.join("; ")))
                        .size(11.5)
                        .color(p.text_dim),
                );
            }
            if !v.unsupported.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "It could not translate: {}",
                        v.unsupported.join("; ")
                    ))
                    .size(11.5)
                    .color(s.warning),
                );
            }
            if !v.sandbox.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "Ran in: {} - written by {} ({})",
                        v.sandbox, v.model, v.provider
                    ))
                    .size(11.0)
                    .color(p.text_dim),
                );
            }
        });
    ui.add_space(4.0);
}

fn counterexample(ui: &mut Ui, cx: &Counterexample, p: &Palette) {
    ui.add_space(2.0);
    ui.label(medium("Smallest case where they disagree", 12.5).color(p.text_strong));
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Inputs").size(11.5).color(p.text_dim));
        ui.label(RichText::new(cx.args.join("   ")).monospace().size(12.0));
    });
    egui::Grid::new("kraken_rewrite_counterexample")
        .num_columns(3)
        .spacing([14.0, 2.0])
        .show(ui, |ui| {
            for line in &cx.differences {
                match split_difference(line) {
                    Some((what, orig, rust)) => {
                        ui.label(RichText::new(what).size(11.5).color(p.text_dim));
                        ui.label(
                            RichText::new(format!("original {orig}"))
                                .monospace()
                                .size(12.0),
                        );
                        ui.label(RichText::new(format!("Rust {rust}")).monospace().size(12.0));
                    }
                    None => {
                        ui.label(RichText::new("Difference").size(11.5).color(p.text_dim));
                        ui.label(RichText::new(line).monospace().size(12.0));
                        ui.label("");
                    }
                }
                ui.end_row();
            }
        });
}

fn pane_key(addr: u64, tag: u32, pane: &CodePane) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (addr, tag, pane.text().len()).hash(&mut h);
    h.finish()
}

fn code_view(ui: &mut Ui, d: &UnitDetail, p: &Palette) {
    let version = d.current();
    ui.columns(2, |cols| {
        cols[0].label(medium("Decompiled C  (the original)", 12.5).color(p.text_strong));
        match &d.c {
            Some(c) => {
                TokenText::new(&c.0)
                    .id_salt(("rewrite_c", d.address))
                    .cache_id(pane_key(d.address, 0, c))
                    .show(&mut cols[0]);
            }
            None => {
                cols[0].label(RichText::new("Reading the decompiled code...").color(p.text_dim));
            }
        }
        let title = match version {
            Some(v) => format!("Generated Rust  (version {})", v.version),
            None => "Generated Rust".to_string(),
        };
        cols[1].label(medium(title, 12.5).color(p.text_strong));
        match version.and_then(|v| v.rust.as_ref().map(|r| (v.version, r))) {
            Some((n, r)) => {
                TokenText::new(&r.0)
                    .id_salt(("rewrite_rust", d.address, n))
                    .cache_id(pane_key(d.address, n, r))
                    .show(&mut cols[1]);
            }
            None => {
                let msg = match version {
                    None => "No Rust yet. Press \"Rewrite this function\" to have it written and tested.",
                    Some(_) => "This version's code is not available in this window.",
                };
                cols[1].label(RichText::new(msg).color(p.text_dim));
                if let Some(n) = d.stored_note.as_ref().filter(|_| version.is_some()) {
                    cols[1].label(RichText::new(n).size(11.5).color(p.text_dim));
                }
            }
        }
    });
}
