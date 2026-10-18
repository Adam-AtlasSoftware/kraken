//! Spec mode: the rendered Markdown spec, with every cited address clickable.

use egui::{RichText, Ui};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::rewrite::{Availability, Inline, SpecBlock, SpecDoc};

use super::{Acts, RewriteUi};
use crate::style::{self, medium, pal};

pub(super) fn show(ui: &mut Ui, vm: &ViewModel, st: &mut RewriteUi, addr: u64, acts: &mut Acts) {
    let p = pal(ui);
    let name = vm
        .rewrite
        .row(addr)
        .map_or_else(|| format!("{addr:#x}"), |r| r.name.clone());
    let target = if st.program_spec { None } else { Some(addr) };
    ui.horizontal(|ui| {
        if ui
            .selectable_label(!st.program_spec, format!("Spec of {name}"))
            .on_hover_text("The description of this function")
            .clicked()
        {
            st.program_spec = false;
        }
        if ui
            .selectable_label(st.program_spec, "Spec of the program")
            .on_hover_text("The description of the whole program")
            .clicked()
        {
            st.program_spec = true;
        }
        let writing = vm
            .rewrite
            .jobs
            .iter()
            .any(|j| j.running() && matches!(j.kind, kraken_viewmodel::rewrite::JobKind::Spec { address } if address == target));
        let ready = !matches!(vm.rewrite.availability, Availability::NotAttached(_));
        let doc = vm.rewrite.spec_for(target);
        let label = if doc.is_some() { "Write it again" } else { "Write the spec" };
        if ui
            .add_enabled(ready && !writing, egui::Button::new(label))
            .on_hover_text(
                "Have the AI provider describe what this does, citing the address behind every fact. Nothing is run. The decompiled code is sent to the provider.",
            )
            .on_disabled_hover_text(if writing {
                "A spec is being written"
            } else {
                "The assistant is not available here. Settings > AI explains why"
            })
            .clicked()
        {
            acts.spec = Some(target);
        }
        if writing {
            ui.spinner();
        }
    });
    let Some(doc) = vm.rewrite.spec_for(target) else {
        ui.add_space(8.0);
        ui.label(
            RichText::new(if st.program_spec {
                "No spec of the whole program yet. It is written from the first functions of the plan and gives the overall picture."
            } else {
                "No spec of this function yet. A spec says what the function must do, in words, with each fact tied to an address. \"Rewrite from the spec\" then works from the spec alone."
            })
            .color(p.text_dim),
        );
        return;
    };
    ui.label(
        RichText::new(format!(
            "{} cited fact{} from {} function{} - written by {} ({})",
            doc.facts,
            if doc.facts == 1 { "" } else { "s" },
            doc.functions,
            if doc.functions == 1 { "" } else { "s" },
            doc.model,
            doc.provider
        ))
        .size(11.5)
        .color(p.text_dim),
    );
    egui::ScrollArea::vertical()
        .id_salt("kraken_rewrite_spec_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| render(ui, vm, doc, &p, acts));
}

fn render(ui: &mut Ui, vm: &ViewModel, doc: &SpecDoc, p: &Palette, acts: &mut Acts) {
    for b in &doc.blocks {
        match b {
            SpecBlock::Heading { level, text } => {
                ui.add_space(if *level <= 1 { 4.0 } else { 8.0 });
                let size = match level {
                    1 => 17.0,
                    2 => 14.5,
                    _ => 13.0,
                };
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    inline(ui, vm, text, p, Some(size), acts);
                });
            }
            SpecBlock::Paragraph(t) => {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    inline(ui, vm, t, p, None, acts);
                });
            }
            SpecBlock::Bullet(t) => {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(RichText::new("  \u{2022}  ").color(p.text_dim));
                    inline(ui, vm, t, p, None, acts);
                });
            }
            SpecBlock::Code(code) => {
                egui::Frame::new()
                    .fill(p.surface)
                    .corner_radius(6)
                    .inner_margin(8)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(code).monospace().size(12.0));
                    });
            }
        }
    }
}

fn inline(
    ui: &mut Ui,
    vm: &ViewModel,
    parts: &[Inline],
    p: &Palette,
    heading: Option<f32>,
    acts: &mut Acts,
) {
    for part in parts {
        match part {
            Inline::Text(t) => match heading {
                Some(size) => {
                    ui.label(medium(t, size).color(p.text_strong));
                }
                None => {
                    ui.label(RichText::new(t).color(p.text));
                }
            },
            Inline::Bold(t) => {
                ui.label(medium(t, 13.0).color(p.text_strong));
            }
            Inline::Code(t) => {
                ui.label(RichText::new(t).monospace().size(12.0).color(p.accent));
            }
            Inline::Cite(a) => {
                let name = vm
                    .functions
                    .items
                    .iter()
                    .find(|f| f.address == *a)
                    .map(|f| f.name.clone());
                let s = style::status(style::dark(ui));
                let text = RichText::new(format!("@{a:#x}"))
                    .monospace()
                    .size(11.5)
                    .color(s.info);
                let r = ui.link(text).on_hover_text(match &name {
                    Some(n) => format!("Cited from {n}. Click to read it in the Decompiler."),
                    None => "Click to go to this address.".to_string(),
                });
                if r.clicked() {
                    acts.goto = Some(*a);
                }
            }
        }
    }
}
