//! The one-time warning shown before the first run (decision 50: warn only).

use egui::{Frame, Margin, RichText, Stroke, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::agents::{WARNING_TEXT, WARNING_TITLE};

use crate::style::{self, medium, pal};

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let name = vm
        .agents
        .pending_notice
        .as_deref()
        .and_then(|id| vm.agents.row(id))
        .map_or_else(|| "the agent".to_string(), |r| r.name.clone());
    let mut start = false;
    let mut cancel = false;
    egui::ScrollArea::vertical()
        .id_salt("kraken_agents_notice")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add_space(8.0);
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, s.warning.gamma_multiply(0.7)))
                .corner_radius(10)
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(medium(WARNING_TITLE, 16.0).color(s.warning)).wrap());
                    ui.add_space(6.0);
                    for para in WARNING_TEXT.split("\n\n") {
                        ui.add(
                            egui::Label::new(RichText::new(para).size(13.0).color(p.text)).wrap(),
                        );
                        ui.add_space(6.0);
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if style::primary_button(ui, &format!("I understand, start {name}"))
                            .clicked()
                        {
                            start = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("KRAKEN shows this once.")
                            .size(11.5)
                            .color(p.text_dim),
                    );
                });
        });
    if start {
        vm.agents_acknowledge();
    } else if cancel {
        vm.agents_cancel_notice();
    }
}
