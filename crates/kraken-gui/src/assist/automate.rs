//! The Automate dialog: pick what the assistant should do on its own, see what that means, and
//! start it. The run itself is a task of the view-model; its steps show in the Assistant tab.

use egui::{Align2, Id, RichText, vec2};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::AutomateGoal;

use crate::style::{self, medium, primary_button};

/// State of the dialog.
#[derive(Debug, Default)]
pub struct AutomateUi {
    /// The dialog is showing.
    pub open: bool,
    /// The goal picked.
    pub goal: AutomateGoal,
}

impl AutomateUi {
    /// Shows the dialog.
    pub fn show(&mut self) {
        self.open = true;
    }
}

fn title(goal: AutomateGoal) -> &'static str {
    match goal {
        AutomateGoal::Understand => "Understand the program",
        AutomateGoal::Rewrite => "Rewrite it in Rust",
        AutomateGoal::Both => "Understand it, then rewrite it",
    }
}

/// What the assistant will do for `goal`, one plain sentence per step.
pub fn steps(goal: AutomateGoal) -> Vec<&'static str> {
    let mut v = Vec::new();
    if goal.names() {
        v.push("Run the analysis if it has not run yet.");
        v.push(
            "Read the entry point, the imports and the strings to work out what the program is.",
        );
        v.push("Give up to 15 important functions a name and a short comment.");
    } else {
        v.push("Run the analysis if it has not run yet.");
    }
    if goal.rewrites() {
        v.push("Plan the rewrite of the whole program, callees first.");
        v.push(
            "Translate every function to Rust and test the result against the original program.",
        );
        v.push("Explain any test case that differs, and try again once or twice.");
        v.push("Export the Rust project.");
    }
    v
}

/// What the assistant will ask you about, or what stays yours, for `goal`.
pub fn asks(goal: AutomateGoal) -> Vec<&'static str> {
    let mut v = vec![
        "Names that would replace a name you or someone else already chose become proposals. You accept or reject them in the Proposals tab.",
        "Every change it makes is in the History tab, and you can undo the whole run.",
    ];
    if goal.rewrites() {
        v.push("It asks before it runs the original program on test inputs (inside a sandbox with no network).");
        v.push("It sends decompiled code to the AI you chose in Settings > AI to get Rust back.");
        v.push("Accepting the verified Rust functions is always your step, in the Rewrite tab.");
    }
    v
}

/// Draws the dialog while it is open.
pub fn dialog(ctx: &egui::Context, vm: &mut ViewModel, ui_state: &mut AutomateUi) {
    if !ui_state.open {
        return;
    }
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let badge = vm.assist.backend.as_ref().map(|b| b.badge.clone());
    let busy = vm.assist.busy();
    let mut start = false;
    let mut close = false;
    egui::Window::new(medium("Automate with the assistant", 15.0))
        .id(Id::new("kraken_automate"))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -30.0))
        .fixed_size(vec2(520.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(
                    "The assistant works through the steps on its own and tells you what it does as it goes. You stay in charge: it cannot accept its own work.",
                )
                .color(p.text_dim),
            );
            ui.add_space(6.0);
            for goal in [
                AutomateGoal::Understand,
                AutomateGoal::Rewrite,
                AutomateGoal::Both,
            ] {
                ui.radio_value(&mut ui_state.goal, goal, medium(title(goal), 13.5))
                    .on_hover_text(goal.describe());
                ui.indent(("automate_goal", goal.as_str()), |ui| {
                    ui.label(RichText::new(goal.describe()).size(12.5).color(p.text_dim));
                });
            }
            ui.add_space(8.0);
            ui.label(medium("What it will do", 13.0).color(p.text_strong));
            for (n, step) in steps(ui_state.goal).iter().enumerate() {
                ui.label(RichText::new(format!("{}. {step}", n + 1)).size(12.5));
            }
            ui.add_space(6.0);
            ui.label(medium("What it will ask you, and what stays yours", 13.0).color(p.text_strong));
            for line in asks(ui_state.goal) {
                ui.label(RichText::new(format!("\u{2022} {line}")).size(12.5));
            }
            ui.add_space(8.0);
            match &badge {
                Some(b) => {
                    ui.label(
                        RichText::new(format!("It will use: {} / {}", b.service, b.model))
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .on_hover_text(
                        "The AI model or terminal agent chosen under Settings > AI does the work.",
                    );
                }
                None => {
                    ui.label(
                        RichText::new(
                            "No AI model or terminal agent is set up yet. Choose one under Settings > AI first.",
                        )
                        .size(12.5)
                        .color(s.warning),
                    );
                }
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let can_start = badge.is_some() && !busy;
                ui.add_enabled_ui(can_start, |ui| {
                    if primary_button(ui, "Start")
                        .on_hover_text("Start the steps above. You can press Stop in the Assistant tab at any time.")
                        .on_disabled_hover_text(if busy {
                            "The assistant is still working on something else. Wait for it or press Stop in the Assistant tab."
                        } else {
                            "Choose an AI model or terminal agent under Settings > AI first."
                        })
                        .clicked()
                    {
                        start = true;
                    }
                });
                if ui
                    .button("Cancel")
                    .on_hover_text("Close this window without starting anything.")
                    .clicked()
                {
                    close = true;
                }
            });
        });
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        close = true;
    }
    if start {
        vm.assist_automate(ui_state.goal);
        ui_state.open = false;
    } else if close {
        ui_state.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_goal_explains_its_steps_and_what_stays_with_the_person() {
        for goal in [
            AutomateGoal::Understand,
            AutomateGoal::Rewrite,
            AutomateGoal::Both,
        ] {
            assert!(steps(goal).len() >= 2, "{goal:?}");
            assert!(asks(goal).iter().any(|l| l.contains("History")));
        }
        assert!(
            !asks(AutomateGoal::Understand)
                .iter()
                .any(|l| l.contains("sandbox")),
            "naming alone runs no program"
        );
        for goal in [AutomateGoal::Rewrite, AutomateGoal::Both] {
            let asks = asks(goal).join(" ");
            assert!(
                asks.contains("sandbox") && asks.contains("Accepting"),
                "{asks}"
            );
        }
    }
}
