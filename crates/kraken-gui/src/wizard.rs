//! The window of a [`WizardFlow`]: stepper, one sentence per step, Back / Next / Finish with the
//! reason when Next is off, a box with the CLI commands that do the same, and the keyboard
//! (Alt+Right and Alt+Left move between steps, Enter goes on when no field has focus, Escape
//! cancels). The flows decide everything else; see `kraken-viewmodel`'s `wizard` module.

use egui::{Align2, Id, Key, Modifiers, RichText, Ui, vec2};
use kraken_viewmodel::wizard::{self, WizardFlow, WizardNav};

use crate::rewrite::{gated_button, gated_primary};
use crate::style::{self, medium, pal};

/// What the person did this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardEvent {
    /// Nothing that ends the wizard.
    None,
    /// The last step's button was pressed (and allowed).
    Finish,
    /// Cancel or Escape.
    Cancel,
}

/// Draws `flow` in a window titled `title`; `body` draws the current step.
pub fn show<F: WizardFlow>(
    ctx: &egui::Context,
    title: &str,
    flow: &mut F,
    body: impl FnOnce(&mut Ui, &mut F),
) -> WizardEvent {
    let mut event = WizardEvent::None;
    let max_h = (ctx.content_rect().height() - 120.0).clamp(300.0, 760.0);
    // Keys act before the window draws so a step change shows in the same frame.
    let focused = ctx.memory(|m| m.focused().is_some());
    let (alt_next, alt_back, enter, escape) = ctx.input_mut(|i| {
        (
            i.consume_key(Modifiers::ALT, Key::ArrowRight),
            i.consume_key(Modifiers::ALT, Key::ArrowLeft),
            !focused && i.consume_key(Modifiers::NONE, Key::Enter),
            i.key_pressed(Key::Escape),
        )
    });
    if alt_back {
        wizard::back(flow);
    }
    if alt_next || enter {
        event = advance(flow);
    }
    egui::Window::new(medium(title, 15.0))
        .id(Id::new(("kraken_wizard", F::ID)))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -20.0))
        .default_width(720.0)
        .max_width(720.0)
        .show(ctx, |ui| {
            stepper(ui, flow);
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt(("kraken_wizard_scroll", F::ID))
                .max_height(max_h - 170.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    header(ui, flow);
                    ui.add_space(6.0);
                    body(ui, flow);
                    if wizard::is_last(flow) {
                        cli_box(ui, flow);
                    }
                });
            ui.separator();
            let ev = footer(ui, flow);
            if ev != WizardEvent::None {
                event = ev;
            }
        });
    if escape {
        event = WizardEvent::Cancel;
    }
    event
}

fn advance<F: WizardFlow>(flow: &mut F) -> WizardEvent {
    match wizard::next(flow) {
        WizardNav::Finish => WizardEvent::Finish,
        WizardNav::Moved | WizardNav::Blocked(_) => WizardEvent::None,
    }
}

fn stepper<F: WizardFlow>(ui: &mut Ui, flow: &mut F) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let steps = flow.steps();
    let here = flow.current();
    let at = steps.iter().position(|x| *x == here).unwrap_or(0);
    let mut jump = None;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for (i, step) in steps.iter().enumerate() {
            let text = format!("{}  {}", i + 1, flow.title(*step));
            if i == at {
                ui.add(
                    egui::Button::new(medium(text, 12.5).color(p.text_strong))
                        .fill(p.selection)
                        .stroke(egui::Stroke::new(1.5, p.accent)),
                )
                .on_hover_text(format!("You are here. {}", flow.explain(*step)));
            } else if i < at {
                let r = ui
                    .add(
                        egui::Button::new(RichText::new(text).size(12.5).color(s.success))
                            .frame(false),
                    )
                    .on_hover_text(format!(
                        "Done. {} Click to go back to this step.",
                        flow.explain(*step)
                    ));
                if r.clicked() {
                    jump = Some(*step);
                }
            } else {
                ui.add_enabled(
                    false,
                    egui::Button::new(RichText::new(text).size(12.5).color(p.text_dim))
                        .frame(false),
                )
                .on_disabled_hover_text(format!(
                    "Later. {} Finish the steps before it first.",
                    flow.explain(*step)
                ));
            }
        }
    });
    if let Some(step) = jump {
        wizard::jump_back(flow, step);
    }
}

fn header<F: WizardFlow>(ui: &mut Ui, flow: &F) {
    let p = pal(ui);
    let (at, n) = wizard::position(flow);
    let step = flow.current();
    ui.label(medium(format!("Step {at} of {n}: {}", flow.title(step)), 14.0).color(p.text_strong));
    ui.label(
        RichText::new(flow.explain(step))
            .size(12.5)
            .color(p.text_dim),
    );
}

fn cli_box<F: WizardFlow>(ui: &mut Ui, flow: &F) {
    let lines = flow.commands();
    if lines.is_empty() {
        return;
    }
    let p = pal(ui);
    ui.add_space(8.0);
    ui.label(medium("Do the same from the command line", 13.0).color(p.text_strong));
    egui::Frame::new()
        .fill(p.surface)
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for l in &lines {
                ui.add(
                    egui::Label::new(RichText::new(l).monospace().size(12.0).color(p.text)).wrap(),
                );
            }
        });
    if ui
        .button("Copy commands")
        .on_hover_text("Copy these commands to the clipboard")
        .clicked()
    {
        ui.ctx().copy_text(lines.join("\n"));
    }
}

fn footer<F: WizardFlow>(ui: &mut Ui, flow: &mut F) -> WizardEvent {
    let s = style::status(style::dark(ui));
    let blocker = flow.blocker();
    let last = wizard::is_last(flow);
    let mut event = WizardEvent::None;
    if let Some(why) = &blocker {
        ui.label(RichText::new(why).size(12.0).color(s.warning));
    }
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if last { flow.finish_label() } else { "Next" };
            if gated_primary(
                ui,
                label,
                blocker.as_deref(),
                if last {
                    "Do it: the choices on this page are used now."
                } else {
                    "Go to the next step (Alt+Right)."
                },
            ) {
                event = advance(flow);
            }
            let can_back = wizard::can_back(flow);
            if gated_button(
                ui,
                "Back",
                (!can_back).then_some("This is the first step."),
                "Go back one step. Nothing is undone (Alt+Left).",
            ) {
                wizard::back(flow);
            }
            if ui
                .button("Cancel")
                .on_hover_text("Close the wizard without doing anything (Esc)")
                .clicked()
            {
                event = WizardEvent::Cancel;
            }
        });
    });
    event
}
