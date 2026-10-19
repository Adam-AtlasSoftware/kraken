//! The window of the guided model setup: four steps, each with a one-line explanation. The
//! steps, the choices and the work are `kraken_viewmodel::infer::LocalSetup`; this draws them
//! and presses its buttons.

use egui::{Align, Color32, Layout, RichText, Ui};
use kraken_viewmodel::infer::{
    Choice, FitLevel, LocalSetup, SetupStep, Stage, Survey, SurveyState,
};

use super::{run_on, several};
use crate::style::{self, chip, medium, pal};

const WIDTH: f32 = 560.0;
const LIST_HEIGHT: f32 = 280.0;

/// Draws the setup and handles its buttons and Escape. The caller drops the setup once
/// [`LocalSetup::is_closed`].
pub fn show(ctx: &egui::Context, setup: &mut LocalSetup) {
    let mut want_next = false;
    let mut want_back = false;
    let mut want_cancel =
        ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
    let mut want_retry = false;
    let mut want_look = false;
    let mut open = true;
    egui::Window::new(medium("Set up a model on this computer", 15.0))
        .id(egui::Id::new("kraken_local_setup"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_width(WIDTH);
            steps_row(ui, setup.step());
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(RichText::new(setup.step().explain()).color(pal(ui).text_dim))
                    .wrap(),
            );
            ui.separator();
            match setup.step() {
                SetupStep::Check => check(ui, setup, &mut want_look),
                SetupStep::PickModel => pick_model(ui, setup),
                SetupStep::PickCards => pick_cards(ui, setup),
                SetupStep::Download => download(ui, setup),
            }
            ui.add_space(8.0);
            ui.separator();
            footer(
                ui,
                setup,
                &mut want_next,
                &mut want_back,
                &mut want_cancel,
                &mut want_retry,
            );
        });
    if !open {
        want_cancel = true;
    }
    if want_look {
        setup.look();
    }
    if want_retry {
        setup.retry();
    }
    if want_back {
        setup.go_back();
    }
    if want_next {
        setup.go_next();
    }
    if want_cancel {
        setup.cancel();
    }
}

fn steps_row(ui: &mut Ui, current: SetupStep) {
    let p = pal(ui);
    let all = [
        SetupStep::Check,
        SetupStep::PickModel,
        SetupStep::PickCards,
        SetupStep::Download,
    ];
    ui.horizontal_wrapped(|ui| {
        for s in all {
            let text = format!("{}  {}", s.number(), s.title());
            let rich = if s == current {
                medium(
                    format!("Step {} of 4 \u{b7} {}", s.number(), s.title()),
                    13.0,
                )
                .color(p.accent)
            } else if s.number() < current.number() {
                RichText::new(format!("\u{2713} {}", s.title()))
                    .size(12.0)
                    .color(p.text_dim)
            } else {
                RichText::new(text).size(12.0).color(p.text_dim)
            };
            ui.label(rich);
            ui.add_space(6.0);
        }
    });
}

fn note(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add(egui::Label::new(RichText::new(text).size(12.0).color(p.text_dim)).wrap());
}

fn problem(ui: &mut Ui, text: &str) {
    let s = style::status(style::dark(ui));
    ui.add(egui::Label::new(RichText::new(text).color(s.danger)).wrap());
}

fn check(ui: &mut Ui, setup: &LocalSetup, look_again: &mut bool) {
    match setup.survey() {
        SurveyState::Loading => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Looking at this computer...");
            });
        }
        SurveyState::Failed(e) => {
            problem(ui, &e);
            if ui
                .button("Check again")
                .on_hover_text("Look at this computer once more")
                .clicked()
            {
                *look_again = true;
            }
        }
        SurveyState::Ready(s) => {
            for line in s.computer.lines() {
                ui.add(egui::Label::new(line).wrap());
            }
            ui.add_space(4.0);
            note(
                ui,
                "RAM is the computer's main memory. Video memory (VRAM) sits on the graphics card.",
            );
            if ui
                .button("Check again")
                .on_hover_text(
                    "Look at this computer once more, for instance after closing programs",
                )
                .clicked()
            {
                *look_again = true;
            }
        }
    }
}

fn fit_color(fit: FitLevel, s: &style::Status) -> Color32 {
    match fit {
        FitLevel::Fits => s.success,
        FitLevel::Tight => s.warning,
        FitLevel::WontFit => s.danger,
    }
}

fn pick_model(ui: &mut Ui, setup: &mut LocalSetup) {
    let s = style::status(style::dark(ui));
    let p = pal(ui);
    let survey: std::sync::Arc<Survey> = match setup.survey() {
        SurveyState::Ready(s) => s,
        SurveyState::Loading => {
            ui.spinner();
            return;
        }
        SurveyState::Failed(e) => {
            problem(ui, &e);
            return;
        }
    };
    for n in &survey.notes {
        ui.add(egui::Label::new(RichText::new(n).size(12.0).color(s.warning)).wrap());
    }
    let chosen = setup.chosen().map(|c| c.id);
    let mut pick: Option<String> = None;
    egui::ScrollArea::vertical()
        .max_height(LIST_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for c in &survey.choices {
                row(
                    ui,
                    c,
                    chosen.as_deref() == Some(c.id.as_str()),
                    &s,
                    &p,
                    &mut pick,
                );
                ui.add_space(4.0);
            }
        });
    if let Some(id) = pick {
        setup.choose(&id);
    }
}

fn row(
    ui: &mut Ui,
    c: &Choice,
    picked: bool,
    s: &style::Status,
    p: &kraken_gui_widgets::Palette,
    pick: &mut Option<String>,
) {
    ui.horizontal(|ui| {
        let label = format!("{} \u{b7} {}", c.name, c.quant);
        let r = ui.add_enabled(
            c.selectable(),
            egui::RadioButton::new(picked, medium(label, 13.0)),
        );
        let r = if c.selectable() {
            r.on_hover_text("Use this model")
        } else {
            r.on_disabled_hover_text(c.why.clone())
        };
        if r.clicked() {
            *pick = Some(c.id.clone());
        }
        chip(ui, c.fit.label(), fit_color(c.fit, s));
        if c.recommended {
            chip(ui, "Recommended", p.accent);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(c.download_label())
                    .size(12.0)
                    .color(p.text_dim),
            );
        });
    });
    ui.indent(("why", &c.id), |ui| {
        ui.add(egui::Label::new(RichText::new(&c.why).size(12.0).color(p.text_dim)).wrap());
    });
}

fn pick_cards(ui: &mut Ui, setup: &mut LocalSetup) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(c) = setup.chosen() else {
        note(ui, "Pick a model first.");
        return;
    };
    ui.label(RichText::new(format!("{} \u{b7} {}", c.name, c.engine_label())).color(p.text_strong));
    ui.add_space(4.0);
    setup.edit_draft(|m, found| {
        run_on(ui, &p, m, found);
        if kraken_viewmodel::infer::card::several_cards(m, found) {
            several(ui, &p, m);
        }
    });
    if let Some(t) = setup.fit_text() {
        ui.add_space(4.0);
        let color = match setup.fit_on_chosen_cards() {
            Some(f) => fit_color(f, &s),
            None => p.text,
        };
        ui.add(egui::Label::new(RichText::new(t).color(color)).wrap());
    }
}

fn download(ui: &mut Ui, setup: &LocalSetup) {
    let s = style::status(style::dark(ui));
    let name = setup.chosen().map_or_else(String::new, |c| c.name);
    match setup.stage() {
        Stage::Idle => {
            ui.label("Getting ready...");
        }
        Stage::Failed(why) => {
            problem(ui, &why);
        }
        stage => {
            if let Some(pr) = setup.progress() {
                ui.add(egui::ProgressBar::new(pr.fraction).text(pr.text));
            }
            match stage {
                Stage::Downloading => {
                    ui.add_space(4.0);
                    note(
                        ui,
                        "If KRAKEN asks whether it may download, say yes. Cancel stops the wait; what already arrived is kept.",
                    );
                }
                Stage::Done => {
                    ui.add_space(6.0);
                    if let Some(r) = setup.test_reply() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "It works. {name} answered \"{}\" in {:.1} seconds.",
                                    r.reply,
                                    r.millis as f64 / 1000.0
                                ))
                                .color(s.success),
                            )
                            .wrap(),
                        );
                    }
                    note(
                        ui,
                        "The assistant uses this model now, and KRAKEN starts it when it opens. You can change that in Settings.",
                    );
                }
                _ => {}
            }
        }
    }
}

fn footer(
    ui: &mut Ui,
    setup: &LocalSetup,
    next: &mut bool,
    back: &mut bool,
    cancel: &mut bool,
    retry: &mut bool,
) {
    let step = setup.step();
    let stage = setup.stage();
    let done = step == SetupStep::Download && stage == Stage::Done;
    let failed = matches!(stage, Stage::Failed(_));
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), 30.0),
        Layout::right_to_left(Align::Center),
        |ui| {
            if done {
                if style::primary_button(ui, "Done")
                    .on_hover_text("Close this window")
                    .clicked()
                {
                    *next = true;
                }
                return;
            }
            if step == SetupStep::Download {
                if failed
                    && style::primary_button(ui, "Try again")
                        .on_hover_text("Run the last step once more")
                        .clicked()
                {
                    *retry = true;
                }
            } else {
                let label = if step == SetupStep::PickCards {
                    "Download and test"
                } else {
                    "Next"
                };
                let blocked = setup.blocked();
                let r = ui.add_enabled_ui(blocked.is_none(), |ui| style::primary_button(ui, label));
                let r = r.inner.on_hover_text(match step {
                    SetupStep::PickCards => "Download the model, start it and test it",
                    _ => "Go to the next step",
                });
                if let Some(why) = blocked {
                    r.on_disabled_hover_text(why);
                } else if r.clicked() {
                    *next = true;
                }
            }
            if ui
                .button("Cancel")
                .on_hover_text("Close this window without setting up a model")
                .clicked()
            {
                *cancel = true;
            }
            if step != SetupStep::Check
                && ui
                    .button("Back")
                    .on_hover_text("Go back one step")
                    .clicked()
            {
                *back = true;
            }
        },
    );
    if let (SetupStep::Check | SetupStep::PickModel, Some(why)) = (step, setup.blocked()) {
        note(ui, &why);
    }
}
