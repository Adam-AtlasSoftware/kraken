//! The first-run tour: a few cards that point at the main areas of the window, with Next, Back
//! and Skip. It starts on the first launch and again from Help > Take the tour.

use egui::{Align2, Area, Context, Id, LayerId, Margin, Order, Rect, RichText, Stroke};

use crate::style::{card, medium};

/// The part of the window a step points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spot {
    /// Nothing in particular.
    None,
    /// The menu bar.
    Menu,
    /// A dock panel, named by its tab title.
    Panel(&'static str),
}

struct Step {
    title: &'static str,
    text: &'static str,
    spot: Spot,
    /// The step makes sense only with a project open.
    needs_project: bool,
}

const STEPS: &[Step] = &[
    Step {
        title: "Welcome to KRAKEN",
        text: "KRAKEN helps you understand a program you do not have the source code for. This tour takes a minute. Drop a program on the window, or choose File > Open program, to begin. The demo project is a good first look.",
        spot: Spot::None,
        needs_project: false,
    },
    Step {
        title: "The menu bar",
        text: "Everything you can do is in the menus, and each item says what it does when you hover it. Press Ctrl+K to search every action by name. Help has this tour, the help pages and the shortcuts (F1).",
        spot: Spot::Menu,
        needs_project: false,
    },
    Step {
        title: "Functions",
        text: "A program is made of functions. This list holds every one KRAKEN found. Click one to read it. Type in the filter box to find one by name.",
        spot: Spot::Panel("Functions"),
        needs_project: true,
    },
    Step {
        title: "The decompiler",
        text: "This shows the selected function as C-like code. Click a call to follow it and press Alt+Left to come back. To give a function a better name, select it and press N.",
        spot: Spot::Panel("Decompiler"),
        needs_project: true,
    },
    Step {
        title: "The right-click menu",
        text: "Right-click a name or a line in the code. The menu offers rename, change type, comment, show references and bookmark, and lets you ask the assistant to explain it.",
        spot: Spot::Panel("Decompiler"),
        needs_project: true,
    },
    Step {
        title: "The assistant",
        text: "The Assistant tab answers questions about the program in plain language. Choose which AI it uses in Settings. AI > Automate lets it work through the whole flow while you watch.",
        spot: Spot::Panel("Assistant"),
        needs_project: true,
    },
    Step {
        title: "Rewrite in Rust",
        text: "When you understand a program, the Rewrite menu turns it into Rust and checks every function against the original. The Help window explains each step. That is the tour. Press F1 at any time for help.",
        spot: Spot::Menu,
        needs_project: true,
    },
];

/// How many steps the tour has.
pub const STEP_COUNT: usize = STEPS.len();

/// What the tour asks of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TourEvent {
    /// It ended, by Done or Skip: do not offer it again on its own.
    Ended,
}

/// State of the tour.
#[derive(Debug, Default)]
pub struct Tour {
    active: bool,
    step: usize,
}

fn spot_key(spot: Spot) -> Option<Id> {
    match spot {
        Spot::None => None,
        Spot::Menu => Some(Id::new("kraken_tour_spot_menu")),
        Spot::Panel(name) => Some(Id::new(("kraken_tour_spot_panel", name))),
    }
}

/// Remembers where the menu bar or a panel was drawn this frame, so the tour can outline it.
pub fn note_spot(ctx: &Context, spot: Spot, rect: Rect) {
    if let Some(id) = spot_key(spot) {
        ctx.data_mut(|d| d.insert_temp(id, rect));
    }
}

fn spot_rect(ctx: &Context, spot: Spot) -> Option<Rect> {
    ctx.data(|d| d.get_temp::<Rect>(spot_key(spot)?))
}

impl Tour {
    /// Starts at the first step.
    pub fn start(&mut self) {
        self.active = true;
        self.step = 0;
    }

    /// Starts at step `n` (screenshots).
    pub fn start_at(&mut self, n: usize) {
        self.active = true;
        self.step = n.min(STEP_COUNT - 1);
    }

    /// Whether the tour is showing.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The panel the current step points at, by tab title.
    pub fn panel(&self) -> Option<&'static str> {
        match STEPS[self.step].spot {
            Spot::Panel(name) => Some(name),
            _ => None,
        }
    }

    /// The current step number, from 0.
    pub fn step(&self) -> usize {
        self.step
    }

    /// Draws the outline and the card. `project` is true while a project is open.
    pub fn show(&mut self, ctx: &Context, project: bool) -> Option<TourEvent> {
        if !self.active {
            return None;
        }
        let s = &STEPS[self.step];
        let waiting = s.needs_project && !project;
        let rect = if waiting {
            None
        } else {
            spot_rect(ctx, s.spot)
        };
        let p = pal_of(ctx);
        if let Some(r) = rect {
            let painter =
                ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("kraken_tour_glow")));
            let r = r.shrink(1.0);
            painter.rect_filled(r, 6.0, p.accent.gamma_multiply(0.07));
            painter.rect_stroke(r, 6.0, Stroke::new(3.0, p.accent), egui::StrokeKind::Inside);
        }
        // The card sits on the opposite side from what it points at.
        let left = rect.is_some_and(|r| r.center().x > ctx.content_rect().center().x);
        let align = if left {
            Align2::LEFT_BOTTOM
        } else {
            Align2::RIGHT_BOTTOM
        };
        let offset = if left { [24.0, -48.0] } else { [-24.0, -48.0] };
        let mut next = false;
        let mut back = false;
        let mut skip = false;
        Area::new(Id::new("kraken_tour_card"))
            .order(Order::Foreground)
            .anchor(align, offset)
            .show(ctx, |ui| {
                card()
                    .fill(p.panel)
                    .stroke(Stroke::new(1.5, p.accent))
                    .inner_margin(Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_width(340.0);
                        ui.label(
                            RichText::new(format!("Tour: step {} of {}", self.step + 1, STEP_COUNT))
                                .size(11.5)
                                .color(p.text_dim),
                        );
                        ui.label(medium(s.title, 16.0).color(p.text_strong));
                        ui.add_space(4.0);
                        ui.label(RichText::new(s.text).size(13.0).color(p.text));
                        if waiting {
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(
                                    "This step shows the project screen. Open a program or the demo project and the tour carries on.",
                                )
                                .size(12.5)
                                .color(p.accent),
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let first = self.step == 0;
                            if ui
                                .add_enabled(!first, egui::Button::new("Back"))
                                .on_hover_text("Go to the previous step")
                                .on_disabled_hover_text("This is the first step")
                                .clicked()
                            {
                                back = true;
                            }
                            let last = self.step + 1 == STEP_COUNT;
                            let label = if last { "Done" } else { "Next" };
                            let can_next = !waiting;
                            if ui
                                .add_enabled(can_next, egui::Button::new(label))
                                .on_hover_text(if last {
                                    "End the tour"
                                } else {
                                    "Go to the next step"
                                })
                                .on_disabled_hover_text(
                                    "Open a program or the demo project first. The tour carries on by itself",
                                )
                                .clicked()
                            {
                                next = true;
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui
                                    .button("Skip tour")
                                    .on_hover_text(
                                        "Close the tour. Help > Take the tour starts it again",
                                    )
                                    .clicked()
                                {
                                    skip = true;
                                }
                            });
                        });
                    });
            });
        if skip {
            self.active = false;
            return Some(TourEvent::Ended);
        }
        if back {
            self.step = self.step.saturating_sub(1);
            if !project {
                while self.step > 0 && STEPS[self.step].needs_project {
                    self.step -= 1;
                }
            }
        }
        if next {
            if self.step + 1 == STEP_COUNT {
                self.active = false;
                return Some(TourEvent::Ended);
            }
            self.step += 1;
        }
        None
    }
}

fn pal_of(ctx: &Context) -> kraken_gui_widgets::Palette {
    kraken_gui_widgets::KrakenTheme::from_ctx(ctx).palette()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tour_has_five_to_seven_steps_and_each_says_something() {
        assert!((5..=7).contains(&STEP_COUNT));
        for s in STEPS {
            assert!(!s.title.is_empty() && s.text.len() > 40);
        }
    }

    #[test]
    fn the_first_steps_work_without_a_project() {
        assert!(!STEPS[0].needs_project && !STEPS[1].needs_project);
        assert!(STEPS[2..].iter().all(|s| s.needs_project));
    }
}
