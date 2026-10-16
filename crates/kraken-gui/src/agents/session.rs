//! A running session: header, conversation, tool chips, permission cards and the prompt box.

use egui::{Align, Frame, Id, Key, Layout, Margin, RichText, Sense, Stroke, Ui, vec2};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::agents::{
    AgentItem, AgentTool, PermissionCard, PermissionState, PlanLine, SessionPhase,
};

use super::AgentsUi;
use crate::assist::text;
use crate::style::{self, chip, medium, pal};

#[derive(Default)]
struct Acts {
    answer: Vec<(u64, bool)>,
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, a: &mut AgentsUi) {
    let p = pal(ui);
    header(ui, vm, &p);
    ui.add_space(2.0);
    ui.separator();

    egui::Panel::bottom(Id::new("kraken_agents_input"))
        .frame(Frame::new().inner_margin(Margin::symmetric(0, 4)))
        .show_separator_line(false)
        .show(ui, |ui| input_area(ui, vm, a, &p));

    let mut acts = Acts::default();
    let Some(session) = vm.agents.session.as_ref() else {
        return;
    };
    let items = session.items.clone();
    let phase = session.phase.clone();
    let working = session.busy;
    let waiting = session.waiting_permissions();
    let stopping = session.stopping;
    let name = session.agent_name.clone();
    let tail = session.stderr_tail.clone();
    egui::ScrollArea::vertical()
        .id_salt("kraken_agents_scroll")
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            match &phase {
                SessionPhase::Starting => {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(format!("Starting {name}...")).color(p.text_dim));
                    });
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(120));
                }
                SessionPhase::Ready if items.is_empty() => welcome(ui, &p, &name),
                _ => {}
            }
            for item in &items {
                draw_item(ui, vm, &p, &name, item, &mut acts, &mut a.goto);
                ui.add_space(6.0);
            }
            if let SessionPhase::Ended(why) = &phase {
                ended(ui, &p, why, &items, &tail);
            }
            if working {
                ui.horizontal(|ui| {
                    if waiting > 0 {
                        ui.label(RichText::new("Waiting for your answer above").color(p.text_dim));
                    } else {
                        ui.spinner();
                        ui.label(
                            RichText::new(if stopping {
                                "Stopping..."
                            } else {
                                "Working..."
                            })
                            .color(p.text_dim),
                        );
                        ui.ctx()
                            .request_repaint_after(std::time::Duration::from_millis(120));
                    }
                });
            }
            a.seen_items = items.len();
        });
    for (id, allow) in acts.answer {
        vm.agents_answer_permission(id, allow);
    }
}

fn header(ui: &mut Ui, vm: &mut ViewModel, p: &Palette) {
    let s = style::status(style::dark(ui));
    let Some(session) = vm.agents.session.as_ref() else {
        return;
    };
    let ended = matches!(session.phase, SessionPhase::Ended(_));
    let mut close = false;
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let text = if ended {
                "Back to agents"
            } else {
                "End session"
            };
            if ui
                .add(egui::Button::new(text).small())
                .on_hover_text(if ended {
                    "Return to the list of agents"
                } else {
                    "Stop the agent and close it"
                })
                .clicked()
            {
                close = true;
            }
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.label(medium(&session.agent_name, 14.0).color(p.text_strong))
                    .on_hover_text(format!("Working in {}", session.project_dir));
                if let Some(label) = &session.agent_label {
                    chip(ui, label, p.text_dim).on_hover_text("What the agent says it is");
                }
                match &session.model {
                    Some(m) => {
                        chip(ui, m, s.info).on_hover_text("The model the agent is using");
                    }
                    None => {
                        chip(ui, "model chosen by the agent", p.text_dim)
                            .on_hover_text("This agent did not say which model it uses");
                    }
                }
            });
        });
    });
    ui.add(
        egui::Label::new(
            RichText::new(format!(
                "KRAKEN's tools reach it {}. Its own tools (shell, files) are outside KRAKEN's safety net.",
                session.tools_via
            ))
            .size(11.5)
            .color(p.text_dim),
        )
        .wrap(),
    );
    if close {
        vm.agents_close_session();
    }
}

fn welcome(ui: &mut Ui, p: &Palette, name: &str) {
    ui.add_space(10.0);
    ui.label(medium(format!("{name} is ready"), 16.0).color(p.text_strong));
    ui.add(
        egui::Label::new(
            RichText::new(
                "Tell it what to look into. It can read the program with KRAKEN's tools, and its changes appear here as they happen. It asks before running anything of its own.",
            )
            .size(12.5)
            .color(p.text_dim),
        )
        .wrap(),
    );
    ui.add_space(8.0);
}

fn ended(ui: &mut Ui, p: &Palette, why: &str, items: &[AgentItem], tail: &[String]) {
    let s = style::status(style::dark(ui));
    let already_listed = items
        .iter()
        .any(|i| matches!(i, AgentItem::Error(e) if e == why));
    Frame::new()
        .stroke(Stroke::new(1.0, s.danger.gamma_multiply(0.6)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if !already_listed {
                ui.add(egui::Label::new(RichText::new(why).color(s.danger)).wrap());
            }
            if !tail.is_empty() {
                ui.label(
                    RichText::new("The agent said:")
                        .size(11.5)
                        .color(p.text_dim),
                );
                for l in tail.iter().rev().take(4).rev() {
                    ui.add(
                        egui::Label::new(RichText::new(l).monospace().size(11.0).color(p.text_dim))
                            .wrap(),
                    );
                }
            }
            ui.label(
                RichText::new("The session is over. Use Back to agents to start again.")
                    .size(12.0)
                    .color(p.text_dim),
            );
        });
}

fn input_area(ui: &mut Ui, vm: &mut ViewModel, a: &mut AgentsUi, p: &Palette) {
    let Some(session) = vm.agents.session.as_ref() else {
        return;
    };
    let ready = session.phase == SessionPhase::Ready;
    let busy = session.busy;
    let stopping = session.stopping;
    let who = session.agent_name.clone();
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 70.0).max(80.0);
        let edit = egui::TextEdit::singleline(&mut a.input)
            .id(Id::new("kraken_agents_input_text"))
            .hint_text(if ready {
                format!("Tell {who} what to do...")
            } else {
                "Waiting for the agent...".to_string()
            })
            .desired_width(w);
        let r = ui.add_enabled(ready && !busy, edit);
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if a.focus_input {
            a.focus_input = false;
            r.request_focus();
        }
        if busy {
            if ui
                .add_enabled(!stopping, egui::Button::new("Stop"))
                .on_hover_text("Stop the agent now")
                .clicked()
            {
                vm.agents_stop();
            }
        } else {
            let send = ui.add_enabled(
                ready && !a.input.trim().is_empty(),
                egui::Button::new("Send"),
            );
            if send.clicked() || (enter && ready && !a.input.trim().is_empty()) {
                let text = std::mem::take(&mut a.input);
                vm.agents_send(&text);
                a.focus_input = true;
            }
        }
    });
    ui.label(
        RichText::new("The agent works on its own and asks before it runs commands.")
            .size(11.0)
            .color(p.text_dim),
    );
}

fn draw_item(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    agent: &str,
    item: &AgentItem,
    acts: &mut Acts,
    goto: &mut Option<u64>,
) {
    let s = style::status(style::dark(ui));
    match item {
        AgentItem::User(t) => {
            Frame::new()
                .fill(p.selection)
                .corner_radius(8)
                .inner_margin(Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("You").size(11.0).color(p.text_dim));
                    ui.add(egui::Label::new(RichText::new(t).color(p.text_strong)).wrap());
                });
        }
        AgentItem::Text { text: t, streaming } => {
            ui.label(RichText::new(agent).size(11.0).color(p.accent));
            text::paragraphs(ui, vm, p, t, 13.5, goto);
            if *streaming {
                ui.label(RichText::new("\u{2026}").color(p.text_dim));
            }
        }
        AgentItem::Thought(t) => {
            let one: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
            let short: String = one.chars().take(110).collect();
            let more = if one.chars().count() > 110 {
                "\u{2026}"
            } else {
                ""
            };
            ui.add(
                egui::Label::new(
                    RichText::new(format!("Thinking: {short}{more}"))
                        .italics()
                        .size(12.0)
                        .color(p.text_dim),
                )
                .truncate(),
            );
        }
        AgentItem::Tool(t) => tool_chip(ui, p, &s, t),
        AgentItem::Permission(c) => permission_card(ui, p, &s, c, acts),
        AgentItem::Plan(lines) => plan(ui, p, &s, lines),
        AgentItem::Notice(t) => {
            ui.add(
                egui::Label::new(RichText::new(t).italics().size(12.5).color(p.text_dim)).wrap(),
            );
        }
        AgentItem::Error(t) => {
            Frame::new()
                .stroke(Stroke::new(1.0, s.danger.gamma_multiply(0.6)))
                .corner_radius(8)
                .inner_margin(Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(t).color(s.danger)).wrap());
                });
        }
    }
}

fn plan(ui: &mut Ui, p: &Palette, s: &style::Status, lines: &[PlanLine]) {
    Frame::new()
        .fill(p.surface)
        .corner_radius(8)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Plan").size(11.0).color(p.text_dim));
            for l in lines {
                let (mark, color) = match l.status.as_str() {
                    "completed" => ("\u{2713}", s.success),
                    "in_progress" => ("\u{25b6}", s.info),
                    _ => ("\u{25cb}", p.text_dim),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(mark).color(color));
                    ui.add(
                        egui::Label::new(RichText::new(&l.text).size(12.5).color(p.text)).wrap(),
                    );
                });
            }
        });
}

fn tool_chip(ui: &mut Ui, p: &Palette, s: &style::Status, t: &AgentTool) {
    let dot = if t.failed() {
        s.danger
    } else if t.working() {
        p.text_dim
    } else {
        s.success
    };
    let state = if t.failed() {
        "failed"
    } else if t.working() {
        "working"
    } else {
        "done"
    };
    let id = ui.make_persistent_id(("kraken_agent_chip", &t.id));
    let mut open: bool = ui.data(|d| d.get_temp(id)).unwrap_or(false);
    let first = ui.available_width();
    Frame::new()
        .fill(p.surface)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.set_width(first - 16.0);
            let row = ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(8.0, 14.0), Sense::hover());
                ui.painter().circle_filled(rect.center(), 3.5, dot);
                if t.is_kraken {
                    ui.label(RichText::new("KRAKEN").size(10.0).color(s.info));
                } else {
                    ui.label(RichText::new("agent tool").size(10.0).color(s.warning));
                }
                let mut head = egui::text::LayoutJob::default();
                head.append(
                    &t.name,
                    0.0,
                    egui::TextFormat::simple(egui::FontId::monospace(12.0), p.text_strong),
                );
                if t.is_kraken
                    && let Some(input) = &t.input
                {
                    head.append(
                        &format!("  {}", compact_json(input)),
                        0.0,
                        egui::TextFormat::simple(egui::FontId::monospace(11.5), p.text_dim),
                    );
                }
                ui.add(egui::Label::new(head).truncate());
            });
            let hit = ui
                .interact(row.response.rect, id.with("hit"), Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(if open { "Hide details" } else { "Show details" });
            if hit.clicked() {
                open = !open;
            }
            if open {
                ui.add_space(2.0);
                let who = if t.is_kraken {
                    "The agent asked KRAKEN to run this tool"
                } else {
                    "One of the agent's own tools, outside KRAKEN's safety net"
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("{who} ({state}). {}", t.kind))
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .wrap(),
                );
                for path in &t.paths {
                    ui.label(RichText::new(path).monospace().size(11.5));
                }
                if let Some(input) = &t.input {
                    ui.add(egui::Label::new(RichText::new(input).monospace().size(11.5)).wrap());
                }
                if let Some(out) = &t.output {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("Result: {out}"))
                                .size(12.0)
                                .color(p.text),
                        )
                        .wrap(),
                    );
                }
            }
        });
    ui.data_mut(|d| d.insert_temp(id, open));
}

fn compact_json(s: &str) -> String {
    let flat: String = s
        .trim_matches(|c| c == '{' || c == '}')
        .replace('"', "")
        .replace(':', ": ")
        .replace(',', ", ");
    if flat.chars().count() > 70 {
        let cut: String = flat.chars().take(69).collect();
        format!("{cut}\u{2026}")
    } else {
        flat
    }
}

fn permission_card(
    ui: &mut Ui,
    p: &Palette,
    s: &style::Status,
    c: &PermissionCard,
    acts: &mut Acts,
) {
    let req = &c.request;
    if c.state != PermissionState::Waiting {
        let (word, color) = match c.state {
            PermissionState::Allowed => ("Allowed", s.success),
            PermissionState::Denied => ("Denied", s.danger),
            _ => ("Withdrawn", p.text_dim),
        };
        ui.horizontal_wrapped(|ui| {
            chip(ui, word, color);
            ui.add(
                egui::Label::new(RichText::new(&req.title).size(12.5).color(p.text_dim)).truncate(),
            );
        });
        return;
    }
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, s.warning.gamma_multiply(0.7)))
        .corner_radius(8)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                chip(ui, "asks permission", s.warning);
                if let Some(k) = &req.tool_kind {
                    ui.label(RichText::new(k).size(11.5).color(p.text_dim));
                }
            });
            ui.add_space(2.0);
            ui.add(egui::Label::new(medium(&req.title, 13.5).color(p.text_strong)).wrap());
            if let Some(input) = &req.input {
                ui.add(
                    egui::Label::new(
                        RichText::new(input)
                            .monospace()
                            .size(11.5)
                            .color(p.text_dim),
                    )
                    .wrap(),
                );
            }
            for path in &req.paths {
                ui.label(RichText::new(path).monospace().size(11.5).color(p.text_dim));
            }
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "This is one of the agent's own tools. KRAKEN cannot undo what it does.",
                    )
                    .size(11.5)
                    .color(p.text_dim),
                )
                .wrap(),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if style::primary_button(ui, "Allow once").clicked() {
                    acts.answer.push((req.request_id, true));
                }
                if ui.button("Deny").clicked() {
                    acts.answer.push((req.request_id, false));
                }
            });
        });
}
