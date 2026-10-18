//! The Assistant tab: provider line, conversation, progress and input.

use egui::{Align, Color32, Frame, Id, Key, Layout, Margin, RichText, Sense, Stroke, Ui, vec2};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::{
    ChatItem, ExplainCard, OverviewCard, PermissionCard, PermissionState, ProposalCard,
    ProposalState, ProviderKind, ToolChip,
};

use super::text;
use super::{AssistRequest, AssistUi};
use crate::style::{self, chip, medium, pal};
use crate::workspace::{Tab, UiState};

const STARTERS: [&str; 3] = [
    "What does this program do?",
    "Which functions should I read first?",
    "Explain the function I have open",
];

/// What a click inside the conversation asks for, applied after drawing.
#[derive(Default)]
struct Acts {
    goto: Option<u64>,
    decide: Vec<(String, bool)>,
    answer: Vec<(String, bool)>,
    rename: Option<(u64, String)>,
}

/// The Assistant tab.
pub fn panel(ui: &mut Ui, vm: &mut ViewModel, st: &mut UiState) {
    let p = pal(ui);
    header(ui, vm, &mut st.assist);
    ui.add_space(2.0);
    ui.separator();

    if vm.assist.backend.is_none() && vm.assist.items.is_empty() {
        setup_state(ui, vm, &mut st.assist);
        goto(vm, st);
        return;
    }

    egui::Panel::bottom(Id::new("kraken_assist_input"))
        .frame(Frame::new().inner_margin(Margin::symmetric(0, 4)))
        .show_separator_line(false)
        .show(ui, |ui| input_area(ui, vm, &mut st.assist, &p));

    let mut acts = Acts::default();
    egui::ScrollArea::vertical()
        .id_salt("kraken_assist_scroll")
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if vm.assist.items.is_empty() {
                welcome(ui, vm, &p);
            }
            let items = vm.assist.items.clone();
            // A new card is read from its top; new chat text is followed to the bottom.
            let new_card = (items.len() > st.assist.seen_items)
                .then(|| {
                    items.iter().rposition(|i| {
                        matches!(i, ChatItem::Explanation(_) | ChatItem::Overview(_))
                    })
                })
                .flatten()
                .filter(|i| *i >= st.assist.seen_items);
            for (i, item) in items.iter().enumerate() {
                let rect = ui
                    .scope(|ui| draw_item(ui, vm, &p, item, &mut acts))
                    .response
                    .rect;
                if new_card == Some(i) {
                    ui.scroll_to_rect(rect, Some(Align::TOP));
                }
                ui.add_space(6.0);
            }
            st.assist.seen_items = items.len();
            progress(ui, vm, &p);
        });
    if acts.goto.is_some() {
        st.assist.goto = acts.goto;
    }
    for (call_id, accept) in acts.decide {
        vm.assist_decide_proposal(&call_id, accept);
    }
    for (id, allow) in acts.answer {
        vm.assist_answer_permission(&id, allow);
    }
    if let Some((addr, name)) = acts.rename {
        vm.begin_rename(addr, None);
        vm.set_rename_input(name);
    }
    goto(vm, st);
}

/// Follows an address the person clicked in the conversation.
fn goto(vm: &mut ViewModel, st: &mut UiState) {
    if let Some(addr) = st.assist.goto.take() {
        vm.navigate_to(addr);
        st.bring_to_front = Some(Tab::Decompiler);
    }
}

fn header(ui: &mut Ui, vm: &mut ViewModel, a: &mut AssistUi) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let badge = vm.assist.badge();
    ui.horizontal_wrapped(|ui| match &badge {
        Some(b) => {
            ui.label(medium(b.title(), 13.0).color(p.text_strong))
                .on_hover_text(if b.terminal_agent {
                    "The terminal agent answering. Change it under Settings > AI."
                } else {
                    "The AI model answering. Change it under Settings > AI."
                });
            if b.terminal_agent {
                chip(ui, "terminal agent", s.info).on_hover_text(b.privacy());
                if b.model.is_empty() {
                    ui.label(
                        RichText::new("model chosen by the agent")
                            .size(11.5)
                            .color(p.text_dim),
                    );
                }
            } else if b.local {
                chip(ui, "on this computer", s.success).on_hover_text(b.privacy());
            } else {
                chip(ui, "cloud service", s.warning).on_hover_text(b.privacy());
            }
        }
        None => {
            ui.label(medium("No AI model or agent set up", 13.0).color(p.text_dim));
        }
    });
    ui.horizontal(|ui| {
        let can_clear = !vm.assist.busy() && !vm.assist.items.is_empty();
        if ui
            .add_enabled(can_clear, egui::Button::new("New chat").small())
            .on_hover_text("Clear the conversation")
            .on_disabled_hover_text(
                "There is nothing to clear, or the assistant is still answering",
            )
            .clicked()
        {
            vm.assist_clear();
        }
        if ui
            .add(egui::Button::new("Settings").small())
            .on_hover_text("Choose the AI model or terminal agent")
            .clicked()
        {
            a.requests.push(AssistRequest::OpenSettings(None));
        }
        if ui
            .add(egui::Button::new("?").small())
            .on_hover_text("What is this panel?")
            .clicked()
        {
            a.help_open = !a.help_open;
        }
    });
    if a.help_open
        && let Some(h) = kraken_viewmodel::assist::panel_help("Assistant")
    {
        Frame::new()
            .fill(p.surface)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(8)
            .inner_margin(Margin::same(8))
            .show(ui, |ui| {
                ui.label(RichText::new(h.text).size(12.5).color(p.text));
                super::learn::term_list(ui, vm, h.terms);
            });
    }
}

fn setup_state(ui: &mut Ui, vm: &ViewModel, a: &mut AssistUi) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    egui::ScrollArea::vertical()
        .id_salt("kraken_assist_setup")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(14.0);
            ui.label(medium("Ask questions about this program", 17.0).color(p.text_strong));
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "The assistant reads the code for you, explains it in plain language and can suggest names for functions. It needs an AI model or a terminal agent to work with. Pick one to get started; you can change it any time under Settings > AI.",
                )
                .color(p.text_dim),
            );
            if let Some(problem) = &vm.assist.provider_problem {
                ui.add_space(8.0);
                ui.label(RichText::new(problem).color(s.danger));
            }
            ui.add_space(12.0);
            ui.label(medium("Runs on your computer (nothing is sent anywhere)", 13.0).color(p.text_strong));
            for kind in [
                ProviderKind::Ollama,
                ProviderKind::LmStudio,
                ProviderKind::LlamaServer,
            ] {
                preset_row(ui, a, &p, kind, true);
            }
            ui.add_space(10.0);
            ui.label(medium("Cloud services (the code the assistant reads is sent to them)", 13.0).color(p.text_strong));
            for kind in [ProviderKind::Anthropic, ProviderKind::OpenAi, ProviderKind::Gemini] {
                preset_row(ui, a, &p, kind, false);
            }
            ui.add_space(10.0);
            ui.label(
                medium(
                    "Terminal agents (Claude Code, Codex, Gemini CLI; they run on your computer)",
                    13.0,
                )
                .color(p.text_strong),
            );
            preset_row(ui, a, &p, ProviderKind::TerminalAgent, false);
            ui.add_space(10.0);
            if ui.button("More options in Settings")
.on_hover_text("Open Settings > AI to choose a model, test it and set keys").clicked() {
                a.requests.push(AssistRequest::OpenSettings(None));
            }
        });
}

fn preset_row(ui: &mut Ui, a: &mut AssistUi, p: &Palette, kind: ProviderKind, one_click: bool) {
    style::card().fill(p.surface).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(medium(kind.label(), 13.5).color(p.text_strong));
                ui.add(
                    egui::Label::new(RichText::new(kind.help()).size(12.0).color(p.text_dim))
                        .wrap(),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if one_click {
                    if style::primary_button(ui, "Use this")
                        .on_hover_text("Use this as the assistant")
                        .clicked()
                    {
                        a.requests.push(AssistRequest::UsePreset(kind));
                    }
                } else if ui
                    .button("Set up...")
                    .on_hover_text("Open Settings to set up this kind of assistant")
                    .clicked()
                {
                    a.requests.push(AssistRequest::OpenSettings(Some(kind)));
                }
            });
        });
    });
    ui.add_space(4.0);
}

fn welcome(ui: &mut Ui, vm: &mut ViewModel, p: &Palette) {
    ui.add_space(10.0);
    ui.label(medium("How can I help?", 16.0).color(p.text_strong));
    ui.label(
        RichText::new(
            "Ask about this program in your own words. I read it with the same tools you have, and I ask before changing anything you already set.",
        )
        .size(12.5)
        .color(p.text_dim),
    );
    ui.add_space(6.0);
    for q in STARTERS {
        if ui
            .button(q)
            .on_hover_text("Ask the assistant this question")
            .clicked()
        {
            vm.assist_send(q);
        }
    }
    ui.add_space(8.0);
}

fn input_area(ui: &mut Ui, vm: &mut ViewModel, a: &mut AssistUi, p: &Palette) {
    let busy = vm.assist.busy();
    let has_backend = vm.assist.backend.is_some();
    if vm.assist.agent_notice_pending() {
        let s = style::status(style::dark(ui));
        if super::agents_ui::notice_card(ui, p, &s, "I understand") {
            a.requests.push(AssistRequest::AcknowledgeAgents);
        }
        ui.add_space(4.0);
    }
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 70.0).max(80.0);
        let edit = egui::TextEdit::singleline(&mut a.input)
            .id(Id::new("kraken_assist_input_text"))
            .hint_text(if has_backend {
                "Ask about this program..."
            } else {
                "Set up an AI model or agent first (Settings > AI)"
            })
            .desired_width(w);
        let r = ui
            .add_enabled(has_backend, edit)
            .on_hover_text("Type a question about this program and press Enter")
            .on_disabled_hover_text("Choose an AI model or a terminal agent first (Settings > AI)");
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if a.focus_input {
            a.focus_input = false;
            r.request_focus();
        }
        if busy {
            if ui
                .button("Stop")
                .on_hover_text("Stop the assistant now")
                .clicked()
            {
                vm.assist_stop();
            }
        } else {
            let send = ui
                .add_enabled(
                    has_backend && !a.input.trim().is_empty(),
                    egui::Button::new("Send"),
                )
                .on_hover_text("Send the question (Enter)")
                .on_disabled_hover_text(if has_backend {
                    "Type a question first"
                } else {
                    "Choose an AI model or a terminal agent first (Settings > AI)"
                });
            if send.clicked() || (enter && !a.input.trim().is_empty()) {
                let text = std::mem::take(&mut a.input);
                vm.assist_send(&text);
                a.focus_input = true;
            }
        }
    });
    let u = vm.assist.usage;
    let badge = vm.assist.badge();
    let model = badge
        .as_ref()
        .map_or_else(|| "no model".to_string(), |b| b.title());
    let agent = badge.as_ref().is_some_and(|b| b.terminal_agent);
    let line = if agent {
        format!("{model}  \u{00b7}  terminal agents do not report token use")
    } else if u.total() > 0 {
        format!(
            "{model}  \u{00b7}  {} tokens used ({} in, {} out)",
            fmt_count(u.total()),
            fmt_count(u.input_tokens),
            fmt_count(u.output_tokens)
        )
    } else {
        format!("{model}  \u{00b7}  no tokens used yet")
    };
    ui.label(RichText::new(line).size(11.0).color(p.text_dim))
        .on_hover_text(
            "Tokens are the pieces of text the model reads and writes. Cloud services bill by them; local models are free.",
        );
}

fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn progress(ui: &mut Ui, vm: &ViewModel, p: &Palette) {
    let Some(kind) = vm.assist.running() else {
        return;
    };
    let asking = vm
        .assist
        .items
        .iter()
        .any(|i| matches!(i, ChatItem::Permission(c) if c.state == PermissionState::Waiting));
    ui.horizontal(|ui| {
        if asking && !vm.assist.stopping() {
            ui.label(RichText::new("Waiting for your answer above").color(p.text_dim));
            return;
        }
        ui.spinner();
        let text = if vm.assist.stopping() {
            "Stopping..."
        } else {
            kind.working_text()
        };
        ui.label(RichText::new(text).color(p.text_dim));
    });
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(120));
}

fn draw_item(ui: &mut Ui, vm: &ViewModel, p: &Palette, item: &ChatItem, acts: &mut Acts) {
    let s = style::status(style::dark(ui));
    match item {
        ChatItem::User(t) => {
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
        ChatItem::Assistant { text, streaming } => {
            ui.label(RichText::new("Assistant").size(11.0).color(p.accent));
            text::paragraphs(ui, vm, p, text, 13.5, &mut acts.goto);
            if *streaming {
                ui.label(RichText::new("\u{2026}").color(p.text_dim));
            }
        }
        ChatItem::Tool(c) => tool_chip(ui, p, &s, c),
        ChatItem::Proposal(c) => proposal_card(ui, p, &s, c, acts),
        ChatItem::Permission(c) => permission_card(ui, p, &s, c, acts),
        ChatItem::Explanation(c) => explain_card(ui, vm, p, c, acts),
        ChatItem::Overview(c) => overview_card(ui, vm, p, c, acts),
        ChatItem::Notice(t) => {
            ui.add(
                egui::Label::new(RichText::new(t).italics().size(12.5).color(p.text_dim)).wrap(),
            );
        }
        ChatItem::Error(t) => {
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

fn tool_chip(ui: &mut Ui, p: &Palette, s: &style::Status, c: &ToolChip) {
    let (dot, state) = match (&c.summary, c.is_error) {
        (None, _) => (p.text_dim, "working"),
        (Some(_), true) => (s.danger, "failed"),
        (Some(_), false) => (s.success, "done"),
    };
    let mut head = egui::text::LayoutJob::default();
    let font = |size: f32, mono: bool| {
        if mono {
            egui::FontId::monospace(size)
        } else {
            egui::FontId::new(size, crate::fonts::medium())
        }
    };
    head.append(
        &c.name,
        0.0,
        egui::TextFormat::simple(font(12.0, true), p.text_strong),
    );
    if !c.args_short.is_empty() {
        head.append(
            &format!("  {}", c.args_short),
            0.0,
            egui::TextFormat::simple(font(11.5, true), p.text_dim),
        );
    }
    let result = match &c.summary {
        Some(sum) => {
            let short: String = sum.chars().take(48).collect();
            let more = if sum.chars().count() > 48 {
                "\u{2026}"
            } else {
                ""
            };
            format!("  \u{2192} {short}{more}")
        }
        None => "  ...".to_string(),
    };
    head.append(
        &result,
        0.0,
        egui::TextFormat::simple(
            font(11.5, false),
            if c.is_error { s.danger } else { p.text_dim },
        ),
    );
    let id = ui.make_persistent_id(("kraken_chip", &c.id));
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
                if c.own_tool {
                    ui.label(RichText::new("agent tool").size(10.0).color(s.warning))
                        .on_hover_text(
                            "One of the agent's own tools, outside KRAKEN's safety net",
                        );
                }
                let (tri, _) = ui.allocate_exact_size(vec2(9.0, 14.0), Sense::hover());
                let c0 = tri.center();
                let points = if open {
                    vec![
                        c0 + vec2(-4.0, -2.0),
                        c0 + vec2(4.0, -2.0),
                        c0 + vec2(0.0, 3.0),
                    ]
                } else {
                    vec![
                        c0 + vec2(-2.0, -4.0),
                        c0 + vec2(-2.0, 4.0),
                        c0 + vec2(3.0, 0.0),
                    ]
                };
                ui.painter().add(egui::Shape::convex_polygon(
                    points,
                    p.text_dim,
                    Stroke::NONE,
                ));
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
                let who = if c.own_tool {
                    format!(
                        "The agent used one of its own tools, `{}` ({state}). KRAKEN cannot undo what it does.",
                        c.name
                    )
                } else {
                    format!("The assistant asked KRAKEN to run `{}` ({state}).", c.name)
                };
                ui.add(egui::Label::new(RichText::new(who).size(12.0).color(p.text_dim)).wrap());
                let args = serde_json::to_string_pretty(&c.args).unwrap_or_default();
                ui.add(egui::Label::new(RichText::new(args).monospace().size(11.5)).wrap());
                if let Some(sum) = &c.summary {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("Result: {sum}"))
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

/// A terminal agent asking to use one of its own tools.
fn permission_card(
    ui: &mut Ui,
    p: &Palette,
    s: &style::Status,
    c: &PermissionCard,
    acts: &mut Acts,
) {
    if c.state != PermissionState::Waiting {
        let (word, color) = match c.state {
            PermissionState::Allowed => ("Allowed", s.success),
            PermissionState::Denied => ("Denied", s.danger),
            _ => ("Withdrawn", p.text_dim),
        };
        ui.horizontal_wrapped(|ui| {
            chip(ui, word, color);
            ui.add(
                egui::Label::new(RichText::new(&c.title).size(12.5).color(p.text_dim)).truncate(),
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
                if let Some(k) = &c.kind {
                    ui.label(RichText::new(k).size(11.5).color(p.text_dim));
                }
            });
            ui.add_space(2.0);
            ui.add(egui::Label::new(medium(&c.title, 13.5).color(p.text_strong)).wrap());
            if let Some(input) = &c.input {
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
            for path in &c.paths {
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
                if style::primary_button(ui, "Allow once")
                    .on_hover_text("Let the agent do this once. Ask again next time")
                    .clicked()
                {
                    acts.answer.push((c.id.clone(), true));
                }
                if ui
                    .button("Deny")
                    .on_hover_text("Refuse. The agent cannot do this")
                    .clicked()
                {
                    acts.answer.push((c.id.clone(), false));
                }
            });
        });
}

fn proposal_card(ui: &mut Ui, p: &Palette, s: &style::Status, c: &ProposalCard, acts: &mut Acts) {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, s.info.gamma_multiply(0.6)))
        .corner_radius(8)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                chip(ui, "needs your approval", s.info);
            });
            ui.add_space(2.0);
            ui.add(egui::Label::new(medium(&c.what, 13.5).color(p.text_strong)).wrap());
            ui.add(
                egui::Label::new(
                    RichText::new(format!("Waiting because: {}", c.reason))
                        .size(12.0)
                        .color(p.text_dim),
                )
                .wrap(),
            );
            ui.add_space(4.0);
            match &c.state {
                ProposalState::Waiting | ProposalState::Failed(_) => {
                    ui.horizontal(|ui| {
                        if style::primary_button(ui, "Accept")
                            .on_hover_text("Apply this change. You can undo it from History")
                            .clicked()
                        {
                            acts.decide.push((c.call_id.clone(), true));
                        }
                        if ui
                            .button("Reject")
                            .on_hover_text("Throw this change away. Nothing is changed")
                            .clicked()
                        {
                            acts.decide.push((c.call_id.clone(), false));
                        }
                    });
                    if let ProposalState::Failed(why) = &c.state {
                        ui.add(
                            egui::Label::new(RichText::new(why).size(12.0).color(s.danger)).wrap(),
                        );
                    }
                }
                ProposalState::Working => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Sending your decision...").color(p.text_dim));
                    });
                }
                ProposalState::Accepted => {
                    ui.label(RichText::new("Accepted. Applied as your own edit.").color(s.success));
                }
                ProposalState::Rejected => {
                    ui.label(RichText::new("Rejected. Nothing was changed.").color(p.text_dim));
                }
            }
        });
}

fn card_title(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    title: &str,
    addr: Option<u64>,
    acts: &mut Acts,
) {
    ui.horizontal(|ui| {
        ui.label(medium(title, 14.0).color(p.text_strong));
        if let Some(a) = addr {
            let name = vm.functions.find(a).map(|f| f.name.clone());
            if let Some(n) = name {
                ui.label(RichText::new(n).monospace().size(12.5).color(p.text));
            }
            text::address_link(ui, vm, p, &format!("{a:#x}"), a, 13.0, &mut acts.goto);
        }
    });
}

fn bullets(ui: &mut Ui, vm: &ViewModel, p: &Palette, items: &[String], acts: &mut Acts) {
    for b in items {
        text::line(ui, vm, p, &format!("\u{2022} {b}"), 13.0, &mut acts.goto);
    }
}

fn explain_card(ui: &mut Ui, vm: &ViewModel, p: &Palette, c: &ExplainCard, acts: &mut Acts) {
    let s = style::status(style::dark(ui));
    style::card().fill(p.surface).stroke(Stroke::new(1.0, p.border)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        card_title(ui, vm, p, &c.title, c.address, acts);
        ui.add_space(2.0);
        text::paragraphs(ui, vm, p, &c.summary, 13.5, &mut acts.goto);
        if !c.key_behaviours.is_empty() {
            ui.add_space(6.0);
            ui.label(medium("What it does", 12.5).color(p.accent));
            bullets(ui, vm, p, &c.key_behaviours, acts);
        }
        if !c.suggested_names.is_empty() {
            ui.add_space(6.0);
            ui.label(medium("Names worth considering", 12.5).color(p.accent));
            for (name, why) in &c.suggested_names {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(name).monospace().color(p.text_strong));
                    ui.label(RichText::new(format!("\u{2014} {why}")).size(12.5).color(p.text_dim));
                    if let Some(a) = c.address
                        && ui
                            .small_button("Use this name")
                            .on_hover_text("Opens the rename box with this name filled in. Nothing changes until you confirm.")
                            .clicked()
                    {
                        acts.rename = Some((a, name.clone()));
                    }
                });
            }
        }
        if !c.caveats.is_empty() {
            ui.add_space(6.0);
            ui.label(medium("Not sure about", 12.5).color(p.accent));
            bullets(ui, vm, p, &c.caveats, acts);
        }
        for w in &c.warnings {
            ui.add(egui::Label::new(RichText::new(w).size(12.0).color(s.warning)).wrap());
        }
    });
}

fn overview_card(ui: &mut Ui, vm: &ViewModel, p: &Palette, c: &OverviewCard, acts: &mut Acts) {
    let s = style::status(style::dark(ui));
    style::card()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(medium("Overview of this program", 14.5).color(p.text_strong));
            ui.add_space(2.0);
            text::paragraphs(ui, vm, p, &c.what_it_is, 13.5, &mut acts.goto);
            if !c.components.is_empty() {
                ui.add_space(6.0);
                ui.label(medium("Main parts", 12.5).color(p.accent));
                for (name, desc) in &c.components {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        ui.label(medium(name, 13.0).color(p.text_strong));
                        ui.label(
                            RichText::new(format!("\u{2014} {desc}"))
                                .size(12.5)
                                .color(p.text_dim),
                        );
                    });
                }
            }
            if !c.interesting.is_empty() {
                ui.add_space(6.0);
                ui.label(medium("Good places to start", 12.5).color(p.accent));
                for f in &c.interesting {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        if let Some(a) = f.address {
                            text::address_link(
                                ui,
                                vm,
                                p,
                                &format!("{a:#x}"),
                                a,
                                13.0,
                                &mut acts.goto,
                            );
                        }
                        if !f.name.is_empty() {
                            ui.label(
                                RichText::new(&f.name)
                                    .monospace()
                                    .size(12.5)
                                    .color(p.text_strong),
                            );
                        }
                        ui.label(
                            RichText::new(format!("\u{2014} {}", f.reason))
                                .size(12.5)
                                .color(p.text_dim),
                        );
                    });
                }
            }
            if !c.next_steps.is_empty() {
                ui.add_space(6.0);
                ui.label(medium("What to do next", 12.5).color(p.accent));
                bullets(ui, vm, p, &c.next_steps, acts);
            }
            for m in &c.missing_data {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Note: {m}."))
                            .italics()
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .wrap(),
                );
            }
            for w in &c.warnings {
                ui.add(egui::Label::new(RichText::new(w).size(12.0).color(s.warning)).wrap());
            }
        });
}

/// The "Suggest names..." button for the Functions panel header.
pub fn suggest_names_button(ui: &mut Ui, vm: &mut ViewModel) {
    let busy = vm.assist.busy();
    let r = ui
        .add_enabled(!busy, egui::Button::new("Suggest names...").small())
        .on_hover_text(
            "Ask the assistant to propose names for functions that still have placeholder names like FUN_00401340. You review them before anything changes.",
        )
        .on_disabled_hover_text("Wait for the assistant to finish what it is doing");
    if r.clicked() {
        vm.assist_auto_name(10);
    }
}

/// Colour helper for confidence chips (kept next to the chat so the table matches).
pub fn confidence_color(c: kraken_viewmodel::assist::Confidence, dark: bool) -> Color32 {
    let s = style::status(dark);
    match c {
        kraken_viewmodel::assist::Confidence::High => s.success,
        kraken_viewmodel::assist::Confidence::Medium => s.info,
        kraken_viewmodel::assist::Confidence::Low => s.warning,
    }
}
