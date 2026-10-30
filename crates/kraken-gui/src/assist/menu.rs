//! The right-click menu of the decompiler, the function list, the listing and the graph: the
//! editing and navigation items (`panels::context`) above the assistant's Explain items.

use egui::{Align2, Frame, Id, Key, Margin, Pos2, RichText, Stroke, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::SelectionKind;

use super::AssistUi;
use crate::panels::context::{self, NavChoice, Target, TargetKind};

/// What the menu offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuState {
    /// Where the person right-clicked.
    pub pos: Pos2,
    /// The word under the pointer.
    pub token: Option<String>,
    /// The line of code or listing the word is on.
    pub line: Option<String>,
    /// What `line` is.
    pub line_kind: SelectionKind,
    /// The function the click was in.
    pub function: Option<u64>,
    /// What the editing and navigation items act on.
    pub target: Option<Target>,
}

fn pointer(ui: &Ui) -> Option<Pos2> {
    ui.input(|i| i.pointer.interact_pos())
}

fn right_clicked(ui: &Ui) -> bool {
    ui.input(|i| i.pointer.secondary_clicked())
}

/// Call right after drawing the decompiler text: a right-click inside it opens the menu for the
/// word under the pointer, its line and the whole function.
pub fn capture_decompiler(
    ui: &Ui,
    out: &kraken_gui_widgets::TokenTextResponse,
    d: &kraken_viewmodel::Decompiled,
    function: u64,
    a: &mut AssistUi,
) {
    let Some(pos) = pointer(ui).filter(|p| out.response.rect.contains(*p)) else {
        return;
    };
    if !right_clicked(ui) {
        return;
    }
    let text = &d.result.text;
    let tok = out.hovered.and_then(|i| d.result.tokens.get(i));
    let token = tok
        .and_then(|t| text.get(t.start as usize..t.end as usize))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let target = Some(match tok {
        Some(t) => context::token_target(t, text, function),
        None => Target {
            kind: TargetKind::Function,
            address: Some(function),
            name: None,
            function: Some(function),
            varnode: None,
        },
    });
    let line = tok.and_then(|t| {
        let start = t.start as usize;
        let from = text.get(..start)?.rfind('\n').map_or(0, |i| i + 1);
        let to = text
            .get(start..)?
            .find('\n')
            .map_or(text.len(), |i| start + i);
        text.get(from..to)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
    });
    a.menu = Some(MenuState {
        pos,
        token,
        line,
        line_kind: SelectionKind::Decompile,
        function: Some(function),
        target,
    });
}

/// Call with the response of a function-list row (or any row standing for a function): a
/// right-click offers "Explain this function".
pub fn capture_function_row(ui: &Ui, row: &egui::Response, function: u64, a: &mut AssistUi) {
    if row.hovered()
        && right_clicked(ui)
        && let Some(pos) = pointer(ui)
    {
        a.menu = Some(MenuState {
            pos,
            token: None,
            line: None,
            line_kind: SelectionKind::Decompile,
            function: Some(function),
            target: Some(Target {
                kind: TargetKind::Function,
                address: Some(function),
                name: None,
                function: Some(function),
                varnode: None,
            }),
        });
    }
}

/// Call when the pointer is over an instruction (a listing row, a graph block) inside `rect`: a
/// right-click opens the menu for that address, with Explain for the instruction and the
/// function.
pub fn capture_instruction_at(
    ui: &Ui,
    rect: egui::Rect,
    address: u64,
    instruction: &str,
    function: Option<u64>,
    a: &mut AssistUi,
) {
    if let Some(pos) = pointer(ui).filter(|p| rect.contains(*p))
        && right_clicked(ui)
    {
        a.menu = Some(MenuState {
            pos,
            token: None,
            line: Some(instruction.trim().to_string()).filter(|l| !l.is_empty()),
            line_kind: SelectionKind::Instruction,
            function,
            target: Some(Target {
                kind: TargetKind::Code,
                address: Some(address),
                name: None,
                function,
                varnode: None,
            }),
        });
    }
}

fn clip(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}\u{2026}")
    } else {
        t
    }
}

/// Draws the open menu and runs the chosen explanation.
pub fn show(ctx: &egui::Context, vm: &mut ViewModel, a: &mut AssistUi) {
    let Some(m) = a.menu.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let mut choice: Option<Choice> = None;
    let mut nav: Option<NavChoice> = None;
    let target = m.target.clone().map(|mut t| {
        if t.name.is_none()
            && t.kind == TargetKind::Function
            && let Some(f) = t.address.and_then(|a| vm.functions.find(a))
        {
            t.name = Some(f.name.clone());
        }
        t
    });
    let nav_items = target
        .as_ref()
        .map(|t| context::items(vm, t))
        .unwrap_or_default();
    let area = egui::Area::new(Id::new("kraken_explain_menu"))
        .order(egui::Order::Foreground)
        .fixed_pos(m.pos)
        .pivot(Align2::LEFT_TOP)
        .show(ctx, |ui| {
            Frame::new()
                .fill(p.panel)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(8)
                .inner_margin(Margin::same(6))
                .shadow(egui::Shadow {
                    offset: [0, 6],
                    blur: 18,
                    spread: 0,
                    color: egui::Color32::from_black_alpha(120),
                })
                .show(ui, |ui| {
                    ui.set_min_width(230.0);
                    if let Some(t) = &target {
                        context::heading(ui, t, p.text_dim);
                        context::draw(ui, &nav_items, &mut nav);
                        ui.separator();
                    }
                    ui.label(
                        RichText::new("Ask the assistant")
                            .size(11.0)
                            .color(p.text_dim),
                    );
                    if let Some(t) = &m.token
                        && ui
                            .button(format!("Explain `{}`", clip(t, 28)))
                            .on_hover_text("Ask the assistant what this name means")
                            .clicked()
                    {
                        choice = Some(Choice::Text(m.line_kind, t.clone()));
                    }
                    if let Some(l) = &m.line {
                        let what = if m.line_kind == SelectionKind::Instruction {
                            "this instruction"
                        } else {
                            "this line"
                        };
                        if ui
                            .button(format!("Explain {what}"))
                            .on_hover_text(clip(l, 120))
                            .clicked()
                        {
                            choice = Some(Choice::Text(m.line_kind, l.clone()));
                        }
                    }
                    if m.function.is_some()
                        && ui
                            .button("Explain this function")
                            .on_hover_text("Ask the assistant what the whole function does")
                            .clicked()
                    {
                        choice = Some(Choice::Function);
                    }
                });
        });
    let outside = ctx.input(|i| i.pointer.any_pressed())
        && ctx
            .input(|i| i.pointer.interact_pos())
            .is_some_and(|p| !area.response.rect.contains(p));
    let esc = ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Escape));
    if let (Some(n), Some(t)) = (nav, &target) {
        a.menu = None;
        context::run(ctx, vm, t, n);
        return;
    }
    match choice {
        Some(Choice::Function) => {
            if let Some(f) = m.function {
                vm.assist_explain_function(f);
            }
            a.menu = None;
        }
        Some(Choice::Text(kind, text)) => {
            vm.assist_explain_selection(kind, &text, m.function);
            a.menu = None;
        }
        None if outside || esc => a.menu = None,
        None => {}
    }
}

enum Choice {
    Function,
    Text(SelectionKind, String),
}
