//! The dock layout and the panels that fill it.

use std::time::{Duration, Instant};

use egui::{Id, RichText, Ui, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use kraken_gui_widgets::{TokenText, VirtualList};
use kraken_proto::{Locator, TokenKind};
use kraken_viewmodel::{Decompiled, FunctionItem, Load, ToastLevel, ViewModel};

use crate::panels::{self, PanelState};
use crate::style::{self, chip, empty_state, medium, pal};

/// Time a call-target click waits for a possible second click (a rename) before navigating.
pub const DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(260);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Tab {
    Functions,
    Decompiler,
    Hex,
    Listing,
    Graph,
    Xrefs,
    Strings,
    Symbols,
    History,
    Proposals,
    Assistant,
    Agents,
    Rewrite,
}

impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Tab::Functions => "Functions",
            Tab::Decompiler => "Decompiler",
            Tab::Hex => "Hex",
            Tab::Listing => "Listing",
            Tab::Graph => "Graph",
            Tab::Xrefs => "Xrefs",
            Tab::Strings => "Strings",
            Tab::Symbols => "Imports / Exports",
            Tab::History => "History",
            Tab::Proposals => "Proposals",
            Tab::Assistant => "Assistant",
            Tab::Agents => "Agents",
            Tab::Rewrite => "Rewrite",
        }
    }

    /// One plain sentence for the tab's tooltip (decision 20, staged).
    pub fn tooltip(self) -> &'static str {
        match self {
            Tab::Functions => "Every function KRAKEN found in the program. Click one to read it.",
            Tab::Decompiler => {
                "The selected function rewritten as readable C-like code. Click a call to follow it."
            }
            Tab::Hex => "The raw bytes of the program, as hexadecimal numbers and text.",
            Tab::Listing => "The machine instructions behind the code, one per line.",
            Tab::Graph => {
                "The same code as boxes joined by arrows. Space swaps it with the listing."
            }
            Tab::Xrefs => "Who calls this function, what it calls, and what refers to any address.",
            Tab::Strings => "Text found inside the program. Double-click one to see what uses it.",
            Tab::Symbols => "What the program borrows from libraries, and what it makes available.",
            Tab::History => "Every change made to this project, who made it, and a way to undo it.",
            Tab::Proposals => "Changes suggested by AI assistants that wait for your approval.",
            Tab::Assistant => {
                "Ask the AI assistant questions about this program and get plain-language answers."
            }
            Tab::Agents => {
                "Run a terminal coding agent such as Claude Code on this project, with KRAKEN's tools."
            }
            Tab::Rewrite => {
                "Rewrite functions in Rust, check each against the original, and export what you accept."
            }
        }
    }
}

pub fn initial_dock() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Decompiler]);
    let surface = dock.main_surface_mut();
    let [center, _left] = surface.split_left(NodeIndex::root(), 0.18, vec![Tab::Functions]);
    let [center, right] = surface.split_right(center, 0.5, vec![Tab::Hex]);
    let [_hex, _code] = surface.split_below(right, 0.34, vec![Tab::Listing, Tab::Graph]);
    let [_center, _bottom] = surface.split_below(
        center,
        0.64,
        vec![
            Tab::Xrefs,
            Tab::Strings,
            Tab::Symbols,
            Tab::History,
            Tab::Proposals,
            Tab::Rewrite,
        ],
    );
    dock
}

/// A layout that gives the graph the room it needs: decompiler and graph side by side.
pub fn graph_dock() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Decompiler]);
    let surface = dock.main_surface_mut();
    let [center, _left] = surface.split_left(NodeIndex::root(), 0.17, vec![Tab::Functions]);
    let [center, _graph] = surface.split_right(center, 0.4, vec![Tab::Graph, Tab::Listing]);
    let [_decompiler, _bottom] = surface.split_below(
        center,
        0.66,
        vec![
            Tab::Hex,
            Tab::Xrefs,
            Tab::Strings,
            Tab::Symbols,
            Tab::History,
            Tab::Proposals,
            Tab::Rewrite,
        ],
    );
    dock
}

/// GUI-only state that does not belong in the view-model.
#[derive(Default)]
pub struct UiState {
    pub filter_text: String,
    pub focus_filter: bool,
    /// A call-target click waiting out the double-click window.
    pub pending_nav: Option<(u64, Instant)>,
    /// Symbol highlighted when the decompiler first draws (screenshot mode).
    pub initial_highlight: Option<String>,
    pub bring_to_front: Option<Tab>,
    /// State of the program views (listing, hex, graph, lists).
    pub panels: PanelState,
    pub assist: crate::assist::AssistUi,
    pub agents: crate::agents::AgentsUi,
    pub rewrite: crate::rewrite::RewriteUi,
}

impl UiState {
    /// Applies a navigation click once the double-click window has passed.
    pub fn flush_pending_nav(&mut self, vm: &mut ViewModel, ctx: &egui::Context) {
        if let Some((addr, at)) = self.pending_nav {
            let waited = at.elapsed();
            if waited >= DOUBLE_CLICK_WINDOW {
                self.pending_nav = None;
                vm.navigate_to(addr);
            } else {
                ctx.request_repaint_after(DOUBLE_CLICK_WINDOW - waited);
            }
        }
    }
}

pub struct Viewer<'a> {
    pub vm: &'a mut ViewModel,
    pub ui: &'a mut UiState,
}

pub fn show(ui: &mut Ui, dock: &mut DockState<Tab>, vm: &mut ViewModel, state: &mut UiState) {
    panels::global_keys(ui.ctx(), dock, vm, &mut state.panels);
    if std::mem::take(&mut vm.assist.show_requested) {
        state.bring_to_front = Some(Tab::Assistant);
    }
    if let Some(tab) = state.bring_to_front.take()
        && let Some(path) = dock.find_tab(&tab)
    {
        let _ = dock.set_active_tab(path);
    }
    let style = Style::from_egui(ui.style().as_ref());
    let mut viewer = Viewer { vm, ui: state };
    DockArea::new(dock)
        .style(style)
        .show_close_buttons(false)
        .show_leaf_close_all_buttons(false)
        .show_leaf_collapse_buttons(false)
        .show_inside(ui, &mut viewer);
}

impl TabViewer for Viewer<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> Id {
        Id::new(("kraken_tab", *tab))
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        let mut title = tab.title().to_string();
        if *tab == Tab::Proposals && !self.vm.proposals.items.is_empty() {
            title = format!("{title} ({})", self.vm.proposals.items.len());
        }
        if self.vm.assist.learn_mode {
            title.push_str("  ?");
        }
        title.into()
    }

    fn is_closeable(&self, _tab: &Tab) -> bool {
        false
    }

    fn on_tab_button(&mut self, tab: &mut Tab, response: &egui::Response) {
        let tab = *tab;
        let vm = &*self.vm;
        response
            .clone()
            .on_hover_ui(|ui| crate::assist::tab_help(ui, vm, tab));
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        match tab {
            Tab::Functions => functions(ui, self.vm, self.ui),
            Tab::Decompiler => decompiler(ui, self.vm, self.ui),
            Tab::Hex => panels::hex::show(ui, self.vm, &mut self.ui.panels),
            Tab::Listing => panels::listing::show(ui, self.vm, &mut self.ui.panels),
            Tab::Graph => panels::graph::show(ui, self.vm, &mut self.ui.panels),
            Tab::Xrefs => panels::xrefs::show(ui, self.vm, &mut self.ui.panels),
            Tab::Strings => panels::strings::show(ui, self.vm, &mut self.ui.panels),
            Tab::Symbols => panels::symbols::show(ui, self.vm, &mut self.ui.panels),
            Tab::History => crate::history::panel(ui, self.vm),
            Tab::Proposals => proposals(ui, self.vm),
            Tab::Assistant => crate::assist::panel(ui, self.vm, self.ui),
            Tab::Agents => crate::agents::panel(ui, self.vm, self.ui),
            Tab::Rewrite => crate::rewrite::panel(
                ui,
                self.vm,
                &mut self.ui.rewrite,
                &mut self.ui.bring_to_front,
            ),
        }
    }
}

// ---------------------------------------------------------------- functions

fn functions(ui: &mut Ui, vm: &mut ViewModel, st: &mut UiState) {
    let p = pal(ui);
    ui.add_space(2.0);
    let filter_id = Id::new("kraken_function_filter");
    let edit = egui::TextEdit::singleline(&mut st.filter_text)
        .id(filter_id)
        .hint_text("Filter functions  (Ctrl+L)")
        .desired_width(f32::INFINITY);
    let resp = ui.add(edit);
    if st.focus_filter {
        st.focus_filter = false;
        resp.request_focus();
    }
    if resp.changed() {
        vm.set_filter(st.filter_text.clone());
    }
    if resp.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        st.filter_text.clear();
        vm.set_filter("");
        resp.surrender_focus();
    }

    let n = vm.functions.items.len();
    let summary = if vm.functions.loading && n == 0 {
        "Loading...".to_string()
    } else if !vm.functions.filter.is_empty() {
        format!("{n} match{}", if n == 1 { "" } else { "es" })
    } else if let Some(total) = vm.functions.total {
        format!("{n} of {total} functions")
    } else if vm.functions.has_more() {
        format!("{n}+ functions")
    } else {
        format!("{n} function{}", if n == 1 { "" } else { "s" })
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(summary).size(11.5).color(p.text_dim));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            crate::assist::suggest_names_button(ui, vm);
        });
    });
    ui.add_space(2.0);

    if let Some(err) = vm.functions.error.clone() {
        let s = style::status(style::dark(ui));
        ui.label(RichText::new(err).color(s.danger));
        if ui.button("Try again").clicked() {
            vm.refresh_functions();
        }
        return;
    }
    if n == 0 {
        if vm.functions.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Loading functions...").color(p.text_dim));
            });
        } else if !vm.functions.filter.is_empty() {
            empty_state(
                ui,
                "No matches",
                &format!("No function name contains \"{}\".", vm.functions.filter),
                Some("Clear the filter to see everything."),
            );
        } else {
            empty_state(
                ui,
                "No functions yet",
                "Functions appear here once the program has been analyzed.",
                Some("Press Analyze in the top bar."),
            );
        }
        return;
    }

    let mut selected = vm.selected.and_then(|a| vm.functions.index_of(a));
    let mut max_seen = 0usize;
    let items: &[FunctionItem] = &vm.functions.items;
    let stale = &vm.undo.stale;
    let resp = VirtualList::new("functions", n, 22.0).show(ui, &mut selected, |ui, i, sel| {
        max_seen = max_seen.max(i);
        let f = &items[i];
        let addr = RichText::new(format!("{:08x}", f.address))
            .monospace()
            .size(12.0)
            .color(p.address);
        ui.label(addr);
        let color = if sel { p.text_strong } else { p.text };
        let mut name = RichText::new(&f.name).monospace().size(12.5).color(color);
        if f.partial {
            name = name.italics();
        }
        let r = ui.label(name);
        crate::assist::capture_function_row(ui, &r, f.address, &mut st.assist);
        if stale.contains(&f.address) {
            stale_marker(ui);
        }
        if f.partial || f.signature.is_some() {
            let tip = match (&f.signature, f.partial) {
                (Some(s), true) => format!("{s}\nStill being analyzed"),
                (Some(s), false) => s.clone(),
                (None, _) => "Still being analyzed".to_string(),
            };
            r.on_hover_text(tip);
        }
    });
    if resp.changed
        && let Some(i) = selected
        && let Some(f) = vm.functions.items.get(i)
    {
        let addr = f.address;
        st.pending_nav = None;
        vm.select_function(addr);
    }
    vm.ensure_loaded(max_seen + 1);
}

/// The small marker on a function whose derived data is stale after an undo.
fn stale_marker(ui: &mut Ui) {
    let s = style::status(style::dark(ui));
    chip(ui, "stale", s.warning).on_hover_text(
        "A type or signature edit was undone. What was derived from it may be out of date until this function is read again.",
    );
}

// ---------------------------------------------------------------- decompiler

/// What the decompiler pane wants done once its borrow of the view-model ends.
enum Act {
    Rename,
    Comment,
    Retry,
    RenameAt(u64, Option<String>),
    Notice(&'static str),
    SyncListing(u64),
    RewriteThis,
}

fn decompiler(ui: &mut Ui, vm: &mut ViewModel, st: &mut UiState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let mut acts: Vec<Act> = Vec::new();
    {
        let Some(cur) = vm.current.as_ref() else {
            empty_state(
                ui,
                "Pick a function to read",
                "Choose one from the Functions list on the left. KRAKEN turns its machine code into readable C-like code here.",
                Some(
                    "Tip: click a call to follow it, double-click a name (or press N) to rename it.",
                ),
            );
            return;
        };
        ui.horizontal(|ui| {
            ui.label(medium(&cur.name, 15.0).color(p.text_strong));
            ui.label(
                RichText::new(format!("{:#x}", cur.address))
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            );
            if let Load::Ready(d) = &cur.decompiled
                && let Some(reason) = &d.partial_reason
            {
                chip(ui, "partial", s.warning)
                    .on_hover_text(format!("This result may change: {reason}."));
            }
            if vm.is_stale(cur.address) {
                stale_marker(ui);
            }
            if cur.refreshing {
                ui.spinner();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button("Comment")
                    .on_hover_text("Leave a note on this function")
                    .clicked()
                {
                    acts.push(Act::Comment);
                }
                if ui
                    .add_enabled(vm.rewrite.can_run(), egui::Button::new("Rewrite in Rust"))
                    .on_hover_text(vm.rewrite.blocked_note().unwrap_or(
                        "Translate this function to Rust and check it against the original. See the Rewrite tab.",
                    ))
                    .clicked()
                {
                    acts.push(Act::RewriteThis);
                }
                if ui
                    .button("Rename  (N)")
                    .on_hover_text("Give this function a better name")
                    .clicked()
                {
                    acts.push(Act::Rename);
                }
            });
        });
        if let Some(d) = &cur.detail {
            if let Some(sig) = &d.signature {
                ui.label(RichText::new(sig).monospace().size(12.0).color(p.text_dim));
            }
            for c in &d.comments {
                ui.label(
                    RichText::new(format!("// {}", c.text))
                        .italics()
                        .size(12.0)
                        .color(p.text_dim),
                );
            }
        }
        ui.add_space(2.0);
        ui.separator();

        match &cur.decompiled {
            Load::Idle | Load::Loading => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Decompiling...").color(p.text_dim));
                });
            }
            Load::Failed(msg) => {
                ui.add_space(8.0);
                ui.label(RichText::new("This function could not be decompiled.").color(s.danger));
                ui.label(RichText::new(msg).color(p.text_dim));
                if ui.button("Try again").clicked() {
                    acts.push(Act::Retry);
                }
            }
            Load::Ready(d) => code(ui, st, cur.address, d, &mut acts),
        }
    }
    for a in acts {
        match a {
            Act::Rename => vm.begin_rename_current(),
            Act::Comment => vm.begin_comment_current(),
            Act::Retry => vm.refresh_current(),
            Act::RenameAt(addr, name) => vm.begin_rename(addr, name.as_deref()),
            Act::Notice(t) => vm.toast(ToastLevel::Info, t),
            Act::SyncListing(a) => {
                vm.sync_listing_to(a);
            }
            Act::RewriteThis => {
                vm.rewrite_run_current();
                st.bring_to_front = Some(Tab::Rewrite);
            }
        }
    }
}

fn target_of(t: &kraken_proto::Token) -> Option<u64> {
    match &t.target {
        Some(Locator::Native { offset, .. }) => Some(offset.0),
        Some(Locator::Managed { token, .. }) => Some(u64::from(*token)),
        _ => None,
    }
}

fn code(ui: &mut Ui, st: &mut UiState, addr: u64, d: &Decompiled, acts: &mut Vec<Act>) {
    let s = style::status(style::dark(ui));
    if !d.warnings.is_empty() {
        ui.label(
            RichText::new(format!(
                "{} decompiler warning{}: {}",
                d.warnings.len(),
                if d.warnings.len() == 1 { "" } else { "s" },
                d.warnings.join("; ")
            ))
            .size(12.0)
            .color(s.warning),
        );
    }
    if d.truncated {
        ui.label(
            RichText::new("This function is very long; the end is cut off.")
                .size(12.0)
                .color(s.warning),
        );
    }
    let mut widget = TokenText::new(&d.result)
        .id_salt("decompiler")
        .cache_id(d.revision);
    if let Some(sym) = &st.initial_highlight {
        widget = widget.initial_highlight(sym.clone());
    }
    let out = widget.show(ui);
    crate::assist::capture_decompiler(ui, &out, d, addr, &mut st.assist);

    let double = ui.input(|i| {
        i.pointer
            .button_double_clicked(egui::PointerButton::Primary)
    });
    let hovered_tok = out.hovered.and_then(|i| d.result.tokens.get(i));
    if let Some(a) = hovered_tok.and_then(target_of) {
        st.panels.hot = Some(a);
    }

    if double {
        if let Some(t) = hovered_tok {
            st.pending_nav = None;
            match target_of(t) {
                Some(a) => acts.push(Act::RenameAt(a, t.symbol.clone())),
                None => acts.push(Act::Notice(
                    "Only function names can be renamed so far. Variables are coming later.",
                )),
            }
        }
    } else if let Some(c) = out.clicked
        && let Some(target) = c.target.as_ref().and_then(|l| match l {
            Locator::Native { offset, .. } => Some(offset.0),
            Locator::Managed { token, .. } => Some(u64::from(*token)),
            _ => None,
        })
    {
        // The listing follows the click right away; the jump waits out a possible double-click.
        acts.push(Act::SyncListing(target));
        if target != addr {
            st.pending_nav = Some((target, Instant::now()));
            ui.ctx().request_repaint_after(DOUBLE_CLICK_WINDOW);
        }
    }

    // N renames the name under the pointer, or the function being read.
    let typing = ui.ctx().egui_wants_keyboard_input();
    if !typing && ui.input(|i| i.key_pressed(egui::Key::N) && !i.modifiers.any()) {
        match hovered_tok
            .filter(|t| t.kind == TokenKind::Function)
            .and_then(|t| target_of(t).map(|a| (a, t.symbol.clone())))
        {
            Some((a, sym)) => acts.push(Act::RenameAt(a, sym)),
            None => acts.push(Act::Rename),
        }
    }
}

// ---------------------------------------------------------------- proposals

fn proposals(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    if let Some(e) = &vm.proposals.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    if vm.proposals.items.is_empty() {
        empty_state(
            ui,
            "Nothing to review",
            "When an AI assistant suggests a change that needs your approval, it will wait here.",
            None,
        );
        return;
    }
    let mut accept = None;
    let mut reject = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for pr in &vm.proposals.items {
                style::card().fill(p.surface).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        chip(ui, &pr.who, s.info);
                        ui.label(RichText::new(&pr.description).monospace().size(12.5));
                    });
                    ui.label(
                        RichText::new(format!("Waiting because: {}", pr.reason))
                            .size(12.0)
                            .color(p.text_dim),
                    );
                    ui.horizontal(|ui| {
                        if style::primary_button(ui, "Accept").clicked() {
                            accept = Some(pr.id);
                        }
                        if ui.button("Reject").clicked() {
                            reject = Some(pr.id);
                        }
                    });
                });
                ui.add_space(4.0);
            }
        });
    if let Some(id) = accept {
        vm.accept_proposal(id);
    }
    if let Some(id) = reject {
        vm.reject_proposal(id);
    }
}
