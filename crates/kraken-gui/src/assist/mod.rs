//! The assistant's windows and panels (decisions 12, 19, 20): the Assistant tab, the "Explain"
//! menu, the first-overview banner, the name-review window, learn mode and the AI settings.
//!
//! All state lives in the view-model (`vm.assist`); this module only draws it and forwards
//! clicks. [`AssistUi`] holds the little that is purely visual.

mod agent_demo;
mod agents_ui;
pub(crate) mod automate;
mod chat;
mod demo;
mod learn;
mod menu;
mod overlays;
mod settings_ai;
mod settings_cost;
mod settings_extras;
mod setup;
#[cfg(test)]
mod tests;
// The agent tests run the fake ACP agent, a Unix-style process.
#[cfg(all(test, unix))]
mod agent_tests;
pub(crate) mod text;

use egui::Ui;
use egui_dock::DockState;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::ProviderKind;

pub use agent_demo::{FAKE_AGENT_FLAG, SCENE_PROMPT, run_fake_agent, scene_backend, scene_config};
pub use chat::{panel, suggest_names_button};
pub use demo::{CHAT_QUESTION, provider_for};
pub use learn::top_bar_buttons;
pub use menu::{capture_decompiler, capture_function_row};

// Hooks for panels that draw instructions and terms (the listing, the graph): glossary hovers
// and the instruction right-click menu.
#[allow(unused_imports)]
pub use learn::{mnemonic_hover, term_hover};
#[cfg(test)]
pub use menu::MenuState;
pub use menu::capture_instruction_at;
pub use settings_ai::{AiSettings, Change};
pub use setup::AssistSetup;

use crate::workspace::Tab;

/// What the assistant panels ask the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssistRequest {
    /// Save and use the standard settings of a local provider.
    UsePreset(ProviderKind),
    /// Open Settings on the AI section, optionally starting from a provider's settings
    /// (`ProviderKind::TerminalAgent` starts from a terminal agent).
    OpenSettings(Option<ProviderKind>),
    /// The person read the one-time note about terminal agents.
    AcknowledgeAgents,
}

/// Purely visual assistant state.
#[derive(Default)]
pub struct AssistUi {
    /// The chat input box.
    pub input: String,
    /// Put the cursor in the input box next frame.
    pub focus_input: bool,
    /// The "?" explanation under the header is open.
    pub help_open: bool,
    /// The open "Explain" menu.
    pub menu: Option<menu::MenuState>,
    /// An address clicked in the conversation, to open.
    pub goto: Option<u64>,
    /// How many conversation items the panel has already shown.
    pub seen_items: usize,
    /// Things for the app to do.
    pub requests: Vec<AssistRequest>,
    /// The Automate dialog.
    pub automate: automate::AutomateUi,
}

/// Adds the Assistant tab to the leaf that holds the Hex tab (or the focused leaf).
pub fn with_assistant_tab(mut dock: DockState<Tab>) -> DockState<Tab> {
    use egui_dock::{Node, NodeIndex};
    let tree = dock.main_surface_mut();
    let Some((leaf, _)) = tree.find_tab(&Tab::Hex) else {
        dock.push_to_focused_leaf(Tab::Assistant);
        return dock;
    };
    let front = tree[leaf]
        .tabs()
        .and_then(|t| t.iter().position(|x| *x == Tab::Hex));
    tree[leaf].append_tab(Tab::Assistant);
    if let (Some(i), Node::Leaf(l)) = (front, &mut tree[leaf]) {
        let _ = l.set_active_tab(i);
    }
    // A conversation needs room: give the column more width and its top pane more height.
    let mut at: NodeIndex = leaf;
    let mut tall_done = false;
    let mut wide_done = false;
    while let Some(parent) = at.parent() {
        match &mut tree[parent] {
            Node::Vertical(split) if !tall_done && at.is_left() => {
                split.fraction = 0.62;
                tall_done = true;
            }
            Node::Horizontal(split) if !wide_done && !at.is_left() => {
                split.fraction = 0.56;
                wide_done = true;
            }
            _ => {}
        }
        at = parent;
    }
    dock
}

/// The layout of the conversation screenshots: the Assistant tab gets a full-height column
/// beside the code, because a chat needs the room.
pub fn scene_dock() -> DockState<Tab> {
    use egui_dock::NodeIndex;
    let mut dock = DockState::new(vec![Tab::Decompiler]);
    let surface = dock.main_surface_mut();
    let [center, _left] = surface.split_left(NodeIndex::root(), 0.17, vec![Tab::Functions]);
    let [center, _chat] = surface.split_right(center, 0.5, vec![Tab::Assistant]);
    let [_code, _bottom] = surface.split_below(
        center,
        0.68,
        vec![
            Tab::Listing,
            Tab::Graph,
            Tab::Xrefs,
            Tab::Hex,
            Tab::Strings,
            Tab::Symbols,
            Tab::History,
            Tab::Proposals,
        ],
    );
    dock
}

/// Floating assistant parts, drawn after the workspace.
pub fn overlays(ctx: &egui::Context, vm: &mut ViewModel, a: &mut AssistUi) {
    overlays::banner(ctx, vm);
    overlays::autoname(ctx, vm);
    menu::show(ctx, vm, a);
    automate::dialog(ctx, vm, &mut a.automate);
}

/// Hover help for the panel tabs; see [`learn::tab_tooltip`].
pub fn tab_help(ui: &mut Ui, vm: &ViewModel, tab: Tab) {
    learn::tab_tooltip(ui, vm, tab.title(), tab.tooltip());
}
