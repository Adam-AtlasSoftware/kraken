//! The Agents tab (decisions 35, 50): run Claude Code, Codex or Gemini CLI on the open project,
//! connected to KRAKEN's own tools.
//!
//! All state lives in the view-model (`vm.agents`); this module draws it and forwards clicks.

mod demo;
mod list;
mod notice;
mod session;
#[cfg(test)]
mod tests;

use egui::Ui;
use egui_dock::DockState;
use kraken_viewmodel::ViewModel;

pub use demo::{FAKE_AGENT_FLAG, SCENE_PROMPT, run_fake_agent, scene_config};

use crate::style::empty_state;
use crate::workspace::{Tab, UiState};

/// Purely visual state of the tab.
#[derive(Default)]
pub struct AgentsUi {
    /// The prompt box.
    pub input: String,
    /// Put the cursor in the prompt box next frame.
    pub focus_input: bool,
    /// An address clicked in the conversation, to open.
    pub goto: Option<u64>,
    /// How many session items the panel has already shown.
    pub seen_items: usize,
}

/// Adds the Agents tab next to the Assistant tab (or the focused leaf).
pub fn with_agents_tab(mut dock: DockState<Tab>) -> DockState<Tab> {
    let tree = dock.main_surface_mut();
    match tree.find_tab(&Tab::Assistant) {
        Some((leaf, _)) => {
            let front = tree[leaf]
                .tabs()
                .and_then(|t| t.iter().position(|x| *x == Tab::Hex));
            tree[leaf].append_tab(Tab::Agents);
            if let (Some(i), egui_dock::Node::Leaf(l)) = (front, &mut tree[leaf]) {
                let _ = l.set_active_tab(i);
            }
        }
        None => dock.push_to_focused_leaf(Tab::Agents),
    }
    dock
}

/// The layout of the conversation screenshots: `first` gets a full-height column.
pub fn scene_dock(first: Tab) -> DockState<Tab> {
    let second = if first == Tab::Agents {
        Tab::Assistant
    } else {
        Tab::Agents
    };
    use egui_dock::NodeIndex;
    let mut dock = DockState::new(vec![Tab::Decompiler]);
    let surface = dock.main_surface_mut();
    let [center, _left] = surface.split_left(NodeIndex::root(), 0.17, vec![Tab::Functions]);
    let [center, _agents] = surface.split_right(center, 0.5, vec![first, second]);
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

/// The Agents tab.
pub fn panel(ui: &mut Ui, vm: &mut ViewModel, st: &mut UiState) {
    vm.agents_ensure_loaded();
    if vm.agents.session.is_some() {
        session::show(ui, vm, &mut st.agents);
    } else if vm.agents.pending_notice.is_some() {
        notice::show(ui, vm);
    } else if vm.project.is_none() {
        empty_state(
            ui,
            "No project open",
            "Terminal agents work on an open project. Open one first.",
            None,
        );
    } else {
        list::show(ui, vm);
    }
    if let Some(addr) = st.agents.goto.take() {
        vm.navigate_to(addr);
        st.bring_to_front = Some(Tab::Decompiler);
    }
}
