//! Command palette state: a fuzzy list over app actions and backend commands.

use crate::backend::{CommandInfo, Permission};
use crate::fuzzy;

/// Things the GUI can do, with or without a backend command behind them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppAction {
    /// Run analysis on the open project.
    Analyze,
    /// Cancel the running analysis.
    CancelAnalysis,
    /// Undo the user's most recent edit.
    UndoLast,
    /// Reload every panel from the backend.
    RefreshAll,
    /// Go to the previous function.
    Back,
    /// Go to the next function.
    Forward,
    /// Rename the function being viewed.
    RenameCurrent,
    /// Comment on the function being viewed.
    CommentCurrent,
    /// Switch between light and dark.
    ToggleTheme,
    /// Put the cursor in the function filter.
    FocusFunctionFilter,
    /// Show the history tab.
    ShowHistory,
    /// Show the proposals tab.
    ShowProposals,
    /// Open an existing project.
    OpenProject,
    /// Start a project from a binary.
    NewProject,
    /// Open the built-in demo project.
    OpenDemo,
    /// Open the settings window.
    OpenSettings,
}

impl AppAction {
    /// Every action, in palette order.
    pub const ALL: [AppAction; 16] = [
        AppAction::RenameCurrent,
        AppAction::CommentCurrent,
        AppAction::Back,
        AppAction::Forward,
        AppAction::FocusFunctionFilter,
        AppAction::Analyze,
        AppAction::CancelAnalysis,
        AppAction::UndoLast,
        AppAction::RefreshAll,
        AppAction::ShowHistory,
        AppAction::ShowProposals,
        AppAction::ToggleTheme,
        AppAction::OpenProject,
        AppAction::NewProject,
        AppAction::OpenDemo,
        AppAction::OpenSettings,
    ];

    /// Palette title.
    pub fn label(self) -> &'static str {
        match self {
            AppAction::Analyze => "Analyze program",
            AppAction::CancelAnalysis => "Cancel analysis",
            AppAction::UndoLast => "Undo my last change",
            AppAction::RefreshAll => "Refresh everything",
            AppAction::Back => "Go back",
            AppAction::Forward => "Go forward",
            AppAction::RenameCurrent => "Rename this function",
            AppAction::CommentCurrent => "Add a comment to this function",
            AppAction::ToggleTheme => "Switch light / dark theme",
            AppAction::FocusFunctionFilter => "Search functions",
            AppAction::ShowHistory => "Show history",
            AppAction::ShowProposals => "Show proposals",
            AppAction::OpenProject => "Open project...",
            AppAction::NewProject => "New project from a binary...",
            AppAction::OpenDemo => "Open demo project",
            AppAction::OpenSettings => "Settings...",
        }
    }

    /// One plain sentence for the palette's second line.
    pub fn hint(self) -> &'static str {
        match self {
            AppAction::Analyze => "Let the engine find and name functions",
            AppAction::CancelAnalysis => "Stop the analysis that is running",
            AppAction::UndoLast => "Reverse the most recent edit you made",
            AppAction::RefreshAll => "Reload functions, history and proposals",
            AppAction::Back => "Return to the previous function",
            AppAction::Forward => "Return to the next function",
            AppAction::RenameCurrent => "Give the function you are reading a better name",
            AppAction::CommentCurrent => "Leave a note for yourself or your team",
            AppAction::ToggleTheme => "Change between the dark and light look",
            AppAction::FocusFunctionFilter => "Jump to the function filter box",
            AppAction::ShowHistory => "See every change made to this project",
            AppAction::ShowProposals => "Review changes suggested by agents",
            AppAction::OpenProject => "Open a KRAKEN project folder",
            AppAction::NewProject => "Start analysing an executable",
            AppAction::OpenDemo => "Try KRAKEN on a small built-in program",
            AppAction::OpenSettings => "Engine paths, theme, daemon status and setup",
        }
    }

    /// Keyboard shortcut text, if the action has one.
    pub fn shortcut(self) -> Option<&'static str> {
        match self {
            AppAction::Back => Some("Alt+Left"),
            AppAction::Forward => Some("Alt+Right"),
            AppAction::RenameCurrent => Some("N"),
            AppAction::FocusFunctionFilter => Some("Ctrl+L"),
            AppAction::OpenSettings => Some("Ctrl+,"),
            _ => None,
        }
    }

    /// The action behind a backend command, when the GUI has a ready-made flow for it.
    pub fn for_command(name: &str) -> Option<AppAction> {
        Some(match name {
            "analyze" => AppAction::Analyze,
            "job_cancel" => AppAction::CancelAnalysis,
            "undo" => AppAction::UndoLast,
            "project_info" => AppAction::RefreshAll,
            "history" => AppAction::ShowHistory,
            "proposals_list" => AppAction::ShowProposals,
            _ => return None,
        })
    }
}

/// Something only the window can do; the view-model hands these back to the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiRequest {
    /// Flip the theme.
    ToggleTheme,
    /// Focus the function filter text box.
    FocusFunctionFilter,
    /// Bring the history tab forward.
    ShowHistory,
    /// Bring the proposals tab forward.
    ShowProposals,
    /// Show the open-project chooser.
    OpenProject,
    /// Show the new-project chooser.
    NewProject,
    /// Open the demo project.
    OpenDemo,
    /// Show the settings window.
    OpenSettings,
}

/// What a palette row does when chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaletteTarget {
    /// A GUI action.
    Action(AppAction),
    /// A backend command with no ready-made GUI flow.
    Command(String),
}

/// One palette row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteItem {
    /// First line.
    pub title: String,
    /// Second line.
    pub subtitle: String,
    /// Shortcut text shown at the right.
    pub shortcut: Option<&'static str>,
    /// What choosing it does.
    pub target: PaletteTarget,
    /// True for commands that change the project.
    pub mutating: bool,
}

/// Palette state. Rows are rebuilt every time the palette opens.
#[derive(Debug, Clone, Default)]
pub struct PaletteState {
    /// Whether the palette is showing.
    pub open: bool,
    /// What the person typed.
    pub query: String,
    /// Index into [`PaletteState::visible`] of the highlighted row.
    pub selected: usize,
    items: Vec<PaletteItem>,
}

/// `rewrite_plan` as `Rewrite plan`: registry command names are developer-facing, so rows made
/// from commands read like the curated actions beside them. The raw name still matches queries.
pub fn humanize_command(name: &str) -> String {
    let spaced = name.replace(['_', '-'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

impl PaletteState {
    /// Builds the rows for `commands` and opens the palette with an empty query.
    pub fn open_with(&mut self, commands: &[CommandInfo]) {
        let mut items: Vec<PaletteItem> = AppAction::ALL
            .iter()
            .map(|&a| PaletteItem {
                title: a.label().to_string(),
                subtitle: a.hint().to_string(),
                shortcut: a.shortcut(),
                target: PaletteTarget::Action(a),
                mutating: false,
            })
            .collect();
        items.extend(
            commands
                .iter()
                .filter(|c| AppAction::for_command(&c.name).is_none())
                .map(|c| PaletteItem {
                    title: humanize_command(&c.name),
                    subtitle: c.summary.clone(),
                    shortcut: None,
                    target: PaletteTarget::Command(c.name.clone()),
                    mutating: c.permission != Permission::Safe,
                }),
        );
        self.items = items;
        self.query.clear();
        self.selected = 0;
        self.open = true;
    }

    /// Closes the palette.
    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.selected = 0;
    }

    /// Replaces the query and highlights the best match.
    pub fn set_query(&mut self, q: impl Into<String>) {
        self.query = q.into();
        self.selected = 0;
    }

    /// Rows matching the query, best first.
    pub fn visible(&self) -> Vec<&PaletteItem> {
        if self.query.trim().is_empty() {
            return self.items.iter().collect();
        }
        let mut scored: Vec<(i32, usize, &PaletteItem)> = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| {
                let raw = match &it.target {
                    PaletteTarget::Command(name) => fuzzy::score(&self.query, name),
                    PaletteTarget::Action(_) => None,
                };
                let t = fuzzy::score(&self.query, &it.title).max(raw);
                let s = fuzzy::score(&self.query, &it.subtitle).map(|s| s / 4 - 20);
                let bonus = i32::from(matches!(it.target, PaletteTarget::Action(_))) * 20;
                t.into_iter().chain(s).max().map(|sc| (sc + bonus, i, it))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, it)| it).collect()
    }

    /// Moves the highlight by `delta` rows, wrapping around.
    pub fn move_selection(&mut self, delta: isize) {
        let n = self.visible().len();
        if n == 0 {
            self.selected = 0;
            return;
        }
        self.selected = (self.selected as isize + delta).rem_euclid(n as isize) as usize;
    }

    /// The highlighted row.
    pub fn selected_item(&self) -> Option<PaletteItem> {
        self.visible().get(self.selected).map(|i| (*i).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CommandKind;

    fn cmd(name: &str, perm: Permission) -> CommandInfo {
        CommandInfo {
            name: name.into(),
            summary: format!("does {name}"),
            kind: CommandKind::Query,
            permission: perm,
        }
    }

    fn open() -> PaletteState {
        let mut p = PaletteState::default();
        p.open_with(&[
            cmd("analyze", Permission::Mutating),
            cmd("rebuild", Permission::Mutating),
            cmd("decompile", Permission::Safe),
        ]);
        p
    }

    #[test]
    fn lists_actions_and_unmapped_commands_without_duplicates() {
        let p = open();
        let all = p.visible();
        assert_eq!(all.len(), AppAction::ALL.len() + 2);
        let analyze = all.iter().filter(|i| i.title == "Analyze").count();
        assert_eq!(analyze, 0, "analyze is covered by the Analyze action");
        assert!(all.iter().any(|i| i.title == "Rebuild" && i.mutating));
        assert!(all.iter().any(|i| i.title == "Decompile" && !i.mutating));
    }

    #[test]
    fn command_rows_read_like_words_and_still_match_the_raw_name() {
        assert_eq!(humanize_command("rewrite_plan"), "Rewrite plan");
        assert_eq!(humanize_command("x"), "X");
        assert_eq!(humanize_command(""), "");
        let mut p = PaletteState::default();
        p.open_with(&[cmd("rewrite_plan", Permission::Safe)]);
        p.set_query("rewrite_plan");
        let v = p.visible();
        assert_eq!(v[0].title, "Rewrite plan");
    }

    #[test]
    fn fuzzy_filter_ranks_best_first() {
        let mut p = open();
        p.set_query("rnm");
        let v = p.visible();
        assert_eq!(v[0].target, PaletteTarget::Action(AppAction::RenameCurrent));
        p.set_query("decomp");
        assert_eq!(
            p.visible()[0].target,
            PaletteTarget::Command("decompile".into())
        );
        p.set_query("zzzzqq");
        assert!(p.visible().is_empty());
        assert!(p.selected_item().is_none());
    }

    #[test]
    fn selection_wraps() {
        let mut p = open();
        let n = p.visible().len() as isize;
        p.move_selection(-1);
        assert_eq!(p.selected as isize, n - 1);
        p.move_selection(1);
        assert_eq!(p.selected, 0);
        p.set_query("theme");
        p.move_selection(5);
        assert!(p.selected < p.visible().len());
    }

    #[test]
    fn close_resets() {
        let mut p = open();
        p.set_query("x");
        p.close();
        assert!(!p.open && p.query.is_empty());
    }
}
