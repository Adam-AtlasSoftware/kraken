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
    /// Close the open project and go back to the welcome screen.
    CloseProject,
    /// Forget the recent projects list.
    ClearRecent,
    /// Close the window.
    Quit,
    /// Open the command palette.
    OpenPalette,
    /// Turn learn mode (a short explanation on every panel) on or off.
    ToggleLearnMode,
    /// Show the keyboard shortcut cheat sheet.
    ShowShortcuts,
    /// Open the user guide.
    OpenDocs,
    /// Open the help window (F1 opens the topic of the panel you are in).
    ShowHelp,
    /// Start the short guided tour again.
    TakeTour,
    /// Open `main`, or the entry point when there is no `main`.
    GoToMain,
    /// Ask the assistant for an overview of the program.
    ExplainProgram,
    /// Open the step-by-step rewrite window.
    RewriteWizard,
    /// Let the assistant work through the whole flow (the Automate dialog).
    Automate,
    /// Jump to an address, a function or a symbol by name.
    GoTo,
    /// Open the Search tab.
    Search,
    /// Change the type of the item at the cursor.
    Retype,
    /// Edit the C prototype of the function being viewed.
    EditSignature,
    /// Comment on the address at the cursor.
    CommentHere,
    /// List what refers to the address at the cursor.
    ShowReferences,
    /// Bookmark the address at the cursor.
    AddBookmark,
    /// Show the Bookmarks tab.
    ShowBookmarks,
    /// Mark the code at the cursor as a function.
    CreateFunctionHere,
    /// Remove the function being viewed.
    DeleteFunction,
    /// Show the AI Activity tab: running and recent AI work, its cost, and Stop.
    ShowAiActivity,
    /// Open the assistant with a question about KRAKEN itself.
    AskAboutKraken,
}

impl AppAction {
    /// Every action, in palette order.
    pub const ALL: [AppAction; 41] = [
        AppAction::GoTo,
        AppAction::Search,
        AppAction::RenameCurrent,
        AppAction::Retype,
        AppAction::EditSignature,
        AppAction::CommentCurrent,
        AppAction::CommentHere,
        AppAction::ShowReferences,
        AppAction::AddBookmark,
        AppAction::ShowBookmarks,
        AppAction::CreateFunctionHere,
        AppAction::DeleteFunction,
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
        AppAction::CloseProject,
        AppAction::ClearRecent,
        AppAction::Quit,
        AppAction::OpenPalette,
        AppAction::ToggleLearnMode,
        AppAction::ShowShortcuts,
        AppAction::OpenDocs,
        AppAction::ShowHelp,
        AppAction::TakeTour,
        AppAction::GoToMain,
        AppAction::ExplainProgram,
        AppAction::RewriteWizard,
        AppAction::Automate,
        AppAction::ShowAiActivity,
        AppAction::AskAboutKraken,
    ];

    /// The snake_case id agents use with `ui_action` (`ShowHistory` is `show_history`).
    pub fn id(self) -> String {
        let name = format!("{self:?}");
        let mut out = String::new();
        for (i, c) in name.chars().enumerate() {
            if c.is_ascii_uppercase() {
                if i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The action with this id.
    pub fn from_id(id: &str) -> Option<AppAction> {
        AppAction::ALL.into_iter().find(|a| a.id() == id)
    }

    /// True when an agent may trigger it through `ui_action`.
    pub fn agent_allowed(self) -> bool {
        !kraken_registry::commands::DENIED_UI_ACTIONS.contains(&self.id().as_str())
    }

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
            AppAction::NewProject => "Open program...",
            AppAction::OpenDemo => "Open demo project",
            AppAction::OpenSettings => "Settings...",
            AppAction::CloseProject => "Close project",
            AppAction::ClearRecent => "Clear recent projects",
            AppAction::Quit => "Quit",
            AppAction::OpenPalette => "Search commands...",
            AppAction::ToggleLearnMode => "Toggle learn mode",
            AppAction::ShowShortcuts => "Keyboard shortcuts",
            AppAction::OpenDocs => "User guide",
            AppAction::ShowHelp => "Help",
            AppAction::TakeTour => "Take the tour",
            AppAction::GoToMain => "Go to main",
            AppAction::ExplainProgram => "Explain this program",
            AppAction::RewriteWizard => "Rewrite in Rust...",
            AppAction::Automate => "Automate with the assistant...",
            AppAction::GoTo => "Go to...",
            AppAction::Search => "Search...",
            AppAction::Retype => "Change type...",
            AppAction::EditSignature => "Edit function signature...",
            AppAction::CommentHere => "Comment at this address...",
            AppAction::ShowReferences => "Show references",
            AppAction::AddBookmark => "Bookmark this address",
            AppAction::ShowBookmarks => "Show bookmarks",
            AppAction::CreateFunctionHere => "Create function here",
            AppAction::DeleteFunction => "Delete this function...",
            AppAction::ShowAiActivity => "Show AI activity",
            AppAction::AskAboutKraken => "Ask the assistant about KRAKEN",
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
            AppAction::NewProject => "Import an executable or library into a new project",
            AppAction::OpenDemo => "Try KRAKEN on a small built-in program",
            AppAction::OpenSettings => "Engine paths, theme, daemon status and setup",
            AppAction::CloseProject => "Stop working on this project and go back to the start",
            AppAction::ClearRecent => "Empty the list of recently opened projects",
            AppAction::Quit => "Close KRAKEN. Your work is already saved",
            AppAction::OpenPalette => "Find any action or command by typing part of its name",
            AppAction::ToggleLearnMode => "Show a short explanation on every panel",
            AppAction::ShowShortcuts => "List every keyboard shortcut",
            AppAction::OpenDocs => "Open the KRAKEN documentation in your browser",
            AppAction::ShowHelp => {
                "Read how KRAKEN works: the first steps, every panel, shortcuts and the glossary"
            }
            AppAction::TakeTour => "Walk through the main areas of the window, one step at a time",
            AppAction::GoToMain => "Open the program's main function, or where it starts",
            AppAction::ExplainProgram => "Ask the assistant what this program does",
            AppAction::RewriteWizard => {
                "Turn the program into Rust step by step, checked against the original"
            }
            AppAction::Automate => {
                "Let the assistant understand, name and rewrite the program step by step"
            }
            AppAction::GoTo => "Jump to an address, a function or a symbol by name",
            AppAction::Search => "Find names, strings, bytes or instructions anywhere",
            AppAction::Retype => "Set the type of the data or function at the cursor",
            AppAction::EditSignature => "Fix the return type and parameters of this function",
            AppAction::CommentHere => "Leave a note on the line at the cursor",
            AppAction::ShowReferences => "List everything that uses the address at the cursor",
            AppAction::AddBookmark => "Mark the address at the cursor to come back to",
            AppAction::ShowBookmarks => "See every address you or an agent bookmarked",
            AppAction::CreateFunctionHere => "Tell KRAKEN the code at the cursor is a function",
            AppAction::DeleteFunction => "Remove a function the analysis got wrong",
            AppAction::AskAboutKraken => {
                "Ask how a KRAKEN feature works; the assistant reads KRAKEN's own documentation"
            }
            AppAction::ShowAiActivity => {
                "See which AI work runs, on which model, what it has cost so far, and stop it"
            }
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
            AppAction::NewProject => Some("Ctrl+O"),
            AppAction::OpenProject => Some("Ctrl+Shift+O"),
            AppAction::CloseProject => Some("Ctrl+W"),
            AppAction::Quit => Some("Ctrl+Q"),
            AppAction::OpenPalette => Some("Ctrl+K"),
            AppAction::ShowShortcuts => Some("Ctrl+/"),
            AppAction::ShowHelp => Some("F1"),
            AppAction::UndoLast => Some("Ctrl+Z"),
            AppAction::GoTo => Some("G"),
            AppAction::Search => Some("Ctrl+Shift+F"),
            AppAction::Retype => Some("Y"),
            AppAction::CommentHere => Some(";"),
            AppAction::ShowReferences => Some("X"),
            AppAction::AddBookmark => Some("Ctrl+D"),
            AppAction::CreateFunctionHere => Some("P"),
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
            "search" => AppAction::Search,
            "bookmark_list" => AppAction::ShowBookmarks,
            "bookmark_add" => AppAction::AddBookmark,
            "create_function" => AppAction::CreateFunctionHere,
            "delete_function" => AppAction::DeleteFunction,
            _ => return None,
        })
    }
}

/// One row of the keyboard cheat sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortcut {
    /// The keys, such as `Ctrl+Shift+F`.
    pub keys: &'static str,
    /// What they do, in one plain sentence.
    pub what: &'static str,
    /// Where they work.
    pub place: &'static str,
}

const fn sc(keys: &'static str, what: &'static str, place: &'static str) -> Shortcut {
    Shortcut { keys, what, place }
}

/// Every keyboard shortcut, for the cheat sheet. Single-letter keys do nothing while a text
/// field has the focus.
pub const SHORTCUTS: &[Shortcut] = &[
    sc(
        "Ctrl+O",
        "Open a program (import it into a new project)",
        "Anywhere",
    ),
    sc("Ctrl+Shift+O", "Open a KRAKEN project folder", "Anywhere"),
    sc("Ctrl+W", "Close the project", "Project"),
    sc("Ctrl+Q", "Quit KRAKEN", "Anywhere"),
    sc("Ctrl+,", "Settings", "Anywhere"),
    sc(
        "Ctrl+K or Ctrl+Shift+P",
        "Search every action and command",
        "Project",
    ),
    sc("Ctrl+/", "This list of shortcuts", "Anywhere"),
    sc(
        "F1",
        "Open help (the topic of the panel you are in)",
        "Anywhere",
    ),
    sc("G", "Go to an address, a function or a symbol", "Project"),
    sc(
        "Ctrl+Shift+F",
        "Search names, strings, bytes or instructions",
        "Project",
    ),
    sc("Ctrl+L", "Search functions", "Project"),
    sc("Alt+Left", "Go back", "Project"),
    sc("Alt+Right", "Go forward again", "Project"),
    sc(
        "N",
        "Rename the name under the pointer, or this function",
        "Code views",
    ),
    sc("Y", "Change the type at the cursor", "Code views"),
    sc(";", "Comment at the cursor", "Code views"),
    sc(
        "X",
        "Show what refers to the address under the pointer",
        "Code views",
    ),
    sc("Ctrl+D", "Bookmark the address at the cursor", "Code views"),
    sc("P", "Create a function at the cursor", "Code views"),
    sc("Ctrl+Z", "Undo your last change", "Project"),
    sc(
        "Space",
        "Swap between the listing and the graph",
        "Code views",
    ),
    sc("F", "Fit the graph to the panel", "Graph"),
    sc(
        "Ctrl+Tab / Ctrl+Shift+Tab",
        "Next or previous tab in the focused pane",
        "Project",
    ),
    sc(
        "Ctrl+1 ... Ctrl+9",
        "Jump to a tab of the focused pane",
        "Project",
    ),
    sc(
        "Up / Down, Enter",
        "Move through a list and open the row",
        "Lists and palette",
    ),
    sc("Escape", "Close a dialog, menu or the palette", "Dialogs"),
];

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
    /// Close the project (asks first when a job runs).
    CloseProject,
    /// Empty the recent projects list.
    ClearRecent,
    /// Close the window.
    Quit,
    /// Show the shortcut cheat sheet.
    ShowShortcuts,
    /// Open the documentation.
    OpenDocs,
    /// Show the help window.
    ShowHelp,
    /// Start the guided tour.
    TakeTour,
    /// Show the Automate dialog.
    OpenAutomate,
    /// Bring the AI Activity tab forward.
    ShowAiActivity,
    /// Open the assistant with the cursor in a question about KRAKEN.
    AskAboutKraken,
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
    #[test]
    fn action_ids_round_trip_and_dangerous_ones_are_refused_to_agents() {
        for a in super::AppAction::ALL {
            assert_eq!(super::AppAction::from_id(&a.id()), Some(a), "{a:?}");
        }
        assert_eq!(super::AppAction::ShowHistory.id(), "show_history");
        assert!(super::AppAction::ShowHistory.agent_allowed());
        for a in [
            super::AppAction::Quit,
            super::AppAction::CloseProject,
            super::AppAction::DeleteFunction,
            super::AppAction::ClearRecent,
        ] {
            assert!(!a.agent_allowed(), "{a:?}");
        }
    }

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
    fn the_cheat_sheet_lists_every_action_shortcut() {
        for a in AppAction::ALL {
            if let Some(keys) = a.shortcut() {
                assert!(
                    SHORTCUTS.iter().any(|s| s.keys.contains(keys)),
                    "{keys} ({}) is missing from SHORTCUTS",
                    a.label()
                );
            }
            assert!(!a.hint().is_empty());
        }
        let mut seen = std::collections::HashSet::new();
        for s in SHORTCUTS {
            assert!(!s.what.is_empty());
            assert!(seen.insert(s.keys), "{} is listed twice", s.keys);
        }
    }

    #[test]
    fn close_resets() {
        let mut p = open();
        p.set_query("x");
        p.close();
        assert!(!p.open && p.query.is_empty());
    }
}
