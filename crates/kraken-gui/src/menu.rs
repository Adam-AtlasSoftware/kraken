//! The menu bar. Every item is an [`AppAction`] run through the same path as the command
//! palette, shows its shortcut and says what it does; a disabled item says why.

use egui::{Button, Ui};
use kraken_viewmodel::AppAction;

use crate::recent::RecentProject;
use crate::workspace::Tab;

/// What a menu click asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuCmd {
    /// Run an action.
    Action(AppAction),
    /// Show a dock tab and bring it to the front.
    ShowTab(Tab),
    /// Open a recent project.
    OpenRecent(String),
}

/// What the menus need to know to enable their items.
pub struct MenuEnv<'a> {
    /// A project is open (not the welcome screen).
    pub project: bool,
    /// Analysis is running.
    pub analyzing: bool,
    /// Back and forward history.
    pub can_back: bool,
    pub can_forward: bool,
    /// A function is being viewed.
    pub has_function: bool,
    /// Learn mode is on.
    pub learn_mode: bool,
    /// The dark theme is in use.
    pub dark: bool,
    pub recents: &'a [RecentProject],
    /// Keep the File menu open (the menu screenshot).
    pub open_file: bool,
}

/// The tabs the View menu lists, in menu order.
pub const VIEW_TABS: [Tab; 20] = [
    Tab::Functions,
    Tab::Decompiler,
    Tab::Listing,
    Tab::Graph,
    Tab::Hex,
    Tab::Xrefs,
    Tab::Strings,
    Tab::Symbols,
    Tab::Search,
    Tab::Bookmarks,
    Tab::Types,
    Tab::Patches,
    Tab::Edit,
    Tab::Emulation,
    Tab::Debug,
    Tab::History,
    Tab::Proposals,
    Tab::Assistant,
    Tab::Rewrite,
    Tab::AiActivity,
];

const NEED_PROJECT: &str = "Open a project first.";

/// Why `a` cannot run now, or `None` when it can.
pub fn disabled_reason(a: AppAction, env: &MenuEnv<'_>) -> Option<&'static str> {
    let needs_project = matches!(
        a,
        AppAction::Analyze
            | AppAction::CancelAnalysis
            | AppAction::UndoLast
            | AppAction::RefreshAll
            | AppAction::Back
            | AppAction::Forward
            | AppAction::RenameCurrent
            | AppAction::CommentCurrent
            | AppAction::FocusFunctionFilter
            | AppAction::ShowHistory
            | AppAction::ShowProposals
            | AppAction::CloseProject
            | AppAction::OpenPalette
            | AppAction::GoToMain
            | AppAction::ExplainProgram
            | AppAction::RewriteWizard
            | AppAction::Automate
            | AppAction::GoTo
            | AppAction::Search
            | AppAction::Retype
            | AppAction::EditSignature
            | AppAction::CommentHere
            | AppAction::ShowReferences
            | AppAction::AddBookmark
            | AppAction::ShowBookmarks
            | AppAction::PatchHere
            | AppAction::ShowPatches
            | AppAction::ExportPatched
            | AppAction::ImportPatchFile
            | AppAction::ImportSymbols
            | AppAction::RunInEmulator
            | AppAction::RunProgram
            | AppAction::RunPatched
            | AppAction::ComparePatched
            | AppAction::VerifyPatches
            | AppAction::CheckPatches
            | AppAction::CallFunction
            | AppAction::ShowEmulation
            | AppAction::CreateFunctionHere
            | AppAction::DeleteFunction
            | AppAction::ShowAiActivity
    );
    if needs_project && !env.project {
        return Some(NEED_PROJECT);
    }
    match a {
        AppAction::Analyze if env.analyzing => Some("The analysis is already running."),
        AppAction::CancelAnalysis if !env.analyzing => Some("No analysis is running."),
        AppAction::Back if !env.can_back => Some("There is no earlier function to go back to."),
        AppAction::Forward if !env.can_forward => Some("There is no later function to go to."),
        AppAction::RenameCurrent
        | AppAction::CommentCurrent
        | AppAction::EditSignature
        | AppAction::DeleteFunction
            if !env.has_function =>
        {
            Some("Open a function first: click one in the Functions list.")
        }
        AppAction::ClearRecent if env.recents.is_empty() => Some("The list is already empty."),
        _ => None,
    }
}

/// One menu item for `a`.
fn item(ui: &mut Ui, a: AppAction, env: &MenuEnv<'_>, out: &mut Vec<MenuCmd>) {
    let reason = disabled_reason(a, env);
    let mut button = Button::new(a.label());
    if let Some(sc) = a.shortcut() {
        button = button.shortcut_text(sc);
    }
    let r = ui
        .add_enabled(reason.is_none(), button)
        .on_hover_text(a.hint())
        .on_disabled_hover_text(reason.unwrap_or_default());
    if r.clicked() {
        out.push(MenuCmd::Action(a));
        ui.close();
    }
}

fn toggle(ui: &mut Ui, a: AppAction, on: bool, env: &MenuEnv<'_>, out: &mut Vec<MenuCmd>) {
    let reason = disabled_reason(a, env);
    let label = if on {
        format!("\u{2713} {}", a.label())
    } else {
        format!("    {}", a.label())
    };
    let r = ui
        .add_enabled(reason.is_none(), Button::new(label))
        .on_hover_text(a.hint())
        .on_disabled_hover_text(reason.unwrap_or_default());
    if r.clicked() {
        out.push(MenuCmd::Action(a));
        ui.close();
    }
}

fn tab_item(ui: &mut Ui, tab: Tab, label: &str, env: &MenuEnv<'_>, out: &mut Vec<MenuCmd>) {
    let r = ui
        .add_enabled(env.project, Button::new(label))
        .on_hover_text(format!("Show the {} tab. {}", tab.title(), tab.tooltip()))
        .on_disabled_hover_text(NEED_PROJECT);
    if r.clicked() {
        out.push(MenuCmd::ShowTab(tab));
        ui.close();
    }
}

fn file_menu(ui: &mut Ui, env: &MenuEnv<'_>, out: &mut Vec<MenuCmd>) {
    item(ui, AppAction::NewProject, env, out);
    item(ui, AppAction::ImportProgram, env, out);
    item(ui, AppAction::OpenProject, env, out);
    // The default submenu arrow is not in the bundled fonts.
    egui::containers::menu::SubMenuButton::from_button(
        Button::new("Open recent").right_text("\u{203a}"),
    )
    .ui(ui, |ui| {
        if env.recents.is_empty() {
            ui.add_enabled(false, Button::new("No recent projects"))
                .on_disabled_hover_text("Projects you open are listed here.");
        }
        for r in env.recents.iter().take(12) {
            if ui
                .button(&r.name)
                .on_hover_text(format!("Open {}", r.path))
                .clicked()
            {
                out.push(MenuCmd::OpenRecent(r.path.clone()));
                ui.close();
            }
        }
        ui.separator();
        item(ui, AppAction::ClearRecent, env, out);
    })
    .0
    .on_hover_text("Projects you opened before");
    item(ui, AppAction::OpenDemo, env, out);
    ui.separator();
    item(ui, AppAction::ImportSymbols, env, out);
    ui.separator();
    item(ui, AppAction::CloseProject, env, out);
    ui.separator();
    item(ui, AppAction::OpenSettings, env, out);
    ui.separator();
    item(ui, AppAction::Quit, env, out);
}

fn help_menu(ui: &mut Ui, env: &MenuEnv<'_>, out: &mut Vec<MenuCmd>) {
    item(ui, AppAction::ShowHelp, env, out);
    item(ui, AppAction::TakeTour, env, out);
    item(ui, AppAction::AskAboutKraken, env, out);
    item(ui, AppAction::OpenPalette, env, out);
    toggle(ui, AppAction::ToggleLearnMode, env.learn_mode, env, out);
    item(ui, AppAction::ShowShortcuts, env, out);
    item(ui, AppAction::ShowSetupStatus, env, out);
    ui.separator();
    item(ui, AppAction::OpenDocs, env, out);
}

/// Draws the menu bar. On the welcome screen only File and Help are shown.
pub fn bar(ui: &mut Ui, env: &MenuEnv<'_>) -> Vec<MenuCmd> {
    bar_measured(ui, env).0
}

/// The same, with the x position where the last menu ends (the title bar puts the model chips
/// after it).
pub fn bar_measured(ui: &mut Ui, env: &MenuEnv<'_>) -> (Vec<MenuCmd>, f32) {
    let mut out = Vec::new();
    let mut end = 0.0;
    egui::MenuBar::new().ui(ui, |ui| {
        let file = ui
            .menu_button("File", |ui| file_menu(ui, env, &mut out))
            .response
            .on_hover_text("Open and import programs, projects and settings");
        if env.open_file {
            let id = egui::Popup::default_response_id(&file);
            if !egui::Popup::is_id_open(ui.ctx(), id) {
                egui::Popup::open_id(ui.ctx(), id);
            }
        }
        if env.project {
            ui.menu_button("Edit", |ui| {
                item(ui, AppAction::UndoLast, env, &mut out);
                ui.separator();
                item(ui, AppAction::RenameCurrent, env, &mut out);
                item(ui, AppAction::Retype, env, &mut out);
                item(ui, AppAction::EditSignature, env, &mut out);
                item(ui, AppAction::CommentCurrent, env, &mut out);
                item(ui, AppAction::CommentHere, env, &mut out);
                ui.separator();
                item(ui, AppAction::OpenPalette, env, &mut out);
            })
            .response
            .on_hover_text("Undo, rename, retype and comment");
            ui.menu_button("View", |ui| {
                for tab in VIEW_TABS {
                    tab_item(ui, tab, tab.title(), env, &mut out);
                }
                ui.separator();
                let theme = if env.dark {
                    "Switch to the light theme"
                } else {
                    "Switch to the dark theme"
                };
                let r = ui
                    .button(theme)
                    .on_hover_text(AppAction::ToggleTheme.hint());
                if r.clicked() {
                    out.push(MenuCmd::Action(AppAction::ToggleTheme));
                    ui.close();
                }
                toggle(
                    ui,
                    AppAction::ToggleLearnMode,
                    env.learn_mode,
                    env,
                    &mut out,
                );
                item(ui, AppAction::RefreshAll, env, &mut out);
            })
            .response
            .on_hover_text("Show panels and change the look");
            ui.menu_button("Navigate", |ui| {
                item(ui, AppAction::Back, env, &mut out);
                item(ui, AppAction::Forward, env, &mut out);
                ui.separator();
                item(ui, AppAction::GoTo, env, &mut out);
                item(ui, AppAction::GoToMain, env, &mut out);
                item(ui, AppAction::FocusFunctionFilter, env, &mut out);
                item(ui, AppAction::Search, env, &mut out);
                ui.separator();
                item(ui, AppAction::ShowReferences, env, &mut out);
                item(ui, AppAction::AddBookmark, env, &mut out);
                item(ui, AppAction::ShowBookmarks, env, &mut out);
            })
            .response
            .on_hover_text("Move around the program, search it and keep bookmarks");
            ui.menu_button("Analysis", |ui| {
                item(ui, AppAction::Analyze, env, &mut out);
                item(ui, AppAction::CancelAnalysis, env, &mut out);
                ui.separator();
                item(ui, AppAction::CreateFunctionHere, env, &mut out);
                item(ui, AppAction::DeleteFunction, env, &mut out);
                ui.separator();
                item(ui, AppAction::ShowHistory, env, &mut out);
                item(ui, AppAction::ShowProposals, env, &mut out);
            })
            .response
            .on_hover_text("Find functions and review changes");
            ui.menu_button("Rewrite", |ui| {
                item(ui, AppAction::RewriteWizard, env, &mut out);
                tab_item(ui, Tab::Rewrite, "Show the Rewrite tab", env, &mut out);
            })
            .response
            .on_hover_text("Turn the program into Rust");
            ui.menu_button("Patch", |ui| {
                item(ui, AppAction::PatchHere, env, &mut out);
                item(ui, AppAction::ShowPatches, env, &mut out);
                ui.separator();
                item(ui, AppAction::ExportPatched, env, &mut out);
                item(ui, AppAction::ImportPatchFile, env, &mut out);
                ui.separator();
                item(ui, AppAction::RunInEmulator, env, &mut out);
            })
            .response
            .on_hover_text("Change the program's bytes and write a patched copy");
            ui.menu_button("Emulate", |ui| {
                item(ui, AppAction::RunProgram, env, &mut out);
                item(ui, AppAction::RunPatched, env, &mut out);
                item(ui, AppAction::ComparePatched, env, &mut out);
                item(ui, AppAction::VerifyPatches, env, &mut out);
                item(ui, AppAction::CheckPatches, env, &mut out);
                item(ui, AppAction::CallFunction, env, &mut out);
                ui.separator();
                item(ui, AppAction::ShowEmulation, env, &mut out);
                item(ui, AppAction::EmulationHelp, env, &mut out);
            })
            .response
            .on_hover_text(
                "Run the program safely in the emulator and compare patched against original",
            );
            ui.menu_button("Debug", |ui| {
                tab_item(ui, Tab::Debug, "Show the Debug tab", env, &mut out);
            })
            .response
            .on_hover_text("Run the program in the emulator and step through it");
            ui.menu_button("AI", |ui| {
                item(ui, AppAction::ExplainProgram, env, &mut out);
                item(ui, AppAction::Automate, env, &mut out);
                item(ui, AppAction::SetUpLocalModel, env, &mut out);
                tab_item(ui, Tab::Assistant, "Show the Assistant tab", env, &mut out);
                ui.separator();
                item(ui, AppAction::ShowAiActivity, env, &mut out);
                toggle(
                    ui,
                    AppAction::ToggleLearnMode,
                    env.learn_mode,
                    env,
                    &mut out,
                );
            })
            .response
            .on_hover_text("Ask the assistant about the program, or let it do the work");
        }
        ui.menu_button("Tools", |ui| {
            item(ui, AppAction::ShowIntegrations, env, &mut out);
        })
        .response
        .on_hover_text("Install or find the emulators and tools KRAKEN can use");
        ui.menu_button("Help", |ui| help_menu(ui, env, &mut out))
            .response
            .on_hover_text("Help pages, the tour, shortcuts, learn mode and the user guide");
        end = ui.cursor().left();
    });
    (out, end)
}

/// The cheat sheet window, built from [`kraken_viewmodel::SHORTCUTS`].
pub fn shortcuts_window(ctx: &egui::Context, open: &mut bool) {
    if !*open {
        return;
    }
    if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
        *open = false;
        return;
    }
    egui::Window::new("Keyboard shortcuts")
        .open(open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            egui::Grid::new("kraken_shortcuts")
                .num_columns(3)
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Keys");
                    ui.strong("What it does");
                    ui.strong("Where");
                    ui.end_row();
                    for s in kraken_viewmodel::SHORTCUTS {
                        ui.monospace(s.keys);
                        ui.label(s.what);
                        ui.weak(s.place);
                        ui.end_row();
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(project: bool) -> MenuEnv<'static> {
        MenuEnv {
            project,
            analyzing: false,
            can_back: false,
            can_forward: false,
            has_function: false,
            learn_mode: false,
            dark: true,
            recents: &[],
            open_file: false,
        }
    }

    #[test]
    fn disabled_items_say_why() {
        let welcome = env(false);
        assert_eq!(
            disabled_reason(AppAction::CloseProject, &welcome),
            Some(NEED_PROJECT)
        );
        assert_eq!(disabled_reason(AppAction::NewProject, &welcome), None);
        assert_eq!(disabled_reason(AppAction::ShowShortcuts, &welcome), None);
        assert!(disabled_reason(AppAction::ClearRecent, &welcome).is_some());
        let open = env(true);
        assert!(
            disabled_reason(AppAction::CancelAnalysis, &open)
                .unwrap()
                .contains("No analysis")
        );
        assert!(
            disabled_reason(AppAction::RenameCurrent, &open)
                .unwrap()
                .contains("Functions list")
        );
        assert_eq!(disabled_reason(AppAction::Analyze, &open), None);
    }

    #[test]
    fn every_action_is_reachable_from_a_menu() {
        let source = include_str!("menu.rs");
        let start = source.find("fn file_menu").unwrap();
        let end = source.find("pub fn shortcuts_window").unwrap();
        let menus = &source[start..end];
        for a in AppAction::ALL {
            let name = format!("AppAction::{a:?}");
            assert!(menus.contains(&name), "{name} is not in a menu");
        }
    }
}
