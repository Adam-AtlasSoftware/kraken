//! `cargo xtask docs` also renders `docs/gui.md`: every menu, panel and shortcut of the GUI.
//!
//! The actions (name, hint, shortcut) and the panel help come from `kraken-viewmodel`, the same
//! data the app shows. Which menu holds which action is read from `menu.rs`, so a new menu item
//! shows up here without anyone remembering to document it.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use kraken_viewmodel::assist::PANEL_HELP;
use kraken_viewmodel::{AppAction, SHORTCUTS};

use crate::{Result, workspace_root};

/// Path of the committed page.
pub fn page_path() -> PathBuf {
    workspace_root().join("docs/gui.md")
}

const MENU_ORDER: &[&str] = &[
    "File", "Edit", "View", "Navigate", "Analysis", "Rewrite", "AI", "Help",
];

const MENU_ABOUT: &[(&str, &str)] = &[
    (
        "File",
        "Open and import programs and projects, and settings.",
    ),
    ("Edit", "Undo, rename, retype and comment."),
    ("View", "Show panels and change the look."),
    (
        "Navigate",
        "Move around the program, search it and keep bookmarks.",
    ),
    ("Analysis", "Find functions and review changes."),
    ("Rewrite", "Turn the program into Rust."),
    (
        "AI",
        "Ask the assistant about the program, or let it do the work.",
    ),
    (
        "Help",
        "Help pages, the tour, shortcuts, learn mode and the user guide.",
    ),
];

/// One menu entry.
struct Item {
    label: String,
    hint: String,
    shortcut: Option<&'static str>,
}

fn action_named(name: &str) -> Option<AppAction> {
    AppAction::ALL
        .into_iter()
        .find(|a| format!("{a:?}") == name)
}

fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.find(marker).map(|i| &line[i + marker.len()..])
}

fn ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// The menus of `menu.rs` with their items, in source order of items.
fn menus(source: &str) -> Result<Vec<(String, Vec<Item>)>> {
    let start = source
        .find("fn file_menu")
        .ok_or("menu.rs has no file_menu")?;
    let end = source
        .find("pub fn shortcuts_window")
        .ok_or("menu.rs has no shortcuts_window")?;
    let mut out: Vec<(String, Vec<Item>)> = Vec::new();
    let mut current: Option<usize> = None;
    let open = |out: &mut Vec<(String, Vec<Item>)>, name: &str| {
        if let Some(i) = out.iter().position(|(n, _)| n == name) {
            i
        } else {
            out.push((name.to_string(), Vec::new()));
            out.len() - 1
        }
    };
    for line in source[start..end].lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("fn file_menu") {
            current = Some(open(&mut out, "File"));
        } else if t.starts_with("fn help_menu") {
            current = Some(open(&mut out, "Help"));
        } else if let Some(rest) = after(t, "menu_button(\"") {
            current = Some(open(&mut out, &ident_until_quote(rest)));
        }
        let Some(cur) = current else {
            continue;
        };
        let items = &mut out[cur].1;
        if let Some(rest) = after(t, "AppAction::") {
            let name = ident(rest);
            if let Some(a) = action_named(&name)
                && !items.iter().any(|i| i.label == a.label())
            {
                items.push(Item {
                    label: a.label().to_string(),
                    hint: a.hint().to_string(),
                    shortcut: a.shortcut(),
                });
            }
        } else if let Some(rest) = after(t, "tab_item(ui, Tab::")
            && let Some(label) = after(rest, ", \"").map(ident_until_quote)
        {
            if !items.iter().any(|i| i.label == label) {
                items.push(Item {
                    hint: format!(
                        "Show the {} and bring it to the front.",
                        label.trim_start_matches("Show the ")
                    ),
                    label,
                    shortcut: None,
                });
            }
        } else if t.contains("tab_item(ui, tab, tab.title()") {
            let panels: Vec<&str> = PANEL_HELP.iter().map(|h| h.panel).collect();
            items.push(Item {
                label: "One item per panel".into(),
                hint: format!(
                    "Show a panel and bring it to the front: {}.",
                    panels.join(", ")
                ),
                shortcut: None,
            });
        } else if t.contains("Button::new(\"Open recent\")") {
            items.push(Item {
                label: "Open recent".into(),
                hint: "Projects you opened before.".into(),
                shortcut: None,
            });
        }
    }
    if out.is_empty() {
        return Err("found no menus in menu.rs".into());
    }
    Ok(out)
}

fn ident_until_quote(s: &str) -> String {
    s.chars().take_while(|c| *c != '"').collect()
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// Renders the whole page.
pub fn render() -> Result<String> {
    let menu_path = workspace_root().join("crates/kraken-gui/src/menu.rs");
    let source = fs::read_to_string(&menu_path)
        .map_err(|e| format!("cannot read {}: {e}", menu_path.display()))?;
    let mut menus = menus(&source)?;
    menus.sort_by_key(|(n, _)| MENU_ORDER.iter().position(|m| m == n).unwrap_or(usize::MAX));

    let mut out = String::new();
    out.push_str(
        "# The GUI, menu by menu

<!-- Generated by `cargo xtask docs` from the menus, the actions, the panel help and the shortcut list of the GUI. Do not edit by hand. -->

This page lists everything in the KRAKEN window: the menus, the panels and the keyboard shortcuts. For a walk through the flow, see the [tutorial](tutorial.md). Inside the app, press **F1** for the same help, and **Help > Take the tour** for a short guided tour.

Every menu item and every button says what it does when you hover it. An item that is switched off says why. Every menu item is also in the command palette (**Ctrl+K**), and single-letter shortcuts do nothing while a text box has the focus.

## Menus

On the welcome screen only **File** and **Help** are shown. The other menus appear when a project is open.
",
    );
    for (name, items) in &menus {
        let _ = writeln!(out, "\n### {name}\n");
        if let Some((_, about)) = MENU_ABOUT.iter().find(|(n, _)| n == name) {
            let _ = writeln!(out, "{about}\n");
        }
        out.push_str("| Item | What it does | Shortcut |\n|---|---|---|\n");
        for i in items {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                cell(&i.label),
                cell(&i.hint),
                i.shortcut.map_or(String::new(), |s| format!("`{s}`"))
            );
        }
    }

    out.push_str("\n## Panels\n\nPanels live in tabs. Drag a tab to move it, and show any panel from the **View** menu. Right-click a tab and choose **Help for this panel** (or press **F1** in the panel) for the help page.\n");
    for h in PANEL_HELP {
        let _ = write!(out, "\n### {}\n\n{}\n\n{}\n\n", h.panel, h.short, h.text);
        out.push_str("How to use it:\n\n");
        for step in h.how {
            let _ = writeln!(out, "- {step}");
        }
        let keys: Vec<String> = h
            .keys
            .iter()
            .filter_map(|k| SHORTCUTS.iter().find(|s| s.keys == *k))
            .map(|s| format!("`{}` {}", s.keys, s.what.to_lowercase()))
            .collect();
        if !keys.is_empty() {
            let _ = write!(out, "\nShortcuts here: {}.\n", keys.join("; "));
        }
    }

    out.push_str("\n## Keyboard shortcuts\n\n| Keys | What it does | Where |\n|---|---|---|\n");
    for s in SHORTCUTS {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} |",
            cell(s.keys),
            cell(s.what),
            cell(s.place)
        );
    }
    out.push_str("\nPress **Ctrl+/** in the app for this list.\n");
    Ok(out)
}

/// Writes the page.
pub fn write_page() -> Result<()> {
    let path = page_path();
    fs::write(&path, render()?).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("docs: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_gui_page_is_up_to_date() {
        let committed = fs::read_to_string(page_path()).unwrap_or_default();
        assert!(
            committed == render().expect("renders"),
            "docs/gui.md is stale: run `cargo xtask docs` and commit the result"
        );
    }

    #[test]
    fn every_menu_is_found_and_every_action_is_listed() {
        let text = render().expect("renders");
        for m in MENU_ORDER {
            assert!(text.contains(&format!("\n### {m}\n")), "no {m} menu");
        }
        for a in AppAction::ALL {
            assert!(text.contains(a.label()), "{} is in no menu", a.label());
        }
    }
}
