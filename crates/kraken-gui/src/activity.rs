//! What agents are doing, in the status bar, and the requests they make of the window.
//!
//! The status bar calls [`status_chip`] once. [`apply_requests`] runs once per frame while a
//! project is open: it turns a chip click into the History tab and an agent's `gui_navigate`
//! request into a focused tab.

use egui::{Id, Sense, Ui};
use kraken_viewmodel::{ViewModel, activity::ActivitySummary};

use crate::style::{self, chip};
use crate::workspace::{Tab, UiState};

const OPEN_HISTORY: &str = "kraken_activity_open_history";

/// The tab an agent's `gui_navigate` names.
pub fn tab_from_name(name: &str) -> Option<Tab> {
    Some(match name {
        "decompiler" => Tab::Decompiler,
        "listing" => Tab::Listing,
        "graph" => Tab::Graph,
        "hex" => Tab::Hex,
        "xrefs" => Tab::Xrefs,
        "functions" => Tab::Functions,
        _ => return None,
    })
}

/// The hover text of the chip.
pub fn hover_text(s: &ActivitySummary) -> String {
    let mut text = format!(
        "{} is working on this project through the command line or an assistant. It has made {} \
         change{}",
        s.who,
        s.changes,
        if s.changes == 1 { "" } else { "s" }
    );
    if s.proposed > 0 {
        text.push_str(&format!(
            ", {} of them waiting for your decision",
            s.proposed
        ));
    }
    if s.jobs > 0 {
        text.push_str(&format!(" and started {} job(s)", s.jobs));
    }
    text.push_str(&format!(
        ", the first {} ago. Click to open the History tab, where you can review and undo them.",
        ago(s.since.as_secs())
    ));
    text
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h", secs / 3600),
    }
}

/// Draws the chip ("Claude Code: 4 changes, renaming...") when an agent has been at work; draws
/// nothing otherwise. A click opens the History tab.
pub fn status_chip(ui: &mut Ui, vm: &ViewModel) {
    let Some(s) = vm.agent_activity.summary(std::time::Instant::now()) else {
        return;
    };
    let status = style::status(style::dark(ui));
    let color = if s.active {
        status.info
    } else {
        style::pal(ui).text_dim
    };
    if s.active {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(500));
    }
    let response = chip(ui, &s.text(), color)
        .interact(Sense::click())
        .on_hover_text(hover_text(&s))
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.clicked() {
        ui.ctx()
            .data_mut(|d| d.insert_temp(Id::new(OPEN_HISTORY), true));
    }
}

/// Acts on a chip click and on an agent's `gui_navigate` request. Call once per frame.
pub fn apply_requests(ctx: &egui::Context, vm: &mut ViewModel, state: &mut UiState) {
    let clicked = ctx.data_mut(|d| d.remove_temp::<bool>(Id::new(OPEN_HISTORY)));
    if clicked == Some(true) {
        state.bring_to_front = Some(Tab::History);
    }
    if let Some(name) = vm.take_focus_request() {
        state.bring_to_front = Some(tab_from_name(&name).unwrap_or(Tab::Decompiler));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn summary() -> ActivitySummary {
        ActivitySummary {
            who: "claude".into(),
            what: "renaming".into(),
            changes: 4,
            proposed: 1,
            jobs: 1,
            since: Duration::from_secs(125),
            active: true,
        }
    }

    #[test]
    fn tab_names_map_and_unknown_names_do_not() {
        assert_eq!(tab_from_name("listing"), Some(Tab::Listing));
        assert_eq!(tab_from_name("decompiler"), Some(Tab::Decompiler));
        assert_eq!(tab_from_name("assistant"), None);
    }

    #[test]
    fn the_hover_text_says_who_what_and_how_to_undo() {
        let t = hover_text(&summary());
        assert!(t.contains("claude"), "{t}");
        assert!(t.contains("4 changes"), "{t}");
        assert!(t.contains("1 of them waiting"), "{t}");
        assert!(t.contains("2 min"), "{t}");
        assert!(t.contains("History"), "{t}");
    }
}
