//! The next-steps strip above the Decompiler: what `next_steps` suggests, which of it the person
//! dismissed, and running a suggestion with one click.

use std::collections::BTreeSet;

use kraken_registry::guide::Suggestion;
use serde_json::{Value, json};

use crate::errors::plain_error;
use crate::state::{AnalysisPhase, Connection, ToastLevel};
use crate::vm::{ViewModel, parse};

/// Most suggestions the strip shows.
pub const STRIP_MAX: usize = 3;

/// What the last fetch was made for; a different key means the answer may have changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    phase: AnalysisPhase,
    function: Option<u64>,
    epoch: u64,
}

/// State of the strip.
#[derive(Debug, Default)]
pub struct NextStepsPanel {
    /// What `next_steps` said last, most useful first.
    pub steps: Vec<Suggestion>,
    /// Ids the person dismissed this session.
    pub dismissed: BTreeSet<String>,
    /// A call is running.
    pub loading: bool,
    /// Why the last fetch failed (not shown; the strip just stays empty).
    pub error: Option<String>,
    fetched_for: Option<Key>,
    /// Bumped by edits, so the next frame fetches again.
    epoch: u64,
}

#[derive(serde::Deserialize)]
struct StepsWire {
    suggestions: Vec<Suggestion>,
}

impl NextStepsPanel {
    /// The suggestions the strip shows: not dismissed, at most [`STRIP_MAX`].
    pub fn visible(&self) -> Vec<&Suggestion> {
        self.steps
            .iter()
            .filter(|s| !self.dismissed.contains(&s.id))
            .take(STRIP_MAX)
            .collect()
    }

    /// True when something was dismissed and could come back.
    pub fn has_dismissed(&self) -> bool {
        !self.dismissed.is_empty()
    }
}

impl ViewModel {
    /// Asks for new suggestions when the project, the analysis or the function in view changed
    /// since the last ask. Cheap to call every frame.
    pub fn ensure_next_steps(&mut self) {
        if self.connection != Connection::Open {
            return;
        }
        let key = Key {
            phase: self.analysis.phase,
            function: self.current.as_ref().map(|c| c.address),
            epoch: self.tools.next_steps.epoch,
        };
        let p = &mut self.tools.next_steps;
        if p.loading || p.fetched_for == Some(key) {
            return;
        }
        p.loading = true;
        p.fetched_for = Some(key);
        let mut args = json!({"limit": 6});
        if let Some(a) = key.function {
            args["function"] = json!(format!("{a:#x}"));
        }
        self.call("next_steps", args, move |vm, res| {
            let p = &mut vm.tools.next_steps;
            p.loading = false;
            match res.and_then(parse::<StepsWire>) {
                Ok(w) => {
                    p.steps = w.suggestions;
                    p.error = None;
                }
                Err(e) => {
                    p.steps.clear();
                    p.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Makes the strip ask again on the next frame (after an edit or a change of state).
    pub fn refresh_next_steps(&mut self) {
        self.tools.next_steps.epoch += 1;
    }

    /// Hides a suggestion for the rest of the session.
    pub fn dismiss_next_step(&mut self, id: &str) {
        self.tools.next_steps.dismissed.insert(id.to_string());
    }

    /// Brings every dismissed suggestion back.
    pub fn restore_next_steps(&mut self) {
        self.tools.next_steps.dismissed.clear();
    }

    /// Does what suggestion `id` says. Steps the GUI already has a flow for use it (analysis, the
    /// assistant, which asks before it spends money); other commands run and show their result.
    pub fn run_next_step(&mut self, id: &str) {
        let Some(step) = self
            .tools
            .next_steps
            .steps
            .iter()
            .find(|s| s.id == id)
            .cloned()
        else {
            return;
        };
        match (step.command.as_deref(), step.runnable) {
            (Some("analyze"), true) => self.start_analysis(),
            (Some("assist_auto_name"), true) => self.assist_auto_name(10),
            (Some(command), true) => self.run_command_with(command, &step.args),
            (Some("set_local"), false) => self.toast(
                ToastLevel::Info,
                "Click a variable in the code and press N to name it.",
            ),
            _ => self.toast(ToastLevel::Info, step.reason),
        }
    }

    /// Runs `command` with `args` and shows the result window, as the palette's forms do.
    fn run_command_with(&mut self, command: &str, args: &Value) {
        self.open_command_form_with(command, args, true);
    }
}
