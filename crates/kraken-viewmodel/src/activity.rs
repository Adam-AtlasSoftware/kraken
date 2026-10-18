//! What agents (clients other than the GUI itself) did lately: edits applied or proposed and
//! jobs they started. The window shows a one-line summary in its status bar.

use std::time::{Duration, Instant};

use crate::backend::ChangeInfo;

/// An agent that has been quiet this long is no longer reported.
pub const ACTIVITY_WINDOW: Duration = Duration::from_secs(30 * 60);
/// An agent whose last action is newer than this counts as working right now.
pub const ACTIVE_NOW: Duration = Duration::from_secs(20);
/// Most agents tracked at once.
const MAX_ACTORS: usize = 16;

/// One agent's recent work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentActor {
    /// Agent id as the daemon reports it.
    pub author: String,
    /// Edits applied.
    pub applied: u32,
    /// Edits held back as proposals.
    pub proposed: u32,
    /// Jobs started.
    pub jobs: u32,
    /// The command of the latest action.
    pub last_command: String,
    /// When the first counted action happened.
    pub first_at: Instant,
    /// When the latest action happened.
    pub last_at: Instant,
}

/// A line for the status bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivitySummary {
    /// Who: the agent id.
    pub who: String,
    /// What it is doing, as a verb phrase such as "renaming".
    pub what: String,
    /// Edits applied plus edits proposed.
    pub changes: u32,
    /// Of those, proposals waiting for the person.
    pub proposed: u32,
    /// Jobs it started.
    pub jobs: u32,
    /// Time since its first action in this window.
    pub since: Duration,
    /// True when it acted in the last few seconds.
    pub active: bool,
}

impl ActivitySummary {
    /// The chip text, e.g. "Claude Code: 4 changes, renaming...".
    pub fn text(&self) -> String {
        let mut parts = Vec::new();
        if self.changes > 0 {
            parts.push(format!(
                "{} change{}",
                self.changes,
                if self.changes == 1 { "" } else { "s" }
            ));
        }
        if self.jobs > 0 {
            parts.push(format!(
                "{} job{}",
                self.jobs,
                if self.jobs == 1 { "" } else { "s" }
            ));
        }
        if self.active {
            parts.push(format!("{}...", self.what));
        }
        if parts.is_empty() {
            parts.push("idle".into());
        }
        format!("{}: {}", self.who, parts.join(", "))
    }
}

/// The verb phrase for what a command does.
pub fn what_it_does(command: &str) -> &'static str {
    match command {
        "rename_symbol" => "renaming",
        "set_comment" => "commenting",
        "set_type" | "set_calling_convention" => "retyping",
        "apply_edits" => "editing",
        "create_function" | "delete_function" | "set_function_bounds" => "reshaping functions",
        "analyze" => "analysing",
        "rewrite_function" | "rewrite_program" => "rewriting in Rust",
        "rebuild" => "rebuilding",
        _ => "working",
    }
}

/// Recent agent activity, oldest agent first.
#[derive(Debug, Default, Clone)]
pub struct AgentActivity {
    actors: Vec<AgentActor>,
}

impl AgentActivity {
    fn actor(&mut self, author: &str, now: Instant) -> &mut AgentActor {
        self.actors
            .retain(|a| now.saturating_duration_since(a.last_at) <= ACTIVITY_WINDOW);
        let idx = match self.actors.iter().position(|a| a.author == author) {
            Some(i) => i,
            None => {
                if self.actors.len() >= MAX_ACTORS {
                    self.actors.remove(0);
                }
                self.actors.push(AgentActor {
                    author: author.to_string(),
                    applied: 0,
                    proposed: 0,
                    jobs: 0,
                    last_command: String::new(),
                    first_at: now,
                    last_at: now,
                });
                self.actors.len() - 1
            }
        };
        &mut self.actors[idx]
    }

    /// Records an edit by an agent that was applied or queued.
    pub fn applied(&mut self, c: &ChangeInfo, now: Instant) {
        if !c.by_agent {
            return;
        }
        let a = self.actor(&c.author, now);
        a.applied += 1;
        a.last_command = c.command.clone();
        a.last_at = now;
    }

    /// Records an edit by an agent that became a proposal.
    pub fn proposed(&mut self, c: &ChangeInfo, now: Instant) {
        if !c.by_agent {
            return;
        }
        let a = self.actor(&c.author, now);
        a.proposed += 1;
        a.last_command = c.command.clone();
        a.last_at = now;
    }

    /// Records a job an agent started.
    pub fn job_started(&mut self, c: &ChangeInfo, now: Instant) {
        if !c.by_agent {
            return;
        }
        let a = self.actor(&c.author, now);
        a.jobs += 1;
        a.last_command = c.command.clone();
        a.last_at = now;
    }

    /// Forgets everything (a different project was opened).
    pub fn clear(&mut self) {
        self.actors.clear();
    }

    /// The agent that acted last, if any acted inside the window.
    pub fn summary(&self, now: Instant) -> Option<ActivitySummary> {
        let a = self
            .actors
            .iter()
            .filter(|a| now.saturating_duration_since(a.last_at) <= ACTIVITY_WINDOW)
            .max_by_key(|a| a.last_at)?;
        Some(ActivitySummary {
            who: a.author.clone(),
            what: what_it_does(&a.last_command).to_string(),
            changes: a.applied + a.proposed,
            proposed: a.proposed,
            jobs: a.jobs,
            since: now.saturating_duration_since(a.first_at),
            active: now.saturating_duration_since(a.last_at) <= ACTIVE_NOW,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(author: &str, command: &str, by_agent: bool) -> ChangeInfo {
        ChangeInfo {
            command: command.into(),
            by_agent,
            author: author.into(),
            run_id: None,
            entry_ids: vec![],
            key: None,
        }
    }

    #[test]
    fn counts_changes_and_ignores_people() {
        let t0 = Instant::now();
        let mut a = AgentActivity::default();
        assert!(a.summary(t0).is_none());
        a.applied(&change("claude", "rename_symbol", true), t0);
        a.applied(&change("claude", "rename_symbol", true), t0);
        a.proposed(&change("claude", "set_comment", true), t0);
        a.applied(&change("adam", "rename_symbol", false), t0);
        a.job_started(&change("claude", "analyze", true), t0);
        let s = a.summary(t0 + Duration::from_secs(5)).expect("summary");
        assert_eq!(s.who, "claude");
        assert_eq!((s.changes, s.proposed, s.jobs), (3, 1, 1));
        assert!(s.active);
        assert_eq!(s.what, "analysing");
        assert_eq!(s.text(), "claude: 3 changes, 1 job, analysing...");
    }

    #[test]
    fn quiet_agents_become_idle_and_then_vanish() {
        let t0 = Instant::now();
        let mut a = AgentActivity::default();
        a.applied(&change("claude", "rename_symbol", true), t0);
        let s = a.summary(t0 + Duration::from_secs(60)).expect("summary");
        assert!(!s.active);
        assert_eq!(s.text(), "claude: 1 change");
        assert!(
            a.summary(t0 + ACTIVITY_WINDOW + Duration::from_secs(1))
                .is_none()
        );
    }
}
