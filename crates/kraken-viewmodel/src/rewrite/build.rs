//! Building and testing the exported crate (`rewrite_build`): the last steps of the rewrite
//! flow.

use kraken_registry::commands::RewriteBuildResult;
use serde_json::json;

use super::JobKind;
use super::program::split_args;
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, parse};

/// One step of a finished build.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildStepItem {
    /// `build`, `test` or `run`.
    pub step: String,
    /// The step exited with status 0.
    pub passed: bool,
    /// `exit 0`, `exit 101`, `signal 9` or `timeout`.
    pub exit: String,
    /// Wall-clock seconds.
    pub seconds: f64,
    /// The end of the step's output.
    pub log: String,
}

impl BuildStepItem {
    /// "Build", "Test" or "Run" for the heading of the log.
    pub fn title(&self) -> &'static str {
        match self.step.as_str() {
            "build" => "Build",
            "test" => "Test",
            _ => "Run",
        }
    }
}

/// The result of the last build.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildOutcome {
    /// The folder that was built.
    pub dir: String,
    /// `export` or `program`.
    pub kind: String,
    /// Every step that ran passed.
    pub passed: bool,
    /// The steps that ran.
    pub steps: Vec<BuildStepItem>,
    /// How the steps were confined.
    pub sandbox: String,
}

/// State of the build step.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildState {
    /// Run the tests too.
    pub test: bool,
    /// Run the program after the tests (program crates only).
    pub run: bool,
    /// Arguments of that run, as typed.
    pub run_args: String,
    /// The last result.
    pub result: Option<BuildOutcome>,
    /// Plain-language reason the build could not start or finish.
    pub error: Option<String>,
    /// The person said no to the approval question.
    pub declined: Option<String>,
}

impl Default for BuildState {
    fn default() -> Self {
        BuildState {
            test: true,
            run: false,
            run_args: String::new(),
            result: None,
            error: None,
            declined: None,
        }
    }
}

impl ViewModel {
    /// Builds (and tests, and runs) the exported crate in `dir`; a job. The daemon asks the person
    /// first, because the crate is generated code, through the approval dialog.
    pub fn rewrite_build_start(&mut self, dir: &str) {
        if !self.rewrite.can_run() || self.rewrite.building() || dir.trim().is_empty() {
            return;
        }
        let is_program = self
            .rewrite
            .program
            .detail
            .as_ref()
            .is_some_and(|d| d.crate_dir == dir);
        let mut args = json!({ "dir": dir, "test": self.rewrite.build.test });
        if self.rewrite.build.run && is_program {
            match split_args(&self.rewrite.build.run_args) {
                Ok(a) => args["run_args"] = json!(a),
                Err(why) => {
                    self.rewrite.build.error = Some(why);
                    return;
                }
            }
        }
        let b = &mut self.rewrite.build;
        b.error = None;
        b.declined = None;
        b.result = None;
        self.rewrite_start_job(
            JobKind::Build,
            "Building and testing the Rust crate".into(),
            "rewrite_build",
            args,
        );
    }

    pub(crate) fn rewrite_build_declined(&mut self) {
        self.rewrite.build.declined = Some(
            "Not built. Building runs the generated Rust (inside a sandbox with no network), and you did not allow that."
                .into(),
        );
    }

    pub(crate) fn rewrite_build_done(
        &mut self,
        result: serde_json::Value,
    ) -> Result<String, String> {
        let r = parse::<RewriteBuildResult>(result).map_err(|e| plain_error(&e))?;
        let outcome = BuildOutcome {
            dir: r.dir,
            kind: r.kind,
            passed: r.passed,
            sandbox: r.sandbox,
            steps: r
                .steps
                .into_iter()
                .map(|s| BuildStepItem {
                    step: s.step,
                    passed: s.passed,
                    exit: s.exit,
                    seconds: s.seconds,
                    log: s.log_tail.0,
                })
                .collect(),
        };
        let text = match outcome.steps.iter().find(|s| !s.passed) {
            None => {
                let names: Vec<&str> = outcome.steps.iter().map(|s| s.step.as_str()).collect();
                format!("The Rust crate passed: {}.", names.join(", "))
            }
            Some(bad) => format!(
                "The Rust crate failed at the {} step. The log shows why.",
                bad.step
            ),
        };
        let level = if outcome.passed {
            ToastLevel::Success
        } else {
            ToastLevel::Warning
        };
        self.rewrite.build.result = Some(outcome);
        self.rewrite.build.error = None;
        self.toast(level, text.clone());
        Ok(text)
    }
}
