//! Progress of opening a program: the stages, what the engine reports and what clients see.
//!
//! An engine reports [`OpenUpdate`]s (its own stage and, when it can tell, how far into it it
//! is). The registry turns them into [`OpenProgress`]: the stage list of the engine, an overall
//! fraction that never goes back, the elapsed time and the job that can cancel the open.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One step of opening a program, in order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OpenStage {
    /// Checking the file and the project folder, hashing the file.
    Prepare,
    /// Starting the engine process.
    StartEngine,
    /// Reading the file (Ghidra: importing it; .NET: loading the assemblies).
    ReadFile,
    /// Loading the symbol table and debug information.
    Symbols,
    /// Finding the functions (the slow part of a first open).
    Functions,
    /// Types and signatures of known library functions.
    Types,
    /// Restoring the changes saved in the project.
    Replay,
    /// Done.
    Ready,
}

impl OpenStage {
    /// Wire name such as `"functions"`.
    pub fn as_str(self) -> &'static str {
        match self {
            OpenStage::Prepare => "prepare",
            OpenStage::StartEngine => "start_engine",
            OpenStage::ReadFile => "read_file",
            OpenStage::Symbols => "symbols",
            OpenStage::Functions => "functions",
            OpenStage::Types => "types",
            OpenStage::Replay => "replay",
            OpenStage::Ready => "ready",
        }
    }

    /// A short name for people, such as `"Finding functions"`.
    pub fn label(self) -> &'static str {
        match self {
            OpenStage::Prepare => "Checking the file",
            OpenStage::StartEngine => "Starting the engine",
            OpenStage::ReadFile => "Reading the file",
            OpenStage::Symbols => "Loading symbols and debug info",
            OpenStage::Functions => "Finding functions",
            OpenStage::Types => "Types and signatures",
            OpenStage::Replay => "Restoring your changes",
            OpenStage::Ready => "Ready",
        }
    }
}

/// What an engine says while it opens a program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenUpdate {
    /// The stage the engine is in.
    pub stage: OpenStage,
    /// How far into the stage, 0 to 1, when the engine can tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_fraction: Option<f64>,
    /// Functions found so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<u64>,
    /// Functions waiting to be looked at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<u64>,
    /// Bytes of code inside the functions found so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_bytes: Option<u64>,
    /// Bytes of code in the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_bytes: Option<u64>,
    /// True when the stage reads results saved by an earlier open.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_cache: bool,
    /// One line for people; may contain engine text.
    #[serde(default)]
    pub message: String,
}

impl OpenUpdate {
    /// An update that only names the stage.
    pub fn stage(stage: OpenStage, message: impl Into<String>) -> Self {
        OpenUpdate {
            stage,
            stage_fraction: None,
            found: None,
            queued: None,
            covered_bytes: None,
            code_bytes: None,
            from_cache: false,
            message: message.into(),
        }
    }
}

/// Progress of a running `project_create` or `project_open`, as clients see it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenProgress {
    /// The command that opens the project.
    pub command: String,
    /// File name of the program.
    pub program: String,
    /// The job that tracks the open; `job_cancel` with it stops the open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The engine opening it (`native`, `ghidra`, `dotnet`), once it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// Every stage of this open, in order.
    pub stages: Vec<OpenStage>,
    /// The current stage.
    pub stage: OpenStage,
    /// Overall share done, 0 to 1; absent while the current stage cannot tell. Never decreases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fraction: Option<f64>,
    /// Share done of the current stage, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_fraction: Option<f64>,
    /// Functions found so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<u64>,
    /// Functions waiting to be looked at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<u64>,
    /// Bytes of code inside the functions found so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_bytes: Option<u64>,
    /// Bytes of code in the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_bytes: Option<u64>,
    /// True when the engine reads results saved by an earlier open (a reopen).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_cache: bool,
    /// One line for people; may contain engine text.
    #[serde(default)]
    pub message: String,
    /// Milliseconds since the open started.
    pub elapsed_ms: u64,
}

/// The stages of one engine with the share of the time each usually takes, used to turn a stage
/// and its fraction into an overall fraction.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenPlan {
    weights: Vec<(OpenStage, f64)>,
}

impl OpenPlan {
    /// The plan of an engine (`native`, `ghidra`, `dotnet`); `None` before the engine is known,
    /// which gives the stages every engine has.
    pub fn for_engine(engine: Option<&str>) -> OpenPlan {
        use OpenStage::*;
        let weights: &[(OpenStage, f64)] = match engine {
            // finding functions is nearly all of a first open (docs/performance.md)
            Some("native") => &[
                (Prepare, 1.0),
                (StartEngine, 1.0),
                (ReadFile, 1.0),
                (Symbols, 1.0),
                (Functions, 92.0),
                (Types, 3.0),
                (Replay, 1.0),
                (Ready, 0.0),
            ],
            Some("ghidra") => &[
                (Prepare, 2.0),
                (StartEngine, 18.0),
                (ReadFile, 75.0),
                (Replay, 5.0),
                (Ready, 0.0),
            ],
            Some("dotnet") => &[
                (Prepare, 5.0),
                (StartEngine, 40.0),
                (ReadFile, 50.0),
                (Replay, 5.0),
                (Ready, 0.0),
            ],
            _ => &[
                (Prepare, 5.0),
                (StartEngine, 10.0),
                (ReadFile, 80.0),
                (Replay, 5.0),
                (Ready, 0.0),
            ],
        };
        OpenPlan {
            weights: weights.to_vec(),
        }
    }

    /// The stages in order.
    pub fn stages(&self) -> Vec<OpenStage> {
        self.weights.iter().map(|(s, _)| *s).collect()
    }

    /// The overall fraction at `stage` with `stage_fraction` done of it; `None` when the stage
    /// is not in the plan or its own fraction is unknown. `Ready` is 1.
    pub fn fraction(&self, stage: OpenStage, stage_fraction: Option<f64>) -> Option<f64> {
        if stage == OpenStage::Ready {
            return Some(1.0);
        }
        let total: f64 = self.weights.iter().map(|(_, w)| w).sum();
        let i = self.weights.iter().position(|(s, _)| *s == stage)?;
        let before: f64 = self.weights[..i].iter().map(|(_, w)| w).sum();
        let within = stage_fraction?.clamp(0.0, 1.0) * self.weights[i].1;
        (total > 0.0).then(|| ((before + within) / total).clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overall_fraction_follows_the_stage_weights() {
        let p = OpenPlan::for_engine(Some("native"));
        assert_eq!(p.stages().first(), Some(&OpenStage::Prepare));
        assert_eq!(p.stages().last(), Some(&OpenStage::Ready));
        let start = p.fraction(OpenStage::Functions, Some(0.0)).unwrap();
        let half = p.fraction(OpenStage::Functions, Some(0.5)).unwrap();
        let end = p.fraction(OpenStage::Functions, Some(1.0)).unwrap();
        assert!((start - 0.04).abs() < 1e-9, "{start}");
        assert!(start < half && half < end && end < 1.0);
        assert_eq!(p.fraction(OpenStage::Functions, None), None);
        assert_eq!(p.fraction(OpenStage::Ready, None), Some(1.0));
        // Ghidra has no separate symbol stage
        assert_eq!(
            OpenPlan::for_engine(Some("ghidra")).fraction(OpenStage::Symbols, Some(1.0)),
            None
        );
    }

    #[test]
    fn progress_round_trips_without_empty_fields() {
        let p = OpenProgress {
            command: "project_open".into(),
            program: "libpython.so".into(),
            job_id: Some("job-1".into()),
            engine: Some("native".into()),
            stages: OpenPlan::for_engine(Some("native")).stages(),
            stage: OpenStage::Functions,
            fraction: Some(0.5),
            stage_fraction: Some(0.48),
            found: Some(12_410),
            queued: Some(2_300),
            covered_bytes: None,
            code_bytes: None,
            from_cache: false,
            message: "12410 functions found".into(),
            elapsed_ms: 1500,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["stage"], "functions");
        assert!(v.get("covered_bytes").is_none() && v.get("from_cache").is_none());
        assert_eq!(serde_json::from_value::<OpenProgress>(v).unwrap(), p);
    }
}
