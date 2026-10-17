//! Eval cassettes: the model exchanges of a run, grouped by task.
//!
//! `ReplayProvider` normally finds a recording by a fingerprint of the whole request, so any
//! change to a tool description or the system prompt makes every recording miss. An evaluation
//! asks the same questions in the same order each time, so its cassette is keyed by task id
//! instead: the n-th model call of a task gets the n-th recorded response. The responses are the
//! ordinary `StreamEvent`s `RecordingProvider` records, and replay goes through
//! `ReplayProvider::scripted`.

use std::collections::BTreeMap;
use std::path::Path;

use kraken_agent::StreamEvent;
use serde::{Deserialize, Serialize};

use crate::error::EvalError;

/// Version of the cassette format.
pub const CASSETTE_VERSION: u32 = 1;

/// Recorded model responses per task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalCassette {
    /// Format version.
    pub version: u32,
    /// Who recorded it: a model name, or a note saying it is a scripted stand-in.
    pub recorded_with: String,
    /// Task id to the responses of its model calls, in order.
    pub tasks: BTreeMap<String, Vec<Vec<StreamEvent>>>,
}

impl EvalCassette {
    /// An empty cassette.
    pub fn new(recorded_with: impl Into<String>) -> Self {
        EvalCassette {
            version: CASSETTE_VERSION,
            recorded_with: recorded_with.into(),
            tasks: BTreeMap::new(),
        }
    }

    /// Parses a cassette.
    pub fn from_json(text: &str) -> Result<Self, EvalError> {
        let c: EvalCassette =
            serde_json::from_str(text).map_err(|e| EvalError::Cassette(e.to_string()))?;
        if c.version != CASSETTE_VERSION {
            return Err(EvalError::Cassette(format!(
                "unsupported cassette version {}",
                c.version
            )));
        }
        Ok(c)
    }

    /// Pretty JSON with a trailing newline.
    pub fn to_json(&self) -> Result<String, EvalError> {
        let mut s =
            serde_json::to_string_pretty(self).map_err(|e| EvalError::Cassette(e.to_string()))?;
        s.push('\n');
        Ok(s)
    }

    /// Reads a cassette file.
    pub fn load(path: &Path) -> Result<Self, EvalError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| EvalError::Cassette(format!("{}: {e}", path.display())))?;
        Self::from_json(&text)
    }

    /// Writes a cassette file.
    pub fn save(&self, path: &Path) -> Result<(), EvalError> {
        std::fs::write(path, self.to_json()?)
            .map_err(|e| EvalError::Cassette(format!("{}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_agent::FinishReason;

    #[test]
    fn a_cassette_round_trips() {
        let mut c = EvalCassette::new("a test");
        c.tasks.insert(
            "find/x".into(),
            vec![vec![
                StreamEvent::TextDelta { text: "hi".into() },
                StreamEvent::Finish {
                    reason: FinishReason::Stop,
                },
            ]],
        );
        let back = EvalCassette::from_json(&c.to_json().expect("json")).expect("parse");
        assert_eq!(back, c);
        assert!(
            EvalCassette::from_json("{\"version\": 9, \"recorded_with\": \"\", \"tasks\": {}}")
                .is_err()
        );
    }
}
