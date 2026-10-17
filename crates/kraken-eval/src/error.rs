//! Errors of the evaluation harness.

/// Why an evaluation could not be set up or run. A model that answers badly is not an error: that
/// is a low score in the report.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    /// The corpus directory (binaries, truth, fixtures) is missing or incomplete.
    #[error("corpus: {0}")]
    Corpus(String),
    /// The task suite is malformed or disagrees with the corpus.
    #[error("suite: {0}")]
    Suite(String),
    /// A binary could not be prepared for the run (project creation, analysis).
    #[error("setup: {0}")]
    Setup(String),
    /// A cassette is missing, malformed or out of date.
    #[error("cassette: {0}")]
    Cassette(String),
    /// The assistant backend could not be built.
    #[error("backend: {0}")]
    Backend(String),
    /// A report could not be written.
    #[error("report: {0}")]
    Report(String),
}
