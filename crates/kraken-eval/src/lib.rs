//! KRAKEN evaluation harness (`kraken eval`).
//!
//! Scripted tasks over the test corpus, scored against ground truth, for any assistant backend:
//!
//! - **name stripped functions**: the answer is scored against the DWARF names by token overlap
//!   ([`score`]);
//! - **find the function that does X**: right when the answered address lies inside the truth
//!   function;
//! - **questions about strings and imports**: yes/no, sets and exact text.
//!
//! The [`Runner`] asks each task of a [`Suite`] through an [`Assistant`](kraken_assist::Assistant)
//! (so the model API, a local model and a terminal agent are all measured the same way), reads
//! the `<kraken-answer>` block of the reply, scores it, and produces a [`Report`]: JSON and
//! Markdown with the scores, tokens and cost where the backend reports them, tool use and one
//! transcript per task.
//!
//! [`ci`] makes the whole thing deterministic and offline: recorded engine fixtures, answers
//! from a committed script, delivered either through `ReplayProvider` cassettes or by the fake
//! ACP agent. See `docs/assistant.md` for how to run it against Ollama, llama-server or Claude
//! Code.

pub mod cassette;
pub mod ci;
pub mod corpus;
pub mod error;
pub mod prompt;
pub mod report;
pub mod rewrite;
pub mod runner;
pub mod score;
pub mod sources;
pub mod suite;

pub use cassette::EvalCassette;
pub use corpus::Corpus;
pub use error::EvalError;
pub use report::{Price, Report, TaskReport, TokenUse, TranscriptEntry, Written, write_report};
pub use rewrite::{Answers, RewriteMetrics, RewriteRunner, RewriteSummary};
pub use runner::{AssistantSource, Environment, Prepared, RunOptions, Runner};
pub use sources::{ApiSource, FakeAgentSource, FnSource, RecordingSource, ReplaySource};
pub use suite::{Kind, ResolvedTask, Suite, TaskDef};
