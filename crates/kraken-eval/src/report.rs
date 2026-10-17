//! The result of a run: scores, tokens, tool use and transcripts, as JSON and as Markdown.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kraken_assist::BackendInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::EvalError;
use crate::suite::Kind;

/// Version of the report format.
pub const REPORT_VERSION: u32 = 1;

/// Longest reply kept in a report.
pub(crate) const MAX_REPLY: usize = 6000;

/// One step of what happened during a task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TranscriptEntry {
    /// What the assistant was asked.
    Prompt {
        /// The user message.
        text: String,
    },
    /// What it said between tool calls.
    Text {
        /// The text.
        text: String,
    },
    /// A tool call and what came back.
    ToolCall {
        /// Command name.
        name: String,
        /// The arguments it was called with.
        arguments: Value,
        /// A short single-line summary of the result.
        result: String,
        /// True when the call failed.
        is_error: bool,
    },
    /// An error the run reported.
    Error {
        /// The message.
        message: String,
    },
    /// How the run ended.
    Done {
        /// The stop reason.
        stop: String,
    },
}

/// Tokens a run used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUse {
    /// Tokens sent to the model.
    pub input: u64,
    /// Tokens the model wrote.
    pub output: u64,
}

impl TokenUse {
    /// Input plus output.
    pub fn total(self) -> u64 {
        self.input + self.output
    }
}

/// Dollars per million tokens, for a cost estimate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Price {
    /// Per million input tokens.
    pub input_per_million: f64,
    /// Per million output tokens.
    pub output_per_million: f64,
}

impl Price {
    /// The cost of `tokens`.
    pub fn cost(self, tokens: TokenUse) -> f64 {
        tokens.input as f64 * self.input_per_million / 1e6
            + tokens.output as f64 * self.output_per_million / 1e6
    }
}

/// The outcome of one task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskReport {
    /// Task id.
    pub id: String,
    /// Task kind.
    pub kind: Kind,
    /// Corpus binary.
    pub binary: String,
    /// 0 to 1.
    pub score: f64,
    /// True when the score is 1.
    pub correct: bool,
    /// Why there is no score to speak of: an unreadable answer, a failed run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// What was compared: truth, answer, the parts of the score.
    pub detail: Value,
    /// The answer block, when one was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<Value>,
    /// The final reply text (cut at a few thousand characters).
    pub reply: String,
    /// How the run ended.
    pub stop: String,
    /// The error the run reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Tokens used, when the backend reports them (a terminal agent usually does not).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenUse>,
    /// Estimated cost, when a price was given and tokens are known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// Tool calls made.
    pub tool_calls: usize,
    /// Tool calls that failed.
    pub tool_errors: usize,
    /// Wall time; left out of deterministic runs so their reports are identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Everything that happened.
    pub transcript: Vec<TranscriptEntry>,
}

/// Totals for one kind of task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KindSummary {
    /// Tasks of this kind.
    pub tasks: usize,
    /// Mean score.
    pub mean_score: f64,
    /// Tasks with a perfect score.
    pub correct: usize,
}

/// Totals for the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Tasks run.
    pub tasks: usize,
    /// Mean score over all tasks.
    pub mean_score: f64,
    /// Tasks with a perfect score.
    pub correct: usize,
    /// Tasks whose answer could not be read or whose run failed.
    pub problems: usize,
    /// Per kind, keyed by the kind's name.
    pub by_kind: BTreeMap<String, KindSummary>,
    /// Tokens used, when any task reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenUse>,
    /// Estimated cost, when a price was given and tokens are known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// Tool calls made.
    pub tool_calls: usize,
    /// Wall time of the run, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// A whole run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Format version.
    pub schema_version: u32,
    /// Suite name.
    pub suite: String,
    /// `live`, `ci-replay` or `ci-agent`.
    pub mode: String,
    /// What answered.
    pub backend: BackendInfo,
    /// What served the engine side (fixtures, or an engine build).
    pub engine: String,
    /// Totals.
    pub summary: Summary,
    /// One entry per task, in run order.
    pub tasks: Vec<TaskReport>,
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// Cuts `s` to `max` characters, marking the cut.
pub(crate) fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}...")
    }
}

impl Summary {
    /// Totals over `tasks`, whose costs are already worked out.
    pub fn of(tasks: &[TaskReport], duration_ms: Option<u64>) -> Summary {
        let mut by_kind: BTreeMap<String, (usize, f64, usize)> = BTreeMap::new();
        let mut tokens: Option<TokenUse> = None;
        let mut cost: Option<f64> = None;
        for t in tasks {
            let e = by_kind.entry(t.kind.as_str().to_string()).or_default();
            e.0 += 1;
            e.1 += t.score;
            e.2 += usize::from(t.correct);
            if let Some(u) = t.tokens {
                let sum = tokens.get_or_insert_with(TokenUse::default);
                sum.input += u.input;
                sum.output += u.output;
            }
            if let Some(c) = t.cost_usd {
                *cost.get_or_insert(0.0) += c;
            }
        }
        let n = tasks.len();
        let total: f64 = tasks.iter().map(|t| t.score).sum();
        Summary {
            tasks: n,
            mean_score: if n == 0 {
                0.0
            } else {
                round4(total / n as f64)
            },
            correct: tasks.iter().filter(|t| t.correct).count(),
            problems: tasks.iter().filter(|t| t.problem.is_some()).count(),
            by_kind: by_kind
                .into_iter()
                .map(|(k, (tasks, sum, correct))| {
                    (
                        k,
                        KindSummary {
                            tasks,
                            mean_score: round4(sum / tasks as f64),
                            correct,
                        },
                    )
                })
                .collect(),
            tokens,
            cost_usd: cost.map(round4),
            tool_calls: tasks.iter().map(|t| t.tool_calls).sum(),
            duration_ms,
        }
    }
}

fn file_stem(id: &str) -> String {
    id.replace('/', "-")
}

fn pct(x: f64) -> String {
    format!("{:.1}%", x * 100.0)
}

impl Report {
    /// The report as pretty JSON.
    pub fn to_json(&self) -> Result<String, EvalError> {
        let mut s =
            serde_json::to_string_pretty(self).map_err(|e| EvalError::Report(e.to_string()))?;
        s.push('\n');
        Ok(s)
    }

    /// The report as Markdown: the totals, a table of tasks, and what went wrong in the weak ones.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let s = &self.summary;
        let _ = writeln!(out, "# KRAKEN evaluation: {}\n", self.suite);
        let _ = writeln!(
            out,
            "- Backend: {} ({:?})",
            self.backend.title(),
            self.backend.kind
        );
        let _ = writeln!(out, "- Mode: {}; engine: {}", self.mode, self.engine);
        let _ = writeln!(
            out,
            "- **Mean score: {}** over {} tasks ({} perfect, {} with problems)",
            pct(s.mean_score),
            s.tasks,
            s.correct,
            s.problems
        );
        match s.tokens {
            Some(t) => {
                let _ = writeln!(
                    out,
                    "- Tokens: {} in, {} out ({} total){}",
                    t.input,
                    t.output,
                    t.total(),
                    s.cost_usd
                        .map(|c| format!(", estimated cost ${c:.4}"))
                        .unwrap_or_default()
                );
            }
            None => {
                let _ = writeln!(out, "- Tokens: not reported by this backend");
            }
        }
        let _ = writeln!(out, "- Tool calls: {}", s.tool_calls);
        if let Some(ms) = s.duration_ms {
            let _ = writeln!(out, "- Time: {:.1} s", ms as f64 / 1000.0);
        }

        out.push_str(
            "\n## By kind\n\n| Kind | Tasks | Mean score | Perfect |\n|---|---:|---:|---:|\n",
        );
        for (k, v) in &s.by_kind {
            let _ = writeln!(
                out,
                "| {k} | {} | {} | {} |",
                v.tasks,
                pct(v.mean_score),
                v.correct
            );
        }

        out.push_str("\n## Tasks\n\n| Task | Binary | Score | Tokens | Tools | Note |\n|---|---|---:|---:|---:|---|\n");
        for t in &self.tasks {
            let note = t
                .problem
                .as_deref()
                .or(t.error.as_deref())
                .map(|n| clip(n, 70).replace('|', "/"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "| [{}](transcripts/{}.md) | {} | {} | {} | {} | {} |",
                t.id,
                file_stem(&t.id),
                t.binary,
                pct(t.score),
                t.tokens.map_or("-".to_string(), |u| u.total().to_string()),
                t.tool_calls,
                note
            );
        }

        let weak: Vec<&TaskReport> = self.tasks.iter().filter(|t| !t.correct).collect();
        if !weak.is_empty() {
            out.push_str("\n## What was missed\n");
            for t in weak {
                let _ = writeln!(out, "\n### {} ({})\n", t.id, pct(t.score));
                if let Some(p) = &t.problem {
                    let _ = writeln!(out, "Problem: {p}\n");
                }
                if let Some(rows) = t.detail.get("functions").and_then(Value::as_array) {
                    out.push_str("| Address | Truth | Answered | F1 |\n|---|---|---|---:|\n");
                    for r in rows {
                        let _ = writeln!(
                            out,
                            "| {} | `{}` | {} | {} |",
                            r["address"].as_str().unwrap_or(""),
                            r["truth"].as_str().unwrap_or(""),
                            r["predicted"]
                                .as_str()
                                .map_or("(none)".to_string(), |n| format!("`{n}`")),
                            r["f1"]
                        );
                    }
                } else {
                    let _ = writeln!(out, "```json\n{}\n```", t.detail);
                }
            }
        }
        out
    }
}

impl TaskReport {
    /// One task's transcript as Markdown.
    pub fn transcript_markdown(&self) -> String {
        let mut out = format!(
            "# {}\n\nBinary `{}`; score {}; stop `{}`.\n",
            self.id,
            self.binary,
            pct(self.score),
            self.stop
        );
        for e in &self.transcript {
            match e {
                TranscriptEntry::Prompt { text } => {
                    let _ = write!(out, "\n## Prompt\n\n```text\n{text}\n```\n");
                }
                TranscriptEntry::Text { text } => {
                    let _ = write!(out, "\n## Assistant\n\n{}\n", text.trim());
                }
                TranscriptEntry::ToolCall {
                    name,
                    arguments,
                    result,
                    is_error,
                } => {
                    let _ = write!(
                        out,
                        "\n- tool `{name}` {arguments}{}: {}\n",
                        if *is_error { " (failed)" } else { "" },
                        result
                    );
                }
                TranscriptEntry::Error { message } => {
                    let _ = write!(out, "\n## Error\n\n{message}\n");
                }
                TranscriptEntry::Done { stop } => {
                    let _ = write!(out, "\n_Run ended: {stop}._\n");
                }
            }
        }
        out
    }
}

/// The files a report was written to.
#[derive(Debug, Clone)]
pub struct Written {
    /// `report.json`.
    pub json: PathBuf,
    /// `report.md`.
    pub markdown: PathBuf,
    /// The transcript folder.
    pub transcripts: PathBuf,
}

/// Writes `report.json`, `report.md` and `transcripts/<task>.md` into `dir`.
pub fn write_report(report: &Report, dir: &Path) -> Result<Written, EvalError> {
    let io = |p: &Path, e: std::io::Error| EvalError::Report(format!("{}: {e}", p.display()));
    let transcripts = dir.join("transcripts");
    std::fs::create_dir_all(&transcripts).map_err(|e| io(&transcripts, e))?;
    let json = dir.join("report.json");
    std::fs::write(&json, report.to_json()?).map_err(|e| io(&json, e))?;
    let markdown = dir.join("report.md");
    std::fs::write(&markdown, report.to_markdown()).map_err(|e| io(&markdown, e))?;
    for t in &report.tasks {
        let p = transcripts.join(format!("{}.md", file_stem(&t.id)));
        std::fs::write(&p, t.transcript_markdown()).map_err(|e| io(&p, e))?;
    }
    Ok(Written {
        json,
        markdown,
        transcripts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_assist::BackendKind;
    use serde_json::json;

    fn task(id: &str, kind: Kind, score: f64, tokens: Option<TokenUse>) -> TaskReport {
        TaskReport {
            id: id.into(),
            kind,
            binary: "b".into(),
            score,
            correct: score >= 1.0,
            problem: None,
            detail: json!({}),
            answer: None,
            reply: String::new(),
            stop: "completed".into(),
            error: None,
            tokens,
            cost_usd: tokens.map(|t| {
                Price {
                    input_per_million: 3.0,
                    output_per_million: 15.0,
                }
                .cost(t)
            }),
            tool_calls: 2,
            tool_errors: 0,
            duration_ms: None,
            transcript: vec![TranscriptEntry::Done {
                stop: "completed".into(),
            }],
        }
    }

    #[test]
    fn totals_add_up_per_kind_and_overall() {
        let t = vec![
            task(
                "a/1",
                Kind::FindFunction,
                1.0,
                Some(TokenUse {
                    input: 1000,
                    output: 100,
                }),
            ),
            task(
                "a/2",
                Kind::FindFunction,
                0.0,
                Some(TokenUse {
                    input: 2000,
                    output: 200,
                }),
            ),
            task("n/1", Kind::NameFunctions, 0.5, None),
        ];
        let s = Summary::of(&t, None);
        assert_eq!(s.tasks, 3);
        assert!((s.mean_score - 0.5).abs() < 1e-9);
        assert_eq!(s.correct, 1);
        assert_eq!(s.by_kind["find_function"].tasks, 2);
        assert!((s.by_kind["find_function"].mean_score - 0.5).abs() < 1e-9);
        assert_eq!(
            s.tokens,
            Some(TokenUse {
                input: 3000,
                output: 300
            })
        );
        // 3000 * 3 / 1e6 + 300 * 15 / 1e6
        assert!((s.cost_usd.unwrap() - 0.0135).abs() < 1e-9);
        assert_eq!(s.tool_calls, 6);
    }

    #[test]
    fn a_report_round_trips_and_renders() {
        let tasks = vec![task("find/x", Kind::FindFunction, 0.0, None)];
        let report = Report {
            schema_version: REPORT_VERSION,
            suite: "corpus".into(),
            mode: "ci-replay".into(),
            backend: BackendInfo {
                kind: BackendKind::Api,
                id: "replay".into(),
                name: "replay".into(),
                model: Some("cassette".into()),
            },
            engine: "fixtures".into(),
            summary: Summary::of(&tasks, None),
            tasks,
        };
        let json = report.to_json().expect("json");
        let back: Report = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, report);
        let md = report.to_markdown();
        assert!(md.contains("# KRAKEN evaluation: corpus"));
        assert!(md.contains("[find/x](transcripts/find-x.md)"));
        assert!(md.contains("Tokens: not reported"));
        assert!(md.contains("## What was missed"));
    }

    #[test]
    fn reports_are_written_with_one_transcript_per_task() {
        let tasks = vec![task("find/x", Kind::FindFunction, 1.0, None)];
        let report = Report {
            schema_version: REPORT_VERSION,
            suite: "s".into(),
            mode: "live".into(),
            backend: BackendInfo {
                kind: BackendKind::TerminalAgent,
                id: "claude".into(),
                name: "Claude Code".into(),
                model: None,
            },
            engine: "e".into(),
            summary: Summary::of(&tasks, None),
            tasks,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let w = write_report(&report, dir.path()).expect("write");
        assert!(w.json.is_file() && w.markdown.is_file());
        assert!(w.transcripts.join("find-x.md").is_file());
    }
}
