//! Structured task results and how they are parsed from the model's final answer.
//!
//! The model is asked to end its answer with one `<kraken-result>{json}</kraken-result>` block.
//! Everything it says is data: strings are sanitised, sizes are capped, and anything that does
//! not parse degrades to the plain text instead of failing the run.

use std::collections::BTreeSet;

use kraken_proto::{Hex64, sanitize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::host::{CallRecord, HostStats};

/// Opening tag of the result block.
pub const RESULT_OPEN: &str = "<kraken-result>";
/// Closing tag of the result block.
pub const RESULT_CLOSE: &str = "</kraken-result>";

const MAX_ITEMS: usize = 50;
const MAX_TEXT: usize = 2000;

fn clean(s: &str) -> String {
    let s = sanitize(s);
    let s = s.trim();
    if s.chars().count() > MAX_TEXT {
        let cut: String = s.chars().take(MAX_TEXT).collect();
        format!("{cut}...")
    } else {
        s.to_string()
    }
}

fn clean_all(v: Vec<String>) -> Vec<String> {
    v.iter()
        .take(MAX_ITEMS)
        .map(|s| clean(s))
        .filter(|s| !s.is_empty())
        .collect()
}

/// A name the model proposes for what it explained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedName {
    /// The proposed name.
    pub name: String,
    /// Why, in a sentence.
    #[serde(default)]
    pub reason: String,
}

/// Result of `explain_function` and `explain_selection`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// A short plain-language explanation.
    #[serde(default)]
    pub summary: String,
    /// What the code does, one behaviour per entry.
    #[serde(default)]
    pub key_behaviours: Vec<String>,
    /// Names worth considering. Nothing is renamed by an explanation.
    #[serde(default)]
    pub suggested_names: Vec<SuggestedName>,
    /// What the model is unsure about.
    #[serde(default)]
    pub caveats: Vec<String>,
}

/// A main part of the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Short name.
    pub name: String,
    /// What it does.
    #[serde(default)]
    pub description: String,
}

/// A function worth looking at first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterestingFunction {
    /// Address as `0x...`.
    pub address: String,
    /// Name, when known.
    #[serde(default)]
    pub name: Option<String>,
    /// Why it is interesting.
    #[serde(default)]
    pub reason: String,
}

/// Result of `overview`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    /// What the program appears to be, in plain language.
    #[serde(default)]
    pub what_it_is: String,
    /// Its main parts.
    #[serde(default)]
    pub components: Vec<Component>,
    /// Functions to start with.
    #[serde(default)]
    pub interesting_functions: Vec<InterestingFunction>,
    /// What to do next.
    #[serde(default)]
    pub next_steps: Vec<String>,
    /// Information the assistant could not get (a tool this build lacks, no analysis yet, ...).
    /// Filled by KRAKEN, not by the model.
    #[serde(default)]
    pub missing_data: Vec<String>,
}

/// Kind of evidence behind a suggested name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A string the function uses.
    String,
    /// A library function it imports or calls.
    Import,
    /// How its callers use it.
    Caller,
    /// What it calls.
    Callee,
    /// Reading the decompiled code alone.
    Decompile,
    /// Anything else.
    #[serde(other)]
    Other,
}

impl EvidenceKind {
    /// True for kinds that are independent of the code's own text.
    fn is_independent(self) -> bool {
        matches!(
            self,
            EvidenceKind::String
                | EvidenceKind::Import
                | EvidenceKind::Caller
                | EvidenceKind::Callee
        )
    }

    fn label(self) -> &'static str {
        match self {
            EvidenceKind::String => "string",
            EvidenceKind::Import => "import",
            EvidenceKind::Caller => "caller",
            EvidenceKind::Callee => "callee",
            EvidenceKind::Decompile => "decompile",
            EvidenceKind::Other => "other",
        }
    }
}

/// One piece of evidence for a suggestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What kind of evidence.
    pub kind: EvidenceKind,
    /// The specifics (a string, an import name, a caller).
    #[serde(default)]
    pub detail: String,
}

/// How much evidence backs a suggestion. This is an ordinal label from counting independent
/// kinds of evidence; it is not a probability and is not calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// One kind of evidence or less.
    Low,
    /// Two independent kinds agree.
    Medium,
    /// Three or more independent kinds agree.
    High,
}

impl Confidence {
    /// Derives the label from the evidence, plus a sentence saying how.
    pub fn from_evidence(evidence: &[Evidence]) -> (Confidence, String) {
        let kinds: BTreeSet<EvidenceKind> = evidence
            .iter()
            .map(|e| e.kind)
            .filter(|k| k.is_independent())
            .collect();
        let level = match kinds.len() {
            0 | 1 => Confidence::Low,
            2 => Confidence::Medium,
            _ => Confidence::High,
        };
        let basis = if kinds.is_empty() {
            "no independent evidence (strings, imports, callers or callees) was cited".to_string()
        } else {
            let names: Vec<&str> = kinds.iter().map(|k| k.label()).collect();
            format!(
                "{} independent kind(s) of evidence cited: {}",
                kinds.len(),
                names.join(", ")
            )
        };
        (level, basis)
    }
}

/// What happened to a write the assistant attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Applied to the project (can be undone).
    Applied,
    /// Saved while analysis runs; applied when it finishes.
    Queued,
    /// Waiting for the person to accept it.
    Proposed,
    /// The registry refused it.
    Rejected,
    /// Dry run or the write cap: nothing was attempted.
    NotAttempted,
}

/// A suggested name and/or comment for one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameSuggestion {
    /// Function address as `0x...`.
    pub address: String,
    /// The name it has now.
    #[serde(default)]
    pub current_name: Option<String>,
    /// The suggested name.
    #[serde(default)]
    pub new_name: Option<String>,
    /// The suggested comment.
    #[serde(default)]
    pub comment: Option<String>,
    /// The evidence behind it.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Evidence label (derived by KRAKEN from `evidence`, not reported by the model).
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    /// How the label was derived.
    #[serde(default)]
    pub confidence_basis: String,
    /// What happened to the rename.
    #[serde(default)]
    pub rename_outcome: Option<Outcome>,
    /// What happened to the comment.
    #[serde(default)]
    pub comment_outcome: Option<Outcome>,
}

fn default_confidence() -> Confidence {
    Confidence::Low
}

/// Result of `auto_name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoNameReport {
    /// True when nothing was written.
    pub dry_run: bool,
    /// The cap on functions this run was asked to look at.
    pub limit: usize,
    /// One entry per function the model suggested something for.
    pub suggestions: Vec<NameSuggestion>,
    /// Edits applied to the project.
    pub applied: usize,
    /// Edits saved while analysis runs.
    pub queued: usize,
    /// Edits waiting for the person to accept.
    pub proposed: usize,
    /// Edits the registry refused or the cap stopped.
    pub failed: usize,
    /// A reminder of what the confidence labels mean.
    pub note: String,
}

/// The parsed result of a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskOutput {
    /// `explain_function` / `explain_selection`.
    Explanation(Explanation),
    /// `overview`.
    Overview(Overview),
    /// `auto_name`.
    AutoName(AutoNameReport),
}

/// The JSON of the last result block in `text`, and `text` without any result block.
pub fn split_result(text: &str) -> (String, Option<Value>) {
    let mut json: Option<Value> = None;
    let mut prose = String::new();
    let mut rest = text;
    while let Some(start) = rest.find(RESULT_OPEN) {
        prose.push_str(&rest[..start]);
        let after = &rest[start + RESULT_OPEN.len()..];
        match after.find(RESULT_CLOSE) {
            Some(end) => {
                if let Some(v) = parse_json_loose(&after[..end]) {
                    json = Some(v);
                }
                rest = &after[end + RESULT_CLOSE.len()..];
            }
            None => {
                // Unterminated block (output cut off): still try to read it.
                if let Some(v) = parse_json_loose(after) {
                    json = Some(v);
                }
                rest = "";
            }
        }
    }
    prose.push_str(rest);
    (prose.trim().to_string(), json)
}

/// Parses JSON that may be wrapped in a markdown code fence.
fn parse_json_loose(s: &str) -> Option<Value> {
    let t = s.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t);
    let t = t.strip_suffix("```").unwrap_or(t).trim();
    serde_json::from_str(t).ok()
}

/// Parses an explanation; unparseable input yields the prose as the summary.
pub fn parse_explanation(prose: &str, json: Option<Value>) -> (Explanation, Option<String>) {
    let parsed = json.and_then(|v| serde_json::from_value::<Explanation>(v).ok());
    match parsed {
        Some(mut e) => {
            e.summary = clean(&e.summary);
            e.key_behaviours = clean_all(e.key_behaviours);
            e.caveats = clean_all(e.caveats);
            e.suggested_names = e
                .suggested_names
                .into_iter()
                .take(MAX_ITEMS)
                .map(|n| SuggestedName {
                    name: clean(&n.name),
                    reason: clean(&n.reason),
                })
                .filter(|n| !n.name.is_empty())
                .collect();
            (e, None)
        }
        None => (
            Explanation {
                summary: clean(prose),
                ..Explanation::default()
            },
            Some("the answer had no structured result block; showing the text only".into()),
        ),
    }
}

/// Parses an overview.
pub fn parse_overview(prose: &str, json: Option<Value>) -> (Overview, Option<String>) {
    let parsed = json.and_then(|v| serde_json::from_value::<Overview>(v).ok());
    match parsed {
        Some(mut o) => {
            o.what_it_is = clean(&o.what_it_is);
            o.components = o
                .components
                .into_iter()
                .take(MAX_ITEMS)
                .map(|c| Component {
                    name: clean(&c.name),
                    description: clean(&c.description),
                })
                .collect();
            o.interesting_functions = o
                .interesting_functions
                .into_iter()
                .take(MAX_ITEMS)
                .filter(|f| f.address.parse::<Hex64>().is_ok())
                .map(|f| InterestingFunction {
                    address: f.address.trim().to_string(),
                    name: f.name.map(|n| clean(&n)),
                    reason: clean(&f.reason),
                })
                .collect();
            o.next_steps = clean_all(o.next_steps);
            o.missing_data.clear();
            (o, None)
        }
        None => (
            Overview {
                what_it_is: clean(prose),
                ..Overview::default()
            },
            Some("the answer had no structured result block; showing the text only".into()),
        ),
    }
}

/// What the model may say about one function; fields like its own "confidence" are ignored.
#[derive(Deserialize)]
struct RawSuggestion {
    address: String,
    #[serde(default)]
    current_name: Option<String>,
    #[serde(default)]
    new_name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
struct RawAutoName {
    #[serde(default)]
    suggestions: Vec<RawSuggestion>,
}

fn normalise_address(s: &str) -> Option<String> {
    s.trim().parse::<Hex64>().ok().map(|a| a.to_hex())
}

fn outcome_of(rec: &CallRecord) -> Outcome {
    if !rec.ok {
        return if rec.error_code.as_deref() == Some("write_limit") {
            Outcome::NotAttempted
        } else {
            Outcome::Rejected
        };
    }
    match rec.status.as_deref() {
        Some("applied") => Outcome::Applied,
        Some("queued") => Outcome::Queued,
        Some("proposed") => Outcome::Proposed,
        _ => Outcome::Rejected,
    }
}

fn outcome_for(stats: &HostStats, tool: &str, address: &str) -> Option<Outcome> {
    stats
        .calls_to(tool)
        .filter(|c| {
            c.args
                .get("address")
                .and_then(Value::as_str)
                .and_then(normalise_address)
                .as_deref()
                == Some(address)
        })
        .last()
        .map(outcome_of)
}

/// Builds the auto-name report from the model's suggestions and what the host actually did.
pub fn build_autoname(
    json: Option<Value>,
    stats: &HostStats,
    dry_run: bool,
    limit: usize,
) -> (AutoNameReport, Option<String>) {
    let raw = json.and_then(|v| serde_json::from_value::<RawAutoName>(v).ok());
    let warning = raw
        .is_none()
        .then(|| "the answer had no structured result block; no suggestion list".to_string());
    let mut suggestions = Vec::new();
    for s in raw
        .map(|r| r.suggestions)
        .unwrap_or_default()
        .into_iter()
        .take(limit.max(1) * 2)
    {
        let Some(address) = normalise_address(&s.address) else {
            continue;
        };
        let new_name = s.new_name.map(|n| clean(&n)).filter(|n| !n.is_empty());
        let comment = s.comment.map(|c| clean(&c)).filter(|c| !c.is_empty());
        if new_name.is_none() && comment.is_none() {
            continue;
        }
        let evidence: Vec<Evidence> = s
            .evidence
            .into_iter()
            .take(10)
            .map(|e| Evidence {
                kind: e.kind,
                detail: clean(&e.detail),
            })
            .collect();
        let (confidence, confidence_basis) = Confidence::from_evidence(&evidence);
        let (rename_outcome, comment_outcome) = if dry_run {
            (
                new_name.as_ref().map(|_| Outcome::NotAttempted),
                comment.as_ref().map(|_| Outcome::NotAttempted),
            )
        } else {
            (
                new_name.as_ref().map(|_| {
                    outcome_for(stats, "rename_symbol", &address).unwrap_or(Outcome::NotAttempted)
                }),
                comment.as_ref().map(|_| {
                    outcome_for(stats, "set_comment", &address).unwrap_or(Outcome::NotAttempted)
                }),
            )
        };
        suggestions.push(NameSuggestion {
            address,
            current_name: s.current_name.map(|n| clean(&n)),
            new_name,
            comment,
            evidence,
            confidence,
            confidence_basis,
            rename_outcome,
            comment_outcome,
        });
    }
    suggestions.sort_by_key(|a| std::cmp::Reverse(a.confidence));
    let report = AutoNameReport {
        dry_run,
        limit,
        suggestions,
        applied: stats.writes_with_status("applied"),
        queued: stats.writes_with_status("queued"),
        proposed: stats.writes_with_status("proposed"),
        failed: stats.failed_writes(),
        note: "Confidence is a count of independent kinds of evidence (strings, imports, callers, \
               callees) that agree. It is a rough guide for review order, not a probability. \
               Applied edits are logged under the assistant and can be undone."
            .to_string(),
    };
    (report, warning)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(kind: EvidenceKind) -> Evidence {
        Evidence {
            kind,
            detail: String::new(),
        }
    }

    #[test]
    fn splits_the_result_block_from_the_prose() {
        let t = "It reads a file.\n<kraken-result>{\"summary\":\"x\"}</kraken-result>\nBye";
        let (prose, json) = split_result(t);
        assert!(prose.starts_with("It reads a file."));
        assert!(prose.ends_with("Bye"));
        assert!(!prose.contains("kraken-result"));
        assert_eq!(json.unwrap()["summary"], "x");
    }

    #[test]
    fn fenced_and_unterminated_blocks_are_read() {
        let (_, j) = split_result("<kraken-result>\n```json\n{\"a\":1}\n```\n</kraken-result>");
        assert_eq!(j.unwrap()["a"], 1);
        let (_, j) = split_result("text <kraken-result>{\"a\":2}");
        assert_eq!(j.unwrap()["a"], 2);
        let (p, j) = split_result("only prose");
        assert_eq!(p, "only prose");
        assert!(j.is_none());
    }

    #[test]
    fn confidence_counts_independent_kinds_only() {
        use EvidenceKind::*;
        assert_eq!(Confidence::from_evidence(&[]).0, Confidence::Low);
        assert_eq!(
            Confidence::from_evidence(&[ev(Decompile), ev(Decompile)]).0,
            Confidence::Low
        );
        assert_eq!(
            Confidence::from_evidence(&[ev(String), ev(String)]).0,
            Confidence::Low
        );
        assert_eq!(
            Confidence::from_evidence(&[ev(String), ev(Import)]).0,
            Confidence::Medium
        );
        let (c, basis) = Confidence::from_evidence(&[ev(String), ev(Import), ev(Caller)]);
        assert_eq!(c, Confidence::High);
        assert!(basis.contains("3 independent"));
    }

    #[test]
    fn unparseable_explanations_fall_back_to_text() {
        let (e, warn) = parse_explanation("plain words", None);
        assert_eq!(e.summary, "plain words");
        assert!(warn.is_some());
    }

    #[test]
    fn explanation_strings_are_sanitised() {
        let j = json!({"summary": "ok\u{1b}[31mred", "suggested_names": [{"name": "n\u{202e}x"}]});
        let (e, warn) = parse_explanation("", Some(j));
        assert!(warn.is_none());
        assert_eq!(e.summary, "okred");
        assert_eq!(e.suggested_names[0].name, "nx");
    }

    #[test]
    fn autoname_ignores_model_confidence_and_bad_addresses() {
        let j = json!({"suggestions": [
            {"address": "0x401000", "new_name": "parse_args", "confidence": "high",
             "evidence": [{"kind": "string", "detail": "usage:"}]},
            {"address": "not-an-address", "new_name": "x"},
            {"address": "0x401040"}
        ]});
        let (r, warn) = build_autoname(Some(j), &HostStats::default(), true, 5);
        assert!(warn.is_none());
        assert_eq!(r.suggestions.len(), 1);
        assert_eq!(r.suggestions[0].confidence, Confidence::Low);
        assert_eq!(r.suggestions[0].rename_outcome, Some(Outcome::NotAttempted));
    }
}
