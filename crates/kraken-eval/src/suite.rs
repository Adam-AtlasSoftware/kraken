//! Task suites: what is asked, and the ground truth the answers are scored against.
//!
//! A suite is a JSON file (the built-in one is `data/corpus.json`). Each task names a corpus
//! binary and a kind:
//!
//! - `name_functions`: name stripped functions; the truth is the DWARF name of the unstripped twin.
//! - `find_function`: find the function that does something; the truth is a function of the truth
//!   file, and an answer is right when its address lies inside that function.
//! - `question`: a question about the binary's strings or imports with a yes/no, set or text
//!   answer.
//!
//! The truth for names and function bodies comes from the truth files; the truth of the other
//! questions is written in the suite and [`Suite::validate`] checks it against the recorded
//! fixtures, so the two cannot drift apart unnoticed.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::corpus::{Corpus, Truth, engine_address};
use crate::error::EvalError;

const BUILTIN: &str = include_str!("../data/corpus.json");

/// Functions shorter than this are left out of naming tasks: a four-instruction stub says too
/// little to name.
const MIN_NAMED_SIZE: u64 = 40;
const DEFAULT_SAMPLE: usize = 8;

/// What a task asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Name stripped functions.
    NameFunctions,
    /// Find the function that does something.
    FindFunction,
    /// Answer a question about strings or imports.
    Question,
}

impl Kind {
    /// The name used in suites and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::NameFunctions => "name_functions",
            Kind::FindFunction => "find_function",
            Kind::Question => "question",
        }
    }
}

/// The expected answer of a `find_function` or `question` task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Expect {
    /// The function with this truth name.
    Function {
        /// Name in the truth file.
        name: String,
    },
    /// Yes or no.
    YesNo {
        /// The right answer.
        value: bool,
    },
    /// A set of names.
    Set {
        /// The members.
        items: Vec<String>,
    },
    /// A piece of text (a format string, say).
    Text {
        /// The right text; a newline is a real newline here.
        text: String,
    },
}

/// Facts about the fixture an expectation is checked against by [`Suite::validate`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// The imports contain this name exactly when the expected `yes_no` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports_contain: Option<String>,
    /// The expected `set` is every import whose name does not start with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports_without_prefix: Option<String>,
    /// This string is among the binary's strings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
}

/// One task of a suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDef {
    /// Unique id, such as `find/vm-interpreter`.
    pub id: String,
    /// What it asks for.
    pub kind: Kind,
    /// Corpus binary, such as `switch_vm-O0-stripped`.
    pub binary: String,
    /// The question, for `find_function` and `question`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    /// For `name_functions`: most functions to ask about (default 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<usize>,
    /// The expected answer, for `find_function` and `question`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expect>,
    /// How [`Suite::validate`] checks `expect`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Check>,
}

/// A suite of tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suite {
    /// Format version (1).
    pub version: u32,
    /// Suite name.
    pub name: String,
    /// The tasks, in run order.
    pub tasks: Vec<TaskDef>,
}

/// One function to name, with its truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameTruth {
    /// Entry address in the engine's terms.
    pub address: u64,
    /// The DWARF name.
    pub name: String,
}

/// What a resolved task is scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Expected {
    /// Names for these functions.
    Names {
        /// The functions and their truth names.
        functions: Vec<NameTruth>,
    },
    /// An address inside this function.
    Function {
        /// Truth name.
        name: String,
        /// Entry address in the engine's terms.
        start: u64,
        /// Size in bytes.
        size: u64,
    },
    /// Yes or no.
    YesNo {
        /// The right answer.
        value: bool,
    },
    /// A set of names.
    Set {
        /// The members.
        items: Vec<String>,
    },
    /// A piece of text.
    Text {
        /// The right text.
        text: String,
    },
}

/// A task with addresses worked out for one engine, ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTask {
    /// Task id.
    pub id: String,
    /// Task kind.
    pub kind: Kind,
    /// Corpus binary.
    pub binary: String,
    /// The user message (starts with `<kraken-eval id="...">`).
    pub goal: String,
    /// Trusted instructions appended to the system prompt: the answer format.
    pub instructions: String,
    /// What the answer is scored against.
    pub expected: Expected,
}

impl Suite {
    /// The built-in suite over the corpus.
    pub fn builtin() -> Suite {
        // The file is compiled in and covered by tests.
        serde_json::from_str(BUILTIN).unwrap_or(Suite {
            version: 1,
            name: "corpus".into(),
            tasks: Vec::new(),
        })
    }

    /// Reads a suite from a JSON file.
    pub fn from_path(path: &Path) -> Result<Suite, EvalError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| EvalError::Suite(format!("{}: {e}", path.display())))?;
        let suite: Suite = serde_json::from_str(&text)
            .map_err(|e| EvalError::Suite(format!("{}: {e}", path.display())))?;
        suite.check_shape()?;
        Ok(suite)
    }

    /// The distinct binaries, in order of first use.
    pub fn binaries(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in &self.tasks {
            if !out.contains(&t.binary) {
                out.push(t.binary.clone());
            }
        }
        out
    }

    /// Structural checks that need no corpus: unique ids, an expectation where one is needed.
    pub fn check_shape(&self) -> Result<(), EvalError> {
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.tasks {
            if !seen.insert(t.id.as_str()) {
                return Err(EvalError::Suite(format!("duplicate task id `{}`", t.id)));
            }
            if t.id.trim().is_empty()
                || t.id
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')))
            {
                return Err(EvalError::Suite(format!(
                    "task id `{}` may only use letters, digits and / - _ .",
                    t.id
                )));
            }
            match (t.kind, &t.expect) {
                (Kind::NameFunctions, _) => {
                    if !t.binary.ends_with("-stripped") {
                        return Err(EvalError::Suite(format!(
                            "`{}`: names are only a test on a stripped binary, not `{}`",
                            t.id, t.binary
                        )));
                    }
                }
                (Kind::FindFunction, Some(Expect::Function { .. })) => {}
                (Kind::FindFunction, _) => {
                    return Err(EvalError::Suite(format!(
                        "`{}`: a find_function task expects a function",
                        t.id
                    )));
                }
                (Kind::Question, Some(Expect::Function { .. }) | None) => {
                    return Err(EvalError::Suite(format!(
                        "`{}`: a question expects yes_no, set or text",
                        t.id
                    )));
                }
                (Kind::Question, Some(_)) => {}
            }
            if t.kind != Kind::NameFunctions && t.question.as_deref().is_none_or(str::is_empty) {
                return Err(EvalError::Suite(format!("`{}` has no question", t.id)));
            }
        }
        Ok(())
    }

    /// Checks every task against the corpus: the files exist, truth functions exist, and the
    /// expectations about strings and imports agree with the recorded fixtures.
    pub fn validate(&self, corpus: &Corpus) -> Result<(), EvalError> {
        self.check_shape()?;
        for t in &self.tasks {
            let bad = |m: String| EvalError::Suite(format!("`{}`: {m}", t.id));
            if !corpus.binary(&t.binary).is_file() {
                return Err(bad(format!("no binary {}", t.binary)));
            }
            let truth = corpus.truth(&t.binary)?;
            let fixture = corpus.fixture(&t.binary)?;
            if let Some(Expect::Function { name }) = &t.expect
                && !truth.functions.iter().any(|f| &f.name == name)
            {
                return Err(bad(format!("`{name}` is not a function of the truth file")));
            }
            let Some(check) = &t.check else { continue };
            let imports: Vec<&str> = fixture
                .imports
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|s| s.name.as_str())
                .collect();
            if let Some(name) = &check.imports_contain {
                let Some(Expect::YesNo { value }) = &t.expect else {
                    return Err(bad("imports_contain needs a yes_no expectation".into()));
                };
                if imports.contains(&name.as_str()) != *value {
                    return Err(bad(format!(
                        "the fixture's imports disagree about `{name}` (expected {value})"
                    )));
                }
            }
            if let Some(prefix) = &check.imports_without_prefix {
                let Some(Expect::Set { items }) = &t.expect else {
                    return Err(bad("imports_without_prefix needs a set expectation".into()));
                };
                let mut derived: Vec<&str> = imports
                    .iter()
                    .copied()
                    .filter(|n| !n.starts_with(prefix.as_str()))
                    .collect();
                derived.sort_unstable();
                derived.dedup();
                let mut want: Vec<&str> = items.iter().map(String::as_str).collect();
                want.sort_unstable();
                if derived != want {
                    return Err(bad(format!(
                        "the fixture's imports give {derived:?}, the suite says {want:?}"
                    )));
                }
            }
            if let Some(s) = &check.string
                && !fixture
                    .strings
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|e| &e.value == s)
            {
                return Err(bad(format!("the fixture has no string {s:?}")));
            }
        }
        Ok(())
    }
}

impl TaskDef {
    /// Works out the addresses for an engine that loads the binary at `base`.
    pub fn resolve(&self, truth: &Truth, base: u64) -> Result<ResolvedTask, EvalError> {
        let bad = |m: String| EvalError::Suite(format!("`{}`: {m}", self.id));
        let expected = match (&self.kind, &self.expect) {
            (Kind::NameFunctions, _) => {
                let n = self.sample.unwrap_or(DEFAULT_SAMPLE).max(1);
                let functions: Vec<NameTruth> = truth
                    .functions
                    .iter()
                    .filter(|f| f.size >= MIN_NAMED_SIZE)
                    .take(n)
                    .map(|f| NameTruth {
                        address: engine_address(f.entry, base),
                        name: f.name.clone(),
                    })
                    .collect();
                if functions.is_empty() {
                    return Err(bad(
                        "the truth file has no function big enough to name".into()
                    ));
                }
                Expected::Names { functions }
            }
            (_, Some(Expect::Function { name })) => {
                let f = truth
                    .functions
                    .iter()
                    .find(|f| &f.name == name)
                    .ok_or_else(|| bad(format!("`{name}` is not in the truth file")))?;
                Expected::Function {
                    name: f.name.clone(),
                    start: engine_address(f.entry, base),
                    size: f.size,
                }
            }
            (_, Some(Expect::YesNo { value })) => Expected::YesNo { value: *value },
            (_, Some(Expect::Set { items })) => Expected::Set {
                items: items.clone(),
            },
            (_, Some(Expect::Text { text })) => Expected::Text { text: text.clone() },
            (_, None) => return Err(bad("no expected answer".into())),
        };
        Ok(ResolvedTask {
            id: self.id.clone(),
            kind: self.kind,
            binary: self.binary.clone(),
            goal: crate::prompt::goal(self, &expected),
            instructions: crate::prompt::instructions(&expected),
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_suite_is_well_formed() {
        let s = Suite::builtin();
        assert!(s.tasks.len() >= 20, "{} tasks", s.tasks.len());
        s.check_shape().expect("shape");
        for kind in [Kind::NameFunctions, Kind::FindFunction, Kind::Question] {
            assert!(s.tasks.iter().any(|t| t.kind == kind), "{kind:?}");
        }
        assert_eq!(s.binaries().len(), 4);
    }

    #[test]
    fn the_builtin_suite_agrees_with_the_corpus() {
        let corpus = Corpus::locate(None, None).expect("corpus");
        Suite::builtin().validate(&corpus).expect("valid");
    }

    #[test]
    fn a_bad_suite_is_refused() {
        let mut s = Suite::builtin();
        s.tasks.push(s.tasks[0].clone());
        assert!(s.check_shape().is_err());
        let mut s = Suite::builtin();
        s.tasks[0].id = "has space".into();
        assert!(s.check_shape().is_err());
        let mut s = Suite::builtin();
        let q = s
            .tasks
            .iter_mut()
            .find(|t| t.kind == Kind::FindFunction)
            .expect("find task");
        q.expect = Some(Expect::YesNo { value: true });
        assert!(s.check_shape().is_err());
    }

    #[test]
    fn a_wrong_truth_is_caught_against_the_fixture() {
        let corpus = Corpus::locate(None, None).expect("corpus");
        let mut s = Suite::builtin();
        let t = s
            .tasks
            .iter_mut()
            .find(|t| {
                t.check
                    .as_ref()
                    .is_some_and(|c| c.imports_contain.is_some())
            })
            .expect("an imports task");
        if let Some(Expect::YesNo { value }) = &mut t.expect {
            *value = !*value;
        }
        assert!(s.validate(&corpus).is_err());
    }

    #[test]
    fn naming_tasks_skip_tiny_functions_and_rebase_pie_addresses() {
        let corpus = Corpus::locate(None, None).expect("corpus");
        let s = Suite::builtin();
        let def = s
            .tasks
            .iter()
            .find(|t| t.id == "name/switch_vm")
            .expect("task");
        let truth = corpus.truth(&def.binary).expect("truth");
        let r = def.resolve(&truth, 0x10_0000).expect("resolve");
        let Expected::Names { functions } = &r.expected else {
            panic!("names")
        };
        assert!(functions.iter().all(|f| f.address >= 0x10_0000));
        assert!(functions.iter().any(|f| f.name == "vm_run"));
        assert!(r.goal.starts_with("<kraken-eval id=\"name/switch_vm\""));
        assert!(
            !r.goal.contains("vm_run"),
            "the truth must not leak into the prompt"
        );
    }
}
