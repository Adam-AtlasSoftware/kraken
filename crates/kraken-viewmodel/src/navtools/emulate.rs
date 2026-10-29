//! Running the program in the emulator: the Run dialog (`emulate_run` and `emulate_compare`) and
//! the Emulation tab that shows what a run or a comparison found.
//!
//! A run changes nothing in the project; it is a query that happens in the sandboxed emulator,
//! so none of this asks for approval.

use kraken_registry::commands::{EmulateCompareOut, EmulateRunOut};
use serde_json::{Value, json};

use super::NavTab;
use crate::errors::plain_error;
use crate::rewrite::{DiffLine, line_diff, split_args};
use crate::vm::{ViewModel, parse};

/// Largest file offered as an input, in bytes (matches the registry).
pub const MAX_INPUT_FILE: usize = 1 << 20;

/// What the dialog will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulateMode {
    /// The program as it is on disk.
    Run,
    /// A copy with the project's byte patches applied.
    RunPatched,
    /// Both, with the same input, side by side.
    Compare,
}

impl EmulateMode {
    /// The dialog's title.
    pub fn title(self) -> &'static str {
        match self {
            EmulateMode::Run => "Run the program",
            EmulateMode::RunPatched => "Run the patched program",
            EmulateMode::Compare => "Compare original and patched",
        }
    }

    /// The button that starts it.
    pub fn button(self) -> &'static str {
        match self {
            EmulateMode::Run | EmulateMode::RunPatched => "Run",
            EmulateMode::Compare => "Run both and compare",
        }
    }
}

/// A file put into the program's `/work` before it starts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputRow {
    /// The path inside `/work`.
    pub name: String,
    /// The contents typed or read as text.
    pub text: String,
    /// The contents when the file read from disk is not text.
    pub binary: Option<Vec<u8>>,
}

impl InputRow {
    /// A row read from `path` on disk.
    pub fn from_disk(path: &std::path::Path) -> Result<InputRow, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if data.len() > MAX_INPUT_FILE {
            return Err(format!(
                "{} is larger than {} KiB, the most a run takes as an input file.",
                path.display(),
                MAX_INPUT_FILE / 1024
            ));
        }
        let name = path
            .file_name()
            .map_or_else(|| "input".to_string(), |n| n.to_string_lossy().into_owned());
        Ok(match String::from_utf8(data) {
            Ok(text) => InputRow {
                name,
                text,
                binary: None,
            },
            Err(e) => InputRow {
                name,
                text: String::new(),
                binary: Some(e.into_bytes()),
            },
        })
    }

    fn json(&self) -> Value {
        match &self.binary {
            Some(b) => {
                let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
                json!({"name": self.name.trim(), "hex": hex})
            }
            None => json!({"name": self.name.trim(), "text": self.text}),
        }
    }
}

/// The dialog that sets up a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulateDialog {
    /// What it will run.
    pub mode: EmulateMode,
    /// Arguments after the program name, typed as on a command line.
    pub argv: String,
    /// What the program sees as its own name; empty for the default.
    pub argv0: String,
    /// Standard input.
    pub stdin: String,
    /// Environment variables, one `NAME=value` per line.
    pub env: String,
    /// Files seeded into `/work`.
    pub inputs: Vec<InputRow>,
    /// Instruction budget as typed; empty for the default.
    pub max_steps: String,
    /// Time limit in seconds as typed; empty for the default.
    pub timeout: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// The run is in progress.
    pub running: bool,
}

impl EmulateDialog {
    fn new(mode: EmulateMode) -> Self {
        EmulateDialog {
            mode,
            argv: String::new(),
            argv0: String::new(),
            stdin: String::new(),
            env: String::new(),
            inputs: Vec::new(),
            max_steps: String::new(),
            timeout: String::new(),
            error: None,
            running: false,
        }
    }

    /// The arguments shared by `emulate_run` and `emulate_compare`, or what is wrong.
    pub fn base_args(&self) -> Result<serde_json::Map<String, Value>, String> {
        let mut m = serde_json::Map::new();
        let argv = split_args(&self.argv)?;
        if !argv.is_empty() {
            m.insert("argv".into(), json!(argv));
        }
        if !self.stdin.is_empty() {
            m.insert("stdin".into(), json!(self.stdin));
        }
        if !self.argv0.trim().is_empty() {
            m.insert("argv0".into(), json!(self.argv0.trim()));
        }
        let mut env = serde_json::Map::new();
        for (n, line) in self.env.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(format!(
                    "Environment line {} needs the form NAME=value.",
                    n + 1
                ));
            };
            env.insert(k.trim().to_string(), json!(v));
        }
        if !env.is_empty() {
            m.insert("env".into(), Value::Object(env));
        }
        let inputs: Vec<Value> = self.inputs.iter().map(InputRow::json).collect();
        if !inputs.is_empty() {
            m.insert("inputs".into(), json!(inputs));
        }
        if !self.max_steps.trim().is_empty() {
            let steps: u64 = self
                .max_steps
                .trim()
                .replace('_', "")
                .parse()
                .map_err(|_| "The step limit must be a whole number.".to_string())?;
            m.insert("max_steps".into(), json!(steps));
        }
        if !self.timeout.trim().is_empty() {
            let secs: u64 = self
                .timeout
                .trim()
                .parse()
                .map_err(|_| "The time limit must be a whole number of seconds.".to_string())?;
            m.insert("timeout_seconds".into(), json!(secs));
        }
        Ok(m)
    }

    /// One line saying what the run was given, for the results.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.argv.trim().is_empty() {
            parts.push(format!("arguments {}", self.argv.trim()));
        }
        if !self.stdin.is_empty() {
            parts.push(format!("{} bytes of input", self.stdin.len()));
        }
        let env = self.env.lines().filter(|l| !l.trim().is_empty()).count();
        if env > 0 {
            parts.push(format!("{env} environment variable{}", plural(env)));
        }
        if !self.inputs.is_empty() {
            parts.push(format!(
                "{} input file{}",
                self.inputs.len(),
                plural(self.inputs.len())
            ));
        }
        if parts.is_empty() {
            "no arguments and no input".to_string()
        } else {
            parts.join(", ")
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// A file the program wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDetail {
    /// The path inside `/work`.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// The start of it: text, or hex for binary data.
    pub preview: String,
    /// True when the preview is hex.
    pub binary: bool,
}

/// One finished run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDetail {
    /// How it ended, in words ("exit code 0").
    pub exit: String,
    /// True when it ended with exit code 0.
    pub clean: bool,
    /// Standard output (program data).
    pub stdout: String,
    /// Standard error (program data).
    pub stderr: String,
    /// Instructions executed.
    pub steps: u64,
    /// The emulator's notes.
    pub notes: Vec<String>,
    /// Files the program wrote.
    pub files: Vec<FileDetail>,
    /// An output stream was cut.
    pub truncated: bool,
}

impl From<EmulateRunOut> for RunDetail {
    fn from(o: EmulateRunOut) -> Self {
        use kraken_registry::commands::EmulateExitKind as K;
        let exit = match (o.exit.kind, o.exit.value) {
            (K::Code, Some(v)) => format!("exit code {v}"),
            (K::Signal, Some(v)) => format!("signal {v}"),
            (K::Timeout, _) => "ran out of time".into(),
            (K::StepLimit, _) => "ran out of instructions".into(),
            (K::Unsupported, _) => "needs something the emulator lacks".into(),
            (K::Code | K::Signal, None) => "ended".into(),
        };
        RunDetail {
            clean: o.exit.kind == K::Code && o.exit.value == Some(0),
            exit,
            stdout: o.stdout.0,
            stderr: o.stderr.0,
            steps: o.steps,
            notes: o.notes,
            truncated: o.truncated,
            files: o
                .files
                .into_iter()
                .map(|f| FileDetail {
                    name: f.name,
                    size: f.size,
                    preview: f.preview.0,
                    binary: f.binary,
                })
                .collect(),
        }
    }
}

impl RunDetail {
    /// The output streams as line diffs against `other`: (stdout, stderr).
    pub fn diffs(&self, other: &RunDetail) -> (Vec<DiffLine>, Vec<DiffLine>) {
        (
            line_diff(&self.stdout, &other.stdout),
            line_diff(&self.stderr, &other.stderr),
        )
    }
}

/// One way two runs differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// `exit`, `stdout`, `stderr` or `file <name>`.
    pub field: String,
    /// What differs.
    pub summary: String,
}

/// What the Emulation tab shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationResult {
    /// One function called.
    Call(Box<super::CallDetail>),
    /// One run.
    Run {
        /// True for the patched copy.
        patched: bool,
        /// What it was given.
        given: String,
        /// How it went.
        run: Box<RunDetail>,
    },
    /// Two runs with the same input.
    Compare {
        /// What both were given.
        given: String,
        /// The original.
        a: Box<RunDetail>,
        /// The patched copy.
        b: Box<RunDetail>,
        /// Everything agrees.
        same: bool,
        /// Every difference.
        differences: Vec<Difference>,
        /// The first place they diverge.
        first_divergence: String,
    },
}

/// State of the Emulation tab.
#[derive(Debug, Clone, Default)]
pub struct EmulationPanel {
    /// A run is in progress.
    pub running: bool,
    /// What it is doing, while it runs.
    pub doing: String,
    /// The last result.
    pub result: Option<EmulationResult>,
    /// Why the last run failed outside the dialog.
    pub error: Option<String>,
}

impl ViewModel {
    /// Opens the Run dialog in `mode`, keeping what was typed last time.
    pub fn begin_emulate(&mut self, mode: EmulateMode) {
        if self.tools.emulate_dialog.is_none() {
            self.tools.emulate_dialog = Some(EmulateDialog::new(mode));
        } else if let Some(d) = self.tools.emulate_dialog.as_mut() {
            d.mode = mode;
        }
        if let Some(d) = self.tools.emulate_dialog.as_mut() {
            d.error = None;
        }
    }

    /// Closes the dialog.
    pub fn cancel_emulate(&mut self) {
        if self
            .tools
            .emulate_dialog
            .as_ref()
            .is_some_and(|d| d.running)
        {
            return;
        }
        self.tools.emulate_dialog = None;
    }

    /// Starts the run (or the comparison) the dialog describes.
    pub fn submit_emulate(&mut self) {
        let Some(d) = self.tools.emulate_dialog.as_mut().filter(|d| !d.running) else {
            return;
        };
        let mut args = match d.base_args() {
            Ok(a) => a,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.error = None;
        d.running = true;
        let (mode, given) = (d.mode, d.summary());
        let command = match mode {
            EmulateMode::Run | EmulateMode::RunPatched => {
                args.insert("patched".into(), json!(mode == EmulateMode::RunPatched));
                args.insert("return_files".into(), json!(true));
                "emulate_run"
            }
            EmulateMode::Compare => "emulate_compare",
        };
        self.tools.emulation.running = true;
        self.tools.emulation.doing = match mode {
            EmulateMode::Run => "Running the program".into(),
            EmulateMode::RunPatched => "Running the patched program".into(),
            EmulateMode::Compare => "Running the original and the patched program".into(),
        };
        self.call(command, Value::Object(args), move |vm, res| {
            vm.tools.emulation.running = false;
            let outcome = res.and_then(|v| accept(mode, given, v)).map_err(|e| {
                if e.message.contains("no byte patches") {
                    "The project has no byte patches yet. Stage one in the Patches tab, then \
                         compare."
                        .to_string()
                } else {
                    plain_error(&e)
                }
            });
            match outcome {
                Ok(result) => {
                    vm.tools.emulate_dialog = None;
                    vm.tools.emulation.error = None;
                    vm.tools.emulation.result = Some(result);
                    vm.tools.request_tab(NavTab::Emulation);
                }
                Err(e) => match vm.tools.emulate_dialog.as_mut() {
                    Some(d) => {
                        d.running = false;
                        d.error = Some(e);
                    }
                    None => vm.tools.emulation.error = Some(e),
                },
            }
        });
    }

    /// Compares the original and the patched program with no arguments and no input, and shows
    /// the Emulation tab (used after staging patches from an edit of the decompiled code).
    pub fn compare_patched_now(&mut self) {
        let mut d = EmulateDialog::new(EmulateMode::Compare);
        d.argv.clear();
        self.tools.emulate_dialog = Some(d);
        self.submit_emulate();
    }

    /// Shows the Emulation tab.
    pub fn show_emulation(&mut self) {
        self.tools.request_tab(NavTab::Emulation);
    }
}

fn accept(
    mode: EmulateMode,
    given: String,
    v: Value,
) -> Result<EmulationResult, kraken_proto::ProtoError> {
    Ok(match mode {
        EmulateMode::Run | EmulateMode::RunPatched => EmulationResult::Run {
            patched: mode == EmulateMode::RunPatched,
            given,
            run: Box::new(parse::<EmulateRunOut>(v)?.into()),
        },
        EmulateMode::Compare => {
            let c = parse::<EmulateCompareOut>(v)?;
            EmulationResult::Compare {
                given,
                a: Box::new(c.a.into()),
                b: Box::new(c.b.into()),
                same: c.same,
                differences: c
                    .differences
                    .into_iter()
                    .map(|d| Difference {
                        field: d.field,
                        summary: d.summary.0,
                    })
                    .collect(),
                first_divergence: c.first_divergence.0,
            }
        }
    })
}

/// One row of a side-by-side comparison of two outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideRow {
    /// The line of the first run, when it has one here.
    pub left: Option<String>,
    /// The line of the second run, when it has one here.
    pub right: Option<String>,
    /// The two sides differ on this row.
    pub changed: bool,
}

/// Lays a line diff out in two columns: lines both runs printed are shared, a run of lines only
/// one side printed is paired with the other side's run, row by row.
pub fn side_by_side(diff: &[DiffLine]) -> Vec<SideRow> {
    use crate::rewrite::DiffKind;
    let mut rows = Vec::new();
    let (mut gone, mut came): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    let flush = |rows: &mut Vec<SideRow>, gone: &mut Vec<&str>, came: &mut Vec<&str>| {
        for i in 0..gone.len().max(came.len()) {
            rows.push(SideRow {
                left: gone.get(i).map(|s| (*s).to_string()),
                right: came.get(i).map(|s| (*s).to_string()),
                changed: true,
            });
        }
        gone.clear();
        came.clear();
    };
    for l in diff {
        match l.kind {
            DiffKind::Same => {
                flush(&mut rows, &mut gone, &mut came);
                rows.push(SideRow {
                    left: Some(l.text.clone()),
                    right: Some(l.text.clone()),
                    changed: false,
                });
            }
            DiffKind::Original => gone.push(&l.text),
            DiffKind::Rewritten => came.push(&l.text),
        }
    }
    flush(&mut rows, &mut gone, &mut came);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_line_is_paired_across_the_two_columns() {
        let rows = side_by_side(&line_diff("a\nhash=1\nz", "a\nHASH=1\nz"));
        assert_eq!(rows.len(), 3);
        assert!(!rows[0].changed && !rows[2].changed);
        assert_eq!(
            (rows[1].left.as_deref(), rows[1].right.as_deref()),
            (Some("hash=1"), Some("HASH=1"))
        );
        assert!(rows[1].changed);
        let longer = side_by_side(&line_diff("a", "a\nb\nc"));
        assert_eq!(longer.iter().filter(|r| r.changed).count(), 2);
        assert!(longer[1].left.is_none());
    }

    #[test]
    fn the_dialog_builds_the_arguments_and_names_what_is_wrong() {
        let mut d = EmulateDialog::new(EmulateMode::Run);
        d.argv = "-v 'two words'".into();
        d.stdin = "hi\n".into();
        d.env = "MODE=fast\n\nA=b=c".into();
        d.inputs.push(InputRow {
            name: "in.txt".into(),
            text: "x".into(),
            binary: None,
        });
        d.inputs.push(InputRow {
            name: "b.bin".into(),
            text: String::new(),
            binary: Some(vec![0, 255]),
        });
        d.max_steps = "1_000".into();
        d.timeout = "5".into();
        let a = Value::Object(d.base_args().expect("valid"));
        assert_eq!(a["argv"], json!(["-v", "two words"]));
        assert_eq!(a["env"], json!({"MODE": "fast", "A": "b=c"}));
        assert_eq!(a["inputs"][1], json!({"name": "b.bin", "hex": "00ff"}));
        assert_eq!(
            (a["max_steps"].clone(), a["timeout_seconds"].clone()),
            (json!(1000), json!(5))
        );
        assert!(d.summary().contains("2 input files"), "{}", d.summary());
        d.env = "no equals sign".into();
        assert!(d.base_args().expect_err("bad env").contains("line 1"));
        d.env.clear();
        d.timeout = "soon".into();
        assert!(d.base_args().is_err());
    }
}
