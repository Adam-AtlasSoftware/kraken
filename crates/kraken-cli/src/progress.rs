//! Progress of opening a project and of analysis jobs on stderr: one rewritten line with a bar
//! on a terminal, plain lines otherwise (every new stage, then at most one every few seconds).

use std::io::Write;
use std::time::{Duration, Instant};

use kraken_proto::OpenProgress;

use crate::app::emit;

/// Least time between two plain lines of the same stage.
const PLAIN_EVERY: Duration = Duration::from_secs(5);
/// An open that is done sooner than this prints no plain lines at all.
const PLAIN_AFTER_MS: u64 = 2000;
/// ...and draws no bar.
const BAR_AFTER_MS: u64 = 300;
/// Width of the bar in characters.
const BAR: usize = 24;

/// Draws progress reports.
pub(crate) struct ProgressPrinter {
    tty: bool,
    stage: Option<String>,
    printed: Option<Instant>,
    in_line: bool,
    started: Instant,
}

/// `12,410`: a count as people read it.
pub(crate) fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `1:05`, `1:02:03`.
pub(crate) fn clock(ms: u64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// `[#########---------------]  37%`, or a moving block when the share is not known.
fn bar(fraction: Option<f64>, elapsed_ms: u64) -> String {
    match fraction {
        Some(f) => {
            let f = f.clamp(0.0, 1.0);
            let filled = ((f * BAR as f64).round() as usize).min(BAR);
            format!(
                "[{}{}] {:>3}%",
                "#".repeat(filled),
                "-".repeat(BAR - filled),
                (f * 100.0).floor() as u64
            )
        }
        None => {
            let pos = ((elapsed_ms / 150) as usize) % (2 * (BAR - 4));
            let at = if pos < BAR - 4 {
                pos
            } else {
                2 * (BAR - 4) - pos
            };
            format!("[{}####{}]  ..", "-".repeat(at), "-".repeat(BAR - 4 - at))
        }
    }
}

/// What an open report says in words: the stage and its counts.
pub(crate) fn open_text(p: &OpenProgress) -> String {
    let label = p.stage.label();
    let mut text = label.to_string();
    if let Some(found) = p.found {
        text.push_str(&format!(": {} functions found", count(found)));
        if let Some(q) = p.queued.filter(|q| *q > 0) {
            text.push_str(&format!(", {} to look at", count(q)));
        }
    } else if p.message.starts_with(label) {
        text.clone_from(&p.message);
    } else if !p.message.is_empty() {
        text.push_str(": ");
        text.push_str(&p.message);
    }
    if p.from_cache {
        text.push_str(" (saved results)");
    }
    text
}

impl ProgressPrinter {
    /// A printer for stderr; `tty` draws a rewritten bar.
    pub(crate) fn new(tty: bool) -> Self {
        ProgressPrinter {
            tty,
            stage: None,
            printed: None,
            in_line: false,
            started: Instant::now(),
        }
    }

    /// Shows one report of an open.
    pub(crate) fn open(&mut self, p: &OpenProgress, err: &mut dyn Write) {
        let name = p.stage.as_str().to_string();
        let text = open_text(p);
        let line = format!(
            "{} {}  {}",
            bar(p.fraction, p.elapsed_ms),
            clock(p.elapsed_ms),
            text
        );
        let plain = format!("[{}] {text}", clock(p.elapsed_ms));
        let quiet = if self.tty {
            BAR_AFTER_MS
        } else {
            PLAIN_AFTER_MS
        };
        if p.elapsed_ms < quiet {
            return;
        }
        self.show(&name, &line, &plain, true, err);
    }

    /// Shows one report of a job: its phase, `done` of `total` and the message.
    pub(crate) fn job(
        &mut self,
        phase: &str,
        done: u64,
        total: u64,
        message: &str,
        err: &mut dyn Write,
    ) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fraction = (total > 0).then(|| done as f64 / total as f64);
        let counts = if total > 0 {
            format!("{} of {}", count(done), count(total))
        } else {
            String::new()
        };
        let text = [phase, counts.as_str(), message]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("  ");
        let line = format!("{} {}  {text}", bar(fraction, elapsed), clock(elapsed));
        // the plain form keeps the format scripts already read
        let plain = format!("[{phase}] {done}/{total} {message}");
        self.show(phase, &line, &plain, false, err);
    }

    /// `throttle` keeps plain output to one line per stage plus one every [`PLAIN_EVERY`].
    fn show(&mut self, stage: &str, line: &str, plain: &str, throttle: bool, err: &mut dyn Write) {
        let new_stage = self.stage.as_deref() != Some(stage);
        if self.tty {
            if new_stage && self.in_line {
                emit(err, "\n");
            }
            // a terminal line is rewritten in place; keep it short enough not to wrap
            let shown: String = line.chars().take(118).collect();
            emit(err, &format!("\r{shown:<118}"));
            let _ = err.flush();
            self.in_line = true;
        } else if !throttle || new_stage || self.printed.is_none_or(|t| t.elapsed() >= PLAIN_EVERY)
        {
            emit(err, &format!("{plain}\n"));
            self.printed = Some(Instant::now());
        }
        self.stage = Some(stage.to_string());
    }

    /// Ends the rewritten line, so what follows starts on a fresh one.
    pub(crate) fn finish(&mut self, err: &mut dyn Write) {
        if self.in_line {
            emit(err, "\n");
            self.in_line = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{OpenPlan, OpenStage};

    fn report(stage: OpenStage, fraction: Option<f64>, found: Option<u64>) -> OpenProgress {
        OpenProgress {
            command: "project_create".into(),
            program: "a".into(),
            job_id: None,
            engine: Some("native".into()),
            stages: OpenPlan::for_engine(Some("native")).stages(),
            stage,
            fraction,
            stage_fraction: None,
            found,
            queued: found.map(|_| 2300),
            covered_bytes: None,
            code_bytes: None,
            from_cache: false,
            message: "m".into(),
            elapsed_ms: 83_000,
        }
    }

    #[test]
    fn plain_output_has_a_line_per_stage() {
        let mut out = Vec::new();
        let mut p = ProgressPrinter::new(false);
        let mut quick = report(OpenStage::Ready, Some(1.0), None);
        quick.elapsed_ms = 10;
        p.open(&quick, &mut out);
        assert!(out.is_empty(), "a quick open prints nothing");
        p.open(&report(OpenStage::Prepare, None, None), &mut out);
        p.open(
            &report(OpenStage::Functions, Some(0.4), Some(12_410)),
            &mut out,
        );
        p.open(
            &report(OpenStage::Functions, Some(0.5), Some(12_500)),
            &mut out,
        );
        p.finish(&mut out);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0], "[1:23] Checking the file: m");
        assert_eq!(
            lines[1],
            "[1:23] Finding functions: 12,410 functions found, 2,300 to look at"
        );
    }

    #[test]
    fn a_terminal_gets_a_bar() {
        let mut out = Vec::new();
        let mut p = ProgressPrinter::new(true);
        p.open(&report(OpenStage::Functions, Some(0.5), Some(10)), &mut out);
        p.open(&report(OpenStage::Ready, Some(1.0), None), &mut out);
        p.finish(&mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("[############------------]  50% 1:23"),
            "{text}"
        );
        assert!(text.contains("[########################] 100%"), "{text}");
        assert!(text.ends_with('\n'));
        assert!(bar(None, 0).starts_with("[####"));
    }

    #[test]
    fn counts_and_clocks_read_well() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(clock(5_000), "0:05");
        assert_eq!(clock(3_723_000), "1:02:03");
    }
}
