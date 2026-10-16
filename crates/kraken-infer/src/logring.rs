use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

const MAX_LINE_CHARS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
    /// Messages produced by the supervisor itself (spawn, exit, restart).
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub seq: u64,
    pub stream: LogStream,
    pub text: String,
}

type Hook = Arc<dyn Fn(&LogLine) + Send + Sync>;

struct Inner {
    capacity: usize,
    next_seq: u64,
    lines: VecDeque<LogLine>,
    hook: Option<Hook>,
}

/// Bounded, thread-safe line buffer; the oldest lines are dropped first.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<Inner>>,
}

impl LogRing {
    pub fn new(capacity: usize) -> Self {
        Self::with_hook(capacity, None)
    }

    pub(crate) fn with_hook(capacity: usize, hook: Option<Hook>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                capacity: capacity.max(1),
                next_seq: 0,
                lines: VecDeque::new(),
                hook,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn push(&self, stream: LogStream, text: impl Into<String>) {
        let mut text: String = text.into();
        if text.chars().count() > MAX_LINE_CHARS {
            text = text.chars().take(MAX_LINE_CHARS).collect();
        }
        let (line, hook) = {
            let mut g = self.lock();
            let line = LogLine {
                seq: g.next_seq,
                stream,
                text,
            };
            g.next_seq += 1;
            if g.lines.len() == g.capacity {
                g.lines.pop_front();
            }
            g.lines.push_back(line.clone());
            (line, g.hook.clone())
        };
        if let Some(h) = hook {
            h(&line);
        }
    }

    pub fn snapshot(&self) -> Vec<LogLine> {
        self.lock().lines.iter().cloned().collect()
    }

    /// Lines with `seq > after` (all lines when `None`), for incremental polling.
    pub fn since(&self, after: Option<u64>) -> Vec<LogLine> {
        self.lock()
            .lines
            .iter()
            .filter(|l| after.is_none_or(|a| l.seq > a))
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.lock().lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_oldest_when_full() {
        let r = LogRing::new(3);
        for i in 0..5 {
            r.push(LogStream::Stdout, format!("l{i}"));
        }
        let s = r.snapshot();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].text, "l2");
        assert_eq!(s[2].seq, 4);
        assert_eq!(r.since(Some(3)).len(), 1);
    }

    #[test]
    fn truncates_long_lines() {
        let r = LogRing::new(2);
        r.push(LogStream::Stderr, "x".repeat(10_000));
        assert_eq!(r.snapshot()[0].text.chars().count(), MAX_LINE_CHARS);
    }
}
