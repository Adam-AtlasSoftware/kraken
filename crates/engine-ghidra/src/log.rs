//! Bounded capture of the sidecar's stdout/stderr.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex, PoisonError};

/// Lines kept in the ring buffer.
pub const LOG_CAPACITY: usize = 2000;
/// Longer lines are truncated.
pub const MAX_LINE_BYTES: usize = 4096;

#[derive(Debug, Default)]
struct Ring {
    lines: VecDeque<String>,
    dropped: u64,
}

/// A shared, bounded ring of the sidecar's output lines. Every line is also emitted as a
/// `tracing` event (target `engine_ghidra::sidecar`, DEBUG).
#[derive(Debug, Clone)]
pub struct LogSink {
    ring: Arc<Mutex<Ring>>,
    capacity: usize,
}

impl Default for LogSink {
    fn default() -> Self {
        Self::with_capacity(LOG_CAPACITY)
    }
}

impl LogSink {
    /// A sink keeping the last `capacity` lines.
    pub fn with_capacity(capacity: usize) -> Self {
        LogSink {
            ring: Arc::default(),
            capacity: capacity.max(1),
        }
    }

    /// Appends one line (truncated to [`MAX_LINE_BYTES`]).
    pub fn push(&self, line: impl Into<String>) {
        let mut line = line.into();
        if line.len() > MAX_LINE_BYTES {
            let mut cut = MAX_LINE_BYTES;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
            line.push_str(" [truncated]");
        }
        tracing::debug!(target: "engine_ghidra::sidecar", "{line}");
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        if ring.lines.len() >= self.capacity {
            ring.lines.pop_front();
            ring.dropped += 1;
        }
        ring.lines.push_back(line);
    }

    /// The last `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        let skip = ring.lines.len().saturating_sub(n);
        ring.lines.iter().skip(skip).cloned().collect()
    }

    /// Every retained line, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.tail(usize::MAX)
    }

    /// How many lines were evicted because the ring was full.
    pub fn dropped(&self) -> u64 {
        self.ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dropped
    }

    /// Reads `reader` to EOF, pushing one entry per line. Blocking; run it on its own thread.
    pub fn pump(&self, mut reader: impl Read) {
        let mut chunk = [0u8; 8192];
        let mut line: Vec<u8> = Vec::new();
        let mut overflow = false;
        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            for &b in &chunk[..n] {
                if b == b'\n' {
                    self.push(
                        String::from_utf8_lossy(&line)
                            .trim_end_matches('\r')
                            .to_string(),
                    );
                    line.clear();
                    overflow = false;
                } else if line.len() < MAX_LINE_BYTES {
                    line.push(b);
                } else if !overflow {
                    overflow = true;
                    line.extend_from_slice(b" [truncated]");
                }
            }
        }
        if !line.is_empty() {
            self.push(String::from_utf8_lossy(&line).to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_ordered() {
        let sink = LogSink::with_capacity(3);
        for i in 0..5 {
            sink.push(format!("l{i}"));
        }
        assert_eq!(sink.lines(), ["l2", "l3", "l4"]);
        assert_eq!(sink.tail(2), ["l3", "l4"]);
        assert_eq!(sink.dropped(), 2);
    }

    #[test]
    fn pump_splits_lines_and_truncates() {
        let sink = LogSink::default();
        let mut input = b"one\r\ntwo\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES * 3));
        input.extend_from_slice(b"\nlast");
        sink.pump(input.as_slice());
        let lines = sink.lines();
        assert_eq!(lines[0], "one");
        assert_eq!(lines[1], "two");
        assert!(lines[2].ends_with("[truncated]") && lines[2].len() < MAX_LINE_BYTES + 32);
        assert_eq!(lines[3], "last");
    }

    #[test]
    fn long_push_cuts_on_a_char_boundary() {
        let sink = LogSink::default();
        sink.push("é".repeat(MAX_LINE_BYTES));
        assert!(sink.lines()[0].ends_with("[truncated]"));
    }
}
