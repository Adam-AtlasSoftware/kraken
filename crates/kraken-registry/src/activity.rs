//! How busy an engine's process is, from the operating system: what tells a long analysis step
//! that reports nothing apart from a stuck one.

use std::time::Instant;

/// Clock ticks per second of `/proc/<pid>/stat` times. Linux has used 100 on every mainstream
/// architecture for decades; reading `sysconf(_SC_CLK_TCK)` would need a C call.
const CLK_TCK: f64 = 100.0;

/// Processor time used by `pid` so far, in clock ticks (user plus system); `None` when it cannot
/// be read (the process ended, or not Linux).
pub fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ticks(&stat)
}

/// `utime + stime` from a `/proc/<pid>/stat` line. The command name in parentheses may hold
/// spaces, so fields are counted after the last `)`.
fn parse_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state is field 3, utime field 14, stime field 15 (1-based in proc(5)).
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// Processor use of one process between samples.
#[derive(Debug)]
pub struct CpuSampler {
    pid: u32,
    last: Option<(Instant, u64)>,
}

impl CpuSampler {
    /// A sampler of `pid`.
    pub fn new(pid: u32) -> Self {
        CpuSampler { pid, last: None }
    }

    /// Percent of one core used since the previous sample; `None` on the first sample or when
    /// the process cannot be read.
    pub fn sample(&mut self) -> Option<u32> {
        let ticks = cpu_ticks(self.pid)?;
        let now = Instant::now();
        let prev = self.last.replace((now, ticks));
        let (then, before) = prev?;
        let secs = now.duration_since(then).as_secs_f64();
        if secs <= 0.0 {
            return None;
        }
        let used = ticks.saturating_sub(before) as f64 / CLK_TCK;
        Some((used / secs * 100.0).round() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_read_after_the_command_name() {
        let line = "1234 (java (kraken) x) S 1 2 3 4 5 6 7 8 9 10 250 30 0 0 20 0 21 0 99";
        assert_eq!(parse_ticks(line), Some(280));
        assert_eq!(parse_ticks("garbage"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_burning_a_core_shows_up() {
        let mut s = CpuSampler::new(std::process::id());
        assert_eq!(
            s.sample(),
            None,
            "the first sample has nothing to compare with"
        );
        let until = Instant::now() + std::time::Duration::from_millis(300);
        let mut x = 0u64;
        while Instant::now() < until {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
        std::hint::black_box(x);
        let pct = s.sample().expect("second sample");
        assert!(pct >= 40, "a busy loop is busy: {pct}%");
    }
}
