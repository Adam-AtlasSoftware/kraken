//! A size-rotated log file for the daemon.
//!
//! `krakend.log` grows to `max_bytes`, then becomes `krakend.log.1` (older ones shift up to
//! `keep`), and a fresh file starts. It plugs into `tracing_subscriber` as a `MakeWriter`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use tracing_subscriber::fmt::MakeWriter;

/// Default size at which the log rotates.
pub const DEFAULT_MAX_BYTES: u64 = 5 << 20;
/// Default number of rotated files kept.
pub const DEFAULT_KEEP: usize = 3;

struct State {
    path: PathBuf,
    file: File,
    written: u64,
    max_bytes: u64,
    keep: usize,
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn rotated(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

impl State {
    fn rotate(&mut self) -> io::Result<()> {
        // Shift .N-1 -> .N, ..., .1 -> .2, then the live file -> .1.
        for n in (1..self.keep).rev() {
            let from = rotated(&self.path, n);
            if from.exists() {
                std::fs::rename(&from, rotated(&self.path, n + 1))?;
            }
        }
        if self.keep > 0 {
            std::fs::rename(&self.path, rotated(&self.path, 1))?;
        } else {
            std::fs::remove_file(&self.path)?;
        }
        self.file = open_append(&self.path)?;
        self.written = 0;
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.written > 0 && self.written + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(buf)?;
        self.written += buf.len() as u64;
        Ok(())
    }
}

/// A rotating log file; cloning shares the file.
#[derive(Clone)]
pub struct RotatingLog {
    state: Arc<Mutex<State>>,
}

impl RotatingLog {
    /// Opens (appending) `path`.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let path = path.into();
        let file = open_append(&path)?;
        let written = file.metadata()?.len();
        Ok(RotatingLog {
            state: Arc::new(Mutex::new(State {
                path,
                file,
                written,
                max_bytes: max_bytes.max(1),
                keep,
            })),
        })
    }
}

/// The writer handed to one log event.
pub struct LogWriter(RotatingLog);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .file
            .flush()
    }
}

impl<'a> MakeWriter<'a> for RotatingLog {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(log: &RotatingLog, text: &str) {
        let mut w = log.make_writer();
        w.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn rotates_by_size_and_keeps_a_bounded_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("krakend.log");
        let log = RotatingLog::open(&path, 20, 2).unwrap();
        for i in 0..10 {
            line(&log, &format!("line-{i:02}-0123456\n"));
        }
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"krakend.log".to_string()));
        assert!(names.contains(&"krakend.log.1".to_string()));
        assert!(names.contains(&"krakend.log.2".to_string()));
        assert!(!names.contains(&"krakend.log.3".to_string()), "{names:?}");
        let live = std::fs::read_to_string(&path).unwrap();
        assert!(live.ends_with("line-09-0123456\n"), "{live}");
        let first = std::fs::read_to_string(rotated(&path, 1)).unwrap();
        assert!(first.contains("line-08"), "{first}");
        for n in [&path, &rotated(&path, 1), &rotated(&path, 2)] {
            assert!(std::fs::metadata(n).unwrap().len() <= 40, "{n:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("krakend.log");
        RotatingLog::open(&path, 100, 1).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn reopening_appends_and_counts_existing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("krakend.log");
        line(
            &RotatingLog::open(&path, 30, 1).unwrap(),
            "0123456789012345\n",
        );
        let log = RotatingLog::open(&path, 30, 1).unwrap();
        line(&log, "abcdefghijklmnop\n");
        assert!(path.with_extension("log.1").exists() || rotated(&path, 1).exists());
    }
}
