//! The test corpus: prebuilt binaries, DWARF-derived ground truth and recorded engine fixtures
//! (`corpus/` in the repository; see its README).

use std::path::{Path, PathBuf};

use engine_fake::FixtureFile;
use serde::Deserialize;

use crate::error::EvalError;

/// A located corpus directory.
#[derive(Debug, Clone)]
pub struct Corpus {
    root: PathBuf,
}

/// One function of the ground truth, from the DWARF of the unstripped build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthFunction {
    /// Source-level name.
    pub name: String,
    /// Link-time entry address (relative to the image base for a PIE).
    pub entry: u64,
    /// Size in bytes.
    pub size: u64,
}

/// The ground truth of one binary.
#[derive(Debug, Clone)]
pub struct Truth {
    /// The binary's name, such as `switch_vm-O0-stripped`.
    pub binary: String,
    /// Functions in the order the file lists them.
    pub functions: Vec<TruthFunction>,
}

#[derive(Deserialize)]
struct TruthFile {
    functions: Vec<TruthRow>,
}

#[derive(Deserialize)]
struct TruthRow {
    name: String,
    entry: String,
    size: u64,
}

fn parse_hex(s: &str) -> Result<u64, EvalError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| EvalError::Corpus(format!("`{s}` is not a hex address")))
}

impl Corpus {
    /// The corpus at `root`.
    pub fn at(root: impl Into<PathBuf>) -> Result<Corpus, EvalError> {
        let root = root.into();
        if !root.join("truth").is_dir() {
            return Err(EvalError::Corpus(format!(
                "{} has no truth/ directory; point --corpus at the repository's corpus/ folder",
                root.display()
            )));
        }
        Ok(Corpus { root })
    }

    /// Finds the corpus: `explicit`, else `KRAKEN_CORPUS`, else a `corpus/` folder in the working
    /// directory or above it, else the one next to this crate in a source checkout.
    pub fn locate(explicit: Option<&Path>, env: Option<&str>) -> Result<Corpus, EvalError> {
        if let Some(p) = explicit {
            return Corpus::at(p);
        }
        if let Some(p) = env.filter(|p| !p.is_empty()) {
            return Corpus::at(p);
        }
        if let Ok(mut dir) = std::env::current_dir() {
            loop {
                let candidate = dir.join("corpus");
                if candidate.join("truth").is_dir() {
                    return Corpus::at(candidate);
                }
                if !dir.pop() {
                    break;
                }
            }
        }
        let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        Corpus::at(here).map_err(|_| {
            EvalError::Corpus(
                "cannot find the corpus; pass --corpus <dir> or set KRAKEN_CORPUS".to_string(),
            )
        })
    }

    /// The corpus directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of the binary `name`.
    pub fn binary(&self, name: &str) -> PathBuf {
        self.root.join("bin").join(name)
    }

    /// The recorded engine fixture of `name`.
    pub fn fixture(&self, name: &str) -> Result<FixtureFile, EvalError> {
        let path = self.root.join("fixtures").join(format!("{name}.json"));
        FixtureFile::from_path(&path).map_err(|e| EvalError::Corpus(e.message))
    }

    /// The ground truth of `name`.
    pub fn truth(&self, name: &str) -> Result<Truth, EvalError> {
        let path = self.root.join("truth").join(format!("{name}.json"));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| EvalError::Corpus(format!("{}: {e}", path.display())))?;
        let file: TruthFile = serde_json::from_str(&text)
            .map_err(|e| EvalError::Corpus(format!("{}: {e}", path.display())))?;
        let functions = file
            .functions
            .into_iter()
            .map(|r| {
                Ok(TruthFunction {
                    name: r.name,
                    entry: parse_hex(&r.entry)?,
                    size: r.size,
                })
            })
            .collect::<Result<Vec<_>, EvalError>>()?;
        Ok(Truth {
            binary: name.to_string(),
            functions,
        })
    }
}

/// The address an engine reports for a truth entry. Truth is in link-time addresses: a PIE's are
/// relative to zero and the engine loads it at `base`; a fixed-address binary's are absolute.
pub fn engine_address(entry: u64, base: u64) -> u64 {
    if entry >= base { entry } else { base + entry }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pie_entries_are_rebased_and_absolute_ones_are_not() {
        assert_eq!(engine_address(0x1159, 0x10_0000), 0x10_1159);
        assert_eq!(engine_address(0x40_1725, 0x40_0000), 0x40_1725);
        assert_eq!(engine_address(0x1159, 0), 0x1159);
    }

    #[test]
    fn the_checked_in_corpus_is_found_and_read() {
        let c = Corpus::locate(None, None).expect("corpus");
        let t = c.truth("switch_vm-O0-stripped").expect("truth");
        assert!(
            t.functions
                .iter()
                .any(|f| f.name == "vm_run" && f.size > 900)
        );
        let fx = c.fixture("switch_vm-O0-stripped").expect("fixture");
        assert_eq!(fx.program.base.0, 0x10_0000);
        assert!(c.binary("switch_vm-O0-stripped").is_file());
    }
}
