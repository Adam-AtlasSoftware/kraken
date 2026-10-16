//! Recording one binary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use engine_fake::{FixtureFile, FixtureFunction, Recording};
use engine_ghidra::{EngineConfig, GhidraEngine, GhidraError, GhidraInstall};
use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec,
    TypeStore, type_def_name,
};
use kraken_proto::{DecompileResult, FunctionSummary, Locator, PageRequest, ProtoError, TypeDef};

/// Functions recorded per binary unless overridden.
pub const DEFAULT_FUNCTION_CAP: usize = 200;
/// Types recorded per binary unless overridden.
pub const DEFAULT_TYPE_CAP: usize = 200;

const PAGE: u32 = 500;

/// Failures while recording.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The engine rejected a call.
    #[error("{binary}: {source}")]
    Engine {
        /// Binary being recorded.
        binary: String,
        /// The engine's error.
        source: ProtoError,
    },
    /// Ghidra could not be set up.
    #[error("ghidra setup: {0}")]
    Setup(#[from] GhidraError),
    /// Scratch directory or file I/O failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The engine returned something the fixture format cannot hold.
    #[error("{0}")]
    Invalid(String),
}

/// What to record.
#[derive(Debug, Clone)]
pub struct RecordOptions {
    /// Maximum number of functions (smallest addresses first, externals excluded).
    pub function_cap: usize,
    /// Maximum number of types.
    pub type_cap: usize,
    /// Directory for throw-away Ghidra projects; must have no dot-prefixed path element.
    pub scratch_root: PathBuf,
}

impl Default for RecordOptions {
    fn default() -> Self {
        RecordOptions {
            function_cap: DEFAULT_FUNCTION_CAP,
            type_cap: DEFAULT_TYPE_CAP,
            scratch_root: std::env::temp_dir(),
        }
    }
}

/// Serializes a fixture the way the recorder writes it: sorted keys, short values on one line
/// (see [`crate::render`]), trailing newline.
pub fn render_fixture(fx: &FixtureFile) -> Result<String, RecordError> {
    let value = serde_json::to_value(fx).map_err(|e| RecordError::Invalid(e.to_string()))?;
    Ok(crate::render::render(&value))
}

fn offset_of(l: &Locator) -> (String, u64) {
    match l {
        Locator::Native { space, offset } => (space.clone(), offset.0),
        _ => (String::new(), 0),
    }
}

/// Opens `binary` in a fresh temporary project, runs full analysis and records a fixture.
pub async fn record_binary(
    install: &GhidraInstall,
    binary: &Path,
    opts: &RecordOptions,
) -> Result<FixtureFile, RecordError> {
    let name = binary
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let eng = |source: ProtoError| RecordError::Engine {
        binary: name.clone(),
        source,
    };
    let scratch = tempfile::Builder::new()
        .prefix("kraken-record-")
        .tempdir_in(&opts.scratch_root)
        .map_err(|source| RecordError::Io {
            what: format!("scratch dir in {}", opts.scratch_root.display()),
            source,
        })?;
    let engine = GhidraEngine::new(EngineConfig::new(
        install.clone(),
        scratch.path().join("project"),
    ));
    let result = record_with(&engine, install, binary, opts, &eng).await;
    engine.shutdown().await;
    result
}

async fn record_with(
    engine: &GhidraEngine,
    install: &GhidraInstall,
    binary: &Path,
    opts: &RecordOptions,
    eng: &impl Fn(ProtoError) -> RecordError,
) -> Result<FixtureFile, RecordError> {
    let cancel = CancellationToken::new();
    let program = engine
        .open_binary(binary, &LoaderSpec::default(), &cancel)
        .await
        .map_err(eng)?;
    engine
        .analyze(AnalyzeRequest::default(), cancel.clone())
        .await
        .map_err(eng)?
        .wait()
        .await
        .map_err(eng)?;

    let mut listed = Vec::new();
    let mut cursor = None;
    loop {
        let page = engine
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(PAGE),
                },
                &cancel,
            )
            .await
            .map_err(eng)?;
        listed.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    listed.sort_by_key(|f| offset_of(&f.locator));

    // Imported/external stubs live in a synthetic memory block: one byte long, and the
    // decompiler reports bad instruction data for them. They are skipped, not recorded.
    let mut functions = Vec::new();
    let mut skipped = 0usize;
    for summary in &listed {
        if functions.len() >= opts.function_cap {
            break;
        }
        match engine.decompile(&summary.locator, &cancel).await {
            Ok(decompile)
                if decompile.function == summary.locator && !is_external(summary, &decompile) =>
            {
                functions.push(FixtureFunction {
                    summary: summary.clone(),
                    decompile,
                });
            }
            Ok(_) | Err(_) => skipped += 1,
        }
    }

    let (types, types_listed) = record_types(engine, &functions, opts.type_cap, &cancel)
        .await
        .map_err(eng)?;
    let recording = Recording {
        recorder: format!("kraken-record {}", env!("CARGO_PKG_VERSION")),
        function_cap: opts.function_cap,
        functions_listed: listed.len(),
        functions_recorded: functions.len(),
        functions_skipped: skipped,
        type_cap: opts.type_cap,
        types_listed,
        types_recorded: types.len(),
    };
    Ok(FixtureFile {
        ghidra_version: install.ghidra_version.clone(),
        program,
        functions,
        types,
        recording: Some(recording),
    })
}

async fn record_types(
    engine: &GhidraEngine,
    functions: &[FixtureFunction],
    cap: usize,
    cancel: &CancellationToken,
) -> Result<(Vec<TypeDef>, usize), ProtoError> {
    let mut all: BTreeMap<String, TypeDef> = BTreeMap::new();
    let mut cursor = None;
    let mut listed = 0usize;
    loop {
        let page = engine
            .list_types(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(PAGE),
                },
                cancel,
            )
            .await?;
        for def in page.items {
            listed += 1;
            if let Some(n) = type_def_name(&def) {
                all.entry(n.to_string()).or_insert(def);
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    // Types named by a recorded signature, plus whatever those types name in turn.
    let mut wanted: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = Vec::new();
    for f in functions {
        for ident in identifiers(f.summary.signature.as_deref().unwrap_or("")) {
            // function prototypes named like functions are not what the signature mentions
            let is_type = all
                .get(ident)
                .is_some_and(|d| !matches!(d, TypeDef::Function(_)));
            if is_type && wanted.insert(ident.to_string()) {
                queue.push(ident.to_string());
            }
        }
    }
    while let Some(n) = queue.pop() {
        let Some(def) = all.get(&n) else { continue };
        let mut refs = Vec::new();
        named_refs(&serde_json::to_value(def).unwrap_or_default(), &mut refs);
        for r in refs {
            if all.contains_key(&r) && wanted.insert(r.clone()) {
                queue.push(r);
            }
        }
    }
    let chosen: Vec<String> = if wanted.is_empty() {
        all.keys().take(cap).cloned().collect()
    } else {
        wanted.into_iter().take(cap).collect()
    };
    let types = chosen.into_iter().filter_map(|n| all.remove(&n)).collect();
    Ok((types, listed))
}

fn is_external(summary: &FunctionSummary, decompile: &DecompileResult) -> bool {
    summary.size == Some(1) && decompile.text.contains("bad instruction data")
}

fn identifiers(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

fn named_refs(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            if m.get("kind").and_then(|k| k.as_str()) == Some("named")
                && let Some(n) = m.get("name").and_then(|n| n.as_str())
            {
                out.push(n.to_string());
            }
            m.values().for_each(|x| named_refs(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| named_refs(x, out)),
        _ => {}
    }
}
