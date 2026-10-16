//! Recording one binary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use engine_fake::{FixtureFile, FixtureFunction, Recording};
use engine_ghidra::{EngineConfig, GhidraEngine, GhidraError, GhidraInstall};
use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Decompiler, DisasmRequest, Disassembler,
    FlowGraph, FunctionLister, Loader, LoaderSpec, MemoryReader, StringLister, StringsRequest,
    SymbolLister, TypeStore, XrefProvider, XrefRequest, type_def_name,
};
use kraken_proto::{
    DecompileResult, DisasmScope, FunctionSummary, Hex64, Locator, Page, PageRequest, ProtoError,
    TypeDef, Xref, XrefDirection, XrefKind,
};

/// Functions recorded per binary unless overridden.
pub const DEFAULT_FUNCTION_CAP: usize = 200;
/// Functions recorded for the statically linked `static_strops` binaries, whose fixtures would
/// otherwise grow to several megabytes each. The user functions all lie within the first 96.
pub const STATIC_FUNCTION_CAP: usize = 96;
/// Types recorded per binary unless overridden.
pub const DEFAULT_TYPE_CAP: usize = 200;
/// Strings recorded per binary.
pub const STRING_CAP: usize = 300;
/// Shortest string recorded, in characters.
pub const STRING_MIN_LEN: u32 = 4;
/// References to a function entry recorded per function.
const INCOMING_XREF_CAP: usize = 100;

/// The function cap used for a corpus binary file name when none is given.
pub fn default_function_cap(binary_file_name: &str) -> usize {
    if binary_file_name.starts_with("static_") {
        STATIC_FUNCTION_CAP
    } else {
        DEFAULT_FUNCTION_CAP
    }
}

const PAGE: u32 = 500;

/// Failures while recording.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The engine rejected a call.
    #[error("{binary}: {source}")]
    Engine {
        /// Binary being recorded.
        binary: String,
        /// The engine's error (boxed: `ProtoError` carries a JSON value and is large).
        source: Box<ProtoError>,
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
    /// Maximum number of functions (smallest addresses first, externals excluded); `None` picks
    /// [`default_function_cap`] for the binary.
    pub function_cap: Option<usize>,
    /// Maximum number of types.
    pub type_cap: usize,
    /// Directory for throw-away Ghidra projects; must have no dot-prefixed path element.
    pub scratch_root: PathBuf,
}

impl Default for RecordOptions {
    fn default() -> Self {
        RecordOptions {
            function_cap: None,
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
        source: Box::new(source),
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
    let function_cap = opts.function_cap.unwrap_or_else(|| {
        default_function_cap(
            &binary
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    });
    let mut functions = Vec::new();
    let mut skipped = 0usize;
    for summary in &listed {
        if functions.len() >= function_cap {
            break;
        }
        match engine.decompile(&summary.locator, &cancel).await {
            Ok(decompile)
                if decompile.function == summary.locator && !is_external(summary, &decompile) =>
            {
                let mut f = FixtureFunction::new(summary.clone(), decompile);
                record_listing(engine, &mut f, &cancel).await.map_err(eng)?;
                functions.push(f);
            }
            Ok(_) | Err(_) => skipped += 1,
        }
    }

    let memory = engine.memory_map(&cancel).await.map_err(eng)?;
    let token = &cancel;
    let imports = collect_all(|page| async move { engine.imports(&page, token).await })
        .await
        .map_err(eng)?;
    let exports = collect_all(|page| async move { engine.exports(&page, token).await })
        .await
        .map_err(eng)?;
    let (strings, strings_listed) = record_strings(engine, &functions, &cancel)
        .await
        .map_err(eng)?;

    let (types, types_listed) = record_types(engine, &functions, opts.type_cap, &cancel)
        .await
        .map_err(eng)?;
    let recording = Recording {
        recorder: format!("kraken-record {}", env!("CARGO_PKG_VERSION")),
        function_cap,
        functions_listed: listed.len(),
        functions_recorded: functions.len(),
        functions_skipped: skipped,
        type_cap: opts.type_cap,
        types_listed,
        types_recorded: types.len(),
        string_cap: STRING_CAP,
        strings_listed,
        strings_recorded: strings.len(),
    };
    Ok(FixtureFile {
        ghidra_version: install.ghidra_version.clone(),
        program,
        functions,
        types,
        memory: Some(memory),
        strings: Some(strings),
        imports: Some(imports),
        exports: Some(exports),
        recording: Some(recording),
    })
}

/// Pages through a listing with the largest page size.
async fn collect_all<T, F, Fut>(mut next: F) -> Result<Vec<T>, ProtoError>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Page<T>, ProtoError>>,
{
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = next(PageRequest {
            cursor: cursor.clone(),
            limit: Some(PAGE),
        })
        .await?;
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
}

/// Records the listing, control-flow graph and references of one function.
async fn record_listing(
    engine: &GhidraEngine,
    f: &mut FixtureFunction,
    cancel: &CancellationToken,
) -> Result<(), ProtoError> {
    let (_, entry) = offset_of(&f.summary.locator);
    let req = DisasmRequest {
        start: Hex64(entry),
        scope: DisasmScope::Function,
    };
    let req_ref = &req;
    f.disassembly = Some(
        collect_all(|page| async move { engine.disassemble(req_ref, &page, cancel).await }).await?,
    );
    f.cfg = Some(engine.cfg(&f.summary.locator, cancel).await?);

    let from = XrefRequest {
        address: Hex64(entry),
        direction: XrefDirection::From,
        kind: None,
        whole_function: true,
    };
    let from_ref = &from;
    let mut xrefs: Vec<Xref> =
        collect_all(|page| async move { engine.xrefs(from_ref, &page, cancel).await }).await?;
    let to = XrefRequest {
        address: Hex64(entry),
        direction: XrefDirection::To,
        kind: None,
        whole_function: false,
    };
    let incoming = engine
        .xrefs(
            &to,
            &PageRequest {
                cursor: None,
                limit: Some(INCOMING_XREF_CAP as u32),
            },
            cancel,
        )
        .await?;
    xrefs.extend(incoming.items);
    xrefs.sort_by_key(|x| (x.from, x.to, x.kind));
    xrefs.dedup();
    f.xrefs = Some(xrefs);
    Ok(())
}

/// Strings of at least [`STRING_MIN_LEN`] characters: those a recorded function refers to first,
/// then the lowest addresses, up to [`STRING_CAP`], ordered by address. Also returns how many the
/// engine listed.
async fn record_strings(
    engine: &GhidraEngine,
    functions: &[FixtureFunction],
    cancel: &CancellationToken,
) -> Result<(Vec<kraken_proto::StringEntry>, usize), ProtoError> {
    let req = StringsRequest {
        min_len: STRING_MIN_LEN,
        filter: None,
    };
    let req_ref = &req;
    let all =
        collect_all(|page| async move { engine.strings(req_ref, &page, cancel).await }).await?;
    let listed = all.len();
    let referenced: BTreeSet<Hex64> = functions
        .iter()
        .flat_map(|f| f.xrefs.iter().flatten())
        .filter(|x| matches!(x.kind, XrefKind::Data | XrefKind::Read | XrefKind::Write))
        .map(|x| x.to)
        .collect();
    let (mut chosen, rest): (Vec<_>, Vec<_>) = all
        .into_iter()
        .partition(|s| referenced.contains(&s.address));
    chosen.truncate(STRING_CAP);
    let room = STRING_CAP - chosen.len();
    chosen.extend(rest.into_iter().take(room));
    chosen.sort_by_key(|s| s.address);
    Ok((chosen, listed))
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
