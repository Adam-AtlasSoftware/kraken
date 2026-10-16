//! The fake engine.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{
    AnalysisJob, AnalysisSummary, AnalyzeRequest, Analyzer, CancellationToken, Cap, Decompiler,
    Engine, EngineCaps, EngineRejected, EngineResult, FunctionLister, Loader, LoaderSpec, Mutator,
    ProgramInfo, Progress, Stage, TypeStore, Watermark, type_def_name,
};
use kraken_proto::{
    DecompileResult, ErrorCode, FunctionSummary, Locator, LogOp, Page, PageRequest, ProtoError,
    TypeDef, VersionedLogOp,
};

use crate::fixture::{FixtureFile, FixtureFunction, Perturb, key_of, stub_decompile};
use crate::text::{rename_in_result, replace_word};

const STEPS_PER_STAGE: u64 = 3;
const DEFAULT_STAGE_DELAY: Duration = Duration::from_millis(2);

type FnKey = (String, u64);

#[derive(Debug)]
struct State {
    program: ProgramInfo,
    functions: BTreeMap<FnKey, FixtureFunction>,
    types: BTreeMap<String, TypeDef>,
    applied: Vec<VersionedLogOp>,
    saved: usize,
}

/// An in-memory engine serving a [`FixtureFile`]. See the crate docs for semantics.
#[derive(Debug)]
pub struct FakeEngine {
    state: Mutex<State>,
    ghidra_version: String,
    caps: BTreeSet<Cap>,
    stage_delay: Duration,
}

fn cancelled() -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, "operation cancelled")
}

fn check(cancel: &CancellationToken) -> EngineResult<()> {
    if cancel.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

fn not_found(what: impl std::fmt::Display) -> EngineRejected {
    EngineRejected::new(ErrorCode::NotFound, format!("{what} not found"))
}

fn fn_key(l: &Locator) -> EngineResult<FnKey> {
    match l {
        Locator::Native { space, offset } => Ok((space.clone(), offset.0)),
        _ => Err(ProtoError::new(
            ErrorCode::Unsupported,
            "unsupported locator kind",
        )),
    }
}

impl FakeEngine {
    /// An engine with every capability serving `fixture`.
    pub fn new(fixture: FixtureFile) -> Self {
        let functions = fixture
            .functions
            .into_iter()
            .map(|f| (key_of(&f.summary.locator), f))
            .collect();
        let types = fixture
            .types
            .into_iter()
            .filter_map(|t| type_def_name(&t).map(|n| (n.to_string(), t.clone())))
            .collect();
        FakeEngine {
            state: Mutex::new(State {
                program: fixture.program,
                functions,
                types,
                applied: Vec::new(),
                saved: 0,
            }),
            ghidra_version: fixture.ghidra_version,
            caps: Cap::ALL.into_iter().collect(),
            stage_delay: DEFAULT_STAGE_DELAY,
        }
    }

    /// Parses `json` as a [`FixtureFile`] and serves it.
    pub fn from_json(json: &str) -> EngineResult<Self> {
        Ok(Self::new(FixtureFile::from_json(json)?))
    }

    /// Serves the fixture after applying `perturb` (decision 49).
    pub fn perturbed(fixture: FixtureFile, perturb: Perturb) -> Self {
        Self::new(perturb.apply(&fixture))
    }

    /// Removes a capability: the accessor returns `None` and the handshake omits it.
    pub fn without(mut self, cap: Cap) -> Self {
        self.caps.remove(&cap);
        self
    }

    /// Sets the sleep per analysis step (three steps per stage); zero makes analysis instant.
    pub fn with_stage_delay(mut self, delay: Duration) -> Self {
        self.stage_delay = delay;
        self
    }

    /// Log ops applied so far, in order.
    pub fn applied_ops(&self) -> Vec<VersionedLogOp> {
        self.lock().applied.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has(&self, cap: Cap) -> bool {
        self.caps.contains(&cap)
    }
}

impl Engine for FakeEngine {
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            format!("engine-fake (fixture ghidra {})", self.ghidra_version),
            self.caps.iter().copied(),
        )
    }
    fn loader(&self) -> Option<&dyn Loader> {
        self.has(Cap::Loader).then_some(self as &dyn Loader)
    }
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        self.has(Cap::Analyzer).then_some(self as &dyn Analyzer)
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        self.has(Cap::Decompiler).then_some(self as &dyn Decompiler)
    }
    fn type_store(&self) -> Option<&dyn TypeStore> {
        self.has(Cap::TypeStore).then_some(self as &dyn TypeStore)
    }
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        self.has(Cap::FunctionLister)
            .then_some(self as &dyn FunctionLister)
    }
    fn mutator(&self) -> Option<&dyn Mutator> {
        self.has(Cap::Mutator).then_some(self as &dyn Mutator)
    }
}

#[async_trait]
impl Loader for FakeEngine {
    async fn open_binary(
        &self,
        _path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo> {
        check(cancel)?;
        let mut info = self.lock().program.clone();
        if let Some(f) = &spec.format
            && *f != info.format
        {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("format {f} is not supported"),
            ));
        }
        if let Some(a) = &spec.arch {
            info.arch = a.clone();
        }
        if let Some(b) = spec.base {
            info.base = b;
        }
        Ok(info)
    }
}

#[async_trait]
impl Analyzer for FakeEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        check(&cancel)?;
        let count = self.lock().functions.len() as u64;
        let delay = self.stage_delay;
        Ok(AnalysisJob::spawn(cancel, move |tx, cancel| async move {
            let mut done = Vec::new();
            for stage in Stage::ALL {
                if req.resume_from.is_some_and(|r| stage < r) {
                    continue;
                }
                for step in 1..=STEPS_PER_STAGE {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Err(cancelled()),
                        () = tokio::time::sleep(delay) => {}
                    }
                    tx.send(Progress {
                        stage,
                        done: step,
                        total: STEPS_PER_STAGE,
                        message: format!("{} pass {step}/{STEPS_PER_STAGE}", stage.as_str()),
                    });
                }
                done.push(stage);
            }
            Ok(AnalysisSummary {
                stages_completed: done,
                function_count: count,
            })
        }))
    }
}

#[async_trait]
impl Decompiler for FakeEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        check(cancel)?;
        let key = fn_key(locator)?;
        self.lock()
            .functions
            .get(&key)
            .map(|f| f.decompile.clone())
            .ok_or_else(|| ProtoError::from(not_found(format!("function at {key:?}"))))
    }
}

#[async_trait]
impl TypeStore for FakeEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        check(cancel)?;
        self.lock()
            .types
            .get(name)
            .cloned()
            .ok_or_else(|| not_found(format!("type {name}")).into())
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        let Some(name) = type_def_name(&def).map(str::to_string) else {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "anonymous types cannot be defined",
            ));
        };
        if name.is_empty() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "empty type name",
            ));
        }
        self.lock().types.insert(name, def);
        Ok(())
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        check(cancel)?;
        let after =
            match &page.cursor {
                None => None,
                Some(c) => Some(c.strip_prefix("t:").map(str::to_string).ok_or_else(|| {
                    ProtoError::new(ErrorCode::InvalidArgument, "malformed cursor")
                })?),
            };
        let limit = page.effective_limit() as usize;
        let st = self.lock();
        let lower = after.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut it = st.types.range::<str, _>((lower, Bound::Unbounded));
        let items: Vec<(&String, &TypeDef)> = it.by_ref().take(limit).collect();
        let more = it.next().is_some();
        let next_cursor = more
            .then(|| items.last().map(|(k, _)| format!("t:{k}")))
            .flatten();
        Ok(Page {
            items: items.into_iter().map(|(_, v)| v.clone()).collect(),
            next_cursor,
            total: Some(st.types.len() as u64),
        })
    }
}

fn parse_cursor(c: &str) -> EngineResult<FnKey> {
    let bad = || ProtoError::new(ErrorCode::InvalidArgument, "malformed cursor");
    let (space, off) = c.rsplit_once(':').ok_or_else(bad)?;
    let off = u64::from_str_radix(off, 16).map_err(|_| bad())?;
    Ok((space.to_string(), off))
}

#[async_trait]
impl FunctionLister for FakeEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        check(cancel)?;
        let after = page.cursor.as_deref().map(parse_cursor).transpose()?;
        let limit = page.effective_limit() as usize;
        let st = self.lock();
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut it = st.functions.range((lower, Bound::Unbounded));
        let items: Vec<(&FnKey, &FixtureFunction)> = it.by_ref().take(limit).collect();
        let more = it.next().is_some();
        let next_cursor = more
            .then(|| items.last().map(|(k, _)| format!("{}:{:x}", k.0, k.1)))
            .flatten();
        Ok(Page {
            items: items.into_iter().map(|(_, f)| f.summary.clone()).collect(),
            next_cursor,
            total: Some(st.functions.len() as u64),
        })
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        check(cancel)?;
        let key = fn_key(locator)?;
        self.lock()
            .functions
            .get(&key)
            .map(|f| f.summary.clone())
            .ok_or_else(|| ProtoError::from(not_found(format!("function at {key:?}"))))
    }
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && !n.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn check_hash(f: &FixtureFunction, anchor_hash: &str) -> Result<(), EngineRejected> {
    match &f.summary.fn_hash {
        Some(h) if !anchor_hash.is_empty() && h != anchor_hash => Err(EngineRejected::new(
            ErrorCode::ConflictStaleRead,
            format!("function hash is {h}, anchor has {anchor_hash}"),
        )),
        _ => Ok(()),
    }
}

impl State {
    fn apply_op(&mut self, op: &LogOp) -> Result<(), EngineRejected> {
        match op {
            LogOp::Rename {
                anchor,
                old_name,
                new_name,
            } => {
                let (space, offset, entry, hash) = anchor.native()?;
                if offset != entry {
                    return Err(EngineRejected::new(
                        ErrorCode::Unsupported,
                        "the fake only renames functions",
                    ));
                }
                let f = self
                    .functions
                    .get_mut(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                if !valid_name(new_name) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "invalid function name",
                    ));
                }
                let current = f.summary.name.clone();
                if &current == new_name {
                    return Ok(());
                }
                if old_name.as_ref().is_some_and(|o| *o != current) {
                    return Err(EngineRejected::new(
                        ErrorCode::ConflictStaleRead,
                        format!("function is named {current}"),
                    ));
                }
                rename_in_result(&mut f.decompile, &current, new_name);
                f.summary.signature = f
                    .summary
                    .signature
                    .as_ref()
                    .map(|s| replace_word(s, &current, new_name));
                f.summary.name = new_name.clone();
                Ok(())
            }
            LogOp::CreateFunction { anchor, name, body } => {
                let (space, _, entry, hash) = anchor.native()?;
                let key = (space.to_string(), entry.0);
                let name = name
                    .clone()
                    .unwrap_or_else(|| format!("FUN_{:08x}", entry.0));
                if !valid_name(&name) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "invalid function name",
                    ));
                }
                if let Some(existing) = self.functions.get(&key) {
                    let same = existing.summary.name == name
                        && existing.summary.fn_hash.as_deref().unwrap_or("") == hash;
                    return if same {
                        Ok(())
                    } else {
                        Err(EngineRejected::rejected(format!(
                            "a function already exists at {space}:{entry}"
                        )))
                    };
                }
                let locator = Locator::Native {
                    space: space.to_string(),
                    offset: entry,
                };
                let mut decompile = stub_decompile(&locator, &name);
                decompile.function = locator.clone();
                let summary = FunctionSummary {
                    locator,
                    name: name.clone(),
                    size: body.as_ref().map(|b| b.end.0.saturating_sub(b.start.0)),
                    signature: Some(format!("void {name}(void)")),
                    fn_hash: (!hash.is_empty()).then(|| hash.to_string()),
                    completeness: kraken_proto::Completeness::Complete,
                };
                self.functions
                    .insert(key, FixtureFunction { summary, decompile });
                Ok(())
            }
            LogOp::DeleteFunction { anchor, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let key = (space.to_string(), entry.0);
                let f = self
                    .functions
                    .get(&key)
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                self.functions.remove(&key);
                Ok(())
            }
            LogOp::SetFunctionBounds { anchor, new, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let f = self
                    .functions
                    .get_mut(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                if new.start != entry || new.end < new.start {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "bounds must start at the function entry",
                    ));
                }
                f.summary.size = Some(new.end.0 - new.start.0);
                Ok(())
            }
            LogOp::SetType { anchor, .. }
            | LogOp::SetComment { anchor, .. }
            | LogOp::SetCodeData { anchor, .. }
            | LogOp::SetCallingConvention { anchor, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let f = self
                    .functions
                    .get(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)
            }
        }
    }
}

#[async_trait]
impl Mutator for FakeEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        check(cancel)?;
        op.check_version()?;
        let mut st = self.lock();
        st.apply_op(&op.op)?;
        st.applied.push(op.clone());
        Ok(())
    }

    async fn save(&self, cancel: &CancellationToken) -> EngineResult<Watermark> {
        check(cancel)?;
        let mut st = self.lock();
        st.saved = st.applied.len();
        Ok(Watermark(format!("fake-{}", st.saved)))
    }
}
