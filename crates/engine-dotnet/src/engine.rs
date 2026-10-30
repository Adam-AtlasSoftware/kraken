//! [`DotnetEngine`]: Loader, FunctionLister, Decompiler, a read-only TypeStore and a Mutator over
//! the sidecar. The Mutator keeps renames and comments in memory (ILSpy cannot write them); the
//! engine applies them to the names and C# the sidecar returns. KRAKEN's edit log is the store.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{
    CancellationToken, Cap, Decompiler, Engine, EngineCaps, EngineRejected, EngineResult,
    FunctionLister, Loader, LoaderSpec, Mutator, OpenReporter, ProgramInfo, TypeStore, Watermark,
    unsupported,
};
use kraken_proto::{
    DecompileResult, ErrorCode, FunctionSummary, Hex64, Locator, LogOp, OpenStage, OpenUpdate,
    PROTOCOL_VERSION, Page, PageRequest, ProtoError, TypeDef, VersionedLogOp,
};
use kraken_sidecar::LogSink;
use kraken_sidecar::rpc::RpcClient;
use kraken_sidecar::sandbox::{ConfinementOptions, ConfinementReport, ExitInfo};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::annotate::{self, Annotations};
use crate::install::DotnetInstall;
use crate::launch::{Guard, LaunchPlan, launch};

/// Sidecar capabilities this crate cannot work without.
pub const REQUIRED_SIDECAR_CAPABILITIES: &[&str] = &[
    "open_assembly",
    "list_functions",
    "decompile.tokens",
    "list_types",
    "types.read",
];

/// Output language tag of this engine's decompiler.
pub const LANGUAGE_CSHARP: &str = kraken_proto::LANGUAGE_CSHARP;

/// Per-call deadlines.
#[derive(Debug, Clone)]
pub struct Deadlines {
    /// Listings and lookups.
    pub default: Duration,
    /// Decompilation (also sent to the sidecar as `timeout_ms`).
    pub decompile: Duration,
    /// Opening an assembly, including the runtime start.
    pub open: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Deadlines {
            default: Duration::from_secs(60),
            decompile: Duration::from_secs(30),
            open: Duration::from_secs(120),
        }
    }
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The .NET installation and the sidecar build.
    pub install: DotnetInstall,
    /// Confinement policy; unconfined runs are refused unless `allow_unconfined` is set.
    pub confinement: ConfinementOptions,
    /// Managed heap cap of the sidecar in MiB.
    pub max_heap_mb: u64,
    /// Per-call deadlines.
    pub deadlines: Deadlines,
    /// Time allowed for the sidecar to answer its handshake.
    pub startup_timeout: Duration,
    /// Directory for the per-session private home; the system temp dir when unset.
    pub temp_root: Option<PathBuf>,
}

impl EngineConfig {
    /// Defaults for `install`.
    pub fn new(install: DotnetInstall) -> Self {
        EngineConfig {
            install,
            confinement: ConfinementOptions::default(),
            max_heap_mb: 2048,
            deadlines: Deadlines::default(),
            startup_timeout: Duration::from_secs(60),
            temp_root: None,
        }
    }
}

/// Facts the sidecar reports beyond [`ProgramInfo`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AssemblyInfo {
    /// Module version id (MVID) used as `module` in managed locators.
    pub module_mvid: String,
    /// Assembly simple name.
    pub assembly: String,
    /// Target framework moniker, if the assembly declares one.
    #[serde(default)]
    pub target_framework: Option<String>,
    /// Number of method definitions.
    pub method_count: u64,
    /// Number of type definitions (without `<Module>`).
    pub type_count: u64,
}

#[derive(Deserialize)]
struct WireProgramInfo {
    arch: String,
    format: String,
    base: Hex64,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
struct WireHandshake {
    protocol: kraken_proto::ProtocolVersion,
    build: String,
    capabilities: Vec<kraken_proto::Capability>,
}

/// State of a running sidecar.
struct Running {
    client: RpcClient,
    log: LogSink,
    report: ConfinementReport,
    pid: u32,
    build: String,
    info: AssemblyInfo,
    exit: watch::Receiver<Option<ExitInfo>>,
    guard: Guard,
}

impl Running {
    fn enrich(&self, mut e: ProtoError) -> ProtoError {
        if e.code == ErrorCode::Internal && e.message == kraken_sidecar::rpc::SIDECAR_EXITED {
            e = e.with_details(json!({
                "exit": self.exit.borrow().map(|x| json!({"code": x.code, "signal": x.signal})),
                "log_tail": self.log.tail(20),
            }));
        }
        e
    }
}

/// What the engine knows about its sidecar, for `kraken doctor`-style output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    /// `not_started`, `running` or `exited`.
    pub state: &'static str,
    /// Process id of the running sidecar.
    pub pid: Option<u32>,
    /// Sidecar build string from the handshake.
    pub build: Option<String>,
    /// Applied confinement.
    pub confinement: Option<ConfinementReport>,
    /// Last log lines.
    pub log_tail: Vec<String>,
}

/// The .NET engine. Nothing is started until the first [`Loader::open_binary`]; opening another
/// assembly replaces (kills) the previous sidecar.
pub struct DotnetEngine {
    config: EngineConfig,
    running: Mutex<Option<Arc<Running>>>,
    annotations: Mutex<Annotations>,
    applied: AtomicU64,
}

fn page_params(page: &PageRequest) -> Value {
    json!({"cursor": page.cursor, "limit": page.effective_limit()})
}

impl DotnetEngine {
    /// An engine for `config`.
    pub fn new(config: EngineConfig) -> Self {
        DotnetEngine {
            config,
            running: Mutex::new(None),
            annotations: Mutex::new(Annotations::new()),
            applied: AtomicU64::new(0),
        }
    }

    fn notes(&self) -> Annotations {
        self.annotations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn running(&self) -> EngineResult<Arc<Running>> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "no assembly is open; call open_binary first",
                )
            })
    }

    /// The MVID of the open assembly (the `module` of its locators).
    pub fn module_mvid(&self) -> EngineResult<String> {
        Ok(self.running()?.info.module_mvid.clone())
    }

    /// Facts about the open assembly.
    pub fn assembly_info(&self) -> EngineResult<AssemblyInfo> {
        Ok(self.running()?.info.clone())
    }

    /// Process state and confinement.
    pub fn diagnostics(&self) -> Diagnostics {
        let cur = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match cur {
            None => Diagnostics {
                state: "not_started",
                pid: None,
                build: None,
                confinement: None,
                log_tail: vec![],
            },
            Some(r) => Diagnostics {
                state: if r.exit.borrow().is_none() && !r.client.is_closed() {
                    "running"
                } else {
                    "exited"
                },
                pid: Some(r.pid),
                build: Some(r.build.clone()),
                confinement: Some(r.report.clone()),
                log_tail: r.log.tail(50),
            },
        }
    }

    /// Kills the sidecar, if any.
    pub fn shutdown(&self) {
        let old = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(r) = old {
            r.guard.kill();
        }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> EngineResult<T> {
        let r = self.running()?;
        r.client
            .call_typed(method, params, Some(deadline), Some(cancel))
            .await
            .map_err(|e| r.enrich(e))
    }

    /// The method as the assembly names it, without annotations.
    async fn raw_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        let locator = self.require_managed(locator)?;
        self.call(
            "get_function",
            json!({"locator": locator}),
            self.config.deadlines.default,
            cancel,
        )
        .await
    }

    fn require_managed<'a>(&self, locator: &'a Locator) -> EngineResult<&'a Locator> {
        match locator {
            Locator::Managed { .. } => Ok(locator),
            _ => Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "the .NET engine only takes managed locators",
            )),
        }
    }
}

impl Drop for DotnetEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Engine for DotnetEngine {
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            concat!("engine-dotnet ", env!("CARGO_PKG_VERSION"), " (ilspy)"),
            [
                Cap::Loader,
                Cap::Decompiler,
                Cap::TypeStore,
                Cap::FunctionLister,
                Cap::Mutator,
            ],
        )
    }

    fn loader(&self) -> Option<&dyn Loader> {
        Some(self)
    }

    fn decompiler(&self) -> Option<&dyn Decompiler> {
        Some(self)
    }

    fn type_store(&self) -> Option<&dyn TypeStore> {
        Some(self)
    }

    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        Some(self)
    }

    fn mutator(&self) -> Option<&dyn Mutator> {
        Some(self)
    }
}

fn check_handshake(h: &WireHandshake) -> Result<(), ProtoError> {
    if h.protocol != PROTOCOL_VERSION {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "the sidecar speaks protocol {}.{}, this build needs {}.{}; rebuild it with \
                 `cargo xtask dotnet-ext`",
                h.protocol.major, h.protocol.minor, PROTOCOL_VERSION.major, PROTOCOL_VERSION.minor
            ),
        ));
    }
    let missing: Vec<&str> = REQUIRED_SIDECAR_CAPABILITIES
        .iter()
        .copied()
        .filter(|c| !h.capabilities.iter().any(|x| x.name == *c))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("the sidecar lacks capabilities: {}", missing.join(", ")),
        ))
    }
}

#[async_trait]
impl Loader for DotnetEngine {
    async fn open_binary(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo> {
        self.open(path, spec, cancel, None).await
    }

    async fn open_binary_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: OpenReporter,
    ) -> EngineResult<ProgramInfo> {
        self.open(path, spec, cancel, Some(&report)).await
    }
}

impl DotnetEngine {
    /// Opens `path`, telling `report` the coarse stages (the sidecar reports nothing itself).
    async fn open(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: Option<&OpenReporter>,
    ) -> EngineResult<ProgramInfo> {
        let say = |stage: OpenStage, message: &str| {
            if let Some(r) = report {
                r(OpenUpdate::stage(stage, message));
            }
        };
        if let Some(f) = &spec.format
            && f != "dotnet"
        {
            return Err(unsupported(&format!(
                "format `{f}` (this engine opens `dotnet`)"
            )));
        }
        if spec.arch.is_some() {
            return Err(unsupported("an arch override"));
        }
        if spec.base.is_some() {
            return Err(unsupported("an image base override"));
        }
        let assembly = std::fs::canonicalize(path).map_err(|e| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!("cannot open {}: {e}", path.display()),
            )
        })?;

        self.shutdown();
        *self
            .annotations
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Annotations::new();
        say(OpenStage::StartEngine, "Starting the .NET engine");
        let launched = launch(LaunchPlan {
            install: self.config.install.clone(),
            assembly: assembly.clone(),
            heap_mb: self.config.max_heap_mb,
            confinement: self.config.confinement.clone(),
            temp_root: self.config.temp_root.clone(),
        })
        .await?;
        let client = RpcClient::new(launched.reader, launched.writer);
        let handshake: WireHandshake = client
            .call_typed(
                "handshake",
                json!({}),
                Some(self.config.startup_timeout),
                Some(cancel),
            )
            .await
            .map_err(|e| e.with_details(json!({"log_tail": launched.log.tail(20)})))?;
        check_handshake(&handshake)?;

        let params = json!({"path": assembly});
        say(OpenStage::ReadFile, "Loading the assemblies");
        let raw: Value = client
            .call(
                "open_assembly",
                params,
                Some(self.config.deadlines.open),
                Some(cancel),
            )
            .await
            .map_err(|e| e.with_details(json!({"log_tail": launched.log.tail(20)})))?;
        let wire: WireProgramInfo = serde_json::from_value(raw.clone()).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("malformed open_assembly result: {e}"),
            )
        })?;
        let info: AssemblyInfo = serde_json::from_value(raw).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("malformed open_assembly result: {e}"),
            )
        })?;

        let running = Arc::new(Running {
            client,
            log: launched.log,
            report: launched.report,
            pid: launched.pid,
            build: handshake.build,
            info,
            exit: launched.exit,
            guard: launched.guard,
        });
        *self.running.lock().unwrap_or_else(PoisonError::into_inner) = Some(running);
        Ok(ProgramInfo {
            arch: wire.arch,
            format: wire.format,
            base: wire.base,
            sha256: wire.sha256,
            size: wire.size,
            ..ProgramInfo::default()
        })
    }
}

#[async_trait]
impl FunctionLister for DotnetEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        let mut p: Page<FunctionSummary> = self
            .call(
                "list_functions",
                page_params(page),
                self.config.deadlines.default,
                cancel,
            )
            .await?;
        let notes = self.notes();
        if !notes.is_empty() {
            let mvid = self.module_mvid()?;
            p.items = p
                .items
                .into_iter()
                .map(|f| notes.apply_summary(f, &mvid))
                .collect();
        }
        Ok(p)
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        let f = self.raw_function(locator, cancel).await?;
        Ok(self.notes().apply_summary(f, &self.module_mvid()?))
    }
}

#[async_trait]
impl Decompiler for DotnetEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        let locator = self.require_managed(locator)?;
        let d = self.config.deadlines.decompile;
        // The sidecar gets a slightly shorter timeout so that its error arrives first.
        let sidecar_ms = u64::try_from(d.as_millis().saturating_sub(500))
            .unwrap_or(u64::MAX)
            .max(1);
        let result: DecompileResult = self
            .call(
                "decompile",
                json!({"locator": locator, "timeout_ms": sidecar_ms}),
                d,
                cancel,
            )
            .await?;
        result.validate_tokens()?;
        let result = self.notes().apply_decompile(result, &self.module_mvid()?);
        result.validate_tokens()?;
        Ok(result)
    }
}

#[async_trait]
impl TypeStore for DotnetEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        self.call(
            "get_type",
            json!({"name": name}),
            self.config.deadlines.default,
            cancel,
        )
        .await
    }

    async fn define_type(&self, _def: TypeDef, _cancel: &CancellationToken) -> EngineResult<()> {
        Err(unsupported(
            "defining types in a managed assembly (the .NET engine's type store is read-only)",
        ))
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        self.call(
            "list_types",
            page_params(page),
            self.config.deadlines.default,
            cancel,
        )
        .await
    }
}

fn parse_anchor(anchor: &kraken_proto::Anchor, mvid: &str) -> Result<u32, EngineRejected> {
    let Some((module, token)) = anchor.managed_parts() else {
        return Err(EngineRejected::new(
            ErrorCode::Unsupported,
            "the .NET engine takes managed anchors only (use the `module` argument)",
        ));
    };
    if module != mvid {
        return Err(EngineRejected::new(
            ErrorCode::NotFound,
            format!("module {module} is not the open assembly ({mvid})"),
        ));
    }
    Ok(token)
}

#[async_trait]
impl Mutator for DotnetEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        op.check_version()?;
        let mvid = self.module_mvid()?;
        match &op.op {
            LogOp::Rename {
                anchor,
                old_name,
                new_name,
            } => {
                let token = parse_anchor(anchor, &mvid)?;
                if !annotate::is_renamable(token) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        format!("token {token:#x} is not a type, member or parameter"),
                    ));
                }
                let listed = match annotate::table_of(token) {
                    0x06 => Some(
                        self.raw_function(&Locator::managed(&mvid, token), cancel)
                            .await?
                            .name,
                    ),
                    _ => None,
                };
                if listed.as_deref().is_some_and(annotate::is_constructor) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "a constructor is named after its type; rename the type instead",
                    ));
                }
                let original = listed.as_deref().map(annotate::ident_of);
                let mut notes = self
                    .annotations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let current = notes.name(token).or(original).map(str::to_string);
                // The edit log holds the listed name (`Ns.Type.Method`) or the bare identifier.
                let is_current = |name: &str| {
                    current.as_deref().is_some_and(|c| {
                        name == c
                            || listed
                                .as_deref()
                                .is_some_and(|l| name == annotate::display_name(l, c))
                    })
                };
                if let Some(old) = old_name
                    && current.is_some()
                    && !is_current(old)
                    && !is_current(new_name)
                {
                    return Err(EngineRejected::new(
                        ErrorCode::ConflictStaleRead,
                        format!("the name is not `{old}`"),
                    ));
                }
                // Undo hands back the listed name; anything else must be a plain identifier.
                let new_ident = listed
                    .as_deref()
                    .and_then(|l| l.rsplit_once('.'))
                    .and_then(|(prefix, _)| new_name.strip_prefix(prefix))
                    .and_then(|r| r.strip_prefix('.'))
                    .unwrap_or(new_name);
                if new_name.is_empty() || original == Some(new_ident) {
                    notes.set_name(token, None);
                } else {
                    annotate::validate_identifier(new_ident)?;
                    notes.set_name(token, Some(new_ident.to_string()));
                }
            }
            LogOp::SetComment {
                anchor,
                comment_kind,
                old,
                new,
            } => {
                let token = parse_anchor(anchor, &mvid)?;
                if annotate::table_of(token) != 0x06 {
                    return Err(EngineRejected::new(
                        ErrorCode::Unsupported,
                        "comments attach to methods only in the .NET engine",
                    ));
                }
                self.raw_function(&Locator::managed(&mvid, token), cancel)
                    .await?;
                let mut notes = self
                    .annotations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let cur = notes.comment(token, *comment_kind).map(str::to_string);
                if let (Some(old), Some(cur)) = (old.as_deref(), cur.as_deref())
                    && old != cur
                    && new.as_deref() != Some(cur)
                {
                    return Err(EngineRejected::new(
                        ErrorCode::ConflictStaleRead,
                        "the comment changed since it was read",
                    ));
                }
                notes.set_comment(token, *comment_kind, new.clone());
            }
            other => {
                return Err(EngineRejected::new(
                    ErrorCode::Unsupported,
                    format!(
                        "{} is not supported for .NET assemblies; only renames and comments are",
                        op_name(other)
                    ),
                ));
            }
        }
        self.applied.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn save(&self, _cancel: &CancellationToken) -> EngineResult<Watermark> {
        Ok(Watermark(format!(
            "dotnet-{}",
            self.applied.load(Ordering::Relaxed)
        )))
    }
}

fn op_name(op: &LogOp) -> &'static str {
    match op {
        LogOp::Rename { .. } => "rename",
        LogOp::SetType { .. } => "set_type",
        LogOp::SetComment { .. } => "set_comment",
        LogOp::CreateFunction { .. } => "create_function",
        LogOp::DeleteFunction { .. } => "delete_function",
        LogOp::SetFunctionBounds { .. } => "set_function_bounds",
        LogOp::SetCodeData { .. } => "set_code_data",
        LogOp::SetCallingConvention { .. } => "set_calling_convention",
        LogOp::SetPatch { .. } => "set_patch",
        LogOp::SetLocal { .. } => "set_local",
        LogOp::DefineType { .. } => "define_type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::Capability;

    fn hs(major: u32, minor: u32, caps: &[&str]) -> WireHandshake {
        WireHandshake {
            protocol: kraken_proto::ProtocolVersion { major, minor },
            build: "t".into(),
            capabilities: caps
                .iter()
                .map(|n| Capability {
                    name: (*n).to_string(),
                    version: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn handshake_checks_protocol_and_capabilities() {
        assert!(check_handshake(&hs(0, 1, REQUIRED_SIDECAR_CAPABILITIES)).is_ok());
        let e = check_handshake(&hs(0, 2, REQUIRED_SIDECAR_CAPABILITIES)).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
        let e = check_handshake(&hs(0, 1, &["open_assembly"])).unwrap_err();
        assert!(e.message.contains("decompile.tokens"), "{}", e.message);
    }

    #[test]
    fn page_params_clamp_limit() {
        let p = page_params(&PageRequest {
            cursor: Some("7".into()),
            limit: Some(0),
        });
        assert_eq!(p, json!({"cursor": "7", "limit": 1}));
    }

    #[test]
    fn asm_info_parses_the_open_result() {
        let v = json!({
            "arch": "cil", "format": "dotnet", "base": "0x400000", "sha256": "ab", "size": 3,
            "module_mvid": "61a35c05-1940-4673-81a7-f2157a66b75c", "assembly": "x",
            "target_framework": ".NETCoreApp,Version=v10.0", "method_count": 13, "type_count": 7,
        });
        let info: AssemblyInfo = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(info.method_count, 13);
        let w: WireProgramInfo = serde_json::from_value(v).unwrap();
        assert_eq!((w.arch.as_str(), w.format.as_str()), ("cil", "dotnet"));
    }
}
