//! `debuginfo_probe`, `debuginfo_attach` and `debuginfo_detach`: the debug information a program
//! refers to, whether the matching file is on this computer, and attaching it to a project.
//!
//! A match is never taken on a name alone: an ELF debug file must carry the program's GNU
//! build-id (or, without one, the CRC-32 of the program's `.gnu_debuglink`), a PDB must carry the
//! GUID and age of the program's CodeView record.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kraken_proto::{DebugRefs, DwarfState, ErrorCode, ProtoError, Untrusted};
use object::{Object, ObjectSection};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{AnalysisPhase, EngineKind, Session, blocking};
use crate::trust;

use super::probe::{debug_refs, format_guid};
use super::{JobStarted, NoArgs};

/// A debug file larger than this is not read.
const MAX_DEBUG_FILE: u64 = 2 << 30;
/// Where distributions install debug packages.
const SYSTEM_DEBUG_DIR: &str = "/usr/lib/debug";

/// Where a candidate file was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    /// Next to the program (or in its `.debug` directory).
    Beside,
    /// Under `/usr/lib/debug` (installed debug packages).
    System,
    /// In the debuginfod download cache.
    Debuginfod,
    /// The file or folder the person named.
    Chosen,
}

impl CandidateSource {
    /// Where the file is, in words.
    pub fn label(self) -> &'static str {
        match self {
            CandidateSource::Beside => "beside the program",
            CandidateSource::System => "in the system debug directory",
            CandidateSource::Debuginfod => "in the debuginfod cache",
            CandidateSource::Chosen => "chosen by you",
        }
    }
}

/// Whether a candidate is the program's own debug file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The build-id, CRC or GUID and age agree.
    Match,
    /// The program carries nothing to check against, but the file holds debug information.
    Unverified,
    /// The file belongs to another build.
    Mismatch,
    /// The file holds no debug information, or is not a format KRAKEN reads.
    NotDebugInfo,
}

/// One file that might hold the program's debug information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugCandidate {
    /// Absolute path of the file.
    pub path: Untrusted<String>,
    /// Where it was found.
    pub source: CandidateSource,
    /// The result of the check.
    pub verdict: Verdict,
    /// What was compared, in a sentence a person can read; on a mismatch it says why.
    pub detail: Untrusted<String>,
}

/// How the program stands with its debug information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugStatus {
    /// The debug information is inside the program.
    Embedded,
    /// It is in a separate file and a matching file was found.
    Found,
    /// It is in a separate file and none was found.
    Missing,
    /// The program neither holds nor names any.
    None,
}

/// Arguments of `debuginfo_probe`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugInfoProbeArgs {
    /// Path of the program.
    pub path: String,
    /// A debug file, or a folder to look in, to check against the program as well.
    #[serde(default)]
    pub debug_file: Option<String>,
}

/// What `debuginfo_probe` found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugInfoProbeOut {
    /// The program that was read.
    pub path: Untrusted<String>,
    /// What the program says about its debug information.
    pub refs: DebugRefs,
    /// Where the program stands.
    pub status: DebugStatus,
    /// One or two sentences in plain words.
    pub summary: String,
    /// What a matching file must carry, one line each (`GNU build-id ...`).
    pub wants: Vec<String>,
    /// The places that were searched.
    pub searched: Vec<Untrusted<String>>,
    /// Files that exist at those places (and the one that was chosen), each checked.
    pub candidates: Vec<DebugCandidate>,
    /// The first candidate that matches, or is unverified; what `debuginfo_attach` would use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub best: Option<Untrusted<String>>,
}

fn invalid(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, m.into())
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    !data.iter().fold(!0u32, |c, b| {
        table[((c ^ u32::from(*b)) & 0xff) as usize] ^ (c >> 8)
    })
}

/// GUID and age of a PDB (the MSF container's stream 1); `None` when the data is not one.
pub fn pdb_identity(data: &[u8]) -> Option<(String, u32)> {
    const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
    if data.get(..MAGIC.len())? != MAGIC {
        return None;
    }
    let u32_at = |d: &[u8], o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
    };
    let bs = u32_at(data, 32)? as usize;
    let dir_bytes = u32_at(data, 44)? as usize;
    let map_addr = u32_at(data, 52)? as usize;
    if !(512..=65536).contains(&bs) || dir_bytes > data.len() {
        return None;
    }
    let block = |i: usize| {
        let start = i.checked_mul(bs)?;
        data.get(start..start.checked_add(bs)?)
    };
    let dir_blocks = dir_bytes.div_ceil(bs);
    let mut dir = Vec::with_capacity(dir_blocks * bs);
    for n in 0..dir_blocks {
        let at = map_addr.checked_mul(bs)?.checked_add(n * 4)?;
        dir.extend_from_slice(block(u32_at(data, at)? as usize)?);
    }
    dir.truncate(dir_bytes);
    let streams = u32_at(&dir, 0)? as usize;
    if streams < 2 || streams > dir.len() / 4 {
        return None;
    }
    let size = |n: usize| -> Option<usize> {
        let s = u32_at(&dir, 4 + n * 4)?;
        Some(if s == u32::MAX { 0 } else { s as usize })
    };
    let (s0, s1) = (size(0)?, size(1)?);
    if s1 < 28 {
        return None;
    }
    // block lists follow the sizes, stream by stream
    let first1 = 4 + streams * 4 + s0.div_ceil(bs) * 4;
    let mut info = Vec::new();
    for n in 0..s1.div_ceil(bs).min(2) {
        info.extend_from_slice(block(u32_at(&dir, first1 + n * 4)? as usize)?);
    }
    let age = u32_at(&info, 8)?;
    let g: [u8; 16] = info.get(12..28)?.try_into().ok()?;
    Some((format_guid(&g), age))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn base_name(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

/// What a matching file must carry, in words.
fn wants_of(refs: &DebugRefs) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(p) = &refs.pdb {
        w.push(format!(
            "PDB {} with GUID {} and age {}",
            base_name(&p.name.0),
            p.guid,
            p.age
        ));
    }
    if let Some(id) = &refs.build_id {
        w.push(format!("GNU build-id {id}"));
    }
    if let Some(l) = &refs.debuglink {
        w.push(format!(
            "debug link `{}` with CRC-32 {:#010x}",
            l.name.0, l.crc
        ));
    }
    w
}

/// Checks one file against what the program refers to.
fn verify(refs: &DebugRefs, candidate: &Path) -> (Verdict, String) {
    let meta = match std::fs::metadata(candidate) {
        Ok(m) if m.is_file() => m,
        _ => return (Verdict::NotDebugInfo, "it is not a readable file".into()),
    };
    if meta.len() > MAX_DEBUG_FILE {
        return (Verdict::NotDebugInfo, "it is too large to read".into());
    }
    let Ok(data) = std::fs::read(candidate) else {
        return (Verdict::NotDebugInfo, "it could not be read".into());
    };
    if let Some(pdb) = &refs.pdb {
        let Some((guid, age)) = pdb_identity(&data) else {
            return (
                Verdict::NotDebugInfo,
                "the program names a PDB, and this is not one".into(),
            );
        };
        if guid != pdb.guid {
            return (
                Verdict::Mismatch,
                format!(
                    "the PDB's GUID is {guid} but the program was built with {}: it is from another build",
                    pdb.guid
                ),
            );
        }
        if age != pdb.age {
            return (
                Verdict::Mismatch,
                format!(
                    "the GUID agrees but the PDB's age is {age} and the program's is {}: one of them was rebuilt or relinked",
                    pdb.age
                ),
            );
        }
        return (
            Verdict::Match,
            format!("GUID {guid} and age {age} agree with the program"),
        );
    }
    let Ok(file) = object::File::parse(&*data) else {
        return (
            Verdict::NotDebugInfo,
            "it is not an object file KRAKEN reads (expected an ELF debug file)".into(),
        );
    };
    let has_dwarf = file.sections().any(|s| {
        s.name()
            .is_ok_and(|n| matches!(n, ".debug_info" | ".zdebug_info"))
    });
    if !has_dwarf {
        return (
            Verdict::NotDebugInfo,
            "the file has no debug information (no DWARF .debug_info section)".into(),
        );
    }
    if let (Some(want), Ok(Some(theirs))) = (&refs.build_id, file.build_id()) {
        return if hex(theirs) == *want {
            (
                Verdict::Match,
                format!("build-id {want} agrees with the program"),
            )
        } else {
            (
                Verdict::Mismatch,
                format!(
                    "its build-id is {} but the program's is {want}: it is from another build",
                    hex(theirs)
                ),
            )
        };
    }
    if let Some(link) = &refs.debuglink {
        let got = crc32(&data);
        return if got == link.crc {
            (
                Verdict::Match,
                format!("the CRC-32 {got:#010x} is the one the debug link names"),
            )
        } else {
            (
                Verdict::Mismatch,
                format!(
                    "its CRC-32 is {got:#010x} but the program's debug link wants {:#010x}: it is from another build or was changed",
                    link.crc
                ),
            )
        };
    }
    (
        Verdict::Unverified,
        "the program carries no build-id or debug link, so KRAKEN cannot prove this file belongs to it".into(),
    )
}

fn debuginfod_cache() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DEBUGINFOD_CACHE_PATH") {
        return Some(PathBuf::from(p));
    }
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(x).join("debuginfod_client"));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/debuginfod_client"))
}

/// The places a debug file for `binary` may be, best first.
fn locations(binary: &Path, refs: &DebugRefs, system: &Path) -> Vec<(PathBuf, CandidateSource)> {
    let mut out = Vec::new();
    let dir = binary.parent().map(Path::to_path_buf).unwrap_or_default();
    if let Some(p) = &refs.pdb {
        let name = base_name(&p.name.0);
        if !name.is_empty() {
            out.push((dir.join(name), CandidateSource::Beside));
        }
        if let Some(stem) = binary.file_stem() {
            let mut n = stem.to_os_string();
            n.push(".pdb");
            out.push((dir.join(n), CandidateSource::Beside));
        }
    }
    if let Some(id) = &refs.build_id
        && id.len() > 2
    {
        let rel = format!(".build-id/{}/{}.debug", &id[..2], &id[2..]);
        out.push((dir.join(&rel), CandidateSource::Beside));
        out.push((system.join(&rel), CandidateSource::System));
        if let Some(c) = debuginfod_cache() {
            out.push((c.join(id).join("debuginfo"), CandidateSource::Debuginfod));
        }
    }
    if let Some(l) = &refs.debuglink
        && !l.name.0.is_empty()
        && !l.name.0.contains('/')
    {
        let name = &l.name.0;
        out.push((dir.join(name), CandidateSource::Beside));
        out.push((dir.join(".debug").join(name), CandidateSource::Beside));
        let abs = dir.canonicalize().unwrap_or(dir);
        out.push((
            system
                .join(abs.strip_prefix("/").unwrap_or(&abs))
                .join(name),
            CandidateSource::System,
        ));
    }
    let mut seen = Vec::new();
    out.retain(|(p, _)| {
        let new = !seen.contains(p);
        seen.push(p.clone());
        new
    });
    out
}

/// The files a folder chosen by the person may hold the debug file in.
fn in_folder(folder: &Path, binary: &Path, refs: &DebugRefs) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = &refs.pdb {
        out.push(folder.join(base_name(&p.name.0)));
    }
    if let Some(stem) = binary.file_stem().and_then(|s| s.to_str()) {
        out.push(folder.join(format!("{stem}.pdb")));
        out.push(folder.join(format!("{stem}.debug")));
    }
    if let Some(name) = binary.file_name().and_then(|s| s.to_str()) {
        out.push(folder.join(format!("{name}.debug")));
    }
    if let Some(id) = &refs.build_id
        && id.len() > 2
    {
        out.push(folder.join(format!(".build-id/{}/{}.debug", &id[..2], &id[2..])));
        out.push(folder.join(format!("{id}.debug")));
    }
    if let Some(l) = &refs.debuglink
        && !l.name.0.contains('/')
    {
        out.push(folder.join(&l.name.0));
        out.push(folder.join(".debug").join(&l.name.0));
    }
    out
}

fn status_of(refs: &DebugRefs, found: bool) -> DebugStatus {
    if refs.embedded() {
        DebugStatus::Embedded
    } else if refs.external() || found {
        if found {
            DebugStatus::Found
        } else {
            DebugStatus::Missing
        }
    } else {
        DebugStatus::None
    }
}

fn summary_of(
    refs: &DebugRefs,
    status: DebugStatus,
    wants: &[String],
    found: Option<&str>,
) -> String {
    match status {
        DebugStatus::Embedded => format!(
            "The debug information is inside the program ({}). Nothing else is needed.",
            if refs.dwarf == Some(DwarfState::Compressed) {
                "compressed DWARF"
            } else {
                "DWARF"
            }
        ),
        DebugStatus::Found => format!(
            "A matching debug file was found: {}.",
            found.unwrap_or("")
        ),
        DebugStatus::Missing => format!(
            "The program keeps its debug information in a separate file that was not found. It looks for: {}. Point KRAKEN at the file or the folder that has it.",
            wants.join("; ")
        ),
        DebugStatus::None => "The program holds no debug information and does not name a file that does (it is stripped). Names will come from symbols and analysis only, unless you have a debug file: point KRAKEN at it.".into(),
    }
}

fn add_candidate(
    refs: &DebugRefs,
    p: PathBuf,
    source: CandidateSource,
    candidates: &mut Vec<DebugCandidate>,
) {
    let p = std::fs::canonicalize(&p).unwrap_or(p);
    let shown = p.to_string_lossy().into_owned();
    if candidates.iter().any(|c| c.path.0 == shown) {
        return;
    }
    let (verdict, detail) = verify(refs, &p);
    candidates.push(DebugCandidate {
        path: Untrusted::sanitized(&shown),
        source,
        verdict,
        detail: Untrusted::sanitized(&detail),
    });
}

/// Reads `path` and checks everything the program refers to, plus `extra` (a file or folder).
pub fn probe(path: &Path, extra: Option<&Path>) -> Result<DebugInfoProbeOut, ProtoError> {
    probe_in(path, extra, Path::new(SYSTEM_DEBUG_DIR))
}

fn probe_in(
    path: &Path,
    extra: Option<&Path>,
    system: &Path,
) -> Result<DebugInfoProbeOut, ProtoError> {
    trust::ensure_regular_file(path)?;
    let data = std::fs::read(path).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let refs = object::File::parse(&*data)
        .map(|f| debug_refs(&f))
        .map_err(|_| {
            invalid(format!(
                "{} is not an ELF, PE or Mach-O file",
                path.display()
            ))
        })?;
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut searched = Vec::new();
    let mut candidates: Vec<DebugCandidate> = Vec::new();
    if refs.external() {
        for (p, source) in locations(&abs, &refs, system) {
            searched.push(Untrusted::sanitized(&p.to_string_lossy()));
            if p.is_file() {
                add_candidate(&refs, p, source, &mut candidates);
            }
        }
    }
    if let Some(extra) = extra {
        if extra.is_dir() {
            let before = candidates.len();
            let mut tried = Vec::new();
            for p in in_folder(extra, &abs, &refs) {
                tried.push(base_name(&p.to_string_lossy()).to_string());
                let shown = Untrusted::sanitized(&p.to_string_lossy());
                if !searched.contains(&shown) {
                    searched.push(shown);
                }
                if p.is_file() {
                    add_candidate(&refs, p, CandidateSource::Chosen, &mut candidates);
                }
            }
            if candidates.len() == before {
                tried.dedup();
                return Err(invalid(format!(
                    "{} has no debug file for this program (looked for {})",
                    extra.display(),
                    tried.join(", ")
                )));
            }
        } else {
            if !extra.exists() {
                return Err(ProtoError::new(
                    ErrorCode::NotFound,
                    format!("{} does not exist", extra.display()),
                ));
            }
            searched.push(Untrusted::sanitized(&extra.to_string_lossy()));
            add_candidate(
                &refs,
                extra.to_path_buf(),
                CandidateSource::Chosen,
                &mut candidates,
            );
        }
    }
    let rank = |c: &DebugCandidate| match c.verdict {
        Verdict::Match => 0,
        Verdict::Unverified => 1,
        _ => 2,
    };
    candidates.sort_by_key(rank);
    let best_candidate = candidates
        .iter()
        .find(|c| matches!(c.verdict, Verdict::Match | Verdict::Unverified));
    let best = best_candidate.map(|c| c.path.clone());
    let wants = wants_of(&refs);
    let status = status_of(&refs, best.is_some());
    let found = best_candidate.map(|c| format!("{} ({})", c.path.0, c.source.label()));
    let summary = summary_of(&refs, status, &wants, found.as_deref());
    Ok(DebugInfoProbeOut {
        path: Untrusted::sanitized(&abs.to_string_lossy()),
        refs,
        status,
        summary,
        wants,
        searched,
        candidates,
        best,
    })
}

/// The file to attach to `binary` for `debug_file` (a file or a folder): checked, or the reason
/// it cannot be used.
pub fn resolve_for_attach(binary: &Path, debug_file: &Path) -> Result<PathBuf, ProtoError> {
    let out = probe(binary, Some(debug_file))?;
    let chosen: Vec<_> = out
        .candidates
        .iter()
        .filter(|c| c.source == CandidateSource::Chosen)
        .collect();
    if let Some(c) = chosen
        .iter()
        .find(|c| matches!(c.verdict, Verdict::Match | Verdict::Unverified))
    {
        return Ok(PathBuf::from(&c.path.0));
    }
    let why = chosen.first().map_or_else(
        || "it is not a debug file".to_string(),
        |c| c.detail.0.clone(),
    );
    Err(invalid(format!(
        "{} is not the debug file of this program: {why}",
        debug_file.display()
    )))
}

fn check_path(ctx: &CallContext, what: &str, p: &str) -> Result<PathBuf, ProtoError> {
    if ctx.needs_user_approval() {
        trust::check_agent_path(what, Path::new(p))
    } else {
        Ok(PathBuf::from(p))
    }
}

/// Looks for the debug information of a program.
pub struct DebugInfoProbe;

#[async_trait]
impl Command for DebugInfoProbe {
    type Args = DebugInfoProbeArgs;
    type Output = DebugInfoProbeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debuginfo_probe",
            "Say what debug information a program refers to and where a matching file is",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Reads a program's PDB reference (name, GUID, age), GNU build-id, debug link and \
             DWARF state, then looks where such files live (beside the program, `.debug`, \
             `/usr/lib/debug`, the debuginfod cache) and checks every file it finds: the \
             build-id, the debug-link CRC or the PDB's GUID and age must agree. Pass \
             `debug_file` (a file or a folder) to check one you have. Needs no project.\n\
             Example: debuginfo_probe {\"path\": \"/usr/bin/ls\"}",
        )
        .details(
            "`status` is `embedded` (inside the program), `found` (a separate file matched or \
             could not be disproved), `missing` or `none`. Each candidate has a `verdict`: \
             `match`, `unverified` (the program has nothing to compare), `mismatch` (another \
             build; `detail` says what differs) or `not_debug_info`. `best` is what \
             `debuginfo_attach` or `project_create` with `debug_file` would use. Nothing is \
             attached and no file is changed. Agents may not read files in hidden folders of the \
             home directory.",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        ctx: &CallContext,
        args: DebugInfoProbeArgs,
    ) -> Result<DebugInfoProbeOut, ProtoError> {
        let path = check_path(ctx, "path", &args.path)?;
        let extra = args
            .debug_file
            .filter(|d| !d.trim().is_empty())
            .map(|d| check_path(ctx, "debug_file", &d))
            .transpose()?;
        blocking(move || probe(&path, extra.as_deref())).await
    }
}

/// Arguments of `debuginfo_attach`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugInfoAttachArgs {
    /// The debug file (an ELF `.debug` file with DWARF), or a folder that holds it.
    pub debug_file: String,
}

/// Whether `kind` can use `file`: the native engine reads separate DWARF, Ghidra a PDB.
pub fn engine_accepts(kind: EngineKind, file: &Path) -> Result<(), ProtoError> {
    let is_pdb = std::fs::read(file)
        .ok()
        .is_some_and(|d| pdb_identity(&d).is_some());
    let unsupported = |m: &str| Err(ProtoError::new(ErrorCode::Unsupported, m.to_string()));
    match (kind, is_pdb) {
        (EngineKind::Native, false) | (EngineKind::Ghidra, true) => Ok(()),
        (EngineKind::Native, true) => unsupported(
            "the native engine does not read PDB files yet; open the program with the Ghidra engine to use a PDB",
        ),
        (EngineKind::Ghidra, false) => unsupported(
            "Ghidra reads PDB files; a separate DWARF file works with the native engine (`engine: native`)",
        ),
        (EngineKind::Dotnet, _) => {
            unsupported("a .NET assembly carries its own metadata; debug files do not apply")
        }
    }
}

/// Where the Ghidra engine finds a PDB: the one beside the program under the program's name.
fn ghidra_sees(binary: &Path, pdb: &Path) -> bool {
    let (Some(dir), Some(stem)) = (binary.parent(), binary.file_stem()) else {
        return false;
    };
    let mut n = stem.to_os_string();
    n.push(".pdb");
    match (dir.join(n).canonicalize(), pdb.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn set_debug_file(m: &mut crate::session::ProjectMeta, file: Option<String>) {
    let mut loader = m.loader.take().unwrap_or_default();
    loader.debug_file = file;
    m.loader = (loader != kraken_engine::LoaderSpec::default()).then_some(loader);
}

async fn rebuild_with(s: &Session, file: Option<String>) -> Result<JobStarted, ProtoError> {
    let project = s.project()?;
    let factory = s.factory().clone();
    let prev = project.analysis().phase;
    let old_file = project.meta().loader.and_then(|l| l.debug_file);
    let started = project.begin_analysis(|| {
        let project = project.clone();
        project.update_meta(|m| set_debug_file(m, file));
        s.jobs().spawn("rebuild", move |reporter| async move {
            if let Err(e) = project.persist_meta().await {
                project.end_analysis(back_to(prev), None, Some(e.message.clone()));
                return Err(e);
            }
            let r = super::rebuild::run_rebuild(project.clone(), factory, reporter, prev).await;
            if r.is_err() {
                project.update_meta(|m| set_debug_file(m, old_file));
                let _ = project.persist_meta().await;
            }
            r
        })
    });
    match started {
        Ok(id) => Ok(JobStarted { job_id: id.0 }),
        Err(_) => Err(invalid("analysis or a rebuild is already running")),
    }
}

fn back_to(p: AnalysisPhase) -> AnalysisPhase {
    if p == AnalysisPhase::Running {
        AnalysisPhase::NotStarted
    } else {
        p
    }
}

/// Attaches a separate debug file to the open project.
pub struct DebugInfoAttach;

#[async_trait]
impl Command for DebugInfoAttach {
    type Args = DebugInfoAttachArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debuginfo_attach",
            "Attach a separate debug file to the project and reopen the engine with it (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Checks that the file is this program's own debug file (build-id or debug-link \
             CRC for DWARF; GUID and age for a PDB), records it in the project, and rebuilds \
             the engine project with it, which re-analyses and replays your edits. Returns a \
             `job_id`. Undo it with `debuginfo_detach`.\n\
             Example: debuginfo_attach {\"debug_file\": \"./prog.debug\"}",
        )
        .details(
            "A file that belongs to another build is refused with the reason (`debuginfo_probe` \
             shows the comparison). The native engine reads separate DWARF (ELF); Ghidra reads \
             a PDB that sits beside the program as `<name>.pdb`. The path is kept in \
             `meta.json` (`loader.debug_file`) and used on every reopen and `rebuild`. The job \
             result is a `RebuildReport`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: DebugInfoAttachArgs,
    ) -> Result<JobStarted, ProtoError> {
        let given = check_path(ctx, "debug_file", &args.debug_file)?;
        let meta = s.project()?.meta();
        let binary = PathBuf::from(&meta.binary_path);
        let kind = meta.engine_kind;
        let file = blocking(move || {
            let file = resolve_for_attach(&binary, &given)?;
            engine_accepts(kind, &file)?;
            if kind == EngineKind::Ghidra && !ghidra_sees(&binary, &file) {
                let stem = binary
                    .file_stem()
                    .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "Ghidra reads a PDB that is beside the program under the program's name; copy {} next to {} as {stem}.pdb and attach that",
                        file.display(),
                        binary.display(),
                    ),
                ));
            }
            Ok(file)
        })
        .await?;
        rebuild_with(s, Some(file.to_string_lossy().into_owned())).await
    }
}

/// Removes the attached debug file from the open project.
pub struct DebugInfoDetach;

#[async_trait]
impl Command for DebugInfoDetach {
    type Args = NoArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debuginfo_detach",
            "Remove the attached debug file and reopen the engine without it (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Forgets the debug file attached with `debuginfo_attach` and rebuilds the engine \
             project without it. The file itself is not touched. Fails when none is attached.\n\
             Example: debuginfo_detach {}",
        )
        .details(
            "Returns a `job_id` like `rebuild`. A file the engine finds on its own (beside the \
             program, under `/usr/lib/debug`) is still used after detaching.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<JobStarted, ProtoError> {
        let meta = s.project()?.meta();
        if meta.loader.and_then(|l| l.debug_file).is_none() {
            return Err(invalid("no debug file is attached to this project"));
        }
        rebuild_with(s, None).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal MSF 7 file: block size 512, stream 0 empty, stream 1 the PDB info stream.
    pub(crate) fn synthetic_pdb(guid: [u8; 16], age: u32) -> Vec<u8> {
        let bs = 512usize;
        let mut f = vec![0u8; bs * 5];
        f[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
        let put = |f: &mut Vec<u8>, o: usize, v: u32| f[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut f, 32, bs as u32);
        put(&mut f, 40, 5);
        put(&mut f, 44, 4 + 2 * 4 + 4);
        put(&mut f, 52, 2);
        put(&mut f, 2 * bs, 3);
        let d = 3 * bs;
        put(&mut f, d, 2);
        put(&mut f, d + 4, 0);
        put(&mut f, d + 8, 28);
        put(&mut f, d + 12, 4);
        let i = 4 * bs;
        put(&mut f, i + 8, age);
        f[i + 12..i + 28].copy_from_slice(&guid);
        f
    }

    #[test]
    fn crc32_matches_the_reference_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn pdb_identity_reads_stream_one_and_rejects_other_data() {
        assert!(pdb_identity(b"MZ not a pdb").is_none());
        let pdb = synthetic_pdb([7; 16], 3);
        let (guid, age) = pdb_identity(&pdb).expect("pdb");
        assert_eq!(age, 3);
        assert_eq!(guid, "07070707-0707-0707-0707-070707070707");
        assert!(pdb_identity(&pdb[..100]).is_none());
    }

    #[test]
    fn a_pdb_must_agree_in_guid_and_age_and_says_which_differs() {
        use kraken_proto::PdbRef;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.pdb");
        std::fs::write(&file, synthetic_pdb([7; 16], 3)).unwrap();
        let refs = |guid: &str, age: u32| DebugRefs {
            pdb: Some(PdbRef {
                name: Untrusted("C:\\build\\a.pdb".into()),
                guid: guid.into(),
                age,
            }),
            ..DebugRefs::default()
        };
        let same = "07070707-0707-0707-0707-070707070707";
        assert_eq!(verify(&refs(same, 3), &file).0, Verdict::Match);
        let (v, why) = verify(&refs(same, 2), &file);
        assert_eq!(v, Verdict::Mismatch);
        assert!(
            why.contains("age is 3") && why.contains("program's is 2"),
            "{why}"
        );
        let (v, why) = verify(&refs("AAAAAAAA-0000-0000-0000-000000000000", 3), &file);
        assert_eq!(v, Verdict::Mismatch);
        assert!(why.contains("another build"), "{why}");
        let elf = dir.path().join("x");
        std::fs::write(&elf, b"\x7fELF nothing").unwrap();
        assert_eq!(verify(&refs(same, 3), &elf).0, Verdict::NotDebugInfo);
        // the program's name for the PDB is a Windows path; the file beside it is found by base name
        assert_eq!(base_name("C:\\build\\a.pdb"), "a.pdb");
    }
}
