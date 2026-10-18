//! `binary_probe`: what a file is and which engine should open it, before a project exists.

use std::io::Read;
use std::path::Path;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use object::read::pe::ImageNtHeaders;
use object::{FileKind, LittleEndian, Object, ObjectKind, ObjectSymbol};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{EngineChoice, EngineFactory, EngineKind, EngineStatus, Session, blocking};
use crate::trust;

/// Files larger than this are only identified by their header: no symbol or debug check.
const MAX_PARSE_BYTES: u64 = 512 << 20;
/// Bytes read for the header of a file too large to parse whole.
const HEADER_BYTES: usize = 1 << 20;

/// The container format of a probed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    /// An ELF file (Linux, BSD and most Unix systems).
    Elf,
    /// A Windows PE image with native code.
    Pe,
    /// A Mach-O file (macOS, iOS).
    MachO,
    /// A .NET assembly (a PE image with managed code).
    Dotnet,
    /// A COFF object file (`.obj`, Windows code that is not linked yet) or a single import
    /// member.
    Coff,
    /// An `ar` archive: a static library (`.a`, `.lib`) or a Windows import library
    /// (`.dll.a`, `.lib`).
    Archive,
    /// Not a program KRAKEN recognises.
    Unknown,
}

impl BinaryFormat {
    /// The format in plain words.
    pub fn label(self) -> &'static str {
        match self {
            BinaryFormat::Elf => "ELF",
            BinaryFormat::Pe => "Windows PE",
            BinaryFormat::MachO => "Mach-O",
            BinaryFormat::Dotnet => ".NET assembly",
            BinaryFormat::Coff => "COFF",
            BinaryFormat::Archive => "library archive",
            BinaryFormat::Unknown => "unknown",
        }
    }
}

/// How many archive members `binary_probe` lists; `member_count` has the total.
pub const MAX_LISTED_MEMBERS: usize = 200;
/// Most members read from an archive.
const MAX_ARCHIVE_MEMBERS: usize = 200_000;

/// Arguments of `binary_probe`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BinaryProbeArgs {
    /// Path of the file to look at.
    pub path: String,
}

/// What `binary_probe` found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BinaryProbeOut {
    /// The absolute path that was read. Chosen by whoever supplied the file, so untrusted.
    pub path: Untrusted<String>,
    /// Container format.
    pub format: BinaryFormat,
    /// `executable`, `shared_library`, `object`, `static_library`, `import_library`, `core` or
    /// `unknown`.
    pub kind: String,
    /// What the file is, in plain words: `Linux shared library`, `Windows static library with
    /// 12 objects`, `COFF object (a Windows object file)`, `import library for KERNEL32.dll`.
    pub description: String,
    /// The members of an archive in file order, at most [`MAX_LISTED_MEMBERS`]; empty for other
    /// files. Names come from the file, so they are untrusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Untrusted<String>>,
    /// How many members the archive has; absent for other files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
    /// Processor, such as `x86-64`, `x86` or `AArch64`; absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// 32 or 64; absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u8>,
    /// `little` or `big`; absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endian: Option<String>,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 of the file, the hash a project would record.
    pub sha256: String,
    /// True when the file has no symbol table (function names are gone); absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stripped: Option<bool>,
    /// True when debug information (DWARF, or a PDB reference) is present; absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<bool>,
    /// Where execution starts; absent for formats without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<Hex64>,
    /// The engine `project_create` with `engine: auto` would use; absent for unknown files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_engine: Option<EngineKind>,
    /// Why that engine, in a sentence.
    pub recommended_reason: String,
    /// Each engine and whether it can run on this machine.
    pub engines: Vec<EngineStatus>,
    /// True when KRAKEN can make a project from this file.
    pub supported: bool,
    /// Why it cannot, when `supported` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

/// Header facts of a file, without the engine part.
#[derive(Debug, Clone, PartialEq, Default)]
struct Facts {
    format: Option<BinaryFormat>,
    kind: Option<&'static str>,
    arch: Option<String>,
    bits: Option<u8>,
    little: Option<bool>,
    stripped: Option<bool>,
    debug_info: Option<bool>,
    entry: Option<u64>,
    description: Option<String>,
    members: Vec<String>,
    /// Why no engine opens a file of a known format (an archive without x86 objects).
    problem: Option<String>,
}

/// What the members of an archive are.
#[derive(Debug, Default)]
struct Members {
    names: Vec<String>,
    elf: usize,
    coff: usize,
    imports: usize,
    dlls: Vec<String>,
    arch: Option<object::Architecture>,
    bits: Option<u8>,
    other_arch: Option<object::Architecture>,
    thin: bool,
}

/// Whether a file holds 64-bit code (a COFF object says so only through its machine).
fn is_64(f: &object::File<'_>) -> bool {
    f.is_64() || f.architecture().address_size() == Some(object::AddressSize::U64)
}

fn push_dll(dlls: &mut Vec<String>, dll: &str) {
    if !dll.is_empty() && !dlls.iter().any(|d| d.eq_ignore_ascii_case(dll)) {
        dlls.push(dll.to_string());
    }
}

/// Whether a COFF object is a member of a GNU import library (`.idata$` sections); its DLL
/// name when it is the member that carries it.
fn gnu_import_member(f: &object::File<'_>) -> Option<Option<String>> {
    use object::ObjectSection;
    if !f
        .sections()
        .any(|s| s.name().is_ok_and(|n| n.starts_with(".idata$")))
    {
        return None;
    }
    let iname = f
        .symbols()
        .any(|s| s.is_definition() && s.name().is_ok_and(|n| n.ends_with("_iname")));
    let dll = f
        .section_by_name(".idata$7")
        .filter(|_| iname)
        .and_then(|s| s.data().ok())
        .map(|d| {
            let end = d.iter().position(|b| *b == 0).unwrap_or(d.len());
            String::from_utf8_lossy(&d[..end]).into_owned()
        })
        .filter(|d| !d.is_empty());
    Some(dll)
}

/// Reads an archive's member list and what each member is.
fn archive_members(data: &[u8]) -> Members {
    use object::read::archive::ArchiveFile;
    use object::read::coff::ImportFile;
    let mut m = Members::default();
    let Ok(archive) = ArchiveFile::parse(data) else {
        return m;
    };
    m.thin = archive.is_thin();
    let note_arch = |m: &mut Members, a: object::Architecture, is_64: bool| {
        if m.arch.is_none() {
            m.arch = Some(a);
            m.bits = Some(if is_64 { 64 } else { 32 });
        } else if m.arch != Some(a) {
            m.other_arch.get_or_insert(a);
        }
    };
    for member in archive.members().take(MAX_ARCHIVE_MEMBERS) {
        let Ok(member) = member else { break };
        let name = String::from_utf8_lossy(member.name());
        m.names.push(name.trim_end_matches('/').to_string());
        let Ok(bytes) = member.data(data) else {
            continue;
        };
        match FileKind::parse(bytes) {
            Ok(FileKind::CoffImport) => {
                m.imports += 1;
                if let Ok(imp) = ImportFile::parse(bytes) {
                    push_dll(&mut m.dlls, &String::from_utf8_lossy(imp.dll()));
                    note_arch(
                        &mut m,
                        imp.architecture(),
                        imp.architecture().address_size() == Some(object::AddressSize::U64),
                    );
                }
            }
            Ok(FileKind::Elf32 | FileKind::Elf64 | FileKind::Coff | FileKind::CoffBig) => {
                let Ok(f) = object::File::parse(bytes) else {
                    continue;
                };
                match gnu_import_member(&f) {
                    Some(dll) => {
                        if let Some(d) = dll {
                            push_dll(&mut m.dlls, &d);
                        } else if f.symbols().any(|s| {
                            s.is_definition() && s.name().is_ok_and(|n| n.starts_with("__imp_"))
                        }) {
                            m.imports += 1;
                        }
                    }
                    None if f.format() == object::BinaryFormat::Elf => m.elf += 1,
                    None => m.coff += 1,
                }
                note_arch(&mut m, f.architecture(), is_64(&f));
            }
            _ => {}
        }
    }
    m
}

impl Members {
    fn objects(&self) -> usize {
        self.elf + self.coff
    }

    fn is_import_library(&self) -> bool {
        self.imports > 0 && self.objects() == 0
    }

    fn describe(&self) -> String {
        if self.is_import_library() {
            return match self.dlls.as_slice() {
                [] => "import library".into(),
                [one] => format!("import library for {one}"),
                [first, rest @ ..] => format!(
                    "import library for {first} and {} more DLL{}",
                    rest.len(),
                    if rest.len() == 1 { "" } else { "s" }
                ),
            };
        }
        let n = self.objects();
        let platform = if self.elf >= self.coff {
            "Linux"
        } else {
            "Windows"
        };
        format!(
            "{platform} static library with {n} object{}",
            if n == 1 { "" } else { "s" }
        )
    }

    /// Why the native engine cannot load the archive, if so.
    fn problem(&self) -> Option<String> {
        use object::Architecture as A;
        if self.thin {
            return Some(
                "it is a thin archive: its members are separate files, which KRAKEN does not \
                 follow. Make a normal archive with `ar rc` instead."
                    .into(),
            );
        }
        if self.objects() == 0 && self.imports == 0 {
            return Some(
                "the archive holds no object files KRAKEN can read (it may hold LLVM bitcode or \
                 other data)"
                    .into(),
            );
        }
        if let Some(other) = self.other_arch {
            return Some(format!(
                "the archive mixes processors ({} and {}); KRAKEN loads archives for one \
                 processor",
                arch_name(self.arch.unwrap_or(A::Unknown)),
                arch_name(other)
            ));
        }
        match self.arch {
            Some(A::X86_64 | A::I386) | None => None,
            Some(a) => Some(format!(
                "its objects are for {}; KRAKEN opens object files and libraries for x86 and \
                 x86-64 only",
                arch_name(a)
            )),
        }
    }
}

/// The plain-words description of a linked file or object.
fn describe_kind(format: BinaryFormat, kind: &str) -> String {
    match (format, kind) {
        (BinaryFormat::Elf, "executable") => "Linux program".into(),
        (BinaryFormat::Elf, "shared_library") => "Linux shared library".into(),
        (BinaryFormat::Elf, "object") => "Linux object file".into(),
        (BinaryFormat::Elf, "core") => "Linux core dump".into(),
        (BinaryFormat::Pe, "executable") => "Windows program".into(),
        (BinaryFormat::Pe, "shared_library") => "Windows DLL".into(),
        (BinaryFormat::Coff, _) => "COFF object (a Windows object file)".into(),
        (BinaryFormat::Dotnet, "shared_library") => ".NET library (an assembly)".into(),
        (BinaryFormat::Dotnet, _) => ".NET program (an assembly)".into(),
        (BinaryFormat::MachO, "shared_library") => "macOS library (Mach-O)".into(),
        (BinaryFormat::MachO, _) => "macOS program (Mach-O)".into(),
        (f, _) => format!("{} file", f.label()),
    }
}

fn arch_name(a: object::Architecture) -> String {
    use object::Architecture as A;
    match a {
        A::X86_64 => "x86-64".into(),
        A::X86_64_X32 => "x86-64 (x32)".into(),
        A::I386 => "x86".into(),
        A::Aarch64 => "AArch64".into(),
        A::Aarch64_Ilp32 => "AArch64 (ILP32)".into(),
        A::Arm => "ARM".into(),
        A::Mips => "MIPS".into(),
        A::Mips64 => "MIPS64".into(),
        A::PowerPc => "PowerPC".into(),
        A::PowerPc64 => "PowerPC64".into(),
        A::Riscv32 => "RISC-V 32".into(),
        A::Riscv64 => "RISC-V 64".into(),
        A::Unknown => "unknown".into(),
        other => format!("{other:?}"),
    }
}

fn kind_name(k: ObjectKind) -> &'static str {
    match k {
        ObjectKind::Executable => "executable",
        ObjectKind::Dynamic => "shared_library",
        ObjectKind::Relocatable => "object",
        ObjectKind::Core => "core",
        _ => "unknown",
    }
}

/// A PE image carries managed code when its CLR runtime header directory is set.
fn pe_is_managed<H: ImageNtHeaders>(data: &[u8]) -> bool {
    object::read::pe::PeFile::<H>::parse(data)
        .ok()
        .and_then(|f| {
            f.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                .map(|d| d.virtual_address.get(LittleEndian) != 0)
        })
        .unwrap_or(false)
}

/// Reads what the header (and, for a whole file, the symbol table and debug sections) says.
fn facts_of(data: &[u8], whole: bool) -> Facts {
    let Ok(file_kind) = FileKind::parse(data) else {
        return Facts::default();
    };
    match file_kind {
        FileKind::Archive => {
            let m = archive_members(data);
            let kind = if m.is_import_library() {
                "import_library"
            } else {
                "static_library"
            };
            return Facts {
                format: Some(BinaryFormat::Archive),
                kind: Some(kind),
                arch: m.arch.map(arch_name),
                bits: m.bits,
                little: m.arch.map(|_| true),
                description: Some(m.describe()),
                problem: m.problem(),
                members: m.names,
                ..Facts::default()
            };
        }
        FileKind::CoffImport => {
            let imp = object::read::coff::ImportFile::parse(data).ok();
            return Facts {
                format: Some(BinaryFormat::Coff),
                kind: Some("import_library"),
                arch: imp.as_ref().map(|i| arch_name(i.architecture())),
                little: Some(true),
                description: Some(match &imp {
                    Some(i) => format!(
                        "import library for {} (one symbol)",
                        String::from_utf8_lossy(i.dll())
                    ),
                    None => "import library".into(),
                }),
                ..Facts::default()
            };
        }
        _ => {}
    }
    let format = match file_kind {
        FileKind::Elf32 | FileKind::Elf64 => BinaryFormat::Elf,
        FileKind::Coff | FileKind::CoffBig => BinaryFormat::Coff,
        FileKind::Pe32 if pe_is_managed::<object::pe::ImageNtHeaders32>(data) => {
            BinaryFormat::Dotnet
        }
        FileKind::Pe64 if pe_is_managed::<object::pe::ImageNtHeaders64>(data) => {
            BinaryFormat::Dotnet
        }
        FileKind::Pe32 | FileKind::Pe64 => BinaryFormat::Pe,
        FileKind::MachO32 | FileKind::MachO64 => BinaryFormat::MachO,
        FileKind::MachOFat32 | FileKind::MachOFat64 => {
            return Facts {
                format: Some(BinaryFormat::MachO),
                kind: Some("executable"),
                arch: Some("several (universal binary)".into()),
                ..Facts::default()
            };
        }
        _ => return Facts::default(),
    };
    let Ok(f) = object::File::parse(data) else {
        return Facts {
            format: Some(format),
            ..Facts::default()
        };
    };
    let (stripped, debug_info) = if whole {
        let pdb = f.pdb_info().ok().flatten().is_some();
        (
            Some(f.symbols().next().is_none()),
            Some(f.has_debug_symbols() || pdb),
        )
    } else {
        (None, None)
    };
    let entry = f.entry();
    // A position-independent executable is a shared object with an interpreter.
    let kind = match f.kind() {
        ObjectKind::Dynamic
            if format == BinaryFormat::Elf && f.section_by_name(".interp").is_some() =>
        {
            "executable"
        }
        k => kind_name(k),
    };
    let problem = match (format, f.architecture()) {
        (BinaryFormat::Coff, object::Architecture::X86_64 | object::Architecture::I386) => None,
        (BinaryFormat::Coff, a) => Some(format!(
            "it is a COFF object for {}; KRAKEN opens object files for x86 and x86-64 only",
            arch_name(a)
        )),
        _ => None,
    };
    Facts {
        format: Some(format),
        kind: Some(kind),
        description: Some(describe_kind(format, kind)),
        problem,
        arch: Some(arch_name(f.architecture())),
        bits: Some(if is_64(&f) { 64 } else { 32 }),
        little: Some(f.is_little_endian()),
        stripped,
        debug_info,
        entry: (entry != 0).then_some(entry),
        members: Vec::new(),
    }
}

/// Why an archive goes to the native engine.
const NATIVE_ONLY: &str =
    "static and import libraries open with the native engine only (Ghidra does not load archives)";

/// The engine `auto` would pick and why; `None` for files no engine opens.
fn recommend(
    factory: &dyn EngineFactory,
    path: &Path,
    format: BinaryFormat,
) -> (Option<EngineKind>, String) {
    match format {
        BinaryFormat::Unknown => (
            None,
            "no engine opens this file: it is not an ELF, PE or Mach-O program or a .NET assembly"
                .into(),
        ),
        BinaryFormat::Dotnet => (
            Some(EngineKind::Dotnet),
            match factory.select_kind(path, Some(EngineChoice::Auto)) {
                Ok(s) => s.reason,
                Err(e) => e.message,
            },
        ),
        // archives (and single import members) are read by the native engine only
        BinaryFormat::Archive => (
            Some(EngineKind::Native),
            match factory.select_kind(path, Some(EngineChoice::Auto)) {
                Ok(s) if s.kind == EngineKind::Native => s.reason,
                Ok(_) => NATIVE_ONLY.into(),
                Err(e) => e.message,
            },
        ),
        _ => match factory.select_kind(path, Some(EngineChoice::Auto)) {
            Ok(s) => (Some(s.kind), s.reason),
            Err(e) => (Some(EngineKind::Ghidra), e.message),
        },
    }
}

/// Probes the file at `path` with `factory` deciding the engine. Blocking: reads and hashes the
/// whole file. The path is not checked against the agent policy; the command does that.
pub fn probe_binary(
    factory: &dyn EngineFactory,
    path: &Path,
) -> Result<BinaryProbeOut, ProtoError> {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    trust::ensure_regular_file(&abs)?;
    let io = |e: std::io::Error| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("cannot read {}: {e}", abs.display()),
        )
    };
    let size = std::fs::metadata(&abs).map_err(io)?.len();
    let whole = size <= MAX_PARSE_BYTES;
    let data = if whole {
        std::fs::read(&abs).map_err(io)?
    } else {
        let mut head = vec![0u8; HEADER_BYTES];
        let n = std::fs::File::open(&abs)
            .and_then(|mut f| f.read(&mut head))
            .map_err(io)?;
        head.truncate(n);
        head
    };
    let sha256 = if whole {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(&data))
    } else {
        crate::session::hash_file(&abs)?
    };
    let facts = facts_of(&data, whole);
    drop(data);
    let format = facts.format.unwrap_or(BinaryFormat::Unknown);
    let (recommended_engine, recommended_reason) = recommend(factory, &abs, format);
    let engines = factory.engine_status();
    let problem = match format {
        BinaryFormat::Unknown => Some(
            "KRAKEN does not recognise this file. It opens ELF, Windows PE and Mach-O programs, \
             object files, static and import libraries, and .NET assemblies."
                .to_string(),
        ),
        _ if facts.problem.is_some() => facts.problem.clone(),
        _ => recommended_engine.and_then(|kind| {
            engines
                .iter()
                .find(|e| e.kind == kind && !e.usable)
                .map(|e| match &e.problem {
                    Some(why) => format!("the {} engine is not ready: {why}", kind.as_str()),
                    None => format!("the {} engine is not ready", kind.as_str()),
                })
        }),
    };
    let kind = facts.kind.unwrap_or("unknown").to_string();
    let description = match format {
        BinaryFormat::Unknown => "not a program KRAKEN recognises".to_string(),
        _ => facts
            .description
            .clone()
            .unwrap_or_else(|| describe_kind(format, &kind)),
    };
    let member_count = (format == BinaryFormat::Archive).then_some(facts.members.len() as u64);
    let members = facts
        .members
        .iter()
        .take(MAX_LISTED_MEMBERS)
        .map(|m| Untrusted::sanitized(m))
        .collect();
    let supported = format != BinaryFormat::Unknown && facts.problem.is_none();
    Ok(BinaryProbeOut {
        path: Untrusted::sanitized(&abs.to_string_lossy()),
        format,
        kind,
        description,
        members,
        member_count,
        arch: facts.arch,
        bits: facts.bits,
        endian: facts
            .little
            .map(|l| if l { "little" } else { "big" }.to_string()),
        size,
        sha256,
        stripped: facts.stripped,
        debug_info: facts.debug_info,
        entry_point: facts.entry.map(Hex64),
        recommended_engine,
        recommended_reason,
        engines,
        supported,
        problem,
    })
}

/// Describes a file before a project is made from it.
pub struct BinaryProbe;

#[async_trait]
impl Command for BinaryProbe {
    type Args = BinaryProbeArgs;
    type Output = BinaryProbeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "binary_probe",
            "Describe a file and say which engine should open it, without making a project",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Reads a file's headers before `project_create`: format (ELF, PE, Mach-O, .NET, \
             COFF object, library archive or unknown), the kind in plain words (`Linux shared \
             library`, `Windows static library with 12 objects`), processor, 32 or 64 bit, \
             size, SHA-256, whether it is stripped or has debug info, the entry point, the \
             recommended engine with the reason, and which engines are installed. Needs no open \
             project. Agents may not probe files in hidden folders of the home directory.\n\
             Example: binary_probe {\"path\": \"/usr/bin/ls\"}",
        )
        .details(
            "`recommended_engine` is what `project_create` picks with `engine: auto`. \
             `supported` is false for files no engine opens; `problem` says why, or which \
             engine still has to be installed (`kraken setup`). For an archive, `members` lists \
             up to 200 member names and `member_count` has the total; a static library loads \
             all its members into one project, and an import library opens as its list of \
             imported symbols. Archives need the native engine.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: BinaryProbeArgs,
    ) -> Result<BinaryProbeOut, ProtoError> {
        let path = if ctx.needs_user_approval() {
            trust::check_agent_path("path", Path::new(&args.path))?
        } else {
            Path::new(&args.path).to_path_buf()
        };
        let factory = s.factory().clone();
        blocking(move || probe_binary(factory.as_ref(), &path)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(rel)
    }

    struct OneEngine;

    #[async_trait]
    impl EngineFactory for OneEngine {
        async fn create(&self, _dir: &Path) -> Result<kraken_engine::SharedEngine, ProtoError> {
            Err(ProtoError::new(
                ErrorCode::Unsupported,
                "no engine in tests",
            ))
        }
    }

    #[test]
    fn elf_files_are_described() {
        let out = probe_binary(&OneEngine, &corpus("bin/pie_list-O0")).unwrap();
        assert_eq!(out.format, BinaryFormat::Elf);
        assert_eq!(out.arch.as_deref(), Some("x86-64"));
        assert_eq!(out.bits, Some(64));
        assert_eq!(out.endian.as_deref(), Some("little"));
        assert_eq!(out.stripped, Some(false));
        assert_eq!(out.kind, "executable", "a PIE is a program, not a library");
        assert_eq!(out.debug_info, Some(true));
        assert!(out.entry_point.is_some());
        assert_eq!(out.sha256.len(), 64);
        assert!(out.supported && out.problem.is_none());
        assert_eq!(out.recommended_engine, Some(EngineKind::Ghidra));
        assert_eq!(out.engines.len(), 1);

        let stripped = probe_binary(&OneEngine, &corpus("bin/pie_list-O0-stripped")).unwrap();
        assert_eq!(stripped.stripped, Some(true));
        assert_eq!(stripped.debug_info, Some(false));
    }

    #[test]
    fn pe_and_dotnet_files_are_told_apart() {
        let exe = probe_binary(&OneEngine, &corpus("pe/bin/switch_vm-x86-O0.exe")).unwrap();
        assert_eq!(exe.format, BinaryFormat::Pe);
        assert_eq!(exe.arch.as_deref(), Some("x86"));
        assert_eq!(exe.bits, Some(32));
        let dll = probe_binary(&OneEngine, &corpus("pe/bin/win_dll-x64-O0.dll")).unwrap();
        assert_eq!(dll.format, BinaryFormat::Pe);
        assert_eq!(dll.kind, "shared_library");
        let net = probe_binary(&OneEngine, &corpus("dotnet/bin/kraken-corpus.dll")).unwrap();
        assert_eq!(net.format, BinaryFormat::Dotnet);
        assert_eq!(net.recommended_engine, Some(EngineKind::Dotnet));
        assert!(net.supported);
    }

    #[test]
    fn libraries_and_objects_are_described_in_plain_words() {
        let cases = [
            (
                "libkr.so",
                BinaryFormat::Elf,
                "shared_library",
                "Linux shared library",
                Some(64),
            ),
            (
                "kr.o",
                BinaryFormat::Elf,
                "object",
                "Linux object file",
                Some(64),
            ),
            (
                "kr-i386.o",
                BinaryFormat::Elf,
                "object",
                "Linux object file",
                Some(32),
            ),
            (
                "libkr.a",
                BinaryFormat::Archive,
                "static_library",
                "Linux static library with 2 objects",
                Some(64),
            ),
            (
                "kr-x64.dll",
                BinaryFormat::Pe,
                "shared_library",
                "Windows DLL",
                Some(64),
            ),
            (
                "kr-x86.obj",
                BinaryFormat::Coff,
                "object",
                "COFF object (a Windows object file)",
                Some(32),
            ),
            (
                "kr-x64.lib",
                BinaryFormat::Archive,
                "static_library",
                "Windows static library with 2 objects",
                Some(64),
            ),
            (
                "libkr-x86.dll.a",
                BinaryFormat::Archive,
                "import_library",
                "import library for kr.dll",
                Some(32),
            ),
        ];
        for (file, format, kind, description, bits) in cases {
            let out = probe_binary(&OneEngine, &corpus(&format!("lib/bin/{file}"))).unwrap();
            assert_eq!(out.format, format, "{file}");
            assert_eq!(out.kind, kind, "{file}");
            assert_eq!(out.description, description, "{file}");
            assert_eq!(out.bits, bits, "{file}");
            assert!(out.supported, "{file}: {:?}", out.problem);
            if format == BinaryFormat::Archive {
                assert_eq!(out.recommended_engine, Some(EngineKind::Native), "{file}");
                assert!(
                    out.recommended_reason.contains("native engine only"),
                    "{file}"
                );
                assert_eq!(out.member_count, Some(out.members.len() as u64));
            } else {
                assert!(out.members.is_empty() && out.member_count.is_none());
            }
        }
        let lib = probe_binary(&OneEngine, &corpus("lib/bin/libkr.a")).unwrap();
        let names: Vec<&str> = lib.members.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(names, ["kr_core.o", "kr_text.o"]);
        let implib = probe_binary(&OneEngine, &corpus("lib/bin/libkr-x64.dll.a")).unwrap();
        assert_eq!(implib.member_count, Some(8));
        let exe = probe_binary(&OneEngine, &corpus("pe/bin/switch_vm-x64-O0.exe")).unwrap();
        assert_eq!(exe.description, "Windows program");
        let elf = probe_binary(&OneEngine, &corpus("bin/pie_list-O0")).unwrap();
        assert_eq!(elf.description, "Linux program");
    }

    #[test]
    fn archives_no_engine_reads_say_why() {
        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("libnotes.a");
        // an archive member that is not an object file
        let mut data = b"!<arch>\n".to_vec();
        data.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "notes.txt/", 0, 0, 0, 644, 4
            )
            .as_bytes(),
        );
        data.extend_from_slice(b"text");
        std::fs::write(&txt, &data).unwrap();
        let out = probe_binary(&OneEngine, &txt).unwrap();
        assert_eq!(out.format, BinaryFormat::Archive);
        assert!(!out.supported);
        assert!(out.problem.unwrap().contains("no object files"));
        // a GNU linker script named like a library is not an archive
        let script = dir.path().join("libm.a");
        std::fs::write(&script, b"/* GNU ld script */\nGROUP ( libm.so.6 )\n").unwrap();
        assert_eq!(
            probe_binary(&OneEngine, &script).unwrap().format,
            BinaryFormat::Unknown
        );
    }

    #[test]
    fn other_files_are_unknown_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("notes.txt");
        std::fs::write(&txt, b"just some text\n").unwrap();
        let out = probe_binary(&OneEngine, &txt).unwrap();
        assert_eq!(out.format, BinaryFormat::Unknown);
        assert!(!out.supported);
        assert!(out.recommended_engine.is_none());
        assert!(out.problem.unwrap().contains("does not recognise"));
        assert_eq!(out.size, 15);

        let missing = probe_binary(&OneEngine, &dir.path().join("nope")).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
        let folder = probe_binary(&OneEngine, dir.path()).unwrap_err();
        assert_eq!(folder.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_missing_engine_is_named_as_the_problem() {
        struct NoGhidra;
        #[async_trait]
        impl EngineFactory for NoGhidra {
            async fn create(&self, _dir: &Path) -> Result<kraken_engine::SharedEngine, ProtoError> {
                Err(ProtoError::new(ErrorCode::Unsupported, "none"))
            }
            fn engine_status(&self) -> Vec<EngineStatus> {
                vec![EngineStatus {
                    kind: EngineKind::Ghidra,
                    usable: false,
                    problem: Some("run `kraken setup`".into()),
                }]
            }
        }
        let out = probe_binary(&NoGhidra, &corpus("bin/pie_list-O0")).unwrap();
        assert!(out.supported);
        assert!(out.problem.unwrap().contains("kraken setup"));
    }
}
