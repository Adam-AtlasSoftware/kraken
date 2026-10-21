//! The Strata engine: pinned manifest, what this computer is missing for it, and which of its
//! models to offer.
//!
//! Strata keeps a large mixture-of-experts model's expert weights in system RAM and streams
//! them to a small GPU, so video memory plus RAM together bound the model size, and RAM mostly
//! decides which model fits. Nothing here downloads or runs anything: `kraken-host` installs
//! from [`manifest`] and `kraken-infer`'s generic backend supervises the server.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::generic::Manifest;
use crate::hardware::{GpuVendor, HardwareInfo, Probe};

const GIB: u64 = 1 << 30;

/// One pinned source archive.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Source {
    pub commit: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub license: String,
}

/// Strata itself, with its stated minimums.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EngineSource {
    pub version: String,
    #[serde(flatten)]
    pub source: Source,
    /// SHA-256 of `requirements.txt` in the archive: the Python pins are checked before use.
    pub requirements_sha256: String,
    pub min_vram_gib: u64,
    pub min_ram_gib: u64,
    pub min_disk_gib: u64,
    /// Disk for the venv, llama.cpp sources and the build, on top of the model files.
    pub build_disk_gib: u64,
    pub python_min: String,
}

/// One model file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrataFile {
    pub name: String,
    pub url: String,
    pub size: u64,
    /// Hugging Face's published LFS oid (SHA-256).
    pub sha256: String,
}

/// One Strata-supported model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrataModel {
    pub id: String,
    pub name: String,
    /// Strata's `--family` value.
    pub family: String,
    /// Strata's `--model` value (the quantisation).
    pub quant: String,
    /// RAM Strata states for this model.
    pub min_ram_gib: u64,
    pub arena_gib: f64,
    pub license: String,
    #[serde(rename = "file")]
    pub files: Vec<StrataFile>,
}

impl StrataModel {
    pub fn download_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// A model the person already has on disk: every shard of a Strata-supported GGUF in one folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingModel {
    /// The folder with every shard (Strata's `--gguf-dir`).
    pub dir: PathBuf,
    /// Strata's `--family` value (`qwen`, `swift`, `coder`, `unsloth`).
    pub family: String,
    /// Strata's `--model` value (the quantisation).
    pub quant: String,
    pub shards: u32,
    /// Size of all shards together.
    pub bytes: u64,
}

impl ExistingModel {
    /// The id this model is registered under: `strata-existing-<family>-<quant>`.
    pub fn id(&self) -> String {
        format!(
            "strata-existing-{}-{}",
            self.family,
            self.quant.to_ascii_lowercase()
        )
    }

    /// A name for people.
    pub fn title(&self) -> String {
        let family = match self.family.as_str() {
            "swift" => "Swift 1.5",
            "coder" => "Qwen3.8 Flash Next Coder",
            "unsloth" => "Qwen3.8 Flash Next (Unsloth)",
            _ => "Qwen3.8 Flash Next",
        };
        format!("{family} {} (your file)", self.quant)
    }

    /// The model as the setup treats it: no files to download.
    pub fn as_model(&self) -> StrataModel {
        StrataModel {
            id: self.id(),
            name: self.title(),
            family: self.family.clone(),
            quant: self.quant.clone(),
            min_ram_gib: 0,
            arena_gib: 0.0,
            license: "your own file".into(),
            files: Vec::new(),
        }
    }
}

/// Recognises a Strata model from the name of one of its shards and checks that the folder has
/// all of them. Strata only runs GGUFs named the way its installer names them, so the name tells
/// the family and the quantisation.
pub fn existing_model(path: &Path) -> Result<ExistingModel, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("that is not a file")?;
    let stem = name
        .strip_suffix(".gguf")
        .ok_or("pick a .gguf file (any shard of the model)")?;
    let bad = || {
        format!(
            "`{name}` is not named like a Strata model, for example \
             `Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00001-of-00002.gguf`"
        )
    };
    let (head, of) = stem.rsplit_once("-of-").ok_or_else(bad)?;
    let (prefix, index) = head.rsplit_once('-').ok_or_else(bad)?;
    let digits = |t: &str| t.len() == 5 && t.bytes().all(|b| b.is_ascii_digit());
    if !digits(index) || !digits(of) {
        return Err(bad());
    }
    let shards: u32 = of.parse().map_err(|_| bad())?;
    let (family, quant) = if let Some(q) = prefix.strip_prefix("Swift-Qwen3.8-Flash-Next-GSQ-RCO-")
    {
        ("swift", q)
    } else if let Some(q) = prefix.strip_prefix("Qwen3.8-Flash-Next-GSQ-RCO-") {
        (if q == "IQ1_M" { "coder" } else { "qwen" }, q)
    } else if let Some(q) = prefix.strip_prefix("Qwen3.8-Flash-Next-") {
        ("unsloth", q)
    } else {
        return Err(bad());
    };
    if quant.is_empty()
        || !quant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(bad());
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let mut bytes = 0;
    for i in 1..=shards {
        let shard = dir.join(format!("{prefix}-{i:05}-of-{shards:05}.gguf"));
        let meta = std::fs::metadata(&shard).map_err(|_| {
            format!(
                "shard {i} of {shards} is missing: `{}` must sit next to the file you picked",
                shard.file_name().and_then(|n| n.to_str()).unwrap_or("")
            )
        })?;
        bytes += meta.len();
    }
    Ok(ExistingModel {
        dir,
        family: family.into(),
        quant: quant.into(),
        shards,
        bytes,
    })
}

/// The bundled, pinned manifest (`data/strata.toml`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StrataManifest {
    pub engine: EngineSource,
    pub llama_cpp: Source,
    #[serde(rename = "model")]
    pub models: Vec<StrataModel>,
}

/// Parses a manifest.
pub fn parse_manifest(text: &str) -> Result<StrataManifest, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

/// The bundled manifest (empty when the bundled file is broken, which a test rules out).
pub fn manifest() -> StrataManifest {
    parse_manifest(include_str!("../data/strata.toml")).unwrap_or_else(|_| StrataManifest {
        engine: EngineSource {
            version: String::new(),
            source: Source {
                commit: String::new(),
                url: String::new(),
                sha256: String::new(),
                size: 0,
                license: String::new(),
            },
            requirements_sha256: String::new(),
            min_vram_gib: 12,
            min_ram_gib: 32,
            min_disk_gib: 80,
            build_disk_gib: 8,
            python_min: "3.10".into(),
        },
        llama_cpp: Source {
            commit: String::new(),
            url: String::new(),
            sha256: String::new(),
            size: 0,
            license: String::new(),
        },
        models: Vec::new(),
    })
}

/// Something the computer lacks that KRAKEN will not install for you.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Missing {
    pub what: String,
    pub how_to_fix: String,
}

/// How Strata's engine gets onto the computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineMethod {
    /// Strata's ready-made engine for this computer, downloaded by Strata's own installer.
    #[default]
    Prebuilt,
    /// Compiled here from source (10 to 20 minutes; needs `nvcc` and a C++ compiler).
    Build,
}

/// Which Strata revision to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineVersion {
    /// The newest published release.
    #[default]
    LatestRelease,
    /// The revision pinned in the bundled manifest: its archives are checked against SHA-256
    /// hashes written down in advance.
    Pinned,
    /// The newest commit of the main branch (can be broken; source build only).
    LatestCommit,
}

/// What the person chose for the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SetupOptions {
    pub method: EngineMethod,
    pub version: EngineVersion,
}

impl SetupOptions {
    /// Why this combination cannot be installed, or `None`.
    pub fn problem(&self) -> Option<&'static str> {
        (self.method == EngineMethod::Prebuilt && self.version == EngineVersion::LatestCommit)
            .then_some(
                "The newest commit has no ready-made engine; build it from source or pick the \
                 latest release.",
            )
    }
}

/// Looks for the system pieces the engine's setup needs: an NVIDIA driver, Python with `venv`,
/// and for a source build also `nvcc` and a C++ compiler. KRAKEN never installs these (no
/// sudo, no system packages).
pub fn missing_prerequisites(
    probe: &dyn Probe,
    hw: &HardwareInfo,
    python_min: &str,
    method: EngineMethod,
) -> Vec<Missing> {
    let mut out = Vec::new();
    if !hw.gpus.iter().any(|g| g.vendor == GpuVendor::Nvidia) {
        out.push(Missing {
            what: "NVIDIA GPU with a working driver (CUDA)".into(),
            how_to_fix: "`nvidia-smi` found no card. Install the vendor's NVIDIA driver (525 or \
                         newer; 580 for CUDA 13). KRAKEN's Strata setup supports NVIDIA only."
                .into(),
        });
    }
    if method == EngineMethod::Build && probe.run("nvcc", &["--version"]).is_none() {
        out.push(Missing {
            what: "CUDA toolkit (`nvcc` not on PATH)".into(),
            how_to_fix: "Install the CUDA toolkit from your distribution or NVIDIA (for example \
                         `sudo apt install nvidia-cuda-toolkit` or `sudo pacman -S cuda`) and \
                         make sure `nvcc --version` works."
                .into(),
        });
    }
    if method == EngineMethod::Build
        && probe
            .run("c++", &["--version"])
            .or_else(|| probe.run("g++", &["--version"]))
            .is_none()
    {
        out.push(Missing {
            what: "C++ compiler (`c++`/`g++`)".into(),
            how_to_fix: "Install it, for example `sudo apt install build-essential`, \
                         `sudo dnf install gcc-c++` or `sudo pacman -S base-devel`."
                .into(),
        });
    }
    let py = probe.run("python3", &["--version"]);
    let ok = py
        .as_deref()
        .and_then(|v| v.split_whitespace().nth(1))
        .is_some_and(|v| version_at_least(v, python_min));
    if !ok {
        out.push(Missing {
            what: format!("Python {python_min} or newer (`python3`)"),
            how_to_fix: "Install python3 with the venv module, for example \
                         `sudo apt install python3 python3-venv`."
                .into(),
        });
    } else if probe
        .run("python3", &["-c", "import venv, ensurepip"])
        .is_none()
    {
        out.push(Missing {
            what: "Python `venv` and `ensurepip` modules".into(),
            how_to_fix: "Install them, for example `sudo apt install python3-venv`.".into(),
        });
    }
    out
}

fn version_at_least(have: &str, want: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parse(have) >= parse(want)
}

/// How a model relates to this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fit {
    /// Strata's stated minimums are met for this model.
    Fits,
    /// A stated minimum is not met: expect slow or failing runs.
    BelowMinimum,
    /// Not enough free disk for the files.
    NoDisk,
}

/// One model with its verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub model: StrataModel,
    pub fit: Fit,
    pub warnings: Vec<String>,
    /// Rough, unmeasured expectation.
    pub speed: String,
    pub download_bytes: u64,
    /// Model files plus the venv, sources and build.
    pub disk_bytes: u64,
}

/// The answer for "evaluate this system" with Strata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    /// Best first: models the memory holds, then those below the minimum.
    pub candidates: Vec<Candidate>,
    /// Index into `candidates`; `None` when no model fits the disk.
    pub recommended: Option<usize>,
    pub missing: Vec<Missing>,
    pub notes: Vec<String>,
}

fn speed_text(vram: u64, has_gpu: bool) -> String {
    if !has_gpu {
        return "Needs an NVIDIA GPU: not usable without one.".into();
    }
    let v = vram / GIB;
    let band = if v >= 24 {
        "roughly 15-30 tokens/s"
    } else if v >= 12 {
        "roughly 8-20 tokens/s"
    } else {
        "roughly 3-10 tokens/s, if it runs at all"
    };
    format!(
        "{band} (a rule of thumb, not measured here; the experts stream from RAM, so RAM and \
         disk speed matter)"
    )
}

fn gib(b: u64) -> f64 {
    b as f64 / GIB as f64
}

/// Which Strata models to offer on `hw`. Video memory and RAM together bound the size: a model
/// needs the RAM Strata states for it, and video memory mostly sets the speed. A model under
/// Strata's stated minimums is offered with a warning, not hidden.
pub fn assess(hw: &HardwareInfo, m: &StrataManifest, missing: Vec<Missing>) -> Assessment {
    let vram = hw.vram_bytes();
    let has_gpu = hw.gpus.iter().any(|g| g.vendor == GpuVendor::Nvidia);
    let e = &m.engine;
    let mut notes = vec![format!(
        "Strata {} keeps expert weights in RAM and the hot path on the GPU, so video memory \
         ({:.1} GiB) and RAM ({:.1} GiB) together bound the model.",
        e.version,
        gib(vram),
        gib(hw.ram_bytes)
    )];
    let mut machine = Vec::new();
    if vram < e.min_vram_gib * GIB {
        machine.push(format!(
            "Video memory {:.1} GiB is below Strata's stated minimum of {} GiB: expect slow or \
             failing runs.",
            gib(vram),
            e.min_vram_gib
        ));
    }
    if hw.ram_bytes < e.min_ram_gib * GIB {
        machine.push(format!(
            "RAM {:.1} GiB is below Strata's stated minimum of {} GiB: expect slow or failing \
             runs.",
            gib(hw.ram_bytes),
            e.min_ram_gib
        ));
    }
    let mut cands: Vec<Candidate> = m
        .models
        .iter()
        .map(|model| {
            let download = model.download_bytes();
            let disk = download + e.build_disk_gib * GIB;
            let mut warnings = machine.clone();
            if hw.ram_bytes < model.min_ram_gib * GIB {
                warnings.push(format!(
                    "{} needs {} GiB of RAM and this computer has {:.1} GiB: below Strata's \
                     stated minimum for this model, expect slow or failing runs.",
                    model.quant,
                    model.min_ram_gib,
                    gib(hw.ram_bytes)
                ));
            }
            let fit = if hw.free_disk_bytes < disk {
                warnings.push(format!(
                    "Needs {:.1} GiB of free disk and {:.1} GiB are free.",
                    gib(disk),
                    gib(hw.free_disk_bytes)
                ));
                Fit::NoDisk
            } else if warnings.is_empty() {
                Fit::Fits
            } else {
                Fit::BelowMinimum
            };
            Candidate {
                model: model.clone(),
                fit,
                warnings,
                speed: speed_text(vram, has_gpu),
                download_bytes: download,
                disk_bytes: disk,
            }
        })
        .collect();
    // The biggest quantisation the RAM holds is the best model; a model that does not fit the
    // disk or its RAM need sorts after those that do.
    let ram_ok = |c: &Candidate| hw.ram_bytes >= c.model.min_ram_gib * GIB;
    cands.sort_by(|a, b| {
        let key = |c: &Candidate| (c.fit != Fit::NoDisk, ram_ok(c));
        key(b).cmp(&key(a)).then(
            b.model
                .arena_gib
                .partial_cmp(&a.model.arena_gib)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    let recommended = cands
        .iter()
        .position(|c| c.fit != Fit::NoDisk && ram_ok(c))
        .or_else(|| {
            cands
                .iter()
                .enumerate()
                .filter(|(_, c)| c.fit != Fit::NoDisk)
                .min_by_key(|(_, c)| c.model.min_ram_gib)
                .map(|(i, _)| i)
        });
    match recommended {
        None => notes.push("No Strata model fits the free disk.".into()),
        Some(i) if cands[i].fit == Fit::BelowMinimum => notes.push(
            "The recommended model is below Strata's stated minimum for this computer; it is \
             offered anyway."
                .into(),
        ),
        _ => {}
    }
    Assessment {
        candidates: cands,
        recommended,
        missing,
        notes,
    }
}

/// The supervised-server manifest for an installed Strata: the private venv's Python runs
/// `serve/server.py` from the install directory on the port KRAKEN picks (the manifest has no port
/// setting, so a configured one cannot override it), bound to loopback by the run config written
/// at setup. Card choices are appended as argv overrides by [`crate::launch::launch_spec`].
pub fn backend_manifest_text(python: &str, install_dir: &str, config: &str) -> String {
    let esc = |s: &str| toml_str(&s.replace('{', "{{").replace('}', "}}"));
    format!(
        r#"id = "strata"
name = "Strata"
license = "MIT"
command = [{}, {}, "--engine", "strata", "--config", {}, "--port", "{{port}}"]
managed_port = true
cwd = {}
health_path = "/v1/models"
ready_timeout_secs = 1800
grace_secs = 15

[capabilities]
gpu_apis = ["cuda"]
min_ram_mb = 32768
supports_moe_offload = true
supports_tool_calls = true

[settings_schema]
type = "object"
"#,
        esc(python),
        esc(&format!("{install_dir}/serve/server.py")),
        esc(config),
        toml_str(install_dir),
    )
}

/// [`backend_manifest_text`], parsed and validated.
pub fn backend_manifest(python: &str, install_dir: &str, config: &str) -> Result<Manifest, String> {
    Manifest::parse(&backend_manifest_text(python, install_dir, config)).map_err(|e| e.to_string())
}

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::GpuInfo;
    use crate::recommend::{catalog, recommend};

    struct Tools(&'static [&'static str]);
    impl Probe for Tools {
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            self.0.contains(&program).then(|| {
                if program == "python3" && args.contains(&"--version") {
                    "Python 3.12.3\n".into()
                } else {
                    "ok\n".into()
                }
            })
        }
        fn read(&self, _: &str) -> Option<String> {
            None
        }
        fn list(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn cpu_cores(&self) -> u32 {
            8
        }
    }

    fn hw(vram: u64, ram: u64, disk: u64) -> HardwareInfo {
        HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: GpuVendor::Nvidia,
                name: "RTX".into(),
                vram_bytes: Some(vram * GIB),
            }],
            ram_bytes: ram * GIB,
            free_disk_bytes: disk * GIB,
            cpu_cores: 8,
        }
    }

    #[test]
    fn the_bundled_manifest_is_pinned() {
        let m = parse_manifest(include_str!("../data/strata.toml")).expect("parses");
        assert_eq!(m.engine.source.commit.len(), 40);
        assert_eq!(m.engine.source.sha256.len(), 64);
        assert_eq!(m.llama_cpp.sha256.len(), 64);
        assert!(m.models.len() >= 5);
        for model in &m.models {
            assert_eq!(model.files.len(), 2, "{}", model.id);
            for f in &model.files {
                assert_eq!(f.sha256.len(), 64);
                assert!(f.url.starts_with("https://huggingface.co/") && f.size > 0);
                assert!(f.url.contains("/resolve/") && !f.url.contains("/main/"));
            }
        }
    }

    #[test]
    fn eight_gib_vram_and_64_gib_ram_gets_a_bigger_model_than_llama_server() {
        let h = hw(8, 64, 500);
        let a = assess(&h, &manifest(), vec![]);
        let c = &a.candidates[a.recommended.expect("a pick")];
        assert_eq!(c.model.quant, "IQ3_S");
        assert_eq!(c.fit, Fit::BelowMinimum);
        assert!(c.warnings.iter().any(|w| w.contains("stated minimum")));
        let llama = recommend(&h, &catalog()).model.expect("llama pick");
        assert!(c.model.download_bytes() > llama.size * 5);
    }

    #[test]
    fn enough_everything_fits_without_warnings() {
        let a = assess(&hw(24, 96, 500), &manifest(), vec![]);
        let c = &a.candidates[a.recommended.expect("a pick")];
        assert_eq!(c.fit, Fit::Fits);
        assert!(c.warnings.is_empty());
    }

    #[test]
    fn below_the_ram_minimum_is_offered_with_a_warning() {
        let a = assess(&hw(16, 24, 500), &manifest(), vec![]);
        assert_eq!(a.candidates.len(), manifest().models.len());
        let c = &a.candidates[a.recommended.expect("a pick")];
        assert_eq!(c.model.quant, "IQ1_M");
        assert_eq!(c.fit, Fit::BelowMinimum);
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("expect slow or failing"))
        );
    }

    #[test]
    fn a_small_disk_rules_models_out() {
        let a = assess(&hw(24, 64, 65), &manifest(), vec![]);
        let pick = a.recommended.map(|i| a.candidates[i].model.quant.clone());
        assert_eq!(pick.as_deref(), Some("IQ1_M"));
        assert!(
            a.candidates
                .iter()
                .any(|c| c.fit == Fit::NoDisk && c.model.quant == "IQ3_S")
        );
    }

    #[test]
    fn missing_cuda_and_compiler_are_named() {
        let none = HardwareInfo {
            gpus: vec![],
            ram_bytes: 64 * GIB,
            free_disk_bytes: 500 * GIB,
            cpu_cores: 8,
        };
        let m = missing_prerequisites(&Tools(&["python3"]), &none, "3.10", EngineMethod::Build);
        let all: String = m
            .iter()
            .map(|x| x.what.clone())
            .collect::<Vec<_>>()
            .join("|");
        assert!(all.contains("NVIDIA GPU"), "{all}");
        assert!(all.contains("nvcc"), "{all}");
        assert!(all.contains("C++ compiler"), "{all}");
        assert!(!all.contains("Python"), "{all}");
        let ok = missing_prerequisites(
            &Tools(&["python3", "nvcc", "c++"]),
            &hw(12, 32, 80),
            "3.10",
            EngineMethod::Build,
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn the_server_manifest_is_valid_and_has_a_cwd() {
        let m = backend_manifest("/d/venv/bin/python", "/d/src", "/d/cfg.json").expect("manifest");
        assert_eq!(m.cwd.as_deref(), Some("/d/src"));
        assert!(m.command.iter().any(|a| a == "{port}"));
        assert!(m.managed_port);
    }

    #[test]
    fn a_prebuilt_engine_needs_no_compiler() {
        let none = hw(12, 32, 80);
        let tools = Tools(&["python3"]);
        let m = missing_prerequisites(&tools, &none, "3.10", EngineMethod::Prebuilt);
        assert!(
            m.iter()
                .all(|x| !x.what.contains("nvcc") && !x.what.contains("C++"))
        );
        let m = missing_prerequisites(&tools, &none, "3.10", EngineMethod::Build);
        assert!(m.iter().any(|x| x.what.contains("nvcc")));
        assert!(m.iter().any(|x| x.what.contains("C++")));
    }

    #[test]
    fn the_newest_commit_has_no_prebuilt_engine() {
        let mut o = SetupOptions::default();
        assert_eq!(o.method, EngineMethod::Prebuilt);
        assert_eq!(o.version, EngineVersion::LatestRelease);
        assert!(o.problem().is_none());
        o.version = EngineVersion::LatestCommit;
        assert!(o.problem().is_some());
        o.method = EngineMethod::Build;
        assert!(o.problem().is_none());
    }

    fn shards(dir: &Path, prefix: &str, n: u32) -> PathBuf {
        for i in 1..=n {
            std::fs::write(
                dir.join(format!("{prefix}-{i:05}-of-{n:05}.gguf")),
                vec![0u8; 10],
            )
            .expect("shard");
        }
        dir.join(format!("{prefix}-00001-of-{n:05}.gguf"))
    }

    #[test]
    fn an_existing_model_is_recognised_by_its_shard_names() {
        let d = tempfile::tempdir().expect("dir");
        let swift = shards(d.path(), "Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS", 2);
        let m = existing_model(&swift).expect("swift");
        assert_eq!(
            (m.family.as_str(), m.quant.as_str(), m.shards),
            ("swift", "IQ2_XS", 2)
        );
        assert_eq!((m.bytes, m.dir.as_path()), (20, d.path()));
        assert_eq!(m.id(), "strata-existing-swift-iq2_xs");
        assert!(m.as_model().files.is_empty());
        let second = d
            .path()
            .join("Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00002-of-00002.gguf");
        assert_eq!(existing_model(&second).expect("any shard"), m);

        let q = shards(d.path(), "Qwen3.8-Flash-Next-GSQ-RCO-IQ3_S", 2);
        assert_eq!(existing_model(&q).expect("qwen").family, "qwen");
        let c = shards(d.path(), "Qwen3.8-Flash-Next-GSQ-RCO-IQ1_M", 2);
        assert_eq!(existing_model(&c).expect("coder").family, "coder");
        let u = shards(d.path(), "Qwen3.8-Flash-Next-UD-IQ4_XS", 3);
        let u = existing_model(&u).expect("unsloth");
        assert_eq!(
            (u.family.as_str(), u.quant.as_str(), u.shards),
            ("unsloth", "UD-IQ4_XS", 3)
        );
    }

    #[test]
    fn an_existing_model_must_be_whole_and_named_for_strata() {
        let d = tempfile::tempdir().expect("dir");
        let first = shards(d.path(), "Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS", 2);
        std::fs::remove_file(
            d.path()
                .join("Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00002-of-00002.gguf"),
        )
        .expect("rm");
        let e = existing_model(&first).expect_err("incomplete");
        assert!(e.contains("shard 2 of 2"), "{e}");
        for name in [
            "llama-7b.gguf",
            "model.bin",
            "Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-1-of-2.gguf",
        ] {
            let p = d.path().join(name);
            std::fs::write(&p, b"x").expect("file");
            assert!(existing_model(&p).is_err(), "{name}");
        }
    }
}
