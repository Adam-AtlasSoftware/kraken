use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <command>

Commands:
  ghidra-ext   Build the Ghidra extension in java/kraken-ghidra with Gradle.
               Honours GHIDRA_INSTALL_DIR, JAVA_HOME and GRADLE (default: `gradle`);
               falls back to the pinned copies in ~/.cache/kraken-dev.
  schema       Write schema/kraken-proto.schema.json from the kraken-proto types.";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("help") | Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("ghidra-ext") => ghidra_ext(),
        Some("schema") => schema(),
        Some(other) => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("xtask: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kraken-dev"))
}

/// First directory entry of `parent` (the pinned archives each extract to one top-level directory).
fn sole_child(parent: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

fn env_or_cache(var: &str, sub: &str) -> Result<PathBuf> {
    if let Some(v) = std::env::var_os(var) {
        return Ok(PathBuf::from(v));
    }
    cache_dir()
        .and_then(|c| sole_child(&c.join(sub)))
        .ok_or_else(|| format!("{var} is not set and no copy found in ~/.cache/kraken-dev/{sub}"))
}

fn schema() -> Result<()> {
    let path = workspace_root().join("schema/kraken-proto.schema.json");
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    fs::write(&path, kraken_proto::schema_json())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("schema: {}", path.display());
    Ok(())
}

fn ghidra_ext() -> Result<()> {
    let ghidra = env_or_cache("GHIDRA_INSTALL_DIR", "ghidra")?;
    let java_home = env_or_cache("JAVA_HOME", "jdk")?;
    let gradle = std::env::var("GRADLE").unwrap_or_else(|_| "gradle".to_string());
    let dir = workspace_root().join("java/kraken-ghidra");

    // Nothing is resolved from the network: the extension only depends on Ghidra's own jars.
    let status = Command::new(&gradle)
        .args(["--offline", "--no-daemon", "buildExtension"])
        .current_dir(&dir)
        .env("GHIDRA_INSTALL_DIR", &ghidra)
        .env("JAVA_HOME", &java_home)
        .status()
        .map_err(|e| format!("cannot run `{gradle}`: {e}"))?;
    if !status.success() {
        return Err(format!("gradle failed: {status}"));
    }

    let dist = dir.join("dist");
    let mut zips: Vec<PathBuf> = fs::read_dir(&dist)
        .map_err(|e| format!("cannot read {}: {e}", dist.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "zip"))
        .collect();
    zips.sort();
    match zips.last() {
        Some(z) => {
            println!("extension: {}", z.display());
            Ok(())
        }
        None => Err("gradle succeeded but dist/ has no zip".to_string()),
    }
}
