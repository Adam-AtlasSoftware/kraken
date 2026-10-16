mod docs;
mod samples;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <command>

Commands:
  ghidra-ext   Build the Ghidra extension in java/kraken-ghidra with Gradle.
               Honours GHIDRA_INSTALL_DIR, JAVA_HOME and GRADLE (default: `gradle`);
               falls back to the pinned copies in ~/.cache/kraken-dev.
  ghidra-ext-test [binary]
               Build the extension, then run its in-process self-test against `binary`
               (default: a copy of /bin/ls in a temp dir). Prints PASS/FAIL lines.
  schema       Write schema/kraken-proto.schema.json from the kraken-proto types.
  samples      Write one JSON sample per kraken-proto type/variant to schema/samples/.
  docs         Write docs/reference/commands.md from the command registry.";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("help") | Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("ghidra-ext") => ghidra_ext(),
        Some("ghidra-ext-test") => ghidra_ext_test(args.get(1).map(PathBuf::from)),
        Some("schema") => schema(),
        Some("samples") => write_samples(),
        Some("docs") => docs::write_docs(),
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

fn write_samples() -> Result<()> {
    let dir = workspace_root().join("schema/samples");
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let samples = samples::samples()?;
    let wanted: Vec<&str> = samples.iter().map(|(n, _)| n.as_str()).collect();
    for entry in fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !wanted.contains(&name.as_str()) {
            fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
        }
    }
    for (name, value) in &samples {
        let mut text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
        text.push('\n');
        fs::write(dir.join(name), text).map_err(|e| format!("cannot write {name}: {e}"))?;
    }
    println!("samples: {} files in {}", samples.len(), dir.display());
    Ok(())
}

fn jars_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            jars_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "jar") {
            out.push(path);
        }
    }
}

/// Same jar set as Ghidra's buildExtension.gradle puts on the compile classpath, plus the extension.
fn classpath(ghidra: &Path, ext_jar_dir: &Path) -> String {
    let mut jars = Vec::new();
    for sub in ["Framework", "Features", "Debug", "Processors"] {
        jars_under(&ghidra.join("Ghidra").join(sub), &mut jars);
    }
    jars_under(ext_jar_dir, &mut jars);
    jars.sort();
    jars.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
}

fn ghidra_ext_test(binary: Option<PathBuf>) -> Result<()> {
    ghidra_ext()?;
    let ghidra = env_or_cache("GHIDRA_INSTALL_DIR", "ghidra")?;
    let java_home = env_or_cache("JAVA_HOME", "jdk")?;
    let root = workspace_root();
    let ext_jar_dir = root.join("java/kraken-ghidra/build/libs");
    let samples_dir = root.join("schema/samples");

    let tmp = std::env::temp_dir().join(format!("kraken-ghidra-test-{}", std::process::id()));
    let home = tmp.join("home");
    let work = tmp.join("work");
    for d in [&home.join("tmp"), &work] {
        fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }
    let binary = match binary {
        Some(b) => b,
        None => {
            let copy = work.join("ls");
            fs::copy("/bin/ls", &copy).map_err(|e| format!("cannot copy /bin/ls: {e}"))?;
            copy
        }
    };

    let status = Command::new(java_home.join("bin/java"))
        .args(["-Xmx3g", "-XX:+UseSerialGC", "-Djava.awt.headless=true"])
        .arg(format!("-Duser.home={}", home.display()))
        .arg(format!("-Djava.io.tmpdir={}", home.join("tmp").display()))
        .arg(format!("-Dghidra.install.dir={}", ghidra.display()))
        .arg("-cp")
        .arg(classpath(&ghidra, &ext_jar_dir))
        .arg("kraken.ghidra.KrakenSidecar")
        .arg("--self-test")
        .arg(&binary)
        .arg(work.join("project"))
        .arg(&samples_dir)
        .status()
        .map_err(|e| format!("cannot run java: {e}"));
    let _ = fs::remove_dir_all(&tmp);
    let status = status?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("self-test failed: {status}"))
    }
}
