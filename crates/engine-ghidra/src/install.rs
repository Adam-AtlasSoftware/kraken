//! Locating a Ghidra installation, a JDK and the KRAKEN extension jar.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GhidraError;

/// Ghidra versions the sidecar has been tested against (decision 42).
pub const TESTED_GHIDRA_VERSIONS: &[&str] = &["12.1.4"];

/// Environment variable naming the Ghidra install directory.
pub const ENV_GHIDRA_HOME: &str = "KRAKEN_GHIDRA_HOME";
/// Environment variable naming the JDK (falls back to `JAVA_HOME`).
pub const ENV_JAVA_HOME: &str = "KRAKEN_JAVA_HOME";
/// Environment variable naming the extension jar.
pub const ENV_EXT_JAR: &str = "KRAKEN_GHIDRA_EXT_JAR";

/// The JDK launcher's file name.
#[cfg(windows)]
const JAVA_BINARY: &str = "java.exe";
/// The JDK launcher's file name.
#[cfg(not(windows))]
const JAVA_BINARY: &str = "java";

/// Separator between `-cp` entries.
#[cfg(windows)]
const CLASSPATH_SEPARATOR: &str = ";";
/// Separator between `-cp` entries.
#[cfg(not(windows))]
const CLASSPATH_SEPARATOR: &str = ":";

/// Explicit locations; unset fields are looked up in the environment.
#[derive(Debug, Clone, Default)]
pub struct InstallConfig {
    /// Ghidra install directory (the one containing `Ghidra/` and `support/`).
    pub ghidra_home: Option<PathBuf>,
    /// JDK home (containing `bin/java`).
    pub java_home: Option<PathBuf>,
    /// `kraken-ghidra.jar`.
    pub ext_jar: Option<PathBuf>,
}

/// A validated Ghidra + JDK + extension combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraInstall {
    /// Canonical Ghidra install directory.
    pub ghidra_home: PathBuf,
    /// Canonical JDK home.
    pub java_home: PathBuf,
    /// Canonical extension jar.
    pub ext_jar: PathBuf,
    /// Version read from `Ghidra/application.properties`.
    pub ghidra_version: String,
}

/// Where `cargo xtask ghidra-ext` leaves the jar (`java/kraken-ghidra/build/libs/`), relative to
/// this source tree. Only meaningful in a development checkout.
pub fn xtask_ext_jar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../java/kraken-ghidra/build/libs/kraken-ghidra.jar")
}

/// Extracts `application.version` from the text of Ghidra's `application.properties`.
pub fn parse_application_version(props: &str) -> Option<String> {
    props.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "application.version").then(|| v.trim().to_string())
    })
}

impl GhidraInstall {
    /// Resolves the install from `cfg`, then the process environment.
    pub fn discover(cfg: &InstallConfig) -> Result<Self, GhidraError> {
        Self::discover_with(cfg, &|k| std::env::var_os(k))
    }

    /// Resolves the install from the environment only.
    pub fn from_env() -> Result<Self, GhidraError> {
        Self::discover(&InstallConfig::default())
    }

    /// [`discover`](Self::discover) with an injectable environment.
    pub fn discover_with(
        cfg: &InstallConfig,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Self, GhidraError> {
        let pick = |explicit: &Option<PathBuf>, vars: &[&str]| -> Option<PathBuf> {
            explicit.clone().or_else(|| {
                vars.iter()
                    .find_map(|v| env(v).filter(|s| !s.is_empty()))
                    .map(PathBuf::from)
            })
        };
        let ghidra = pick(&cfg.ghidra_home, &[ENV_GHIDRA_HOME]).ok_or_else(|| {
            GhidraError::Install(format!(
                "no Ghidra install configured (set {ENV_GHIDRA_HOME} or InstallConfig::ghidra_home)"
            ))
        })?;
        let java = pick(&cfg.java_home, &[ENV_JAVA_HOME, "JAVA_HOME"]).ok_or_else(|| {
            GhidraError::Install(format!(
                "no JDK configured (set {ENV_JAVA_HOME} or JAVA_HOME, or InstallConfig::java_home)"
            ))
        })?;
        let ext = match pick(&cfg.ext_jar, &[ENV_EXT_JAR]) {
            Some(p) => p,
            None => {
                let p = xtask_ext_jar_path();
                if !p.is_file() {
                    return Err(GhidraError::Install(format!(
                        "no extension jar: set {ENV_EXT_JAR} or run `cargo xtask ghidra-ext` (looked for {})",
                        p.display()
                    )));
                }
                p
            }
        };
        Self::validate(&ghidra, &java, &ext)
    }

    fn validate(ghidra: &Path, java: &Path, ext: &Path) -> Result<Self, GhidraError> {
        let canon = |p: &Path, what: &str| {
            fs::canonicalize(p)
                .map(|c| simplify_verbatim(&c))
                .map_err(|e| GhidraError::Install(format!("{what} {}: {e}", p.display())))
        };
        let ghidra_home = canon(ghidra, "Ghidra home")?;
        let java_home = canon(java, "JDK home")?;
        let ext_jar = canon(ext, "extension jar")?;

        let props_path = ghidra_home.join("Ghidra/application.properties");
        let props = fs::read_to_string(&props_path).map_err(|e| {
            GhidraError::Install(format!(
                "{} is not a Ghidra install (cannot read {}: {e})",
                ghidra_home.display(),
                props_path.display()
            ))
        })?;
        let ghidra_version = parse_application_version(&props).ok_or_else(|| {
            GhidraError::Install(format!(
                "no application.version in {}",
                props_path.display()
            ))
        })?;
        if !TESTED_GHIDRA_VERSIONS.contains(&ghidra_version.as_str()) {
            return Err(GhidraError::Install(format!(
                "Ghidra {ghidra_version} at {} is not a tested version (tested: {})",
                ghidra_home.display(),
                TESTED_GHIDRA_VERSIONS.join(", ")
            )));
        }
        let java_bin = java_home.join("bin").join(JAVA_BINARY);
        if !java_bin.is_file() {
            return Err(GhidraError::Install(format!(
                "{} does not exist (JDK home {})",
                java_bin.display(),
                java_home.display()
            )));
        }
        if !ext_jar.is_file() {
            return Err(GhidraError::Install(format!(
                "extension jar {} is not a file",
                ext_jar.display()
            )));
        }
        Ok(GhidraInstall {
            ghidra_home,
            java_home,
            ext_jar,
            ghidra_version,
        })
    }

    /// Path of the `java` launcher.
    pub fn java(&self) -> PathBuf {
        self.java_home.join("bin").join(JAVA_BINARY)
    }

    /// The `-cp` value: every Ghidra jar (the set Ghidra's `buildExtension.gradle` compiles
    /// against) followed by the extension jar.
    pub fn classpath(&self) -> Result<String, GhidraError> {
        let mut jars = Vec::new();
        for sub in ["Framework", "Features", "Debug", "Processors"] {
            let dir = self.ghidra_home.join("Ghidra").join(sub);
            if dir.is_dir() {
                jars_under(&dir, &mut jars)?;
            }
        }
        if jars.is_empty() {
            return Err(GhidraError::Install(format!(
                "no Ghidra jars under {}",
                self.ghidra_home.display()
            )));
        }
        jars.sort();
        jars.push(self.ext_jar.clone());
        Ok(jars
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(CLASSPATH_SEPARATOR))
    }
}

/// Turns a Windows verbatim path (`\\?\C:\dir`, what `canonicalize` returns there) back into the
/// plain `C:\dir` form, which the JVM and Ghidra's launch scripts handle; UNC verbatim paths and
/// every non-Windows path are returned unchanged.
pub(crate) fn simplify_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.len() > 2 && rest.as_bytes()[1] == b':' => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

fn jars_under(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), GhidraError> {
    let ctx = || format!("reading {}", dir.display());
    for entry in fs::read_dir(dir).map_err(|e| GhidraError::io(ctx(), e))? {
        let path = entry.map_err(|e| GhidraError::io(ctx(), e))?.path();
        if path.is_dir() {
            jars_under(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "jar") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_install(root: &Path, version: &str) -> (PathBuf, PathBuf, PathBuf) {
        let ghidra = root.join("ghidra");
        fs::create_dir_all(ghidra.join("Ghidra/Framework/Utility/lib")).unwrap();
        fs::write(ghidra.join("Ghidra/Framework/Utility/lib/u.jar"), b"").unwrap();
        fs::write(
            ghidra.join("Ghidra/application.properties"),
            format!("application.name=Ghidra\napplication.version = {version}\n"),
        )
        .unwrap();
        let jdk = root.join("jdk");
        fs::create_dir_all(jdk.join("bin")).unwrap();
        fs::write(jdk.join("bin/java"), b"").unwrap();
        let jar = root.join("kraken-ghidra.jar");
        fs::write(&jar, b"").unwrap();
        (ghidra, jdk, jar)
    }

    #[test]
    fn parses_version() {
        assert_eq!(
            parse_application_version("a=b\napplication.version=12.1.4\n").as_deref(),
            Some("12.1.4")
        );
        assert_eq!(parse_application_version("x=y"), None);
    }

    #[test]
    fn explicit_config_wins_over_env() {
        let dir = tempfile::tempdir().unwrap();
        let (ghidra, jdk, jar) = fake_install(dir.path(), "12.1.4");
        let cfg = InstallConfig {
            ghidra_home: Some(ghidra.clone()),
            java_home: Some(jdk),
            ext_jar: Some(jar),
        };
        let env = |_: &str| Some(OsString::from("/nonexistent"));
        let i = GhidraInstall::discover_with(&cfg, &env).unwrap();
        assert_eq!(i.ghidra_version, "12.1.4");
        assert_eq!(i.ghidra_home, fs::canonicalize(ghidra).unwrap());
        let cp = i.classpath().unwrap();
        assert!(cp.ends_with("kraken-ghidra.jar"), "{cp}");
        assert!(cp.contains("u.jar"), "{cp}");
    }

    #[test]
    fn env_is_used_and_java_home_is_the_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let (ghidra, jdk, jar) = fake_install(dir.path(), "12.1.4");
        let env = move |k: &str| match k {
            ENV_GHIDRA_HOME => Some(ghidra.clone().into()),
            "JAVA_HOME" => Some(jdk.clone().into()),
            ENV_EXT_JAR => Some(jar.clone().into()),
            _ => None,
        };
        assert!(GhidraInstall::discover_with(&InstallConfig::default(), &env).is_ok());
    }

    #[test]
    fn untested_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (ghidra, jdk, jar) = fake_install(dir.path(), "99.0.0");
        let cfg = InstallConfig {
            ghidra_home: Some(ghidra),
            java_home: Some(jdk),
            ext_jar: Some(jar),
        };
        let err = GhidraInstall::discover_with(&cfg, &|_| None).unwrap_err();
        assert!(err.to_string().contains("not a tested version"), "{err}");
    }

    #[test]
    fn missing_pieces_are_named() {
        let err = GhidraInstall::discover_with(&InstallConfig::default(), &|_| None).unwrap_err();
        assert!(err.to_string().contains(ENV_GHIDRA_HOME), "{err}");
    }
}
