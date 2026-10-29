//! The manifest format of the integrations catalogue and its checks.
//!
//! One TOML file holds `[[emulator]]` tables (an emulator, a compatibility layer or a tool that
//! runs programs). The catalogue that ships with KRAKEN is compiled in; a person adds their own
//! emulator by dropping a file in `<config dir>/emulators.d/`.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The catalogue that ships with KRAKEN.
pub const CATALOGUE: &str = include_str!("catalogue.toml");

/// The only placeholders an argv template may use.
pub const PLACEHOLDERS: [&str; 4] = ["{exe}", "{binary}", "{dir}", "{port}"];

/// A manifest file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    /// Format version (1).
    pub schema: u32,
    /// The entries.
    #[serde(default)]
    pub emulator: Vec<Entry>,
}

/// One emulator, compatibility layer or tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Lower-case id: letters, digits and `-`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// `emulator` (default), `compat_layer` or `tool`.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// One line.
    pub summary: String,
    /// Upstream page.
    #[serde(default)]
    pub homepage: String,
    /// Systems or program kinds it runs.
    #[serde(default)]
    pub platforms: Vec<String>,
    /// File extensions it opens.
    #[serde(default)]
    pub formats: Vec<String>,
    /// SPDX identifier or a short licence name.
    pub license: String,
    /// What to read before installing.
    #[serde(default)]
    pub notice: String,
    /// The download embeds key material.
    #[serde(default)]
    pub contains_key_material: bool,
    /// How to find a copy on this computer.
    #[serde(default)]
    pub detect: Detect,
    /// How to run it.
    pub run: Run,
    /// Upstream releases KRAKEN may download.
    #[serde(default)]
    pub artifact: Vec<Artifact>,
}

fn default_kind() -> String {
    "emulator".into()
}

/// How to find an installed copy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Program names to look for on `PATH`.
    #[serde(default)]
    pub names: Vec<String>,
    /// Paths, with `~` and `*` in the last component, to look at.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Flatpak application id: its export wrapper is looked for.
    #[serde(default)]
    pub flatpak: Option<String>,
    /// Ask the program for its version (`--version`) when found on this computer.
    #[serde(default)]
    pub probe: bool,
}

/// How an emulator is started.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// Command line template; the first element must be `{exe}`.
    pub argv: Vec<String>,
    /// A windowed program that keeps running (default true).
    #[serde(default = "yes")]
    pub gui: bool,
    /// Command line for a launch that waits for a debugger.
    #[serde(default)]
    pub gdb_argv: Option<Vec<String>>,
    /// Port of the GDB stub (default 1234).
    #[serde(default)]
    pub gdb_port: Option<u16>,
    /// Extra environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

fn yes() -> bool {
    true
}

/// Archive container of a download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// The download is the program (an AppImage or a binary).
    File,
    /// A zip archive.
    Zip,
    /// A gzip-compressed tar.
    TarGz,
    /// An xz-compressed tar.
    TarXz,
}

/// One pinned upstream release asset.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// `linux` (default).
    #[serde(default = "linux")]
    pub os: String,
    /// `x86_64` (default).
    #[serde(default = "x86_64")]
    pub arch: String,
    /// Release the asset belongs to.
    pub version: String,
    /// `https://` URL of the asset.
    pub url: String,
    /// Lower-case hex SHA-256 of the asset.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Container.
    pub format: Format,
    /// The program: its file name for `file`, else its path inside the archive.
    pub entry: String,
}

fn linux() -> String {
    "linux".into()
}

fn x86_64() -> String {
    "x86_64".into()
}

/// Failure to read or accept a manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// Not valid TOML for the format.
    #[error("{0}")]
    Parse(String),
    /// A rule of the format is broken.
    #[error("{id}: {problem}")]
    Lint {
        /// The entry.
        id: String,
        /// What is wrong.
        problem: String,
    },
}

/// Parses `text` and checks every entry.
pub fn parse(text: &str) -> Result<Vec<Entry>, ManifestError> {
    let file: ManifestFile =
        toml::from_str(text).map_err(|e| ManifestError::Parse(e.to_string()))?;
    if file.schema != 1 {
        return Err(ManifestError::Parse(format!(
            "unknown schema {}; this KRAKEN reads schema 1",
            file.schema
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &file.emulator {
        lint(e)?;
        if !seen.insert(e.id.clone()) {
            return Err(ManifestError::Lint {
                id: e.id.clone(),
                problem: "defined twice".into(),
            });
        }
    }
    Ok(file.emulator)
}

fn bad(id: &str, problem: impl Into<String>) -> ManifestError {
    ManifestError::Lint {
        id: id.to_string(),
        problem: problem.into(),
    }
}

fn check_template(id: &str, what: &str, argv: &[String]) -> Result<(), ManifestError> {
    if argv.first().map(String::as_str) != Some("{exe}") {
        return Err(bad(id, format!("{what} must start with {{exe}}")));
    }
    for a in argv {
        if a.contains('\0') {
            return Err(bad(id, format!("{what} holds a NUL byte")));
        }
        let mut rest = a.as_str();
        while let Some(i) = rest.find('{') {
            let Some(j) = rest[i..].find('}') else {
                return Err(bad(id, format!("{what}: unclosed `{{` in {a:?}")));
            };
            let token = &rest[i..=i + j];
            if !PLACEHOLDERS.contains(&token) {
                return Err(bad(
                    id,
                    format!(
                        "{what}: unknown placeholder {token}; allowed: {}",
                        PLACEHOLDERS.join(" ")
                    ),
                ));
            }
            rest = &rest[i + j + 1..];
        }
    }
    Ok(())
}

/// Checks one entry against the rules of the format.
pub fn lint(e: &Entry) -> Result<(), ManifestError> {
    let id = e.id.as_str();
    let id_ok = !id.is_empty()
        && id.len() <= 40
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !id_ok {
        return Err(bad(id, "id must be 1-40 characters of a-z, 0-9 and `-`"));
    }
    if !matches!(e.kind.as_str(), "emulator" | "compat_layer" | "tool") {
        return Err(bad(id, "kind must be emulator, compat_layer or tool"));
    }
    if e.name.trim().is_empty() || e.license.trim().is_empty() {
        return Err(bad(id, "name and license are required"));
    }
    check_template(id, "run.argv", &e.run.argv)?;
    if let Some(g) = &e.run.gdb_argv {
        check_template(id, "run.gdb_argv", g)?;
    }
    for k in e.run.env.keys() {
        if k.is_empty() || k.contains('=') || k.contains('\0') {
            return Err(bad(id, format!("bad environment variable name {k:?}")));
        }
    }
    for n in &e.detect.names {
        if n.is_empty() || n.contains('/') {
            return Err(bad(id, "detect.names are bare program names"));
        }
    }
    for a in &e.artifact {
        if !a.url.to_ascii_lowercase().starts_with("https://") {
            return Err(bad(id, format!("artifact URL {} is not https", a.url)));
        }
        let hex = a.sha256.len() == 64
            && a.sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        if !hex {
            return Err(bad(id, "artifact sha256 must be 64 lower-case hex digits"));
        }
        if a.size == 0 {
            return Err(bad(id, "artifact size is required"));
        }
        let p = std::path::Path::new(&a.entry);
        let plain = !a.entry.is_empty()
            && p.components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        if !plain {
            return Err(bad(
                id,
                "artifact entry must be a relative path without `..`",
            ));
        }
        if a.format == Format::File && a.entry.contains('/') {
            return Err(bad(id, "a `file` artifact's entry is a file name"));
        }
        if a.version.is_empty() || a.version.contains('/') || a.version.starts_with('.') {
            return Err(bad(id, "artifact version must be a plain string"));
        }
    }
    if e.contains_key_material && e.artifact.is_empty() {
        return Err(bad(id, "contains_key_material without an artifact"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_catalogue_parses_and_lints() {
        let entries = parse(CATALOGUE).expect("catalogue");
        assert!(entries.len() >= 18);
        for want in [
            "xemu",
            "xenia-canary",
            "shadps4",
            "rpcs3",
            "pcsx2",
            "ppsspp",
            "dolphin",
            "duckstation",
            "mgba",
            "melonds",
            "ryubing",
            "cemu",
            "mame",
            "ares",
            "wine",
            "qemu-user-x86-64",
        ] {
            assert!(entries.iter().any(|e| e.id == want), "{want} is missing");
        }
        // Every downloadable entry names its notice and licence.
        for e in entries.iter().filter(|e| !e.artifact.is_empty()) {
            assert!(!e.notice.is_empty(), "{} needs a notice", e.id);
        }
        let xenia = entries.iter().find(|e| e.id == "xenia-canary").unwrap();
        assert!(xenia.contains_key_material);
    }

    fn one(extra: &str) -> String {
        format!(
            "schema = 1\n[[emulator]]\nid = \"t\"\nname = \"T\"\nsummary = \"s\"\nlicense = \"MIT\"\n{extra}"
        )
    }

    #[test]
    fn rules_of_the_format() {
        let ok = one("[emulator.run]\nargv = [\"{exe}\", \"{binary}\"]\n");
        assert!(parse(&ok).is_ok());
        for (extra, needle) in [
            (
                "[emulator.run]\nargv = [\"sh\", \"{binary}\"]\n",
                "start with {exe}",
            ),
            (
                "[emulator.run]\nargv = [\"{exe}\", \"{key}\"]\n",
                "unknown placeholder",
            ),
            (
                "[emulator.run]\nargv = [\"{exe}\"]\n[[emulator.artifact]]\nversion=\"1\"\nurl=\"http://x/y\"\nsha256=\"00\"\nsize=1\nformat=\"file\"\nentry=\"y\"\n",
                "not https",
            ),
            (
                "[emulator.run]\nargv = [\"{exe}\"]\n[[emulator.artifact]]\nversion=\"1\"\nurl=\"https://x/y\"\nsha256=\"00\"\nsize=1\nformat=\"file\"\nentry=\"y\"\n",
                "sha256",
            ),
            (
                "[emulator.run]\nargv = [\"{exe}\"]\n[[emulator.artifact]]\nversion=\"1\"\nurl=\"https://x/y\"\nsha256=\"0000000000000000000000000000000000000000000000000000000000000000\"\nsize=1\nformat=\"zip\"\nentry=\"../y\"\n",
                "entry",
            ),
        ] {
            let err = parse(&one(extra)).unwrap_err().to_string();
            assert!(err.contains(needle), "{err} should mention {needle}");
        }
    }
}
