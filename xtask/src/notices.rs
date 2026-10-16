//! `cargo xtask notices`: renders `THIRD-PARTY-NOTICES.md` from `cargo metadata`.
//!
//! The page lists every crate that can end up in a shipped binary (`kraken`, `krakend`,
//! `kraken-gui`: normal and build dependencies, no dev-only ones), grouped by license, with the
//! license and notice files found in each crate's registry source. Identical texts are printed
//! once. Non-Rust bundled assets and the separately downloaded components are described by hand.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::{Result, workspace_root};

/// Binaries whose dependency closure is listed.
const SHIPPED: &[&str] = &["kraken-cli", "krakend", "kraken-gui"];

const FONT_LICENSE: &str = "crates/kraken-gui/assets/fonts/LICENSE.txt";

/// Path of the committed notices file.
pub fn notices_path() -> PathBuf {
    workspace_root().join("THIRD-PARTY-NOTICES.md")
}

/// Why the notices could not be rendered.
#[derive(Debug)]
pub enum NoticesError {
    /// Crate sources (or the metadata that needs them) are not available locally.
    SourceUnavailable(String),
    /// Anything else.
    Other(String),
}

impl std::fmt::Display for NoticesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoticesError::SourceUnavailable(m) | NoticesError::Other(m) => f.write_str(m),
        }
    }
}

pub fn write_notices() -> Result<()> {
    let text = generate(false).map_err(|e| e.to_string())?;
    let path = notices_path();
    fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("notices: {}", path.display());
    Ok(())
}

/// Runs `cargo metadata` and renders the page. `offline` keeps cargo off the network.
pub fn generate(offline: bool) -> std::result::Result<String, NoticesError> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.args(["metadata", "--format-version", "1", "--locked"]);
    if offline {
        cmd.arg("--offline");
    }
    let out = cmd
        .current_dir(workspace_root())
        .output()
        .map_err(|e| NoticesError::Other(format!("cannot run cargo metadata: {e}")))?;
    if !out.status.success() {
        let msg = format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return Err(if offline {
            NoticesError::SourceUnavailable(msg)
        } else {
            NoticesError::Other(msg)
        });
    }
    let meta: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| NoticesError::Other(format!("bad cargo metadata output: {e}")))?;
    render(&meta, &workspace_root())
}

struct Krate {
    name: String,
    version: String,
    license: String,
    repository: Option<String>,
    dir: PathBuf,
    declared_file: Option<String>,
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

/// SPDX expression with the legacy `/` separator and stray spacing normalised.
fn normalise_license(raw: &str) -> String {
    raw.replace(" / ", " OR ")
        .replace('/', " OR ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The packages reachable from the shipped binaries over non-dev edges.
fn shipped_crates(meta: &Value) -> std::result::Result<Vec<Krate>, NoticesError> {
    let bad = |what: &str| NoticesError::Other(format!("unexpected cargo metadata: {what}"));
    let packages = meta["packages"].as_array().ok_or_else(|| bad("packages"))?;
    let by_id: HashMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| bad("resolve.nodes"))?;
    let node_by_id: HashMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();

    let mut stack: Vec<&str> = packages
        .iter()
        .filter(|p| p["source"].is_null())
        .filter(|p| p["name"].as_str().is_some_and(|n| SHIPPED.contains(&n)))
        .filter_map(|p| p["id"].as_str())
        .collect();
    if stack.len() != SHIPPED.len() {
        return Err(bad("a shipped binary crate is missing"));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(node) = node_by_id.get(id) else {
            continue;
        };
        for dep in node["deps"].as_array().into_iter().flatten() {
            let non_dev = dep["dep_kinds"].as_array().is_none_or(|ks| {
                ks.iter()
                    .any(|k| !k["kind"].is_string() || k["kind"] == "build")
            });
            if let (true, Some(did)) = (non_dev, dep["pkg"].as_str()) {
                stack.push(did);
            }
        }
    }

    let mut out = Vec::new();
    for id in seen {
        let Some(p) = by_id.get(id) else { continue };
        if p["source"].is_null() {
            continue; // workspace members are KRAKEN itself
        }
        let name = str_field(p, "name").ok_or_else(|| bad("package name"))?;
        let manifest = str_field(p, "manifest_path").ok_or_else(|| bad("manifest_path"))?;
        let dir = Path::new(&manifest)
            .parent()
            .ok_or_else(|| bad("manifest_path"))?
            .to_path_buf();
        out.push(Krate {
            version: str_field(p, "version").unwrap_or_default(),
            license: str_field(p, "license")
                .map(|l| normalise_license(&l))
                .unwrap_or_else(|| "UNSPECIFIED".to_string()),
            repository: str_field(p, "repository"),
            declared_file: str_field(p, "license_file"),
            dir,
            name,
        });
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn is_license_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "license",
        "licence",
        "copying",
        "unlicense",
        "notice",
        "copyright",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

/// `(file name, text)` of the license and notice files in a crate's source directory.
fn license_texts(k: &Krate) -> std::result::Result<Vec<(String, String)>, NoticesError> {
    let missing = |what: String| NoticesError::SourceUnavailable(what);
    if !k.dir.is_dir() {
        return Err(missing(format!(
            "source of {} {} not found at {}",
            k.name,
            k.version,
            k.dir.display()
        )));
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    if let Ok(rd) = fs::read_dir(&k.dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_file() && is_license_file_name(&name) {
                names.insert(name);
            }
        }
    }
    if let Some(f) = &k.declared_file
        && k.dir.join(f).is_file()
    {
        names.insert(f.clone());
    }
    let mut out = Vec::new();
    for name in names {
        let bytes = fs::read(k.dir.join(&name))
            .map_err(|e| NoticesError::Other(format!("cannot read {name} of {}: {e}", k.name)))?;
        out.push((name, clean(&String::from_utf8_lossy(&bytes))));
    }
    Ok(out)
}

/// LF line ends, no trailing whitespace, no surrounding blank lines.
fn clean(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    lines.join("\n").trim_matches('\n').to_string()
}

fn indent(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "    {line}");
        }
    }
    out
}

const INTRO: &str = "# Third-party notices

<!-- Generated by `cargo xtask notices` from `cargo metadata`. Do not edit by hand. -->

KRAKEN is licensed under GPL-3.0-or-later (see `LICENSE`). It includes or depends on the
third-party components below. Each is used under its own license; the license texts are
reproduced as shipped by the component.

## Bundled assets

### IBM Plex fonts (SIL Open Font License 1.1)

The KRAKEN GUI embeds IBM Plex Sans (Regular, Medium) and IBM Plex Mono (Regular), from the
IBM Plex project (<https://github.com/IBM/plex>). License text, as shipped with the fonts:
";

const DOWNLOADED: &str = "## Components downloaded at setup time (not redistributed)

The default KRAKEN release does not contain the following. `kraken setup` downloads them from
their publishers, verifies pinned SHA-256 checksums, and runs them as separate processes (they are
not linked into KRAKEN).

- **Ghidra** (<https://github.com/NationalSecurityAgency/ghidra>), Apache License 2.0. Downloaded
  from the NSA's GitHub release. Its own `LICENSE` and `NOTICE` files come with the download.
- **Eclipse Temurin JDK 21** (<https://adoptium.net/>), GPL-2.0-only with the Classpath Exception
  (GPLv2+CE). Downloaded from the Adoptium release. Its license files come with the download.

If a future release bundles either component, this page and the release archive will carry their
full notices.

## Rust crates

Every crate that can be part of the `kraken`, `krakend` or `kraken-gui` binaries (normal and
build dependencies on any target platform, no dev-only dependencies), grouped by the license
expression in its `Cargo.toml`. For crates offered under a choice of licenses (`OR`), KRAKEN
elects the license compatible with GPL-3.0-or-later. Where several crates ship an identical
license text, it is printed once.
";

/// Renders the whole page.
pub fn render(meta: &Value, root: &Path) -> std::result::Result<String, NoticesError> {
    let font_license = fs::read_to_string(root.join(FONT_LICENSE))
        .map_err(|e| NoticesError::Other(format!("cannot read {FONT_LICENSE}: {e}")))?;
    let crates = shipped_crates(meta)?;

    let mut groups: BTreeMap<&str, Vec<&Krate>> = BTreeMap::new();
    for k in &crates {
        groups.entry(k.license.as_str()).or_default().push(k);
    }

    let mut out = String::from(INTRO);
    out.push('\n');
    out.push_str(&indent(&clean(&font_license)));
    out.push('\n');
    out.push_str(DOWNLOADED);
    let _ = writeln!(
        out,
        "\n{} crates in {} license groups.",
        crates.len(),
        groups.len()
    );

    for (license, members) in &groups {
        let _ = writeln!(out, "\n### {license}\n");
        for k in members {
            match &k.repository {
                Some(r) => {
                    let _ = writeln!(out, "- {} {} (<{r}>)", k.name, k.version);
                }
                None => {
                    let _ = writeln!(out, "- {} {}", k.name, k.version);
                }
            }
        }
        // text -> (file names, crates)
        let mut texts: BTreeMap<String, (BTreeSet<String>, Vec<String>)> = BTreeMap::new();
        let mut without: Vec<String> = Vec::new();
        for k in members {
            let files = license_texts(k)?;
            if files.is_empty() {
                without.push(format!("{} {}", k.name, k.version));
            }
            for (name, text) in files {
                if text.is_empty() {
                    continue;
                }
                let e = texts.entry(text).or_default();
                e.0.insert(name);
                let label = format!("{} {}", k.name, k.version);
                if !e.1.contains(&label) {
                    e.1.push(label);
                }
            }
        }
        for (text, (names, users)) in &texts {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let _ = writeln!(out, "\n**{}** — {}\n", names.join(", "), users.join(", "));
            out.push_str(&indent(text));
        }
        if !without.is_empty() {
            let _ = writeln!(
                out,
                "\nNo license file in the source of: {}. They are distributed under the SPDX expression `{license}` above.",
                without.join(", ")
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_separators_are_normalised() {
        assert_eq!(normalise_license("MIT/Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(normalise_license("MIT / Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(
            normalise_license("Apache-2.0 WITH LLVM-exception"),
            "Apache-2.0 WITH LLVM-exception"
        );
    }

    #[test]
    fn license_file_names_are_recognised() {
        for n in [
            "LICENSE",
            "LICENSE-MIT",
            "LICENCE.md",
            "COPYING",
            "UNLICENSE",
            "NOTICE",
        ] {
            assert!(is_license_file_name(n), "{n}");
        }
        assert!(!is_license_file_name("Cargo.toml"));
    }

    #[test]
    fn text_is_cleaned() {
        assert_eq!(clean("\n\na  \r\nb\t\n\n"), "a\nb");
    }

    /// Skipped when the registry sources are not on this machine (minimal CI); the normal CI
    /// test job runs `cargo fetch` first so it is enforced there.
    #[test]
    fn committed_notices_are_up_to_date() {
        let rendered = match generate(true) {
            Ok(r) => r,
            Err(NoticesError::SourceUnavailable(why)) => {
                eprintln!("skipping notices staleness check: {why}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let path = notices_path();
        let committed = fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == rendered,
            "{} is stale: run `cargo xtask notices` and commit the result",
            path.display()
        );
    }

    #[test]
    fn page_has_the_fixed_sections() {
        let meta: Value = serde_json::json!({
            "packages": [
                {"id": "a", "name": "kraken-cli", "version": "0.0.0", "source": null, "manifest_path": "/x/Cargo.toml"},
                {"id": "b", "name": "krakend", "version": "0.0.0", "source": null, "manifest_path": "/x/Cargo.toml"},
                {"id": "c", "name": "kraken-gui", "version": "0.0.0", "source": null, "manifest_path": "/x/Cargo.toml"},
            ],
            "resolve": {"nodes": []}
        });
        let text = render(&meta, &workspace_root()).expect("render");
        for needle in ["IBM Plex", "Ghidra", "Temurin", "GPLv2+CE", "0 crates"] {
            assert!(text.contains(needle), "{needle}");
        }
    }
}
