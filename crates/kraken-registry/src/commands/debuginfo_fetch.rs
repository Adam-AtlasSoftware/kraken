//! The network side of `debuginfo_find`: asks debuginfod servers for an ELF debug file by
//! build-id and Microsoft-style symbol servers for a PDB by GUID and age, checks what comes back
//! with the same rules as a file on disk, and keeps it in KRAKEN's download cache.
//!
//! Nothing here decides whether a download is allowed; the command does that before it calls
//! [`fetch`]. A file only reaches the cache after `verify_file` calls it a match, so a server
//! cannot make KRAKEN attach another build's symbols.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kraken_proto::{DebugRefs, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::debuginfo::{Verdict, base_name, verify_file};

/// A download larger than this is abandoned.
pub const MAX_DOWNLOAD: u64 = 1 << 30;
/// How long one server may take to answer and to send the file.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// What a file in the cache is a debug file for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// An ELF debug file for this GNU build-id (lower-case hex).
    BuildId(String),
    /// A PDB with this base name, GUID (canonical text) and age.
    Pdb {
        /// File name of the PDB, safe as a path element.
        name: String,
        /// GUID in the canonical text form.
        guid: String,
        /// Age.
        age: u32,
    },
}

/// What a server was asked for and what it said.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FindAttempt {
    /// The server.
    pub server: Untrusted<String>,
    /// The address that was requested.
    pub url: Untrusted<String>,
    /// What came of it, in a sentence.
    pub outcome: Untrusted<String>,
}

/// What `debuginfo_find` did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugFindOut {
    /// True when a verified debug file is now in the cache.
    pub found: bool,
    /// The cached file: what `debuginfo_attach` takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<Untrusted<String>>,
    /// The address it came from; absent for a cache hit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Untrusted<String>>,
    /// True when the cache already had the file and no server was asked.
    pub cache_hit: bool,
    /// Size of the file.
    pub bytes: u64,
    /// What each server answered, in the order asked.
    pub attempts: Vec<FindAttempt>,
    /// One or two sentences in plain words.
    pub summary: String,
}

impl DebugFindOut {
    fn empty() -> Self {
        DebugFindOut {
            found: false,
            file: None,
            from: None,
            cache_hit: false,
            bytes: 0,
            attempts: Vec::new(),
            summary: String::new(),
        }
    }

    /// The answer when the cache already holds the file.
    pub fn hit(path: &Path, bytes: u64) -> Self {
        DebugFindOut {
            found: true,
            file: Some(Untrusted::sanitized(&path.to_string_lossy())),
            cache_hit: true,
            bytes,
            summary: "The download cache already holds a matching file; no server was asked."
                .into(),
            ..Self::empty()
        }
    }
}

/// What the program wants from a server, when it says enough.
pub fn wanted_of(refs: &DebugRefs) -> Option<Wanted> {
    if let Some(p) = &refs.pdb
        && let Some(name) = safe_name(base_name(&p.name.0))
        && name.to_ascii_lowercase().ends_with(".pdb")
    {
        return Some(Wanted::Pdb {
            name,
            guid: p.guid.clone(),
            age: p.age,
        });
    }
    let id = refs.build_id.as_deref()?;
    (id.len() >= 2
        && id.len() <= 128
        && id.len() % 2 == 0
        && id.bytes().all(|b| b.is_ascii_hexdigit()))
    .then(|| Wanted::BuildId(id.to_ascii_lowercase()))
}

/// `name` when it is plain enough to be a path element and a URL segment.
fn safe_name(name: &str) -> Option<String> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'));
    ok.then(|| name.to_string())
}

fn guid_key(guid: &str) -> String {
    guid.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Where the cache keeps the file for `w` under `root`.
pub fn cache_path(root: &Path, w: &Wanted) -> PathBuf {
    match w {
        Wanted::BuildId(id) => root.join("buildid").join(id).join("debuginfo"),
        Wanted::Pdb { name, guid, age } => root
            .join("symbols")
            .join(name)
            .join(format!("{}{age:X}", guid_key(guid)))
            .join(name),
    }
}

/// KRAKEN's download cache: `$KRAKEN_DEBUGINFO_CACHE`, else `<data dir>/kraken/debuginfo`.
pub fn download_cache() -> Option<PathBuf> {
    let set = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(p) = set("KRAKEN_DEBUGINFO_CACHE") {
        return Some(p);
    }
    if let Some(x) = set("XDG_DATA_HOME").filter(|p| p.is_absolute()) {
        return Some(x.join("kraken/debuginfo"));
    }
    set("HOME").map(|h| h.join(".local/share/kraken/debuginfo"))
}

/// Every address a server could hold the file at: the plain file first, then (for a PDB) the
/// compressed `.pd_` form, flagged `true`.
pub fn urls(server: &str, w: &Wanted) -> Vec<(String, bool)> {
    let base = server.trim_end_matches('/');
    match w {
        Wanted::BuildId(id) => vec![(format!("{base}/buildid/{id}/debuginfo"), false)],
        Wanted::Pdb { name, guid, age } => {
            let key = format!("{}{age:X}", guid_key(guid));
            let packed = format!("{}_", &name[..name.len() - 1]);
            vec![
                (format!("{base}/{name}/{key}/{name}"), false),
                (format!("{base}/{name}/{key}/{packed}"), true),
            ]
        }
    }
}

/// `s` as a server address, or why it is not one.
pub fn normalize_server(s: &str) -> Result<String, String> {
    let t = s.trim();
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .ok_or_else(|| format!("`{t}` is not an http:// or https:// address"))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(format!(
            "`{t}` has no usable host (credentials in the address are not accepted)"
        ));
    }
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("`{t}` contains spaces or control characters"));
    }
    Ok(t.trim_end_matches('/').to_string())
}

enum Got {
    File(tempfile::NamedTempFile, u64),
    Absent,
    Failed(String),
}

async fn download(client: &reqwest::Client, url: &str, dir: &Path) -> Got {
    let mut resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return Got::Failed(format!("could not reach it: {}", short(&e))),
    };
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Got::Absent;
    }
    if !status.is_success() {
        return Got::Failed(format!("the server answered {status}"));
    }
    let too_big = || {
        Got::Failed(format!(
            "it is larger than the {} MiB limit",
            MAX_DOWNLOAD >> 20
        ))
    };
    if resp.content_length().is_some_and(|n| n > MAX_DOWNLOAD) {
        return too_big();
    }
    let mut tmp = match tempfile::Builder::new().prefix(".part-").tempfile_in(dir) {
        Ok(t) => t,
        Err(e) => return Got::Failed(format!("cannot write the cache: {e}")),
    };
    let mut total = 0u64;
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                total += c.len() as u64;
                if total > MAX_DOWNLOAD {
                    return too_big();
                }
                if let Err(e) = tmp.write_all(&c) {
                    return Got::Failed(format!("cannot write the cache: {e}"));
                }
            }
            Ok(None) => break,
            Err(e) => return Got::Failed(format!("the download broke off: {}", short(&e))),
        }
    }
    if tmp.flush().is_err() {
        return Got::Failed("cannot write the cache".into());
    }
    Got::File(tmp, total)
}

fn short(e: &reqwest::Error) -> String {
    let m = e.to_string();
    match std::error::Error::source(e) {
        Some(src) => format!("{m}: {src}"),
        None => m,
    }
}

/// The cached file for `w` when it is there and still verifies.
pub fn cached(root: &Path, refs: &DebugRefs, w: &Wanted) -> Option<(PathBuf, u64)> {
    let p = cache_path(root, w);
    let len = std::fs::metadata(&p).ok().filter(|m| m.is_file())?.len();
    (verify_file(refs, &p).0 == Verdict::Match).then_some((p, len))
}

/// Asks `servers` in turn for the file `w` stands for; the first file that verifies is kept in
/// the cache under `root`.
pub async fn fetch(refs: &DebugRefs, w: &Wanted, servers: &[String], root: &Path) -> DebugFindOut {
    let mut out = DebugFindOut::empty();
    let dest = cache_path(root, w);
    let Some(dir) = dest.parent().map(Path::to_path_buf) else {
        out.summary = "the cache location is not usable".into();
        return out;
    };
    if let Err(e) = make_private_dir(&dir) {
        out.summary = format!("cannot create the cache folder {}: {e}", dir.display());
        return out;
    }
    let client = match reqwest::Client::builder()
        .user_agent(concat!("kraken/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            out.summary = format!("cannot start the HTTP client: {e}");
            return out;
        }
    };
    let mut only_compressed = false;
    for server in servers {
        for (url, compressed) in urls(server, w) {
            let note = |outcome: &str| FindAttempt {
                server: Untrusted::sanitized(server),
                url: Untrusted::sanitized(&url),
                outcome: Untrusted::sanitized(outcome),
            };
            let got = download(&client, &url, &dir).await;
            let outcome = match got {
                Got::Absent if compressed => continue,
                Got::Absent => "the server does not have it (404)".to_string(),
                Got::Failed(m) => m,
                Got::File(..) if compressed => {
                    only_compressed = true;
                    "the server only has the compressed .pd_ form, which KRAKEN cannot unpack; expand it with `cabextract` or `expand`, then attach the .pdb with debuginfo_attach".into()
                }
                Got::File(tmp, n) => {
                    let (verdict, why) = verify_file(refs, tmp.path());
                    if verdict != Verdict::Match {
                        format!("refused: this is not the program's debug file: {why}")
                    } else {
                        match tmp.persist(&dest) {
                            Ok(_) => {
                                out.attempts.push(note(&format!(
                                    "downloaded {n} bytes and checked them against the program"
                                )));
                                out.found = true;
                                out.bytes = n;
                                out.from = Some(Untrusted::sanitized(&url));
                                out.file = Some(Untrusted::sanitized(&dest.to_string_lossy()));
                                out.summary = format!(
                                    "Downloaded {n} bytes from {server}; they match the program."
                                );
                                return out;
                            }
                            Err(e) => format!("cannot store the file: {}", e.error),
                        }
                    }
                }
            };
            out.attempts.push(note(&outcome));
        }
    }
    out.summary = if only_compressed {
        "A server has the PDB only in the compressed .pd_ form, which KRAKEN cannot unpack; expand it yourself and attach the result.".into()
    } else {
        format!(
            "None of the {} server(s) delivered a debug file that matches the program.",
            servers.len()
        )
    };
    out
}

/// What the import wizard does: the cached file for the program's identity, or a search of
/// `servers`. The caller has the person's consent already.
pub async fn find(refs: &DebugRefs, servers: &[String]) -> Result<DebugFindOut, String> {
    let w = wanted_of(refs)
        .ok_or("the program carries no build-id or PDB reference a server could be asked about")?;
    let root = download_cache()
        .ok_or("cannot place the download cache: set HOME or KRAKEN_DEBUGINFO_CACHE")?;
    if let Some((file, bytes)) = cached(&root, refs, &w) {
        return Ok(DebugFindOut::hit(&file, bytes));
    }
    Ok(fetch(refs, &w, servers, &root).await)
}

/// The servers in `configured`, then those of `DEBUGINFOD_URLS`, each once.
pub fn servers_with_env(configured: &[String]) -> Vec<String> {
    let env = std::env::var("DEBUGINFOD_URLS").unwrap_or_default();
    let mut all: Vec<String> = Vec::new();
    for u in configured
        .iter()
        .map(String::as_str)
        .chain(env.split_whitespace())
    {
        if let Ok(u) = normalize_server(u)
            && !all.contains(&u)
        {
            all.push(u);
        }
    }
    all
}

/// True when `KRAKEN_OFFLINE` is set.
pub fn offline_env() -> bool {
    std::env::var("KRAKEN_OFFLINE").is_ok_and(|v| !v.is_empty() && v != "0")
}

fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_style_addresses_use_the_guid_without_dashes_and_the_age_in_hex() {
        let w = Wanted::Pdb {
            name: "a.pdb".into(),
            guid: "1B72224D-37B8-1792-2820-0ED8994498B2".into(),
            age: 17,
        };
        let u = urls("https://syms.example/sym/", &w);
        assert_eq!(
            u[0].0,
            "https://syms.example/sym/a.pdb/1B72224D37B8179228200ED8994498B211/a.pdb"
        );
        assert!(u[1].1 && u[1].0.ends_with("/a.pd_"));
        let b = urls("http://h:8002", &Wanted::BuildId("abcd".into()));
        assert_eq!(b[0].0, "http://h:8002/buildid/abcd/debuginfo");
    }

    #[test]
    fn odd_names_and_servers_are_refused() {
        assert!(safe_name("../x.pdb").is_none());
        assert!(safe_name("a b.pdb").is_none());
        assert_eq!(safe_name("ntdll.pdb").as_deref(), Some("ntdll.pdb"));
        assert!(normalize_server("ftp://x").is_err());
        assert!(normalize_server("https://user@x/").is_err());
        assert_eq!(
            normalize_server(" https://x.org/a/ ").unwrap(),
            "https://x.org/a"
        );
    }
}
