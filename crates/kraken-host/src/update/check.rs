//! Asking GitHub for the newest release (ADR 0015, "Checking").

use std::ffi::OsString;
use std::time::Duration;

use semver::Version;
use serde::Deserialize;

use super::UpdateError;
use crate::config::UpdateChannel;
use crate::provision::{Fetcher, HttpsFetcher};

/// The one host the check talks to.
pub const API_HOSTS: &[&str] = &["api.github.com"];
/// The hosts release files are downloaded from, redirects included.
pub const DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
/// The latest release.
pub const LATEST_URL: &str =
    "https://api.github.com/repos/Adam-AtlasSoftware/kraken/releases/latest";
/// The newest releases, prereleases included.
pub const LIST_URL: &str =
    "https://api.github.com/repos/Adam-AtlasSoftware/kraken/releases?per_page=20";
/// Where release files are downloaded from: `<base>/v<version>/<name>`.
pub const DOWNLOAD_BASE: &str = "https://github.com/Adam-AtlasSoftware/kraken/releases/download";
/// Largest release listing accepted.
const MAX_LISTING: usize = 4 << 20;

/// The release a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Version, without the `v`.
    pub version: Version,
    /// Release page.
    pub notes_url: String,
    /// It has `SHA256SUMS.minisig`.
    pub signed: bool,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

/// The version of a tag that matches `^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`; anything else is
/// ignored.
pub fn parse_tag(tag: &str) -> Option<Version> {
    let rest = tag.strip_prefix('v')?;
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if let Some(p) = pre
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
    {
        return None;
    }
    Version::parse(rest).ok()
}

/// True when `latest` should replace `current`: strictly newer, never a downgrade.
pub fn is_newer(latest: &Version, current: &Version) -> bool {
    latest > current
}

fn found_of(r: &Release) -> Option<Found> {
    if r.draft {
        return None;
    }
    Some(Found {
        version: parse_tag(&r.tag_name)?,
        notes_url: if r.html_url.starts_with("https://github.com/") {
            r.html_url.clone()
        } else {
            format!(
                "https://github.com/Adam-AtlasSoftware/kraken/releases/tag/{}",
                r.tag_name
            )
        },
        signed: r.assets.iter().any(|a| a.name == "SHA256SUMS.minisig"),
    })
}

/// The newest release in a `releases/latest` answer (`stable`) or a releases list
/// (`prerelease`).
pub fn parse_answer(text: &str, channel: UpdateChannel) -> Result<Option<Found>, UpdateError> {
    let bad = |e: serde_json::Error| UpdateError::Check(format!("unexpected answer: {e}"));
    match channel {
        UpdateChannel::Stable => {
            let r: Release = serde_json::from_str(text).map_err(bad)?;
            Ok(found_of(&r).filter(|f| !r.prerelease && f.version.pre.is_empty()))
        }
        UpdateChannel::Prerelease => {
            let list: Vec<Release> = serde_json::from_str(text).map_err(bad)?;
            Ok(list
                .iter()
                .filter_map(found_of)
                .max_by(|a, b| a.version.cmp(&b.version)))
        }
    }
}

/// Reads a small answer, at most `cap` bytes.
pub async fn fetch_capped(
    fetcher: &dyn Fetcher,
    url: &str,
    cap: usize,
) -> Result<Vec<u8>, UpdateError> {
    let mut body = fetcher.fetch(url, 0).await?.body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next_chunk().await? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > cap {
            return Err(UpdateError::Check(format!(
                "{url} answered with more than {cap} bytes"
            )));
        }
    }
    Ok(bytes)
}

/// Asks GitHub for the newest release on `channel`.
pub async fn latest(
    fetcher: &dyn Fetcher,
    channel: UpdateChannel,
) -> Result<Option<Found>, UpdateError> {
    let url = match channel {
        UpdateChannel::Stable => LATEST_URL,
        UpdateChannel::Prerelease => LIST_URL,
    };
    let bytes = fetch_capped(fetcher, url, MAX_LISTING).await?;
    let text = String::from_utf8(bytes)
        .map_err(|_| UpdateError::Check("the answer is not text".into()))?;
    parse_answer(&text, channel)
}

/// The fetcher of the check: api.github.com only, `timeout` for the whole request.
pub fn api_fetcher(timeout: Duration) -> Result<HttpsFetcher, UpdateError> {
    Ok(HttpsFetcher::restricted(API_HOSTS, timeout)?)
}

/// The fetcher of release downloads: GitHub's download hosts only.
pub fn download_fetcher() -> Result<HttpsFetcher, UpdateError> {
    Ok(HttpsFetcher::restricted(
        DOWNLOAD_HOSTS,
        Duration::from_secs(30 * 60),
    )?)
}

/// What turns checks off, if anything: `KRAKEN_NO_UPDATE_CHECK`, `CI` or the setting.
pub fn disabled_by(env: &dyn Fn(&str) -> Option<OsString>, setting: bool) -> Option<String> {
    let set = |k: &str| {
        env(k).is_some_and(|v| {
            let v = v.to_string_lossy();
            !v.is_empty() && !matches!(v.as_ref(), "0" | "false" | "no" | "off")
        })
    };
    if set("KRAKEN_NO_UPDATE_CHECK") {
        Some("KRAKEN_NO_UPDATE_CHECK".into())
    } else if set("CI") {
        Some("CI".into())
    } else if !setting {
        Some("updates.check = false".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_strict_tags_count() {
        assert_eq!(parse_tag("v0.4.0"), Some(Version::new(0, 4, 0)));
        assert!(parse_tag("v1.2.3-rc.1").is_some());
        assert!(parse_tag("v1.2.3-rc1").is_some());
        for bad in [
            "0.4.0",
            "v0.4",
            "v0.4.0.1",
            "v0.4.0+build",
            "v0.4.0-",
            "v0.4.0-rc_1",
            "v01.2.3",
            "v1.2.3-rc/../x",
            "vX.Y.Z",
            "v1.2.3 ",
        ] {
            assert_eq!(parse_tag(bad), None, "{bad}");
        }
    }

    #[test]
    fn newer_means_strictly_newer_by_semver() {
        let v = |s: &str| Version::parse(s).expect("version");
        assert!(is_newer(&v("0.4.0"), &v("0.3.0")));
        assert!(is_newer(&v("0.10.0"), &v("0.9.9")));
        assert!(is_newer(&v("0.4.0"), &v("0.4.0-rc.1")));
        assert!(!is_newer(&v("0.4.0-rc.1"), &v("0.4.0")));
        assert!(!is_newer(&v("0.3.0"), &v("0.3.0")));
        assert!(!is_newer(&v("0.2.9"), &v("0.3.0")));
    }

    #[test]
    fn the_answers_are_read_per_channel() {
        let latest = r#"{"tag_name":"v0.3.0","html_url":"https://github.com/Adam-AtlasSoftware/kraken/releases/tag/v0.3.0","draft":false,"prerelease":false,"assets":[{"name":"SHA256SUMS"}]}"#;
        let f = parse_answer(latest, UpdateChannel::Stable)
            .expect("parse")
            .expect("found");
        assert_eq!(f.version, Version::new(0, 3, 0));
        assert!(!f.signed);
        let list = r#"[
          {"tag_name":"v0.5.0-rc.1","html_url":"https://evil.example/x","prerelease":true,"assets":[{"name":"SHA256SUMS.minisig"}]},
          {"tag_name":"v0.6.0","draft":true},
          {"tag_name":"nightly","prerelease":true},
          {"tag_name":"v0.4.0","assets":[]}
        ]"#;
        let f = parse_answer(list, UpdateChannel::Prerelease)
            .expect("parse")
            .expect("found");
        assert_eq!(f.version.to_string(), "0.5.0-rc.1");
        assert!(f.signed);
        assert!(f.notes_url.starts_with("https://github.com/"));
        // A prerelease on the latest endpoint does not count for stable.
        let pre = r#"{"tag_name":"v0.5.0-rc.1","prerelease":true}"#;
        assert_eq!(
            parse_answer(pre, UpdateChannel::Stable).expect("parse"),
            None
        );
        assert!(parse_answer("[]", UpdateChannel::Stable).is_err());
    }

    #[test]
    fn checks_turn_off_by_variable_ci_or_setting() {
        let none = |_: &str| None;
        assert_eq!(disabled_by(&none, true), None);
        assert_eq!(
            disabled_by(&none, false).as_deref(),
            Some("updates.check = false")
        );
        let ci = |k: &str| (k == "CI").then(|| OsString::from("true"));
        assert_eq!(disabled_by(&ci, true).as_deref(), Some("CI"));
        let off = |k: &str| (k == "KRAKEN_NO_UPDATE_CHECK").then(|| OsString::from("1"));
        assert_eq!(
            disabled_by(&off, true).as_deref(),
            Some("KRAKEN_NO_UPDATE_CHECK")
        );
        let zero = |k: &str| (k == "KRAKEN_NO_UPDATE_CHECK").then(|| OsString::from("0"));
        assert_eq!(disabled_by(&zero, true), None);
    }
}
