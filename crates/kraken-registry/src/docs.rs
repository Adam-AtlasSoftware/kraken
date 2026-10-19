//! The bundled documentation: the pages of `docs/`, the glossary, and a search over both.
//!
//! `kraken_help` returns short sections of it; the MCP server serves whole pages as
//! `kraken://docs/{page}`.

use std::sync::OnceLock;

use serde::Deserialize;

/// Page name and text of every bundled page of `docs/`.
const PAGES: &[(&str, &str)] = &[
    ("assistant", include_str!("../../../docs/assistant.md")),
    ("cli", include_str!("../../../docs/cli.md")),
    ("concepts", include_str!("../../../docs/concepts.md")),
    ("dotnet", include_str!("../../../docs/dotnet.md")),
    (
        "getting-started",
        include_str!("../../../docs/getting-started.md"),
    ),
    ("gui", include_str!("../../../docs/gui.md")),
    ("install", include_str!("../../../docs/install.md")),
    (
        "introduction",
        include_str!("../../../docs/introduction.md"),
    ),
    (
        "local-models",
        include_str!("../../../docs/local-models.md"),
    ),
    ("mcp", include_str!("../../../docs/mcp.md")),
    (
        "native-engine",
        include_str!("../../../docs/native-engine.md"),
    ),
    ("performance", include_str!("../../../docs/performance.md")),
    ("python", include_str!("../../../docs/python.md")),
    ("rewrite", include_str!("../../../docs/rewrite.md")),
    ("security", include_str!("../../../docs/security.md")),
    ("tutorial", include_str!("../../../docs/tutorial.md")),
];

const GLOSSARY: &str = include_str!("../../kraken-assist/data/glossary.toml");

/// Longest excerpt of a section a search returns.
pub const MAX_EXCERPT: usize = 700;

/// The names of the bundled pages.
pub fn page_names() -> Vec<&'static str> {
    PAGES.iter().map(|(n, _)| *n).collect()
}

/// The whole text of a bundled page.
pub fn page(name: &str) -> Option<&'static str> {
    let name = name.trim().trim_end_matches(".md");
    PAGES.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

/// One searchable piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Page name, or `glossary`.
    pub page: String,
    /// The heading (the term for glossary entries).
    pub heading: String,
    pub text: String,
}

#[derive(Deserialize)]
struct GlossaryFile {
    entry: Vec<GlossaryEntry>,
}

#[derive(Deserialize)]
struct GlossaryEntry {
    term: String,
    #[serde(default)]
    aliases: Vec<String>,
    short: String,
    #[serde(default)]
    note: Option<String>,
}

/// Splits markdown at its headings. Text before the first heading belongs to the page title.
pub fn split_sections(page: &str, text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    let mut in_code = false;
    let mut cur = Section {
        page: page.to_string(),
        heading: page.to_string(),
        text: String::new(),
    };
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
        }
        let heading = (!in_code && line.starts_with('#'))
            .then(|| line.trim_start_matches('#').trim())
            .filter(|h| !h.is_empty());
        if let Some(h) = heading {
            if !cur.text.trim().is_empty() {
                out.push(cur);
            }
            cur = Section {
                page: page.to_string(),
                heading: h.to_string(),
                text: String::new(),
            };
        } else {
            cur.text.push_str(line);
            cur.text.push('\n');
        }
    }
    if !cur.text.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Every section of the bundled docs and glossary.
pub fn sections() -> &'static [Section] {
    static S: OnceLock<Vec<Section>> = OnceLock::new();
    S.get_or_init(|| {
        let mut all: Vec<Section> = PAGES
            .iter()
            .flat_map(|(n, t)| split_sections(n, t))
            .collect();
        if let Ok(g) = toml::from_str::<GlossaryFile>(GLOSSARY) {
            for e in g.entry {
                let mut text = e.short;
                if let Some(n) = e.note {
                    text.push(' ');
                    text.push_str(&n);
                }
                if !e.aliases.is_empty() {
                    text.push_str(&format!("\n(also: {})", e.aliases.join(", ")));
                }
                all.push(Section {
                    page: "glossary".into(),
                    heading: e.term,
                    text,
                });
            }
        }
        all
    })
}

/// A search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub section: &'static Section,
    pub score: u32,
}

/// Best sections for `query` (words; a heading hit counts more than a body hit), best first.
pub fn search(query: &str, limit: usize) -> Vec<Hit> {
    let words: Vec<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.len() >= 2)
        .map(str::to_string)
        .collect();
    if words.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<Hit> = sections()
        .iter()
        .filter_map(|s| {
            let head = s.heading.to_lowercase();
            let body = s.text.to_lowercase();
            let mut score = 0u32;
            for w in &words {
                if head.contains(w.as_str()) {
                    score += 6;
                }
                score += (body.matches(w.as_str()).count() as u32).min(5);
            }
            (score > 0).then_some(Hit { section: s, score })
        })
        .collect();
    hits.sort_by_key(|h| std::cmp::Reverse(h.score));
    hits.truncate(limit);
    hits
}

/// `text` cut to [`MAX_EXCERPT`] characters at a line end where possible.
pub fn excerpt(text: &str) -> String {
    let t = text.trim();
    if t.chars().count() <= MAX_EXCERPT {
        return t.to_string();
    }
    let cut: String = t.chars().take(MAX_EXCERPT).collect();
    let cut = cut.rsplit_once('\n').map_or(cut.as_str(), |(a, _)| a);
    format!("{}...", cut.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_bundled_and_split() {
        assert!(page("assistant").is_some_and(|t| t.contains("assistant")));
        assert!(page("gui.md").is_some());
        assert!(sections().len() > 100);
    }

    #[test]
    fn a_heading_hit_beats_a_passing_mention() {
        let hits = search("local models", 5);
        assert!(!hits.is_empty());
        assert!(
            hits[0].section.page == "local-models"
                || hits[0].section.heading.to_lowercase().contains("local"),
            "{:?}",
            hits[0].section
        );
    }

    #[test]
    fn the_glossary_is_searchable() {
        let hits = search("decompiler", 10);
        assert!(hits.iter().any(|h| h.section.page == "glossary"));
    }

    #[test]
    fn nothing_matches_nonsense() {
        assert!(search("zzqxjv", 5).is_empty());
        assert!(search("  ", 5).is_empty());
    }
}
