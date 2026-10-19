//! `kraken_help`: search KRAKEN's own documentation and glossary.

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::docs;
use crate::session::Session;

/// Sections returned when `limit` is left out.
pub const DEFAULT_HELP_HITS: u32 = 4;
/// Most sections one call returns.
pub const MAX_HELP_HITS: u32 = 8;

/// Arguments of `kraken_help`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KrakenHelpArgs {
    /// What to look for: a few words ("rewrite program", "local model", "permissions").
    /// Empty lists the pages.
    #[serde(default)]
    pub query: Option<String>,
    /// Most sections to return (default 4, at most 8).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One section of the docs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HelpSection {
    /// Page name, or `glossary`.
    pub page: String,
    /// Section heading.
    pub heading: String,
    /// The start of the section.
    pub text: String,
    /// `kraken://docs/<page>` serves the whole page (MCP resource).
    pub uri: String,
}

/// Result of `kraken_help`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct KrakenHelpOut {
    /// Best sections first.
    pub sections: Vec<HelpSection>,
    /// All pages (for browsing).
    pub pages: Vec<String>,
}

/// Searches the bundled docs.
pub struct KrakenHelp;

#[async_trait]
impl Command for KrakenHelp {
    type Args = KrakenHelpArgs;
    type Output = KrakenHelpOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "kraken_help",
            "Search KRAKEN's own documentation and glossary",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Use it to answer questions about KRAKEN itself (how a feature works, which command \
             or setting to use, what a term means). Returns short sections; the MCP resource \
             `kraken://docs/{page}` has a whole page. Does not read the open project.\n\
             Example: kraken_help {\"query\": \"local models\"}",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: KrakenHelpArgs,
    ) -> Result<KrakenHelpOut, ProtoError> {
        let limit = args
            .limit
            .unwrap_or(DEFAULT_HELP_HITS)
            .clamp(1, MAX_HELP_HITS) as usize;
        let query = args.query.unwrap_or_default();
        if query.len() > 200 {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "query is at most 200 characters",
            ));
        }
        let sections = docs::search(&query, limit)
            .into_iter()
            .map(|h| HelpSection {
                page: h.section.page.clone(),
                heading: h.section.heading.clone(),
                text: docs::excerpt(&h.section.text),
                uri: if h.section.page == "glossary" {
                    format!("kraken://glossary/{}", h.section.heading)
                } else {
                    format!("kraken://docs/{}", h.section.page)
                },
            })
            .collect();
        Ok(KrakenHelpOut {
            sections,
            pages: docs::page_names().into_iter().map(String::from).collect(),
        })
    }
}
