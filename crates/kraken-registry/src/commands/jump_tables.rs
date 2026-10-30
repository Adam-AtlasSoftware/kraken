//! `jump_tables`: the computed jumps of the program and where each can go.

use async_trait::async_trait;
use kraken_engine::{Cap, unsupported};
use kraken_proto::{Hex64, JumpTable, Page, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

use super::page_request;

/// Most targets of one jump table `jump_tables` lists.
pub const MAX_TABLE_TARGETS: usize = 256;

/// Arguments of `jump_tables`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JumpTablesArgs {
    /// Cursor from the previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size (default 100, at most 200).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One computed jump with the addresses it can reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JumpTableView {
    /// Entry of the function holding the jump.
    pub function: Hex64,
    /// Address of the computed jump instruction.
    pub jump: Hex64,
    /// Number of distinct targets.
    pub target_count: u32,
    /// Targets, ascending, at most 256.
    pub targets: Vec<Hex64>,
    /// Whether `targets` is cut short of `target_count`.
    pub truncated: bool,
}

impl From<&JumpTable> for JumpTableView {
    fn from(t: &JumpTable) -> Self {
        JumpTableView {
            function: t.function,
            jump: t.jump,
            target_count: u32::try_from(t.targets.len()).unwrap_or(u32::MAX),
            targets: t.targets.iter().take(MAX_TABLE_TARGETS).copied().collect(),
            truncated: t.targets.len() > MAX_TABLE_TARGETS,
        }
    }
}

/// Lists the program's computed jumps and their targets.
pub struct JumpTablesCommand;

#[async_trait]
impl Command for JumpTablesCommand {
    type Args = JumpTablesArgs;
    type Output = Page<JumpTableView>;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "jump_tables",
            "List the computed jumps (switch tables) with the addresses each can reach",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Every computed jump the engine resolved, ordered by jump address: the function it \
             is in, the jump instruction and its targets. These are the edges the CFG draws as \
             `switch`; use it to see how a dispatch loop or a `switch` fans out.\n\
             Example: jump_tables {\"limit\": 20}",
        )
        .details(
            "A table with more than 256 targets lists the first 256 and sets `truncated`; \
             `target_count` is the full count. Engines that cannot resolve computed jumps do \
             not offer the command (`unsupported`).",
        )
        .needs(&[Cap::JumpTables])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: JumpTablesArgs,
    ) -> Result<Page<JumpTableView>, ProtoError> {
        let engine = s.project()?.engine();
        let lister = engine
            .jump_tables()
            .ok_or_else(|| unsupported("jump_tables"))?;
        let page = lister
            .list_jump_tables(
                &page_request(args.cursor, args.limit, s.config().list_page_cap),
                &ctx.cancel,
            )
            .await?;
        Ok(Page {
            items: page.items.iter().map(JumpTableView::from).collect(),
            next_cursor: page.next_cursor,
            total: page.total,
        })
    }
}
