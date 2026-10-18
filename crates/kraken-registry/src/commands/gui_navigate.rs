//! `gui_navigate`: an agent asks the person's GUI to show an address.
//!
//! The command itself only checks the request. The daemon turns a successful call into a
//! `gui_navigate` event that every connected GUI of the project receives.

use async_trait::async_trait;
use kraken_proto::{Hex64, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

/// A GUI tab an agent may ask to focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuiTabName {
    /// The function in readable C-like code (default).
    Decompiler,
    /// Disassembly.
    Listing,
    /// Control-flow graph.
    Graph,
    /// Raw bytes.
    Hex,
    /// References to the address.
    Xrefs,
    /// The function list.
    Functions,
}

/// Arguments of `gui_navigate`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuiNavigateArgs {
    /// Address to show, as `0x...`.
    pub address: Hex64,
    /// Tab to focus; the Decompiler when left out.
    #[serde(default)]
    pub tab: Option<GuiTabName>,
}

/// Result of `gui_navigate`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuiNavigateOut {
    /// The address asked for.
    pub address: Hex64,
    /// The tab asked for.
    pub tab: GuiTabName,
    /// Always true: the request was sent. Nothing happens when no GUI has the project open.
    pub requested: bool,
}

/// Asks every GUI that has the project open to show an address.
pub struct GuiNavigate;

#[async_trait]
impl Command for GuiNavigate {
    type Args = GuiNavigateArgs;
    type Output = GuiNavigateOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "gui_navigate",
            "Show an address in the person's GUI",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Makes every GUI that has this project open jump to an address and focus a tab \
             (default: the Decompiler). Use it to point the person at what you found. It changes \
             nothing in the project and does nothing when no GUI is open.\n\
             Example: gui_navigate {\"address\": \"0x401136\", \"tab\": \"decompiler\"}",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: GuiNavigateArgs,
    ) -> Result<GuiNavigateOut, ProtoError> {
        Ok(GuiNavigateOut {
            address: args.address,
            tab: args.tab.unwrap_or(GuiTabName::Decompiler),
            requested: true,
        })
    }
}
