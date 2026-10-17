//! KRAKEN's terminal-agent host (0.3).
//!
//! KRAKEN launches terminal coding agents (Claude Code, Codex, Gemini CLI, or any ACP agent listed
//! in `agents.toml`) over the Agent Client Protocol, pre-connected to KRAKEN's own MCP server, and
//! reports what they do as [`AcpEvent`]s for a chat UI.
//!
//! - [`AcpHost`]: spawn the agent, speak ACP as the client, open a session whose `mcpServers`
//!   points at `kraken mcp`, stream updates, answer permission requests, cancel, shut down.
//! - [`AgentProfile`] / [`Resolver`]: how each agent is started and whether it can run here.
//! - [`NodeRuntime`] / [`install_adapter`]: detect Node.js or download a pinned one, install the
//!   npm adapters from a pinned lockfile with `--ignore-scripts`.
//! - [`notice`]: the one-time "agents work outside KRAKEN's safety net" warning (decision 50).
//!
//! See `crates/kraken-acp/README.md` for the protocol research and `docs/assistant.md` for users.

pub mod adapter;
pub mod agents;
pub mod confine;
pub mod fake_agent;
pub mod host;
pub mod node;
pub mod notice;
pub mod paths;
pub mod platform;
pub mod process;
pub mod profile;

pub use adapter::{AdapterError, install_adapter};
pub use agents::{
    AGENTS_FILE, AgentReport, AgentStatus, AgentsFileError, LaunchSpec, Resolver, load_catalogue,
    report,
};
pub use host::{
    AcpError, AcpEvent, AcpHost, AgentInfo, AllowAll, DenyAll, HostConfig, MCP_SERVER_NAME,
    McpServerConfig, PermissionDecision, PermissionHandler, PermissionOptionInfo, PermissionPolicy,
    PermissionRequest, PlanStep, ToolCallChange, ToolCallInfo, TurnEnd,
};
pub use node::{
    MIN_NODE_MAJOR, NODE_VERSION, NodeDownload, NodeError, NodeOrigin, NodeRuntime, NodeVersion,
    node_download_for,
};
pub use notice::{NoticeStore, WARNING_TEXT, WARNING_TITLE, WARNING_VERSION};
pub use paths::{AgentPaths, config_dir_with};
pub use platform::{Platform, PlatformReport};
pub use profile::{AdapterSpec, AgentProfile, AgentSetup, builtin_profile, builtin_profiles};
