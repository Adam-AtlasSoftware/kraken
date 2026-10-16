//! KRAKEN MCP server.
//!
//! One tool per registry command (name, `summary + doc` description, the args JSON Schema as
//! `inputSchema`, the output schema as `outputSchema`, and annotations: `readOnlyHint` for safe
//! commands, `destructiveHint` for dangerous ones). Analysis and rebuild are jobs: they return a
//! job id, and `job_status` / `job_await` / `job_cancel` are ordinary tools; a `job_await` call
//! that carries a progress token streams MCP progress notifications while it waits.
//!
//! - Author: an agent whose id is the client's `clientInfo.name`; one run id per connection,
//!   logged when the client initialises.
//! - Results: JSON text content plus `structuredContent`; failures are `isError` results whose
//!   text is the `ProtoError` JSON.
//! - Dangerous commands: approved through MCP elicitation when the client declared the
//!   capability, denied with an explanation otherwise (decision 77).
//! - The session lives in the server. Without a project only `project_create` and `project_open`
//!   can succeed; everything else answers `not_found` until one is opened.

mod approval;
mod server;
mod tools;

pub use approval::McpApprover;
pub use server::{KrakenMcp, McpOptions, ServeError, serve_stdio, serve_transport};
pub use tools::{tool_for, tools_for};
