# kraken-acp

KRAKEN's terminal-agent host (0.3, decisions 12, 35, 50, 69). It launches Claude Code, Codex and
Gemini CLI (or any ACP agent) over the Agent Client Protocol, pre-connected to `kraken mcp`, and
reports what they do as `AcpEvent`s for a chat UI. User documentation: `docs/assistant.md` (terminal agents section).

## Research notes (checked 2026-10-16)

### The Rust crate

- `agent-client-protocol` **3.4.0** (Apache-2.0, Zed's `rust-sdk`), pinned `=3.4.0`; it pins
  `agent-client-protocol-schema =1.12.0`. The newest crates.io listing also has
  `agent-client-protocol-rmcp`, `-tokio` and `-derive`; KRAKEN needs only the core crate.
- It is a futures-based builder, not a trait to implement. Client side:
  `Client.builder().name(..).on_receive_notification(..).on_receive_request(..).connect_with(transport, main)`.
  `transport` is anything implementing `ConnectTo`; `ByteStreams::new(AsyncWrite, AsyncRead)` over
  the child's stdin/stdout (via `tokio_util::compat`) is what we use, so KRAKEN keeps control of
  how the process is spawned. The crate's own `AcpAgent` (feature `process`) spawns by itself and
  could not set a scrubbed environment, a process group or PDEATHSIG.
- Inside `main` you get a cloneable `ConnectionTo<Agent>`: `send_request(req).block_task().await`,
  `send_notification(..)`, `spawn(..)`. The connection ends when `main` returns, so the host keeps
  `main` parked on a shutdown channel and hands a clone of the connection to `AcpHost`.
- Callbacks run inside the dispatch loop and block it. The permission callback therefore does
  `cx.spawn(..)` and answers from the spawned task, so a person can take minutes without stalling
  `session/update` traffic.
- **Requests with no registered handler are not answered** (the agent would wait forever). KRAKEN
  registers explicit handlers for `fs/read_text_file`, `fs/write_text_file` and `terminal/create`
  that reply with a JSON-RPC error saying KRAKEN does not offer them.
- Schema types are `#[non_exhaustive]` with `::new(..)` constructors and builder methods
  (`InitializeRequest::new(ProtocolVersion::V1).client_capabilities(..)`,
  `NewSessionRequest::new(cwd).mcp_servers(vec![McpServer::Stdio(McpServerStdio::new(name, cmd).args(..).env(..))])`).
  Stable types are under `agent_client_protocol::schema::v1`.

### The protocol (v1) subset KRAKEN uses

- `initialize` (client sends `protocolVersion: 1`, `clientCapabilities`, `clientInfo`; agent answers
  `agentCapabilities`, `authMethods`, `agentInfo`). KRAKEN advertises **no** `fs.readTextFile`,
  `fs.writeTextFile` or `terminal`; the agent keeps using its own tools for files and shells
  (decision 50: warn only).
- `session/new { cwd, mcpServers: [{ name, command, args, env }] }` -> `{ sessionId }`. KRAKEN sends
  one stdio entry named `kraken` running `kraken mcp --project <dir>` (or `kraken mcp --daemon
  [--project <dir>]`). Authentication is not performed by KRAKEN: an agent that needs a login
  answers `session/new` with an error (`-32000 Authentication required`, or a message such as
  "API key is missing"); KRAKEN reports "sign in with the agent's own command line".
- `session/prompt { sessionId, prompt: [ContentBlock] }` -> `{ stopReason }` (`end_turn`,
  `max_tokens`, `max_turn_requests`, `refusal`, `cancelled`).
- `session/update` notifications: `agent_message_chunk`, `agent_thought_chunk`,
  `user_message_chunk` (replay only), `tool_call`, `tool_call_update`, `plan`,
  `available_commands_update`, `current_mode_update`, `config_option_update`, `session_info_update`,
  `usage_update` and newer ones; unknown kinds become `AcpEvent::Info`.
- `session/request_permission { sessionId, toolCall, options[] }` (agent -> client request) ->
  `{ outcome: { outcome: "selected", optionId } | { outcome: "cancelled" } }`. Option kinds:
  `allow_once`, `allow_always`, `reject_once`, `reject_always`.
- `session/cancel` (client -> agent notification). The client must answer pending permission
  requests with `cancelled`; `AcpHost::cancel` does that. The turn then ends with
  `stopReason: cancelled`.
- Transport: newline-delimited JSON-RPC 2.0 on the agent's stdin/stdout. stderr is free for logs
  (KRAKEN keeps the last 40 lines for error messages).

### Adapters (npm, exact versions pinned here)

| Agent | Package | Pinned | Needs | Run as |
| --- | --- | --- | --- | --- |
| Claude Code | `@agentclientprotocol/claude-agent-acp` (successor of `@zed-industries/claude-code-acp`) | 0.89.1 | Node >= 22 | `node node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js` (bin `claude-agent-acp`) |
| Codex | `@agentclientprotocol/codex-acp` (replaces deprecated `@zed-industries/codex-acp`) | 2.2.2 | Node (works on 20+) | `node node_modules/@agentclientprotocol/codex-acp/dist/index.js` (bin `codex-acp`) |
| Gemini CLI | `@google/gemini-cli` (native ACP) | 0.62.0 | Node >= 20 | `gemini --acp` (older: `--experimental-acp`, deprecated) |

- 0.92.0 of the Claude adapter was published the day this was written, so the pin is 0.89.1
  (six days old); revisit when bumping.
- None of the three packages (nor the SDKs they pull in: `@anthropic-ai/claude-agent-sdk`,
  `@openai/codex`) declares an install script. The platform-specific native helpers arrive as
  `optionalDependencies` (`@anthropic-ai/claude-agent-sdk-linux-x64`, `@openai/codex-linux-x64`,
  ...), which npm selects by `os`/`cpu`, so `npm ci --ignore-scripts` is enough.
- Gemini CLI has two optional native add-ons with install scripts (`node-pty`, `@github/keytar`).
  With `--ignore-scripts` they stay unbuilt; the CLI has pre-built `@lydell/node-pty-*` packages and
  falls back to file based credential storage, and ACP mode does not need either.
- Lockfiles: `adapters/<id>/package.json` + `package-lock.json` are generated with
  `npm install --package-lock-only --ignore-scripts` and embedded with `include_str!`. Every entry
  has a `resolved` URL on `registry.npmjs.org` and a SHA-512 `integrity`; a unit test checks this.
  To bump a version: edit `package.json`, regenerate the lockfile in that directory, update the
  `AdapterSpec` in `src/profile.rs`, run the tests.
- Authentication is the agent's business: `claude` (login or `ANTHROPIC_API_KEY`), `codex login`,
  `gemini` (Google login or `GEMINI_API_KEY`). KRAKEN passes none of its own settings, and API key
  variables are not forwarded unless the person lists them under `[env_allow]` in `agents.toml`.

### Node.js

Pinned **v24.21.0** ("Krypton" LTS), hashes copied from `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt`
(the PGP signature of that file is not checked; the hashes are compiled in, so a tampered download
fails, and a tampered nodejs.org page would not matter):

| Platform | File | SHA-256 |
| --- | --- | --- |
| linux-x64 | `node-v24.21.0-linux-x64.tar.gz` | `6e1db87e...88dc5ff` |
| darwin-arm64 | `node-v24.21.0-darwin-arm64.tar.gz` | `bed7eea5...f6057` |
| win-x64 | `node-v24.21.0-win-x64.zip` | `158f7685...de9e541` |

Full hashes are in `src/node.rs`. Downloads reuse `kraken_host::provision` (HTTPS only, resume,
hash before extraction, zip-slip/symlink checks, mtimes kept). The linux-x64 download was verified
against the real server (`cargo test -p kraken-acp --lib real_download -- --ignored`). Other
platforms use a Node.js already on `PATH`; riscv64 is unsupported (decision 69).

## Layout

- `host.rs` `AcpHost`, `AcpEvent`, permission handling, `McpServerConfig`.
- `process.rs` spawner thread: PDEATHSIG, own process group, SIGTERM then SIGKILL, kill on drop.
- `profile.rs` `AgentProfile`, built-in profiles, environment allowlist.
- `agents.rs` catalogue (`agents.toml`), `Resolver`, `AgentStatus` (`detected`/`available`/`missing`/`unsupported`).
- `node.rs` `NodeRuntime::{detect, provision}`; `adapter.rs` `install_adapter`.
- `notice.rs` the one-time warning text and its acknowledgement file.
- `fake_agent.rs` + `src/bin/kraken-fake-acp-agent.rs` a hand-written ACP agent for tests.

## Tests

`cargo test -p kraken-acp`: no network, no real agents. `tests/host.rs` runs `AcpHost` against the
fake agent process (handshake and MCP config, streaming, permission round trips, cancel, fs
declined, environment scrubbing, auth error, crash, timeout, cleanup). Node and adapter tests use
fake `node`/`npm` scripts and local fixture archives (hash mismatch, zip-slip for tar and zip).
