# 0008. AI integration paths and inference backends

Status: Accepted
Date: 2026-10-15

## Context

Users want AI help in different ways. Some already use a coding agent and want it to drive KRAKEN. Some want a chat built into the tool. Some need to run models locally for privacy or cost. Local hardware varies a lot. Some machines have little VRAM and plenty of system RAM.

## Decision

**Four integration paths.**

1. **MCP server** (`kraken mcp`, from the `rmcp` crate). Any MCP client can use KRAKEN. Ships in 0.1.
2. **Built-in agent.** Talks to OpenAI-compatible HTTP servers (Ollama, LM Studio, llama-server, vLLM) and to the Anthropic, OpenAI and Gemini APIs, through the `genai` crate. Ships in 0.2, with the OpenAI-compatible path first.
3. **Terminal agents over ACP** (Agent Client Protocol): Claude Code, Codex, Gemini CLI and others. Their adapters need Node.js. KRAKEN detects Node and can download a pinned copy on tier 1 platforms. Adapters are installed with npm using a pinned lockfile and integrity hashes. An agent that cannot run on a platform is shown disabled with the reason. See ADR 0005 for the safety position.
4. **Supervised or in-process local inference.** Ships in 0.4.

**Inference backends.** Every backend implements an `InferenceBackend` trait and runs as a supervised child process: start, health check, restart, memory budget. It speaks a local streaming API. llama.cpp can also link in-process, as an optional variant of the same trait. The first version supervises hash-pinned upstream `llama-server` release binaries. In-process llama.cpp is a source-build cargo feature only.

Each backend publishes a capability descriptor (OS, architecture, GPU API, RAM needs) and a settings schema. The GUI draws offload options from the schema without knowing the backend. Later backends can target large models on machines with little VRAM and a lot of RAM, by offloading layers or mixture-of-experts weights to CPU memory.

The built-in agent and all backends share one provider abstraction. The agent loop does not know which one it uses.

A loaded model's lifetime is independent of the daemon's idle timer. The UI always shows which provider a request goes to.

**Licensing.** Any inference backend is license-reviewed before it joins the default build. CUDA is never bundled.

## Consequences

- Users choose how they use AI.
- Supervised processes isolate crashes and memory use from the daemon.
- More moving parts to install and update.
- Local inference arrives after the GUI and agent, because the HTTP path already covers local models.

## Alternatives considered

- Build on an existing Rust agent framework. None suitable exists to embed.
- Use an existing Node RE orchestrator as a dependency. It has no embedding API and needs Node.
- Link only llama.cpp in-process. A crash or leak takes down the daemon, and it ties us to one engine.
- Only MCP. Gives no built-in experience for beginners.
