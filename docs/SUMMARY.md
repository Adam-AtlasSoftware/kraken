# Summary

[Introduction](introduction.md)

# User guide

- [Tutorial: your first reverse-engineering session](tutorial.md)
- [Install](install.md)
- [Getting started](getting-started.md)
- [The GUI, menu by menu](gui.md)
- [Concepts](concepts.md)
- [Rewrite a program in Rust](rewrite.md)
- [Connecting AI agents (MCP)](mcp.md)
- [The built-in assistant (AI models and terminal agents)](assistant.md)
- [Running a model on this computer](local-models.md)
- [.NET assemblies](dotnet.md)
- [The native engine](native-engine.md)
- [Performance](performance.md)
- [Scripting with the CLI](cli.md)
- [Scripting with Python](python.md)
- [Security](security.md)

# Reference

- [Command reference](reference/commands.md)

# Design

- [Design decisions](design/README.md)
  - [0001. Ghidra sidecar now, native engine later](design/0001-ghidra-sidecar-now-native-engine-later.md)
  - [0002. The edit log is the source of truth; the Ghidra project is a cache](design/0002-edit-log-is-source-of-truth.md)
  - [0003. One command registry](design/0003-one-command-registry.md)
  - [0004. Process model](design/0004-process-model.md)
  - [0005. Agent safety](design/0005-agent-safety.md)
  - [0006. Undo and concurrency](design/0006-undo-and-concurrency.md)
  - [0007. Sidecar confinement](design/0007-sidecar-confinement.md)
  - [0008. AI integration paths and inference backends](design/0008-ai-integration-and-inference.md)
  - [0009. Platforms and distribution](design/0009-platforms-and-distribution.md)
  - [0010. GUI framework](design/0010-gui-framework.md)
  - [0011. License and dependency allowlist](design/0011-license-and-dependencies.md)
  - [0012. Milestones](design/0012-milestones.md)
  - [0013. The rewrite pipeline](design/0013-rewrite-pipeline.md)
  - [0014. The native engine](design/0014-native-engine.md)
