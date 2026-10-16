# Introduction

KRAKEN is an open-source reverse-engineering workbench written in Rust. It uses Ghidra as its analysis engine.

You can drive it from a command line, from an MCP client such as a coding agent, and later from a desktop GUI. All of them use the same set of commands.

KRAKEN keeps your edits (names, types, comments) in its own log. Ghidra's project is a cache that can be rebuilt from that log.

KRAKEN is pre-alpha. The [design decisions](design/README.md) explain how it is meant to work.
