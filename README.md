# KRAKEN

KRAKEN is an AI-assisted reverse engineering workbench built on Ghidra's analysis engine. It
exposes one command registry through a CLI, an MCP server and a GUI, so people and AI agents work
on the same project and see the same changes. The long-term goal is Rust rewrites of binaries,
done function by function and checked against tests.

Status: pre-alpha.

## Build

```sh
cargo build
```

Requires the stable Rust toolchain (pinned in `rust-toolchain.toml`).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Use KRAKEN only on software you are permitted to analyse.
