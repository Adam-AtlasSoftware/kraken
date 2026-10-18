# 0011. License and dependency allowlist

Status: Accepted
Date: 2026-10-15

## Context

KRAKEN is open source and public. We must be able to combine it with Ghidra, the MCP and ACP SDKs, and many Rust crates, and keep that clean as the dependency tree grows.

## Decision

KRAKEN is licensed **GPL-3.0-or-later**. Every crate says so in its `Cargo.toml`.

**Allowed dependency licenses:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Zlib, Unicode-3.0, and OFL for fonts. All are compatible with GPL-3.0. Ghidra, `rmcp` and the ACP SDK are Apache-2.0.

**Enforcement.** `cargo-deny` checks licenses in CI. A Gradle license check covers the Java extension.

**Separate components.** Ghidra and the JRE are distributed as separate components. KRAKEN does not link them. The Ghidra NOTICE is shipped. A `THIRD-PARTY-NOTICES` file is generated.

**Compiled-in code.** The native engine (ADR 0014) is the exception: `engine-native-sys` compiles Ghidra's decompiler and Sleigh (Apache-2.0) and the zlib subset Ghidra bundles (zlib License) into the binaries. Their license and notice texts (Ghidra's `LICENSE` and `NOTICE`, the zlib license) are committed in `crates/engine-native-sys/licenses`, refreshed from the pinned source archive by `cargo xtask notices`, reproduced in `THIRD-PARTY-NOTICES.md`, and shipped as `licenses/` in the release archive; tests fail when the copies or the page are stale.

**New components.** An inference backend gets a license review before it joins the default build. CUDA is never bundled.

**Legal use.** KRAKEN is a neutral tool. The README has one line on lawful use, and nothing more.

## Consequences

- Contributors know which dependencies are acceptable.
- Copyleft applies to anyone who builds on KRAKEN code.
- Crates under licenses outside the list (for example LGPL) need an explicit decision first.
- Reference-only projects with other licenses can inform the design, but their code is not copied.

## Alternatives considered

- Apache-2.0 or MIT. Easier for others to embed, but allows closed forks of an analysis tool.
- AGPL-3.0. Network-service copyleft is not needed for a local tool.
- GPL-3.0 only. "Or later" keeps room for future license versions.
