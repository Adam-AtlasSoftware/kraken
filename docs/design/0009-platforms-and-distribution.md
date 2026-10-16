# 0009. Platforms and distribution

Status: Accepted
Date: 2026-10-15

## Context

KRAKEN needs Ghidra and a JRE at run time. Both have native parts that differ per OS and CPU. Each extra platform needs its own build, testing and signing work. A small team cannot support all of them with real Ghidra in CI.

## Decision

**Tier 1 only for 1.0:** Linux x86_64, macOS arm64, Windows x86_64. Real-Ghidra tests run on tier 1. Linux arm64, Windows arm64 and Linux riscv64 return with the JVM-free native engine (ADR 0001). CI may still build headless Rust binaries for them. They are unsupported.

**Order of arrival.** Release 0.1 is Linux x86_64 only. Release 0.2 ships the GUI on Linux first. macOS arm64 and Windows x86_64 follow as 0.2.x releases.

**Auto-download.** On first run KRAKEN downloads a pinned Ghidra and a trimmed JRE (built with `jlink`). Download checksums are compiled into the binary, and the hashes live in the repository. An existing Ghidra install is accepted only if its version is on a tested list. Otherwise KRAKEN fails with a clear message. An offline bundle is also published.

**Version pins.** The auto-downloaded Ghidra is one exact version. Projects stay on the Ghidra they were built with (ADR 0002).

**Signing timeline.**

- 0.2.x macOS and Windows builds are unsigned. The docs explain how to override the OS warnings. Releases ship checksums. CI ad-hoc signs Mach-O files so they launch.
- From 0.3, macOS builds use an Apple Developer ID and notarization in CI. Windows builds use SignPath Foundation.

**Build separation.** The Rust workspace builds and tests offline, without a JDK, using `FakeEngine`. The Java extension is built by a separate job and published as a hash-pinned artifact. One cached real-Ghidra job per pull request runs on Linux x86_64.

## Consequences

- A clear support promise for 1.0.
- Some users on arm64 or riscv64 must wait for the native engine.
- Early macOS and Windows users see OS warnings.
- Auto-download needs network at first run. The offline bundle covers air-gapped use.

## Alternatives considered

- Support every platform in 1.0. Not testable with real Ghidra at our size.
- Build Ghidra native overlays for tier 2 and 3 platforms in our CI. Costly to keep working across Ghidra versions. Dropped for 1.0.
- Require users to install Ghidra and Java themselves. Worse first-run experience.
- Bundle Ghidra inside the KRAKEN binary. Mixes licenses and bloats downloads. Ghidra and the JRE ship as separate components.
