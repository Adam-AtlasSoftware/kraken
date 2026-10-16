# 0007. Sidecar confinement

Status: Accepted
Date: 2026-10-15

## Context

The Ghidra sidecar parses untrusted binaries with a large amount of third-party code. A parser bug should not give an attacker the user's files, API keys or network.

## Decision

From release 0.1a on Linux, the sidecar runs confined.

**Environment.** The child gets a scrubbed environment. API keys, the daemon token path and inherited file descriptors are not passed on. Secrets live only in the daemon or CLI process.

**Filesystem (Landlock).**

- Read-only: the JDK, Ghidra, the extension jar directory, the binary under analysis, `/usr/lib`, `/dev/random`, `/dev/urandom`.
- Read-write: a temporary home directory and the project directory.

**Network.** Landlock ABI v4 denies TCP. ABI v6 adds scoping. Landlock does not cover UDP, so the sidecar also enters new user and network namespaces (`CLONE_NEWUSER | CLONE_NEWNET`) where available. A partially enforced ruleset is accepted. A ruleset that is not enforced at all is an error. This is checked before exec, not inside `pre_exec`.

**Channel.** The protocol uses a socketpair. One end is the child's stdin (fd 0), and it carries both directions. The Java side writes frames to that descriptor directly. Native code that writes to stdout cannot corrupt the framing. No `/proc` access is needed. Stdout and stderr both go to the log. Frames are a 4-byte big-endian length followed by UTF-8 JSON-RPC 2.0. Ghidra logging goes to stderr.

**Launch.** Plain `java -cp` with the Ghidra jars and the extension jar. The Ghidra install directory is set explicitly. `user.home` and the temp directory point to a throwaway location, so the sidecar uses an isolated Ghidra user directory. The spawner thread stays parked for the child's whole life, because Linux ties parent-death signals to the spawning thread.

**Other platforms.** macOS will use `sandbox-exec`. Windows will use AppContainer. They come with those platforms.

## Consequences

- A compromised parser has little to reach.
- Full confinement needs a recent Linux kernel. Older kernels get partial enforcement or a clear error.
- Some Ghidra features that want network or wide file access will not work in the sidecar.
- macOS and Windows have no confinement until their work lands.

## Alternatives considered

- No confinement. Simple, but a poor default for malware analysis.
- Containers. Heavy, and not available on every platform.
- seccomp filters alone. Hard to maintain for a JVM.
- stdio pipes for the protocol. Native code writing to stdout can break the framing.
