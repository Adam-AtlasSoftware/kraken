# S2: Ghidra sidecar echo (spike notes)

Date: 2026-10-15. Host: Arch x86_64, kernel 7.2.9 (Landlock ABI 10 reported by the kernel; the
`landlock` crate reports effective ABI V9), system cargo/rustc 1.99, system Gradle 9.8.0.

## Pins and checksums

| Artifact | Version | sha256 |
| --- | --- | --- |
| Ghidra (GitHub release `Ghidra_12.1.4_build`, `ghidra_12.1.4_PUBLIC_20260921.zip`) | 12.1.4 | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Temurin JDK (`OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz`, adoptium/temurin21-binaries `jdk-21.0.12.1+1`) | 21.0.12.1+1 | `ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94` |

The Ghidra hash matches the `digest` the GitHub release API reports; the Temurin hash matches the
Adoptium API `checksum` field. Both are extracted under `~/.cache/kraken-dev/{ghidra,jdk}`.
Rust: `landlock` 0.4.7, `libc` 0.2.190, `serde_json` 1.0.154, `anyhow` 1.0.104.

## What was built

- `java/kraken-ghidra`: extension (Gradle). `src/main/java/kraken/ghidra/KrakenSidecar.java`.
- `xtask ghidra-ext` (`cargo xtask ghidra-ext`, alias in `.cargo/config.toml`; std-only, no deps).
- `spikes/sidecar-echo`: Rust spawner and RPC client (own `[workspace]`).

## Build path: Gradle works offline (chosen)

`support/buildExtension.gradle` from the Ghidra install is applied by the extension's
`build.gradle`; `GHIDRA_INSTALL_DIR` selects the install. It needs no downloads because the
extension depends only on Ghidra's own jars (a `fileTree` over `Ghidra/{Framework,Features,Debug,Processors}`).
`gradle --offline --no-daemon buildExtension` takes about 8 s and produces
`dist/ghidra_12.1.4_PUBLIC_<date>_kraken-ghidra.zip` plus `build/libs/kraken-ghidra.jar`.
Ghidra 12.1.4 declares `application.gradle.min=8.5` and no max, so the system Gradle 9.8.0 is accepted;
it was run with `JAVA_HOME` = Temurin 21 (Gradle 9.8 itself also runs on JDK 21). No Gradle wrapper
is needed in the repo. The javac+jar fallback was not needed. The Ghidra API surface used (12.x):
`ghidra.app.util.importer.ProgramLoader` (not `opinion`; `GhidraProject.importProgram` is deprecated),
`ghidra.GhidraApplicationLayout` (not `ghidra.framework`), `ghidra.framework.HeadlessGhidraApplicationConfiguration`,
`ghidra.base.project.GhidraProject`.

## Headless entry: custom main works (chosen)

`kraken.ghidra.KrakenSidecar.main` calls
`Application.initializeApplication(new GhidraApplicationLayout(), new HeadlessGhidraApplicationConfiguration())`
and is run as a plain `java -cp <all Ghidra jars + kraken-ghidra.jar> -Dghidra.install.dir=...`.
No `launch.sh`, no `GhidraClassLoader`, no extension installation into a user dir was needed;
the extension jar is simply on the classpath (the packaged zip is still produced for the
eventual installed form). `support/analyzeHeadless` / a GhidraScript was not tried: it prints
banners and logs on stdout and has no natural place for a long-lived stdio loop, so the custom
main is the better fit.
Facts that matter:
- Protocol frames use the original fd 1; `System.setOut(System.err)` is done before Ghidra
  initialises, so log4j's console appender (and any stray `println`) goes to stderr. Verified:
  stdout carried only frames. Native code writing directly to fd 1 (the decompiler is a separate
  process with its own pipes, so not an issue so far) would still corrupt framing; T4 may want
  `dup2` of stderr over fd 1 via a tiny JNI-free trick, or a socketpair/inherited fd instead.
- Analysis must be wrapped in `program.startTransaction(...)`: `mgr.initializeOptions();
  mgr.reAnalyzeAll(null); mgr.startAnalysis(monitor)`. `GhidraProject.analyze(program)` alone throws
  `NoTransactionException`.
- Ghidra writes its log to `<user.home>/.config/ghidra/ghidra_12.1.4_PUBLIC/application.log`
  and caches under `java.io.tmpdir/ghidra`. Java ignores `$HOME` for `user.home`, so pass
  `-Duser.home=` and `-Djava.io.tmpdir=` explicitly.
- A "ready" notification (`{"method":"ready","params":{ghidra_version,init_ms}}`) is sent once
  initialised. Framing: 4-byte big-endian length plus UTF-8 JSON-RPC 2.0. `ping` returns
  `{"pong":true}`; `open_binary(path)` returns `{function_count, language, load_ms, analyze_ms}`.
  Gson from Ghidra's own jars is used for JSON, so no extra dependency.
- JVM flags used: `-Xmx2g -XX:+UseSerialGC -Djava.awt.headless=true`.

## Confinement (Rust spike)

- Spawn happens on a dedicated `spawner` thread that stays parked until the sandbox handle is
  dropped (PDEATHSIG is tied to the thread that forked, not the process). `pre_exec` sets
  `PR_SET_PDEATHSIG(SIGKILL)` (with a `getppid()==1` race check), optionally
  `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, then `restrict_self()`. Verified: `kill -9` of the spike
  kills the JVM.
- The Landlock ruleset is built in the parent and only `restrict_self()` runs after fork.
  (The crate's `restrict_self` may allocate; acceptable for a spike, T5 should keep it.)
- Env: `env_clear()` plus `PATH=<jdk>/bin`, `HOME=<tmp>/home`, `JAVA_HOME`, `LANG=C.UTF-8`.
- Result of `restrict_self` is `PartiallyEnforced` (file rules drop dir-only bits), so the
  spike only fails on `NotEnforced`. Do not require `FullyEnforced`: it makes `pre_exec` fail with an
  opaque EINVAL (std reports any non-OS io::Error from `pre_exec` as EINVAL).
- Minimal filesystem set that works (found by removing entries one at a time):
  - read-only: JDK dir, Ghidra install dir, directory holding `kraken-ghidra.jar`, the copied
    binary (file rule), `/usr/lib` (`/lib` and `/lib64` are symlinks to it on Arch, one rule
    covers all), `/dev/random`, `/dev/urandom`.
  - read-write: temp `home` (also holds `tmp/` and `.config/`) and temp `project` dir only.
  - NOT needed: `/proc`, `/dev/null`, `/etc/ld.so.cache`, `/etc`, `/usr/bin`, `/sys`.
  - Skipping Ghidra or `/usr/lib` fails immediately (proves rules are enforced).
- Surprise: without `/dev/random` the JVM's SecureRandom seeding falls back to a thread-timing seed
  generator, adding about 8 s to the first `open_binary` (load 9.7 s instead of 1.8 s). Bisected
  by granting `/dev` read access. `/dev/urandom` alone is not enough.
- Network, both mechanisms verified with `sidecar-echo net-probe --net <mode>` (child under the same
  confinement code tries TCP connect to a local listener and a bind):
  - `landlock` (ABI v4 `AccessNet::{BindTcp,ConnectTcp}` handled with no allow rules, plus ABI v6
    `Scope::{AbstractUnixSocket,Signal}`): connect and bind both `EACCES`. Works on this kernel.
    Does not cover UDP or non-TCP sockets, nor pathname unix sockets outside the FS rules.
  - `unshare` (user+net namespaces): connect `ENETUNREACH`; bind on the namespace's own
    loopback succeeds (harmless, isolated). Works unprivileged here
    (`max_user_namespaces=256156`) but is often disabled on hardened distros/containers.
  - Recommendation: Landlock net as primary (no namespace dependency), add unshare when available
    (`--net both` also works and passes the full run); record in docs that UDP is only covered by unshare.

## Results for /bin/ls (copied into the temp dir)

`function_count = 562` (x86:LE:64:default, ELF, Ghidra 12.1.4 default analyzers), identical
confined and unconfined and for every net mode.

Confined, net=landlock, debug build (final run):
`startup(spawn->ready)=1.62s ping=0.5ms open_binary(total)=22.20s (load=1788ms analyze=20405ms) wall=23.82s`

Other runs (all confined): net=unshare 1.59 s / 21.51 s total (load 1.76 s, analyze 19.7 s);
net=both 1.59 s / 21.34 s; release build, landlock: 1.60 s / 20.68 s (analyze 18.9 s).
Unconfined: 1.59 s / 20.57 s (load 1.8 s, analyze 18.6 s). So confinement costs nothing measurable.
Time is dominated by auto-analysis; `Decompiler Switch Analysis` alone is about 13 s of it, a
candidate to disable for a fast first pass (T4).

## Other findings for later cards

- Ghidra logs "ELF Relocation Failure: R_X86_64_COPY" and "no external libraries configured" for
  `ls`; harmless. Library resolution searches the system paths only if libraries are in the project.
- `--ro/--skip` flags on the spike exist only to explore the minimal path set.
- The spike kills the sidecar after a 600 s watchdog; there is no per-call timeout yet.
- `cargo xtask` alias lives in `.cargo/config.toml` (new; T0 had none).
