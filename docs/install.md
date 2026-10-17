# Install

KRAKEN ships as a few programs: `kraken` (the command line and MCP server), `krakend` (the background daemon) and `kraken-gui`. It needs Ghidra and a JDK at run time, but those are downloaded for you on first run and are not part of the release archive.

Platforms: Linux x86_64 is supported today. macOS (Apple silicon) and Windows (x86_64) archives are published when their builds succeed and are experimental.

## Install from a release

### One command (Linux and macOS)

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
```

The script finds the latest release for your platform, downloads it over HTTPS, checks the archive against the release's `SHA256SUMS` and only then installs. The script can also verify a detached minisign signature (`SHA256SUMS.minisig`) of `SHA256SUMS`. That check is built but dormant: it switches on, and then becomes mandatory, once the project owner generates a release signing key and pastes its public key into `KRAKEN_MINISIGN_PUBKEY` in the script. Until then `SHA256SUMS` only guards against corruption, because it comes from the same place as the archive. It never uses `sudo`: programs go to `~/.local/bin` and the bundled Ghidra extension to `~/.local/share/kraken`. Read it first if you like, it is short: [`scripts/install.sh`](https://github.com/Adam-AtlasSoftware/kraken/blob/main/scripts/install.sh).

Set `KRAKEN_VERSION=v0.1.0` to pick a release, or `KRAKEN_PREFIX=/some/dir` to install somewhere other than `~/.local`. If `~/.local/bin` is not on your `PATH`, the script says so.

### By hand

1. Download `kraken-<version>-<target>.tar.gz` (`.zip` on Windows) and `SHA256SUMS` from the [releases page](https://github.com/Adam-AtlasSoftware/kraken/releases).
2. Check the download:

   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   ```

   On macOS use `shasum -a 256 -c SHA256SUMS --ignore-missing`. Release files also carry GitHub build provenance attestations: `gh attestation verify <archive> --repo Adam-AtlasSoftware/kraken`.
3. Unpack it and copy `bin` and `share` into a prefix on your `PATH`, for example `cp -R bin share ~/.local/`. Keep `share/kraken/kraken-ghidra.jar` next to `bin`: KRAKEN looks for it beside the program and in `../share/kraken`.

The archive also holds this documentation (`docs/`), the license and `THIRD-PARTY-NOTICES.md`.

### macOS and Windows warnings

The first macOS and Windows releases are not signed by a recognised publisher (signing comes later). The macOS binaries are ad-hoc signed so they launch, but Gatekeeper may still block a download. Remove the quarantine flag with `xattr -d com.apple.quarantine ~/.local/bin/kraken*`, or allow the programs in System Settings, Privacy & Security. On Windows, SmartScreen shows "More info", then "Run anyway".

## Install from source

You need Rust (stable), a JDK 21, Ghidra 12.1.4 and Gradle to build the extension. The [Getting started](getting-started.md) page walks through it. In short:

```sh
git clone https://github.com/Adam-AtlasSoftware/kraken
cd kraken
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC JAVA_HOME=/path/to/jdk-21
cargo xtask ghidra-ext
cargo install --path crates/kraken-cli
cargo install --path crates/krakend
cargo install --path crates/kraken-gui
```

Without Gradle you can still run `kraken setup` (below): it compiles the extension with the JDK it downloads.

## First run

```sh
kraken setup
```

`kraken setup` downloads the pinned Ghidra and Temurin JDK 21 into your user data directory (`~/.local/share/kraken/runtime`), checks them against SHA-256 hashes compiled into the program, and installs the Ghidra extension: the bundled `kraken-ghidra.jar` from a release, or one compiled with the downloaded JDK otherwise. It needs network access once. Interrupted downloads resume, and running it again does nothing if everything is in place (`--force` redoes it). Nothing needs root.

Then try it:

```sh
kraken --help
kraken-gui
```

Ghidra (Apache-2.0) and the Temurin JDK (GPL-2.0 with the Classpath Exception) come from their publishers and are not redistributed by KRAKEN. Their licenses come with the downloads. See `THIRD-PARTY-NOTICES.md` for everything that is part of the release.

## Uninstall

1. Stop the daemon: `kraken daemon stop`.
2. Remove the programs: `rm ~/.local/bin/kraken ~/.local/bin/krakend ~/.local/bin/kraken-gui` and `rm ~/.local/share/kraken/kraken-ghidra.jar` (or the whole `~/.local/share/kraken/` directory; that also removes the downloaded Ghidra and JDK, a few GiB).
3. Optionally remove your settings in `~/.config/kraken/`. Your analysis projects live where you created them (by default under your projects directory) and are not touched.

If you installed with `cargo install`, use `cargo uninstall kraken-cli krakend kraken-gui` instead of step 2's `rm` of the programs.
