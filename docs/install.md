# Install

KRAKEN ships as a few programs: `kraken` (the command line and MCP server), `krakend` (the background daemon) and `kraken-gui`. It has two analysis engines:

- **Native** needs no Java and no Ghidra: the decompiler is a library linked into KRAKEN. It opens Linux, Windows and macOS programs and libraries of every kind (see [Supported files](#supported-files)). The Linux release (archive, AppImage and AUR package) carries it ready to use, with Ghidra's processor specifications compiled for it; new projects use it whenever it can open the file.
- **Ghidra** opens every format and reads debug-info types. It needs Ghidra and a JDK 25 at run time, which `kraken setup` downloads on first run; they are not part of the release archive.

The [native engine page](native-engine.md#native-or-ghidra) compares them.

## Supported files

| File | Example | Native engine | Ghidra engine |
|---|---|---|---|
| Linux program (ELF, static or dynamic, PIE or not) | `/usr/bin/ls` | x86-64, 32-bit x86, ARM (A32 and Thumb-2), AArch64, RISC-V 64, RISC-V 32, MIPS (32-bit, either byte order), PowerPC (32-bit) | yes |
| Linux shared library (ELF) | `libkr.so` | x86-64, 32-bit x86, ARM, AArch64, RISC-V 64, MIPS, PowerPC | yes |
| Linux object file (ELF relocatable) | `kr.o` | x86-64, 32-bit x86, ARM, AArch64, RISC-V 64, RISC-V 32 | yes |
| Linux static library (`ar` archive of objects) | `libkr.a` | x86-64, 32-bit x86, ARM, AArch64, RISC-V: all members in one project | no |
| Windows program or DLL (PE) | `app.exe`, `kr.dll` | x86, x86-64 | yes |
| Windows object file (COFF) | `kr.obj` | x86, x86-64 | yes |
| Windows static library (COFF archive) | `kr.lib`, mingw `libkr.a` | x86, x86-64: all members in one project | no |
| Windows import library | `kernel32.lib`, `libkr.dll.a` | the list of imported symbols and their DLL (no code) | no |
| macOS program or library (Mach-O) | `app`, `libkr.dylib`, plug-ins | x86-64, arm64 (Apple silicon) | yes |
| macOS universal (fat) binary | `app` with two architectures | x86-64, arm64: KRAKEN asks which one | no |
| .NET assembly (exe or dll) | `app.dll` | goes to the .NET engine | goes to the .NET engine |

`kraken binary-probe --path <file>` (and the import dialog in the GUI) says what a file is in
plain words, lists the members of a library and the architectures of a universal binary, and
names the engine `auto` would pick. Libraries (archives) and universal binaries open with the
native engine only; `kraken project-create --slice arm64` picks the architecture, and the GUI asks
when there is more than one it can open.

Platforms: Linux x86_64 is supported today. macOS (Apple silicon) and Windows (x86_64) archives are published when their builds succeed and are experimental.

## Install from a release

### One command (Linux and macOS)

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
```

The script finds the latest release for your platform, downloads it over HTTPS, checks the minisign signature of the release's `SHA256SUMS` against the release key embedded in the script, checks the archive against `SHA256SUMS` and only then installs. It uses the `minisign` tool when you have it and OpenSSL 3 otherwise, which most Linux systems already have (on macOS, `brew install minisign`); without a valid signature nothing is installed. Releases up to v0.3.0 were made before signing began: for those the script accepts only the exact `SHA256SUMS` it has pinned. It never uses `sudo`: programs go to `~/.local/bin` and the bundled Ghidra extension to `~/.local/share/kraken`. It also writes `~/.local/share/kraken/install.json`, which tells KRAKEN it was installed this way so it can update itself. Read it first if you like, it is short: [`scripts/install.sh`](https://github.com/Adam-AtlasSoftware/kraken/blob/main/scripts/install.sh).

Set `KRAKEN_VERSION=v0.1.0` to pick a release, or `KRAKEN_PREFIX=/some/dir` to install somewhere other than `~/.local`. If `~/.local/bin` is not on your `PATH`, the script says so.

### AppImage (Linux)

Download `KRAKEN-<version>-x86_64.AppImage` from the [releases page](https://github.com/Adam-AtlasSoftware/kraken/releases), make it executable and run it:

```sh
chmod +x KRAKEN-*-x86_64.AppImage
./KRAKEN-*-x86_64.AppImage                     # the app
./KRAKEN-*-x86_64.AppImage kraken --help       # the command line
```

The first argument `kraken` or `krakend` runs that program instead of the app, so an agent can be connected with `claude mcp add kraken -- /path/to/KRAKEN.AppImage kraken mcp --project ~/kraken-projects/calc`. The AppImage holds the same programs as the archive, native engine included.

### Arch Linux (AUR)

```sh
yay -S kraken-workbench-bin        # or paru, or makepkg -si in a clone of the AUR repository
```

It installs the release archive's programs into `/usr/bin` and its data into `/usr/share/kraken`, with the desktop entry. Update it with your AUR helper as usual.

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

### Windows

Windows support is an early preview. Unzip `kraken-<version>-x86_64-pc-windows-msvc.zip` anywhere and add its `bin` folder to your `PATH`: `kraken.exe` is the command line and MCP server, `kraken-gui.exe` the app and `krakend.exe` the daemon. Windows has the Ghidra engine only (`kraken setup` downloads Ghidra and a JDK). KRAKEN's sandbox around the engine exists on Linux only, so on Windows analysis is refused until you set the environment variable `KRAKEN_ALLOW_UNCONFINED=1` (or `allow_unconfined = true` in the config file that `KRAKEN_CONFIG` names); Ghidra then runs as you, unconfined, so open only files you trust. Linux is the platform to use today. An installer that updates itself is planned.

## Updating

KRAKEN looks for a new release once a day and tells you: a strip at the top of the app, or one line after a command in a terminal (`KRAKEN 0.4.0 is available (you have 0.3.0): run kraken update`). The check sends one request to GitHub with KRAKEN's version and nothing else. Turn it off in the first-run wizard, in Help > Check for updates..., with `kraken config-set --key updates.check --value false`, or with `KRAKEN_NO_UPDATE_CHECK=1`; it is also off when `CI` is set. `[updates] channel = "prerelease"` in `config.toml` includes prereleases.

`kraken --version` (and Help > About) says how KRAKEN was installed. That decides how it is updated:

| Installed with | How to update |
|---|---|
| The one-command script, or a release archive unpacked into a folder you own | `kraken update`, or Update now in the app |
| The AppImage | `kraken update` (run `./KRAKEN.AppImage kraken update`), or Update now in the app: the file is replaced |
| The Windows zip | `kraken update`, or Update now in the app |
| AUR (`kraken-workbench-bin`) | `yay -Syu kraken-workbench-bin` (or `paru`) |
| A distribution package | your distribution's upgrade command |
| `cargo install` | `cargo install --locked --git https://github.com/Adam-AtlasSoftware/kraken --tag vX.Y.Z kraken-cli krakend kraken-gui` |
| A clone built from source | `git pull --ff-only` and the `cargo build` above |

**Per-user and system-wide installs.** An install in your home folder (the script, the AppImage, the Windows zip) belongs to you, so KRAKEN updates it itself when you say so. An install in `/usr` or `/opt` (the AUR package, a distribution package) belongs to the package manager: KRAKEN never runs `sudo` or asks for administrator rights, so it shows you the exact command instead, with a copy button in the app. `kraken update` also refuses to run as root, so `sudo kraken update` cannot rewrite a system install.

What `kraken update` does: it downloads the release's `SHA256SUMS` and checks its signature against the key compiled into KRAKEN (the signature must name the new version), downloads the archive and checks its SHA-256, unpacks it into a private folder, runs the new `kraken --version`, and only then swaps the files, one rename at a time, keeping the old ones in `~/.local/share/kraken/previous/`. If anything fails, what was already swapped is put back. It never installs an older version. Restart KRAKEN afterwards (the app offers Restart now). `kraken update --rollback` goes back to the kept version; `--check` only checks; `--yes` skips the question; `--json` prints the result for scripts.

## Install from source

### Native engine (no Java)

You need Rust (stable) and a C++ compiler. The [Getting started](getting-started.md) page walks through it. In short:

```sh
git clone https://github.com/Adam-AtlasSoftware/kraken
cd kraken
cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native
cp target/release/{kraken,krakend,kraken-gui,kraken-native-worker} ~/.local/bin/
kraken setup --native
```

`kraken-native-worker` has to sit next to `kraken` and `krakend` (or be named by `KRAKEN_NATIVE_WORKER`). `kraken setup --native` fetches the pinned Ghidra sources, compiles the specifications into `~/.cache/kraken-dev/native-sla` and tells you when it is done; run it from the checkout. Then create projects with `--engine native`, or set `engine = "native"` in `~/.config/kraken/config.toml`.

### Ghidra engine

You need Rust (stable), a JDK 25, Ghidra 12.2 and Gradle to build the extension. In short:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC JAVA_HOME=/path/to/jdk-25
cargo xtask ghidra-ext
cargo install --path crates/kraken-cli
cargo install --path crates/krakend
cargo install --path crates/kraken-gui
```

Without Gradle you can still run `kraken setup` (below): it compiles the extension with the JDK it downloads.

## First run (Ghidra engine)

Skip this if you only use the native engine.

```sh
kraken setup
```

`kraken setup` downloads the pinned Ghidra and Temurin JDK 25 into your user data directory (`~/.local/share/kraken/runtime`), checks them against SHA-256 hashes compiled into the program, and installs the Ghidra extension: the bundled `kraken-ghidra.jar` from a release, or one compiled with the downloaded JDK otherwise. It needs network access once. Interrupted downloads resume, and running it again does nothing if everything is in place (`--force` redoes it). Nothing needs root.

To open .NET assemblies as well, run `kraken setup --dotnet` once. It downloads a pinned .NET runtime the same way and installs the sidecar that ships with the release; see [.NET assemblies](dotnet.md).

Then try it:

```sh
kraken --help
kraken-gui
```

Ghidra (Apache-2.0) and the Temurin JDK (GPL-2.0 with the Classpath Exception) come from their publishers and are not redistributed by KRAKEN. Their licenses come with the downloads. See `THIRD-PARTY-NOTICES.md` for everything that is part of the release.

## Uninstall

1. Stop the daemon: `kraken daemon stop`.
2. Remove the programs: `rm ~/.local/bin/kraken ~/.local/bin/krakend ~/.local/bin/kraken-gui ~/.local/bin/kraken-native-worker` and `rm ~/.local/share/kraken/kraken-ghidra.jar` (or the whole `~/.local/share/kraken/` directory; that also removes the downloaded Ghidra and JDK, a few GiB).
3. Optionally remove your settings in `~/.config/kraken/`. Your analysis projects live where you created them (by default under your projects directory) and are not touched.

If you installed with `cargo install`, use `cargo uninstall kraken-cli krakend kraken-gui` instead of step 2's `rm` of the programs.
