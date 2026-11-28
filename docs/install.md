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

On Windows, see [Windows](#windows).

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

Windows support is an early preview. Everything is per user: nothing needs administrator rights.

The native engine is in the archive (`bin\kraken-native-worker.exe` and the compiled Sleigh files in `share\kraken\native-sla`), so Windows programs (PE, x86 and x86-64) are decompiled without Java; `kraken setup` downloads Ghidra and a JDK when you want the Ghidra engine as well. KRAKEN's sandbox around the engine exists on Linux only for now: on Windows analysis is refused until you set `KRAKEN_ALLOW_UNCONFINED=1` (or `allow_unconfined = true` in the config file), and the engine then runs as you, so open only files you trust.

**One command.** In PowerShell (Windows PowerShell 5.1, which every Windows 10 and 11 has, or PowerShell 7):

```powershell
irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1 | iex
```

A piped script takes no options; to pass some, turn it into a script block first:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1))) -Version v0.4.1
```

Options: `-Version vX.Y.Z` (default: the newest release), `-InstallDir <folder>`, `-NoPath`, `-NoShortcut`, `-Proxy <url>`, `-Force` (stop running KRAKEN programs without asking, install over a folder the script did not create, or install the x86-64 build on Windows on ARM). `KRAKEN_VERSION`, `KRAKEN_INSTALL_DIR` and `KRAKEN_PROXY` in the environment do the same for the piped form. Read the script first if you like: [`scripts/install.ps1`](https://github.com/Adam-AtlasSoftware/kraken/blob/main/scripts/install.ps1).

What the script checks before it installs anything:

1. The script itself comes from this repository over HTTPS and carries the release public key (minisign, key id `E9CBFBBF6ECFB91C`), the same key as `install.sh` and the one compiled into `kraken.exe`.
2. It downloads the release's `SHA256SUMS` and `SHA256SUMS.minisig` and checks the signature with that key. Windows PowerShell has no Ed25519 or BLAKE2b, so the script carries a small verifier (C#, compiled on the spot with `Add-Type`); it accepts only current minisign signatures whose trusted comment is exactly `kraken v<version> SHA256SUMS`, so an old signed list cannot pass for a newer release.
3. The zip must have the SHA-256 that the signed list gives. Only then is it unpacked, into a folder beside the install, refusing any entry that would land outside it; the new `kraken.exe --version` must report the expected version before the old install is touched.

Without a valid signature nothing is installed. Someone who controls the download server or a release page still cannot get a file installed without the signing key. Release files also carry GitHub build provenance attestations: `gh attestation verify <zip> --repo Adam-AtlasSoftware/kraken`.

The script uses the system proxy settings (signed in as you, for a proxy that asks for your Windows login), or `-Proxy`, `KRAKEN_PROXY` or `HTTPS_PROXY`; on Windows PowerShell 5.1 it turns on TLS 1.2. It retries downloads, and file moves that an antivirus scan of the new files holds up for a moment. Running it again reinstalls or updates: it stops the daemon (`kraken daemon stop`) and any KRAKEN program running from the install folder (asking first when you run the saved script yourself), puts the old folder aside, moves the new one in and deletes the old one; if something still holds it, the next run removes it.

**What gets written where:**

| What | Where |
|---|---|
| Programs (`kraken.exe`, `krakend.exe`, `kraken-gui.exe`, ...), `share\kraken\`, `docs\`, `licenses\` | `%LOCALAPPDATA%\Programs\KRAKEN` (or `-InstallDir`) |
| Install receipt (how KRAKEN was installed, so `kraken update` can update it in place) | `%LOCALAPPDATA%\Programs\KRAKEN\share\kraken\install.json` |
| Its `bin` folder, added at the end of your user `Path` (unless already there, or `-NoPath`) | `HKCU\Environment` |
| Start Menu shortcut (unless `-NoShortcut`) | Start Menu, `Programs\KRAKEN\KRAKEN.lnk` |
| What KRAKEN downloads later (Ghidra and a JDK from `kraken setup`, models, caches), the update lock and the version kept for rollback (`previous\`) | `%LOCALAPPDATA%\kraken` (the same folder as `%LOCALAPPDATA%\KRAKEN`; Windows ignores case) |
| Your settings (`config.toml`), written when you change one | `%APPDATA%\kraken` |

Your analysis projects live where you create them. Open a new terminal after installing so the `kraken` command is found.

**By hand.** Unzip `kraken-<version>-x86_64-pc-windows-msvc.zip` into a folder you own and add its `bin` folder to your `Path`. Check the zip against `SHA256SUMS` first: `Get-FileHash .\kraken-<version>-x86_64-pc-windows-msvc.zip` must print the hash the list gives. KRAKEN updates such a copy too (`kraken --version` calls it "Windows zip").

**Using it.** `kraken.exe` is the command line and MCP server (`claude mcp add kraken -- kraken mcp` connects an agent), `kraken-gui.exe` the app and `krakend.exe` the daemon. Windows releases have the Ghidra engine (`kraken setup` downloads Ghidra and a JDK); the native engine comes to Windows when a release ships `kraken-native-worker.exe`, and the install script says which one you got. KRAKEN's sandbox around the engine exists on Linux only, so on Windows analysis is refused until you set the environment variable `KRAKEN_ALLOW_UNCONFINED=1` (or `allow_unconfined = true` in the config file that `KRAKEN_CONFIG` names); Ghidra then runs as you, unconfined, so open only files you trust. Linux is the platform to use today.

**Updating on Windows.** `kraken update` (or Update now in the app) checks the release exactly as the script does, with the key compiled into KRAKEN, and works for an install by the script and for a zip you unpacked into a folder you own (`kraken --version` says which one it found). Windows does not let a running program be overwritten or deleted, but it can be renamed, so every step is a rename: `kraken update` stops the daemon first (the engines it started keep files of the install open), renames the old files into `%LOCALAPPDATA%\kraken\previous\<old version>\`, running `kraken.exe` included, and renames the new ones into place, retrying for a few seconds while an antivirus scan holds a new file. When the install is on another drive than that folder, each old file is first renamed beside itself (`<name>.kraken-old-<n>`) and copied there; the renamed files are deleted the next time KRAKEN starts. If a file stays in use, everything already moved is put back and KRAKEN says so: close KRAKEN (`kraken daemon stop`) and try again. Restart KRAKEN afterwards. `kraken update --rollback` puts the previous version back the same way. The update check and the download use the system proxy settings (Settings, Network, Proxy; an automatic configuration script is not read) or `HTTPS_PROXY`, and trust the certificates in the Windows store as well as the usual public ones, so a proxy that inspects TLS with your organisation's certificate works. Running the install script again also updates.

**Uninstalling on Windows.**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1))) -Uninstall
```

It stops KRAKEN, removes the install folder, the `Path` entry it added and its Start Menu shortcut, and nothing else: it refuses a folder without its receipt. Your projects and `%LOCALAPPDATA%\kraken` stay; add `-Purge` to remove that folder too (downloaded engines, caches, the kept version, and the `Path` entry of `kraken setup --launchers`). For a copy you unzipped by hand, run `kraken daemon stop`, delete the folder and take its `bin` folder off your `Path`.

## Updating

KRAKEN looks for a new release once a day and tells you: a strip at the top of the app, or one line after a command in a terminal (`KRAKEN 0.4.0 is available (you have 0.3.0): run kraken update`). The check sends one request to GitHub with KRAKEN's version and nothing else. Turn it off in the first-run wizard, in Help > Check for updates..., with `kraken config-set --key updates.check --value false`, or with `KRAKEN_NO_UPDATE_CHECK=1`; it is also off when `CI` is set. `[updates] channel = "prerelease"` in `config.toml` includes prereleases.

`kraken --version` (and Help > About) says how KRAKEN was installed. That decides how it is updated:

| Installed with | How to update |
|---|---|
| The one-command script, or a release archive unpacked into a folder you own | `kraken update`, or Update now in the app |
| The AppImage | `kraken update` (run `./KRAKEN.AppImage kraken update`), or Update now in the app: the file is replaced |
| The Windows install script, or the Windows zip | `kraken update`, or Update now in the app (see [Updating on Windows](#windows)) |
| AUR (`kraken-workbench-bin`) | `yay -Syu kraken-workbench-bin` (or `paru`) |
| A distribution package | your distribution's upgrade command |
| `cargo install` | `cargo install --locked --git https://github.com/Adam-AtlasSoftware/kraken --tag vX.Y.Z kraken-cli krakend kraken-gui` |
| A clone built from source | `git pull --ff-only` and the `cargo build` above |

**Per-user and system-wide installs.** An install in your home folder (the scripts, the AppImage, the Windows zip) belongs to you, so KRAKEN updates it itself when you say so. An install in `/usr` or `/opt` (the AUR package, a distribution package) belongs to the package manager: KRAKEN never runs `sudo` or asks for administrator rights, so it shows you the exact command instead, with a copy button in the app. `kraken update` also refuses to run as root, so `sudo kraken update` cannot rewrite a system install.

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

On Windows, see [Uninstalling on Windows](#windows). On Linux and macOS:

1. Stop the daemon: `kraken daemon stop`.
2. Remove the programs: `rm ~/.local/bin/kraken ~/.local/bin/krakend ~/.local/bin/kraken-gui ~/.local/bin/kraken-native-worker` and `rm ~/.local/share/kraken/kraken-ghidra.jar` (or the whole `~/.local/share/kraken/` directory; that also removes the downloaded Ghidra and JDK, a few GiB).
3. Optionally remove your settings in `~/.config/kraken/`. Your analysis projects live where you created them (by default under your projects directory) and are not touched.

If you installed with `cargo install`, use `cargo uninstall kraken-cli krakend kraken-gui` instead of step 2's `rm` of the programs.
