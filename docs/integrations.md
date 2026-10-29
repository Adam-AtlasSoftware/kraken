# Emulators and tools

KRAKEN can hand a program, a patched copy of it, or any file it writes to a real emulator or
compatibility layer. **Nothing is bundled.** For every emulator, whatever its licence, KRAKEN offers
three things:

- **Install** downloads the program from its own project's release page, on your computer, checks the
  SHA-256 it has pinned for that release and unpacks it under KRAKEN's data folder
  (`~/.local/share/kraken/integrations/<id>/<version>/`). KRAKEN never mirrors or redistributes it.
- **Use existing** points KRAKEN at a copy you already have: found on `PATH`, in `~/Applications`,
  `~/.local/bin` or a Flatpak export, or a path you type.
- **Remove** deletes what KRAKEN installed (and forgets a chosen path). A copy of yours is never touched.

KRAKEN never ships or fetches keys, BIOS images, firmware or games. Each entry's notice says what the
emulator needs from you.

## In the window

**Tools > Emulators and tools...** lists every entry with a status chip (Installed by KRAKEN, Found on
this computer, Your path, Not installed, Use your own copy). Pick one to see its licence, what it
runs, the command KRAKEN will start and the notice to read. Install stays disabled until you tick that
you read the licence and notice; a progress bar shows the download. **Patch > Run in emulator...**
(with a project open) starts the chosen emulator on the original program or on a copy with your byte
patches, optionally waiting for a GDB debugger when the emulator has a GDB stub. KRAKEN asks before it
runs, because the emulator is a real program on your computer and not KRAKEN's confined interpreter
(`emulate_run`).

## On the command line, MCP and Python

```sh
kraken integrations-list
kraken integration-install --id mgba --accept-licence
kraken integration-use-path --id pcsx2 --path /opt/pcsx2/pcsx2-qt
kraken emulator-run --project ./proj --id mgba --target patched --debug
kraken integration-remove --id mgba
```

| Command | What it does |
|---|---|
| `integrations_list` | Every entry with status, version, source, licence and notice |
| `integration_install` | Download and install the pinned upstream release (`accept_licence` required) |
| `integration_use_path` | Use a program you already have |
| `integration_remove` | Delete KRAKEN's copy (asks first) |
| `emulator_run` | Run the original, the patched copy or any file in an emulator (asks first) |

Agents and MCP callers are asked before an install or `use_path`, and an entry that embeds key
material (Xenia Canary) is never installed on an agent's say-so: a person installs it.

## The catalogue

Linux x86-64 builds, checked against upstream's releases on 2026-10-28.

| Entry | Runs | Install |
|---|---|---|
| xemu | Original Xbox | AppImage from xemu-project/xemu |
| Xenia Canary | Xbox 360 | tar.xz from xenia-canary-releases (embeds key material; a person installs it) |
| shadPS4 | PlayStation 4 | zip with an AppImage |
| RPCS3 | PlayStation 3 | AppImage from rpcs3-binaries-linux |
| PCSX2 | PlayStation 2 | AppImage |
| PPSSPP | PlayStation Portable | AppImage |
| DuckStation | PlayStation 1 | AppImage (CC BY-NC-ND 4.0) |
| mGBA | Game Boy, GBC, GBA | AppImage (has a GDB stub) |
| melonDS | Nintendo DS | zip |
| Cemu | Wii U | AppImage |
| Dolphin | GameCube, Wii | use your copy (no Linux download upstream) |
| Ryubing (Ryujinx fork) | Nintendo Switch | use your copy (releases are on its own GitLab without digests) |
| MAME, ares | many systems | use your copy |
| QEMU user mode (x86-64, AArch64, ARM, RISC-V 64) | Linux programs, with a GDB stub | detected from your install |
| Wine | Windows programs | detected from your install |

AppImages run with `APPIMAGE_EXTRACT_AND_RUN=1`, so they need no FUSE. Some emulators need system
libraries of their own (for example melonDS wants `libenet`); the run log says what is missing.

## Your own emulator

Any emulator on any silicon works as soon as you describe it. Drop a TOML file into
`~/.config/kraken/emulators.d/` (or `$XDG_CONFIG_HOME/kraken/emulators.d/`):

```toml
schema = 1

[[emulator]]
id = "my-emu"                 # a-z, 0-9 and -
name = "My emulator"
summary = "Runs my board's firmware images"
platforms = ["My board"]
formats = ["bin", "elf"]
license = "GPL-3.0-or-later"
notice = "Needs the board's bootloader from your own device."

[emulator.detect]             # optional: where to look on this computer
names = ["my-emu"]            # on PATH
paths = ["~/Applications/my-emu*.AppImage"]
probe = true                  # ask `--version` and show it

[emulator.run]
argv = ["{exe}", "--machine", "board", "{binary}"]   # {exe} {binary} {dir} {port}
gui = false                   # false: wait for it and show its output; true: leave it running
gdb_argv = ["{exe}", "--machine", "board", "-gdb", "tcp::{port}", "-S", "{binary}"]
gdb_port = 1234

[[emulator.artifact]]         # optional: makes Install work
version = "1.0"
url = "https://example.org/my-emu-1.0-linux-x86_64.zip"   # https only
sha256 = "<64 hex digits>"
size = 1234567
format = "zip"                # file, zip, tar_gz or tar_xz
entry = "my-emu/bin/my-emu"   # the program inside the archive
```

Rules: the first element of `argv` is `{exe}`; the only placeholders are `{exe}`, `{binary}` (the file
being run), `{dir}` (a private run directory) and `{port}`; artifact URLs are `https://` with a SHA-256;
an id that the built-in catalogue already uses is skipped. Your entries are marked "your manifest, not
reviewed", because `argv` is a command KRAKEN will run. A file that does not parse is skipped, with the
reason in the daemon's log.

## How a run works

`emulator_run` expands the argv template for the file (the project's original, a copy with your patches
written under a private temporary directory, or the file you name), starts the emulator from that
directory with its output going to `emulator.log`, and returns the command line, pid, exit code and
the first 4000 characters of output (program data, so untrusted). A windowed emulator is left running;
close its window to end it. The temporary directory is not deleted, so the emulator can keep using
the patched copy.
