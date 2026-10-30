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
| `integration_install_start` | The same install as a background job: returns a `job_id` (`job-gN`) at once; `job_status` shows the download, `job_cancel` stops it (needs no project) |
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

### Libraries for dynamically linked programs, and the Rust toolchain

Two kinds of entry are not programs you start. They are what emulation and rewriting need, so
that neither needs developer tools on your computer.

| Entry | What it is | Install |
|---|---|---|
| `sysroot-aarch64`, `sysroot-armhf`, `sysroot-riscv64`, `sysroot-i386`, `sysroot-x86-64` | The dynamic loader and the C and C++ runtime libraries of one architecture | Debian 13 (trixie) `libc6`, `libgcc-s1` and `libstdc++6` packages from deb.debian.org, pinned by SHA-256, unpacked by KRAKEN itself (no `dpkg`, no root) |
| `rust-toolchain` | `rustc` and `cargo`, to build the Rust rewrites | `cargo` on your `PATH` is used first. Otherwise KRAKEN downloads `rustup-init` (pinned, SHA-256 checked) and runs it with its own `RUSTUP_HOME` and `CARGO_HOME`, so your `~/.cargo`, `~/.rustup` and shell profile are never touched. Installs the pinned toolchain and the `x86_64-unknown-linux-musl` target (about 250 MB to download, 800 MB on disk). A C linker (`cc`) is still needed to link builds for the host target |

Install them from Help > Setup status (the Emulators and Rust toolchain cards), the rewrite
wizard's Check step (the Rust toolchain row has a "Set it up..." button), `kraken setup --sysroots`
and `kraken setup --rust`, the jobs `setup_sysroots` and `setup_rust`, or one by one with
`integration_install` (`{"id": "sysroot-aarch64", "accept_licence": true}`). The files go to
`<data dir>/integrations/<id>/<version>/`; `integration_remove` deletes them.

A sysroot is laid out like the one `cargo xtask emu-sysroots` makes (`usr/lib/<triplet>/` with `lib`
linking to `usr/lib`). `emulate_run`, `emulate_call`, the debugger and the rewrite oracle find an
installed one by themselves; a sysroot you built yourself (`KRAKEN_EMU_SYSROOTS`, the developer
cache) wins over an installed one. **There is no riscv32 sysroot**: Debian has no riscv32 port, so
RISC-V 32-bit programs run in the emulator only when they are statically linked, and a dynamic one
gets a message that says so.

The pinned package versions come from the trixie archive of 2026-10-30. Debian drops a package
from `deb.debian.org` once a newer one replaces it, so after a security update the download answers
404 until KRAKEN's catalogue is updated; `emulators.d/` can carry an entry with updated pins in the
meantime.

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
gdb_argv = ["{exe}", "--machine", "board", "-gdb", "unix:{dir}/gdb.sock,server=on,wait=off", "-S", "{binary}"]
# a stub at {dir}/gdb.sock is reported as that path (gdb: target remote | or `target remote unix:`);
# with a TCP {port} (gdb_port, default 1234) the stub may listen on all interfaces, and the result says so

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
