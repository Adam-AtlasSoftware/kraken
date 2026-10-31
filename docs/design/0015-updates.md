# 0015. Updates

Status: Accepted
Date: 2026-10-31

## Context

KRAKEN ships often, and people install it in different ways: the one-command script into `~/.local`, the AppImage, the AUR package `kraken-workbench-bin`, `cargo install`, a clone built from source, the Windows zip, and the Python module. Each needs a different update, and most users do not remember which one they used. Users should hear about a new release without looking for it, and updating should take one click wherever KRAKEN can do it safely.

An updater replaces the programs that later read people's projects and run untrusted binaries in a sandbox. A compromised update channel would compromise every install, so the update path needs the strongest checks in the product.

## Decision

### Who updates what

KRAKEN never runs `sudo`, never asks for administrator rights and never runs a command that needs them. That gives two kinds of install:

- **Per-user installs update themselves.** The script install (`~/.local`), the AppImage, the Windows zip (and the planned per-user Windows installer in `%LOCALAPPDATA%`), and a release archive unpacked by hand into a directory the user owns. KRAKEN downloads, verifies and swaps its own files.
- **System-wide installs belong to their package manager.** The AUR and any later distribution package (in `/usr`), a future Windows MSI in `Program Files`, `cargo install`, `pip`, and a source checkout. KRAKEN detects which one it is and shows the exact command, with a copy button. The user runs it. The package manager updates KRAKEN along with everything else anyway (`yay -Syu`).

The documented default for a direct download is the per-user install, as rustup, VS Code's user setup and Zed do. Global installs stay first-class through package managers.

### Knowing the install

`kraken-host/src/update/install.rs` works out an `InstallKind` once per process, in this order:

1. **Build channel.** `release.yml` builds with `KRAKEN_BUILD_CHANNEL=release`; every other build is `source`. The target triple is compiled in.
2. **AppImage.** `APPIMAGE` is set and the running program is inside `APPDIR`. Self-update replaces the file `APPIMAGE` names.
3. **Install receipt.** `install.sh` writes `<prefix>/share/kraken/install.json` (`{"method": "script", "version": ..., "prefix": ...}`). A receipt is a hint, not a grant: self-update is offered only if every file it would replace is a regular file owned by the current user in a writable directory.
4. **Package owner.** For a program under `/usr` or `/opt`, ask `pacman -Qqo`, `dpkg -S` and `rpm -qf`, each without a shell and with a timeout. `pacman -Qqm` tells an AUR package from a repository one.
5. **cargo.** The program is in `$CARGO_HOME/bin` and `.crates2.json` lists `kraken-cli`.
6. **Source checkout.** The channel is `source` and the program is in `<dir>/target/{release,debug}`, with KRAKEN's workspace `Cargo.toml` in `<dir>`.
7. **Windows.** A receipt from the installer, or else `portable` (the zip) when the directory is writable.
8. Otherwise `unknown`: KRAKEN links to the releases page.

Each kind carries a plain-words label ("AppImage at ~/Apps/KRAKEN.AppImage", "AUR package kraken-workbench-bin"), whether KRAKEN can update it itself, and otherwise the command the user should run:

| Kind | Update |
|---|---|
| script, archive, Windows zip | KRAKEN updates itself |
| AppImage | KRAKEN updates itself (replaces the file) |
| AUR | `yay -Syu kraken-workbench-bin` (or `paru`, whichever is installed) |
| pacman/dpkg/rpm package | the distribution's upgrade command |
| cargo | `cargo install --locked --git https://github.com/Adam-AtlasSoftware/kraken --tag vX.Y.Z kraken-cli krakend kraken-gui` |
| source checkout | `git -C <dir> pull --ff-only && cargo build --release ...` (see the install page) |
| Python module | `pip install -U kraken-workbench` |

`kraken --version`, Help > About, `setup_status` and bug reports show the version, target, channel and install kind.

### Checking

- **Default on, asked once.** The GUI's first-run wizard has an Updates step with the switch on, and says what is sent. The first interactive CLI run prints a one-time notice saying how to turn it off. Settings: `[updates] check = true|false` and `channel = "stable"|"prerelease"`. `KRAKEN_NO_UPDATE_CHECK=1` and `CI` turn checks off, and so does `updates.check = false`.
- **What is sent.** One HTTPS GET to `api.github.com/repos/Adam-AtlasSoftware/kraken/releases/latest` (or the releases list for `prerelease`), with the User-Agent `kraken/<version>`. GitHub sees the IP address and the version, nothing else.
- **How often.** At most once a day. The result is cached in `<data dir>/update-state.json` with the time, latest version, notes URL, skipped version and the last notice time.
- **Who checks.** The GUI checks at start in the background. The daemon checks once a day while it runs. The CLI only reads the cache. When the cache is stale it checks after an interactive command finishes (stderr is a terminal, not `mcp`, not `--json`), with a 3 s timeout. Nothing ever delays a command.

### Telling the user

- **GUI.** A dismissible strip above the main view (like the next-steps strip): "KRAKEN 0.4.0 is available (you have 0.3.0)", with [What's new] [Update now] [Skip this version] [Later]. For a package-managed install, [Update now] becomes [Copy command] and the text "Your package manager installed KRAKEN, so it updates it: `yay -Syu kraken-workbench-bin`". Help > Check for updates... opens the Updates dialog: version, install kind, channel, last check, the switch, [Check now].
- **CLI.** One line on stderr after an interactive command, at most once a day: `KRAKEN 0.4.0 is available (you have 0.3.0): run kraken update`. For package-managed installs it shows their command instead.
- **Agents and MCP.** `update_status` and `update_check` are read-only and agents may call them. `update_apply` and `update_rollback` are for a person only; an agent is refused.

### Installing (self-updating kinds)

`kraken update` (CLI; `--yes` skips the question, `--check` only checks, `--rollback`, `--json`) and the GUI's [Update now] both run the `update_apply` job:

1. Fetch the release metadata. Accept only a tag matching `^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$` that is newer than the running version (semver). Never downgrade.
2. Work out the asset name from the version and the compiled-in target (`kraken-<v>-<target>.tar.gz`, `.zip`, or `KRAKEN-<v>-x86_64.AppImage`). Asset names are never taken from the metadata.
3. Download `SHA256SUMS` and `SHA256SUMS.minisig`. Verify the signature with the release public key compiled into KRAKEN (`minisign-verify`). The trusted comment must be `kraken v<version> SHA256SUMS`, so an old signed file cannot be replayed as a newer release. **Without a valid signature nothing is installed.**
4. Download the asset over HTTPS only, following redirects only to `github.com`, `objects.githubusercontent.com` and `release-assets.githubusercontent.com`, with a size cap. Check its SHA-256 against the signed list.
5. Unpack into a private staging directory (`0700`) on the same filesystem as the install, with the existing extractors: no links, no absolute or `..` paths.
6. Run the staged `kraken --version` with a timeout. It must report the expected version.
7. Swap the files under an exclusive lock. For each file the release ships, check that the current file is a regular file the user owns (not a symlink), move it to `<data dir>/previous/<old version>/`, and rename the new one into place. Renames stay within one filesystem, so each one is atomic. On Windows a running `.exe` can be renamed, though not deleted. Any failure puts back what was already moved.
8. Report "Updated to 0.4.0. Restart KRAKEN to use it." The GUI offers [Restart now]: it stops the daemon when no job is running and starts the new GUI. A client that meets an older daemon asks it to exit once it is idle.

For an AppImage, steps 4–7 download the new AppImage beside the old one as `.part`, verify it, make it executable, keep the old one in `previous/`, and rename the new one over `APPIMAGE`.

`kraken update --rollback` restores the one kept generation. Updates refuse to run as root (euid 0), so `sudo kraken update` cannot rewrite a system install.

### Release side

- `release.yml` builds with `KRAKEN_BUILD_CHANNEL=release`. It signs `SHA256SUMS` with the `KRAKEN_MINISIGN_KEY` secret, using a pinned, hash-checked minisign with the trusted comment `kraken <tag> SHA256SUMS`, and uploads `SHA256SUMS.minisig` next to it. The public key (`RWQcuc9uv/vL6fNGCFoY+ea132bmfUHhfczZGY/UgdNbC08hjU6DYmln`, key id `E9CBFBBF6ECFB91C`) is compiled into KRAKEN and embedded in `install.sh`, whose signature check therefore becomes mandatory.
- `install.sh` writes the install receipt.
- Releases up to 0.3.0 are unsigned and cannot be updated to. Installs older than the updater update once by hand.

## Consequences

- Most users update with one click. Package-managed users get the right command instead of a wrong button.
- A hijacked GitHub account or release cannot reach existing installs without the signing key. The key is a single secret: it lives in the repository's Actions secrets and in the owner's password manager. Losing it means shipping a release whose updater trusts a new key, signed with the old key while it is still available.
- The check is a privacy-relevant network call. It is visible in the first-run wizard, off with one setting or variable, and sends nothing but the version.

## Options not taken

- **Running the package manager for the user.** AUR helpers and system package managers escalate with `sudo`. KRAKEN does not run privileged commands.
- **Silent background installs.** Replacing programs under a running session, without the user asking, surprises people and makes failures hard to explain. KRAKEN downloads only when the user says so.
- **Trusting GitHub alone (TLS and `SHA256SUMS`).** Anyone who controls a release would then control every install.
- **Verifying GitHub's Sigstore attestations in-process.** It is strong, but needs a large dependency tree and a TUF trust root. minisign is one small, audited crate. Attestations stay available for manual checks.
- **zsync delta updates for the AppImage.** A full download is a few tens of MiB. This can come later.
