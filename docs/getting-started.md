# Getting started

This page takes you from nothing to a renamed function in a real binary. KRAKEN 0.1a runs on Linux x86_64 only, and you build it from source.

## What you need

- **Rust**, the stable toolchain. Install it with [rustup](https://rustup.rs/).
- **JDK 21.** Ghidra runs on Java. [Temurin 21](https://adoptium.net/) works well.
- **Ghidra 12.1.4.** KRAKEN uses Ghidra to analyse binaries. It starts Ghidra itself, so you never open the Ghidra window.
- **Gradle 9.8** (or a recent Gradle on your `PATH`) to build the small KRAKEN extension that runs inside Ghidra.
- A Linux kernel with [Landlock](https://docs.kernel.org/userspace-api/landlock.html) (5.13 or newer; 6.x is better). KRAKEN uses it to confine Ghidra. See [Security](security.md).

## 1. Get the code

```sh
git clone https://github.com/Adam-AtlasSoftware/kraken
cd kraken
```

## 2. Download Ghidra and check it

```sh
curl -fLO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  ghidra_12.1.4_PUBLIC_20260921.zip" | sha256sum -c -
unzip -q ghidra_12.1.4_PUBLIC_20260921.zip -d ~/ghidra
```

The `sha256sum` line must print `OK`. If it does not, delete the download and try again. The extension is built against exactly this Ghidra version.

## 3. Build KRAKEN and its Ghidra extension

```sh
export GHIDRA_INSTALL_DIR=~/ghidra/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/path/to/jdk-21
cargo xtask ghidra-ext
cargo install --path crates/kraken-cli
```

`cargo xtask ghidra-ext` builds `kraken-ghidra.jar` with Gradle. `cargo install` puts the `kraken` program in `~/.cargo/bin`.

## 4. Tell KRAKEN where things are

Create `~/.config/kraken/config.toml`:

```toml
ghidra_home = "/home/you/ghidra/ghidra_12.1.4_PUBLIC"
java_home   = "/path/to/jdk-21"
```

All keys are optional, and unknown keys are an error (so typos do not go unnoticed).

| Key | Environment variable | Meaning |
|---|---|---|
| `ghidra_home` | `KRAKEN_GHIDRA_HOME` | Ghidra install directory |
| `java_home` | `KRAKEN_JAVA_HOME` | JDK 21 home (`JAVA_HOME` is used as a fallback) |
| `ext_jar` | `KRAKEN_GHIDRA_EXT_JAR` | Path of `kraken-ghidra.jar`; default is the `cargo xtask ghidra-ext` output |
| `max_heap_mb` | `KRAKEN_MAX_HEAP_MB` | Upper bound for Ghidra's memory, in MiB |
| `allow_unconfined` | `KRAKEN_ALLOW_UNCONFINED` | Run Ghidra without Landlock when the kernel lacks it. Default `false`. Leave it off unless you understand the risk |
| `per_run_cap` | `KRAKEN_PER_RUN_CAP` | How many edits an AI agent may apply on its own per run before the rest become proposals (default 200) |
| `projects_root` | `KRAKEN_PROJECTS_ROOT` | Where projects go when you do not give a directory |

Environment variables win over the file. Set `KRAKEN_CONFIG` to use a config file somewhere else. The default location follows `$XDG_CONFIG_HOME` when it is set.

> **Project paths must not contain a dot-prefixed folder** (such as `~/.local/...`), because Ghidra rejects them. By default KRAKEN keeps projects in `~/kraken-projects`.

## 5. Your first project

The repository contains small test programs in `corpus/bin`. We use `pie_list-O0`, a linked-list program compiled with debug info.

```sh
export KRAKEN_PROJECT=~/kraken-projects/demo

kraken project-create --binary corpus/bin/pie_list-O0
kraken analyze
kraken list-functions --limit 20
```

`project-create` makes the project folder and loads the binary. `analyze` asks Ghidra to find the functions; it takes a minute or so and prints progress. `list-functions` shows a table of addresses, sizes and names.

Look at one function as C-like code. Use an address from your own table (`0x1189` below is only an example):

```sh
kraken decompile --address 0x1189
```

Look under the C: the same function as instructions, who calls it, and the bytes it is made of.

```sh
kraken disassemble --function 0x1189
kraken callers --address 0x1189
kraken read-bytes --address 0x1189 --length 32
```

`memory-map`, `strings`, `imports`, `exports`, `xrefs`, `callees` and `cfg` (basic blocks and edges) complete the picture. Every list is paged: add `--cursor` from the footer to continue. Names, comments and strings in the output come from the binary, so `--json` marks them as untrusted data.

Give it a better name:

```sh
kraken rename-symbol --address 0x1189 --new-name list_push
kraken list-functions --name-filter list_push
```

Changed your mind? Undo it:

```sh
kraken undo
```

And see everything that happened, newest first:

```sh
kraken history
```

Your edits live in a log inside the project folder. Close the terminal, come back tomorrow, set `KRAKEN_PROJECT` again, and your work is there.

## Next steps

- [Concepts](concepts.md) explains the words used above.
- [Connect an AI agent](mcp.md) to do the naming for you.
- [Script the CLI](cli.md) with `--json` and `jq`.
