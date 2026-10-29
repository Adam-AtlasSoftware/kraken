# KRAKEN test corpus

Small prebuilt x86_64 ELF programs with DWARF-derived ground truth (decisions 23, 65, 78), plus
smaller sets: Windows PE images (`pe/`), 32-bit x86 ELF programs (`elf32/`), one library built as
every kind of library and object file (`lib/`), and the same C programs for ARM and RISC-V
(`arm32/`, `aarch64/`, `riscv64/`, `riscv32/`) with the expected outputs of the x86-64 builds
(`expected/`), see below.
Binaries are committed. Rebuilding is a manual job: it should open a PR, never run in normal CI.

## Programs (`src/`)

| program | shape it exercises |
|---|---|
| `static_strops.c` | statically linked (`-static -no-pie`), several small helpers and string ops; libc is inside the binary, only the 8 program functions have ground truth |
| `pie_list.c` | PIE (`-fPIE -pie`), function pointers (comparators, visitors in a table), struct-heavy singly linked list |
| `stripped_calc.c` | recursive-descent expression evaluator; the `-stripped` binaries are the intended "no symbols" targets |
| `cpp_shapes.cpp` | C++: class hierarchy, virtual methods and vtables, a class template, `std::string`/`std::vector`/`unique_ptr` (many libstdc++ instantiations) |
| `switch_vm.c` | bytecode VM: dense `switch` compiled to a jump table, plus a `noreturn` error function (`vm_fail`) |

Each program is deterministic, uses no network or files, and exits 0.

## Outputs

For every program, `bin/<name>-O0`, `bin/<name>-O2` (both `-g`, unstripped) and
`bin/<name>-O0-stripped`, `bin/<name>-O2-stripped` (`strip --strip-all` of the same file, so
addresses are identical). `truth/<binary>.json` exists for all 20 binaries; stripped ones take
their truth from the unstripped twin (`ground_truth_from`).

Truth schema: `{binary, ground_truth_from, sha256, source_file, opt, functions: [{name, demangled, entry: "0x..", size}]}`.
`entry`/`size` are file virtual addresses as in the ELF (PIE binaries are link-time addresses, base 0).
Only functions with DWARF from the corpus source file are listed (libc internals in the static
binary are excluded; C++ includes template instantiations from libstdc++ headers). At `-O2`
inlined helpers (e.g. `hash_str`, `caesar` in `static_strops`) have no standalone function, so they
are absent from truth.

## The PE set (`pe/`)

Built with the mingw-w64 cross compilers (win32 thread model) in the same pinned container,
`-O0` and `-O2`, for x86-64 (PE32+) and x86 (PE32):

| program | shape it exercises |
|---|---|
| `pe/src/win_tls.c` (`win_tls-<arch>-<opt>.exe`) | a TLS callback, Win32 imports (`GetModuleHandleA`, `GetProcAddress`, `VirtualAlloc`, `lstrlenA`, `Sleep`), C runtime imports through thunks (`qsort`, `printf`), imports from `win_dll.dll` by name and by ordinal (`kr_secret` is ordinal 3, `Ordinal_3`), a data import, a jump-table switch, a function-pointer table; `-O2-stripped` twins without the COFF symbol table |
| `pe/src/win_dll.c` + `win_dll.def` (`win_dll-<arch>-<opt>.dll`) | exports by name, one export by ordinal only (`NONAME`), an exported variable, `DllMain`, base relocations, a high preferred base on x86-64 |
| `src/switch_vm.c` (`switch_vm-<arch>-<opt>.exe`) | the ELF corpus's VM: dense switch and a noreturn function, as PE |

The images carry no debug information, like a Windows program without its PDB: build.sh compiles
the objects with `-g` (which does not change the code) and links with `--strip-debug`. The truth
(`pe/truth/<binary>.json`, `python3 -I corpus/tools/groundtruth_pe.py`, host binutils with PE
support) takes the program's functions from its own object files (kept in the ignored
`pe/.build/`), their addresses from the image's COFF symbol table and their sizes from the
objects' DWARF; `name` is the COFF symbol (`_on_tls@12` on x86) and `demangled` the C name.
`pe/fixtures/` holds Ghidra recordings of five of the images with the first 32 functions each
(`kraken-record --corpus corpus/pe --function-cap 32`); recording all 14 with the default cap
takes about 60 MB, which is why only these are committed.

## The 32-bit ELF set (`elf32/`)

`pie_list` and `switch_vm` built with `gcc -m32` (multilib), position-independent like the
distribution default, `-O0`/`-O2` with `-stripped` twins: `elf32/bin/<name>-i386-<opt>`. Truth
from DWARF as for the main set (`python3 -I corpus/tools/groundtruth.py --set elf32`, link-time
addresses; Ghidra loads these at 0x10000). All eight have Ghidra fixtures in `elf32/fixtures/`.

## The library set (`lib/`)

One small C library, libkr (`lib/src/kr_core.c` with a dense switch, a static helper and calls to
the other file and to the C library; `lib/src/kr_text.c` with strings, a switch over them, a loop,
`malloc` and `toupper`), built at `-O2 -g` as every kind of library and object file:

| file | what it is |
|---|---|
| `lib/bin/libkr.so` | Linux shared library (x86-64, `-fPIC`, no entry point) |
| `lib/bin/libkr.a` | Linux static library: `kr_core.o` and `kr_text.o` |
| `lib/bin/kr.o`, `lib/bin/kr-i386.o` | Linux object files (`kr_core.c`, x86-64 and `-m32`), with GOT and PLT relocations |
| `lib/bin/kr-<arch>.dll` | Windows DLL (mingw-w64, `lib/src/kr.def`: `kr_checksum` exported by ordinal 4 only, `kr_calls` as data), linked without debug information |
| `lib/bin/kr-<arch>.lib` | Windows static library (a COFF archive of `kr_core.obj` and `kr_text.obj`) |
| `lib/bin/libkr-<arch>.dll.a` | the DLL's import library (`ld --out-implib`: GNU `.idata$` members) |
| `lib/bin/kr-<arch>.obj` | Windows object file (`kr_core.c`) |

`<arch>` is `x64` or `x86`. Objects and archives keep their DWARF. The truth
(`lib/truth/<file>.json`, `python3 -I corpus/tools/groundtruth_lib.py`, host binutils with PE
support) comes from the toolchain's view of each file: function symbols per member (ELF
`st_size`, COFF lengths from the objects' DWARF), the DLL's COFF symbols and export table, the
undefined symbols, and for the import libraries each symbol with its DLL. The objects behind the
DLLs stay in the ignored `lib/.build/`.

## The cross-architecture sets (`arm32/`, `aarch64/`, `riscv64/`, `riscv32/`)

The four C programs (`static_strops`, `pie_list`, `stripped_calc`, `switch_vm`; `cpp_shapes` is
left out to keep the sets small) for ARM and RISC-V, `-O0`/`-O2`, each with a `-stripped` twin:
`<set>/bin/<name>-<set>-<opt>[-stripped]`. They are for analysing, emulating, stepping through
and rewriting non-x86 code; the native engine analyses all four (`crates/engine-native/tests/arch.rs`).

| set | target | toolchain | binaries |
|---|---|---|---|
| `arm32` | armv7-a, hard float, A32 (`-marm`), Linux glibc | `arm-linux-gnueabihf-gcc` | 20: the 16 below plus `switch_vm-arm32-thumb-<opt>[-stripped]`, built as Thumb-2 (`-mthumb`, the Debian armhf default) |
| `aarch64` | armv8-a, Linux glibc | `aarch64-linux-gnu-gcc` | 16 |
| `riscv64` | rv64gc, lp64d, Linux glibc | `riscv64-linux-gnu-gcc` | 16 |
| `riscv32` | rv32imac, ilp32, static, picolibc | `riscv64-unknown-elf-gcc` | 16 |

On the three Linux sets `static_strops` is statically linked (`-static -no-pie`, glibc inside,
runs under emulation without a sysroot) and the other three are dynamic PIEs, as in the main set.

riscv32: Debian has no riscv32 Linux userland (no glibc or musl for it), so these are static
executables linked with the bare-metal compiler against picolibc (`--specs=picolibc.specs`, the
`rv32imac/ilp32` multilib) and `riscv32/src/linux_rt.c`, which plays the operating system's part:
`_start` takes argc/argv from the Linux initial stack, sets `gp` and points `tp` at a zeroed block
(picolibc's `errno` is thread-local; build.sh checks there is no initialised TLS), stdout and
stderr write one byte at a time with the raw Linux `write` syscall (64), `_exit` is
`exit_group` (94), and `sbrk` hands out a 64 KiB static heap. The link uses ld's default ELF
script (`ld -m elf32lriscv --verbose`, text at 0x10000) instead of picolibc's embedded memory
layout. The result runs under Linux user-mode emulation (`qemu-riscv32 <binary>`) and makes no
other system calls. clang/lld were not needed: gcc 14.2 from the same pinned image does it.

Ground truth: `python3 -I corpus/tools/groundtruth.py --set <set>` (DWARF of the unstripped twin,
link-time addresses; only the program's own `src/<name>.c` functions, not glibc, picolibc or
`linux_rt.c`). On `arm32` the Thumb functions carry `"thumb": true` and their `entry` is the
first instruction (DWARF `low_pc`), one less than the odd ELF symbol value.

`<set>/QEMU-CHECK.txt` (written by build.sh) runs every binary under `qemu-user` 10.0 in the
build container (dynamic ones with the cross glibc as `QEMU_LD_PREFIX`) and compares exit status,
stdout and stderr with the x86-64 build: all agree except `static_strops` on the ILP32 targets
(`arm32`, `riscv32`), whose last line is `hash=36474` instead of `hash=6490`, because its
`unsigned long` hash is 32 bits wide there. That is the program's behaviour, not a build fault.

Expected outputs: `expected/<program>.json` holds, for each program, the standard cases of the
program oracle (the source-derived cases of `kraken_rewrite::process::derive_cases`, no generated
cases: argv, stdin) with the exit status, stdout and stderr of the x86-64 build `bin/<name>-O0`
(`stdout_hex`/`stdin_hex` instead when not UTF-8). None of the four programs reads its arguments
or input, so every case prints the baseline output. `crates/kraken-rewrite/tests/corpus_expected.rs`
checks the cases still match `derive_cases` and that the x86-64 `-O0` and `-O2` builds still give
these results; `KRAKEN_CORPUS_BLESS=1` rewrites the files.

Ghidra fixtures (`<set>/fixtures/`, `kraken-record --corpus corpus/<set>`): real Ghidra 12.2 imports all 68 binaries (languages
`ARM:LE:32:v8`, `AARCH64:LE:64:v8A`, `RISCV:LE:64:default`, and `RISCV:LE:32:AndeStar_v5` for
riscv32, which is what Ghidra's ELF loader picks for these files). Recording all of them would
take about 25 MB, so like the PE set only a subset is committed: per Linux set
`switch_vm-<set>-O0`, `switch_vm-<set>-O2-stripped`, `pie_list-<set>-O2` and
`stripped_calc-<set>-O0-stripped` with `--function-cap 32` (all functions of these dynamic
binaries), plus `switch_vm-arm32-thumb-O2`; for riscv32 `switch_vm-riscv32-O0` and
`pie_list-riscv32-O2-stripped` with `--function-cap 16` (the program and `linux_rt.c`; picolibc's
`vfprintf` and friends follow and are large). 15 fixtures, 5.6 MB.

`crates/kraken-host/tests/cross_corpus.rs` checks that every binary is present, matches its
set's `MANIFEST.sha256` and has truth, and that `binary_probe` reports an ELF executable of the
right processor (`ARM`, `AArch64`, `RISC-V 64`, `RISC-V 32`), width and endianness.

## The cross-architecture library set (`xlib/`)

libkr of the library set (`lib/src`) for the four cross targets, `-O2 -g -fPIC`, built in the
`cross` stage: `xlib/bin/kr-<set>.o` (`kr_core.c`), `xlib/bin/libkr-<set>.a` (both objects) and,
for the Linux targets, `xlib/bin/libkr-<set>.so`. ARM is Thumb-2 (the armhf default) with one
A32 object besides, `kr-arm32-a32.o`; riscv32 uses the bare-metal compiler with picolibc's
headers and has no shared library. Truth: `python3 -I corpus/tools/groundtruth_lib.py --set xlib`
(the processor from the ELF header; ARM shared-library entries keep the Thumb bit of their
symbols). `crates/engine-native/tests/libraries.rs` opens all twelve.

## Rebuild

```
corpus/build.sh [elf] [pe] [elf32] [lib] [arm32] [aarch64] [riscv64] [riscv32] [xlib]
                                                     # needs docker; builds image, compiles in container
python3 -I corpus/tools/groundtruth.py               # host, stdlib only; needs binutils (readelf, nm)
python3 -I corpus/tools/groundtruth.py --set elf32   # likewise arm32, aarch64, riscv64, riscv32
python3 -I corpus/tools/groundtruth_pe.py            # host binutils with PE support (nm, objdump)
python3 -I corpus/tools/groundtruth_lib.py           # host binutils with PE support (readelf, objdump, ar)
python3 -I corpus/tools/groundtruth_lib.py --set xlib  # host readelf, objdump, ar
```

With no set named, all nine are built. The PE and 32-bit sets were added with a second
Containerfile layer (`gcc-mingw-w64-*-win32`, `gcc-multilib`), so the first layer and the ELF set
built with it did not change; each set has its own `MANIFEST.sha256` and `TOOLCHAIN.txt`. The
cross-architecture sets came with a third layer (the Linux cross compilers and their
`libc6-dev-*-cross`, `gcc-riscv64-unknown-elf`, `picolibc-riscv64-unknown-elf`, `qemu-user`) in a
second Containerfile stage, `cross`: apt removes `gcc-multilib` when it installs the Linux cross
compilers (Debian declares them conflicting), so the elf, pe, elf32 and lib sets keep building in
the first stage, `native`, which is the image they were built in. Rebuilding those four in it gave
the committed binaries and `TOOLCHAIN.txt` files byte for byte.

`build.sh` uses `docker run --rm -v corpus:/work` as the invoking user. Deterministic flags:
`SOURCE_DATE_EPOCH=1704067200`, `-ffile-prefix-map=/work=.`, `-Wl,--build-id=none`, relative
source paths (DWARF names are `src/<file>`). A second build produced identical hashes
(`MANIFEST.sha256` covers bin/, src/, build.sh, Containerfile, groundtruth.py). The in-container
toolchain is recorded in `TOOLCHAIN.txt` on every build.

## Toolchain used for the committed binaries

- Base image: `debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f`
- gcc / g++ 14.2.0 (Debian 14.2.0-19; package `4:14.2.0-1`)
- binutils 2.44-3 (ld, strip), make 4.4.1-2, libc6-dev 2.41-12+deb13u4
- PE: gcc-mingw-w64-{x86-64,i686}-win32 14.2.0-19+27+b1, binutils-mingw-w64 2.44-3+12+b1,
  mingw-w64 runtime 12.0.0-5 (`pe/TOOLCHAIN.txt`)
- 32-bit ELF: gcc-multilib 4:14.2.0-1, libc6-dev-i386 2.41-12+deb13u4 (`elf32/TOOLCHAIN.txt`)
- arm32 / aarch64 / riscv64: gcc-14-{arm-linux-gnueabihf,aarch64-linux-gnu,riscv64-linux-gnu}
  14.2.0-19cross1, binutils 2.44-3, libc6-dev-{armhf,arm64,riscv64}-cross 2.41-11cross1
  (`<set>/TOOLCHAIN.txt`)
- riscv32: gcc-riscv64-unknown-elf 14.2.0+19, binutils-riscv64-unknown-elf 2.44-3+7+b1,
  picolibc-riscv64-unknown-elf 1.8.10-2 (`riscv32/TOOLCHAIN.txt`)
- qemu-user 1:10.0.13+ds-0+deb13u1 for the `QEMU-CHECK.txt` runs

Two builds of the PE, 32-bit and library sets gave identical hashes.

Packages are unpinned beyond the image digest, so rebuilding later may pull newer trixie
updates; check `TOOLCHAIN.txt` and the manifest diff.

Decision 78 also wants a "small source edit" variant of each program for mapping-precision
tests; that is not part of this first corpus drop.

## lang

`corpus/lang` holds small freestanding programs in other languages for name and metadata tests.
`rust_hello` (Rust, `no_std`) is built with legacy and v0 symbol mangling, with symbols and
stripped, by `corpus/lang/build.sh` using the host's `rustc` (no container). `legacy` needs
`RUSTC_BOOTSTRAP=1`, which the script sets.
