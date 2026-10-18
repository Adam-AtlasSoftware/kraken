# KRAKEN test corpus

Small prebuilt x86_64 ELF programs with DWARF-derived ground truth (decisions 23, 65, 78), plus
two smaller sets: Windows PE images (`pe/`) and 32-bit x86 ELF programs (`elf32/`), see below.
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

## Rebuild

```
corpus/build.sh [elf] [pe] [elf32]    # needs docker; builds image, compiles in container
python3 -I corpus/tools/groundtruth.py               # host, stdlib only; needs binutils (readelf, nm)
python3 -I corpus/tools/groundtruth.py --set elf32
python3 -I corpus/tools/groundtruth_pe.py            # host binutils with PE support (nm, objdump)
```

With no set named, all three are built. The PE and 32-bit sets were added with a second
Containerfile layer (`gcc-mingw-w64-*-win32`, `gcc-multilib`), so the first layer and the ELF set
built with it did not change; each set has its own `MANIFEST.sha256` and `TOOLCHAIN.txt`.

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

Two builds of the PE and 32-bit sets gave identical hashes.

Packages are unpinned beyond the image digest, so rebuilding later may pull newer trixie
updates; check `TOOLCHAIN.txt` and the manifest diff.

Decision 78 also wants a "small source edit" variant of each program for mapping-precision
tests; that is not part of this first corpus drop.
