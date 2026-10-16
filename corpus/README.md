# KRAKEN test corpus

Small prebuilt x86_64 ELF programs with DWARF-derived ground truth (decisions 23, 65, 78).
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

## Rebuild

```
corpus/build.sh                       # needs docker; builds image, compiles in container
python3 -I corpus/tools/groundtruth.py   # host, stdlib only; needs binutils (readelf, nm)
```

`build.sh` uses `docker run --rm -v corpus:/work` as the invoking user. Deterministic flags:
`SOURCE_DATE_EPOCH=1704067200`, `-ffile-prefix-map=/work=.`, `-Wl,--build-id=none`, relative
source paths (DWARF names are `src/<file>`). A second build produced identical hashes
(`MANIFEST.sha256` covers bin/, src/, build.sh, Containerfile, groundtruth.py). The in-container
toolchain is recorded in `TOOLCHAIN.txt` on every build.

## Toolchain used for the committed binaries

- Base image: `debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f`
- gcc / g++ 14.2.0 (Debian 14.2.0-19; package `4:14.2.0-1`)
- binutils 2.44-3 (ld, strip), make 4.4.1-2, libc6-dev 2.41-12+deb13u4

Packages are unpinned beyond the image digest, so rebuilding later may pull newer trixie
updates; check `TOOLCHAIN.txt` and the manifest diff.

Decision 78 also wants a "small source edit" variant of each program for mapping-precision
tests; that is not part of this first corpus drop.
