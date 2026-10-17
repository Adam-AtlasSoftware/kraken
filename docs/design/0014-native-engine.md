# 0014. The native engine

Status: Accepted (phase 1 done)
Date: 2026-10-17

## Context

ADR 0001 chose a Ghidra sidecar first and a native engine later, behind the same capability traits. Decision 95 moves the native (JVM-free) backend up: Linux feature-completeness comes first, and a KRAKEN that needs no JVM is part of that. Windows follows on the same code, and macOS later.

Ghidra's decompiler and its Sleigh lifter are C++ (Apache-2.0) and build without the rest of Ghidra; the Makefile has `libdecomp.a` and `libsla.a` targets. What the Java side normally supplies has to come from the host: an `Architecture` with a `LoadImage` (bytes), a `Scope` (symbols), core types, and a way to get the output out. rz-ghidra (LGPL-3.0) shows that this glue works without a JVM. We use it as a reference only and copy nothing from it.

The parts that exist only in Java (loaders, the program database, auto-analysis, the data type manager, FID, the demanglers) have to be rewritten in Rust over time. Each can land separately because the engine is a set of traits.

## Decision

### Crates

- **`engine-native-sys`** builds Ghidra's decompiler core and Sleigh from the pinned source (tag `Ghidra_12.1.4_build`). `cargo xtask native-src` downloads GitHub's source archive, checks its SHA-256 (`2a858300…6cec`, recorded in `xtask/src/native_src.rs`), and extracts only `Ghidra/Features/Decompiler/src/decompile/{cpp,zlib}` and Ghidra's `LICENSE` into `~/.cache/kraken-dev/ghidra-src/Ghidra_12.1.4_build`. `build.rs` compiles the Makefile's CORE, DECCORE and SLEIGH sets plus `sleigh_arch` and `inject_sleigh` as C++17 with the `cc` crate, and the bundled zlib with `LOCAL_ZLIB`/`NO_GZIP` (Ghidra's own Windows build does the same). It leaves out the console, Ghidra-protocol, BFD and sleigh-compiler files, so the archive has no system dependencies. `KRAKEN_GHIDRA_SRC` points it at another copy. Without the sources, `build.rs` builds a stub whose `available()` is false and prints how to fetch them. The `require-native` feature makes that a build error, and `KRAKEN_NATIVE_STUB=1` forces the stub. Workspace builds therefore never fail for want of the cache, and so far only Linux builds the native library.
- **A C++ shim** (`shim/kraken_shim.{hh,cc}`, our own code, GPL-3.0-or-later) is bridged with `cxx`. It contains:
  - `KrakenArchitecture`, a `SleighArchitecture` subclass. Its `LoadImage` reads bytes through a Rust callback, with read-only ranges for constant propagation.
  - The default global scope, fed with function symbols from Rust.
  - Ghidra's core type names (`int`, `uint`, `undefined8`, …).
  - A `PrintC` whose emitter writes plain text and records token spans: kind, symbol, target address and varnode. That gives decision 55's text plus token map without parsing markup.
  - Entry points: decode and flow-classify instructions, lift a range to raw p-code, decompile a function, and recover a function's switch tables with the decompiler's flow analysis.

  Each session owns a private `Sleigh` translator. The base class would share one per language, which would tie sessions together. Ghidra exceptions are rethrown as `std::runtime_error` so they reach Rust as errors.
- **`engine-native`** implements `Loader` (ELF through the `object` crate), `FunctionLister`, `Decompiler`, `Disassembler` and `MemoryReader`. A position-independent ELF linked at 0 is loaded at 0x100000, as Ghidra does, so addresses and anchors match Ghidra projects of the same binary. The `fn_hash` uses Ghidra's definition (SHA-256 of the body bytes in address order) and the size uses Ghidra's (the number of body addresses). The other capabilities are absent until a later phase implements them.
- **Run-time inputs:** only the `.ldefs`, `.pspec`, `.cspec` and precompiled `.sla` files of a Ghidra install (`KRAKEN_GHIDRA_HOME`, else the newest copy under `~/.cache/kraken-dev/ghidra`). No JVM is started.

### Function discovery (phase 1)

Discovery is seeded with these:

- defined function symbols
- the entry point (named `entry` when it has no symbol)
- PLT stubs, named after the GOT slot their `jmp [rip+disp]` reads
- pointers in `.init_array`, `.fini_array` and `.preinit_array`
- the start of `.plt`

Recursive descent follows Sleigh's p-code flow: branch, conditional branch, call, return, computed jumps and calls. Calls to known no-return imports end a block. A jump to another function's entry is a tail call. A computed jump that does not load its target from a fixed slot (so it is not a stub) triggers the decompiler's flow analysis. That analysis recovers jump tables on a partial copy of the function, and their targets join the body.

After the calls are exhausted, two kinds of address are tried as function starts if they lie in code that no body covers yet:

- address-sized constants in instructions (`lea` of a function, `main` passed to `__libc_start_main`)
- pointers in data (relative-relocation addends, or aligned words for fixed-address images)

On the corpus this matches Ghidra exactly where it was measured:

- For `pie_list-O0` and `switch_vm-O0`, all 44 functions Ghidra recorded have the same entry, size and body hash.
- Truth recall is 100% for both, with or without the symbol table, and for their stripped builds.
- Across all 20 corpus binaries, recall is 100% for every non-stripped build and 75 to 100% for the -O2 stripped ones.

### In-process now, confined child later

Phase 1 runs the decompiler in the engine's process (in practice, `krakend`). The library keeps global state and is not thread-safe, so every call takes one process-wide lock in `engine-native-sys`, and the engine runs calls on blocking threads.

The design keeps a later move cheap. The engine only uses the `Session` API (bytes in through a callback, plain values out), and the engine traits are the boundary everyone else sees. Phase 3 moves `Session` behind the sidecar plumbing that `kraken-sidecar` already provides: socketpair JSON-RPC, Landlock, seccomp, netns, and supervision. The image callback then becomes a request back to the parent, or a read-only shared mapping.

## Phases

1. **Done:** source fetch and build, shim, ELF loader, discovery, decompile with tokens, disassembly, memory, Sleigh lifting (`NativeEngine::lift`), and the contract-suite subset. x86-64, with AArch64 working on a hand-built binary.
2. **Feature parity for the read side:**
   - Data:
     - xrefs from the decoded flow and refs
     - CFG from the body and flow
     - strings
     - imports and exports
     - a DWARF-free type store (`TypeStore`) seeded with the core types and fed to the decompiler through a custom `Scope` and `TypeFactory` entries
     - prototypes for imports
     - exception-handler landing pads (`.eh_frame`, `.gcc_except_table`), which `cpp_shapes` needs for full bodies
     - noreturn propagation
     - the `Analyzer` job
   - Formats and targets:
     - PE and Mach-O loaders through `object`
     - 32-bit x86
   - Decompiler control:
     - decompiler options, such as a timeout through the action break hooks
     - the `.sla` compiled from `.slaspec` with `sleigh_opt` built from the same sources, so not even a Ghidra install is needed
3. **Confinement:** `Session` moves into a confined child process (`kraken-native-worker`) under the existing sidecar spawner. A crash or hang in C++ then costs one decompile, not the daemon. A watchdog gives real timeouts and cancellation.
4. **Mutation and the host:** `Mutator` (renames, comments, function create/delete, types) applied from the edit log as the .NET engine does, plus `kraken-host` engine selection with Ghidra/native/auto per project recorded in `meta.json`. `THIRD-PARTY-NOTICES.md` gains the Ghidra decompiler (Apache-2.0) and zlib notices once a shipped binary links the library.
5. **Windows:** build with MSVC or clang-cl (the `cc` crate already handles that; Ghidra's own build has the flags), then decide whether the native engine becomes the default.

## Consequences

- KRAKEN can load, list, disassemble and decompile ELF binaries with no JVM. Decompiling is fast: the 375 functions of `cpp_shapes-O0` take under 0.4 s.
- Building the library takes about 40 s of parallel C++ compilation once per profile. CI without the cached sources builds the stub and skips the native tests.
- Until phase 3, a decompiler crash takes the process with it, and a cancelled decompile still runs to the end. Decompiles are serialized process-wide.
- Without DWARF and a type store, output uses inferred types (`int *param_1`), where Ghidra with DWARF shows `record *a`.
- Static binaries open slowly: a few seconds each, almost all of it spent in switch recovery for hundreds of libc functions.

## Alternatives considered

- **Hand-written `extern "C"` instead of `cxx`.** Fewer dependencies, but more unsafe code on our side. `cxx` (MIT/Apache-2.0) checks both sides of the boundary and passes `cargo deny`.
- **Parsing `EmitMarkup` output.** That is what the Java side does. It needs an XML or packed decoder on the Rust side for something the emitter can record directly.
- **The `libsla` crate for lifting only.** No decompiler, and the decompiler needs Sleigh anyway.
- **Pure-Rust decompiler ports** (koute/ghidra-decompiler, rsleigh). Too young (see ADR 0001).
- **Copying rz-ghidra's glue.** LGPL, and its structure is tied to rizin's analysis model. We read it for orientation only.
- **The child process from day one.** It would mean debugging the glue and the transport at the same time. The trait boundary keeps the move cheap later.
