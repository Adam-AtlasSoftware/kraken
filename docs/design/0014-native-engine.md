# 0014. The native engine

Status: Accepted (phase 1 done; phase 2 done for x86-64 ELF)
Date: 2026-10-17

## Context

ADR 0001 chose a Ghidra sidecar first and a native engine later, behind the same capability traits. Decision 95 moves the native (JVM-free) backend up: Linux feature-completeness comes first, and a KRAKEN that needs no JVM is part of that. Windows follows on the same code, and macOS later.

Ghidra's decompiler and its Sleigh lifter are C++ (Apache-2.0) and build without the rest of Ghidra; the Makefile has `libdecomp.a` and `libsla.a` targets. What the Java side normally supplies has to come from the host: an `Architecture` with a `LoadImage` (bytes), a `Scope` (symbols), core types, and a way to get the output out. rz-ghidra (LGPL-3.0) shows that this glue works without a JVM. We use it as a reference only and copy nothing from it.

The parts that exist only in Java (loaders, the program database, auto-analysis, the data type manager, FID, the demanglers) have to be rewritten in Rust over time. Each can land separately because the engine is a set of traits.

## Decision

### Crates

- **`engine-native-sys`** builds Ghidra's decompiler core and Sleigh from the pinned source (tag `Ghidra_12.1.4_build`). `cargo xtask native-src` downloads GitHub's source archive, checks its SHA-256 (`2a858300…6cec`, recorded in `xtask/src/native_src.rs`), and extracts only `Ghidra/Features/Decompiler/src/decompile/{cpp,zlib}` and Ghidra's `LICENSE` into `~/.cache/kraken-dev/ghidra-src/Ghidra_12.1.4_build`. `build.rs` compiles the Makefile's CORE, DECCORE and SLEIGH sets plus `sleigh_arch` and `inject_sleigh` as C++17 with the `cc` crate, and the bundled zlib with `LOCAL_ZLIB`/`NO_GZIP` (Ghidra's own Windows build does the same). It leaves out the console, Ghidra-protocol, BFD and sleigh-compiler files, so the archive has no system dependencies. `KRAKEN_GHIDRA_SRC` points it at another copy. Without the sources, `build.rs` builds a stub whose `available()` is false and prints how to fetch them. The `require-native` feature makes that a build error, and `KRAKEN_NATIVE_STUB=1` forces the stub. Workspace builds therefore never fail for want of the cache, and so far only Linux builds the native library; `cxx` is a Linux-only dependency, so the stub needs no C++ toolchain on other targets.
- **A C++ shim** (`shim/kraken_shim.{hh,cc}`, our own code, GPL-3.0-or-later) is bridged with `cxx`. It contains:
  - `KrakenArchitecture`, a `SleighArchitecture` subclass. Its `LoadImage` reads bytes through a Rust callback, with read-only ranges for constant propagation.
  - The default global scope, fed with function symbols from Rust.
  - Ghidra's core type names (`int`, `uint`, `undefined8`, …).
  - A `PrintC` whose emitter writes plain text and records token spans: kind, symbol, target address and varnode. That gives decision 55's text plus token map without parsing markup.
  - Entry points: decode and flow-classify instructions, lift a range to raw p-code, decompile a function, and recover a function's switch tables with the decompiler's flow analysis.
  - Phase 2 adds: typed references per instruction (address-sized constant, read, write, narrow constant) and the registers its p-code reads and writes; jump tables as (computed jump, target) pairs; C declarations and prototypes parsed by the decompiler's own C grammar (`parse_C`, `parse_protopieces`) into its type factory and onto functions as locked prototypes; noreturn flags; and a decompile limit (below).

  Each session owns a private `Sleigh` translator. The base class would share one per language, which would tie sessions together. Ghidra exceptions are rethrown as `std::runtime_error` so they reach Rust as errors.
- **`engine-native`** implements every read capability: `Loader` (ELF through the `object` crate, `.eh_frame` through `gimli`), `Analyzer`, `FunctionLister`, `Decompiler`, `TypeStore`, `Disassembler`, `MemoryReader`, `XrefProvider`, `FlowGraph`, `StringLister` and `SymbolLister`. Only `Mutator` is absent. A position-independent ELF linked at 0 is loaded at 0x100000, as Ghidra does, so addresses and anchors match Ghidra projects of the same binary. The `fn_hash` uses Ghidra's definition (SHA-256 of the body bytes in address order) and the size uses Ghidra's (the number of body addresses).
- **Run-time inputs:** only Sleigh specification files: `.ldefs`, `.pspec`, `.cspec` and compiled `.sla`. `cargo xtask native-sla` builds Ghidra's Sleigh compiler from the same pinned archive (the Makefile's `sleigh_opt` set: CORE, SLEIGH and SLACOMP, plus the bundled zlib) with the system C++ compiler, and compiles the x86 and AArch64 `.slaspec` files into `~/.cache/kraken-dev/native-sla/Ghidra_12.1.4_build`, laid out like an install. All five compiled `.sla` files are byte-identical to the ones Ghidra 12.1.4 ships. The engine looks in `KRAKEN_NATIVE_SPECS`, then that tree, then `KRAKEN_GHIDRA_HOME`, then the newest install under `~/.cache/kraken-dev/ghidra`. No JVM is started, and no Ghidra install is needed.

### Function discovery

Discovery is seeded with these:

- defined function symbols
- the entry point (named `entry` when it has no symbol)
- PLT stubs, named after the GOT slot their `jmp [rip+disp]` reads
- pointers in `.init_array`, `.fini_array` and `.preinit_array`, and `DT_INIT`/`DT_FINI`, named `_INIT_<n>`, `_FINI_<n>`, `_DT_INIT` and `_DT_FINI` when no symbol names them (Ghidra's names)
- the start of `.plt`, and in static binaries the IRELATIVE PLT entries, named after the IFUNC symbol at the resolver
- every `.eh_frame` FDE start (phase 2): FDEs exist in stripped binaries too, one per function or separated part (`main.cold`)

Recursive descent follows Sleigh's p-code flow: branch, conditional branch, call, return, computed jumps and calls. Calls to functions that never return end a block. A jump to another function's entry is a tail call. A computed jump that does not load its target from a fixed slot (so it is not a stub) triggers the decompiler's flow analysis. That analysis recovers jump tables on a partial copy of the function, and their targets join the body. The landing pads an FDE's LSDA lists in `.gcc_except_table` join the body of the function at the FDE start; nothing else reaches them.

Noreturn propagation runs discovery in rounds. Functions start out noreturn by name (`exit`, `abort`, `__cxa_throw`, …). After a round, two rules add more: a function none of whose paths returns, and that calls or tail-calls a noreturn function, is noreturn; and a callee is noreturn when a call to it is followed, past alignment padding, by another function's entry (the evidence Ghidra's discovered-noreturn analysis uses, which needs no names). The decompiler learns each new mark, the jump tables of affected callers are recovered again, and discovery reruns until the set stops growing.

After the calls are exhausted, two kinds of address are tried as function starts if they lie in code that no body covers yet:

- address-sized constants in instructions (`lea` of a function, `main` passed to `__libc_start_main`)
- pointers in data (relative-relocation addends, or aligned words for fixed-address images)

On the corpus:

- Truth recall is 100% on all 20 binaries, stripped and `-O2` builds included (phase 1: 75 to 100% on the `-O2` stripped ones).
- For `pie_list-O0` and `switch_vm-O0`, all 44 functions Ghidra recorded have the same entry, size and body hash.
- With landing pads, every `cpp_shapes-O0` function has its symbol-table size.

### Program data (phase 2)

- **References** come from the decoded instructions of every body: calls and jumps from branch targets (a tail call counts as a call), switch-table entries, reads and writes of absolute and RIP-relative memory, taken addresses (`lea`), and, like Ghidra's constant propagation, the next instruction that copies or addresses through a register loaded with an address. Pointers in relocated data slots and the lazy-binding PLT code the GOT points at are indexed too.
- **CFGs** follow Ghidra's `SimpleBlockModel`: a block ends at every flow change, calls included, and starts at branch, switch and landing-pad targets and at a recovered switch's computed jump. Edges are `fallthrough`, `jump`, `conditional_true`/`conditional_false` and `switch`; a call to a noreturn function has no fall-through edge.
- **Strings** are zero-terminated ASCII/UTF-8 and UTF-16LE runs in initialized non-executable blocks; at an address code refers to, any 7-bit run counts, as Ghidra defines strings at data references.
- **Imports and exports** mirror Ghidra's external symbols (address = PLT stub) and external entry points (global and weak definitions, the entry point, init/fini functions), one name per address.
- **Types.** The type store keeps definitions in the neutral model and mirrors them into the decompiler as C declarations in its core type names (`uint`, `undefined8`, `code`); a pointer to a type not defined yet becomes `void *`, and definitions that cannot go in yet wait and are retried. About 240 glibc and C++ runtime prototypes (`libc.rs`) are applied by name to PLT stubs and statically linked functions, so `printf(0x102004,n)` reads `printf("%d\n",n)`; a user prototype on a local function changes its own output (`int cmp_id(record *a,record *b) { return a->id - b->id; }`).
- **The analyzer job** reports `load`, `core` (references, symbols, the string scan) and `expensive` (every function through the decompiler, filling in signatures), with progress per function and cancellation between and inside decompiles.
- **Decompile limit.** The shim sets a start break point on every action of the decompile's action tree (the break points the decompiler's console uses for stepping). `Action::perform` then returns at the start of each action and resumes on the next call, so the shim checks the deadline and a stop flag between actions; past the deadline it abandons the function (`timeout`), and a raised stop flag abandons it as `cancelled`. A single long action (one pass of a rule pool on a huge function) is not split, so the limit is cooperative; phase 3's watchdog makes it hard.

Agreement with the Ghidra fixtures (`tests/agreement.rs`, recall over what Ghidra recorded, precision over ours):

- `pie_list-O0` and `switch_vm-O0` (guarded by the test): functions, bodies, CFGs (blocks, edges and kinds), callers, strings, imports and exports 100%; outgoing references 100% of those that point into the image (Ghidra's other references point into its synthetic `EXTERNAL` block), at 100% and 90% precision.
- All 20 fixtures (1100 functions): functions 98.3%, bodies 94.4%, identical CFGs 90.0% (edges 95.0%), references into the image 93.1% (precision 91.6%), callers 99.3%, strings 97.1% (precision 98.4%).

### In-process now, confined child later

Phase 1 runs the decompiler in the engine's process (in practice, `krakend`). The library keeps global state and is not thread-safe, so every call takes one process-wide lock in `engine-native-sys`, and the engine runs calls on blocking threads.

The design keeps a later move cheap. The engine only uses the `Session` API (bytes in through a callback, plain values out), and the engine traits are the boundary everyone else sees. Phase 3 moves `Session` behind the sidecar plumbing that `kraken-sidecar` already provides: socketpair JSON-RPC, Landlock, seccomp, netns, and supervision. The image callback then becomes a request back to the parent, or a read-only shared mapping.

## Phases

1. **Done:** source fetch and build, shim, ELF loader, discovery, decompile with tokens, disassembly, memory, Sleigh lifting (`NativeEngine::lift`), and the contract-suite subset. x86-64, with AArch64 working on a hand-built binary.
2. **Feature parity for the read side.** Done for x86-64 ELF: xrefs, CFG, strings, imports and exports, the type store fed to the decompiler, library prototypes, landing pads, noreturn propagation, the analyzer job, the decompile limit, and the `.sla` compiled from the pinned sources. The whole contract suite except mutation passes. Left for a phase 2b: PE and Mach-O loaders through `object`, 32-bit x86, DWARF types, a demangler (Ghidra shows demangled C++ names), and decompiler options beyond the limit.
3. **Confinement:** `Session` moves into a confined child process (`kraken-native-worker`) under the existing sidecar spawner. A crash or hang in C++ then costs one decompile, not the daemon. A watchdog gives real timeouts and cancellation.
4. **Mutation and the host:** `Mutator` (renames, comments, function create/delete, types) applied from the edit log as the .NET engine does, plus `kraken-host` engine selection with Ghidra/native/auto per project recorded in `meta.json`. `THIRD-PARTY-NOTICES.md` gains the Ghidra decompiler (Apache-2.0) and zlib notices once a shipped binary links the library.
5. **Windows:** build with MSVC or clang-cl (the `cc` crate already handles that; Ghidra's own build has the flags), then decide whether the native engine becomes the default.

## Consequences

- KRAKEN can load, analyze, list, disassemble and decompile ELF binaries, and answer xref, CFG, string, symbol and type queries, with no JVM and no Ghidra install. Decompiling is fast: the 375 functions of `cpp_shapes-O0` take under 0.4 s.
- Building the library takes about 40 s of parallel C++ compilation once per profile. CI without the cached sources builds the stub and skips the native tests.
- Until phase 3, a decompiler crash takes the process with it. A cancelled or overlong decompile stops at the next action break point, not at once. Decompiles are serialized process-wide.
- Without DWARF, local functions show inferred types (`int *param_1`) until a prototype is defined in the type store; library calls are typed from the prototype table.
- Where the native engine and Ghidra disagree on the corpus, it is mostly by design or a Ghidra artifact: Ghidra gives imports addresses in a synthetic `EXTERNAL` block, makes no operand references in code its switch analysis reaches late, leaves landing pads out of C++ bodies, and shows demangled names.
- Static binaries open slowly: about 10 s each in a debug build, almost all of it spent in the decompiler's switch recovery for glibc functions.

## Alternatives considered

- **Hand-written `extern "C"` instead of `cxx`.** Fewer dependencies, but more unsafe code on our side. `cxx` (MIT/Apache-2.0) checks both sides of the boundary and passes `cargo deny`.
- **Parsing `EmitMarkup` output.** That is what the Java side does. It needs an XML or packed decoder on the Rust side for something the emitter can record directly.
- **The `libsla` crate for lifting only.** No decompiler, and the decompiler needs Sleigh anyway.
- **Pure-Rust decompiler ports** (koute/ghidra-decompiler, rsleigh). Too young (see ADR 0001).
- **Copying rz-ghidra's glue.** LGPL, and its structure is tied to rizin's analysis model. We read it for orientation only.
- **The child process from day one.** It would mean debugging the glue and the transport at the same time. The trait boundary keeps the move cheap later.
