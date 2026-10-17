# Native engine, phases 1 to 3: notes

> Status: the design and the phase plan are in [ADR 0014](../../docs/design/0014-native-engine.md). This file records how the code works, what was measured and the traps found along the way.

The goal (decisions 5, 31, 52–55 and 95) is to load, list, disassemble and decompile ELF binaries with Ghidra's C++ decompiler and Sleigh built from source, and no JVM, behind the same engine traits as the Ghidra sidecar.

Code: `crates/engine-native-sys` (build, shim, bridge) and `crates/engine-native` (engine).

## Running it

```sh
cargo xtask native-src                 # once: ~80 MB download, SHA-256 checked, cpp/ + zlib/ extracted
cargo xtask native-sla                 # once: builds the Sleigh compiler, compiles x86 + AArch64 (~50 s)
cargo test -p engine-native-sys -p engine-native
cargo test -p engine-native --test native -- --ignored     # the whole-corpus sweep (about a minute)
cargo test -p engine-native --test agreement -- --ignored --nocapture   # agreement with Ghidra, all 20
KRAKEN_AGREEMENT_DIFF=1 KRAKEN_AGREEMENT_BINARIES=switch_vm-O0 \
  cargo test -p engine-native --test agreement -- --ignored --nocapture # and every disagreement
KRAKEN_NATIVE_AARCH64_BIN=/path/to/aarch64.elf cargo test -p engine-native aarch64
```

- **Inputs:** the tests need the cached sources (a build-time input) and a Sleigh spec tree: the one `cargo xtask native-sla` compiles (`~/.cache/kraken-dev/native-sla/Ghidra_12.1.4_build`), `KRAKEN_NATIVE_SPECS`, `KRAKEN_GHIDRA_HOME`, or the newest Ghidra install under `~/.cache/kraken-dev/ghidra`, in that order.
- **Missing inputs:** if either is missing the tests print `skipped: …` and pass, the same way the sys crate builds a stub without its sources. `KRAKEN_NATIVE_STUB=1` forces the stub. The `require-native` feature makes missing sources a build error.
- **Build time:** the first build compiles about 80 Ghidra C++ files, which takes about 40 s on 16 threads. The C++ is always built at `-O2`, so debug test runs decompile at full speed.

## What was measured

| Check | Result |
|---|---|
| Truth recall, `pie_list-O0`, `switch_vm-O0` | 100% with symbols, 100% with the symbol table ignored, 100% on the `-stripped` builds |
| Against Ghidra's recorded fixture (same two binaries) | 44/44 functions match Ghidra on entry, name, size and body SHA-256 (`fn_hash`) |
| Whole corpus (20 binaries) | 100% recall on every non-stripped build. `-O0-stripped`: 99 to 100%. `-O2-stripped`: 75 to 100% |
| Decompile every listed function (16 dynamically linked binaries) | No failures, every token span valid. `cpp_shapes-O0` (375 functions) takes about 0.2 s in release |
| `cmp_id` | `int cmp_id(int *param_1,int *param_2) { return *param_1 - *param_2; }`. Ghidra with DWARF prints `int cmp_id(record *a,record *b) { … return a->id - b->id; }`. The shape is the same: an `int` result, two pointer parameters and one subtraction |
| Contract suite (`kraken_engine::testing`) | Passes for `pie_list-O0` and `switch_vm-O0`. The engine provides loader, listing, decompile, memory and disassembly; mutation, types, xrefs, cfg, strings and symbols are absent, so their sections are skipped |
| AArch64 | A zig-built static musl binary loads as `AARCH64:LE:64:v8A`, and `cmp_id` decompiles correctly |

Where `cpp_shapes` sizes differ from the truth, the cause is exception landing pads. They are reached only through `.gcc_except_table`, which discovery does not read yet (phase 2). Ghidra needs its GCC exception analyzer for the same code.

## Traps and how the code avoids them

- **Ghidra exceptions bypass cxx.** `LowlevelError` and `DecoderError` do not derive from `std::exception`. Every shim entry point runs through `guarded()`, which rethrows them as `std::runtime_error`, so `cxx` turns them into `Err`.
- **Shared translators.** `SleighArchitecture` keeps one `Sleigh` per language in a static map and re-points it at the newest architecture's load image and context. Two sessions for the same language would fight over it. `KrakenArchitecture::buildTranslator` creates a private `Sleigh` instead. `Session::Impl` declares it before the architecture so it is destroyed last. Address spaces are refcounted, so the ownership is otherwise clean. The `two_sessions_coexist` test covers this.
- **Global state.** Capability registries, the language list and static caches are process-wide. Every FFI call takes one lock in `engine-native-sys`. That costs nothing now and removes a class of bugs.
- **Static capability registration.** Decompiler capabilities register themselves from static constructors. The archive is linked with `+whole-archive` (through `cc`'s `link_lib_modifier`, because emitting our own `rustc-link-lib` conflicts with `cc`'s). For the same reason the source list leaves out anything with external dependencies (BFD, the console).
- **Pretty printer internals.** `EmitPrettyPrint` keeps its low-level emitter private. `KrakenPrintC` subclasses `PrintC` and replaces the protected `emit` with `TokenEmit`, which writes text directly and records spans. Lines are not wrapped at 100 columns; editors can wrap. `tagLine` must call `emitPending()`, or `if`/`else` braces go missing.
- **Call targets after heritage.** Input 0 of a `CALL` op points into the `fspec` space by then, not `ram`. `FuncCallSpecs::getFspecFromConst` gives the callee's entry address.
- **Renames.** `ScopeInternal::renameSymbol` renames the symbol but not the `Funcdata` the decompiler prints. `add_function` removes the old symbol and adds a new one instead. Discovery also registers every known name before it runs any decompiler flow, because the switch analysis creates functions on the way.
- **Switch recovery is cheap without a full decompile.** `Funcdata::startProcessing()` follows the flow, and that alone recovers jump tables, each on a partial copy. A full decompile per function with a computed jump made opening a static glibc binary take about 35 s; with `startProcessing()` it takes about 9 s. Stubs whose jump loads the target from a fixed slot are skipped. Most of the remaining cost is genuine `jmp reg` dispatch in glibc.
- **Core type names.** Without a `<coretypes>` tag the library names types `int4`, `uint8` and `xunknown4`. `buildCoreTypes` registers Ghidra's Java-side names (LP64).
- **GCC 16 warnings.** cc's `-Wall -Wextra` floods the output with Ghidra header warnings. Ghidra's directory is included as `-isystem` for the shim, warnings are off for Ghidra's own files, and a `-Wmaybe-uninitialized` false positive in cxx's generated `Vec` constructors is silenced.
- **The source archive layout.** GitHub's tarball has a `ghidra-Ghidra_12.1.4_build/` prefix, so `decompile/cpp` needs `--strip-components=6`. GitHub may regenerate archives. A hash mismatch stops `native-src` with instructions, and it never updates the pin silently.

## Not done yet (see the ADR's phases)

- mutation (renames, comments, function create/delete) from the edit log
- PE, Mach-O and 32-bit x86
- DWARF types and a demangler
- engine selection in `kraken-host`

Phase 1 also listed xrefs, CFG, strings, symbols, types, the analyzer job, landing pads, noreturn propagation, decompiler timeouts and compiling the `.sla` files; phase 2 below covers them.

## Phase 2: how it works

- **References** (`refs.rs`) are built once at load from every body instruction. The shim tags each address an instruction mentions: an address-sized constant (`lea`, `mov r64, imm64`) is `data`, a direct or constant-pointer memory input is `read`, an output is `write`, and a 32-bit constant in a fixed-address image is weak `data`. Branch targets give `jump`, call targets `call`, a jump to another function's entry `call`, and switch entries `jump` from the computed jump. Ghidra's constant propagation also refers to an address from the instruction that next copies or addresses through the register it was loaded into (`lea rax,[s]; mov rsi,rax`); the shim reports each instruction's register reads and writes so the index does the same within a block (copies and memory operands only, not compares). Relocated pointer slots in data are `data` references, and the straight-line PLT code the GOT points at before binding (`push n; jmp PLT0`) is indexed too, which gives PLT0 its callers.
- **CFGs** (`cfg.rs`) copy `SimpleBlockModel`: calls end blocks, a recovered switch's computed jump gets a block of its own, landing pads start blocks, and an instruction that branches to itself (Sleigh's `HLT`) has no self-edge.
- **Strings** (`strings.rs`): ASCII/UTF-8 and UTF-16LE (two-byte aligned, plain text only), zero-terminated, in initialized non-executable blocks. `.dynstr` entries are `utf8`, as Ghidra's ELF loader defines them. At a data-reference target any 7-bit run counts, which finds the bytecode program `switch_vm` passes around, as Ghidra's defined data does.
- **Imports and exports** (`symbols.rs`): an import's address is its PLT stub (Ghidra uses a synthetic `EXTERNAL` block for the others; we leave them addressless). Exports are global and weak definitions plus the entry and the init/fini functions; the name at an address is its first typed symbol in symbol-table order (`completed.0` over `__TMC_END__`, `data_start` over `__data_start`), with version suffixes (`stderr@GLIBC_2.2.5`) dropped.
- **Types** (`typestore.rs`, `ctypes.rs`, `libc.rs`): the decompiler's own C grammar does the parsing, so the Rust side only renders C in the decompiler's core type names. Two quirks of that grammar: it has no `unsigned` (so `uint`, `ulong`), and `struct name` does not refer back to a struct from an earlier declaration, so composites are referred to by plain name. A prototype must end in `;`.
- **The decompile limit** uses `Action::setBreakPoint(break_start, name)` on every action of the `decompile` root (the action list is reached through a member pointer of a derived class). The `jumptable` root used by switch recovery is a separate clone and keeps no break points, since its caller does not resume partial runs. After an abandoned run `clearAnalysis` and the next `reset` leave no state behind (the smoke test decompiles again and compares).
- **Cancellation** raises the session's stop flag (an `AtomicBool` the load-image callback object owns) from a watcher task; one decompile runs per program at a time, so the flag only stops its own.

## Phase 2: what was measured

| Check | Result |
|---|---|
| Truth recall, all 20 corpus binaries | 100% on every one, stripped and `-O2` included (phase 1: 75–100% on `-O2` stripped) |
| `cpp_shapes-O0` sizes against the symbol table | all 330 equal, landing pads included |
| `switch_vm-O2` `vm_run` | 1025 of 1112 bytes (phase 1: 114) once `vm_fail` is known not to return; the rest is alignment padding inside the function |
| Compiled `.sla` vs Ghidra 12.1.4's | byte-identical, all five (x86, x86-64, AARCH64, AARCH64BE, AppleSilicon) |
| `cmp_id` with a user prototype | `int cmp_id(record *a,record *b)` … `return a->id - b->id;`, Ghidra-with-DWARF's shape |
| Decompile limit of 1 ms on `vm_run` | `timeout`; the next decompile is complete |
| Contract suite | passes with every capability but mutation, on `pie_list-O0` and `switch_vm-O0` |

Agreement with the Ghidra fixtures (recall over Ghidra's recorded data, precision over ours in brackets):

| Fixtures | Functions | Bodies | CFG identical | CFG edges | Xrefs into the image | Callers | Strings |
|---|---|---|---|---|---|---|---|
| `pie_list-O0` | 100% | 100% | 100% | 100% | 100% (100%) | 100% | 100% |
| `switch_vm-O0` | 100% | 100% | 100% | 100% | 100% (90%) | 100% | 100% |
| `cpp_shapes-O0` | 100% | 92% | 92% | 99.8% | 100% (88.5%) | 100% | 100% |
| `static_strops-O0-stripped` | 96.9% | 95.7% | 84.9% | 88.9% | 83.8% (95.7%) | 98.9% | 96% |
| all 20 (1100 functions) | 98.3% | 94.4% | 90.0% | 95.0% | 93.1% (91.6%) | 99.3% | 97.1% (98.4%) |

Imports agree by name except in C++ binaries (Ghidra demangles), exports 100% on the C binaries and low on C++ and static ones (demangled names; Ghidra lists more entry points in static glibc). The `cpp_shapes` body differences are the landing pads Ghidra leaves out; the stripped static gap is mostly references from code Ghidra reaches later (IFUNC resolvers, switch bodies).

## Phase 2: traps

- **Switch recovery before noreturn is known.** With `vm_fail` not yet marked, the decompiler followed flow past its call into `op_name` and returned `op_name`'s table for `vm_run`, and `vm_run`'s own table failed ("too many branches"). Jump tables of callers are now recovered again when a callee becomes noreturn.
- **`REP STOSQ` looks like a jump.** Sleigh models the repeat as a `CBRANCH` to the next instruction and a `BRANCH` back to itself. An instruction with both is now a fall-through, which fixed a CFG and xref mismatch.
- **`jmp [rip+X]` has no `LOAD`.** Sleigh gives the slot as a direct memory operand, so stubs were taken for switches and sent to the (expensive) switch analysis. A `BRANCHIND` through a memory operand is now a stub.
- **The return address a call pushes** is an address-sized constant in p-code (`STORE [RSP], inst_next`), and was reported as a data reference.
- **Static PLT entries** carry IRELATIVE relocations, not symbols, sit 8 bytes apart, and live in `.rela.plt` outside the dynamic relocations. They are named after the IFUNC symbol at the resolver, as Ghidra names them, so jumps to them are tail calls instead of growing the caller's body.
- **Noreturn without names.** A stripped static binary has no `exit` to start from. Ghidra's discovered-noreturn evidence (a call followed by another function's entry) needs no names and took the stripped static bodies from 58% to 96% agreement.
- **Ghidra artifacts in the fixtures**, not engine errors: imports in a synthetic `EXTERNAL` block at the end of the image; no operand references in code its switch analysis reached late (`switch_vm` case bodies), where we have them; C++ landing pads left out of bodies; demangled names on C++ exports; references to addresses between sections (`__TMC_END__` in `switch_vm`).

## Phase 3: the confined worker

- **Shape.** `NativeEngine` (`src/native.rs`) routes every capability call either to an `InProcessEngine` (the phase 2 engine, renamed) or to `WorkerEngine` (`src/worker/client.rs`), which speaks to `kraken-native-worker` (`src/bin/`, server in `src/worker/serve.rs`). The worker runs an `InProcessEngine`, so the split is above `Session` and the image callback stays local to the worker. Methods are named after the trait methods, plus `open`, `stats`, `lift`, `cancel` and, with `--test-hooks`, `test_hang`, `test_crash` and `test_probe`. Every request carries an `op` number for `cancel`; analysis progress uses the sidecar `progress` notification.
- **Worker lifetime.** A worker is started by `open_binary`, since Landlock's read-only set has to name the binary, and lives until the next open or until it dies. `stats()` and `lift()` became `async` for this.
- **Watchdog** (see the ADR): hard deadlines per request; a timeout or a crash gives a structured error with a `worker` detail, and the next request restarts the worker, re-opening the program and replaying the type definitions. Defaults: 60 s per request, 600 s for open, decompile limit + 5 s, 2 s cancel grace.
- **Trap: core dumps.** The first crash test was flaky: with `systemd-coredump` as `core_pattern` the aborted worker kept its socket open while the core was written, and the request ran into the 3 s deadline instead of seeing a closed channel. The worker now sets `PR_SET_DUMPABLE` to 0 at start (`WorkerOptions::core_dumps` turns that off), which also keeps test crashes out of the coredump store.
- **Trap: the binary path.** The worker may read only the binary itself, so the parent canonicalizes the path before opening (a symlink elsewhere would be refused by Landlock).
- **Measured** (debug build, pie_list-O0): `native.rs` takes 0.85 s in worker mode against 1.8 s in-process on the same machine, so the process boundary adds no visible cost (each test engine gets its own worker, so the in-process run serializes on the process-wide library lock where workers do not). The probe inside the worker gets `EACCES` for TCP connect and bind, UDP, IPv6 and `socket(AF_UNIX)`, and for reading `/etc/passwd`; only the inherited channel and `socketpair(AF_UNIX)` work.
- **Tests:** `tests/native.rs` and `tests/agreement.rs` run in worker mode (`KRAKEN_NATIVE_TEST_IN_PROCESS=1` switches `native.rs` back), and the contract suite runs in both modes. `tests/worker.rs` covers confinement, the hard deadline (with type replay), crashes (twice in a row), hard cancellation, and clean errors with nothing open or no worker binary.
