# Native engine, phases 1 to 3 and the phase 4 mutator: notes

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

## Phase 4: the mutator

How it works is in the ADR (Mutation). Code: `crates/engine-native/src/mutate.rs`; the shim gained `remove_function`, `set_convention` and `set_comments`.

```sh
cargo test -p engine-native --test mutate                       # every op, save, reopen and replay
cargo test -p engine-native --test native contract_suite_subset # the contract suite, mutation included
cargo test -p kraken-e2e --test exit_criterion_native           # the exit-criterion flow, no JVM
```

| Check | Result |
|---|---|
| Contract suite, mutation section | passes on `pie_list-O0` and `switch_vm-O0` (rename visible in listing, decompiler text and tokens; stale `old_name`; managed anchors and newer schemas refused; scratch function created in `.rodata` with a body, decompiled, deleted; an original function deleted; watermarks advance) |
| `tests/mutate.rs` | rename (callers print `make_node(` for `node_new`), labels, plate/pre/end-of-line comments, `set_type` with a user struct (`int by_id(record *a,record *b)` … `a->id - b->id`), `MSABI`, a data item in `.rodata`, bounds and back, delete and create; a fresh engine over the saved state has all of it, and clearing the type goes back to `int by_id(int *param_1,int *param_2)` |
| `exit_criterion_native.rs` | the Ghidra flow's assertions plus: the decompiler shows `exit_first(int count)`, the prototype survives a reopen, the recreated function has the found size, the rebuilt engine directory reopens with the same names and signature; about 0.6 s |

- **In the worker.** Phase 4 was written against the in-process engine; on top of phase 3 the worker gained `apply` and `save`, `OpenParams` carries `state_dir`, and the confinement grants that one directory read-write. The parent's type list became a journal of ops and type definitions; after a restart it replays the entries past what `native-state.json` restored (the worker's `stats().edits` minus the count at open). `tests/worker.rs::edits_survive_a_crash_and_land_in_the_state_dir` checks a save, unsaved edits, a rejected op, two crashes and a fresh engine; `tests/mutate.rs` runs in worker mode (`KRAKEN_NATIVE_TEST_IN_PROCESS=1` for in-process).

- **In the host (4b).** `kraken-host`'s `NativeEngineFactory` builds the engine in worker mode with the project's engine directory as `state_dir` (`native_in_process` / `KRAKEN_NATIVE_IN_PROCESS` for in-process); `NativeProbe` also checks that `kraken-native-worker` can be found, so `auto` falls back to Ghidra without it and `kraken setup --native` asks for a rebuild with `-p engine-native`. `kraken-cli/tests/native_engine.rs` renames through the CLI and checks the new name in a new process.

### Traps

- **Renaming drops the prototype.** `add_function` replaces the symbol, so the new `Funcdata` has a default prototype. Every symbol rebuild applies the function's prototype, convention and noreturn mark again; library prototypes are kept for that in `Program::locked`.
- **Prototype names go through the C grammar.** A name with `::` or `@` (allowed for KRAKEN symbols) breaks `parse_protopieces`, so prototypes are parsed under a placeholder name; the printed name comes from the symbol.
- **Clearing a prototype** has no API: the function symbol is removed and added again.
- **Comment types.** The decompiler prints only the comment types its printer is told to (`setInstructionComment`); the default is `user2` (pre) and warnings. Ghidra's Java side maps end-of-line to `user1`, pre to `user2`, post to `user3` and plate to `header`; the shim shows all of them. User comments are replaced before every decompile (`clearType` on the user types only), so warnings the decompiler adds are not touched and comments follow function bodies through bounds edits.
- **What a reopen needs.** Replaying the journal alone is not enough: the analysed signatures (the analysis job's output) would be missing, and the registry's `rebuild` reported every function as `signature_changed`. The state file keeps them, and the analysis job writes it when it ends.
- **Undo markers.** The log undoes a `set_type` with no earlier type as `undefined`, a bounds change with no earlier bounds as the empty range at 0, and a rename with no old name as the empty name; each restores what the engine found.
- **Type definitions are not in the log.** `define_type` is an engine call, so the journal records definitions too; otherwise a prototype over a user struct came back as `void *` after a reopen.

## Phase 5: licensing, rebuilt references, C++ names, DWARF

How it works is in the ADR (Names, DWARF, rebuilt references and licensing). Code:
`crates/engine-native/src/{demangle,dwarf}.rs`, `Program::reindex` in `engine.rs`, aliases in
`typestore.rs`; `xtask/src/native_licenses.rs`.

```sh
cargo test -p engine-native --test mutate structural          # rebuilt references, exports, noreturn
cargo test -p engine-native --test native cpp_names           # demangled names, mangled kept, DWARF this
cargo test -p engine-native --test agreement -- --nocapture   # guarded binaries plus cpp_shapes-O0 names
cargo test -p xtask native_licenses                            # committed texts vs the pinned archive
```

| Check | Result |
|---|---|
| Names by entry, all 20 fixtures | 65.8% -> 89.2% (`cpp_shapes-O0` 7% -> 100%; the rest are static glibc aliases) |
| Imports / exports (addr, name), all 20 | 69.4% -> 100% / 36.9% -> 51.1% (`cpp_shapes-O0` exports 3.4% -> 100%) |
| Signatures (no spacing), all 20, before analysis | 0.6% -> 19.6%; `cpp_shapes-O0` 70%, and every DWARF function of the C binaries |
| `cpp_shapes-O0` open, debug, in-process | about 0.3 s, every DWARF type accepted by the decompiler (none pending) |
| One structural edit on `static_strops-O0`, debug | about 0.4 s (the whole index is rebuilt) |

### Traps

- **A typedef renames its target in the decompiler.** `parse_C` handles `typedef record rec_t;` by renaming the type `record` to `rec_t` (`TypeFactory::setName`), so after it `record` no longer parses and a second typedef of it fails with a syntax error. Typedefs of named types are kept as aliases in the type store; declarations and prototypes handed to the decompiler are rewritten through them. Typedefs of core types are copies and are safe.
- **Scoped C++ names collide.** `pointer`, `type`, `size_type` and `_Vector_impl` exist in dozens of class scopes; keying by name alone made typedefs of themselves (`pointer_conflict1 -> pointer_conflict1`) that never resolved. Types are keyed by their scope-qualified name, size and members; the display adds `.conflict<n>` only within one scope, as Ghidra does.
- **Empty bases.** `_Alloc_hider` has the empty `allocator<char>` base at offset 0 and `_M_p` at offset 0 too; declaring both made the struct too big for its size and the decompiler refused everything holding a `std::string`. Empty bases are left out.
- **Out-of-line instances** of constructors and destructors list only the parameters they use; Ghidra shows the abstract origin's (with `__in_chrg`), so those are taken when the origin has them.
- **Signatures carry the name they were made with.** A name with parentheses (`operator()`) broke the old name replacement, which took the first `(`; the parameter list is now the parenthesis matching the last one, and the name is replaced when the head ends with the name the signature was made with.
- **Deleted code stays code.** Ghidra keeps instructions and their references when a function is deleted; the index does too (the calls into a deleted function stay, with no callee name), until data is defined over them.


## Phase 6: PE and 32-bit x86

How it works is in the ADR (PE and 32-bit x86). Code: `crates/engine-native/src/{pe,win32}.rs`,
the data models in `ctypes.rs`, PIC and `.refptr` references in `refs.rs`, `pc_thunk_name` in
`discover.rs`, call fixups and core types in the shim; corpus sets `corpus/pe` and
`corpus/elf32`.

```sh
corpus/build.sh pe elf32                                       # mingw-w64 and multilib in the container
python3 -I corpus/tools/groundtruth_pe.py && python3 -I corpus/tools/groundtruth.py --set elf32
cargo run -p kraken-record -- --corpus corpus/pe --function-cap 32 corpus/pe/bin/<image>
cargo test -p engine-native --test windows                     # truth, Win32 calls, TLS, exports, contract suite
KRAKEN_AGREEMENT_SET=corpus/pe cargo test -p engine-native --test agreement agreement_over_the_corpus -- --ignored --nocapture
```

### Traps

- **The C++ decompiler drops call-fixup targets.** `PcodeInjectLibrary::registerCallFixup` keeps the payload but not the `<target name=...>` list, which Ghidra's Java side applies by function name. Without it `__x86.get_pc_thunk.bx` is an ordinary call and every PIC access reads `unaff_EBX + 0xb2e`. The shim reads the targets from the compiler spec's DOM after `init` and sets the inject id when a function of that name is added.
- **Stand-ins need bytes.** A call whose target is an address with no bytes makes the switch analysis throw `unable to load 16 bytes`; the import stand-ins hold `ret` (`ret n` for a 32-bit stdcall function, so the purge matches) and are writable, or a load through a data import folds to `0xc3c3c3c3`.
- **`.eh_frame` is `.eh_fram` in an image.** ld writes 8-byte section names into PE images (no string table entry), so the long name lookup misses it. objdump's `--dwarf=frames` misses it too.
- **The x86 Windows default convention is `__stdcall` with `extrapop="unknown"`**, not `__cdecl`: marking Win32 functions `__stdcall` changes nothing printed, the C runtime has to be marked `__cdecl` explicitly, and x86-64 has only `__fastcall` (`__stdcall`/`__cdecl` are aliases).
- **`long` is not 8 bytes everywhere.** The core types were LP64; a 32-bit or Windows prototype with `size_t` or `long` declared 8-byte parameters and shifted every stack argument. The shim now registers `longlong`/`ulonglong` as the 8-byte names there and the type store spells declarations through `DataModel::spell`.
- **Ghidra's PE names are not one rule.** On x86 it strips `_`/`@n` from static C symbols but not from library or global ones (`_main`, `_printf`, `_DllMain@12` stay; `_mainCRTStartup`, an entry, does not); on x86-64 its TLS label beats the symbol; some functions with both a symbol and a `.text` section symbol at their address are called `.text` (x86-64 only, with no rule visible from outside). The first two are copied, the last is not.
- **x87 instructions refer to themselves.** Sleigh sets the FPU instruction pointer to `inst_start`, an address-sized constant; it is not a reference.
- **mingw puts a `nop` after a call that never returns** (so the return address stays inside the unwind range). The body ends at the call, as Ghidra's does; the compiler's DWARF size counts the `nop`.
