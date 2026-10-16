# Spike: the rewrite loop on single functions

Goal (decisions 2, 46, 53): prove the core loop of KRAKEN's end goal on real corpus functions.

    lift (KRAKEN decompile, via the registry)
      -> translate (a provider; a hand-written reference for deterministic tests)
      -> verify (differential test against the ORIGINAL machine code under emulation)
      -> record (a versioned `RewriteUnit`, JSON file under the project dir)

Code: `crates/kraken-rewrite`. Run: `cargo test -p kraken-rewrite` (29 tests, about 25 s).
Result: the loop works end to end, offline and deterministically, on four corpus functions, and a
deliberately wrong translation is caught every time with a minimal counterexample.

## What was built

| Piece | Where | What it does |
|---|---|---|
| `FunctionOracle` | `src/oracle.rs` | Loads an x86-64 SysV ELF into icicle-emu, applies relocations, points every import slot at a stub, calls one function with integer/buffer arguments, returns result, buffers, stdout/stderr, writes to globals, termination (returned / exit / fault / timeout / unsupported import) |
| libc stubs | `src/oracle.rs`, `src/clib.rs` | `printf`, `fprintf`, `puts`, `putchar`, `exit`, `abort`, `strlen`, `strcmp`, `memcpy`/`memmove`/`memset`, `__ctype_b_loc` (glibc C-locale table), `__stack_chk_fail`; a C `printf` formatter for integer/string/char conversions |
| `NativeRunner` | `src/native.rs` | Compiles the Rust translation with `rustc` (overflow checks on) into a generated runner, one process per case, confined by Landlock |
| Differential harness | `src/difftest.rs` | Seeded generators (edge cases per integer parameter, random struct fields, random bytes, custom coupled generators), comparison, counterexamples (smallest input first), verdict |
| `RewriteUnit` + `UnitStore` | `src/unit.rs` | Decision-46 artifact record; append-only versions per anchor in `<project>/rewrite/units.json` |
| `RewriteTask` | `src/task.rs` | kraken-assist style prompt (trusted system text, decompile only inside `untrusted` blocks), strict output shape (`<kraken-rust>` plus `<kraken-result>` JSON), parse and check |
| `SpecTask` | `src/task.rs` | Spec-then-reimplement sketch: Markdown with fixed headings, every fact cited `[@0xADDR]`, citations checked against the evidence |
| Targets and references | `src/targets.rs`, `references/*.rs` | The four functions, their ABI, input generators, hand-written reference Rust |
| Cassette | `cassettes/rewrite-reference.json` | `ReplayProvider` cassette answering the four rewrite requests with the references; a test fails if prompts drift (`KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test pipeline` regenerates) |

Functions covered (all from the `-O0` unstripped corpus binaries, decompile read through the
registry from the `corpus/fixtures` FakeEngine recordings):

| Target | Binary | Why it is interesting |
|---|---|---|
| `cmp_id` | `pie_list-O0` | struct pointers, signed subtraction that wraps |
| `cmp_dist` | `pie_list-O0` | int multiplication/addition wrap on 32 bits |
| `vm_run` (+ `push`, `pop`, `vm_fail`) | `switch_vm-O0` | jump table, mutable struct, `printf`, `fprintf(stderr)` + `exit(42)` |
| `evaluate` (+ 5 parser callees) | `stripped_calc-O0` | recursion, `__ctype_b_loc`, error returns that leave `*out` untouched |

Expected values for the oracle tests are computed by hand from `corpus/src/*.c` (for example
`cmp_dist` of (3,4) against (1,2) is 25 - 5 = 20; PUSH 6, PUSH 7, MUL, HALT leaves 42 with
`steps == 4`).

Wrong translations that are caught (each also a test): `cmp_id` returning `cmp()` (-1/0/1) instead
of the difference (`return value: original Some(4), translation Some(1)`); `cmp_dist` with plain
operators (original wraps, translation panics: fault vs return); `vm_run` with swapped SUB
operands; `vm_run` with a different error message (caught through stderr); `evaluate` using
`rem_euclid` for `%` (negative operands).

## Decision: the emulator

Requirement: GPL-3.0-or-later compatible, real instruction semantics (a minimal x86-64
interpreter is not acceptable as the main path), usable as a library from Rust.

| Candidate | License | Verdict |
|---|---|---|
| Unicorn (`unicorn-engine`, `unicorn` crates) | GPL-2.0 only | Rejected. GPL-2.0-only cannot be combined into a GPL-3.0-or-later work. QEMU-based tools share the problem |
| icicle-emu | MIT OR Apache-2.0 (LICENCE-MIT, LICENCE-APACHE at the repo root; crate manifests carry no license field) | Chosen. Rust, multi-arch (x86, ARM, AArch64, MIPS, RISC-V, PPC, MSP430, ...), executes Ghidra SLEIGH p-code, so it shares KRAKEN's instruction semantics |
| Ghidra `EmulatorHelper` (Java p-code emulator inside the sidecar) | Apache-2.0 | Viable second oracle (`ghidra-pcode`); no new dependency, all Ghidra languages. Costs a JVM round trip per call and a new sidecar RPC. Keep for cross-checking |
| `iced-x86`, `yaxpeax-x86`, `zydis` | MIT / 0BSD | Decoders, not emulators |
| Hand-written x86 interpreter | n/a | Not acceptable as the main path (task constraint); would also diverge from SLEIGH semantics |

Findings about icicle-emu:

- It is NOT on crates.io (`cargo info icicle-emu`, `icicle-vm`, `icicle-cpu`, `sleigh-runtime`:
  not found). It is used as a git dependency pinned to commit
  `638508b72f480f9be6fe2e267ef09de8f1541f9a` (master at the time of the spike), version
  requirements `0.1.0` / `0.2.0` / `0.2.0` on `icicle-cpu` / `icicle-vm` / `pcode` so cargo-deny's
  wildcard rule passes. Its `sleigh` directory is a git submodule inside the repository; cargo
  fetches it for path dependencies.
- `deny.toml` changes, all explicit and all for this one repository: `allow-git =
  ["https://github.com/icicle-emu/icicle-emu"]`; per-crate `[[licenses.clarify]]` entries
  (`MIT OR Apache-2.0`) for the nine icicle/sleigh crates whose manifests lack a license field
  (no license file can be hashed because the license files sit outside each crate directory); an
  advisory ignore for RUSTSEC-2026-0344 (ruzstd, reached through `object`/`addr2line` inside
  `icicle-cpu` for zstd-compressed debug sections, which the oracle never loads).
- It does not ship the processor specs. `icicle_vm::build_with_path` compiles Ghidra's
  `Processors/x86/data/languages/x86.slaspec` at start-up (about 1 s in a debug build). The oracle
  reads them from the Ghidra install KRAKEN already provisions: `OracleConfig::ghidra_home`, else
  `KRAKEN_GHIDRA_HOME`, else the `kraken setup` runtime. Without one, `FunctionOracle::load`
  returns `RewriteError::NoProcessors` and the tests fail with that message (they do not skip).
- Cost: a longer build (cranelift is compiled for its JIT; the oracle turns the JIT off and uses
  the p-code interpreter) and about 50 new packages in Cargo.lock. Speed in a debug build: 200 `vm_run` calls
  (357k emulated instructions) in 0.5 s including per-call memory reset.
- The API is a bare CPU plus MMU, which suited the spike: map segments, write registers, run
  until a breakpoint. Stubs are breakpoints handled by the host, not hooks, because an
  instruction hook runs before the hooked instruction's own semantics. The user-mode Linux layer
  (`icicle-linux`, with syscalls and a VFS) exists and is the route to whole-program runs.
- Maintenance risk: single upstream, research-grade, no releases. The pin makes builds
  reproducible. The 0.5 ADR should decide between this pin, vendoring a fork, or the Ghidra
  `EmulatorHelper` oracle behind the same trait.

## How the oracle is set up (so the next person does not rediscover it)

- Load: merge `PT_LOAD` ranges into page regions mapped RWX; PIE is loaded at `0x555555554000`.
  Function addresses given by KRAKEN include Ghidra's image base (`0x100000` for these PIEs):
  `FunctionContext::elf_vaddr` subtracts `program.base` from `project_info`.
- Relocations: `R_X86_64_RELATIVE` is applied; each `JUMP_SLOT`/`GLOB_DAT` import slot gets a
  distinct stub address (so PLT code just works); `R_X86_64_COPY` of `stdout`/`stderr` receives
  sentinel `FILE *` values that `fprintf` recognises.
- Call: arguments in RDI, RSI, RDX, RCX, R8, R9; stack 16-byte aligned at entry; the return
  address is a sentinel with a breakpoint. Each pointer argument gets its own region, flush against
  the END of its mapping, so a read past the buffer faults (a one-byte-past read in the original
  is therefore visible, as for `vm_run`'s `code`, which the generator pads).
- Reset per call: all writable segments, the stack and the output buffers, so calls are
  independent (tested). Writes to globals are reported (`global_writes`) and count as a
  difference, because a translation cannot reproduce them.
- Native side: the generated runner allocates each buffer with 64 zeroed guard bytes on both
  sides, mirroring the oracle's zero-filled pages, so reads just outside a buffer (the original's
  `PRINT` with an empty stack reads `stack[-1]`) agree.
- Comparison: termination class (a fault matches a fault; `exit(n)` must match `n`), then stdout,
  stderr, return value (masked to the return width) and buffer contents. After an `exit` only
  status and output are compared, since memory dies with the process.

## Safety of running model-written code

The translation is untrusted code and is executed natively, so this is part of the spike, not an
afterthought (`src/sandbox.rs`):

- Source lint before building: no `include*!`, `env!`, `asm!`, `#[link`, crate attributes,
  `extern crate`, `libc::`, `std::fs/net/env/process::Command/os::unix`. Defence in depth only.
- Build under Landlock (read-only filesystem, write only to the run directory and, for the
  linker, `/tmp`), scrubbed environment, no TCP, scoped signals and abstract sockets.
- Run each case under tighter Landlock (system libraries and `/proc` only, write only to the run
  directory), `RLIMIT_AS` 2 GiB, `RLIMIT_CPU` 30 s, `RLIMIT_FSIZE` 64 MiB, no core files, a
  10 s wall-clock kill, `PR_SET_PDEATHSIG`. A test proves the runner cannot read `/etc/passwd`
  even when the lint is bypassed.
- Fail closed: without Landlock the build and run are refused unless
  `Confinement::allow_unconfined` is set. Not yet done: a network namespace (the sidecar sandbox
  does that too) and a seccomp filter; both should come from sharing one `kraken-sandbox` crate
  with `engine-ghidra`.

## Limits found

- Calls out: only the stubs listed above exist. Any other import ends the case as `Unsupported`;
  a unit whose cases are mostly unsupported gets verdict `inconclusive`. `malloc`/`calloc`/`free`
  are deliberately not modelled yet (pointers they return cannot be compared with Rust's); the
  test `unknown_import_is_reported_not_guessed` shows `node_new` ending as unsupported at
  `calloc`. Indirect calls through function pointers into unmodelled code behave the same.
- Globals: writes are detected and reported, reads are not controlled. A function that reads a
  global (configuration, a counter) is only testable if the global is part of the input. Needs
  "globals as parameters" in the ABI model.
- Floating point: `double`/`float` arguments and returns (XMM) are not passed or read; `%f` in the
  `printf` stub is refused. SSE/x87 instructions inside integer functions execute, but SLEIGH's
  coverage there is less proven.
- Syscalls: a `syscall` instruction faults. Direct-syscall code needs `icicle-linux` or a stub
  table keyed by number.
- Pointers inside buffers are not relocated (no linked lists, no `cmp_fn` tables as inputs), so
  `list_sort`, `list_each`, `node_new` are out of reach until buffers can carry pointer graphs.
- At most six register arguments, no struct-by-value, no varargs callee, no stack arguments.
- Threads, signals, time, randomness, uninitialised memory: zero-filled in both worlds, not
  modelled beyond that.
- Differential testing is evidence, not proof. The `-O0` code has no undefined-behaviour tricks;
  `-O2` code will (the oracle runs the real machine code, so it stays right, but a translation
  that follows C semantics instead of machine behaviour will be flagged, which is the desired
  outcome). Coverage of the original is not measured yet; the pass criterion today is "N seeded
  cases agree". The next step is block coverage through icicle injectors and coverage-guided input
  generation.
- Emulator fidelity: instruction semantics come from SLEIGH, which can have bugs. The `ghidra-pcode`
  second oracle would not catch a SLEIGH bug (same semantics); a native run of the original (for
  same-architecture hosts, sandboxed) would.
- The registry fixtures are `FakeEngine` recordings of real Ghidra; decompile text for the O0 corpus
  is stable. Nothing here used a live Ghidra, daemon or JVM.

## Proposed 0.5 design (input for ADR 0013)

### Crates

- `kraken-sandbox` (new, extracted from `engine-ghidra::sandbox` plus this spike's confinement):
  confined spawning with rlimits, Landlock, network namespace, seccomp; one policy surface for the
  sidecar, inference backends, ACP agents and generated code.
- `kraken-emu` (new): the `Emulator` capability reserved by decision 46 as a Rust trait in
  `kraken-engine` (`call_function(locator, abi, args) -> Observation`, `record_calls(...)`,
  `coverage(...)`) and backends behind feature flags: `icicle` (this spike's oracle), `ghidra-pcode`
  (sidecar `EmulatorHelper`), later `native-process` (sandboxed host run of same-arch originals).
  Keeps the git-pinned dependency out of crates that do not need it.
- `kraken-rewrite` (this crate, grown): units, tasks, difftest, planner, export. Depends on
  `kraken-emu`, `kraken-agent`, `kraken-registry`.
- Registry commands live in `kraken-registry` (so CLI, MCP and GUI are generated), implemented
  against traits from `kraken-rewrite`.

### Commands (all registry commands, hence CLI `kraken rewrite ...`, MCP tools, GUI actions)

| Command | Kind | Does |
|---|---|---|
| `rewrite_plan` | query | Bottom-up order over the call graph (leaves first, strongly connected groups together), per function: ABI guess, unsupported imports, estimated difficulty |
| `rewrite_function` | job | translate + verify + repair loop (compile errors and minimised counterexamples fed back, bounded rounds and tokens); stores a unit; additive, so agents may run it |
| `rewrite_verify` | job | Re-run or extend differential testing (more cases, new seed, other oracle) on a stored unit; records a verification run |
| `rewrite_units` / `rewrite_unit` | query | List and read units, with staleness |
| `rewrite_accept` / `rewrite_reject` | mutation (users only) | Moves a unit to accepted; same rules as proposals |
| `rewrite_export` | job | Assembles a Cargo workspace from accepted units (see below) |
| `spec_function` / `spec_program` | job | `SpecTask` per function, then per module, then program (hierarchical, bounded context) |
| `set_function_abi` | mutation | Overrides the inferred ABI (parameter kinds, buffer sizes, pointer-to-struct layouts); feeds `set_type` / `set_calling_convention` |
| `testcases_harvest` | job | Run the program (or its tests) under `icicle-linux`, record real arguments at the function's entry: the best input source for pointer-heavy functions |

### Data model (decision 46 made concrete)

One generic `artifact` table: `id`, `kind`, `version`, `parent_id`, `status`
(`draft|verified|failed|accepted|stale`), `created_by` (user or agent run id, as in the edit log),
`content_hash`, `payload` (JSON), and an `artifact_link` table of typed links
(`anchors` -> function locator, `derived_from` -> artifact, `depends_on` -> artifact,
`verifies` -> artifact). Kinds:

- `rewrite_unit`: this spike's `RewriteUnit` minus the cases. Immutable; a new translation is a
  new version of the same anchor.
- `testcase_set`: content-addressed cases plus the oracle's expected observations, shared by every
  unit of the function (so a new translation is checked against the same evidence, and
  counterexamples found for one unit become permanent regression cases).
- `verification_run`: oracle kind and pin, seed, counts, coverage, counterexamples. Re-verifying
  does not mint a unit version.
- `behaviour_spec`: Markdown plus parsed citations, scoped to function/module/program.

Staleness uses the read-sets already in `kraken-model`: a unit records that it read the function's
decompile (and its callees'); an edit to a signature, type or the function bounds marks the unit
stale instead of silently invalidating it. Per-function ABI fields are stored beside the
anchor, not in the unit, since several units share one ABI.

Persisting through the DB needs the migration test noted in the decision log; the JSON file used
here has the same shapes so the migration is a copy.

### Pipeline and modes

1. Faithful incremental (strangler): units are exported as a crate per binary with one
   `#[no_mangle] extern "C"` function per accepted unit, plus a loader/interposer so the original
   binary can run with those functions replaced (ELF symbol interposition for exported symbols,
   trampoline patching for internal ones). Calls from rewritten code to not-yet-rewritten code go
   through the original's address via an FFI trampoline; calls between rewritten functions become
   plain Rust calls (a second, mechanical translation step the model never sees). Whole-program
   regression comes for free from running the original's own test inputs.
2. Spec-then-reimplement: function specs -> module specs -> program spec (cited Markdown), a
   human edit point, then idiomatic reimplementation per module checked at module and whole-program
   level with a `process` oracle (same stdin/args/files, compare stdout/stderr/exit code; run the
   original under `icicle-linux` or sandboxed natively).
3. Per function: lift -> ABI inference -> input synthesis (type-aware generators, harvested real
   arguments, coverage-guided mutation) -> translate -> compile -> differential test -> repair loop
   -> accept. Library calls map through a data table (`printf` -> `print!`, `memcpy` ->
   `copy_nonoverlapping`, ...), the same table drives oracle stubs so both sides agree by
   construction.

### UI (GUI over the same commands)

- "Rewrite" dock: function list ordered by the plan, status badge per row (not started,
  translating, verifying, verified with N cases and coverage, failed with counterexample, stale),
  progress for the whole program (functions and bytes rewritten).
- Function view: decompile, Rust and ABI side by side; "Rewrite this function" and "Verify more"
  buttons; assumptions and unsupported items from the model shown as warnings.
- Counterexample inspector: arguments as hex and struct view, original vs translation
  observations (return, buffer diff, stdout/stderr), "add as regression case".
- Spec view: Markdown with `[@0xADDR]` rendered as links that jump to the listing.
- Export dialog: choose accepted units, preview the generated workspace, run the strangler build.
- Beginner mode: the assistant explains a failed counterexample in plain language.

### Questions the ADR must settle

1. Emulator dependency: git pin (as here), a vendored fork, or the Ghidra `EmulatorHelper` oracle
   first. Whichever is chosen sits behind the `Emulator` trait.
2. Where generated code may run: Landlock + rlimits + netns + seccomp is the proposal; Windows and
   macOS need their own story (Job objects / App Sandbox) before the feature is tier-1 there.
3. Whether `rewrite_accept` is user-only (proposed) and whether agents may auto-run
   `rewrite_function` (proposed yes: it only adds artifacts).
4. Cost control: token budgets per function and per program, caching by prompt fingerprint (the
   cassette fingerprint is a ready-made cache key), local-model support (these prompts are short
   enough for a 14B local model for leaf functions; unverified).
5. How much of the call graph is translated together: the spike translates a function with its
   callees as one unit (`vm_run` + helpers, `evaluate` + parser). The planner should group by SCC
   and cap group size.

## Notes for whoever continues

- To re-record the cassette after changing a prompt or reference:
  `KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test pipeline`, then run the suite
  once more without the variable.
- To try a real provider on a target, build `job_for_target` over a real project backend and call
  `rewrite_and_verify` with any `ChatProvider` from `kraken-assist`'s provider config; the model
  answer goes through the same parse, lint, sandboxed build and differential test.
- Tests need `rustc` on PATH (or `RUSTC`), Landlock, and a Ghidra install for the x86 SLEIGH spec
  (`KRAKEN_GHIDRA_HOME`, the provisioned runtime, or the dev cache in `~/.cache/kraken-dev`).
