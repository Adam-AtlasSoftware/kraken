# 0013. The rewrite pipeline

Status: Accepted
Date: 2026-10-16
Revised: 2026-10-16 (task R2: repair attempts, reused callees, stale units)

## Context

KRAKEN's goal is a Rust rewrite of a binary. Decisions 2, 46 and 53 fixed the shape: two modes (faithful incremental, spec-then-reimplement), a generic versioned artifact linked to function anchors, and capability traits that let an emulator or a decompiler be replaced piece by piece. The rewrite spike (`spikes/rewrite-loop/NOTES.md`) proved the loop on four corpus functions: decompile through the registry, translate with a model, run the original machine code and the Rust side by side, record a versioned unit. It also showed what is hard: the translation is untrusted code that has to run, the original has to run somewhere, and "it passed" has to mean something.

This record turns the spike into the pipeline core of release 0.5 (task R1). It settles the questions the spike left open and says what is in the first cut and what is not.

## Decision

### Two modes, one record

A project rewrites function by function. Each `rewrite_function` call picks a mode, and both modes write the same unit record.

- **Incremental, test-verified (strangler).** The model gets the decompile of one function and its direct callees and writes a Rust function behind the original's `extern "C"` signature. The Rust function is checked against the original machine code. Accepted functions are exported as a library and an FFI shim that can stand in for the originals, so the program is replaced a function at a time and keeps running from the original binary for the rest.
- **Spec-then-reimplement.** First `rewrite_spec` has the model write a behavioural spec: Markdown with the headings Purpose, Inputs, Outputs, Side effects, Invariants and Open questions, every fact cited as `[@0xADDR]`. A citation must name a function entry or a hex literal in the evidence, or the reply is rejected. Then `rewrite_function` with `mode: spec` gives the model the spec and the required signature and no decompile, and checks the result with the same differential test. The spec is stored and can be read and corrected by a person (that is the human edit point of the mode). In this cut the spec is per function, plus one program-level spec for orientation. Module specs and whole-program reimplementation checked by a process oracle come later.

The mode is recorded in the unit. Users pick the mode per call; there is no project-wide switch yet.

### The unit lifecycle

A function has a unit; a unit has append-only versions, one per translation. A version has a status:

```
planned -> translated -> verified -> accepted
                     \-> failed
```

- `planned`: the function is in the stored plan and nothing was translated.
- `translated`: Rust exists but there is no passing verdict (the oracle could not evaluate enough cases: `inconclusive`).
- `verified`: the differential test passed on every case that ran.
- `failed`: a case disagreed (the verdict carries the smallest counterexample), or the code was refused by the source lint, or did not compile.
- `accepted`: a user accepted a verified version.

A verdict decides the status of a new version: pass gives `verified`, fail and rejected give `failed`, inconclusive gives `translated`. Only a user moves `verified` to `accepted` (`rewrite_accept`). A function has at most one accepted version; accepting another version replaces it and the old one goes back to `verified`. A later translation does not unaccept a function, so an export is stable while people keep experimenting. Every transition is recorded as an event with its actor.

### Repair attempts

A translation that fails for a reason the model can act on gets another chance. `rewrite_function` runs a bounded loop (`max_attempts`, default 3, at most 8; 1 turns it off): ask for a translation, verify it, and if the new version is `failed` feed the evidence back and ask again. Three things count as repairable and each has its own feedback: `compile` (the compiler output, which `rustc` printed in the sandbox), `rejected` (the source lint's reason) and `counterexample` (the smallest disagreeing input, with what each side did). `inconclusive` and `translated` are not repaired, because the model cannot fix an oracle that could not run the original. A pass ends the loop.

The next request is the first request plus, per failed attempt, the attempt's code and the evidence, both inside `untrusted` blocks (the compiler output and the counterexample come from running model code against the binary, so they are data, like the decompile). A reply that cannot be parsed is an error on the first attempt, as before; on a later one it costs an attempt and the model is told what was wrong with its reply. The loop checks the job's cancel token between attempts.

Every attempt is stored as a version, so the history shows what was tried. A version made in a run carries a repair link (`unit_repairs`: attempt number, the version it answers, the kind of feedback), and its provenance task is `rewrite_function` for the first attempt and `rewrite_function/repair` for the others. The result of the job is the last attempt and says how many were made. The oracle is built once per run, on a dedicated thread, because it is not `Send` and is slow to build; each attempt is a job sent to it. Accepting stays a separate, human step: a repair never accepts anything.

### Reusing accepted callees

Before a translation, each program callee is looked up. When the callee has an accepted unit made from the callee's current decompile (same hash), and the callees that unit reuses in turn are still accepted at the version it was made with, the new translation does not translate it again. The prompt lists the callee by its original name, address and Rust prototype and tells the model to call it and not define it; a reply that defines it anyway is refused. The callee's decompile is left out of the prompt, which keeps prompts short on call-heavy code.

For the differential test the accepted code is compiled together with the new code: each reused callee, and what it needs in turn, in a private module (`__kr_callee_<addr>`, so helper types and functions cannot clash), then `use` lines for the ones the new code calls directly. That composed source is what the lint and the compiler see, and it is part of the test, not of the stored code: the unit keeps only the model's own code, and its callee list records each reused callee with the accepted unit and version it was tested against (`reused`). In the export a unit that reuses a callee gets `use super::u_<callee>::<callee>;` and the export refuses it when the callee is not exported, or is accepted at another version now, because the verdict was about the old callee; the message says to translate the function again. Spec mode does not reuse callees: its prompt contains the spec and nothing derived from the decompile. A callee that is not accepted, or is out of date, is translated inside the unit as before. A function never reuses itself.

### Stale units

A version is stale when the decompile of its function, or of a callee it was made from, is different now. Each version stores the decompile hash and the callee hashes it was made from. The store keeps the newest decompile hash it has seen per function (`observed_hashes`): storing a version records the hashes it was made from, `rewrite_function` records what it just read, and `rewrite_unit` decompiles the function and the callees of its versions and records those. `rewrite_status` reports `stale` per function from what has been recorded, without decompiling anything; `refresh: true` decompiles every function that has a unit, and the callees of the version that counts, first. The version that counts for a function is its accepted one, or else its newest. A stale unit keeps its status: stale is a flag next to it, not a lifecycle state, because the unit may still be right and only the user can say so. Translating the function again from the new decompile and accepting that version clears the flag. It does not block an export (the README of an export should list stale units; not done yet).

### Oracle kinds

Every verdict records the oracle that produced it (`kind`, emulator pin, binary, entry). Kinds:

| Kind | State | What it is |
|---|---|---|
| `icicle-emu/x86-64-sleigh` | implemented | The function runs in icicle-emu, a p-code interpreter fed with Ghidra's x86 SLEIGH spec, with the ELF mapped by hand and a few libc functions stubbed. Observed: result, buffers, stdout and stderr, writes to globals, how it ended. |
| `ghidra-pcode` | reserved | The same idea through Ghidra's `EmulatorHelper` in the sidecar. All Ghidra languages, a JVM round trip per call. Useful as a second opinion; it shares the SLEIGH semantics, so it would not catch a SLEIGH bug. |
| `native-process` | reserved | The original run natively in the sandbox, for same-architecture hosts. The only kind that catches emulator and SLEIGH bugs. |
| `process` | reserved | Whole-program oracle for spec mode: same arguments, stdin and files, compare stdout, stderr and exit status. |

All of them sit behind one trait once a second kind exists (`Emulator` in `kraken-engine`, decision 46). Until then the oracle is the concrete `FunctionOracle` in `kraken-rewrite`, and the trait is extracted when the second implementation needs it. Inputs are generated, not harvested: edge and random values for integers, random bytes in fixed-size buffers for pointers, curated generators for known targets (the corpus). Harvesting real arguments by running the program is planned.

A verdict is evidence, not proof: "N seeded cases agreed". Coverage of the original is not measured yet.

### The emulator dependency

icicle-emu stays a git dependency pinned by commit (`crates/kraken-rewrite/Cargo.toml`, `deny.toml` `allow-git`), used through `icicle-cpu`, `icicle-vm` and `pcode`. It is MIT OR Apache-2.0, executes SLEIGH p-code like Ghidra does, and has no releases. Unicorn is GPL-2.0-only and cannot be combined into a GPL-3.0-or-later work. The risk is a single research-grade upstream, which the pin contains. If upstream stalls, the options are a vendored fork or the `ghidra-pcode` kind as the primary oracle; both fit behind the same trait. This is revisited before the 0.5 release.

### Sandboxing generated code

The translation is model-written code and it is built and run on the user's machine. It is untrusted. Rules:

- It runs only in a confined child process. Today that means Linux with Landlock ABI 4 or newer (kernel 6.7) plus network isolation: a user and network namespace when the host allows one, otherwise a seccomp filter that refuses `socket()` outside `AF_UNIX` (the filter is installed in both cases, also refusing `io_uring_setup`). The build (`rustc`, or `cargo` for an export; the real toolchain binaries from `rustc --print sysroot`, never a rustup proxy) can read only the toolchain sysroot, `/usr`, `/lib*`, `/etc/ld.so.cache` and `/proc/self`, and write only its scratch directory, which lives under a private `0700` directory (`$XDG_RUNTIME_DIR/kraken-rewrite`, never a shared `/tmp`, with no cargo config in any ancestor) with an explicit `CARGO_HOME`; it also runs under `RLIMIT_AS`, `RLIMIT_CPU` and a 120 s (cargo: 600 s) wall-clock limit. `$HOME`, `~/.ssh` and the daemon token are unreadable even to `include_str!`. Each test case runs in a tighter child: system libraries and `/proc/self` read-only, write only to its scratch directory, no sockets at all, no `fork`/`clone` (seccomp), `RLIMIT_AS` 2 GiB, `RLIMIT_CPU` 30 s, `RLIMIT_FSIZE` 64 MiB, no core files, a 10 s wall-clock kill, `PR_SET_PDEATHSIG`. Every child leads its own process group, and a timeout kills the group; reader threads are joined with a deadline so a descendant that escaped cannot hang the daemon. The source lint is a `syn` allowlist (safe computing subset: no `extern` blocks, no `mod x;`, a short list of attributes and macros, no file, network, process, environment or thread APIs) and is defence in depth; tests prove that the confinement holds without it.
- A source lint runs before any build and refuses `include!` and friends, `env!`, inline assembly, `#[link`, crate-level attributes, `extern crate`, `libc::`, `std::fs`, `std::net`, `std::env`, `std::process::Command` and OS-specific modules. It is defence in depth; the sandbox is the boundary.
- It fails closed. A host that cannot enforce this (Landlock ABI 4 and a network barrier) does not run generated code at all: `rewrite_function` and the building part of `rewrite_export` answer `unsupported`. There is no flag to run unconfined from a command. macOS and Windows therefore cannot rewrite until they have their own confinement (App Sandbox, Job objects with restricted tokens). The commands are still defined there and say why they refuse.
- Permission classes follow from this. `rewrite_function` is `mutating`, not `dangerous`, because the sandbox is enforced or the command does not run. It only adds artifacts to `rewrite.sqlite`; it never edits the program, so agents may run it. `rewrite_export` is `mutating` when it writes inside the project directory and asks for approval, exactly like a `dangerous` command, when the target is outside it (the approval request names the directory; a `..` in the path is refused outright). `rewrite_accept` is for users only; agents get `rejected_human_priority`.
- Not done yet: a network namespace and a seccomp filter for the generated code, which should come from one `kraken-sandbox` crate shared with the Ghidra sidecar (ADR 0007), the inference backends and the ACP agents.
- Model calls send decompiled code to the configured provider. A cloud provider sees the code of the functions being rewritten; a local one does not. This is the same as for the assistant (ADR 0008), and the commands' documentation says it.

### Where the pieces live

- `kraken-registry` defines the six commands, their arguments and results, and the `RewriteBackend` trait. A `Session` carries an optional backend (`Session::with_rewrite`), as it carries an `EngineFactory`. Without one the commands answer `unsupported`.
- `kraken-rewrite` implements `RewriteBackend` (`RewriteService`) and owns everything else: the oracle, the tasks, the sandbox, the store, the planner and the export. `krakend` and the `kraken` CLI attach it to the sessions they own. The in-process GUI session does not yet; it reaches the pipeline through the daemon.

The other directions are worse. If the registry depended on `kraken-rewrite`, the registry would link the emulator, the sandbox and a second SQLite schema, and there would be a dependency cycle, since the pipeline reads the program through registry commands. If `kraken-rewrite` registered its commands into a `Registry`, every place that builds `Registry::standard()` (the CLI's command tree, the MCP tool list, the generated reference, the GUI's palette, the daemon contract tests) would have to remember to add them, and a surface that forgot would silently lack the commands. With the commands in the registry they appear everywhere, in the same order, with the same schemas, and the implementation is injected where it is needed.

### Commands

| Command | Kind | Permission | Does |
|---|---|---|---|
| `rewrite_plan` | query | safe | Orders the functions callees first (strongly connected components of the call graph, recursive groups together), leaves out import thunks and compiler glue, flags what the test cannot cover. `scope: all` stores the plan and pages through it; `scope: function` returns one function with the callees it needs. |
| `rewrite_status` | query | safe | Counts per status and one row per function. |
| `rewrite_function` | job | mutating | Decompile, translate with the configured provider, build and test in the sandbox, store a new version. |
| `rewrite_accept` | mutation | mutating, users only | `verified` to `accepted`. |
| `rewrite_spec` | job | mutating | Write and store a cited spec, for one function or the program. |
| `rewrite_export` | job | mutating (approval outside the project) | Write a Cargo workspace from accepted units and build it in the sandbox. |

The plan flags: `needs_stubs` (a library call the oracle does not model, directly or through a callee; the test would be inconclusive), `uses_globals` (a data reference into writable program data; the globals are not inputs of the test), `uses_syscalls` (a call to `syscall`; an inline `syscall` instruction is not detected) and `recursive`. The oracle's stub list is in `kraken_rewrite::oracle::STUBBED_IMPORTS`; the planner uses the same list, so the flag and the oracle agree by construction. References to the program's own copies of `stdout` and `stderr` do not count as globals, because the oracle models them.

The CLI and MCP get all of this from the registry. `kraken` prints `rewrite-plan`, `rewrite-status` and the result of `rewrite-function` as tables and short text; every command has `--json`. The assistant does not get the commands that start model calls or builds (`rewrite_function`, `rewrite_spec`, `rewrite_export`, `rewrite_accept`); it may read the plan and the status.

### Persistence

Rewrite artifacts live in `<project>/rewrite.sqlite`, a file owned by `kraken-rewrite` with its own versioned migrations, not in `project.kraken.sqlite`. The project database is the edit log (ADR 0002) and `kraken-model` changes on its own schedule; the rewrite schema should not be coupled to it, and a rewrite database can be deleted and rebuilt without touching annotations. Decision 46 asked for a generic versioned `artifact` entity with typed links. This cut stores the rewrite artifacts as ordinary tables with the same content and keys (function anchor = program hash plus entry address); the generic table can be introduced in the project database later and fed from these tables by a copy, since versions are immutable.

Tables: `units` (one row per function: status, newest and accepted version), `unit_versions` (code and hashes, ABI, provenance with provider, model and prompt hash, oracle, decompile and callee hashes with the reused unit where there is one, spec id), `unit_repairs` (attempt number and the failed version a repair answers), `observed_hashes` (the newest decompile hash seen per function, for stale checks), `test_cases` (the oracle's expected results, capped at 256 per version), `verdicts` (verdict, counts, seed, sandbox label, counterexamples), `unit_events` (status transitions with the actor), `specs`, and the stored plan (`plan_meta`, `plan_entries`). Migrations are numbered, applied in one transaction, recorded in `schema_version`, and a database from a newer build is refused. A test migrates a database written by migration 1 and checks the data.

### Limits

What the first cut cannot do, so nobody is surprised:

- Calls out: only the stubbed libc functions exist. Any other import ends the case as unsupported, and a function whose cases are mostly unsupported gets `inconclusive`. `malloc` and friends are not modelled; neither are syscalls.
- Signatures: at most six parameters, integers and pointers only, an integer or void result. No floating point, structure by value, varargs, function-pointer parameters or pointer results. `rewrite_function` explains which one and stops before any model call. The ABI is read from the signature KRAKEN shows; overriding it (`set_function_abi`) is not there yet.
- Pointers: buffers must not contain pointers, so linked structures are out of reach. Generic inputs fill 64-byte buffers with random bytes; struct-heavy functions are tested far better with a curated generator.
- Globals are reported when written and flagged by the plan, but not controlled as inputs.
- Translation unit: a function with up to six of its direct program callees (their decompile as context). Callees that are not accepted yet are translated into the same unit, so a helper can exist in several units; accepted ones are called (see above). Translating a recursive group as one unit is a follow-up. The repair loop is bounded and only reacts to failures it can show the model; it does not search for a better prompt, and a model that repeats the same mistake uses up the attempts.
- Cost: one model call per attempt, so up to `max_attempts` (default 3) per function in incremental mode (one more when the spec is new in spec mode; the repair loop runs on the reimplementation, not on the spec), `max_tokens` 4096, temperature 0.1. A spec is reused while the decompile of the function and its callees is unchanged. Whole-program specs read at most 100 functions (30 by default), each cut to 6000 bytes. Token budgets per program and a response cache keyed by prompt fingerprint are not there; the cassette fingerprint is the ready-made key.
- Time: 10 s per case, 600 s for an export build, 2000 test cases at most, 2000 functions in a new plan by default (20000 at most).
- Only x86-64 ELF is run by the oracle. The plan and the specs work on any program the engine can load.
- Emulator fidelity comes from SLEIGH. A bug there is invisible to `icicle-emu` and `ghidra-pcode`; `native-process` is the answer.

### What "done" means for a rewritten program

Three levels, from small to large.

1. **A function is done** when a user accepted a version that passed the differential test on every case that ran, with no counterexample and not mostly `skipped`. Its record says which model wrote it, which cases ran, which oracle checked it and in which sandbox.
2. **A program is rewritten** when every function in the plan is either accepted or deliberately left to the original with a reason (a waiver; not in this cut), no accepted function carries an unexplained `needs_stubs`, `uses_globals` or `uses_syscalls` flag, and the export builds in the sandbox with a symbol table that matches the accepted units. `rewrite_status` shows the counts; the README of the export shows the coverage.
3. **The original is retired** when the program as a whole behaves the same: the original's own test inputs, run through a build that links the exported shim and drops the originals, give the same output, status and files as the original. That whole-program regression check is not automated in this cut (the `process` oracle); until it is, level 3 is a manual step and the export README says so.

Differential testing is evidence. "Done" at every level means "no known difference on what was tested", and the reports say how much was tested.

### The export

`rewrite_export` writes a workspace with a library crate holding the accepted units, one module per function with the model's symbol attributes removed, and an FFI shim crate (`cdylib` and `staticlib`) exposing one `extern "C"` function per unit with the original name and signature, plus a C header, `manifest.json` (symbol, original address, unit, version, cases, provider) and a README. The README states the coverage, what the tests do not control, and three ways to link the shim in place of the originals: rebuilding from source, symbol interposition for dynamically exported functions, and patching the binary (not provided). By default the workspace is built in the sandbox and its dynamic symbol table is compared with the accepted units; any difference fails the export and leaves the files for inspection. The target directory must be absent, empty, or an earlier export (marked by its manifest); anything else is refused.

### The security advisory for `ruzstd`

`cargo deny` reports RUSTSEC-2026-0344, an advisory against the `ruzstd` zstd decoder, for the dependency graph through `icicle-cpu`, which depends on `addr2line`, which pulls in `object` with zstd support. icicle-cpu has no feature that drops this, and a `[patch]` would need the workspace manifest, so the dependency stays and the advisory stays ignored in `deny.toml` with this reason. The code is unreachable from KRAKEN. The decoder runs only when `addr2line::Context::from_dwarf` reads compressed DWARF sections of a program image, and the only caller in icicle is `icicle_cpu::debug_info::DebugInfo::add_file`, used by its PE loader and by `icicle-linux`. The oracle maps `PT_LOAD` segments itself and reads symbols and relocations with `object`'s ELF reader; it calls neither. A test (`crates/kraken-rewrite/tests/no_debug_info.rs`) fails if `kraken-rewrite` source starts to name any of these entry points, or adds an icicle crate beyond the three it uses. The ignore is removed when `object` in icicle moves to `ruzstd` 0.9.1 or later.

## Consequences

- The loop of the spike is a product feature: plan, translate or reimplement, verify, record, accept, export, from the CLI, MCP and (through the daemon) the GUI, with one implementation.
- Generated code never runs outside the sandbox, and hosts without one cannot rewrite. That is a hard limit on macOS and Windows until they have confinement.
- The rewrite state is separate from annotations, so it can be inspected, copied or thrown away on its own, and a schema change in one does not force one in the other.
- The icicle dependency adds a long build and about fifty packages to `krakend` and `kraken`, and one advisory ignore with a documented reason.
- A passing unit is only as good as its inputs. Struct-heavy and stateful functions need curated or harvested inputs before their verdicts mean much; the plan flags make the known gaps visible.

## Alternatives considered

- **One generic `artifact` table in the project database now.** Matches decision 46 literally, but couples the rewrite schema to `kraken-model` while that is changing, and the generic shape has no second user yet.
- **Commands registered by `kraken-rewrite`, or the registry depending on it.** See above: a cycle or a surface that can forget.
- **Unicorn as the emulator.** GPL-2.0-only; cannot be combined.
- **Running the original natively as the only oracle.** Catches emulator bugs, but only works on same-architecture hosts and needs a sandboxed process per case for arbitrary binaries. It stays as a future kind.
- **Letting `rewrite_function` run unconfined behind a flag.** Convenient on hosts without Landlock, and exactly the case where the risk is highest. Refused.
- **Agents may accept.** Acceptance is the human judgement that a verdict is enough; same rule as proposals (ADR 0005).
- **Letting a repair attempt replace the failed version.** Versions are append-only and a failed attempt is evidence; the history of what the model got wrong is worth keeping, and nothing is lost by storing it.
- **A `stale` lifecycle status.** It would have to be set and cleared by events and would hide the real status (a stale accepted unit is still accepted until a person decides). A flag computed from hashes cannot get out of step.
- **Translating whole programs in one model call.** Does not fit in a context window, and a failure has no location. Functions in dependency order give bounded prompts and local failures.
