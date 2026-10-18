# Performance

This page records where KRAKEN spent its time on large real binaries with the native engine, what was
changed, and the numbers before and after. Everything here can be measured again with
`cargo xtask bench` (see [Reproducing](#reproducing)).

The machine: 16 cores, 62 GB of memory, NVMe disk, Linux 7.2. The binaries are copies of system files,
used read-only:

| Binary | Size | Functions found | Notes |
|---|---:|---:|---|
| `libzstd.so.1.5.7` | 0.9 MB | 902 | C, a few huge functions |
| `libpcre2-8.so.0.16.1` | 0.9 MB | 301 | C |
| `libpython3.14.so.1.0` | 6.7 MB | 11 270 | C, many switches |
| `libQt6Widgets.so.6` | 8.0 MB | 14 963 | C++, very large switch tables |
| `cargo` | 26.7 MB | 41 283 | Rust, static |

"Before" is the engine at the start of this work (measured with the same benchmark code), "after"
is this tree. Times are wall clock. Cold opens vary by about 15 % with the load of the machine.

## Summary

| | Before | After |
|---|---:|---:|
| Open `libpython` the first time (engine) | 25.7 min | **4.8 min** |
| Open `libpython` the first time, as a project through `krakend` | fails: the worker's 10 minute limit | **5.1 min** |
| Open `libpython` again (saved state) | 25.7 min (nothing was kept) | **6 s** |
| Open `libQt6Widgets` the first time | fails: the worker's 10 minute limit (2.4 hours of switch analysis in one thread) | **20 to 25 min** |
| Open `libQt6Widgets` again | not possible | **7 s** |
| Open `cargo` | fails: `jump_tables: unable to load 16 bytes` | **4.7 min**, again in 26 s |
| Open `libzstd` again, through `krakend` | 47 s | **1.4 s** |
| Rename a function (`libzstd`, through `krakend`) | 394 ms | **5 ms** |
| First list of strings (`libpython`) | 5.8 s | **0.1 s** |
| Decompile the same function again (p95) | 8.3 s | **0.15 ms in process, 7 ms through the worker** |
| A GUI frame (decompiler, listing, graph, function list) | at most 2 ms | at most 2 ms (nothing to fix) |

The two things that decide how big a program can be are the first open (the decompiler's switch
analysis, one decompiler pass per jump table) and memory. The GUI, the daemon and the other queries
were already fast: they answer in well under a millisecond to a few milliseconds on every binary
above.

## What was slow, and what changed

Found by timing each stage and by sampling the running process with `gdb`.

1. **The switch analysis ran one jump table at a time.** Opening a program asks the decompiler to
   recover every jump table of every function that has a computed jump (to find the cases of a
   `switch`). The open of `libpython` took 1 540 s, nearly all of it in these calls; on Qt Widgets
   there are 2 700 of them, 8 600 s in all, the longest of them 6 minutes. They are independent of each
   other. Discovery now walks the functions in batches on several decompiler sessions at once (one per
   CPU, at most 6 and one per 3 GB of free memory; `KRAKEN_NATIVE_THREADS`, read by the process that
   starts the worker, sets the number). The sessions work on separate programs, so the library's
   process-wide lock became a read/write lock that `decode` and `jump_tables` share; everything else
   still takes it exclusively. `tests/parallel.rs` checks on nine corpus binaries (x86-64 and 32-bit ELF, PE), with and without
   symbols, that one session and four sessions find exactly the same functions, instruction by
   instruction. This relies on separate sessions of Ghidra's decompiler sharing no state (the
   statics of its sources are read-only tables and one C parser used only for types, which stays
   under the exclusive lock); `KRAKEN_NATIVE_THREADS=1` goes back to one at a time.
2. **Nothing was kept between opens.** Every open of the same binary, and every restart of the worker
   after a crash, ran the analysis again. The answers of the switch analysis are now written to the
   project's engine directory (`discovery-cache.json`, keyed by the binary's SHA-256, the engine version
   and whether symbols were used) and read back by the next open. A run that makes the same calls in the
   same order takes the answers from there, so the result is the same as a fresh run, and a file for
   another binary or version is ignored.
3. **Opening had a fixed 10 minute limit.** The worker is killed when a request runs past its hard
   deadline, which for `open` was 600 s in total, so a big program could never be opened. The worker now
   reports how many functions it has found (several times a second); the deadline counts from the last
   report, as it already did for the analysis job.
4. **A huge function does not return its memory.** The switch analysis of one function can allocate
   gigabytes in small pieces, and with one allocator arena per thread the freed pages stayed with the
   process: a Qt Widgets open grew to 19 GB and stayed there. The shim now gives memory back after a slow
   call, the worker does it again when discovery ends, and a session waits for the others while less than
   3 GB of memory is available.
5. **Quadratic loops.** The candidates for function pointers were each tested against every function
   (`functions.values().any(contains)`): now one merged range list and a binary search. The string
   scan removed strings inside referenced strings with a nested loop, and re-read a growing run of
   non-text data from every start (the UTF-16 attempt did not stop at the first byte that cannot be text):
   `libpython` strings went from 5.8 s to 0.1 s.
6. **`cargo` could not be opened at all.** A function whose flow reaches bytes outside the image made
   the decompiler raise, and the whole open failed. Such a function now has no recovered tables (as a
   computed jump the decompiler cannot resolve has none).
7. **No decompile cache.** Going back to a function decompiled it again, from 5 ms to 8 s for the big ones.
   The last 128 results are kept (up to 128 MB) until the next edit of names, types, prototypes,
   comments or the function table, which are counted, so a cached text is never older than the program.
   The analysis job decompiles everything once and does not fill the cache.
8. **A rename rebuilt the world.** Every rename copied the whole function table (every instruction
   address of every function), rebuilt the map from instruction to function and rebuilt the
   cross-reference index. Function bodies are now shared between copies of the table, the owner map is kept
   when no body changed, and renames and prototypes only update the exports and the list of functions that
   never return. A rename on `libpython` takes 9 ms, on `libzstd` 5 ms (394 ms before).
9. **Memory.** The instruction cache kept everything decoded speculatively past branches; only the
   instructions inside function bodies are kept now (they are 98.6 % of what was decoded, so this saves
   little), and the extra sessions' memory is returned. See [Memory](#memory).

Things measured and left alone: the GUI (see below), the daemon's round trip (0.2 ms), listing, CFG,
cross-references and strings queries (all under 10 ms), and the decompiler itself, which is Ghidra's
and is most of the time of the slowest queries.

## Analysis stages

The native analysis job has three stages. `load` and `core` only report what opening already built
(and scan the strings); `expensive` decompiles every function once, which fills in the signatures
of the functions that have none and counts the ones that time out. Through the worker:

| | open | `load` | `core` | `expensive` | functions |
|---|---:|---:|---:|---:|---:|
| `libpcre2-8` | 10.5 s | 0 ms | 0.06 ms | 96.7 s | 301 |
| `libzstd` | 7.7 s | 0 ms | 0.16 ms | 553 s | 902 |

Everything is in the decompiler: `libzstd` has about 45 functions of 3 to 25 seconds each. The
stage runs one decompile at a time, as the decompiler library allows, and a decompile asked for by
the GUI waits for the one in flight (it does not wait for the others).

## Engine, `libpython` (6.7 MB, 11 270 functions)

In process, so that there is no IPC in the numbers. The first row is the engine before this work
(sequential, no saved state), the second the engine now.

| | Before | After |
|---|---:|---:|
| `open_binary`, first time | 1 542.6 s | 290.4 s (worker) |
| `open_binary`, with saved state | 1 542.6 s | 6.3 s |
| `list_functions`, 23 pages of 500 | 23 ms | 22 ms |
| `decompile`, 200 functions: p50 / p95 | 6.2 / 174 ms | 4.3 / 106 ms |
| `decompile` again, p50 / p95 | 2.7 ms / 8.3 s | 0.04 / 0.15 ms |
| `xrefs`, `cfg`, `disassemble`: p95 | 0.01 to 0.4 ms | 0.01 to 0.4 ms |
| strings, 29 pages of 500 | 5 782 ms | 48 ms |
| RSS after open, peak | peak 755 MB | 0.9 GB after the first open, peak 2.4 GB (6 sessions) |

Through the worker (the default), with the process boundary in the numbers:

| stage | n | p50 ms | p95 ms | max ms |
|---|---:|---:|---:|---:|
| open_binary, first time | 1 | 290 417 | | |
| reopen with saved state | 1 | 6 518 | | |
| list_functions, pages of 500 (11 270 functions) | 23 | 5.00 | 6.76 | 7.53 |
| get_function | 200 | 0.06 | 0.08 | 0.18 |
| decompile | 200 | 6.45 | 134.70 | 12 874.69 |
| decompile again (last 50) | 50 | 2.07 | 6.91 | 17.16 |
| xrefs to entry | 200 | 0.07 | 0.23 | 1.37 |
| xrefs from function | 200 | 0.13 | 0.93 | 1.86 |
| cfg | 200 | 0.14 | 1.08 | 10.39 |
| disassemble function (500 rows) | 200 | 0.64 | 6.49 | 7.74 |
| strings pages of 500 (14 063 strings) | 29 | 1.51 | 3.69 | 47.38 |
| imports + exports | 3 | 2.16 | 2.24 | 2.24 |

The slowest decompiles (12 s) are single huge functions: the decompiler's own time.

## The largest programs

| | `libQt6Widgets` (8.0 MB, 14 963 functions) | `cargo` (26.7 MB, 41 283 functions) |
|---|---:|---:|
| Before | cannot be opened: 10 minute limit | cannot be opened: error |
| First open (6 sessions) | 1 191 s and 1 524 s in two runs | 280 s |
| Switch analysis work done | 2 700 recoveries, 8 600 CPU seconds, one of them 6 minutes | |
| Open with saved state | 7.0 s | 26 s |
| RSS after the first open | 1.1 GB | 5.4 GB |
| Peak RSS during the first open | 19.7 GB | 13.0 GB |
| `list_functions` pages of 500: p50 | 6.7 ms | 6.0 ms |
| `decompile` p50 | 11.6 ms | 4.4 ms |
| `xrefs`, `cfg`: p95 | 1.6 ms | 2.5 ms |
| Strings, whole list in pages of 500 | 122 ms | 254 ms |

A first open of these takes a long time because of a handful of functions whose switch analysis takes
minutes and gigabytes in the decompiler itself; the cache and the heartbeat make it a one-time cost.

## Memory

| | RSS after open | Peak |
|---|---:|---:|
| `libzstd` | 0.5 GB | 1.0 GB |
| `libpython` | 0.9 GB | 2.4 GB |
| `libQt6Widgets` | 1.1 GB | 19.7 GB |
| `cargo` | 5.4 GB | 13.0 GB |

About 600 bytes per instruction are kept (the decoded instruction with its text and the registers it
reads and writes), plus about 200 MB for the decompiler and the Sleigh specification of each session.
A first open uses up to 6 sessions at once. The peak of Qt Widgets is the switch analysis of its
worst functions running on several sessions at the same time; lower `KRAKEN_NATIVE_THREADS` to trade
time for memory. A smaller instruction representation is the next step if memory matters more.

## Through `krakend`

A native project through the daemon (a private daemon, the native worker next to it). The first open is
`project_create`; "reopen" is a new daemon opening the project from its saved state.

| `libzstd` (902 functions) | Before | After |
|---|---:|---:|
| `project_create` | 44 717 ms | 11 399 ms |
| reopen (new daemon) | 47 094 ms | 1 681 ms |
| `project_info` round trip, p50 | 0.22 ms | 0.17 to 0.22 ms |
| `list_functions`, 5 pages of 200: p50 | 3.71 ms | 4.31 ms |
| `list_functions` with a name filter: p50 | 2.35 ms | 2.74 ms |
| `rename_symbol`, one call | 394 ms | 5.3 ms |
| `undo`, one call | 366 ms | 4.5 ms |
| `kraken --json project-info` (a process per call), p50 | 9.0 ms | 8.5 ms |
| `kraken --json decompile`, p50 | 11.4 ms | 15.6 ms |
| View-model: select a function until its decompiler is ready, p50 | 10.8 ms | 8.8 ms |

| `libpcre2-8` (301 functions) | Before | After |
|---|---:|---:|
| `project_create` | 31 995 ms | 16 604 ms |
| reopen (new daemon) | 30 207 ms | 896 ms |
| `rename_symbol`, one call | 91 ms | 6.6 ms |

| `libpython` (11 270 functions) | Before | After |
|---|---:|---:|
| `project_create` | fails after 600 s | 308 s |
| reopen (new daemon) | not possible | 6.6 s |
| `project_info` round trip | | 0.17 ms |
| `list_functions`, 57 pages of 200: p50 / p95 | | 2.26 / 2.90 ms |
| `list_functions` with a name filter: p50 | | 13.8 ms |
| `rename_symbol` | | 8.8 ms |
| `kraken --json project-info`, p50 | | 6.6 ms |
| View-model: select, decompiler ready: p50 / p95 | | 6.4 / 156 ms |

The round trip through the daemon costs 0.2 ms; a `kraken` process per command costs 7 to 9 ms, almost
all of it starting the process. The GUI and the MCP server use the daemon without that cost.

## GUI frames

`cargo xtask bench gui` opens a project through a real daemon in the GUI's own test harness and
drives the whole application, frame by frame, as in the GUI's headless tests: scrolling the function
list, selecting the largest function of the binary, scrolling the decompiler and the listing, and
laying out, zooming and panning its graph. A "frame" here is everything the application does for it
(the view-model, layout and building the shapes) but not the GPU's work. Times in milliseconds.

`libpython`, largest function 0x413bf0 (67 780 bytes, 4 000 graph blocks):

| phase | frames | p50 | p95 | max |
|---|---:|---:|---:|---:|
| idle, function list | 100 | 0.13 | 0.16 | 0.25 |
| scroll the function list (300 frames, 200 to 1 800 rows loaded) | 300 | 0.22 | 0.31 | 0.46 |
| frames while the largest function decompiles (6 685 frames) | 6 685 | 0.41 | 0.58 | 5.76 |
| idle, large function | 100 | 0.29 | 0.38 | 0.49 |
| scroll the decompiler | 200 | 0.60 | 0.78 | 0.90 |
| scroll the listing | 200 | 0.49 | 0.55 | 0.81 |
| while the graph loads | 71 | 0.38 | 0.91 | 22.13 |
| graph, steady | 100 | 0.91 | 1.04 | 1.12 |
| graph, zoom in and out | 100 | 0.86 | 0.88 | 0.90 |
| graph, pan by wheel | 100 | 0.41 | 0.86 | 0.88 |

The graph's layout runs on its own thread; its data arrived 206 ms after the tab was brought to the
front, and the slowest frame while it loaded was 22 ms. Selecting the largest function takes 16 s to
decompile, but the frames stay under 6 ms meanwhile: no call blocks the UI thread, and none was
added. On the same machine and the same function list the frames were the same before this work
(`libzstd`: at most 2.4 ms in every phase), because none of the changes is on the GUI's side.

A long function list (the demo project with synthetic rows, nothing else loaded) costs little per
frame even at the size of the biggest programs:

| rows | idle p50 | scrolling p50 / p95 | one selected p50 |
|---|---:|---:|---:|
| 1 000 | 0.15 | 0.15 / 0.28 | 0.18 |
| 50 000 | 0.20 | 0.31 / 0.37 | 0.30 |
| 200 000 | 0.35 | 0.48 / 0.52 | 0.94 |

The list is virtualised; only the work that is proportional to the number of rows (the index of the
visible rows and finding the selected row) grows, to about a millisecond at 200 000 rows. The
widgets' graph stress test (3 000 blocks) draws 0.6 ms per frame with every block visible.

## Native engine and Ghidra

Both through the same daemon, on the same functions. The native engine's analysis job decompiles every
function once (to fill in signatures); Ghidra's runs its analyzers.

| `libzstd` | Native | Ghidra |
|---|---:|---:|
| `project_create` (first open) | 11.4 s | 4.9 s (import only) |
| `analyze` job | 805 s (553 s when run alone) | 199 s |
| reopen (new daemon) | 1.7 s | 3.7 s |
| `list_functions`, 5 pages of 200: p50 | 4.3 ms | 38.8 ms |
| `rename_symbol` | 5.3 ms | 115 ms |
| `xrefs to`: p50 | 0.13 ms | 0.41 ms |
| `cfg`: p50 / p95 | 0.32 / 9.1 ms | 1.7 / 12 ms |
| `disassemble` a function: p50 | 1.5 ms | 2.2 ms |
| `decompile`: p50 / p95 | 14.9 / 3 605 ms | 10.6 / 3 728 ms |
| `kraken --json decompile` (a process per call): p50 | 15.6 ms | 27.3 ms |

| `libpcre2-8` | Native | Ghidra |
|---|---:|---:|
| `project_create` (first open) | 16.6 s | 4.1 s (import only) |
| `analyze` job | 150 s | 155 s |
| reopen (new daemon) | 0.9 s | 4.0 s |
| `rename_symbol` | 6.6 ms | 110 ms |

The decompiler is the same C++ code in both, so its times agree; the native engine answers the
listing, cross-reference and edit queries 3 to 20 times faster than the JVM engine and reopens a project
faster. Its analysis job is slower on `libzstd`: it decompiles every function, including the few that take
20 seconds, one after another (the decompiler allows one decompile at a time per process).

## What is still slow

- **The first open of a big program.** Minutes for a few thousand functions, tens of minutes for the
  worst, all inside the decompiler's switch analysis. It is paid once per project. Reducing it further
  needs either fewer calls (the three overlapping entries of one Qt function each run the same 40-second
  analysis) or a decompiler that does less per jump table; neither is safe to change while the results
  have to stay identical.
- **The analysis job** decompiles every function one after another in the worker (553 s for the 902
  functions of `libzstd`, almost all of it in the 45 functions that take seconds each). A decompile in the
  GUI waits for the one in flight. Running decompiles side by side would need one session per thread
  with the same types and names in each.
- **Memory** for the largest programs (above).
- **Warm opens** (6 s for `libpython`, 26 s for `cargo`) are the decoding of every instruction with
  Sleigh. Spreading it over several sessions did not pay for the sessions' setup (measured: no change).

## Reproducing

```sh
cargo xtask native-src && cargo xtask native-sla      # once: the decompiler and its specifications
cargo xtask bench                                     # engine suite: libpython, cargo, libQt6Widgets
cargo xtask bench engine /usr/lib/libz.so.1           # engine suite on a binary of your own
cargo xtask bench daemon [binary...]                  # through a private krakend
cargo xtask bench gui [binary...]                     # GUI frames
cargo xtask bench widgets                             # the graph stress test
```

The suites are `#[ignore]` tests (`crates/engine-native/tests/bench.rs`,
`crates/kraken-viewmodel/tests/bench_daemon.rs`, `crates/kraken-gui/src/tests/bench.rs`) and print the
tables above. The first open of the big binaries takes a long time; keep the saved state with
`KRAKEN_BENCH_STATE=<dir>` to measure the reopen without paying for it twice. Other variables:
`KRAKEN_BENCH_SAMPLES` (functions per query, 200), `KRAKEN_BENCH_ANALYZE=1` (time the analysis job
and its stages), `KRAKEN_BENCH_IN_PROCESS=1` (no worker), `KRAKEN_NATIVE_THREADS`, and for the daemon
suite `KRAKEN_BENCH_ENGINE=ghidra` with `KRAKEN_GHIDRA_HOME`, `KRAKEN_JAVA_HOME` and
`KRAKEN_GHIDRA_EXT_JAR` (build the extension with `cargo xtask ghidra-ext`).
