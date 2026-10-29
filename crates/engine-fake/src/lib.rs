//! In-memory fake engine for tests, driven by JSON fixtures.
//!
//! [`FakeEngine`] implements every `kraken-engine` capability trait from a [`FixtureFile`].
//!
//! # Fixture format
//!
//! One JSON object (all addresses are `"0x..."` strings, all types are the `kraken-proto` wire
//! types):
//!
//! ```json
//! {
//!   "ghidra_version": "12.2",
//!   "program": { "arch": "x86:LE:64:default", "format": "elf", "base": "0x400000",
//!                "sha256": "<hex>", "size": 8192 },
//!   "functions": [
//!     { "summary":   { /* FunctionSummary: locator, name, size?, signature?, fn_hash?, completeness */ },
//!       "decompile": { /* DecompileResult: function, language?, text, tokens, warnings, completeness */ } }
//!   ],
//!   "types": [ /* TypeDef, internally tagged by "kind"; optional */ ],
//!   "memory": [ /* MemoryBlock; optional */ ],
//!   "strings": [ /* StringEntry; optional */ ],
//!   "imports": [ /* SymbolEntry; optional */ ],
//!   "exports": [ /* SymbolEntry; optional */ ],
//!   "recording": { /* optional provenance and caps, written by kraken-record */ }
//! }
//! ```
//!
//! A function may also carry `disassembly` (`DisasmRow` list of its body), `cfg` (`Cfg`) and
//! `xrefs` (`Xref` list: references from its body, plus any to its entry). Every one of these
//! program-data fields is optional; when absent the engine serves synthetic data derived from
//! the functions (see below), and an explicitly empty list stays empty.
//!
//! `decompile.function` must equal `summary.locator`; token spans must be valid for `text`.
//! Functions may appear in any order and are served ordered by (space, offset).
//!
//! # Semantics
//!
//! * Mutations change in-memory state only. A rename substitutes the old name for the new one
//!   (whole identifiers) in the decompiled text, token symbols and signature, keeping token spans
//!   valid. Only function-level renames are supported; other rename targets are `unsupported`.
//! * `CreateFunction` adds a function with a stub decompilation; `DeleteFunction` removes one
//!   (`not_found` if missing); `SetFunctionBounds` updates the size; the remaining ops validate
//!   their anchor and are recorded (see [`FakeEngine::applied_ops`]) without changing output.
//! * Re-applying a rename or create that is already in effect succeeds; a rename whose `old_name`
//!   differs from the current name is `conflict_stale_read`.
//! * Cursors are opaque `space:hexoffset` strings; listings are stable across deletes.
//! * Analysis is a job that sleeps briefly through the stages `load`, `core`, `expensive` (three
//!   progress events each) and honours cancellation.
//! * Program data, recorded or synthetic:
//!   * `memory_map`: the recorded blocks, else `.text` (r-x, covering the functions), `.rodata`,
//!     `.data` and an uninitialized `.bss`, one page each.
//!   * `read_bytes`: bytes of initialized blocks are the instruction bytes of recorded rows,
//!     elsewhere a fixed pseudo-random filler; uninitialized blocks read as zeros and are
//!     reported in `uninitialized`; the read stops where memory stops.
//!   * `disassemble`: a function's recorded rows, else one row per four bytes (`mov`, a `call`
//!     for each distinct decompiled call target, a final `ret`), whose bytes are the filler.
//!     Function scope starts at the entry; linear scope runs on through the next functions.
//!   * `xrefs`: the recorded references of all functions, else calls and jumps derived from the
//!     rows; `cfg`: the recorded graph, else one block over the listing; `strings`: the
//!     recorded list, else the string literals of the decompiled text, laid out in `.rodata`;
//!     `imports`: call targets that are not functions; `exports`: the lowest function.
//!   * A function rename also renames labels, symbol operands and reference names in the
//!     recorded listing; `SetFunctionBounds` discards a function's recorded listing, graph and
//!     references. Cursors of these listings are decimal indexes, or a `0x` address for
//!     `disassemble`.
//! * [`FakeEngine::without`] removes a capability to exercise `unsupported` paths.
//!
//! # Perturb mode
//!
//! [`FakeEngine::perturbed`] applies a [`Perturb`] (shifted base, split and merged functions) to
//! the fixture first; see [`Perturb`] for the exact rules. `Perturb::apply(&fixture)
//! .expectations(path)` gives matching contract-suite expectations.

mod data;
mod engine;
mod fixture;
mod text;

pub use engine::{FAKE_STATE_FILE, FakeEngine};
pub use fixture::{FixtureFile, FixtureFunction, Perturb, Recording};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_data;
