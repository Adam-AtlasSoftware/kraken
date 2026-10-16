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
//!   "ghidra_version": "12.1.4",
//!   "program": { "arch": "x86:LE:64:default", "format": "elf", "base": "0x400000",
//!                "sha256": "<hex>", "size": 8192 },
//!   "functions": [
//!     { "summary":   { /* FunctionSummary: locator, name, size?, signature?, fn_hash?, completeness */ },
//!       "decompile": { /* DecompileResult: function, language?, text, tokens, warnings, completeness */ } }
//!   ],
//!   "types": [ /* TypeDef, internally tagged by "kind"; optional */ ],
//!   "recording": { /* optional provenance and caps, written by kraken-record */ }
//! }
//! ```
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
//! * [`FakeEngine::without`] removes a capability to exercise `unsupported` paths.
//!
//! # Perturb mode
//!
//! [`FakeEngine::perturbed`] applies a [`Perturb`] (shifted base, split and merged functions) to
//! the fixture first; see [`Perturb`] for the exact rules. `Perturb::apply(&fixture)
//! .expectations(path)` gives matching contract-suite expectations.

mod engine;
mod fixture;
mod text;

pub use engine::FakeEngine;
pub use fixture::{FixtureFile, FixtureFunction, Perturb, Recording};

#[cfg(test)]
mod tests;
