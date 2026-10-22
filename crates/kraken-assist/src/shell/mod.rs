//! The assistant's `shell` tool: a command in a sandbox, for arithmetic, bit twiddling, hashing,
//! hex and base64 and similar helper work, without adding context (one tool, one short
//! description).
//!
//! The sandbox ([`sandbox`], on `kraken-confine`) is the security boundary: no network, the
//! project's files read-only, one scratch directory writable for the session, nothing in it
//! executable. The [`policy`] only decides when the person is asked: a plain pipeline of known
//! harmless programs runs, a few programs are refused, anything else asks. Running the analysed
//! program is `emulate_run`'s job, never the shell's.

pub mod host;
pub mod policy;
pub mod sandbox;
pub mod tokenize;

pub use host::{SHELL_TOOL, ShellHost, ShellReview, review};
pub use policy::{ALLOW, NEVER, PROJECT_FILE, Policy, PolicyFileError, Verdict, add_project_allow};
pub use sandbox::{SHELL_OUTPUT_CHARS, ShellOutcome, ShellSession};
