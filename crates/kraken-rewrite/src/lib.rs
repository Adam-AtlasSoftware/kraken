//! KRAKEN rewrite pipeline core (decisions 2, 46, 53; ADR 0013).
//!
//! lift (KRAKEN decompile) -> translate ([`task::RewriteTask`], or reimplement from a cited spec,
//! [`task::SpecTask`]) -> differential test against the original under emulation
//! ([`oracle::FunctionOracle`], [`difftest`]) -> versioned record ([`unit::RewriteUnit`]) in
//! `<project>/rewrite.sqlite` ([`store::RewriteStore`]) -> accept (a user) -> export a Cargo
//! workspace with an FFI shim ([`export`]).
//!
//! The `rewrite_*` registry commands are defined in `kraken-registry`; [`service::RewriteService`]
//! is what runs them once attached with `Session::with_rewrite`. Generated code only ever runs
//! inside [`sandbox`]. The spike this grew from is described in `spikes/rewrite-loop/NOTES.md`.

pub mod abi;
pub mod blame;
pub mod clib;
pub mod collect;
pub mod difftest;
pub mod error;
pub mod export;
pub mod fetch;
pub mod infer;
pub mod lift;
pub mod lint;
pub mod native;
pub mod oracle;
pub mod pipeline;
pub mod plan;
pub mod process;
pub mod program;
pub mod repair;
pub mod reuse;
#[path = "runtime/rt.rs"]
#[allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]
pub mod rt;
pub mod sandbox;
pub mod service;
pub mod store;
pub mod targets;
pub mod task;
pub mod unit;

pub use error::RewriteError;
pub use service::{ConfigProvider, FixedProvider, ProviderSource, RewriteConfig, RewriteService};

/// The runtime shim ([`rt`]) as source text: the program crate's `src/rt.rs`.
pub const RT_SOURCE: &str = include_str!("runtime/rt.rs");

/// The shim as a private module `rt` for the function-level test of a translation (the module
/// documentation lines are dropped: they are inner attributes, which the lint refuses).
pub fn rt_module_source() -> String {
    let body: String = RT_SOURCE
        .lines()
        .filter(|l| !l.starts_with("//!"))
        .map(|l| format!("{l}\n"))
        .collect();
    format!("#[allow(dead_code, unused)]\nmod rt {{\n{body}}}\n")
}

/// What a program-mode prompt says about the runtime shim (trusted operator text).
pub const RT_PROMPT: &str = "\
The whole program is rewritten as one crate, and a runtime shim is in scope as the module `rt` \
(do not import, define or redeclare it; write `rt::strlen(s)`). It maps libc to Rust std. \
C strings are `*const u8` to NUL-terminated bytes. Available: `rt::printf(fmt, &[args])` and \
`rt::eprintf(fmt, &[args])` (C format strings; each variadic argument is an `rt::Arg::Int(i64)`, \
`rt::Arg::UInt(u64)`, `rt::Arg::Ptr(*const u8)` or `rt::Arg::Double(f64)`), \
`rt::snprintf(dst, n, fmt, &[args])`, `rt::puts`, \
`rt::fputs`, `rt::eputs`, `rt::putchar`, `rt::eputc`, `rt::fflush_stdout`, `rt::exit(code)`, \
`rt::abort`, `rt::strlen`, `rt::strnlen`, `rt::strcmp`, `rt::strncmp`, `rt::strcpy`, \
`rt::strncpy`, `rt::strcat`, `rt::strchr`, `rt::strrchr`, `rt::strstr`, `rt::strdup`, \
`rt::memcpy`, `rt::memmove`, `rt::memset`, `rt::memcmp`, `rt::memchr`, `rt::isspace`, \
`rt::isdigit`, `rt::isalpha`, `rt::isalnum`, `rt::isupper`, `rt::islower`, `rt::isxdigit`, \
`rt::isprint`, `rt::ispunct`, `rt::toupper`, `rt::tolower`, `rt::malloc`, `rt::calloc`, \
`rt::realloc`, `rt::free`, `rt::abs`, `rt::labs`, `rt::strtol`, `rt::atoi`, `rt::atol`. \
Calling the shim is preferred over re-deriving a libc function; `print!`, `eprint!` and \
`std::process::exit` remain fine where the decompile prints a constant or exits. A translated \
function that another translated function calls keeps its C ABI (`extern \"C\"`, integers and \
raw pointers); a pointer result is a `*const u8`.";

/// Identifies the emulator build in unit records.
pub const EMULATOR_PIN: &str = "icicle-emu@638508b72f480f9be6fe2e267ef09de8f1541f9a";
/// Oracle kind in unit records.
pub const ORACLE_KIND: &str = "icicle-emu/x86-64-sleigh";
