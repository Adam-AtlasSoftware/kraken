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
pub mod build;
pub mod clib;
pub mod collect;
pub mod difftest;
pub mod error;
pub mod export;
pub mod fetch;
pub mod hints;
pub mod image;
pub mod infer;
pub mod layouts;
pub mod lift;
pub mod link;
pub mod lint;
pub mod metering;
pub mod native;
pub mod oracle;
pub mod pipeline;
pub mod plan;
pub mod process;
pub mod program;
#[path = "runtime/ptrdesc.rs"]
pub mod ptrdesc;
pub mod repair;
pub mod reuse;
#[path = "runtime/rt.rs"]
#[allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]
pub mod rt;
pub mod sandbox;
pub mod service;
pub mod source_patch;
pub mod store;
pub mod targets;
pub mod task;
pub mod unit;

pub use error::RewriteError;
pub use service::{
    BackendSource, ConfigBackend, FixedBackend, FixedProvider, RewriteConfig, RewriteService,
};

/// [`ptrdesc`] as source text, pasted into the function-level test runner.
pub const PTRDESC_SOURCE: &str = include_str!("runtime/ptrdesc.rs");

/// The runtime shim ([`rt`]) as source text: the program crate's `src/rt.rs`.
pub const RT_SOURCE: &str = include_str!("runtime/rt.rs");

/// The shim as a module `rt` for the function-level test of a translation (the module
/// documentation lines are dropped: they are inner attributes). The shim is KRAKEN's own code:
/// it is compiled in front of the translation but not put through the translation lint (it
/// opens the files the program opens, inside the sandbox), and the module is visible to the
/// test runner, which installs the program image through it.
pub fn rt_module_source() -> String {
    let body: String = RT_SOURCE
        .lines()
        .filter(|l| !l.starts_with("//!"))
        .map(|l| format!("{l}\n"))
        .collect();
    format!("#[allow(dead_code, unused)]\npub(crate) mod rt {{\n{body}}}\n")
}

/// What a program-mode prompt says about the runtime shim (trusted operator text).
pub const RT_PROMPT: &str = "\
The whole program is rewritten as one crate, and a runtime shim is in scope as the module `rt` \
(do not import, define or redeclare it; write `rt::strlen(s)`). It maps the C library to Rust \
std with the same results, so call it wherever the decompile calls the C library. C strings are \
`*const u8` to NUL-terminated bytes. Output: `rt::printf(fmt, &[args])`, \
`rt::eprintf(fmt, &[args])`, `rt::fprintf(stream, fmt, &[args])`, \
`rt::snprintf(dst, n, fmt, &[args])` and `rt::sprintf(dst, fmt, &[args])` take C format strings \
with each variadic argument as an `rt::Arg::Int(i64)`, `rt::Arg::UInt(u64)`, \
`rt::Arg::Ptr(*const u8)` or `rt::Arg::Double(f64)` (a `float` argument is passed as a double, \
as C does); `rt::puts`, `rt::putchar`, `rt::eputs`, `rt::eputc`, `rt::fflush_stdout`. Streams \
(`*mut rt::FILE`): `rt::stdin()`, `rt::stdout()`, `rt::stderr()`, `rt::fopen`, `rt::fclose`, \
`rt::fwrite(ptr, size, n, stream)`, `rt::fread`, `rt::fputs(s, stream)`, `rt::fputc(c, stream)`, \
`rt::fgetc`, `rt::getchar`, `rt::ungetc`, `rt::fgets`, `rt::fflush`, `rt::feof`, `rt::ferror`, \
`rt::fseek`, `rt::ftell`, `rt::rewind`, `rt::remove`, `rt::perror`, `rt::strerror`, \
`rt::errno()`, `rt::errno_location()`. Process: `rt::exit(code)`, `rt::abort`, `rt::atexit`, \
`rt::getenv`. Strings and memory: `rt::strlen`, `rt::strnlen`, `rt::strcmp`, `rt::strncmp`, \
`rt::strcasecmp`, `rt::strncasecmp`, `rt::strcpy`, `rt::strncpy`, `rt::strcat`, `rt::strncat`, \
`rt::strchr`, `rt::strrchr`, `rt::strstr`, `rt::strspn`, `rt::strcspn`, `rt::strpbrk`, \
`rt::strdup`, `rt::memcpy`, `rt::memmove`, `rt::memset`, `rt::memcmp`, `rt::memchr`. Characters: \
`rt::isspace`, `rt::isdigit`, `rt::isalpha`, `rt::isalnum`, `rt::isupper`, `rt::islower`, \
`rt::isxdigit`, `rt::isprint`, `rt::ispunct`, `rt::toupper`, `rt::tolower`. Memory: \
`rt::malloc`, `rt::calloc`, `rt::realloc`, `rt::free`. Numbers: `rt::abs`, `rt::labs`, \
`rt::strtol` (also for `__isoc23_strtol`), `rt::strtoul`, `rt::strtoll`, `rt::strtoull`, \
`rt::atoi`, `rt::atol`, `rt::strtod`, `rt::strtof`, `rt::atof`, `rt::qsort`, `rt::bsearch`, \
`rt::rand`, `rt::srand`. Math with C semantics: `rt::sqrt`, `rt::sqrtf`, `rt::sin`, `rt::sinf`, \
`rt::cos`, `rt::cosf`, `rt::tan`, `rt::tanf`, `rt::atan`, `rt::atan2`, `rt::atan2f`, `rt::exp`, \
`rt::expf`, `rt::exp2`, `rt::exp2f`, `rt::log`, `rt::logf`, `rt::log2`, `rt::log2f`, \
`rt::log10`, `rt::log10f`, `rt::pow`, `rt::powf`, `rt::floor`, `rt::floorf`, `rt::ceil`, \
`rt::ceilf`, `rt::round`, `rt::roundf`, `rt::trunc`, `rt::truncf`, `rt::rint`, `rt::rintf`, \
`rt::lround`, `rt::lroundf`, `rt::lrint`, `rt::lrintf`, `rt::fabs`, `rt::fabsf`, `rt::fmod`, \
`rt::fmodf`, `rt::fmin`, `rt::fmax`, `rt::fminf`, `rt::fmaxf`, `rt::hypot`, `rt::ldexp`. C++ \
runtime: `rt::operator_new(n)` (`operator new`, also `new[]`), `rt::operator_delete(p)` (every \
`operator delete`), `rt::throw_length_error(msg)`, `rt::throw_out_of_range(msg)`, \
`rt::throw_logic_error(msg)`, `rt::throw_invalid_argument(msg)`, `rt::throw_bad_alloc()` (an \
exception nobody catches: the program ends as libstdc++ ends it), `rt::cxa_guard_acquire`, \
`rt::cxa_guard_release`, `rt::cxa_atexit`, `rt::cxa_pure_virtual`, `rt::stack_chk_fail`, \
`rt::unwind_resume` (for `_Unwind_Resume` on a cleanup path). Calling the shim is preferred \
over re-deriving a C library function; `print!`, `eprint!` and `std::process::exit` remain \
fine where the decompile prints a constant or exits. A translated function that another \
translated function calls keeps its C ABI (`extern \"C\"`, integers, floats and raw pointers); \
a pointer result is a `*const u8`.";

/// Identifies the emulator build in unit records.
pub const EMULATOR_PIN: &str = "icicle-emu@638508b72f480f9be6fe2e267ef09de8f1541f9a";
/// Oracle kind in unit records.
pub const ORACLE_KIND: &str = "icicle-emu/x86-64-sleigh";
