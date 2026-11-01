// ----- C++ runtime: allocation, exceptions, static-initialisation guards -----
//
// This file is appended to rt.rs in the generated crate (and in front of a function-level
// translation inside `mod rt`), so it shares rt.rs's private helpers (`die`, `c_str_bytes`,
// `malloc`, `free`). It is not compiled on its own in kraken-rewrite.
//
// Exceptions. A C++ `throw` is `throw(type, what)`: an unwinding Rust panic carrying a
// `CxxException`, when a `try_catch` is active on the thread, and libstdc++'s `terminate`
// (message on stderr, `abort`) when none is, so a program that lets an exception escape ends
// as the original does. `try_catch(body)` runs the body and returns what it threw as `Err`;
// a handler that does not take the exception gives it back with `rethrow(e)` (what `catch (...)
// { throw; }` and the cleanup path ending in `_Unwind_Resume` do). Rust panics that are not C++
// exceptions pass through untouched. Handlers that match by type compare `e.type_name`, which
// is the C++ type as the throw site spells it (`std::runtime_error`); a handler for a base class
// lists the derived names it accepts.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxxException {
    pub type_name: String,
    pub what: String,
}

impl CxxException {
    /// `what()` as a NUL-terminated string that lives as long as the program.
    pub fn what_ptr(&self) -> *const u8 {
        let mut v = self.what.clone().into_bytes();
        v.push(0);
        Box::leak(v.into_boxed_slice()).as_ptr()
    }
}

thread_local! {
    static CATCH_DEPTH: std::cell::Cell<u32> = std::cell::Cell::new(0);
}

fn terminate_after(type_name: &str, what: &str) -> ! {
    die(&format!(
        "terminate called after throwing an instance of '{type_name}'\n  what():  {what}\n"
    ))
}

/// Throws a C++ exception of type `type_name` with `what()` text `what`.
pub fn throw(type_name: &str, what: &str) -> ! {
    rethrow(CxxException {
        type_name: type_name.to_string(),
        what: what.to_string(),
    })
}

/// Throws `e` again (`throw;` in a handler).
pub fn rethrow(e: CxxException) -> ! {
    if CATCH_DEPTH.with(|d| d.get()) == 0 {
        terminate_after(&e.type_name, &e.what);
    }
    std::panic::resume_unwind(Box::new(e))
}

/// Runs `body`; a C++ exception thrown inside it (and not caught inside) is returned as `Err`.
pub fn try_catch<T>(body: impl FnOnce() -> T) -> Result<T, CxxException> {
    CATCH_DEPTH.with(|d| d.set(d.get() + 1));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    CATCH_DEPTH.with(|d| d.set(d.get() - 1));
    match r {
        Ok(v) => Ok(v),
        Err(p) => match p.downcast::<CxxException>() {
            Ok(e) => Err(*e),
            Err(other) => std::panic::resume_unwind(other),
        },
    }
}

/// `operator new` / `operator new[]`: never null (out of memory ends the program like an
/// uncaught `std::bad_alloc`).
pub fn operator_new(n: usize) -> *mut u8 {
    let p = unsafe { malloc(n.max(1)) };
    if p.is_null() {
        throw("std::bad_alloc", "std::bad_alloc");
    }
    p
}

/// `operator delete` / `operator delete[]`, sized or not.
///
/// # Safety
/// As [`free`].
pub unsafe fn operator_delete(p: *mut u8) {
    unsafe { free(p) }
}

/// `std::__throw_length_error(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_length_error(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::length_error", &w)
}

/// `std::__throw_out_of_range(what)` (also `__throw_out_of_range_fmt` with its text).
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_out_of_range(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::out_of_range", &w)
}

/// `std::__throw_bad_alloc()`.
pub fn throw_bad_alloc() -> ! {
    throw("std::bad_alloc", "std::bad_alloc")
}

/// `std::__throw_logic_error(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_logic_error(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::logic_error", &w)
}

/// `std::__throw_invalid_argument(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_invalid_argument(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::invalid_argument", &w)
}

/// `__cxa_pure_virtual`.
pub fn cxa_pure_virtual() -> ! {
    die("pure virtual method called\nterminate called without an active exception\n")
}

/// `__stack_chk_fail`.
pub fn stack_chk_fail() -> ! {
    die("*** stack smashing detected ***: terminated\n")
}

/// `_Unwind_Resume` on a path with no exception in hand: nothing to resume, so the program
/// ends as libstdc++ ends it. A cleanup path that holds the exception from `try_catch` calls
/// `rethrow(e)` instead.
pub fn unwind_resume() -> ! {
    die("terminate called without an active exception\n")
}

/// `__cxa_guard_acquire`: 1 when the caller must run the initialiser of a function-local static.
///
/// # Safety
/// `guard` points to the 8-byte guard of the static (in the program image).
pub unsafe fn cxa_guard_acquire(guard: *mut u64) -> i32 {
    i32::from(unsafe { *(guard as *const u8) } == 0)
}

/// `__cxa_guard_release`: marks the static initialised.
///
/// # Safety
/// As [`cxa_guard_acquire`].
pub unsafe fn cxa_guard_release(guard: *mut u64) {
    unsafe { *(guard as *mut u8) = 1 };
}

/// `__cxa_guard_abort`.
pub fn cxa_guard_abort(_guard: *mut u64) {}

