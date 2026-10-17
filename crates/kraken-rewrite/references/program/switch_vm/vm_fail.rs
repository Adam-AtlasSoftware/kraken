// Reference translation of switch_vm `vm_fail` (corpus/src/switch_vm.c), written by hand and
// checked against the C source; program mode (the runtime shim `rt` is in scope).

/// Prints `vm error at pc=<pc>: <msg>` to stderr and exits with status 42.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_fail(msg: *const u8, pc: u32) {
    unsafe {
        rt::eprintf(
            b"vm error at pc=%u: %s\n\0".as_ptr(),
            &[rt::Arg::UInt(u64::from(pc)), rt::Arg::Ptr(msg)],
        );
    }
    rt::exit(42)
}
