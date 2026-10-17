// Reference translation of switch_vm `pop`; calls the translated `vm_fail`.

#[repr(C)]
pub struct Vm {
    pub stack: [i32; 32],
    pub sp: i32,
    pub pc: u32,
    pub steps: u64,
}

/// Pops the top of the stack; an empty stack ends the program through `vm_fail`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pop(vm: *mut Vm) -> i32 {
    unsafe {
        if (*vm).sp <= 0 {
            vm_fail(b"stack underflow\0".as_ptr() as _, (*vm).pc);
        }
        (*vm).sp = (*vm).sp.wrapping_sub(1);
        (*vm).stack[(*vm).sp as usize]
    }
}
