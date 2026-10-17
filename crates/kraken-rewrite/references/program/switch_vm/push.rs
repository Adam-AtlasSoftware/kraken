// Reference translation of switch_vm `push`; calls the translated `vm_fail`.

#[repr(C)]
pub struct Vm {
    pub stack: [i32; 32],
    pub sp: i32,
    pub pc: u32,
    pub steps: u64,
}

/// Pushes `v`; a full stack ends the program through `vm_fail`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn push(vm: *mut Vm, v: i32) {
    unsafe {
        if (*vm).sp >= 32 {
            vm_fail(b"stack overflow\0".as_ptr() as _, (*vm).pc);
        }
        let sp = (*vm).sp;
        (*vm).stack[sp as usize] = v;
        (*vm).sp = sp.wrapping_add(1);
    }
}
