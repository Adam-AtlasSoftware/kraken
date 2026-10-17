// Reference translation of switch_vm `main`; the entry point of the program. Calls the
// translated `vm_run` and `op_name` and prints through the runtime shim.

#[repr(C)]
pub struct Vm {
    pub stack: [i32; 32],
    pub sp: i32,
    pub pc: u32,
    pub steps: u64,
}

/// Runs a fixed bytecode program (an arithmetic prelude, then a countdown from 5 that prints
/// each value) and prints the result, the step count and the name of the first opcode.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fn_101707() -> i32 {
    const PROG: [u8; 17] = [1, 6, 1, 7, 4, 1, 3, 14, 7, 1, 5, 11, 10, 5, 9, 11, 0];
    let mut vm = Vm {
        stack: [0; 32],
        sp: 0,
        pc: 0,
        steps: 0,
    };
    unsafe {
        let r = vm_run(&mut vm as *mut Vm as _, PROG.as_ptr() as _, PROG.len() as u32);
        let first = op_name(u32::from(PROG[0]));
        rt::printf(
            b"result=%d steps=%lu first=%s\n\0".as_ptr(),
            &[
                rt::Arg::Int(i64::from(r)),
                rt::Arg::UInt(vm.steps),
                rt::Arg::Ptr(first),
            ],
        );
    }
    0
}
