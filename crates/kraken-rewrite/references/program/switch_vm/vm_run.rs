// Reference translation of switch_vm `vm_run`; calls the translated `push`, `pop` and `vm_fail`.

#[repr(C)]
pub struct Vm {
    pub stack: [i32; 32],
    pub sp: i32,
    pub pc: u32,
    pub steps: u64,
}

/// Runs bytecode `code[..len]` on `vm`; returns the top of the stack at HALT (0 when empty).
/// An operand or a jump target is fetched without a bounds check, as in the original.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_run(vm: *mut Vm, code: *const u8, len: u32) -> i32 {
    unsafe {
        loop {
            if (*vm).pc >= len {
                vm_fail(b"pc out of range\0".as_ptr() as _, (*vm).pc);
            }
            let op = *code.add((*vm).pc as usize);
            (*vm).pc = (*vm).pc.wrapping_add(1);
            (*vm).steps = (*vm).steps.wrapping_add(1);
            match op {
                0 => {
                    return if (*vm).sp != 0 {
                        (*vm).stack[((*vm).sp - 1) as usize]
                    } else {
                        0
                    };
                }
                1 => {
                    let imm = *code.add((*vm).pc as usize) as i8 as i32;
                    (*vm).pc = (*vm).pc.wrapping_add(1);
                    push(vm as _, imm);
                }
                2 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a.wrapping_add(b));
                }
                3 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a.wrapping_sub(b));
                }
                4 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a.wrapping_mul(b));
                }
                5 => {
                    let a = pop(vm as _);
                    push(vm as _, a);
                    push(vm as _, a);
                }
                6 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, b);
                    push(vm as _, a);
                }
                7 => {
                    pop(vm as _);
                }
                8 => {
                    let a = pop(vm as _);
                    push(vm as _, a.wrapping_neg());
                }
                9 => {
                    let a = pop(vm as _);
                    if a != 0 {
                        (*vm).pc = u32::from(*code.add((*vm).pc as usize));
                    } else {
                        (*vm).pc = (*vm).pc.wrapping_add(1);
                    }
                }
                10 => {
                    let a = pop(vm as _);
                    push(vm as _, a.wrapping_sub(1));
                }
                11 => {
                    // The original reads stack[sp - 1] without checking sp; so does this.
                    let top = *(*vm).stack.as_ptr().offset((*vm).sp as isize - 1);
                    rt::printf(b"out: %d\n\0".as_ptr(), &[rt::Arg::Int(i64::from(top))]);
                }
                12 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a & b);
                }
                13 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a | b);
                }
                14 => {
                    let b = pop(vm as _);
                    let a = pop(vm as _);
                    push(vm as _, a ^ b);
                }
                _ => vm_fail(b"bad opcode\0".as_ptr() as _, (*vm).pc.wrapping_sub(1)),
            }
        }
    }
}
