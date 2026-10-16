// Reference translation of switch_vm `vm_run` with its helpers push, pop and vm_fail
// (corpus/src/switch_vm.c).

const STACK_MAX: usize = 32;

#[repr(C)]
pub struct Vm {
    pub stack: [i32; STACK_MAX],
    pub sp: i32,
    pub pc: u32,
    pub steps: u64,
}

mod op {
    pub const HALT: u8 = 0;
    pub const PUSH: u8 = 1;
    pub const ADD: u8 = 2;
    pub const SUB: u8 = 3;
    pub const MUL: u8 = 4;
    pub const DUP: u8 = 5;
    pub const SWAP: u8 = 6;
    pub const DROP: u8 = 7;
    pub const NEG: u8 = 8;
    pub const JNZ: u8 = 9;
    pub const DEC: u8 = 10;
    pub const PRINT: u8 = 11;
    pub const AND: u8 = 12;
    pub const OR: u8 = 13;
    pub const XOR: u8 = 14;
}

fn vm_fail(msg: &str, pc: u32) -> ! {
    eprint!("vm error at pc={pc}: {msg}\n");
    std::process::exit(42)
}

fn push(vm: &mut Vm, v: i32) {
    if vm.sp >= STACK_MAX as i32 {
        vm_fail("stack overflow", vm.pc);
    }
    vm.stack[vm.sp as usize] = v;
    vm.sp += 1;
}

fn pop(vm: &mut Vm) -> i32 {
    if vm.sp <= 0 {
        vm_fail("stack underflow", vm.pc);
    }
    vm.sp -= 1;
    vm.stack[vm.sp as usize]
}

/// Runs bytecode `code[..len]` on `vm`; returns the top of stack at HALT (0 if empty).
///
/// # Safety
/// `vm` and `code` must be valid; `code` must be readable one byte past `len` (an operand or a
/// jump target is fetched without a bounds check, as in the original).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_run(vm: *mut Vm, code: *const u8, len: u32) -> i32 {
    let vm = unsafe { &mut *vm };
    let fetch = |at: u32| unsafe { *code.add(at as usize) };
    loop {
        if vm.pc >= len {
            vm_fail("pc out of range", vm.pc);
        }
        let opcode = fetch(vm.pc);
        vm.pc = vm.pc.wrapping_add(1);
        vm.steps = vm.steps.wrapping_add(1);
        match opcode {
            op::HALT => return if vm.sp != 0 { vm.stack[(vm.sp - 1) as usize] } else { 0 },
            op::PUSH => {
                let imm = fetch(vm.pc) as i8 as i32;
                vm.pc = vm.pc.wrapping_add(1);
                push(vm, imm);
            }
            op::ADD => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a.wrapping_add(b));
            }
            op::SUB => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a.wrapping_sub(b));
            }
            op::MUL => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a.wrapping_mul(b));
            }
            op::DUP => {
                let a = pop(vm);
                push(vm, a);
                push(vm, a);
            }
            op::SWAP => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, b);
                push(vm, a);
            }
            op::DROP => {
                pop(vm);
            }
            op::NEG => {
                let a = pop(vm);
                push(vm, a.wrapping_neg());
            }
            op::JNZ => {
                let a = pop(vm);
                if a != 0 {
                    vm.pc = u32::from(fetch(vm.pc));
                } else {
                    vm.pc = vm.pc.wrapping_add(1);
                }
            }
            op::DEC => {
                let a = pop(vm);
                push(vm, a.wrapping_sub(1));
            }
            op::PRINT => {
                // The original reads stack[sp - 1] without checking sp; do the same.
                let top = unsafe { *vm.stack.as_ptr().offset(vm.sp as isize - 1) };
                print!("out: {top}\n");
            }
            op::AND => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a & b);
            }
            op::OR => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a | b);
            }
            op::XOR => {
                let b = pop(vm);
                let a = pop(vm);
                push(vm, a ^ b);
            }
            _ => vm_fail("bad opcode", vm.pc.wrapping_sub(1)),
        }
    }
}
