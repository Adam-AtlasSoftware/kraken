// Reference translation of switch_vm `op_name`: the mnemonic of an opcode, as a pointer to a
// NUL-terminated static string (so the function-level test only compiles it: pointers are not
// comparable between the original and the Rust build).

#[unsafe(no_mangle)]
pub unsafe extern "C" fn op_name(op: u32) -> *const u8 {
    let name: &'static [u8] = match op {
        0 => b"halt\0",
        1 => b"push\0",
        2 => b"add\0",
        3 => b"sub\0",
        4 => b"mul\0",
        5 => b"dup\0",
        6 => b"swap\0",
        7 => b"drop\0",
        8 => b"neg\0",
        9 => b"jnz\0",
        10 => b"dec\0",
        11 => b"print\0",
        12 => b"and\0",
        13 => b"or\0",
        14 => b"xor\0",
        _ => b"?\0",
    };
    name.as_ptr()
}
