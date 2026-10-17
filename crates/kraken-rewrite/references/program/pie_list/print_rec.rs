// Reference translation of pie_list `print_rec`: one line per record (called through a function
// pointer only). The decompile lists the arguments of the variadic call in register order; the C
// source passes id, name, x, y and weight.

#[repr(C)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
pub struct Record {
    pub id: i32,
    pub name: [u8; 16],
    pub pos: Point,
    pub weight: f64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn print_rec(r: *const Record, _ctx: *mut u8) {
    unsafe {
        rt::printf(
            b"  #%d %-6s (%d,%d) %.1f\n\0".as_ptr(),
            &[
                rt::Arg::Int(i64::from((*r).id)),
                rt::Arg::Ptr((*r).name.as_ptr()),
                rt::Arg::Int(i64::from((*r).pos.x)),
                rt::Arg::Int(i64::from((*r).pos.y)),
                rt::Arg::Double((*r).weight),
            ],
        );
    }
}
