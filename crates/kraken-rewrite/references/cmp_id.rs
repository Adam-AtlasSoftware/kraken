// Reference translation of pie_list `cmp_id` (corpus/src/pie_list.c).

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

/// `return a->id - b->id;` The subtraction wraps, as the generated code does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cmp_id(a: *const Record, b: *const Record) -> i32 {
    unsafe { (*a).id.wrapping_sub((*b).id) }
}
