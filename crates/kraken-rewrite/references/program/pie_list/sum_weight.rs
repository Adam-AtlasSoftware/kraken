// Reference translation of pie_list `sum_weight`: adds a record's weight to the double `ctx`
// points to (called through a function pointer only).

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
pub unsafe extern "C" fn sum_weight(r: *const Record, ctx: *mut u8) {
    unsafe {
        *(ctx as *mut f64) += (*r).weight;
    }
}
