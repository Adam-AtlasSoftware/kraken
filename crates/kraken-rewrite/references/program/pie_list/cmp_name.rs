// Reference translation of pie_list `cmp_name`: `strcmp` of the names (called through a function
// pointer only).

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
pub unsafe extern "C" fn cmp_name(a: *const Record, b: *const Record) -> i32 {
    unsafe { rt::strcmp((*a).name.as_ptr(), (*b).name.as_ptr()) }
}
