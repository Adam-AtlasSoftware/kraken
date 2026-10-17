// Reference translation of pie_list `node_new`: allocates a zeroed node and fills its record.
// It returns a pointer, so the function-level test only compiles it.

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

#[repr(C)]
pub struct Node {
    pub rec: Record,
    pub next: *mut Node,
}

/// `calloc(1, sizeof *n)`, `exit(3)` when it fails, then the fields; the name is copied with
/// `strncpy` into at most 15 bytes (the last byte of the field stays NUL from `calloc`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node_new(
    id: i32,
    name: *const u8,
    x: i32,
    y: i32,
    w: f64,
) -> *const u8 {
    unsafe {
        let n = rt::calloc(1, std::mem::size_of::<Node>()) as *mut Node;
        if n.is_null() {
            rt::exit(3);
        }
        (*n).rec.id = id;
        rt::strncpy((*n).rec.name.as_mut_ptr(), name, 15);
        (*n).rec.pos.x = x;
        (*n).rec.pos.y = y;
        (*n).rec.weight = w;
        n as *const u8
    }
}
