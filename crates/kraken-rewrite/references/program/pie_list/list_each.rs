// Reference translation of pie_list `list_each`: calls a visitor on each record, head first.

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

#[repr(C)]
pub struct List {
    pub head: *mut Node,
    pub count: i32,
}

pub type VisitFn = unsafe extern "C" fn(*const Record, *mut u8);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn list_each(l: *const List, f: Option<VisitFn>, ctx: *mut u8) {
    unsafe {
        let mut n = (*l).head;
        while !n.is_null() {
            f.expect("visit callback")(&(*n).rec, ctx);
            n = (*n).next;
        }
    }
}
