// Reference translation of pie_list `list_free`: frees every node and empties the list.

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn list_free(l: *mut List) {
    unsafe {
        while !(*l).head.is_null() {
            let n = (*l).head;
            (*l).head = (*n).next;
            rt::free(n as *mut u8);
        }
        (*l).count = 0;
    }
}
