// Reference translation of pie_list `list_push`: puts a node at the head of the list.

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

/// `n->next = l->head; l->head = n; l->count++;`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn list_push(l: *mut List, n: *mut Node) {
    unsafe {
        (*n).next = (*l).head;
        (*l).head = n;
        (*l).count = (*l).count.wrapping_add(1);
    }
}
