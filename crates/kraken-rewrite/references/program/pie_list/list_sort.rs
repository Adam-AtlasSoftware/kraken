// Reference translation of pie_list `list_sort`: bubble sort of the linked list by relinking
// nodes, with a comparison callback that receives the two records.

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

pub type CmpFn = unsafe extern "C" fn(*const Record, *const Record) -> i32;

/// Passes over the list until nothing is swapped; two neighbours swap when `cmp(a, b) > 0`.
/// `pp` points at the link that points at `a`, which is how the swap relinks without a
/// previous-node pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn list_sort(l: *mut List, cmp: Option<CmpFn>) {
    unsafe {
        loop {
            let mut swapped = false;
            let mut pp: *mut *mut Node = &mut (*l).head;
            while !(*pp).is_null() && !(**pp).next.is_null() {
                let a = *pp;
                let b = (*a).next;
                if cmp.expect("comparison callback")(&(*a).rec, &(*b).rec) > 0 {
                    (*a).next = (*b).next;
                    (*b).next = a;
                    *pp = b;
                    swapped = true;
                }
                pp = &mut (**pp).next;
            }
            if !swapped {
                break;
            }
        }
    }
}
