// Reference translation of pie_list `cmp_dist` (corpus/src/pie_list.c).

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

fn dist2(p: &Point) -> i32 {
    p.x.wrapping_mul(p.x).wrapping_add(p.y.wrapping_mul(p.y))
}

/// Squared distance from the origin of each record's position; returns their difference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cmp_dist(a: *const Record, b: *const Record) -> i32 {
    unsafe { dist2(&(*a).pos).wrapping_sub(dist2(&(*b).pos)) }
}
