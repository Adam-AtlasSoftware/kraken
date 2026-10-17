// Reference translation of pie_list `main`; the entry point of the program. Builds a list of four
// records, sorts it three ways through comparison callbacks, prints it with a visitor and sums the
// weights with another. The callbacks are other translated functions passed by address.

#[repr(C)]
pub struct List {
    pub head: *mut u8,
    pub count: i32,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fn_1014da() -> i32 {
    let mut l = List {
        head: std::ptr::null_mut(),
        count: 0,
    };
    let lp = &mut l as *mut List;
    unsafe {
        list_push(lp as _, node_new(3, b"gamma\0".as_ptr() as _, 5, 1, 2.5) as _);
        list_push(lp as _, node_new(1, b"delta\0".as_ptr() as _, -2, 7, 1.25) as _);
        list_push(lp as _, node_new(2, b"alpha\0".as_ptr() as _, 0, 3, 9.0) as _);
        list_push(lp as _, node_new(4, b"beta\0".as_ptr() as _, 1, 1, 0.5) as _);

        // The table of orders: a label and the comparison function, as addresses.
        let orders: [(&[u8], usize); 3] = [
            (b"by id\0", cmp_id as usize),
            (b"by name\0", cmp_name as usize),
            (b"by distance\0", cmp_dist as usize),
        ];
        for (label, cmp) in orders.iter() {
            rt::printf(b"%s:\n\0".as_ptr(), &[rt::Arg::Ptr(label.as_ptr())]);
            list_sort(lp as _, std::mem::transmute::<usize, _>(*cmp));
            list_each(
                lp as _,
                std::mem::transmute::<usize, _>(print_rec as usize),
                std::ptr::null_mut(),
            );
        }
        let mut total: f64 = 0.0;
        list_each(
            lp as _,
            std::mem::transmute::<usize, _>(sum_weight as usize),
            &mut total as *mut f64 as _,
        );
        rt::printf(
            b"count=%d total=%.2f\n\0".as_ptr(),
            &[rt::Arg::Int(i64::from(l.count)), rt::Arg::Double(total)],
        );
        list_free(lp as _);
    }
    0
}
