use crate::state::{FunctionItem, FunctionList, is_library_stub};

fn item(address: u64, name: &str, size: Option<u64>) -> FunctionItem {
    FunctionItem {
        address,
        name: name.into(),
        size,
        signature: None,
        partial: false,
        stub: is_library_stub(name, size, None),
    }
}

#[test]
fn stubs_are_told_from_program_code() {
    assert!(is_library_stub("_init", Some(27), None));
    assert!(is_library_stub("_fini", None, None));
    assert!(is_library_stub("thunk_FUN_00401000", Some(40), None));
    assert!(is_library_stub("printf@plt", None, None));
    assert!(is_library_stub("free", Some(6), None));
    assert!(is_library_stub("x", Some(40), Some("void x(void) thunk")));
    assert!(!is_library_stub("process_packet", Some(240), None));
    assert!(!is_library_stub("FUN_00401440", Some(8), None));
    assert!(!is_library_stub("main", None, None));
    assert!(!is_library_stub("tiny", Some(0), None));
    assert!(!is_library_stub("get_count", Some(8), None));
    assert!(is_library_stub("__cxa_finalize", Some(16), None));
    assert!(!is_library_stub("free", Some(400), None));
}

#[test]
fn hiding_stubs_keeps_the_rest_in_order() {
    let list = FunctionList {
        items: vec![
            item(0x1000, "_init", Some(27)),
            item(0x1020, "free", Some(6)),
            item(0x1100, "main", Some(200)),
            item(0x1200, "checksum", Some(90)),
        ],
        ..FunctionList::default()
    };
    assert_eq!(list.visible(false), vec![0, 1, 2, 3]);
    assert_eq!(list.visible(true), vec![2, 3]);
}
