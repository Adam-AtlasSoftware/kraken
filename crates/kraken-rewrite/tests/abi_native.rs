//! The call description beyond integers and flat buffers, on the native side only (no emulator,
//! so no Ghidra install): `double` parameters and results, host callbacks for function-pointer
//! parameters, and pointer graphs (objects that point to each other). The emulator side of the
//! same ABI is in `tests/oracle_abi.rs` and needs the SLEIGH specs of a Ghidra install.

use kraken_rewrite::abi::{Arg, Callback, Link, Param, Ret, Signature, Termination};
use kraken_rewrite::difftest::{
    Generator, InputSpec, IntGen, ObjectGen, ParamGen, SlotGen, TextGen, compare,
};
use kraken_rewrite::native::{Build, NativeRunner, build};
use kraken_rewrite::sandbox::{self, Confinement};

fn can_confine() -> bool {
    if sandbox::enforced() {
        true
    } else {
        eprintln!("skipped: this host cannot confine generated code");
        false
    }
}

fn runner(sig: &Signature, code: &str) -> NativeRunner {
    match build(sig, code, &Confinement::default()).expect("build") {
        Build::Ready(r) => r,
        Build::Rejected(why) => panic!("rejected: {why}"),
    }
}

fn i32_ret() -> Ret {
    Ret::Int {
        bits: 32,
        signed: true,
    }
}

fn int(v: i64) -> Param {
    let _ = v;
    Param::Int {
        bits: 32,
        signed: true,
    }
}

#[test]
fn doubles_travel_as_bit_patterns_in_and_out() {
    if !can_confine() {
        return;
    }
    let sig = Signature {
        name: "scale".into(),
        params: vec![Param::Double, int(0)],
        ret: Ret::Double,
    };
    let r = runner(
        &sig,
        r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn scale(x: f64, n: i32) -> f64 { x * n as f64 }"#,
    );
    let obs = r
        .run(&[
            Arg::Double {
                bits: 2.5f64.to_bits(),
            },
            Arg::Int { value: 4 },
        ])
        .expect("run");
    assert_eq!(obs.termination, Termination::Returned);
    assert_eq!(obs.ret, Some(10.0f64.to_bits()));
}

#[test]
fn a_callback_is_called_recorded_and_answers_by_the_values_its_arguments_point_to() {
    if !can_confine() {
        return;
    }
    let sig = Signature {
        name: "apply".into(),
        params: vec![Param::Buf, Param::Buf, Param::FnPtr],
        ret: i32_ret(),
    };
    let r = runner(
        &sig,
        r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn apply(
    a: *mut u8,
    b: *mut u8,
    cmp: Option<unsafe extern "C" fn(*mut u8, *mut u8) -> i32>,
) -> i32 {
    match cmp {
        Some(f) => unsafe { f(a, b) + f(b, a) * 10 },
        None => -1,
    }
}"#,
    );
    let buf = |v: i32| {
        let mut d = v.to_le_bytes().to_vec();
        d.extend([0u8; 12]);
        Arg::Buf { data: d }
    };
    for (cb, expect) in [
        (Callback::Ascending, 5 - 50),
        (Callback::Descending, -5 + 50),
    ] {
        let obs = r
            .run(&[buf(12), buf(7), Arg::FnPtr { callback: cb }])
            .expect("run");
        assert_eq!(obs.termination, Termination::Returned);
        assert_eq!(obs.ret, Some(expect as u32 as u64), "{cb:?}");
        // Both calls are recorded, with the objects they were given and what those hold.
        assert_eq!(obs.callbacks.len(), 2, "{:?}", obs.callbacks);
        assert!(
            obs.callbacks[0].starts_with(&format!("cb{}(o0+0=c,o1+0=7)=", cb.index())),
            "{:?}",
            obs.callbacks
        );
        assert!(
            obs.callbacks[1].contains("(o1+0=7,o0+0=c)"),
            "{:?}",
            obs.callbacks
        );
    }
    // A translation that never calls it differs from one that does.
    let silent = runner(
        &sig,
        r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn apply(
    a: *mut u8,
    b: *mut u8,
    cmp: Option<unsafe extern "C" fn(*mut u8, *mut u8) -> i32>,
) -> i32 {
    5 - 50
}"#,
    );
    let args = [
        buf(12),
        buf(7),
        Arg::FnPtr {
            callback: Callback::Ascending,
        },
    ];
    let called = r.run(&args).expect("run");
    let skipped = silent.run(&args).expect("run");
    let d = compare(&called, &skipped);
    assert!(d.iter().any(|x| x.contains("callback")), "{d:?}");
}

/// `struct node { int value; int _pad; struct node *next; }` and `sum(struct list *)` where the
/// list is `{ node *head; int count; }`.
const SUM_LIST: &str = r#"#[repr(C)]
pub struct Node { value: i32, pad: i32, next: *mut Node }
#[repr(C)]
pub struct List { head: *mut Node, count: i32 }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sum(l: *mut List) -> i32 {
    let mut total = 0;
    let mut n = unsafe { (*l).head };
    let mut seen = 0;
    while !n.is_null() && seen < 100 {
        total += unsafe { (*n).value };
        n = unsafe { (*n).next };
        seen += 1;
    }
    total * 1000 + unsafe { (*l).count }
}"#;

fn list_graph(values: &[i32]) -> Arg {
    let mut list = vec![0u8; 16];
    list[8..12].copy_from_slice(&(values.len() as i32).to_le_bytes());
    let mut objects = vec![list];
    let mut links = Vec::new();
    for (i, v) in values.iter().enumerate() {
        let mut n = vec![0u8; 16];
        n[0..4].copy_from_slice(&v.to_le_bytes());
        objects.push(n);
        links.push(Link {
            from: i, // object 0 is the list; node k is object k + 1 and links from node k - 1
            offset: if i == 0 { 0 } else { 8 },
            to: i + 1,
            to_offset: 0,
        });
    }
    Arg::Graph { objects, links }
}

#[test]
fn a_pointer_graph_is_laid_out_with_its_embedded_pointers() {
    if !can_confine() {
        return;
    }
    let sig = Signature {
        name: "sum".into(),
        params: vec![Param::Buf],
        ret: i32_ret(),
    };
    let r = runner(&sig, SUM_LIST);
    let obs = r.run(&[list_graph(&[3, 4, 5])]).expect("run");
    assert_eq!(obs.termination, Termination::Returned);
    assert_eq!(obs.ret, Some(12 * 1000 + 3));
    // The objects come back in order, with the pointers as the addresses they were given: the
    // same on any side that places objects where `abi::place_object` says.
    assert_eq!(obs.buffers.len(), 4);
    let (_, _, at1) = kraken_rewrite::abi::place_object(1, 16);
    assert_eq!(&obs.buffers[0][0..8], &at1.to_le_bytes());
    let empty = r.run(&[list_graph(&[])]).expect("run");
    assert_eq!(empty.ret, Some(0));
}

#[test]
fn reading_past_an_object_faults_like_it_does_in_the_emulator() {
    if !can_confine() {
        return;
    }
    let sig = Signature {
        name: "peek".into(),
        params: vec![Param::Buf],
        ret: i32_ret(),
    };
    let r = runner(
        &sig,
        r#"#[unsafe(no_mangle)]
pub unsafe extern "C" fn peek(p: *mut u8) -> i32 { unsafe { *p.add(8) as i32 } }"#,
    );
    let inside = r.run(&[Arg::Buf { data: vec![1; 9] }]).expect("run");
    assert_eq!(inside.termination, Termination::Returned);
    let outside = r.run(&[Arg::Buf { data: vec![1; 8] }]).expect("run");
    assert!(
        matches!(outside.termination, Termination::Fault { .. }),
        "{:?}",
        outside.termination
    );
}

#[test]
fn generators_build_linked_lists_texts_and_mixed_structs() {
    // A list: `head` points at a chain of nodes linked through `next`, `count` is the length.
    let node = ObjectGen {
        size: 16,
        pad: 0,
        fields: vec![kraken_rewrite::difftest::FieldGen {
            offset: 0,
            value: IntGen::full(32, true),
        }],
        doubles: Vec::new(),
        slots: Vec::new(),
        count_at: None,
    };
    let list = ObjectGen {
        size: 16,
        pad: 0,
        fields: Vec::new(),
        doubles: Vec::new(),
        slots: vec![(
            0,
            SlotGen::Chain {
                node: Box::new(node),
                next_offset: 8,
                min: 0,
                max: 4,
            },
        )],
        count_at: Some(8),
    };
    let spec = InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(vec![ParamGen::Graph(list)]),
    };
    let cases = spec.cases(7, 40);
    let mut lengths = std::collections::BTreeSet::new();
    for c in &cases {
        let Arg::Graph { objects, links } = &c[0] else {
            panic!("not a graph");
        };
        kraken_rewrite::abi::check_graph(objects, links).expect("well formed");
        let count = i32::from_le_bytes(objects[0][8..12].try_into().expect("count"));
        assert_eq!(count as usize + 1, objects.len(), "count matches the chain");
        assert_eq!(links.len(), count as usize, "one link per member");
        lengths.insert(count);
    }
    assert!(lengths.len() >= 3, "chain lengths vary: {lengths:?}");
    // The same seed gives the same cases.
    assert_eq!(spec.cases(7, 40).len(), cases.len());
    assert_eq!(
        format!("{:?}", spec.cases(7, 5)),
        format!("{:?}", spec.cases(7, 5))
    );

    // A parser struct: a pointer to NUL-terminated text and an int.
    let parser = ObjectGen {
        size: 16,
        pad: 16,
        fields: vec![kraken_rewrite::difftest::FieldGen {
            offset: 8,
            value: IntGen {
                bits: 32,
                signed: true,
                range: Some((0, 1)),
            },
        }],
        doubles: Vec::new(),
        slots: vec![(
            0,
            SlotGen::Text(TextGen {
                min_len: 1,
                max_len: 8,
                alphabet: Some(b"12+ ".to_vec()),
                pad: 8,
            }),
        )],
        count_at: None,
    };
    let spec = InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(vec![ParamGen::Graph(parser)]),
    };
    for c in spec.cases(1, 10) {
        let Arg::Graph { objects, links } = &c[0] else {
            panic!("not a graph");
        };
        assert_eq!(objects.len(), 2);
        assert_eq!(
            links,
            &[Link {
                from: 0,
                offset: 0,
                to: 1,
                to_offset: 0
            }]
        );
        let text = &objects[1];
        let end = text.iter().position(|b| *b == 0).expect("terminated");
        assert!(end >= 1 && text[..end].iter().all(|b| b"12+ ".contains(b)));
    }

    // A struct of unknown layout: some cases have a pointer to text at the first word.
    let mixed = InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(vec![ParamGen::Mixed(TextGen::generic())]),
    };
    let cases = mixed.cases(3, 60);
    assert!(
        cases
            .iter()
            .any(|c| matches!(&c[0], Arg::Graph { links, .. } if !links.is_empty()))
    );
    assert!(
        cases
            .iter()
            .any(|c| matches!(&c[0], Arg::Graph { links, .. } if links.is_empty()))
    );
}
