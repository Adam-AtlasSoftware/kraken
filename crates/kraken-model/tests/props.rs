use std::collections::BTreeMap;

use kraken_model::*;
use kraken_proto::{
    AddressRange, Anchor, CodeData, CommentKind, Hex64, LogOp, Provenance, TypeRef, VersionedLogOp,
};
use proptest::prelude::*;

fn anchor(i: u8) -> Anchor {
    let off = 0x401000 + u64::from(i) * 0x10;
    Anchor::Native {
        space: "ram".into(),
        offset: Hex64(off),
        fn_entry: Hex64(off),
        fn_hash: "h".into(),
    }
}

fn range(i: u8, n: u8) -> AddressRange {
    AddressRange {
        space: "ram".into(),
        start: Hex64(0x401000 + u64::from(i) * 0x10),
        end: Hex64(0x401000 + u64::from(i) * 0x10 + u64::from(n) * 4),
    }
}

fn arb_op() -> impl Strategy<Value = LogOp> {
    let a = 0u8..3;
    let name = prop::sample::select(vec!["", "main", "FUN_00401000", "helper"]);
    let opt_name = prop::option::of(prop::sample::select(vec!["FUN_00401000", "printf", "main"]));
    let text = prop::option::of(prop::sample::select(vec!["a", "b"]));
    let kind = prop::sample::select(vec![CommentKind::Plate, CommentKind::Eol]);
    let ty = prop::sample::select(vec!["int", "char", "undefined"]);
    prop_oneof![
        (a.clone(), opt_name, name).prop_map(|(i, old, new)| LogOp::Rename {
            anchor: anchor(i),
            old_name: old.map(Into::into),
            new_name: new.into(),
        }),
        (a.clone(), ty).prop_map(|(i, t)| LogOp::SetType {
            anchor: anchor(i),
            old: None,
            new: TypeRef::Named { name: t.into() },
        }),
        (a.clone(), kind, text.clone(), text).prop_map(|(i, k, old, new)| LogOp::SetComment {
            anchor: anchor(i),
            comment_kind: k,
            old: old.map(Into::into),
            new: new.map(Into::into),
        }),
        (a.clone(), 0u8..3).prop_map(|(i, n)| LogOp::CreateFunction {
            anchor: anchor(i),
            name: None,
            body: (n > 0).then(|| range(i, n)),
        }),
        a.clone().prop_map(|i| LogOp::DeleteFunction {
            anchor: anchor(i),
            old_body: None,
        }),
        (a.clone(), 0u8..3).prop_map(|(i, n)| LogOp::SetFunctionBounds {
            anchor: anchor(i),
            old: None,
            new: range(i, n),
        }),
        (a.clone(), prop::bool::ANY).prop_map(|(i, c)| LogOp::SetCodeData {
            anchor: anchor(i),
            old: None,
            new: if c {
                CodeData::Code
            } else {
                CodeData::Undefined
            },
            length: None,
        }),
        (a, prop::sample::select(vec!["", "__cdecl", "__fastcall"])).prop_map(|(i, c)| {
            LogOp::SetCallingConvention {
                anchor: anchor(i),
                old: None,
                new: c.into(),
            }
        }),
    ]
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum Step {
    Append {
        op: LogOp,
        agent: bool,
        run: u8,
        fresh_reads: bool,
    },
    UndoLast {
        agent: bool,
    },
    UndoRun {
        run: u8,
    },
    Snapshot,
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (arb_op(), prop::bool::ANY, 0u8..2, prop::bool::ANY).prop_map(
            |(op, agent, run, fresh_reads)| Step::Append { op, agent, run, fresh_reads }
        ),
        2 => prop::bool::ANY.prop_map(|agent| Step::UndoLast { agent }),
        1 => (0u8..2).prop_map(|run| Step::UndoRun { run }),
        1 => Just(Step::Snapshot),
    ]
}

fn author(agent: bool) -> Author {
    if agent {
        Author::agent("bot")
    } else {
        Author::user("u")
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn replay_matches_incremental(steps in prop::collection::vec(arb_step(), 1..40)) {
        let mut store = Store::open_in_memory().unwrap();
        let mut oracle = AnnotationState::new();
        let mut expected_versions: BTreeMap<String, u64> = BTreeMap::new();

        for step in steps {
            let new_ids: Vec<EntryId> = match step {
                Step::Append { op, agent, run, fresh_reads } => {
                    let key = op_key(&op).unwrap();
                    let mut read_set = BTreeMap::new();
                    if fresh_reads {
                        read_set.insert(key.clone(), store.entity_version(&key).unwrap());
                    }
                    let draft = EntryDraft {
                        op: VersionedLogOp::new(op),
                        author: author(agent),
                        run_id: agent.then(|| RunId(format!("r{run}"))),
                        provenance: if agent { Provenance::Agent } else { Provenance::User },
                        read_set,
                    };
                    store.append(draft).ok().into_iter().collect()
                }
                Step::UndoLast { agent } => store.undo_last(&author(agent)).ok().into_iter().collect(),
                Step::UndoRun { run } => store
                    .undo_run(&RunId(format!("r{run}")), &Author::user("u"))
                    .unwrap_or_default(),
                Step::Snapshot => {
                    store.create_snapshot().unwrap();
                    vec![]
                }
            };
            for id in new_ids {
                let e = store.get_entry(id).unwrap();
                apply_op(&mut oracle, &e.op.op);
                *expected_versions.entry(op_key(&e.op.op).unwrap()).or_default() += 1;
            }
            prop_assert_eq!(&store.current_state().unwrap(), &oracle);
        }
        prop_assert_eq!(&store.replay_full().unwrap(), &oracle);
        store.create_snapshot().unwrap();
        prop_assert_eq!(&store.current_state().unwrap(), &store.replay_full().unwrap());
        prop_assert_eq!(&store.entity_versions().unwrap(), &expected_versions);
    }
}
