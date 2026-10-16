use std::collections::{BTreeMap, BTreeSet};

use kraken_model::*;
use kraken_proto::{
    Anchor, CommentKind, ErrorCode, Hex64, LogOp, LogStatus, PageRequest, Provenance, TypeRef,
    VersionedLogOp,
};
use proptest::prelude::*;

fn anchor(i: u64) -> Anchor {
    let off = 0x401000 + i * 0x10;
    Anchor::Native {
        space: "ram".into(),
        offset: Hex64(off),
        fn_entry: Hex64(off),
        fn_hash: "h".into(),
    }
}

fn name_key(i: u64) -> String {
    format!("native:ram:{:#x}:name", 0x401000 + i * 0x10)
}

fn type_key(i: u64) -> String {
    format!("native:ram:{:#x}:type", 0x401000 + i * 0x10)
}

fn named(n: &str) -> TypeRef {
    TypeRef::Named { name: n.into() }
}

fn draft(op: LogOp, author: &Author, run: Option<&str>, reads: &[(String, u64)]) -> EntryDraft {
    EntryDraft {
        op: VersionedLogOp::new(op),
        provenance: match author.kind {
            AuthorKind::User => Provenance::User,
            AuthorKind::Agent => Provenance::Agent,
        },
        author: author.clone(),
        run_id: run.map(|r| RunId(r.into())),
        read_set: reads.iter().cloned().collect(),
    }
}

fn rename(i: u64, old: Option<&str>, new: &str) -> LogOp {
    LogOp::Rename {
        anchor: anchor(i),
        old_name: old.map(Into::into),
        new_name: new.into(),
    }
}

fn set_type(i: u64, old: Option<&str>, new: &str) -> LogOp {
    LogOp::SetType {
        anchor: anchor(i),
        old: old.map(named),
        new: named(new),
    }
}

/// rename (user), set_type (user), agent rename that read the type.
fn scenario() -> (Store, EntryId, EntryId, EntryId) {
    let mut s = Store::open_in_memory().unwrap();
    let user = Author::user("adam");
    let bot = Author::agent("bot");
    let r = s
        .append(draft(rename(0, None, "parse"), &user, None, &[]))
        .unwrap();
    let t = s
        .append(draft(set_type(0, None, "int"), &user, None, &[]))
        .unwrap();
    let a = s
        .append(draft(
            rename(0, Some("parse"), "parse_int"),
            &bot,
            Some("run-1"),
            &[(name_key(0), 1), (type_key(0), 1)],
        ))
        .unwrap();
    (s, r, t, a)
}

#[test]
fn migration_three_adds_the_taint_table() {
    const { assert!(SCHEMA_VERSION >= 3) };
    let s = Store::open_in_memory().unwrap();
    assert!(s.tainted().unwrap().is_empty());
}

#[test]
fn lineage_lists_later_entries_that_read_a_key_the_entry_wrote() {
    let (s, r, t, a) = scenario();
    let deps = s.lineage(t).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].entry.id, a);
    assert_eq!(deps[0].via_keys, vec![type_key(0)]);
    // the rename is a source of the agent rename and, through the keys, of nothing else
    let deps: Vec<_> = s.lineage(r).unwrap().iter().map(|d| d.entry.id).collect();
    assert_eq!(deps, vec![a]);
    assert!(s.lineage(a).unwrap().is_empty());
}

#[test]
fn lineage_is_transitive() {
    let mut s = Store::open_in_memory().unwrap();
    let u = Author::user("u");
    let t = s
        .append(draft(set_type(0, None, "int"), &u, None, &[]))
        .unwrap();
    // reads the type, writes the name of function 0
    let n = s
        .append(draft(
            rename(0, None, "a"),
            &u,
            None,
            &[(type_key(0), 1), (name_key(0), 0)],
        ))
        .unwrap();
    // reads only the name key: depends on the type edit through the rename
    let c = s
        .append(draft(
            LogOp::SetComment {
                anchor: anchor(1),
                comment_kind: CommentKind::Eol,
                old: None,
                new: Some("x".into()),
            },
            &u,
            None,
            &[(name_key(0), 1)],
        ))
        .unwrap();
    // unrelated
    s.append(draft(rename(2, None, "z"), &u, None, &[]))
        .unwrap();
    let ids: Vec<_> = s.lineage(t).unwrap().iter().map(|d| d.entry.id).collect();
    assert_eq!(ids, vec![n, c]);
}

#[test]
fn refuse_lists_dependents_with_authors_commands_and_keys() {
    let (mut s, _, t, a) = scenario();
    let err = s
        .undo_with_dependents(t, UndoPolicy::Refuse, &Author::user("adam"))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let d = err.details.unwrap();
    assert_eq!(d["reason"], "has_dependents");
    assert_eq!(d["dependents"][0]["entry_id"], a.0);
    assert_eq!(d["dependents"][0]["op"], "rename");
    assert_eq!(d["dependents"][0]["author"]["id"], "bot");
    assert_eq!(d["dependents"][0]["keys"][0], type_key(0));
    // nothing was written
    assert_eq!(
        s.history(&PageRequest::default(), &HistoryFilter::default())
            .unwrap()
            .total,
        Some(3)
    );
}

#[test]
fn cascade_undoes_dependents_newest_first_then_the_entry() {
    let (mut s, _, t, a) = scenario();
    let ids = s
        .undo_with_dependents(t, UndoPolicy::Cascade, &Author::user("adam"))
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(s.get_entry(ids[0]).unwrap().undoes_entry_id, Some(a));
    assert_eq!(s.get_entry(ids[1]).unwrap().undoes_entry_id, Some(t));
    let st = s.current_state().unwrap();
    assert_eq!(
        st.get(&name_key(0)),
        Some(&StateValue::Name {
            name: "parse".into()
        })
    );
    assert!(!st.contains_key(&type_key(0)));
    assert_eq!(st, s.replay_full().unwrap());
    // already undone now
    assert_eq!(
        s.undo_with_dependents(t, UndoPolicy::Cascade, &Author::user("adam"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn without_dependents_refuse_works_for_an_older_entry() {
    let mut s = Store::open_in_memory().unwrap();
    let u = Author::user("u");
    let first = s
        .append(draft(rename(0, None, "a"), &u, None, &[]))
        .unwrap();
    s.append(draft(rename(1, None, "b"), &u, None, &[]))
        .unwrap();
    let ids = s
        .undo_with_dependents(first, UndoPolicy::Refuse, &u)
        .unwrap();
    assert_eq!(ids.len(), 1);
    let st = s.current_state().unwrap();
    assert!(!st.contains_key(&name_key(0)));
    assert!(st.contains_key(&name_key(1)));
    assert!(s.tainted().unwrap().is_empty(), "a rename taints nothing");
}

#[test]
fn undoing_a_type_edit_taints_its_key_and_its_dependents_keys() {
    let (mut s, _, t, _) = scenario();
    s.undo_with_dependents(t, UndoPolicy::Cascade, &Author::user("adam"))
        .unwrap();
    let keys: BTreeSet<_> = s.tainted().unwrap().into_iter().map(|k| k.key).collect();
    assert_eq!(keys, BTreeSet::from([name_key(0), type_key(0)]));
    assert_eq!(key_address(&type_key(0)), Some(0x401000));
    assert_eq!(s.clear_tainted_at(0x401000).unwrap(), 2);
    assert!(s.tainted().unwrap().is_empty());
}

#[test]
fn plain_undo_of_a_type_edit_taints_too() {
    let mut s = Store::open_in_memory().unwrap();
    let u = Author::user("u");
    s.append(draft(set_type(0, None, "int"), &u, None, &[]))
        .unwrap();
    s.undo_last(&u).unwrap();
    assert_eq!(s.tainted().unwrap().len(), 1);
}

#[test]
fn plan_matches_the_cascade() {
    let (s, _, t, a) = scenario();
    let p = s.undo_plan(t).unwrap();
    assert_eq!(p.order, vec![a, t]);
    assert_eq!(p.tainted_keys, vec![name_key(0), type_key(0)]);
    assert_eq!(p.entry.id, t);
}

#[test]
fn rejected_and_compensating_entries_are_never_dependents_or_roots() {
    let (mut s, _, t, a) = scenario();
    let comp = s.undo_entry(a, &Author::user("adam")).unwrap();
    // `a` is undone, so the type edit no longer has dependents
    assert!(s.lineage(t).unwrap().is_empty());
    assert_eq!(
        s.undo_plan(comp).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let h = s
        .history(&PageRequest::default(), &HistoryFilter::default())
        .unwrap();
    assert!(h.items.iter().all(|e| e.status == LogStatus::Applied));
}

// ---------------------------------------------------------------- property

#[derive(Debug, Clone)]
enum Step {
    Edit {
        aspect: u8,
        anchor: u8,
        value: u8,
        agent: bool,
        extra: Vec<(u8, u8)>,
    },
    Undo {
        pick: usize,
        cascade: bool,
    },
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        5 => (0u8..3, 0u8..3, 0u8..3, prop::bool::ANY, prop::collection::vec((0u8..3, 0u8..3), 0..3))
            .prop_map(|(aspect, anchor, value, agent, extra)| Step::Edit {
                aspect, anchor, value, agent, extra
            }),
        2 => (0usize..64, prop::bool::ANY).prop_map(|(pick, cascade)| Step::Undo { pick, cascade }),
    ]
}

fn key_for(aspect: u8, anchor: u8) -> String {
    let off = 0x401000 + u64::from(anchor) * 0x10;
    match aspect {
        0 => format!("native:ram:{off:#x}:name"),
        1 => format!("native:ram:{off:#x}:type"),
        _ => format!("native:ram:{off:#x}:cc"),
    }
}

fn op_for(aspect: u8, anchor_i: u8, value: u8, state: &AnnotationState) -> LogOp {
    let a = anchor(u64::from(anchor_i));
    let key = key_for(aspect, anchor_i);
    match aspect {
        0 => LogOp::Rename {
            anchor: a,
            old_name: match state.get(&key) {
                Some(StateValue::Name { name }) => Some(name.clone()),
                _ => None,
            },
            new_name: ["", "alpha", "beta"][usize::from(value)].into(),
        },
        1 => LogOp::SetType {
            anchor: a,
            old: match state.get(&key) {
                Some(StateValue::Type { ty }) => Some(ty.clone()),
                _ => None,
            },
            new: named(["undefined", "int", "char"][usize::from(value)]),
        },
        _ => LogOp::SetCallingConvention {
            anchor: a,
            old: match state.get(&key) {
                Some(StateValue::CallingConvention { name }) => Some(name.clone()),
                _ => None,
            },
            new: ["", "__cdecl", "__fastcall"][usize::from(value)].into(),
        },
    }
}

/// Independent computation of the dependents of `root`: fixpoint over the whole history.
fn naive_dependents(all: &[LogEntryView], root: &LogEntryView) -> BTreeSet<EntryId> {
    let live = |e: &LogEntryView| {
        e.status == LogStatus::Applied
            && e.undoes_entry_id.is_none()
            && e.undone_by.is_none()
            && e.id > root.id
    };
    let mut written: BTreeSet<String> = BTreeSet::from([op_key(&root.op.op).unwrap()]);
    let mut deps = BTreeSet::new();
    for e in all.iter().filter(|e| live(e)) {
        if e.read_set.keys().any(|k| written.contains(k)) {
            deps.insert(e.id);
            written.insert(op_key(&e.op.op).unwrap());
        }
    }
    deps
}

fn all_entries(s: &Store) -> Vec<LogEntryView> {
    let mut v = s
        .history(
            &PageRequest {
                cursor: None,
                limit: Some(100),
            },
            &HistoryFilter::default(),
        )
        .unwrap()
        .items;
    v.reverse();
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn undo_with_dependents_equals_replaying_the_log_without_them(
        steps in prop::collection::vec(arb_step(), 1..30)
    ) {
        let mut s = Store::open_in_memory().unwrap();
        let by = Author::user("u");
        for step in steps {
            match step {
                Step::Edit { aspect, anchor: a, value, agent, extra } => {
                    let state = s.current_state().unwrap();
                    let op = op_for(aspect, a, value, &state);
                    let own = key_for(aspect, a);
                    let mut reads: BTreeMap<String, u64> = BTreeMap::new();
                    for (xa, xk) in extra {
                        let k = key_for(xa, xk);
                        reads.insert(k.clone(), s.entity_version(&k).unwrap());
                    }
                    reads.insert(own.clone(), s.entity_version(&own).unwrap());
                    let author = if agent { Author::agent("bot") } else { by.clone() };
                    let d = EntryDraft {
                        op: VersionedLogOp::new(op),
                        provenance: if agent { Provenance::Agent } else { Provenance::User },
                        author,
                        run_id: agent.then(|| RunId("r".into())),
                        read_set: reads,
                    };
                    // agents may lose to humans; a refused attempt is just audit
                    let _ = s.append(d);
                }
                Step::Undo { pick, cascade } => {
                    let all = all_entries(&s);
                    let candidates: Vec<_> = all.iter().filter(|e| {
                        e.status == LogStatus::Applied
                            && e.undoes_entry_id.is_none()
                            && e.undone_by.is_none()
                    }).collect();
                    if candidates.is_empty() {
                        continue;
                    }
                    let root = candidates[pick % candidates.len()].clone();
                    let expect_deps = naive_dependents(&all, &root);
                    let lineage: BTreeSet<_> =
                        s.lineage(root.id).unwrap().iter().map(|d| d.entry.id).collect();
                    prop_assert_eq!(&lineage, &expect_deps);
                    if cascade {
                        let ids = s.undo_with_dependents(root.id, UndoPolicy::Cascade, &by).unwrap();
                        prop_assert_eq!(ids.len(), expect_deps.len() + 1);
                        // reverse dependency order: newest dependents first, the entry last
                        let originals: Vec<_> = ids.iter()
                            .map(|i| s.get_entry(*i).unwrap().undoes_entry_id.unwrap())
                            .collect();
                        let mut sorted = originals.clone();
                        sorted.sort_by(|a, b| b.cmp(a));
                        prop_assert_eq!(&originals, &sorted);
                        prop_assert_eq!(originals.last().copied(), Some(root.id));
                        // the state equals the log replayed without the entry and its dependents
                        let after = all_entries(&s);
                        let mut removed = expect_deps.clone();
                        removed.insert(root.id);
                        let mut oracle = AnnotationState::new();
                        for e in after.iter().filter(|e| {
                            e.status == LogStatus::Applied
                                && e.undoes_entry_id.is_none()
                                && e.undone_by.is_none()
                                && !removed.contains(&e.id)
                        }) {
                            apply_op(&mut oracle, &e.op.op);
                        }
                        prop_assert_eq!(&s.current_state().unwrap(), &oracle);
                        prop_assert_eq!(&s.replay_full().unwrap(), &oracle);
                    } else {
                        let r = s.undo_with_dependents(root.id, UndoPolicy::Refuse, &by);
                        if expect_deps.is_empty() {
                            prop_assert!(r.is_ok());
                        } else {
                            let e = r.unwrap_err();
                            prop_assert_eq!(e.code, ErrorCode::InvalidArgument);
                            let n = e.details.unwrap()["dependents"].as_array().unwrap().len();
                            prop_assert_eq!(n, expect_deps.len());
                        }
                    }
                }
            }
        }
    }
}
