use kraken_model::*;
use kraken_proto::{
    AddressRange, Anchor, CommentKind, ErrorCode, Hex64, LogOp, LogStatus, PageRequest, Provenance,
    SyncState, VersionedLogOp,
};

fn anchor(off: u64) -> Anchor {
    Anchor::Native {
        space: "ram".into(),
        offset: Hex64(off),
        fn_entry: Hex64(off),
        fn_hash: "h".into(),
    }
}

fn rename(off: u64, old: Option<&str>, new: &str) -> LogOp {
    LogOp::Rename {
        anchor: anchor(off),
        old_name: old.map(Into::into),
        new_name: new.into(),
    }
}

fn draft(op: LogOp, author: Author, run: Option<&str>, reads: &[(&str, u64)]) -> EntryDraft {
    EntryDraft {
        op: VersionedLogOp::new(op),
        provenance: match author.kind {
            AuthorKind::User => Provenance::User,
            AuthorKind::Agent => Provenance::Agent,
        },
        author,
        run_id: run.map(|r| RunId(r.into())),
        read_set: reads.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
    }
}

const NAME: &str = "native:ram:0x401000:name";

#[test]
fn key_format() {
    assert_eq!(op_key(&rename(0x401000, None, "x")).unwrap(), NAME);
    let c = LogOp::SetComment {
        anchor: anchor(0x10),
        comment_kind: CommentKind::Eol,
        old: None,
        new: None,
    };
    assert_eq!(op_key(&c).unwrap(), "native:ram:0x10:comment:eol");
}

#[test]
fn append_bumps_versions_and_pends() {
    let mut s = Store::open_in_memory().unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    let id = s
        .append(draft(
            rename(0x401000, None, "main"),
            Author::user("a"),
            None,
            &[],
        ))
        .unwrap();
    assert_eq!(s.entity_version(NAME).unwrap(), 1);
    let e = s.get_entry(id).unwrap();
    assert_eq!(e.status, LogStatus::Applied);
    assert_eq!(e.sync, SyncState::Pending);
    assert_eq!(s.pending_entries().unwrap().len(), 1);
    s.mark_pushed(id).unwrap();
    assert!(s.pending_entries().unwrap().is_empty());
    s.set_watermark(id, "ckpt-1").unwrap();
    assert_eq!(
        s.watermark().unwrap(),
        Some(Watermark {
            last_pushed_entry_id: id,
            engine_checkpoint: "ckpt-1".into()
        })
    );
}

#[test]
fn stale_read_is_rejected_and_audited() {
    let mut s = Store::open_in_memory().unwrap();
    s.append(draft(
        rename(0x401000, None, "a"),
        Author::user("u"),
        None,
        &[],
    ))
    .unwrap();
    let err = s
        .append(draft(
            rename(0x402000, None, "b"),
            Author::user("u"),
            None,
            &[(NAME, 0)],
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConflictStaleRead);
    let d = err.details.unwrap();
    assert_eq!(d["stale_keys"][0]["key"], NAME);
    assert_eq!(s.entity_version("native:ram:0x402000:name").unwrap(), 0);
    let h = s
        .history(&PageRequest::default(), &HistoryFilter::default())
        .unwrap();
    assert_eq!(h.items.len(), 2);
    assert!(matches!(h.items[0].status, LogStatus::Rejected { .. }));
    assert_eq!(s.pending_entries().unwrap().len(), 1);
}

#[test]
fn human_beats_agent() {
    let mut s = Store::open_in_memory().unwrap();
    s.append(draft(
        rename(0x401000, None, "mine"),
        Author::user("u"),
        None,
        &[],
    ))
    .unwrap();
    let agent = Author::agent("bot");
    let err = s
        .append(draft(
            rename(0x401000, Some("mine"), "bots"),
            agent.clone(),
            Some("r1"),
            &[(NAME, 0)],
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::RejectedHumanPriority);
    // After re-reading, the agent may write.
    s.append(draft(
        rename(0x401000, Some("mine"), "bots"),
        agent,
        Some("r1"),
        &[(NAME, 1)],
    ))
    .unwrap();
    assert_eq!(
        s.count_applied_agent_entries(&RunId("r1".into())).unwrap(),
        1
    );
}

#[test]
fn classify_policy() {
    let mut st = AnnotationState::new();
    assert_eq!(
        classify(&rename(0x401000, Some("FUN_00401000"), "main"), &st),
        Classification::Additive
    );
    assert_eq!(
        classify(&rename(0x401000, Some("printf"), "x"), &st),
        Classification::Overwrite
    );
    apply_op(&mut st, &rename(0x401000, None, "main"));
    assert_eq!(
        classify(&rename(0x401000, None, "other"), &st),
        Classification::Overwrite
    );
    let c = |old: Option<&str>, new: Option<&str>| LogOp::SetComment {
        anchor: anchor(0x10),
        comment_kind: CommentKind::Plate,
        old: old.map(Into::into),
        new: new.map(Into::into),
    };
    assert_eq!(
        classify(&c(None, Some("hi")), &st),
        Classification::Additive
    );
    assert_eq!(
        classify(&c(Some("a"), Some("b")), &st),
        Classification::Overwrite
    );
    assert_eq!(classify(&c(None, None), &st), Classification::Overwrite);
    assert!(is_default_name("FUN_00401000") && !is_default_name("FUN_main"));
}

#[test]
fn undo_last_and_run() {
    let mut s = Store::open_in_memory().unwrap();
    let u = Author::user("u");
    let bot = Author::agent("bot");
    s.append(draft(rename(0x401000, None, "first"), u.clone(), None, &[]))
        .unwrap();
    let a = s
        .append(draft(
            rename(0x401000, Some("first"), "second"),
            bot.clone(),
            Some("r"),
            &[(NAME, 1)],
        ))
        .unwrap();
    let b = s
        .append(draft(
            rename(0x402000, None, "other"),
            bot.clone(),
            Some("r"),
            &[],
        ))
        .unwrap();
    let ids = s.undo_run(&RunId("r".into()), &u).unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(s.get_entry(ids[0]).unwrap().undoes_entry_id, Some(b));
    assert_eq!(s.get_entry(ids[1]).unwrap().undoes_entry_id, Some(a));
    assert_eq!(s.get_entry(a).unwrap().status, LogStatus::Applied);
    assert_eq!(s.get_entry(a).unwrap().undone_by, Some(ids[1]));
    let st = s.current_state().unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(
        st[NAME],
        StateValue::Name {
            name: "first".into()
        }
    );
    assert_eq!(
        s.undo_entry(a, &u).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert!(s.undo_run(&RunId("r".into()), &u).unwrap().is_empty());
    s.undo_last(&u).unwrap();
    assert!(s.current_state().unwrap().is_empty());
    assert_eq!(s.undo_last(&u).unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn function_create_delete_inverts() {
    let mut s = Store::open_in_memory().unwrap();
    let u = Author::user("u");
    let body = AddressRange {
        space: "ram".into(),
        start: Hex64(0x401000),
        end: Hex64(0x401010),
    };
    s.append(draft(
        LogOp::CreateFunction {
            anchor: anchor(0x401000),
            name: None,
            body: Some(body.clone()),
        },
        u.clone(),
        None,
        &[],
    ))
    .unwrap();
    assert_eq!(s.current_state().unwrap().len(), 1);
    s.undo_last(&u).unwrap();
    assert!(s.current_state().unwrap().is_empty());
}

#[test]
fn history_pages_and_filters() {
    let mut s = Store::open_in_memory().unwrap();
    for i in 0..5u64 {
        let who = if i % 2 == 0 {
            Author::user("u")
        } else {
            Author::agent("b")
        };
        s.append(draft(rename(0x1000 + i, None, "n"), who, Some("r"), &[]))
            .unwrap();
    }
    let p1 = s
        .history(
            &PageRequest {
                cursor: None,
                limit: Some(2),
            },
            &HistoryFilter::default(),
        )
        .unwrap();
    assert_eq!(p1.items.len(), 2);
    assert_eq!(p1.total, Some(5));
    let p2 = s
        .history(
            &PageRequest {
                cursor: p1.next_cursor,
                limit: Some(10),
            },
            &HistoryFilter::default(),
        )
        .unwrap();
    assert_eq!(p2.items.len(), 3);
    assert!(p2.next_cursor.is_none());
    let f = HistoryFilter {
        run_id: Some(RunId("r".into())),
        author: Some(Author::agent("b")),
    };
    assert_eq!(
        s.history(&PageRequest::default(), &f).unwrap().items.len(),
        2
    );
}

#[test]
fn reopen_keeps_data_and_migrates_once() {
    let dir = std::env::temp_dir().join(format!("kraken-model-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.db");
    let _ = std::fs::remove_file(&path);
    {
        let mut s = Store::open(&path).unwrap();
        s.append(draft(rename(0x1, None, "x"), Author::user("u"), None, &[]))
            .unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(s.entity_versions().unwrap().len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
