use kraken_model::*;
use kraken_proto::{Anchor, ErrorCode, Hex64, LogOp, PageRequest, Provenance, VersionedLogOp};

fn rename(off: u64, new: &str) -> LogOp {
    LogOp::Rename {
        anchor: Anchor::Native {
            space: "ram".into(),
            offset: Hex64(off),
            fn_entry: Hex64(off),
            fn_hash: "h".into(),
        },
        old_name: None,
        new_name: new.into(),
    }
}

const NAME: &str = "native:ram:0x401000:name";

#[test]
fn proposals_lifecycle_and_paging() {
    let mut s = Store::open_in_memory().unwrap();
    const { assert!(SCHEMA_VERSION >= 2) };
    let mut ids = Vec::new();
    for i in 0..3u64 {
        ids.push(
            s.add_proposal(NewProposal {
                run_id: Some(RunId("r".into())),
                author: Author::agent("bot"),
                op: VersionedLogOp::new(rename(0x401000 + i, "x")),
                reason: "overwrite".into(),
            })
            .unwrap(),
        );
    }
    let p = s.get_proposal(ids[0]).unwrap();
    assert_eq!(p.status, ProposalStatus::Open);
    assert_eq!(p.author, Author::agent("bot"));
    let page1 = s
        .list_proposals(
            &PageRequest {
                cursor: None,
                limit: Some(2),
            },
            Some(ProposalStatus::Open),
        )
        .unwrap();
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.total, Some(3));
    let page2 = s
        .list_proposals(
            &PageRequest {
                cursor: page1.next_cursor,
                limit: Some(2),
            },
            None,
        )
        .unwrap();
    assert_eq!(page2.items.len(), 1);
    assert!(page2.next_cursor.is_none());
    s.accept_proposal(ids[0]).unwrap();
    s.reject_proposal(ids[1]).unwrap();
    assert_eq!(
        s.accept_proposal(ids[0]).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let open = s
        .list_proposals(&PageRequest::default(), Some(ProposalStatus::Open))
        .unwrap();
    assert_eq!(open.items.len(), 1);
    assert_eq!(
        s.get_proposal(ProposalId(99)).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn validate_draft_matches_append_without_storing() {
    let mut s = Store::open_in_memory().unwrap();
    s.append(EntryDraft {
        op: VersionedLogOp::new(rename(0x401000, "mine")),
        author: Author::user("a"),
        run_id: None,
        provenance: Provenance::User,
        read_set: Default::default(),
    })
    .unwrap();
    let agent = EntryDraft {
        op: VersionedLogOp::new(rename(0x401000, "theirs")),
        author: Author::agent("bot"),
        run_id: Some(RunId("r".into())),
        provenance: Provenance::Agent,
        read_set: [(NAME.to_string(), 0)].into_iter().collect(),
    };
    let e = s.validate_draft(&agent).unwrap_err();
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    let h = s
        .history(&PageRequest::default(), &HistoryFilter::default())
        .unwrap();
    assert_eq!(h.items.len(), 1);
}
