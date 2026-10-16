//! Agent proposals: edits an agent may not auto-apply (overwrites, edits above the per-run cap)
//! wait here until a user accepts or rejects them (decision 29).
//!
//! The store only tracks the proposal; applying an accepted proposal is the caller's job (the
//! registry appends the op as the accepting user, then calls [`Store::accept_proposal`]).

use kraken_proto::{ErrorCode, Page, PageRequest, ProtoError, VersionedLogOp};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::store::{db, from_json, kind_str, now_ms, parse_kind, to_json};
use crate::{Author, RunId, Store};

pub(crate) const MIGRATION: &str = "CREATE TABLE proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT,
        author_kind TEXT NOT NULL,
        author_id TEXT NOT NULL,
        op TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open','accepted','rejected')),
        ts INTEGER NOT NULL
    );
    CREATE INDEX proposals_status ON proposals(status, id);";

type Result<T> = std::result::Result<T, ProtoError>;

/// Identifier of a proposal; assigned in strictly increasing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProposalId(pub u64);

/// Lifecycle of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Waiting for a decision.
    Open,
    /// A user accepted it and the edit was applied.
    Accepted,
    /// A user turned it down.
    Rejected,
}

impl ProposalStatus {
    /// The stored and wire string: `open`, `accepted` or `rejected`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Open => "open",
            ProposalStatus::Accepted => "accepted",
            ProposalStatus::Rejected => "rejected",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(ProposalStatus::Open),
            "accepted" => Ok(ProposalStatus::Accepted),
            "rejected" => Ok(ProposalStatus::Rejected),
            other => Err(db(format!("bad proposal status {other:?}"))),
        }
    }
}

/// A proposal to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProposal {
    /// Run that produced it, if any.
    pub run_id: Option<RunId>,
    /// Who proposed it.
    pub author: Author,
    /// The proposed edit.
    pub op: VersionedLogOp,
    /// Why it was not auto-applied.
    pub reason: String,
}

/// A stored proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalView {
    /// Proposal id.
    pub id: ProposalId,
    /// Run that produced it, if any.
    pub run_id: Option<RunId>,
    /// Who proposed it.
    pub author: Author,
    /// The proposed edit.
    pub op: VersionedLogOp,
    /// Why it was not auto-applied.
    pub reason: String,
    /// Current status.
    pub status: ProposalStatus,
    /// Creation time, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

const COLS: &str = "id, run_id, author_kind, author_id, op, reason, status, ts";

type Raw = (
    i64,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    i64,
);

fn read_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
    ))
}

fn view(raw: Raw) -> Result<ProposalView> {
    let (id, run_id, kind, author_id, op, reason, status, ts) = raw;
    Ok(ProposalView {
        id: ProposalId(id as u64),
        run_id: run_id.map(RunId),
        author: Author {
            kind: parse_kind(&kind)?,
            id: author_id,
        },
        op: from_json(&op)?,
        reason,
        status: ProposalStatus::parse(&status)?,
        ts_ms: ts,
    })
}

impl Store {
    /// Stores an open proposal.
    pub fn add_proposal(&mut self, p: NewProposal) -> Result<ProposalId> {
        self.conn
            .execute(
                "INSERT INTO proposals(run_id, author_kind, author_id, op, reason, status, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6)",
                params![
                    p.run_id.as_ref().map(|r| r.0.as_str()),
                    kind_str(p.author.kind),
                    p.author.id,
                    to_json(&p.op)?,
                    p.reason,
                    now_ms()
                ],
            )
            .map_err(db)?;
        Ok(ProposalId(self.conn.last_insert_rowid() as u64))
    }

    /// One proposal by id; `not_found` if there is none.
    pub fn get_proposal(&self, id: ProposalId) -> Result<ProposalView> {
        let raw = self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM proposals WHERE id = ?1"),
                [id.0 as i64],
                read_raw,
            )
            .optional()
            .map_err(db)?;
        match raw {
            Some(r) => view(r),
            None => Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no proposal {}", id.0),
            )),
        }
    }

    /// Proposals oldest first, optionally only those with `status`. The cursor is the id of the
    /// last proposal on the previous page.
    pub fn list_proposals(
        &self,
        page: &PageRequest,
        status: Option<ProposalStatus>,
    ) -> Result<Page<ProposalView>> {
        let limit = page.effective_limit() as usize;
        let after: i64 = match &page.cursor {
            None => 0,
            Some(c) => c.parse().map_err(|_| {
                ProtoError::new(ErrorCode::InvalidArgument, "malformed proposals cursor")
            })?,
        };
        let status = status.map(ProposalStatus::as_str);
        let total: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM proposals WHERE (?1 IS NULL OR status = ?1)",
                [status],
                |r| r.get(0),
            )
            .map_err(db)?;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, run_id, author_kind, author_id, op, reason, status, ts
                 FROM proposals WHERE (?1 IS NULL OR status = ?1) AND id > ?2
                 ORDER BY id LIMIT ?3",
            )
            .map_err(db)?;
        let raws = stmt
            .query_map(params![status, after, limit as i64 + 1], read_raw)
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        let mut items = raws.into_iter().map(view).collect::<Result<Vec<_>>>()?;
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|p| p.id.0.to_string())
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            total: Some(total as u64),
        })
    }

    /// Marks an open proposal accepted; `invalid_argument` if it is not open.
    pub fn accept_proposal(&mut self, id: ProposalId) -> Result<ProposalView> {
        self.resolve_proposal(id, ProposalStatus::Accepted)
    }

    /// Marks an open proposal rejected; `invalid_argument` if it is not open.
    pub fn reject_proposal(&mut self, id: ProposalId) -> Result<ProposalView> {
        self.resolve_proposal(id, ProposalStatus::Rejected)
    }

    fn resolve_proposal(&mut self, id: ProposalId, to: ProposalStatus) -> Result<ProposalView> {
        let current = self.get_proposal(id)?;
        if current.status != ProposalStatus::Open {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("proposal {} is already {}", id.0, current.status.as_str()),
            ));
        }
        self.conn
            .execute(
                "UPDATE proposals SET status = ?2 WHERE id = ?1 AND status = 'open'",
                params![id.0 as i64, to.as_str()],
            )
            .map_err(db)?;
        self.get_proposal(id)
    }
}
