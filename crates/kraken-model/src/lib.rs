//! KRAKEN project database: the append-only annotation log, per-entity versions, undo and
//! materialised annotation state (decisions 27, 28, 34, 49, 57, 58).
//!
//! The API is synchronous; callers on an async runtime use `spawn_blocking`. All errors are
//! [`kraken_proto::ProtoError`]; storage failures map to `internal`.

use std::collections::BTreeMap;

use kraken_proto::{LogStatus, Provenance, SyncState, VersionedLogOp};
use serde::{Deserialize, Serialize};

pub mod keys;
pub mod policy;
pub mod state;
mod store;

pub use keys::{anchor_key, entity_key, op_anchor, op_aspect, op_key};
pub use policy::{Classification, classify, is_default_name};
pub use state::{AnnotationState, StateValue, UNDEFINED_TYPE, apply_op, invert_op};
pub use store::{SCHEMA_VERSION, Store};

/// Identifier of a log entry; assigned in strictly increasing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryId(pub u64);

/// Identifier of an agent run (or any other batch of edits).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

/// Whether an edit came from a person or an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorKind {
    /// A human.
    User,
    /// An agent.
    Agent,
}

/// Who made an edit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Author {
    /// User or agent.
    pub kind: AuthorKind,
    /// User name or agent id.
    pub id: String,
}

impl Author {
    /// A human author.
    pub fn user(id: impl Into<String>) -> Self {
        Author {
            kind: AuthorKind::User,
            id: id.into(),
        }
    }

    /// An agent author.
    pub fn agent(id: impl Into<String>) -> Self {
        Author {
            kind: AuthorKind::Agent,
            id: id.into(),
        }
    }
}

/// A write request for [`Store::append`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDraft {
    /// The operation.
    pub op: VersionedLogOp,
    /// Who makes the edit.
    pub author: Author,
    /// Run the edit belongs to, if any.
    pub run_id: Option<RunId>,
    /// Where the content came from.
    pub provenance: Provenance,
    /// Entity key to the version the author read; validated at append (decision 58).
    pub read_set: BTreeMap<String, u64>,
}

/// A log entry as returned by queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntryView {
    /// Entry id.
    pub id: EntryId,
    /// The operation.
    pub op: VersionedLogOp,
    /// Author.
    pub author: Author,
    /// Run, if any.
    pub run_id: Option<RunId>,
    /// Provenance.
    pub provenance: Provenance,
    /// Versions the author based the edit on.
    pub read_set: BTreeMap<String, u64>,
    /// Applied, rejected (audit only) or orphaned.
    pub status: LogStatus,
    /// Engine sync state; meaningful for applied entries.
    pub sync: SyncState,
    /// For a compensating entry, the entry it reverses.
    pub undoes_entry_id: Option<EntryId>,
    /// The applied compensating entry that reversed this one, if any.
    pub undone_by: Option<EntryId>,
    /// Creation time, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

/// Filter for [`Store::history`]; unset fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    /// Only entries of this run.
    pub run_id: Option<RunId>,
    /// Only entries by this author.
    pub author: Option<Author>,
}

/// Engine push progress saved with a Ghidra save (decision 57).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    /// Last entry known pushed and saved.
    pub last_pushed_entry_id: EntryId,
    /// Opaque engine checkpoint string saved with it.
    pub engine_checkpoint: String,
}
