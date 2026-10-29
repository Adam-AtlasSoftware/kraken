//! Byte patches: a separate overlay layer that records replacement bytes at an address, with the
//! original bytes kept beside them.
//!
//! Like [bookmarks](crate::bookmarks) they live in their own table, not the edit log: a byte
//! patch is not an annotation the engine replays, it is an edit to the program's bytes that a
//! later step (`patch_export`, or a patched emulation) applies to a copy of the binary. The
//! original bytes are stored so a patch can be checked against the file it is applied to and so
//! anchors, which hash the original bytes, keep working. Removing a patch is the way back.

use kraken_proto::{ErrorCode, LogOp, Page, PageRequest, ProtoError};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::store::{db, kind_str, now_ms, parse_kind};
use crate::{Author, Store};

pub(crate) const MIGRATION: &str = "CREATE TABLE patches (
        address INTEGER PRIMARY KEY,
        original BLOB NOT NULL,
        replacement BLOB NOT NULL,
        note TEXT NOT NULL,
        author_kind TEXT NOT NULL,
        author_id TEXT NOT NULL,
        ts INTEGER NOT NULL
    );";

/// Patch sets: the set a patch belongs to, whether it is switched off, and the sets' names with
/// their descriptions.
pub(crate) const MIGRATION_GROUPS: &str = "
    ALTER TABLE patches ADD COLUMN grp TEXT NOT NULL DEFAULT '';
    ALTER TABLE patches ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE patch_groups (
        name TEXT PRIMARY KEY,
        description TEXT NOT NULL
    );";

type Result<T> = std::result::Result<T, ProtoError>;

/// One stored byte patch. `original` and `replacement` are always the same length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// First address of the patched bytes.
    pub address: u64,
    /// The bytes at `address` when the patch was recorded.
    pub original: Vec<u8>,
    /// The bytes to write in their place.
    pub replacement: Vec<u8>,
    /// The note; empty when none was given.
    pub note: String,
    /// The patch set it belongs to; empty for none.
    pub group: String,
    /// Switched off: kept, but neither exported nor emulated.
    pub disabled: bool,
    /// Who set it last.
    pub author: Author,
    /// When it was set last, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

impl Patch {
    /// The number of bytes the patch covers.
    pub fn len(&self) -> usize {
        self.replacement.len()
    }

    /// Whether the patch covers no bytes (never true for a stored patch).
    pub fn is_empty(&self) -> bool {
        self.replacement.is_empty()
    }
}

// SQLite integers are signed; addresses above i64::MAX keep their bits.
fn to_db(a: u64) -> i64 {
    a as i64
}

fn from_db(a: i64) -> u64 {
    a as u64
}

/// Lays an applied `SetPatch` log op onto the overlay table: sets, replaces or removes the patch
/// at its address. Other ops leave the table alone. Called for every entry written as applied,
/// so the table always matches the log, undo entries included.
pub(crate) fn apply_patch_op(conn: &Connection, op: &LogOp, author: &Author) -> Result<()> {
    let LogOp::SetPatch {
        anchor,
        original,
        new,
        ..
    } = op
    else {
        return Ok(());
    };
    let (_, address, _, _) = anchor.native()?;
    match new {
        None => {
            conn.execute("DELETE FROM patches WHERE address = ?1", [to_db(address.0)])
                .map_err(db)?;
        }
        Some(b) => {
            let original = unhex(original)?;
            let replacement = unhex(&b.replacement)?;
            // the originals may cover a longer patch this one replaced
            let original = original.get(..replacement.len()).unwrap_or(&original);
            write_patch(
                conn,
                address.0,
                original,
                &replacement,
                (&b.note, &b.group, b.disabled),
                author,
            )?;
        }
    }
    Ok(())
}

/// Bytes from lower-case (or upper-case) hex.
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "malformed hex bytes in a patch",
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| ProtoError::new(ErrorCode::InvalidArgument, "malformed hex bytes"))
        })
        .collect()
}

fn write_patch(
    conn: &Connection,
    address: u64,
    original: &[u8],
    replacement: &[u8],
    (note, group, disabled): (&str, &str, bool),
    author: &Author,
) -> Result<Patch> {
    if replacement.is_empty() {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "a patch covers at least one byte",
        ));
    }
    if original.len() != replacement.len() {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "the original and the replacement must be the same length",
        ));
    }
    let ts = now_ms();
    conn.execute(
        "INSERT INTO patches(address, original, replacement, note, author_kind, author_id, ts,
                             grp, disabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(address) DO UPDATE SET original = excluded.original,
            replacement = excluded.replacement, note = excluded.note,
            grp = excluded.grp, disabled = excluded.disabled,
            author_kind = excluded.author_kind, author_id = excluded.author_id,
            ts = excluded.ts",
        params![
            to_db(address),
            original,
            replacement,
            note,
            kind_str(author.kind),
            author.id,
            ts,
            group,
            disabled
        ],
    )
    .map_err(db)?;
    Ok(Patch {
        address,
        original: original.to_vec(),
        replacement: replacement.to_vec(),
        note: note.to_string(),
        group: group.to_string(),
        disabled,
        author: author.clone(),
        ts_ms: ts,
    })
}

impl Store {
    /// Gives every patch that has no edit-log entry one, under the author who set it and with
    /// its time: patches recorded before they were logged then show in the history and can be
    /// undone. Returns how many were added.
    pub(crate) fn backfill_patch_entries(&mut self) -> Result<usize> {
        let mut added = 0;
        for p in self.all_patches()? {
            let anchor = kraken_proto::Anchor::Native {
                space: kraken_proto::DEFAULT_SPACE.into(),
                offset: kraken_proto::Hex64(p.address),
                fn_entry: kraken_proto::Hex64(p.address),
                fn_hash: String::new(),
            };
            let op = LogOp::SetPatch {
                anchor,
                original: kraken_proto::hex_bytes(&p.original),
                old: None,
                new: Some(kraken_proto::PatchBytes {
                    replacement: kraken_proto::hex_bytes(&p.replacement),
                    note: p.note.clone(),
                    group: p.group.clone(),
                    disabled: p.disabled,
                }),
            };
            let key = crate::keys::op_key(&op)?;
            if self.entity_version(&key)? > 0 {
                continue;
            }
            let draft = crate::EntryDraft {
                op: kraken_proto::VersionedLogOp::new(op),
                provenance: match p.author.kind {
                    crate::AuthorKind::User => kraken_proto::Provenance::User,
                    crate::AuthorKind::Agent => kraken_proto::Provenance::Agent,
                },
                author: p.author.clone(),
                run_id: None,
                read_set: std::collections::BTreeMap::from([(key, 0)]),
            };
            let id = self.append(draft)?;
            self.conn
                .execute(
                    "UPDATE entries SET ts = ?1 WHERE id = ?2",
                    params![p.ts_ms, id.0 as i64],
                )
                .map_err(db)?;
            self.conn
                .execute(
                    "UPDATE patches SET ts = ?1 WHERE address = ?2",
                    params![p.ts_ms, to_db(p.address)],
                )
                .map_err(db)?;
            added += 1;
        }
        Ok(added)
    }

    /// Records the patch at `address`, replacing one already there. `original` and `replacement`
    /// must be the same non-zero length.
    pub fn patch_set(
        &mut self,
        address: u64,
        original: &[u8],
        replacement: &[u8],
        note: &str,
        author: &Author,
    ) -> Result<Patch> {
        write_patch(
            &self.conn,
            address,
            original,
            replacement,
            (note, "", false),
            author,
        )
    }

    /// Removes the patch at `address`; false when there was none.
    pub fn patch_remove(&mut self, address: u64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM patches WHERE address = ?1", [to_db(address)])
            .map_err(db)?;
        Ok(n > 0)
    }

    /// The patch at `address`, if any.
    pub fn patch_get(&self, address: u64) -> Result<Option<Patch>> {
        self.conn
            .query_row(
                "SELECT address, original, replacement, note, author_kind, author_id, ts, grp, disabled
                 FROM patches WHERE address = ?1",
                [to_db(address)],
                row,
            )
            .optional()
            .map_err(db)?
            .map(finish)
            .transpose()
    }

    /// Every patch, ordered by address, for applying them to a file. Not paginated: the overlay
    /// is small and a patched binary needs all of it at once.
    pub fn all_patches(&self) -> Result<Vec<Patch>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, original, replacement, note, author_kind, author_id, ts, grp, disabled
                 FROM patches ORDER BY address < 0, address",
            )
            .map_err(db)?;
        let raw = stmt
            .query_map([], row)
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        raw.into_iter().map(finish).collect()
    }

    /// The patches that are switched on, ordered by address: what an export or an emulated run
    /// applies. `group` limits them to one patch set.
    pub fn active_patches(&self, group: Option<&str>) -> Result<Vec<Patch>> {
        Ok(self
            .all_patches()?
            .into_iter()
            .filter(|p| !p.disabled && group.is_none_or(|g| p.group == g))
            .collect())
    }

    /// Creates the patch set `name` or changes its description.
    pub fn patch_group_put(&mut self, name: &str, description: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO patch_groups(name, description) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET description = excluded.description",
                params![name, description],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Deletes the patch set `name` (its metadata; the caller checks it has no members).
    pub fn patch_group_delete(&mut self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM patch_groups WHERE name = ?1", [name])
            .map_err(db)?;
        Ok(n > 0)
    }

    /// The patch sets with their descriptions, by name.
    pub fn patch_groups(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, description FROM patch_groups ORDER BY name")
            .map_err(db)?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)
    }

    /// Patches ordered by address, one page at a time. The cursor is the address of the last row
    /// of the previous page, in hex.
    pub fn patches(&self, page: &PageRequest) -> Result<Page<Patch>> {
        let limit = page.effective_limit();
        let after: Option<i64> = match &page.cursor {
            None => None,
            Some(c) => Some(
                u64::from_str_radix(c.trim_start_matches("0x"), 16)
                    .map(to_db)
                    .map_err(|_| {
                        ProtoError::new(ErrorCode::InvalidArgument, "malformed patch cursor")
                    })?,
            ),
        };
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM patches", [], |r| r.get(0))
            .map_err(db)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, original, replacement, note, author_kind, author_id, ts, grp, disabled
                 FROM patches
                 WHERE ?1 IS NULL OR (address < 0, address) > (?1 < 0, ?1)
                 ORDER BY address < 0, address LIMIT ?2",
            )
            .map_err(db)?;
        let raw = stmt
            .query_map(params![after, limit as i64 + 1], row)
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        let mut items = raw.into_iter().map(finish).collect::<Result<Vec<_>>>()?;
        let next_cursor = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|p| format!("{:#x}", p.address))
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            total: Some(total as u64),
        })
    }
}

type Raw = (
    i64,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    i64,
    String,
    bool,
);

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
    ))
}

fn finish(
    (address, original, replacement, note, kind, id, ts, group, disabled): Raw,
) -> Result<Patch> {
    Ok(Patch {
        address: from_db(address),
        original,
        replacement,
        note,
        group,
        disabled,
        author: Author {
            kind: parse_kind(&kind)?,
            id,
        },
        ts_ms: ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_replace_get_list_and_remove() {
        let mut s = Store::open_in_memory().expect("store");
        let me = Author::user("me");
        s.patch_set(
            0x401000,
            &[0x74, 0x10],
            &[0xeb, 0x10],
            "flip jz to jmp",
            &me,
        )
        .expect("set");
        s.patch_set(0x400500, &[0x00], &[0x01], "", &Author::agent("a1"))
            .expect("set");
        // Replace the patch at the same address.
        let p = s
            .patch_set(0x401000, &[0x74, 0x10], &[0x90, 0x90], "nop it", &me)
            .expect("replace");
        assert_eq!(p.replacement, vec![0x90, 0x90]);
        assert_eq!(p.len(), 2);
        assert_eq!(
            s.patch_get(0x401000).expect("get").expect("there").note,
            "nop it"
        );

        let all = s.all_patches().expect("all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].address, 0x400500);
        assert_eq!(all[1].address, 0x401000);

        let page = s
            .patches(&PageRequest {
                cursor: None,
                limit: Some(1),
            })
            .expect("page");
        assert_eq!(page.total, Some(2));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].address, 0x400500);
        let page2 = s
            .patches(&PageRequest {
                cursor: page.next_cursor,
                limit: Some(1),
            })
            .expect("page 2");
        assert_eq!(page2.items[0].address, 0x401000);

        assert!(s.patch_remove(0x401000).expect("remove"));
        assert!(!s.patch_remove(0x401000).expect("remove again"));
        assert!(s.patch_get(0x401000).expect("get").is_none());
    }

    #[test]
    fn length_and_emptiness_are_checked() {
        let mut s = Store::open_in_memory().expect("store");
        let me = Author::user("me");
        assert!(s.patch_set(0x10, &[], &[], "", &me).is_err());
        assert!(s.patch_set(0x10, &[0x00], &[0x01, 0x02], "", &me).is_err());
    }

    #[test]
    fn patches_from_before_the_log_get_an_entry_once_and_undo_removes_them() {
        let mut s = Store::open_in_memory().expect("store");
        let bot = Author::agent("kraken-assistant");
        s.patch_set(0x401000, &[0x89, 0xe8], &[0x31, 0xc0], "return 0", &bot)
            .expect("patch");
        assert_eq!(s.backfill_patch_entries().expect("backfill"), 1);
        assert_eq!(s.backfill_patch_entries().expect("again"), 0, "only once");
        let page = s
            .history(&PageRequest::default(), &crate::HistoryFilter::default())
            .expect("history");
        assert_eq!(page.items.len(), 1);
        let e = &page.items[0];
        assert_eq!(e.author, bot);
        assert!(matches!(e.op.op, LogOp::SetPatch { .. }));
        assert_eq!(
            s.patch_get(0x401000).expect("get").expect("kept").note,
            "return 0"
        );

        s.undo_entry(e.id, &Author::user("me")).expect("undo");
        assert!(
            s.patch_get(0x401000).expect("get").is_none(),
            "undo removes it"
        );
    }
}
