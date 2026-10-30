//! Byte patches: a separate overlay layer that records replacement bytes at an address, with the
//! original bytes kept beside them.
//!
//! Like [bookmarks](crate::bookmarks) they live in their own table, not the edit log: a byte
//! patch is not an annotation the engine replays, it is an edit to the program's bytes that a
//! later step (`patch_export`, or a patched emulation) applies to a copy of the binary. The
//! original bytes are stored so a patch can be checked against the file it is applied to and so
//! anchors, which hash the original bytes, keep working. Removing a patch is the way back.

use kraken_proto::{Anchor, ErrorCode, LogOp, Page, PageRequest, PatchKind, ProtoError};
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

/// Patches keyed by what their start is counted in: `va` (a virtual address, every patch so
/// far), `offset` (a file offset) or `member` (an offset in a container member, named in
/// `member`). Rebuilds the table because SQLite cannot change a primary key in place; the rows
/// that exist are kept as `va`.
pub(crate) const MIGRATION_TARGETS: &str = "
    CREATE TABLE patches_v2 (
        target_kind TEXT NOT NULL DEFAULT 'va',
        member TEXT NOT NULL DEFAULT '',
        start INTEGER NOT NULL,
        original BLOB NOT NULL,
        replacement BLOB NOT NULL,
        note TEXT NOT NULL,
        author_kind TEXT NOT NULL,
        author_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        grp TEXT NOT NULL DEFAULT '',
        disabled INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (target_kind, member, start)
    );
    INSERT INTO patches_v2(target_kind, member, start, original, replacement, note,
                           author_kind, author_id, ts, grp, disabled)
        SELECT 'va', '', address, original, replacement, note, author_kind, author_id, ts,
               grp, disabled FROM patches;
    DROP TABLE patches;
    ALTER TABLE patches_v2 RENAME TO patches;";

/// What running the patched program against the original concluded, one row per patch-set hash.
pub(crate) const MIGRATION_VERDICTS: &str = "CREATE TABLE patch_verdicts (
        set_hash TEXT PRIMARY KEY,
        same INTEGER NOT NULL,
        summary TEXT NOT NULL,
        ts INTEGER NOT NULL
    );";

type Result<T> = std::result::Result<T, ProtoError>;

/// One stored byte patch. `original` and `replacement` are always the same length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// What `address` counts: a virtual address, a file offset or an offset in a member.
    #[serde(default)]
    pub kind: PatchKind,
    /// For [`PatchKind::Member`], the member's node id; empty otherwise.
    #[serde(default)]
    pub member: String,
    /// First address (or offset, see `kind`) of the patched bytes.
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

/// The verdict of a verification run, kept for the patch set it was made on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchVerdict {
    /// Hash of the patches that were on when it ran.
    pub set_hash: String,
    /// True when the original and the patched program behaved the same on the inputs given.
    pub same: bool,
    /// The first difference, or empty when the runs agree.
    pub summary: String,
    /// When it ran, milliseconds since the Unix epoch.
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

/// The overlay key a patch anchor names: what its start counts, the member (for member
/// patches) and the start itself.
pub fn target_of(anchor: &Anchor) -> Result<(PatchKind, String, u64)> {
    Ok(match anchor {
        Anchor::FileOffset { offset } => (PatchKind::Offset, String::new(), offset.0),
        Anchor::Member { node, offset } => (PatchKind::Member, node.clone(), offset.0),
        other => (PatchKind::Va, String::new(), other.native()?.1.0),
    })
}

/// The anchor a patch of `kind` is logged under. A virtual address gets a native anchor with no
/// function around it; callers that know the function build their own.
pub fn plain_anchor(kind: PatchKind, member: &str, start: u64) -> Anchor {
    match kind {
        PatchKind::Va => Anchor::Native {
            space: kraken_proto::DEFAULT_SPACE.into(),
            offset: kraken_proto::Hex64(start),
            fn_entry: kraken_proto::Hex64(start),
            fn_hash: String::new(),
        },
        PatchKind::Offset => Anchor::FileOffset {
            offset: kraken_proto::Hex64(start),
        },
        PatchKind::Member => Anchor::Member {
            node: member.to_string(),
            offset: kraken_proto::Hex64(start),
        },
    }
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
    let (kind, member, start) = target_of(anchor)?;
    match new {
        None => {
            conn.execute(
                "DELETE FROM patches WHERE target_kind = ?1 AND member = ?2 AND start = ?3",
                params![kind.as_str(), member, to_db(start)],
            )
            .map_err(db)?;
        }
        Some(b) => {
            let original = unhex(original)?;
            let replacement = unhex(&b.replacement)?;
            // the originals may cover a longer patch this one replaced
            let original = original.get(..replacement.len()).unwrap_or(&original);
            write_patch(
                conn,
                (kind, &member, start),
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
    (kind, member, start): (PatchKind, &str, u64),
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
        "INSERT INTO patches(target_kind, member, start, original, replacement, note,
                             author_kind, author_id, ts, grp, disabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(target_kind, member, start) DO UPDATE SET original = excluded.original,
            replacement = excluded.replacement, note = excluded.note,
            grp = excluded.grp, disabled = excluded.disabled,
            author_kind = excluded.author_kind, author_id = excluded.author_id,
            ts = excluded.ts",
        params![
            kind.as_str(),
            member,
            to_db(start),
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
        kind,
        member: member.to_string(),
        address: start,
        original: original.to_vec(),
        replacement: replacement.to_vec(),
        note: note.to_string(),
        group: group.to_string(),
        disabled,
        author: author.clone(),
        ts_ms: ts,
    })
}

const COLS: &str = "target_kind, member, start, original, replacement, note, author_kind, \
                    author_id, ts, grp, disabled";

/// Address patches first, then file offsets, then member offsets; each by start (an address
/// above `i64::MAX` is stored negative and sorts last).
const ORDER: &str = "CASE target_kind WHEN 'va' THEN 0 WHEN 'offset' THEN 1 ELSE 2 END, member, \
                     start < 0, start";

impl Store {
    /// Gives every patch that has no edit-log entry one, under the author who set it and with
    /// its time: patches recorded before they were logged then show in the history and can be
    /// undone. Returns how many were added.
    pub(crate) fn backfill_patch_entries(&mut self) -> Result<usize> {
        let mut added = 0;
        for p in self.all_patches()? {
            let anchor = plain_anchor(p.kind, &p.member, p.address);
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
                    "UPDATE patches SET ts = ?1
                     WHERE target_kind = ?2 AND member = ?3 AND start = ?4",
                    params![p.ts_ms, p.kind.as_str(), p.member, to_db(p.address)],
                )
                .map_err(db)?;
            added += 1;
        }
        Ok(added)
    }

    /// Records the patch at the virtual address `address`, replacing one already there.
    /// `original` and `replacement` must be the same non-zero length.
    pub fn patch_set(
        &mut self,
        address: u64,
        original: &[u8],
        replacement: &[u8],
        note: &str,
        author: &Author,
    ) -> Result<Patch> {
        self.patch_set_at(
            (PatchKind::Va, "", address),
            original,
            replacement,
            note,
            author,
        )
    }

    /// [`Store::patch_set`] for a patch of any kind.
    pub fn patch_set_at(
        &mut self,
        target: (PatchKind, &str, u64),
        original: &[u8],
        replacement: &[u8],
        note: &str,
        author: &Author,
    ) -> Result<Patch> {
        write_patch(
            &self.conn,
            target,
            original,
            replacement,
            (note, "", false),
            author,
        )
    }

    /// Removes the patch at the virtual address `address`; false when there was none.
    pub fn patch_remove(&mut self, address: u64) -> Result<bool> {
        let n = self
            .conn
            .execute(
                "DELETE FROM patches WHERE target_kind = 'va' AND member = '' AND start = ?1",
                [to_db(address)],
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    /// The address patch at `address`, if any.
    pub fn patch_get(&self, address: u64) -> Result<Option<Patch>> {
        self.patch_get_at(PatchKind::Va, "", address)
    }

    /// The patch of `kind` (in `member`, for member patches) starting at `start`, if any.
    pub fn patch_get_at(&self, kind: PatchKind, member: &str, start: u64) -> Result<Option<Patch>> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {COLS} FROM patches
                     WHERE target_kind = ?1 AND member = ?2 AND start = ?3"
                ),
                params![kind.as_str(), member, to_db(start)],
                row,
            )
            .optional()
            .map_err(db)?
            .map(finish)
            .transpose()
    }

    /// Every patch, address patches first and then by file offset, for applying them to a file.
    /// Not paginated: the overlay is small and a patched binary needs all of it at once.
    pub fn all_patches(&self) -> Result<Vec<Patch>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLS} FROM patches ORDER BY {ORDER}"))
            .map_err(db)?;
        let raw = stmt
            .query_map([], row)
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        raw.into_iter().map(finish).collect()
    }

    /// The patches that are switched on, in the order of [`Store::all_patches`]: what an export
    /// or an emulated run applies. `group` limits them to one patch set.
    pub fn active_patches(&self, group: Option<&str>) -> Result<Vec<Patch>> {
        Ok(self
            .all_patches()?
            .into_iter()
            .filter(|p| !p.disabled && group.is_none_or(|g| p.group == g))
            .collect())
    }

    /// Records the verdict of a verification run for the patch-set hash `set_hash`, replacing
    /// an earlier one.
    pub fn patch_verdict_put(&mut self, set_hash: &str, same: bool, summary: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO patch_verdicts(set_hash, same, summary, ts) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(set_hash) DO UPDATE SET
                     same = excluded.same, summary = excluded.summary, ts = excluded.ts",
                params![set_hash, same, summary, now_ms()],
            )
            .map_err(db)?;
        Ok(())
    }

    /// The verdict recorded for the patch-set hash `set_hash`, if one was.
    pub fn patch_verdict(&self, set_hash: &str) -> Result<Option<PatchVerdict>> {
        self.conn
            .query_row(
                "SELECT same, summary, ts FROM patch_verdicts WHERE set_hash = ?1",
                [set_hash],
                |r| {
                    Ok(PatchVerdict {
                        set_hash: set_hash.to_string(),
                        same: r.get(0)?,
                        summary: r.get(1)?,
                        ts_ms: r.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(db)
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

    /// Patches in the order of [`Store::all_patches`], one page at a time. The cursor names the
    /// last row of the previous page as `kind:hex-start:member`.
    pub fn patches(&self, page: &PageRequest) -> Result<Page<Patch>> {
        let limit = page.effective_limit();
        let bad = || ProtoError::new(ErrorCode::InvalidArgument, "malformed patch cursor");
        // After which row to start: (kind rank, member, start is negative, start).
        let after: Option<(i64, String, i64, i64)> = match &page.cursor {
            None => None,
            Some(c) => {
                // an older cursor was just the address
                let mut parts = c.splitn(3, ':');
                let (kind, hex, member) = match (parts.next(), parts.next(), parts.next()) {
                    (Some(k), Some(h), Some(m)) => (PatchKind::parse(k).ok_or_else(bad)?, h, m),
                    _ => (PatchKind::Va, c.as_str(), ""),
                };
                let start = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .map(to_db)
                    .map_err(|_| bad())?;
                let rank = match kind {
                    PatchKind::Va => 0,
                    PatchKind::Offset => 1,
                    PatchKind::Member => 2,
                };
                Some((rank, member.to_string(), i64::from(start < 0), start))
            }
        };
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM patches", [], |r| r.get(0))
            .map_err(db)?;
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {COLS} FROM patches
                 WHERE ?1 IS NULL OR
                       (CASE target_kind WHEN 'va' THEN 0 WHEN 'offset' THEN 1 ELSE 2 END,
                        member, start < 0, start) > (?1, ?2, ?3, ?4)
                 ORDER BY {ORDER} LIMIT ?5"
            ))
            .map_err(db)?;
        let (r, m, n, st) = match &after {
            Some((r, m, n, st)) => (Some(*r), m.as_str(), *n, *st),
            None => (None, "", 0, 0),
        };
        let raw = stmt
            .query_map(params![r, m, n, st, limit as i64 + 1], row)
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        let mut items = raw.into_iter().map(finish).collect::<Result<Vec<_>>>()?;
        let next_cursor = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items
                .last()
                .map(|p| format!("{}:{:#x}:{}", p.kind.as_str(), p.address, p.member))
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
    String,
    String,
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
        r.get(9)?,
        r.get(10)?,
    ))
}

fn finish(
    (kind, member, start, original, replacement, note, author_kind, id, ts, group, disabled): Raw,
) -> Result<Patch> {
    Ok(Patch {
        kind: PatchKind::parse(&kind).ok_or_else(|| {
            ProtoError::new(ErrorCode::Internal, format!("unknown patch kind {kind:?}"))
        })?,
        member,
        address: from_db(start),
        original,
        replacement,
        note,
        group,
        disabled,
        author: Author {
            kind: parse_kind(&author_kind)?,
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

    fn set_op(anchor: Anchor, original: &str, replacement: &str) -> crate::EntryDraft {
        let op = LogOp::SetPatch {
            anchor,
            original: original.into(),
            old: None,
            new: Some(kraken_proto::PatchBytes {
                replacement: replacement.into(),
                note: String::new(),
                group: String::new(),
                disabled: false,
            }),
        };
        let key = crate::keys::op_key(&op).expect("key");
        crate::EntryDraft {
            op: kraken_proto::VersionedLogOp::new(op),
            provenance: kraken_proto::Provenance::User,
            author: Author::user("me"),
            run_id: None,
            read_set: std::collections::BTreeMap::from([(key, 0)]),
        }
    }

    fn overlay(s: &Store) -> Vec<(PatchKind, String, u64, Vec<u8>)> {
        s.all_patches()
            .expect("all")
            .into_iter()
            .map(|p| (p.kind, p.member, p.address, p.replacement))
            .collect()
    }

    #[test]
    fn an_address_patch_and_an_offset_patch_with_the_same_number_coexist() {
        let mut s = Store::open_in_memory().expect("store");
        let va = plain_anchor(PatchKind::Va, "", 0x40);
        let off = plain_anchor(PatchKind::Offset, "", 0x40);
        let member = plain_anchor(PatchKind::Member, "fw/app", 0x40);
        s.append(set_op(va, "00", "01")).expect("va");
        let off_id = s.append(set_op(off, "00", "02")).expect("offset");
        s.append(set_op(member, "00", "03")).expect("member");
        let all = overlay(&s);
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![PatchKind::Va, PatchKind::Offset, PatchKind::Member]
        );

        // undoing one leaves the others
        s.undo_entry(off_id, &Author::user("me")).expect("undo");
        let left = overlay(&s);
        assert_eq!(left.len(), 2);
        assert!(left.iter().all(|p| p.0 != PatchKind::Offset));
        assert_eq!(
            s.patch_get_at(PatchKind::Member, "fw/app", 0x40)
                .expect("get")
                .expect("kept")
                .replacement,
            vec![3]
        );
    }

    #[test]
    fn replaying_a_mixed_log_rebuilds_a_byte_identical_overlay() {
        let mut s = Store::open_in_memory().expect("store");
        for (kind, member, at, new) in [
            (PatchKind::Offset, "", 0x10, "aa"),
            (PatchKind::Va, "", 0x10, "bb"),
            (PatchKind::Member, "m1", 0x10, "cc"),
            (PatchKind::Offset, "", 0x7fff_ffff_ffff_ffff, "dd"),
        ] {
            s.append(set_op(plain_anchor(kind, member, at), "00", new))
                .expect("append");
        }
        let before = s.all_patches().expect("all");
        let page = s.patches(&PageRequest::default()).expect("page");
        assert_eq!(page.items.len(), 4);
        // rebuild the overlay from the log alone
        s.conn.execute("DELETE FROM patches", []).expect("clear");
        let entries = s
            .history(&PageRequest::default(), &crate::HistoryFilter::default())
            .expect("history")
            .items;
        for e in entries.iter().rev() {
            apply_patch_op(&s.conn, &e.op.op, &e.author).expect("replay");
        }
        let after = s.all_patches().expect("all");
        let strip = |v: &[Patch]| {
            v.iter()
                .map(|p| {
                    (
                        p.kind,
                        p.member.clone(),
                        p.address,
                        p.original.clone(),
                        p.replacement.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(&before), strip(&after));
    }

    #[test]
    fn a_pre_migration_project_keeps_its_patches_as_address_patches() {
        let dir = std::env::temp_dir().join(format!("kraken-patch-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("old.db");
        let _ = std::fs::remove_file(&path);
        {
            // a database as the build before file-offset patches left it
            let conn = Connection::open(&path).expect("open");
            conn.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                .expect("sv");
            let old = crate::store::MIGRATIONS.len() - 1;
            for (i, sql) in crate::store::MIGRATIONS[..old].iter().enumerate() {
                conn.execute_batch(sql).expect("migrate");
                conn.execute("INSERT INTO schema_version VALUES (?1)", [i as u32 + 1])
                    .expect("version");
            }
            conn.execute(
                "INSERT INTO patches(address, original, replacement, note, author_kind,
                                     author_id, ts, grp, disabled)
                 VALUES (4198400, x'7410', x'eb10', 'flip', 'user', 'me', 5, '', 0),
                        (-1, x'00', x'01', '', 'agent', 'bot', 6, 'set', 1)",
                [],
            )
            .expect("old rows");
        }
        let s = Store::open(&path).expect("migrates");
        assert_eq!(
            s.schema_version().expect("version"),
            crate::store::SCHEMA_VERSION
        );
        let p = s.patch_get(0x401000).expect("get").expect("kept");
        assert_eq!((p.kind, p.member.as_str()), (PatchKind::Va, ""));
        assert_eq!(p.replacement, vec![0xeb, 0x10]);
        assert_eq!(p.note, "flip");
        let high = s.patch_get(u64::MAX).expect("get").expect("kept");
        assert!(high.disabled && high.group == "set");
        // and a file-offset patch can now sit beside them
        drop(s);
        let mut s = Store::open(&path).expect("reopens");
        s.append(set_op(
            plain_anchor(PatchKind::Offset, "", 0x401000),
            "00",
            "ff",
        ))
        .expect("offset patch");
        assert_eq!(s.all_patches().expect("all").len(), 3);
        drop(s);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn length_and_emptiness_are_checked() {
        let mut s = Store::open_in_memory().expect("store");
        let me = Author::user("me");
        assert!(s.patch_set(0x10, &[], &[], "", &me).is_err());
        assert!(s.patch_set(0x10, &[0x00], &[0x01, 0x02], "", &me).is_err());
    }

    #[test]
    fn a_verdict_is_kept_per_set_hash_and_replaced() {
        let mut s = Store::open_in_memory().expect("store");
        assert!(s.patch_verdict("abc").expect("none").is_none());
        s.patch_verdict_put("abc", false, "stdout: line 1")
            .expect("put");
        s.patch_verdict_put("def", true, "").expect("put");
        s.patch_verdict_put("abc", true, "").expect("replace");
        let v = s.patch_verdict("abc").expect("get").expect("kept");
        assert!(v.same && v.summary.is_empty());
        assert!(s.patch_verdict("def").expect("get").is_some());
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
