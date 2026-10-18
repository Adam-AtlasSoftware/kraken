//! Bookmarks: addresses a person or an agent marked to come back to, with an optional note.
//!
//! They are kept in their own table, not in the edit log: a bookmark is a reading aid, not an
//! annotation of the program, so it never reaches the engine, needs no undo entry and is not
//! subject to the agent proposal policy. Removing one is the way back.

use kraken_proto::{ErrorCode, Page, PageRequest, ProtoError};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::store::{db, kind_str, now_ms, parse_kind};
use crate::{Author, Store};

pub(crate) const MIGRATION: &str = "CREATE TABLE bookmarks (
        address INTEGER PRIMARY KEY,
        note TEXT NOT NULL,
        author_kind TEXT NOT NULL,
        author_id TEXT NOT NULL,
        ts INTEGER NOT NULL
    );";

type Result<T> = std::result::Result<T, ProtoError>;

/// One stored bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    /// The marked address.
    pub address: u64,
    /// The note; empty when none was given.
    pub note: String,
    /// Who set it last.
    pub author: Author,
    /// When it was set last, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

// SQLite integers are signed; addresses above i64::MAX keep their bits.
fn to_db(a: u64) -> i64 {
    a as i64
}

fn from_db(a: i64) -> u64 {
    a as u64
}

impl Store {
    /// Sets the bookmark at `address`, replacing the note of an existing one.
    pub fn bookmark_set(&mut self, address: u64, note: &str, author: &Author) -> Result<Bookmark> {
        let ts = now_ms();
        self.conn
            .execute(
                "INSERT INTO bookmarks(address, note, author_kind, author_id, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(address) DO UPDATE SET note = excluded.note,
                    author_kind = excluded.author_kind, author_id = excluded.author_id,
                    ts = excluded.ts",
                params![to_db(address), note, kind_str(author.kind), author.id, ts],
            )
            .map_err(db)?;
        Ok(Bookmark {
            address,
            note: note.to_string(),
            author: author.clone(),
            ts_ms: ts,
        })
    }

    /// Removes the bookmark at `address`; false when there was none.
    pub fn bookmark_remove(&mut self, address: u64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM bookmarks WHERE address = ?1", [to_db(address)])
            .map_err(db)?;
        Ok(n > 0)
    }

    /// The bookmark at `address`, if any.
    pub fn bookmark_get(&self, address: u64) -> Result<Option<Bookmark>> {
        self.conn
            .query_row(
                "SELECT address, note, author_kind, author_id, ts FROM bookmarks
                 WHERE address = ?1",
                [to_db(address)],
                row,
            )
            .optional()
            .map_err(db)?
            .map(finish)
            .transpose()
    }

    /// Bookmarks ordered by address. The cursor is the address of the last row of the previous
    /// page, in hex.
    pub fn bookmarks(&self, page: &PageRequest) -> Result<Page<Bookmark>> {
        let limit = page.effective_limit();
        let after: Option<i64> = match &page.cursor {
            None => None,
            Some(c) => Some(
                u64::from_str_radix(c.trim_start_matches("0x"), 16)
                    .map(to_db)
                    .map_err(|_| {
                        ProtoError::new(ErrorCode::InvalidArgument, "malformed bookmark cursor")
                    })?,
            ),
        };
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM bookmarks", [], |r| r.get(0))
            .map_err(db)?;
        // Ordered as unsigned: rows with the top bit set (negative in SQLite) come last.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, note, author_kind, author_id, ts FROM bookmarks
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
            items.last().map(|b| format!("{:#x}", b.address))
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

type Raw = (i64, String, String, String, i64);

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn finish((address, note, kind, id, ts): Raw) -> Result<Bookmark> {
    Ok(Bookmark {
        address: from_db(address),
        note,
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
    fn set_replace_list_page_and_remove() {
        let mut s = Store::open_in_memory().expect("store");
        let me = Author::user("me");
        s.bookmark_set(0x401000, "entry", &me).expect("set");
        s.bookmark_set(0x400000, "", &Author::agent("a1"))
            .expect("set");
        s.bookmark_set(u64::MAX - 1, "high", &me).expect("set");
        let b = s.bookmark_set(0x401000, "main loop", &me).expect("replace");
        assert_eq!(b.note, "main loop");
        assert_eq!(
            s.bookmark_get(0x401000).expect("get").expect("there").note,
            "main loop"
        );

        let p1 = s
            .bookmarks(&PageRequest {
                cursor: None,
                limit: Some(2),
            })
            .expect("page");
        assert_eq!(p1.total, Some(3));
        let addrs: Vec<u64> = p1.items.iter().map(|b| b.address).collect();
        assert_eq!(addrs, vec![0x400000, 0x401000]);
        let p2 = s
            .bookmarks(&PageRequest {
                cursor: p1.next_cursor,
                limit: Some(2),
            })
            .expect("page 2");
        assert_eq!(p2.items.len(), 1);
        assert_eq!(p2.items[0].address, u64::MAX - 1);
        assert!(p2.next_cursor.is_none());

        assert!(s.bookmark_remove(0x401000).expect("remove"));
        assert!(!s.bookmark_remove(0x401000).expect("remove again"));
        assert!(s.bookmark_get(0x401000).expect("get").is_none());
        assert!(
            s.bookmarks(&PageRequest {
                cursor: Some("zz".into()),
                limit: None
            })
            .is_err()
        );
    }
}
