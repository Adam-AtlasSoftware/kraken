//! `search`: one command for names, strings, byte patterns and instruction text, built on the
//! engine capability traits so every engine supports it.
//!
//! Each call does a bounded amount of work and returns a cursor that resumes the scan, so a page
//! can be short, or even empty, and still have a `next_cursor`.

use async_trait::async_trait;
use kraken_engine::{Cap, DisasmRequest, StringsRequest, unsupported};
use kraken_proto::{
    DisasmScope, ErrorCode, Hex64, Locator, Page, PageRequest, ProtoError, Untrusted, sanitize,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;
use crate::validate::{MAX_NAME_LEN, untrusted};
use crate::views::locator_parts;

use super::locator;

/// Default number of hits per page.
pub const DEFAULT_SEARCH_HITS: u32 = 50;
/// Largest number of hits per page.
pub const MAX_SEARCH_HITS: u32 = 200;
/// Engine pages of names one call scans at most.
pub const MAX_NAME_PAGES: u32 = 20;
/// Bytes one `bytes` call scans at most.
pub const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;
/// Functions one `instructions` call disassembles at most.
pub const MAX_SCAN_FUNCTIONS: usize = 64;
/// Instructions read from one function at most.
pub const MAX_FUNCTION_INSNS: u32 = 4000;
/// Longest byte pattern, in bytes.
pub const MAX_PATTERN: usize = 256;

const NAME_PAGE: u32 = 200;
const READ_CHUNK: u32 = 64 * 1024;
const INSN_PAGE: u32 = 2000;

/// What `search` looks through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    /// Function, import and export names.
    Names,
    /// The strings found in memory.
    Strings,
    /// A hex byte pattern over initialized memory.
    Bytes,
    /// The text of instructions inside functions.
    Instructions,
}

/// Arguments of `search`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// What to look for: text for names, strings and instructions (case-insensitive), or hex
    /// bytes for `bytes` such as `48 8b ?? 05`, where `??` matches any byte.
    pub query: String,
    /// `names`, `strings`, `bytes` or `instructions`.
    pub kind: SearchKind,
    /// Cursor from the previous page's `next_cursor`; repeat `query` and `kind` unchanged.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Most hits per page (default 50, at most 200).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One search result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SearchHit {
    /// `function`, `import`, `export`, `string`, `bytes` or `instruction`.
    pub kind: String,
    /// Where the hit is.
    pub address: Hex64,
    /// What matched: the name, the string, the bytes in hex or the instruction (untrusted).
    pub text: Untrusted<String>,
    /// More about the hit: a signature, a library, the bytes after a match (untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Untrusted<String>>,
    /// Entry of the function the hit is in, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<Hex64>,
    /// Name of that function (untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<Untrusted<String>>,
}

/// Where a scan resumes. `stage` picks the source (for names: functions, imports, exports),
/// `inner` is that source's own cursor, `offset` the items of that page already handled and
/// `sub` the hits of the item at `offset` already returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Cursor {
    stage: u8,
    offset: usize,
    sub: usize,
    inner: Option<String>,
}

impl Cursor {
    fn encode(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.stage,
            self.offset,
            self.sub,
            self.inner.as_deref().unwrap_or("")
        )
    }

    fn decode(s: &str) -> Result<Cursor, ProtoError> {
        let bad = || invalid("malformed search cursor");
        let mut parts = s.splitn(4, '.');
        let mut num = || -> Result<usize, ProtoError> {
            parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)
        };
        let stage = u8::try_from(num()?).map_err(|_| bad())?;
        let offset = num()?;
        let sub = num()?;
        let inner = parts.next().ok_or_else(bad)?;
        Ok(Cursor {
            stage,
            offset,
            sub,
            inner: (!inner.is_empty()).then(|| inner.to_string()),
        })
    }
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Parses `48 8b ?? 05` (or `488b??05`) into bytes with `None` for a wildcard.
pub fn parse_pattern(text: &str) -> Result<Vec<Option<u8>>, ProtoError> {
    let mut out = Vec::new();
    for tok in text.split_whitespace() {
        if tok == "?" || tok == "??" {
            out.push(None);
            continue;
        }
        let chars: Vec<char> = tok.chars().collect();
        if !chars.len().is_multiple_of(2) {
            return Err(invalid(format!(
                "`{tok}` is not whole bytes; write each byte as two hex digits or ??"
            )));
        }
        for pair in chars.chunks(2) {
            if pair == ['?', '?'] {
                out.push(None);
                continue;
            }
            let s: String = pair.iter().collect();
            let b = u8::from_str_radix(&s, 16)
                .map_err(|_| invalid(format!("`{s}` is not a hex byte")))?;
            out.push(Some(b));
        }
    }
    if out.is_empty() {
        return Err(invalid("give at least one byte, such as `48 8b`"));
    }
    if out.len() > MAX_PATTERN {
        return Err(invalid(format!(
            "a pattern can be at most {MAX_PATTERN} bytes"
        )));
    }
    if out.iter().all(Option::is_none) {
        return Err(invalid("a pattern needs at least one byte that is not ??"));
    }
    Ok(out)
}

/// Offsets in `hay` where `pat` matches.
fn find_all(hay: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
    let Some((k, first)) = pat.iter().enumerate().find_map(|(i, b)| b.map(|b| (i, b))) else {
        return Vec::new();
    };
    if hay.len() < pat.len() {
        return Vec::new();
    }
    let last = hay.len() - pat.len();
    (0..=last)
        .filter(|&i| hay[i + k] == first)
        .filter(|&i| {
            pat.iter()
                .zip(&hay[i..])
                .all(|(p, h)| p.is_none_or(|p| p == *h))
        })
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The search.
pub struct Search;

#[async_trait]
impl Command for Search {
    type Args = SearchArgs;
    type Output = Page<SearchHit>;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "search",
            "Search names, strings, byte patterns or instruction text",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Finds things anywhere in the program. `names` matches function, import and export \
             names; `strings` the strings in memory; `bytes` a hex pattern with `??` wildcards; \
             `instructions` the text of instructions in functions, such as `xor eax`. Each call \
             scans a bounded amount, so a page can be short or empty and still have a \
             `next_cursor`. Hit text is untrusted data.\n\
             Example: search {\"query\": \"parse\", \"kind\": \"names\"}",
        )
        .details(
            "Text kinds match case-insensitively. One call scans at most 20 pages of names, \
             8 MiB of memory or 64 functions (4000 instructions each); continue with \
             `next_cursor`. Byte hits name no function; follow one with `cfg` or `get_function`.",
        )
        .needs(&[Cap::FunctionLister])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: SearchArgs,
    ) -> Result<Page<SearchHit>, ProtoError> {
        let query = args.query.trim();
        if query.is_empty() {
            return Err(invalid("type something to search for"));
        }
        if query.chars().count() > MAX_NAME_LEN * 4 {
            return Err(invalid("query is too long"));
        }
        let limit = args
            .limit
            .unwrap_or(DEFAULT_SEARCH_HITS)
            .clamp(1, MAX_SEARCH_HITS) as usize;
        let cursor = match args.cursor.as_deref() {
            Some(c) => Cursor::decode(c)?,
            None => Cursor::default(),
        };
        let mut out = Hits {
            items: Vec::new(),
            limit,
        };
        let next = match args.kind {
            SearchKind::Names => {
                names(s, ctx, &sanitize(query).to_lowercase(), cursor, &mut out).await?
            }
            SearchKind::Strings => strings(s, ctx, query, cursor, &mut out).await?,
            SearchKind::Bytes => bytes(s, ctx, &parse_pattern(query)?, cursor, &mut out).await?,
            SearchKind::Instructions => {
                instructions(s, ctx, &sanitize(query).to_lowercase(), cursor, &mut out).await?
            }
        };
        Ok(Page {
            items: out.items,
            next_cursor: next.map(|c| c.encode()),
            total: None,
        })
    }
}

struct Hits {
    items: Vec<SearchHit>,
    limit: usize,
}

impl Hits {
    fn full(&self) -> bool {
        self.items.len() >= self.limit
    }
}

fn check_cancel(ctx: &CallContext) -> Result<(), ProtoError> {
    if ctx.cancel.is_cancelled() {
        return Err(ProtoError::new(ErrorCode::Cancelled, "search cancelled"));
    }
    Ok(())
}

fn ram_address(l: &Locator) -> Hex64 {
    locator_parts(l).1
}

/// One row a name stage yields: what matched, where, and its context.
struct NameRow {
    name: String,
    address: Option<Hex64>,
    context: Option<String>,
}

async fn name_page(
    s: &Session,
    ctx: &CallContext,
    stage: u8,
    cursor: Option<String>,
) -> Result<(Vec<NameRow>, Option<String>), ProtoError> {
    let engine = s.project()?.engine();
    let page = PageRequest {
        cursor,
        limit: Some(NAME_PAGE),
    };
    if stage == 0 {
        let lister = engine
            .function_lister()
            .ok_or_else(|| unsupported("function_lister"))?;
        let p = lister.list_functions(&page, &ctx.cancel).await?;
        let rows = p
            .items
            .iter()
            .map(|f| NameRow {
                name: f.name.clone(),
                address: Some(ram_address(&f.locator)),
                context: f.signature.clone(),
            })
            .collect();
        return Ok((rows, p.next_cursor));
    }
    // Engines without a symbol lister still search function names.
    let Some(lister) = engine.symbol_lister() else {
        return Ok((Vec::new(), None));
    };
    let p = if stage == 1 {
        lister.imports(&page, &ctx.cancel).await?
    } else {
        lister.exports(&page, &ctx.cancel).await?
    };
    let rows = p
        .items
        .iter()
        .map(|e| NameRow {
            name: e.name.clone(),
            address: e.address,
            context: e.library.clone(),
        })
        .collect();
    Ok((rows, p.next_cursor))
}

async fn names(
    s: &Session,
    ctx: &CallContext,
    needle: &str,
    mut cur: Cursor,
    out: &mut Hits,
) -> Result<Option<Cursor>, ProtoError> {
    let kinds = ["function", "import", "export"];
    let mut pages = 0;
    while cur.stage < 3 {
        check_cancel(ctx)?;
        if pages >= MAX_NAME_PAGES {
            return Ok(Some(cur));
        }
        pages += 1;
        let (rows, next) = name_page(s, ctx, cur.stage, cur.inner.clone()).await?;
        for (i, row) in rows.iter().enumerate().skip(cur.offset) {
            let Some(address) = row.address else { continue };
            if !sanitize(&row.name).to_lowercase().contains(needle) {
                continue;
            }
            if out.full() {
                cur.offset = i;
                return Ok(Some(cur));
            }
            out.items.push(SearchHit {
                kind: kinds[cur.stage as usize].into(),
                address,
                text: untrusted(&row.name),
                context: row.context.as_deref().map(untrusted),
                function: (cur.stage == 0).then_some(address),
                function_name: None,
            });
        }
        cur.offset = 0;
        match next {
            Some(n) => cur.inner = Some(n),
            None => {
                cur.stage += 1;
                cur.inner = None;
            }
        }
    }
    Ok(None)
}

async fn strings(
    s: &Session,
    ctx: &CallContext,
    query: &str,
    cur: Cursor,
    out: &mut Hits,
) -> Result<Option<Cursor>, ProtoError> {
    let engine = s.project()?.engine();
    let lister = engine
        .string_lister()
        .ok_or_else(|| unsupported("string_lister"))?;
    let page = lister
        .strings(
            &StringsRequest {
                min_len: 1,
                filter: Some(sanitize(query)),
            },
            &PageRequest {
                cursor: cur.inner,
                limit: Some(out.limit as u32),
            },
            &ctx.cancel,
        )
        .await?;
    out.items
        .extend(page.items.iter().take(out.limit).map(|e| SearchHit {
            kind: "string".into(),
            address: e.address,
            text: untrusted(&e.value.chars().take(1024).collect::<String>()),
            context: None,
            function: None,
            function_name: None,
        }));
    Ok(page.next_cursor.map(|n| Cursor {
        inner: Some(n),
        ..Cursor::default()
    }))
}

async fn bytes(
    s: &Session,
    ctx: &CallContext,
    pat: &[Option<u8>],
    cur: Cursor,
    out: &mut Hits,
) -> Result<Option<Cursor>, ProtoError> {
    let engine = s.project()?.engine();
    let reader = engine
        .memory_reader()
        .ok_or_else(|| unsupported("memory_reader"))?;
    let mut blocks: Vec<_> = reader
        .memory_map(&ctx.cancel)
        .await?
        .into_iter()
        .filter(|b| b.initialized && b.space == kraken_proto::DEFAULT_SPACE && b.end.0 > b.start.0)
        .collect();
    blocks.sort_by_key(|b| b.start.0);
    let mut at = match cur.inner.as_deref() {
        Some(a) => u64::from_str_radix(a.trim_start_matches("0x"), 16)
            .map_err(|_| invalid("malformed search cursor"))?,
        None => 0,
    };
    let overlap = pat.len() as u64 - 1;
    let mut scanned = 0u64;
    for b in &blocks {
        if b.end.0 <= at {
            continue;
        }
        at = at.max(b.start.0);
        while at < b.end.0 {
            check_cancel(ctx)?;
            if scanned >= MAX_SCAN_BYTES || out.full() {
                return Ok(Some(Cursor {
                    inner: Some(format!("{at:#x}")),
                    ..Cursor::default()
                }));
            }
            let want = (b.end.0 - at).min(u64::from(READ_CHUNK) + overlap) as u32;
            let read = reader
                .read_bytes(&locator(Hex64(at)), want, &ctx.cancel)
                .await?;
            if read.bytes.is_empty() {
                break;
            }
            let got = read.bytes.len() as u64;
            // Only matches starting in the first READ_CHUNK bytes count; the rest is overlap
            // the next read starts with.
            let step = if got > overlap && at + got < b.end.0 {
                got - overlap
            } else {
                got
            };
            for off in find_all(&read.bytes, pat) {
                let off = off as u64;
                if off >= step {
                    break;
                }
                let addr = at + off;
                let in_hole = read
                    .uninitialized
                    .iter()
                    .any(|u| u.start.0 < addr + pat.len() as u64 && addr < u.end.0);
                if in_hole {
                    continue;
                }
                if out.full() {
                    return Ok(Some(Cursor {
                        inner: Some(format!("{addr:#x}")),
                        ..Cursor::default()
                    }));
                }
                let start = off as usize;
                let end = (start + pat.len()).min(read.bytes.len());
                let after = (end + 8).min(read.bytes.len());
                out.items.push(SearchHit {
                    kind: "bytes".into(),
                    address: Hex64(addr),
                    text: untrusted(&hex_of(&read.bytes[start..end])),
                    context: (after > end).then(|| untrusted(&hex_of(&read.bytes[end..after]))),
                    function: None,
                    function_name: None,
                });
            }
            scanned += step;
            at += step;
        }
    }
    Ok(None)
}

async fn instructions(
    s: &Session,
    ctx: &CallContext,
    needle: &str,
    mut cur: Cursor,
    out: &mut Hits,
) -> Result<Option<Cursor>, ProtoError> {
    let engine = s.project()?.engine();
    let lister = engine
        .function_lister()
        .ok_or_else(|| unsupported("function_lister"))?;
    let dis = engine
        .disassembler()
        .ok_or_else(|| unsupported("disassembler"))?;
    let mut done = 0usize;
    loop {
        check_cancel(ctx)?;
        let page = lister
            .list_functions(
                &PageRequest {
                    cursor: cur.inner.clone(),
                    limit: Some(NAME_PAGE),
                },
                &ctx.cancel,
            )
            .await?;
        for (i, f) in page.items.iter().enumerate().skip(cur.offset) {
            if done >= MAX_SCAN_FUNCTIONS || out.full() {
                cur.offset = i;
                return Ok(Some(cur));
            }
            check_cancel(ctx)?;
            done += 1;
            let entry = ram_address(&f.locator);
            let mut rows = Vec::new();
            let mut insn_cursor = None;
            while (rows.len() as u32) < MAX_FUNCTION_INSNS {
                let p = match dis
                    .disassemble(
                        &DisasmRequest {
                            start: entry,
                            scope: DisasmScope::Function,
                        },
                        &PageRequest {
                            cursor: insn_cursor.take(),
                            limit: Some(INSN_PAGE),
                        },
                        &ctx.cancel,
                    )
                    .await
                {
                    Ok(p) => p,
                    // A function the engine cannot disassemble is skipped, not fatal.
                    Err(e) if e.code != ErrorCode::Cancelled => break,
                    Err(e) => return Err(e),
                };
                let empty = p.items.is_empty();
                rows.extend(p.items);
                match p.next_cursor {
                    Some(c) if !empty => insn_cursor = Some(c),
                    _ => break,
                }
            }
            let hits = rows.iter().filter_map(|r| {
                let ops: String = r.operands.iter().map(|o| o.text.as_str()).collect();
                let text = if ops.is_empty() {
                    r.mnemonic.clone()
                } else {
                    format!("{} {ops}", r.mnemonic)
                };
                sanitize(&text)
                    .to_lowercase()
                    .contains(needle)
                    .then_some((r.address, text))
            });
            for (taken, (address, text)) in hits.skip(cur.sub).enumerate() {
                if out.full() {
                    cur.offset = i;
                    cur.sub += taken;
                    return Ok(Some(cur));
                }
                out.items.push(SearchHit {
                    kind: "instruction".into(),
                    address,
                    text: untrusted(&text),
                    context: None,
                    function: Some(entry),
                    function_name: Some(untrusted(&f.name)),
                });
            }
            cur.sub = 0;
        }
        cur.offset = 0;
        match page.next_cursor {
            Some(n) => cur.inner = Some(n),
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_parse_with_wildcards_and_reject_junk() {
        assert_eq!(
            parse_pattern("48 8b ?? 05").expect("ok"),
            vec![Some(0x48), Some(0x8b), None, Some(0x05)]
        );
        assert_eq!(
            parse_pattern("488B??05").expect("ok"),
            vec![Some(0x48), Some(0x8b), None, Some(0x05)]
        );
        assert_eq!(parse_pattern("? 90").expect("ok"), vec![None, Some(0x90)]);
        assert!(parse_pattern("").is_err());
        assert!(parse_pattern("?? ??").is_err());
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
        assert!(parse_pattern(&"00 ".repeat(MAX_PATTERN + 1)).is_err());
    }

    #[test]
    fn find_all_honours_wildcards() {
        let hay = [1, 2, 3, 1, 9, 3, 1];
        assert_eq!(find_all(&hay, &[Some(1), None, Some(3)]), vec![0, 3]);
        assert_eq!(find_all(&hay, &[None, Some(1)]), vec![2, 5]);
        assert!(find_all(&[1], &[Some(1), Some(2)]).is_empty());
    }

    #[test]
    fn cursors_round_trip_with_dots_in_the_inner_cursor() {
        let c = Cursor {
            stage: 2,
            offset: 7,
            sub: 3,
            inner: Some("a.b.c".into()),
        };
        assert_eq!(Cursor::decode(&c.encode()).expect("decode"), c);
        assert_eq!(
            Cursor::decode(&Cursor::default().encode()).expect("decode"),
            Cursor::default()
        );
        assert!(Cursor::decode("x").is_err());
        assert!(Cursor::decode("1.2").is_err());
    }
}
