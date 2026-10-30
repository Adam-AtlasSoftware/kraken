//! Program-data views (memory, bytes, listing, references, CFG, strings, symbols).
//!
//! Each view serves what the fixture recorded and falls back to deterministic synthetic data
//! derived from the functions (and their decompiled text) when the fixture has none, so a
//! hand-written fixture needs no extra fields.

use std::collections::{BTreeMap, BTreeSet};

use kraken_engine::{DisasmRequest, EngineResult, StringsRequest, XrefRequest};
use kraken_proto::{
    AddressRange, BytesRead, Cfg, CfgBlock, CfgEdge, CfgEdgeKind, DEFAULT_SPACE, DisasmRow,
    DisasmScope, ErrorCode, FlowKind, FunctionRef, Hex64, JumpTable, Locator, MemoryBlock,
    MemoryKind, OperandKind, OperandToken, Page, PageRequest, ProtoError, StringEncoding,
    StringEntry, SymbolEntry, SymbolKind, TokenKind, Xref, XrefDirection, XrefKind, hex_bytes,
};

use crate::fixture::{FixtureFunction, key_of};

pub(crate) type FnKey = (String, u64);

/// Bytes per synthetic instruction (the last one may be shorter).
const SYNTH_INSN: u64 = 4;
const PAGE_SIZE: u64 = 0x1000;

fn invalid(msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn not_found(msg: String) -> ProtoError {
    ProtoError::new(ErrorCode::NotFound, msg)
}

/// The byte the fake reports for an address no fixture row covers.
pub(crate) fn synth_byte(addr: u64) -> u8 {
    (addr.wrapping_mul(0x9E37_79B1).rotate_right(13) >> 3) as u8
}

fn ram_offset(l: &Locator) -> Option<u64> {
    match l {
        Locator::Native { space, offset } if space == DEFAULT_SPACE => Some(offset.0),
        _ => None,
    }
}

fn func_size(f: &FixtureFunction) -> u64 {
    f.summary.size.unwrap_or(1).max(1)
}

fn func_ref(f: &FixtureFunction) -> FunctionRef {
    FunctionRef {
        address: Hex64(key_of(&f.summary.locator).1),
        name: f.summary.name.clone(),
    }
}

fn decode_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

/// Distinct call targets in a function's decompiled text, in order of appearance.
fn call_targets(f: &FixtureFunction) -> Vec<(u64, String)> {
    let entry = key_of(&f.summary.locator).1;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for t in &f.decompile.tokens {
        if t.kind != TokenKind::Function {
            continue;
        }
        let Some(target) = t.target.as_ref().and_then(ram_offset) else {
            continue;
        };
        if target != entry && seen.insert(target) {
            out.push((target, t.symbol.clone().unwrap_or_default()));
        }
    }
    out
}

fn synth_rows(f: &FixtureFunction, names: &BTreeMap<u64, String>) -> Vec<DisasmRow> {
    let entry = key_of(&f.summary.locator).1;
    let size = func_size(f);
    let n = size.div_ceil(SYNTH_INSN);
    let targets = call_targets(f);
    (0..n)
        .map(|i| {
            let address = entry + i * SYNTH_INSN;
            let len = (size - i * SYNTH_INSN).min(SYNTH_INSN);
            let bytes: Vec<u8> = (0..len).map(|k| synth_byte(address + k)).collect();
            let labels = if i == 0 {
                vec![f.summary.name.clone()]
            } else {
                Vec::new()
            };
            let (mnemonic, operands, flow) = if i == n - 1 {
                ("ret", Vec::new(), FlowKind::Return)
            } else if let Some((target, symbol)) =
                i.checked_sub(1).and_then(|k| targets.get(k as usize))
            {
                let name = names.get(target).cloned().unwrap_or_else(|| symbol.clone());
                let kind = if name.is_empty() {
                    OperandKind::Address
                } else {
                    OperandKind::Symbol
                };
                let text = if name.is_empty() {
                    format!("{:#x}", target)
                } else {
                    name
                };
                (
                    "call",
                    vec![OperandToken {
                        text,
                        kind,
                        target: Some(Locator::ram(*target)),
                    }],
                    FlowKind::Call,
                )
            } else {
                (
                    "mov",
                    vec![
                        OperandToken {
                            text: "eax".into(),
                            kind: OperandKind::Register,
                            target: None,
                        },
                        OperandToken {
                            text: ", ".into(),
                            kind: OperandKind::Other,
                            target: None,
                        },
                        OperandToken {
                            text: format!("{:#x}", i),
                            kind: OperandKind::Immediate,
                            target: None,
                        },
                    ],
                    FlowKind::Fallthrough,
                )
            };
            DisasmRow {
                address: Hex64(address),
                bytes: hex_bytes(&bytes),
                mnemonic: mnemonic.into(),
                operands,
                comment: None,
                labels,
                flow,
            }
        })
        .collect()
}

fn derive_xrefs(
    f: &FixtureFunction,
    rows: &[DisasmRow],
    names: &BTreeMap<u64, String>,
) -> Vec<Xref> {
    let mut out = Vec::new();
    for r in rows {
        let kind = match r.flow {
            FlowKind::Call => XrefKind::Call,
            FlowKind::Jump | FlowKind::ConditionalJump => XrefKind::Jump,
            _ => continue,
        };
        for op in &r.operands {
            if let Some(to) = op.target.as_ref().and_then(ram_offset) {
                out.push(Xref {
                    from: r.address,
                    to: Hex64(to),
                    kind,
                    from_function: Some(func_ref(f)),
                    to_function: names.get(&to).map(|name| FunctionRef {
                        address: Hex64(to),
                        name: name.clone(),
                    }),
                });
            }
        }
    }
    out
}

/// A page of an in-memory list; the cursor is the decimal index of the next item.
fn page_vec<T: Clone>(all: &[T], page: &PageRequest) -> EngineResult<Page<T>> {
    let from = match &page.cursor {
        None => 0,
        Some(c) => c
            .parse::<usize>()
            .map_err(|_| invalid("malformed cursor"))?,
    };
    let from = from.min(all.len());
    let to = (from + page.effective_limit() as usize).min(all.len());
    Ok(Page {
        items: all[from..to].to_vec(),
        next_cursor: (to < all.len()).then(|| to.to_string()),
        total: Some(all.len() as u64),
    })
}

/// String literals (`"..."`) of C text, unescaped, in order.
fn string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut value = String::new();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    closed = true;
                    break;
                }
                '\n' => break,
                '\\' => match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('t') => value.push('\t'),
                    Some('r') => value.push('\r'),
                    Some('0') => value.push('\0'),
                    Some(other) => value.push(other),
                    None => break,
                },
                other => value.push(other),
            }
        }
        if closed && !value.is_empty() {
            out.push(value);
        }
    }
    out
}

/// What the views read from.
pub(crate) struct DataView<'a> {
    pub functions: &'a BTreeMap<FnKey, FixtureFunction>,
    pub base: u64,
    pub memory: Option<&'a [MemoryBlock]>,
    pub strings: Option<&'a [StringEntry]>,
    pub imports: Option<&'a [SymbolEntry]>,
    pub exports: Option<&'a [SymbolEntry]>,
}

impl DataView<'_> {
    fn ram_functions(&self) -> impl Iterator<Item = (u64, &FixtureFunction)> {
        self.functions
            .iter()
            .filter(|((space, _), _)| space == DEFAULT_SPACE)
            .map(|((_, off), f)| (*off, f))
    }

    fn names(&self) -> BTreeMap<u64, String> {
        self.ram_functions()
            .map(|(off, f)| (off, f.summary.name.clone()))
            .collect()
    }

    /// The function whose body holds `addr`.
    fn containing(&self, addr: u64) -> Option<(u64, &FixtureFunction)> {
        let (key, f) = self
            .functions
            .range((DEFAULT_SPACE.to_string(), 0)..=(DEFAULT_SPACE.to_string(), addr))
            .next_back()?;
        (addr < key.1.saturating_add(func_size(f))).then_some((key.1, f))
    }

    fn rows_of(&self, f: &FixtureFunction, names: &BTreeMap<u64, String>) -> Vec<DisasmRow> {
        f.disassembly
            .clone()
            .unwrap_or_else(|| synth_rows(f, names))
    }

    // ---- memory ---------------------------------------------------------------------

    pub fn memory_map(&self) -> Vec<MemoryBlock> {
        let mut blocks = match self.memory {
            Some(m) => m.to_vec(),
            None => self.synth_memory(),
        };
        blocks.sort_by(|a, b| (&a.space, a.start).cmp(&(&b.space, b.start)));
        blocks
    }

    fn extent(&self) -> (u64, u64) {
        let mut lo = u64::MAX;
        let mut hi = 0;
        for (off, f) in self.ram_functions() {
            lo = lo.min(off);
            hi = hi.max(off.saturating_add(func_size(f)));
        }
        if lo > hi {
            (self.base, self.base.saturating_add(1))
        } else {
            (lo, hi)
        }
    }

    fn synth_text_end(&self) -> u64 {
        let (lo, hi) = self.extent();
        let start = lo & !(PAGE_SIZE - 1);
        let end = hi.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        end.max(start + PAGE_SIZE)
    }

    fn synth_memory(&self) -> Vec<MemoryBlock> {
        let (lo, _) = self.extent();
        let text_start = lo & !(PAGE_SIZE - 1);
        let text_end = self.synth_text_end();
        let block =
            |name: &str, start: u64, end: u64, perms: &str, initialized: bool| MemoryBlock {
                name: name.into(),
                space: DEFAULT_SPACE.into(),
                start: Hex64(start),
                end: Hex64(end),
                perms: perms.into(),
                initialized,
                kind: MemoryKind::Default,
            };
        vec![
            block(".text", text_start, text_end, "r-x", true),
            block(".rodata", text_end, text_end + PAGE_SIZE, "r--", true),
            block(
                ".data",
                text_end + PAGE_SIZE,
                text_end + 2 * PAGE_SIZE,
                "rw-",
                true,
            ),
            block(
                ".bss",
                text_end + 2 * PAGE_SIZE,
                text_end + 3 * PAGE_SIZE,
                "rw-",
                false,
            ),
        ]
    }

    pub fn read_bytes(&self, start: &Locator, length: u32) -> EngineResult<BytesRead> {
        if length == 0 {
            return Err(invalid("length must be positive"));
        }
        let Some(start) = ram_offset(start) else {
            return Err(not_found(format!("no memory at {start:?}")));
        };
        let blocks: Vec<MemoryBlock> = self
            .memory_map()
            .into_iter()
            .filter(|b| b.space == DEFAULT_SPACE)
            .collect();
        let find = |addr: u64| blocks.iter().find(|b| b.start.0 <= addr && addr < b.end.0);
        if find(start).is_none() {
            return Err(not_found(format!("no memory at {start:#x}")));
        }
        let mut data: Vec<u8> = Vec::new();
        let mut uninitialized: Vec<AddressRange> = Vec::new();
        let mut cur = start;
        while (data.len() as u64) < u64::from(length) {
            let Some(b) = find(cur) else { break };
            let n = (b.end.0 - cur).min(u64::from(length) - data.len() as u64);
            if b.initialized {
                data.extend((0..n).map(|k| synth_byte(cur + k)));
            } else {
                data.extend((0..n).map(|_| 0));
                match uninitialized.last_mut() {
                    Some(r) if r.end.0 == cur => r.end = Hex64(cur + n),
                    _ => uninitialized.push(AddressRange {
                        space: DEFAULT_SPACE.into(),
                        start: Hex64(cur),
                        end: Hex64(cur + n),
                    }),
                }
            }
            cur += n;
        }
        // Recorded instruction bytes win over the filler.
        let end = start + data.len() as u64;
        let first = self.containing(start).map_or(start, |(entry, _)| entry);
        for (off, f) in self.ram_functions().filter(|(o, _)| *o >= first) {
            if off >= end {
                break;
            }
            let Some(rows) = &f.disassembly else { continue };
            for r in rows {
                let a = r.address.0;
                if a >= end {
                    break;
                }
                let bytes = decode_hex(&r.bytes);
                for (k, byte) in bytes.iter().enumerate() {
                    let at = a + k as u64;
                    if at >= start && at < end {
                        let skip = uninitialized
                            .iter()
                            .any(|u| u.start.0 <= at && at < u.end.0);
                        if !skip {
                            data[(at - start) as usize] = *byte;
                        }
                    }
                }
            }
        }
        Ok(BytesRead {
            start: Hex64(start),
            bytes: data,
            uninitialized,
        })
    }

    // ---- listing --------------------------------------------------------------------

    pub fn disassemble(
        &self,
        req: &DisasmRequest,
        page: &PageRequest,
    ) -> EngineResult<Page<DisasmRow>> {
        let from = match &page.cursor {
            // a function listing starts at the entry, wherever inside the function `start` lies
            None if req.scope == DisasmScope::Function => 0,
            None => req.start.0,
            Some(c) => {
                c.parse::<Hex64>()
                    .map_err(|_| invalid("malformed cursor"))?
                    .0
            }
        };
        let limit = page.effective_limit() as usize;
        let names = self.names();
        let mut rows: Vec<DisasmRow> = Vec::new();
        match req.scope {
            DisasmScope::Function => {
                let (_, f) = self
                    .containing(req.start.0)
                    .ok_or_else(|| not_found(format!("no function at {}", req.start)))?;
                let all = self.rows_of(f, &names);
                let skip = all.partition_point(|r| r.address.0 < from);
                rows.extend(all.into_iter().skip(skip).take(limit + 1));
            }
            DisasmScope::Linear => {
                let first = self.containing(from).map_or(from, |(entry, _)| entry);
                'outer: for (_, f) in self.ram_functions().filter(|(o, _)| *o >= first) {
                    for r in self.rows_of(f, &names) {
                        if r.address.0 < from {
                            continue;
                        }
                        rows.push(r);
                        if rows.len() > limit {
                            break 'outer;
                        }
                    }
                }
            }
        }
        let next_cursor = if rows.len() > limit {
            rows.pop().map(|r| r.address.to_hex())
        } else {
            None
        };
        Ok(Page {
            items: rows,
            next_cursor,
            total: None,
        })
    }

    // ---- references -----------------------------------------------------------------

    fn all_xrefs(&self) -> Vec<Xref> {
        let names = self.names();
        let mut out: Vec<Xref> = Vec::new();
        for (_, f) in self.ram_functions() {
            match &f.xrefs {
                Some(x) => out.extend(x.iter().cloned()),
                None => out.extend(derive_xrefs(f, &self.rows_of(f, &names), &names)),
            }
        }
        out.sort_by_key(|x| (x.from, x.to, x.kind));
        out.dedup();
        out
    }

    pub fn xrefs(&self, req: &XrefRequest, page: &PageRequest) -> EngineResult<Page<Xref>> {
        let bounds = if req.direction == XrefDirection::From && req.whole_function {
            let (entry, f) = self
                .containing(req.address.0)
                .ok_or_else(|| not_found(format!("no function at {}", req.address)))?;
            Some((entry, entry + func_size(f)))
        } else {
            None
        };
        let items: Vec<Xref> = self
            .all_xrefs()
            .into_iter()
            .filter(|x| match (req.direction, bounds) {
                (XrefDirection::To, _) => x.to == req.address,
                (XrefDirection::From, Some((lo, hi))) => x.from.0 >= lo && x.from.0 < hi,
                (XrefDirection::From, None) => x.from == req.address,
            })
            .filter(|x| req.kind.is_none_or(|k| k == x.kind))
            .collect();
        page_vec(&items, page)
    }

    // ---- control flow ---------------------------------------------------------------

    pub fn cfg(&self, function: &Locator) -> EngineResult<Cfg> {
        let at = ram_offset(function)
            .ok_or_else(|| not_found(format!("no function at {function:?}")))?;
        let (entry, f) = self
            .containing(at)
            .ok_or_else(|| not_found(format!("no function at {at:#x}")))?;
        if let Some(c) = &f.cfg {
            return Ok(c.clone());
        }
        let rows = self.rows_of(f, &self.names());
        let end = rows.last().map_or(entry + func_size(f), |r| {
            r.address.0 + (r.bytes.len() as u64 / 2).max(1)
        });
        Ok(Cfg {
            function: Hex64(entry),
            blocks: vec![CfgBlock {
                start: Hex64(entry),
                end: Hex64(end),
                instructions: rows.len() as u32,
            }],
            edges: Vec::<CfgEdge>::new(),
        })
    }

    /// The computed jumps of every function, read off the `switch` edges of its CFG: the jump is
    /// the last instruction of the block the edges leave.
    pub fn jump_tables(&self, page: &PageRequest) -> EngineResult<Page<JumpTable>> {
        let names = self.names();
        let mut all = Vec::new();
        for (entry, f) in self.ram_functions() {
            let Some(cfg) = &f.cfg else { continue };
            let rows = self.rows_of(f, &names);
            for b in &cfg.blocks {
                let mut targets: Vec<u64> = cfg
                    .edges
                    .iter()
                    .filter(|e| e.kind == CfgEdgeKind::Switch && e.from == b.start)
                    .map(|e| e.to.0)
                    .collect();
                targets.sort_unstable();
                targets.dedup();
                let jump = rows
                    .iter()
                    .map(|r| r.address.0)
                    .filter(|a| (b.start.0..b.end.0).contains(a))
                    .max();
                if let (false, Some(jump)) = (targets.is_empty(), jump) {
                    all.push(JumpTable {
                        function: Hex64(entry),
                        jump: Hex64(jump),
                        targets: targets.into_iter().map(Hex64).collect(),
                    });
                }
            }
        }
        // Two functions' CFGs can share a block; the contract wants one table per jump.
        all.sort_by_key(|t| (t.jump.0, t.function.0));
        let mut merged: Vec<JumpTable> = Vec::with_capacity(all.len());
        for t in all {
            match merged.last_mut() {
                Some(prev) if prev.jump == t.jump => {
                    prev.targets.extend(t.targets);
                    prev.targets.sort_unstable_by_key(|h| h.0);
                    prev.targets.dedup();
                }
                _ => merged.push(t),
            }
        }
        page_vec(&merged, page)
    }

    // ---- strings and symbols --------------------------------------------------------

    fn all_strings(&self) -> Vec<StringEntry> {
        let mut v = match self.strings {
            Some(s) => s.to_vec(),
            None => self.synth_strings(),
        };
        v.sort_by_key(|s| s.address);
        v
    }

    fn synth_strings(&self) -> Vec<StringEntry> {
        let mut at = self.synth_text_end();
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (_, f) in self.ram_functions() {
            for value in string_literals(&f.decompile.text) {
                if !seen.insert(value.clone()) {
                    continue;
                }
                let length = value.len() as u32 + 1;
                out.push(StringEntry {
                    address: Hex64(at),
                    value,
                    encoding: StringEncoding::Ascii,
                    length,
                });
                at += u64::from(length);
            }
        }
        out
    }

    pub fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
    ) -> EngineResult<Page<StringEntry>> {
        let needle = req
            .filter
            .as_deref()
            .filter(|f| !f.is_empty())
            .map(str::to_lowercase);
        let items: Vec<StringEntry> = self
            .all_strings()
            .into_iter()
            .filter(|s| s.value.chars().count() >= req.min_len as usize)
            .filter(|s| {
                needle
                    .as_ref()
                    .is_none_or(|n| s.value.to_lowercase().contains(n))
            })
            .collect();
        page_vec(&items, page)
    }

    pub fn imports(&self, page: &PageRequest) -> EngineResult<Page<SymbolEntry>> {
        let mut v = match self.imports {
            Some(s) => s.to_vec(),
            None => {
                let mut seen = BTreeSet::new();
                let mut out = Vec::new();
                for (_, f) in self.ram_functions() {
                    for (target, symbol) in call_targets(f) {
                        let known = self
                            .functions
                            .contains_key(&(DEFAULT_SPACE.to_string(), target));
                        if !known && !symbol.is_empty() && seen.insert(target) {
                            out.push(SymbolEntry {
                                name: symbol,
                                address: Some(Hex64(target)),
                                library: None,
                                kind: SymbolKind::Function,
                                mangled: None,
                            });
                        }
                    }
                }
                out
            }
        };
        v.sort_by(|a, b| {
            let key = |s: &SymbolEntry| (s.address.is_none(), s.address, s.name.clone());
            key(a).cmp(&key(b))
        });
        page_vec(&v, page)
    }

    pub fn exports(&self, page: &PageRequest) -> EngineResult<Page<SymbolEntry>> {
        let mut v = match self.exports {
            Some(s) => s.to_vec(),
            None => self
                .ram_functions()
                .next()
                .map(|(off, f)| SymbolEntry {
                    name: f.summary.name.clone(),
                    address: Some(Hex64(off)),
                    library: None,
                    kind: SymbolKind::Function,
                    mangled: None,
                })
                .into_iter()
                .collect(),
        };
        v.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        page_vec(&v, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_unescaped() {
        assert_eq!(
            string_literals(r#"puts("a\tb"); x = "q\"r"; y = ""; z = "open"#),
            vec!["a\tb".to_string(), "q\"r".to_string()]
        );
    }

    #[test]
    fn synthetic_bytes_are_deterministic() {
        assert_eq!(synth_byte(0x401000), synth_byte(0x401000));
        assert_ne!(
            (0..16)
                .map(|k| synth_byte(0x401000 + k))
                .collect::<Vec<_>>(),
            vec![0; 16]
        );
    }
}
