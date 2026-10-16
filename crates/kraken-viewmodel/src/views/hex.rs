//! The memory map and the hex view's position.

use std::ops::Range;

use kraken_proto::{ErrorCode, MemoryKind};
use serde_json::json;

use super::wire::MemoryMapWire;
use crate::errors::plain_error;
use crate::vm::{ViewModel, hex, parse};

use super::bytes::{MAX_RUN_PAGES, PAGE_SIZE};

/// One block (segment or section) of memory shown in the hex view's block list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlockItem {
    /// Name such as `.text`.
    pub name: String,
    /// First address.
    pub start: u64,
    /// First address after the block.
    pub end: u64,
    /// `rwx` flags with `-` for missing ones.
    pub perms: String,
    /// False for blocks without contents, such as `.bss`.
    pub initialized: bool,
}

impl MemoryBlockItem {
    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True when the block has no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when `addr` lies in the block.
    pub fn contains(&self, addr: u64) -> bool {
        (self.start..self.end).contains(&addr)
    }

    /// One line for a drop-down: name, range and permissions.
    pub fn label(&self) -> String {
        let note = if self.initialized {
            ""
        } else {
            "  (no contents)"
        };
        format!(
            "{}   {:#x} - {:#x}   {}{note}",
            self.name, self.start, self.end, self.perms
        )
    }
}

/// The program's memory blocks in the default address space.
#[derive(Debug, Clone, Default)]
pub struct MemoryMap {
    /// Blocks ordered by start address; blocks in other spaces and synthetic external blocks are
    /// left out.
    pub blocks: Vec<MemoryBlockItem>,
    /// The map arrived.
    pub loaded: bool,
    /// A request is in flight.
    pub loading: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    pub(crate) req: u64,
}

impl MemoryMap {
    /// Index of the block holding `addr`.
    pub fn block_index_of(&self, addr: u64) -> Option<usize> {
        self.blocks.iter().position(|b| b.contains(addr))
    }
}

/// Where the hex view is looking.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HexState {
    /// The memory block shown; `None` shows just the current function's bytes.
    pub block: Option<usize>,
    /// Address to scroll to next frame; take it with [`HexState::take_scroll`].
    pub scroll_to: Option<u64>,
    /// The current function's range, drawn highlighted.
    pub highlight: Option<Range<u64>>,
    /// Bytes selected in the view (absolute addresses).
    pub selection: Option<Range<u64>>,
}

impl HexState {
    /// Takes the pending scroll target.
    pub fn take_scroll(&mut self) -> Option<u64> {
        self.scroll_to.take()
    }
}

impl ViewModel {
    /// Loads the memory map (once per project; call [`refresh_memory_map`](Self::refresh_memory_map)
    /// to force it).
    pub fn ensure_memory_map(&mut self) {
        let m = &self.views.memory;
        if !m.loaded && !m.loading && m.error.is_none() {
            self.refresh_memory_map();
        }
    }

    /// Reloads the memory map.
    pub fn refresh_memory_map(&mut self) {
        let req = self.views.next_seq();
        let m = &mut self.views.memory;
        m.req = req;
        m.loading = true;
        m.error = None;
        self.call("memory_map", json!({}), move |vm, res| {
            if vm.views.memory.req != req {
                return;
            }
            vm.views.memory.loading = false;
            match res.and_then(parse::<MemoryMapWire>) {
                Ok(w) => {
                    let mut blocks: Vec<MemoryBlockItem> = w
                        .blocks
                        .into_iter()
                        .filter(|b| {
                            b.space
                                .as_deref()
                                .is_none_or(|s| s == kraken_proto::DEFAULT_SPACE)
                                && b.kind != MemoryKind::External
                                && b.end.0 > b.start.0
                        })
                        .map(|b| MemoryBlockItem {
                            name: b.name.0,
                            start: b.start.0,
                            end: b.end.0,
                            perms: b.perms,
                            initialized: b.initialized,
                        })
                        .collect();
                    blocks.sort_by_key(|b| b.start);
                    vm.views
                        .bytes
                        .set_blocks(blocks.iter().map(|b| b.start..b.end).collect());
                    vm.views.memory.blocks = blocks;
                    vm.views.memory.loaded = true;
                    if let Some(h) = vm.views.hex.highlight.clone() {
                        vm.views.hex.block = vm.views.memory.block_index_of(h.start);
                        vm.views.hex.scroll_to = Some(h.start);
                        vm.views.bytes.want_range(h.start, h.end - h.start);
                    }
                    vm.service_bytes();
                }
                Err(e) => {
                    // An engine without the memory capability still gets a function-sized dump.
                    vm.views.memory.error = Some(if e.code == ErrorCode::Unsupported {
                        "this engine cannot list memory".into()
                    } else {
                        plain_error(&e)
                    });
                    if let Some(h) = vm.views.hex.highlight.clone() {
                        vm.views.bytes.want_range(h.start, h.end - h.start);
                    }
                    vm.service_bytes();
                }
            }
        });
    }

    /// The addresses the hex view covers: the chosen block, else the current function.
    pub fn hex_window(&self) -> Option<Range<u64>> {
        let v = &self.views;
        if let Some(b) = v.hex.block.and_then(|i| v.memory.blocks.get(i)) {
            return Some(b.start..b.end);
        }
        let cur = self.current.as_ref()?;
        let size = cur
            .detail
            .as_ref()
            .and_then(|d| d.size)
            .or_else(|| self.functions.find(cur.address).and_then(|f| f.size))
            .unwrap_or(64)
            .max(16);
        Some(cur.address..cur.address.saturating_add(size))
    }

    /// Shows memory block `index` from its first byte.
    pub fn hex_select_block(&mut self, index: usize) {
        let Some(b) = self.views.memory.blocks.get(index) else {
            return;
        };
        let start = b.start;
        self.views.hex.block = Some(index);
        self.views.hex.scroll_to = Some(start);
        self.views.bytes.want_range(start, PAGE_SIZE);
        self.service_bytes();
    }

    /// Scrolls the hex view to `addr`, switching to the block that holds it. False when nothing is
    /// mapped there.
    pub fn hex_goto(&mut self, addr: u64) -> bool {
        let v = &mut self.views;
        match v.memory.block_index_of(addr) {
            Some(i) => v.hex.block = Some(i),
            None if v.memory.loaded => return false,
            None => {}
        }
        v.hex.scroll_to = Some(addr);
        v.bytes.want_range(addr, 256);
        self.service_bytes();
        true
    }

    /// Points the hex view at a function: its block, its range highlighted, its bytes fetched.
    pub(crate) fn hex_follow(&mut self, addr: u64, size: u64) {
        let size = size.max(1);
        let v = &mut self.views;
        v.hex.highlight = Some(addr..addr.saturating_add(size));
        v.hex.block = v.memory.block_index_of(addr);
        v.hex.scroll_to = Some(addr);
        v.hex.selection = None;
        // Before the memory map is known a read could stop at a gap, so wait for it.
        if v.memory.loaded || v.memory.error.is_some() {
            v.bytes
                .want_range(addr, size.min(MAX_RUN_PAGES * PAGE_SIZE));
            self.service_bytes();
        }
    }

    /// Remembers the bytes selected in the hex view.
    pub fn set_hex_selection(&mut self, selection: Option<Range<u64>>) {
        self.views.hex.selection = selection;
    }

    /// Fetches the pages the hex view asked for. Cheap when nothing is missing; the GUI calls it
    /// once per frame after drawing.
    pub fn service_bytes(&mut self) {
        let runs = self.views.bytes.take_runs();
        let generation = self.views.bytes_gen;
        for (run, segments) in runs {
            for seg in segments {
                self.call(
                    "read_bytes",
                    json!({ "address": hex(seg.start), "length": seg.end - seg.start }),
                    move |vm, res| {
                        if vm.views.bytes_gen != generation {
                            return;
                        }
                        let read = res
                            .and_then(parse::<kraken_proto::BytesRead>)
                            .map_err(|_| ());
                        vm.views.bytes.finish_segment(run, seg.start, read);
                        // More pages may have been asked for while this call ran.
                        vm.service_bytes();
                    },
                );
            }
        }
    }
}
