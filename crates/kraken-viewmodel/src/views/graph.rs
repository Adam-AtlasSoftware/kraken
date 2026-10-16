//! The control-flow graph of the current function: `cfg` for the shape, `disassemble` rows for
//! what is inside each block.

use kraken_proto::{CfgBlock, CfgEdge, CfgEdgeKind, TokenKind};
use serde_json::json;

use super::Reveal;
use super::listing::{ListingRowItem, mnemonic_kind, operand_kind};
use super::wire::CfgWire;
use crate::errors::plain_error;
use crate::vm::{ViewModel, hex, parse};

/// Blocks beyond this many are not drawn (the command caps at 4000 too).
pub const MAX_GRAPH_BLOCKS: usize = 4000;

/// Why control moves between two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphEdgeKind {
    /// The next block follows.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Branch taken.
    True,
    /// Branch not taken.
    False,
    /// One case of a computed jump.
    Switch,
}

impl From<CfgEdgeKind> for GraphEdgeKind {
    fn from(k: CfgEdgeKind) -> Self {
        match k {
            CfgEdgeKind::Fallthrough => GraphEdgeKind::Fallthrough,
            CfgEdgeKind::Jump => GraphEdgeKind::Jump,
            CfgEdgeKind::ConditionalTrue => GraphEdgeKind::True,
            CfgEdgeKind::ConditionalFalse => GraphEdgeKind::False,
            CfgEdgeKind::Switch => GraphEdgeKind::Switch,
        }
    }
}

/// A basic block with its instructions as coloured text pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphBlock {
    /// Start address; also the block's id.
    pub id: u64,
    /// First address after the block.
    pub end: u64,
    /// Header text.
    pub title: String,
    /// One entry per instruction; each is a run of `(text, kind)` pieces.
    pub lines: Vec<Vec<(String, TokenKind)>>,
}

/// What the graph widget draws.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphData {
    /// Blocks in address order.
    pub blocks: Vec<GraphBlock>,
    /// Edges between block ids.
    pub edges: Vec<(u64, u64, GraphEdgeKind)>,
    /// Block holding the function's entry.
    pub entry: Option<u64>,
}

/// The graph's state.
#[derive(Debug, Clone, Default)]
pub struct GraphState {
    /// Function the graph belongs to.
    pub function: Option<u64>,
    /// The shape as the command returned it.
    pub shape: Option<(Vec<CfgBlock>, Vec<CfgEdge>)>,
    /// Blocks beyond the cap were left out.
    pub truncated: bool,
    /// The drawable graph, once the shape and every listing row are in.
    pub data: Option<GraphData>,
    /// Changes whenever `data` does; use as a render cache key.
    pub revision: u64,
    /// The `cfg` request is in flight.
    pub loading: bool,
    /// Reload when next drawn.
    pub stale: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// Selected block id.
    pub selected: Option<u64>,
    pub(crate) entry: Option<u64>,
    pub(crate) req: u64,
    pub(crate) shape_rev: u64,
    pub(crate) built: Option<(u64, u64)>,
}

impl GraphState {
    /// Id of the block whose range holds `addr`.
    pub fn block_containing(&self, addr: u64) -> Option<u64> {
        let (blocks, _) = self.shape.as_ref()?;
        blocks
            .iter()
            .find(|b| (b.start.0..b.end.0).contains(&addr))
            .map(|b| b.start.0)
    }
}

/// Builds the drawable graph from the shape and the listing rows.
pub fn build_graph(
    entry_fn: u64,
    blocks: &[CfgBlock],
    edges: &[CfgEdge],
    rows: &[ListingRowItem],
) -> GraphData {
    let mut out = Vec::with_capacity(blocks.len().min(MAX_GRAPH_BLOCKS));
    for b in blocks.iter().take(MAX_GRAPH_BLOCKS) {
        let (start, end) = (b.start.0, b.end.0);
        let first = rows.partition_point(|r| r.address < start);
        let inside = rows[first..].iter().take_while(|r| r.address < end);
        let mut title = format!("{start:#x}");
        let mut lines = Vec::new();
        for (k, r) in inside.enumerate() {
            if k == 0
                && let Some(l) = r.labels.first()
            {
                title = format!("{l}  {start:#x}");
            }
            let mut line = vec![
                (format!("{:x}  ", r.address), TokenKind::Comment),
                (format!("{:<6} ", r.mnemonic), mnemonic_kind(r.flow)),
            ];
            line.extend(
                r.operands
                    .iter()
                    .map(|o| (o.text.clone(), operand_kind(o.kind))),
            );
            lines.push(line);
        }
        out.push(GraphBlock {
            id: start,
            end,
            title,
            lines,
        });
    }
    let ids: std::collections::BTreeSet<u64> = out.iter().map(|b| b.id).collect();
    let edges = edges
        .iter()
        .filter(|e| ids.contains(&e.from.0) && ids.contains(&e.to.0))
        .map(|e| (e.from.0, e.to.0, GraphEdgeKind::from(e.kind)))
        .collect();
    let entry = out
        .iter()
        .find(|b| (b.id..b.end).contains(&entry_fn))
        .or(out.first())
        .map(|b| b.id);
    GraphData {
        blocks: out,
        edges,
        entry,
    }
}

impl ViewModel {
    /// Loads the graph of the current function (its blocks and every listing row) when missing
    /// or out of date.
    pub fn ensure_graph(&mut self) {
        let Some(addr) = self.current.as_ref().map(|c| c.address) else {
            return;
        };
        self.views.listing.want_all = true;
        self.ensure_listing();
        let g = &self.views.graph;
        if g.function == Some(addr)
            && !g.stale
            && (g.shape.is_some() || g.loading || g.error.is_some())
        {
            return;
        }
        self.fetch_cfg(addr);
    }

    /// Retries after a failed load.
    pub fn retry_graph(&mut self) {
        self.views.graph.error = None;
        if let Some(addr) = self.current.as_ref().map(|c| c.address) {
            self.fetch_cfg(addr);
        }
    }

    fn fetch_cfg(&mut self, addr: u64) {
        let req = self.views.next_seq();
        let g = &mut self.views.graph;
        g.function = Some(addr);
        g.req = req;
        g.loading = true;
        g.stale = false;
        g.error = None;
        self.call("cfg", json!({ "function": hex(addr) }), move |vm, res| {
            if vm.views.graph.req != req {
                return;
            }
            vm.views.graph.loading = false;
            match res.and_then(parse::<CfgWire>) {
                Ok(w) => {
                    let g = &mut vm.views.graph;
                    g.entry = Some(w.function.0);
                    g.truncated = w.truncated;
                    g.shape = Some((w.blocks, w.edges));
                    g.shape_rev += 1;
                    vm.rebuild_graph();
                }
                Err(e) => vm.views.graph.error = Some(plain_error(&e)),
            }
        });
    }

    /// Builds the drawable graph once the shape and all rows are loaded.
    pub(crate) fn rebuild_graph(&mut self) {
        let v = &mut self.views;
        let ready = v.listing.loaded
            && !v.listing.has_more()
            && !v.listing.loading
            && v.listing.function == v.graph.function;
        let stamp = (v.listing.revision, v.graph.shape_rev);
        if v.graph.built == Some(stamp) {
            return;
        }
        let Some((blocks, edges)) = v.graph.shape.as_ref().filter(|_| ready) else {
            return;
        };
        let entry = v.graph.entry.or(v.graph.function).unwrap_or(0);
        let data = build_graph(entry, blocks, edges, &v.listing.rows);
        v.graph.built = Some(stamp);
        if v.graph.data.as_ref() == Some(&data) {
            return;
        }
        let revision = v.next_seq();
        v.graph.data = Some(data);
        v.graph.revision = revision;
        if v.graph.selected.is_none() {
            v.graph.selected = v.cursor.and_then(|a| v.graph.block_containing(a));
        }
    }

    /// Selects a block and moves the listing selection to its first instruction.
    pub fn graph_select(&mut self, block: u64) {
        self.views.graph.selected = Some(block);
        self.views.cursor = Some(block);
        self.listing_focus(block);
    }

    /// Opens a block in the listing (a double-click in the graph) and records the jump in the
    /// back/forward history.
    pub fn graph_open(&mut self, block: u64) {
        self.goto_revealing(block, Reveal::Listing);
        self.views.graph.selected = Some(block);
    }
}
