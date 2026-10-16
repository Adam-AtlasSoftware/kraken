// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic layered (Sugiyama-style) layout for control-flow graphs.
//!
//! Pure computation with no UI dependencies, so it can run on a worker thread.
//! Coordinates: `x`/`y` of a [`PlacedNode`] is the top-left corner, y grows downward,
//! layer 0 is at the top. Edge points run from the `from` node to the `to` node.

#![forbid(unsafe_code)]

mod component;

use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    ConditionalTrue,
    ConditionalFalse,
    Back,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeSpec {
    pub id: u64,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeSpec {
    pub from: u64,
    pub to: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Graph {
    pub nodes: Vec<NodeSpec>,
    pub edges: Vec<EdgeSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LayoutOptions {
    /// Vertical gap between consecutive layers.
    pub layer_gap: f32,
    /// Minimum horizontal gap between two nodes in a layer.
    pub node_gap: f32,
    /// Horizontal spacing between parallel edges (and side lanes for back edges).
    pub edge_gap: f32,
    /// Node to place first (top of its component). Defaults to the first source node.
    pub entry: Option<u64>,
    /// Upper bound on crossing-minimisation sweeps per component.
    pub max_crossing_sweeps: usize,
}

impl Default for LayoutOptions {
    fn default() -> Self {
        Self {
            layer_gap: 40.0,
            node_gap: 30.0,
            edge_gap: 12.0,
            entry: None,
            max_crossing_sweeps: 24,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlacedNode {
    pub id: u64,
    pub x: f32,
    pub y: f32,
    pub layer: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoutedEdge {
    pub from: u64,
    pub to: u64,
    pub points: Vec<(f32, f32)>,
    /// `Back` for every edge that was reversed during cycle removal.
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Layout {
    /// Same order as `Graph::nodes`.
    pub nodes: Vec<PlacedNode>,
    /// Same order as `Graph::edges`.
    pub edges: Vec<RoutedEdge>,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("duplicate node id {0}")]
    DuplicateNode(u64),
    #[error("edge references unknown node id {0}")]
    UnknownNode(u64),
    #[error("entry node {0} is not in the graph")]
    UnknownEntry(u64),
    #[error("node {0} has a negative or non-finite size")]
    InvalidSize(u64),
}

pub(crate) struct Spacing {
    pub layer_gap: f64,
    pub node_gap: f64,
    pub edge_gap: f64,
}

pub(crate) struct Ctx<'a> {
    pub w: &'a [f64],
    pub h: &'a [f64],
    pub edges: &'a [(usize, usize)],
    pub reversed: &'a [bool],
    pub entry: Option<usize>,
    pub sp: Spacing,
    pub max_sweeps: usize,
}

fn gap(v: f32) -> f64 {
    if v.is_finite() && v > 0.0 {
        f64::from(v)
    } else {
        0.0
    }
}

/// Computes a layered layout. Identical input always yields identical output.
pub fn layout(graph: &Graph, opts: &LayoutOptions) -> Result<Layout, LayoutError> {
    let n = graph.nodes.len();
    let mut index = BTreeMap::new();
    for (i, nd) in graph.nodes.iter().enumerate() {
        let ok =
            nd.width.is_finite() && nd.height.is_finite() && nd.width >= 0.0 && nd.height >= 0.0;
        if !ok {
            return Err(LayoutError::InvalidSize(nd.id));
        }
        if index.insert(nd.id, i).is_some() {
            return Err(LayoutError::DuplicateNode(nd.id));
        }
    }
    let mut edges = Vec::with_capacity(graph.edges.len());
    for e in &graph.edges {
        let u = *index.get(&e.from).ok_or(LayoutError::UnknownNode(e.from))?;
        let v = *index.get(&e.to).ok_or(LayoutError::UnknownNode(e.to))?;
        edges.push((u, v));
    }
    let entry = match opts.entry {
        Some(id) => Some(*index.get(&id).ok_or(LayoutError::UnknownEntry(id))?),
        None => None,
    };

    let reversed = component::remove_cycles(n, &edges, entry);
    let (groups, comp_edges) = component::components(n, &edges, entry);

    let w: Vec<f64> = graph.nodes.iter().map(|x| f64::from(x.width)).collect();
    let h: Vec<f64> = graph.nodes.iter().map(|x| f64::from(x.height)).collect();
    let ctx = Ctx {
        w: &w,
        h: &h,
        edges: &edges,
        reversed: &reversed,
        entry,
        sp: Spacing {
            layer_gap: gap(opts.layer_gap),
            node_gap: gap(opts.node_gap),
            edge_gap: gap(opts.edge_gap),
        },
        max_sweeps: opts.max_crossing_sweeps,
    };

    let mut loc = vec![usize::MAX; n];
    let mut placed: Vec<Option<PlacedNode>> = vec![None; n];
    let mut routes: Vec<Vec<(f32, f32)>> = vec![Vec::new(); edges.len()];
    let mut cursor = 0.0f64;
    let mut height = 0.0f64;
    for (nodes, cedges) in groups.iter().zip(&comp_edges) {
        let out = component::layout_component(&ctx, nodes, cedges, &mut loc);
        for (g, x, y, layer) in out.nodes {
            placed[g] = Some(PlacedNode {
                id: graph.nodes[g].id,
                x: (x + cursor) as f32,
                y: y as f32,
                layer: layer as u32,
            });
        }
        for (e, pts) in out.routes {
            routes[e] = pts
                .into_iter()
                .map(|(x, y)| ((x + cursor) as f32, y as f32))
                .collect();
        }
        cursor += out.width + ctx.sp.node_gap;
        height = height.max(out.height);
    }
    let width = if groups.is_empty() {
        0.0
    } else {
        cursor - ctx.sp.node_gap
    };

    let nodes = placed.into_iter().flatten().collect();
    let edges_out = graph
        .edges
        .iter()
        .zip(routes)
        .enumerate()
        .map(|(i, (e, points))| RoutedEdge {
            from: e.from,
            to: e.to,
            points,
            kind: if reversed[i] { EdgeKind::Back } else { e.kind },
        })
        .collect();
    Ok(Layout {
        nodes,
        edges: edges_out,
        width: width as f32,
        height: height as f32,
    })
}
