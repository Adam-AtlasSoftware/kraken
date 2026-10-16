// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-component pipeline: layering, dummy nodes, crossing minimisation, x placement, routing.

use std::collections::VecDeque;

use crate::Ctx;

pub(crate) struct CompOut {
    /// (global node index, left x, top y, layer)
    pub nodes: Vec<(usize, f64, f64, usize)>,
    /// (edge index, polyline)
    pub routes: Vec<(usize, Vec<(f64, f64)>)>,
    pub width: f64,
    pub height: f64,
}

/// DFS from the entry (then other sources, then anything left); edges closing a cycle are marked.
pub(crate) fn remove_cycles(n: usize, edges: &[(usize, usize)], entry: Option<usize>) -> Vec<bool> {
    let mut out = vec![Vec::new(); n];
    let mut indeg = vec![0usize; n];
    for (e, &(u, v)) in edges.iter().enumerate() {
        out[u].push(e);
        if u != v {
            indeg[v] += 1;
        }
    }
    let roots: Vec<usize> = entry
        .into_iter()
        .chain((0..n).filter(|&i| indeg[i] == 0))
        .chain(0..n)
        .collect();
    let mut reversed = vec![false; edges.len()];
    let mut state = vec![0u8; n];
    let mut ptr = vec![0usize; n];
    let mut stack = Vec::new();
    for r in roots {
        if state[r] != 0 {
            continue;
        }
        state[r] = 1;
        stack.push(r);
        while let Some(&u) = stack.last() {
            if ptr[u] < out[u].len() {
                let e = out[u][ptr[u]];
                ptr[u] += 1;
                let v = edges[e].1;
                if v == u {
                    continue;
                }
                match state[v] {
                    1 => reversed[e] = true,
                    0 => {
                        state[v] = 1;
                        stack.push(v);
                    }
                    _ => {}
                }
            } else {
                state[u] = 2;
                stack.pop();
            }
        }
    }
    reversed
}

fn find(p: &mut [usize], mut x: usize) -> usize {
    while p[x] != x {
        p[x] = p[p[x]];
        x = p[x];
    }
    x
}

/// Connected components (entry's first, then by lowest node index) with their edge indices.
pub(crate) fn components(
    n: usize,
    edges: &[(usize, usize)],
    entry: Option<usize>,
) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let mut p: Vec<usize> = (0..n).collect();
    for &(u, v) in edges {
        let (a, b) = (find(&mut p, u), find(&mut p, v));
        if a != b {
            p[a.max(b)] = a.min(b);
        }
    }
    let mut cid = vec![usize::MAX; n];
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in 0..n {
        let r = find(&mut p, i);
        if cid[r] == usize::MAX {
            cid[r] = groups.len();
            groups.push(Vec::new());
        }
        cid[i] = cid[r];
        groups[cid[i]].push(i);
    }
    let mut cedges = vec![Vec::new(); groups.len()];
    for (e, &(u, _)) in edges.iter().enumerate() {
        cedges[cid[u]].push(e);
    }
    if let Some(en) = entry {
        let c = cid[en];
        groups[..=c].rotate_right(1);
        cedges[..=c].rotate_right(1);
    }
    (groups, cedges)
}

fn count_crossings(layers: &[Vec<usize>], pos: &[usize], succ: &[Vec<usize>]) -> u64 {
    let mut total = 0u64;
    let mut ts = Vec::new();
    for l in 0..layers.len().saturating_sub(1) {
        let mut bit = vec![0u32; layers[l + 1].len() + 1];
        let mut seen = 0u64;
        for &u in &layers[l] {
            ts.clear();
            ts.extend(succ[u].iter().map(|&v| pos[v] + 1));
            ts.sort_unstable();
            for &t in &ts {
                let mut i = t;
                let mut le = 0u64;
                while i > 0 {
                    le += u64::from(bit[i]);
                    i &= i - 1;
                }
                total += seen - le;
            }
            for &t in &ts {
                let mut i = t;
                while i < bit.len() {
                    bit[i] += 1;
                    i += i.isolate_lowest_one();
                }
                seen += 1;
            }
        }
    }
    total
}

fn reorder(layer: &mut [usize], refs: &[Vec<usize>], pos: &mut [usize], median: bool) {
    let keys: Vec<Option<f64>> = layer
        .iter()
        .map(|&v| {
            let r = &refs[v];
            if r.is_empty() {
                None
            } else if median {
                let mut p: Vec<usize> = r.iter().map(|&x| pos[x]).collect();
                p.sort_unstable();
                let n = p.len();
                Some(if n % 2 == 1 {
                    p[n / 2] as f64
                } else {
                    (p[n / 2 - 1] + p[n / 2]) as f64 / 2.0
                })
            } else {
                Some(r.iter().map(|&x| pos[x]).sum::<usize>() as f64 / r.len() as f64)
            }
        })
        .collect();
    let mut movable: Vec<(f64, usize, usize)> = layer
        .iter()
        .enumerate()
        .filter_map(|(i, &v)| keys[i].map(|k| (k, i, v)))
        .collect();
    movable.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut it = movable.into_iter();
    for i in 0..layer.len() {
        if keys[i].is_some()
            && let Some((_, _, v)) = it.next()
        {
            layer[i] = v;
        }
    }
    for (i, &v) in layer.iter().enumerate() {
        pos[v] = i;
    }
}

fn minimise_crossings(
    layers: &mut Vec<Vec<usize>>,
    succ: &[Vec<usize>],
    pred: &[Vec<usize>],
    max_sweeps: usize,
) {
    let nl = layers.len();
    let m = succ.len();
    let mut pos = vec![0usize; m];
    for layer in layers.iter() {
        for (i, &v) in layer.iter().enumerate() {
            pos[v] = i;
        }
    }
    let mut best_c = count_crossings(layers, &pos, succ);
    if best_c == 0 || nl < 2 {
        return;
    }
    let mut best = layers.clone();
    let mut stall = 0;
    for s in 0..max_sweeps {
        let median = (s / 2) % 2 == 1;
        if s % 2 == 0 {
            for layer in layers.iter_mut().skip(1) {
                reorder(layer, pred, &mut pos, median);
            }
        } else {
            for l in (0..nl - 1).rev() {
                reorder(&mut layers[l], succ, &mut pos, median);
            }
        }
        let c = count_crossings(layers, &pos, succ);
        if c < best_c {
            best_c = c;
            best.clone_from(layers);
            stall = 0;
            if c == 0 {
                break;
            }
        } else {
            stall += 1;
            if stall >= 4 {
                break;
            }
        }
    }
    *layers = best;
}

/// Places `layer` as close as possible to the desired positions while keeping the minimum
/// separations (weighted isotonic regression via pool-adjacent-violators).
fn place_layer(layer: &[usize], desired: &[(f64, f64)], seps: &[f64], x: &mut [f64]) {
    let n = layer.len();
    let mut off = Vec::with_capacity(n);
    let mut o = 0.0;
    for i in 0..n {
        if i > 0 {
            o += seps[i - 1];
        }
        off.push(o);
    }
    let mut blocks: Vec<(f64, f64, usize)> = Vec::with_capacity(n);
    for i in 0..n {
        let (d, w) = desired[i];
        blocks.push((w * (d - off[i]), w, 1));
        while blocks.len() >= 2 {
            let b = blocks[blocks.len() - 1];
            let a = blocks[blocks.len() - 2];
            if a.0 / a.1 > b.0 / b.1 {
                blocks.truncate(blocks.len() - 2);
                blocks.push((a.0 + b.0, a.1 + b.1, a.2 + b.2));
            } else {
                break;
            }
        }
    }
    let mut idx = 0;
    for b in blocks {
        let z = b.0 / b.1;
        for _ in 0..b.2 {
            x[layer[idx]] = z + off[idx];
            idx += 1;
        }
    }
}

fn collapse(points: Vec<(f64, f64)>) -> Vec<(f64, f64)> {
    let mut out: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for p in points {
        if out.last() == Some(&p) {
            continue;
        }
        while out.len() >= 2 {
            let (a, b) = (out[out.len() - 2], out[out.len() - 1]);
            if (a.0 == b.0 && b.0 == p.0) || (a.1 == b.1 && b.1 == p.1) {
                out.pop();
            } else {
                break;
            }
        }
        out.push(p);
    }
    out
}

pub(crate) fn layout_component(
    cx: &Ctx<'_>,
    nodes: &[usize],
    cedges: &[usize],
    loc: &mut [usize],
) -> CompOut {
    let k = nodes.len();
    for (i, &g) in nodes.iter().enumerate() {
        loc[g] = i;
    }
    let entry_loc = cx.entry.and_then(|g| nodes.binary_search(&g).ok());

    // Layering: longest path, then promotion.
    let mut outs = vec![Vec::new(); k];
    let mut ins = vec![Vec::new(); k];
    for &e in cedges {
        let (u, v) = cx.edges[e];
        if u == v {
            continue;
        }
        let (a, b) = if cx.reversed[e] {
            (loc[v], loc[u])
        } else {
            (loc[u], loc[v])
        };
        outs[a].push(b);
        ins[b].push(a);
    }
    let mut layer = vec![0usize; k];
    let mut indeg: Vec<usize> = ins.iter().map(Vec::len).collect();
    let mut q: VecDeque<usize> = (0..k).filter(|&i| indeg[i] == 0).collect();
    while let Some(u) = q.pop_front() {
        for &v in &outs[u] {
            layer[v] = layer[v].max(layer[u] + 1);
            indeg[v] -= 1;
            if indeg[v] == 0 {
                q.push_back(v);
            }
        }
    }
    for _ in 0..10 {
        let mut changed = false;
        for v in 0..k {
            if Some(v) == entry_loc {
                continue;
            }
            if outs[v].len() > ins[v].len() {
                if let Some(ms) = outs[v].iter().map(|&s| layer[s]).min() {
                    while layer[v] + 1 < ms {
                        layer[v] += 1;
                        changed = true;
                    }
                }
            } else if ins[v].len() > outs[v].len()
                && let Some(mp) = ins[v].iter().map(|&p| layer[p]).max()
            {
                while layer[v] > mp + 1 {
                    layer[v] -= 1;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let minl = layer.iter().copied().min().unwrap_or(0);
    for l in &mut layer {
        *l -= minl;
    }
    let nl = layer.iter().copied().max().map_or(0, |m| m + 1);

    // Dummy nodes for edges spanning more than one layer (reversed edges are routed on the side).
    let mut elayer = layer.clone();
    let mut succ = vec![Vec::new(); k];
    let mut pred = vec![Vec::new(); k];
    let mut chains: Vec<(usize, Vec<usize>)> = Vec::new();
    for &e in cedges {
        let (u, v) = cx.edges[e];
        if u == v || cx.reversed[e] {
            continue;
        }
        let (a, b) = (loc[u], loc[v]);
        let mut prev = a;
        let mut chain = Vec::new();
        for l in layer[a] + 1..layer[b] {
            let d = elayer.len();
            elayer.push(l);
            succ.push(Vec::new());
            pred.push(Vec::new());
            succ[prev].push(d);
            pred[d].push(prev);
            chain.push(d);
            prev = d;
        }
        succ[prev].push(b);
        pred[b].push(prev);
        chains.push((e, chain));
    }
    let m = elayer.len();
    let width_of = |i: usize| if i < k { cx.w[nodes[i]] } else { 0.0 };

    // Initial order: DFS preorder.
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); nl];
    let mut seen = vec![false; m];
    let mut stack = Vec::new();
    let roots: Vec<usize> = entry_loc
        .into_iter()
        .chain((0..m).filter(|&i| pred[i].is_empty()))
        .chain(0..m)
        .collect();
    for r in roots {
        stack.push(r);
        while let Some(u) = stack.pop() {
            if seen[u] {
                continue;
            }
            seen[u] = true;
            layers[elayer[u]].push(u);
            for &s in succ[u].iter().rev() {
                if !seen[s] {
                    stack.push(s);
                }
            }
        }
    }

    minimise_crossings(&mut layers, &succ, &pred, cx.max_sweeps);

    // X assignment.
    let sp = &cx.sp;
    let sep = |a: usize, b: usize| {
        let g = match (a >= k, b >= k) {
            (false, false) => sp.node_gap,
            (true, true) => sp.edge_gap,
            _ => sp.edge_gap.max(sp.node_gap / 2.0),
        };
        (width_of(a) + width_of(b)) / 2.0 + g
    };
    let ew = |a: usize, b: usize| match (a >= k, b >= k) {
        (true, true) => 8.0,
        (false, false) => 1.0,
        _ => 2.0,
    };
    let seps: Vec<Vec<f64>> = layers
        .iter()
        .map(|l| l.windows(2).map(|p| sep(p[0], p[1])).collect())
        .collect();
    let mut x = vec![0.0f64; m];
    for layer in &layers {
        let mut c = 0.0;
        for (i, &v) in layer.iter().enumerate() {
            c = if i == 0 {
                width_of(v) / 2.0
            } else {
                c + sep(layer[i - 1], v)
            };
            x[v] = c;
        }
    }
    const PASSES: usize = 12;
    let mut desired = Vec::new();
    for p in 0..PASSES {
        let (use_pred, use_succ) = if p < 8 {
            (p % 2 == 0, p % 2 == 1)
        } else {
            (true, true)
        };
        let order: Vec<usize> = if p < 8 {
            if use_pred {
                (1..nl).collect()
            } else {
                (0..nl.saturating_sub(1)).rev().collect()
            }
        } else if p % 2 == 0 {
            (0..nl).collect()
        } else {
            (0..nl).rev().collect()
        };
        for l in order {
            desired.clear();
            for &v in &layers[l] {
                let (mut sx, mut sw) = (0.0, 0.0);
                if use_pred {
                    for &u in &pred[v] {
                        let w = ew(u, v);
                        sx += w * x[u];
                        sw += w;
                    }
                }
                if use_succ {
                    for &u in &succ[v] {
                        let w = ew(u, v);
                        sx += w * x[u];
                        sw += w;
                    }
                }
                desired.push(if sw > 0.0 {
                    (sx / sw, sw)
                } else {
                    (x[v], 0.05)
                });
            }
            place_layer(&layers[l], &desired, &seps[l], &mut x);
        }
    }

    // Y assignment.
    let mut row_top = vec![0.0f64; nl];
    let mut row_bot = vec![0.0f64; nl];
    let mut y = 0.0;
    for l in 0..nl {
        let rh = layers[l]
            .iter()
            .filter(|&&v| v < k)
            .map(|&v| cx.h[nodes[v]])
            .fold(0.0, f64::max);
        row_top[l] = y;
        row_bot[l] = y + rh;
        y += rh + sp.layer_gap;
    }
    let height = row_bot.last().copied().unwrap_or(0.0);
    let ny = |v: usize| {
        row_top[layer[v]] + (row_bot[layer[v]] - row_top[layer[v]] - cx.h[nodes[v]]) / 2.0
    };

    let minx = (0..m)
        .map(|v| x[v] - width_of(v) / 2.0)
        .fold(f64::INFINITY, f64::min);
    let shift = if minx.is_finite() { -minx } else { 0.0 };
    for v in &mut x {
        *v += shift;
    }
    let mut right = (0..m).map(|v| x[v] + width_of(v) / 2.0).fold(0.0, f64::max);

    let mut routes: Vec<(usize, Vec<(f64, f64)>)> = Vec::with_capacity(cedges.len());
    let mut chain_it = chains.into_iter();
    let mut lanes = 0usize;
    let loop_ext = sp.edge_gap.min(sp.node_gap / 2.0).max(1.0);
    let base_right = right;
    for &e in cedges {
        let (u, v) = cx.edges[e];
        let (a, b) = (loc[u], loc[v]);
        let pts = if u == v {
            let (r, cy, h) = (x[a] + cx.w[u] / 2.0, ny(a) + cx.h[u] / 2.0, cx.h[u]);
            right = right.max(r + loop_ext);
            vec![
                (r, cy - h / 4.0),
                (r + loop_ext, cy - h / 4.0),
                (r + loop_ext, cy + h / 4.0),
                (r, cy + h / 4.0),
            ]
        } else if cx.reversed[e] {
            lanes += 1;
            let lane = base_right + sp.edge_gap * lanes as f64;
            right = right.max(lane);
            let (ra, rb) = (x[a] + cx.w[u] / 2.0, x[b] + cx.w[v] / 2.0);
            let (ca, cb) = (ny(a) + cx.h[u] / 2.0, ny(b) + cx.h[v] / 2.0);
            vec![(ra, ca), (lane, ca), (lane, cb), (rb, cb)]
        } else if let Some((ce, chain)) = chain_it.next() {
            debug_assert_eq!(ce, e);
            let mut xs = vec![x[a]];
            xs.extend(chain.iter().map(|&d| x[d]));
            xs.push(x[b]);
            let mut pts = vec![(xs[0], ny(a) + cx.h[u])];
            for i in 0..xs.len() - 1 {
                let l = layer[a] + i;
                let mid = (row_bot[l] + row_top[l + 1]) / 2.0;
                pts.push((xs[i], mid));
                pts.push((xs[i + 1], mid));
            }
            pts.push((xs[xs.len() - 1], ny(b)));
            collapse(pts)
        } else {
            Vec::new()
        };
        routes.push((e, pts));
    }

    let out_nodes = (0..k)
        .map(|v| (nodes[v], x[v] - cx.w[nodes[v]] / 2.0, ny(v), layer[v]))
        .collect();
    CompOut {
        nodes: out_nodes,
        routes,
        width: right,
        height,
    }
}
