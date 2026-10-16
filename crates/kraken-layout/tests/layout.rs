// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used)]

use kraken_layout::{
    EdgeKind, EdgeSpec, Graph, Layout, LayoutError, LayoutOptions, NodeSpec, layout,
};
use proptest::prelude::*;

const EPS: f32 = 1e-3;

fn graph(sizes: &[(f32, f32)], edges: &[(u64, u64)]) -> Graph {
    Graph {
        nodes: sizes
            .iter()
            .enumerate()
            .map(|(i, &(width, height))| NodeSpec {
                id: i as u64,
                width,
                height,
            })
            .collect(),
        edges: edges
            .iter()
            .map(|&(from, to)| EdgeSpec {
                from,
                to,
                kind: EdgeKind::Jump,
            })
            .collect(),
    }
}

fn uniform(n: usize, edges: &[(u64, u64)]) -> Graph {
    graph(&vec![(60.0, 30.0); n], edges)
}

fn check(g: &Graph, l: &Layout) {
    assert_eq!(l.nodes.len(), g.nodes.len());
    assert_eq!(l.edges.len(), g.edges.len());
    for (a, na) in l.nodes.iter().enumerate() {
        let sa = &g.nodes[a];
        assert_eq!(na.id, sa.id);
        assert!(na.x >= -EPS && na.x + sa.width <= l.width + EPS);
        assert!(na.y >= -EPS && na.y + sa.height <= l.height + EPS);
        for (b, nb) in l.nodes.iter().enumerate().skip(a + 1) {
            let sb = &g.nodes[b];
            let ox = na.x < nb.x + sb.width - EPS && nb.x < na.x + sa.width - EPS;
            let oy = na.y < nb.y + sb.height - EPS && nb.y < na.y + sa.height - EPS;
            assert!(!(ox && oy), "nodes {} and {} overlap", na.id, nb.id);
        }
    }
    let find = |id: u64| {
        let i = g.nodes.iter().position(|n| n.id == id).unwrap();
        (&l.nodes[i], &g.nodes[i])
    };
    for e in &l.edges {
        assert!(e.points.len() >= 2);
        let on = |p: (f32, f32), id: u64| {
            let (n, s) = find(id);
            p.0 >= n.x - EPS
                && p.0 <= n.x + s.width + EPS
                && p.1 >= n.y - EPS
                && p.1 <= n.y + s.height + EPS
        };
        assert!(on(e.points[0], e.from), "edge start off node {}", e.from);
        assert!(
            on(*e.points.last().unwrap(), e.to),
            "edge end off node {}",
            e.to
        );
        if e.from != e.to && e.kind != EdgeKind::Back {
            assert!(find(e.from).0.layer < find(e.to).0.layer);
        }
    }
}

fn run(g: &Graph) -> Layout {
    let l = layout(g, &LayoutOptions::default()).unwrap();
    check(g, &l);
    assert_eq!(l, layout(g, &LayoutOptions::default()).unwrap());
    l
}

#[test]
fn empty_graph() {
    let l = run(&Graph::default());
    assert!(l.nodes.is_empty());
}

#[test]
fn diamond() {
    let g = uniform(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let l = run(&g);
    let layers: Vec<u32> = l.nodes.iter().map(|n| n.layer).collect();
    assert_eq!(layers, [0, 1, 1, 2]);
    // Entry and exit are centred over the two arms.
    let cx = |i: usize| l.nodes[i].x + 30.0;
    assert!((cx(0) - (cx(1) + cx(2)) / 2.0).abs() < 1.0);
    assert!((cx(3) - (cx(1) + cx(2)) / 2.0).abs() < 1.0);
}

#[test]
fn loop_with_back_edge() {
    let g = uniform(4, &[(0, 1), (1, 2), (2, 1), (2, 3)]);
    let l = run(&g);
    assert_eq!(l.edges[2].kind, EdgeKind::Back);
    assert_eq!(l.edges[1].kind, EdgeKind::Jump);
    let layers: Vec<u32> = l.nodes.iter().map(|n| n.layer).collect();
    assert_eq!(layers, [0, 1, 2, 3]);
    // Back edge runs along the right side of everything.
    let right = l.nodes.iter().map(|n| n.x + 60.0).fold(0.0, f32::max);
    assert!(l.edges[2].points.iter().any(|p| p.0 > right));
}

#[test]
fn switch_fan_out() {
    let mut edges = vec![];
    for c in 1..=6 {
        edges.push((0, c));
        edges.push((c, 7));
    }
    let g = uniform(8, &edges);
    let l = run(&g);
    assert!((1..=6).all(|i| l.nodes[i].layer == 1));
    let xs: Vec<f32> = (1..=6).map(|i| l.nodes[i].x).collect();
    assert!(xs.windows(2).all(|w| w[0] < w[1]), "cases keep edge order");
}

#[test]
fn long_edge_uses_dummies() {
    let g = uniform(4, &[(0, 1), (1, 2), (2, 3), (0, 3)]);
    let l = run(&g);
    assert_eq!(l.nodes[3].layer, 3);
    let long = &l.edges[3];
    assert!(long.points.len() >= 4);
    for p in &long.points {
        for n in &l.nodes[1..3] {
            let inside = p.0 > n.x + EPS
                && p.0 < n.x + 60.0 - EPS
                && p.1 > n.y + EPS
                && p.1 < n.y + 30.0 - EPS;
            assert!(!inside, "long edge passes through node {}", n.id);
        }
    }
}

#[test]
fn self_loop() {
    let g = uniform(2, &[(0, 0), (0, 1)]);
    let l = run(&g);
    assert_eq!(l.edges[0].kind, EdgeKind::Jump);
    assert!(l.edges[0].points.len() >= 3);
}

#[test]
fn disconnected_components_side_by_side() {
    let g = uniform(5, &[(0, 1), (2, 3)]);
    let l = run(&g);
    let span = |ids: &[usize]| {
        (
            ids.iter().map(|&i| l.nodes[i].x).fold(f32::MAX, f32::min),
            ids.iter().map(|&i| l.nodes[i].x + 60.0).fold(0.0, f32::max),
        )
    };
    let (a, b, c) = (span(&[0, 1]), span(&[2, 3]), span(&[4]));
    assert!(a.1 < b.0 && b.1 < c.0);
}

#[test]
fn entry_component_first() {
    let g = uniform(4, &[(0, 1), (2, 3)]);
    let opts = LayoutOptions {
        entry: Some(2),
        ..LayoutOptions::default()
    };
    let l = layout(&g, &opts).unwrap();
    check(&g, &l);
    assert!(l.nodes[2].x < l.nodes[0].x);
}

#[test]
fn mixed_sizes_and_cycle_through_entry() {
    let g = graph(
        &[(100.0, 20.0), (40.0, 80.0), (70.0, 30.0)],
        &[(0, 1), (1, 2), (2, 0), (1, 1)],
    );
    run(&g);
}

#[test]
fn errors() {
    let opts = LayoutOptions::default();
    let mut g = uniform(2, &[(0, 1)]);
    g.edges[0].to = 9;
    assert_eq!(layout(&g, &opts), Err(LayoutError::UnknownNode(9)));
    let mut g = uniform(2, &[]);
    g.nodes[1].id = 0;
    assert_eq!(layout(&g, &opts), Err(LayoutError::DuplicateNode(0)));
    let g = uniform(2, &[]);
    let o = LayoutOptions {
        entry: Some(5),
        ..opts.clone()
    };
    assert_eq!(layout(&g, &o), Err(LayoutError::UnknownEntry(5)));
    let mut g = uniform(1, &[]);
    g.nodes[0].width = f32::NAN;
    assert_eq!(layout(&g, &opts), Err(LayoutError::InvalidSize(0)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn random_graphs_are_valid(
        sizes in prop::collection::vec((1.0f32..200.0, 1.0f32..120.0), 1..40),
        raw in prop::collection::vec((any::<u16>(), any::<u16>(), any::<bool>()), 0..80),
    ) {
        let n = sizes.len() as u64;
        let edges: Vec<(u64, u64)> = raw
            .iter()
            .map(|&(a, b, fwd)| {
                let (a, b) = (u64::from(a) % n, u64::from(b) % n);
                if fwd && a > b { (b, a) } else { (a, b) }
            })
            .collect();
        let g = graph(&sizes, &edges);
        let l = layout(&g, &LayoutOptions::default()).unwrap();
        check(&g, &l);
        prop_assert_eq!(&l, &layout(&g, &LayoutOptions::default()).unwrap());
    }
}
