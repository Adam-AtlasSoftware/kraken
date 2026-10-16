// SPDX-License-Identifier: GPL-3.0-or-later
//! Run with: cargo test -p kraken-layout --release --test timing -- --ignored --nocapture
#![allow(clippy::unwrap_used)]

use std::time::Instant;

use kraken_layout::{EdgeKind, EdgeSpec, Graph, LayoutOptions, NodeSpec, layout};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

/// CFG-like: sequential blocks with diamonds, switches, loops and a few long jumps.
fn synthetic(n: u64) -> Graph {
    let mut rng = Lcg(42);
    let nodes = (0..n)
        .map(|id| NodeSpec {
            id,
            width: 80.0 + rng.next(120) as f32,
            height: 20.0 + 14.0 * rng.next(8) as f32,
        })
        .collect();
    let mut edges = Vec::new();
    let mut e = |from, to, kind| edges.push(EdgeSpec { from, to, kind });
    let mut i = 0;
    while i + 8 < n {
        match rng.next(5) {
            0 => {
                e(i, i + 1, EdgeKind::ConditionalTrue);
                e(i, i + 2, EdgeKind::ConditionalFalse);
                e(i + 1, i + 3, EdgeKind::Jump);
                e(i + 2, i + 3, EdgeKind::Fallthrough);
                i += 3;
            }
            1 => {
                for c in 1..=5 {
                    e(i, i + c, EdgeKind::Jump);
                    e(i + c, i + 6, EdgeKind::Jump);
                }
                i += 6;
            }
            2 => {
                e(i, i + 1, EdgeKind::Fallthrough);
                e(i + 1, i + 2, EdgeKind::ConditionalTrue);
                e(i + 2, i + 1, EdgeKind::Back);
                e(i + 1, i + 3, EdgeKind::ConditionalFalse);
                i += 3;
            }
            _ => {
                e(i, i + 1, EdgeKind::Fallthrough);
                i += 1;
            }
        }
        if rng.next(40) == 0 {
            e(i, (i + 5 + rng.next(60)).min(n - 1), EdgeKind::Jump);
        }
    }
    Graph { nodes, edges }
}

#[test]
#[ignore = "timing; run in release"]
fn layout_5000_nodes() {
    let g = synthetic(5000);
    let t = Instant::now();
    let l = layout(&g, &LayoutOptions::default()).unwrap();
    let dt = t.elapsed();
    println!(
        "5000 nodes, {} edges: {dt:?} ({}x{})",
        g.edges.len(),
        l.width,
        l.height
    );
    assert_eq!(l.nodes.len(), 5000);
}
