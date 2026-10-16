//! egui_kittest tests for `GraphView`: off-thread layout, selection, culling.

use std::time::{Duration, Instant};

use egui::{Event, Pos2, Vec2};
use egui_kittest::Harness;
use kraken_gui_widgets::{BlockModel, CfgModel, EdgeKind, GraphView, KrakenTheme};
use kraken_proto::TokenKind;

fn block(id: u64) -> BlockModel {
    BlockModel {
        id,
        title: format!("0x{:x}", 0x1000 + id * 8),
        lines: vec![
            vec![
                ("mov".into(), TokenKind::Keyword),
                (" ".into(), TokenKind::Other),
                ("rax".into(), TokenKind::Variable),
                (", ".into(), TokenKind::Op),
                ("1".into(), TokenKind::Constant),
            ],
            vec![("ret".into(), TokenKind::Keyword)],
        ],
    }
}

/// A chain of diamonds: 0 -> (1 | 2) -> 3 -> (4 | 5) -> 6 ...
fn diamonds(n: u64) -> CfgModel {
    let mut edges = Vec::new();
    let mut i = 0;
    while i + 3 < n {
        edges.push((i, i + 1, EdgeKind::ConditionalTrue));
        edges.push((i, i + 2, EdgeKind::ConditionalFalse));
        edges.push((i + 1, i + 3, EdgeKind::Jump));
        edges.push((i + 2, i + 3, EdgeKind::Fallthrough));
        i += 3;
    }
    CfgModel {
        blocks: (0..n).map(block).collect(),
        edges,
        entry: Some(0),
    }
}

struct Ui {
    model: CfgModel,
    selected: Option<u64>,
    laying_out: bool,
    drawn: usize,
    changed: bool,
    rev: u64,
}

fn harness(model: CfgModel) -> Harness<'static, Ui> {
    let mut h = Harness::builder()
        .with_size(Vec2::new(900.0, 700.0))
        .build_ui_state(
            |ui, s: &mut Ui| {
                KrakenTheme::DARK.apply(ui.ctx());
                let out = GraphView::new(&s.model)
                    .id_salt("t")
                    .cache_id(s.rev)
                    .show(ui, &mut s.selected);
                s.laying_out = out.laying_out;
                s.drawn = out.drawn_blocks;
                s.changed |= out.changed;
            },
            Ui {
                model,
                selected: None,
                laying_out: true,
                drawn: 0,
                changed: false,
                rev: 1,
            },
        );
    h.step();
    h
}

fn settle(h: &mut Harness<'_, Ui>) {
    let t0 = Instant::now();
    while h.state().laying_out {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "layout never finished"
        );
        std::thread::sleep(Duration::from_millis(5));
        h.step();
    }
    h.step();
    h.step();
}

#[test]
fn small_graph_lays_out_off_thread_and_draws_everything() {
    let mut h = harness(diamonds(7));
    settle(&mut h);
    assert_eq!(h.state().drawn, 7, "fit-to-view shows every block");
}

#[test]
fn empty_graph_renders() {
    let mut h = harness(CfgModel::default());
    h.step();
    h.step();
    assert!(!h.state().laying_out || h.state().drawn == 0);
}

#[test]
fn clicking_a_block_selects_it() {
    let mut h = harness(CfgModel {
        blocks: vec![block(42)],
        edges: vec![],
        entry: Some(42),
    });
    settle(&mut h);
    // A lone block is centred in the 900x700 view.
    let centre = Pos2::new(450.0, 350.0);
    h.event(Event::PointerMoved(centre));
    h.step();
    h.event(Event::PointerButton {
        pos: centre,
        button: egui::PointerButton::Primary,
        pressed: true,
        modifiers: Default::default(),
    });
    h.event(Event::PointerButton {
        pos: centre,
        button: egui::PointerButton::Primary,
        pressed: false,
        modifiers: Default::default(),
    });
    h.step();
    h.step();
    assert_eq!(h.state().selected, Some(42));
    assert!(h.state().changed);
}

#[test]
fn zooming_in_culls_offscreen_blocks() {
    let mut h = harness(diamonds(600));
    settle(&mut h);
    let all = h.state().drawn;
    assert_eq!(all, 600, "fit shows the whole graph");
    h.event(Event::PointerMoved(Pos2::new(450.0, 350.0)));
    h.step();
    for _ in 0..4 {
        h.event(Event::Zoom(2.0));
        h.step();
    }
    h.step();
    assert!(
        h.state().drawn < all / 4,
        "drew {} of {all}",
        h.state().drawn
    );
}

#[test]
fn model_change_discards_old_layout_and_relays_out() {
    let mut h = harness(diamonds(10));
    settle(&mut h);
    assert_eq!(h.state().drawn, 10);
    h.state_mut().model = diamonds(4);
    h.state_mut().rev = 2;
    h.step();
    settle(&mut h);
    assert_eq!(h.state().drawn, 4);
}

/// Not part of the normal run: `cargo test --release -p kraken-gui-widgets --test graph_view
/// stress_frame_time -- --ignored --nocapture`.
#[test]
#[ignore]
fn stress_frame_time() {
    let n = 3000;
    let mut model = diamonds(n);
    // Add loops so the layout has back edges too.
    for i in (10..n).step_by(25) {
        model.edges.push((i, i - 7, EdgeKind::Back));
    }
    let t0 = Instant::now();
    let mut h = harness(model);
    settle(&mut h);
    println!("layout of {n} blocks ready after {:?}", t0.elapsed());
    for (name, zoom) in [("fit (all blocks)", 1.0f32), ("zoomed in", 8.0)] {
        h.event(Event::PointerMoved(Pos2::new(450.0, 350.0)));
        h.step();
        if zoom != 1.0 {
            h.event(Event::Zoom(zoom));
            h.step();
        }
        let frames = 60;
        let t = Instant::now();
        for _ in 0..frames {
            h.step();
        }
        println!(
            "{name}: {:.2} ms/frame, {} blocks drawn",
            t.elapsed().as_secs_f64() * 1000.0 / frames as f64,
            h.state().drawn
        );
    }
}
