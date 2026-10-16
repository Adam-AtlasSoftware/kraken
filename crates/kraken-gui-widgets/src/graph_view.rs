//! Control-flow graph view: blocks of syntax-coloured lines connected by routed edges.
//!
//! Layout runs on a worker thread (`kraken-layout`), results are cached by a hash of the model
//! and font size, and only blocks and edges intersecting the viewport are painted.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::sync::{Arc, Mutex};

use egui::text::{LayoutJob, TextFormat};
use egui::{
    Align2, Color32, Context, CornerRadius, Id, Key, Pos2, Rect, Response, Sense, Shape, Stroke,
    StrokeKind, Ui, Vec2,
};
use kraken_layout::{Graph, Layout, LayoutOptions, NodeSpec};
use kraken_proto::TokenKind;

pub use kraken_layout::EdgeKind;

use crate::theme::{KrakenTheme, Palette};

/// One basic block: an address title and its (disassembly or pseudo-code) lines.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockModel {
    pub id: u64,
    pub title: String,
    /// Each line is a run of `(text, kind)` pieces drawn back to back.
    pub lines: Vec<Vec<(String, TokenKind)>>,
}

/// The graph to show. Edges referencing unknown block ids and duplicate block ids are ignored.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CfgModel {
    pub blocks: Vec<BlockModel>,
    pub edges: Vec<(u64, u64, EdgeKind)>,
    pub entry: Option<u64>,
}

/// A token that was double-clicked.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphToken {
    pub block: u64,
    pub line: usize,
    /// Index of the piece within the line.
    pub index: usize,
    pub text: String,
    pub kind: TokenKind,
}

pub struct GraphViewResponse {
    pub response: Response,
    /// The selection was changed by a click this frame.
    pub changed: bool,
    pub token: Option<GraphToken>,
    /// A layout job for the current model is still running.
    pub laying_out: bool,
    /// Number of blocks painted this frame (after culling).
    pub drawn_blocks: usize,
}

pub const MIN_ZOOM: f32 = 0.002;
pub const MAX_ZOOM: f32 = 4.0;

/// Pan/zoom transform. `pan` is the screen offset (relative to the widget's top-left) of the
/// world origin, so `screen = origin + pan + world * zoom`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    pub pan: Vec2,
    pub zoom: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            pan: Vec2::ZERO,
            zoom: 1.0,
        }
    }
}

impl Viewport {
    pub fn to_screen(&self, origin: Pos2, world: Pos2) -> Pos2 {
        origin + self.pan + world.to_vec2() * self.zoom
    }

    pub fn to_world(&self, origin: Pos2, screen: Pos2) -> Pos2 {
        ((screen - origin - self.pan) / self.zoom).to_pos2()
    }

    /// Multiplies the zoom by `factor` (clamped), keeping the point at `anchor` (relative to the
    /// widget's top-left) fixed on screen.
    pub fn zoom_at(&mut self, anchor: Vec2, factor: f32) {
        let new = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let ratio = new / self.zoom;
        self.pan = anchor - (anchor - self.pan) * ratio;
        self.zoom = new;
    }

    /// The world-space rectangle visible in a widget of `view` size.
    pub fn visible_world(&self, view: Vec2) -> Rect {
        Rect::from_min_size((-self.pan / self.zoom).to_pos2(), view / self.zoom)
    }

    /// Pans so that `world` is at the centre of a widget of `view` size.
    pub fn center_on(&mut self, world: Pos2, view: Vec2) {
        self.pan = view / 2.0 - world.to_vec2() * self.zoom;
    }

    /// Transform showing all of `content` centred in `view`, never zoomed in past 1:1.
    pub fn fit(content: Vec2, view: Vec2, margin: f32) -> Self {
        if content.x <= 0.0 || content.y <= 0.0 {
            return Self::default();
        }
        let avail = (view - Vec2::splat(2.0 * margin)).max(Vec2::splat(1.0));
        let zoom = (avail.x / content.x)
            .min(avail.y / content.y)
            .clamp(MIN_ZOOM, 1.0);
        Self {
            pan: (view - content * zoom) / 2.0,
            zoom,
        }
    }
}

/// Indices of `rects` intersecting `view`.
pub fn cull(rects: &[Rect], view: Rect) -> impl Iterator<Item = usize> + '_ {
    rects
        .iter()
        .enumerate()
        .filter(move |(_, r)| r.intersects(view))
        .map(|(i, _)| i)
}

/// Cache identity of a model rendered with the given font size.
pub fn cache_key(model: &CfgModel, font_bits: u32) -> u64 {
    let mut h = DefaultHasher::new();
    font_bits.hash(&mut h);
    model.entry.hash(&mut h);
    for b in &model.blocks {
        b.id.hash(&mut h);
        b.title.hash(&mut h);
        b.lines.len().hash(&mut h);
        for line in &b.lines {
            line.len().hash(&mut h);
            for (t, k) in line {
                t.hash(&mut h);
                k.hash(&mut h);
            }
        }
    }
    for (a, b, k) in &model.edges {
        (a, b, *k as u8).hash(&mut h);
    }
    h.finish()
}

const PAD_X: f32 = 10.0;
const PAD_Y: f32 = 6.0;
const MIN_BLOCK_W: f32 = 96.0;
const FIT_MARGIN: f32 = 24.0;
const CACHE_SLOTS: usize = 4;
const DEFAULT_MINIMAP_BLOCKS: usize = 30;

#[derive(Debug, Clone, Copy)]
struct Metrics {
    cw: f32,
    row_h: f32,
}

impl Metrics {
    fn header_h(&self) -> f32 {
        self.row_h + 8.0
    }

    fn block_size(&self, b: &BlockModel) -> Vec2 {
        let chars = b
            .lines
            .iter()
            .map(|l| l.iter().map(|(t, _)| t.chars().count()).sum::<usize>())
            .max()
            .unwrap_or(0)
            .max(b.title.chars().count() + 2);
        let w = (chars as f32 * self.cw + 2.0 * PAD_X).max(MIN_BLOCK_W);
        let h = self.header_h() + 2.0 * PAD_Y + b.lines.len() as f32 * self.row_h;
        Vec2::new(w, h)
    }
}

/// Everything derived from a layout that painting needs.
struct Prepared {
    key: u64,
    /// Snapshot the layout was computed from, so a stale layout stays drawable while a new
    /// model is being laid out.
    model: Arc<CfgModel>,
    /// Block index (into `CfgModel::blocks`) per placed node.
    node_block: Vec<usize>,
    rects: Vec<Rect>,
    layout: Layout,
    edge_bbox: Vec<Rect>,
    content: Vec2,
    error: Option<String>,
}

struct Job {
    model: Arc<CfgModel>,
    nodes: Vec<(u64, usize, Vec2)>,
    edges: Vec<(u64, u64, EdgeKind)>,
    entry: Option<u64>,
}

fn build_job(model: &CfgModel, m: Metrics) -> Job {
    let mut seen = HashMap::new();
    let mut nodes = Vec::new();
    for (i, b) in model.blocks.iter().enumerate() {
        if seen.insert(b.id, ()).is_none() {
            nodes.push((b.id, i, m.block_size(b)));
        }
    }
    let edges = model
        .edges
        .iter()
        .filter(|(a, b, _)| seen.contains_key(a) && seen.contains_key(b))
        .copied()
        .collect();
    let entry = model.entry.filter(|e| seen.contains_key(e));
    Job {
        model: Arc::new(model.clone()),
        nodes,
        edges,
        entry,
    }
}

fn run_job(key: u64, job: Job) -> Prepared {
    let graph = Graph {
        nodes: job
            .nodes
            .iter()
            .map(|&(id, _, s)| NodeSpec {
                id,
                width: s.x,
                height: s.y,
            })
            .collect(),
        edges: job
            .edges
            .iter()
            .map(|&(from, to, kind)| kraken_layout::EdgeSpec { from, to, kind })
            .collect(),
    };
    let opts = LayoutOptions {
        entry: job.entry,
        ..LayoutOptions::default()
    };
    match kraken_layout::layout(&graph, &opts) {
        Ok(layout) => {
            let rects = layout
                .nodes
                .iter()
                .zip(&job.nodes)
                .map(|(p, n)| Rect::from_min_size(Pos2::new(p.x, p.y), n.2))
                .collect();
            let edge_bbox = layout
                .edges
                .iter()
                .map(|e| {
                    let mut r = Rect::NOTHING;
                    for &(x, y) in &e.points {
                        r.extend_with(Pos2::new(x, y));
                    }
                    r.expand(6.0)
                })
                .collect();
            let content = Vec2::new(layout.width, layout.height);
            Prepared {
                key,
                model: job.model,
                node_block: job.nodes.iter().map(|n| n.1).collect(),
                rects,
                layout,
                edge_bbox,
                content,
                error: None,
            }
        }
        Err(e) => Prepared {
            key,
            model: job.model,
            node_block: Vec::new(),
            rects: Vec::new(),
            layout: Layout::default(),
            edge_bbox: Vec::new(),
            content: Vec2::ZERO,
            error: Some(e.to_string()),
        },
    }
}

struct Pending {
    key: u64,
    rx: Receiver<Prepared>,
}

#[derive(Default)]
struct State {
    vp: Viewport,
    need_fit: bool,
    current: Option<Arc<Prepared>>,
    cache: Vec<Arc<Prepared>>,
    pending: Option<Pending>,
}

impl State {
    /// Collects a finished job (discarding stale ones) and makes `key` current if cached.
    /// Returns true when a job for `key` still has to be started.
    fn poll(&mut self, key: u64) -> bool {
        if let Some(p) = &self.pending {
            match p.rx.try_recv() {
                Ok(prep) => {
                    self.pending = None;
                    if prep.key == key {
                        self.insert(Arc::new(prep));
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.pending = None,
            }
        }
        if self.current.as_ref().is_some_and(|c| c.key == key) {
            return false;
        }
        if let Some(i) = self.cache.iter().position(|c| c.key == key) {
            let hit = self.cache.remove(i);
            self.insert(hit);
            return false;
        }
        self.pending.as_ref().is_none_or(|p| p.key != key)
    }

    fn insert(&mut self, prep: Arc<Prepared>) {
        self.cache.retain(|c| c.key != prep.key);
        self.cache.insert(0, prep.clone());
        self.cache.truncate(CACHE_SLOTS);
        self.current = Some(prep);
        self.need_fit = true;
    }
}

fn edge_color(kind: EdgeKind, theme: &KrakenTheme, pal: &Palette) -> Color32 {
    let (green, red, neutral) = if theme.dark {
        (
            Color32::from_rgb(0x4c, 0xc3, 0x8a),
            Color32::from_rgb(0xe5, 0x68, 0x6d),
            Color32::from_rgb(0x8f, 0xa8, 0xb5),
        )
    } else {
        (
            Color32::from_rgb(0x1d, 0x8a, 0x4a),
            Color32::from_rgb(0xc0, 0x39, 0x2b),
            Color32::from_rgb(0x5d, 0x74, 0x80),
        )
    };
    match kind {
        EdgeKind::ConditionalTrue => green,
        EdgeKind::ConditionalFalse => red,
        EdgeKind::Back => pal.accent,
        EdgeKind::Jump | EdgeKind::Fallthrough => neutral,
    }
}

pub struct GraphView<'a> {
    model: &'a CfgModel,
    id: Id,
    cache_id: Option<u64>,
    minimap_blocks: usize,
}

impl<'a> GraphView<'a> {
    pub fn new(model: &'a CfgModel) -> Self {
        Self {
            model,
            id: Id::new("kraken_graph_view"),
            cache_id: None,
            minimap_blocks: DEFAULT_MINIMAP_BLOCKS,
        }
    }

    pub fn id_salt(mut self, salt: impl Hash + std::fmt::Debug) -> Self {
        self.id = Id::new("kraken_graph_view").with(salt);
        self
    }

    /// Caller-supplied identity of the model (e.g. a revision number). When set, the model is
    /// not re-hashed every frame. It must change whenever the model does.
    pub fn cache_id(mut self, id: u64) -> Self {
        self.cache_id = Some(id);
        self
    }

    /// Show the minimap for graphs with at least this many blocks (default 30).
    pub fn minimap_min_blocks(mut self, n: usize) -> Self {
        self.minimap_blocks = n;
        self
    }

    pub fn show(self, ui: &mut Ui, selected: &mut Option<u64>) -> GraphViewResponse {
        let theme = KrakenTheme::from_ctx(ui.ctx());
        let pal = theme.palette();
        let font = KrakenTheme::mono_font();
        let m = Metrics {
            cw: ui.fonts_mut(|f| f.glyph_width(&font, '0')),
            row_h: ui.fonts_mut(|f| f.row_height(&font)) + 3.0,
        };
        let font_bits = font.size.to_bits();
        let key = match self.cache_id {
            Some(c) => {
                let mut h = DefaultHasher::new();
                (c, font_bits).hash(&mut h);
                h.finish()
            }
            None => cache_key(self.model, font_bits),
        };

        let state_id = ui.make_persistent_id(self.id);
        let state: Arc<Mutex<State>> = ui.data_mut(|d| {
            d.get_temp_mut_or_insert_with(state_id, || {
                Arc::new(Mutex::new(State {
                    need_fit: true,
                    ..State::default()
                }))
            })
            .clone()
        });
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());

        if st.poll(key) {
            let job = build_job(self.model, m);
            let (tx, rx) = channel();
            let ctx: Context = ui.ctx().clone();
            let spawned = std::thread::Builder::new()
                .name("kraken-graph-layout".into())
                .spawn(move || {
                    let _ = tx.send(run_job(key, job));
                    ctx.request_repaint();
                });
            st.pending = spawned.is_ok().then_some(Pending { key, rx });
        }
        let laying_out = st.current.as_ref().is_none_or(|c| c.key != key);

        let size = ui.available_size().max(Vec2::splat(32.0));
        let (rect, resp) = ui.allocate_exact_size(size, Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, pal.bg);

        let mut out = GraphViewResponse {
            response: resp.clone(),
            changed: false,
            token: None,
            laying_out,
            drawn_blocks: 0,
        };

        let Some(prep) = st.current.clone() else {
            if self.model.blocks.is_empty() {
                painter.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    "empty graph",
                    font,
                    pal.text_dim,
                );
            } else {
                overlay(ui, &painter, rect, "laying out…", &pal);
            }
            return out;
        };
        if let Some(e) = &prep.error {
            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                format!("layout failed: {e}"),
                font,
                pal.text_dim,
            );
            return out;
        }

        if st.need_fit {
            st.vp = Viewport::fit(prep.content, rect.size(), FIT_MARGIN);
            st.need_fit = false;
        }

        // Minimap geometry and interaction come first so the main handlers can yield to it.
        let minimap = (prep.model.blocks.len() >= self.minimap_blocks && prep.content.x > 0.0)
            .then(|| minimap_rect(rect, prep.content));
        let mut over_minimap = false;
        if let Some(mm) = minimap {
            let r = ui.interact(mm, state_id.with("minimap"), Sense::click_and_drag());
            if (r.dragged() || r.clicked() || r.is_pointer_button_down_on())
                && let Some(p) = r.interact_pointer_pos()
            {
                let s = mm.width() / prep.content.x;
                let world = ((p - mm.min) / s).to_pos2();
                let size = rect.size();
                st.vp.center_on(world, size);
                over_minimap = true;
            }
            over_minimap |= r.hovered();
        }

        if !over_minimap {
            if resp.dragged_by(egui::PointerButton::Primary)
                || resp.dragged_by(egui::PointerButton::Middle)
            {
                st.vp.pan += resp.drag_delta();
                ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
            }
            if resp.hovered() {
                let zoom = ui.input(|i| i.zoom_delta());
                if zoom != 1.0 {
                    let anchor = resp.hover_pos().map_or(rect.size() / 2.0, |p| p - rect.min);
                    st.vp.zoom_at(anchor, zoom);
                }
                let scroll = ui.input(|i| i.smooth_scroll_delta());
                st.vp.pan += scroll;
            }
        }
        if (resp.hovered() || resp.has_focus()) && ui.input(|i| i.key_pressed(Key::F)) {
            st.vp = Viewport::fit(prep.content, rect.size(), FIT_MARGIN);
        }
        let vp = st.vp;
        let origin = rect.min;
        let view = vp.visible_world(rect.size());

        let hit = |p: Pos2| -> Option<usize> {
            let w = vp.to_world(origin, p);
            (0..prep.rects.len())
                .rev()
                .find(|&i| prep.rects[i].contains(w))
        };
        if resp.clicked() || resp.double_clicked() {
            resp.request_focus();
            if let Some(i) = resp.interact_pointer_pos().and_then(hit) {
                let id = prep.model.blocks[prep.node_block[i]].id;
                if *selected != Some(id) {
                    *selected = Some(id);
                    out.changed = true;
                }
            }
        }
        if resp.double_clicked()
            && let Some(p) = resp.interact_pointer_pos()
            && let Some(i) = hit(p)
        {
            let block = &prep.model.blocks[prep.node_block[i]];
            out.token = token_at(block, &prep.rects[i], vp.to_world(origin, p), m);
        }

        let style = theme.token_style();
        let z = vp.zoom;
        let sel_node = selected.and_then(|s| {
            (0..prep.rects.len()).find(|&i| prep.model.blocks[prep.node_block[i]].id == s)
        });
        let sel_id = *selected;

        // Edges first so blocks cover their endpoints.
        let detail_edges = z >= 0.25;
        for ei in cull(&prep.edge_bbox, view) {
            let e = &prep.layout.edges[ei];
            let pts: Vec<Pos2> = e
                .points
                .iter()
                .map(|&(x, y)| vp.to_screen(origin, Pos2::new(x, y)))
                .collect();
            if pts.len() < 2 {
                continue;
            }
            let touches = sel_id.is_some_and(|s| e.from == s || e.to == s);
            let color = edge_color(e.kind, &theme, &pal);
            let width = if touches {
                (2.2 * z).clamp(1.6, 3.2)
            } else {
                (1.4 * z).clamp(0.8, 2.2)
            };
            let color = if sel_id.is_some() && !touches {
                color.gamma_multiply(0.55)
            } else {
                color
            };
            let stroke = Stroke::new(width, color);
            if e.kind == EdgeKind::Back && detail_edges {
                painter.extend(Shape::dashed_line(&pts, stroke, 7.0 * z, 4.0 * z));
            } else {
                painter.add(Shape::line(pts.clone(), stroke));
            }
            if z >= 0.1 {
                let tip = pts[pts.len() - 1];
                let prev = pts[pts.len() - 2];
                let d = tip - prev;
                if d.length() > 0.01 {
                    let dir = d.normalized();
                    let perp = Vec2::new(-dir.y, dir.x);
                    let s = (9.0 * z).clamp(4.0, 12.0);
                    painter.add(Shape::convex_polygon(
                        vec![
                            tip,
                            tip - dir * s + perp * s * 0.45,
                            tip - dir * s - perp * s * 0.45,
                        ],
                        color,
                        Stroke::NONE,
                    ));
                }
            }
        }

        // Blocks.
        let hover = resp.hover_pos().filter(|_| !over_minimap).and_then(hit);
        let text_px = KrakenTheme::MONO_SIZE * z;
        let draw_text = text_px >= 5.5;
        let scaled_font = egui::FontId::monospace(((text_px * 2.0).round() / 2.0).max(1.0));
        let radius = CornerRadius::same(((6.0 * z).round() as i32).clamp(0, 8) as u8);
        for i in cull(&prep.rects, view) {
            out.drawn_blocks += 1;
            let block = &prep.model.blocks[prep.node_block[i]];
            let wr = prep.rects[i];
            let r = Rect::from_min_max(vp.to_screen(origin, wr.min), vp.to_screen(origin, wr.max));
            let is_sel = Some(i) == sel_node;
            let fill = if Some(i) == hover {
                pal.surface_hover
            } else {
                pal.surface
            };
            if z < 0.08 {
                painter.rect_filled(r, 0.0, if is_sel { pal.accent } else { pal.border });
                continue;
            }
            let stroke = if is_sel {
                Stroke::new(2.0, pal.accent)
            } else {
                Stroke::new(1.0, pal.border)
            };
            painter.rect_filled(r, radius, fill);
            let header_h = m.header_h() * z;
            let header = Rect::from_min_size(r.min, Vec2::new(r.width(), header_h));
            painter.rect_filled(
                header,
                CornerRadius {
                    nw: radius.nw,
                    ne: radius.ne,
                    sw: 0,
                    se: 0,
                },
                pal.panel,
            );
            painter.rect_stroke(r, radius, stroke, StrokeKind::Inside);
            let is_entry = prep.model.entry == Some(block.id);
            let title_color = if is_entry { pal.accent } else { pal.address };
            if draw_text {
                painter.text(
                    Pos2::new(r.left() + PAD_X * z, header.center().y),
                    Align2::LEFT_CENTER,
                    &block.title,
                    scaled_font.clone(),
                    title_color,
                );
            } else if z >= 0.12 {
                let w = (block.title.chars().count() as f32 * m.cw * z).min(r.width() - 8.0 * z);
                painter.rect_filled(
                    Rect::from_min_size(
                        Pos2::new(r.left() + PAD_X * z, header.center().y - 1.5 * z),
                        Vec2::new(w.max(1.0), 3.0 * z),
                    ),
                    1.0,
                    title_color.gamma_multiply(0.7),
                );
            }
            let body_top = r.top() + (m.header_h() + PAD_Y) * z;
            let row = m.row_h * z;
            let x0 = r.left() + PAD_X * z;
            // Skip lines outside the viewport vertically.
            let first = (((rect.top() - body_top) / row).floor().max(0.0)) as usize;
            let last = ((((rect.bottom() - body_top) / row).ceil()).max(0.0) as usize)
                .min(block.lines.len());
            for li in first..last {
                let y = body_top + li as f32 * row;
                let line = &block.lines[li];
                if draw_text {
                    let mut job = LayoutJob::default();
                    job.wrap.max_width = f32::INFINITY;
                    for (text, kind) in line {
                        let mut fmt = TextFormat::simple(scaled_font.clone(), style.color(*kind));
                        fmt.italics = style.italic(*kind);
                        job.append(text, 0.0, fmt);
                    }
                    let galley = painter.layout_job(job);
                    painter.galley(
                        Pos2::new(x0, y + (row - galley.size().y) / 2.0),
                        galley,
                        pal.text,
                    );
                } else if z >= 0.12 {
                    let mut x = x0;
                    for (text, kind) in line {
                        let w = text.chars().count() as f32 * m.cw * z;
                        if *kind != TokenKind::Other || !text.trim().is_empty() {
                            painter.rect_filled(
                                Rect::from_min_size(
                                    Pos2::new(x, y + row * 0.3),
                                    Vec2::new(w, row * 0.4),
                                ),
                                0.0,
                                style.color(*kind).gamma_multiply(0.45),
                            );
                        }
                        x += w;
                    }
                }
            }
        }

        if let Some(mm) = minimap {
            paint_minimap(&painter, mm, &prep, &vp, rect.size(), sel_node, &pal);
        }
        if laying_out {
            overlay(ui, &painter, rect, "laying out…", &pal);
        }
        out
    }
}

fn overlay(ui: &Ui, painter: &egui::Painter, rect: Rect, text: &str, pal: &Palette) {
    let font = egui::FontId::proportional(12.0);
    let galley = painter.layout_no_wrap(text.to_string(), font, pal.text_dim);
    let pill = Rect::from_min_size(
        rect.left_top() + Vec2::new(10.0, 10.0),
        galley.size() + Vec2::new(16.0, 8.0),
    );
    painter.rect_filled(pill, 10.0, pal.panel.gamma_multiply(0.9));
    painter.galley(pill.min + Vec2::new(8.0, 4.0), galley, pal.text_dim);
    ui.ctx().request_repaint();
}

fn minimap_rect(view: Rect, content: Vec2) -> Rect {
    let max = Vec2::new(190.0, 130.0);
    let s = (max.x / content.x).min(max.y / content.y);
    let size = (content * s).max(Vec2::splat(24.0));
    Rect::from_min_size(
        Pos2::new(view.right() - size.x - 12.0, view.bottom() - size.y - 12.0),
        size,
    )
}

fn paint_minimap(
    painter: &egui::Painter,
    mm: Rect,
    prep: &Prepared,
    vp: &Viewport,
    view_size: Vec2,
    sel: Option<usize>,
    pal: &Palette,
) {
    let s = mm.width() / prep.content.x;
    painter.rect_filled(mm.expand(3.0), 4.0, pal.panel.gamma_multiply(0.92));
    painter.rect_stroke(
        mm.expand(3.0),
        4.0,
        Stroke::new(1.0, pal.border),
        StrokeKind::Inside,
    );
    let clip = painter.with_clip_rect(mm);
    for (i, r) in prep.rects.iter().enumerate() {
        let sr = Rect::from_min_max(mm.min + r.min.to_vec2() * s, mm.min + r.max.to_vec2() * s);
        let color = if Some(i) == sel {
            pal.accent
        } else {
            pal.text_dim
        };
        clip.rect_filled(
            Rect::from_center_size(sr.center(), sr.size().max(Vec2::splat(1.5))),
            0.0,
            color,
        );
    }
    let v = vp.visible_world(view_size);
    let vr = Rect::from_min_max(mm.min + v.min.to_vec2() * s, mm.min + v.max.to_vec2() * s);
    clip.rect_filled(vr, 0.0, pal.selection);
    clip.rect_stroke(vr, 0.0, Stroke::new(1.0, pal.accent), StrokeKind::Inside);
}

/// The token piece under world point `w` in `block` (whose world rect is `wr`).
pub fn token_at_world(
    block: &BlockModel,
    wr: &Rect,
    w: Pos2,
    cw: f32,
    row_h: f32,
    header_h: f32,
) -> Option<(usize, usize)> {
    let top = wr.top() + header_h + PAD_Y;
    let dy = w.y - top;
    let dx = w.x - (wr.left() + PAD_X);
    if dy < 0.0 || dx < 0.0 {
        return None;
    }
    let line = (dy / row_h) as usize;
    let col = (dx / cw) as usize;
    let pieces = block.lines.get(line)?;
    let mut start = 0;
    for (i, (t, _)) in pieces.iter().enumerate() {
        let end = start + t.chars().count();
        if col < end {
            return Some((line, i));
        }
        start = end;
    }
    None
}

fn token_at(block: &BlockModel, wr: &Rect, w: Pos2, m: Metrics) -> Option<GraphToken> {
    let (line, index) = token_at_world(block, wr, w, m.cw, m.row_h, m.header_h())?;
    let (text, kind) = block.lines[line][index].clone();
    Some(GraphToken {
        block: block.id,
        line,
        index,
        text,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(n: u64) -> CfgModel {
        CfgModel {
            blocks: (0..n)
                .map(|id| BlockModel {
                    id,
                    title: format!("{id:#x}"),
                    lines: vec![vec![("mov".into(), TokenKind::Keyword)]],
                })
                .collect(),
            edges: (1..n).map(|i| (i - 1, i, EdgeKind::Fallthrough)).collect(),
            entry: Some(0),
        }
    }

    #[test]
    fn screen_world_round_trip() {
        let vp = Viewport {
            pan: Vec2::new(30.0, -12.0),
            zoom: 0.5,
        };
        let o = Pos2::new(100.0, 50.0);
        let w = Pos2::new(240.0, 80.0);
        let s = vp.to_screen(o, w);
        assert_eq!(s, Pos2::new(100.0 + 30.0 + 120.0, 50.0 - 12.0 + 40.0));
        assert!((vp.to_world(o, s) - w).length() < 1e-4);
    }

    #[test]
    fn zoom_keeps_anchor_fixed_and_clamps() {
        let mut vp = Viewport {
            pan: Vec2::new(10.0, 20.0),
            zoom: 1.0,
        };
        let o = Pos2::ZERO;
        let anchor = Vec2::new(200.0, 150.0);
        let before = vp.to_world(o, anchor.to_pos2());
        vp.zoom_at(anchor, 2.0);
        assert_eq!(vp.zoom, 2.0);
        assert!((vp.to_world(o, anchor.to_pos2()) - before).length() < 1e-3);
        vp.zoom_at(anchor, 1000.0);
        assert_eq!(vp.zoom, MAX_ZOOM);
        vp.zoom_at(anchor, 1e-9);
        assert_eq!(vp.zoom, MIN_ZOOM);
    }

    #[test]
    fn fit_centres_and_never_upscales() {
        let vp = Viewport::fit(Vec2::new(1000.0, 500.0), Vec2::new(500.0, 500.0), 0.0);
        assert_eq!(vp.zoom, 0.5);
        assert_eq!(vp.pan, Vec2::new(0.0, 125.0));
        let small = Viewport::fit(Vec2::new(100.0, 50.0), Vec2::new(800.0, 600.0), 10.0);
        assert_eq!(small.zoom, 1.0);
        assert_eq!(small.pan, Vec2::new(350.0, 275.0));
        assert_eq!(
            Viewport::fit(Vec2::ZERO, Vec2::splat(100.0), 5.0),
            Viewport::default()
        );
        let huge = Viewport::fit(Vec2::splat(1e9), Vec2::splat(100.0), 5.0);
        assert_eq!(huge.zoom, MIN_ZOOM);
    }

    #[test]
    fn visible_world_matches_transform() {
        let vp = Viewport {
            pan: Vec2::new(-100.0, 40.0),
            zoom: 2.0,
        };
        let v = vp.visible_world(Vec2::new(400.0, 200.0));
        assert_eq!(v.min, Pos2::new(50.0, -20.0));
        assert_eq!(v.size(), Vec2::new(200.0, 100.0));
        let mut c = Viewport::default();
        c.center_on(Pos2::new(500.0, 300.0), Vec2::new(200.0, 100.0));
        assert_eq!(
            c.visible_world(Vec2::new(200.0, 100.0)).center(),
            Pos2::new(500.0, 300.0)
        );
    }

    #[test]
    fn culling_selects_intersecting_rects() {
        let rects = vec![
            Rect::from_min_size(Pos2::new(0.0, 0.0), Vec2::splat(10.0)),
            Rect::from_min_size(Pos2::new(100.0, 0.0), Vec2::splat(10.0)),
            Rect::from_min_size(Pos2::new(5.0, 500.0), Vec2::splat(10.0)),
            Rect::from_min_size(Pos2::new(-50.0, 5.0), Vec2::splat(60.0)),
        ];
        let view = Rect::from_min_size(Pos2::new(0.0, 0.0), Vec2::new(50.0, 50.0));
        assert_eq!(cull(&rects, view).collect::<Vec<_>>(), vec![0, 3]);
    }

    #[test]
    fn cache_key_tracks_content_and_font() {
        let a = model(5);
        let k = cache_key(&a, 13f32.to_bits());
        assert_eq!(k, cache_key(&a.clone(), 13f32.to_bits()));
        assert_ne!(k, cache_key(&a, 14f32.to_bits()));
        let mut b = a.clone();
        b.blocks[2].lines[0][0].0 = "xor".into();
        assert_ne!(k, cache_key(&b, 13f32.to_bits()));
        let mut c = a.clone();
        c.edges[0].2 = EdgeKind::Jump;
        assert_ne!(k, cache_key(&c, 13f32.to_bits()));
        let mut d = a.clone();
        d.entry = None;
        assert_ne!(k, cache_key(&d, 13f32.to_bits()));
    }

    #[test]
    fn state_discards_stale_results_and_caches() {
        let mut st = State::default();
        let (tx, rx) = channel();
        st.pending = Some(Pending { key: 1, rx });
        tx.send(run_job(
            1,
            build_job(
                &model(3),
                Metrics {
                    cw: 7.0,
                    row_h: 16.0,
                },
            ),
        ))
        .unwrap();
        // Wanting key 2 now: the result for key 1 is stale and must not become current.
        assert!(st.poll(2));
        assert!(st.current.is_none());
        assert!(st.pending.is_none());

        let (tx, rx) = channel();
        st.pending = Some(Pending { key: 3, rx });
        tx.send(run_job(
            3,
            build_job(
                &model(3),
                Metrics {
                    cw: 7.0,
                    row_h: 16.0,
                },
            ),
        ))
        .unwrap();
        assert!(!st.poll(3));
        assert_eq!(st.current.as_ref().map(|c| c.key), Some(3));
        assert!(st.need_fit);
        // A different key misses; going back to 3 is a cache hit.
        assert!(st.poll(4));
        st.pending = None;
        assert!(!st.poll(3));
    }

    #[test]
    fn job_drops_duplicates_and_dangling_edges() {
        let mut m = model(3);
        m.blocks.push(m.blocks[1].clone());
        m.edges.push((0, 99, EdgeKind::Jump));
        let job = build_job(
            &m,
            Metrics {
                cw: 7.0,
                row_h: 16.0,
            },
        );
        assert_eq!(job.nodes.len(), 3);
        assert_eq!(job.edges.len(), 2);
        let p = run_job(0, job);
        assert!(p.error.is_none());
        assert_eq!(p.rects.len(), 3);
    }

    #[test]
    fn token_hit_testing() {
        let block = BlockModel {
            id: 1,
            title: "0x10".into(),
            lines: vec![
                vec![
                    ("mov".into(), TokenKind::Keyword),
                    (" rax".into(), TokenKind::Variable),
                ],
                vec![("ret".into(), TokenKind::Keyword)],
            ],
        };
        let wr = Rect::from_min_size(Pos2::new(100.0, 100.0), Vec2::new(200.0, 100.0));
        let (cw, row, hh) = (8.0, 16.0, 24.0);
        let top = 100.0 + hh + PAD_Y;
        let at = |col: f32, line: f32| {
            token_at_world(
                &block,
                &wr,
                Pos2::new(100.0 + PAD_X + col * cw + 1.0, top + line * row + 2.0),
                cw,
                row,
                hh,
            )
        };
        assert_eq!(at(0.0, 0.0), Some((0, 0)));
        assert_eq!(at(4.0, 0.0), Some((0, 1)));
        assert_eq!(at(0.0, 1.0), Some((1, 0)));
        assert_eq!(at(10.0, 0.0), None);
        assert_eq!(at(0.0, 5.0), None);
    }
}
