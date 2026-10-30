//! Headless tests of the program views: the whole app is driven frame by frame, with key events
//! injected, over the demo project.

use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Context, Event, Key, Modifiers, RawInput, Rect, pos2};
use egui_dock::DockState;
use kraken_gui_widgets::ByteSource;
use kraken_viewmodel::{AnalysisPhase, ByteState, Connection, Load, Reveal, XrefWhich};

use super::hex::CacheSource;
use super::{cycled, space_target};
use crate::app::KrakenApp;
use crate::args::{Options, RendererChoice, Scene};
use crate::fonts;
use crate::services::Services;
use crate::workspace::Tab;

mod nav;

const WAIT: Duration = Duration::from_secs(20);

struct Harness {
    ctx: Context,
    app: KrakenApp,
    _rt: Arc<tokio::runtime::Runtime>,
}

impl Harness {
    fn demo() -> Self {
        Self::demo_with(Services::offline())
    }

    fn demo_with(services: Services) -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        fonts::install(&ctx);
        let opts = Options {
            scene: Scene::Main,
            renderer: RendererChoice::Wgpu,
            demo: true,
            screenshot: None,
            light: false,
            no_daemon: false,
            open_project: None,
            function: None,
            path: None,
        };
        let app = KrakenApp::new(&ctx, rt.clone(), services, &opts);
        let mut h = Harness { ctx, app, _rt: rt };
        h.run_until("the demo to finish analysis", |a| {
            a.view_model().is_some_and(|vm| {
                vm.connection == Connection::Open
                    && vm.analysis.phase == AnalysisPhase::Complete
                    && !vm.functions.items.is_empty()
                    && !vm.busy()
            })
        });
        h
    }

    fn step_with(&mut self, events: Vec<Event>) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1440.0, 900.0))),
            events,
            ..Default::default()
        };
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(input, |ui| app.frame(ui));
        out.textures_delta.clear();
    }

    fn step(&mut self) {
        self.step_with(Vec::new());
    }

    fn run_until(&mut self, what: &str, cond: impl Fn(&KrakenApp) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !cond(&self.app) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            self.step();
            std::thread::sleep(Duration::from_millis(4));
        }
    }

    /// Draws a few frames so queued results are applied and views load.
    fn settle(&mut self) {
        for _ in 0..12 {
            self.step();
            std::thread::sleep(Duration::from_millis(8));
        }
        self.run_until("calls to finish", |a| {
            a.view_model().is_some_and(|vm| !vm.busy())
        });
        for _ in 0..3 {
            self.step();
        }
    }

    fn press(&mut self, key: Key) {
        for pressed in [true, false] {
            self.step_with(vec![Event::Key {
                key,
                physical_key: Some(key),
                pressed,
                repeat: false,
                modifiers: Modifiers::NONE,
            }]);
        }
    }

    fn select(&mut self, name: &str) -> u64 {
        let vm = self.app.view_model_mut().unwrap();
        let addr = vm
            .functions
            .items
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no function {name}"))
            .address;
        vm.select_function(addr);
        self.run_until("the function to decompile", |a| {
            a.view_model()
                .and_then(|vm| vm.current.as_ref())
                .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)))
        });
        self.settle();
        addr
    }
}

fn is_front(dock: &DockState<Tab>, tab: Tab) -> bool {
    let Some(p) = dock.find_tab(&tab) else {
        return false;
    };
    dock[p.surface][p.node]
        .get_leaf()
        .is_some_and(|l| l.active == p.tab)
}

#[test]
fn listing_hex_and_xrefs_load_when_their_tabs_are_drawn() {
    let mut h = Harness::demo();
    let main = h.select("main");
    assert!(is_front(h.app.dock(), Tab::Listing));
    let vm = h.app.view_model().unwrap();
    // The tab bar shows Listing, Hex and Xrefs by default, so their data is in.
    let l = &vm.views.listing;
    assert_eq!(l.function, Some(main));
    assert!(l.loaded && !l.rows.is_empty());
    assert_eq!(l.rows[0].address, main);
    assert_eq!(l.selected, Some(0), "the entry row is selected");
    assert_eq!(vm.views.hex.highlight.as_ref().map(|r| r.start), Some(main));
    assert_eq!(vm.views.bytes.state(main), ByteState::Ready);
    assert_eq!(vm.views.xrefs.function, Some(main));
    assert!(
        !vm.views.xrefs.callees.items.is_empty(),
        "main calls things"
    );
    // The graph is not the visible tab, so it has not been fetched yet.
    assert!(vm.views.graph.shape.is_none());
}

#[test]
fn the_hex_source_reads_the_cache_and_reports_what_is_loaded() {
    let mut h = Harness::demo();
    let main = h.select("main");
    let vm = h.app.view_model().unwrap();
    let window = vm.hex_window().expect("a window");
    let src = CacheSource {
        cache: &vm.views.bytes,
        start: window.start,
        len: window.end - window.start,
    };
    assert_eq!(src.len(), window.end - window.start);
    let mut buf = [0u8; 16];
    let off = main - window.start;
    assert_eq!(src.read(off, &mut buf), 16);
    assert_eq!(src.state(off), kraken_gui_widgets::ByteState::Ready);
    // Reads stop at the end of the window.
    assert_eq!(src.read(src.len() - 4, &mut buf), 4);
    assert_eq!(src.read(src.len() + 10, &mut buf), 0);
}

#[test]
fn space_swaps_the_listing_and_the_graph_like_ida() {
    assert_eq!(space_target(Some(Tab::Listing)), Tab::Graph);
    assert_eq!(space_target(Some(Tab::Graph)), Tab::Listing);
    assert_eq!(space_target(None), Tab::Listing);

    let mut h = Harness::demo();
    h.select("main");
    assert!(is_front(h.app.dock(), Tab::Listing));
    h.press(Key::Space);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::Graph), "Space shows the graph");
    // Drawing the graph loads the control-flow graph and every row of the listing.
    let vm = h.app.view_model().unwrap();
    assert!(vm.views.graph.data.is_some(), "{:?}", vm.views.graph.error);
    h.press(Key::Space);
    h.settle();
    assert!(
        is_front(h.app.dock(), Tab::Listing),
        "Space shows the listing again"
    );
}

#[test]
fn space_is_ignored_while_typing_in_a_filter() {
    let mut h = Harness::demo();
    h.select("main");
    h.app.pending_nav().focus_filter = true;
    h.step();
    h.step();
    h.press(Key::Space);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::Listing));
}

#[test]
fn x_lists_what_refers_to_the_address_under_the_pointer() {
    let mut h = Harness::demo();
    let main = h.select("main");
    let helper = h
        .app
        .view_model()
        .unwrap()
        .functions
        .items
        .iter()
        .find(|f| f.name == "helper")
        .unwrap()
        .address;
    // The panels record the address under the pointer; X asks about it.
    h.app.pending_nav().panels.hot = Some(helper);
    h.press(Key::X);
    h.settle();
    let vm = h.app.view_model().unwrap();
    let refs = vm.views.xrefs.references.as_ref().expect("references");
    assert_eq!(refs.address, helper);
    assert!(
        refs.list
            .items
            .iter()
            .any(|x| x.from_function.as_ref().is_some_and(|f| f.address == main)),
        "main calls helper: {:?}",
        refs.list.items
    );
    assert!(is_front(h.app.dock(), Tab::Xrefs));
    assert_eq!(
        vm.views.xrefs.list(XrefWhich::References).map(|l| l.loaded),
        Some(true)
    );

    // With nothing under the pointer X uses the cursor.
    let vm = h.app.view_model_mut().unwrap();
    vm.views.cursor = Some(main);
    h.press(Key::X);
    h.settle();
    let vm = h.app.view_model().unwrap();
    assert_eq!(vm.views.xrefs.references.as_ref().unwrap().address, main);
}

#[test]
fn navigations_bring_the_right_tab_forward() {
    let mut h = Harness::demo();
    let main = h.select("main");
    let vm = h.app.view_model_mut().unwrap();
    vm.goto_revealing(main + 8, Reveal::Graph);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::Graph));
    let vm = h.app.view_model_mut().unwrap();
    vm.graph_open(main);
    h.settle();
    assert!(is_front(h.app.dock(), Tab::Listing));
    let vm = h.app.view_model().unwrap();
    assert_eq!(
        vm.views.listing.selected_row().map(|r| r.address),
        Some(main)
    );
}

#[test]
fn strings_and_imports_tabs_load_their_lists() {
    let mut h = Harness::demo();
    h.select("main");
    for tab in [Tab::Strings, Tab::Symbols] {
        h.app.pending_nav().bring_to_front = Some(tab);
        h.settle();
        assert!(is_front(h.app.dock(), tab));
    }
    let vm = h.app.view_model().unwrap();
    assert!(vm.views.strings.loaded, "{:?}", vm.views.strings.error);
    assert!(vm.views.imports.loaded, "{:?}", vm.views.imports.error);
}

/// The tabs of the focused pane, in order, and which one is in front.
fn focused_pane(dock: &DockState<Tab>) -> (Vec<Tab>, usize) {
    let node = super::target_pane(dock).expect("a pane");
    let leaf = dock[node.surface][node.node].get_leaf().expect("a leaf");
    (leaf.tabs.clone(), leaf.active.0)
}

fn ctrl() -> Modifiers {
    Modifiers {
        ctrl: true,
        command: true,
        ..Modifiers::NONE
    }
}

impl Harness {
    fn press_with(&mut self, key: Key, modifiers: Modifiers) {
        for pressed in [true, false] {
            self.step_with(vec![Event::Key {
                key,
                physical_key: Some(key),
                pressed,
                repeat: false,
                modifiers,
            }]);
        }
    }
}

#[test]
fn tab_switching_wraps_around() {
    assert_eq!(cycled(4, 0, false), 1);
    assert_eq!(cycled(4, 3, false), 0);
    assert_eq!(cycled(4, 0, true), 3);
    assert_eq!(cycled(4, 2, true), 1);
    assert_eq!(cycled(0, 0, true), 0);
}

#[test]
fn ctrl_tab_and_ctrl_number_switch_dock_tabs() {
    let mut h = Harness::demo();
    h.settle();
    let (tabs, active) = focused_pane(h.app.dock());
    assert!(
        tabs.len() > 2,
        "the focused pane has several tabs: {tabs:?}"
    );

    h.press_with(Key::Tab, ctrl());
    let (_, now) = focused_pane(h.app.dock());
    assert_eq!(now, cycled(tabs.len(), active, false), "Ctrl+Tab goes on");

    h.press_with(
        Key::Tab,
        Modifiers {
            shift: true,
            ..ctrl()
        },
    );
    let (_, back) = focused_pane(h.app.dock());
    assert_eq!(back, active, "Ctrl+Shift+Tab goes back");

    h.press_with(Key::Num2, ctrl());
    assert_eq!(focused_pane(h.app.dock()).1, 1, "Ctrl+2 is the second tab");
    h.press_with(Key::Num1, ctrl());
    assert_eq!(focused_pane(h.app.dock()).1, 0, "Ctrl+1 is the first tab");
    h.press_with(Key::Num9, ctrl());
    assert_eq!(
        focused_pane(h.app.dock()).1,
        0,
        "a number past the last tab does nothing"
    );
}
