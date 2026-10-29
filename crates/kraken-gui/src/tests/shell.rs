//! The app shell: menu bar, import dialog, drag and drop, closing and the next-steps notice.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::{Key, Modifiers, RawInput, Rect, pos2};
use egui_kittest::kittest::{NodeT, Queryable};
use kraken_viewmodel::{AnalysisPhase, AppAction, Connection};

use super::{CTRL, Harness, options};
use crate::app::{KrakenApp, Pending};
use crate::import::Picked;
use crate::services::Services;

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

#[derive(Debug)]
struct TestDrop(PathBuf);

impl egui::DroppedFile for TestDrop {
    fn path(&self) -> &Path {
        &self.0
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        std::fs::read(&self.0).map_err(|e| e.to_string())
    }
}

impl Harness {
    fn step_raw(&mut self, mut input: RawInput) {
        input.screen_rect = Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1280.0, 800.0)));
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(input, |ui| app.frame(ui));
        out.textures_delta.clear();
    }

    fn drop_file(&mut self, path: &Path) {
        let input = RawInput {
            dropped_files: vec![Arc::new(TestDrop(path.to_path_buf()))],
            ..Default::default()
        };
        self.step_raw(input);
    }

    fn wait_for_probe(&mut self) {
        self.run_until("the probe", |a| {
            a.import_dialog().is_some_and(|d| d.probed().is_some())
        });
    }
}

/// The whole app in an egui_kittest harness, so widgets can be found by their labels.
pub(super) struct Kit {
    pub(super) h: egui_kittest::Harness<'static, KrakenApp>,
    _rt: Arc<tokio::runtime::Runtime>,
}

pub(super) fn kit(demo: bool) -> Kit {
    kit_with(demo, false)
}

/// `gpu` renders with wgpu so `render()` gives a picture (documentation screenshots).
pub(super) fn kit_with(demo: bool, gpu: bool) -> Kit {
    kit_from(Services::offline(), &options(demo), gpu)
}

/// A harness over the app built from `services` and `opts`.
pub(super) fn kit_from(services: Services, opts: &crate::args::Options, gpu: bool) -> Kit {
    kit_sized(services, opts, gpu, [1280.0, 800.0])
}

/// [`kit_from`] on a screen of `size` points.
pub(super) fn kit_sized(
    services: Services,
    opts: &crate::args::Options,
    gpu: bool,
    size: [f32; 2],
) -> Kit {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let ctx = egui::Context::default();
    let app = KrakenApp::new(&ctx, rt.clone(), services, opts);
    let mut fonts_done = false;
    let builder = egui_kittest::Harness::builder().with_size(size);
    let builder = if gpu { builder.wgpu() } else { builder };
    let h = builder.build_ui_state(
        move |ui, app: &mut KrakenApp| {
            // The first frame runs inside the builder, before the fonts can be installed: it
            // draws nothing.
            if !fonts_done {
                crate::fonts::install(ui.ctx());
                fonts_done = true;
                return;
            }
            app.frame(ui);
        },
        app,
    );
    Kit { h, _rt: rt }
}

#[test]
fn the_welcome_screen_has_a_file_and_help_menu_only() {
    let mut k = kit(false);
    k.h.run_steps(3);
    assert!(k.h.query_by_label("File").is_some());
    assert!(k.h.query_by_label("Help").is_some());
    assert!(k.h.query_by_label("Analysis").is_none());
    k.h.get_by_label("File").click();
    k.h.run_steps(3);
    assert!(k.h.query_by_label_contains("Open program...").is_some());
    assert!(k.h.query_by_label_contains("Close project").is_some());
    k.h.get_by_label("Help").click();
    k.h.run_steps(3);
    k.h.get_by_label_contains("Keyboard shortcuts").click();
    k.h.run_steps(3);
    assert!(k.h.state().shortcuts_open());
    assert!(k.h.query_by_label("What it does").is_some());
}

#[test]
fn an_open_project_gets_every_menu_and_menu_items_run_actions() {
    let mut k = kit(true);
    for _ in 0..2000 {
        k.h.run_steps(1);
        let ready = k.h.state().view_model().is_some_and(|vm| {
            vm.connection == Connection::Open && vm.analysis.phase == AnalysisPhase::Complete
        });
        if ready {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    k.h.run_steps(2);
    for m in [
        "File", "Edit", "View", "Navigate", "Analysis", "Rewrite", "AI", "Help",
    ] {
        assert!(k.h.query_by_label(m).is_some(), "{m} menu");
    }
    k.h.get_by_label("Help").click();
    k.h.run_steps(2);
    k.h.get_by_label_contains("User guide").click();
    k.h.run_steps(2);
    let url =
        k.h.state()
            .opened_url()
            .expect("the guide was opened")
            .to_string();
    assert!(url.contains("docs"), "{url}");
}

#[test]
fn the_import_dialog_probes_and_enables_import_for_a_program() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    let bin = corpus("bin/pie_list-O0");
    k.h.state_mut().open_path(&bin, &ctx);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h
            .state()
            .import_dialog()
            .is_some_and(|d| d.probed().is_some())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    k.h.run_steps(2);
    assert!(
        k.h.query_by_label_contains("Linux program (x86-64")
            .is_some()
    );
    assert!(
        k.h.query_by_label_contains("Analyze after import")
            .is_some()
    );
    let import = k.h.get_by_label("Import");
    assert!(
        !import.accesskit_node().is_disabled(),
        "Import is enabled for a program"
    );
    k.h.get_by_label("Cancel").click();
    k.h.run_steps(2);
    assert!(k.h.state().import_dialog().is_none());
}

#[test]
fn the_import_dialog_lists_the_members_of_a_static_library() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().open_path(&corpus("lib/bin/libkr.a"), &ctx);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h
            .state()
            .import_dialog()
            .is_some_and(|d| d.probed().is_some())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    k.h.run_steps(2);
    assert!(
        k.h.query_by_label_contains("Linux static library with 2 objects")
            .is_some()
    );
    assert!(
        k.h.query_by_label_contains("All 2 members are loaded together")
            .is_some()
    );
    // the member list opens on a click and is read-only text
    k.h.get_by_label_contains("Members (2)").click();
    k.h.run_steps(2);
    assert!(k.h.query_by_label("kr_text.o").is_some());
    // Ghidra does not read archives, so its choice is off
    let ghidra = k.h.get_by_label("Ghidra");
    assert!(ghidra.accesskit_node().is_disabled());
}

#[test]
fn the_import_dialog_keeps_import_disabled_for_a_text_file() {
    let tmp = crate::testutil::tempdir();
    let txt = tmp.path().join("notes.txt");
    std::fs::write(&txt, b"not a program").unwrap();
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().open_path(&txt, &ctx);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h
            .state()
            .import_dialog()
            .is_some_and(|d| d.probed().is_some())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    k.h.run_steps(2);
    assert!(
        k.h.query_all_by_label_contains("does not recognise")
            .next()
            .is_some()
    );
    assert!(k.h.get_by_label("Import").accesskit_node().is_disabled());
}

#[test]
fn a_dropped_program_opens_the_import_dialog_and_a_plain_folder_is_explained() {
    let mut h = Harness::new(false);
    h.step();
    h.drop_file(&corpus("pe/bin/switch_vm-x64-O0.exe"));
    h.wait_for_probe();
    let d = h.app.import_dialog().unwrap();
    assert_eq!(
        d.probed().unwrap().format,
        kraken_registry::commands::BinaryFormat::Pe
    );
    assert_eq!(d.name, "switch_vm-x64-O0_exe");

    let mut h = Harness::new(false);
    let tmp = crate::testutil::tempdir();
    h.drop_file(tmp.path());
    assert!(h.app.import_dialog().is_none());
    assert!(
        h.app
            .welcome_error()
            .is_some_and(|e| e.contains("not a KRAKEN project"))
    );
}

#[test]
fn a_dropped_project_folder_is_opened() {
    let mut h = Harness::new(false);
    let tmp = crate::testutil::tempdir();
    std::fs::write(tmp.path().join("meta.json"), b"{}").unwrap();
    h.drop_file(tmp.path());
    // No daemon in this test: opening is attempted and fails with the daemon message.
    h.run_until("the open attempt", |a| {
        a.welcome_error()
            .is_some_and(|e| e.contains("Could not reach"))
    });
}

#[test]
fn hovering_files_shows_the_drop_overlay() {
    let mut h = Harness::new(false);
    let input = RawInput {
        hovered_files: vec![egui::HoveredFile {
            path: Some(corpus("bin/pie_list-O0")),
            mime: String::new(),
        }],
        ..Default::default()
    };
    // Drawing the overlay must not disturb the screen under it.
    h.step_raw(input);
    h.step();
    assert!(crate::app::DROP_TEXT.contains("Drop a program"));
    assert!(h.app.import_dialog().is_none());
}

#[test]
fn ctrl_o_style_picks_reach_the_import_dialog_and_the_open_path() {
    let mut h = Harness::new(false);
    h.app.picker().inject(Picked::Binary(
        corpus("bin/pie_list-O0").to_string_lossy().into(),
    ));
    h.step();
    let d = h.app.import_dialog().expect("the import dialog");
    assert!(d.binary.ends_with("pie_list-O0"));
}

#[test]
fn ctrl_w_closes_the_demo_and_returns_to_the_welcome_screen() {
    let mut h = Harness::ready_demo();
    assert!(h.app.next_steps().is_some(), "the next-steps notice shows");
    h.key(Key::W, CTRL);
    h.step();
    assert!(h.app.view_model().is_none());
    assert!(h.app.next_steps().is_none());
    h.step();
}

#[test]
fn closing_while_analysis_runs_asks_first() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.view_model_mut().unwrap().analysis.phase = AnalysisPhase::Running;
    h.app.dispatch(AppAction::CloseProject, &ctx);
    assert_eq!(h.app.confirming(), Some(&Pending::Close));
    h.step();
    h.step();
    assert!(
        h.app.view_model().is_some(),
        "nothing closes before the answer"
    );
    h.key(Key::Escape, Modifiers::NONE);
    h.step();
    assert!(h.app.confirming().is_none());
    assert!(h.app.view_model().is_some());
}

#[test]
fn next_steps_open_main_and_the_rewrite_wizard() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    h.app.dispatch(AppAction::GoToMain, &ctx);
    h.run_until("main to open", |a| {
        a.view_model()
            .and_then(|vm| vm.current.as_ref())
            .is_some_and(|c| c.name == "main")
    });
    h.app.dispatch(AppAction::RewriteWizard, &ctx);
    assert!(h.app.view_model().is_some_and(|vm| vm.rewrite.wizard.open));
}

#[test]
fn ctrl_slash_opens_the_shortcut_list_on_the_welcome_screen() {
    let mut h = Harness::new(false);
    h.key(Key::Slash, CTRL);
    h.step();
    assert!(h.app.shortcuts_open());
    h.key(Key::Escape, Modifiers::NONE);
    assert!(!h.app.shortcuts_open());
}

#[test]
fn the_import_dialog_offers_a_raw_binary_for_firmware() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    let bin = corpus("raw/fw_cortexm.bin");
    k.h.state_mut().open_path(&bin, &ctx);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h
            .state()
            .import_dialog()
            .is_some_and(|d| d.probed().is_some())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    k.h.run_steps(3);
    // the raw section is there instead of a dead end, filled in from the vector table
    assert!(
        k.h.query_by_label_contains("Import as a raw binary")
            .is_some()
    );
    assert!(k.h.query_by_label_contains("(high confidence)").is_some());
    assert!(k.h.query_by_label_contains("Base address").is_some());
    let d = k.h.state().import_dialog().unwrap();
    assert!(d.raw_active());
    assert_eq!(d.raw_load.language, "cortex-m");
    assert_eq!(d.raw_load.base, "0x8000000");
    assert_eq!(d.raw_load.entry, "0x80000dd");
    assert!(
        !k.h.get_by_label("Import").accesskit_node().is_disabled(),
        "{:?}",
        d.blocker()
    );
    match d.choice() {
        Some(crate::welcome::Choice::NewProject { raw: Some(r), .. }) => {
            assert_eq!(r.language, "cortex-m");
        }
        other => panic!("{other:?}"),
    }

    // without a processor Import is off and says why
    k.h.state_mut()
        .import_dialog_mut()
        .unwrap()
        .raw_load
        .language
        .clear();
    k.h.run_steps(2);
    assert!(k.h.get_by_label("Import").accesskit_node().is_disabled());
    assert!(
        k.h.state()
            .import_dialog()
            .unwrap()
            .blocker()
            .unwrap()
            .contains("processor")
    );
    // a bad number is named
    let d = k.h.state_mut().import_dialog_mut().unwrap();
    d.raw_load.language = "arm".into();
    d.raw_load.base = "zzz".into();
    assert!(d.blocker().unwrap().contains("Base address"));
}
