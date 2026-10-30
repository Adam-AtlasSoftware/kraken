//! The Import wizard walked through the whole app: an ELF program whose debug information is in
//! a separate file (found by the debug link, checked by CRC, a file of another build refused with
//! the reason), and an Intel HEX firmware image that needs a processor.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui_kittest::kittest::{NodeT, Queryable};
use kraken_viewmodel::AppAction;
use kraken_viewmodel::wizard::WizardFlow;

use super::options;
use super::shell::Kit;
use super::shell::{kit, kit_from};
use crate::import::Picked;
use crate::import_wizard::ImportStep;
use crate::welcome::Choice;

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn tool(name: &str, args: &[&std::ffi::OsStr]) -> bool {
    std::process::Command::new(name)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// `prog` (stripped, with a debug link) in `bin/`; `prog.debug` and a debug file of another build
/// in `dbg/`.
fn split_program(root: &Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (bin, dbg) = (root.join("bin"), root.join("dbg"));
    std::fs::create_dir_all(&bin).ok()?;
    std::fs::create_dir_all(&dbg).ok()?;
    let (src, o2) = (corpus("bin/pie_list-O0"), corpus("bin/pie_list-O2"));
    let (prog, debug, other) = (
        bin.join("prog"),
        dbg.join("prog.debug"),
        dbg.join("other.debug"),
    );
    let o = std::ffi::OsStr::new;
    let ok = tool(
        "objcopy",
        &[o("--only-keep-debug"), src.as_os_str(), debug.as_os_str()],
    ) && tool(
        "objcopy",
        &[o("--only-keep-debug"), o2.as_os_str(), other.as_os_str()],
    ) && tool(
        "strip",
        &[o("--strip-all"), o("-o"), prog.as_os_str(), src.as_os_str()],
    ) && tool(
        "objcopy",
        &[
            o(&format!("--add-gnu-debuglink={}", debug.display())),
            prog.as_os_str(),
        ],
    );
    ok.then_some((prog, debug, other))
}

fn until(k: &mut Kit, what: &str, cond: impl Fn(&mut Kit) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        k.h.run_steps(2);
        if cond(k) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn step(k: &Kit) -> ImportStep {
    k.h.state()
        .import_wizard()
        .expect("the wizard is open")
        .step()
}

fn next(k: &mut Kit) {
    k.h.get_by_label("Next").click();
    k.h.run_steps(3);
}

fn open_wizard(k: &mut Kit, path: &Path) {
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ImportProgram, &ctx);
    k.h.run_steps(3);
    assert_eq!(step(k), ImportStep::File);
    assert!(
        k.h.get_by_label("Next").accesskit_node().is_disabled(),
        "Next waits for a file"
    );
    k.h.state_mut().import_wizard_mut().unwrap().path = path.to_string_lossy().into_owned();
    k.h.run_steps(2);
    assert!(!k.h.get_by_label("Next").accesskit_node().is_disabled());
    next(k);
    assert_eq!(step(k), ImportStep::Kind);
}

#[test]
fn the_wizard_finds_checks_and_attaches_a_separate_debug_file() {
    let tmp = tempfile::Builder::new().prefix("wizard").tempdir().unwrap();
    let Some((prog, debug, other)) = split_program(tmp.path()) else {
        eprintln!("skipped: objcopy or strip is not available");
        return;
    };
    let mut services = crate::services::Services::offline();
    // the native engine runs inside the test process: no worker binary is built for tests
    services.cfg.native_in_process = true;
    let mut k = kit_from(services, &options(false), false);
    open_wizard(&mut k, &prog);

    // step 2: what it is, in words
    until(&mut k, "the probe", |k| {
        k.h.state()
            .import_wizard()
            .and_then(|w| w.dialog.as_ref())
            .is_some_and(|d| d.probed().is_some())
    });
    k.h.run_steps(3);
    assert!(has(&k, "What KRAKEN can do"));
    assert!(has(&k, "Function names"));
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Engine);
    next(&mut k);
    assert_eq!(
        step(&k),
        ImportStep::DebugInfo,
        "an ELF program has the step"
    );

    // step 5: the program names prog.debug, which is not beside it
    until(&mut k, "the debug probe", |k| {
        k.h.state()
            .import_wizard()
            .is_some_and(|w| w.debug.answer().is_some())
    });
    k.h.run_steps(3);
    assert!(has(&k, "prog.debug"));
    assert!(has(&k, "was not found"));
    assert!(has(&k, "Debug link"));
    assert_eq!(
        k.h.state().import_wizard().unwrap().debug_file(),
        None,
        "nothing to attach yet"
    );

    // a file of another build is refused, with the reason
    k.h.state()
        .import_wizard()
        .unwrap()
        .picker()
        .inject(Picked::DebugFile(other.to_string_lossy().into_owned()));
    until(&mut k, "the mismatch", |k| has(k, "Does not match"));
    assert!(has(&k, "another build"));
    assert_eq!(k.h.state().import_wizard().unwrap().debug_file(), None);

    // a folder that holds the right one: it matches and is used
    k.h.state()
        .import_wizard()
        .unwrap()
        .picker()
        .inject(Picked::DebugFolder(
            debug.parent().unwrap().to_string_lossy().into_owned(),
        ));
    until(&mut k, "the match", |k| has(k, "Matches"));
    assert!(has(&k, "Use this file"));
    let want = debug.canonicalize().unwrap().to_string_lossy().into_owned();
    assert_eq!(
        k.h.state().import_wizard().unwrap().debug_file().as_deref(),
        Some(want.as_str())
    );
    let w = k.h.state().import_wizard().unwrap();
    assert_eq!(
        w.blocker(),
        None,
        "engine {:?} {:?}",
        w.dialog.as_ref().map(|d| d.engine),
        w.dialog
            .as_ref()
            .and_then(|d| d.probed())
            .map(|p| p.engines.clone())
    );
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Analysis);

    // steps 6 and 7: the project goes where we say; the summary and the CLI box agree
    {
        let d =
            k.h.state_mut()
                .import_wizard_mut()
                .unwrap()
                .dialog
                .as_mut()
                .unwrap();
        d.name = "wizard-project".into();
        d.location = tmp.path().to_string_lossy().into_owned();
    }
    k.h.run_steps(2);
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Summary);
    assert!(has(&k, "separate file"));
    assert!(has(&k, "kraken project-create --binary"));
    assert!(has(&k, "--debug-file"));
    let w = k.h.state().import_wizard().unwrap();
    let cmds = w.commands();
    assert!(
        cmds[0].contains(&format!("--debug-file {want}")),
        "{cmds:?}"
    );
    assert_eq!(cmds[1], "kraken analyze");
    match w.choice() {
        Some(Choice::NewProject {
            debug_file, binary, ..
        }) => {
            assert_eq!(debug_file.as_deref(), Some(want.as_str()));
            assert_eq!(binary, prog.to_string_lossy());
        }
        other => panic!("{other:?}"),
    }
    assert!(
        !k.h.get_by_label("Create project")
            .accesskit_node()
            .is_disabled()
    );

    // Back walks the steps in reverse and Escape closes the wizard
    k.h.key_press_modifiers(egui::Modifiers::ALT, egui::Key::ArrowLeft);
    k.h.run_steps(3);
    assert_eq!(step(&k), ImportStep::Analysis, "Alt+Left goes back");
    k.h.get_by_label("Next").click();
    k.h.run_steps(8);
    assert_eq!(step(&k), ImportStep::Summary);
    k.h.get_by_label("Back").click();
    k.h.run_steps(3);
    assert_eq!(step(&k), ImportStep::Analysis);
    k.h.key_press(egui::Key::Escape);
    k.h.run_steps(3);
    assert!(k.h.state().import_wizard().is_none());
}

#[test]
fn a_firmware_image_asks_for_the_processor_and_skips_the_debug_step() {
    let mut k = kit(false);
    open_wizard(&mut k, &corpus("raw/fw_cortexm.hex"));
    until(&mut k, "the probe", |k| {
        k.h.state()
            .import_wizard()
            .and_then(|w| w.dialog.as_ref())
            .is_some_and(|d| d.probed().is_some())
    });
    k.h.run_steps(3);
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Engine);
    next(&mut k);
    assert_eq!(
        step(&k),
        ImportStep::Loader,
        "a record file needs a processor"
    );
    k.h.run_steps(3);
    assert!(has(&k, "only the processor"));
    {
        let w = k.h.state().import_wizard().unwrap();
        assert!(!w.steps().contains(&ImportStep::DebugInfo));
        assert_eq!(
            w.dialog.as_ref().unwrap().raw_load.language,
            "cortex-m",
            "the vector table suggests it"
        );
    }
    // without a processor the wizard says why it cannot go on
    k.h.state_mut()
        .import_wizard_mut()
        .unwrap()
        .dialog
        .as_mut()
        .unwrap()
        .raw_load
        .language
        .clear();
    k.h.run_steps(3);
    assert!(k.h.get_by_label("Next").accesskit_node().is_disabled());
    assert!(
        k.h.state()
            .import_wizard()
            .unwrap()
            .blocker()
            .unwrap()
            .contains("processor")
    );
    k.h.state_mut()
        .import_wizard_mut()
        .unwrap()
        .dialog
        .as_mut()
        .unwrap()
        .raw_load
        .language = "cortex-m".into();
    k.h.run_steps(3);
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Analysis);
    next(&mut k);
    assert_eq!(step(&k), ImportStep::Summary);
    let w = k.h.state().import_wizard().unwrap();
    match w.choice() {
        Some(Choice::NewProject {
            raw: Some(r),
            debug_file,
            ..
        }) => {
            assert!(r.records, "the file loads by its own format");
            assert_eq!(r.language, "cortex-m");
            assert_eq!(debug_file, None);
        }
        other => panic!("{other:?}"),
    }
    let cmd = &w.commands()[0];
    assert!(cmd.contains("--language cortex-m"), "{cmd}");
    assert!(!cmd.contains("--loader raw"), "{cmd}");
}

fn has(k: &Kit, text: &str) -> bool {
    k.h.query_all_by_label_contains(text).next().is_some()
}

/// `src` with the GNU build-id `[0x77; 20]` added.
fn with_build_id(src: &Path, dst: &Path) -> bool {
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&20u32.to_le_bytes());
    note.extend_from_slice(&3u32.to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(&[0x77; 20]);
    let note_path = dst.with_extension("note");
    std::fs::write(&note_path, &note).unwrap();
    std::process::Command::new("objcopy")
        .arg("--add-section")
        .arg(format!(".note.gnu.build-id={}", note_path.display()))
        .arg("--set-section-flags")
        .arg(".note.gnu.build-id=alloc,readonly")
        .arg(src)
        .arg(dst)
        .status()
        .is_ok_and(|s| s.success())
}

/// A debuginfod stand-in that serves `body` for `path` and 404 for everything else.
fn serve_debuginfod(path: String, body: Vec<u8>) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let text = String::from_utf8_lossy(&req).into_owned();
            let asked = text.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (status, data) = if asked == path {
                ("200 OK", body.clone())
            } else {
                ("404 Not Found", b"no".to_vec())
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                data.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&data);
        }
    });
    url
}

#[test]
fn the_wizard_searches_symbol_servers_only_after_consent_and_uses_what_it_finds() {
    let tmp = tempfile::Builder::new().prefix("wizsym").tempdir().unwrap();
    let prog = tmp.path().join("prog");
    let full = tmp.path().join("prog.full");
    if !with_build_id(&corpus("bin/stripped_calc-O0-stripped"), &prog)
        || !with_build_id(&corpus("bin/stripped_calc-O0"), &full)
    {
        eprintln!("skipped: objcopy is not available");
        return;
    }
    let cache = tmp.path().join("cache");
    // SAFETY: only this test reads the variable, and it is set before the wizard looks at it.
    unsafe {
        std::env::set_var("KRAKEN_DEBUGINFO_CACHE", &cache);
        std::env::remove_var("KRAKEN_OFFLINE");
    }
    let id = "77".repeat(20);
    let url = serve_debuginfod(
        format!("/buildid/{id}/debuginfo"),
        std::fs::read(&full).unwrap(),
    );
    let config = tmp.path().join("config.toml");

    let mut services = crate::services::Services::offline();
    services.cfg.native_in_process = true;
    let mut k = kit_from(services, &options(false), false);
    open_wizard(&mut k, &prog);
    until(&mut k, "the probe", |k| {
        k.h.state()
            .import_wizard()
            .and_then(|w| w.dialog.as_ref())
            .is_some_and(|d| d.probed().is_some())
    });
    next(&mut k);
    next(&mut k);
    assert_eq!(step(&k), ImportStep::DebugInfo);
    until(&mut k, "the debug probe", |k| {
        k.h.state()
            .import_wizard()
            .is_some_and(|w| w.debug.answer().is_some())
    });
    k.h.run_steps(3);
    assert!(has(&k, "Symbol servers"), "the search is offered");
    k.h.state_mut().import_wizard_mut().unwrap().config_path = Some(config.clone());
    k.h.state_mut()
        .import_wizard_mut()
        .unwrap()
        .set_search(&url, false);
    k.h.run_steps(3);
    assert!(
        k.h.get_by_label("Search symbol servers")
            .accesskit_node()
            .is_disabled(),
        "nothing can be sent before the consent box is ticked"
    );
    assert!(!config.exists() && !cache.exists());

    // the person ticks the box: the button works, the consent is recorded, the file arrives
    k.h.state_mut()
        .import_wizard_mut()
        .unwrap()
        .set_search(&url, true);
    k.h.run_steps(3);
    assert!(
        !k.h.get_by_label("Search symbol servers")
            .accesskit_node()
            .is_disabled()
    );
    k.h.get_by_label("Search symbol servers").click();
    until(&mut k, "the download", |k| has(k, "Matches"));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains("consent = true") && text.contains(&url),
        "{text}"
    );
    let file =
        k.h.state()
            .import_wizard()
            .unwrap()
            .debug_file()
            .expect("the downloaded file is used");
    assert!(file.contains(&id), "{file}");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        std::fs::read(&full).unwrap(),
        "the cached file is the one the server sent"
    );
}
