use std::path::PathBuf;

use eframe::Renderer;
use egui::{Id, Ui, ViewportCommand, WidgetText};
use egui_dock::{DockArea, DockState, Style, TabViewer};

struct Viewer;

impl TabViewer for Viewer {
    type Tab = String;

    fn id(&mut self, tab: &mut Self::Tab) -> Id {
        Id::new(tab)
    }

    fn title(&mut self, tab: &mut Self::Tab) -> WidgetText {
        tab.as_str().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        ui.heading(format!("KRAKEN spike: {tab}"));
        ui.label("hello from egui_dock");
    }
}

struct App {
    dock: DockState<String>,
    renderer: &'static str,
    screenshot: Option<PathBuf>,
    frames: u32,
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let style = Style::from_egui(ui.style().as_ref());
        DockArea::new(&mut self.dock)
            .style(style)
            .show_inside(ui, &mut Viewer);
        ui.label(format!("renderer: {}", self.renderer));

        self.frames += 1;
        let ctx = ui.ctx().clone();
        if let Some(path) = self.screenshot.clone() {
            if self.frames == 10 {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
            }
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(img) = shot {
                let rgba: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
                let [w, h] = img.size;
                match image::save_buffer(&path, &rgba, w as u32, h as u32, image::ColorType::Rgba8)
                {
                    Ok(()) => println!("screenshot saved: {} ({w}x{h})", path.display()),
                    Err(e) => eprintln!("screenshot failed: {e}"),
                }
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            ctx.request_repaint();
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut renderer = Renderer::default();
    let mut screenshot = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--renderer" => {
                renderer = match args.next().as_deref() {
                    Some("glow") => Renderer::Glow,
                    Some("wgpu") => Renderer::Wgpu,
                    other => anyhow::bail!("unknown renderer {other:?} (glow|wgpu)"),
                }
            }
            "--screenshot" => screenshot = args.next().map(PathBuf::from),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let name = match renderer {
        Renderer::Glow => "glow",
        Renderer::Wgpu => "wgpu",
    };
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default().with_inner_size([640.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "gui-hello",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(App {
                dock: DockState::new(vec!["Alpha".to_string(), "Beta".to_string()]),
                renderer: name,
                screenshot,
                frames: 0,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}
