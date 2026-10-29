//! KRAKEN desktop GUI.

mod activity;
mod ai_activity;
mod app;
mod args;
mod assist;
mod chrome;
mod fonts;
mod help;
mod history;
mod import;
mod infer;
mod integrations;
mod loading;
mod menu;
mod model_chip;
mod overlays;
mod panels;
mod private;
mod recent;
mod rewrite;
mod services;
mod settings;
mod setup_status;
mod style;
mod titlebar;
mod tour;
mod welcome;
mod workspace;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;

use std::sync::Arc;

use anyhow::anyhow;
use args::{Parsed, RendererChoice};

fn main() -> anyhow::Result<()> {
    // Hidden: act as the scripted ACP agent of the terminal-agent screenshot (see
    // `assist::agent_demo`).
    if std::env::args().nth(1).as_deref() == Some(assist::FAKE_AGENT_FLAG) {
        std::process::exit(assist::run_fake_agent());
    }
    let opts = match args::parse(std::env::args().skip(1)) {
        Ok(Parsed::Run(o)) => o,
        Ok(Parsed::Help) => {
            println!("{}", args::USAGE);
            return Ok(());
        }
        Err(e) => {
            eprintln!("kraken-gui: {e}\n\n{}", args::USAGE);
            std::process::exit(2);
        }
    };

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kraken-gui-worker")
            .enable_all()
            .build()?,
    );
    let services = services::Services::from_env(opts.no_daemon);

    let size = if opts.screenshot.is_some() {
        [1440.0, 900.0]
    } else {
        [1360.0, 840.0]
    };
    let custom_bar =
        opts.screenshot.is_none() && titlebar::custom_here(services.cfg.local_serving.titlebar);
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("KRAKEN")
            .with_app_id("kraken-gui")
            .with_icon(window_icon())
            .with_inner_size(size)
            .with_min_inner_size([900.0, 560.0])
            .with_decorations(!custom_bar)
            .with_transparent(false),
        renderer: match opts.renderer {
            RendererChoice::Glow => eframe::Renderer::Glow,
            RendererChoice::Wgpu => eframe::Renderer::Wgpu,
        },
        ..Default::default()
    };
    let rt_for_app = rt.clone();
    let mut services = Some(services);
    eframe::run_native(
        "KRAKEN",
        native,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            let services = services
                .take()
                .ok_or_else(|| anyhow!("the application was created twice"))?;
            Ok(Box::new(app::KrakenApp::new(
                &cc.egui_ctx,
                rt_for_app,
                services,
                &opts,
            )))
        }),
    )
    .map_err(|e| anyhow!("{e}"))
}

/// The window icon (taskbars that do not read the desktop entry, such as X11 and Windows ones).
fn window_icon() -> egui::IconData {
    let png = include_bytes!("../assets/kraken-icon.png");
    match image::load_from_memory(png) {
        Ok(img) => {
            let img = img.into_rgba8();
            let (width, height) = img.dimensions();
            egui::IconData {
                rgba: img.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}
