//! KRAKEN desktop GUI.

mod app;
mod args;
mod chrome;
mod engine;
mod fonts;
mod overlays;
mod style;
mod welcome;
mod workspace;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::anyhow;
use args::{Parsed, RendererChoice};

fn main() -> anyhow::Result<()> {
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
    let factory = engine::real_engine_factory();

    let size = if opts.screenshot.is_some() {
        [1440.0, 900.0]
    } else {
        [1360.0, 840.0]
    };
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("KRAKEN")
            .with_app_id("kraken-gui")
            .with_inner_size(size)
            .with_min_inner_size([900.0, 560.0]),
        renderer: match opts.renderer {
            RendererChoice::Glow => eframe::Renderer::Glow,
            RendererChoice::Wgpu => eframe::Renderer::Wgpu,
        },
        ..Default::default()
    };
    let rt_for_app = rt.clone();
    eframe::run_native(
        "KRAKEN",
        native,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            Ok(Box::new(app::KrakenApp::new(
                &cc.egui_ctx,
                rt_for_app,
                factory,
                &opts,
            )))
        }),
    )
    .map_err(|e| anyhow!("{e}"))
}
