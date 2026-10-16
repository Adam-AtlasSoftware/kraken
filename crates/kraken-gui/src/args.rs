//! Command-line options.

use std::path::PathBuf;

/// Which graphics backend to render with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererChoice {
    Glow,
    Wgpu,
}

/// What a screenshot shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scene {
    /// The demo project with `main` open (default).
    Main,
    /// The command palette with a query typed.
    Palette,
    /// The rename dialog.
    Rename,
    /// The welcome screen (no demo needed).
    Welcome,
    /// The control-flow graph next to the decompiler.
    Graph,
    /// The Assistant tab after a scripted conversation (hidden).
    Assistant,
    /// An "Explain" card (hidden).
    Explain,
    /// The name-review window (hidden).
    AutoName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub scene: Scene,
    pub renderer: RendererChoice,
    /// Open the demo project at startup.
    pub demo: bool,
    /// Render the demo, save a PNG and exit.
    pub screenshot: Option<PathBuf>,
    pub light: bool,
    /// Run the engine inside the GUI process instead of through `krakend`.
    pub no_daemon: bool,
    /// Open this project at startup (scripting and screenshots).
    pub open_project: Option<PathBuf>,
    /// Function a screenshot opens instead of `main` (hidden).
    pub function: Option<String>,
}

pub const USAGE: &str =
    "kraken-gui [--renderer glow|wgpu] [--demo | --no-daemon] [--light] [--screenshot <png> [--scene S]]

  --renderer R       graphics backend: wgpu (default) or glow
  --demo             open the built-in demo project at startup (fake engine, no daemon)
  --no-daemon        run the engine inside this window instead of through krakend
  --light            start with the light theme
  --screenshot FILE  with --demo or a hidden --open-project: select a function, render, save
                     FILE as a PNG and exit
  --scene S          what --screenshot shows: main (default), graph, palette, rename or welcome
  -h, --help         show this text";

#[derive(Debug)]
pub enum Parsed {
    Run(Options),
    Help,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Parsed, String> {
    let mut o = Options {
        scene: Scene::Main,
        renderer: RendererChoice::Wgpu,
        demo: false,
        screenshot: None,
        light: false,
        no_daemon: false,
        open_project: None,
        function: None,
    };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--demo" => o.demo = true,
            "--light" => o.light = true,
            "--no-daemon" => o.no_daemon = true,
            "--open-project" => {
                o.open_project = Some(PathBuf::from(
                    it.next().ok_or("--open-project needs a project folder")?,
                ));
            }
            "--function" => {
                o.function = Some(it.next().ok_or("--function needs a function name")?);
            }
            "--renderer" => {
                o.renderer = match it.next().as_deref() {
                    Some("glow") => RendererChoice::Glow,
                    Some("wgpu") => RendererChoice::Wgpu,
                    other => {
                        return Err(format!(
                            "--renderer needs `glow` or `wgpu`, got {}",
                            other.unwrap_or("nothing")
                        ));
                    }
                }
            }
            "--scene" => {
                o.scene = match it.next().as_deref() {
                    Some("main") => Scene::Main,
                    Some("palette") => Scene::Palette,
                    Some("rename") => Scene::Rename,
                    Some("welcome") => Scene::Welcome,
                    Some("graph") => Scene::Graph,
                    Some("assistant") => Scene::Assistant,
                    Some("explain") => Scene::Explain,
                    Some("autoname") => Scene::AutoName,
                    other => {
                        return Err(format!(
                            "--scene needs main, graph, palette, rename or welcome, got {}",
                            other.unwrap_or("nothing")
                        ));
                    }
                }
            }
            "--screenshot" => {
                o.screenshot = Some(PathBuf::from(
                    it.next().ok_or("--screenshot needs a file name")?,
                ));
            }
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if o.screenshot.is_some() && !o.demo && o.open_project.is_none() && o.scene != Scene::Welcome {
        return Err("--screenshot needs --demo".into());
    }
    if o.demo && o.open_project.is_some() {
        return Err("--demo and --open-project cannot be combined".into());
    }
    Ok(Parsed::Run(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_and_flags() {
        match p(&[]).unwrap() {
            Parsed::Run(o) => {
                assert_eq!(o.renderer, RendererChoice::Wgpu);
                assert!(!o.demo && !o.light && o.screenshot.is_none());
            }
            Parsed::Help => panic!(),
        }
        match p(&[
            "--renderer",
            "glow",
            "--demo",
            "--light",
            "--screenshot",
            "x.png",
        ])
        .unwrap()
        {
            Parsed::Run(o) => {
                assert_eq!(o.renderer, RendererChoice::Glow);
                assert!(o.demo && o.light);
                assert_eq!(o.screenshot, Some(PathBuf::from("x.png")));
            }
            Parsed::Help => panic!(),
        }
        assert!(matches!(p(&["--help"]).unwrap(), Parsed::Help));
    }

    #[test]
    fn daemon_flags() {
        match p(&["--no-daemon"]).unwrap() {
            Parsed::Run(o) => assert!(o.no_daemon && o.open_project.is_none()),
            Parsed::Help => panic!(),
        }
        match p(&["--open-project", "/p", "--screenshot", "a.png"]).unwrap() {
            Parsed::Run(o) => {
                assert_eq!(o.open_project, Some(PathBuf::from("/p")));
                assert!(!o.no_daemon);
            }
            Parsed::Help => panic!(),
        }
    }

    #[test]
    fn bad_input_is_explained() {
        assert!(p(&["--renderer", "metal"]).unwrap_err().contains("glow"));
        assert!(p(&["--renderer"]).is_err());
        assert!(p(&["--screenshot"]).is_err());
        assert!(
            p(&["--screenshot", "a.png"])
                .unwrap_err()
                .contains("--demo")
        );
        assert!(p(&["--nope"]).unwrap_err().contains("--nope"));
        assert!(p(&["--open-project"]).is_err());
        assert!(p(&["--demo", "--open-project", "/x"]).is_err());
        assert!(p(&["--scene", "x"]).unwrap_err().contains("palette"));
        assert!(p(&["--screenshot", "a.png", "--scene", "welcome"]).is_ok());
    }
}
