# S1 spike notes: rmcp + eframe

Date: 2026-10-15. Host: Arch x86_64, rustc/cargo 1.99.0.

## Pinned versions (exact)

| crate | version | note |
|---|---|---|
| rmcp | =3.5.1 | features `server macros transport-io`; dev: `client transport-child-process` |
| schemars | =1.2.3 | 1.x (not 0.8); rmcp 3.5.1 re-exports it |
| tokio | =1.53.3 | features `macros rt-multi-thread io-std` |
| eframe | =0.36.2 | NOT 0.37, see below |
| egui | =0.36.2 | |
| egui_dock | =0.21.1 | latest on crates.io; depends on egui `0.36` |
| image | 0.25 | png only, for writing screenshots |

## Key finding: egui_dock 0.21.1 does not support egui 0.37

crates.io latest egui_dock is 0.21.1 (2026-08-06) and its upstream HEAD still depends on egui/eframe
`0.36`. With eframe/egui 0.37.0 cargo pulls two egui versions and the `TabViewer`/`DockArea` types
mismatch. Options:

1. (chosen, in `spikes/gui-hello`) pin eframe/egui 0.36.2 + egui_dock 0.21.1.
2. Vendor/fork egui_dock with deps bumped to 0.37. Verified in `~/.cache/kraken-dev/exp`: bump the two
   `version = "0.36"` lines in egui_dock/Cargo.toml and change one line in
   `src/widgets/dock_area/show/window_surface.rs` (`format!(..).into()` for `Id` becomes
   `egui::Id::new(format!(..))`, since `Id: From<String>` is gone). Builds and runs (wgpu); only
   deprecation warnings (`Id::new` deprecated in 0.37 in favour of `Id::unique` / `IdSalt::new`).
   Alternatively wait for upstream or use egui_tiles.

The seed plan says "egui 0.37"; decide between 1 and 2 before T-cards that touch the GUI.

## rmcp 3.5.1 API notes

- Minimal server: `#[tool_router(server_handler)] impl Echo { #[tool(description = "..")] fn echo(&self,
  Parameters(args): Parameters<EchoArgs>) -> String }`. The `server_handler` flag generates the
  `ServerHandler` impl (no separate `#[tool_handler]` / `get_info` needed; tools capability enabled).
- Serve: `Echo.serve(rmcp::transport::stdio()).await?.waiting().await?` (`ServiceExt`).
- Input type derives `serde::Deserialize + schemars::JsonSchema`; doc comments become schema descriptions.
- Server info type is `ServerConfig` (older SDKs: `ServerInfo`); call params are builder-style:
  `CallToolRequestParams::new("echo").with_arguments(json_object)`.
- Client over child process: `().serve(TokioChildProcess::new(Command::new(bin).configure(|_| {}))?)`
  (`transport::ConfigureCommandExt`); `client.list_all_tools()`, `client.call_tool(..)`, `client.cancel()`.
  `().serve` (unit ClientHandler) is enough for a test client.
- `tools[0].input_schema` is `Arc<JsonObject>`; deref to serialize.
- Test uses `env!("CARGO_BIN_EXE_mcp-echo")` to locate the server binary; no npx needed.
- Server must never print to stdout (it is the transport).

## eframe/egui 0.36 API notes (differences from older docs)

- `eframe::App` has `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut Frame)` (required) plus optional
  `logic(ctx, frame)`; there is no `update(ctx, frame)` any more. The root `Ui` has no margin or
  background; wrap in `CentralPanel` if you want them. egui_dock: `DockArea::new(&mut state)
  .style(Style::from_egui(ui.style().as_ref())).show_inside(ui, &mut viewer)`.
- Features: `default-features = false` with `glow`, `wgpu`, `x11`, `wayland`, `default_fonts` builds both
  renderers into one binary; select at runtime with `NativeOptions { renderer: Renderer::Glow | Wgpu }`.
  `Renderer` variants only exist when the matching feature is on. eframe default features include
  `wgpu` but NOT `glow`.
- Screenshot, 0.36: `ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()))`, result
  arrives next frame as `egui::Event::Screenshot { image: Arc<ColorImage>, .. }` in `ctx.input(|i| i.events)`.
  In 0.37 this changes to `ctx.request_screenshot(|Arc<ColorImage>| ..)` (`ScreenshotCallback`).
- eframe 0.37 features list also has `inspection` (egui_inspection) for the MCP/UI-tree idea; not tried.

## Verification

- MCP: `cargo test` in spikes/mcp-echo passes (lists one tool `echo`, schema has `message: string`,
  call returns the same text).
- GUI: both `--renderer glow` and `--renderer wgpu` build in one binary and ran and produced a 640x400
  screenshot (two tabs "Alpha" / "Beta" shown). `xvfb-run`/`Xvfb` are NOT installed; the run used the live
  Wayland session (WAYLAND_DISPLAY=wayland-0, DISPLAY=:0 via Xwayland), so a window briefly appeared on
  the desktop. CI will need `xvfb` (or a headless compositor) for GUI smoke tests.
  Run: `cargo run -- --renderer wgpu --screenshot out.png` (the app exits after saving).
- `cargo fmt` and `cargo clippy --all-targets -D warnings` clean in both spikes.
- Root workspace: `exclude = ["spikes"]` works; each spike has its own empty `[workspace]` table.
