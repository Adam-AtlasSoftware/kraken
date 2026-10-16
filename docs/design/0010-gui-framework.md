# 0010. GUI framework

Status: Accepted
Date: 2026-10-15

## Context

An RE workbench needs many dockable panes: functions, disassembly, decompiler, hex, graph, history. It needs custom painting for graphs and code views. We want an all-Rust framework without a separate UI language.

## Decision

Use **egui** with **eframe** and **egui_dock** for docking. egui is pure Rust, has no DSL and allows custom painting.

**Version.** Pinned to egui and eframe 0.36 for now, because the latest egui_dock needs egui 0.36. We move to 0.37 when egui_dock supports it. A small patch is known to work. We use the eframe 0.36 APIs, such as `App::ui` and screenshots through `ViewportCommand::Screenshot`.

**Renderers.** Both glow (OpenGL) and wgpu are built in, with fallback at run time. This helps on machines with poor GPU drivers.

**Accessibility.** AccessKit is wired in. Platform support is limited by what AccessKit and eframe provide.

**Look.** egui needs a custom theme to look good. That is part of the GUI work.

**Testing.** GUI state lives in a headless view-model crate that is tested without egui. egui_kittest gives semantic assertions. Pixel snapshots run on one pinned Linux runner only. Smoke tests run under Xvfb in CI. The eframe `inspection` feature lets a tool read the UI tree and inject input, which helps GUI tests and agent-driven UI.

## Consequences

- One language and one build for the whole app.
- Immediate-mode UI makes custom views simple but needs care for large data.
- A pinned older version until the docking crate catches up.
- The look needs deliberate design work.

## Alternatives considered

- Slint: license-compatible and has an Android backend, but docking is weak.
- GPUI: desktop only, and less mature outside its home project.
- A web or Electron UI: a second language and runtime.
- Qt bindings: a large C++ dependency and a license to track.
