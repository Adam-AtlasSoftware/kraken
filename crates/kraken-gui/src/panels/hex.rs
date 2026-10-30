//! The Hex tab: raw program bytes, loaded a page at a time as the person scrolls.

use std::ops::Range;

use egui::{RichText, Ui};
use kraken_gui_widgets::{ByteSource, ByteState as WidgetState, HexView};
use kraken_viewmodel::{ByteCache, ByteState, ViewModel};

use super::PanelState;
use crate::style::{self, empty_state, pal};

/// The cache seen as the hex widget's byte source: `len` bytes starting at address `start`.
pub struct CacheSource<'a> {
    pub cache: &'a ByteCache,
    pub start: u64,
    pub len: u64,
}

impl ByteSource for CacheSource<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let left = self.len.saturating_sub(offset);
        let n = (buf.len() as u64).min(left) as usize;
        self.cache.read(self.start + offset, &mut buf[..n]);
        n
    }

    fn state(&self, offset: u64) -> WidgetState {
        match self.cache.state(self.start + offset) {
            ByteState::Ready => WidgetState::Ready,
            ByteState::Uninitialized => WidgetState::Uninitialized,
            ByteState::Loading => WidgetState::Pending,
            ByteState::Unmapped => WidgetState::Unmapped,
        }
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_memory_map();
    let Some(window) = vm.hex_window() else {
        empty_state(
            ui,
            "No bytes to show yet",
            "Select a function and its raw bytes appear here, as hexadecimal numbers and text.",
            Some("Use the list at the top to jump to any part of the program's memory."),
        );
        return;
    };

    let mut pick = None;
    ui.horizontal(|ui| {
        let m = &vm.views.memory;
        let current = vm
            .views
            .hex
            .block
            .and_then(|i| m.blocks.get(i))
            .map_or_else(|| "This function".to_string(), |b| b.name.clone());
        ui.label(RichText::new("Show").size(12.0).color(p.text_dim));
        egui::ComboBox::from_id_salt("hex_block")
            .selected_text(current)
            .width(150.0)
            .show_ui(ui, |ui| {
                for (i, b) in m.blocks.iter().enumerate() {
                    let on = vm.views.hex.block == Some(i);
                    if ui
                        .selectable_label(on, b.label())
                        .on_hover_text("Show this section of memory")
                        .clicked()
                    {
                        pick = Some(i);
                    }
                }
            })
            .response
            .on_hover_text(
                "Jump to a section of the program's memory, such as the code or the data",
            );
        if m.loading {
            ui.spinner();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let sel = vm.views.hex.selection.clone();
            let label = match &sel {
                Some(r) if r.end - r.start > 1 => {
                    format!("{} bytes at {:#x}", r.end - r.start, r.start)
                }
                Some(r) => format!("byte at {:#x}", r.start),
                None => String::new(),
            };
            if sel.is_some()
                && ui
                    .button("Patch selection")
                    .on_hover_text(
                        "Replace the selected bytes. Nothing on disk changes until you export",
                    )
                    .clicked()
            {
                vm.begin_patch_bytes();
            }
            if ui
                .button("Patch file offset...")
                .on_hover_text(
                    "Patch bytes by their offset in the file, for headers, padding or data the \
                     program does not map. Nothing on disk changes until you export",
                )
                .clicked()
            {
                vm.begin_patch_file_offset();
            }
            if sel.is_some()
                && ui
                    .button("Who refers here  (X)")
                    .on_hover_text("List everything that points at the selected byte")
                    .clicked()
            {
                vm.show_references(sel.map_or(window.start, |r| r.start), None);
            }
            ui.label(
                RichText::new(label)
                    .monospace()
                    .size(11.5)
                    .color(p.text_dim),
            );
        });
    });
    if let Some(i) = pick {
        vm.hex_select_block(i);
    }
    if let Some(e) = vm
        .views
        .memory
        .error
        .as_ref()
        .filter(|_| vm.views.memory.blocks.is_empty())
    {
        ui.label(
            RichText::new(format!("Showing only this function's bytes: {e}."))
                .size(11.5)
                .color(s.warning),
        );
    }
    ui.add_space(2.0);

    let window = vm.hex_window().unwrap_or(window);
    let scroll = vm
        .views
        .hex
        .take_scroll()
        .filter(|a| window.contains(a))
        .map(|a| a - window.start);
    let clip = |h: Range<u64>, c: egui::Color32| {
        let (a, b) = (h.start.max(window.start), h.end.min(window.end));
        (a < b).then(|| (a - window.start..b - window.start, c))
    };
    // Staged patches show over the bytes they replace (the view shows the bytes on disk).
    vm.ensure_patches();
    let patched = s.warning.gamma_multiply(0.55);
    // Later ranges paint over earlier ones: patches over the function highlight.
    let highlight: Vec<(Range<u64>, egui::Color32)> = vm
        .views
        .hex
        .highlight
        .iter()
        .filter_map(|h| clip(h.clone(), p.highlight))
        .chain(
            vm.tools
                .patches
                .items
                .iter()
                .filter(|it| !it.by_offset)
                .filter_map(|it| clip(it.range(), patched)),
        )
        .collect();
    let src = CacheSource {
        cache: &vm.views.bytes,
        start: window.start,
        len: window.end - window.start,
    };
    let mut view = HexView::new(&src, window.start)
        .id_salt(("hex", window.start))
        .highlights(&highlight);
    if let Some(off) = scroll {
        view = view.scroll_to(off);
    }
    let out = view.show(ui);
    if let Some(sel) = out.selection {
        let abs = window.start + sel.start..window.start + sel.end;
        if vm.views.hex.selection.as_ref() != Some(&abs) {
            vm.set_hex_selection(Some(abs));
        }
    }
    if let Some(h) = out.hovered {
        st.hot = Some(window.start + h);
    } else if let Some(sel) = &vm.views.hex.selection {
        st.hot.get_or_insert(sel.start);
    }
    vm.service_bytes();
}
