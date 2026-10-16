//! Fixed-row-height virtualised list with a selected index and keyboard navigation.

use egui::{Id, Key, Modifiers, Rect, Sense, Ui, UiBuilder, Vec2};

use crate::theme::KrakenTheme;

/// Keyboard navigation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
}

/// New selection after a navigation key; `None` when the list is empty.
pub fn navigate(current: Option<usize>, nav: Nav, len: usize, page: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    let page = page.max(1);
    let cur = current.map(|c| c.min(last));
    Some(match (nav, cur) {
        (Nav::Home, _) => 0,
        (Nav::End, _) => last,
        (Nav::Down | Nav::PageDown, None) => 0,
        (Nav::Up | Nav::PageUp, None) => last,
        (Nav::Up, Some(c)) => c.saturating_sub(1),
        (Nav::Down, Some(c)) => (c + 1).min(last),
        (Nav::PageUp, Some(c)) => c.saturating_sub(page),
        (Nav::PageDown, Some(c)) => (c + page).min(last),
    })
}

/// Scroll offset that brings `index` fully into view, or `None` if it already is.
pub fn scroll_for_selection(
    index: usize,
    row_pitch: f32,
    offset: f32,
    viewport_h: f32,
) -> Option<f32> {
    let top = index as f32 * row_pitch;
    let bottom = top + row_pitch;
    if top < offset {
        Some(top)
    } else if bottom > offset + viewport_h {
        Some((bottom - viewport_h).max(0.0))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ScrollMemo {
    offset: f32,
    viewport_h: f32,
    pending: Option<usize>,
}

/// What happened in a [`VirtualList::show`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtualListResponse {
    /// Row clicked this frame.
    pub clicked: Option<usize>,
    /// Row double-clicked this frame.
    pub double_clicked: Option<usize>,
    /// Selection changed this frame (click or keyboard).
    pub changed: bool,
}

/// A list of `len` rows of `row_height` points; only visible rows are built.
pub struct VirtualList {
    id: Id,
    len: usize,
    row_height: f32,
    scroll_to: Option<usize>,
}

impl VirtualList {
    pub fn new(
        id_salt: impl std::hash::Hash + std::fmt::Debug,
        len: usize,
        row_height: f32,
    ) -> Self {
        Self {
            id: Id::new("kraken_vlist").with(id_salt),
            len,
            row_height,
            scroll_to: None,
        }
    }

    /// Scroll the given row into view this frame.
    pub fn scroll_to(mut self, index: usize) -> Self {
        self.scroll_to = Some(index);
        self
    }

    /// Shows the list. `add_row` paints row `index` into `ui`, which is exactly one row tall
    /// and already carries the selection / hover background.
    pub fn show(
        self,
        ui: &mut Ui,
        selected: &mut Option<usize>,
        mut add_row: impl FnMut(&mut Ui, usize, bool),
    ) -> VirtualListResponse {
        let palette = KrakenTheme::from_ctx(ui.ctx()).palette();
        let id = ui.make_persistent_id(self.id);
        let mut memo: ScrollMemo = ui.data(|d| d.get_temp(id)).unwrap_or_default();
        let mut out = VirtualListResponse::default();
        let pitch = self.row_height;

        let focused = ui.memory(|m| m.has_focus(id));
        let hovered = ui.rect_contains_pointer(ui.available_rect_before_wrap());
        if (focused || hovered) && self.len > 0 {
            let page = ((memo.viewport_h / pitch).floor() as usize).saturating_sub(1);
            let keys = [
                (Key::ArrowUp, Nav::Up),
                (Key::ArrowDown, Nav::Down),
                (Key::PageUp, Nav::PageUp),
                (Key::PageDown, Nav::PageDown),
                (Key::Home, Nav::Home),
                (Key::End, Nav::End),
            ];
            for (key, nav) in keys {
                if ui.input_mut(|i| i.consume_key(Modifiers::NONE, key)) {
                    let next = navigate(*selected, nav, self.len, page);
                    if next != *selected {
                        *selected = next;
                        out.changed = true;
                    }
                    memo.pending = *selected;
                }
            }
        }
        if let Some(i) = self.scroll_to {
            memo.pending = Some(i);
        }

        let mut area = egui::ScrollArea::vertical()
            .id_salt(id.with("scroll"))
            .auto_shrink([false, false]);
        // The viewport is unknown on the first frame; wait one frame instead of guessing.
        if memo.viewport_h > 0.0
            && let Some(idx) = memo.pending.take()
            && let Some(off) = scroll_for_selection(idx, pitch, memo.offset, memo.viewport_h)
        {
            area = area.vertical_scroll_offset(off);
        }

        let spacing_y = ui.spacing().item_spacing.y;
        // The rows are laid out without spacing, so the scroll area must count them that way too.
        ui.spacing_mut().item_spacing.y = 0.0;
        let output = area.show_rows(ui, pitch, self.len, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let width = ui.available_width();
            for index in range {
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, pitch), Sense::click());
                let is_sel = *selected == Some(index);
                if is_sel {
                    ui.painter().rect_filled(rect, 0.0, palette.selection);
                    let bar = Rect::from_min_size(rect.min, Vec2::new(2.0, pitch));
                    ui.painter().rect_filled(bar, 0.0, palette.accent);
                } else if resp.hovered() {
                    ui.painter().rect_filled(rect, 0.0, palette.row_hover);
                }
                let mut child = ui.new_child(
                    UiBuilder::new()
                        .max_rect(rect.shrink2(Vec2::new(8.0, 0.0)))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                add_row(&mut child, index, is_sel);
                if resp.clicked() {
                    ui.memory_mut(|m| m.request_focus(id));
                    if *selected != Some(index) {
                        *selected = Some(index);
                        out.changed = true;
                    }
                    out.clicked = Some(index);
                }
                if resp.double_clicked() {
                    out.double_clicked = Some(index);
                }
            }
        });
        ui.spacing_mut().item_spacing.y = spacing_y;
        memo.offset = output.state.offset.y;
        memo.viewport_h = output.inner_rect.height();
        ui.data_mut(|d| d.insert_temp(id, memo));
        // Keep focus-capable state so arrow keys keep working after a click.
        ui.interact(output.inner_rect, id, Sense::focusable_noninteractive());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_clamps() {
        assert_eq!(navigate(None, Nav::Down, 10, 5), Some(0));
        assert_eq!(navigate(None, Nav::Up, 10, 5), Some(9));
        assert_eq!(navigate(Some(0), Nav::Up, 10, 5), Some(0));
        assert_eq!(navigate(Some(9), Nav::Down, 10, 5), Some(9));
        assert_eq!(navigate(Some(3), Nav::PageDown, 10, 5), Some(8));
        assert_eq!(navigate(Some(8), Nav::PageDown, 10, 5), Some(9));
        assert_eq!(navigate(Some(2), Nav::PageUp, 10, 5), Some(0));
        assert_eq!(navigate(Some(4), Nav::Home, 10, 5), Some(0));
        assert_eq!(navigate(Some(4), Nav::End, 10, 5), Some(9));
        assert_eq!(navigate(Some(50), Nav::Up, 10, 5), Some(8));
        assert_eq!(navigate(Some(1), Nav::Down, 0, 5), None);
        assert_eq!(navigate(Some(1), Nav::PageDown, 100_000, 0), Some(2));
    }

    #[test]
    fn scroll_only_when_needed() {
        // viewport shows rows 10..20 (pitch 10, offset 100, height 100)
        assert_eq!(scroll_for_selection(12, 10.0, 100.0, 100.0), None);
        assert_eq!(scroll_for_selection(9, 10.0, 100.0, 100.0), Some(90.0));
        assert_eq!(scroll_for_selection(20, 10.0, 100.0, 100.0), Some(110.0));
        assert_eq!(scroll_for_selection(0, 10.0, 0.0, 100.0), None);
    }
}
