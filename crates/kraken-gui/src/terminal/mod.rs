//! The Terminal tab: the person's own shell in a real terminal, as a terminal emulator gives it.
//!
//! `alacritty_terminal` does the work of a terminal: it starts the shell on a pseudo-terminal
//! (the login shell from the user database, or `$SHELL`; ConPTY on Windows) with the person's
//! environment, reads its output on its own thread and keeps the screen, the scrollback and the
//! modes programs set. This module draws that screen and turns keys, pastes and the mouse into
//! what the program expects, as xterm does: full-screen programs, colours, mouse reporting,
//! bracketed paste and the alternate screen all work.

mod keys;

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use alacritty_terminal::event::{Event as TermEvent, EventListener, WindowSize};
use alacritty_terminal::event_loop::{EventLoop, EventLoopSender, Msg};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::sync::FairMutex;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::tty;
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Rgb};
use egui::{Color32, FontId, Id, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2, pos2, vec2};

pub use keys::{MouseButton, key_bytes, mouse_bytes, paste_bytes};

use crate::style::pal;

/// Lines kept above the screen.
const SCROLLBACK: usize = 10_000;
/// Text size of the terminal.
const FONT_SIZE: f32 = 13.0;

/// Passes the terminal's events on and wakes the window.
#[derive(Clone)]
struct Proxy {
    tx: Sender<TermEvent>,
    ctx: egui::Context,
}

impl EventListener for Proxy {
    fn send_event(&self, event: TermEvent) {
        let _ = self.tx.send(event);
        self.ctx.request_repaint();
    }
}

/// The size of the screen in cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Size {
    cols: usize,
    lines: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// One shell.
pub struct Session {
    id: u64,
    title: String,
    term: Arc<FairMutex<Term<Proxy>>>,
    loop_tx: EventLoopSender,
    events: Receiver<TermEvent>,
    size: Size,
    cell: Vec2,
    /// How the shell ended, once it has.
    ended: Option<String>,
    focused: bool,
    /// A mouse button held for a mouse report.
    held: Option<MouseButton>,
    /// Wheel movement not yet a whole line.
    scroll_lines: f32,
}

/// What to start: the person's shell, or a given program (tests).
#[derive(Debug, Clone, Default)]
pub struct Launch {
    pub program: Option<(String, Vec<String>)>,
    pub cwd: Option<PathBuf>,
}

impl Session {
    /// Starts a shell; `size` is the first guess of the screen, corrected when it is drawn.
    pub fn start(ctx: &egui::Context, id: u64, launch: &Launch) -> std::io::Result<Session> {
        let size = Size {
            cols: 80,
            lines: 24,
        };
        let (tx, events) = channel();
        let proxy = Proxy {
            tx,
            ctx: ctx.clone(),
        };
        let mut env = std::collections::HashMap::new();
        // What a modern terminal announces; programs choose their colours and keys by it.
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        env.insert("COLORTERM".to_string(), "truecolor".to_string());
        env.insert("TERM_PROGRAM".to_string(), "KRAKEN".to_string());
        env.insert(
            "TERM_PROGRAM_VERSION".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        let options = tty::Options {
            shell: launch
                .program
                .as_ref()
                .map(|(p, a)| tty::Shell::new(p.clone(), a.clone())),
            working_directory: launch.cwd.clone(),
            drain_on_exit: true,
            env,
            #[cfg(windows)]
            escape_args: true,
        };
        let window = WindowSize {
            num_lines: size.lines as u16,
            num_cols: size.cols as u16,
            cell_width: 8,
            cell_height: 16,
        };
        let pty = tty::new(&options, window, id)?;
        let config = Config {
            scrolling_history: SCROLLBACK,
            ..Config::default()
        };
        let term = Arc::new(FairMutex::new(Term::new(config, &size, proxy.clone())));
        let event_loop = EventLoop::new(term.clone(), proxy, pty, true, false)?;
        let loop_tx = event_loop.channel();
        event_loop.spawn();
        Ok(Session {
            id,
            title: "Terminal".to_string(),
            term,
            loop_tx,
            events,
            size,
            cell: vec2(8.0, 16.0),
            ended: None,
            focused: false,
            held: None,
            scroll_lines: 0.0,
        })
    }

    /// Sends bytes to the program.
    pub fn write(&self, bytes: impl Into<Cow<'static, [u8]>>) {
        let _ = self.loop_tx.send(Msg::Input(bytes.into()));
    }

    /// What the screen shows, line by line (tests).
    #[cfg(test)]
    pub fn screen_text(&self) -> String {
        let term = self.term.lock();
        let grid = term.grid();
        let mut out = String::new();
        for line in 0..grid.screen_lines() {
            let row = &grid[Line(line as i32)];
            let text: String = (0..grid.columns()).map(|c| row[Column(c)].c).collect();
            out.push_str(text.trim_end());
            out.push('\n');
        }
        out
    }

    /// True once the shell has ended.
    pub fn ended(&self) -> bool {
        self.ended.is_some()
    }

    /// Takes what the terminal reported since the last frame.
    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                TermEvent::Title(t) => self.title = t,
                TermEvent::ResetTitle => self.title = "Terminal".to_string(),
                // Answers the terminal owes the program (cursor position, device attributes).
                TermEvent::PtyWrite(s) => self.write(s.into_bytes()),
                // A program may put text on the clipboard (OSC 52), as in other terminals; it
                // may not read it back, which would hand it whatever was copied elsewhere.
                TermEvent::ClipboardStore(_, text) => ctx.copy_text(text),
                TermEvent::ClipboardLoad(..) => {}
                TermEvent::ColorRequest(i, answer) => {
                    let c = default_color(i, ctx.global_style().visuals.dark_mode);
                    self.write(
                        answer(Rgb {
                            r: c.r(),
                            g: c.g(),
                            b: c.b(),
                        })
                        .into_bytes(),
                    );
                }
                TermEvent::TextAreaSizeRequest(answer) => {
                    self.write(answer(self.window_size()).into_bytes());
                }
                TermEvent::ChildExit(status) => {
                    self.ended = Some(match status.code() {
                        Some(0) => "The shell ended.".to_string(),
                        Some(c) => format!("The shell ended with code {c}."),
                        None => "The shell was stopped.".to_string(),
                    });
                }
                TermEvent::Exit if self.ended.is_none() => {
                    self.ended = Some("The shell ended.".to_string());
                }
                _ => {}
            }
        }
    }

    fn window_size(&self) -> WindowSize {
        WindowSize {
            num_lines: self.size.lines as u16,
            num_cols: self.size.cols as u16,
            cell_width: self.cell.x as u16,
            cell_height: self.cell.y as u16,
        }
    }

    fn resize(&mut self, size: Size) {
        if size == self.size || size.cols == 0 || size.lines == 0 {
            return;
        }
        self.size = size;
        self.term.lock().resize(size);
        let _ = self.loop_tx.send(Msg::Resize(self.window_size()));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Closing the pseudo-terminal hangs up on the shell, as closing a terminal window does.
        let _ = self.loop_tx.send(Msg::Shutdown);
    }
}

/// The xterm colour `i` of the 256: the first 16 picked to read well on KRAKEN's backgrounds,
/// then the colour cube and the grey ramp. Past 255 the named colours (foreground and the like).
fn default_color(i: usize, dark: bool) -> Color32 {
    const DARK: [u32; 16] = [
        0x1d2021, 0xea6962, 0xa9b665, 0xd8a657, 0x7daea3, 0xd3869b, 0x89b482, 0xd4be98, 0x5a524c,
        0xef8a85, 0xbfd08a, 0xe8bd72, 0x9cc4bb, 0xe3a3b6, 0xa6cba1, 0xf2e5bc,
    ];
    const LIGHT: [u32; 16] = [
        0x3c3836, 0xc14a4a, 0x6c782e, 0xb47109, 0x45707a, 0x945e80, 0x4c7a5d, 0x7c6f64, 0x928374,
        0xd65d5d, 0x7d8a39, 0xc98510, 0x518590, 0xa96f94, 0x5a8b6b, 0x282828,
    ];
    let hex = |v: u32| Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8);
    match i {
        0..=15 => hex(if dark { DARK[i] } else { LIGHT[i] }),
        16..=231 => {
            let n = i - 16;
            let level = |v: usize| if v == 0 { 0 } else { (55 + v * 40) as u8 };
            Color32::from_rgb(level(n / 36), level(n / 6 % 6), level(n % 6))
        }
        232..=255 => {
            let v = (8 + (i - 232) * 10) as u8;
            Color32::from_rgb(v, v, v)
        }
        _ => {
            let (fg, bg) = if dark {
                (0xd4be98, 0x14191d)
            } else {
                (0x282828, 0xfbf5e6)
            };
            match i {
                n if n == NamedColor::Background as usize => hex(bg),
                n if n == NamedColor::Cursor as usize => {
                    hex(if dark { 0xe8e2d0 } else { 0x282828 })
                }
                n if (NamedColor::DimBlack as usize..=NamedColor::DimWhite as usize)
                    .contains(&n) =>
                {
                    default_color(n - NamedColor::DimBlack as usize, dark).gamma_multiply(0.7)
                }
                n if n == NamedColor::DimForeground as usize => hex(fg).gamma_multiply(0.7),
                _ => hex(fg),
            }
        }
    }
}

/// The colour of `c`: what the program set by OSC 4 first, then the defaults.
fn resolve(c: Color, colors: &alacritty_terminal::term::color::Colors, dark: bool) -> Color32 {
    match c {
        Color::Spec(rgb) => Color32::from_rgb(rgb.r, rgb.g, rgb.b),
        Color::Indexed(i) => colors[i as usize].map_or_else(
            || default_color(i as usize, dark),
            |r| Color32::from_rgb(r.r, r.g, r.b),
        ),
        Color::Named(n) => colors[n].map_or_else(
            || default_color(n as usize, dark),
            |r| Color32::from_rgb(r.r, r.g, r.b),
        ),
    }
}

/// Every open shell of the window.
#[derive(Default)]
pub struct Terminals {
    sessions: Vec<Session>,
    active: usize,
    next: u64,
    error: Option<String>,
    /// Where new shells start: the open project's folder.
    pub cwd: Option<PathBuf>,
    /// A program to run instead of the person's shell (tests).
    pub program: Option<(String, Vec<String>)>,
}

impl Terminals {
    fn open(&mut self, ctx: &egui::Context) {
        self.next += 1;
        let launch = Launch {
            program: self.program.clone(),
            cwd: self.cwd.clone().filter(|d| d.is_dir()),
        };
        match Session::start(ctx, self.next, &launch) {
            Ok(s) => {
                self.sessions.push(s);
                self.active = self.sessions.len() - 1;
                self.error = None;
            }
            Err(e) => self.error = Some(format!("The shell could not be started: {e}")),
        }
    }

    /// True while a shell has the keyboard: the window's own shortcuts then leave the keys to it.
    /// Ctrl+Tab and Ctrl+1 to Ctrl+9 still switch tabs, which is the way out.
    pub fn has_keyboard(&self, ctx: &egui::Context) -> bool {
        ctx.memory(|m| m.focused()).is_some_and(|f| {
            self.sessions
                .iter()
                .any(|s| f == Terminals::focus_id().with(s.id))
        })
    }

    /// The shell on show (tests).
    #[cfg(test)]
    pub fn active(&self) -> Option<&Session> {
        self.sessions.get(self.active)
    }

    /// The terminal's keyboard focus id: while it has the focus, the window's shortcuts wait.
    pub fn focus_id() -> Id {
        Id::new("kraken_terminal_screen")
    }
}

/// Draws the Terminal tab.
pub fn panel(ui: &mut Ui, t: &mut Terminals) {
    let ctx = ui.ctx().clone();
    if t.sessions.is_empty() && t.error.is_none() {
        t.open(&ctx);
    }
    for s in &mut t.sessions {
        s.drain(&ctx);
    }
    let p = pal(ui);
    let mut close = None;
    let mut new = false;
    ui.horizontal(|ui| {
        for (i, s) in t.sessions.iter().enumerate() {
            let label = if s.ended() {
                format!("{} (ended)", s.title)
            } else {
                s.title.clone()
            };
            let r = ui
                .selectable_label(i == t.active, label)
                .on_hover_text("Show this shell. Middle-click to close it");
            if r.clicked() {
                t.active = i;
            }
            if r.middle_clicked() {
                close = Some(i);
            }
        }
        if ui
            .small_button("+")
            .on_hover_text("Open another shell")
            .clicked()
        {
            new = true;
        }
        if !t.sessions.is_empty()
            && ui
                .small_button("Close")
                .on_hover_text("Close this shell; what runs in it is hung up on")
                .clicked()
        {
            close = Some(t.active);
        }
    });
    if new {
        t.open(&ctx);
    }
    if let Some(i) = close {
        t.sessions.remove(i);
        t.active = t.active.min(t.sessions.len().saturating_sub(1));
    }
    if let Some(e) = &t.error {
        ui.label(RichText::new(e).color(crate::style::status(crate::style::dark(ui)).danger));
        if ui
            .button("Try again")
            .on_hover_text("Start the shell again")
            .clicked()
        {
            t.error = None;
        }
        return;
    }
    let Some(s) = t.sessions.get_mut(t.active) else {
        return;
    };
    if let Some(why) = s.ended.clone() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(why).color(p.text_dim));
            if ui
                .button("Start a new shell")
                .on_hover_text("Open the shell again in this tab")
                .clicked()
            {
                new = true;
            }
        });
    }
    screen(ui, s);
    if new && let Some(i) = t.sessions.iter().position(Session::ended) {
        t.sessions.remove(i);
        t.open(&ctx);
    }
}

/// The cell under `pos`, and which half of it.
fn cell_at(rect: Rect, cell: Vec2, size: Size, pos: Pos2) -> (usize, usize, Side) {
    let x = ((pos.x - rect.left()) / cell.x).max(0.0);
    let y = ((pos.y - rect.top()) / cell.y).max(0.0);
    let col = (x as usize).min(size.cols.saturating_sub(1));
    let line = (y as usize).min(size.lines.saturating_sub(1));
    let side = if x.fract() < 0.5 {
        Side::Left
    } else {
        Side::Right
    };
    (col, line, side)
}

/// The screen: draws the grid and takes the keyboard and the mouse.
fn screen(ui: &mut Ui, s: &mut Session) {
    let font = FontId::monospace(FONT_SIZE);
    let dark = ui.visuals().dark_mode;
    let cell = {
        let g = ui
            .painter()
            .layout_no_wrap("M".to_string(), font.clone(), Color32::WHITE);
        vec2(g.size().x.max(1.0), g.size().y.max(1.0).ceil())
    };
    s.cell = cell;
    let rect = ui.available_rect_before_wrap();
    let id = Terminals::focus_id().with(s.id);
    let resp = ui.interact(rect, id, Sense::click_and_drag());
    ui.allocate_rect(rect, Sense::hover());
    let size = Size {
        cols: ((rect.width() - 4.0) / cell.x).floor().max(2.0) as usize,
        lines: (rect.height() / cell.y).floor().max(1.0) as usize,
    };
    s.resize(size);

    if resp.clicked() || resp.drag_started() {
        resp.request_focus();
    }
    let focused = resp.has_focus();
    if focused {
        // Tab, arrows and Escape belong to the program, not to moving between widgets.
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                egui::EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            );
        });
    }
    let mode = *s.term.lock().mode();
    if focused != s.focused {
        s.focused = focused;
        if mode.contains(TermMode::FOCUS_IN_OUT) {
            s.write(if focused {
                &b"\x1b[I"[..]
            } else {
                &b"\x1b[O"[..]
            });
        }
    }
    if focused {
        keyboard(ui, s, mode);
    }
    mouse(ui, s, &resp, rect, cell, mode);
    resp.context_menu(|ui| {
        if ui
            .button("Copy")
            .on_hover_text("Copy the selected text (Ctrl+Shift+C)")
            .clicked()
        {
            if let Some(t) = s.term.lock().selection_to_string() {
                ui.ctx().copy_text(t);
            }
            ui.close();
        }
        if ui
            .button("Paste")
            .on_hover_text("Paste the clipboard (Ctrl+Shift+V)")
            .clicked()
        {
            if let Ok(text) = arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                s.write(paste_bytes(&text, mode.contains(TermMode::BRACKETED_PASTE)));
            }
            ui.close();
        }
        if ui
            .button("Clear scrollback")
            .on_hover_text("Forget the lines above the screen")
            .clicked()
        {
            s.term.lock().grid_mut().clear_history();
            ui.close();
        }
    });
    draw(ui, s, rect, cell, &font, dark, focused);
}

fn keyboard(ui: &mut Ui, s: &mut Session, mode: TermMode) {
    let app_cursor = mode.contains(TermMode::APP_CURSOR);
    let bracketed = mode.contains(TermMode::BRACKETED_PASTE);
    let mut out: Vec<u8> = Vec::new();
    let (events, shift) = ui.input(|i| (i.events.clone(), i.modifiers.shift));
    // With Ctrl or Alt held the key itself says what to send; text of the same press is dropped.
    let mut chord = false;
    let mut typed = false;
    for e in &events {
        match e {
            egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } => {
                if let Some(b) = key_bytes(*key, *modifiers, app_cursor) {
                    chord |= modifiers.ctrl || modifiers.alt;
                    out.extend(b);
                    typed = true;
                }
            }
            egui::Event::Text(t) if !chord => {
                out.extend(t.as_bytes());
                typed = true;
            }
            // Ctrl+C reaches egui as Copy. Kitty's keys: with Shift it copies, without it is the
            // interrupt the shell expects.
            egui::Event::Copy => {
                if shift {
                    if let Some(t) = s.term.lock().selection_to_string() {
                        ui.ctx().copy_text(t);
                    }
                } else {
                    out.push(0x03);
                    typed = true;
                }
            }
            egui::Event::Cut => {
                out.push(0x18);
                typed = true;
            }
            egui::Event::Paste(text) => {
                if shift {
                    out.extend(paste_bytes(text, bracketed));
                } else {
                    out.push(0x16);
                }
                typed = true;
            }
            _ => {}
        }
    }
    if typed {
        let mut term = s.term.lock();
        term.scroll_display(Scroll::Bottom);
        term.selection = None;
    }
    if !out.is_empty() {
        s.write(out);
    }
    // Keep the keys from the window's own shortcuts and from egui's widgets.
    ui.input_mut(|i| {
        i.events.retain(|e| {
            !matches!(
                e,
                egui::Event::Key { .. }
                    | egui::Event::Text(_)
                    | egui::Event::Copy
                    | egui::Event::Cut
                    | egui::Event::Paste(_)
            )
        });
    });
}

fn mouse(
    ui: &mut Ui,
    s: &mut Session,
    resp: &egui::Response,
    rect: Rect,
    cell: Vec2,
    mode: TermMode,
) {
    let screen_lines = s.size.lines as f32;
    let (wheel, mods, pos) = ui.input(|i| {
        let wheel: f32 = i
            .events
            .iter()
            .filter_map(|e| match e {
                egui::Event::MouseWheel { unit, delta, .. } => Some(match unit {
                    egui::MouseWheelUnit::Line => delta.y,
                    egui::MouseWheelUnit::Page => delta.y * screen_lines,
                    egui::MouseWheelUnit::Point => delta.y / cell.y,
                }),
                _ => None,
            })
            .sum();
        (wheel, i.modifiers, i.pointer.interact_pos())
    });
    let size = s.size;
    let report = mode.intersects(TermMode::MOUSE_MODE) && !mods.shift;
    let sgr = mode.contains(TermMode::SGR_MOUSE);
    let hovered = resp.hovered();
    // Wheels and touchpads move in fractions of a line; whole lines go to the program.
    if hovered {
        s.scroll_lines += wheel;
    }
    let lines = s.scroll_lines.trunc() as i32;
    s.scroll_lines -= lines as f32;
    if hovered && lines != 0 {
        if report && let Some(pos) = pos {
            let (col, line, _) = cell_at(rect, cell, size, pos);
            let button = if lines > 0 {
                MouseButton::WheelUp
            } else {
                MouseButton::WheelDown
            };
            for _ in 0..lines.unsigned_abs().min(8) {
                s.write(mouse_bytes(button, true, false, mods, col, line, sgr));
            }
        } else if mode.contains(TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL) {
            let key = if lines > 0 { b"A" } else { b"B" };
            let prefix: &[u8] = if mode.contains(TermMode::APP_CURSOR) {
                b"\x1bO"
            } else {
                b"\x1b["
            };
            for _ in 0..lines.unsigned_abs().min(8) {
                let mut b = prefix.to_vec();
                b.extend(key);
                s.write(b);
            }
        } else {
            s.term.lock().scroll_display(Scroll::Delta(lines));
        }
    }
    let Some(pos) = pos else { return };
    let (col, line, side) = cell_at(rect, cell, size, pos);
    if report {
        let pressed = ui.input(|i| {
            [
                egui::PointerButton::Primary,
                egui::PointerButton::Middle,
                egui::PointerButton::Secondary,
            ]
            .into_iter()
            .find(|b| i.pointer.button_pressed(*b))
        });
        let released = ui.input(|i| {
            [
                egui::PointerButton::Primary,
                egui::PointerButton::Middle,
                egui::PointerButton::Secondary,
            ]
            .into_iter()
            .find(|b| i.pointer.button_released(*b))
        });
        let as_button = |b: egui::PointerButton| match b {
            egui::PointerButton::Middle => MouseButton::Middle,
            egui::PointerButton::Secondary => MouseButton::Right,
            _ => MouseButton::Left,
        };
        if hovered && let Some(b) = pressed {
            s.held = Some(as_button(b));
            s.write(mouse_bytes(as_button(b), true, false, mods, col, line, sgr));
        } else if let Some(b) = released.filter(|_| s.held.is_some()) {
            s.held = None;
            s.write(mouse_bytes(
                as_button(b),
                false,
                false,
                mods,
                col,
                line,
                sgr,
            ));
        } else if ui.input(|i| i.pointer.delta() != Vec2::ZERO) && hovered {
            let motion = match s.held {
                Some(b) if mode.intersects(TermMode::MOUSE_DRAG | TermMode::MOUSE_MOTION) => {
                    Some(b)
                }
                None if mode.contains(TermMode::MOUSE_MOTION) => Some(MouseButton::None),
                _ => None,
            };
            if let Some(b) = motion {
                s.write(mouse_bytes(b, true, true, mods, col, line, sgr));
            }
        }
        return;
    }
    // Selecting: drag for characters, double-click for a word, triple-click for lines.
    let mut term = s.term.lock();
    let offset = term.grid().display_offset() as i32;
    let point = Point::new(Line(line as i32 - offset), Column(col));
    let clicks = ui.input(|i| {
        if i.pointer
            .button_triple_clicked(egui::PointerButton::Primary)
        {
            3
        } else if i
            .pointer
            .button_double_clicked(egui::PointerButton::Primary)
        {
            2
        } else {
            0
        }
    });
    if hovered && clicks > 0 {
        let ty = if clicks == 3 {
            SelectionType::Lines
        } else {
            SelectionType::Semantic
        };
        let mut sel = Selection::new(ty, point, side);
        sel.update(point, side);
        term.selection = Some(sel);
    } else if resp.drag_started() {
        term.selection = Some(Selection::new(SelectionType::Simple, point, side));
    } else if resp.dragged() {
        if let Some(sel) = term.selection.as_mut() {
            sel.update(point, side);
        }
    } else if resp.clicked() {
        term.selection = None;
    }
    if resp.drag_stopped()
        && let Some(text) = term.selection_to_string().filter(|t| !t.is_empty())
    {
        // Selected text is ready to paste, as X11 terminals do with the primary selection.
        let _ = arboard::Clipboard::new().and_then(|mut c| {
            #[cfg(target_os = "linux")]
            {
                use arboard::SetExtLinux;
                c.set()
                    .clipboard(arboard::LinuxClipboardKind::Primary)
                    .text(text)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&mut c, text);
                Ok(())
            }
        });
    }
}

fn draw(
    ui: &mut Ui,
    s: &Session,
    rect: Rect,
    cell: Vec2,
    font: &FontId,
    dark: bool,
    focused: bool,
) {
    let painter = ui.painter_at(rect);
    let term = s.term.lock();
    let content = term.renderable_content();
    let colors = content.colors;
    let background = resolve(Color::Named(NamedColor::Background), colors, dark);
    painter.rect_filled(rect, 0.0, background);
    let offset = content.display_offset as i32;
    let selection = content.selection;
    let origin = pos2(rect.left() + 2.0, rect.top());
    let at = |line: i32, col: usize| {
        pos2(
            origin.x + col as f32 * cell.x,
            origin.y + line as f32 * cell.y,
        )
    };
    for indexed in content.display_iter {
        let cell_flags = indexed.cell.flags;
        if cell_flags.contains(Flags::WIDE_CHAR_SPACER) {
            continue;
        }
        let row = indexed.point.line.0 + offset;
        let col = indexed.point.column.0;
        let mut fg = resolve(indexed.cell.fg, colors, dark);
        let mut bg = resolve(indexed.cell.bg, colors, dark);
        if cell_flags.contains(Flags::INVERSE) {
            std::mem::swap(&mut fg, &mut bg);
        }
        if cell_flags.contains(Flags::DIM) {
            fg = fg.gamma_multiply(0.66);
        }
        if selection.is_some_and(|r| r.contains(indexed.point)) {
            bg = ui.visuals().selection.bg_fill;
        }
        let width = if cell_flags.contains(Flags::WIDE_CHAR) {
            2.0
        } else {
            1.0
        };
        let top_left = at(row, col);
        let r = Rect::from_min_size(top_left, vec2(cell.x * width, cell.y));
        if bg != background {
            painter.rect_filled(r, 0.0, bg);
        }
        let c = indexed.cell.c;
        if c != ' ' && c != '\t' && !cell_flags.contains(Flags::HIDDEN) {
            let mut text = c.to_string();
            if let Some(extra) = indexed.cell.zerowidth() {
                text.extend(extra);
            }
            painter.text(top_left, egui::Align2::LEFT_TOP, text, font.clone(), fg);
        }
        if cell_flags.intersects(Flags::ALL_UNDERLINES) {
            let y = r.bottom() - 1.5;
            painter.hline(r.x_range(), y, Stroke::new(1.0, fg));
        }
        if cell_flags.contains(Flags::STRIKEOUT) {
            painter.hline(r.x_range(), r.center().y, Stroke::new(1.0, fg));
        }
    }
    let cursor = content.cursor;
    if cursor.shape != CursorShape::Hidden && term.mode().contains(TermMode::SHOW_CURSOR) {
        let row = cursor.point.line.0 + offset;
        if (0..s.size.lines as i32).contains(&row) {
            let r = Rect::from_min_size(at(row, cursor.point.column.0), cell);
            let color = resolve(Color::Named(NamedColor::Cursor), colors, dark);
            match (focused, cursor.shape) {
                (false, _) | (_, CursorShape::HollowBlock) => {
                    painter.rect_stroke(
                        r.shrink(0.5),
                        0.0,
                        Stroke::new(1.0, color),
                        egui::StrokeKind::Inside,
                    );
                }
                (_, CursorShape::Beam) => {
                    painter.rect_filled(Rect::from_min_size(r.min, vec2(2.0, cell.y)), 0.0, color);
                }
                (_, CursorShape::Underline) => {
                    painter.rect_filled(
                        Rect::from_min_size(pos2(r.left(), r.bottom() - 2.0), vec2(cell.x, 2.0)),
                        0.0,
                        color,
                    );
                }
                _ => {
                    painter.rect_filled(r, 0.0, color);
                    let under = term.grid()[cursor.point].c;
                    if under != ' ' {
                        painter.text(
                            r.min,
                            egui::Align2::LEFT_TOP,
                            under.to_string(),
                            font.clone(),
                            background,
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(s: &mut Session, ctx: &egui::Context, what: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            s.drain(ctx);
            let text = s.screen_text();
            if text.contains(what) {
                return text;
            }
            assert!(Instant::now() < deadline, "no {what:?} in:\n{text}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shell_runs_on_a_real_terminal_and_answers_typed_commands() {
        let ctx = egui::Context::default();
        let launch = Launch {
            program: Some(("/bin/sh".into(), vec![])),
            cwd: Some(std::env::temp_dir()),
        };
        let mut s = Session::start(&ctx, 1, &launch).unwrap();
        // A terminal, with the size and the type a program asks about.
        s.write(&b"stty size; tty; echo \"$TERM\"; printf 'x%sy\\n' z\r"[..]);
        let text = wait_for(&mut s, &ctx, "xzy");
        assert!(text.contains("24 80"), "{text}");
        assert!(text.contains("/dev/pts/"), "{text}");
        assert!(text.contains("xterm-256color"), "{text}");
        s.resize(Size {
            cols: 100,
            lines: 30,
        });
        s.write(&b"stty size\r"[..]);
        wait_for(&mut s, &ctx, "30 100");
        // Ctrl+C reaches the program as the interrupt.
        s.write(&b"sleep 30; echo slept\r"[..]);
        std::thread::sleep(Duration::from_millis(200));
        s.write(vec![0x03]);
        s.write(&b"echo interrupted\r"[..]);
        let text = wait_for(&mut s, &ctx, "interrupted\n");
        assert!(!text.lines().any(|l| l == "slept"), "{text}");
        s.write(&b"exit 3\r"[..]);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !s.ended() {
            s.drain(&ctx);
            assert!(Instant::now() < deadline, "the shell did not end");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(s.ended.as_deref(), Some("The shell ended with code 3."));
    }

    #[test]
    fn the_256_colours_follow_xterm() {
        assert_eq!(default_color(16, true), Color32::from_rgb(0, 0, 0));
        assert_eq!(default_color(231, true), Color32::from_rgb(255, 255, 255));
        assert_eq!(default_color(196, true), Color32::from_rgb(255, 0, 0));
        assert_eq!(default_color(232, true), Color32::from_rgb(8, 8, 8));
        assert_ne!(
            default_color(NamedColor::Background as usize, true),
            default_color(NamedColor::Background as usize, false)
        );
    }
}
