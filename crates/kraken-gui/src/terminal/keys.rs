//! What a key, a paste or a mouse event sends to the program in the terminal, as xterm does.

use egui::{Key, Modifiers};

/// The modifier number of xterm's `CSI 1;m` forms: 1 plus shift 1, alt 2, ctrl 4.
fn modifier_code(m: Modifiers) -> u8 {
    1 + u8::from(m.shift) + 2 * u8::from(m.alt) + 4 * u8::from(m.ctrl)
}

fn has_mods(m: Modifiers) -> bool {
    m.shift || m.alt || m.ctrl
}

/// A cursor or editing key: `CSI x` (`SS3 x` in application mode), `CSI 1;m x` with modifiers.
fn letter_key(letter: char, m: Modifiers, app: bool) -> Vec<u8> {
    if has_mods(m) {
        format!("\x1b[1;{}{letter}", modifier_code(m)).into_bytes()
    } else if app {
        format!("\x1bO{letter}").into_bytes()
    } else {
        format!("\x1b[{letter}").into_bytes()
    }
}

/// A key of the `CSI n ~` kind, `CSI n;m ~` with modifiers.
fn tilde_key(n: u8, m: Modifiers) -> Vec<u8> {
    if has_mods(m) {
        format!("\x1b[{n};{}~", modifier_code(m)).into_bytes()
    } else {
        format!("\x1b[{n}~").into_bytes()
    }
}

/// The control byte of Ctrl+`key`, for the keys that have one.
fn control_byte(key: Key) -> Option<u8> {
    let name = key.name();
    if name.len() == 1 {
        let c = name.as_bytes()[0];
        if c.is_ascii_alphabetic() {
            return Some(c.to_ascii_uppercase() - b'A' + 1);
        }
    }
    Some(match key {
        Key::Space | Key::Num2 => 0,
        Key::OpenBracket => 0x1b,
        Key::Backslash => 0x1c,
        Key::CloseBracket => 0x1d,
        Key::Num6 => 0x1e,
        Key::Minus | Key::Slash => 0x1f,
        _ => return None,
    })
}

/// The bytes of a key press, or `None` for a key whose text arrives as a text event instead.
/// `app_cursor` is the application cursor mode the program asked for.
pub fn key_bytes(key: Key, m: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let alt = |mut b: Vec<u8>| {
        if m.alt {
            b.insert(0, 0x1b);
        }
        b
    };
    Some(match key {
        Key::Enter => alt(b"\r".to_vec()),
        Key::Backspace if m.ctrl => alt(vec![0x08]),
        Key::Backspace => alt(vec![0x7f]),
        Key::Tab if m.shift => b"\x1b[Z".to_vec(),
        Key::Tab => alt(b"\t".to_vec()),
        Key::Escape => alt(vec![0x1b]),
        Key::ArrowUp => letter_key('A', m, app_cursor),
        Key::ArrowDown => letter_key('B', m, app_cursor),
        Key::ArrowRight => letter_key('C', m, app_cursor),
        Key::ArrowLeft => letter_key('D', m, app_cursor),
        Key::Home => letter_key('H', m, app_cursor),
        Key::End => letter_key('F', m, app_cursor),
        Key::Insert => tilde_key(2, m),
        Key::Delete => tilde_key(3, m),
        Key::PageUp => tilde_key(5, m),
        Key::PageDown => tilde_key(6, m),
        Key::F1 => letter_key('P', m, true),
        Key::F2 => letter_key('Q', m, true),
        Key::F3 => letter_key('R', m, true),
        Key::F4 => letter_key('S', m, true),
        Key::F5 => tilde_key(15, m),
        Key::F6 => tilde_key(17, m),
        Key::F7 => tilde_key(18, m),
        Key::F8 => tilde_key(19, m),
        Key::F9 => tilde_key(20, m),
        Key::F10 => tilde_key(21, m),
        Key::F11 => tilde_key(23, m),
        Key::F12 => tilde_key(24, m),
        _ if m.ctrl => alt(vec![control_byte(key)?]),
        _ if m.alt => {
            let name = key.name();
            let mut c = name.chars().next()?;
            if name.chars().count() != 1 {
                return None;
            }
            c = if m.shift {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            vec![0x1b, c as u8]
        }
        _ => return None,
    })
}

/// A paste: wrapped for a program that asked for bracketed paste, with line ends as Enter.
pub fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let text = text.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed {
        // A pasted end marker would let the text out of the bracket.
        let inner = text.replace('\x1b', "");
        format!("\x1b[200~{inner}\x1b[201~").into_bytes()
    } else {
        text.into_bytes()
    }
}

/// A mouse button of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    /// Movement with no button held.
    None,
}

/// A mouse report: SGR (`CSI < b;x;y M/m`) when the program asked for it, else the classic form.
/// `col` and `line` count from 0.
pub fn mouse_bytes(
    button: MouseButton,
    pressed: bool,
    motion: bool,
    m: Modifiers,
    col: usize,
    line: usize,
    sgr: bool,
) -> Vec<u8> {
    let mut b: u32 = match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
        MouseButton::None => 3,
        MouseButton::WheelUp => 64,
        MouseButton::WheelDown => 65,
    };
    if motion {
        b += 32;
    }
    b += 4 * u32::from(m.shift) + 8 * u32::from(m.alt) + 16 * u32::from(m.ctrl);
    if sgr {
        let end = if pressed { 'M' } else { 'm' };
        return format!("\x1b[<{b};{};{}{end}", col + 1, line + 1).into_bytes();
    }
    // The classic form has no release of a particular button, and stops at column 223.
    let b = if pressed { b } else { 3 + (b & !3) };
    let at = |n: usize| (32 + 1 + n).min(255) as u8;
    vec![0x1b, b'[', b'M', (32 + b).min(255) as u8, at(col), at(line)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Modifiers = Modifiers::NONE;

    fn with(f: impl FnOnce(&mut Modifiers)) -> Modifiers {
        let mut m = Modifiers::NONE;
        f(&mut m);
        m
    }

    #[test]
    fn editing_keys_follow_xterm() {
        assert_eq!(key_bytes(Key::Enter, NONE, false).unwrap(), b"\r");
        assert_eq!(key_bytes(Key::Backspace, NONE, false).unwrap(), [0x7f]);
        assert_eq!(
            key_bytes(Key::Tab, with(|m| m.shift = true), false).unwrap(),
            b"\x1b[Z"
        );
        assert_eq!(key_bytes(Key::Delete, NONE, false).unwrap(), b"\x1b[3~");
        assert_eq!(key_bytes(Key::F5, NONE, false).unwrap(), b"\x1b[15~");
        assert_eq!(key_bytes(Key::F1, NONE, false).unwrap(), b"\x1bOP");
    }

    #[test]
    fn arrows_follow_the_cursor_mode_and_take_modifiers() {
        assert_eq!(key_bytes(Key::ArrowUp, NONE, false).unwrap(), b"\x1b[A");
        assert_eq!(key_bytes(Key::ArrowUp, NONE, true).unwrap(), b"\x1bOA");
        let ctrl = with(|m| m.ctrl = true);
        assert_eq!(key_bytes(Key::ArrowLeft, ctrl, true).unwrap(), b"\x1b[1;5D");
        let shift = with(|m| m.shift = true);
        assert_eq!(key_bytes(Key::PageUp, shift, false).unwrap(), b"\x1b[5;2~");
    }

    #[test]
    fn ctrl_and_alt_letters_are_control_bytes_and_escapes() {
        let ctrl = with(|m| m.ctrl = true);
        assert_eq!(key_bytes(Key::D, ctrl, false).unwrap(), [4]);
        assert_eq!(key_bytes(Key::Z, ctrl, false).unwrap(), [26]);
        assert_eq!(key_bytes(Key::OpenBracket, ctrl, false).unwrap(), [0x1b]);
        let alt = with(|m| m.alt = true);
        assert_eq!(key_bytes(Key::B, alt, false).unwrap(), b"\x1bb");
        assert_eq!(key_bytes(Key::Enter, alt, false).unwrap(), b"\x1b\r");
        assert_eq!(
            key_bytes(Key::A, NONE, false),
            None,
            "plain letters come as text"
        );
    }

    #[test]
    fn a_paste_is_bracketed_when_asked_and_cannot_close_the_bracket() {
        assert_eq!(paste_bytes("a\nb", false), b"a\rb");
        assert_eq!(
            paste_bytes("x\x1b[201~rm -rf", true),
            b"\x1b[200~x[201~rm -rf\x1b[201~"
        );
    }

    #[test]
    fn mouse_reports_in_both_forms() {
        let r = mouse_bytes(MouseButton::Left, true, false, NONE, 4, 9, true);
        assert_eq!(r, b"\x1b[<0;5;10M");
        let r = mouse_bytes(MouseButton::Left, false, false, NONE, 4, 9, true);
        assert_eq!(r, b"\x1b[<0;5;10m");
        let r = mouse_bytes(MouseButton::WheelDown, true, false, NONE, 0, 0, true);
        assert_eq!(r, b"\x1b[<65;1;1M");
        let r = mouse_bytes(MouseButton::Left, true, false, NONE, 0, 0, false);
        assert_eq!(r, [0x1b, b'[', b'M', 32, 33, 33]);
    }
}
