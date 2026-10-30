//! Keyboard shortcut presets. The presets are data (`data/keymaps/*.toml`: action name, chords)
//! read once; the window keeps the active one in the egui context (`install`), and every place
//! that reacts to a key asks it (`Keymap::consume`) instead of naming the key. The chosen id is
//! the `ui.keymap` setting.

use std::sync::OnceLock;

use egui::{Context, InputState, Key, Modifiers};
use kraken_viewmodel::AppAction;
use serde::Deserialize;

/// The id used when none is set or the saved one is unknown.
pub const DEFAULT_ID: &str = "kraken";

/// One key with its modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    pub mods: Modifiers,
    pub key: Key,
}

impl Chord {
    /// Reads `Ctrl+Shift+O`, `Alt+Left`, `N`, `;`, `F1`.
    pub fn parse(text: &str) -> Result<Chord, String> {
        let mut mods = Modifiers::NONE;
        let mut parts: Vec<&str> = text.split('+').collect();
        // A trailing "+" key would split into an empty last part; none of the presets bind it.
        let key_text = parts
            .pop()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| format!("`{text}` has no key"))?;
        for m in parts {
            match m {
                "Ctrl" | "Cmd" => mods |= Modifiers::COMMAND,
                "Shift" => mods |= Modifiers::SHIFT,
                "Alt" => mods |= Modifiers::ALT,
                other => return Err(format!("`{text}`: unknown modifier `{other}`")),
            }
        }
        let key = match key_text {
            "," => Some(Key::Comma),
            "/" => Some(Key::Slash),
            ";" => Some(Key::Semicolon),
            "." => Some(Key::Period),
            "-" => Some(Key::Minus),
            "Left" => Some(Key::ArrowLeft),
            "Right" => Some(Key::ArrowRight),
            "Up" => Some(Key::ArrowUp),
            "Down" => Some(Key::ArrowDown),
            other => Key::from_name(other),
        }
        .ok_or_else(|| format!("`{text}`: unknown key `{key_text}`"))?;
        Ok(Chord { mods, key })
    }
}

#[derive(Deserialize)]
struct Raw {
    id: String,
    name: String,
    blurb: String,
    keys: std::collections::BTreeMap<String, Vec<String>>,
}

/// One preset: which keys do which action.
#[derive(Debug)]
pub struct Keymap {
    /// The id stored in `ui.keymap`.
    pub id: String,
    /// The name shown (a neutral one, never a product's).
    pub name: String,
    /// What the preset is like, in a sentence.
    pub blurb: String,
    bindings: Vec<Binding>,
}

#[derive(Debug)]
struct Binding {
    action: AppAction,
    /// The chords as written, the first is the one shown.
    labels: Vec<String>,
    chords: Vec<Chord>,
}

fn action_named(name: &str) -> Option<AppAction> {
    AppAction::ALL
        .into_iter()
        .find(|a| format!("{a:?}") == name)
}

impl Keymap {
    /// Reads a preset file.
    pub fn parse(text: &str) -> Result<Keymap, String> {
        let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut bindings = Vec::new();
        for (name, labels) in raw.keys {
            let action = action_named(&name)
                .ok_or_else(|| format!("{}: `{name}` is not an action", raw.id))?;
            let chords = labels
                .iter()
                .map(|l| Chord::parse(l))
                .collect::<Result<Vec<_>, _>>()?;
            bindings.push(Binding {
                action,
                labels,
                chords,
            });
        }
        Ok(Keymap {
            id: raw.id,
            name: raw.name,
            blurb: raw.blurb,
            bindings,
        })
    }

    /// The text of the first chord of `action` (`Ctrl+Shift+O`), for menus and the cheat sheet.
    pub fn label(&self, action: AppAction) -> Option<&str> {
        self.binding(action)
            .and_then(|b| b.labels.first().map(String::as_str))
    }

    /// The actions this preset binds, with their chords' text.
    pub fn bound(&self) -> impl Iterator<Item = (AppAction, String)> + '_ {
        self.bindings
            .iter()
            .map(|b| (b.action, b.labels.join(" or ")))
    }

    fn binding(&self, action: AppAction) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.action == action)
    }

    /// Takes the key press of `action` out of `i`, and says whether there was one. A chord
    /// without Shift does not take a press that carries Shift when another action has that same
    /// chord with Shift (Ctrl+O must not swallow Ctrl+Shift+O).
    pub fn consume(&self, i: &mut InputState, action: AppAction) -> bool {
        let Some(b) = self.binding(action) else {
            return false;
        };
        for c in &b.chords {
            if !c.mods.shift && i.modifiers.shift && self.shifted_twin_exists(c) {
                continue;
            }
            if i.consume_key(c.mods, c.key) {
                return true;
            }
        }
        false
    }

    fn shifted_twin_exists(&self, c: &Chord) -> bool {
        self.bindings.iter().flat_map(|b| &b.chords).any(|o| {
            o.key == c.key
                && o.mods.shift
                && o.mods.alt == c.mods.alt
                && o.mods.command == c.mods.command
                && o.mods.ctrl == c.mods.ctrl
        })
    }

    /// Every chord of the preset with the action it belongs to, for collision checks.
    #[cfg(test)]
    fn all_chords(&self) -> impl Iterator<Item = (Chord, AppAction)> + '_ {
        self.bindings
            .iter()
            .flat_map(|b| b.chords.iter().map(|c| (*c, b.action)))
    }
}

const FILES: [&str; 4] = [
    include_str!("../data/keymaps/kraken.toml"),
    include_str!("../data/keymaps/classic.toml"),
    include_str!("../data/keymaps/ida-like.toml"),
    include_str!("../data/keymaps/binja-like.toml"),
];

/// The presets, KRAKEN's own first.
pub fn presets() -> &'static [Keymap] {
    static ALL: OnceLock<Vec<Keymap>> = OnceLock::new();
    ALL.get_or_init(|| {
        FILES
            .iter()
            .map(|t| Keymap::parse(t).unwrap_or_else(|e| panic!("keymap preset: {e}")))
            .collect()
    })
}

/// The preset with this id.
pub fn preset(id: &str) -> Option<&'static Keymap> {
    presets().iter().find(|k| k.id == id)
}

/// The preset with this id, or KRAKEN's own.
pub fn preset_or_default(id: Option<&str>) -> &'static Keymap {
    id.and_then(preset)
        .or_else(|| preset(DEFAULT_ID))
        .unwrap_or(&presets()[0])
}

fn slot() -> egui::Id {
    egui::Id::new("kraken_active_keymap")
}

/// Makes `keymap` the one every key handler of this context reads.
pub fn install(ctx: &Context, keymap: &'static Keymap) {
    ctx.data_mut(|d| d.insert_temp(slot(), keymap));
}

/// The keymap in force in this context.
pub fn of(ctx: &Context) -> &'static Keymap {
    ctx.data(|d| d.get_temp::<&'static Keymap>(slot()))
        .unwrap_or(&presets()[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_parses_and_names_only_real_actions() {
        // `parse` fails on an unknown action, key or modifier.
        let all = presets();
        assert_eq!(all.len(), 4);
        let ids: Vec<&str> = all.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, ["kraken", "classic", "ida-like", "binja-like"]);
        for k in all {
            assert!(!k.name.is_empty() && !k.blurb.is_empty());
            assert!(k.bound().count() >= 15, "{} binds too few actions", k.id);
        }
    }

    #[test]
    fn no_chord_is_bound_to_two_actions_in_a_preset() {
        for k in presets() {
            let chords: Vec<_> = k.all_chords().collect();
            for (n, (c, a)) in chords.iter().enumerate() {
                for (o, b) in &chords[n + 1..] {
                    assert!(c != o || a == b, "{}: {a:?} and {b:?} share {:?}", k.id, c);
                }
            }
        }
    }

    #[test]
    fn presets_show_neutral_names() {
        for k in presets() {
            let text = format!("{} {}", k.name, k.blurb).to_lowercase();
            for banned in ["ida", "binary ninja", "binja", "ghidra", "hopper", "radare"] {
                assert!(!text.contains(banned), "{} names a product", k.id);
            }
        }
    }

    #[test]
    fn the_default_preset_keeps_the_keys_the_menus_always_showed() {
        let k = preset(DEFAULT_ID).expect("default preset");
        for a in AppAction::ALL {
            if let Some(sc) = a.shortcut() {
                assert_eq!(k.label(a), Some(sc), "{a:?}");
            }
        }
    }

    #[test]
    fn a_press_is_taken_by_the_action_bound_to_it() {
        let k = preset("classic").expect("preset");
        let mut i = InputState::default();
        i.modifiers = Modifiers::COMMAND;
        i.events.push(egui::Event::Key {
            key: Key::G,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::COMMAND,
        });
        assert!(!k.consume(&mut i, AppAction::Search));
        assert!(k.consume(&mut i, AppAction::GoTo));
        assert!(!k.consume(&mut i, AppAction::GoTo), "taken once");
    }
}
