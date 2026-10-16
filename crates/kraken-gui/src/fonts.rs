//! Bundled fonts (decision 93): IBM Plex Sans and Mono, SIL OFL 1.1 (see `assets/fonts/LICENSE.txt`).
//! egui's own default fonts are disabled at build time, so these are the only fonts.

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily};

const SANS: &[u8] = include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf");
const SANS_MEDIUM: &[u8] = include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf");
const MONO: &[u8] = include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf");

/// Family for medium-weight proportional text (headings, chips).
pub fn medium() -> FontFamily {
    FontFamily::Name("plex-sans-medium".into())
}

/// The definitions that register Plex for the proportional, monospace and medium families.
pub fn definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::empty();
    for (name, bytes) in [
        ("plex-sans", SANS),
        ("plex-sans-medium", SANS_MEDIUM),
        ("plex-mono", MONO),
    ] {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    }
    fonts
        .families
        .insert(FontFamily::Proportional, vec!["plex-sans".into()]);
    fonts
        .families
        .insert(FontFamily::Monospace, vec!["plex-mono".into()]);
    fonts.families.insert(
        medium(),
        vec!["plex-sans-medium".into(), "plex-sans".into()],
    );
    fonts
}

/// Installs the bundled fonts on `ctx`.
pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(definitions());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_resolves_to_a_bundled_font() {
        let d = definitions();
        for (family, fonts) in &d.families {
            assert!(!fonts.is_empty(), "{family:?}");
            for f in fonts {
                assert!(d.font_data.contains_key(f), "{f} is not registered");
            }
        }
        assert!(d.families.contains_key(&FontFamily::Proportional));
        assert!(d.families.contains_key(&FontFamily::Monospace));
        assert!(d.families.contains_key(&medium()));
    }
}
