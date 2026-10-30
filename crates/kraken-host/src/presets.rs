//! Loader presets for raw firmware and ROM images: the processor and the usual load address
//! (`data/loader_presets.toml`, public architectural facts only).

use serde::Deserialize;

/// One starting point for a raw image.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LoaderPreset {
    pub id: String,
    pub title: String,
    pub family: String,
    /// A short processor name (`cortex-m`) or a Sleigh language id.
    pub language: String,
    /// Where the first byte of the image sits in memory.
    pub base: u64,
    /// `native` or `ghidra`: which engine loads this processor as a raw image.
    pub engine: String,
    pub note: String,
}

#[derive(Deserialize)]
struct File {
    preset: Vec<LoaderPreset>,
}

const TABLE: &str = include_str!("../data/loader_presets.toml");

/// The presets, in file order. The table is compiled in and linted by the tests.
pub fn loader_presets() -> &'static [LoaderPreset] {
    static PRESETS: std::sync::OnceLock<Vec<LoaderPreset>> = std::sync::OnceLock::new();
    PRESETS.get_or_init(|| toml::from_str::<File>(TABLE).map_or_else(|_| Vec::new(), |f| f.preset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_parses_and_ids_are_unique() {
        let p = loader_presets();
        assert!(p.len() >= 10);
        let mut ids: Vec<_> = p.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), p.len(), "duplicate preset id");
    }

    #[test]
    fn every_preset_names_a_language_the_engine_named_loads() {
        for p in loader_presets().iter() {
            let native = crate::native::raw_native_supported(&p.language);
            match p.engine.as_str() {
                "native" => assert!(
                    native,
                    "{}: the native engine has no raw loader for {}",
                    p.id, p.language
                ),
                "ghidra" => {
                    assert!(!native, "{}: marked ghidra but native loads it", p.id);
                    let id = kraken_engine::language_id(&p.language);
                    assert!(
                        id.contains(':'),
                        "{}: {} is not a known language",
                        p.id,
                        p.language
                    );
                }
                other => panic!("{}: unknown engine {other}", p.id),
            }
            assert!(!p.title.is_empty() && !p.note.is_empty(), "{}", p.id);
        }
    }

    #[test]
    fn cortex_m_presets_cover_the_common_flash_bases() {
        let bases: Vec<u64> = loader_presets()
            .iter()
            .filter(|p| p.language == "cortex-m")
            .map(|p| p.base)
            .collect();
        assert!(bases.contains(&0x0800_0000) && bases.contains(&0));
    }
}
