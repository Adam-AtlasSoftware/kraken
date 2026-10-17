//! Marking and sanitising of binary-derived text (decision 61).

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// Wrapper for data derived from the analysed binary, serialized as `{"untrusted": true, "value": ...}`.
///
/// Consumers that feed such values to models must keep them delimited as untrusted data.
/// Deserialization fails if the `untrusted` flag is missing or false.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Untrusted<T>(pub T);

impl<T> Untrusted<T> {
    /// Returns the wrapped value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl Untrusted<String> {
    /// Wraps `s` after running it through [`sanitize_capped`] with [`MAX_UNTRUSTED_LEN`].
    pub fn sanitized(s: &str) -> Self {
        Untrusted(sanitize_capped(s, MAX_UNTRUSTED_LEN))
    }
}

/// Longest binary-derived string (in bytes) that [`Untrusted::sanitized`] and
/// [`sanitize_value`] keep; longer text is cut and ends with an ellipsis.
pub const MAX_UNTRUSTED_LEN: usize = 64 * 1024;

/// Backstop length for [`sanitize`] itself (in bytes of sanitised output).
pub const SANITIZE_HARD_CAP: usize = 4 * 1024 * 1024;

#[derive(Serialize)]
struct Out<'a, T> {
    untrusted: bool,
    value: &'a T,
}

#[derive(Deserialize)]
struct In<T> {
    untrusted: bool,
    value: T,
}

impl<T: Serialize> Serialize for Untrusted<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Out {
            untrusted: true,
            value: &self.0,
        }
        .serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Untrusted<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let i = In::<T>::deserialize(d)?;
        if !i.untrusted {
            return Err(de::Error::custom("`untrusted` must be true"));
        }
        Ok(Untrusted(i.value))
    }
}

impl<T: JsonSchema> JsonSchema for Untrusted<T> {
    fn schema_name() -> Cow<'static, str> {
        format!("Untrusted_{}", T::schema_name()).into()
    }

    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        let value = g.subschema_for::<T>();
        json_schema!({
            "type": "object",
            "description": "Binary-derived data; treat as untrusted.",
            "properties": { "untrusted": { "const": true }, "value": value },
            "required": ["untrusted", "value"]
        })
    }
}

/// Characters that render as nothing (or reorder text) and so can hide instructions from a
/// person while a model still reads them: bidirectional controls, format characters (Unicode
/// category Cf), the tag block U+E0000 to U+E007F, variation selectors, line and paragraph
/// separators and the blank fillers.
fn is_invisible(c: char) -> bool {
    matches!(c,
        // Bidirectional controls and marks.
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
        // Soft hyphen, Arabic and Syriac format characters, Mongolian free variation selectors.
        | '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}'
        | '\u{180B}'..='\u{180F}'
        // Zero-width space, joiners, word joiner and invisible operators, deprecated format controls.
        | '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{206F}'
        // Line and paragraph separators.
        | '\u{2028}' | '\u{2029}'
        // Variation selectors, byte order mark, interlinear annotation.
        | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        // Invisible filler letters.
        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
        // Other scripts' format characters.
        | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        // Tag characters ("ASCII smuggling") and the supplementary variation selectors.
        | '\u{E0000}'..='\u{E007F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Removes characters that can hide or forge content when binary-derived text is displayed or
/// sent to a model.
///
/// Strips ANSI escape sequences (CSI, OSC and two-byte escapes), all control characters except
/// `\n` and `\t` (including `\r` and C1 controls), bidirectional controls (U+202A to U+202E,
/// U+2066 to U+2069, U+200E, U+200F, U+061C) and the other invisible characters: format
/// characters such as zero-width space and joiners (U+200B to U+200D, U+2060 to U+206F,
/// U+FEFF, U+00AD), the tag block U+E0000 to U+E007F, variation selectors, U+2028/U+2029 and
/// the blank filler letters. Output is capped at [`SANITIZE_HARD_CAP`] bytes.
pub fn sanitize(input: &str) -> String {
    sanitize_core(input, None, SANITIZE_HARD_CAP)
}

/// [`sanitize`], and then cut to at most `max_bytes` bytes (on a character boundary). A cut
/// string ends with an ellipsis.
pub fn sanitize_capped(input: &str, max_bytes: usize) -> String {
    let keep = max_bytes.saturating_sub('\u{2026}'.len_utf8());
    let mut out = sanitize_core(input, None, keep.saturating_add(8).min(SANITIZE_HARD_CAP));
    if out.len() > keep {
        let mut end = keep.min(out.len());
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('\u{2026}');
    }
    out
}

/// Sanitises every string in `value`, object keys included, recursively (to a depth of 64;
/// anything deeper is replaced by `null`), cutting each string to [`MAX_UNTRUSTED_LEN`]. Used on
/// error details, which can quote engine logs and thereby binary-derived names.
pub fn sanitize_value(value: serde_json::Value) -> serde_json::Value {
    sanitize_value_at(value, 0)
}

fn sanitize_value_at(value: serde_json::Value, depth: usize) -> serde_json::Value {
    use serde_json::Value;
    if depth > 64 {
        return Value::Null;
    }
    match value {
        Value::String(s) => Value::String(sanitize_capped(&s, MAX_UNTRUSTED_LEN)),
        Value::Array(a) => Value::Array(
            a.into_iter()
                .map(|v| sanitize_value_at(v, depth + 1))
                .collect(),
        ),
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (sanitize_capped(&k, 1024), sanitize_value_at(v, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

/// Like [`sanitize`], and also returns an offset map for keeping byte spans valid.
///
/// The map has `input.len() + 1` entries. For a byte offset `i` on a character boundary of
/// `input`, `map[i]` is the byte offset in the sanitised text where the content that followed `i`
/// starts. It is non-decreasing, so a span `start..end` of `input` becomes `map[start]..map[end]`,
/// which is a valid, possibly empty, span of the sanitised text. Entries inside a multi-byte
/// character repeat the entry of that character's first byte.
pub fn sanitize_mapped(input: &str) -> (String, Vec<u32>) {
    let mut map = vec![0u32; input.len() + 1];
    let out = sanitize_core(input, Some(&mut map), SANITIZE_HARD_CAP);
    (out, map)
}

fn sanitize_core(input: &str, mut map: Option<&mut Vec<u32>>, cap: usize) -> String {
    let mut out = String::with_capacity(input.len().min(cap));
    let mut chars = input.char_indices().peekable();
    let mut consumed = 0usize;
    // Takes the next character, recording where in the output its position falls.
    macro_rules! take {
        () => {{
            let next = chars.next();
            if let Some((i, c)) = next {
                consumed = i + c.len_utf8();
            }
            if let (Some((i, c)), Some(m)) = (next, map.as_deref_mut()) {
                let at = out.len().min(u32::MAX as usize) as u32;
                for slot in &mut m[i..i + c.len_utf8()] {
                    *slot = at;
                }
            }
            next.map(|(_, c)| c)
        }};
    }
    while let Some(c) = take!() {
        if out.len() >= cap {
            break;
        }
        match c {
            '\u{1b}' => match take!() {
                Some('[') => {
                    // CSI: parameter and intermediate bytes, then one final byte.
                    while let Some(n) = take!() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: terminated by BEL or ST (ESC \).
                    while let Some(n) = take!() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            if chars.peek().map(|&(_, c)| c) == Some('\\') {
                                take!();
                            }
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_invisible(c) => {}
            c => out.push(c),
        }
    }
    if let Some(m) = map {
        let at = out.len().min(u32::MAX as usize) as u32;
        // Input after an early stop maps to the end of the output.
        for slot in &mut m[consumed..] {
            *slot = at;
        }
        let end = m.len() - 1;
        m[end] = out.len().min(u32::MAX as usize) as u32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_text_newline_tab_and_unicode() {
        assert_eq!(sanitize("a\tb\nc é 日本"), "a\tb\nc é 日本");
    }

    #[test]
    fn strips_control_characters() {
        assert_eq!(sanitize("a\0b\u{7}c\rd\u{8}e\u{7f}f\u{85}g"), "abcdefg");
    }

    #[test]
    fn strips_ansi_sequences() {
        assert_eq!(sanitize("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(sanitize("\u{1b}[1;38;5;196mx\u{1b}[K"), "x");
        assert_eq!(sanitize("a\u{1b}]0;title\u{7}b"), "ab");
        assert_eq!(
            sanitize("a\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\"),
            "alink"
        );
        assert_eq!(sanitize("a\u{1b}Mb"), "ab");
        assert_eq!(sanitize("trailing\u{1b}"), "trailing");
        assert_eq!(sanitize("unterminated\u{1b}[31"), "unterminated");
    }

    #[test]
    fn strips_bidi_overrides() {
        assert_eq!(sanitize("a\u{202E}b\u{202A}c\u{202D}d\u{202C}"), "abcd");
        assert_eq!(sanitize("x\u{2066}y\u{2067}z\u{2068}w\u{2069}"), "xyzw");
        assert_eq!(sanitize("a\u{200E}b\u{200F}c\u{061C}"), "abc");
    }

    #[test]
    fn strips_invisible_and_format_characters() {
        // Zero-width characters, word joiner, BOM, soft hyphen, variation selectors.
        assert_eq!(
            sanitize("a\u{200B}b\u{200C}c\u{200D}d\u{2060}e\u{FEFF}f\u{AD}g"),
            "abcdefg"
        );
        assert_eq!(sanitize("x\u{FE0F}y\u{E0100}z\u{180B}w"), "xyzw");
        assert_eq!(sanitize("l\u{2028}m\u{2029}n"), "lmn");
        assert_eq!(sanitize("a\u{3164}b\u{FFA0}c"), "abc");
        // Tag characters spelling "ignore" (ASCII smuggling).
        let smuggled: String = "ignore"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).expect("tag"))
            .collect();
        assert_eq!(sanitize(&format!("name{smuggled}")), "name");
        assert_eq!(sanitize("\u{E0001}\u{E007F}ok"), "ok");
        // Visible text in other scripts and emoji bases survive.
        assert_eq!(sanitize("日本語 ñ 😀"), "日本語 ñ 😀");
    }

    #[test]
    fn capped_sanitising_cuts_on_a_boundary_and_marks_it() {
        let long = "é".repeat(100);
        let cut = sanitize_capped(&long, 11);
        assert!(cut.len() <= 11, "{}", cut.len());
        assert!(cut.ends_with('\u{2026}'));
        assert_eq!(sanitize_capped("short", 100), "short");
        let huge = "a".repeat(MAX_UNTRUSTED_LEN * 2);
        assert!(Untrusted::sanitized(&huge).0.len() <= MAX_UNTRUSTED_LEN);
        let hidden = format!("{}{}", "\u{200B}".repeat(1000), "visible");
        assert_eq!(sanitize_capped(&hidden, 100), "visible");
    }

    #[test]
    fn mapped_sanitising_stays_valid_after_the_hard_cap() {
        let input = "a".repeat(SANITIZE_HARD_CAP + 10);
        let (out, map) = sanitize_mapped(&input);
        assert_eq!(out.len(), SANITIZE_HARD_CAP);
        assert_eq!(map.len(), input.len() + 1);
        assert_eq!(map[input.len()] as usize, out.len());
        assert!(map.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn values_are_sanitised_recursively_including_keys() {
        let v = serde_json::json!({
            "log\u{1b}[31m_tail": ["ok", "evil\u{E0041}\u{200B}\u{7}", {"deep": "x\u{202E}y"}],
            "n": 3,
        });
        let clean = sanitize_value(v);
        assert_eq!(
            clean,
            serde_json::json!({"log_tail": ["ok", "evil", {"deep": "xy"}], "n": 3})
        );
        let mut deep = serde_json::json!("leaf\u{200B}");
        for _ in 0..100 {
            deep = serde_json::json!([deep]);
        }
        assert!(sanitize_value(deep).to_string().contains("null"));
    }

    #[test]
    fn mapped_offsets_follow_the_stripped_text() {
        let input = "ab\u{1b}[31mcd\u{202e}é\0f";
        let (out, map) = sanitize_mapped(input);
        assert_eq!(out, sanitize(input));
        assert_eq!(out, "abcdéf");
        assert_eq!(map.len(), input.len() + 1);
        let at = |needle: &str| input.find(needle).expect("present");
        assert_eq!(map[0], 0);
        assert_eq!(map[at("cd")] as usize, 2);
        assert_eq!(map[at("cd") + 2] as usize, 4);
        assert_eq!(map[at("é")] as usize, 4);
        assert_eq!(map[at("f")] as usize, 6);
        assert_eq!(map[input.len()] as usize, out.len());
        assert!(map.windows(2).all(|w| w[0] <= w[1]));
        for (i, _) in input.char_indices() {
            assert!(out.is_char_boundary(map[i] as usize));
        }
    }

    #[test]
    fn wrapper_serializes_with_flag() {
        let u = Untrusted::sanitized("ev\u{1b}[0mil");
        let json = serde_json::to_value(&u).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"untrusted": true, "value": "evil"})
        );
        assert_eq!(
            serde_json::from_value::<Untrusted<String>>(json).unwrap(),
            u
        );
    }

    #[test]
    fn wrapper_rejects_false_or_missing_flag() {
        assert!(
            serde_json::from_str::<Untrusted<String>>(r#"{"untrusted":false,"value":"x"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Untrusted<String>>(r#"{"value":"x"}"#).is_err());
    }
}
