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
    /// Wraps `s` after running it through [`sanitize`].
    pub fn sanitized(s: &str) -> Self {
        Untrusted(sanitize(s))
    }
}

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

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// Removes characters that can hide or forge content when binary-derived text is displayed or
/// sent to a model.
///
/// Strips ANSI escape sequences (CSI, OSC and two-byte escapes), all control characters except
/// `\n` and `\t` (including `\r` and C1 controls), and bidirectional controls: U+202A to U+202E,
/// U+2066 to U+2069, plus the marks U+200E, U+200F and U+061C.
pub fn sanitize(input: &str) -> String {
    sanitize_core(input, None)
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
    let out = sanitize_core(input, Some(&mut map));
    (out, map)
}

fn sanitize_core(input: &str, mut map: Option<&mut Vec<u32>>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    // Takes the next character, recording where in the output its position falls.
    macro_rules! take {
        () => {{
            let next = chars.next();
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
            c if c.is_control() || is_bidi(c) => {}
            c => out.push(c),
        }
    }
    if let Some(m) = map {
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
