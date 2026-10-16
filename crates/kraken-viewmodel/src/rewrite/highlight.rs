//! A small Rust lexer for colouring generated code. It only has to be good enough to tell
//! keywords, types, calls, literals and comments apart; it never rejects input.

use kraken_proto::{Token, TokenKind};

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self",
    "Self", "static", "struct", "super", "trait", "type", "unsafe", "use", "where", "while",
    "true", "false",
];

const PRIMITIVES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool",
    "char", "str", "f32", "f64",
];

/// Colours `text`. Offsets are byte offsets into `text`.
pub fn highlight_rust(text: &str) -> Vec<Token> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if text[i..].starts_with("//") {
            i += text[i..].find('\n').unwrap_or(text.len() - i);
            out.push(tok(start, i, TokenKind::Comment));
        } else if text[i..].starts_with("/*") {
            i += text[i..].find("*/").map_or(text.len() - i, |p| p + 2);
            out.push(tok(start, i, TokenKind::Comment));
        } else if c == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
            out.push(tok(start, i, TokenKind::Constant));
        } else if c == b'\'' && is_char_literal(&b[i..]) {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
            out.push(tok(start, i, TokenKind::Constant));
        } else if c == b'#' && b.get(i + 1) == Some(&b'[') {
            i += text[i..].find(']').map_or(text.len() - i, |p| p + 1);
            out.push(tok(start, i, TokenKind::Other));
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(tok(start, i, TokenKind::Constant));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &text[start..i];
            let next = text[i..].trim_start_matches([' ', '\t']).as_bytes().first();
            let kind = if KEYWORDS.contains(&word) {
                TokenKind::Keyword
            } else if PRIMITIVES.contains(&word) || word.starts_with(|c: char| c.is_uppercase()) {
                TokenKind::Type
            } else if next == Some(&b'(')
                || (text[i..].starts_with('!') && !text[i..].starts_with("!="))
            {
                TokenKind::Function
            } else {
                TokenKind::Variable
            };
            out.push(tok(start, i, kind));
        } else if c.is_ascii() {
            i += 1;
            out.push(tok(start, i, TokenKind::Op));
        } else {
            i += text[i..].chars().next().map_or(1, char::len_utf8);
            out.push(tok(start, i, TokenKind::Other));
        }
    }
    out
}

/// `'a'` or `'\n'` as opposed to a lifetime such as `'a`.
fn is_char_literal(rest: &[u8]) -> bool {
    matches!(rest, [b'\'', b'\\', ..] | [b'\'', _, b'\'', ..])
}

fn tok(start: usize, end: usize, kind: TokenKind) -> Token {
    Token {
        start: start as u32,
        end: end as u32,
        kind,
        target: None,
        symbol: None,
        varnode: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(&str, TokenKind)> {
        highlight_rust(text)
            .iter()
            .map(|t| (&text[t.start as usize..t.end as usize], t.kind))
            .collect()
    }

    #[test]
    fn colours_the_parts_of_a_function() {
        let k = kinds("pub extern \"C\" fn f(x: u32) -> u32 { x.wrapping_add(1) } // done");
        assert!(k.contains(&("pub", TokenKind::Keyword)));
        assert!(k.contains(&("\"C\"", TokenKind::Constant)));
        assert!(k.contains(&("f", TokenKind::Function)));
        assert!(k.contains(&("u32", TokenKind::Type)));
        assert!(k.contains(&("wrapping_add", TokenKind::Function)));
        assert!(k.contains(&("x", TokenKind::Variable)));
        assert!(k.contains(&("1", TokenKind::Constant)));
        assert!(k.contains(&("// done", TokenKind::Comment)));
    }

    #[test]
    fn lifetimes_are_not_strings_and_odd_input_does_not_panic() {
        let k = kinds("fn g<'a>(s: &'a str) { let c = 'x'; }");
        assert!(k.contains(&("'x'", TokenKind::Constant)));
        assert!(!k.iter().any(|(t, _)| t.starts_with("'a>")));
        // Unterminated strings and comments, attributes and non-ASCII text.
        for s in ["\"open", "/* open", "#[no_mangle", "let é = 1;", "'", "\\"] {
            let toks = highlight_rust(s);
            assert!(toks.iter().all(|t| (t.end as usize) <= s.len()));
        }
    }
}
