//! Client-side tokenizer for decompiled C.
//!
//! The `decompile` command returns text plus a list of call/data references but not token spans,
//! so the GUI derives the token map itself: a small C lexer for the syntax classes, with the
//! references supplying jump targets. When the command starts returning engine token spans this
//! module becomes a fallback.

use std::collections::HashMap;

use kraken_proto::{Locator, Token, TokenKind};

const KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "return", "switch", "case", "default", "break", "continue",
    "goto", "sizeof", "struct", "union", "enum", "typedef", "static", "extern", "const",
    "volatile", "unsigned", "signed",
];

const TYPES: &[&str] = &[
    "void",
    "int",
    "char",
    "short",
    "long",
    "float",
    "double",
    "bool",
    "byte",
    "word",
    "dword",
    "qword",
    "code",
    "uint",
    "ulong",
    "ushort",
    "uchar",
    "undefined",
    "size_t",
    "ssize_t",
];

const CONSTANTS: &[&str] = &["NULL", "true", "false"];

fn is_type(word: &str) -> bool {
    TYPES.contains(&word)
        || word.ends_with("_t")
        || word
            .strip_prefix("undefined")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
}

fn is_pascal_case(word: &str) -> bool {
    word.chars().next().is_some_and(char::is_uppercase) && word.chars().any(char::is_lowercase)
}

/// Tokenizes `text`. `targets` maps a function name to its entry address.
pub fn tokenize(text: &str, targets: &HashMap<String, u64>) -> Vec<Token> {
    let b = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut after_member = false;
    let mk = |start: usize, end: usize, kind: TokenKind| Token {
        start: start as u32,
        end: end as u32,
        kind,
        target: None,
        symbol: None,
        varnode: None,
    };
    while i < b.len() {
        let start = i;
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if text[i..].starts_with("//") {
            i += text[i..].find('\n').unwrap_or(text.len() - i);
            tokens.push(mk(start, i, TokenKind::Comment));
        } else if text[i..].starts_with("/*") {
            i += text[i..].find("*/").map_or(text.len() - i, |p| p + 2);
            tokens.push(mk(start, i, TokenKind::Comment));
        } else if c == b'"' || c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != c && b[i] != b'\n' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(b.len());
            while !text.is_char_boundary(i) {
                i += 1;
            }
            tokens.push(mk(start, i, TokenKind::Constant));
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                i += 1;
            }
            tokens.push(mk(start, i, TokenKind::Constant));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &text[start..i];
            let mut t = if after_member {
                mk(start, i, TokenKind::Field)
            } else if KEYWORDS.contains(&word) {
                mk(start, i, TokenKind::Keyword)
            } else if CONSTANTS.contains(&word) {
                mk(start, i, TokenKind::Constant)
            } else if is_type(word) || (is_pascal_case(word) && b.get(i) != Some(&b'(')) {
                mk(start, i, TokenKind::Type)
            } else if let Some(addr) = targets.get(word) {
                let mut t = mk(start, i, TokenKind::Function);
                t.target = Some(Locator::ram(*addr));
                t
            } else if b.get(i) == Some(&b'(') {
                mk(start, i, TokenKind::Function)
            } else {
                mk(start, i, TokenKind::Variable)
            };
            if t.kind != TokenKind::Keyword && t.kind != TokenKind::Constant {
                t.symbol = Some(word.to_string());
            }
            tokens.push(t);
            after_member = false;
            continue;
        } else if c.is_ascii() {
            let two = text.get(i..i + 2).unwrap_or("");
            let len = if [
                "->", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "++", "--", "+=", "-=",
            ]
            .contains(&two)
            {
                2
            } else {
                1
            };
            i += len;
            after_member = &text[start..i] == "->" || &text[start..i] == ".";
            tokens.push(mk(start, i, TokenKind::Op));
            continue;
        } else {
            // Non-ASCII text outside strings and comments: skip one character.
            i += 1;
            while !text.is_char_boundary(i) {
                i += 1;
            }
            tokens.push(mk(start, i, TokenKind::Other));
        }
        after_member = false;
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str, targets: &[(&str, u64)]) -> Vec<(String, TokenKind, bool)> {
        let map: HashMap<String, u64> = targets.iter().map(|(n, a)| (n.to_string(), *a)).collect();
        tokenize(text, &map)
            .iter()
            .map(|t| {
                (
                    text[t.start as usize..t.end as usize].to_string(),
                    t.kind,
                    t.target.is_some(),
                )
            })
            .collect()
    }

    #[test]
    fn classifies_a_small_function() {
        let got = kinds(
            "int main(int argc)\n{\n  helper(argc); // go\n  return 0;\n}\n",
            &[("main", 0x401000), ("helper", 0x401040)],
        );
        assert!(got.contains(&("int".into(), TokenKind::Type, false)));
        assert!(got.contains(&("main".into(), TokenKind::Function, true)));
        assert!(got.contains(&("helper".into(), TokenKind::Function, true)));
        assert!(got.contains(&("argc".into(), TokenKind::Variable, false)));
        assert!(got.contains(&("return".into(), TokenKind::Keyword, false)));
        assert!(got.contains(&("0".into(), TokenKind::Constant, false)));
        assert!(got.contains(&("// go".into(), TokenKind::Comment, false)));
    }

    #[test]
    fn unknown_callee_is_a_function_without_target_and_fields_follow_arrows() {
        let got = kinds("x = p->len + foo(1);", &[]);
        assert!(got.contains(&("len".into(), TokenKind::Field, false)));
        assert!(got.contains(&("foo".into(), TokenKind::Function, false)));
    }

    #[test]
    fn tokens_are_valid_for_the_text() {
        let text = "char *s = \"héllo \\\" x\";\n/* é */ undefined8 v = 0x1f; // ü\n";
        let toks = tokenize(text, &HashMap::new());
        for t in &toks {
            assert!(text.is_char_boundary(t.start as usize));
            assert!(text.is_char_boundary(t.end as usize));
            assert!(t.start < t.end);
        }
        let r = kraken_proto::DecompileResult {
            function: Locator::ram(0),
            language: "c".into(),
            text: text.into(),
            tokens: toks,
            warnings: vec![],
            completeness: kraken_proto::Completeness::Complete,
        };
        r.validate_tokens().expect("valid tokens");
    }

    #[test]
    fn unterminated_string_does_not_panic() {
        let _ = tokenize("char *s = \"abc", &HashMap::new());
        let _ = tokenize("'", &HashMap::new());
        let _ = tokenize("/* open", &HashMap::new());
    }
}
